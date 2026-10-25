"""Stateful trust decisions with bounded memory and quarantine latching."""
from collections import deque
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import RLock
from time import perf_counter

from adaptive_threshold import adaptive_threshold
from config import EngineConfig, unit
from device_state import DeviceState, Observation, validate_device_id
from features import FeatureVector, baseline_risk, clip, extract_features
from static_baseline import static_threshold


class DeviceNotFound(KeyError):
    pass


class DeviceAlreadyExists(ValueError):
    pass


class StaleObservation(ValueError):
    pass


class CapacityExceeded(ValueError):
    pass


@dataclass(frozen=True)
class Decision:
    device_id: str
    mode: str
    timestamp: str
    trust_value: float
    threshold: float
    action: str
    reason_code: str
    evidence_ref: str
    behavior_risk: float | None
    baseline: float
    is_probe: bool
    latency_ms: float
    features: FeatureVector
    attack_class: str | None = None
    confidence: float | None = None
    anomaly_score: float | None = None

    def to_dict(self):
        return {
            "deviceId": self.device_id, "mode": self.mode, "timestamp": self.timestamp,
            "trustValue": self.trust_value, "threshold": self.threshold,
            "action": self.action, "reasonCode": self.reason_code,
            "evidenceRef": self.evidence_ref, "BehaviorRisk": self.behavior_risk,
            "baselineRisk": self.baseline, "isProbe": self.is_probe,
            "latencyMs": self.latency_ms, "features": self.features.as_dict(),
            "attackClass": self.attack_class, "confidence": self.confidence,
            "anomalyScore": self.anomaly_score,
        }


class TrustEngine:
    def __init__(self, mode: str = "adaptive", config: EngineConfig | None = None, logger=None):
        if mode not in ("adaptive", "static"):
            raise ValueError("mode must be adaptive or static")
        self.mode = mode
        self.config = config or EngineConfig()
        self.logger = logger
        self._devices: dict[str, DeviceState] = {}
        self._lock = RLock()

    def register_device(self, device_id: str, criticality: float = 0.5, *, quarantined=False,
                        initial_threshold=None, initial_trust=None, last_timestamp=None):
        validate_device_id(device_id)
        criticality = unit(criticality, "criticality")
        threshold = (static_threshold(criticality, self.config) if initial_threshold is None
                     else unit(initial_threshold, "initial_threshold"))
        if initial_trust is not None:
            initial_trust = unit(initial_trust, "initial_trust")
        if type(quarantined) is not bool:
            raise ValueError("quarantined must be boolean")
        if last_timestamp is not None:
            if not isinstance(last_timestamp, datetime) or last_timestamp.utcoffset() is None:
                raise ValueError("last_timestamp must be timezone-aware")
            last_timestamp = last_timestamp.astimezone(timezone.utc)
        with self._lock:
            if device_id in self._devices:
                raise DeviceAlreadyExists(device_id)
            if len(self._devices) >= self.config.max_devices:
                raise CapacityExceeded("device capacity reached")
            self._devices[device_id] = DeviceState(
                device_id=device_id, criticality=criticality,
                threshold=threshold, quarantined=quarantined,
                previous_trust=initial_trust, last_timestamp=last_timestamp,
                baseline_risks=deque(maxlen=self.config.baseline_samples),
                decisions=deque(maxlen=self.config.history_limit),
            )
        return {"deviceId": device_id, "criticality": criticality}

    def get_state(self, device_id: str) -> DeviceState:
        with self._lock:
            if device_id not in self._devices:
                raise DeviceNotFound(device_id)
            return deepcopy(self._devices[device_id])

    def history(self, device_id: str, limit: int = 100):
        if type(limit) is not int or not 1 <= limit <= self.config.history_limit:
            raise ValueError("history limit out of range")
        state = self.get_state(device_id)
        return [item.to_dict() for item in list(state.decisions)[-limit:]]

    def evaluate(self, observation: Observation) -> Decision:
        # The single-process lock covers evaluation, logging, and state commit.
        with self._lock:
            if observation.device_id not in self._devices:
                raise DeviceNotFound(observation.device_id)
            original = self._devices[observation.device_id]
            if original.last_timestamp is not None and observation.timestamp <= original.last_timestamp:
                raise StaleObservation("timestamp must be newer than the previous observation")
            state = deepcopy(original)
            started = perf_counter()
            baseline = baseline_risk(state, self.config)
            trust = 0.0 if observation.behavior_risk is None else 1.0 - observation.behavior_risk
            if observation.behavior_risk is None:
                vector = FeatureVector(state.criticality, state.history_pressure, 0.0, 0.0, observation.network_context)
            else:
                vector = extract_features(state, observation, self.config)

            if state.quarantined:
                threshold = state.threshold
                reason = "QUARANTINE_LATCHED"
                quarantine = True
            elif observation.behavior_risk is None:
                threshold = state.threshold
                reason = "MISSING_BEHAVIOR_RISK"
                quarantine = True
            else:
                threshold = static_threshold(state.criticality, self.config) if self.mode == "static" else adaptive_threshold(
                    vector, self.config, state.threshold, state.probe_streak > 0
                )
                # Equality is allowed. The boundary is a minimum required trust.
                quarantine = trust < threshold
                reason = "BELOW_THRESHOLD" if quarantine else "TRUST_ACCEPTED"

            probe = not quarantine and (trust - threshold <= self.config.probe_band)
            if probe:
                reason = "NEAR_BOUNDARY_MONITOR"
            suspicious = probe or quarantine
            state.history_pressure = clip(
                self.config.history_decay * state.history_pressure
                + (self.config.history_increment if suspicious else 0.0)
            )
            state.probe_streak = state.probe_streak + 1 if probe else 0
            state.near_boundary_events += int(probe)
            state.violations += int(quarantine and not state.quarantined)
            state.quarantined = quarantine
            state.threshold = threshold
            state.last_timestamp = observation.timestamp
            state.previous_trust = None if observation.behavior_risk is None else trust
            if (not suspicious and observation.behavior_risk is not None
                    and observation.behavior_risk <= self.config.baseline_update_max_risk):
                state.baseline_risks.append(observation.behavior_risk)

            latency = (perf_counter() - started) * 1000
            decision = Decision(
                device_id=state.device_id, mode=self.mode,
                timestamp=observation.timestamp.isoformat(), trust_value=trust,
                threshold=threshold, action="quarantine" if quarantine else "allow",
                reason_code=reason, evidence_ref=observation.evidence_ref,
                behavior_risk=observation.behavior_risk, baseline=baseline,
                is_probe=probe, latency_ms=latency, features=vector,
                attack_class=observation.attack_class, confidence=observation.confidence,
                anomaly_score=observation.anomaly_score,
            )
            # A logging failure must not silently advance in-memory state.
            if self.logger is not None:
                self.logger.append(decision.to_dict())
            state.decisions.append(decision)
            self._devices[observation.device_id] = state
            return decision

