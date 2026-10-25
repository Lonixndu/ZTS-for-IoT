"""Features use only earlier device state and the current observation."""
from dataclasses import asdict, dataclass
from statistics import mean

from config import EngineConfig
from device_state import DeviceState, Observation


def clip(value: float, lower: float = 0.0, upper: float = 1.0) -> float:
    return max(lower, min(upper, value))


@dataclass(frozen=True)
class FeatureVector:
    criticality: float
    violation_history: float
    score_velocity: float
    personal_baseline: float
    network_context: float

    def as_dict(self):
        return asdict(self)


def baseline_risk(state: DeviceState, config: EngineConfig) -> float:
    if len(state.baseline_risks) < config.baseline_samples:
        return config.default_baseline_risk
    return mean(state.baseline_risks)


def extract_features(state: DeviceState, obs: Observation, config: EngineConfig) -> FeatureVector:
    # Missing risk is handled conservatively by the engine; it is not imputed here.
    if obs.behavior_risk is None:
        raise ValueError("feature extraction requires a risk value")
    trust = 1.0 - obs.behavior_risk
    velocity = 0.0 if state.previous_trust is None else clip(
        (state.previous_trust - trust) / config.velocity_scale
    )
    deviation = clip((obs.behavior_risk - baseline_risk(state, config)) / config.baseline_scale)
    return FeatureVector(
        criticality=state.criticality,
        violation_history=state.history_pressure,
        score_velocity=velocity,
        personal_baseline=deviation,
        network_context=obs.network_context,
    )

