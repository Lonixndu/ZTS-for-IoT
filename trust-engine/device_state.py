"""Scoring data contracts; predicted AI labels are metadata, never ground truth."""
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import re

from config import unit

DEVICE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$"
ATTACK_CLASS_PATTERN = r"^[A-Za-z0-9_.:-]{0,64}$"


def validate_device_id(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(DEVICE_ID_PATTERN, value):
        raise ValueError("device_id must contain 1-64 letters, digits, _, ., : or -")
    return value


@dataclass(frozen=True)
class Observation:
    device_id: str
    behavior_risk: float | None
    timestamp: datetime
    evidence_ref: str
    network_context: float = 0.0
    attack_class: str | None = None
    confidence: float | None = None
    anomaly_score: float | None = None

    def __post_init__(self):
        validate_device_id(self.device_id)
        if self.behavior_risk is not None:
            unit(self.behavior_risk, "behavior_risk")
        unit(self.network_context, "network_context")
        if not isinstance(self.timestamp, datetime) or self.timestamp.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        object.__setattr__(self, "timestamp", self.timestamp.astimezone(timezone.utc))
        if not isinstance(self.evidence_ref, str) or not 1 <= len(self.evidence_ref.strip()) <= 200:
            raise ValueError("evidence_ref must contain 1-200 characters")
        if self.attack_class is not None and (not isinstance(self.attack_class, str)
                or not re.fullmatch(ATTACK_CLASS_PATTERN, self.attack_class)):
            raise ValueError("attack_class must contain at most 64 letters, digits or _.:-")
        for name in ("confidence", "anomaly_score"):
            if getattr(self, name) is not None:
                unit(getattr(self, name), name)


@dataclass
class DeviceState:
    device_id: str
    criticality: float
    threshold: float
    baseline_risks: deque = field(default_factory=deque)
    decisions: deque = field(default_factory=deque)
    previous_trust: float | None = None
    last_timestamp: datetime | None = None
    history_pressure: float = 0.0
    probe_streak: int = 0
    quarantined: bool = False
    violations: int = 0
    near_boundary_events: int = 0

