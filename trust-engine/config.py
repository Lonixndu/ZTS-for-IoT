"""Provisional research settings. These weights have not been fitted to a dataset."""
from dataclasses import dataclass, fields, replace
from math import isfinite
from numbers import Real

VERSION = "0.3.0"
FEATURE_NAMES = (
    "criticality", "violation_history", "score_velocity",
    "personal_baseline", "network_context",
)


def unit(value: float, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ValueError(f"{name} must be a number")
    value = float(value)
    if not isfinite(value) or not 0 <= value <= 1:
        raise ValueError(f"{name} must be finite and between 0 and 1")
    return value


@dataclass(frozen=True)
class Weights:
    criticality: float = 0.08
    violation_history: float = 0.22
    score_velocity: float = 0.10
    personal_baseline: float = 0.08
    network_context: float = 0.06

    def __post_init__(self):
        for field in fields(self):
            unit(getattr(self, field.name), field.name)


@dataclass(frozen=True)
class EngineConfig:
    weights: Weights = Weights()
    base_threshold: float = 0.50
    minimum_threshold: float = 0.10
    maximum_threshold: float = 0.95
    probe_band: float = 0.08
    history_decay: float = 0.90
    history_increment: float = 0.35
    velocity_scale: float = 0.15
    baseline_scale: float = 0.40
    default_baseline_risk: float = 0.15
    baseline_update_max_risk: float = 0.25
    baseline_samples: int = 5
    history_limit: int = 256
    max_devices: int = 200

    def __post_init__(self):
        if not isinstance(self.weights, Weights):
            raise ValueError("weights must be a Weights instance")
        for name in (
            "base_threshold", "minimum_threshold", "maximum_threshold", "probe_band",
            "history_decay", "history_increment", "velocity_scale", "baseline_scale",
            "default_baseline_risk", "baseline_update_max_risk",
        ):
            unit(getattr(self, name), name)
        if not self.minimum_threshold <= self.base_threshold <= self.maximum_threshold:
            raise ValueError("threshold bounds must contain base_threshold")
        if self.history_decay >= 1:
            raise ValueError("history_decay must be less than 1")
        for name in ("velocity_scale", "baseline_scale", "history_increment"):
            if getattr(self, name) <= 0:
                raise ValueError(f"{name} must be positive")
        for name in ("baseline_samples", "history_limit", "max_devices"):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")

    def ablate(self, feature: str):
        if feature not in FEATURE_NAMES:
            raise ValueError(f"Unknown feature: {feature}")
        return replace(self, weights=replace(self.weights, **{feature: 0.0}))

