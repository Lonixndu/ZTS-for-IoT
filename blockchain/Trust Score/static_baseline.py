"""A fixed per-device threshold, calibrated once at onboarding."""
from config import EngineConfig, unit
from features import clip


def static_threshold(criticality: float, config: EngineConfig) -> float:
    unit(criticality, "criticality")
    return clip(
        config.base_threshold + config.weights.criticality * criticality,
        config.minimum_threshold,
        config.maximum_threshold,
    )

