"""An explicit, provisional five-variable formula for the first prototype."""
from config import EngineConfig
from features import FeatureVector, clip


def adaptive_threshold(features: FeatureVector, config: EngineConfig,
                       previous_threshold: float, probing_in_progress: bool) -> float:
    weighted = sum(
        getattr(config.weights, name) * value
        for name, value in features.as_dict().items()
    )
    candidate = config.base_threshold + weighted
    # Do not relax the boundary while the previous observation was a probe.
    if probing_in_progress:
        candidate = max(previous_threshold, candidate)
    return clip(candidate, config.minimum_threshold, config.maximum_threshold)

