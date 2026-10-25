"""Synthetic risk-value generators; these do not transmit network traffic."""
from random import Random

from config import unit
from features import clip

STRATEGIES = ("fixed_margin", "slow_drift", "randomised")


def next_risk(strategy: str, attack_round: int, reference_threshold: float, rng: Random,
              margin: float = 0.025) -> float:
    """Choose risk below the supplied trust boundary, using prior-round feedback."""
    unit(reference_threshold, "reference_threshold")
    unit(margin, "margin")
    if type(attack_round) is not int or attack_round < 1:
        raise ValueError("attack_round must be positive")
    ceiling = clip(1.0 - reference_threshold - margin)
    if strategy == "fixed_margin":
        return ceiling
    if strategy == "slow_drift":
        return min(ceiling, 0.15 + 0.025 * attack_round)
    if strategy == "randomised":
        return rng.uniform(max(0.0, ceiling - 0.12), ceiling)
    raise ValueError(f"Unknown strategy: {strategy}")

