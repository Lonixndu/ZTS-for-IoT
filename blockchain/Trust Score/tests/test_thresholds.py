from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from config import EngineConfig, Weights
from device_state import Observation
from engine import CapacityExceeded, DeviceAlreadyExists, DeviceNotFound, StaleObservation, TrustEngine

START = datetime(2026, 10, 17, tzinfo=timezone.utc)


def obs(risk, step=1, device="sensor-1", context=0.0):
    return Observation(device, risk, START + timedelta(seconds=step), f"test:{step}", context)


def registered(mode="adaptive", config=None):
    engine = TrustEngine(mode, config)
    engine.register_device("sensor-1", 0.5)
    return engine


def test_benign_device_stays_allowed_and_learns_baseline():
    engine = registered()
    for step in range(1, 20):
        assert engine.evaluate(obs(0.1, step)).action == "allow"
    state = engine.get_state("sensor-1")
    assert len(state.baseline_risks) == 5
    assert state.history_pressure == 0
    assert engine.evaluate(obs(0.1, 20)).baseline == pytest.approx(0.1)


def test_repeated_near_boundary_risk_is_caught_only_by_adaptive():
    adaptive, static = registered(), registered("static")
    first = adaptive.evaluate(obs(0.4))
    assert first.action == "allow"
    assert first.is_probe
    assert first.threshold == pytest.approx(0.59)
    second = adaptive.evaluate(obs(0.4, 2))
    assert second.action == "quarantine"
    assert second.threshold > first.threshold
    for step in range(1, 8):
        result = static.evaluate(obs(0.4, step))
        assert result.action == "allow"
        assert result.threshold == pytest.approx(0.54)


def test_quarantine_is_latched_even_when_risk_falls():
    engine = registered()
    assert engine.evaluate(obs(0.95)).action == "quarantine"
    decision = engine.evaluate(obs(0.0, 2))
    assert decision.action == "quarantine"
    assert decision.reason_code == "QUARANTINE_LATCHED"
    with pytest.raises(DeviceAlreadyExists):
        engine.register_device("sensor-1")


def test_explicit_missing_risk_is_fail_closed():
    engine = registered()
    result = engine.evaluate(obs(None))
    assert result.action == "quarantine"
    assert result.reason_code == "MISSING_BEHAVIOR_RISK"
    assert result.trust_value == 0


@pytest.mark.parametrize("risk", [-0.1, 1.1, float("nan"), float("inf"), "0.2", True])
def test_invalid_risk_rejected_before_state_mutation(risk):
    engine = registered()
    with pytest.raises(ValueError):
        engine.evaluate(obs(risk))
    assert not engine.history("sensor-1")


def test_naive_timestamp_rejected():
    with pytest.raises(ValueError):
        Observation("sensor-1", 0.1, datetime(2026, 10, 17), "test")


def test_stale_or_duplicate_timestamp_is_rejected():
    engine = registered()
    engine.evaluate(obs(0.1, 3))
    for step in (2, 3):
        with pytest.raises(StaleObservation):
            engine.evaluate(obs(0.95, step))
    assert len(engine.history("sensor-1")) == 1
    assert not engine.get_state("sensor-1").quarantined


def test_device_state_is_isolated_and_returned_as_a_copy():
    engine = registered()
    engine.register_device("sensor-2")
    engine.evaluate(obs(0.99))
    other = engine.evaluate(obs(0.1, device="sensor-2"))
    assert other.action == "allow"
    state_copy = engine.get_state("sensor-2")
    state_copy.quarantined = True
    state_copy.baseline_risks.append(1.0)
    assert not engine.get_state("sensor-2").quarantined
    assert list(engine.get_state("sensor-2").baseline_risks) == [0.1]


def test_fixed_threshold_allows_equality():
    engine = registered("static", EngineConfig(base_threshold=0.5, weights=Weights(criticality=0)))
    assert engine.evaluate(obs(0.5)).action == "allow"


def test_higher_context_and_criticality_raise_threshold():
    low, high = registered(), registered()
    assert high.evaluate(obs(0.1, context=1)).threshold > low.evaluate(obs(0.1)).threshold
    engine = TrustEngine()
    engine.register_device("low", 0.0)
    engine.register_device("high", 1.0)
    assert engine.evaluate(obs(0.1, device="high")).threshold > engine.evaluate(obs(0.1, device="low")).threshold


def test_threshold_and_history_are_bounded():
    engine = registered(config=EngineConfig(history_limit=2))
    for step in range(1, 9):
        decision = engine.evaluate(obs(0.9, step, context=1.0))
        assert 0.1 <= decision.threshold <= 0.95
        assert all(0 <= value <= 1 for value in decision.features.as_dict().values())
    assert len(engine.history("sensor-1", 2)) == 2


def test_history_ablation_changes_repeated_probe_behavior():
    config = EngineConfig().ablate("violation_history")
    engine = registered(config=config)
    assert engine.evaluate(obs(0.4)).action == "allow"
    assert engine.evaluate(obs(0.4, 2)).action == "allow"


def test_logging_failure_does_not_commit_state():
    class BrokenLog:
        def append(self, _):
            raise OSError("disk unavailable")
    engine = registered()
    engine.logger = BrokenLog()
    with pytest.raises(OSError):
        engine.evaluate(obs(0.99))
    state = engine.get_state("sensor-1")
    assert state.last_timestamp is None
    assert not state.quarantined
    assert not state.decisions


def test_unregistered_device_and_capacity_limit():
    engine = TrustEngine(config=EngineConfig(max_devices=1))
    with pytest.raises(DeviceNotFound):
        engine.evaluate(obs(0.1))
    engine.register_device("sensor-1")
    with pytest.raises(CapacityExceeded):
        engine.register_device("sensor-2")


def test_concurrent_devices_keep_separate_histories():
    engine = TrustEngine()
    for index in range(5):
        engine.register_device(f"sensor-{index}")
    def work(index):
        for step in range(1, 6):
            engine.evaluate(obs(0.1, step, f"sensor-{index}"))
    with ThreadPoolExecutor(max_workers=5) as pool:
        list(pool.map(work, range(5)))
    for index in range(5):
        history = engine.history(f"sensor-{index}")
        assert len(history) == 5
        assert all(item["deviceId"] == f"sensor-{index}" for item in history)


@pytest.mark.parametrize("kwargs", [
    {"velocity_scale": 0}, {"history_decay": 1}, {"max_devices": 0},
    {"base_threshold": float("nan")}, {"minimum_threshold": 0.9},
])
def test_invalid_config_rejected(kwargs):
    with pytest.raises(ValueError):
        EngineConfig(**kwargs)

