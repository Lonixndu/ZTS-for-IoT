import json
from random import Random

import pytest

from attacker_strategies import STRATEGIES, next_risk
from config import FEATURE_NAMES
from metrics import summarize
from simulation import run_simulation, write_results


def without_latency(rows):
    return [{key: value for key, value in row.items() if key != "latencyMs"} for row in rows]


def test_seed_reproducibility_and_identical_engine_inputs():
    a, _ = run_simulation(seed=7, devices_per_scenario=2, rounds=6)
    b, _ = run_simulation(seed=7, devices_per_scenario=2, rounds=6)
    assert without_latency(a) == without_latency(b)
    for static, adaptive in zip(a[::2], a[1::2]):
        assert static["mode"] == "static" and adaptive["mode"] == "adaptive"
        for name in ("deviceId", "BehaviorRisk", "timestamp", "evidenceRef", "groundTruth"):
            assert static[name] == adaptive[name]


@pytest.mark.parametrize("feature", FEATURE_NAMES)
def test_each_ablation_runs(feature):
    rows, summary = run_simulation(devices_per_scenario=1, rounds=3, ablation=feature)
    assert len(rows) == 4 * 8 * 2
    assert summary["config"]["weights"][feature] == 0


def test_adaptive_feedback_runs_and_metrics_are_valid():
    _, summary = run_simulation(devices_per_scenario=2, rounds=8, feedback="adaptive")
    assert summary["feedback"] == "adaptive"
    for result in summary["metrics"].values():
        assert 0 <= result["falsePositiveRate"] <= 1
        assert 0 <= result["evasionCatchRate"] <= 1


@pytest.mark.parametrize("strategy", STRATEGIES)
def test_attack_generator_respects_reference_boundary(strategy):
    rng = Random(42)
    for step in range(1, 10):
        risk = next_risk(strategy, step, 0.6, rng)
        assert 0 <= risk <= 0.375


def row(device, scenario, phase, step, action):
    return {"mode": "adaptive", "deviceId": device, "scenario": scenario,
            "phase": phase, "round": step, "attackRound": step if phase == "attack" else 0,
            "action": action, "isProbe": False, "latencyMs": 1.0}


def test_metrics_keep_uncaught_and_exclude_pre_attack_false_quarantine():
    records = [
        row("caught", "fixed_margin", "attack", 2, "quarantine"),
        row("escaped", "fixed_margin", "attack", 5, "allow"),
        row("early", "fixed_margin", "warmup", 1, "quarantine"),
        row("early", "fixed_margin", "attack", 2, "quarantine"),
        row("normal", "benign", "benign", 1, "allow"),
        row("false-alarm", "benign", "benign", 1, "quarantine"),
    ]
    result = summarize(records)["adaptive"]
    assert result["attackDevices"] == 3
    assert result["preAttackQuarantines"] == 1
    assert result["eligibleAttackDevices"] == 2
    assert result["uncaughtAttackDevices"] == 1
    assert result["evasionCatchRate"] == 0.5
    assert result["falsePositiveRate"] == 0.5
    assert result["medianRoundsToQuarantineAmongCaught"] == 2


def test_late_catch_is_not_counted_within_ten_rounds():
    result = summarize([row("late", "slow_drift", "attack", 11, "quarantine")])["adaptive"]
    assert result["evasionCatchRate"] == 1
    assert result["evasionCatchRateWithin10Rounds"] == 0
    assert result["falsePositiveRate"] is None


def test_csv_and_json_export_do_not_overwrite_silently(tmp_path):
    rows, summary = run_simulation(devices_per_scenario=1, rounds=3)
    write_results(rows, summary, tmp_path)
    assert json.loads((tmp_path / "summary.json").read_text())["seed"] == 42
    with pytest.raises(FileExistsError):
        write_results(rows, summary, tmp_path)


@pytest.mark.parametrize("kwargs", [{"rounds": 0}, {"devices_per_scenario": 0}, {"warmup": 0}, {"feedback": "unknown"}])
def test_invalid_simulation_arguments(kwargs):
    with pytest.raises(ValueError):
        run_simulation(**kwargs)

