"""Tests for the Member 3 feeder that sends Member 1 engine decisions to the ledger.

They run feed_trust.py in --offline mode, so no bridge, connector or Fabric is
needed. Same seed -> same synthetic inputs -> same decisions (deterministic).
"""
from pathlib import Path
from random import Random
import re
import subprocess
import sys

import pytest

from blockchain_client import make_trust_update
from config import EngineConfig
from device_state import Observation
from engine import TrustEngine
from feed_trust import behaviour_risk, choose_attackers

HERE = Path(__file__).resolve().parents[1]


def run_offline(tmp_path, *args):
    out = subprocess.run(
        [sys.executable, "feed_trust.py", "--offline", "--output", str(tmp_path), *args],
        cwd=HERE, capture_output=True, text=True, check=True,
    ).stdout
    caught, total = map(int, re.search(r"attackers marked SUSPECT: (\d+)/(\d+)", out).groups())
    false_alarms = int(re.search(r"normal devices marked SUSPECT: (\d+)/", out).group(1))
    return caught, total, false_alarms


def test_attackers_are_spread_across_the_fleet():
    ids = [f"dev-{i:03d}" for i in range(1, 25)]
    assert choose_attackers(ids, 3) == {"dev-002", "dev-010", "dev-018"}
    assert choose_attackers(ids, 0) == set()


def test_behaviour_risk_stays_in_range():
    rng = Random(1)
    for scenario in ("burst", "fixed_margin", "slow_drift", "randomised"):
        for step in range(1, 30):
            for attacker in (True, False):
                risk = behaviour_risk(scenario, attacker, step, 2, 0.54, rng)
                assert 0.0 <= risk <= 1.0


def test_ledger_payload_matches_engine_decision():
    engine = TrustEngine("adaptive", EngineConfig())
    engine.register_device("dev-002", 0.75)
    from datetime import datetime, timezone
    decision = engine.evaluate(Observation("dev-002", 0.6, datetime(2026, 10, 24, tzinfo=timezone.utc),
                                           "test:1", attack_class="burst", confidence=0.9)).to_dict()
    payload = make_trust_update(decision)
    assert 0 <= payload["trust_value"] <= 100 and 0 <= payload["threshold"] <= 100
    # the ledger rule (trust < threshold -> SUSPECT) gives the same answer as the engine
    assert (payload["trust_value"] < payload["threshold"]) == (decision["action"] == "quarantine")
    assert payload["attack_class"] == "burst" and payload["reason_code"] == "AI_ANOMALY"


def test_burst_attack_is_caught_without_false_alarms(tmp_path):
    caught, total, false_alarms = run_offline(tmp_path, "--scenario", "burst", "--steps", "8")
    assert (caught, total, false_alarms) == (3, 3, 0)


@pytest.mark.parametrize("scenario", ["slow_drift", "fixed_margin", "randomised"])
def test_adaptive_engine_catches_evasive_attackers_that_static_misses(tmp_path, scenario):
    adaptive = run_offline(tmp_path, "--scenario", scenario, "--steps", "15", "--mode", "adaptive")
    static = run_offline(tmp_path, "--scenario", scenario, "--steps", "15", "--mode", "static")
    assert adaptive[0] == 3 and adaptive[2] == 0
    assert static[0] == 0
