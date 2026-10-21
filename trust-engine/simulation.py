"""Run both engines on identical synthetic observations and export CSV/JSON."""
import argparse
import csv
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import json
from math import sin
from pathlib import Path
from random import Random

from attacker_strategies import STRATEGIES, next_risk
from config import EngineConfig, FEATURE_NAMES, VERSION
from decision_logger import DECISION_FIELDS, safe_csv_value
from device_state import Observation
from engine import TrustEngine
from features import clip
from metrics import summarize
from static_baseline import static_threshold

SCENARIOS = ("benign",) + STRATEGIES
SIMULATION_FIELDS = ["scenario", "phase", "round", "attackRound", "groundTruth"] + DECISION_FIELDS


def run_simulation(seed: int = 42, devices_per_scenario: int = 20, rounds: int = 20,
                   warmup: int = 5, feedback: str = "static", ablation: str | None = None):
    if type(seed) is not int or seed < 0:
        raise ValueError("seed must be a non-negative integer")
    if type(devices_per_scenario) is not int or not 1 <= devices_per_scenario <= 50:
        raise ValueError("devices_per_scenario must be 1-50")
    if type(rounds) is not int or not 1 <= rounds <= 200:
        raise ValueError("rounds must be 1-200")
    if type(warmup) is not int or not 1 <= warmup <= 100:
        raise ValueError("warmup must be 1-100")
    if feedback not in ("static", "adaptive"):
        raise ValueError("feedback must be static or adaptive")
    config = EngineConfig()
    if ablation is not None:
        config = config.ablate(ablation)
    engines = {mode: TrustEngine(mode, config) for mode in ("static", "adaptive")}
    rows = []
    start = datetime(2026, 10, 17, tzinfo=timezone.utc)
    for scenario_index, scenario in enumerate(SCENARIOS):
        for index in range(devices_per_scenario):
            rng = Random(seed * 10007 + scenario_index * 1009 + index)
            device_id = f"{scenario}-{index:03d}"
            criticality = rng.uniform(0.2, 0.8)
            for engine in engines.values():
                engine.register_device(device_id, criticality)
            for step in range(1, warmup + rounds + 1):
                attack_round = max(0, step - warmup)
                if step <= warmup:
                    risk = rng.uniform(0.08, 0.16)
                    phase = "warmup"
                elif scenario == "benign":
                    phase = "benign"
                    risk = clip(0.12 + 0.06 * sin(attack_round / 3) + rng.uniform(-0.025, 0.025))
                    # Some benign devices have legitimate bursts; false positives are observable.
                    if index % 5 == 0 and attack_round % 9 == 0:
                        risk = rng.uniform(0.28, 0.35)
                else:
                    phase = "attack"
                    reference = static_threshold(criticality, config) if feedback == "static" else engines["adaptive"].get_state(device_id).threshold
                    risk = next_risk(scenario, attack_round, reference, rng)
                observation = Observation(
                    device_id=device_id, behavior_risk=risk,
                    timestamp=start + timedelta(seconds=step),
                    evidence_ref=f"synthetic:{seed}:{device_id}:{step}", network_context=0.05,
                )
                # Ground truth is added AFTER evaluation and never reaches either engine.
                for engine in engines.values():
                    decision = engine.evaluate(observation).to_dict()
                    rows.append({
                        "scenario": scenario, "phase": phase, "round": step,
                        "attackRound": attack_round,
                        "groundTruth": "attack" if phase == "attack" else "benign",
                        **decision,
                    })
    summary = {
        "prototypeVersion": VERSION,
        "dataSource": "synthetic risk values only",
        "seed": seed, "devicesPerScenario": devices_per_scenario,
        "attackRounds": rounds, "warmupRounds": warmup,
        "feedback": feedback, "ablation": ablation,
        "config": asdict(config), "metrics": summarize(rows),
        "notes": [
            "Weights are provisional; these are demonstration metrics, not validated research results.",
            "Both engines receive the same observations and have separate device state.",
            "Static feedback constrains probes to evade the fixed boundary by construction.",
            "Adaptive feedback uses the previous adaptive threshold, not a next-step optimisation oracle.",
            "Compute latency excludes locking, state copying, CSV output, HTTP, and network enforcement.",
        ],
    }
    return rows, summary


def write_results(rows: list[dict], summary: dict, out: Path, overwrite: bool = False):
    csv_path, json_path = out / "decisions.csv", out / "summary.json"
    if not overwrite and (csv_path.exists() or json_path.exists()):
        raise FileExistsError("output already exists; choose a new --output or add --overwrite")
    out.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=SIMULATION_FIELDS)
        writer.writeheader()
        for row in rows:
            record = {**row, "features": json.dumps(row["features"], sort_keys=True)}
            writer.writerow({key: safe_csv_value(record[key]) for key in SIMULATION_FIELDS})
    json_path.write_text(json.dumps(summary, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--devices-per-scenario", type=int, default=20)
    parser.add_argument("--rounds", type=int, default=20)
    parser.add_argument("--warmup", type=int, default=5)
    parser.add_argument("--feedback", choices=("static", "adaptive"), default="static")
    parser.add_argument("--ablate", choices=FEATURE_NAMES)
    parser.add_argument("--output", type=Path, default=Path("results/demo"))
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    if not args.overwrite and any((args.output / name).exists() for name in ("decisions.csv", "summary.json")):
        parser.error("output already exists; choose a new --output or add --overwrite")
    try:
        rows, summary = run_simulation(
            args.seed, args.devices_per_scenario, args.rounds, args.warmup, args.feedback, args.ablate
        )
        write_results(rows, summary, args.output, args.overwrite)
    except (ValueError, FileExistsError) as exc:
        parser.error(str(exc))
    print(json.dumps(summary["metrics"], indent=2, allow_nan=False))
    print(f"Wrote {len(rows)} decisions to {args.output}")


if __name__ == "__main__":
    main()

