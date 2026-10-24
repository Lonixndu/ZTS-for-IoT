
from pathlib import Path
import sys
import json

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "inference"))

from offline_predict import load_engine, predict_batch

SOURCE = ROOT / "results/original_test/nonoverlap_test.csv"
CONFIG = ROOT / "results/fusion_v4_experiments/selected_candidate.json"
OUT = ROOT / "results/fusion_v4_experiments/test_evaluation"
OUT.mkdir(parents=True, exist_ok=True)

with open(CONFIG, encoding="utf-8") as f:
    candidate = json.load(f)

weight = float(candidate["xgb_weight"])
threshold = float(candidate["threshold"])

print("Loading frozen models...")
engine = load_engine()

counts = {
    "total": 0,
    "benign": 0,
    "attacks": 0,
    "v3_fp": 0,
    "v3_tp": 0,
    "v4_fp": 0,
    "v4_tp": 0,
    "pingsweep_total": 0,
    "v3_pingsweep_detected": 0,
    "v4_pingsweep_detected": 0,
}

for chunk_number, chunk in enumerate(
    pd.read_csv(SOURCE, chunksize=10000), start=1
):
    predictions = predict_batch(engine, chunk)

    labels = predictions["actual_label"].to_numpy()
    attack = labels != "BenignTraffic"
    benign = ~attack
    ping = labels == "Recon-PingSweep"

    v3_detected = predictions[
        "detected_attack"
    ].to_numpy(dtype=bool)

    xgb = predictions[
        "xgb_attack_score"
    ].to_numpy(dtype=float)

    ae = predictions[
        "ae_score"
    ].to_numpy(dtype=float)

    v4_risk = weight * xgb + (1 - weight) * ae
    v4_detected = v4_risk > threshold

    counts["total"] += len(chunk)
    counts["benign"] += int(benign.sum())
    counts["attacks"] += int(attack.sum())

    counts["v3_fp"] += int((v3_detected & benign).sum())
    counts["v3_tp"] += int((v3_detected & attack).sum())

    counts["v4_fp"] += int((v4_detected & benign).sum())
    counts["v4_tp"] += int((v4_detected & attack).sum())

    counts["pingsweep_total"] += int(ping.sum())

    counts["v3_pingsweep_detected"] += int(
        (v3_detected & ping).sum()
    )

    counts["v4_pingsweep_detected"] += int(
        (v4_detected & ping).sum()
    )

    if chunk_number % 20 == 0:
        print(f"Processed {counts['total']:,} records")

def safe_div(a, b):
    return a / b if b else 0.0

summary = {
    "test_records": counts["total"],
    "candidate_xgb_weight": weight,
    "candidate_threshold": threshold,
    "v3": {
        "fpr": safe_div(counts["v3_fp"], counts["benign"]),
        "attack_recall": safe_div(counts["v3_tp"], counts["attacks"]),
        "false_positives": counts["v3_fp"],
        "true_positives": counts["v3_tp"],
        "pingsweep_detected": counts["v3_pingsweep_detected"],
        "pingsweep_total": counts["pingsweep_total"],
    },
    "v4": {
        "fpr": safe_div(counts["v4_fp"], counts["benign"]),
        "attack_recall": safe_div(counts["v4_tp"], counts["attacks"]),
        "false_positives": counts["v4_fp"],
        "true_positives": counts["v4_tp"],
        "pingsweep_detected": counts["v4_pingsweep_detected"],
        "pingsweep_total": counts["pingsweep_total"],
    }
}

with open(
    OUT / "comparison.json", "w", encoding="utf-8"
) as f:
    json.dump(summary, f, indent=4)

print("\n===== ADDITIONAL TEST COMPARISON =====")

for name in ("v3", "v4"):
    result = summary[name]

    print(f"\n{name.upper()}")
    print(f"Benign FPR: {result['fpr']:.4%}")
    print(f"Attack recall: {result['attack_recall']:.4%}")
    print(f"False positives: {result['false_positives']}")
    print(f"True positives: {result['true_positives']}")
    print(
        "PingSweep detected:",
        f"{result['pingsweep_detected']}/"
        f"{result['pingsweep_total']}"
    )

print("\nSaved:", OUT / "comparison.json")
