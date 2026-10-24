
from pathlib import Path
import sys
import json

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "inference"))

from offline_predict import load_engine, predict_batch

VALIDATION = ROOT / "datasets/processed/splits/validation.csv"
OUT = ROOT / "results/fusion_v4_experiments"
OUT.mkdir(parents=True, exist_ok=True)

WEIGHTS = [1.0, 0.95, 0.90, 0.80, 0.70]
TARGET_FPRS = [0.01, 0.02, 0.04]

print("Loading frozen Fusion v3 components...")
engine = load_engine()

print("Running validation inference...")

all_predictions = []

for i, chunk in enumerate(
    pd.read_csv(VALIDATION, chunksize=10000), start=1
):
    result = predict_batch(engine, chunk)

    all_predictions.append(
        result[
            [
                "actual_label",
                "xgb_attack_score",
                "ae_score",
                "predicted_class"
            ]
        ].copy()
    )

    if i % 20 == 0:
        print(f"Processed {i * 10000:,} records")

predictions = pd.concat(
    all_predictions,
    ignore_index=True
)

actual_attack = (
    predictions["actual_label"].to_numpy()
    != "BenignTraffic"
)

xgb = predictions[
    "xgb_attack_score"
].to_numpy(dtype=np.float64)

ae = predictions[
    "ae_score"
].to_numpy(dtype=np.float64)

pingsweep = (
    predictions["actual_label"].to_numpy()
    == "Recon-PingSweep"
)

print("\nValidation records:", len(predictions))
print("Validation PingSweep records:", int(pingsweep.sum()))

results = []

for weight in WEIGHTS:
    scores = weight * xgb + (1 - weight) * ae

    benign_scores = scores[~actual_attack]

    for target_fpr in TARGET_FPRS:
        # Candidate thresholds derived from benign
        # validation scores only.
        threshold = float(
            np.quantile(
                benign_scores,
                1 - target_fpr
            )
        )

        detected = scores > threshold

        benign_fpr = float(
            detected[~actual_attack].mean()
        )

        attack_recall = float(
            detected[actual_attack].mean()
        )

        ping_recall = (
            float(detected[pingsweep].mean())
            if pingsweep.any()
            else None
        )

        results.append({
            "xgb_weight": weight,
            "ae_weight": 1 - weight,
            "target_fpr": target_fpr,
            "threshold": threshold,
            "actual_fpr": benign_fpr,
            "attack_recall": attack_recall,
            "pingsweep_binary_recall": ping_recall,
            "pingsweep_detected": int(
                detected[pingsweep].sum()
            ),
            "pingsweep_total": int(
                pingsweep.sum()
            )
        })

results_df = pd.DataFrame(results)

results_df.to_csv(
    OUT / "validation_comparison.csv",
    index=False
)

print("\n===== VALIDATION COMPARISON =====")

print(
    results_df[
        [
            "xgb_weight",
            "target_fpr",
            "threshold",
            "actual_fpr",
            "attack_recall",
            "pingsweep_detected",
            "pingsweep_total"
        ]
    ].to_string(index=False)
)

# Select candidate using validation only.
# Primary: meet 2% FPR target.
# Secondary: maximize attack recall.
# Tie-break: maximize PingSweep binary recall.

eligible = results_df[
    results_df["actual_fpr"] <= 0.020001
].copy()

if eligible.empty:
    raise RuntimeError(
        "No candidate met the 2% FPR requirement."
    )

eligible = eligible.sort_values(
    by=[
        "attack_recall",
        "pingsweep_binary_recall",
        "xgb_weight"
    ],
    ascending=[False, False, False]
)

best = eligible.iloc[0].to_dict()

with open(
    OUT / "selected_candidate.json",
    "w",
    encoding="utf-8"
) as f:
    json.dump(best, f, indent=4)

print("\n===== SELECTED VALIDATION CANDIDATE =====")

print(
    json.dumps(best, indent=4)
)

print("\nSaved results to:", OUT)
