
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

BASE = Path("results/fusion_v1")
OUT = Path("results/fusion_v2")
OUT.mkdir(parents=True, exist_ok=True)

pred = np.load(BASE / "validation_predictions.npz")
prob = np.load(BASE / "validation_probabilities.npz")

y = pred["actual"].astype(bool)

if not np.array_equal(
    pred["actual"], prob["actual"]
):
    raise ValueError("Validation alignment mismatch")

xgb = prob["xgb_attack_score"].astype(np.float64)
rf = prob["rf_attack_score"].astype(np.float64)
ae_error = pred["ae_errors"].astype(np.float64)

# Reuse the exact normalization scale from Fusion v2.
import json

metadata = json.loads(
    (OUT / "experiment_metadata.json").read_text(
        encoding="utf-8"
    )
)

ae_scale = float(metadata["ae_scale"])
ae = np.clip(ae_error / ae_scale, 0, 1)

scores = {
    "XGBoost only": xgb,
    "RF only": rf,
    "XGBoost 90% + AE 10%": 0.9*xgb + 0.1*ae,
    "XGBoost 80% + AE 20%": 0.8*xgb + 0.2*ae,
    "XGBoost 70% + AE 30%": 0.7*xgb + 0.3*ae,
}

# Use benign records to choose the threshold at each
# target FPR, then evaluate attacks at that threshold.
# This is validation-stage selection, not test evaluation.
TARGET_FPRS = [0.01, 0.02, 0.03, 0.04, 0.05]

results = []

for model_name, score in scores.items():
    benign_scores = score[~y]
    attack_scores = score[y]

    auc = roc_auc_score(y, score)

    for target in TARGET_FPRS:
        # Threshold selected using benign validation scores.
        # Exact observed FPR can differ slightly due to ties.
        threshold = float(
            np.quantile(benign_scores, 1 - target)
        )

        benign_fp = int(
            np.sum(benign_scores > threshold)
        )
        attack_tp = int(
            np.sum(attack_scores > threshold)
        )

        actual_fpr = benign_fp / len(benign_scores)
        attack_recall = attack_tp / len(attack_scores)

        results.append({
            "model": model_name,
            "target_fpr": target,
            "actual_fpr": actual_fpr,
            "attack_recall": attack_recall,
            "threshold": threshold,
            "false_alarms": benign_fp,
            "missed_attacks": (
                len(attack_scores) - attack_tp
            ),
            "roc_auc": auc
        })

df = pd.DataFrame(results)

df.to_csv(
    OUT / "matched_fpr_comparison.csv",
    index=False
)

print("\n===== MATCHED-FPR COMPARISON =====")

for target in TARGET_FPRS:
    print(f"\nTARGET FPR: {target:.0%}")

    subset = df[
        df["target_fpr"] == target
    ].sort_values(
        "attack_recall",
        ascending=False
    )

    print(
        subset[
            [
                "model",
                "actual_fpr",
                "attack_recall",
                "false_alarms",
                "missed_attacks"
            ]
        ].to_string(index=False)
    )

print("\nSaved:", OUT / "matched_fpr_comparison.csv")
