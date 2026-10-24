
from pathlib import Path
import json

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

BASE = Path("results/fusion_v1")
OUT = Path("results/fusion_v2")
OUT.mkdir(parents=True, exist_ok=True)

# Load aligned validation outputs
pred = np.load(BASE / "validation_predictions.npz")
prob = np.load(BASE / "validation_probabilities.npz")

y = pred["actual"].astype(bool)
ae_error = pred["ae_errors"].astype(np.float64)

rf_score = prob["rf_attack_score"].astype(np.float64)
xgb_score = prob["xgb_attack_score"].astype(np.float64)

if not np.array_equal(y, prob["actual"].astype(bool)):
    raise ValueError("Validation arrays are misaligned")

if not (
    len(y) == len(ae_error) == len(rf_score) == len(xgb_score)
):
    raise ValueError("Array lengths do not match")

if not all(np.isfinite(a).all() for a in
           [ae_error, rf_score, xgb_score]):
    raise ValueError("Non-finite scores detected")

# Normalize AE error with a monotonic transformation.
# This maps scores to [0,1], but NOT to probabilities.
# The scale is chosen from benign validation records.
benign_errors = ae_error[~y]
scale = float(np.quantile(benign_errors, 0.99))

if scale <= 0:
    raise ValueError("Invalid anomaly normalization scale")

ae_score = np.clip(ae_error / scale, 0.0, 1.0)

def metrics(score, threshold):
    prediction = score >= threshold

    tp = int(np.sum(y & prediction))
    tn = int(np.sum(~y & ~prediction))
    fp = int(np.sum(~y & prediction))
    fn = int(np.sum(y & ~prediction))

    return {
        "attack_recall": tp / (tp + fn),
        "benign_fpr": fp / (fp + tn),
        "precision": tp / (tp + fp) if tp + fp else 0,
        "f1": (
            2 * tp / (2 * tp + fp + fn)
            if 2 * tp + fp + fn else 0
        ),
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn
    }

# Candidate operating points
WEIGHTS = np.arange(0, 1.01, 0.1)
THRESHOLDS = np.arange(0.1, 1.0, 0.05)

results = []

for model_name, supervised_score in [
    ("RF", rf_score),
    ("XGBoost", xgb_score)
]:
    for weight in WEIGHTS:
        fused = (
            weight * supervised_score
            + (1.0 - weight) * ae_score
        )

        auc = roc_auc_score(y, fused)

        for threshold in THRESHOLDS:
            row = metrics(fused, threshold)
            row.update({
                "model": model_name,
                "supervised_weight": round(float(weight), 2),
                "ae_weight": round(float(1 - weight), 2),
                "threshold": round(float(threshold), 3),
                "roc_auc": float(auc)
            })
            results.append(row)

comparison = pd.DataFrame(results)

comparison.to_csv(
    OUT / "all_fusion_results.csv",
    index=False
)

# Illustrative research objective:
# Maximize attack recall while keeping benign FPR <= 5%.
# This target is provisional, not a deployment requirement.
eligible = comparison[
    comparison["benign_fpr"] <= 0.05
].copy()

if len(eligible):
    best = eligible.sort_values(
        ["attack_recall", "benign_fpr"],
        ascending=[False, True]
    ).iloc[0]

    print("\nBEST FUSION WITH FPR <= 5%")
else:
    # If none meet the constraint, show lowest-FPR candidate.
    best = comparison.sort_values(
        ["benign_fpr", "attack_recall"],
        ascending=[True, False]
    ).iloc[0]

    print("\nNO CANDIDATE MET THE 5% FPR TARGET")
    print("Showing lowest-FPR candidate instead")

print(best.to_string())

# Also save the top candidates for each supervised model.
if len(eligible):
    top = (
        eligible.sort_values(
            ["attack_recall", "benign_fpr"],
            ascending=[False, True]
        )
        .groupby("model", group_keys=False)
        .head(5)
    )
else:
    top = comparison.sort_values(
        ["benign_fpr", "attack_recall"],
        ascending=[True, False]
    ).groupby("model", group_keys=False).head(5)

top.to_csv(
    OUT / "top_candidates.csv",
    index=False
)

metadata = {
    "validation_records": len(y),
    "ae_normalization": "clip(error / scale, 0, 1)",
    "ae_scale": scale,
    "fpr_constraint": 0.05,
    "note": (
        "Validation-only model selection. "
        "Scores are not calibrated probabilities. "
        "Test partition remains untouched."
    )
}

(OUT / "experiment_metadata.json").write_text(
    json.dumps(metadata, indent=4),
    encoding="utf-8"
)

print("\nTOP CANDIDATES")
print(
    top[
        [
            "model",
            "supervised_weight",
            "ae_weight",
            "threshold",
            "attack_recall",
            "benign_fpr",
            "FP",
            "FN"
        ]
    ].to_string(index=False)
)

print("\nSaved results to:", OUT)
