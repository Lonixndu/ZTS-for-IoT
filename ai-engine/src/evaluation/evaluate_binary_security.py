
from pathlib import Path
import json

import pandas as pd

MODELS = {
    "Random Forest v2": Path(
        "results/random_forest_v2/confusion_matrix.csv"
    ),
    "XGBoost v1": Path(
        "results/xgboost_v1/confusion_matrix.csv"
    )
}

BENIGN = "BenignTraffic"
results = {}

for name, path in MODELS.items():
    cm = pd.read_csv(path, index_col=0)

    if BENIGN not in cm.index or BENIGN not in cm.columns:
        raise ValueError(f"Missing benign class: {name}")

    # Rows = actual labels; columns = predicted labels.
    tn = int(cm.loc[BENIGN, BENIGN])

    fp = int(cm.loc[BENIGN].sum() - tn)

    fn = int(cm[BENIGN].sum() - tn)

    tp = int(cm.to_numpy().sum() - tn - fp - fn)

    fpr = fp / (fp + tn)
    tpr = tp / (tp + fn)
    precision = tp / (tp + fp)

    results[name] = {
        "true_positive": tp,
        "true_negative": tn,
        "false_positive": fp,
        "false_negative": fn,
        "attack_detection_rate": tpr,
        "benign_false_positive_rate": fpr,
        "binary_precision": precision
    }

    print(f"\n{name}")
    print(f"Attack detection rate: {tpr * 100:.4f}%")
    print(f"Benign false-positive rate: {fpr * 100:.4f}%")
    print(f"Missed attack records: {fn:,}")
    print(f"False alarms: {fp:,}")
    print(f"Binary precision: {precision * 100:.4f}%")

out = Path("results/security_comparison")
out.mkdir(parents=True, exist_ok=True)

with open(
    out / "binary_security_metrics.json",
    "w",
    encoding="utf-8"
) as file:
    json.dump(results, file, indent=4)

print("\nResults saved successfully.")
