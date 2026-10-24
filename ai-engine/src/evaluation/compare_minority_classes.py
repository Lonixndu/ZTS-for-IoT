
from pathlib import Path
import gc

import joblib
import numpy as np
import pandas as pd

from sklearn.metrics import (
    classification_report,
    f1_score,
    accuracy_score
)

VALIDATION_FILE = Path(
    "datasets/processed/splits/validation.csv"
)

OUTPUT_DIR = Path(
    "results/minority_class_analysis"
)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

CHUNK_SIZE = 10000

MODELS = {
    "XGBoost_v1": "models/xgboost_v1.joblib",
    "XGBoost_v3_44": (
        "models/xgboost_v3_b60000_reduced.joblib"
    ),
    "XGBoost_v4_42": (
        "models/xgboost_v4_remove_number_weight.joblib"
    )
}

MINORITY_CLASSES = [
    "Uploading_Attack",
    "Recon-PingSweep",
    "Backdoor_Malware",
    "XSS",
    "SqlInjection",
    "CommandInjection",
    "BrowserHijacking"
]

all_results = []
overall_results = []

for model_name, model_path in MODELS.items():

    print("\n" + "=" * 55)
    print("Evaluating:", model_name)

    package = joblib.load(model_path)

    model = package["model"]
    encoder = package["encoder"]
    features = list(package["features"])

    actual = []
    predicted = []

    for chunk in pd.read_csv(
        VALIDATION_FILE,
        chunksize=CHUNK_SIZE
    ):
        X = chunk[features].astype(np.float32)

        pred_ids = model.predict(X).astype(int)

        pred_labels = encoder.inverse_transform(
            pred_ids
        )

        actual.extend(chunk["label"].tolist())
        predicted.extend(pred_labels.tolist())

    report = classification_report(
        actual,
        predicted,
        output_dict=True,
        zero_division=0
    )

    for attack_class in MINORITY_CLASSES:

        if attack_class not in report:
            print(
                "WARNING: Class missing:",
                attack_class
            )
            continue

        metrics = report[attack_class]

        all_results.append({
            "model": model_name,
            "attack_class": attack_class,
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1": metrics["f1-score"],
            "support": int(metrics["support"])
        })

    macro_f1 = f1_score(
        actual,
        predicted,
        average="macro",
        zero_division=0
    )

    accuracy = accuracy_score(
        actual,
        predicted
    )

    overall_results.append({
        "model": model_name,
        "accuracy": accuracy,
        "macro_f1": macro_f1
    })

    print("Accuracy:", round(accuracy, 6))
    print("Macro F1:", round(macro_f1, 6))

    del model, package, actual, predicted
    gc.collect()

# ==========================================
# Save detailed results
# ==========================================

details = pd.DataFrame(all_results)

details.to_csv(
    OUTPUT_DIR / "minority_class_comparison.csv",
    index=False
)

overall = pd.DataFrame(overall_results)

overall.to_csv(
    OUTPUT_DIR / "overall_comparison.csv",
    index=False
)

# ==========================================
# Display minority-class F1 comparison
# ==========================================

pivot = details.pivot(
    index="attack_class",
    columns="model",
    values="f1"
)

print("\n===== MINORITY-CLASS F1 COMPARISON =====")
print(pivot.round(4).to_string())

print("\n===== OVERALL COMPARISON =====")
print(overall.round(6).to_string(index=False))

# ==========================================
# Identify best model per class
# ==========================================

winners = (
    details.loc[
        details.groupby("attack_class")["f1"].idxmax()
    ][
        ["attack_class", "model", "f1"]
    ]
)

print("\n===== BEST MODEL PER MINORITY CLASS =====")
print(winners.to_string(index=False))

print("\nResults saved to:", OUTPUT_DIR)
