
from pathlib import Path
import sys
import json
import time

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "inference"))

from offline_predict import load_engine, predict_batch

DATASET = ROOT / "datasets/processed/splits/test.csv"
OUT = ROOT / "results/fusion_v3_detailed"

OUT.mkdir(parents=True, exist_ok=True)

CHUNK_SIZE = 10000

print("\nLoading frozen Fusion v3...")
engine = load_engine()

print("Reading test records in batches...")

all_results = []
total_inference_time = 0
total_records = 0

# Warm up both models
first = pd.read_csv(DATASET, nrows=1)
predict_batch(engine, first)

for chunk_number, chunk in enumerate(
    pd.read_csv(DATASET, chunksize=CHUNK_SIZE),
    start=1
):
    start = time.perf_counter()

    result = predict_batch(engine, chunk)

    total_inference_time += (
        time.perf_counter() - start
    )

    all_results.append(result)
    total_records += len(result)

    if chunk_number % 10 == 0:
        print(f"Processed {total_records:,} records")

results = pd.concat(
    all_results,
    ignore_index=True
)

print("\nCalculating evaluation metrics...")

actual = results["actual_label"].to_numpy()
predicted = results["predicted_class"].to_numpy()

actual_binary = (
    actual != "BenignTraffic"
).astype(int)

predicted_binary = (
    results["detected_attack"]
    .to_numpy()
    .astype(int)
)

tn, fp, fn, tp = confusion_matrix(
    actual_binary,
    predicted_binary,
    labels=[0, 1]
).ravel()

binary_accuracy = accuracy_score(
    actual_binary,
    predicted_binary
)

multiclass_accuracy = accuracy_score(
    actual,
    predicted
)

attack_recall = tp / (tp + fn)
benign_fpr = fp / (fp + tn)

report = classification_report(
    actual,
    predicted,
    output_dict=True,
    zero_division=0
)

per_class = pd.DataFrame(report).T
per_class.to_csv(
    OUT / "per_class_metrics.csv"
)

classes = sorted(
    set(actual) | set(predicted)
)

matrix = confusion_matrix(
    actual,
    predicted,
    labels=classes
)

pd.DataFrame(
    matrix,
    index=classes,
    columns=classes
).to_csv(
    OUT / "multiclass_confusion_matrix.csv"
)

# Save errors separately for investigation
errors = results[
    ~results["correct_class"]
].copy()

errors.to_csv(
    OUT / "misclassified_records.csv",
    index=False
)

metrics = {
    "model": "Fusion v3 frozen",
    "dataset": str(DATASET),
    "evaluation_type": "retrospective_existing_test_partition",
    "records": int(total_records),
    "binary_accuracy": float(binary_accuracy),
    "multiclass_accuracy": float(multiclass_accuracy),
    "attack_recall": float(attack_recall),
    "benign_fpr": float(benign_fpr),
    "true_positive": int(tp),
    "true_negative": int(tn),
    "false_positive": int(fp),
    "false_negative": int(fn),
    "inference_seconds": float(total_inference_time),
    "throughput_records_per_second": float(
        total_records / total_inference_time
    ),
    "note": (
        "This test partition was previously evaluated. "
        "Results are not a new independent generalization test."
    )
}

with open(
    OUT / "metrics.json",
    "w",
    encoding="utf-8"
) as file:
    json.dump(metrics, file, indent=4)

print("\n===== FUSION V3 FULL TEST EVALUATION =====")
print("Records:", f"{total_records:,}")
print(f"Multiclass accuracy: {multiclass_accuracy:.6%}")
print(f"Binary accuracy: {binary_accuracy:.6%}")
print(f"Attack recall: {attack_recall:.6%}")
print(f"Benign FPR: {benign_fpr:.6%}")

print("\nConfusion matrix:")
print("TP:", tp)
print("TN:", tn)
print("FP:", fp)
print("FN:", fn)

print("\n===== PERFORMANCE =====")
print(
    f"Inference time: {total_inference_time:.3f} seconds"
)
print(
    f"Throughput: "
    f"{total_records / total_inference_time:,.0f} "
    "records/second"
)

print("\n===== LOWEST F1 ATTACK CLASSES =====")

attack_classes = per_class[
    per_class.index.isin(classes)
].drop(index="BenignTraffic", errors="ignore")

print(
    attack_classes.sort_values("f1-score")
    .head(10)[
        ["precision", "recall", "f1-score", "support"]
    ].to_string()
)

print("\nResults saved to:", OUT)
