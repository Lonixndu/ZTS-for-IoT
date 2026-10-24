
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

DATASET = ROOT / "results/original_test/nonoverlap_test.csv"
OUT = ROOT / "results/original_test/evaluation"
OUT.mkdir(parents=True, exist_ok=True)

CHUNK_SIZE = 10000

print("Loading frozen Fusion v3...")
engine = load_engine()

print("Warming up inference engine...")
first = pd.read_csv(DATASET, nrows=1)
predict_batch(engine, first)

actual_labels = []
predicted_labels = []
binary_decisions = []

total_records = 0
inference_seconds = 0.0

print("\nEvaluating filtered original test dataset...")

for chunk in pd.read_csv(DATASET, chunksize=CHUNK_SIZE):
    start = time.perf_counter()
    result = predict_batch(engine, chunk)
    inference_seconds += time.perf_counter() - start

    actual_labels.extend(result["actual_label"].tolist())
    predicted_labels.extend(result["predicted_class"].tolist())
    binary_decisions.extend(result["detected_attack"].tolist())

    total_records += len(result)

    if total_records % 100000 < CHUNK_SIZE:
        print(f"Processed {total_records:,} records")

actual = np.asarray(actual_labels)
predicted = np.asarray(predicted_labels)
decisions = np.asarray(binary_decisions, dtype=bool)

actual_binary = actual != "BenignTraffic"

tn, fp, fn, tp = confusion_matrix(
    actual_binary,
    decisions,
    labels=[False, True]
).ravel()

binary_accuracy = accuracy_score(actual_binary, decisions)
multiclass_accuracy = accuracy_score(actual, predicted)

attack_recall = tp / (tp + fn)
benign_fpr = fp / (fp + tn)

report = classification_report(
    actual,
    predicted,
    output_dict=True,
    zero_division=0
)

per_class = pd.DataFrame(report).T
per_class.to_csv(OUT / "per_class_metrics.csv")

classes = sorted(set(actual) | set(predicted))
matrix = confusion_matrix(actual, predicted, labels=classes)

pd.DataFrame(
    matrix,
    index=classes,
    columns=classes
).to_csv(OUT / "confusion_matrix.csv")

metrics = {
    "evaluation": "filtered_original_ciciot2023_test",
    "records": int(total_records),
    "multiclass_accuracy": float(multiclass_accuracy),
    "binary_accuracy": float(binary_accuracy),
    "attack_recall": float(attack_recall),
    "benign_fpr": float(benign_fpr),
    "tp": int(tp),
    "tn": int(tn),
    "fp": int(fp),
    "fn": int(fn),
    "inference_seconds": inference_seconds,
    "throughput": total_records / inference_seconds,
    "note": (
        "Exact matching 44-feature-plus-label rows removed. "
        "Dataset remains part of CICIoT2023 collection."
    )
}

with open(OUT / "metrics.json", "w", encoding="utf-8") as f:
    json.dump(metrics, f, indent=4)

print("\n===== ADDITIONAL TEST EVALUATION =====")
print(f"Records: {total_records:,}")
print(f"Multiclass accuracy: {multiclass_accuracy:.6%}")
print(f"Binary accuracy: {binary_accuracy:.6%}")
print(f"Attack recall: {attack_recall:.6%}")
print(f"Benign FPR: {benign_fpr:.6%}")

print("\nConfusion matrix:")
print(f"TP: {tp:,}")
print(f"TN: {tn:,}")
print(f"FP: {fp:,}")
print(f"FN: {fn:,}")

print("\n===== PERFORMANCE =====")
print(f"Inference time: {inference_seconds:.3f} s")
print(f"Throughput: {total_records/inference_seconds:,.0f} records/s")

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

print("\n===== PINGSWEEP PERFORMANCE =====")

if "Recon-PingSweep" in per_class.index:
    print(per_class.loc[
        "Recon-PingSweep",
        ["precision", "recall", "f1-score", "support"]
    ])

print("\nResults saved to:", OUT)
