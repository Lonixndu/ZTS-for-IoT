
from pathlib import Path
import sys
import json

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "inference"))

from offline_predict import load_engine, predict_batch

SOURCE = ROOT / "results/original_test/nonoverlap_test.csv"
OUT = ROOT / "results/pingsweep_analysis"
OUT.mkdir(parents=True, exist_ok=True)

TARGET = "Recon-PingSweep"

print("Loading PingSweep records...")

parts = []

for chunk in pd.read_csv(SOURCE, chunksize=50000):
    matches = chunk[chunk["label"] == TARGET]
    if not matches.empty:
        parts.append(matches.copy())

if not parts:
    raise SystemExit("No PingSweep records found.")

data = pd.concat(parts, ignore_index=True)

print(f"Records found: {len(data)}")

print("\nLoading frozen Fusion v3...")
engine = load_engine()

predictions = predict_batch(engine, data)

correct_class = predictions["predicted_class"] == TARGET
detected = predictions["detected_attack"].astype(bool)

total = len(predictions)

correct_class_count = int(correct_class.sum())
detected_count = int(detected.sum())
missed_count = int((~detected).sum())

wrong_class_but_detected = int(
    ((~correct_class) & detected).sum()
)

wrong_class_and_missed = int(
    ((~correct_class) & (~detected)).sum()
)

print("\n===== PINGSWEEP DETECTION ANALYSIS =====")
print("Total PingSweep records:", total)

print("\nMulticlass classification:")
print("Correctly classified:", correct_class_count)
print("Incorrectly classified:", total - correct_class_count)
print(
    "PingSweep class recall:",
    f"{correct_class_count / total:.2%}"
)

print("\nBinary attack detection:")
print("Detected as malicious:", detected_count)
print("Missed as benign:", missed_count)
print(
    "PingSweep binary recall:",
    f"{detected_count / total:.2%}"
)

print("\nMisclassification breakdown:")
print("Wrong class but attack detected:", wrong_class_but_detected)
print("Wrong class and attack missed:", wrong_class_and_missed)

print("\n===== PREDICTED CLASS DISTRIBUTION =====")
print(
    predictions["predicted_class"]
    .value_counts()
    .to_string()
)

print("\n===== BEHAVIOR RISK STATISTICS =====")
print(
    predictions["behavior_risk"]
    .describe()
    .to_string()
)

print("\n===== MISSED PINGSWEEP EXAMPLES =====")
missed = predictions[~detected]

if not missed.empty:
    print(
        missed[
            [
                "predicted_class",
                "confidence",
                "xgb_attack_score",
                "ae_score",
                "behavior_risk"
            ]
        ].head(10).to_string(index=False)
    )

predictions.to_csv(
    OUT / "pingsweep_predictions.csv",
    index=False
)

summary = {
    "total": total,
    "correct_class": correct_class_count,
    "incorrect_class": total - correct_class_count,
    "binary_detected": detected_count,
    "binary_missed": missed_count,
    "multiclass_recall": correct_class_count / total,
    "binary_recall": detected_count / total,
    "wrong_class_but_detected": wrong_class_but_detected,
    "wrong_class_and_missed": wrong_class_and_missed
}

with open(
    OUT / "summary.json",
    "w",
    encoding="utf-8"
) as f:
    json.dump(summary, f, indent=4)

print("\nResults saved to:", OUT)
