
from pathlib import Path
import sys
import time

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    classification_report
)

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "inference"))

from offline_predict import load_engine, predict_batch

SOURCE = ROOT / "datasets/processed/splits/test.csv"
OUT = ROOT / "results/offline_demo/balanced"
OUT.mkdir(parents=True, exist_ok=True)

SEED = 42
SAMPLES_PER_GROUP = 100

print("Selecting reproducible evaluation samples...")

# Reservoir sampling avoids loading the entire test CSV
# into memory and avoids always taking the first rows.
rng = np.random.default_rng(SEED)
reservoirs = {"benign": [], "attack": []}
seen = {"benign": 0, "attack": 0}

for chunk in pd.read_csv(SOURCE, chunksize=50000):
    for row in chunk.itertuples(index=False, name=None):
        label = row[-1]
        group = "benign" if label == "BenignTraffic" else "attack"
        seen[group] += 1

        pool = reservoirs[group]

        if len(pool) < SAMPLES_PER_GROUP:
            pool.append(row)
        else:
            j = rng.integers(0, seen[group])
            if j < SAMPLES_PER_GROUP:
                pool[j] = row

columns = pd.read_csv(SOURCE, nrows=0).columns.tolist()

frames = []
for group in ("benign", "attack"):
    frames.append(pd.DataFrame(reservoirs[group], columns=columns))

sample = pd.concat(frames, ignore_index=True)
sample = sample.sample(frac=1, random_state=SEED).reset_index(drop=True)

sample.to_csv(OUT / "sample.csv", index=False)

print("Selected:", len(sample), "records")
print(sample["label"].eq("BenignTraffic").value_counts())

print("\nLoading frozen Fusion v3...")
engine = load_engine()

# Warm up
predict_batch(engine, sample.iloc[:1])

start = time.perf_counter()
predictions = predict_batch(engine, sample)
elapsed = time.perf_counter() - start

predictions.to_csv(OUT / "predictions.csv", index=False)

actual_binary = (
    predictions["actual_label"] != "BenignTraffic"
).astype(int)

predicted_binary = (
    predictions["detected_attack"]
).astype(int)

tn, fp, fn, tp = confusion_matrix(
    actual_binary,
    predicted_binary,
    labels=[0, 1]
).ravel()

print("\n===== BALANCED EVALUATION =====")
print("True positives:", tp)
print("True negatives:", tn)
print("False positives:", fp)
print("False negatives:", fn)

print("Attack recall:", tp / (tp + fn))
print("Benign FPR:", fp / (fp + tn))
print(
    "Binary accuracy:",
    accuracy_score(actual_binary, predicted_binary)
)

print(
    "Multiclass accuracy:",
    accuracy_score(
        predictions["actual_label"],
        predictions["predicted_class"]
    )
)

print("\nClassification report:")
print(
    classification_report(
        actual_binary,
        predicted_binary,
        target_names=["Benign", "Attack"],
        zero_division=0
    )
)

print(f"\nBatch inference time: {elapsed:.6f} s")
print("Saved results:", OUT)
