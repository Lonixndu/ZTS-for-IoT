
from pathlib import Path
import time

import joblib
import numpy as np
import pandas as pd

VALIDATION_FILE = Path(
    "datasets/processed/splits/validation.csv"
)

OUTPUT_FILE = Path(
    "results/fusion_v1/validation_probabilities.npz"
)

CHUNK_SIZE = 10_000

print("Loading Random Forest...")
rf_package = joblib.load(
    "models/random_forest_v2.joblib"
)

rf = rf_package["model"]
rf_features = list(rf_package["features"])

print("Loading XGBoost...")
xgb_package = joblib.load(
    "models/xgboost_v1.joblib"
)

xgb = xgb_package["model"]
xgb_features = list(xgb_package["features"])
encoder = xgb_package["encoder"]

if rf_features != xgb_features:
    raise ValueError("Model feature orders do not match")

rf_classes = list(rf.classes_)
xgb_classes = list(encoder.classes_)

rf_benign_index = rf_classes.index("BenignTraffic")
xgb_benign_index = xgb_classes.index("BenignTraffic")

rf_scores = []
xgb_scores = []
actual_labels = []

start = time.perf_counter()

print("\nGenerating attack probability scores...")

for number, chunk in enumerate(
    pd.read_csv(
        VALIDATION_FILE,
        chunksize=CHUNK_SIZE
    ),
    start=1
):
    X = chunk[rf_features]

    rf_probabilities = rf.predict_proba(X)
    xgb_probabilities = xgb.predict_proba(X)

    rf_attack_score = (
        1.0 - rf_probabilities[:, rf_benign_index]
    )

    xgb_attack_score = (
        1.0 - xgb_probabilities[:, xgb_benign_index]
    )

    actual = (
        chunk["label"] != "BenignTraffic"
    ).to_numpy(dtype=np.uint8)

    rf_scores.append(
        rf_attack_score.astype(np.float32)
    )

    xgb_scores.append(
        xgb_attack_score.astype(np.float32)
    )

    actual_labels.append(actual)

    print(
        f"Chunk {number}: {len(chunk):,} records"
    )

rf_scores = np.concatenate(rf_scores)
xgb_scores = np.concatenate(xgb_scores)
actual = np.concatenate(actual_labels)

previous = np.load(
    "results/fusion_v1/validation_predictions.npz"
)

if not np.array_equal(actual, previous["actual"]):
    raise ValueError(
        "Validation row alignment mismatch!"
    )

np.savez_compressed(
    OUTPUT_FILE,
    actual=actual,
    rf_attack_score=rf_scores,
    xgb_attack_score=xgb_scores
)

print("\n===== COMPLETED =====")
print("Records:", len(actual))
print("RF score range:", rf_scores.min(), rf_scores.max())
print("XGB score range:", xgb_scores.min(), xgb_scores.max())
print(
    "Elapsed seconds:",
    round(time.perf_counter() - start, 2)
)
print("Saved:", OUTPUT_FILE)
