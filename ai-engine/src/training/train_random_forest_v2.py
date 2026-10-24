
from pathlib import Path
import json
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    classification_report,
    confusion_matrix
)

SEED = 42
TRAIN_FILE = Path("datasets/processed/splits/train.csv")
VALIDATION_FILE = Path("datasets/processed/splits/validation.csv")

MODEL_DIR = Path("models")
RESULT_DIR = Path("results/random_forest_v2")
MODEL_DIR.mkdir(exist_ok=True)
RESULT_DIR.mkdir(parents=True, exist_ok=True)

# Cap large classes but retain all records from
# classes with fewer than 15,000 examples.
MAX_PER_CLASS = 15_000
CHUNK_SIZE = 100_000

rng = np.random.default_rng(SEED)
samples = {}

print("Loading training data in chunks...")

# Keep a bounded, randomized sample per class.
# This is training-only undersampling.
for chunk in pd.read_csv(TRAIN_FILE, chunksize=CHUNK_SIZE):
    for label, group in chunk.groupby("label"):
        existing = samples.get(label)

        if existing is None:
            combined = group
        else:
            combined = pd.concat(
                [existing, group],
                ignore_index=True
            )

        if len(combined) > MAX_PER_CLASS:
            indices = rng.choice(
                len(combined),
                size=MAX_PER_CLASS,
                replace=False
            )
            combined = combined.iloc[indices].reset_index(
                drop=True
            )

        samples[label] = combined

train_df = pd.concat(
    samples.values(),
    ignore_index=True
)

train_df = train_df.sample(
    frac=1,
    random_state=SEED
).reset_index(drop=True)

print("Training records:", len(train_df))
print("Training classes:", train_df["label"].nunique())

features = [
    col for col in train_df.columns
    if col != "label"
]

X_train = train_df[features].astype("float32")
y_train = train_df["label"]

print("Training Random Forest v2...")

model = RandomForestClassifier(
    n_estimators=150,
    max_depth=None,
    min_samples_leaf=1,
    class_weight="balanced_subsample",
    random_state=SEED,
    n_jobs=-1
)

start = time.perf_counter()
model.fit(X_train, y_train)
training_seconds = time.perf_counter() - start

print(f"Training completed in {training_seconds:.2f} seconds")

model_path = MODEL_DIR / "random_forest_v2.joblib"
joblib.dump(
    {
        "model": model,
        "features": features,
        "version": "v2"
    },
    model_path,
    compress=3
)

print("Saved model:", model_path)

# Validation is used for development feedback.
# The test set remains untouched.
print("Evaluating on validation dataset...")

actual = []
predicted = []

for chunk in pd.read_csv(
    VALIDATION_FILE,
    chunksize=CHUNK_SIZE
):
    X = chunk[features].astype("float32")
    predictions = model.predict(X)

    actual.extend(chunk["label"].tolist())
    predicted.extend(predictions.tolist())

accuracy = accuracy_score(actual, predicted)
macro_f1 = f1_score(
    actual,
    predicted,
    average="macro",
    zero_division=0
)
weighted_f1 = f1_score(
    actual,
    predicted,
    average="weighted",
    zero_division=0
)

report = classification_report(
    actual,
    predicted,
    output_dict=True,
    zero_division=0
)

pd.DataFrame(report).transpose().to_csv(
    RESULT_DIR / "classification_report.csv"
)

labels = sorted(set(actual) | set(predicted))
cm = confusion_matrix(actual, predicted, labels=labels)

pd.DataFrame(
    cm,
    index=labels,
    columns=labels
).to_csv(RESULT_DIR / "confusion_matrix.csv")

importance = pd.DataFrame({
    "feature": features,
    "importance": model.feature_importances_
}).sort_values("importance", ascending=False)

importance.to_csv(
    RESULT_DIR / "feature_importance.csv",
    index=False
)

metrics = {
    "model": "Random Forest v2",
    "dataset": "CICIoT2023 cleaned",
    "training_records": len(train_df),
    "validation_records": len(actual),
    "feature_count": len(features),
    "class_count": len(labels),
    "max_training_samples_per_class": MAX_PER_CLASS,
    "training_seconds": training_seconds,
    "validation_accuracy": accuracy,
    "validation_macro_f1": macro_f1,
    "validation_weighted_f1": weighted_f1
}

with open(
    RESULT_DIR / "metrics.json",
    "w",
    encoding="utf-8"
) as f:
    json.dump(metrics, f, indent=4)

print("\n===== RANDOM FOREST V2 RESULTS =====")
print(f"Training samples: {len(train_df):,}")
print(f"Validation samples: {len(actual):,}")
print(f"Accuracy: {accuracy:.4f}")
print(f"Macro F1: {macro_f1:.4f}")
print(f"Weighted F1: {weighted_f1:.4f}")
print(f"Training time: {training_seconds:.2f} seconds")
print("Results saved to:", RESULT_DIR)
