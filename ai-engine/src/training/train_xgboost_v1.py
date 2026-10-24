
from pathlib import Path
import json
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    classification_report,
    confusion_matrix
)
from xgboost import XGBClassifier

SEED = 42
CHUNK_SIZE = 100_000
MAX_PER_CLASS = 15_000

TRAIN_FILE = Path("datasets/processed/splits/train.csv")
VALIDATION_FILE = Path("datasets/processed/splits/validation.csv")

MODEL_DIR = Path("models")
RESULT_DIR = Path("results/xgboost_v1")

MODEL_DIR.mkdir(exist_ok=True)
RESULT_DIR.mkdir(parents=True, exist_ok=True)

rng = np.random.default_rng(SEED)
samples = {}

print("Loading training data in chunks...")

# Same sampling algorithm and parameters as RF v2.
for chunk in pd.read_csv(
    TRAIN_FILE,
    chunksize=CHUNK_SIZE
):
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

features = [
    col for col in train_df.columns
    if col != "label"
]

X_train = train_df[features].astype("float32")

encoder = LabelEncoder()
y_train = encoder.fit_transform(train_df["label"])

print("Training records:", len(train_df))
print("Features:", len(features))
print("Classes:", len(encoder.classes_))

# Compute class weights from the sampled training data.
class_counts = np.bincount(y_train)
class_weights = len(y_train) / (
    len(class_counts) * class_counts
)

# Limit extreme weights to avoid unstable training.
class_weights = np.clip(class_weights, 0.2, 20.0)
sample_weights = class_weights[y_train]

model = XGBClassifier(
    objective="multi:softprob",
    num_class=len(encoder.classes_),
    n_estimators=250,
    max_depth=6,
    learning_rate=0.08,
    subsample=0.85,
    colsample_bytree=0.85,
    tree_method="hist",
    eval_metric="mlogloss",
    random_state=SEED,
    n_jobs=4
)

print("Training XGBoost v1...")

start = time.perf_counter()

model.fit(
    X_train,
    y_train,
    sample_weight=sample_weights,
    verbose=False
)

training_seconds = time.perf_counter() - start

print(
    f"Training completed in {training_seconds:.2f} seconds"
)

model_path = MODEL_DIR / "xgboost_v1.joblib"

joblib.dump(
    {
        "model": model,
        "encoder": encoder,
        "features": features,
        "version": "v1"
    },
    model_path,
    compress=3
)

print("Saved model:", model_path)

print("Evaluating on validation dataset...")

actual = []
predicted = []

for chunk in pd.read_csv(
    VALIDATION_FILE,
    chunksize=CHUNK_SIZE
):
    X = chunk[features].astype("float32")

    pred_ids = model.predict(X)
    pred_labels = encoder.inverse_transform(
        pred_ids.astype(int)
    )

    actual.extend(chunk["label"].tolist())
    predicted.extend(pred_labels.tolist())

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

cm = confusion_matrix(
    actual,
    predicted,
    labels=labels
)

pd.DataFrame(
    cm,
    index=labels,
    columns=labels
).to_csv(
    RESULT_DIR / "confusion_matrix.csv"
)

importance = pd.DataFrame({
    "feature": features,
    "importance": model.feature_importances_
}).sort_values(
    "importance",
    ascending=False
)

importance.to_csv(
    RESULT_DIR / "feature_importance.csv",
    index=False
)

metrics = {
    "model": "XGBoost v1",
    "dataset": "CICIoT2023 cleaned",
    "training_records": len(train_df),
    "validation_records": len(actual),
    "feature_count": len(features),
    "class_count": len(encoder.classes_),
    "max_training_samples_per_class": MAX_PER_CLASS,
    "training_seconds": training_seconds,
    "validation_accuracy": accuracy,
    "validation_macro_f1": macro_f1,
    "validation_weighted_f1": weighted_f1,
    "parameters": model.get_params()
}

with open(
    RESULT_DIR / "metrics.json",
    "w",
    encoding="utf-8"
) as f:
    json.dump(metrics, f, indent=4, default=str)

print("\n===== XGBOOST V1 RESULTS =====")
print(f"Training samples: {len(train_df):,}")
print(f"Validation samples: {len(actual):,}")
print(f"Accuracy: {accuracy:.4f}")
print(f"Macro F1: {macro_f1:.4f}")
print(f"Weighted F1: {weighted_f1:.4f}")
print(f"Training time: {training_seconds:.2f} seconds")
print("Results saved to:", RESULT_DIR)
