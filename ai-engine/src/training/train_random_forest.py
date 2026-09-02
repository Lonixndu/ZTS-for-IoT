from pathlib import Path
import time
import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)


# --------------------------------------------------
# Paths
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parents[2]

DATA_FILE = BASE_DIR / "datasets" / "raw" / "train.csv"
MODEL_DIR = BASE_DIR / "models"

MODEL_DIR.mkdir(parents=True, exist_ok=True)

MODEL_FILE = MODEL_DIR / "random_forest_v1.joblib"


# --------------------------------------------------
# Configuration
# --------------------------------------------------

SAMPLE_SIZE = 500_000
RANDOM_STATE = 42


print("=" * 60)
print(" Zero Trust IoT - AI Anomaly Detection Engine")
print(" Random Forest Baseline")
print("=" * 60)


# --------------------------------------------------
# Load dataset
# --------------------------------------------------

print("\n[1/6] Loading CICIoT2023 dataset...")

df = pd.read_csv(DATA_FILE)

print(f"Dataset shape: {df.shape}")


# --------------------------------------------------
# Create development sample
# --------------------------------------------------

print("\n[2/6] Creating development sample...")

if len(df) > SAMPLE_SIZE:

    # Stratified sampling so small attack classes are represented
    sample_fraction = SAMPLE_SIZE / len(df)

    df, _ = train_test_split(
        df,
        train_size=sample_fraction,
        stratify=df["label"],
        random_state=RANDOM_STATE
    )

print(f"Development dataset: {df.shape}")


# --------------------------------------------------
# Features / labels
# --------------------------------------------------

print("\n[3/6] Preparing features...")

X = df.drop(columns=["label"])
y = df["label"]

print(f"Features: {X.shape[1]}")
print(f"Attack classes: {y.nunique()}")


# --------------------------------------------------
# Train/test split
# --------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=RANDOM_STATE,
    stratify=y
)

print(f"Training samples: {len(X_train):,}")
print(f"Testing samples:  {len(X_test):,}")


# --------------------------------------------------
# Train Random Forest
# --------------------------------------------------

print("\n[4/6] Training Random Forest...")

model = RandomForestClassifier(
    n_estimators=100,
    max_depth=None,
    n_jobs=-1,
    random_state=RANDOM_STATE,
    class_weight="balanced_subsample"
)

start = time.time()

model.fit(X_train, y_train)

training_time = time.time() - start

print(f"Training completed in {training_time:.2f} seconds.")


# --------------------------------------------------
# Evaluation
# --------------------------------------------------

print("\n[5/6] Evaluating model...")

start = time.time()

predictions = model.predict(X_test)

inference_time = time.time() - start

accuracy = accuracy_score(y_test, predictions)

print("\n" + "=" * 60)
print("RESULTS")
print("=" * 60)

print(f"\nAccuracy: {accuracy:.4f}")
print(f"Inference time: {inference_time:.2f} seconds")
print(
    f"Average inference latency: "
    f"{(inference_time / len(X_test)) * 1000:.6f} ms/sample"
)

print("\nClassification Report:\n")

print(
    classification_report(
        y_test,
        predictions,
        digits=4,
        zero_division=0
    )
)


# --------------------------------------------------
# Save model
# --------------------------------------------------

print("\n[6/6] Saving trained model...")

joblib.dump(model, MODEL_FILE)

print(f"Model saved to:")
print(MODEL_FILE)

print("\nRandom Forest baseline completed successfully.")