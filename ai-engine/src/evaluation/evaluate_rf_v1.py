from pathlib import Path
import json
import joblib
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    recall_score,
    classification_report,
    ConfusionMatrixDisplay
)

BASE_DIR = Path(__file__).resolve().parents[2]

DATA_FILE = BASE_DIR / "datasets" / "raw" / "train.csv"
MODEL_FILE = BASE_DIR / "models" / "random_forest_v1.joblib"

RESULT_DIR = BASE_DIR / "results" / "random_forest_v1"
RESULT_DIR.mkdir(parents=True, exist_ok=True)

SAMPLE_SIZE = 500_000
RANDOM_STATE = 42


print("Loading dataset...")
df = pd.read_csv(DATA_FILE)

# Reproduce same 500k development sample
sample_fraction = SAMPLE_SIZE / len(df)

df, _ = train_test_split(
    df,
    train_size=sample_fraction,
    stratify=df["label"],
    random_state=RANDOM_STATE
)

X = df.drop(columns=["label"])
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=RANDOM_STATE,
    stratify=y
)

print("Loading trained Random Forest...")
model = joblib.load(MODEL_FILE)

print("Running predictions...")
predictions = model.predict(X_test)

# ----------------------------
# Metrics
# ----------------------------

accuracy = accuracy_score(y_test, predictions)
macro_f1 = f1_score(y_test, predictions, average="macro")
weighted_f1 = f1_score(y_test, predictions, average="weighted")
macro_recall = recall_score(y_test, predictions, average="macro")

metrics = {
    "model": "Random Forest v1",
    "dataset": "CICIoT2023",
    "development_samples": len(df),
    "training_samples": len(X_train),
    "testing_samples": len(X_test),
    "number_of_features": X.shape[1],
    "number_of_classes": y.nunique(),
    "accuracy": accuracy,
    "macro_f1": macro_f1,
    "weighted_f1": weighted_f1,
    "macro_recall": macro_recall
}

with open(RESULT_DIR / "metrics.json", "w") as f:
    json.dump(metrics, f, indent=4)


# ----------------------------
# Classification report
# ----------------------------

report = classification_report(
    y_test,
    predictions,
    output_dict=True,
    zero_division=0
)

report_df = pd.DataFrame(report).transpose()

report_df.to_csv(
    RESULT_DIR / "classification_report.csv"
)


# ----------------------------
# Feature importance
# ----------------------------

importance_df = pd.DataFrame({
    "feature": X.columns,
    "importance": model.feature_importances_
})

importance_df = importance_df.sort_values(
    by="importance",
    ascending=False
)

importance_df.to_csv(
    RESULT_DIR / "feature_importance.csv",
    index=False
)


# Top 15 feature importance graph
top_features = importance_df.head(15)

plt.figure(figsize=(10, 7))

plt.barh(
    top_features["feature"][::-1],
    top_features["importance"][::-1]
)

plt.xlabel("Feature Importance")
plt.ylabel("Network Feature")
plt.title("Random Forest - Top 15 Feature Importances")

plt.tight_layout()

plt.savefig(
    RESULT_DIR / "feature_importance.png",
    dpi=300
)

plt.close()


# ----------------------------
# Confusion Matrix
# ----------------------------

print("Generating confusion matrix...")

fig, ax = plt.subplots(figsize=(20, 20))

ConfusionMatrixDisplay.from_predictions(
    y_test,
    predictions,
    normalize="true",
    xticks_rotation=90,
    values_format=".2f",
    ax=ax,
    cmap="Blues",
    include_values=False
)

plt.title(
    "Random Forest v1 - Normalized Confusion Matrix"
)

plt.tight_layout()

plt.savefig(
    RESULT_DIR / "confusion_matrix.png",
    dpi=300
)

plt.close()


print("\nEvaluation complete.")

print(f"Accuracy:      {accuracy:.4f}")
print(f"Macro F1:      {macro_f1:.4f}")
print(f"Weighted F1:   {weighted_f1:.4f}")
print(f"Macro Recall:  {macro_recall:.4f}")

print("\nResults saved to:")
print(RESULT_DIR)