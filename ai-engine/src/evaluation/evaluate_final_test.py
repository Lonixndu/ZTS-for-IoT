
from pathlib import Path
import json
import time

import joblib
import numpy as np
import pandas as pd
import torch
from torch import nn
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)

TEST_FILE = Path("datasets/processed/splits/test.csv")
OUTPUT_DIR = Path("results/final_test")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

CHUNK_SIZE = 10000
AE_BATCH_SIZE = 4096

torch.set_num_threads(4)

config = json.loads(
    Path("results/fusion_v2/frozen_config.json")
    .read_text(encoding="utf-8")
)

# ------------------------------------------
# Load models
# ------------------------------------------

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

class Autoencoder(nn.Module):
    def __init__(self, input_dim):
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(input_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, 8),
            nn.ReLU(),
            nn.Linear(8, 16),
            nn.ReLU(),
            nn.Linear(16, 32),
            nn.ReLU(),
            nn.Linear(32, input_dim)
        )

    def forward(self, x):
        return self.network(x)

print("Loading Autoencoder...")

ae_package = torch.load(
    "models/autoencoder_v1.pt",
    map_location="cpu",
    weights_only=True
)

ae = Autoencoder(ae_package["input_dim"])
ae.load_state_dict(ae_package["model_state_dict"])
ae.eval()

scaler = joblib.load(
    "models/autoencoder_scaler_v1.joblib"
)

ae_features = list(ae_package["features"])
clip_value = float(ae_package["clip_value"])

if not (
    rf_features == xgb_features == ae_features
):
    raise ValueError("Feature order mismatch")

if list(encoder.classes_) != list(
    encoder.inverse_transform(
        np.arange(len(encoder.classes_))
    )
):
    raise ValueError("XGBoost label encoding mismatch")

rf_benign_index = list(rf.classes_).index(
    "BenignTraffic"
)

xgb_benign_index = list(encoder.classes_).index(
    "BenignTraffic"
)

ae_scale = config["ae_normalization"]["scale"]

if ae_scale <= 0:
    raise ValueError("Invalid AE scale")

# ------------------------------------------
# Autoencoder inference
# ------------------------------------------

@torch.no_grad()
def calculate_ae_errors(frame):
    errors = []

    for start in range(0, len(frame), AE_BATCH_SIZE):
        part = frame.iloc[start:start + AE_BATCH_SIZE]

        values = part[ae_features].to_numpy(
            dtype=np.float32
        )

        values = scaler.transform(values)

        values = np.clip(
            values, -clip_value, clip_value
        ).astype(np.float32)

        tensor = torch.from_numpy(values)
        reconstruction = ae(tensor)

        mse = torch.mean(
            (tensor - reconstruction) ** 2,
            dim=1
        )

        errors.append(mse.numpy())

    return np.concatenate(errors)

# ------------------------------------------
# Test inference
# ------------------------------------------

actual_binary = []
actual_multiclass = []

rf_binary = []
xgb_default_binary = []
xgb_frozen_binary = []
fusion_binary = []

xgb_multiclass = []
rf_multiclass = []

xgb_scores = []
fusion_scores = []

start_time = time.perf_counter()

print("\nEvaluating untouched test partition...")

for chunk_number, chunk in enumerate(
    pd.read_csv(
        TEST_FILE,
        chunksize=CHUNK_SIZE
    ),
    start=1
):
    X = chunk[rf_features]

    labels = chunk["label"].to_numpy()

    actual_multiclass.append(labels)

    actual = (
        labels != "BenignTraffic"
    ).astype(np.uint8)

    actual_binary.append(actual)

    rf_prob = rf.predict_proba(X)

    rf_labels = rf.classes_[
        np.argmax(rf_prob, axis=1)
    ]

    rf_multiclass.append(rf_labels)

    rf_binary.append(
        (rf_labels != "BenignTraffic")
        .astype(np.uint8)
    )

    xgb_prob = xgb.predict_proba(X)

    xgb_indices = np.argmax(
        xgb_prob, axis=1
    )

    xgb_labels = encoder.inverse_transform(
        xgb_indices
    )

    xgb_multiclass.append(xgb_labels)

    xgb_default_binary.append(
        (xgb_labels != "BenignTraffic")
        .astype(np.uint8)
    )

    attack_score = (
        1.0 - xgb_prob[:, xgb_benign_index]
    )

    ae_errors = calculate_ae_errors(chunk)

    ae_score = np.clip(
        ae_errors / ae_scale, 0.0, 1.0
    )

    xgb_config = config["candidates"]["xgboost_only"]

    xgb_frozen_binary.append(
        (attack_score > xgb_config["threshold"])
        .astype(np.uint8)
    )

    fusion_config = config["candidates"][
        "xgboost_ae_fusion"
    ]

    fused_score = (
        fusion_config["xgb_weight"] * attack_score
        + fusion_config["ae_weight"] * ae_score
    )

    fusion_binary.append(
        (fused_score > fusion_config["threshold"])
        .astype(np.uint8)
    )

    xgb_scores.append(
        attack_score.astype(np.float32)
    )

    fusion_scores.append(
        fused_score.astype(np.float32)
    )

    print(
        f"Chunk {chunk_number}: "
        f"{len(chunk):,} records"
    )

# ------------------------------------------
# Combine aligned outputs
# ------------------------------------------

y = np.concatenate(actual_binary)
y_multiclass = np.concatenate(actual_multiclass)

predictions = {
    "Random Forest v2": np.concatenate(rf_binary),
    "XGBoost v1 default": np.concatenate(
        xgb_default_binary
    ),
    "XGBoost frozen threshold": np.concatenate(
        xgb_frozen_binary
    ),
    "XGBoost + AE frozen fusion": np.concatenate(
        fusion_binary
    )
}

rf_labels = np.concatenate(rf_multiclass)
xgb_labels = np.concatenate(xgb_multiclass)

xgb_scores = np.concatenate(xgb_scores)
fusion_scores = np.concatenate(fusion_scores)

# ------------------------------------------
# Calculate binary security metrics
# ------------------------------------------

results = []

for name, predicted in predictions.items():
    tn, fp, fn, tp = confusion_matrix(
        y, predicted, labels=[0, 1]
    ).ravel()

    results.append({
        "model": name,
        "attack_recall": float(
            recall_score(y, predicted)
        ),
        "benign_fpr": float(fp / (fp + tn)),
        "precision": float(
            precision_score(
                y, predicted, zero_division=0
            )
        ),
        "f1": float(f1_score(y, predicted)),
        "TP": int(tp),
        "TN": int(tn),
        "FP": int(fp),
        "FN": int(fn)
    })

comparison = pd.DataFrame(results)

comparison.to_csv(
    OUTPUT_DIR / "binary_comparison.csv",
    index=False
)

# ------------------------------------------
# Multiclass evaluation
# ------------------------------------------

multiclass_results = {}

for name, predicted in [
    ("Random Forest v2", rf_labels),
    ("XGBoost v1", xgb_labels)
]:
    multiclass_results[name] = {
        "accuracy": float(
            accuracy_score(y_multiclass, predicted)
        ),
        "macro_f1": float(
            f1_score(
                y_multiclass,
                predicted,
                average="macro",
                zero_division=0
            )
        ),
        "weighted_f1": float(
            f1_score(
                y_multiclass,
                predicted,
                average="weighted",
                zero_division=0
            )
        )
    }

    report = classification_report(
        y_multiclass,
        predicted,
        output_dict=True,
        zero_division=0
    )

    filename = (
        "rf_multiclass_report.csv"
        if name.startswith("Random")
        else "xgb_multiclass_report.csv"
    )

    pd.DataFrame(report).transpose().to_csv(
        OUTPUT_DIR / filename
    )

# ------------------------------------------
# Save summary
# ------------------------------------------

summary = {
    "test_records": len(y),
    "benign_records": int(np.sum(y == 0)),
    "attack_records": int(np.sum(y == 1)),
    "roc_auc": {
        "xgboost": float(
            roc_auc_score(y, xgb_scores)
        ),
        "fusion": float(
            roc_auc_score(y, fusion_scores)
        )
    },
    "multiclass_results": multiclass_results,
    "configuration": config,
    "evaluation_seconds": (
        time.perf_counter() - start_time
    )
}

(OUTPUT_DIR / "summary.json").write_text(
    json.dumps(summary, indent=4),
    encoding="utf-8"
)

print("\n===== FINAL TEST RESULTS =====")

print(
    comparison[
        [
            "model",
            "attack_recall",
            "benign_fpr",
            "FP",
            "FN"
        ]
    ].to_string(index=False)
)

print("\nMULTICLASS RESULTS")

for name, metrics in multiclass_results.items():
    print(name, metrics)

print("\nROC AUC:", summary["roc_auc"])
print("\nSaved to:", OUTPUT_DIR)
