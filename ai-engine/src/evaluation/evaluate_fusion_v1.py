
from pathlib import Path
import json
import time

import joblib
import numpy as np
import pandas as pd
import torch
from torch import nn
from sklearn.metrics import roc_auc_score

# ================================================
# CONFIGURATION
# ================================================

VALIDATION_FILE = Path(
    "datasets/processed/splits/validation.csv"
)

RESULT_DIR = Path("results/fusion_v1")
RESULT_DIR.mkdir(parents=True, exist_ok=True)

CHUNK_SIZE = 20_000
AE_BATCH_SIZE = 4096

torch.set_num_threads(4)

# ================================================
# AUTOENCODER ARCHITECTURE
# ================================================

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


# ================================================
# LOAD TRAINED MODELS
# ================================================

print("Loading Random Forest...")
rf_package = joblib.load(
    "models/random_forest_v2.joblib"
)

rf = rf_package["model"]
rf_features = rf_package["features"]

print("Loading XGBoost...")
xgb_package = joblib.load(
    "models/xgboost_v1.joblib"
)

xgb = xgb_package["model"]
xgb_features = xgb_package["features"]
encoder = xgb_package["encoder"]

print("Loading Autoencoder...")
ae_package = torch.load(
    "models/autoencoder_v1.pt",
    map_location="cpu",
    weights_only=True
)

ae_features = ae_package["features"]
clip_value = ae_package["clip_value"]

ae = Autoencoder(ae_package["input_dim"])
ae.load_state_dict(ae_package["model_state_dict"])
ae.eval()

scaler = joblib.load(
    "models/autoencoder_scaler_v1.joblib"
)

assert rf_features == xgb_features == ae_features, (
    "Feature ordering differs between models!"
)

print("All models loaded.")
print("Feature count:", len(ae_features))

# ================================================
# AUTOENCODER RECONSTRUCTION ERRORS
# ================================================

@torch.no_grad()
def calculate_ae_errors(frame):
    errors = []

    for start in range(0, len(frame), AE_BATCH_SIZE):
        part = frame.iloc[
            start:start + AE_BATCH_SIZE
        ]

        values = part[ae_features].to_numpy(
            dtype=np.float32
        )

        values = scaler.transform(values)
        values = np.clip(
            values, -clip_value, clip_value
        ).astype(np.float32)

        tensor = torch.from_numpy(values)
        reconstructed = ae(tensor)

        mse = torch.mean(
            (tensor - reconstructed) ** 2,
            dim=1
        )

        errors.append(mse.numpy())

    return np.concatenate(errors)


# ================================================
# GENERATE ALIGNED VALIDATION PREDICTIONS
# ================================================

print("\nGenerating validation predictions...")

all_actual = []
all_rf = []
all_xgb = []
all_ae_errors = []

start_time = time.perf_counter()

for index, chunk in enumerate(
    pd.read_csv(
        VALIDATION_FILE,
        chunksize=CHUNK_SIZE
    ),
    start=1
):
    actual = (
        chunk["label"] != "BenignTraffic"
    ).to_numpy(dtype=np.uint8)

    X = chunk[rf_features]

    rf_predictions = rf.predict(X)
    rf_attack = (
        rf_predictions != "BenignTraffic"
    ).astype(np.uint8)

    xgb_encoded = xgb.predict(X)
    xgb_predictions = encoder.inverse_transform(
        np.asarray(xgb_encoded, dtype=np.int64)
    )
    xgb_attack = (
        xgb_predictions != "BenignTraffic"
    ).astype(np.uint8)

    ae_errors = calculate_ae_errors(chunk)

    all_actual.append(actual)
    all_rf.append(rf_attack)
    all_xgb.append(xgb_attack)
    all_ae_errors.append(ae_errors)

    print(
        f"Processed chunk {index}: "
        f"{len(chunk):,} records"
    )

actual = np.concatenate(all_actual)
rf_pred = np.concatenate(all_rf)
xgb_pred = np.concatenate(all_xgb)
ae_errors = np.concatenate(all_ae_errors)

# ================================================
# THRESHOLDS FROM PREVIOUS AE EXPERIMENT
# ================================================

ae_metrics = json.loads(
    Path(
        "results/autoencoder_v1/metrics.json"
    ).read_text(encoding="utf-8")
)

thresholds = {
    f"AE q{int(round(r['quantile'] * 1000)) / 10:g}":
        r["threshold"]
    for r in ae_metrics["threshold_experiments"]
    if r["quantile"] in (0.95, 0.99)
}

# ================================================
# SECURITY METRICS
# ================================================

def calculate_metrics(y_true, y_pred):
    y_true = np.asarray(y_true, dtype=bool)
    y_pred = np.asarray(y_pred, dtype=bool)

    tp = int(np.sum(y_true & y_pred))
    tn = int(np.sum(~y_true & ~y_pred))
    fp = int(np.sum(~y_true & y_pred))
    fn = int(np.sum(y_true & ~y_pred))

    return {
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "attack_recall": tp / (tp + fn),
        "benign_fpr": fp / (fp + tn),
        "precision": tp / (tp + fp)
        if tp + fp else 0,
        "f1": (2 * tp) / (2 * tp + fp + fn)
        if 2 * tp + fp + fn else 0
    }


results = []

def record(name, prediction):
    metrics = calculate_metrics(actual, prediction)
    metrics["strategy"] = name
    results.append(metrics)


record("Random Forest v2", rf_pred)
record("XGBoost v1", xgb_pred)

for name, threshold in thresholds.items():
    ae_pred = (ae_errors > threshold).astype(np.uint8)

    record(name, ae_pred)

    for model_name, supervised in [
        ("RF", rf_pred),
        ("XGBoost", xgb_pred)
    ]:
        record(
            f"{model_name} OR {name}",
            supervised | ae_pred
        )

        record(
            f"{model_name} AND {name}",
            supervised & ae_pred
        )

# ================================================
# SAVE RESULTS
# ================================================

comparison = pd.DataFrame(results)

comparison = comparison[
    [
        "strategy",
        "attack_recall",
        "benign_fpr",
        "precision",
        "f1",
        "TP", "TN", "FP", "FN"
    ]
]

comparison.to_csv(
    RESULT_DIR / "fusion_comparison.csv",
    index=False
)

# Keep aligned outputs for future experiments.
np.savez_compressed(
    RESULT_DIR / "validation_predictions.npz",
    actual=actual,
    rf_pred=rf_pred,
    xgb_pred=xgb_pred,
    ae_errors=ae_errors
)

elapsed = time.perf_counter() - start_time

print("\n===== FUSION RESULTS =====")
print(
    comparison[
        [
            "strategy",
            "attack_recall",
            "benign_fpr",
            "FP",
            "FN"
        ]
    ].to_string(index=False)
)

print(f"\nEvaluation time: {elapsed:.2f} s")
print("Saved to:", RESULT_DIR)
