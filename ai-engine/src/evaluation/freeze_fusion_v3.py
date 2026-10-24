
from pathlib import Path
import json
import hashlib
import joblib
import pandas as pd

OUT = Path("config/fusion_v3_frozen.json")
RESULTS = Path("results/fusion_v3/comparison.csv")

MODEL = Path("models/xgboost_v3_b88504_reduced.joblib")
AE_MODEL = Path("models/autoencoder_v1.pt")
AE_SCALER = Path("models/autoencoder_scaler_v1.joblib")

for path in [RESULTS, MODEL, AE_MODEL, AE_SCALER]:
    if not path.is_file():
        raise FileNotFoundError(path)

df = pd.read_csv(RESULTS)

selected = df[
    (df["model"] == "XGBoost_v3_88504")
    & (abs(df["ae_weight"] - 0.10) < 1e-8)
    & (abs(df["target_fpr"] - 0.04) < 1e-8)
]

if len(selected) != 1:
    raise ValueError(
        f"Expected one configuration, found {len(selected)}"
    )

row = selected.iloc[0]

package = joblib.load(MODEL)
features = list(package["features"])

if len(features) != 44:
    raise ValueError("Expected 44 XGBoost features")

# Verify AE feature order from checkpoint metadata.
import torch
checkpoint = torch.load(
    AE_MODEL,
    map_location="cpu",
    weights_only=True
)
ae_features = list(checkpoint["features"])

if features != ae_features:
    raise ValueError(
        "XGBoost and Autoencoder feature order differs"
    )

metadata = json.loads(
    Path("results/fusion_v2/experiment_metadata.json")
    .read_text(encoding="utf-8")
)

def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        for chunk in iter(
            lambda: file.read(1024 * 1024), b""
        ):
            digest.update(chunk)
    return digest.hexdigest()

config = {
    "version": "fusion_v3_frozen",
    "status": "validation_selected",
    "xgboost_model": str(MODEL),
    "autoencoder_model": str(AE_MODEL),
    "autoencoder_scaler": str(AE_SCALER),
    "xgboost_weight": float(row["xgb_weight"]),
    "autoencoder_weight": float(row["ae_weight"]),
    "decision_threshold": float(row["threshold"]),
    "ae_normalization": "clip(error / scale, 0, 1)",
    "ae_scale": float(metadata["ae_scale"]),
    "ae_input_clip_value": float(checkpoint["clip_value"]),
    "features": features,
    "feature_count": len(features),
    "validation": {
        "target_fpr": float(row["target_fpr"]),
        "actual_fpr": float(row["actual_fpr"]),
        "attack_recall": float(row["attack_recall"]),
        "false_alarms": int(row["false_alarms"]),
        "missed_attacks": int(row["missed_attacks"])
    },
    "sha256": {
        "xgboost": sha256(MODEL),
        "autoencoder": sha256(AE_MODEL),
        "scaler": sha256(AE_SCALER)
    }
}

OUT.parent.mkdir(parents=True, exist_ok=True)

OUT.write_text(
    json.dumps(config, indent=4),
    encoding="utf-8"
)

print("\n===== FUSION V3 FROZEN =====")
print("Configuration:", OUT)
print("XGBoost model:", MODEL)
print("AE model:", AE_MODEL)
print("Features:", len(features))
print("XGBoost weight:", config["xgboost_weight"])
print("AE weight:", config["autoencoder_weight"])
print("Threshold:", config["decision_threshold"])
print("Validation recall:", config["validation"]["attack_recall"])
print("Validation FPR:", config["validation"]["actual_fpr"])
print("SHA256 checksums saved.")
