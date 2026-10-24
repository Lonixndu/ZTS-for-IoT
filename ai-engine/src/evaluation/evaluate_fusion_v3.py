
from pathlib import Path
import json
import gc

import joblib
import numpy as np
import pandas as pd

from sklearn.metrics import roc_auc_score

# ==========================================
# Configuration
# ==========================================

VAL_FILE = Path(
    "datasets/processed/splits/validation.csv"
)

OUT = Path("results/fusion_v3")
OUT.mkdir(parents=True, exist_ok=True)

CHUNK_SIZE = 10000
BENIGN = "BenignTraffic"

TARGET_FPRS = [0.01, 0.02, 0.04]
AE_WEIGHTS = [0.0, 0.05, 0.10, 0.15, 0.20]

MODELS = {
    "XGBoost_v1": "models/xgboost_v1.joblib",
    "XGBoost_v3_44": (
        "models/xgboost_v3_b60000_reduced.joblib"
    ),
    "XGBoost_v3_88504": (
        "models/xgboost_v3_b88504_reduced.joblib"
    )
}

metadata = json.loads(
    Path("results/fusion_v2/experiment_metadata.json")
    .read_text(encoding="utf-8")
)

AE_SCALE = float(metadata["ae_scale"])

if AE_SCALE <= 0:
    raise ValueError("Invalid AE normalization scale")

# ==========================================
# Load existing validation AE errors
# ==========================================

print("Loading saved Autoencoder errors...")

predictions = np.load(
    "results/fusion_v1/validation_predictions.npz"
)

ae_errors = predictions["ae_errors"].astype(
    np.float64
)

saved_actual = predictions["actual"]

ae_scores = np.clip(
    ae_errors / AE_SCALE,
    0.0,
    1.0
)

# ==========================================
# Load validation labels
# ==========================================

print("Loading validation labels...")

labels = pd.read_csv(
    VAL_FILE,
    usecols=["label"]
)["label"].to_numpy()

actual_attack = labels != BENIGN

if len(actual_attack) != len(ae_scores):
    raise ValueError(
        "Validation and AE score lengths differ"
    )

if not np.array_equal(
    actual_attack.astype(np.uint8),
    saved_actual.astype(np.uint8)
):
    raise ValueError(
        "AE scores are not aligned with validation"
    )

# ==========================================
# Evaluate models
# ==========================================

results = []

for model_name, model_path in MODELS.items():

    print("\n" + "=" * 55)
    print("Evaluating:", model_name)

    package = joblib.load(model_path)

    model = package["model"]
    encoder = package["encoder"]
    features = list(package["features"])

    if len(features) != 44:
        raise ValueError(
            f"{model_name} does not use 44 features"
        )

    benign_index = list(
        encoder.classes_
    ).index(BENIGN)

    attack_score_chunks = []

    for chunk in pd.read_csv(
        VAL_FILE,
        chunksize=CHUNK_SIZE
    ):
        X = chunk[features].astype(np.float32)

        probabilities = model.predict_proba(X)

        attack_score_chunks.append(
            (
                1.0 - probabilities[:, benign_index]
            ).astype(np.float64)
        )

    xgb_scores = np.concatenate(
        attack_score_chunks
    )

    if len(xgb_scores) != len(ae_scores):
        raise ValueError(
            "Score length mismatch"
        )

    for ae_weight in AE_WEIGHTS:

        xgb_weight = 1.0 - ae_weight

        fused_scores = (
            xgb_weight * xgb_scores
            + ae_weight * ae_scores
        )

        benign_scores = fused_scores[
            ~actual_attack
        ]

        attack_scores = fused_scores[
            actual_attack
        ]

        auc = roc_auc_score(
            actual_attack,
            fused_scores
        )

        for target in TARGET_FPRS:

            threshold = float(
                np.quantile(
                    benign_scores,
                    1.0 - target
                )
            )

            fp = int(np.sum(
                benign_scores > threshold
            ))

            tp = int(np.sum(
                attack_scores > threshold
            ))

            fn = len(attack_scores) - tp

            results.append({
                "model": model_name,
                "xgb_weight": xgb_weight,
                "ae_weight": ae_weight,
                "target_fpr": target,
                "actual_fpr": (
                    fp / len(benign_scores)
                ),
                "attack_recall": (
                    tp / len(attack_scores)
                ),
                "false_alarms": fp,
                "missed_attacks": fn,
                "threshold": threshold,
                "roc_auc": auc
            })

        print(
            f"AE weight {ae_weight:.0%} evaluated"
        )

    pd.DataFrame(results).to_csv(
        OUT / "comparison.csv",
        index=False
    )

    del model, package, xgb_scores
    gc.collect()

# ==========================================
# Display comparison
# ==========================================

df = pd.DataFrame(results)

print("\n===== FUSION V3 RESULTS =====")

for target in TARGET_FPRS:

    print(f"\nTARGET FPR: {target:.0%}")

    subset = df[
        df["target_fpr"] == target
    ].sort_values(
        "attack_recall",
        ascending=False
    )

    print(
        subset[
            [
                "model",
                "ae_weight",
                "actual_fpr",
                "attack_recall",
                "missed_attacks",
                "roc_auc"
            ]
        ].head(10).to_string(index=False)
    )

print("\nSaved to:", OUT / "comparison.csv")
