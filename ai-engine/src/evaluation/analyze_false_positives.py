
from pathlib import Path
import json

import joblib
import numpy as np
import pandas as pd

# ==========================================
# CONFIGURATION
# ==========================================

VALIDATION_FILE = Path(
    "datasets/processed/splits/validation.csv"
)

OUTPUT_DIR = Path(
    "results/false_positive_analysis"
)

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

CHUNK_SIZE = 10000
BENIGN = "BenignTraffic"

# Load validation-selected threshold.
config = json.loads(
    Path("results/fusion_v2/frozen_config.json")
    .read_text(encoding="utf-8")
)

threshold = float(
    config["candidates"]["xgboost_only"]["threshold"]
)

# ==========================================
# LOAD MODEL
# ==========================================

print("Loading XGBoost...")

package = joblib.load(
    "models/xgboost_v1.joblib"
)

model = package["model"]
encoder = package["encoder"]
features = list(package["features"])

benign_index = list(encoder.classes_).index(BENIGN)

# ==========================================
# ANALYZE VALIDATION RECORDS
# ==========================================

false_positive_frames = []
true_negative_frames = []

predicted_class_counts = {}
total_benign = 0
total_false_positives = 0

for chunk_number, chunk in enumerate(
    pd.read_csv(
        VALIDATION_FILE,
        chunksize=CHUNK_SIZE
    ),
    start=1
):
    benign = chunk.loc[
        chunk["label"] == BENIGN
    ].copy()

    if benign.empty:
        continue

    total_benign += len(benign)

    X = benign[features]

    probabilities = model.predict_proba(X)

    attack_scores = (
        1.0 - probabilities[:, benign_index]
    )

    predicted_indices = np.argmax(
        probabilities,
        axis=1
    )

    predicted_classes = encoder.inverse_transform(
        predicted_indices
    )

    benign["attack_score"] = attack_scores
    benign["predicted_class"] = predicted_classes

    # False positives at the frozen threshold.
    fp_mask = attack_scores > threshold

    false_positives = benign.loc[fp_mask].copy()
    true_negatives = benign.loc[~fp_mask].copy()

    false_positive_frames.append(false_positives)
    true_negative_frames.append(true_negatives)

    total_false_positives += int(fp_mask.sum())

    for label, count in (
        false_positives["predicted_class"]
        .value_counts()
        .items()
    ):
        predicted_class_counts[label] = (
            predicted_class_counts.get(label, 0)
            + int(count)
        )

    print(
        f"Chunk {chunk_number}: "
        f"{len(benign):,} benign records, "
        f"{int(fp_mask.sum()):,} false positives"
    )

# ==========================================
# SAVE FALSE POSITIVES
# ==========================================

fp_df = pd.concat(
    false_positive_frames,
    ignore_index=True
)

tn_df = pd.concat(
    true_negative_frames,
    ignore_index=True
)

fp_df.to_csv(
    OUTPUT_DIR / "false_positive_records.csv",
    index=False
)

# ==========================================
# FEATURE COMPARISON
# ==========================================

feature_comparison = []

for feature in features:
    feature_comparison.append({
        "feature": feature,
        "fp_mean": float(fp_df[feature].mean()),
        "tn_mean": float(tn_df[feature].mean()),
        "fp_median": float(fp_df[feature].median()),
        "tn_median": float(tn_df[feature].median()),
        "fp_std": float(fp_df[feature].std()),
        "tn_std": float(tn_df[feature].std())
    })

pd.DataFrame(
    feature_comparison
).to_csv(
    OUTPUT_DIR / "feature_comparison.csv",
    index=False
)

# ==========================================
# PREDICTED ATTACK CLASSES
# ==========================================

class_summary = (
    pd.Series(predicted_class_counts)
    .sort_values(ascending=False)
    .rename_axis("predicted_class")
    .reset_index(name="false_positive_count")
)

class_summary.to_csv(
    OUTPUT_DIR / "false_positive_classes.csv",
    index=False
)

# ==========================================
# SUMMARY
# ==========================================

summary = {
    "model": "XGBoost v1",
    "threshold": threshold,
    "benign_validation_records": total_benign,
    "false_positive_records": total_false_positives,
    "benign_fpr": (
        total_false_positives / total_benign
    ),
    "true_negative_records": (
        total_benign - total_false_positives
    )
}

(OUTPUT_DIR / "summary.json").write_text(
    json.dumps(summary, indent=4),
    encoding="utf-8"
)

print("\n===== FALSE POSITIVE ANALYSIS =====")
print("Benign validation records:", total_benign)
print("False positives:", total_false_positives)
print(
    "Benign FPR:",
    round(summary["benign_fpr"] * 100, 4),
    "%"
)

print("\nTOP PREDICTED CLASSES")
print(class_summary.head(10).to_string(index=False))

print("\nResults saved to:", OUTPUT_DIR)
