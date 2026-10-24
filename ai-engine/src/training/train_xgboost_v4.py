
from pathlib import Path
import gc
import time

import joblib
import numpy as np
import pandas as pd

from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    f1_score,
    accuracy_score,
    roc_auc_score
)
from xgboost import XGBClassifier

SEED = 42
CHUNK_SIZE = 100_000
BENIGN = "BenignTraffic"

BENIGN_CAP = 60_000
ATTACK_CAP = 15_000
TARGET_FPRS = [0.01, 0.02, 0.04]

TRAIN_FILE = Path(
    "datasets/processed/splits/train.csv"
)
VAL_FILE = Path(
    "datasets/processed/splits/validation.csv"
)

MODEL_DIR = Path("models")
OUT = Path("results/xgboost_v4")

MODEL_DIR.mkdir(exist_ok=True)
OUT.mkdir(parents=True, exist_ok=True)

EXPERIMENTS = {
    "remove_weight": ["Weight"],
    "remove_number_weight": [
        "Number", "Weight"
    ],
    "remove_rst": ["rst_count"],
    "remove_number_weight_rst": [
        "Number", "Weight", "rst_count"
    ]
}

# =========================================
# 1. Reproduce v3 sampling
# =========================================

print("Loading training samples...")

rng = np.random.default_rng(SEED)
samples = {}

for chunk in pd.read_csv(
    TRAIN_FILE,
    chunksize=CHUNK_SIZE
):
    for label, group in chunk.groupby("label"):
        cap = (
            88_504 if label == BENIGN
            else ATTACK_CAP
        )

        existing = samples.get(label)

        combined = (
            group.copy()
            if existing is None
            else pd.concat(
                [existing, group],
                ignore_index=True
            )
        )

        if len(combined) > cap:
            indices = rng.choice(
                len(combined),
                size=cap,
                replace=False
            )

            combined = combined.iloc[
                indices
            ].reset_index(drop=True)

        samples[label] = combined

benign_pool = samples.pop(BENIGN).sample(
    frac=1,
    random_state=SEED
).reset_index(drop=True)

attack_pool = pd.concat(
    samples.values(),
    ignore_index=True
)

train_df = pd.concat(
    [
        attack_pool,
        benign_pool.iloc[:BENIGN_CAP]
    ],
    ignore_index=True
).sample(
    frac=1,
    random_state=SEED
).reset_index(drop=True)

all_features = [
    c for c in train_df.columns
    if c != "label"
]

encoder = LabelEncoder()
y_train = encoder.fit_transform(
    train_df["label"]
)

counts = np.bincount(y_train)

original_weights = np.clip(
    len(y_train) / (
        len(counts) * counts
    ),
    0.2,
    20.0
)

reduced_weights = (
    1.0 + 0.5 * (
        original_weights - 1.0
    )
)

sample_weights = reduced_weights[y_train]

print("Training records:", len(train_df))
print("Original features:", len(all_features))

# =========================================
# 2. Load validation once
# =========================================

print("Loading validation dataset...")

validation = pd.read_csv(VAL_FILE)

y_val_labels = validation["label"].to_numpy()
y_val_attack = y_val_labels != BENIGN

results = []

# =========================================
# 3. Reuse v3 baseline
# =========================================

baseline_package = joblib.load(
    "models/xgboost_v3_b60000_reduced.joblib"
)

experiments = {
    "baseline_44": {
        "model": baseline_package["model"],
        "features": baseline_package["features"],
        "train": False
    }
}

for name, removed in EXPERIMENTS.items():
    experiments[name] = {
        "model": None,
        "features": [
            f for f in all_features
            if f not in removed
        ],
        "train": True
    }

# =========================================
# 4. Train and evaluate
# =========================================

for name, experiment in experiments.items():
    print("\n" + "=" * 55)
    print("Experiment:", name)

    features = list(experiment["features"])

    if experiment["train"]:
        X_train = train_df[features].astype(
            np.float32
        )

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

        start = time.perf_counter()

        model.fit(
            X_train,
            y_train,
            sample_weight=sample_weights,
            verbose=False
        )

        elapsed = time.perf_counter() - start

        joblib.dump(
            {
                "model": model,
                "encoder": encoder,
                "features": features,
                "version": "v4",
                "removed_features": EXPERIMENTS[name]
            },
            MODEL_DIR / f"xgboost_v4_{name}.joblib",
            compress=3
        )

        del X_train
    else:
        model = experiment["model"]
        elapsed = None

    X_val = validation[features].astype(
        np.float32
    )

    probabilities = model.predict_proba(X_val)

    benign_index = list(
        encoder.classes_
    ).index(BENIGN)

    attack_scores = (
        1.0 - probabilities[:, benign_index]
    )

    predicted_ids = np.argmax(
        probabilities,
        axis=1
    )

    predicted_labels = encoder.inverse_transform(
        predicted_ids
    )

    macro_f1 = f1_score(
        y_val_labels,
        predicted_labels,
        average="macro",
        zero_division=0
    )

    accuracy = accuracy_score(
        y_val_labels,
        predicted_labels
    )

    auc = roc_auc_score(
        y_val_attack,
        attack_scores
    )

    benign_scores = attack_scores[
        ~y_val_attack
    ]

    attack_only_scores = attack_scores[
        y_val_attack
    ]

    for target in TARGET_FPRS:
        threshold = float(
            np.quantile(
                benign_scores,
                1 - target
            )
        )

        fp = int(np.sum(
            benign_scores > threshold
        ))

        tp = int(np.sum(
            attack_only_scores > threshold
        ))

        fn = len(attack_only_scores) - tp

        results.append({
            "experiment": name,
            "features": len(features),
            "target_fpr": target,
            "actual_fpr": (
                fp / len(benign_scores)
            ),
            "attack_recall": (
                tp / len(attack_only_scores)
            ),
            "false_alarms": fp,
            "missed_attacks": fn,
            "macro_f1": macro_f1,
            "accuracy": accuracy,
            "roc_auc": auc,
            "training_seconds": elapsed
        })

    pd.DataFrame(results).to_csv(
        OUT / "comparison.csv",
        index=False
    )

    print("Features:", len(features))
    print(f"Macro F1: {macro_f1:.6f}")
    print(f"ROC AUC: {auc:.6f}")

    for row in results[-len(TARGET_FPRS):]:
        print(
            f"FPR target {row['target_fpr']:.0%}: "
            f"recall={row['attack_recall']:.6f}, "
            f"missed={row['missed_attacks']}"
        )

    del probabilities, X_val
    if experiment["train"]:
        del model
    gc.collect()

# =========================================
# 5. Final comparison
# =========================================

comparison = pd.DataFrame(results)

print("\n===== XGBOOST V4 RESULTS =====")

for target in TARGET_FPRS:
    print(f"\nTARGET FPR: {target:.0%}")

    subset = comparison[
        comparison["target_fpr"] == target
    ].sort_values(
        "attack_recall",
        ascending=False
    )

    print(
        subset[
            [
                "experiment",
                "features",
                "actual_fpr",
                "attack_recall",
                "missed_attacks",
                "macro_f1"
            ]
        ].to_string(index=False)
    )

print("\nResults saved to:", OUT)
