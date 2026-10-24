
from pathlib import Path
import json
import time
import gc

import joblib
import numpy as np
import pandas as pd

from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    roc_auc_score
)
from xgboost import XGBClassifier

SEED = 42
CHUNK_SIZE = 100_000
ATTACK_CAP = 15_000
BENIGN_CAPS = [15_000, 30_000, 60_000, 88_504]
BENIGN = "BenignTraffic"
TARGET_FPR = 0.04

TRAIN_FILE = Path("datasets/processed/splits/train.csv")
VAL_FILE = Path("datasets/processed/splits/validation.csv")

MODEL_DIR = Path("models")
RESULT_DIR = Path("results/xgboost_v2")

MODEL_DIR.mkdir(exist_ok=True)
RESULT_DIR.mkdir(parents=True, exist_ok=True)


def load_training_samples():
    """
    Build one fixed candidate pool.

    Attack samples are held constant across experiments.
    Benign candidates are sampled once, then nested so
    smaller benign sets are subsets of larger sets.
    """
    rng = np.random.default_rng(SEED)
    samples = {}

    for chunk in pd.read_csv(
        TRAIN_FILE,
        chunksize=CHUNK_SIZE
    ):
        for label, group in chunk.groupby("label"):
            cap = (
                max(BENIGN_CAPS)
                if label == BENIGN
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

    return samples


print("Loading training samples...")
samples = load_training_samples()

benign_pool = samples.pop(BENIGN).sample(
    frac=1,
    random_state=SEED
).reset_index(drop=True)

attack_pool = pd.concat(
    samples.values(),
    ignore_index=True
)

features = [
    col for col in attack_pool.columns
    if col != "label"
]

print("Benign pool:", len(benign_pool))
print("Attack pool:", len(attack_pool))
print("Features:", len(features))

# Load validation once to avoid repeated CSV reading.
print("Loading validation data...")

validation = pd.read_csv(VAL_FILE)

X_val = validation[features].astype("float32")
y_val_labels = validation["label"].to_numpy()
y_val_attack = y_val_labels != BENIGN

results = []

for benign_cap in BENIGN_CAPS:
    print("\n" + "=" * 55)
    print("Training benign cap:", benign_cap)

    train_df = pd.concat(
        [
            attack_pool,
            benign_pool.iloc[:benign_cap]
        ],
        ignore_index=True
    )

    train_df = train_df.sample(
        frac=1,
        random_state=SEED
    ).reset_index(drop=True)

    X_train = train_df[features].astype("float32")

    encoder = LabelEncoder()
    y_train = encoder.fit_transform(
        train_df["label"]
    )

    class_counts = np.bincount(y_train)

    class_weights = len(y_train) / (
        len(class_counts) * class_counts
    )

    class_weights = np.clip(
        class_weights, 0.2, 20.0
    )

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

    start = time.perf_counter()

    model.fit(
        X_train,
        y_train,
        sample_weight=sample_weights,
        verbose=False
    )

    elapsed = time.perf_counter() - start

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

    benign_scores = attack_scores[
        ~y_val_attack
    ]

    # Select operating threshold on validation benign
    # records only. Ties may lower actual FPR.
    threshold = float(
        np.quantile(
            benign_scores,
            1 - TARGET_FPR
        )
    )

    binary_predictions = (
        attack_scores > threshold
    )

    tp = int(np.sum(
        y_val_attack & binary_predictions
    ))
    tn = int(np.sum(
        ~y_val_attack & ~binary_predictions
    ))
    fp = int(np.sum(
        ~y_val_attack & binary_predictions
    ))
    fn = int(np.sum(
        y_val_attack & ~binary_predictions
    ))

    name = f"xgboost_v2_benign_{benign_cap}"

    joblib.dump(
        {
            "model": model,
            "encoder": encoder,
            "features": features,
            "version": "v2",
            "benign_cap": benign_cap
        },
        MODEL_DIR / f"{name}.joblib",
        compress=3
    )

    row = {
        "model": name,
        "benign_cap": benign_cap,
        "training_records": len(train_df),
        "training_seconds": elapsed,
        "threshold": threshold,
        "attack_recall": tp / (tp + fn),
        "benign_fpr": fp / (fp + tn),
        "false_alarms": fp,
        "missed_attacks": fn,
        "roc_auc": roc_auc_score(
            y_val_attack,
            attack_scores
        ),
        "multiclass_accuracy": accuracy_score(
            y_val_labels,
            predicted_labels
        ),
        "multiclass_macro_f1": f1_score(
            y_val_labels,
            predicted_labels,
            average="macro",
            zero_division=0
        )
    }

    results.append(row)

    print(
        f"Attack recall: {row['attack_recall']:.6f}"
    )
    print(
        f"Benign FPR: {row['benign_fpr']:.6f}"
    )
    print("False alarms:", fp)
    print("Missed attacks:", fn)
    print(
        f"Macro F1: {row['multiclass_macro_f1']:.6f}"
    )
    print(f"Training time: {elapsed:.2f} s")

    pd.DataFrame(results).to_csv(
        RESULT_DIR / "comparison.csv",
        index=False
    )

    del model, X_train, train_df, probabilities
    gc.collect()

print("\n===== XGBOOST V2 COMPARISON =====")

comparison = pd.DataFrame(results)

print(
    comparison[
        [
            "benign_cap",
            "attack_recall",
            "benign_fpr",
            "false_alarms",
            "missed_attacks",
            "multiclass_macro_f1"
        ]
    ].to_string(index=False)
)

print("\nSaved to:", RESULT_DIR)
