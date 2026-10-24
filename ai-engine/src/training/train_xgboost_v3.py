
from pathlib import Path
import gc
import json
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score, f1_score, roc_auc_score,
    classification_report
)
from xgboost import XGBClassifier

SEED = 42
CHUNK_SIZE = 100_000
ATTACK_CAP = 15_000
BENIGN_CAPS = [60_000, 88_504]
WEIGHT_MODES = ["original", "reduced", "none"]
TARGET_FPRS = [0.01, 0.02, 0.04]
BENIGN = "BenignTraffic"

TRAIN_FILE = Path("datasets/processed/splits/train.csv")
VAL_FILE = Path("datasets/processed/splits/validation.csv")
MODEL_DIR = Path("models")
OUT = Path("results/xgboost_v3")

MODEL_DIR.mkdir(exist_ok=True)
OUT.mkdir(parents=True, exist_ok=True)

# Reproduce the shared-pool sampling used in v2.
rng = np.random.default_rng(SEED)
samples = {}

print("Loading training samples...")

for chunk in pd.read_csv(TRAIN_FILE, chunksize=CHUNK_SIZE):
    for label, group in chunk.groupby("label"):
        cap = max(BENIGN_CAPS) if label == BENIGN else ATTACK_CAP
        existing = samples.get(label)

        combined = (
            group.copy()
            if existing is None
            else pd.concat([existing, group], ignore_index=True)
        )

        if len(combined) > cap:
            indices = rng.choice(
                len(combined), size=cap, replace=False
            )
            combined = combined.iloc[indices].reset_index(drop=True)

        samples[label] = combined

benign_pool = samples.pop(BENIGN).sample(
    frac=1, random_state=SEED
).reset_index(drop=True)

attack_pool = pd.concat(samples.values(), ignore_index=True)

features = [c for c in attack_pool.columns if c != "label"]

print("Benign records:", len(benign_pool))
print("Attack records:", len(attack_pool))
print("Features:", len(features))

print("Loading validation dataset...")

validation = pd.read_csv(VAL_FILE)
X_val = validation[features].astype(np.float32)
y_val_labels = validation["label"].to_numpy()
y_val_attack = y_val_labels != BENIGN

results = []

for benign_cap in BENIGN_CAPS:
    train_df = pd.concat(
        [attack_pool, benign_pool.iloc[:benign_cap]],
        ignore_index=True
    ).sample(frac=1, random_state=SEED).reset_index(drop=True)

    X_train = train_df[features].astype(np.float32)

    encoder = LabelEncoder()
    y_train = encoder.fit_transform(train_df["label"])

    counts = np.bincount(y_train)
    original_weights = np.clip(
        len(y_train) / (len(counts) * counts),
        0.2, 20.0
    )

    for mode in WEIGHT_MODES:
        if mode == "original":
            class_weights = original_weights
        elif mode == "reduced":
            class_weights = 1.0 + 0.5 * (
                original_weights - 1.0
            )
        else:
            class_weights = np.ones_like(original_weights)

        sample_weights = class_weights[y_train]

        name = f"xgboost_v3_b{benign_cap}_{mode}"

        print(f"\nTraining {name}...")
        start = time.perf_counter()

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

        model.fit(
            X_train,
            y_train,
            sample_weight=sample_weights,
            verbose=False
        )

        training_seconds = time.perf_counter() - start

        probabilities = model.predict_proba(X_val)
        benign_index = list(encoder.classes_).index(BENIGN)

        attack_scores = 1.0 - probabilities[:, benign_index]

        pred_ids = np.argmax(probabilities, axis=1)
        pred_labels = encoder.inverse_transform(pred_ids)

        macro_f1 = f1_score(
            y_val_labels, pred_labels,
            average="macro", zero_division=0
        )

        class_report = classification_report(
            y_val_labels, pred_labels,
            output_dict=True, zero_division=0
        )

        pd.DataFrame(class_report).transpose().to_csv(
            OUT / f"{name}_classification_report.csv"
        )

        auc = roc_auc_score(y_val_attack, attack_scores)

        benign_scores = attack_scores[~y_val_attack]
        attack_only_scores = attack_scores[y_val_attack]

        for target in TARGET_FPRS:
            threshold = float(
                np.quantile(benign_scores, 1 - target)
            )

            fp = int(np.sum(benign_scores > threshold))
            tp = int(np.sum(attack_only_scores > threshold))
            fn = len(attack_only_scores) - tp

            results.append({
                "model": name,
                "benign_cap": benign_cap,
                "weight_mode": mode,
                "target_fpr": target,
                "actual_fpr": fp / len(benign_scores),
                "attack_recall": tp / len(attack_only_scores),
                "false_alarms": fp,
                "missed_attacks": fn,
                "threshold": threshold,
                "macro_f1": macro_f1,
                "roc_auc": auc,
                "training_seconds": training_seconds
            })

        joblib.dump(
            {
                "model": model,
                "encoder": encoder,
                "features": features,
                "version": "v3",
                "benign_cap": benign_cap,
                "weight_mode": mode
            },
            MODEL_DIR / f"{name}.joblib",
            compress=3
        )

        pd.DataFrame(results).to_csv(
            OUT / "comparison.csv", index=False
        )

        selected = results[-1]
        print(
            f"4% FPR: recall={selected['attack_recall']:.6f}, "
            f"missed={selected['missed_attacks']}, "
            f"macro F1={macro_f1:.6f}, "
            f"AUC={auc:.6f}"
        )

        del model, probabilities, pred_ids, pred_labels
        gc.collect()

    del train_df, X_train
    gc.collect()

comparison = pd.DataFrame(results)

print("\n===== XGBOOST V3 RESULTS =====")

for target in TARGET_FPRS:
    print(f"\nTARGET FPR: {target:.0%}")

    subset = comparison[
        comparison["target_fpr"] == target
    ].sort_values(
        "attack_recall", ascending=False
    )

    print(
        subset[
            [
                "benign_cap", "weight_mode",
                "actual_fpr", "attack_recall",
                "missed_attacks", "macro_f1"
            ]
        ].to_string(index=False)
    )

print("\nResults saved to:", OUT)
