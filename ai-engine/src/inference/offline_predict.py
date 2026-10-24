
from pathlib import Path
import argparse
import hashlib
import json
import time

import joblib
import numpy as np
import pandas as pd
import torch
from torch import nn


CONFIG_FILE = Path("config/fusion_v3_frozen.json")


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


def sha256(path):
    digest = hashlib.sha256()

    with open(path, "rb") as file:
        for chunk in iter(
            lambda: file.read(1024 * 1024), b""
        ):
            digest.update(chunk)

    return digest.hexdigest()


def load_engine():
    config = json.loads(
        CONFIG_FILE.read_text(encoding="utf-8")
    )

    model_files = {
        "xgboost": Path(config["xgboost_model"]),
        "autoencoder": Path(config["autoencoder_model"]),
        "scaler": Path(config["autoencoder_scaler"])
    }

    for name, path in model_files.items():
        if not path.is_file():
            raise FileNotFoundError(path)

        expected = config["sha256"][name]
        actual = sha256(path)

        if actual != expected:
            raise RuntimeError(
                f"Model integrity check failed: {name}"
            )

    xgb_package = joblib.load(model_files["xgboost"])
    xgb_model = xgb_package["model"]
    encoder = xgb_package["encoder"]

    features = list(config["features"])

    if list(xgb_package["features"]) != features:
        raise ValueError("XGBoost feature mismatch")

    checkpoint = torch.load(
        model_files["autoencoder"],
        map_location="cpu",
        weights_only=True
    )

    if list(checkpoint["features"]) != features:
        raise ValueError("Autoencoder feature mismatch")

    ae_model = Autoencoder(len(features))
    ae_model.load_state_dict(
        checkpoint["model_state_dict"]
    )
    ae_model.eval()

    scaler = joblib.load(model_files["scaler"])

    benign_matches = np.flatnonzero(
        encoder.classes_ == "BenignTraffic"
    )

    if len(benign_matches) != 1:
        raise ValueError(
            "BenignTraffic class not found"
        )

    return {
        "config": config,
        "features": features,
        "xgb_model": xgb_model,
        "encoder": encoder,
        "ae_model": ae_model,
        "scaler": scaler,
        "benign_index": int(benign_matches[0])
    }


@torch.no_grad()
def predict_batch(engine, frame):
    features = engine["features"]
    config = engine["config"]

    missing = [
        col for col in features
        if col not in frame.columns
    ]

    if missing:
        raise ValueError(
            f"Missing features: {missing}"
        )

    X = frame[features].to_numpy(
        dtype=np.float32
    )

    if not np.isfinite(X).all():
        raise ValueError(
            "Input contains NaN or infinity"
        )

    # Supervised XGBoost inference
    probabilities = engine["xgb_model"].predict_proba(X)

    predicted_indices = np.argmax(
        probabilities, axis=1
    )

    predicted_classes = engine["encoder"].inverse_transform(
        predicted_indices
    )

    confidence = np.max(probabilities, axis=1)

    xgb_attack_score = (
        1.0 - probabilities[:, engine["benign_index"]]
    )

    # Autoencoder preprocessing
    X_scaled = engine["scaler"].transform(X)

    X_scaled = np.clip(
        X_scaled,
        -config["ae_input_clip_value"],
        config["ae_input_clip_value"]
    ).astype(np.float32)

    tensor = torch.from_numpy(X_scaled)

    reconstructed = engine["ae_model"](tensor)

    errors = torch.mean(
        (tensor - reconstructed) ** 2,
        dim=1
    ).numpy()

    ae_score = np.clip(
        errors / config["ae_scale"],
        0.0,
        1.0
    )

    fusion_score = (
        config["xgboost_weight"] * xgb_attack_score
        + config["autoencoder_weight"] * ae_score
    )

    detected = (
        fusion_score > config["decision_threshold"]
    )

    results = pd.DataFrame({
        "predicted_class": predicted_classes,
        "confidence": confidence,
        "xgb_attack_score": xgb_attack_score,
        "ae_reconstruction_error": errors,
        "ae_score": ae_score,
        "behavior_risk": fusion_score,
        "detected_attack": detected
    })

    if "label" in frame.columns:
        results.insert(
            0,
            "actual_label",
            frame["label"].to_numpy()
        )

        results["correct_class"] = (
            results["actual_label"]
            == results["predicted_class"]
        )

        results["correct_binary"] = (
            (results["actual_label"] != "BenignTraffic")
            == results["detected_attack"]
        )

    return results


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--input",
        default="datasets/processed/splits/test.csv"
    )

    parser.add_argument(
        "--rows",
        type=int,
        default=20
    )

    parser.add_argument(
        "--output",
        default="results/offline_demo/predictions.csv"
    )

    args = parser.parse_args()

    if args.rows <= 0:
        raise ValueError("--rows must be positive")

    torch.set_num_threads(4)

    print("\nLoading frozen Fusion v3 engine...")

    start = time.perf_counter()
    engine = load_engine()
    loading_time = time.perf_counter() - start

    print(f"Model loading time: {loading_time:.3f} s")
    print("Features:", len(engine["features"]))
    print(
        "Decision threshold:",
        engine["config"]["decision_threshold"]
    )

    print("\nReading network-flow records...")

    frame = pd.read_csv(
        args.input,
        nrows=args.rows
    )

    if frame.empty:
        raise ValueError("Input CSV is empty")

    # Warm-up prediction
    predict_batch(engine, frame.iloc[:1])

    print("\nRunning model inference...")

    start = time.perf_counter()
    results = predict_batch(engine, frame)
    elapsed = time.perf_counter() - start

    results.insert(
        0,
        "source_row",
        np.arange(len(results))
    )

    output_path = Path(args.output)
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    results.to_csv(output_path, index=False)

    print("\n===== OFFLINE DETECTION RESULTS =====")

    display_columns = [
        "source_row",
        "predicted_class",
        "confidence",
        "behavior_risk",
        "detected_attack"
    ]

    if "actual_label" in results.columns:
        display_columns.insert(1, "actual_label")

    print(
        results[display_columns]
        .to_string(index=False)
    )

    print("\n===== PERFORMANCE =====")
    print("Records:", len(results))
    print(f"Total inference time: {elapsed:.6f} s")
    print(
        f"Average latency: "
        f"{elapsed / len(results) * 1000:.4f} ms/record"
    )
    print(
        f"Throughput: "
        f"{len(results) / elapsed:.2f} records/second"
    )

    if "correct_class" in results.columns:
        print(
            "Multiclass accuracy (sample):",
            f"{results['correct_class'].mean():.4%}"
        )

        print(
            "Binary accuracy (sample):",
            f"{results['correct_binary'].mean():.4%}"
        )

    print("\nSaved predictions to:", output_path)


if __name__ == "__main__":
    main()
