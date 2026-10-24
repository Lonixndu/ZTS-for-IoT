
from pathlib import Path
import json
import random
import time

import joblib
import numpy as np
import pandas as pd
import torch
from torch import nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import (
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
)

SEED = 42
CHUNK_SIZE = 100_000
BATCH_SIZE = 512
EPOCHS = 30
LEARNING_RATE = 0.001

TRAIN_FILE = Path("datasets/processed/splits/train.csv")
VAL_FILE = Path("datasets/processed/splits/validation.csv")

MODEL_DIR = Path("models")
RESULT_DIR = Path("results/autoencoder_v1")

MODEL_DIR.mkdir(exist_ok=True)
RESULT_DIR.mkdir(parents=True, exist_ok=True)

random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)
torch.set_num_threads(4)

device = torch.device("cpu")

# --------------------------------------------------
# 1. Load benign training records only
# --------------------------------------------------

print("Loading benign training traffic...")

benign_chunks = []

for chunk in pd.read_csv(
    TRAIN_FILE,
    chunksize=CHUNK_SIZE
):
    benign = chunk[
        chunk["label"] == "BenignTraffic"
    ]

    if not benign.empty:
        benign_chunks.append(benign)

train_df = pd.concat(
    benign_chunks,
    ignore_index=True
)

features = [
    c for c in train_df.columns if c != "label"
]

print("Benign training records:", len(train_df))
print("Features:", len(features))

# --------------------------------------------------
# 2. Fit scaler on benign training data only
# --------------------------------------------------

X_raw = train_df[features].to_numpy(
    dtype=np.float32
)

scaler = RobustScaler()
X_scaled = scaler.fit_transform(X_raw)

# Limit extreme scaled values for stable training.
# Apply exactly the same clipping during inference.
CLIP_VALUE = 10.0

X_scaled = np.clip(
    X_scaled, -CLIP_VALUE, CLIP_VALUE
).astype(np.float32)

# --------------------------------------------------
# 3. Define Autoencoder
# --------------------------------------------------

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


model = Autoencoder(len(features)).to(device)

dataset = TensorDataset(
    torch.from_numpy(X_scaled)
)

loader = DataLoader(
    dataset,
    batch_size=BATCH_SIZE,
    shuffle=True,
    num_workers=0
)

optimizer = torch.optim.Adam(
    model.parameters(),
    lr=LEARNING_RATE
)

loss_function = nn.MSELoss()

# --------------------------------------------------
# 4. Train on benign traffic
# --------------------------------------------------

print("\nTraining Autoencoder v1...")

start = time.perf_counter()
loss_history = []

for epoch in range(EPOCHS):
    model.train()

    total_loss = 0.0
    total_samples = 0

    for (batch,) in loader:
        batch = batch.to(device)

        reconstructed = model(batch)
        loss = loss_function(reconstructed, batch)

        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

        total_loss += loss.item() * len(batch)
        total_samples += len(batch)

    epoch_loss = total_loss / total_samples
    loss_history.append(epoch_loss)

    print(
        f"Epoch {epoch + 1:02d}/{EPOCHS} "
        f"- Loss: {epoch_loss:.6f}"
    )

training_seconds = time.perf_counter() - start

# --------------------------------------------------
# 5. Calculate reconstruction errors
# --------------------------------------------------

@torch.no_grad()
def reconstruction_errors(frame):
    model.eval()
    all_errors = []

    for begin in range(0, len(frame), 8192):
        part = frame.iloc[begin:begin + 8192]

        X = part[features].to_numpy(
            dtype=np.float32
        )

        X = scaler.transform(X)

        X = np.clip(
            X, -CLIP_VALUE, CLIP_VALUE
        ).astype(np.float32)

        tensor = torch.from_numpy(X).to(device)
        reconstructed = model(tensor)

        error = torch.mean(
            (tensor - reconstructed) ** 2,
            dim=1
        )

        all_errors.append(
            error.cpu().numpy()
        )

    return np.concatenate(all_errors)


print("\nCalculating benign training errors...")

train_errors = reconstruction_errors(train_df)

# A preliminary threshold based only on training data.
threshold_99 = float(
    np.quantile(train_errors, 0.99)
)

print("Training 99th-percentile threshold:", threshold_99)

# --------------------------------------------------
# 6. Evaluate on validation partition
# --------------------------------------------------

print("\nEvaluating validation data...")

validation_errors = []
validation_labels = []

for chunk in pd.read_csv(
    VAL_FILE,
    chunksize=CHUNK_SIZE
):
    errors = reconstruction_errors(chunk)

    validation_errors.append(errors)

    validation_labels.append(
        (chunk["label"] != "BenignTraffic")
        .astype(np.int8)
        .to_numpy()
    )

scores = np.concatenate(validation_errors)
y_true = np.concatenate(validation_labels)

# Evaluate a set of training-benign quantile thresholds.
# Do not use the test partition here.
threshold_results = []

for quantile in [0.95, 0.97, 0.99, 0.995, 0.999]:
    threshold = float(
        np.quantile(train_errors, quantile)
    )

    y_pred = (scores > threshold).astype(np.int8)

    tn, fp, fn, tp = confusion_matrix(
        y_true,
        y_pred,
        labels=[0, 1]
    ).ravel()

    threshold_results.append({
        "quantile": quantile,
        "threshold": threshold,
        "tp": int(tp),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "attack_recall": float(
            recall_score(y_true, y_pred)
        ),
        "benign_fpr": float(fp / (fp + tn)),
        "precision": float(
            precision_score(
                y_true, y_pred, zero_division=0
            )
        ),
        "f1": float(
            f1_score(y_true, y_pred, zero_division=0)
        )
    })

# Use 99th-percentile training threshold as the
# initial fixed operating point. We will review
# validation results before choosing a final one.
selected = next(
    r for r in threshold_results
    if r["quantile"] == 0.99
)

roc_auc = float(
    roc_auc_score(y_true, scores)
)

pr_auc = float(
    average_precision_score(y_true, scores)
)

# --------------------------------------------------
# 7. Save artifacts
# --------------------------------------------------

torch.save(
    {
        "model_state_dict": model.state_dict(),
        "input_dim": len(features),
        "features": features,
        "clip_value": CLIP_VALUE,
        "threshold": threshold_99,
        "version": "v1"
    },
    MODEL_DIR / "autoencoder_v1.pt"
)

joblib.dump(
    scaler,
    MODEL_DIR / "autoencoder_scaler_v1.joblib"
)

metrics = {
    "model": "Autoencoder v1",
    "training_records": len(train_df),
    "validation_records": len(y_true),
    "features": len(features),
    "epochs": EPOCHS,
    "training_seconds": training_seconds,
    "final_training_loss": loss_history[-1],
    "roc_auc": roc_auc,
    "average_precision": pr_auc,
    "threshold_experiments": threshold_results,
    "initial_threshold": selected
}

with open(
    RESULT_DIR / "metrics.json",
    "w",
    encoding="utf-8"
) as f:
    json.dump(metrics, f, indent=4)

pd.DataFrame(
    threshold_results
).to_csv(
    RESULT_DIR / "threshold_comparison.csv",
    index=False
)

pd.DataFrame({
    "epoch": range(1, EPOCHS + 1),
    "loss": loss_history
}).to_csv(
    RESULT_DIR / "training_loss.csv",
    index=False
)

print("\n===== AUTOENCODER V1 RESULTS =====")
print("Benign training records:", len(train_df))
print("Validation records:", len(y_true))
print(f"Training time: {training_seconds:.2f} s")
print(f"ROC AUC: {roc_auc:.4f}")
print(f"Average precision: {pr_auc:.4f}")
print(f"Initial threshold: {threshold_99:.6f}")
print(f"Attack recall: {selected['attack_recall']:.4f}")
print(f"Benign FPR: {selected['benign_fpr']:.4f}")
print("Results saved to:", RESULT_DIR)
