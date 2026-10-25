"""
impact_autoencoder.py
Does the label swap detector actually protect Member 2's model?

Trains Member 2's Autoencoder v1 — EXACT recipe from
ai-engine/src/training/train_autoencoder_v1.py (same architecture, RobustScaler
fit on benign-labelled rows, clip ±10, MSE, Adam 1e-3, batch 512, 30 epochs,
seed 42) — once per training set, then evaluates every model on the same
untouched evaluation set (Member 2's validation.csv).

Why the Autoencoder: it trains ONLY on rows labelled benign, so every
attack→BenignTraffic flip lands straight in its training data and teaches it
that attack traffic is "normal".

Usage:
  python impact_autoencoder.py \
      --train clean=data/m2/round.csv \
      --train poisoned=data/m2/poisoned.csv \
      --train cleaned=data/m2/cleaned.csv \
      --eval  ../ai-engine/datasets/processed/splits/validation.csv \
      --out   results/impact_ae

Reports per training set:
  - ROC AUC / PR AUC                         (threshold-free)
  - attack recall at a fixed benign FPR       (fair comparison, threshold set on eval benign)
  - attack recall at Member 2's own threshold rule (quantile of TRAINING benign errors —
    what a real operator would do, so a poisoned training set also poisons the threshold)
  - per-class recall at the fixed FPR          (which attacks the model went blind to)

Author: IT23195370
"""

import argparse
import json
import os
import random
import time

import numpy as np
import pandas as pd
import torch
from torch import nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import roc_auc_score, average_precision_score

# Member 2's 44 features — config/fusion_v3_frozen.json (Telnet, IRC dropped)
FEATURES = [
    "flow_duration", "Header_Length", "Protocol Type", "Duration", "Rate",
    "Srate", "Drate", "fin_flag_number", "syn_flag_number", "rst_flag_number",
    "psh_flag_number", "ack_flag_number", "ece_flag_number", "cwr_flag_number",
    "ack_count", "syn_count", "fin_count", "urg_count", "rst_count",
    "HTTP", "HTTPS", "DNS", "SMTP", "SSH", "TCP", "UDP", "DHCP", "ARP",
    "ICMP", "IPv", "LLC", "Tot sum", "Min", "Max", "AVG", "Std", "Tot size",
    "IAT", "Number", "Magnitue", "Radius", "Covariance", "Variance", "Weight",
]

# Member 2's hyper-parameters
SEED          = 42
BATCH_SIZE    = 512
EPOCHS        = 30
LEARNING_RATE = 0.001
CLIP_VALUE    = 10.0
CHUNK_SIZE    = 200_000


class Autoencoder(nn.Module):
    """Identical to Member 2's Autoencoder v1."""
    def __init__(self, input_dim):
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(input_dim, 32), nn.ReLU(),
            nn.Linear(32, 16), nn.ReLU(),
            nn.Linear(16, 8), nn.ReLU(),
            nn.Linear(8, 16), nn.ReLU(),
            nn.Linear(16, 32), nn.ReLU(),
            nn.Linear(32, input_dim),
        )

    def forward(self, x):
        return self.network(x)


# ════════════════════════════════════════════════════════
# DATA
# ════════════════════════════════════════════════════════

def label_column(path):
    cols = list(pd.read_csv(path, nrows=0).columns)
    missing = [f for f in FEATURES if f not in cols]
    if missing:
        raise ValueError(f"{path} is missing Member 2 features: {missing}")
    for c in ("label", "Label"):
        if c in cols:
            return c
    raise ValueError(f"No label column in {path}")


def is_benign(series):
    return series.astype(str).str.strip().str.upper().isin(["BENIGN", "BENIGNTRAFFIC"])


def load_benign_rows(path):
    """Rows LABELLED benign — exactly what Member 2's training script selects."""
    lc = label_column(path)
    parts, total = [], 0
    for chunk in pd.read_csv(path, usecols=FEATURES + [lc], chunksize=CHUNK_SIZE):
        total += len(chunk)
        b = chunk[is_benign(chunk[lc])]
        if len(b):
            parts.append(b[FEATURES].to_numpy(dtype=np.float32))
    X = np.concatenate(parts) if parts else np.empty((0, len(FEATURES)), np.float32)
    return X, total


def load_eval(path, max_rows=None):
    lc = label_column(path)
    Xs, labels = [], []
    n = 0
    for chunk in pd.read_csv(path, usecols=FEATURES + [lc], chunksize=CHUNK_SIZE):
        if max_rows and n >= max_rows:
            break
        if max_rows:
            chunk = chunk.iloc[: max_rows - n]
        Xs.append(chunk[FEATURES].to_numpy(dtype=np.float32))
        labels.append(chunk[lc].astype(str).to_numpy())
        n += len(chunk)
    X = np.concatenate(Xs)
    y_label = np.concatenate(labels)
    y_attack = ~pd.Series(y_label).str.strip().str.upper().isin(
        ["BENIGN", "BENIGNTRAFFIC"]).to_numpy()
    return X, y_label, y_attack


# ════════════════════════════════════════════════════════
# MODEL
# ════════════════════════════════════════════════════════

def set_seed(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def train_autoencoder(X_benign, epochs, seed):
    set_seed(seed)                      # same init + same shuffling for every run

    scaler = RobustScaler()
    X = np.clip(scaler.fit_transform(X_benign), -CLIP_VALUE, CLIP_VALUE).astype(np.float32)

    model = Autoencoder(len(FEATURES))
    loader = DataLoader(TensorDataset(torch.from_numpy(X)),
                        batch_size=BATCH_SIZE, shuffle=True, num_workers=0)
    optimizer = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE)
    loss_fn = nn.MSELoss()

    losses = []
    for epoch in range(epochs):
        model.train()
        tot, cnt = 0.0, 0
        for (batch,) in loader:
            rec = model(batch)
            loss = loss_fn(rec, batch)
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            tot += loss.item() * len(batch)
            cnt += len(batch)
        losses.append(tot / cnt)
        if epoch == 0 or (epoch + 1) % 10 == 0:
            print(f"      epoch {epoch+1:02d}/{epochs}  loss {losses[-1]:.6f}")
    return model, scaler, losses


@torch.no_grad()
def reconstruction_errors(model, scaler, X):
    model.eval()
    out = []
    for i in range(0, len(X), 8192):
        x = np.clip(scaler.transform(X[i:i + 8192]), -CLIP_VALUE, CLIP_VALUE).astype(np.float32)
        t = torch.from_numpy(x)
        out.append(torch.mean((t - model(t)) ** 2, dim=1).numpy())
    return np.concatenate(out)


# ════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(description="Autoencoder impact experiment")
    ap.add_argument("--train", action="append", required=True, metavar="NAME=CSV",
                    help="Training set (repeat). Rows labelled benign are used, like Member 2's script.")
    ap.add_argument("--eval", required=True, help="Untouched evaluation CSV (Member 2's validation.csv)")
    ap.add_argument("--eval-rows", type=int, default=None, help="Use only the first N eval rows")
    ap.add_argument("--epochs", type=int, default=EPOCHS)
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--fpr", type=float, nargs="+", default=[0.01, 0.05],
                    help="Benign false-positive rates to compare recall at")
    ap.add_argument("--quantile", type=float, nargs="+", default=[0.95, 0.99],
                    help="Member 2's threshold rule: quantile of TRAINING benign errors")
    ap.add_argument("--out", default="results/impact_ae")
    ap.add_argument("--save-models", action="store_true")
    args = ap.parse_args()

    sets = []
    for item in args.train:
        if "=" not in item:
            raise SystemExit(f"--train expects NAME=CSV, got {item!r}")
        name, path = item.split("=", 1)
        sets.append((name.strip(), path.strip()))

    os.makedirs(args.out, exist_ok=True)
    torch.set_num_threads(4)

    print("=" * 62)
    print("  IMPACT EXPERIMENT — Member 2's Autoencoder v1")
    print("=" * 62)

    print(f"\nLoading evaluation set: {args.eval}")
    t = time.time()
    X_eval, y_label, y_attack = load_eval(args.eval, args.eval_rows)
    n_ben, n_att = int((~y_attack).sum()), int(y_attack.sum())
    print(f"  {len(X_eval):,} rows  |  benign {n_ben:,}  |  attack {n_att:,}  ({time.time()-t:.1f}s)")
    if not np.isfinite(X_eval).all():
        raise SystemExit("Eval set contains NaN/inf — Member 2's pipeline rejects these too")

    results, per_class = [], {}
    main_fpr = max(args.fpr)

    for name, path in sets:
        print(f"\n[{name}] {path}")
        t = time.time()
        X_tr, n_rows = load_benign_rows(path)
        print(f"  rows labelled benign: {len(X_tr):,} of {n_rows:,}  ({time.time()-t:.1f}s)")
        if len(X_tr) < 100:
            print("  SKIP: fewer than 100 benign-labelled rows")
            continue
        if not np.isfinite(X_tr).all():
            keep = np.isfinite(X_tr).all(axis=1)
            print(f"  dropping {int((~keep).sum()):,} rows with NaN/inf")
            X_tr = X_tr[keep]

        t = time.time()
        model, scaler, losses = train_autoencoder(X_tr, args.epochs, args.seed)
        train_s = time.time() - t
        print(f"  trained in {train_s:.1f}s")

        train_err = reconstruction_errors(model, scaler, X_tr)
        err = reconstruction_errors(model, scaler, X_eval)
        ben_err, att_err = err[~y_attack], err[y_attack]

        row = {
            "train_set": name,
            "train_csv": path,
            "benign_labelled_rows": int(len(X_tr)),
            "final_loss": losses[-1],
            "train_seconds": round(train_s, 1),
            "roc_auc": float(roc_auc_score(y_attack, err)),
            "pr_auc": float(average_precision_score(y_attack, err)),
        }

        for fpr in args.fpr:
            thr = float(np.quantile(ben_err, 1 - fpr))
            det = err > thr
            row[f"recall@fpr{fpr:g}"] = float(det[y_attack].mean())
            row[f"missed@fpr{fpr:g}"] = int((~det[y_attack]).sum())
            if fpr == main_fpr:
                s = pd.Series(det[y_attack]).groupby(y_label[y_attack]).mean()
                per_class[name] = s

        for q in args.quantile:
            thr = float(np.quantile(train_err, q))
            det = err > thr
            row[f"q{q:g}_threshold"] = thr
            row[f"q{q:g}_recall"] = float(det[y_attack].mean())
            row[f"q{q:g}_fpr"] = float(det[~y_attack].mean())

        results.append(row)
        print(f"  ROC AUC {row['roc_auc']:.4f}  |  recall@{main_fpr:g} FPR "
              f"{row[f'recall@fpr{main_fpr:g}']*100:.2f}%")

        if args.save_models:
            torch.save({"model_state_dict": model.state_dict(), "features": FEATURES,
                        "clip_value": CLIP_VALUE, "train_set": name},
                       os.path.join(args.out, f"autoencoder_{name}.pt"))

    if not results:
        raise SystemExit("No training set could be used")

    # ── Summary ──────────────────────────────────────────
    df = pd.DataFrame(results)
    df.to_csv(os.path.join(args.out, "summary.csv"), index=False)
    with open(os.path.join(args.out, "summary.json"), "w") as f:
        json.dump({"eval_csv": args.eval, "eval_rows": len(X_eval),
                   "eval_benign": n_ben, "eval_attack": n_att,
                   "epochs": args.epochs, "seed": args.seed, "results": results}, f, indent=2)

    print("\n" + "=" * 62)
    print("  RESULTS  (same eval set for every model)")
    print("=" * 62)
    hdr = f"  {'train set':<12}{'benign rows':>12}{'ROC AUC':>9}"
    for fpr in args.fpr:
        hdr += f"{'rec@' + format(fpr*100, 'g') + '%FPR':>13}"
    for q in args.quantile:
        hdr += f"{'q' + format(q, 'g') + ' rec/FPR':>17}"
    print(hdr)
    for r in results:
        line = f"  {r['train_set']:<12}{r['benign_labelled_rows']:>12,}{r['roc_auc']:>9.4f}"
        for fpr in args.fpr:
            line += f"{r[f'recall@fpr{fpr:g}']*100:>12.2f}%"
        for q in args.quantile:
            line += f"{r[f'q{q:g}_recall']*100:>9.1f}%/{r[f'q{q:g}_fpr']*100:>5.1f}%"
        print(line)

    print(f"\n  Missed attacks at {main_fpr*100:g}% benign FPR "
          f"(out of {n_att:,}):")
    for r in results:
        print(f"    {r['train_set']:<12}{r[f'missed@fpr{main_fpr:g}']:>12,}")

    if per_class:
        pc = pd.DataFrame(per_class)
        pc.index.name = "attack_class"
        pc.to_csv(os.path.join(args.out, "per_class_recall.csv"))
        names = list(per_class)
        if len(names) >= 2:
            ref, worst = names[0], min(names, key=lambda n: results[names.index(n)]["roc_auc"])
            if worst != ref:
                drop = (pc[ref] - pc[worst]).sort_values(ascending=False).head(8)
                print(f"\n  Biggest per-class recall drops at {main_fpr*100:g}% FPR "
                      f"('{ref}' → '{worst}'):")
                for cls, d in drop.items():
                    line = f"    {cls:<28}"
                    for n in names:
                        line += f"{n}={pc.at[cls, n]*100:5.1f}%  "
                    print(line)

    print(f"\n  Saved: {args.out}/summary.csv, summary.json, per_class_recall.csv")


if __name__ == "__main__":
    main()
