"""
split.py — train/test split for HB-NIID-LSD experiments

Learn mode must NOT see the rows the detector is judged on, otherwise the
history has already "seen the exam paper". This splits the dataset into:
  data/train.csv  → python niidlsd.py --mode learn --input data/train.csv
  data/test.csv   → python attacker.py --input data/test.csv ...
                    python niidlsd.py --mode detect --input data/poisoned_dataset.csv ...

Stratified by (device_type, Label) so every device/label mix keeps its ratio
in both halves (important: smart_lock has only 42 benign rows).

Usage:
  python split.py --input dataset_with_devices.csv --test-size 0.3 --seed 42

Changelog (24 Oct 2026): works with Member 2's Kaggle schema ('label', 'BenignTraffic').

Author: IT23195370
"""

import argparse
import os
import time
import numpy as np
import pandas as pd


def main():
    ap = argparse.ArgumentParser(description="Stratified train/test split")
    ap.add_argument("--input", required=True)
    ap.add_argument("--test-size", type=float, default=0.30)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--outdir", default="data")
    args = ap.parse_args()

    t = time.time()
    df = pd.read_csv(args.input)
    print(f"Loaded {len(df):,} rows ({time.time()-t:.1f}s)")

    # Works with both CICIoT2023 versions: MERGED 'Label' / Kaggle 'label'
    label_col = "Label" if "Label" in df.columns else "label"
    is_benign = df[label_col].astype(str).str.upper().isin(["BENIGN", "BENIGNTRAFFIC"])

    rng = np.random.default_rng(args.seed)
    test_mask = np.zeros(len(df), dtype=bool)

    # Stratify: within each (device_type, Label) group, send test_size of rows to test
    for _, idx in df.groupby(["device_type", label_col]).indices.items():
        n_test = int(round(len(idx) * args.test_size))
        if n_test:
            test_mask[rng.choice(idx, n_test, replace=False)] = True

    os.makedirs(args.outdir, exist_ok=True)
    train_path = os.path.join(args.outdir, "train.csv")
    test_path  = os.path.join(args.outdir, "test.csv")

    # index=False + fresh 0..n-1 order → poison_log indices line up with detect mode
    tr, te = df[~test_mask], df[test_mask]
    tr.to_csv(train_path, index=False)
    te.to_csv(test_path, index=False)
    print(f"\nTrain: {len(tr):,} rows → {train_path}")
    print(f"Test:  {len(te):,} rows → {test_path}")

    print(f"\n  {'device':<14}{'train':>10}{'train_ben':>11}{'test':>10}{'test_ben':>10}")
    ben_tr, ben_te = is_benign[~test_mask], is_benign[test_mask]
    for dev in sorted(df["device_type"].unique()):
        a = (tr.device_type == dev).to_numpy()
        b = (te.device_type == dev).to_numpy()
        print(f"  {dev:<14}{a.sum():>10,}{(a & ben_tr.to_numpy()).sum():>11,}"
              f"{b.sum():>10,}{(b & ben_te.to_numpy()).sum():>10,}")

    print("\nNext:")
    print(f"  python niidlsd.py --mode learn  --input {train_path}")
    print(f"  python attacker.py --input {test_path} --output {os.path.join(args.outdir, 'poisoned.csv')}")
    print(f"  python niidlsd.py --mode detect --input {os.path.join(args.outdir, 'poisoned.csv')} "
          f"--output {os.path.join(args.outdir, 'cleaned.csv')}")

if __name__ == "__main__":
    main()
