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

    rng = np.random.default_rng(args.seed)
    test_mask = np.zeros(len(df), dtype=bool)

    # Stratify: within each (device_type, Label) group, send test_size of rows to test
    for _, idx in df.groupby(["device_type", "Label"]).indices.items():
        n_test = int(round(len(idx) * args.test_size))
        if n_test:
            test_mask[rng.choice(idx, n_test, replace=False)] = True

    os.makedirs(args.outdir, exist_ok=True)
    train_path = os.path.join(args.outdir, "train.csv")
    test_path  = os.path.join(args.outdir, "test.csv")

    # index=False + fresh 0..n-1 order → poison_log indices line up with detect mode
    df[~test_mask].to_csv(train_path, index=False)
    df[test_mask].to_csv(test_path, index=False)

    tr, te = df[~test_mask], df[test_mask]
    print(f"\nTrain: {len(tr):,} rows → {train_path}")
    print(f"Test:  {len(te):,} rows → {test_path}")

    print(f"\n  {'device':<14}{'train':>10}{'train_ben':>11}{'test':>10}{'test_ben':>10}")
    for dev in sorted(df["device_type"].unique()):
        a = tr[tr.device_type == dev]
        b = te[te.device_type == dev]
        print(f"  {dev:<14}{len(a):>10,}{(a.Label=='BENIGN').sum():>11,}"
              f"{len(b):>10,}{(b.Label=='BENIGN').sum():>10,}")

    print("\nNext:")
    print(f"  python niidlsd.py --mode learn  --input {train_path}")
    print(f"  python attacker.py --input {test_path} --mode random --seed 42")
    print(f"  python niidlsd.py --mode detect --input data/poisoned_dataset.csv \\")
    print(f"         --output data/clean_output.csv --log data/poison_log.json")


if __name__ == "__main__":
    main()
