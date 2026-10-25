"""
attacker.py — Label Poisoning Attack Simulator

Plays a compromised FL client: takes its local training data and relabels a share
of the ATTACK rows as BENIGN before the training round, so the model learns that
attack traffic is normal.

    python attacker.py --input data/test.csv --output data/poisoned.csv

Writes the poisoned CSV to --output and the answer key (exactly which rows were
flipped) to data/poison_log.json. niidlsd.py --mode detect grades itself against it.

Flipped rows get the SAME benign label the file already uses ('BenignTraffic' in
Member 2's data, 'BENIGN' in the MERGED version) — otherwise Member 2's training
code, which selects label == "BenignTraffic", would never see the poison.

Full research version (targeted mode, custom rates): attacker_full_backup.py.

Author: IT23195370
"""

import argparse
import json
import os
import random
import time

import pandas as pd

# ════════════════════════════════════════════════════════
# CONFIGURATION
# ════════════════════════════════════════════════════════
FLIP_RATE  = 0.10                                  # share of attack rows relabelled BENIGN
SEED       = 42                                    # same seed → same rows flipped every run
POISON_LOG = os.path.join("data", "poison_log.json")


def detect_schema(df):
    """(label column, benign value) for this file."""
    col = "Label" if "Label" in df.columns else ("label" if "label" in df.columns else None)
    if col is None:
        raise SystemExit("No 'Label' or 'label' column found")
    values = set(df[col].astype(str).unique())
    for v in ("BenignTraffic", "BENIGN"):
        if v in values:
            return col, v
    for v in values:
        if v.strip().upper() in ("BENIGN", "BENIGNTRAFFIC"):
            return col, v
    raise SystemExit(f"No benign label found in column '{col}'")


def main():
    ap = argparse.ArgumentParser(description="Label poisoning attack simulator")
    ap.add_argument("--input", required=True, help="Clean CSV (the client's training round)")
    ap.add_argument("--output", required=True, help="Where to write the poisoned CSV")
    args = ap.parse_args()

    print("\n" + "=" * 55)
    print("  ATTACKER — Label Poisoning Simulator")
    print(f"  Flipping {FLIP_RATE*100:g}% of attack rows → BENIGN  (seed {SEED})")
    print("=" * 55 + "\n")

    start = time.time()
    df = pd.read_csv(args.input)
    label_col, benign = detect_schema(df)
    print(f"  Loaded {len(df):,} rows  ({time.time()-start:.1f}s)")
    print(f"  Label column '{label_col}', benign value '{benign}'")

    random.seed(SEED)
    attack_rows = df[df[label_col] != benign].index.tolist()
    flip = random.sample(attack_rows, int(len(attack_rows) * FLIP_RATE))
    print(f"  Attack rows: {len(attack_rows):,}   →   flipping {len(flip):,}")

    before = df.loc[flip, [label_col] + (["device_type"] if "device_type" in df else [])].copy()
    df.loc[flip, label_col] = benign

    for path in (args.output, POISON_LOG):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    df.to_csv(args.output, index=False)

    with open(POISON_LOG, "w") as f:
        json.dump({
            "poisoned_csv":    args.output,
            "clean_csv":       args.input,
            "rows":            len(df),
            "flip_rate":       FLIP_RATE,
            "seed":            SEED,
            "label_column":    label_col,
            "benign_value":    benign,
            "total_flipped":   len(flip),
            "flipped_indices": [int(i) for i in flip],
            "original_labels": {int(i): str(l) for i, l in before[label_col].items()},
        }, f, indent=2)

    print(f"\n  Saved poisoned data: {args.output}")
    print(f"  Saved answer key:    {POISON_LOG}")

    print("\n  Flipped, by original label:")
    for label, n in before[label_col].value_counts().items():
        print(f"    {label:<32} {n:>8,}")
    if "device_type" in before:
        print("\n  Flipped, by device:")
        for dev, n in before["device_type"].value_counts().items():
            print(f"    {dev:<32} {n:>8,}")

    print(f"\n  Next: python niidlsd.py --mode detect --input {args.output} "
          f"--output data/cleaned.csv\n")


if __name__ == "__main__":
    main()
