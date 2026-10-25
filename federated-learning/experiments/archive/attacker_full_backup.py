"""
attacker.py
Label Poisoning Attack Simulator

Simulates a compromised FL client that flips attack labels → BENIGN
before the local training round, to poison the federated model.

Usage:
  python attacker.py --input dataset_with_devices.csv --mode random
  python attacker.py --input dataset_with_devices.csv --mode targeted \
         --device camera --attack DDOS-HTTP_FLOOD
  python attacker.py --input data/m2/round.csv --flip-rate 0.05 \
         --output data/m2/poisoned_05.csv --log data/m2/poison_log_05.json

Works with both CICIoT2023 versions:
  MERGED (ours):     'Label' column, benign = 'BENIGN'
  Kaggle (Member 2): 'label' column, benign = 'BenignTraffic'
The flipped rows get the SAME benign value the file already uses — otherwise
Member 2's training code (label == "BenignTraffic") would never see the poison.

Outputs (defaults):
  data/poisoned_dataset.csv   — modified dataset with flipped labels
  data/poison_log.json        — exact indices flipped (for detector verification)

Changelog (24 Oct 2026): label column / benign value auto-detected;
  --flip-rate, --output, --log; targeted --attack matching is case-insensitive.

Author: IT23195370
"""

import pandas as pd
import json
import argparse
import random
import os
import time

# ── Defaults ─────────────────────────────────────────────────────────
OUTPUT_CSV  = "data/poisoned_dataset.csv"
OUTPUT_LOG  = "data/poison_log.json"
FLIP_RATE   = 0.10    # flip 10% of eligible attack rows


def detect_schema(df):
    """Returns (label_column, benign_value) for this file."""
    if "Label" in df.columns:
        col = "Label"
    elif "label" in df.columns:
        col = "label"
    else:
        raise ValueError("No 'Label' or 'label' column found")

    values = set(df[col].astype(str).unique())
    for candidate in ("BenignTraffic", "BENIGN"):
        if candidate in values:
            return col, candidate
    for v in values:                         # any casing of the two
        if v.strip().upper() in ("BENIGN", "BENIGNTRAFFIC"):
            return col, v
    raise ValueError(f"No benign label found in column '{col}'")


def run_attack(args):
    for path in (args.output, args.log):
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)

    print(f"\n{'='*55}")
    print(f"  ATTACKER — Label Poisoning Simulator")
    print(f"  Mode: {args.mode.upper()}   |   Flip rate: {args.flip_rate*100:g}%")
    print(f"{'='*55}\n")

    print(f"Loading: {args.input}")
    start = time.time()
    df = pd.read_csv(args.input)
    print(f"  Loaded {len(df):,} rows  ({time.time()-start:.1f}s)")

    label_col, benign = detect_schema(df)
    print(f"  Label column: '{label_col}'   benign value: '{benign}'\n")

    attack_mask = df[label_col] != benign

    if args.mode == "random":
        eligible_indices = df[attack_mask].index.tolist()
        n_flip = int(len(eligible_indices) * args.flip_rate)
        flip_indices = random.sample(eligible_indices, n_flip)

        print(f"  Total attack rows:  {len(eligible_indices):,}")
        print(f"  Rows to flip:       {n_flip:,}")

    elif args.mode == "targeted":
        if not args.device or not args.attack:
            print("ERROR: --mode targeted requires --device and --attack")
            print("  Example: --device camera --attack DDOS-HTTP_FLOOD")
            return
        if "device_type" not in df.columns:
            print("ERROR: targeted mode needs a device_type column (run dataset_builder.py)")
            return

        targeted_mask = (
            attack_mask &
            (df["device_type"] == args.device) &
            (df[label_col].astype(str).str.upper() == args.attack.upper())
        )
        eligible_indices = df[targeted_mask].index.tolist()

        if not eligible_indices:
            print(f"ERROR: No rows found for device={args.device}, label={args.attack}")
            return

        n_flip = int(len(eligible_indices) * args.flip_rate)
        if n_flip == 0:
            n_flip = min(50, len(eligible_indices))
        flip_indices = random.sample(eligible_indices, n_flip)

        print(f"  Target device:      {args.device}")
        print(f"  Target attack:      {args.attack}")
        print(f"  Eligible rows:      {len(eligible_indices):,}")
        print(f"  Rows to flip:       {n_flip:,}")

    else:
        print(f"ERROR: Unknown mode '{args.mode}'. Use 'random' or 'targeted'.")
        return

    # ── Apply flips ───────────────────────────────────────────────────
    original_labels = {int(idx): str(df.at[idx, label_col]) for idx in flip_indices}
    flipped_df = df.loc[flip_indices, [label_col] +
                        (["device_type"] if "device_type" in df.columns else [])].copy()
    df.loc[flip_indices, label_col] = benign      # in place: no 2nd copy of a 1.8M-row frame

    # ── Save poisoned dataset ─────────────────────────────────────────
    df.to_csv(args.output, index=False)
    print(f"\n  Saved poisoned dataset: {args.output}")

    # ── Save poison log ───────────────────────────────────────────────
    log = {
        "mode":            args.mode,
        "flip_rate":       args.flip_rate,
        "seed":            args.seed,
        "label_column":    label_col,
        "benign_value":    benign,
        "total_flipped":   len(flip_indices),
        "flipped_indices": [int(i) for i in flip_indices],
        "original_labels": original_labels,
        "device_filter":   args.device  if args.mode == "targeted" else "all",
        "attack_filter":   args.attack  if args.mode == "targeted" else "all",
    }
    with open(args.log, "w") as f:
        json.dump(log, f, indent=2)
    print(f"  Saved poison log:       {args.log}")

    # ── Summary ───────────────────────────────────────────────────────
    print(f"\n{'='*55}")
    print(f"  ATTACK COMPLETE")
    print(f"{'='*55}")
    print(f"  Rows flipped (attack -> {benign}): {len(flip_indices):,}")

    print(f"\n  Flipped label breakdown:")
    for label, count in flipped_df[label_col].value_counts().items():
        print(f"    {label:<40} {count:>8,}")

    if "device_type" in flipped_df.columns:
        print(f"\n  Flipped device breakdown:")
        for dtype, count in flipped_df["device_type"].value_counts().items():
            print(f"    {dtype:<20} {count:>8,}")

    print(f"\n  Now run the detector:")
    print(f"    python niidlsd.py --mode detect \\")
    print(f"           --input {args.output} \\")
    print(f"           --output data/clean_output.csv \\")
    print(f"           --log    {args.log}")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Label poisoning attack simulator")
    parser.add_argument("--input",  required=True,        help="Input CSV (with device_type)")
    parser.add_argument("--mode",   default="random",     help="random | targeted")
    parser.add_argument("--device", default=None,         help="[targeted] device type to attack")
    parser.add_argument("--attack", default=None,         help="[targeted] attack label to flip")
    parser.add_argument("--flip-rate", type=float, default=FLIP_RATE,
                        help="Share of eligible attack rows to flip (default 0.10)")
    parser.add_argument("--output", default=OUTPUT_CSV,   help="Poisoned CSV path")
    parser.add_argument("--log",    default=OUTPUT_LOG,   help="Poison log path")
    parser.add_argument("--seed",   type=int, default=42, help="Random seed for reproducibility")
    args = parser.parse_args()

    random.seed(args.seed)
    run_attack(args)
