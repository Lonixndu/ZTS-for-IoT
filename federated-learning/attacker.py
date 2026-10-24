"""
attacker.py
Label Poisoning Attack Simulator

Simulates a compromised FL client that flips attack labels → BENIGN
before the local training round, to poison the federated model.

Usage:
  python attacker.py --input dataset_with_devices.csv --mode random
  python attacker.py --input dataset_with_devices.csv --mode targeted \
         --device camera --attack DDOS-HTTP_FLOOD

Outputs:
  data/poisoned_dataset.csv   — modified dataset with flipped labels
  data/poison_log.json        — exact indices flipped (for detector verification)

Author: IT23195370
"""

import pandas as pd
import json
import argparse
import random
import os
import time

# ── Config ───────────────────────────────────────────────────────────
OUTPUT_CSV  = "data/poisoned_dataset.csv"
OUTPUT_LOG  = "data/poison_log.json"
FLIP_RATE   = 0.10    # flip 10% of eligible attack rows

BENIGN_LABEL = "BENIGN"


def run_attack(args):
    os.makedirs("data", exist_ok=True)

    print(f"\n{'='*55}")
    print(f"  ATTACKER — Label Poisoning Simulator")
    print(f"  Mode: {args.mode.upper()}")
    print(f"{'='*55}\n")

    print(f"Loading: {args.input}")
    start = time.time()
    df = pd.read_csv(args.input)
    print(f"  Loaded {len(df):,} rows  ({time.time()-start:.1f}s)\n")

    attack_mask = df["Label"] != BENIGN_LABEL

    if args.mode == "random":
        eligible_indices = df[attack_mask].index.tolist()
        n_flip = int(len(eligible_indices) * FLIP_RATE)
        flip_indices = random.sample(eligible_indices, n_flip)

        print(f"  Total attack rows:  {len(eligible_indices):,}")
        print(f"  Flip rate:          {FLIP_RATE*100:.0f}%")
        print(f"  Rows to flip:       {n_flip:,}")

    elif args.mode == "targeted":
        if not args.device or not args.attack:
            print("ERROR: --mode targeted requires --device and --attack")
            print("  Example: --device camera --attack DDOS-HTTP_FLOOD")
            return

        targeted_mask = (
            attack_mask &
            (df["device_type"] == args.device) &
            (df["Label"] == args.attack)
        )
        eligible_indices = df[targeted_mask].index.tolist()

        if not eligible_indices:
            print(f"ERROR: No rows found for device={args.device}, label={args.attack}")
            return

        n_flip = int(len(eligible_indices) * FLIP_RATE)
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
    poisoned_df = df.copy()
    original_labels = {int(idx): str(df.at[idx, "Label"]) for idx in flip_indices}
    poisoned_df.loc[flip_indices, "Label"] = BENIGN_LABEL

    # ── Save poisoned dataset ─────────────────────────────────────────
    poisoned_df.to_csv(OUTPUT_CSV, index=False)
    print(f"\n  Saved poisoned dataset: {OUTPUT_CSV}")

    # ── Save poison log ───────────────────────────────────────────────
    log = {
        "mode":            args.mode,
        "flip_rate":       FLIP_RATE,
        "total_flipped":   len(flip_indices),
        "flipped_indices": [int(i) for i in flip_indices],
        "original_labels": original_labels,
        "device_filter":   args.device  if args.mode == "targeted" else "all",
        "attack_filter":   args.attack  if args.mode == "targeted" else "all",
    }
    with open(OUTPUT_LOG, "w") as f:
        json.dump(log, f, indent=2)
    print(f"  Saved poison log:       {OUTPUT_LOG}")

    # ── Summary ───────────────────────────────────────────────────────
    print(f"\n{'='*55}")
    print(f"  ATTACK COMPLETE")
    print(f"{'='*55}")
    print(f"  Rows flipped (attack -> BENIGN): {len(flip_indices):,}")

    flipped_df = df.loc[flip_indices]
    print(f"\n  Flipped label breakdown:")
    for label, count in flipped_df["Label"].value_counts().items():
        print(f"    {label:<40} {count:>6,}")

    print(f"\n  Flipped device breakdown:")
    for dtype, count in flipped_df["device_type"].value_counts().items():
        print(f"    {dtype:<20} {count:>6,}")

    print(f"\n  Now run the detector:")
    print(f"    python niidlsd.py --mode detect \\")
    print(f"           --input data/poisoned_dataset.csv \\")
    print(f"           --output data/clean_output.csv \\")
    print(f"           --log    data/poison_log.json")
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Label poisoning attack simulator")
    parser.add_argument("--input",  required=True,        help="Path to dataset_with_devices.csv")
    parser.add_argument("--mode",   default="random",     help="random | targeted")
    parser.add_argument("--device", default=None,         help="[targeted] device type to attack")
    parser.add_argument("--attack", default=None,         help="[targeted] exact attack label to flip")
    parser.add_argument("--seed",   type=int, default=42, help="Random seed for reproducibility")
    args = parser.parse_args()

    random.seed(args.seed)
    run_attack(args)
