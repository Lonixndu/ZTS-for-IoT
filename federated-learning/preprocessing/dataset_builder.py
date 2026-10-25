"""
dataset_builder.py
Adds a 'device_type' column to a CICIoT2023 CSV
based on dominant protocol columns.

Usage:
    python dataset_builder.py --input merged.csv --output dataset_with_devices.csv
    python dataset_builder.py --input ../ai-engine/datasets/processed/splits/train.csv \
                              --output data/m2/train_devices.csv

Works with both CICIoT2023 versions (MERGED 'Label' / Kaggle 'label').
Member 2's splits drop Telnet and IRC (constant 0) — missing protocol
columns are treated as 0.

Changelog (24 Oct 2026): vectorised (same rules, same priority, ~50x faster),
  writes chunk-by-chunk (no full dataset in memory), label column auto-detected.
"""

import argparse
import os
import time
from collections import Counter

import numpy as np
import pandas as pd


# ── Device type assignment logic ─────────────────────────
# Priority order matters — first matching rule wins:
#   SSH/DNS/DHCP → router      (management protocols, routers use these legitimately)
#   HTTP/HTTPS   → camera      (web interface traffic, IP cameras use these)
#   ICMP/ARP     → sensor      (low-level network protocols, IoT sensors ping/arp)
#   UDP, no TCP  → smart_lock  (closest proxy to MQTT in CICIoT)
#   TCP          → generic_iot (TCP-only flows, no application protocol identified)
#   otherwise    → unknown
#
# Real deployment: device_type comes from Member 3's blockchain registry via IP lookup.
# POC: derived from protocol columns since CICIoT has no IP addresses.

def assign_device_types(chunk):
    def col(name):
        if name in chunk.columns:
            return chunk[name].to_numpy() == 1
        return np.zeros(len(chunk), dtype=bool)

    conditions = [
        col("SSH") | col("DNS") | col("DHCP"),
        col("HTTP") | col("HTTPS"),
        col("ICMP") | col("ARP"),
        col("UDP") & ~col("TCP"),
        col("TCP"),
    ]
    choices = ["router", "camera", "sensor", "smart_lock", "generic_iot"]
    return np.select(conditions, choices, default="unknown")


# ── Main ─────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Add device_type column to CICIoT dataset")
    parser.add_argument("--input",  required=True, help="Path to CICIoT CSV")
    parser.add_argument("--output", default="dataset_with_devices.csv", help="Output CSV path")
    parser.add_argument("--chunksize", type=int, default=200000, help="Rows per chunk")
    args = parser.parse_args()

    cols = list(pd.read_csv(args.input, nrows=0).columns)
    label_col = "Label" if "Label" in cols else ("label" if "label" in cols else None)
    if label_col is None:
        raise ValueError("No 'Label' or 'label' column found")
    if "device_type" in cols:
        raise ValueError("Input already has a device_type column")

    out_dir = os.path.dirname(args.output)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    print(f"\nLoading: {args.input}   (label column: '{label_col}')")
    start = time.time()
    total_rows = 0
    devices, labels, cross = Counter(), Counter(), Counter()

    for i, chunk in enumerate(pd.read_csv(args.input, chunksize=args.chunksize)):
        chunk["device_type"] = assign_device_types(chunk)

        devices.update(chunk["device_type"].value_counts().to_dict())
        labels.update(chunk[label_col].value_counts().to_dict())
        cross.update(chunk.groupby(["device_type", label_col]).size().to_dict())

        chunk.to_csv(args.output, mode="w" if i == 0 else "a",
                     header=(i == 0), index=False)
        total_rows += len(chunk)
        print(f"  Chunk {i+1}: {total_rows:,} rows processed  ({time.time()-start:.1f}s)")

    # ── Stats ─────────────────────────────────────────────
    print("\n" + "="*50)
    print("DEVICE TYPE DISTRIBUTION")
    print("="*50)
    for dtype, count in devices.most_common():
        print(f"  {dtype:<15} {count:>9,} rows  ({count/total_rows*100:.1f}%)")

    print("\n" + "="*50)
    print("LABEL DISTRIBUTION")
    print("="*50)
    for label, count in labels.most_common():
        print(f"  {label:<35} {count:>9,}  ({count/total_rows*100:.1f}%)")

    benign_values = {l for l in labels if str(l).upper() in ("BENIGN", "BENIGNTRAFFIC")}
    print("\n" + "="*50)
    print("BENIGN ROWS PER DEVICE TYPE")
    print("="*50)
    for dtype in sorted(devices):
        b = sum(c for (d, l), c in cross.items() if d == dtype and l in benign_values)
        print(f"  {dtype:<15} {b:>9,} benign of {devices[dtype]:,}")

    print(f"\nSaved: {args.output}")
    print(f"Done. {total_rows:,} rows in {time.time()-start:.1f}s")


if __name__ == "__main__":
    main()
