
from pathlib import Path
import pandas as pd
import json

ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = ROOT / "datasets/raw/CICIOT23/test"
CONFIG = ROOT / "config/fusion_v3_frozen.json"

with open(CONFIG, encoding="utf-8") as f:
    config = json.load(f)

required_features = config["features"]

files = sorted(DATA_DIR.rglob("*.csv"))

print("\n===== ORIGINAL TEST DATASET INSPECTION =====")
print("Folder:", DATA_DIR)
print("CSV files found:", len(files))

if not files:
    raise SystemExit("No CSV files found.")

total_records = 0

for file in files:
    print("\nFile:", file.name)

    header = pd.read_csv(file, nrows=0)
    columns = header.columns.tolist()

    missing = [
        feature for feature in required_features
        if feature not in columns
    ]

    print("Columns:", len(columns))
    print("Missing model features:", missing)

    if "label" not in columns:
        print("WARNING: label column not found")
        continue

    counts = {}

    for chunk in pd.read_csv(
        file,
        usecols=["label"],
        chunksize=100000
    ):
        for label, count in chunk["label"].value_counts().items():
            counts[label] = counts.get(label, 0) + int(count)

    records = sum(counts.values())
    total_records += records

    print("Records:", f"{records:,}")
    print("Attack classes:", len(counts))

    for label, count in sorted(counts.items()):
        print(f"  {label}: {count:,}")

print("\n===== SUMMARY =====")
print("Total records:", f"{total_records:,}")
print("Expected model features:", len(required_features))
