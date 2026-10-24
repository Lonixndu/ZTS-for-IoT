
from pathlib import Path
import json

import pandas as pd

SOURCE = Path("datasets/raw/train.csv")
OUTPUT = Path("results/dataset_audit")
OUTPUT.mkdir(parents=True, exist_ok=True)

CHUNK_SIZE = 100_000

# 64-bit hashes are used for scalable screening.
# Hash collisions are theoretically possible.
seen_rows = set()
seen_features = {}

exact_duplicates = 0
feature_duplicates = 0
conflicting_label_rows = 0
processed = 0

print("Starting duplicate screening...")

for chunk in pd.read_csv(
    SOURCE,
    chunksize=CHUNK_SIZE,
    low_memory=False
):
    feature_cols = [
        col for col in chunk.columns if col != "label"
    ]

    row_hashes = pd.util.hash_pandas_object(
        chunk, index=False
    ).to_numpy()

    feature_hashes = pd.util.hash_pandas_object(
        chunk[feature_cols], index=False
    ).to_numpy()

    labels = chunk["label"].to_numpy()

    for row_hash, feature_hash, label in zip(
        row_hashes, feature_hashes, labels
    ):
        row_key = int(row_hash)
        feature_key = int(feature_hash)

        if row_key in seen_rows:
            exact_duplicates += 1
        else:
            seen_rows.add(row_key)

        if feature_key in seen_features:
            feature_duplicates += 1

            if seen_features[feature_key] != label:
                conflicting_label_rows += 1
        else:
            seen_features[feature_key] = label

    processed += len(chunk)
    print(f"Processed {processed:,} records")

summary = {
    "total_records": processed,
    "exact_duplicate_hash_matches": exact_duplicates,
    "feature_duplicate_hash_matches": feature_duplicates,
    "conflicting_label_hash_matches": conflicting_label_rows,
    "note": (
        "Hash-based screening. Hash collisions are possible. "
        "Conflicting-label count compares each duplicate "
        "with the first observed label for its feature hash."
    )
}

with open(
    OUTPUT / "duplicate_screening.json",
    "w",
    encoding="utf-8"
) as f:
    json.dump(summary, f, indent=4)

print("\nDuplicate screening completed.")
print("Exact duplicate matches:", exact_duplicates)
print("Feature duplicate matches:", feature_duplicates)
print("Conflicting-label matches:", conflicting_label_rows)
