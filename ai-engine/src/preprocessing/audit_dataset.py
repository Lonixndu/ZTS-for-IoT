
from pathlib import Path
from collections import Counter
import json

import numpy as np
import pandas as pd

DATASET = Path("datasets/raw/train.csv")
OUTPUT = Path("results/dataset_audit")
CHUNK_SIZE = 100_000

OUTPUT.mkdir(parents=True, exist_ok=True)

rows = 0
missing = Counter()
infinite = Counter()
labels = Counter()
column_types = {}
columns = None

print("Starting CICIoT2023 dataset audit...")

for number, chunk in enumerate(
    pd.read_csv(DATASET, chunksize=CHUNK_SIZE, low_memory=False),
    start=1
):
    if columns is None:
        columns = chunk.columns.tolist()
        column_types = {
            col: str(dtype)
            for col, dtype in chunk.dtypes.items()
        }

    rows += len(chunk)

    missing.update(
        chunk.isna().sum().to_dict()
    )

    if "label" in chunk.columns:
        labels.update(
            chunk["label"].value_counts(dropna=False).to_dict()
        )

    numeric = chunk.select_dtypes(include=[np.number])

inf_counts = np.isinf(numeric.to_numpy()).sum(axis=0)

for col, count in zip(numeric.columns, inf_counts):
    infinite[col] += int(count)

    print(f"Chunk {number}: {rows:,} records processed")

summary = {
    "total_rows": rows,
    "total_columns": len(columns),
    "column_types": column_types,
    "missing_values": dict(missing),
    "infinite_values": dict(infinite),
    "class_distribution": {
        str(k): int(v) for k, v in labels.items()
    }
}

with open(OUTPUT / "dataset_audit.json", "w") as f:
    json.dump(summary, f, indent=4)

pd.DataFrame(
    sorted(labels.items(), key=lambda x: x[1], reverse=True),
    columns=["class", "count"]
).to_csv(OUTPUT / "class_distribution.csv", index=False)

print("\nAudit completed.")
print("Total records:", f"{rows:,}")
print("Total columns:", len(columns))
print("Missing values:", sum(missing.values()))
print("Infinite values:", sum(infinite.values()))
print("Classes:", len(labels))
print("Results saved to:", OUTPUT)
