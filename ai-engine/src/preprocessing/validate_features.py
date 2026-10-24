
from pathlib import Path
import json
import numpy as np
import pandas as pd

SOURCE = Path("datasets/processed/ciciot2023_cleaned.csv")
OUT = Path("results/dataset_audit")
OUT.mkdir(parents=True, exist_ok=True)

CHUNK_SIZE = 100_000

total_rows = 0
non_numeric = {}
minimums = {}
maximums = {}
missing = {}
infinite = {}
feature_names = None

print("Validating cleaned dataset features...")

for chunk in pd.read_csv(
    SOURCE,
    chunksize=CHUNK_SIZE,
    low_memory=False
):
    if feature_names is None:
        feature_names = [
            c for c in chunk.columns if c != "label"
        ]

    for col in feature_names:
        original = chunk[col]

        numeric = pd.to_numeric(
            original, errors="coerce"
        )

        invalid = numeric.isna() & original.notna()

        non_numeric[col] = (
            non_numeric.get(col, 0) + int(invalid.sum())
        )

        missing[col] = (
            missing.get(col, 0) + int(original.isna().sum())
        )

        values = numeric.to_numpy(dtype=np.float64)
        finite = values[np.isfinite(values)]

        infinite[col] = (
            infinite.get(col, 0) +
            int(np.isinf(values).sum())
        )

        if finite.size:
            low = float(finite.min())
            high = float(finite.max())

            minimums[col] = min(
                minimums.get(col, low), low
            )
            maximums[col] = max(
                maximums.get(col, high), high
            )

    total_rows += len(chunk)
    print(f"Validated {total_rows:,} rows")

report = {
    "total_rows": total_rows,
    "feature_count": len(feature_names),
    "non_numeric_values": non_numeric,
    "missing_values": missing,
    "infinite_values": infinite,
    "feature_ranges": {
        col: {
            "min": minimums.get(col),
            "max": maximums.get(col)
        }
        for col in feature_names
    }
}

with open(
    OUT / "feature_validation.json",
    "w",
    encoding="utf-8"
) as f:
    json.dump(report, f, indent=4)

print("\nFeature validation completed.")
print("Rows:", total_rows)
print("Features:", len(feature_names))
print("Non-numeric:", sum(non_numeric.values()))
print("Missing:", sum(missing.values()))
print("Infinite:", sum(infinite.values()))
print("Report:", OUT / "feature_validation.json")
