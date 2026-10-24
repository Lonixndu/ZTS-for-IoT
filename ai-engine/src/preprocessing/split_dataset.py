
from pathlib import Path
import csv
import json
import hashlib
from collections import Counter

import duckdb

SOURCE = Path("datasets/processed/ciciot2023_cleaned.csv")
OUT = Path("datasets/processed/splits")
REPORT = Path("results/dataset_audit")

OUT.mkdir(parents=True, exist_ok=True)
REPORT.mkdir(parents=True, exist_ok=True)

DROP_FEATURES = {"Telnet", "IRC"}
SEED = 42

# Assign each unique row a reproducible random-like
# number using a stable cryptographic hash.
def partition(row):
    payload = "\x1f".join(row).encode("utf-8")
    digest = hashlib.blake2b(
        payload,
        digest_size=8,
        person=b"IoTSplit"
    ).digest()

    value = int.from_bytes(digest, "big") / (2**64)

    if value < 0.70:
        return "train"
    elif value < 0.85:
        return "validation"
    else:
        return "test"


counts = {
    "train": Counter(),
    "validation": Counter(),
    "test": Counter()
}

files = {
    name: open(
        OUT / f"{name}.csv",
        "w",
        newline="",
        encoding="utf-8"
    )
    for name in counts
}

writers = {
    name: csv.writer(handle)
    for name, handle in files.items()
}

try:
    with open(
        SOURCE,
        "r",
        newline="",
        encoding="utf-8"
    ) as source:
        reader = csv.reader(source)
        header = next(reader)

        keep_indices = [
            i for i, col in enumerate(header)
            if col not in DROP_FEATURES
        ]

        label_index = header.index("label")
        new_header = [
            header[i] for i in keep_indices
        ]

        for writer in writers.values():
            writer.writerow(new_header)

        for number, row in enumerate(reader, 1):
            group = partition(row)
            writers[group].writerow(
                [row[i] for i in keep_indices]
            )

            counts[group][row[label_index]] += 1

            if number % 500_000 == 0:
                print(f"Processed {number:,} rows")

finally:
    for handle in files.values():
        handle.close()

summary = {
    "seed": SEED,
    "method": "Stable row hash, approximate 70/15/15",
    "removed_constant_features": sorted(DROP_FEATURES),
    "splits": {
        name: {
            "total": sum(classes.values()),
            "classes": dict(classes)
        }
        for name, classes in counts.items()
    }
}

with open(
    REPORT / "split_summary.json",
    "w",
    encoding="utf-8"
) as f:
    json.dump(summary, f, indent=4)

print("\nDataset splitting completed.")

for name, classes in counts.items():
    print(
        name,
        f"{sum(classes.values()):,}",
        "rows",
        f"{len(classes)} classes"
    )
