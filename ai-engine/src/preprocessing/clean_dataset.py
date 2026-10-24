
from pathlib import Path
import json

import duckdb

RAW = Path("datasets/raw/train.csv").resolve()
OUT = Path("datasets/processed").resolve()
REPORT = Path("results/dataset_audit").resolve()

OUT.mkdir(parents=True, exist_ok=True)
REPORT.mkdir(parents=True, exist_ok=True)

CLEANED = OUT / "ciciot2023_cleaned.csv"

con = duckdb.connect(str(REPORT / "cleaning.duckdb"))
con.execute("SET memory_limit='4GB'")
con.execute("SET threads=2")
con.execute(f"SET temp_directory='{(REPORT / 'temp').as_posix()}'")

source = RAW.as_posix().replace("'", "''")
destination = CLEANED.as_posix().replace("'", "''")

print("Reading original dataset...")

con.execute(f"""
    CREATE OR REPLACE VIEW raw_data AS
    SELECT *
    FROM read_csv(
        '{source}',
        header=true,
        all_varchar=true
    )
""")

original_count = con.execute(
    "SELECT COUNT(*) FROM raw_data"
).fetchone()[0]

print("Original records:", f"{original_count:,}")

# DISTINCT compares complete rows, including labels.
# all_varchar preserves CSV field representations
# during exact-row comparison.
print("Creating cleaned dataset...")

con.execute(f"""
    COPY (
        SELECT DISTINCT *
        FROM raw_data
    )
    TO '{destination}'
    (HEADER, DELIMITER ',')
""")

print("Verifying cleaned dataset...")

cleaned_source = destination.replace("'", "''")

con.execute(f"""
    CREATE OR REPLACE VIEW cleaned_data AS
    SELECT *
    FROM read_csv(
        '{cleaned_source}',
        header=true,
        all_varchar=true
    )
""")

cleaned_count = con.execute(
    "SELECT COUNT(*) FROM cleaned_data"
).fetchone()[0]

before = dict(con.execute("""
    SELECT label, COUNT(*)
    FROM raw_data
    GROUP BY label
""").fetchall())

after = dict(con.execute("""
    SELECT label, COUNT(*)
    FROM cleaned_data
    GROUP BY label
""").fetchall())

summary = {
    "original_records": original_count,
    "cleaned_records": cleaned_count,
    "removed_records": original_count - cleaned_count,
    "removal_percentage": round(
        100 * (original_count - cleaned_count) / original_count, 4
    ),
    "class_comparison": {
        label: {
            "before": count,
            "after": after.get(label, 0),
            "removed": count - after.get(label, 0)
        }
        for label, count in before.items()
    },
    "method": (
        "Exact full-row DISTINCT using CSV string values; "
        "original raw dataset preserved."
    )
}

with open(
    REPORT / "cleaning_summary.json",
    "w",
    encoding="utf-8"
) as f:
    json.dump(summary, f, indent=4)

print("\nCleaning completed.")
print("Original:", f"{original_count:,}")
print("Cleaned:", f"{cleaned_count:,}")
print("Removed:", f"{original_count - cleaned_count:,}")
print("Output:", CLEANED)

con.close()
