
from pathlib import Path
import duckdb
import json
import time

ROOT = Path(__file__).resolve().parents[2]

ORIGINAL = ROOT / "datasets/raw/CICIOT23/test/test.csv"
SPLITS = ROOT / "datasets/processed/splits"
CONFIG = ROOT / "config/fusion_v3_frozen.json"

OUT = ROOT / "results/original_test"
OUT.mkdir(parents=True, exist_ok=True)

OUTPUT_CSV = OUT / "nonoverlap_test.csv"

with open(CONFIG, encoding="utf-8") as f:
    config = json.load(f)

features = config["features"]
columns = features + ["label"]

def q(name):
    return '"' + name.replace('"', '""') + '"'

def path_sql(path):
    return str(path).replace("\\", "/").replace("'", "''")

def source(path):
    return (
        f"read_csv_auto('{path_sql(path)}', "
        "sample_size=-1)"
    )

con = duckdb.connect()
con.execute("SET threads=4")
con.execute("SET preserve_insertion_order=false")

print("Checking schemas...")

for name, path in [
    ("original", ORIGINAL),
    ("train", SPLITS / "train.csv"),
    ("validation", SPLITS / "validation.csv"),
    ("test", SPLITS / "test.csv")
]:
    if not path.exists():
        raise FileNotFoundError(path)

    found = {
        row[0] for row in con.execute(
            f"DESCRIBE SELECT * FROM {source(path)}"
        ).fetchall()
    }

    missing = [c for c in columns if c not in found]

    if missing:
        raise ValueError(
            f"{name} missing columns: {missing}"
        )

    print(f"{name}: OK")

# Compare the 44 model features and label.
# Casting both datasets to DOUBLE makes numeric
# comparisons consistent with the previous screening.
expressions = [
    f"CAST({q(c)} AS DOUBLE) AS {q(c)}"
    for c in features
]
expressions.append('CAST("label" AS VARCHAR) AS "label"')

projection = ", ".join(expressions)

print("\nBuilding reference table...")
start = time.perf_counter()

# The reference includes all existing partitions.
# UNION removes repeated records.
con.execute(f"""
CREATE TEMP TABLE reference_rows AS
SELECT {projection}
FROM {source(SPLITS / 'train.csv')}
UNION
SELECT {projection}
FROM {source(SPLITS / 'validation.csv')}
UNION
SELECT {projection}
FROM {source(SPLITS / 'test.csv')}
""")

print(
    f"Reference ready in "
    f"{time.perf_counter()-start:.1f}s"
)

# Exact equality across all selected columns.
join_conditions = " AND ".join(
    f"o.{q(c)} IS NOT DISTINCT FROM r.{q(c)}"
    for c in columns
)

print("\nFiltering original test dataset...")

# Use a hash prefilter for speed, followed by
# exact equality across all 45 selected columns.
hash_expression = "hash(" + ", ".join(
    q(c) for c in columns
) + ")"

con.execute(f"""
CREATE TEMP TABLE reference_hashes AS
SELECT
    {hash_expression} AS fingerprint,
    *
FROM reference_rows
""")

con.execute("""
CREATE INDEX ref_hash_idx
ON reference_hashes(fingerprint)
""")

original_projection = ", ".join(
    f"CAST({q(c)} AS DOUBLE) AS {q(c)}"
    for c in features
) + ', CAST("label" AS VARCHAR) AS "label"'

con.execute(f"""
CREATE TEMP VIEW original_rows AS
SELECT {original_projection}
FROM {source(ORIGINAL)}
""")

original_hash = "hash(" + ", ".join(
    f"o.{q(c)}" for c in columns
) + ")"

query = f"""
SELECT o.*
FROM original_rows o
WHERE NOT EXISTS (
    SELECT 1
    FROM reference_hashes r
    WHERE r.fingerprint = {original_hash}
      AND {join_conditions}
)
"""

con.execute(f"""
COPY ({query})
TO '{path_sql(OUTPUT_CSV)}'
(HEADER, DELIMITER ',')
""")

original_count = con.execute(
    f"SELECT COUNT(*) FROM {source(ORIGINAL)}"
).fetchone()[0]

remaining = con.execute(
    f"SELECT COUNT(*) FROM {source(OUTPUT_CSV)}"
).fetchone()[0]

removed = original_count - remaining

print("\n===== FILTERING COMPLETE =====")
print(f"Original records: {original_count:,}")
print(f"Overlapping records removed: {removed:,}")
print(f"Remaining records: {remaining:,}")
print(f"Retained percentage: {remaining/original_count:.2%}")

print("\nRemaining PingSweep records:")

ping_count = con.execute(f"""
SELECT COUNT(*)
FROM {source(OUTPUT_CSV)}
WHERE label = 'Recon-PingSweep'
""").fetchone()[0]

print(f"Recon-PingSweep: {ping_count:,}")

summary = {
    "original_records": original_count,
    "overlapping_records_removed": removed,
    "remaining_records": remaining,
    "remaining_pingsweep": ping_count,
    "comparison_columns": columns,
    "comparison_method": (
        "DuckDB numeric DOUBLE equality on 44 model "
        "features plus label; hash prefilter and "
        "exact column equality"
    ),
    "limitation": (
        "No exact 45-column matches to existing "
        "partitions. This does not establish "
        "capture-session or device independence."
    )
}

with open(
    OUT / "filter_summary.json",
    "w",
    encoding="utf-8"
) as f:
    json.dump(summary, f, indent=4)

print("\nSaved filtered dataset:")
print(OUTPUT_CSV)
