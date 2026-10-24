
from pathlib import Path
import duckdb
import json

ROOT = Path(__file__).resolve().parents[2]

ORIGINAL_TEST = ROOT / "datasets/raw/CICIOT23/test/test.csv"
SPLITS = ROOT / "datasets/processed/splits"
CONFIG = ROOT / "config/fusion_v3_frozen.json"

OUT = ROOT / "results/original_test"
OUT.mkdir(parents=True, exist_ok=True)

with open(CONFIG, encoding="utf-8") as f:
    config = json.load(f)

# Compare only the 44 features used by our model,
# plus the original class label.
columns = config["features"] + ["label"]

con = duckdb.connect()
con.execute("SET threads=4")
con.execute("SET preserve_insertion_order=false")

def sql_path(path):
    return str(path).replace("\\", "/").replace("'", "''")

def quoted(column):
    return '"' + column.replace('"', '""') + '"'

original = sql_path(ORIGINAL_TEST)

print("\n===== ORIGINAL TEST OVERLAP CHECK =====")

print("Comparison columns:", len(columns))

# Ensure every required column exists.
for name, path in [
    ("original_test", ORIGINAL_TEST),
    ("train", SPLITS / "train.csv"),
    ("validation", SPLITS / "validation.csv"),
    ("test", SPLITS / "test.csv")
]:
    schema = con.execute(
        f"DESCRIBE SELECT * FROM read_csv_auto('{sql_path(path)}')"
    ).fetchall()

    available = {row[0] for row in schema}
    missing = [col for col in columns if col not in available]

    if missing:
        raise ValueError(
            f"Missing columns in {name}: {missing}"
        )

    print(f"{name}: schema verified")

# Hash the same columns in the same order.
# This is a fingerprint screening method.
expression = "hash(" + ", ".join(
    f"CAST({quoted(col)} AS DOUBLE)"
    if col != "label"
    else f"CAST({quoted(col)} AS VARCHAR)"
    for col in columns
) + ")"

print("\nBuilding original test fingerprints...")

con.execute(f"""
CREATE TEMP TABLE original_hashes AS
SELECT DISTINCT {expression} AS fingerprint
FROM read_csv_auto('{original}')
""")

summary = {}

for name in ["train", "validation", "test"]:
    print(f"\nChecking {name}...")

    path = sql_path(SPLITS / f"{name}.csv")

    count = con.execute(f"""
        SELECT COUNT(*)
        FROM read_csv_auto('{path}')
        WHERE {expression} IN (
            SELECT fingerprint
            FROM original_hashes
        )
    """).fetchone()[0]

    summary[name] = int(count)

    print(f"Matching records: {count:,}")

with open(
    OUT / "overlap_screening.json",
    "w",
    encoding="utf-8"
) as f:
    json.dump(summary, f, indent=4)

print("\n===== SUMMARY =====")

for name, count in summary.items():
    print(f"{name}: {count:,}")

print("\nSaved to:", OUT)
print(
    "This checks matching 44-feature-plus-label "
    "fingerprints, not capture-session independence."
)
