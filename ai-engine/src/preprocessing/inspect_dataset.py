from pathlib import Path
import pandas as pd


DATA_DIR = Path(__file__).resolve().parents[2] / "datasets" / "raw"


csv_files = list(DATA_DIR.glob("*.csv"))

if not csv_files:
    raise FileNotFoundError(
        f"No CSV files found in {DATA_DIR}"
    )

print(f"Found {len(csv_files)} CSV file(s).")

first_file = csv_files[0]

print(f"\nLoading: {first_file.name}")

df = pd.read_csv(first_file)

print("\nShape:")
print(df.shape)

print("\nColumns:")
for col in df.columns:
    print(col)

print("\nFirst 5 rows:")
print(df.head())

print("\nData types:")
print(df.dtypes)

print("\nMissing values:")
print(df.isnull().sum().sort_values(ascending=False).head(20))

possible_labels = [
    "label",
    "Label",
    "class",
    "Class",
    "attack",
    "Attack"
]

for label_col in possible_labels:
    if label_col in df.columns:
        print(f"\nDetected label column: {label_col}")
        print(df[label_col].value_counts())
        break
else:
    print("\nCould not automatically identify label column.")