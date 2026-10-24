from pathlib import Path
import argparse
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split


BASE_DIR = Path(__file__).resolve().parents[2]

DATA_FILE = BASE_DIR / "datasets" / "raw" / "train.csv"
MODEL_FILE = BASE_DIR / "models" / "random_forest_v1.joblib"

SAMPLE_SIZE = 500_000
RANDOM_STATE = 42


parser = argparse.ArgumentParser()

parser.add_argument(
    "--attack",
    default="DoS-SYN_Flood",
    help="Attack type to demonstrate"
)

args = parser.parse_args()


print("=" * 65)
print("       ZERO TRUST IoT - AI ATTACK DETECTION DEMO")
print("=" * 65)

print("\nLoading trained AI model...")

model = joblib.load(MODEL_FILE)


# --------------------------------------------------
# Reproduce the exact development dataset
# --------------------------------------------------

print("Preparing unseen test traffic...")

df = pd.read_csv(DATA_FILE)

sample_fraction = SAMPLE_SIZE / len(df)

df, _ = train_test_split(
    df,
    train_size=sample_fraction,
    stratify=df["label"],
    random_state=RANDOM_STATE
)

X = df.drop(columns=["label"])
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=RANDOM_STATE,
    stratify=y
)


# --------------------------------------------------
# Select attack sample from TEST SET
# --------------------------------------------------

requested_attack = args.attack

matching_indices = y_test[
    y_test == requested_attack
].index

if len(matching_indices) == 0:

    print(f"\nAttack type not found: {requested_attack}")
    print("\nAvailable attack types:")

    for label in sorted(y_test.unique()):
        print(" -", label)

    raise SystemExit


sample_index = matching_indices[0]

sample = X_test.loc[[sample_index]]

actual_label = y_test.loc[sample_index]


# --------------------------------------------------
# AI prediction
# --------------------------------------------------

prediction = model.predict(sample)[0]

probabilities = model.predict_proba(sample)[0]

confidence = probabilities.max()

status = (
    "BENIGN"
    if prediction == "BenignTraffic"
    else "MALICIOUS"
)


# --------------------------------------------------
# Display
# --------------------------------------------------

print("\n" + "-" * 65)

print("NETWORK TRAFFIC SAMPLE")

print("-" * 65)

print(f"Sample ID       : {sample_index}")

print(f"\nActual Label    : {actual_label}")

print("\nAI ANALYSIS")
print("-" * 65)

print(f"Predicted Attack: {prediction}")
print(f"Confidence      : {confidence * 100:.2f}%")
print(f"Security Status : {status}")


if prediction == actual_label:

    print("\nDetection Result: CORRECT ✓")

else:

    print("\nDetection Result: INCORRECT ✗")


print("\n" + "=" * 65)

if status == "MALICIOUS":

    print("AI SECURITY EVENT GENERATED")
    print("Attack evidence ready for Trust Scoring Engine.")

else:

    print("Traffic classified as normal.")

print("=" * 65)