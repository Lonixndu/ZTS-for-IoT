
from pathlib import Path
import sys
import time

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "inference"))

from offline_predict import load_engine, predict_batch

SOURCE = ROOT / "results/original_test/nonoverlap_test.csv"
OUT = ROOT / "results/offline_demo/presentation"
OUT.mkdir(parents=True, exist_ok=True)

TARGETS = [
    "BenignTraffic",
    "DDoS-SYN_Flood",
    "SqlInjection",
    "Recon-PingSweep"
]

print("\n==========================================")
print(" ZERO TRUST IoT - AI DETECTION ENGINE")
print(" Fusion v3 Offline Demonstration")
print("==========================================")

print("\nLoading frozen models...")
engine = load_engine()

print("Searching for demonstration records...")

candidates = {label: [] for label in TARGETS}
MAX_PER_CLASS = 200

for chunk in pd.read_csv(SOURCE, chunksize=10000):
    for label in TARGETS:
        remaining = MAX_PER_CLASS - len(candidates[label])

        if remaining <= 0:
            continue

        selected = chunk[
            chunk["label"] == label
        ].head(remaining)

        if not selected.empty:
            candidates[label].append(selected)

    if all(
        sum(len(x) for x in candidates[label])
        >= MAX_PER_CLASS
        for label in TARGETS
        if label != "Recon-PingSweep"
    ):
        # Continue until all PingSweep records have been read.
        pass

frames = {}

for label, parts in candidates.items():
    if not parts:
        raise RuntimeError(
            f"No records found for {label}"
        )

    frames[label] = pd.concat(
        parts,
        ignore_index=True
    ).head(MAX_PER_CLASS)

print("\nRunning candidate inference...")

selected_cases = []

def choose_case(label, condition, description):
    frame = frames[label]
    predictions = predict_batch(engine, frame)

    mask = condition(predictions)

    matches = predictions[mask]

    if matches.empty:
        print(
            f"WARNING: No example found for {description}"
        )
        return

    index = matches.index[0]

    selected_cases.append({
        "scenario": description,
        "input": frame.loc[[index]].copy()
    })

choose_case(
    "BenignTraffic",
    lambda p: ~p["detected_attack"],
    "Correct benign prediction"
)

choose_case(
    "DDoS-SYN_Flood",
    lambda p: (
        p["detected_attack"]
        & (p["predicted_class"] == "DDoS-SYN_Flood")
    ),
    "Correct common attack"
)

choose_case(
    "SqlInjection",
    lambda p: (
        p["detected_attack"]
        & (p["predicted_class"] == "SqlInjection")
    ),
    "Correct rare attack"
)

choose_case(
    "Recon-PingSweep",
    lambda p: (
        p["predicted_class"] != "Recon-PingSweep"
    ),
    "Misclassified PingSweep"
)

if not selected_cases:
    raise RuntimeError("No demonstration cases selected.")

print("\n==========================================")
print(" LIVE OFFLINE INFERENCE DEMONSTRATION")
print("==========================================")

output_rows = []

for number, case in enumerate(selected_cases, start=1):
    frame = case["input"]

    start = time.perf_counter()
    result = predict_batch(engine, frame)
    elapsed_ms = (time.perf_counter() - start) * 1000

    record = result.iloc[0]

    print(f"\nSCENARIO {number}: {case['scenario']}")
    print("-" * 45)
    print("Actual label:       ", record["actual_label"])
    print("Predicted class:    ", record["predicted_class"])
    print(
        "Class confidence:   ",
        f"{record['confidence']:.4%}"
    )
    print(
        "XGBoost attack score:",
        f"{record['xgb_attack_score']:.4f}"
    )
    print(
        "AE anomaly score:   ",
        f"{record['ae_score']:.4f}"
    )
    print(
        "Fused behavior risk:",
        f"{record['behavior_risk']:.4f}"
    )
    print(
        "Attack detected:    ",
        bool(record["detected_attack"])
    )
    print(
        "Class correct:      ",
        bool(record["correct_class"])
    )
    print(
        "Inference latency:  ",
        f"{elapsed_ms:.3f} ms"
    )

    row = record.to_dict()
    row["scenario"] = case["scenario"]
    row["inference_ms"] = elapsed_ms
    output_rows.append(row)

pd.DataFrame(output_rows).to_csv(
    OUT / "demo_results.csv",
    index=False
)

print("\n==========================================")
print(" DEMONSTRATION COMPLETED")
print("==========================================")
print("Results:", OUT / "demo_results.csv")
