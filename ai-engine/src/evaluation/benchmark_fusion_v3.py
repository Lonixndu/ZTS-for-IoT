
from pathlib import Path
import sys
import time
import json
import statistics
import threading

import numpy as np
import pandas as pd
import psutil
import torch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "inference"))

from offline_predict import load_engine, predict_batch

DATASET = ROOT / "datasets/processed/splits/test.csv"
OUT = ROOT / "results/fusion_v3_benchmark"
OUT.mkdir(parents=True, exist_ok=True)

SINGLE_RUNS = 1000
BATCH_SIZES = [1, 10, 100, 1000, 10000]
REPEATS = 5

torch.set_num_threads(4)

process = psutil.Process()
process.cpu_percent(interval=None)

print("Loading frozen Fusion v3...")

load_start = time.perf_counter()
engine = load_engine()
load_seconds = time.perf_counter() - load_start

print(f"Loading time: {load_seconds:.3f} s")

# Use a fixed sample for reproducibility.
# This measures inference performance, not generalization.
data = pd.read_csv(DATASET, nrows=10000)

if len(data) < 10000:
    raise ValueError("Expected at least 10,000 records")

# Warm up model execution
for _ in range(20):
    predict_batch(engine, data.iloc[:1])

print("\nBenchmarking single-record inference...")

latencies = []

for i in range(SINGLE_RUNS):
    row = data.iloc[[i % len(data)]]

    start = time.perf_counter()
    predict_batch(engine, row)
    elapsed = time.perf_counter() - start

    latencies.append(elapsed * 1000)

single_metrics = {
    "runs": SINGLE_RUNS,
    "mean_ms": statistics.mean(latencies),
    "median_ms": statistics.median(latencies),
    "p95_ms": float(np.percentile(latencies, 95)),
    "p99_ms": float(np.percentile(latencies, 99)),
    "min_ms": min(latencies),
    "max_ms": max(latencies)
}

print("\n===== SINGLE RECORD LATENCY =====")
for key, value in single_metrics.items():
    print(f"{key}: {value:.4f}" if key != "runs"
          else f"{key}: {value}")

print("\nBenchmarking batch throughput...")

batch_results = []

for batch_size in BATCH_SIZES:
    frame = data.iloc[:batch_size]

    # Warm up this batch size
    predict_batch(engine, frame)

    timings = []

    for _ in range(REPEATS):
        start = time.perf_counter()
        predict_batch(engine, frame)
        timings.append(time.perf_counter() - start)

    median_seconds = statistics.median(timings)

    batch_results.append({
        "batch_size": batch_size,
        "median_seconds": median_seconds,
        "records_per_second": batch_size / median_seconds,
        "milliseconds_per_record":
            median_seconds * 1000 / batch_size
    })

batch_df = pd.DataFrame(batch_results)
batch_df.to_csv(
    OUT / "batch_benchmark.csv",
    index=False
)

print(batch_df.to_string(index=False))

# Sample process memory and CPU utilization during
# repeated inference on the 10,000-record batch.
print("\nSampling CPU and memory usage...")

cpu_samples = []
rss_samples = []
stop_event = threading.Event()

def monitor():
    process.cpu_percent(interval=None)

    while not stop_event.wait(0.1):
        cpu_samples.append(
            process.cpu_percent(interval=None)
        )
        rss_samples.append(
            process.memory_info().rss / (1024 ** 2)
        )

monitor_thread = threading.Thread(
    target=monitor,
    daemon=True
)
monitor_thread.start()

resource_start = time.perf_counter()
iterations = 0

try:
    while time.perf_counter() - resource_start < 5:
        predict_batch(engine, data)
        iterations += 1
finally:
    stop_event.set()
    monitor_thread.join()

resource_seconds = time.perf_counter() - resource_start

resources = {
    "cpu_percent_mean": (
        statistics.mean(cpu_samples)
        if cpu_samples else None
    ),
    "cpu_percent_max": (
        max(cpu_samples)
        if cpu_samples else None
    ),
    "rss_memory_mb_mean": (
        statistics.mean(rss_samples)
        if rss_samples else None
    ),
    "rss_memory_mb_max": (
        max(rss_samples)
        if rss_samples else None
    ),
    "resource_test_iterations": iterations,
    "resource_test_seconds": resource_seconds
}

print("\n===== RESOURCE UTILIZATION =====")
for key, value in resources.items():
    print(f"{key}: {value}")

summary = {
    "model": "Frozen Fusion v3",
    "hardware": "Local CPU",
    "load_seconds": load_seconds,
    "single_record_latency": single_metrics,
    "resources": resources,
    "batch_results": batch_results
}

with open(
    OUT / "benchmark_summary.json",
    "w",
    encoding="utf-8"
) as file:
    json.dump(summary, file, indent=4)

pd.DataFrame({
    "latency_ms": latencies
}).to_csv(
    OUT / "single_record_latencies.csv",
    index=False
)

print("\nBenchmark results saved to:", OUT)
