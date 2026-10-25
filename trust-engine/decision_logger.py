"""Append-only local CSV output. This is not an immutable blockchain ledger."""
import csv
import json
from pathlib import Path
from threading import Lock

DECISION_FIELDS = [
    "deviceId", "mode", "timestamp", "trustValue", "threshold", "action",
    "reasonCode", "evidenceRef", "BehaviorRisk", "baselineRisk", "isProbe",
    "latencyMs", "features",
]


def safe_csv_value(value):
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r", "\n")):
        return "'" + value
    return value


class DecisionLogger:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = Lock()

    def append(self, decision: dict):
        row = dict(decision)
        row["features"] = json.dumps(row["features"], sort_keys=True)
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            new_file = not self.path.exists() or self.path.stat().st_size == 0
            with self.path.open("a", encoding="utf-8", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=DECISION_FIELDS)
                if new_file:
                    writer.writeheader()
                writer.writerow({k: safe_csv_value(row[k]) for k in DECISION_FIELDS})
                stream.flush()

