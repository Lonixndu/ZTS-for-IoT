"""
readers.py — read-only views of the files your scripts produce.

Nothing here writes to the project. niidlsd.py's settings are read with Python's
`ast` module (the file is parsed as text, never imported or executed).
"""

import ast
import hashlib
import json
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

import config

CATEGORIES = ["normal", "ddos", "dos", "recon", "mirai", "intrusion", "exploit", "unknown"]


def _read_json(path):
    try:
        text = Path(path).read_text(encoding="utf-8").strip()
        return json.loads(text) if text else None
    except (OSError, ValueError):
        return None


# ── Detector settings (constants at the top of niidlsd.py) ───────────────
def detector_settings():
    path = config.project_path(config.DETECTOR_SCRIPT)
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return {}
    out = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                and isinstance(node.targets[0], ast.Name):
            try:
                out[node.targets[0].id] = ast.literal_eval(node.value)
            except (ValueError, SyntaxError, TypeError):
                pass
    return out


# ── Layer 2: label history ───────────────────────────────────────────────
def history_table(settings):
    hist = _read_json(config.project_path(config.HISTORY_FILE))
    if not hist:
        return None
    min_n = settings.get("MIN_HISTORY_COUNT", 100)
    thresh = settings.get("ATTACK_RATIO_THRESH", 0.90)
    rows = []
    for key, counts in hist.items():
        device, _, protocol = key.partition("|")
        n = sum(counts.values())
        attack = n - counts.get("normal", 0)
        share = attack / n if n else 0
        row = {"device": device, "protocol": protocol, "key": key, "rows": n,
               "benign": counts.get("normal", 0), "attack": attack, "attack_share": share,
               "active": n >= min_n, "suspicious": n >= min_n and share >= thresh}
        for c in CATEGORIES:
            row[c] = counts.get(c, 0)
        rows.append(row)
    return pd.DataFrame(rows).sort_values("rows", ascending=False).reset_index(drop=True)


# ── Layer 3: benign profiles ─────────────────────────────────────────────
def profiles(settings):
    prof = _read_json(config.project_path(config.PROFILE_FILE))
    if not prof:
        return None, None, {}
    meta = prof.get("__meta__", {})
    features = meta.get("features", [])
    min_b = settings.get("MIN_BENIGN_SAMPLES", 50)
    summary, medians = [], {}
    for key, p in prof.items():
        if key == "__meta__":
            continue
        name = "ALL (pooled)" if key == settings.get("GLOBAL_PROFILE", "__global__") else key
        usable = sum(1 for f in features if (p.get(f"{f}_scale") or 0) > 0)
        summary.append({"profile": name, "benign_rows": p.get("count", 0),
                        "sample_used": p.get("sample_size"),
                        "active": p.get("count", 0) >= min_b,
                        "features_usable": usable, "features_total": len(features)})
        # centers are on sign·log1p scale → back to real units for display
        medians[name] = {f: float(np.sign(c) * np.expm1(abs(c)))
                         for f in features
                         if (c := p.get(f"{f}_center")) is not None}
    df = pd.DataFrame(summary).sort_values("benign_rows", ascending=False).reset_index(drop=True)
    med = pd.DataFrame(medians)
    return df, med, meta


# ── Attacker's answer key ────────────────────────────────────────────────
def poison_log():
    log = _read_json(config.project_path(config.POISON_LOG))
    if not log:
        return None
    by_label = Counter((log.get("original_labels") or {}).values())
    return {
        "rows": log.get("rows"),
        "flip_rate": log.get("flip_rate"),
        "seed": log.get("seed"),
        "total_flipped": log.get("total_flipped"),
        "poisoned_csv": log.get("poisoned_csv"),
        "clean_csv": log.get("clean_csv"),
        "label_column": log.get("label_column"),
        "benign_value": log.get("benign_value"),
        "flipped_by_label": pd.Series(by_label, dtype="int64").sort_values(ascending=False),
        "flipped_indices": log.get("flipped_indices") or [],
    }


# ── Composition of the poisoned dataset (cached on disk, slow first time) ──
def dataset_summary_cached(rel):
    """Returns the cached summary if the file hasn't changed since, else None."""
    p = _cache_path(rel)
    return _read_json(p) if p and p.exists() else None


def dataset_summary(rel, flipped_indices):
    path = config.project_path(rel)
    cols = list(pd.read_csv(path, nrows=0).columns)
    label_col = "Label" if "Label" in cols else ("label" if "label" in cols else None)
    if label_col is None or "device_type" not in cols:
        return {"error": "Needs a label column and a device_type column."}
    usecols = [label_col, "device_type"]
    try:
        df = pd.read_csv(path, usecols=usecols, engine="pyarrow")
    except Exception:
        df = pd.read_csv(path, usecols=usecols, dtype=str)
    dev = df["device_type"].astype(str).to_numpy()
    benign = df[label_col].astype(str).str.strip().str.upper() \
                .isin(["BENIGN", "BENIGNTRAFFIC"]).to_numpy()
    swapped = np.zeros(len(df), dtype=bool)
    idx = np.asarray([i for i in flipped_indices if 0 <= i < len(df)], dtype=int)
    swapped[idx] = True

    rows = []
    for d in sorted(set(dev)):
        m = dev == d
        rows.append({"device": d, "rows": int(m.sum()),
                     "real_benign": int((m & benign & ~swapped).sum()),
                     "swapped": int((m & swapped).sum()),
                     "attack": int((m & ~benign).sum())})
    out = {"rows": int(len(df)), "label_column": label_col, "by_device": rows,
           "labels": df[label_col].astype(str).value_counts().head(40).to_dict()}
    cp = _cache_path(rel)
    if cp:
        cp.parent.mkdir(parents=True, exist_ok=True)
        cp.write_text(json.dumps(out), encoding="utf-8")
    return out


def _cache_path(rel):
    p = config.project_path(rel)
    if not p.exists():
        return None
    st = p.stat()
    log = config.project_path(config.POISON_LOG)
    log_m = log.stat().st_mtime if log.exists() else 0
    key = f"{p.resolve()}|{st.st_size}|{st.st_mtime}|{log_m}"
    return config.CACHE_DIR / f"dataset_{hashlib.md5(key.encode()).hexdigest()[:12]}.json"


def preview(rel, n=100):
    return pd.read_csv(config.project_path(rel), nrows=n)


# ── Impact experiment (impact_autoencoder.py output) ─────────────────────
def impact_results():
    d = config.project_path(config.IMPACT_DIR)
    summary = d / "summary.csv"
    if not summary.exists():
        return None, None, None
    s = pd.read_csv(summary)
    per = d / "per_class_recall.csv"
    pc = pd.read_csv(per, index_col=0) if per.exists() else None
    meta = _read_json(d / "summary.json") or {}
    meta["mtime"] = summary.stat().st_mtime
    return s, pc, meta
