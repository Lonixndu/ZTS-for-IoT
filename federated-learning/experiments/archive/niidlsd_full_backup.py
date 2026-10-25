"""
niidlsd.py
History-Based Non-IID Label Swap Detector (HB-NIID-LSD)

Two modes:
  --mode learn    : Process clean dataset, build history + benign profiles
                    (starts FRESH by default; old history is backed up first)
  --mode detect   : Run detection on (potentially poisoned) dataset
                    (history is READ-ONLY by default; pass --update-history
                     to write verified-clean rows back, i.e. production mode)

Usage:
  python niidlsd.py --mode learn  --input dataset_with_devices.csv
  python niidlsd.py --mode detect --input data/poisoned_dataset.csv \
                    --output data/clean_output.csv --log data/poison_log.json

Optional:
  --history-dir DIR     keep each experiment's history separate (default: history)
  --append              (learn) add to existing history instead of starting fresh
  --update-history      (detect) write clean rows back into history

Changelog (17 Oct 2026):
  - Finding 1: empty / invalid ruleset.json now falls back to the default ruleset
  - Finding 4: learn starts fresh + backs up; detect no longer contaminates history
  - Finding 5: non-finite values (inf / NaN) are skipped in Layer 3
  - Verification: in-scope vs out-of-scope misses, per-device breakdown, precision
  - Clean CSV is written chunk-by-chunk (no 700k-row list of Series in memory)
  - Unmapped labels are counted and reported

Changelog (23–24 Oct 2026):
  - --decision gated / --check-unknown, global benign profile, benign retention report
  - Works on Member 2's Kaggle CICIoT2023 schema too: 'label' column,
    'BenignTraffic', case-insensitive labels, 'Duration' used for 'Time_To_Live'

Changelog (25 Oct 2026):
  - --l3-scale log (learn): Layer 3 on log scale — raw Z-scores broke on Member 2's
    heavy-tailed features (recall 22.6%). Scale is stored in the profiles.
  - --l3-stats robust (learn): median/MAD instead of mean/std — outlier-proof
  - --z-thresh / --min-hits (detect) for tuning Layer 3 without editing the code
  - --suspicious-z / --suspicious-min-hits (detect, gated): separate Layer 3 bar
    for rows Layer 2 already finds suspicious
  - --mode sweep: recall / benign kept for a grid of Layer 3 settings in one pass

Author: IT23195370
"""

import pandas as pd
import numpy as np
import json
import os
import shutil
import argparse
import time
from collections import Counter, defaultdict

# ── Paths ────────────────────────────────────────────────
DEFAULT_HISTORY_DIR = "history"
HISTORY_FILENAME    = "label_history.json"
PROFILE_FILENAME    = "benign_profiles.json"
RULESET_FILE        = "ruleset.json"
GLOBAL_PROFILE      = "__global__"   # benign profile pooled over ALL benign rows (incl. unknown device)

# ── Tuning parameters ────────────────────────────────────
MIN_HISTORY_COUNT   = 100    # minimum label counts before history is trusted
MIN_BENIGN_SAMPLES  = 50     # minimum benign rows before statistical profile is trusted
ATTACK_RATIO_THRESH = 0.90   # if protocol is 90%+ attack historically → flag as benign suspicious
ZSCORE_THRESH       = 3.5    # Z-score beyond this = statistically anomalous
ZSCORE_MIN_HITS     = 2      # must breach Z-score on at least this many features to flag

# Layer 3 scale. "raw" = original behaviour. "log" = Z-scores on sign·log1p(value).
# Why (25 Oct run on Member 2's data): a few benign rows with huge Rate / IAT values
# (Rate up to 8.4M, IAT up to 1.7e8) inflate the raw std so much that almost nothing
# breaches Z>3.5 — L3 "cleared" 138k poisoned rows. Log scale stops the extremes
# dominating. Chosen at learn time and stored in the profiles (__meta__), so
# detect always uses the same scale the profiles were built with.
L3_SCALE            = "raw"
META_KEY            = "__meta__"

# Layer 3 statistics. "meanstd" = Welford mean/std (original). "robust" = median and
# MAD (median absolute deviation) of the benign rows — outliers can't drag them.
# Same 25 Oct finding: with heavy tails, even log-scale mean/std let poison through.
# Robust stats are computed at the end of learn mode from (a reservoir sample of)
# the benign rows; the profiles store {feat}_center / {feat}_scale.
L3_STATS            = "meanstd"

# Gated mode: Layer 3 bar for rows Layer 2 already finds suspicious (≥90%-attack
# device+protocol). None = same bar as every other row. A lower bar there is the
# "strong prior needs less evidence" idea: history already says BENIGN is unlikely.
SUSPICIOUS_Z        = None
SUSPICIOUS_MIN_HITS = None
RESERVOIR_SIZE      = 100_000   # max benign rows kept per profile for robust stats

# ── Statistical features used for Layer 3 ───────────────
# These are Member 2's training features — same columns
BASE_STAT_FEATURES = [
    "Header_Length", "Protocol Type", "Time_To_Live", "Rate",
    "fin_flag_number", "syn_flag_number", "rst_flag_number",
    "psh_flag_number", "ack_flag_number", "ack_count", "syn_count",
    "Tot sum", "Min", "Max", "AVG", "IAT"
]
# Same feature, different name in Member 2's (Kaggle) version of CICIoT2023
FEATURE_ALIASES = {"Time_To_Live": "Duration"}

# Resolved per input file by prepare_schema() — don't edit these two by hand
STAT_FEATURES = list(BASE_STAT_FEATURES)
LABEL_COL     = "Label"


def prepare_schema(input_path):
    """
    Works with both CICIoT2023 versions:
      MERGED (ours):     'Label' column, 'BENIGN',        'Time_To_Live'
      Kaggle (Member 2): 'label' column, 'BenignTraffic', 'Duration'
    Sets LABEL_COL and STAT_FEATURES for this file and reports anything missing
    (previously a missing feature was skipped silently).
    """
    global LABEL_COL, STAT_FEATURES
    cols = list(pd.read_csv(input_path, nrows=0).columns)

    if "Label" in cols:
        LABEL_COL = "Label"
    elif "label" in cols:
        LABEL_COL = "label"
    else:
        raise ValueError(f"No 'Label' or 'label' column in {input_path}")

    if "device_type" not in cols:
        print("  WARNING: no 'device_type' column — every row is 'unknown'. "
              "Run dataset_builder.py first.")

    resolved, missing = [], []
    for f in BASE_STAT_FEATURES:
        if f in cols:
            resolved.append(f)
        elif FEATURE_ALIASES.get(f) in cols:
            resolved.append(FEATURE_ALIASES[f])
        else:
            missing.append(f)
    STAT_FEATURES = resolved

    print(f"  Schema: label column '{LABEL_COL}', {len(STAT_FEATURES)} L3 features"
          + (f"  (MISSING: {missing})" if missing else ""))

# ── Label groups — 33 attack types → 6 attack categories + normal ──
LABEL_GROUPS = {
    "BENIGN": "normal",              "BENIGNTRAFFIC": "normal",
    "DDOS-SYN_FLOOD": "ddos",        "DDOS-UDP_FLOOD": "ddos",
    "DDOS-TCP_FLOOD": "ddos",        "DDOS-ICMP_FLOOD": "ddos",
    "DDOS-PSHACK_FLOOD": "ddos",     "DDOS-RSTFINFLOOD": "ddos",
    "DDOS-SLOWLORIS": "ddos",        "DDOS-HTTP_FLOOD": "ddos",
    "DDOS-UDP_FRAGMENTATION": "ddos","DDOS-ICMP_FRAGMENTATION": "ddos",
    "DDOS-ACK_FRAGMENTATION": "ddos","DDOS-SYNONYMOUSIP_FLOOD": "ddos",
    "DOS-SYN_FLOOD": "dos",          "DOS-UDP_FLOOD": "dos",
    "DOS-TCP_FLOOD": "dos",          "DOS-HTTP_FLOOD": "dos",
    "RECON-PORTSCAN": "recon",       "RECON-OSSCAN": "recon",
    "RECON-PINGSWEEP": "recon",      "RECON-HOSTDISCOVERY": "recon",
    "VULNERABILITYSCAN": "recon",
    "MIRAI-GREIP_FLOOD": "mirai",    "MIRAI-GREETH_FLOOD": "mirai",
    "MIRAI-UDPPLAIN": "mirai",
    "MITM-ARPSPOOFING": "intrusion", "DNS_SPOOFING": "intrusion",
    "BACKDOOR_MALWARE": "intrusion", "BROWSERHIJACKING": "intrusion",
    "COMMANDINJECTION": "exploit",   "SQLINJECTION": "exploit",
    "XSS": "exploit",               "DICTIONARYBRUTEFORCE": "exploit",
    "UPLOADING_ATTACK": "exploit",
}

def normalize_label(raw):
    # Case-insensitive: 'DDoS-ICMP_Flood' (Kaggle) == 'DDOS-ICMP_FLOOD' (MERGED)
    return LABEL_GROUPS.get(str(raw).strip().upper(), "unknown")


# ════════════════════════════════════════════════════════
# JSON / PATH HELPERS
# ════════════════════════════════════════════════════════

def history_paths(history_dir):
    return (os.path.join(history_dir, HISTORY_FILENAME),
            os.path.join(history_dir, PROFILE_FILENAME))

def load_json(path):
    if os.path.exists(path):
        with open(path, "r") as f:
            content = f.read().strip()
            if content:
                return json.loads(content)
    return {}

def save_json(path, data):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def backup_history(history_dir):
    """Copy existing history files to history_dir/backup_<timestamp>/ before overwriting."""
    files = [p for p in history_paths(history_dir) if os.path.exists(p)]
    if not files:
        return None
    stamp = time.strftime("%Y%m%d_%H%M%S")
    backup_dir = os.path.join(history_dir, f"backup_{stamp}")
    os.makedirs(backup_dir, exist_ok=True)
    for p in files:
        shutil.copy2(p, backup_dir)
    return backup_dir

def l3_value(val):
    """Apply the Layer 3 scale (see L3_SCALE) to an already-finite value."""
    if val is None or L3_SCALE == "raw":
        return val
    return float(np.sign(val) * np.log1p(abs(val)))

def to_finite(val):
    """
    Returns val as float if it is a real, finite number, else None.
    (Finding 5: CICIoT2023 'Rate' contains inf — pd.isna() does NOT catch inf,
     and one inf poisons Welford's mean → inf → NaN forever.)
    """
    if val is None:
        return None
    try:
        f = float(val)
    except (TypeError, ValueError):
        return None
    return f if np.isfinite(f) else None


# ════════════════════════════════════════════════════════
# RULESET
# ════════════════════════════════════════════════════════

DEFAULT_RULESET = {
    "camera": {
        "expected_normal": ["HTTP", "HTTPS", "TCP"],
        "always_attack":   ["Telnet", "IRC"],
        "suspicious_if_normal": ["SSH", "SMTP", "IGMP"]
    },
    "router": {
        "expected_normal": ["SSH", "DNS", "HTTP", "HTTPS", "DHCP", "TCP"],
        "always_attack":   ["IRC"],
        "suspicious_if_normal": ["Telnet"]
    },
    "sensor": {
        "expected_normal": ["ICMP", "ARP", "UDP"],
        "always_attack":   ["IRC", "Telnet", "SSH"],
        "suspicious_if_normal": ["HTTP", "HTTPS"]
    },
    "smart_lock": {
        "expected_normal": ["UDP", "TCP"],
        "always_attack":   ["IRC", "Telnet"],
        "suspicious_if_normal": ["SSH", "SMTP"]
    },
    "generic_iot": {
        "expected_normal": ["TCP", "UDP"],
        "always_attack":   ["IRC", "Telnet"],
        "suspicious_if_normal": ["SSH", "IGMP"]
    }
}

def load_ruleset():
    """
    Load device-type ruleset from JSON.
    In real deployment, this is a shared file synced with Member 1 and Member 3.
    For POC, we maintain it locally.

    Finding 1 fix: a missing, EMPTY, invalid or {} file all fall back to the
    default ruleset (previously an empty file loaded as {} → Layer 1 silently dead).
    """
    ruleset, problem = None, None
    if not os.path.exists(RULESET_FILE):
        problem = "missing"
    else:
        try:
            ruleset = load_json(RULESET_FILE)
            if not ruleset:
                problem = "empty"
        except json.JSONDecodeError as e:
            problem = f"invalid JSON ({e})"

    if problem:
        print(f"  WARNING: {RULESET_FILE} is {problem} → writing default ruleset")
        save_json(RULESET_FILE, DEFAULT_RULESET)
        ruleset = DEFAULT_RULESET

    n_rules = sum(len(v.get("always_attack", [])) + len(v.get("suspicious_if_normal", []))
                  for v in ruleset.values())
    print(f"  Ruleset loaded: {len(ruleset)} device types, {n_rules} L1 rules")
    return ruleset


# ════════════════════════════════════════════════════════
# PROTOCOL DETECTION
# ════════════════════════════════════════════════════════

PROTOCOL_COLS = ["HTTP","HTTPS","DNS","Telnet","SMTP","SSH","IRC",
                 "TCP","UDP","DHCP","ARP","ICMP","IGMP","IPv","LLC"]

def get_dominant_protocol(row):
    """Returns the first active protocol found (priority order)."""
    priority = ["SSH","DNS","DHCP","HTTP","HTTPS","Telnet","IRC",
                "SMTP","ICMP","ARP","UDP","TCP","IGMP","IPv","LLC"]
    for p in priority:
        if row.get(p, 0) == 1:
            return p
    return "UNKNOWN"


# ════════════════════════════════════════════════════════
# LAYER 1 — RULESET CHECK
# ════════════════════════════════════════════════════════

def check_layer1_ruleset(device_type, protocol, label_group, ruleset):
    rules = ruleset.get(device_type, {})

    if protocol in rules.get("always_attack", []):
        if label_group == "normal":
            return True, f"L1-RULESET: {device_type}+{protocol} is always attack, got BENIGN"

    if protocol in rules.get("suspicious_if_normal", []):
        if label_group == "normal":
            return True, f"L1-RULESET: {device_type}+{protocol} is suspicious as BENIGN"

    return False, ""


# ════════════════════════════════════════════════════════
# LAYER 2 — LABEL HISTORY CHECK
# ════════════════════════════════════════════════════════

def check_layer2_history(device_type, protocol, label_group, history):
    key = f"{device_type}|{protocol}"
    proto_hist = history.get(key, {})
    total = sum(proto_hist.values())

    if total < MIN_HISTORY_COUNT:
        return False, ""

    normal_count = proto_hist.get("normal", 0)
    attack_ratio = (total - normal_count) / total

    if attack_ratio >= ATTACK_RATIO_THRESH and label_group == "normal":
        return True, (f"L2-HISTORY: {device_type}+{protocol} is "
                      f"{attack_ratio*100:.1f}% attack historically, got BENIGN "
                      f"(n={total})")

    return False, ""

def update_label_history(history, device_type, protocol, label_group):
    key = f"{device_type}|{protocol}"
    if key not in history:
        history[key] = {}
    history[key][label_group] = history[key].get(label_group, 0) + 1
    return history


# ════════════════════════════════════════════════════════
# LAYER 3 — STATISTICAL BOUNDARY CHECK
# ════════════════════════════════════════════════════════

def pick_profile(device_type, benign_profiles):
    """
    Which benign profile should judge this row?
      1. the device's own profile, if it has enough samples
      2. unknown device → the global (pooled) benign profile, if it exists
      3. else None → Layer 3 can't judge it, so Layer 2 decides alone

    Why the global profile is NOT a fallback for known devices (23 Oct run):
    pooled benign traffic is so varied that its std is huge, so almost
    nothing breaches Z>3.5 against it. Using it to "confirm" L2 on sensor /
    smart_lock cleared nearly all poison (recall 100% → 5.5% / 0%).
    A known device with ~no benign history is exactly where L2 is right.
    """
    if benign_profiles.get(device_type, {}).get("count", 0) >= MIN_BENIGN_SAMPLES:
        return device_type
    if device_type == "unknown" and \
            benign_profiles.get(GLOBAL_PROFILE, {}).get("count", 0) >= MIN_BENIGN_SAMPLES:
        return GLOBAL_PROFILE
    return None

def layer3_zscores(row, profile):
    """[(feature, |Z|), ...] for every usable feature of this row vs a benign profile."""
    c_key, s_key = (("_center", "_scale") if L3_STATS == "robust"
                    else ("_mean", "_std"))
    out = []
    for feat in STAT_FEATURES:
        val  = l3_value(to_finite(row.get(feat, None)))
        mean = to_finite(profile.get(f"{feat}{c_key}"))
        std  = to_finite(profile.get(f"{feat}{s_key}"))
        if val is None or mean is None or std is None or std == 0:
            continue
        out.append((feat, abs((val - mean) / std)))
    return out

def check_layer3_statistical(device_type, row, label_group, benign_profiles,
                             profile_key=None, z_thresh=None, min_hits=None):
    if label_group != "normal":
        return False, ""

    z_thresh = ZSCORE_THRESH if z_thresh is None else z_thresh
    min_hits = ZSCORE_MIN_HITS if min_hits is None else min_hits

    profile_key = profile_key or device_type
    profile = benign_profiles.get(profile_key, {})
    if profile.get("count", 0) < MIN_BENIGN_SAMPLES:
        return False, ""

    breaches = [f"{feat}(Z={z:.1f})" for feat, z in layer3_zscores(row, profile)
                if z > z_thresh]

    if len(breaches) >= min_hits:
        src = " (global profile)" if profile_key == GLOBAL_PROFILE else ""
        return True, (f"L3-STATS: {device_type} BENIGN row{src} "
                      f"statistically anomalous on {len(breaches)} features: "
                      f"{', '.join(breaches[:3])}")

    return False, ""

def update_benign_profile(benign_profiles, device_type, row):
    """
    Welford's online algorithm, PER FEATURE count.
    Each feature keeps its own n, so skipping an inf/NaN value for one feature
    doesn't corrupt the mean/std of that feature (or any other).
    """
    if device_type not in benign_profiles:
        benign_profiles[device_type] = {"count": 0}

    p = benign_profiles[device_type]
    p["count"] = p["count"] + 1

    for feat in STAT_FEATURES:
        val = l3_value(to_finite(row.get(feat, None)))
        if val is None:
            continue

        n_key, mean_key, m2_key = f"{feat}_n", f"{feat}_mean", f"{feat}_m2"
        n = p.get(n_key, 0) + 1
        p[n_key] = n

        if n == 1:
            p[mean_key] = val
            p[m2_key]   = 0.0
        else:
            old_mean     = p[mean_key]
            p[mean_key] += (val - old_mean) / n
            p[m2_key]   += (val - old_mean) * (val - p[mean_key])

        p[f"{feat}_std"] = (p[m2_key] / (n - 1)) ** 0.5 if n > 1 else 0.0

    return benign_profiles


def reservoir_add(samples, key, row, rng):
    """Algorithm R: keep a uniform random sample of ≤RESERVOIR_SIZE benign rows."""
    vals = [l3_value(to_finite(row.get(f, None))) for f in STAT_FEATURES]
    vals = [np.nan if v is None else v for v in vals]
    r = samples.setdefault(key, {"rows": [], "seen": 0})
    r["seen"] += 1
    if len(r["rows"]) < RESERVOIR_SIZE:
        r["rows"].append(vals)
    else:
        j = int(rng.integers(0, r["seen"]))
        if j < RESERVOIR_SIZE:
            r["rows"][j] = vals

def add_robust_stats(benign_profiles, samples):
    """
    Per profile + feature: center = median, scale = 1.4826·MAD (≈ std for normal data).
    If MAD = 0 (e.g. a flag that is 0 in >50% of benign rows) fall back to
    1.2533·mean|x − median| so rare values still count; if that is 0 too, the
    feature is constant for this device and is skipped (scale 0), like std == 0.
    """
    for key, r in samples.items():
        if key not in benign_profiles or not r["rows"]:
            continue
        X = np.asarray(r["rows"], dtype=float)
        p = benign_profiles[key]
        for i, feat in enumerate(STAT_FEATURES):
            col = X[:, i][np.isfinite(X[:, i])]
            if len(col) == 0:
                continue
            med = float(np.median(col))
            dev = np.abs(col - med)
            scale = 1.4826 * float(np.median(dev))
            if scale == 0:
                scale = 1.2533 * float(dev.mean())
            p[f"{feat}_center"] = med
            p[f"{feat}_scale"]  = scale
        p["robust_sample_size"] = len(r["rows"])


# ════════════════════════════════════════════════════════
# LEARNING MODE
# ════════════════════════════════════════════════════════

def run_learning_mode(input_path, history_dir, append=False, l3_scale="raw",
                      l3_stats="meanstd"):
    global L3_SCALE, L3_STATS
    L3_SCALE = l3_scale
    L3_STATS = l3_stats
    print("\n" + "="*55)
    print("  NIIDLSD — LEARNING MODE")
    print(f"  History dir: {history_dir}   ({'APPEND' if append else 'FRESH'})"
          f"   |   L3: {L3_STATS.upper()} on {L3_SCALE.upper()} scale")
    print("="*55 + "\n")

    history_file, profile_file = history_paths(history_dir)

    backup = backup_history(history_dir)
    if backup:
        print(f"  Backed up existing history → {backup}")

    load_ruleset()
    prepare_schema(input_path)
    if append:
        history         = load_json(history_file)
        benign_profiles = load_json(profile_file)
        old = benign_profiles.get(META_KEY, {})
        if benign_profiles and (old.get("l3_scale", "raw") != L3_SCALE
                                or old.get("l3_stats", "meanstd") != L3_STATS):
            raise SystemExit("Existing profiles were built with different L3 settings "
                             f"({old}) — can't append. Learn fresh instead.")
        if L3_STATS == "robust":
            raise SystemExit("--append with robust stats isn't supported yet "
                             "(medians need the rows). Learn fresh instead.")
    else:
        history, benign_profiles = {}, {}   # Finding 4: no silent accumulation
    benign_profiles[META_KEY] = {"l3_scale": L3_SCALE, "l3_stats": L3_STATS}
    samples = {}                                 # robust stats: benign row reservoirs
    rng = np.random.default_rng(42)

    total = skipped_unknown = benign_learned = attack_learned = 0
    unmapped_labels = Counter()
    nonfinite = Counter()
    start = time.time()

    for chunk in pd.read_csv(input_path, chunksize=50000):
        for _, row in chunk.iterrows():
            device_type = str(row.get("device_type", "unknown")).strip()
            raw_label   = str(row.get(LABEL_COL, "unknown")).strip()
            label_group = normalize_label(raw_label)
            protocol    = get_dominant_protocol(row)
            total += 1

            if label_group == "unknown":
                unmapped_labels[raw_label] += 1

            # Global benign profile learns from EVERY benign row — including
            # unknown-device ones, which the per-device stuff below skips.
            if label_group == "normal":
                benign_profiles = update_benign_profile(benign_profiles, GLOBAL_PROFILE, row)
                if L3_STATS == "robust":
                    reservoir_add(samples, GLOBAL_PROFILE, row, rng)

            if device_type == "unknown":
                skipped_unknown += 1
                continue

            history = update_label_history(history, device_type, protocol, label_group)

            if label_group == "normal":
                for feat in STAT_FEATURES:
                    if feat in row and to_finite(row[feat]) is None:
                        nonfinite[feat] += 1
                benign_profiles = update_benign_profile(benign_profiles, device_type, row)
                if L3_STATS == "robust":
                    reservoir_add(samples, device_type, row, rng)
                benign_learned += 1
            else:
                attack_learned += 1

        print(f"  Processed {total:,} rows  |  benign learned: {benign_learned:,}  "
              f"|  attack learned: {attack_learned:,}  ({time.time()-start:.1f}s)")

    if L3_STATS == "robust":
        add_robust_stats(benign_profiles, samples)

    save_json(history_file, history)
    save_json(profile_file, benign_profiles)

    print("\n" + "="*55)
    print("  LEARNING COMPLETE")
    print("="*55)
    print(f"  Total rows processed:  {total:,}")
    print(f"  Skipped (unknown dev): {skipped_unknown:,}")
    print(f"  Benign rows learned:   {benign_learned:,}")
    print(f"  Attack rows learned:   {attack_learned:,}")

    if unmapped_labels:
        print(f"\n  ⚠ Unmapped labels (counted as ATTACK in L2!): "
              f"{sum(unmapped_labels.values()):,} rows")
        for lbl, c in unmapped_labels.most_common(10):
            print(f"    {lbl!r:<40} {c:,}")

    if nonfinite:
        print(f"\n  Non-finite values skipped in benign profiles:")
        for feat, c in nonfinite.most_common():
            print(f"    {feat:<20} {c:,}")

    print(f"\n  Label history entries: {len(history)}")
    print(f"  Benign profiles built: {len(benign_profiles)}")

    print("\n  Benign profile sample counts per device type:")
    for dtype, profile in benign_profiles.items():
        if dtype == META_KEY:
            continue
        flag = "" if profile.get("count", 0) >= MIN_BENIGN_SAMPLES else "  (L3 inactive)"
        if dtype == GLOBAL_PROFILE:
            dtype, flag = "ALL (global)", "  ← pooled over every device incl. unknown"
        print(f"    {dtype:<15}: {profile.get('count', 0):,} benign rows{flag}")

    print("\n  History sample (attack ratios):")
    for key, counts in sorted(history.items()):
        total_h = sum(counts.values())
        if total_h < 10:
            continue
        ratio = (total_h - counts.get("normal", 0)) / total_h * 100
        print(f"    {key:<30}: {ratio:.1f}% attack  (n={total_h:,})")

    print(f"\n  Saved: {history_file}")
    print(f"  Saved: {profile_file}")


# ════════════════════════════════════════════════════════
# DETECTION MODE
# ════════════════════════════════════════════════════════

def verify_against_poison_log(removed_indices, device_by_idx, n_rows, log_path,
                              benign_by_dev=None, check_unknown=False):
    """Cross-checks detector removals against attacker's poison log."""
    if not log_path:
        return
    if not os.path.exists(log_path):
        print(f"\n  WARNING: poison log not found: {log_path}")
        return
    with open(log_path) as f:
        log = json.load(f)

    poisoned = set(log["flipped_indices"])
    caught   = poisoned & removed_indices
    missed   = poisoned - removed_indices
    false_pos = removed_indices - poisoned

    missed_unknown = (set() if check_unknown else
                      {i for i in missed if device_by_idx[i] == "unknown"})
    missed_inscope = missed - missed_unknown
    in_scope       = poisoned - missed_unknown

    def pct(a, b):
        return f"{a/b*100:.1f}%" if b else "n/a"

    print(f"\n{'='*55}")
    print(f"  POISON LOG VERIFICATION")
    print(f"{'='*55}")
    print(f"  Total poisoned rows:        {len(poisoned):,}")
    print(f"    out of scope (unknown):   {len(missed_unknown):,}")
    print(f"    in scope (known device):  {len(in_scope):,}")
    print(f"  Caught:                     {len(caught):,}")
    print(f"  Missed (in scope):          {len(missed_inscope):,}")
    print(f"  False positives:            {len(false_pos):,}  (clean rows wrongly removed)")
    print(f"  ─────────────────────────────────────────────")
    print(f"  Recall (all poisoned):      {pct(len(caught), len(poisoned))}")
    print(f"  Recall (in scope):          {pct(len(caught), len(in_scope))}")
    print(f"  Precision:                  {pct(len(caught), len(removed_indices))}")
    # FP rate vs REAL BENIGN rows (the only rows that can be false positives).
    # The old line divided by all non-poisoned rows — mostly attack rows — so
    # 78% benign lost showed up as "2.0%". (Fixed 25 Oct.)
    real_benign = sum((benign_by_dev or {}).values()) - len(poisoned)
    print(f"  FP rate (of real benign):   {pct(len(false_pos), real_benign)}"
          f"  ({len(false_pos):,} of {real_benign:,} real benign rows removed)")

    # Per-device breakdown
    per = defaultdict(lambda: Counter())
    for i in caught:    per[device_by_idx[i]]["caught"] += 1
    for i in missed:    per[device_by_idx[i]]["missed"] += 1
    for i in false_pos: per[device_by_idx[i]]["fp"] += 1

    # Genuine benign per device = rows labelled BENIGN in the poisoned file
    # minus the poisoned ones. Retention = share of REAL benign the detector kept.
    # (This is what the FL client actually needs — a detector that deletes every
    #  benign row has great recall and a useless client.)
    benign_by_dev = benign_by_dev or {}
    poisoned_by_dev = Counter(device_by_idx[i] for i in poisoned)

    print(f"\n  {'device':<12}{'caught':>8}{'missed':>8}{'FP':>7}{'recall':>8}"
          f"{'real_ben':>10}{'retained':>10}")
    tot_real = tot_fp = 0
    for dev in sorted(set(per) | set(benign_by_dev)):
        c = per[dev]
        real = benign_by_dev.get(dev, 0) - poisoned_by_dev.get(dev, 0)
        in_scope_dev = check_unknown or dev != "unknown"
        ret  = pct(real - c['fp'], real) if in_scope_dev else "skip"
        if in_scope_dev:
            tot_real += real
            tot_fp   += c['fp']
        print(f"  {dev:<12}{c['caught']:>8,}{c['missed']:>8,}{c['fp']:>7,}"
              f"{pct(c['caught'], c['caught']+c['missed']):>8}{real:>10,}{ret:>10}")
    print(f"  ─────────────────────────────────────────────")
    print(f"  Real benign retained (in scope): {pct(tot_real - tot_fp, tot_real)}"
          f"  ({tot_real - tot_fp:,} / {tot_real:,})")
    print(f"{'='*55}")


def run_detection_mode(input_path, output_path, history_dir,
                       log_path=None, update_history=False,
                       decision="any", check_unknown=False):
    """
    decision="any"   : (baseline) remove if L1 OR L2 OR L3 fires
    decision="gated" : L2 only raises SUSPICION. Removal needs:
                         - L1 fires, OR
                         - L3 fires (device's own profile; global only for unknown), OR
                         - L2 fires AND the device has no benign profile of its own
                       → real benign rows that fit the benign profile survive
                         even on a "99.5% attack" device+protocol.
    check_unknown    : run L3 (global profile) on unknown-device rows
                       instead of skipping them.
    """
    print("\n" + "="*55)
    print("  NIIDLSD — DETECTION MODE")
    print(f"  History dir: {history_dir}   "
          f"({'UPDATING' if update_history else 'READ-ONLY'})")
    print(f"  Decision: {decision.upper()}   |   Unknown devices: "
          f"{'CHECKED (global profile)' if check_unknown else 'SKIPPED'}")
    print("="*55 + "\n")

    history_file, profile_file = history_paths(history_dir)
    ruleset         = load_ruleset()
    prepare_schema(input_path)
    history         = load_json(history_file)
    benign_profiles = load_json(profile_file)

    global L3_SCALE, L3_STATS
    meta = benign_profiles.get(META_KEY, {})
    L3_SCALE = meta.get("l3_scale", "raw")
    L3_STATS = meta.get("l3_stats", "meanstd")
    print(f"  L3: {L3_STATS.upper()} on {L3_SCALE.upper()} scale (from profiles), "
          f"Z > {ZSCORE_THRESH} on ≥{ZSCORE_MIN_HITS} features")
    if decision == "gated" and (SUSPICIOUS_Z is not None or SUSPICIOUS_MIN_HITS is not None):
        print(f"      L2-suspicious rows: Z > "
              f"{ZSCORE_THRESH if SUSPICIOUS_Z is None else SUSPICIOUS_Z} on ≥"
              f"{ZSCORE_MIN_HITS if SUSPICIOUS_MIN_HITS is None else SUSPICIOUS_MIN_HITS}")
    if L3_STATS == "robust" and update_history:
        print("  NOTE: --update-history refreshes counts/mean/std only; the robust "
              "medians stay as learned until the next learn run.")

    if not history:
        print("  WARNING: No history found. Run --mode learn first.")
        print("  Proceeding with Layer 1 (ruleset) only.\n")

    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    if os.path.exists(output_path):
        os.remove(output_path)

    if decision == "gated" or check_unknown:
        g = benign_profiles.get(GLOBAL_PROFILE, {}).get("count", 0)
        if g < MIN_BENIGN_SAMPLES:
            print(f"  WARNING: global benign profile missing/small (n={g}). "
                  f"Re-run --mode learn with this version.\n")

    removed = kept = skipped = total = 0
    l1_catches = l2_catches = l3_catches = 0
    l2_cleared = 0            # gated: L2 suspicious, but L3 said "fits benign" → kept
    removal_log     = []
    removed_indices = set()
    device_by_idx   = []      # device_type for every row (for verification)
    benign_by_dev   = Counter()  # rows labelled BENIGN per device (poisoned + real)
    global_idx      = 0
    first_chunk     = True
    start = time.time()

    for chunk in pd.read_csv(input_path, chunksize=50000):
        keep = []
        for _, row in chunk.iterrows():
            device_type = str(row.get("device_type", "unknown")).strip()
            raw_label   = str(row.get(LABEL_COL, "unknown")).strip()
            label_group = normalize_label(raw_label)
            protocol    = get_dominant_protocol(row)
            total      += 1
            row_idx     = global_idx
            global_idx += 1
            device_by_idx.append(device_type)
            if label_group == "normal":
                benign_by_dev[device_type] += 1

            if device_type == "unknown" and not check_unknown:
                skipped += 1
                keep.append(True)     # can't judge it → keep
                continue

            l1_flag, l1_reason = check_layer1_ruleset(device_type, protocol, label_group, ruleset)
            l2_flag, l2_reason = check_layer2_history(device_type, protocol, label_group, history)

            if decision == "any":
                pkey = GLOBAL_PROFILE if device_type == "unknown" else device_type
            else:
                pkey = pick_profile(device_type, benign_profiles)

            if pkey:
                if decision == "gated" and l2_flag:
                    l3_flag, l3_reason = check_layer3_statistical(
                        device_type, row, label_group, benign_profiles, profile_key=pkey,
                        z_thresh=SUSPICIOUS_Z, min_hits=SUSPICIOUS_MIN_HITS)
                else:
                    l3_flag, l3_reason = check_layer3_statistical(
                        device_type, row, label_group, benign_profiles, profile_key=pkey)
            else:
                l3_flag, l3_reason = False, ""

            if decision == "any":
                flagged = l1_flag or l2_flag or l3_flag
            else:
                flagged = l1_flag or l3_flag or (l2_flag and pkey is None)
                if l2_flag and not flagged:
                    l2_cleared += 1

            if flagged:
                removed += 1
                removed_indices.add(row_idx)
                keep.append(False)
                if len(removal_log) < 5000:
                    removal_log.append({
                        "layer":       "L1" if l1_flag else ("L3" if l3_flag else "L2"),
                        "device_type": device_type,
                        "protocol":    protocol,
                        "label":       raw_label,
                        "reason":      l1_reason or l3_reason or l2_reason
                    })
                l1_catches += l1_flag
                l2_catches += l2_flag
                l3_catches += l3_flag
            else:
                keep.append(True)
                if update_history:    # Finding 4: only when explicitly asked
                    history = update_label_history(history, device_type, protocol, label_group)
                    if label_group == "normal":
                        benign_profiles = update_benign_profile(benign_profiles, device_type, row)

        clean_chunk = chunk[keep]
        kept += len(clean_chunk)
        clean_chunk.to_csv(output_path, mode="a", header=first_chunk, index=False)
        first_chunk = False
        print(f"  Scanned {total:,} rows  |  removed so far: {removed:,}  "
              f"({time.time()-start:.1f}s)")

    elapsed = time.time() - start

    if update_history:
        backup = backup_history(history_dir)
        if backup:
            print(f"\n  Backed up history before update → {backup}")
        save_json(history_file, history)
        save_json(profile_file, benign_profiles)
        print(f"  History updated with this round's clean rows")

    print("\n" + "="*55)
    print("  DETECTION RESULTS")
    print("="*55)
    print(f"  Total rows scanned:   {total:,}")
    print(f"  Skipped (unknown):    {skipped:,}")
    print(f"  REMOVED (flagged):    {removed:,}  ({removed/max(total,1)*100:.2f}%)")
    print(f"  Clean rows kept:      {kept:,}")
    print(f"\n  Layer breakdown (layers overlap):")
    print(f"    Layer 1 (Ruleset):  {l1_catches:,} catches")
    print(f"    Layer 2 (History):  {l2_catches:,} catches")
    print(f"    Layer 3 (Stats):    {l3_catches:,} catches")
    if decision == "gated":
        print(f"    L2 suspicious but cleared by L3 (kept): {l2_cleared:,}")
    print(f"\n  Sample removal reasons:")
    seen = set()
    for entry in removal_log:
        key = entry["layer"] + entry["device_type"] + entry["protocol"]
        if key not in seen:
            print(f"    [{entry['layer']}] {entry['device_type']} | "
                  f"{entry['protocol']} | {entry['label']}")
            print(f"         → {entry['reason']}")
            seen.add(key)
        if len(seen) >= 8:
            break

    print(f"\n  Saved clean dataset → {output_path}")
    print(f"  Time: {elapsed:.1f}s")

    verify_against_poison_log(removed_indices, device_by_idx, total, log_path,
                              benign_by_dev=benign_by_dev,
                              check_unknown=check_unknown)
    return removed, kept


# ════════════════════════════════════════════════════════
# SWEEP MODE — tune Layer 3 in one pass
# ════════════════════════════════════════════════════════

SWEEP_Z    = [2.0, 2.5, 3.0, 3.5, 4.0, 5.0, 6.0]
SWEEP_HITS = [1, 2, 3]

def run_sweep_mode(input_path, history_dir, log_path, check_unknown=False):
    """
    Same rows and same gated logic as detect, but instead of one (Z, hits) setting
    it scores a whole grid from ONE pass: for every BENIGN-labelled row it keeps the
    3 largest Layer 3 Z-scores, then "flagged at (z, k)" = k-th largest Z > z.
    Needs the poison log. Writes no CSV — pick a setting, then run detect with it.
    """
    print("\n" + "="*62)
    print("  NIIDLSD — SWEEP MODE (gated)")
    print(f"  History dir: {history_dir}   |   Unknown devices: "
          f"{'CHECKED' if check_unknown else 'SKIPPED'}")
    print("="*62 + "\n")
    if not log_path or not os.path.exists(log_path):
        raise SystemExit("Sweep mode needs --log poison_log.json")

    history_file, profile_file = history_paths(history_dir)
    ruleset         = load_ruleset()
    prepare_schema(input_path)
    history         = load_json(history_file)
    benign_profiles = load_json(profile_file)

    global L3_SCALE, L3_STATS
    meta = benign_profiles.get(META_KEY, {})
    L3_SCALE = meta.get("l3_scale", "raw")
    L3_STATS = meta.get("l3_stats", "meanstd")
    print(f"  L3: {L3_STATS.upper()} on {L3_SCALE.upper()} scale (from profiles)")

    with open(log_path) as f:
        poisoned = set(json.load(f)["flipped_indices"])

    # per BENIGN-labelled, in-scope row
    is_poison, is_l1, is_l2, has_prof, top = [], [], [], [], []
    out_of_scope_poison = 0
    idx, start = 0, time.time()

    for chunk in pd.read_csv(input_path, chunksize=50000):
        for _, row in chunk.iterrows():
            i, idx = idx, idx + 1
            label_group = normalize_label(str(row.get(LABEL_COL, "unknown")).strip())
            if label_group != "normal":
                continue
            device_type = str(row.get("device_type", "unknown")).strip()
            if device_type == "unknown" and not check_unknown:
                out_of_scope_poison += i in poisoned
                continue
            protocol = get_dominant_protocol(row)
            l1, _ = check_layer1_ruleset(device_type, protocol, label_group, ruleset)
            l2, _ = check_layer2_history(device_type, protocol, label_group, history)
            pkey = pick_profile(device_type, benign_profiles)
            zs = (sorted((z for _, z in layer3_zscores(row, benign_profiles[pkey])),
                         reverse=True) if pkey else [])
            zs = (zs + [0.0, 0.0, 0.0])[:3]
            is_poison.append(i in poisoned); is_l1.append(l1); is_l2.append(l2)
            has_prof.append(pkey is not None); top.append(zs)
        print(f"  Scanned {idx:,} rows  ({time.time()-start:.1f}s)")

    P  = np.array(is_poison); L1 = np.array(is_l1); L2 = np.array(is_l2)
    HP = np.array(has_prof);  T  = np.array(top)
    n_poison = len(poisoned)
    n_real   = int((~P).sum())
    base     = L1 | (L2 & ~HP)            # removed regardless of the Layer 3 bar

    def score(flag):
        caught = int((flag & P).sum()); fp = int((flag & ~P).sum())
        return caught, n_poison - caught, fp

    def table(title, make_flag):
        print(f"\n  {title}")
        print(f"  {'Z >':>6}{'hits':>6}{'recall':>9}{'missed':>9}{'FP':>9}"
              f"{'benign kept':>13}{'precision':>11}")
        rows = []
        for z in SWEEP_Z:
            for k in SWEEP_HITS:
                flag = make_flag(z, k)
                c, m, fp = score(flag)
                rows.append((z, k, c, m, fp))
                prec = c / (c + fp) * 100 if c + fp else 0
                print(f"  {z:>6}{k:>6}{c/n_poison*100:>8.1f}%{m:>9,}{fp:>9,}"
                      f"{(n_real-fp)/n_real*100:>12.1f}%{prec:>10.1f}%")
        return rows

    print(f"\n  Poisoned rows: {n_poison:,}   real benign in scope: {n_real:,}"
          + (f"   (poison out of scope: {out_of_scope_poison:,})" if out_of_scope_poison else ""))

    table("A) Same Layer 3 bar for every row",
          lambda z, k: base | (HP & (T[:, k-1] > z)))
    table(f"B) Normal rows fixed at Z>{ZSCORE_THRESH}/≥{ZSCORE_MIN_HITS}; "
          f"bar below applies to L2-suspicious rows only",
          lambda z, k: base | (HP & ~L2 & (T[:, ZSCORE_MIN_HITS-1] > ZSCORE_THRESH))
                            | (HP & L2 & (T[:, k-1] > z)))
    print("\n  Pick a row, then run detect with --z-thresh/--min-hits (table A)")
    print("  or --suspicious-z/--suspicious-min-hits (table B).")


# ════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════

def main():
    global ZSCORE_THRESH, ZSCORE_MIN_HITS, SUSPICIOUS_Z, SUSPICIOUS_MIN_HITS
    parser = argparse.ArgumentParser(
        description="HB-NIID-LSD — History-Based Non-IID Label Swap Detector"
    )
    parser.add_argument("--mode",   required=True, choices=["learn", "detect", "sweep"])
    parser.add_argument("--input",  required=True,
                        help="Input CSV (must have device_type and Label columns)")
    parser.add_argument("--output", default="clean_output.csv",
                        help="Output CSV path (detect mode only)")
    parser.add_argument("--log",    default=None,
                        help="Path to poison_log.json for catch-rate verification")
    parser.add_argument("--history-dir", default=DEFAULT_HISTORY_DIR,
                        help="Folder for label_history.json + benign_profiles.json")
    parser.add_argument("--append", action="store_true",
                        help="(learn) add to existing history instead of starting fresh")
    parser.add_argument("--update-history", action="store_true",
                        help="(detect) write verified-clean rows back to history")
    parser.add_argument("--decision", choices=["any", "gated"], default="any",
                        help="(detect) any = baseline OR of layers; "
                             "gated = L2 suspicion must be confirmed by L3")
    parser.add_argument("--check-unknown", action="store_true",
                        help="(detect) check unknown-device rows with the global benign profile")
    parser.add_argument("--l3-scale", choices=["raw", "log"], default="raw",
                        help="(learn) scale for Layer 3 profiles; detect reads it from the profiles")
    parser.add_argument("--l3-stats", choices=["meanstd", "robust"], default="meanstd",
                        help="(learn) meanstd = Welford mean/std; robust = median/MAD")
    parser.add_argument("--z-thresh", type=float, default=None,
                        help=f"(detect) Layer 3 Z-score threshold (default {ZSCORE_THRESH})")
    parser.add_argument("--min-hits", type=int, default=None,
                        help=f"(detect) features that must breach (default {ZSCORE_MIN_HITS})")
    parser.add_argument("--suspicious-z", type=float, default=None,
                        help="(detect, gated) Layer 3 Z threshold for L2-suspicious rows")
    parser.add_argument("--suspicious-min-hits", type=int, default=None,
                        help="(detect, gated) features that must breach on L2-suspicious rows")
    args = parser.parse_args()

    if args.z_thresh is not None:
        ZSCORE_THRESH = args.z_thresh
    if args.min_hits is not None:
        ZSCORE_MIN_HITS = args.min_hits
    SUSPICIOUS_Z        = args.suspicious_z
    SUSPICIOUS_MIN_HITS = args.suspicious_min_hits

    if args.mode == "learn":
        run_learning_mode(args.input, args.history_dir, append=args.append,
                          l3_scale=args.l3_scale, l3_stats=args.l3_stats)
    elif args.mode == "sweep":
        run_sweep_mode(args.input, args.history_dir, args.log,
                       check_unknown=args.check_unknown)
    else:
        run_detection_mode(args.input, args.output, args.history_dir,
                           log_path=args.log, update_history=args.update_history,
                           decision=args.decision, check_unknown=args.check_unknown)

if __name__ == "__main__":
    main()
