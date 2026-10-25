"""
niidlsd.py — History-Based Non-IID Label Swap Detector (HB-NIID-LSD)

Cleans a client's local training data BEFORE federated learning by removing rows
whose label was swapped from an attack to BENIGN.

    python niidlsd.py --mode learn  --input data/train.csv
    python niidlsd.py --mode detect --input data/poisoned.csv --output data/cleaned.csv

learn   reads CLEAN historical data and builds the history in history/
detect  scans a (possibly poisoned) dataset and writes the rows it keeps to --output.
        If data/poison_log.json belongs to the input file, it also grades itself
        against the attacker's answer key.

How a BENIGN-labelled row is judged ("balanced" configuration, chosen 25 Oct 2026):

  Layer 1  Ruleset   — is this protocol ever benign on this device type?
                       (ruleset.json; can't fire on CICIoT2023 — see README)
  Layer 2  History   — has this device+protocol been ≥90% attack before?
                       If yes the row is SUSPICIOUS. It only raises suspicion;
                       Layer 3 makes the call.
  Layer 3  Statistics— how far are the row's traffic statistics from this device's
                       real benign traffic? Measured on a log scale with median and
                       MAD (median absolute deviation), so a few extreme benign rows
                       can't stretch "normal" until attacks fit inside it.

  Removed if:  Layer 1 fires
           or  normal row:      ≥2 features with Z > 3.5
           or  suspicious row:  ≥1 feature  with Z > 2.0   (strong history → less evidence needed)
           or  suspicious row on a device with no benign profile (Layer 2 decides alone)
  Unknown devices are checked against a profile pooled over ALL benign traffic.

All settings are the constants below. Full research version with every option:
niidlsd_full_backup.py.

Author: IT23195370
"""

import argparse
import json
import os
import shutil
import time
from collections import Counter, defaultdict

import numpy as np
import pandas as pd


# ════════════════════════════════════════════════════════
# CONFIGURATION
# ════════════════════════════════════════════════════════

# ── Files ────────────────────────────────────────────────
HISTORY_DIR   = "history"
HISTORY_FILE  = os.path.join(HISTORY_DIR, "label_history.json")
PROFILE_FILE  = os.path.join(HISTORY_DIR, "benign_profiles.json")
RULESET_FILE  = "ruleset.json"
POISON_LOG    = os.path.join("data", "poison_log.json")   # written by attacker.py
CHUNK_SIZE    = 50_000

# ── Layer 2: history ─────────────────────────────────────
MIN_HISTORY_COUNT   = 100     # device+protocol needs this many past rows before history counts
ATTACK_RATIO_THRESH = 0.90    # ≥90% attack historically → a BENIGN row there is suspicious

# ── Layer 3: statistics ──────────────────────────────────
MIN_BENIGN_SAMPLES  = 50      # device needs this many benign rows for its own profile
Z_THRESH            = 3.5     # normal rows: a feature is "odd" above this robust Z ...
MIN_HITS            = 2       # ... and this many odd features remove the row
SUSPICIOUS_Z        = 2.0     # suspicious rows (Layer 2): lower bar ...
SUSPICIOUS_MIN_HITS = 1       # ... one odd feature is enough
RESERVOIR_SIZE      = 100_000 # max benign rows kept per profile to compute medians
GLOBAL_PROFILE      = "__global__"   # pooled benign profile, used for unknown devices

# Traffic statistics compared by Layer 3 (Member 2's training features)
STAT_FEATURES = [
    "Header_Length", "Protocol Type", "Time_To_Live", "Rate",
    "fin_flag_number", "syn_flag_number", "rst_flag_number",
    "psh_flag_number", "ack_flag_number", "ack_count", "syn_count",
    "Tot sum", "Min", "Max", "AVG", "IAT",
]
# Same feature, different name in Member 2's (Kaggle) version of CICIoT2023
FEATURE_ALIASES = {"Time_To_Live": "Duration"}

# ── Protocols, checked in this priority order ───────────
PROTOCOL_PRIORITY = ["SSH", "DNS", "DHCP", "HTTP", "HTTPS", "Telnet", "IRC",
                     "SMTP", "ICMP", "ARP", "UDP", "TCP", "IGMP", "IPv", "LLC"]

# ── 33 attack labels → 6 categories + normal (case-insensitive) ──
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
    "XSS": "exploit",                "DICTIONARYBRUTEFORCE": "exploit",
    "UPLOADING_ATTACK": "exploit",
}

# ── Layer 1 default ruleset (written to ruleset.json if missing/empty) ──
DEFAULT_RULESET = {
    "camera":      {"expected_normal": ["HTTP", "HTTPS", "TCP"],
                    "always_attack": ["Telnet", "IRC"],
                    "suspicious_if_normal": ["SSH", "SMTP", "IGMP"]},
    "router":      {"expected_normal": ["SSH", "DNS", "HTTP", "HTTPS", "DHCP", "TCP"],
                    "always_attack": ["IRC"],
                    "suspicious_if_normal": ["Telnet"]},
    "sensor":      {"expected_normal": ["ICMP", "ARP", "UDP"],
                    "always_attack": ["IRC", "Telnet", "SSH"],
                    "suspicious_if_normal": ["HTTP", "HTTPS"]},
    "smart_lock":  {"expected_normal": ["UDP", "TCP"],
                    "always_attack": ["IRC", "Telnet"],
                    "suspicious_if_normal": ["SSH", "SMTP"]},
    "generic_iot": {"expected_normal": ["TCP", "UDP"],
                    "always_attack": ["IRC", "Telnet"],
                    "suspicious_if_normal": ["SSH", "IGMP"]},
}


# ════════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════════

def load_json(path):
    if os.path.exists(path):
        with open(path) as f:
            content = f.read().strip()
            if content:
                return json.loads(content)
    return {}

def save_json(path, data):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def normalize_label(raw):
    return LABEL_GROUPS.get(str(raw).strip().upper(), "unknown")

def to_finite(val):
    """float if val is a real finite number, else None (catches NaN AND inf)."""
    try:
        f = float(val)
    except (TypeError, ValueError):
        return None
    return f if np.isfinite(f) else None

def log_scale(val):
    """sign·log1p(|x|): 10 → 2.4, 1,000 → 6.9, 1,000,000 → 13.8 — giants become just tall."""
    return None if val is None else float(np.sign(val) * np.log1p(abs(val)))

def get_dominant_protocol(row):
    for p in PROTOCOL_PRIORITY:
        if row.get(p, 0) == 1:
            return p
    return "UNKNOWN"

def read_schema(path):
    """
    Works with both CICIoT2023 versions:
      MERGED (ours):     'Label', 'BENIGN',        'Time_To_Live'
      Kaggle (Member 2): 'label', 'BenignTraffic', 'Duration'
    Returns (label_column, resolved stat feature names).
    """
    cols = list(pd.read_csv(path, nrows=0).columns)
    label_col = "Label" if "Label" in cols else ("label" if "label" in cols else None)
    if label_col is None:
        raise SystemExit(f"No 'Label' or 'label' column in {path}")
    if "device_type" not in cols:
        raise SystemExit(f"No 'device_type' column in {path} — run dataset_builder.py first")

    features, missing = [], []
    for f in STAT_FEATURES:
        if f in cols:
            features.append(f)
        elif FEATURE_ALIASES.get(f) in cols:
            features.append(FEATURE_ALIASES[f])
        else:
            missing.append(f)
    print(f"  Schema: label column '{label_col}', {len(features)} Layer 3 features"
          + (f"  (MISSING: {missing})" if missing else ""))
    return label_col, features

def load_ruleset():
    try:
        ruleset = load_json(RULESET_FILE)
    except json.JSONDecodeError:
        ruleset = {}
    if not ruleset:
        print(f"  {RULESET_FILE} missing/empty → writing default ruleset")
        save_json(RULESET_FILE, DEFAULT_RULESET)
        ruleset = DEFAULT_RULESET
    return ruleset

def read_row(row, label_col):
    return (str(row.get("device_type", "unknown")).strip(),
            str(row.get(label_col, "unknown")).strip())


# ════════════════════════════════════════════════════════
# THE THREE LAYERS
# ════════════════════════════════════════════════════════

def layer1_ruleset(device_type, protocol, ruleset):
    rules = ruleset.get(device_type, {})
    if protocol in rules.get("always_attack", []):
        return True, f"L1-RULESET: {device_type}+{protocol} is always attack, got BENIGN"
    if protocol in rules.get("suspicious_if_normal", []):
        return True, f"L1-RULESET: {device_type}+{protocol} is suspicious as BENIGN"
    return False, ""

def layer2_history(device_type, protocol, history):
    counts = history.get(f"{device_type}|{protocol}", {})
    total = sum(counts.values())
    if total < MIN_HISTORY_COUNT:
        return False, ""
    attack_ratio = (total - counts.get("normal", 0)) / total
    if attack_ratio >= ATTACK_RATIO_THRESH:
        return True, (f"L2-HISTORY: {device_type}+{protocol} is {attack_ratio*100:.1f}% "
                      f"attack historically (n={total:,})")
    return False, ""

def pick_profile(device_type, profiles):
    """Device's own benign profile; unknown devices use the pooled one; else None."""
    if profiles.get(device_type, {}).get("count", 0) >= MIN_BENIGN_SAMPLES:
        return device_type
    if device_type == "unknown" and \
            profiles.get(GLOBAL_PROFILE, {}).get("count", 0) >= MIN_BENIGN_SAMPLES:
        return GLOBAL_PROFILE
    return None

def layer3_statistics(row, profile, features, z_thresh, min_hits):
    """Robust Z per feature on log scale: |log(x) − median| / (1.4826·MAD)."""
    odd = []
    for feat in features:
        val    = log_scale(to_finite(row.get(feat)))
        center = to_finite(profile.get(f"{feat}_center"))
        scale  = to_finite(profile.get(f"{feat}_scale"))
        if val is None or center is None or scale is None or scale == 0:
            continue
        z = abs((val - center) / scale)
        if z > z_thresh:
            odd.append(f"{feat}(Z={z:.1f})")
    if len(odd) >= min_hits:
        return True, f"L3-STATS: {len(odd)} odd feature(s): {', '.join(odd[:3])}"
    return False, ""

def judge_benign_row(row, device_type, ruleset, history, profiles, features):
    """
    Returns (removed, layer, reason, suspicious) for a BENIGN-labelled row.
    This is the whole decision logic of the detector.
    """
    protocol = get_dominant_protocol(row)

    l1, why = layer1_ruleset(device_type, protocol, ruleset)
    if l1:
        return True, "L1", why, False

    suspicious, why2 = layer2_history(device_type, protocol, history)
    pkey = pick_profile(device_type, profiles)

    if pkey is None:                          # no benign profile → Layer 2 decides alone
        return suspicious, "L2", why2, suspicious

    z, hits = (SUSPICIOUS_Z, SUSPICIOUS_MIN_HITS) if suspicious else (Z_THRESH, MIN_HITS)
    l3, why3 = layer3_statistics(row, profiles[pkey], features, z, hits)
    if l3:
        where = " vs pooled profile" if pkey == GLOBAL_PROFILE else ""
        return True, "L3", why3 + where + (f"  [{why2}]" if suspicious else ""), suspicious
    return False, "", "", suspicious


# ════════════════════════════════════════════════════════
# LEARN
# ════════════════════════════════════════════════════════

def reservoir_add(samples, key, values, rng):
    """Keep a uniform random sample of ≤RESERVOIR_SIZE rows (Algorithm R)."""
    r = samples.setdefault(key, {"rows": [], "seen": 0})
    r["seen"] += 1
    if len(r["rows"]) < RESERVOIR_SIZE:
        r["rows"].append(values)
    else:
        j = int(rng.integers(0, r["seen"]))
        if j < RESERVOIR_SIZE:
            r["rows"][j] = values

def build_profile(rows, features, count):
    """
    center = median, scale = 1.4826·MAD (≈ std for normal data).
    MAD = 0 (e.g. a flag that's 0 in >50% of rows) → fall back to 1.2533·mean|x − median|
    so rare values still count; still 0 → feature is constant here and skipped.
    """
    X = np.asarray(rows, dtype=float)
    profile = {"count": count, "sample_size": len(rows)}
    for i, feat in enumerate(features):
        col = X[:, i][np.isfinite(X[:, i])]
        if len(col) == 0:
            continue
        med = float(np.median(col))
        dev = np.abs(col - med)
        scale = 1.4826 * float(np.median(dev))
        if scale == 0:
            scale = 1.2533 * float(dev.mean())
        profile[f"{feat}_center"] = med
        profile[f"{feat}_scale"]  = scale
    return profile

def run_learn(input_path):
    print("\n" + "=" * 55)
    print("  NIIDLSD — LEARN")
    print("=" * 55 + "\n")

    if os.path.exists(HISTORY_DIR) and os.listdir(HISTORY_DIR):
        backup = os.path.join(HISTORY_DIR + "_backups", time.strftime("%Y%m%d_%H%M%S"))
        shutil.copytree(HISTORY_DIR, backup)
        print(f"  Old history backed up → {backup}")

    load_ruleset()
    label_col, features = read_schema(input_path)

    history, samples, counts = {}, {}, Counter()
    rng = np.random.default_rng(42)
    total = skipped = 0
    unmapped = Counter()
    start = time.time()

    for chunk in pd.read_csv(input_path, chunksize=CHUNK_SIZE):
        for _, row in chunk.iterrows():
            total += 1
            device_type, raw_label = read_row(row, label_col)
            group = normalize_label(raw_label)
            if group == "unknown":
                unmapped[raw_label] += 1

            if group == "normal":                       # pooled profile: ALL benign rows
                values = [log_scale(to_finite(row.get(f))) for f in features]
                values = [np.nan if v is None else v for v in values]
                counts[GLOBAL_PROFILE] += 1
                reservoir_add(samples, GLOBAL_PROFILE, values, rng)

            if device_type == "unknown":
                skipped += 1
                continue

            key = f"{device_type}|{get_dominant_protocol(row)}"
            history.setdefault(key, {})
            history[key][group] = history[key].get(group, 0) + 1

            if group == "normal":
                counts[device_type] += 1
                reservoir_add(samples, device_type, values, rng)
        print(f"  Processed {total:,} rows  ({time.time()-start:.1f}s)")

    profiles = {k: build_profile(r["rows"], features, counts[k]) for k, r in samples.items()}
    profiles["__meta__"] = {"features": features,
                            "method": "median/MAD on sign·log1p scale"}
    save_json(HISTORY_FILE, history)
    save_json(PROFILE_FILE, profiles)

    print("\n" + "=" * 55)
    print("  LEARNING COMPLETE")
    print("=" * 55)
    print(f"  Rows processed:          {total:,}")
    print(f"  Skipped (unknown device): {skipped:,}  (still used for the pooled profile)")
    if unmapped:
        print(f"  ⚠ Unmapped labels: {sum(unmapped.values()):,} rows "
              f"(e.g. {', '.join(map(repr, list(unmapped)[:3]))})")

    print("\n  Benign profiles (Layer 3):")
    for key in sorted(k for k in profiles if k != "__meta__"):
        name = "ALL (pooled)" if key == GLOBAL_PROFILE else key
        note = ("  ← used for unknown devices" if key == GLOBAL_PROFILE else
                "" if profiles[key]["count"] >= MIN_BENIGN_SAMPLES else
                "  (too few → Layer 2 decides alone)")
        print(f"    {name:<14} {profiles[key]['count']:>8,} benign rows{note}")

    print("\n  History (Layer 2) — attack share per device+protocol:")
    for key, c in sorted(history.items()):
        n = sum(c.values())
        if n >= 10:
            ratio = (n - c.get("normal", 0)) / n
            flag = "  ← BENIGN here is suspicious" if (ratio >= ATTACK_RATIO_THRESH
                                                    and n >= MIN_HISTORY_COUNT) else ""
            print(f"    {key:<24} {ratio*100:5.1f}% attack  (n={n:,}){flag}")

    print(f"\n  Saved: {HISTORY_FILE}, {PROFILE_FILE}")


# ════════════════════════════════════════════════════════
# DETECT
# ════════════════════════════════════════════════════════

def run_detect(input_path, output_path):
    print("\n" + "=" * 55)
    print("  NIIDLSD — DETECT")
    print("=" * 55 + "\n")

    history  = load_json(HISTORY_FILE)
    profiles = load_json(PROFILE_FILE)
    if not history or "__meta__" not in profiles:
        raise SystemExit(f"No (current) history in {HISTORY_DIR}/ — run --mode learn first")
    ruleset = load_ruleset()
    label_col, features = read_schema(input_path)
    if features != profiles["__meta__"].get("features"):
        raise SystemExit("History was learned by an older version or on a file with different "
                         "columns — re-run --mode learn")

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    total = removed = suspicious_kept = 0
    by_layer, examples = Counter(), {}
    removed_idx, device_by_idx, benign_by_dev = set(), [], Counter()
    idx, first, start = 0, True, time.time()

    for chunk in pd.read_csv(input_path, chunksize=CHUNK_SIZE):
        keep = []
        for _, row in chunk.iterrows():
            device_type, raw_label = read_row(row, label_col)
            device_by_idx.append(device_type)
            total += 1

            if normalize_label(raw_label) != "normal":   # only BENIGN labels can be swaps
                keep.append(True)
                idx += 1
                continue

            benign_by_dev[device_type] += 1
            out, layer, why, suspicious = judge_benign_row(
                row, device_type, ruleset, history, profiles, features)
            if out:
                removed += 1
                removed_idx.add(idx)
                by_layer[layer] += 1
                examples.setdefault((layer, device_type), why)
            elif suspicious:
                suspicious_kept += 1
            keep.append(not out)
            idx += 1

        chunk[keep].to_csv(output_path, mode="w" if first else "a", header=first, index=False)
        first = False
        print(f"  Scanned {total:,} rows  |  removed so far: {removed:,}  "
              f"({time.time()-start:.1f}s)")

    print("\n" + "=" * 55)
    print("  DETECTION RESULTS")
    print("=" * 55)
    print(f"  Rows scanned:          {total:,}")
    print(f"  BENIGN-labelled rows:  {sum(benign_by_dev.values()):,}")
    print(f"  REMOVED as swaps:      {removed:,}")
    print(f"  Rows kept → output:    {total - removed:,}")
    print(f"\n  Removed by:  Layer 1 {by_layer['L1']:,}  |  Layer 2 alone {by_layer['L2']:,}"
          f"  |  Layer 3 {by_layer['L3']:,}")
    print(f"  Suspicious (Layer 2) but Layer 3 said benign → kept: {suspicious_kept:,}")
    print("\n  Example reasons:")
    for (layer, dev), why in list(examples.items())[:8]:
        print(f"    [{layer}] {dev:<12} {why}")
    print(f"\n  Saved: {output_path}   ({time.time()-start:.1f}s)")

    verify(input_path, removed_idx, device_by_idx, benign_by_dev)


# ════════════════════════════════════════════════════════
# VERIFY AGAINST THE ATTACKER'S ANSWER KEY
# ════════════════════════════════════════════════════════

def verify(input_path, removed_idx, device_by_idx, benign_by_dev):
    if not os.path.exists(POISON_LOG):
        print(f"\n  (No {POISON_LOG} — skipping verification)")
        return
    log = load_json(POISON_LOG)
    log_file = log.get("poisoned_csv")
    if log_file and os.path.abspath(log_file) != os.path.abspath(input_path):
        print(f"\n  ({POISON_LOG} belongs to {log_file} — skipping verification)")
        return
    poisoned = set(log["flipped_indices"])
    if poisoned and max(poisoned) >= len(device_by_idx):
        print(f"\n  ({POISON_LOG} doesn't match this file's rows — skipping verification)")
        return

    caught    = poisoned & removed_idx
    missed    = poisoned - removed_idx
    false_pos = removed_idx - poisoned
    real_benign = sum(benign_by_dev.values()) - len(poisoned)

    def pct(a, b):
        return f"{a/b*100:.1f}%" if b else "n/a"

    print("\n" + "=" * 55)
    print("  VERIFICATION (vs attacker's poison log)")
    print("=" * 55)
    if not log_file:
        print("  (old log without a file name — assuming it matches)")
    print(f"  Swapped rows (poison):   {len(poisoned):,}")
    print(f"  Caught:                  {len(caught):,}")
    print(f"  Missed:                  {len(missed):,}")
    print(f"  Real benign removed:     {len(false_pos):,}  (false positives)")
    print("  " + "─" * 45)
    print(f"  Recall (swaps caught):   {pct(len(caught), len(poisoned))}")
    print(f"  Precision:               {pct(len(caught), len(removed_idx))}"
          "  (of removed rows, share that were swaps)")
    print(f"  Real benign kept:        {pct(real_benign - len(false_pos), real_benign)}"
          f"  ({real_benign - len(false_pos):,} / {real_benign:,})")

    per = defaultdict(Counter)
    for i in caught:    per[device_by_idx[i]]["caught"] += 1
    for i in missed:    per[device_by_idx[i]]["missed"] += 1
    for i in false_pos: per[device_by_idx[i]]["fp"] += 1
    pois_by_dev = Counter(device_by_idx[i] for i in poisoned)

    print(f"\n  {'device':<12}{'caught':>9}{'missed':>8}{'FP':>8}{'recall':>8}"
          f"{'real_ben':>10}{'kept':>8}")
    for dev in sorted(set(per) | set(benign_by_dev)):
        c = per[dev]
        real = benign_by_dev.get(dev, 0) - pois_by_dev.get(dev, 0)
        print(f"  {dev:<12}{c['caught']:>9,}{c['missed']:>8,}{c['fp']:>8,}"
              f"{pct(c['caught'], c['caught'] + c['missed']):>8}{real:>10,}"
              f"{pct(real - c['fp'], real):>8}")
    print("=" * 55)


# ════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(description="Non-IID Label Swap Detector")
    ap.add_argument("--mode", required=True, choices=["learn", "detect"])
    ap.add_argument("--input", required=True, help="CSV with device_type + label columns")
    ap.add_argument("--output", help="(detect) where to write the cleaned CSV")
    args = ap.parse_args()

    if args.mode == "learn":
        run_learn(args.input)
    else:
        if not args.output:
            raise SystemExit("--mode detect needs --output")
        run_detect(args.input, args.output)

if __name__ == "__main__":
    main()
