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

# ── Tuning parameters ────────────────────────────────────
MIN_HISTORY_COUNT   = 100    # minimum label counts before history is trusted
MIN_BENIGN_SAMPLES  = 50     # minimum benign rows before statistical profile is trusted
ATTACK_RATIO_THRESH = 0.90   # if protocol is 90%+ attack historically → flag as benign suspicious
ZSCORE_THRESH       = 3.5    # Z-score beyond this = statistically anomalous
ZSCORE_MIN_HITS     = 2      # must breach Z-score on at least this many features to flag

# ── Statistical features used for Layer 3 ───────────────
# These are Member 2's training features — same columns
STAT_FEATURES = [
    "Header_Length", "Protocol Type", "Time_To_Live", "Rate",
    "fin_flag_number", "syn_flag_number", "rst_flag_number",
    "psh_flag_number", "ack_flag_number", "ack_count", "syn_count",
    "Tot sum", "Min", "Max", "AVG", "IAT"
]

# ── Label groups — 33 attack types → 6 attack categories + normal ──
LABEL_GROUPS = {
    "BENIGN": "normal",
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
    return LABEL_GROUPS.get(str(raw).strip(), "unknown")


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

def check_layer3_statistical(device_type, row, label_group, benign_profiles):
    if label_group != "normal":
        return False, ""

    profile = benign_profiles.get(device_type, {})
    if profile.get("count", 0) < MIN_BENIGN_SAMPLES:
        return False, ""

    breaches = []
    for feat in STAT_FEATURES:
        val  = to_finite(row.get(feat, None))
        mean = to_finite(profile.get(f"{feat}_mean"))
        std  = to_finite(profile.get(f"{feat}_std"))
        if val is None or mean is None or std is None or std == 0:
            continue
        z = abs((val - mean) / std)
        if z > ZSCORE_THRESH:
            breaches.append(f"{feat}(Z={z:.1f})")

    if len(breaches) >= ZSCORE_MIN_HITS:
        return True, (f"L3-STATS: {device_type} BENIGN row "
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
        val = to_finite(row.get(feat, None))
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


# ════════════════════════════════════════════════════════
# LEARNING MODE
# ════════════════════════════════════════════════════════

def run_learning_mode(input_path, history_dir, append=False):
    print("\n" + "="*55)
    print("  NIIDLSD — LEARNING MODE")
    print(f"  History dir: {history_dir}   ({'APPEND' if append else 'FRESH'})")
    print("="*55 + "\n")

    history_file, profile_file = history_paths(history_dir)

    backup = backup_history(history_dir)
    if backup:
        print(f"  Backed up existing history → {backup}")

    load_ruleset()
    if append:
        history         = load_json(history_file)
        benign_profiles = load_json(profile_file)
    else:
        history, benign_profiles = {}, {}   # Finding 4: no silent accumulation

    total = skipped_unknown = benign_learned = attack_learned = 0
    unmapped_labels = Counter()
    nonfinite = Counter()
    start = time.time()

    for chunk in pd.read_csv(input_path, chunksize=50000):
        for _, row in chunk.iterrows():
            device_type = str(row.get("device_type", "unknown")).strip()
            raw_label   = str(row.get("Label", "unknown")).strip()
            label_group = normalize_label(raw_label)
            protocol    = get_dominant_protocol(row)
            total += 1

            if label_group == "unknown":
                unmapped_labels[raw_label] += 1

            if device_type == "unknown":
                skipped_unknown += 1
                continue

            history = update_label_history(history, device_type, protocol, label_group)

            if label_group == "normal":
                for feat in STAT_FEATURES:
                    if feat in row and to_finite(row[feat]) is None:
                        nonfinite[feat] += 1
                benign_profiles = update_benign_profile(benign_profiles, device_type, row)
                benign_learned += 1
            else:
                attack_learned += 1

        print(f"  Processed {total:,} rows  |  benign learned: {benign_learned:,}  "
              f"|  attack learned: {attack_learned:,}  ({time.time()-start:.1f}s)")

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
        flag = "" if profile.get("count", 0) >= MIN_BENIGN_SAMPLES else "  (L3 inactive)"
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

def verify_against_poison_log(removed_indices, device_by_idx, n_rows, log_path):
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

    missed_unknown = {i for i in missed if device_by_idx[i] == "unknown"}
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
    print(f"  FP rate (of clean rows):    {pct(len(false_pos), n_rows - len(poisoned))}")

    # Per-device breakdown
    per = defaultdict(lambda: Counter())
    for i in caught:    per[device_by_idx[i]]["caught"] += 1
    for i in missed:    per[device_by_idx[i]]["missed"] += 1
    for i in false_pos: per[device_by_idx[i]]["fp"] += 1

    print(f"\n  {'device':<14}{'caught':>9}{'missed':>9}{'FP':>9}{'recall':>9}")
    for dev in sorted(per):
        c = per[dev]
        print(f"  {dev:<14}{c['caught']:>9,}{c['missed']:>9,}{c['fp']:>9,}"
              f"{pct(c['caught'], c['caught']+c['missed']):>9}")
    print(f"{'='*55}")


def run_detection_mode(input_path, output_path, history_dir,
                       log_path=None, update_history=False):
    print("\n" + "="*55)
    print("  NIIDLSD — DETECTION MODE")
    print(f"  History dir: {history_dir}   "
          f"({'UPDATING' if update_history else 'READ-ONLY'})")
    print("="*55 + "\n")

    history_file, profile_file = history_paths(history_dir)
    ruleset         = load_ruleset()
    history         = load_json(history_file)
    benign_profiles = load_json(profile_file)

    if not history:
        print("  WARNING: No history found. Run --mode learn first.")
        print("  Proceeding with Layer 1 (ruleset) only.\n")

    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    if os.path.exists(output_path):
        os.remove(output_path)

    removed = kept = skipped = total = 0
    l1_catches = l2_catches = l3_catches = 0
    removal_log     = []
    removed_indices = set()
    device_by_idx   = []      # device_type for every row (for verification)
    global_idx      = 0
    first_chunk     = True
    start = time.time()

    for chunk in pd.read_csv(input_path, chunksize=50000):
        keep = []
        for _, row in chunk.iterrows():
            device_type = str(row.get("device_type", "unknown")).strip()
            raw_label   = str(row.get("Label", "unknown")).strip()
            label_group = normalize_label(raw_label)
            protocol    = get_dominant_protocol(row)
            total      += 1
            row_idx     = global_idx
            global_idx += 1
            device_by_idx.append(device_type)

            if device_type == "unknown":
                skipped += 1
                keep.append(True)     # can't judge it → keep
                continue

            l1_flag, l1_reason = check_layer1_ruleset(device_type, protocol, label_group, ruleset)
            l2_flag, l2_reason = check_layer2_history(device_type, protocol, label_group, history)
            l3_flag, l3_reason = check_layer3_statistical(device_type, row, label_group, benign_profiles)

            if l1_flag or l2_flag or l3_flag:
                removed += 1
                removed_indices.add(row_idx)
                keep.append(False)
                if len(removal_log) < 5000:
                    removal_log.append({
                        "layer":       "L1" if l1_flag else ("L2" if l2_flag else "L3"),
                        "device_type": device_type,
                        "protocol":    protocol,
                        "label":       raw_label,
                        "reason":      l1_reason or l2_reason or l3_reason
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

    verify_against_poison_log(removed_indices, device_by_idx, total, log_path)
    return removed, kept


# ════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="HB-NIID-LSD — History-Based Non-IID Label Swap Detector"
    )
    parser.add_argument("--mode",   required=True, choices=["learn", "detect"])
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
    args = parser.parse_args()

    if args.mode == "learn":
        run_learning_mode(args.input, args.history_dir, append=args.append)
    else:
        run_detection_mode(args.input, args.output, args.history_dir,
                           log_path=args.log, update_history=args.update_history)

if __name__ == "__main__":
    main()
