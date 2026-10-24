"""
niidlsd.py
History-Based Non-IID Label Swap Detector (HB-NIID-LSD)

Two modes:
  --mode learn    : Process clean dataset, build history + benign profiles
  --mode detect   : Run detection on (potentially poisoned) dataset

Usage:
  python niidlsd.py --mode learn  --input dataset_with_devices.csv
  python niidlsd.py --mode detect --input poisoned_dataset.csv --output clean_dataset.csv

Author: IT23195370
"""

import pandas as pd
import numpy as np
import json
import os
import argparse
import time
from collections import defaultdict

# ── Paths ────────────────────────────────────────────────
HISTORY_FILE        = "history/label_history.json"
BENIGN_PROFILE_FILE = "history/benign_profiles.json"
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

# ── Label groups — 33 attack types → 6 categories ───────
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
# JSON HELPERS
# ════════════════════════════════════════════════════════

def load_json(path):
    if os.path.exists(path):
        with open(path, "r") as f:
            content = f.read().strip()
            if content:
                return json.loads(content)
    return {}

def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def load_ruleset():
    """
    Load device-type ruleset from JSON.
    In real deployment, this is a shared file synced with Member 1 and Member 3.
    For POC, we maintain it locally.
    """
    if not os.path.exists(RULESET_FILE):
        # Auto-create a default ruleset if none exists
        default = {
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
        save_json(RULESET_FILE, default)
        print(f"  Created default ruleset at {RULESET_FILE}")
    return load_json(RULESET_FILE)


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
# "Is this protocol always-attack or suspicious for this device type?"
# Works from round 1 — no history needed.
# ════════════════════════════════════════════════════════

def check_layer1_ruleset(device_type, protocol, label_group, ruleset):
    """
    Returns (flagged: bool, reason: str)
    """
    rules = ruleset.get(device_type, {})

    # Hard block: this protocol should NEVER be benign for this device type
    if protocol in rules.get("always_attack", []):
        if label_group == "normal":
            return True, f"L1-RULESET: {device_type}+{protocol} is always attack, got BENIGN"

    # Soft check: suspicious when labeled benign for this device type
    if protocol in rules.get("suspicious_if_normal", []):
        if label_group == "normal":
            return True, f"L1-RULESET: {device_type}+{protocol} is suspicious as BENIGN"

    return False, ""


# ════════════════════════════════════════════════════════
# LAYER 2 — LABEL HISTORY CHECK
# "Does this label match what this device historically labels this protocol as?"
# Requires MIN_HISTORY_COUNT entries before activating.
# ════════════════════════════════════════════════════════

def check_layer2_history(device_type, protocol, label_group, history):
    """
    Returns (flagged: bool, reason: str)
    """
    key = f"{device_type}|{protocol}"
    proto_hist = history.get(key, {})
    total = sum(proto_hist.values())

    if total < MIN_HISTORY_COUNT:
        return False, ""  # warming up — not enough data yet

    normal_count = proto_hist.get("normal", 0)
    attack_total = total - normal_count
    attack_ratio = attack_total / total

    # If historically almost always attack, but this row says normal → flip detected
    if attack_ratio >= ATTACK_RATIO_THRESH and label_group == "normal":
        return True, (f"L2-HISTORY: {device_type}+{protocol} is "
                      f"{attack_ratio*100:.1f}% attack historically, got BENIGN "
                      f"(n={total})")

    return False, ""

def update_label_history(history, device_type, protocol, label_group):
    """Add one verified-clean row to the label history."""
    key = f"{device_type}|{protocol}"
    if key not in history:
        history[key] = {}
    history[key][label_group] = history[key].get(label_group, 0) + 1
    return history


# ════════════════════════════════════════════════════════
# LAYER 3 — STATISTICAL BOUNDARY CHECK
# "Do the statistical features of this BENIGN-labeled row
#  actually match the benign traffic profile for this device type?"
#
# This catches the hard case: camera + HTTP + BENIGN but Rate=50,000
# (DDoS on a normal port, label flipped to BENIGN)
#
# Only runs on rows labeled BENIGN.
# Requires MIN_BENIGN_SAMPLES in profile before activating.
# ════════════════════════════════════════════════════════

def check_layer3_statistical(device_type, row, label_group, benign_profiles):
    """
    Returns (flagged: bool, reason: str)
    Only meaningful for rows labeled BENIGN.
    """
    if label_group != "normal":
        return False, ""  # only check rows claiming to be benign

    profile = benign_profiles.get(device_type, {})
    if profile.get("count", 0) < MIN_BENIGN_SAMPLES:
        return False, ""  # not enough benign data yet to build a profile

    breaches = []
    for feat in STAT_FEATURES:
        val = row.get(feat, None)
        if val is None or pd.isna(val):
            continue
        mean = profile.get(f"{feat}_mean")
        std  = profile.get(f"{feat}_std")
        if mean is None or std is None or std == 0:
            continue
        z = abs((float(val) - mean) / std)
        if z > ZSCORE_THRESH:
            breaches.append(f"{feat}(Z={z:.1f})")

    if len(breaches) >= ZSCORE_MIN_HITS:
        return True, (f"L3-STATS: {device_type} BENIGN row "
                      f"statistically anomalous on {len(breaches)} features: "
                      f"{', '.join(breaches[:3])}")

    return False, ""

def update_benign_profile(benign_profiles, device_type, row):
    """
    Incrementally updates the running mean and std for benign traffic
    of this device type using Welford's online algorithm.
    (Welford's = computes mean/std without storing all values in memory)
    """
    if device_type not in benign_profiles:
        benign_profiles[device_type] = {"count": 0}

    p = benign_profiles[device_type]
    n = p["count"] + 1
    p["count"] = n

    for feat in STAT_FEATURES:
        val = row.get(feat, None)
        if val is None or pd.isna(val):
            continue
        val = float(val)

        mean_key = f"{feat}_mean"
        m2_key   = f"{feat}_m2"   # sum of squared deviations (for std)

        if mean_key not in p:
            p[mean_key] = val
            p[m2_key]   = 0.0
        else:
            old_mean     = p[mean_key]
            p[mean_key] += (val - old_mean) / n
            p[m2_key]   += (val - old_mean) * (val - p[mean_key])

        # Compute std from M2
        if n > 1:
            p[f"{feat}_std"] = (p[m2_key] / (n - 1)) ** 0.5
        else:
            p[f"{feat}_std"] = 0.0

    return benign_profiles


# ════════════════════════════════════════════════════════
# LEARNING MODE
# Process clean dataset → build history + benign profiles
# ════════════════════════════════════════════════════════

def run_learning_mode(input_path):
    print("\n" + "="*55)
    print("  NIIDLSD — LEARNING MODE")
    print("  Building history and benign profiles from clean data")
    print("="*55 + "\n")

    ruleset        = load_ruleset()
    history        = load_json(HISTORY_FILE)
    benign_profiles = load_json(BENIGN_PROFILE_FILE)

    total = 0
    skipped_unknown = 0
    benign_learned  = 0
    attack_learned  = 0

    start = time.time()

    for chunk in pd.read_csv(input_path, chunksize=50000):
        for _, row in chunk.iterrows():
            device_type = str(row.get("device_type", "unknown")).strip()
            raw_label   = str(row.get("Label", "unknown")).strip()
            label_group = normalize_label(raw_label)
            protocol    = get_dominant_protocol(row)

            total += 1

            # Skip unknowns — no device context to learn from
            if device_type == "unknown":
                skipped_unknown += 1
                continue

            # Update label history for this device+protocol combination
            history = update_label_history(history, device_type, protocol, label_group)

            # If benign, update statistical profile for Layer 3
            if label_group == "normal":
                benign_profiles = update_benign_profile(benign_profiles, device_type, row)
                benign_learned += 1
            else:
                attack_learned += 1

        elapsed = time.time() - start
        print(f"  Processed {total:,} rows  |  benign learned: {benign_learned:,}  "
              f"|  attack learned: {attack_learned:,}  ({elapsed:.1f}s)")

    # Save
    save_json(HISTORY_FILE, history)
    save_json(BENIGN_PROFILE_FILE, benign_profiles)

    # ── Summary ───────────────────────────────────────────
    print("\n" + "="*55)
    print("  LEARNING COMPLETE")
    print("="*55)
    print(f"  Total rows processed:  {total:,}")
    print(f"  Skipped (unknown):     {skipped_unknown:,}")
    print(f"  Benign rows learned:   {benign_learned:,}")
    print(f"  Attack rows learned:   {attack_learned:,}")

    print(f"\n  Label history entries: {len(history)}")
    print(f"  Benign profiles built: {len(benign_profiles)}")

    print("\n  Benign profile sample counts per device type:")
    for dtype, profile in benign_profiles.items():
        print(f"    {dtype:<15}: {profile.get('count', 0):,} benign rows")

    print("\n  History sample (attack ratios):")
    for key, counts in history.items():
        total_h = sum(counts.values())
        if total_h < 10:
            continue
        normal = counts.get("normal", 0)
        attack = total_h - normal
        ratio  = (attack / total_h) * 100
        print(f"    {key:<30}: {ratio:.1f}% attack  (n={total_h:,})")

    print(f"\n  Saved: {HISTORY_FILE}")
    print(f"  Saved: {BENIGN_PROFILE_FILE}")


# ════════════════════════════════════════════════════════
# DETECTION MODE
# Run three-layer checks on potentially poisoned dataset
# ════════════════════════════════════════════════════════

def verify_against_poison_log(removed_indices, log_path):
    """Cross-checks detector removals against attacker's poison log."""
    if not log_path or not os.path.exists(log_path):
        return
    with open(log_path) as f:
        log = json.load(f)

    poisoned_set = set(log["flipped_indices"])
    caught       = poisoned_set.intersection(removed_indices)
    missed       = poisoned_set - removed_indices
    false_pos    = removed_indices - poisoned_set   # removed but weren't poisoned

    print(f"\n{'='*55}")
    print(f"  POISON LOG VERIFICATION")
    print(f"{'='*55}")
    print(f"  Total poisoned rows:    {len(poisoned_set):,}")
    print(f"  Caught by detector:     {len(caught):,}  "
          f"({len(caught)/len(poisoned_set)*100:.1f}%)")
    print(f"  Missed by detector:     {len(missed):,}  "
          f"({len(missed)/len(poisoned_set)*100:.1f}%)")
    print(f"  False positives:        {len(false_pos):,}  "
          f"(clean rows wrongly removed)")
    print(f"{'='*55}")


def run_detection_mode(input_path, output_path, log_path=None):
    print("\n" + "="*55)
    print("  NIIDLSD — DETECTION MODE")
    print("  Scanning for label swap attacks")
    print("="*55 + "\n")

    ruleset         = load_ruleset()
    history         = load_json(HISTORY_FILE)
    benign_profiles = load_json(BENIGN_PROFILE_FILE)

    if not history:
        print("  WARNING: No history found. Run --mode learn first.")
        print("  Proceeding with Layer 1 (ruleset) only.\n")

    clean_rows       = []
    removed          = 0
    l1_catches       = 0
    l2_catches       = 0
    l3_catches       = 0
    skipped          = 0
    total            = 0
    removal_log      = []
    removed_indices  = set()   # tracks original CSV row indices for log verification
    global_idx       = 0       # running row index across chunks

    start = time.time()

    for chunk in pd.read_csv(input_path, chunksize=50000):
        for _, row in chunk.iterrows():
            device_type = str(row.get("device_type", "unknown")).strip()
            raw_label   = str(row.get("Label", "unknown")).strip()
            label_group = normalize_label(raw_label)
            protocol    = get_dominant_protocol(row)
            total      += 1
            row_idx     = global_idx
            global_idx += 1

            # Skip unknown device types — no context for detection
            if device_type == "unknown":
                skipped += 1
                clean_rows.append(row)  # keep it, can't judge it
                continue

            # ── Layer 1: Ruleset ─────────────────────────
            l1_flag, l1_reason = check_layer1_ruleset(
                device_type, protocol, label_group, ruleset)

            # ── Layer 2: Label history ───────────────────
            l2_flag, l2_reason = check_layer2_history(
                device_type, protocol, label_group, history)

            # ── Layer 3: Statistical boundary ────────────
            l3_flag, l3_reason = check_layer3_statistical(
                device_type, row, label_group, benign_profiles)

            # ── Decision ─────────────────────────────────
            if l1_flag or l2_flag or l3_flag:
                removed += 1
                removed_indices.add(row_idx)
                reason = l1_reason or l2_reason or l3_reason
                removal_log.append({
                    "layer":       "L1" if l1_flag else ("L2" if l2_flag else "L3"),
                    "device_type": device_type,
                    "protocol":    protocol,
                    "label":       raw_label,
                    "reason":      reason
                })
                if l1_flag: l1_catches += 1
                if l2_flag: l2_catches += 1
                if l3_flag: l3_catches += 1
            else:
                clean_rows.append(row)
                # Update history with verified-clean rows
                history = update_label_history(history, device_type, protocol, label_group)
                if label_group == "normal":
                    benign_profiles = update_benign_profile(
                        benign_profiles, device_type, row)

    elapsed = time.time() - start

    # ── Save clean dataset ────────────────────────────────
    clean_df = pd.DataFrame(clean_rows)
    clean_df.to_csv(output_path, index=False)

    # Save updated history (learned from clean rows this round)
    save_json(HISTORY_FILE, history)
    save_json(BENIGN_PROFILE_FILE, benign_profiles)

    # ── Results ───────────────────────────────────────────
    print("="*55)
    print("  DETECTION RESULTS")
    print("="*55)
    print(f"  Total rows scanned:   {total:,}")
    print(f"  Skipped (unknown):    {skipped:,}")
    print(f"  REMOVED (flagged):    {removed:,}  ({removed/total*100:.2f}%)")
    print(f"  Clean rows kept:      {len(clean_rows):,}")
    print(f"\n  Layer breakdown:")
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

    # ── Cross-check against poison log if provided ────────
    verify_against_poison_log(removed_indices, log_path)

    return removed, len(clean_rows)


# ════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="HB-NIID-LSD — History-Based Non-IID Label Swap Detector"
    )
    parser.add_argument("--mode",   required=True, choices=["learn", "detect"],
                        help="learn: build history | detect: scan for label swaps")
    parser.add_argument("--input",  required=True,
                        help="Input CSV (must have device_type and Label columns)")
    parser.add_argument("--output", default="clean_output.csv",
                        help="Output CSV path (detect mode only)")
    parser.add_argument("--log",    default=None,
                        help="Path to poison_log.json for catch-rate verification")
    args = parser.parse_args()

    if args.mode == "learn":
        run_learning_mode(args.input)
    elif args.mode == "detect":
        run_detection_mode(args.input, args.output, log_path=args.log)

if __name__ == "__main__":
    main()
