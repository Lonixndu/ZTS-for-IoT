"""
parsers.py — turns what niidlsd.py prints into numbers for the dashboard.

Pure text parsing, no imports from the project. If niidlsd.py's wording ever
changes, this is the only file to update; anything not found comes back as None
and the dashboard shows "—" instead of crashing.
"""

import re

NUM = r"([\d,]+)"


def _int(s):
    return int(s.replace(",", "")) if s is not None else None


def _find_int(pattern, text):
    m = re.search(pattern, text, re.M)
    return _int(m.group(1)) if m else None


def _pct(a, b):
    return (a / b) if (a is not None and b) else None


# ── Progress (one line at a time, while the run is going) ────────────────
PROGRESS_RE = re.compile(r"^\s*(Processed|Scanned) ([\d,]+) rows"
                         r"(?:\s*\|\s*removed so far: ([\d,]+))?")


def parse_progress_line(line):
    """{'rows': int, 'removed': int|None} for a progress line, else None."""
    m = PROGRESS_RE.match(line)
    if not m:
        return None
    return {"rows": _int(m.group(2)), "removed": _int(m.group(3))}


# ── Learn mode ───────────────────────────────────────────────────────────
def parse_learn(text):
    s = {
        "completed": "LEARNING COMPLETE" in text,
        "rows_processed": _find_int(r"Rows processed:\s+" + NUM, text),
        "skipped_unknown": _find_int(r"Skipped \(unknown device\):\s+" + NUM, text),
        "unmapped_labels": _find_int(r"Unmapped labels:\s+" + NUM, text),
        "backup": None,
        "profiles": [],
        "seconds": None,
        "error": None,
    }
    m = re.search(r"Old history backed up → (.+)$", text, re.M)
    if m:
        s["backup"] = m.group(1).strip()

    times = re.findall(r"Processed [\d,]+ rows\s+\(([\d.]+)s\)", text)
    if times:
        s["seconds"] = float(times[-1])

    sec = re.search(r"Benign profiles \(Layer 3\):\n(.*?)(?:\n\s*\n|\Z)", text, re.S)
    if sec:
        for line in sec.group(1).splitlines():
            m = re.match(r"^\s{4}(\S.*?)\s+([\d,]+) benign rows(.*)$", line)
            if m:
                s["profiles"].append({"profile": m.group(1).strip(),
                                      "benign_rows": _int(m.group(2)),
                                      "note": m.group(3).strip(" ←")})
    s["error"] = _error_tail(text) if not s["completed"] else None
    return s


# ── Detect mode ──────────────────────────────────────────────────────────
def parse_detect(text):
    s = {
        "completed": "DETECTION RESULTS" in text,
        "rows_scanned": _find_int(r"Rows scanned:\s+" + NUM, text),
        "benign_labelled": _find_int(r"BENIGN-labelled rows:\s+" + NUM, text),
        "removed": _find_int(r"REMOVED as swaps:\s+" + NUM, text),
        "kept": _find_int(r"Rows kept.*?:\s+" + NUM, text),
        "layer1": None, "layer2": None, "layer3": None,
        "suspicious_kept": _find_int(r"Suspicious \(Layer 2\).*?kept:\s+" + NUM, text),
        "examples": [],
        "seconds": None,
        "verified": False,
        "verify_note": None,
        "error": None,
    }
    m = re.search(r"Layer 1 ([\d,]+)\s*\|\s*Layer 2 alone ([\d,]+)\s*\|\s*Layer 3 ([\d,]+)", text)
    if m:
        s["layer1"], s["layer2"], s["layer3"] = (_int(m.group(i)) for i in (1, 2, 3))

    m = re.search(r"Saved: .*?\(([\d.]+)s\)", text)
    if m:
        s["seconds"] = float(m.group(1))

    sec = re.search(r"Example reasons:\n(.*?)(?:\n\s*\n|\Z)", text, re.S)
    if sec:
        for line in sec.group(1).splitlines():
            m = re.match(r"^\s+\[(L\d)\]\s+(\S+)\s+(.*)$", line)
            if m:
                s["examples"].append({"layer": m.group(1), "device": m.group(2),
                                      "reason": m.group(3).strip()})

    # ── verification block ──
    m = re.search(r"\(([^\n]*skipping verification)\)", text)
    if m:
        s["verify_note"] = m.group(1)

    if "VERIFICATION" in text:
        v = {
            "poisoned": _find_int(r"Swapped rows \(poison\):\s+" + NUM, text),
            "caught": _find_int(r"^\s+Caught:\s+" + NUM, text),
            "missed": _find_int(r"^\s+Missed:\s+" + NUM, text),
            "false_pos": _find_int(r"Real benign removed:\s+" + NUM, text),
            "real_benign_kept": None, "real_benign": None,
        }
        m = re.search(r"Real benign kept:\s+\S+\s+\(([\d,]+) / ([\d,]+)\)", text)
        if m:
            v["real_benign_kept"], v["real_benign"] = _int(m.group(1)), _int(m.group(2))
        v["recall"] = _pct(v["caught"], v["poisoned"])
        v["precision"] = _pct(v["caught"], s["removed"])
        v["benign_kept_rate"] = _pct(v["real_benign_kept"], v["real_benign"])
        s.update(v)
        s["verified"] = v["poisoned"] is not None
        s["per_device"] = _per_device_table(text)

    s["error"] = _error_tail(text) if not s["completed"] else None
    return s


def _per_device_table(text):
    rows = []
    sec = re.search(r"^\s+device\s+caught\s+missed\s+FP.*?\n(.*?)^\s*=+", text, re.S | re.M)
    if not sec:
        return rows
    for line in sec.group(1).splitlines():
        p = line.split()
        if len(p) != 7:
            continue
        dev, caught, missed, fp, _recall, real, _kept = p
        try:
            caught, missed, fp, real = (_int(x) for x in (caught, missed, fp, real))
        except ValueError:
            continue
        rows.append({
            "device": dev, "caught": caught, "missed": missed, "false_pos": fp,
            "recall": _pct(caught, caught + missed),
            "real_benign": real,
            "benign_kept": _pct(real - fp, real),
        })
    return rows


def _error_tail(text, n=12):
    """Last lines of output when a run didn't finish — usually the error message."""
    lines = [l for l in text.strip().splitlines() if l.strip()]
    return "\n".join(lines[-n:]) if lines else None
