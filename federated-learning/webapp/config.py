"""
config.py — where the web app finds your project and which commands it runs.

This is the ONLY file you should need to edit.

The web app never imports or changes niidlsd.py. It runs it exactly like you do in
the terminal (same commands as the README) and reads what it prints and the files
it writes.
"""

import os
import sys
from pathlib import Path

WEBAPP_DIR = Path(__file__).resolve().parent

# Folder that contains niidlsd.py, attacker.py, data/, history/ ...
# Default: the folder ABOVE webapp/ (i.e. put webapp/ inside your project folder).
# Override without editing: set the NIIDLSD_PROJECT_DIR environment variable.
PROJECT_DIR = Path(os.environ.get("NIIDLSD_PROJECT_DIR", WEBAPP_DIR.parent)).resolve()

# Python used to run niidlsd.py. Default: the same Python that runs Streamlit.
# If your project uses a different virtual environment, set NIIDLSD_PYTHON to that
# python executable (e.g. C:\path\to\venv\Scripts\python.exe).
PYTHON = os.environ.get("NIIDLSD_PYTHON", sys.executable)

# ── Files, relative to PROJECT_DIR (same as the README pipeline) ──
DETECTOR_SCRIPT = "niidlsd.py"
LEARN_INPUT     = "data/train.csv"      # history half (clean)
DETECT_INPUT    = "data/poisoned.csv"   # client round after attacker.py
DETECT_OUTPUT   = "data/cleaned.csv"    # rows the detector keeps
POISON_LOG      = "data/poison_log.json"
HISTORY_FILE    = "history/label_history.json"
PROFILE_FILE    = "history/benign_profiles.json"
RULESET_FILE    = "ruleset.json"
IMPACT_DIR      = "results/impact"      # impact_autoencoder.py --out

# ── The two commands the Re-Run buttons execute (run from PROJECT_DIR) ──
LEARN_ARGS  = [DETECTOR_SCRIPT, "--mode", "learn", "--input", LEARN_INPUT]
DETECT_ARGS = [DETECTOR_SCRIPT, "--mode", "detect",
               "--input", DETECT_INPUT, "--output", DETECT_OUTPUT]

# ── Where the web app keeps its own records (never inside your project files) ──
RUNS_DIR  = WEBAPP_DIR / "runs"     # one folder per run: log, status, parsed stats
CACHE_DIR = WEBAPP_DIR / "cache"    # cached dataset summaries

# A running job that hasn't reported in this long is treated as crashed.
STALE_AFTER_S = 45


def project_path(rel):
    return PROJECT_DIR / rel
