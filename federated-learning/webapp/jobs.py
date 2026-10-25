"""
jobs.py — start / stop / look up niidlsd.py runs made from the web app.

Every run gets its own folder:  webapp/runs/<learn|detect>/<YYYYmmdd_HHMMSS>/
    job.json     what was run, from where, and a snapshot of the input files
    status.json  live progress (written by runner.py)
    log.txt      everything niidlsd.py printed
    stats.json   the numbers parsed from log.txt when the run ended
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import config

RUNNING_STATES = ("starting", "running")


def _read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def file_info(rel):
    p = config.project_path(rel)
    if not p.exists():
        return {"path": rel, "exists": False}
    st = p.stat()
    return {"path": rel, "exists": True, "size": st.st_size, "mtime": st.st_mtime}


def _poison_log_rows():
    """Row count from the attacker's log, if it belongs to the detection input."""
    log = _read_json(config.project_path(config.POISON_LOG)) or {}
    src = log.get("poisoned_csv")
    if not src:
        return None
    same = (os.path.normcase(os.path.abspath(config.PROJECT_DIR / src))
            == os.path.normcase(os.path.abspath(config.project_path(config.DETECT_INPUT))))
    return log.get("rows") if same else None


# ── Looking runs up ──────────────────────────────────────────────────────
def list_runs(job):
    d = config.RUNS_DIR / job
    if not d.exists():
        return []
    return sorted((p for p in d.iterdir() if (p / "job.json").exists()),
                  key=lambda p: p.name, reverse=True)


def load_status(run_dir):
    st = _read_json(Path(run_dir) / "status.json")
    if st is None:                                   # runner hasn't written yet
        job = _read_json(Path(run_dir) / "job.json") or {}
        st = {"state": "starting", "updated": job.get("created", time.time()),
              "started": job.get("created"), "run_id": Path(run_dir).name}
    if st.get("state") in RUNNING_STATES and \
            time.time() - st.get("updated", 0) > config.STALE_AFTER_S:
        st["state"] = "lost"                         # runner died (PC slept, killed, …)
    return st


def load_run(run_dir):
    run_dir = Path(run_dir)
    return {
        "dir": run_dir,
        "id": run_dir.name,
        "job": _read_json(run_dir / "job.json") or {},
        "status": load_status(run_dir),
        "stats": _read_json(run_dir / "stats.json"),
    }


def finished_runs(job, limit=None):
    """Completed runs (with stats), newest first."""
    out = []
    for d in list_runs(job):
        r = load_run(d)
        if r["stats"] and r["status"].get("state") == "done":
            out.append(r)
            if limit and len(out) >= limit:
                break
    return out


def active_run():
    """The run in progress (learn or detect), or None. Only one at a time."""
    for job in ("learn", "detect"):
        runs = list_runs(job)
        if runs:
            r = load_run(runs[0])
            if r["status"].get("state") in RUNNING_STATES:
                return r
    return None


def read_log(run_dir, tail=None):
    try:
        text = (Path(run_dir) / "log.txt").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    if tail:
        return "\n".join([l for l in text.splitlines() if l.strip()][-tail:])
    return text


# ── Starting / stopping ──────────────────────────────────────────────────
def start(job):
    if active_run():
        raise RuntimeError("Another run is still in progress.")
    script = config.project_path(config.DETECTOR_SCRIPT)
    if not script.exists():
        raise FileNotFoundError(f"{script} not found — check PROJECT_DIR in config.py")

    args = config.LEARN_ARGS if job == "learn" else config.DETECT_ARGS
    inp = config.LEARN_INPUT if job == "learn" else config.DETECT_INPUT
    if not config.project_path(inp).exists():
        raise FileNotFoundError(f"Input file {inp} not found in {config.PROJECT_DIR}")

    run_dir = config.RUNS_DIR / job / time.strftime("%Y%m%d_%H%M%S")
    while run_dir.exists():                          # two clicks in the same second
        time.sleep(1)
        run_dir = config.RUNS_DIR / job / time.strftime("%Y%m%d_%H%M%S")
    run_dir.mkdir(parents=True)

    spec = {
        "job": job,
        "created": time.time(),
        "cwd": str(config.PROJECT_DIR),
        "python": config.PYTHON,
        "args": list(args),
        "command": "python " + " ".join(args),
        "input": inp,
        "total_rows": _poison_log_rows() if job == "detect" else None,
        "snapshot": {
            "input": file_info(inp),
            "history": file_info(config.HISTORY_FILE),
            "profiles": file_info(config.PROFILE_FILE),
            "poison_log": file_info(config.POISON_LOG),
        },
    }
    (run_dir / "job.json").write_text(json.dumps(spec, indent=2), encoding="utf-8")

    kwargs = {}
    if os.name == "nt":   # own process group + hidden console: survives Ctrl+C on Streamlit
        kwargs["creationflags"] = 0x00000200 | 0x08000000
    else:
        kwargs["start_new_session"] = True
    with open(run_dir / "runner_output.txt", "w") as out:
        subprocess.Popen([sys.executable, str(config.WEBAPP_DIR / "runner.py"), str(run_dir)],
                         cwd=str(config.WEBAPP_DIR), stdout=out, stderr=subprocess.STDOUT,
                         stdin=subprocess.DEVNULL, close_fds=True, **kwargs)
    return run_dir


def request_stop(run_dir):
    (Path(run_dir) / "STOP").write_text("stop requested from the web app", encoding="utf-8")
