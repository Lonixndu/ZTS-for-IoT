"""
runner.py — runs ONE niidlsd.py job in the background for the web app.

Started by jobs.py as its own process, so a run keeps going even if the browser
tab is closed or Streamlit reruns the page. It:
  1. runs the command stored in <run_dir>/job.json from the project folder
     (exactly what you'd type in the terminal),
  2. copies everything niidlsd.py prints into <run_dir>/log.txt,
  3. keeps <run_dir>/status.json up to date (progress, heartbeat, exit code),
  4. when finished, parses the log into <run_dir>/stats.json.

Stop: the web app creates <run_dir>/STOP; the runner then terminates the job.

    python runner.py <run_dir>
"""

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import parsers  # noqa: E402

HEARTBEAT_S = 2.0


def write_json(path, data):
    """Atomic write (temp file + replace), retried: on Windows a reader can briefly lock it."""
    tmp = Path(str(path) + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    for _ in range(20):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            time.sleep(0.05)
    os.replace(tmp, path)


def count_rows(path):
    """Data rows in a CSV (newlines minus the header) — fast, without parsing."""
    n, last = 0, b"\n"
    with open(path, "rb") as f:
        while True:
            block = f.read(1 << 24)
            if not block:
                break
            n += block.count(b"\n")
            last = block[-1:]
    if last != b"\n":
        n += 1
    return max(n - 1, 0)


def main(run_dir):
    run_dir = Path(run_dir)
    job = json.loads((run_dir / "job.json").read_text(encoding="utf-8"))
    status_path, log_path = run_dir / "status.json", run_dir / "log.txt"
    lock = threading.Lock()
    status = {
        "state": "starting", "job": job["job"], "run_id": run_dir.name,
        "runner_pid": os.getpid(), "started": time.time(), "updated": time.time(),
        "ended": None, "returncode": None, "total_rows": job.get("total_rows"),
        "rows_done": 0, "removed_so_far": None, "last_line": "Starting…",
    }

    def save(**changes):
        with lock:
            status.update(changes, updated=time.time())
            write_json(status_path, status)

    save()

    if not status["total_rows"]:
        save(last_line="Counting rows in the input file…")
        try:
            status["total_rows"] = count_rows(Path(job["cwd"]) / job["input"])
        except OSError:
            status["total_rows"] = None

    env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1", PYTHONUNBUFFERED="1")
    flags = 0x08000000 if os.name == "nt" else 0          # CREATE_NO_WINDOW
    proc = subprocess.Popen(
        [job["python"], "-u", *job["args"]], cwd=job["cwd"], env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
        text=True, encoding="utf-8", errors="replace", bufsize=1, creationflags=flags,
    )
    save(state="running", child_pid=proc.pid, last_line="Running…")

    stopped = threading.Event()

    def heartbeat():
        while proc.poll() is None:
            if (run_dir / "STOP").exists() and not stopped.is_set():
                stopped.set()
                proc.terminate()
            save()
            time.sleep(HEARTBEAT_S)

    threading.Thread(target=heartbeat, daemon=True).start()

    with open(log_path, "w", encoding="utf-8") as log:
        for line in proc.stdout:
            log.write(line)
            log.flush()
            text = line.rstrip()
            if not text.strip():
                continue
            p = parsers.parse_progress_line(text)
            if p:
                save(rows_done=p["rows"], removed_so_far=p["removed"], last_line=text.strip())
            else:
                save(last_line=text.strip())

    rc = proc.wait()
    text = log_path.read_text(encoding="utf-8", errors="replace")
    stats = parsers.parse_learn(text) if job["job"] == "learn" else parsers.parse_detect(text)
    stats["returncode"] = rc
    write_json(run_dir / "stats.json", stats)

    state = "stopped" if stopped.is_set() else ("done" if rc == 0 and stats["completed"] else "failed")
    save(state=state, returncode=rc, ended=time.time())


if __name__ == "__main__":
    try:
        main(sys.argv[1])
    except Exception as e:                       # never die silently
        rd = Path(sys.argv[1])
        try:
            st = json.loads((rd / "status.json").read_text(encoding="utf-8"))
        except Exception:
            st = {"run_id": rd.name}
        st.update(state="failed", ended=time.time(), updated=time.time(),
                  last_line=f"Runner error: {e!r}")
        write_json(rd / "status.json", st)
        raise
