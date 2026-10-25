# Federated Learning web app (Member 4)

Streamlit dashboard for the Label Swap Detector (HB-NIID-LSD).

**It never imports or edits `niidlsd.py`.** The Re-Run buttons start the exact
terminal commands from the main README in a background process; the dashboards
read what the scripts print and the files they write (`history/`,
`data/poison_log.json`, `results/impact/`).

## Setup

1. Put this `webapp/` folder **inside your project folder** (next to `niidlsd.py`):

   ```
   your-project/
   ├── niidlsd.py
   ├── attacker.py
   ├── data/  history/  results/ ...
   └── webapp/        ← here
   ```

2. Install (same environment as your project):

   ```bash
   pip install -r webapp/requirements.txt
   ```

3. Run it:

   ```bash
   cd webapp
   streamlit run app.py
   ```

   It opens at http://localhost:8501.

If your files live elsewhere, edit `config.py` (paths and the two commands are
at the top) or set `NIIDLSD_PROJECT_DIR`. If the project uses a different
Python/venv than Streamlit, set `NIIDLSD_PYTHON` to that `python` executable.

## What's on the page

**Label Swap Detection**
- **Learn Mode**: current history (Layer 2 attack share per device+protocol,
  Layer 3 benign profiles), last learn run, Re-Run button. Asks for
  confirmation first (niidlsd.py backs the old history up to `history_backups/`).
- **Detection Mode**: the poisoned client round (what the attacker hid, real vs
  swapped BENIGN rows per device), the last detection run (recall, real benign
  kept, precision, misses, false positives, per-device table, which layer
  removed what), run history with changes vs the previous run, Re-Run button.
- **Impact on Member 2's model**: reads `results/impact/summary.csv` from
  `impact_autoencoder.py` (read-only, no re-run button).

**Federated Learning (coming soon)**: planned architecture and roadmap.

## Good to know

- **Detection results appear only after a run made from the dashboard.** Run
  Detection mode once before presenting so the numbers are on screen.
- A run keeps going if you refresh or close the tab; reopen the page to see
  its progress. Only one run at a time.
- **Stop** ends the run. A stopped detection leaves a partial
  `data/cleaned.csv`; re-run before using it.
- If the PC sleeps or the run is killed, the dashboard marks it as lost after
  ~45 s and you can start a new one.
- The dashboard's own records live in `webapp/runs/` (log, status and parsed
  numbers per run) and `webapp/cache/`. Deleting them only clears the
  dashboard's history; your project files are untouched.
- Wording changes in niidlsd.py's printed output only need updating in
  `parsers.py`; missing numbers show as "—" instead of crashing.

## Files

| File | Job |
|---|---|
| `app.py` | The page |
| `config.py` | Paths and commands (the only file you should need to edit) |
| `jobs.py` | Starts, stops and finds runs |
| `runner.py` | Background process: runs niidlsd.py, saves log + progress |
| `parsers.py` | Turns niidlsd.py's output into numbers |
| `readers.py` | Read-only views of history, profiles, poison log, impact results |
