"""
app.py — Member 4 web app: Federated Learning · Label Swap Detection

    cd webapp
    streamlit run app.py

Never imports or edits niidlsd.py. "Re-Run" starts the same terminal command you'd
type (see config.py) in a background process; the page reads what it prints and
the files it writes.
"""

import time
from datetime import datetime

import altair as alt
import pandas as pd
import streamlit as st

import config
import jobs
import readers

st.set_page_config(page_title="NIID-LSD-FL", page_icon="🛡️", layout="wide",
                   initial_sidebar_state="collapsed")

# Dark-mode steps of the reference palette
BLUE, ORANGE, AQUA, GRAY = "#3987e5", "#d95926", "#199e70", "#8a8984"

st.markdown("""
<style>
  [data-testid="stSidebar"], [data-testid="stSidebarCollapsedControl"] { display: none; }
  .block-container { max-width: 1100px; padding-top: 2.5rem; }
  div[data-testid="stMetricValue"] { font-variant-numeric: tabular-nums; }
  .step { border: 1px solid rgba(250,250,250,.12); border-radius: 12px;
          padding: 14px 16px; height: 100%; }
  .step b { display: block; margin-bottom: 4px; }
  .step span { opacity: .7; font-size: .9rem; }
  .step.done { border-color: #3987e5; background: rgba(57,135,229,.10); }
  .arrow { text-align: center; font-size: 1.4rem; opacity: .5; padding-top: 22px; }
  .muted { opacity: .65; font-size: .9rem; }
</style>""", unsafe_allow_html=True)


# ── formatting ──────────────────────────────────────────
def n(v):
    return "—" if v is None else f"{v:,}"

def pct(v):
    return "—" if v is None else f"{v*100:.1f}%"

def when(ts):
    return datetime.fromtimestamp(ts).strftime("%d %b, %H:%M") if ts else "—"

def dur(s):
    if s is None:
        return "—"
    s = int(round(s))
    return f"{s//60}m {s%60:02d}s" if s >= 60 else f"{s}s"

def tabs(labels, key):
    try:
        return st.tabs(labels, key=key)
    except TypeError:
        return st.tabs(labels)


# ── charts ──────────────────────────────────────────────
def show(c, rows, legend=False):
    st.altair_chart(c, width="stretch", height=34 * rows + 70 + (40 if legend else 0))

def bars(df, cat, val, title, fmt=",.0f", color=BLUE, rule=None):
    c = alt.Chart(df).mark_bar(cornerRadiusEnd=4, height={"band": 0.65}, color=color).encode(
        y=alt.Y(f"{cat}:N", sort="-x", title=None, axis=alt.Axis(labelLimit=240)),
        x=alt.X(f"{val}:Q", title=title, axis=alt.Axis(format=fmt)),
        tooltip=[alt.Tooltip(f"{cat}:N", title=" "), alt.Tooltip(f"{val}:Q", format=fmt, title=title)])
    if rule is not None:
        c = c + alt.Chart(pd.DataFrame({"r": [rule]})).mark_rule(
            strokeDash=[4, 3], color=GRAY).encode(x="r:Q")
    show(c, len(df))

def stacked(long, cat, part, val, title, domain, colors):
    c = alt.Chart(long).mark_bar(height={"band": 0.65}).encode(
        y=alt.Y(f"{cat}:N", title=None, axis=alt.Axis(labelLimit=240),
                sort=alt.EncodingSortField(val, op="sum", order="descending")),
        x=alt.X(f"sum({val}):Q", title=title, axis=alt.Axis(format=",.0f")),
        color=alt.Color(f"{part}:N", title=None, scale=alt.Scale(domain=domain, range=colors),
                        legend=alt.Legend(orient="top", labelLimit=0)),
        order=alt.Order("order:Q"),
        tooltip=[alt.Tooltip(f"{cat}:N", title=" "), alt.Tooltip(f"{part}:N", title=" "),
                 alt.Tooltip(f"{val}:Q", format=",", title="rows")])
    show(c, long[cat].nunique(), legend=True)


# ── running jobs ────────────────────────────────────────
NAME = {"learn": "Learn", "detect": "Detection"}

def start(job):
    try:
        jobs.start(job)
        time.sleep(0.8)
    except (RuntimeError, FileNotFoundError) as e:
        st.session_state["err"] = str(e)
    st.rerun()

@st.dialog("Rebuild the history?")
def confirm_learn():
    st.write("Learn mode rebuilds what the detector knows from scratch. "
             "The current history is backed up first.")
    a, b = st.columns(2)
    if a.button("Rebuild", type="primary", width="stretch"):
        start("learn")
    if b.button("Cancel", width="stretch"):
        st.rerun()

def run_button(job):
    active = jobs.active_run()
    mine = active is not None and active["job"].get("job") == job
    if st.button("Running…" if mine else f"Re-run {NAME[job]}", type="primary",
                 icon=":material/play_arrow:", disabled=bool(active), key=f"run_{job}"):
        confirm_learn() if job == "learn" else start(job)
    if active and not mine:
        st.caption(f"{NAME[active['job']['job']]} is running — wait for it to finish.")
    if st.session_state.get("err"):
        st.error(st.session_state.pop("err"))
    if mine:
        live(str(active["dir"]))
    _last_failure(job)

@st.fragment(run_every=2)
def live(run_dir):
    s = jobs.load_status(run_dir)
    if s.get("state") not in jobs.RUNNING_STATES:
        st.rerun()
    total, done = s.get("total_rows"), s.get("rows_done") or 0
    elapsed = time.time() - (s.get("started") or time.time())
    rate = done / elapsed if elapsed > 1 and done else None
    eta = (total - done) / rate if rate and total and done < total else None
    if total and done >= total:
        text = "Finishing up…"
    elif total:
        text = f"{n(done)} of {n(total)} rows · {dur(elapsed)} elapsed" + \
               (f" · about {dur(eta)} left" if eta else "")
    else:
        text = f"{n(done)} rows · {dur(elapsed)} elapsed"
    st.progress(min(done / total, 1.0) if total else 0.0, text=text)
    if st.button("Stop", icon=":material/stop:", key=f"stop_{run_dir}"):
        jobs.request_stop(run_dir)

def _last_failure(job):
    runs = jobs.list_runs(job)
    if runs:
        r = jobs.load_run(runs[0])
        if r["status"].get("state") in ("failed", "lost"):
            with st.expander("⚠️ The last run didn't finish — showing the previous result"):
                st.code((r["stats"] or {}).get("error") or jobs.read_log(r["dir"], tail=12),
                        language=None)


# ════════════════════════════════════════════════════════
# PAGE
# ════════════════════════════════════════════════════════

st.title("Non-IID Label Swap Detection & Federated Learning")
st.markdown("<p class='muted'>IT23195370 · Zero Trust Security for IoT using AI and Blockchain</p>",
            unsafe_allow_html=True)

tab_lsd, tab_fl = tabs(["Label Swap Detection", "Federated Learning · coming soon"], "main")

with tab_lsd:
    st.markdown("A hacked IoT device can relabel **attack traffic as BENIGN** in its training "
                "data, teaching the shared model that attacks are normal. The detector removes "
                "those fake labels **before** the device trains.")
    st.write("")
    sub_learn, sub_detect, sub_impact = tabs(["Learn 📖", "Detect 🔍", "Impact 📈"], "lsd")

    settings = readers.detector_settings()

    # ── LEARN ──────────────────────────────────────────
    with sub_learn:
        st.subheader("Train the Label Swap Detector")
        st.markdown("<p class='muted'>Learned from clean past traffic, per device type.</p>",
                    unsafe_allow_html=True)
        run_button("learn")

        hist = readers.history_table(settings)
        prof, _, _ = readers.profiles(settings)
        if hist is None or prof is None:
            st.info("Nothing learned yet — click **Re-run Learn**.")
        else:
            last = jobs.finished_runs("learn", limit=1)
            rows = last[0]["stats"].get("rows_processed") if last else int(hist["rows"].sum())
            st.write("")
            m = st.columns(3)
            m[0].metric("Rows learned from", n(rows), border=True)
            m[1].metric("Device types profiled", n(int(prof[prof["profile"] != "ALL (pooled)"]["active"].sum())),
                        border=True)
            m[2].metric("High-risk combinations", n(int(hist["suspicious"].sum())), border=True,
                        help="Device + protocol pairs that were almost always attacks. "
                             "A BENIGN label there gets a closer look.")
            st.write("")
            st.markdown("**How often each device + protocol was an attack**")
            h = hist[hist["rows"] >= 100].copy()
            h["combo"] = h["device"] + " · " + h["protocol"]
            bars(h, "combo", "attack_share", "share of past traffic that was an attack",
                 fmt=".0%", rule=settings.get("ATTACK_RATIO_THRESH", 0.9))
            st.caption("Past the dashed line, a BENIGN label is treated as suspicious.")

    # ── DETECT ─────────────────────────────────────────
    with sub_detect:
        st.subheader("Detect Poisoned Labels")
        pl = readers.poison_log()
        if pl:
            st.markdown(f"<p class='muted'>The attacker relabelled <b>{n(pl['total_flipped'])}</b> "
                        f"attack rows as BENIGN in a round of {n(pl['rows'])} rows.</p>",
                        unsafe_allow_html=True)
        run_button("detect")

        runs = jobs.finished_runs("detect", limit=1)
        if not runs:
            st.info("No results yet — click **Re-run Detection**.")
        else:
            r = runs[0]
            s = r["stats"]
            snap = r["job"].get("snapshot", {})
            now_h = jobs.file_info(config.HISTORY_FILE).get("mtime")
            if now_h and abs((snap.get("history", {}).get("mtime") or 0) - now_h) > 1:
                st.warning("The history was rebuilt after this run — re-run Detection.")
            st.write("")
            if s.get("verified"):
                m = st.columns(4)
                m[0].metric("Swapped Labels Caught", pct(s.get("recall")), border=True,
                            help="Share of the attacker's swapped rows that were removed")
                m[1].metric("Swapped Labels Missed", n(s.get("missed")), border=True)
                m[2].metric("Real Benign Kept", pct(s.get("benign_kept_rate")), border=True,
                            help="Genuine benign rows the device still trains on")
                m[3].metric("Precision", pct(s.get("precision")), border=True,
                            help="Of the rows removed, how many really were fake")
            else:
                st.metric("Rows removed", n(s.get("removed")))
            st.markdown(f"<p class='muted'>Last run {when(r['status'].get('ended'))} · "
                        f"{n(s.get('rows_scanned'))} rows in {dur(s.get('seconds'))}</p>",
                        unsafe_allow_html=True)

            if s.get("per_device"):
                st.write("")
                st.markdown("**Per device type**")
                pdv = pd.DataFrame(s["per_device"])
                names = {"caught": "label swaps caught", "missed": "label swaps missed",
                         "false_pos": "real benign removed"}
                long = pdv.melt(id_vars="device", value_vars=list(names),
                                var_name="part", value_name="count")
                long["part"] = long["part"].map(names)
                long["order"] = long["part"].map({v: i for i, v in enumerate(names.values())})
                stacked(long, "device", "part", "count", "rows",
                        list(names.values()), [BLUE, ORANGE, AQUA])

            with st.expander("Full detector output"):
                st.code(jobs.read_log(r["dir"]), language=None)

    # ── IMPACT ─────────────────────────────────────────
    with sub_impact:
        st.subheader("Does Cleaning Protect the Model?")
        st.markdown("<p class='muted'>Member 2's Autoencoder trained three times on the same "
                    "round, then tested on the same unseen data. Score: ROC AUC "
                    "(1.0 perfect, 0.5 coin flip).</p>", unsafe_allow_html=True)
        summ, _, _ = readers.impact_results()
        if summ is None:
            st.info("No results yet — run experiments/impact_autoencoder.py.")
        else:
            sets = dict(zip(summ["train_set"], summ["roc_auc"]))
            labels = {"clean": "Clean data", "poisoned": "Poisoned data",
                      "cleaned": "Cleaned by the detector"}
            st.write("")
            cols = st.columns(len(sets))
            for col, (k, v) in zip(cols, sets.items()):
                col.metric(labels.get(k, k), f"{v:.3f}", border=True)
            if {"clean", "poisoned", "cleaned"} <= set(sets) and sets["clean"] != sets["poisoned"]:
                rec = (sets["cleaned"] - sets["poisoned"]) / (sets["clean"] - sets["poisoned"])
                st.success(f"Poisoning wrecks the model. The detector restores "
                           f"**{rec*100:.0f}%** of what was lost.")
            d = summ[["train_set", "roc_auc"]].copy()
            d["train_set"] = d["train_set"].map(lambda k: labels.get(k, k))
            bars(d, "train_set", "roc_auc", "ROC AUC", fmt=".2f", rule=0.5)
            st.caption("Dashed line = coin flip.")

with tab_fl:
    st.subheader("Training together without sharing data")
    st.markdown("Each device trains Member 2's models on its own traffic and shares only model "
                "updates. The label swap detector runs on every device **before** each round.")
    st.write("")
    steps = [("Device traffic", "labelled by Member 2's IDS", False),
             ("Label swap detector", "removes fake labels ✓ done", True),
             ("Local training", "on the cleaned data", False),
             ("FL server", "combines updates (Flower)", False)]
    cols = st.columns([4, 1, 4, 1, 4, 1, 4])
    for i, (title, sub, done) in enumerate(steps):
        cols[i * 2].markdown(f"<div class='step {'done' if done else ''}'><b>{title}</b>"
                             f"<span>{sub}</span></div>", unsafe_allow_html=True)
        if i < 3:
            cols[i * 2 + 1].markdown("<div class='arrow'>→</div>", unsafe_allow_html=True)
    st.write("")
    st.markdown("**Next steps**")
    st.markdown("- Flower setup: one client per device type, detector before each round\n"
                "- Federated training of Member 2's Autoencoder\n"
                "- Weight each device's update by Member 1's trust score")
