import hashlib
import ipaddress
import math
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import altair as alt
import httpx
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]                 # the blockchain folder
FEEDER = ROOT / "Trust Score" / "feed_trust.py"            # Member 1 engine -> ledger
DEVICE_TYPES = ["camera", "sensor", "actuator", "gateway", "meter", "lock"]
REASON_CODES = ["AI_ANOMALY", "POLICY_VIOLATION", "RECOVERY", "MANUAL"]
SCENARIOS = ["burst", "slow_drift", "fixed_margin", "randomised"]
NICE = {"burst": "Burst", "slow_drift": "Slow Drift", "fixed_margin": "Fixed Margin",
        "randomised": "Randomised", "adaptive": "Adaptive", "static": "Static"}
NAVY, ORANGE, GREEN, RED = "#000080", "#FF7000", "#1B7F3B", "#C62828"
STATUS_COLOURS = alt.Scale(domain=["ACTIVE", "SUSPECT"], range=[GREEN, RED])

st.set_page_config(page_title="ZTIoT Trust Ledger", page_icon="🛡️", layout="wide")
# Hide the Streamlit toolbar (Deploy button and the three-dot menu).
st.markdown("<style>[data-testid='stToolbar'], [data-testid='stAppDeployButton'], [data-testid='stMainMenu'] {display: none !important;}</style>", unsafe_allow_html=True)



# Settings (sidebar)

def sidebar():
    st.sidebar.title("ZTIoT Trust Ledger", anchor=False)
    s = st.session_state
    s.setdefault("bridge", os.getenv("BLOCKCHAIN_URL", "http://127.0.0.1:8000"))
    s.setdefault("key", os.getenv("BRIDGE_API_KEY", "dev-key"))
    s.setdefault("couch1", "http://127.0.0.1:5984")
    s.setdefault("couch2", "http://127.0.0.1:7984")
    s.setdefault("couch_user", "admin")
    s.setdefault("couch_pass", "adminpw")
    with st.sidebar.expander("Connection settings"):
        s.bridge = st.text_input("Bridge URL", s.bridge)
        s.key = st.text_input("Bridge API key (x-api-key)", s.key, type="password")
        s.couch1 = st.text_input("CouchDB Org1", s.couch1)
        s.couch2 = st.text_input("CouchDB Org2", s.couch2)
        s.couch_user = st.text_input("CouchDB user", s.couch_user)
        s.couch_pass = st.text_input("CouchDB password", s.couch_pass, type="password")

    # Nothing is shown when all is well; a warning appears only if something is down.
    code, body = call("GET", "/health", key=False)
    if code == 200 and isinstance(body, dict):
        conn = body.get("connector")
        if not (isinstance(conn, dict) and conn.get("status") == "ok"):
            st.sidebar.warning("Bridge ok · connector unreachable (start npm start)")
    else:
        st.sidebar.error("Bridge not reachable (start uvicorn on port 8000)")

    if st.sidebar.button("Refresh data", use_container_width=True):
        st.cache_data.clear()
    page = st.sidebar.radio("Page", list(PAGES))
    return page



# HTTP helpers

def call(method, path, body=None, key=True, raw=None, api_key=None):
    """Call the bridge. Returns (status code, parsed JSON or text). Never raises."""
    headers = {}
    if key:
        headers["x-api-key"] = st.session_state.key if api_key is None else api_key
    if raw is not None:
        headers["Content-Type"] = "application/json"
    try:
        with httpx.Client(base_url=st.session_state.bridge.rstrip("/"), timeout=40, trust_env=False) as c:
            r = c.request(method, path, json=body, content=raw, headers=headers)
    except httpx.HTTPError as exc:
        return 0, f"cannot reach the bridge: {exc.__class__.__name__}"
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, r.text


def couch(base, path, body=None):
    """Read-only CouchDB request (GET, or POST for _find). Returns (code, json)."""
    s = st.session_state
    try:
        with httpx.Client(base_url=base.rstrip("/"), timeout=10, trust_env=False,
                          auth=(s.couch_user, s.couch_pass)) as c:
            r = c.post(path, json=body) if body is not None else c.get(path)
        return r.status_code, r.json()
    except (httpx.HTTPError, ValueError) as exc:
        return 0, {"error": str(exc)}


def error_text(body):
    if isinstance(body, dict) and "detail" in body:
        d = body["detail"]
        if isinstance(d, list):
            return "; ".join(f"{'.'.join(str(x) for x in e.get('loc', [])[1:])}: {e.get('msg')}" for e in d)
        return str(d)
    return str(body)


def show_result(code, body, ok_codes=(200,)):
    if code in ok_codes:
        st.success(f"HTTP {code}")
    else:
        st.error(f"HTTP {code}: {error_text(body)}")
    st.json(body if isinstance(body, (dict, list)) else {"response": body}, expanded=False)



# Data loading (cached for a few seconds)

@st.cache_data(ttl=5, show_spinner=False)
def device_ids(couch1, user, password, fallback_n=24):
    """List device IDs from Org1's world state; fall back to dev-001..dev-N."""
    try:
        with httpx.Client(base_url=couch1.rstrip("/"), timeout=10, trust_env=False, auth=(user, password)) as c:
            r = c.post("/ztiotchannel_ztiot/_find",
                       json={"selector": {"docType": "device"}, "fields": ["deviceId"], "limit": 1000})
        ids = sorted(d["deviceId"] for d in r.json().get("docs", []) if "deviceId" in d)
        if ids:
            return ids, "CouchDB (Org1 world state)"
    except (httpx.HTTPError, ValueError, KeyError):
        pass
    return [f"dev-{i:03d}" for i in range(1, fallback_n + 1)], "default list dev-001..dev-024"


@st.cache_data(ttl=5, show_spinner=False)
def load_devices(ids, bridge, key):
    """Read every device through the bridge and the smart contract (in parallel)."""
    def one(device_id):
        try:
            with httpx.Client(base_url=bridge.rstrip("/"), timeout=40, trust_env=False,
                              headers={"x-api-key": key}) as c:
                r = c.get(f"/v1/devices/{device_id}")
            return r.json() if r.status_code == 200 else None
        except (httpx.HTTPError, ValueError):
            return None
    with ThreadPoolExecutor(max_workers=8) as pool:
        rows = [d for d in pool.map(one, ids) if d]
    return rows


def fleet_frame():
    s = st.session_state
    ids, source = device_ids(s.couch1, s.couch_user, s.couch_pass)
    rows = load_devices(tuple(ids), s.bridge, s.key)
    df = pd.DataFrame(rows)
    return df, source



# Pages


def page_fleet():
    st.title("Overview", anchor=False)
    st.caption("Current state of every registered device, read through the smart contract (GetDevice).")
    df, _ = fleet_frame()
    if df.empty:
        st.warning("No devices found. Start the bridge and connector, then run simulator/register_devices.py.")
        return
    total, suspect = len(df), int((df["status"] == "SUSPECT").sum())
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Devices", total)
    c2.metric("ACTIVE", total - suspect)
    c3.metric("SUSPECT", suspect)
    c4.metric("Average trust", f"{df['trustValue'].mean():.1f}")

    chart = alt.Chart(df).mark_bar().encode(
        x=alt.X("deviceId:N", sort=None, title="Device"),
        y=alt.Y("trustValue:Q", title="Trust value", scale=alt.Scale(domain=[0, 100])),
        color=alt.Color("status:N", scale=STATUS_COLOURS, title="Status"),
        tooltip=["deviceId", "deviceType", "networkAddress", "trustValue", "threshold", "status"],
    )
    ticks = alt.Chart(df).mark_tick(color=NAVY, thickness=2, size=18).encode(
        x=alt.X("deviceId:N", sort=None), y="threshold:Q", tooltip=["deviceId", "threshold"])
    st.altair_chart((chart + ticks).properties(height=320), use_container_width=True)
    st.caption("Bars = current trust. Dark ticks = each device's threshold. Below the tick = SUSPECT.")

    cols = ["deviceId", "deviceType", "criticality", "networkAddress", "trustValue", "threshold",
            "status", "updateCount", "dropCount", "lastUpdated"]
    st.dataframe(df[[c for c in cols if c in df.columns]], use_container_width=True, hide_index=True)


def page_device():
    st.title("Device Detail", anchor=False)
    df, _ = fleet_frame()
    ids = list(df["deviceId"]) if not df.empty else ["dev-001"]
    device_id = st.selectbox("Device", ids)
    code, dev = call("GET", f"/v1/devices/{device_id}")
    if code != 200:
        st.error(f"HTTP {code}: {error_text(dev)}")
        return
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Status", dev["status"])
    c2.metric("Trust value", dev["trustValue"])
    c3.metric("Threshold", dev["threshold"])
    c4.metric("Type / criticality", f"{dev['deviceType']} / {dev['criticality']}")
    c5.metric("IP address", dev["networkAddress"])

    tab_hist, tab_events, tab_verify, tab_raw = st.tabs(
        ["Trust over time (history)", "Trust events", "Verify evidence hash", "Raw record"])

    with tab_hist:
        code, hist = call("GET", f"/v1/devices/{device_id}/history")
        if code == 200 and hist:
            h = pd.DataFrame([{"time": e["timestamp"], "trust": e["record"]["trustValue"],
                               "threshold": e["record"]["threshold"], "status": e["record"]["status"],
                               "ip": e["record"]["networkAddress"], "txId": e["txId"]} for e in hist])
            h["time"] = pd.to_datetime(h["time"], utc=True)
            h["when"] = h["time"].dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            # Ledger times are UTC, so show them as UTC (not the browser's local time).
            x = alt.X("time:T", title="Time (UTC)", scale=alt.Scale(type="utc"),
                      axis=alt.Axis(format="%H:%M:%S", labelAngle=0, tickCount=8))
            line = alt.Chart(h).mark_line(color=NAVY).encode(x=x,
                                                             y=alt.Y("trust:Q", scale=alt.Scale(domain=[0, 100]), title="Trust"))
            pts = alt.Chart(h).mark_circle(size=70).encode(
                x=x, y="trust:Q", color=alt.Color("status:N", scale=STATUS_COLOURS),
                tooltip=["when", "trust", "threshold", "status", "txId"])
            thr = alt.Chart(h).mark_line(color=ORANGE, strokeDash=[6, 4]).encode(x=x, y="threshold:Q")
            st.altair_chart((line + thr + pts).properties(height=300), use_container_width=True)
            st.caption("Navy = trust, orange dashed = threshold. Each point is one committed transaction "
                       "(version of the record), read from the peer's history database.")
            st.dataframe(h[["when", "trust", "threshold", "status", "ip", "txId"]],
                         use_container_width=True, hide_index=True)
        else:
            st.info("No history yet.")

    with tab_events:
        code, events = call("GET", f"/v1/devices/{device_id}/events")
        if code == 200 and events:
            e = pd.DataFrame(events)
            cols = ["timestamp", "oldValue", "newValue", "delta", "reasonCode", "attackClass",
                    "confidence", "evidenceHash", "eventId", "submitterMSP"]
            st.dataframe(e[[c for c in cols if c in e.columns]], use_container_width=True, hide_index=True)
            st.caption("Each trust change is a permanent event. Only the SHA-256 hash of the evidence is stored.")
        else:
            st.info("No trust events yet. Send a trust value first.")

    with tab_verify:
        st.write("Type the evidence text that was sent. Its SHA-256 must equal the hash stored on the ledger.")
        text = st.text_input("Evidence text", "1200 ports in 60s")
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        st.code(f"sha256 = {digest}", language="text")
        code, events = call("GET", f"/v1/devices/{device_id}/events")
        matches = [ev for ev in (events if code == 200 else []) if ev.get("evidenceHash") == digest]
        if matches:
            st.success(f"Match: {len(matches)} trust event(s) on the ledger carry this hash "
                       f"(latest at {matches[-1]['timestamp']}, tx {matches[-1]['eventId'][:16]}...).")
        else:
            st.warning("No event of this device has this hash. Any change to the text gives a different hash.")

    with tab_raw:
        st.json(dev)


def page_member1():
    st.title("Trust Engine", anchor=False)
    if not FEEDER.exists():
        st.error(f"Not found: {FEEDER}. Copy the 'Trust Score' folder into the blockchain folder.")
        return
    with st.form("feed"):
        c1, c2, c3 = st.columns(3)
        scenario = c1.selectbox("Scenario", SCENARIOS, index=1, format_func=NICE.get,
                                help="Burst = obvious attack; the others are evasive attackers")
        mode = c2.selectbox("Engine mode", ["adaptive", "static"], format_func=NICE.get,
                            help="Static = fixed threshold, for comparison")
        steps = c3.number_input("Steps (cycles)", 3, 60, 15)
        devices = c1.number_input("Devices (dev-001..dev-N)", 3, 254, 24)
        attackers = c2.number_input("Attackers", 0, 50, 3)
        offline = c3.checkbox("Offline (do not write to the ledger)", value=False)
        run = st.form_submit_button("Run", type="primary")
    if not run:
        return
    args = [sys.executable, str(FEEDER), "--scenario", scenario, "--mode", mode, "--steps", str(steps),
            "--devices", str(devices), "--attackers", str(attackers)]
    if offline:
        args.append("--offline")
    env = dict(os.environ, BRIDGE_API_KEY=st.session_state.key, BLOCKCHAIN_URL=st.session_state.bridge)
    with st.status("Running Member 1 engine..." + ("" if offline else " (each cycle waits for Fabric commits)"),
                   expanded=False) as status:
        try:
            p = subprocess.run(args, cwd=FEEDER.parent, env=env, capture_output=True, text=True, timeout=1800)
        except subprocess.TimeoutExpired:
            status.update(label="Timed out", state="error")
            return
        status.update(label="Finished" if p.returncode == 0 else "Finished with errors",
                      state="complete" if p.returncode == 0 else "error")
        st.code(p.stderr[-4000:] or "(no progress output)", language="text")
    summary = re.search(r"attackers marked SUSPECT: (\d+)/(\d+)\s+normal devices marked SUSPECT: (\d+)/(\d+)", p.stdout)
    if summary:
        caught, total, fa, normal = map(int, summary.groups())
        c1, c2, c3 = st.columns(3)
        c1.metric("Attackers caught (SUSPECT)", f"{caught}/{total}")
        c2.metric("False alarms", f"{fa}/{normal}")
        writes = re.search(r"ledger writes: (\d+) committed, (\d+) failed", p.stdout)
        c3.metric("Ledger writes", f"{writes.group(1)} ok / {writes.group(2)} failed" if writes else "offline")
    saved = re.search(r"decisions saved to (.+)", p.stderr)
    if saved:
        path = (FEEDER.parent / saved.group(1).strip()).resolve()
        if path.exists():
            d = pd.read_csv(path)
            d["role"] = d["attacker"].map({True: "attacker", False: "normal"})
            show = d[d["attacker"] | d["deviceId"].isin(d[~d["attacker"]]["deviceId"].unique()[:2])]
            x = alt.X("step:Q", title="Cycle", axis=alt.Axis(format="d", tickMinStep=1))
            role_colours = alt.Scale(domain=["attacker", "normal"], range=[RED, GREEN])
            trust = alt.Chart(show).mark_line(point=True).encode(
                x=x, y=alt.Y("trust:Q", scale=alt.Scale(domain=[0, 100]), title="Trust"),
                color=alt.Color("role:N", scale=role_colours, title="Device role"), detail="deviceId:N",
                tooltip=["deviceId", "role", "step", "trust", "threshold", "status", "engineReason"])
            thr = alt.Chart(show[show["attacker"]]).mark_line(color=ORANGE, strokeDash=[6, 4], opacity=0.8).encode(
                x=x, y="threshold:Q", detail="deviceId:N")
            st.altair_chart((thr + trust).properties(height=320), use_container_width=True)
            st.caption("Red = attackers, green = two normal devices, orange dashed = each attacker's adaptive "
                       "threshold. When a red line drops below its orange line the device becomes SUSPECT.")
    st.code(p.stdout[-6000:], language="text")


def number_or_none(text):
    """A number from 0 to 100 typed in a box, or None if it is empty or not valid."""
    try:
        value = float(str(text).strip())
    except ValueError:
        return None
    return value if math.isfinite(value) and 0 <= value <= 100 else None


def register_with_trust(device_id, dtype, crit, ip, trust, threshold):
    """Register the device; then, if needed, record the typed trust value and threshold."""
    with st.spinner("Committing..."):
        code, res = call("POST", "/v1/devices", {"device_id": device_id, "device_type": dtype,
                                                 "criticality": crit, "network_address": ip})
        show_result(code, res)
        if code != 200:
            return
        st.cache_data.clear()
        # The contract starts a new device at trust 100 with a threshold from its criticality.
        # Other values are recorded as a second transaction (reason MANUAL).
        _, dev = call("GET", f"/v1/devices/{device_id}")
        start_threshold = float(dev.get("threshold", 70)) if isinstance(dev, dict) else 70.0
        if threshold is None:
            threshold = start_threshold
        if trust != 100.0 or threshold != start_threshold:
            code, res = call("POST", "/v1/trust", {
                "device_id": device_id, "trust_value": trust, "threshold": threshold,
                "reason_code": "MANUAL", "evidence": "trust value set at registration"})
            if code != 200:
                st.error(f"Registered, but the trust value was not saved (HTTP {code}): {error_text(res)}")
        _, dev = call("GET", f"/v1/devices/{device_id}")
        if isinstance(dev, dict) and "status" in dev:
            m1, m2, m3 = st.columns(3)
            m1.metric("Trust value", dev["trustValue"])
            m2.metric("Threshold", dev["threshold"])
            m3.metric("Status", dev["status"])


def page_register():
    st.title("Register Device", anchor=False)
    c1, c2 = st.columns(2)
    with c1, st.form("register"):
        st.subheader("Register", anchor=False)
        device_id = st.text_input("Device ID", "dev-030")
        dtype = st.selectbox("Type", DEVICE_TYPES)
        crit = st.slider("Criticality (1 low - 5 high)", 1, 5, 4)
        ip = st.text_input("IPv4 address", "192.168.10.30")
        trust_text = st.text_input("Trust value (0 - 100)", "100")
        threshold_text = st.text_input("Threshold (0 - 100)", "",
                                       placeholder="Empty = set from criticality")
        go = st.form_submit_button("Register on the ledger", type="primary")
    if go:
        with c1:
            # Check both numbers before anything is written to the ledger.
            trust, threshold, problems = number_or_none(trust_text), number_or_none(threshold_text), []
            if trust is None:
                problems.append("Trust value must be a number from 0 to 100.")
            if threshold_text.strip() and threshold is None:
                problems.append("Threshold must be a number from 0 to 100, or empty.")
            if problems:
                for msg in problems:
                    st.error(msg)
            else:
                register_with_trust(device_id, dtype, crit, ip, trust, threshold)
    with c2, st.form("move"):
        st.subheader("Change IP address", anchor=False)
        df, _ = fleet_frame()
        mid = st.selectbox("Device", list(df["deviceId"]) if not df.empty else ["dev-001"])
        new_ip = st.text_input("New IPv4 address", "192.168.10.31")
        move = st.form_submit_button("Move device")
    if move:
        with c2, st.spinner("Committing..."):
            code, res = call("PUT", f"/v1/devices/{mid}/address", {"network_address": new_ip})
            show_result(code, res)
            if code == 200:
                st.cache_data.clear()


def page_security():
    st.title("Security Alerts", anchor=False)
    tests = [
        ("No API key", "GET", "/v1/devices/dev-001", None, None, False, None, (401,)),
        ("Wrong API key", "GET", "/v1/devices/dev-001", None, None, True, "wrong-key", (401,)),
        ("Trust value 150 (out of range)", "POST", "/v1/trust",
         {"device_id": "dev-001", "trust_value": 150, "threshold": 70, "reason_code": "AI_ANOMALY"}, None, True, None, (422,)),
        ("Trust value NaN (crash found by negative testing)", "POST", "/v1/trust", None,
         b'{"device_id":"dev-001","trust_value":NaN,"threshold":70,"reason_code":"AI_ANOMALY"}', True, None, (422,)),
        ("Unknown reason code", "POST", "/v1/trust",
         {"device_id": "dev-001", "trust_value": 50, "threshold": 70, "reason_code": "HACKED"}, None, True, None, (422,)),
        ("Script in attack class", "POST", "/v1/trust",
         {"device_id": "dev-001", "trust_value": 50, "threshold": 70, "reason_code": "AI_ANOMALY",
          "attack_class": "<script>"}, None, True, None, (422,)),
        ("Invalid IP address", "POST", "/v1/devices",
         {"device_id": "dev-900", "device_type": "camera", "criticality": 4, "network_address": "999.1.1.1"}, None, True, None, (422,)),
        ("Duplicate device (dev-001 again)", "POST", "/v1/devices",
         {"device_id": "dev-001", "device_type": "lock", "criticality": 5, "network_address": "192.168.10.99"}, None, True, None, (400,)),
        ("Trust for an unknown device", "POST", "/v1/trust",
         {"device_id": "dev-999", "trust_value": 50, "threshold": 70, "reason_code": "AI_ANOMALY"}, None, True, None, (400, 404)),
    ]
    # The checks run as soon as the page opens. None of these requests changes the ledger.
    rows = []
    with st.spinner("Checking..."):
        for name, method, path, body, raw, key, api_key, expect in tests:
            code, res = call(method, path, body, key=key, raw=raw, api_key=api_key)
            rows.append({"name": name, "code": code, "blocked": code in expect,
                         "expect": " or ".join(map(str, expect)), "msg": error_text(res)[:120]})
    blocked = sum(r["blocked"] for r in rows)
    c1, c2, c3 = st.columns(3)
    c1.metric("Attacks tried", len(rows))
    c2.metric("Blocked", blocked)
    c3.metric("Not blocked", len(rows) - blocked)
    # One alert per line, as a list.
    for i, r in enumerate(rows, 1):
        if r["blocked"]:
            st.success(f"**{i}. {r['name']}** · Blocked · HTTP {r['code']} · {r['msg']}")
        else:
            st.error(f"**{i}. {r['name']}** · NOT blocked · HTTP {r['code']} (expected {r['expect']}) · {r['msg']}")


def page_couch():
    st.title("Org1 vs Org2: both copies of the ledger state", anchor=False)
    s = st.session_state
    df, _ = fleet_frame()
    device_id = st.selectbox("Device", list(df["deviceId"]) if not df.empty else ["dev-001"])
    fields = ["deviceId", "deviceType", "networkAddress", "trustValue", "threshold", "status",
              "updateCount", "lastUpdated", "~version"]
    docs, rows = {}, []
    for label, base in (("Org1 (couchdb0)", s.couch1), ("Org2 (couchdb1)", s.couch2)):
        code, doc = couch(base, f"/ztiotchannel_ztiot/DEVICE_{device_id}")
        docs[label] = doc if code == 200 else None
        if code != 200:
            st.error(f"{label}: cannot read ({doc.get('error') if isinstance(doc, dict) else code})")
    if all(docs.values()):
        a, b = docs.values()
        for f in fields:
            rows.append({"Field": f, "Org1": str(a.get(f)), "Org2": str(b.get(f)),
                         "Same": "yes" if a.get(f) == b.get(f) else "NO"})
        table = pd.DataFrame(rows)
        same = (table["Same"] == "yes").all()
        (st.success if same else st.error)(
            "Both organisations hold the same record." if same else
            "The copies DIFFER: one CouchDB was changed outside the smart contract.")
        st.dataframe(table, use_container_width=True, hide_index=True)
    st.subheader("Documents in each world state", anchor=False)
    cols = st.columns(2)
    for col, (label, base) in zip(cols, (("Org1", s.couch1), ("Org2", s.couch2))):
        code, info = couch(base, "/ztiotchannel_ztiot")
        col.metric(f"{label}: ztiotchannel_ztiot documents", info.get("doc_count", "?") if code == 200 else "unreachable")



PAGES = {
    "Overview": page_fleet, "Device Detail": page_device, "Trust Engine": page_member1,
    "Register Device": page_register, "Security Alerts": page_security,
    "Org1 vs Org2 (CouchDB)": page_couch,
}
PAGES[sidebar()]()
