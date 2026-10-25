"""
feed_trust.py - real trust scores from Member 1's engine, written to the ledger.

Member 3 (blockchain) side of the Member 1 -> Member 3 integration.

simulator/generate_trust.py sends trust values from fixed curves. This script
instead computes every trust value and threshold with Member 1's adaptive
trust engine (engine.py, unchanged) and writes each decision to the blockchain
through Member 3's service interface (POST /v1/trust), using Member 1's own
bridge adapter (blockchain_client.py, unchanged).

    behaviour risk (synthetic, shaped like Member 2's output)
        -> Member 1 TrustEngine.evaluate()      trust value, adaptive threshold, action
        -> make_trust_update()                  0-1 scale -> 0-100 ledger payload
        -> POST /v1/trust (bridge, port 8000)   API key, input checks
        -> connector -> Fabric smart contract   ACTIVE / SUSPECT, trust event, history

Usage (devices must be registered first with simulator/register_devices.py):

    cd ~/ztiot/"Trust Score"
    python feed_trust.py --devices 24 --attackers 3 --scenario burst --steps 8
    python feed_trust.py --scenario slow_drift --steps 15
    python feed_trust.py --offline --scenario burst          (no bridge or Fabric needed)

The API key is read from --key or the BRIDGE_API_KEY environment variable.

Limits (be honest in the demo): the behaviour risk is synthetic, no Member 2
model runs here, and SUSPECT is a policy decision recorded on the ledger, not a
firewall action. Member 1's full service (Member 2 endpoint, SQLite outbox,
replay) stays in Member 1's own trust-engine folder.
"""

import argparse
import csv
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from random import Random

from attacker_strategies import STRATEGIES, next_risk
from blockchain_client import (BlockchainClient, BlockchainConfig, BridgeError,
                               make_trust_update, normalize_criticality)
from config import EngineConfig
from device_state import Observation
from engine import TrustEngine
from features import clip
from static_baseline import static_threshold

# burst = an obvious attack; the other three are Member 1's evasive attackers
# that try to stay just inside a fixed (static) trust boundary.
SCENARIOS = ("burst",) + STRATEGIES
DEFAULT_CRITICALITY = {"camera": 4, "sensor": 2, "actuator": 5, "gateway": 3, "meter": 2, "lock": 5}
TYPES = ["camera", "sensor", "actuator", "gateway", "meter", "lock"]


def choose_attackers(device_ids, count):
    """Spread attackers across the fleet, the same way as generate_trust.py."""
    if count <= 0:
        return set()
    step = max(1, len(device_ids) // count)
    return {device_ids[(i * step + 1) % len(device_ids)] for i in range(count)}


def behaviour_risk(scenario, attacker, step, warmup, threshold_ref, rng):
    """Synthetic BehaviorRisk in 0..1, shaped like Member 2's output (higher = worse)."""
    if step <= warmup:
        return rng.uniform(0.08, 0.16)                       # quiet start for every device
    if not attacker:
        return clip(0.12 + rng.uniform(-0.03, 0.03))        # normal device
    attack_round = step - warmup
    if scenario == "burst":
        return clip(min(0.85, 0.15 + 0.15 * attack_round) + rng.uniform(-0.02, 0.02))
    # evasive attacker: aims just below the static boundary (Member 1's strategies)
    return next_risk(scenario, attack_round, threshold_ref, rng)


def load_fleet(client, device_ids, offline):
    """Read each device's criticality from the ledger (or use the registration defaults)."""
    fleet = {}
    for i, device_id in enumerate(device_ids):
        if offline:
            dtype = TYPES[i % len(TYPES)]
            fleet[device_id] = {"type": dtype, "criticality": DEFAULT_CRITICALITY[dtype]}
            continue
        try:
            device = client.get_device(device_id)
        except BridgeError as exc:
            sys.exit(f"error: {device_id}: {exc}. Is the bridge running and the device registered "
                     "(simulator/register_devices.py)?")
        fleet[device_id] = {"type": device.deviceType, "criticality": device.criticality}
    return fleet


def submit(client, payload):
    """Write one trust update; if the answer was lost, look for it on the ledger."""
    try:
        return client.submit(payload), None
    except BridgeError as exc:
        if exc.uncertain:
            try:
                tx = client.find_commit(payload)
                if tx:
                    return tx, None
            except BridgeError:
                pass
        return None, str(exc)


def main():
    ap = argparse.ArgumentParser(description="Send Member 1 engine trust decisions to the Member 3 ledger.")
    ap.add_argument("--devices", type=int, default=24, help="devices dev-001 .. dev-N (must be registered)")
    ap.add_argument("--attackers", type=int, default=3, help="number of attacking devices")
    ap.add_argument("--scenario", choices=SCENARIOS, default="burst")
    ap.add_argument("--steps", type=int, default=8, help="evaluation cycles to send")
    ap.add_argument("--warmup", type=int, default=2, help="quiet cycles before the attack starts")
    ap.add_argument("--mode", choices=("adaptive", "static"), default="adaptive",
                    help="Member 1 engine mode (static = fixed threshold, for comparison)")
    ap.add_argument("--url", default=os.getenv("BLOCKCHAIN_URL", "http://127.0.0.1:8000"))
    ap.add_argument("--key", default=os.getenv("BRIDGE_API_KEY", ""), help="the BRIDGE_API_KEY value")
    ap.add_argument("--workers", type=int, default=8, help="parallel ledger writes per cycle")
    ap.add_argument("--seed", type=int, default=42, help="random seed, for a repeatable run")
    ap.add_argument("--offline", action="store_true", help="only compute and print; do not write to the ledger")
    ap.add_argument("--output", default="results", help="folder for the CSV of all decisions")
    a = ap.parse_args()

    if not 1 <= a.devices <= 254 or not 0 <= a.attackers <= a.devices:
        ap.error("--devices must be 1-254 and --attackers 0..devices")
    if not 1 <= a.steps <= 200 or not 0 <= a.warmup < a.steps:
        ap.error("--steps must be 1-200 and --warmup smaller than --steps")
    if not a.offline and not a.key:
        ap.error("give --key or set BRIDGE_API_KEY (or use --offline)")

    rng = Random(a.seed)
    device_ids = [f"dev-{i:03d}" for i in range(1, a.devices + 1)]
    attackers = choose_attackers(device_ids, a.attackers)
    client = None if a.offline else BlockchainClient(BlockchainConfig(url=a.url, api_key=a.key))
    fleet = load_fleet(client, device_ids, a.offline)

    # Member 1's engine; ledger criticality 1-5 becomes the engine's 0-1 scale.
    config = EngineConfig()
    engine = TrustEngine(a.mode, config)
    for device_id, info in fleet.items():
        info["crit01"] = normalize_criticality(info["criticality"])
        engine.register_device(device_id, info["crit01"])

    print(f"engine mode = {a.mode}   scenario = {a.scenario}   devices = {a.devices}   "
          f"attackers = {sorted(attackers) or '(none)'}", file=sys.stderr)
    print(f"target = {'offline (nothing written)' if a.offline else a.url}", file=sys.stderr)
    print("-" * 72, file=sys.stderr)

    start = datetime.now(timezone.utc).replace(microsecond=0)
    rows, sent, failed = [], 0, 0
    with ThreadPoolExecutor(max_workers=max(1, a.workers)) as pool:
        for step in range(1, a.steps + 1):
            jobs = []
            for device_id in device_ids:
                attacker = device_id in attackers
                ref = static_threshold(fleet[device_id]["crit01"], config)
                risk = behaviour_risk(a.scenario, attacker, step, a.warmup, ref, rng)
                attacking = attacker and step > a.warmup
                obs = Observation(
                    device_id=device_id, behavior_risk=round(risk, 4),
                    timestamp=start + timedelta(seconds=step),
                    evidence_ref=f"feed:{a.seed}:{device_id}:{step}",
                    attack_class=a.scenario if attacking else None,
                    confidence=0.9 if attacking else None,
                )
                decision = engine.evaluate(obs).to_dict()      # Member 1 decides
                payload = make_trust_update(decision)          # 0-100 ledger form
                jobs.append((device_id, attacker, decision, payload))

            results = ([(None, None)] * len(jobs) if a.offline
                       else list(pool.map(lambda j: submit(client, j[3]), jobs)))
            for (device_id, attacker, decision, payload), (tx, err) in zip(jobs, results):
                sent += int(tx is not None)
                failed += int(err is not None)
                if err:
                    print(f"  [fail] {device_id}: {err}", file=sys.stderr)
                rows.append({
                    "step": step, "deviceId": device_id, "attacker": attacker,
                    "behaviorRisk": decision["BehaviorRisk"],
                    "trust": payload["trust_value"], "threshold": payload["threshold"],
                    "status": "SUSPECT" if payload["trust_value"] < payload["threshold"] else "ACTIVE",
                    "engineReason": decision["reasonCode"], "ledgerReason": payload["reason_code"],
                    "txId": tx or "", "error": err or "",
                })
            suspects = sum(1 for r in rows[-len(jobs):] if r["status"] == "SUSPECT")
            print(f"[step {step}/{a.steps}] written: {sent}  failed: {failed}  SUSPECT now: {suspects}",
                  file=sys.stderr)

    if client:
        client.close()

    # final state of every device, as decided by Member 1 and recorded by Member 3
    last = {r["deviceId"]: r for r in rows}
    print(f"\n{'device':8} {'role':8} {'trust':>7} {'thresh':>7}  status   engine reason")
    for device_id in device_ids:
        r = last[device_id]
        print(f"{device_id:8} {'ATTACKER' if r['attacker'] else 'normal':8} {r['trust']:7.2f} "
              f"{r['threshold']:7.2f}  {r['status']:7}  {r['engineReason']}")

    caught = sum(1 for d in attackers if last[d]["status"] == "SUSPECT")
    false_alarms = sum(1 for d in device_ids if d not in attackers and last[d]["status"] == "SUSPECT")
    print(f"\nattackers marked SUSPECT: {caught}/{len(attackers)}   "
          f"normal devices marked SUSPECT: {false_alarms}/{len(device_ids) - len(attackers)}")
    print(f"ledger writes: {sent} committed, {failed} failed" if not a.offline
          else "offline run: nothing was written to the ledger")

    out = Path(a.output)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    csv_path = out / f"trust_feed_{a.scenario}_{stamp}.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    (out / f"ground_truth_{stamp}.json").write_text(json.dumps(
        {"scenario": a.scenario, "mode": a.mode, "seed": a.seed, "attackers": sorted(attackers),
         "attack_starts_after_step": a.warmup}, indent=2), encoding="utf-8")
    print(f"decisions saved to {csv_path}", file=sys.stderr)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
