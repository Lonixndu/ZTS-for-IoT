"""
generate_trust.py

Sends realistic trust values through the service interface so the
blockchain component can be built, tested and benchmarked before
Member 1's real trust engine is available.

Usage:
    python simulator/generate_trust.py \
        --scenario low_and_slow --devices 24 --attackers 9 \
        --steps 40 --key "$BRIDGE_API_KEY"

Scenarios:
    normal          all devices behave normally, no attackers
    single_loud      one attacker collapses fast, tests per-device detection
    low_and_slow    attackers drift down slowly together, tests correlation
    burst           attackers drop hard and fast, as a group
    recovering      attackers climb back to a healthy value

The --url, --key and --devices/--attackers options let you replay any
of these against a running service interface. Ground truth (which
devices are attackers, and in which step they start) is printed to
stderr and also written to a JSON file, so detection experiments can
be scored against it later.
"""

import argparse
import json
import random
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import requests


# ---------------------------------------------------------------------------
# Scenario definitions
#
# Each function takes the step index t (0-based) and returns a trust value
# in the range 0 to 100. Non-attacking devices always use "normal".
# ---------------------------------------------------------------------------

def clamp(v: float) -> float:
    """Keep every value inside the 0 to 100 range the ledger accepts."""
    return max(0.0, min(100.0, v))


def normal(t: int) -> float:
    """Healthy device: stays high, small random noise."""
    return clamp(100 - random.gauss(3, 2))


def single_loud(t: int) -> float:
    """One device collapses fast and obviously."""
    return clamp(100 - t * 12)


def low_and_slow(t: int) -> float:
    """Slow, quiet decline. No single step looks alarming on its own."""
    return clamp(100 - t * 0.7 - random.gauss(0, 0.4))


def burst(t: int) -> float:
    """Fast, hard drop shared across several devices at once."""
    return clamp(100 - t * 8 - random.gauss(0, 2))


def recovering(t: int) -> float:
    """Climbs back up after starting low, to test status recovery."""
    return clamp(40 + t * 5 + random.gauss(0, 1))


SCENARIOS = {
    "normal": normal,
    "single_loud": single_loud,
    "low_and_slow": low_and_slow,
    "burst": burst,
    "recovering": recovering,
}


# ---------------------------------------------------------------------------
# Ground truth
# ---------------------------------------------------------------------------

def choose_attackers(device_ids, attacker_count, scenario):
    """
    Spreads attackers evenly across the device population rather than
    clustering them at the start of the list, so a correlation query is
    exercised the same way it would be against a real, mixed fleet.

    For "normal" and "recovering" the concept of an "attacker" does not
    really apply, but we still return a set for consistency, using it
    only to mark which devices follow the named scenario curve.
    """
    if attacker_count <= 0 or scenario == "normal":
        return set()
    n = len(device_ids)
    step = max(1, n // attacker_count)
    chosen = {device_ids[(i * step + 1) % n] for i in range(attacker_count)}
    return chosen


def write_ground_truth(path, scenario, devices, attackers, window_start_step):
    record = {
        "scenario": scenario,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_devices": len(devices),
        "attacker_devices": sorted(attackers),
        "attacker_count": len(attackers),
        "attack_starts_at_step": window_start_step,
    }
    with open(path, "w") as f:
        json.dump(record, f, indent=2)
    print(f"[ground truth] written to {path}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Sending trust values
# ---------------------------------------------------------------------------

def send_trust_value(session, url, key, device_id, trust_value,
                     threshold, reason_code, attack_class, confidence,
                     evidence_tag, timeout=20):
    """
    Posts one trust value to the service interface, in exactly the shape
    the smart contract's RecordTrustValue transaction expects.

    Returns True on success, False on failure. Failures are logged but
    do not stop the run, because one dropped request should not abort
    a whole benchmarking session.
    """
    payload = {
        "device_id": device_id,
        "trust_value": round(trust_value, 2),
        "threshold": threshold,
        "reason_code": reason_code,
        "attack_class": attack_class,
        "confidence": confidence,
        "evidence": evidence_tag,
    }
    try:
        r = session.post(
            f"{url}/v1/trust",
            headers={"x-api-key": key, "Content-Type": "application/json"},
            json=payload,
            timeout=timeout,
        )
        if r.status_code != 200:
            print(f"  [warn] {device_id}: HTTP {r.status_code} {r.text[:200]}",
                  file=sys.stderr)
            return False
        return True
    except requests.exceptions.RequestException as exc:
        print(f"  [error] {device_id}: {exc}", file=sys.stderr)
        return False


# ---------------------------------------------------------------------------
# Main run loop
# ---------------------------------------------------------------------------

def run(scenario, devices, attackers, steps, url, key, delay,
        threshold, confidence, workers=8):
    """Send one value per device per step.

    Values for a step are computed first (so --seed stays repeatable), then
    sent in parallel by `workers` threads. On real Fabric each submit waits
    about 2 seconds for its block, so sending one by one would take
    24 devices x 2 s = 48 s per step. Each device still gets exactly one
    value per step, so parallel sending never creates write conflicts.
    """
    local = threading.local()

    def session():
        if not hasattr(local, "s"):
            local.s = requests.Session()
        return local.s

    reason_code = "AI_ANOMALY" if attackers else "MANUAL"

    sent, failed = 0, 0
    start_time = time.time()

    for t in range(steps):
        jobs = []
        for dev in devices:
            if dev in attackers:
                value = SCENARIOS[scenario](t)
                attack_class = scenario
                conf = confidence
            else:
                value = SCENARIOS["normal"](t)
                attack_class = ""
                conf = 0.0
            jobs.append(dict(
                device_id=dev,
                trust_value=value,
                threshold=threshold,
                reason_code=reason_code if dev in attackers else "MANUAL",
                attack_class=attack_class,
                confidence=conf,
                evidence_tag=f"{dev}-step{t}-{scenario}",
            ))

        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            results = list(pool.map(
                lambda j: send_trust_value(session(), url, key, **j), jobs))
        sent += sum(1 for ok in results if ok)
        failed += sum(1 for ok in results if not ok)

        elapsed = time.time() - start_time
        print(f"[step {t + 1}/{steps}] sent so far: {sent}  failed: {failed}  "
              f"elapsed: {elapsed:.1f}s", file=sys.stderr)
        time.sleep(delay)

    print(f"\ndone. total sent: {sent}  total failed: {failed}", file=sys.stderr)
    if failed > 0:
        print("non-zero failures: check that the service interface is "
              "running and BRIDGE_API_KEY matches the server.",
              file=sys.stderr)


def parse_args():
    ap = argparse.ArgumentParser(
        description="Generate simulated trust values for testing the "
                    "blockchain component before Member 1's trust "
                    "engine is available.")
    ap.add_argument("--scenario", default="low_and_slow",
                    choices=sorted(SCENARIOS),
                    help="which behaviour pattern to replay")
    ap.add_argument("--devices", type=int, default=24,
                    help="total number of simulated devices")
    ap.add_argument("--attackers", type=int, default=9,
                    help="number of devices following the attack scenario; "
                         "the rest always behave normally")
    ap.add_argument("--steps", type=int, default=40,
                    help="number of evaluation cycles to send")
    ap.add_argument("--delay", type=float, default=1.0,
                    help="seconds to sleep between steps")
    ap.add_argument("--threshold", type=float, default=70.0,
                    help="per-device trust threshold sent with every value")
    ap.add_argument("--confidence", type=float, default=0.9,
                    help="confidence value attached to attacker records")
    ap.add_argument("--url", default="http://localhost:8000",
                    help="base URL of the service interface")
    ap.add_argument("--key", required=True,
                    help="API key for the service interface "
                         "(the BRIDGE_API_KEY value)")
    ap.add_argument("--ground-truth-out", default="ground_truth.json",
                    help="file to write the attacker list and scenario info to")
    ap.add_argument("--workers", type=int, default=8,
                    help="parallel senders per step (use 1 to send one by one)")
    ap.add_argument("--seed", type=int, default=None,
                    help="random seed, for a repeatable run")
    return ap.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    if args.attackers > args.devices:
        print("error: --attackers cannot exceed --devices", file=sys.stderr)
        sys.exit(1)

    device_ids = [f"dev-{i:03d}" for i in range(1, args.devices + 1)]
    attacker_set = choose_attackers(device_ids, args.attackers, args.scenario)

    print(f"scenario        = {args.scenario}", file=sys.stderr)
    print(f"total devices   = {len(device_ids)}", file=sys.stderr)
    print(f"attacker devices= {sorted(attacker_set) if attacker_set else '(none)'}",
          file=sys.stderr)
    print(f"target          = {args.url}", file=sys.stderr)
    print("-" * 60, file=sys.stderr)

    write_ground_truth(args.ground_truth_out, args.scenario,
                       device_ids, attacker_set, window_start_step=0)

    run(
        scenario=args.scenario,
        devices=device_ids,
        attackers=attacker_set,
        steps=args.steps,
        url=args.url,
        key=args.key,
        delay=args.delay,
        threshold=args.threshold,
        confidence=args.confidence,
        workers=args.workers,
    )
