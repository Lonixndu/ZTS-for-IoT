import argparse                                  # read command-line options (--scenario, --steps ...)
import json                                      # write the ground truth file
import random                                    # random noise, so values look realistic
import sys                                       # print to stderr, exit with an error code
import threading                                 # one HTTP session per worker thread
import time                                      # measure time, wait between steps
from concurrent.futures import ThreadPoolExecutor  # send several requests at the same time
from datetime import datetime, timezone          # time stamp in the ground truth file

import requests                                  # HTTP client used to call the bridge


# ---------------------------------------------------------------------------
# Scenario definitions
#
# Each function takes the step index t (0-based) and returns a trust value
# in the range 0 to 100. Non-attacking devices always use "normal".
# ---------------------------------------------------------------------------

def clamp(v: float) -> float:
    """Keep every value inside the 0 to 100 range the ledger accepts."""
    # e.g. 104 -> 100 and -6 -> 0. The bridge and the chaincode would
    # reject anything outside 0..100.
    return max(0.0, min(100.0, v))


def normal(t: int) -> float:
    """Healthy device: stays high, small random noise."""
    # random.gauss(3, 2) = a random number around 3 (usually 1 to 5),
    # so the value is usually about 95 to 99
    return clamp(100 - random.gauss(3, 2))


def single_loud(t: int) -> float:
    """One device collapses fast and obviously."""
    # 100, 88, 76, 64 ... : below the threshold 70 from step 3, 0 from step 9.
    # Use with --attackers 1 for a true "single" attacker.
    return clamp(100 - t * 12)


def low_and_slow(t: int) -> float:
    """Slow, quiet decline. No single step looks alarming on its own."""
    # drops only 0.7 per step: after 40 steps it is still about 72.7,
    # ABOVE the threshold 70. A per-device check never flags these devices.
    # This is exactly Gap 2: only a fleet-wide view (many devices drifting
    # down together) can reveal the coordinated attack.
    return clamp(100 - t * 0.7 - random.gauss(0, 0.4))


def burst(t: int) -> float:
    """Fast, hard drop shared across several devices at once."""
    # 8 points per step: below 70 from about step 4
    return clamp(100 - t * 8 - random.gauss(0, 2))


def recovering(t: int) -> float:
    """Climbs back up after starting low, to test status recovery."""
    # starts at 40 (SUSPECT), passes 70 at about step 6 (back to ACTIVE),
    # reaches 100 at about step 12
    return clamp(40 + t * 5 + random.gauss(0, 1))


# name -> function, used by --scenario and by run()
SCENARIOS = {
    "normal": normal,
    "single_loud": single_loud,
    "low_and_slow": low_and_slow,
    "burst": burst,
    "recovering": recovering,
}


# ---------------------------------------------------------------------------
# Ground truth
# The "correct answer": which devices are really attackers. Later a
# detection method (Gap 2) can be scored against it (how many found, how
# many missed, how many false alarms).
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
        return set()                       # no attackers
    n = len(device_ids)
    step = max(1, n // attacker_count)     # gap between attackers, e.g. 24 // 9 = 2
    # pick every "step"-th device, starting from the second one.
    # With 24 devices and 9 attackers: dev-002, dev-004, ..., dev-018
    chosen = {device_ids[(i * step + 1) % n] for i in range(attacker_count)}
    return chosen


def write_ground_truth(path, scenario, devices, attackers, window_start_step):
    # Save the run details as JSON (default file: ground_truth.json)
    record = {
        "scenario": scenario,
        "generated_at": datetime.now(timezone.utc).isoformat(),  # when the run started (UTC)
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
    # The same fields as TrustUpdate in bridge/main.py
    payload = {
        "device_id": device_id,
        "trust_value": round(trust_value, 2),   # 2 decimals, like the chaincode stores
        "threshold": threshold,
        "reason_code": reason_code,
        "attack_class": attack_class,
        "confidence": confidence,
        "evidence": evidence_tag,               # short text; the ledger stores only its SHA-256 hash
    }
    try:
        r = session.post(
            f"{url}/v1/trust",
            headers={"x-api-key": key, "Content-Type": "application/json"},  # API key for the bridge
            json=payload,
            timeout=timeout,                    # give up after 20 s (a Fabric commit takes about 2 s)
        )
        if r.status_code != 200:
            # e.g. 401 wrong key, 422 bad value, 400 device not registered
            print(f"  [warn] {device_id}: HTTP {r.status_code} {r.text[:200]}",
                  file=sys.stderr)
            return False
        return True
    except requests.exceptions.RequestException as exc:
        # the bridge is not running, or no answer in time
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
    # Each thread keeps its own requests.Session (sessions are not safe to
    # share between threads). A session reuses the open connection, which
    # is faster than opening a new one for every request.
    local = threading.local()

    def session():
        if not hasattr(local, "s"):
            local.s = requests.Session()
        return local.s

    # attackers are reported as AI_ANOMALY, normal devices as MANUAL
    reason_code = "AI_ANOMALY" if attackers else "MANUAL"

    sent, failed = 0, 0
    start_time = time.time()

    for t in range(steps):                     # one loop = one evaluation cycle
        # 1. work out every device's value for this step
        jobs = []
        for dev in devices:
            if dev in attackers:
                value = SCENARIOS[scenario](t)  # attacker follows the scenario curve
                attack_class = scenario         # label, e.g. "low_and_slow"
                conf = confidence
            else:
                value = SCENARIOS["normal"](t)  # everyone else behaves normally
                attack_class = ""
                conf = 0.0
            jobs.append(dict(
                device_id=dev,
                trust_value=value,
                threshold=threshold,
                reason_code=reason_code if dev in attackers else "MANUAL",
                attack_class=attack_class,
                confidence=conf,
                evidence_tag=f"{dev}-step{t}-{scenario}",  # e.g. "dev-004-step3-low_and_slow"
            ))

        # 2. send all values of this step in parallel and wait for all answers
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            results = list(pool.map(
                lambda j: send_trust_value(session(), url, key, **j), jobs))  # **j = use the dict as named arguments
        sent += sum(1 for ok in results if ok)
        failed += sum(1 for ok in results if not ok)

        # 3. show progress, then wait before the next step
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
    # Command-line options. Every option has a default except --key.
    ap = argparse.ArgumentParser(
        description="Generate simulated trust values for testing the "
                    "blockchain component before Member 1's trust "
                    "engine is available.")
    ap.add_argument("--scenario", default="low_and_slow",
                    choices=sorted(SCENARIOS),              # only the five names above are accepted
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


# Runs only when the file is started directly (python generate_trust.py),
# not when it is imported by another file.
if __name__ == "__main__":
    args = parse_args()

    # same seed -> same random noise -> the same values every run
    if args.seed is not None:
        random.seed(args.seed)

    if args.attackers > args.devices:
        print("error: --attackers cannot exceed --devices", file=sys.stderr)
        sys.exit(1)

    # device IDs match register_devices.py: dev-001, dev-002, ...
    device_ids = [f"dev-{i:03d}" for i in range(1, args.devices + 1)]
    attacker_set = choose_attackers(device_ids, args.attackers, args.scenario)

    # print the run settings (stderr, so they do not mix with normal output)
    print(f"scenario        = {args.scenario}", file=sys.stderr)
    print(f"total devices   = {len(device_ids)}", file=sys.stderr)
    print(f"attacker devices= {sorted(attacker_set) if attacker_set else '(none)'}",
          file=sys.stderr)
    print(f"target          = {args.url}", file=sys.stderr)
    print("-" * 60, file=sys.stderr)

    # all attackers start at step 0 in these scenarios
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