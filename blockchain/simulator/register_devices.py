import argparse  # read command-line options (--devices, --key ...)
import sys       # print errors to stderr and set the exit code

import requests  # HTTP client used to call the bridge

# (device type, criticality) pairs, used in turn: device 1 = camera,
# device 2 = sensor, ... device 7 = camera again.
# Criticality 1 (low) to 5 (high) sets the starting threshold on the ledger:
# 5 -> 80, 4 -> 70, 3 -> 60, 2 -> 50. Actuators and locks are the most
# critical because they act in the physical world (e.g. open a door).
TYPES = [("camera", 4), ("sensor", 2), ("actuator", 5), ("gateway", 3), ("meter", 2), ("lock", 5)]


def main():
    # ---- 1. command-line options ----
    ap = argparse.ArgumentParser(description="Register simulated devices on the trust ledger.")
    ap.add_argument("--devices", type=int, default=24)                     # how many devices
    ap.add_argument("--subnet", default="192.168.10", help="first three octets of the device addresses")
    ap.add_argument("--url", default="http://localhost:8000")             # where the bridge runs
    ap.add_argument("--key", required=True, help="the BRIDGE_API_KEY value")  # the only required option
    a = ap.parse_args()

    # The device number becomes the last part of the IP address, which can
    # only be 1 to 254 (0 is the network address and 255 is broadcast).
    if not 1 <= a.devices <= 254:
        sys.exit("error: --devices must be between 1 and 254")

    # ---- 2. one HTTP session for all requests ----
    # The session reuses the connection and sends the API key header with
    # every request, so it is set only once.
    s = requests.Session()
    s.headers.update({"x-api-key": a.key})
    created = skipped = failed = 0          # counters for the summary

    # ---- 3. register each device ----
    for i in range(1, a.devices + 1):
        dev_id = f"dev-{i:03d}"             # 3 digits with leading zeros: dev-001, dev-024
        dev_type, crit = TYPES[(i - 1) % len(TYPES)]  # % = remainder, so the list repeats after 6
        # the same fields as DeviceRegistration in bridge/main.py.
        # identity_hash is not sent, so the bridge makes one from the device
        # ID (simulated devices have no real certificate).
        body = {"device_id": dev_id, "device_type": dev_type,
                "criticality": crit, "network_address": f"{a.subnet}.{i}"}
        try:
            # a Fabric transaction waits for its block, so allow up to 30 s
            r = s.post(f"{a.url}/v1/devices", json=body, timeout=30)
        except requests.RequestException as exc:
            # the bridge is not running or did not answer: count it and go on
            print(f"  [error] {dev_id}: {exc}", file=sys.stderr)
            failed += 1
            continue
        if r.status_code == 200:
            # committed on the ledger. {dev_id:8} pads the text to 8 characters so the columns line up
            created += 1
            print(f"registered {dev_id:8} {dev_type:9} crit={crit}  {body['network_address']}")
        elif "already registered" in r.text:
            # the chaincode refused a duplicate: this is fine when the script
            # is run a second time, so it is not counted as a failure
            skipped += 1
            print(f"skipped    {dev_id:8} (already registered)")
        else:
            # any other error, e.g. 401 wrong key, 400 address already used,
            # 400 access denied (connector not using the admin identity)
            failed += 1
            print(f"  [fail] {dev_id}: HTTP {r.status_code} {r.text[:200]}", file=sys.stderr)

    # ---- 4. summary ----
    print(f"\ndone. created={created} skipped={skipped} failed={failed}")
    # exit code 0 = all fine, 1 = something failed (useful in scripts)
    sys.exit(1 if failed else 0)


# Runs only when the file is started directly, not when it is imported.
if __name__ == "__main__":
    main()