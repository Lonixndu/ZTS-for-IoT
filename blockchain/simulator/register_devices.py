"""
register_devices.py

Registers simulated devices on the ledger through the service interface.
Run this once after deploying the contract, before generate_trust.py.

    python simulator/register_devices.py --devices 24 --key "$BRIDGE_API_KEY"

Device dev-001 gets 192.168.10.1, dev-002 gets 192.168.10.2, and so on.
Types and criticality rotate so the fleet is mixed. Devices that already
exist are reported and skipped, so the script is safe to run twice.
"""
import argparse
import sys

import requests

TYPES = [("camera", 4), ("sensor", 2), ("actuator", 5), ("gateway", 3), ("meter", 2), ("lock", 5)]


def main():
    ap = argparse.ArgumentParser(description="Register simulated devices on the trust ledger.")
    ap.add_argument("--devices", type=int, default=24)
    ap.add_argument("--subnet", default="192.168.10", help="first three octets of the device addresses")
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--key", required=True, help="the BRIDGE_API_KEY value")
    a = ap.parse_args()

    if not 1 <= a.devices <= 254:
        sys.exit("error: --devices must be between 1 and 254")

    s = requests.Session()
    s.headers.update({"x-api-key": a.key})
    created = skipped = failed = 0

    for i in range(1, a.devices + 1):
        dev_id = f"dev-{i:03d}"
        dev_type, crit = TYPES[(i - 1) % len(TYPES)]
        body = {"device_id": dev_id, "device_type": dev_type,
                "criticality": crit, "network_address": f"{a.subnet}.{i}"}
        try:
            r = s.post(f"{a.url}/v1/devices", json=body, timeout=30)
        except requests.RequestException as exc:
            print(f"  [error] {dev_id}: {exc}", file=sys.stderr)
            failed += 1
            continue
        if r.status_code == 200:
            created += 1
            print(f"registered {dev_id:8} {dev_type:9} crit={crit}  {body['network_address']}")
        elif "already registered" in r.text:
            skipped += 1
            print(f"skipped    {dev_id:8} (already registered)")
        else:
            failed += 1
            print(f"  [fail] {dev_id}: HTTP {r.status_code} {r.text[:200]}", file=sys.stderr)

    print(f"\ndone. created={created} skipped={skipped} failed={failed}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
