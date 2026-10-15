#!/usr/bin/env bash
# Smoke test straight against the peers with the peer CLI (no bridge, no gateway).
# Proves the chaincode is deployed and working.  Safe to run more than once:
# the second run shows the "already registered" refusal, which is also a pass.
source "$(dirname "$0")/fabric_env.sh"

ID="${1:-cli-001}"
IP="${2:-192.168.50.1}"
HASH=$(printf 'sim-cert:%s' "$ID" | sha256sum | cut -d' ' -f1)

echo "== 1. register $ID at $IP"
cc_invoke "{\"function\":\"DeviceContract:RegisterDevice\",\"Args\":[\"$ID\",\"camera\",\"4\",\"$HASH\",\"$IP\"]}" || true

echo "== 2. record a trust value of 62.5"
cc_invoke "{\"function\":\"TrustContract:RecordTrustValue\",\"Args\":[\"$ID\",\"62.5\",\"70\",\"scan\",\"AI_ANOMALY\",\"{\\\"note\\\":\\\"cli test\\\"}\",\"0.8\"]}"

echo "== 3. read the device"
cc_query "{\"Args\":[\"DeviceContract:GetDevice\",\"$ID\"]}"
echo

echo "== 4. Member 4 lookup by IP"
cc_query "{\"Args\":[\"DeviceContract:GetDeviceByAddress\",\"$IP\"]}"
echo

echo "== 5. trust events"
cc_query "{\"Args\":[\"DeviceContract:GetTrustEvents\",\"$ID\"]}"
echo
