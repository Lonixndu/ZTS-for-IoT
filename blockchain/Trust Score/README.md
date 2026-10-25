# Trust Score (Member 1 parts used by Member 3)

This folder holds the parts of **Member 1's adaptive trust engine** that the blockchain component (Member 3) needs to receive **real trust scores**.

With it, the ledger is no longer fed by fixed simulator curves. Every trust value and threshold is calculated by Member 1's engine and then recorded and enforced by Member 3's smart contract.

```
behaviour risk (synthetic, shaped like Member 2 output)
  -> Member 1 TrustEngine.evaluate()     trust value, adaptive threshold, allow / quarantine
  -> make_trust_update()                 0-1 engine scale -> 0-100 ledger payload
  -> POST /v1/trust  (bridge, port 8000) API key and input checks
  -> connector (port 3000) -> Fabric     smart contract sets ACTIVE / SUSPECT, writes the trust event
```

## What is in this folder

| File | From | Purpose |
|---|---|---|
| `engine.py` | Member 1 (unchanged) | Stateful trust decisions, quarantine latch |
| `adaptive_threshold.py` | Member 1 (unchanged) | Five-variable adaptive threshold |
| `features.py` | Member 1 (unchanged) | Criticality, violation history, score velocity, personal baseline, network context |
| `static_baseline.py` | Member 1 (unchanged) | Fixed threshold, used for comparison |
| `config.py` | Member 1 (unchanged) | Weights and limits (provisional) |
| `device_state.py` | Member 1 (unchanged) | Observation and device state records |
| `attacker_strategies.py` | Member 1 (unchanged) | Evasive attackers: `fixed_margin`, `slow_drift`, `randomised` |
| `blockchain_client.py` | Member 1 (unchanged) | Member 1's adapter to this bridge: payload, API key, receipt check |
| `feed_trust.py` | **Member 3 (new)** | Runs the engine for every registered device and writes each decision to the ledger |
| `tests/test_thresholds.py` | Member 1 (unchanged) | Engine tests |
| `tests/test_feed_trust.py` | **Member 3 (new)** | Feeder tests (offline, deterministic) |

Member 1's full service (Member 2 endpoint, SQLite outbox and replay, admin API) stays in Member 1's own `trust-engine` folder. It is not needed by the blockchain component.

## How to run

1. The Fabric network, the connector (on **Admin** for registration) and the bridge must be running, and the devices registered:

   ```bash
   cd ~/ztiot && source venv/bin/activate
   export BRIDGE_API_KEY=dev-key
   python simulator/register_devices.py --devices 24 --key "$BRIDGE_API_KEY"
   ```

2. Send real trust scores. The folder name has a space, so keep the quotes:

   ```bash
   cd ~/ztiot/"Trust Score"
   python feed_trust.py --scenario burst --steps 8
   python feed_trust.py --scenario slow_drift --steps 15
   ```

3. Check one attacker on the ledger:

   ```bash
   curl -s -H "x-api-key: $BRIDGE_API_KEY" localhost:8000/v1/devices/dev-002 | jq '{trustValue, threshold, status}'
   ```

### Options

| Option | Default | Meaning |
|---|---|---|
| `--devices` | 24 | Devices `dev-001` to `dev-N` (must be registered) |
| `--attackers` | 3 | Attacking devices, spread across the fleet (`dev-002`, `dev-010`, `dev-018`) |
| `--scenario` | burst | `burst` (obvious) or Member 1's evasive `fixed_margin`, `slow_drift`, `randomised` |
| `--steps` / `--warmup` | 8 / 2 | Evaluation cycles, and quiet cycles before the attack |
| `--mode` | adaptive | `static` uses a fixed threshold, for comparison |
| `--offline` | off | Compute and print only; nothing is written to the ledger |
| `--key` | `$BRIDGE_API_KEY` | The bridge API key |

The decisions of each run are saved to `results/` (not committed to Git).

## Tests

```bash
cd ~/ztiot/"Trust Score"
python -m pytest -q
```

Expected: **32 passed**. These tests need no network.

## What it shows

| Scenario | Adaptive engine (Member 1) | Static threshold |
|---|---|---|
| `burst` | 3/3 attackers SUSPECT, 0 false alarms | 3/3 |
| `slow_drift`, `fixed_margin`, `randomised` (15 steps) | **3/3 attackers SUSPECT**, 0 false alarms | **0/3**, the evasive attackers stay ACTIVE |

So the adaptive score (Member 1) catches attackers that hide under a fixed limit, and the smart contract (Member 3) records each decision as an endorsed, permanent trust event.

## Limits

- The behaviour risk is **synthetic**. No Member 2 model runs here.
- The engine weights are **provisional** (Member 1's own note).
- SUSPECT is a **policy decision on the ledger**, not a firewall action.
- A quarantined device stays SUSPECT (Member 1's quarantine latch). Use a fresh network or new device IDs for a new demonstration.
- The ledger reason code is coarse (`MANUAL`, `AI_ANOMALY`, `POLICY_VIOLATION`); Member 1's exact reason is kept inside the evidence (stored on-chain only as a SHA-256 hash).
