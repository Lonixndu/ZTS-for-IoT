# J26-CS-315 - Adaptive Trust Engine v0.3.0

Start with **[START_HERE_WINDOWS.md](START_HERE_WINDOWS.md)** for the complete Windows, VS Code and existing GitHub repository setup. This component belongs in the repository's top-level `trust-engine` folder.

This update implements Member 2's behavior-event contract and connects it to the supplied Member 3 bridge. The original scoring algorithm, weights, five adaptive factors, probe logic and quarantine latch are preserved.

## What this version adds

- `POST /v1/behavior-events` with a dedicated AI bearer token, strict validation and an explicit common device ID.
- SQLite-backed event receipts, conflict detection, duplicate suppression and full engine-state recovery by deterministic replay.
- Atomic persistence of the event, decision and blockchain outbox entry.
- Freshness checks (15-second default), future-clock tolerance (2 seconds), and per-device ordering.
- `GET /v1/devices/{device_id}/trust` with `fresh`, `stale` or `unknown` evidence status.
- Separate administrator authentication for registry changes, history, status and ledger retries.
- A synthetic event demo, a bounded-retry sender example, and actual-HTTP stack verification against Member 3's Go mock ledger.

## Original algorithm

`trustValue = 1 - behavior_risk`, on a 0-1 scale. Five factors adjust the minimum required trust threshold; they do not form the PDF's illustrative weighted TrustScore. The threshold uses base 0.50, weights 0.08/0.22/0.10/0.08/0.06 for criticality/history/velocity/personal-baseline/network-context, and bounds 0.10-0.95. Existing history, probe and baseline update rules remain in force. Quarantine is latched; later benign risk alone does not release it.

The Member 2 adapter sets the starter's existing `network_context` default to 0 because the v1 event does not carry that independent signal. This is a prototype limitation, not measured evidence that the network is safe. Criticality comes from local administrator registration or Member 3's registry, never from the AI sender.

## Local first run

From this folder, using PowerShell after installing Python 3.12:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe configure_local.py
.\.venv\Scripts\python.exe run_server.py
```

In a second terminal in this folder:

```powershell
.\.venv\Scripts\python.exe demo_behavior_events.py --register local --device-id IOT-001
```

Use a fresh registered device for a new independent demonstration. An already quarantined device remains quarantined, including after restart. Never delete a real audit database to release a device.

## Identity and credentials

Use exactly the same, case-sensitive ID throughout the gateway, AI, trust engine and blockchain. The public API uses Member 3's existing pattern: `^[A-Za-z0-9-]{3,64}$`. Example: `IOT-001`. The PDF example `IOT_001` is incompatible with Member 3 and is rejected; no automatic renaming is performed.

`TRUST_SERVICE_TOKEN` is for Member 2's event POST. `TRUST_ADMIN_TOKEN` is for administration and dashboard reads. `BLOCKCHAIN_API_KEY` is the separate value shared with Member 3's `BRIDGE_API_KEY`. The generated `.env` is excluded from Git. HTTP is used only for local loopback demonstrations; use authenticated HTTPS for communication between computers.

## API summary

| Route | Credential | Purpose |
|---|---|---|
| `GET /health` | None | Local service/configuration status; not a Fabric connectivity guarantee |
| `POST /v1/behavior-events` | AI bearer | Validate, persist and apply a behavior event; return 202 |
| `POST /devices` | Admin bearer | Local-only device registration |
| `POST /devices/import` | Admin bearer | Import Member 3's device and criticality |
| `GET /v1/devices/{id}/trust` | Admin bearer | Current evidence status and effective policy recommendation |
| `GET /devices/{id}/history` | Admin bearer | Saved decisions and AI metadata |
| `GET /blockchain/status/{id}` | Admin bearer | Pending/latest delivery receipt |
| `POST /blockchain/retry/{id}` | Admin bearer | Reconcile/retry a saved delivery |
| `POST /evaluate` | Admin bearer | Legacy offline research input; disabled by default |

The API runs one writer process. Launch with `run_server.py` or `uvicorn main:application --factory --workers 1`. A database lock rejects a second writer. Changing the algorithm configuration or blockchain mode requires a separate database; the service rejects incompatible saved state.

## Integration and research limits

An event's 202 response means its trust update is durably recorded locally. Inspect the separate `blockchain.status` before claiming a ledger commit. A committed ledger record does not prove packet blocking or network enforcement.

When AI evidence expires, `/v1/devices/{id}/trust` returns `stale`, a null current score and `hold` (or the existing quarantine latch). It retains the historical score. Member 3's unchanged schema has no freshness field or watchdog: downstream enforcement must poll this endpoint and enforce `hold`; a silent device is not automatically changed on-chain.

The ledger stores scores on a 0-100 scale and rounds to two decimals. The pre-existing adapter preserves quarantine by exporting an effective score just below the threshold when necessary. Both the original engine score and the projection are retained in evidence. Do not interpret a policy-adjusted ledger value as the raw model-derived TrustScore.

This remains a research prototype: the weights and timing defaults are provisional, there is no automatic quarantine-release workflow, no trained Member 2 model is executed by the supplied demo, and no production Fabric network or physical enforcement was exercised in this delivery. SQLite audit history grows until archived; keep it on local disk, back it up while stopped, and monitor available disk space. Multi-worker deployments and performance targets need separate engineering and evaluation.

## Documentation

- [Windows, VS Code and GitHub steps](START_HERE_WINDOWS.md)
- [Integration review and exact field mapping](docs/INTEGRATION_REVIEW.md)
- [Member 2 endpoint contract](docs/MEMBER2_CONTRACT.md)
- [Member 3 setup and delivery behavior](docs/BLOCKCHAIN_INTEGRATION.md)
- [Validation evidence and limits](VALIDATION.md)
- [Original scoring design](docs/DESIGN.md)
- [Changelog](CHANGELOG.md)
