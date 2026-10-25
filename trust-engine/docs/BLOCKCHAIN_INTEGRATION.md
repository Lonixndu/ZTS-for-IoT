# Member 1 -> Member 3 integration

The full Windows startup commands are in [START_HERE_WINDOWS.md](../START_HERE_WINDOWS.md), Steps 11-13. They use the supplied `blockchain(3).zip` unchanged. Member 3's bridge listens on 8000; this trust engine listens on 8001. His Go mock ledger or Node/Fabric connector listens on 3000.

## Verified contract

| Item | Trust-engine behavior | Supplied Member 3 behavior |
|---|---|---|
| Authentication | Sends `x-api-key: BLOCKCHAIN_API_KEY` | Compares against `BRIDGE_API_KEY` |
| Registry lookup | `GET /v1/devices/{id}` before import | Returns device, type, criticality, IPv4 address and status |
| Device identity | Exact `^[A-Za-z0-9-]{3,64}$` on public endpoints | Same pattern in bridge and Go contract |
| Criticality | `(ledger_level - 1) / 4` | Integer 1-5 |
| Score and threshold | Converts engine 0-1 to 0-100, rounds to two decimals | Accepts 0-100; chaincode rounds to two decimals |
| Trust submission | `POST /v1/trust`, snake_case body | Maps to camelCase connector body and RecordTrustValue arguments |
| Receipt | Requires `status: committed` and a nonempty `txId` | Bridge forwards connector receipt |
| Evidence | JSON containing original decision, AI event metadata and projection | SHA-256 fingerprint stored in TrustEvent |
| Reconciliation | `GET /v1/devices/{id}/events`, matching evidence hash/value/device | Exposes immutable trust-event records |

## Payload and reason-code mapping

The bridge payload contains `device_id`, `trust_value`, `threshold`, `reason_code`, `attack_class`, `confidence`, and `evidence`. The actual connector receives `deviceId`, `trustValue`, `threshold`, `reasonCode`, `attackClass`, `confidence`, and `evidence`.

| Engine reason | Bridge reason |
|---|---|
| TRUST_ACCEPTED | MANUAL |
| NEAR_BOUNDARY_MONITOR | AI_ANOMALY |
| BELOW_THRESHOLD | AI_ANOMALY |
| MISSING_BEHAVIOR_RISK | POLICY_VIOLATION |
| QUARANTINE_LATCHED | POLICY_VIOLATION |

This reason map already existed in the starter and is retained for compatibility. `MANUAL` is a coarse permitted ledger code, not a claim that a human made the decision. The exact automatic engine reason remains inside evidence and local history. Agree a more precise ledger vocabulary with Member 3 before changing it.

The bridge has no `action` or quarantine-latch argument. The existing adapter therefore exports an effective trust below the rounded threshold if a quarantined decision would otherwise reactivate the device. For example, raw engine trust 99/100 may be exported as 73.99 against threshold 74 to preserve quarantine. The evidence preserves the raw score and a `policyAdjusted` marker. This projection is unchanged from the starter and does not modify the core trust calculation.

## Durable delivery

The v0.3 API uses one database in integrated mode, selected by `BLOCKCHAIN_OUTBOX`. Registrations, accepted observations, decisions, event receipts and delivery entries are stored there. Acceptance and outbox insertion are atomic. Restarts replay all accepted inputs through the unchanged engine to recover its full adaptive state.

Only one unresolved delivery per device is allowed. A new behavior event receives 503 while an earlier delivery is pending/failed/uncertain. An identical accepted retry returns its saved decision without another scoring operation or submission. Admin retries operate on the saved payload, never a recalculated decision.

The bridge has no caller-provided idempotency key. An uncertain write is reconciled by evidence hash first. Explicitly overriding an uncertain retry can create duplicate chain events and requires inspection. The API does not claim exactly-once ledger delivery under all network failures.

Member 3's bridge has a 30-second connector timeout, while the Node connector allows longer Fabric commit waits. A slow Fabric commit can therefore appear uncertain; preserving/reconciling the outbox is necessary even when local mock tests pass.

## What stays outside this adapter

- Member 3's code is not modified or bundled as a replacement.
- No Fabric network, CA registration, real device certificate, MSP role or signing key is invented.
- A local SQLite audit is editable; only a real distributed ledger deployment establishes the intended blockchain persistence properties.
- A ledger receipt does not prove a firewall/gateway performed quarantine.
- The unchanged ledger has no evidence-expiration field or silence watchdog. Downstream enforcement must poll Member 1's current-trust endpoint and enforce unknown/stale/hold status.
- Model calibration and real flow-to-device mapping remain Member 2/gateway responsibilities.

## Source notes

The attached ZIP is the tested contract source. The GitHub `main` snapshot was also inspected to prepare repository instructions. Its Python bridge has equivalent executable AST after removing documentation, but the trees are not byte-identical: comments/import order differ and GitHub's Go `util.go` contains an additional unused `parseNumber` helper. `RecordTrustValue` still has float64 arguments in both sources. The adapter's finite-number validation prevents these non-finite inputs at the Member 1 boundary. No older blockchain ZIP was available for a byte-level comparison with an earlier conversation.
