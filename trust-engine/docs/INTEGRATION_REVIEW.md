# Integration review - J26-CS-315

Review date: 19 October 2026. Updated component: v0.3.0. Scope: the three supplied files, with a read-only check of the existing GitHub repository for accurate setup instructions.

## Source confirmation

| Source | Opened and checked |
|---|---|
| `zero-trust-iot-starter(2).zip` | 39 ZIP entries; CRC integrity check passed; original baseline 101 Python tests passed |
| `IoT_AI_Member2_to_Member1_TrustScore_Integration_Guide(1).pdf` | Nine readable pages; schema/trust pages also visually inspected |
| `blockchain(3).zip` | 40 ZIP entries; CRC integrity check passed; used as the authoritative newly attached Member 3 source |

Full source hashes and preserved-algorithm hashes are in `validation/source-manifest.json`. The earlier requested `blockchain(2).zip` was not separately available; this review uses the actual `(3)` attachment, not an assumed copy of it.

## Findings and resolutions

| Finding | Implemented resolution | Limit / decision to retain |
|---|---|---|
| Starter exposes `/evaluate`, not Member 2's route/schema | Added `POST /v1/behavior-events` and documented exact v1 mapping | Old `/evaluate` is admin-only and disabled by default |
| Member 2 uses snake_case and several distinct confidence/risk values | `behavior_risk` is the sole risk input; classification confidence maps to confidence metadata; raw components/model versions retained | No second risk fusion or extra factor multiplier |
| No authenticated AI boundary in starter | Dedicated AI bearer token; distinct admin bearer; constant-time comparison; fail closed without credentials | HTTPS required between machines; local demo binds loopback |
| Duplicate retries could influence state more than once | UUID + canonical payload fingerprint stored persistently; identical retries return prior result; conflicts return 409 | Exact-once local acceptance within one preserved database; not a universal ledger exactly-once claim |
| Restart lost most adaptive state | Persisted registry and all accepted observations; deterministic replay restores baseline, history pressure, probe streak, latch and ordering | Single writer; growing audit/startup history requires monitoring and future retention work |
| Event and outbox writes could be separated by failure | One SQLite transaction commits event, decision, receipt and delivery entry | External ledger commit remains a separate operation |
| Freshness and missing-feed behavior absent | 15-second TTL, 2-second future skew, ordering checks; dashboard reports unknown/fresh/stale | Timing defaults are provisional; downstream must enforce hold on stale/unknown evidence |
| `IOT_001` conflicts with Member 3's ID regex | Public APIs consistently use Member 3's 3-64 letters/digits/hyphens; documented `IOT-001` | No silent aliasing; gateway/registry owner must assign IDs consistently |
| PDF's trust formula is only illustrative | Preserved the implemented `trust = 1 - risk` and adaptive-threshold method | Supervisor/group must confirm the research design; no unapproved 70/30 weighted formula introduced |
| Member 3 stores 0-100 scores and restricted reason codes | Retained existing scale conversion, reason map, evidence hashing and latch-preserving projection | `MANUAL` is the existing compatibility code for accepted trust; full original reason remains in evidence |
| A missing ledger receipt can follow a successful commit | Saved uncertain delivery; reconcile by hash before any explicit retry | Bridge provides no idempotency key; explicit uncertain resubmission can duplicate a chain event |
| Request shape and size need protection | Strict schema, finite numeric checks, JSON key/Unicode validation, 16-KiB limit and configurable rate limit | Not a full distributed API gateway or throughput benchmark |

## Algorithm preservation

These files are byte-identical to the starter: `engine.py`, `features.py`, `adaptive_threshold.py`, `static_baseline.py`, and `device_state.py`. `config.py` changes only the version string from 0.2.0 to 0.3.0; every engine parameter and weight is unchanged.

The five threshold factors remain criticality, violation-history pressure, negative score velocity, deviation above personal risk baseline, and network context. The existing history update, allowed baseline update, near-boundary probe behavior, threshold clipping and quarantine latch are preserved.

The receiver does not pretend the missing independent network-context measurement exists: it uses the starter's default 0. The guide's 70/30 weighted-score example is not the implemented algorithm. The exact meaning of these five factors and how to validate their weights remain research decisions.

Transport/quality changes are deliberate: malformed, invalid-quality, stale or out-of-order v1 events never reach the algorithm. An unavailable feed produces an explicit unusable-evidence status instead of a made-up benign risk. These rules govern whether evidence can be scored; they do not rewrite the formula.

## What was executed

- The original starter's 101-test baseline, including its supplied-bridge tests.
- The updated Python suite, including original regressions and new event/reliability cases; see `VALIDATION.md` for the final count.
- Member 3's supplied Go `go test ./...` contract suite, without code edits.
- A real HTTP sequence: synthetic event sender -> updated API -> supplied Python bridge -> supplied Go mock ledger executing the contract. Three new events produced three ledger events; duplicates and a trust-server restart produced no extra ledger writes.
- A synthetic offline experiment writing 240 decisions. Its small sample had false positives; it is a software smoke check, not research accuracy evidence.

No real RF/AE/LSTM inference, live IoT traffic, distributed Fabric network, consensus performance or physical gateway quarantine is claimed. The supplied test report distinguishes actual Go execution from connector doubles and real Fabric deployment.

## Team handoff

Member 2 should adopt the field semantics, registered ID, UTC precision, per-device ordered windows, TTL and retry rules in `MEMBER2_CONTRACT.md`, and publish genuine model output through that endpoint. Missing AE/LSTM values remain null. Model upgrades remain visible in the audit and need calibration validation outside this adapter.

Member 3 does not need a code change for the tested trust submission. Confirm his bridge URL/key, real registry identity, Fabric gateway credentials and existing effective-score/reason mapping for deployment. The GitHub copy differs from the ZIP mostly in documentation/import ordering and includes an additional unused `parseNumber` helper; the supplied Python bridge and GitHub bridge have equivalent executable AST. Do not overwrite his component with this archive.

The enforcement owner must consume the current-trust freshness state and apply hold/quarantine at the actual gateway. A blockchain `committed` response alone is not proof of enforcement. The team must still design controlled quarantine release; benign events do not currently release the preserved latch.
