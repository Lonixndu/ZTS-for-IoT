# Changes in v0.3.0 - 19 October 2026

- Added authenticated Member 2 `/v1/behavior-events` ingestion, exact field mapping,
  registered device-ID validation, UTC freshness/order checks and quality handling.
- Added persistent event deduplication, conflict detection and rejected-event audit.
- Added transactional input/decision/outbox writes and full adaptive-state replay.
- Added separate admin credentials, request-size/rate limits and fail-closed defaults.
- Added current evidence status, safe unknown/stale reporting and documentation of
  downstream enforcement responsibility. No synthetic benign risk on missing data.
- Retained the existing Member 3 wire adapter and quarantine-preserving projection.
- Disabled legacy `/evaluate` by default; provided new synthetic demos and sender.
- Added Windows/VS Code/existing-repository setup, monorepo CI, schema, test evidence,
  and real HTTP verification against Member 3's supplied Go mock ledger.
- No change to the scoring algorithm, feature calculations, weights or latch.

---

# Changes

## 0.2.0 — 17 October 2026

Aligned the trust-engine output with the supplied blockchain repository.

- Added `blockchain_client.py`: exact bridge fields, API-key header, device import,
  criticality normalization, reason mapping, evidence hashing, and receipt checks.
- Added `blockchain_outbox.py`: durable local decisions, ordered delivery, explicit
  retry handling, and reconciliation of uncertain submissions using ledger events.
- Updated `main.py` and `schemas.py` with import/status/retry endpoints and delivery
  receipts. Offline mode remains available without a blockchain key.
- Preserved predicted AI metadata in the engine response, history, and blockchain
  evidence. Restricted prediction labels to the supplied bridge's accepted format.
- Preserved quarantine intent across chaincode rounding and automatic reactivation
  using an explicitly documented effective-score projection.
- Added `demo_blockchain.py`, `.env.example`, compatibility tests, and a complete
  connection guide. Moved the trust-engine example port to 8001; bridge stays 8000.
- Added HTTPX to runtime dependencies. No teammate code is included or changed.

The scoring formula and weights are unchanged. This is an implementation update,
not new dataset evaluation or a claim of achieving the proposal's targets.

## 0.1.0 — 17 October 2026

Initial standalone trust engine, API, synthetic simulations, tests, and documentation.
