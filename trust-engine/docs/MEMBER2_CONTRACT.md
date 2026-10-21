# Member 2 -> Member 1 behavior-event contract

Implementation version: trust engine 0.3.0. Project J26-CS-315. Based on Member 2's supplied guide v1.0, 19 October 2026, pages 3-8. That guide is a proposed interface; the choices below are explicit prototype defaults to confirm with the group.

## Request

Send JSON to `POST http://127.0.0.1:8001/v1/behavior-events` in a local demonstration. Use HTTPS between machines. Set `Authorization: Bearer <TRUST_SERVICE_TOKEN>` and `Content-Type: application/json`.

```json
{
  "event_id": "10000000-0000-4000-8000-000000000001",
  "schema_version": "1.0",
  "device_id": "IOT-001",
  "flow_id": "flow-0123",
  "observed_at": "2026-10-19T05:00:00Z",
  "model_version": "ai-0.3.0",
  "prediction": "DoS-SYN_Flood",
  "attack_probability": 0.92,
  "classification_confidence": 0.95,
  "anomaly_score": 0.80,
  "temporal_risk": null,
  "behavior_risk": 0.878,
  "quality_status": "valid",
  "window_seconds": 5
}
```

This timestamp is an illustration. Generate a current UTC timestamp and a new UUID for each new event. Use the exact same UUID, timestamp and content when retrying that event. `demo_behavior_events.py` does this automatically. `member2_sender.py` is a bounded retry example to adapt inside Member 2's service.

## Mapping and ownership

| Member 2 field | Member 1 use | Member 3 representation |
|---|---|---|
| `event_id` | Global UUID idempotency key; `evidenceRef = behavior-event:<UUID>` | Retained inside hashed evidence; NOT the Fabric transaction ID |
| `device_id` | Exact registered case-sensitive device identity | `device_id` on bridge / `deviceId` on ledger |
| `behavior_risk` | Unchanged `Observation.behavior_risk`; trust = 1 - risk | 0-100 projected trust value |
| `observed_at` | UTC observation time; freshness and ordering | Retained in evidence; ledger timestamp is transaction time |
| `prediction` | `attack_class` metadata | `attack_class` / `attackClass` |
| `classification_confidence` | `confidence` metadata | `confidence`; null uses bridge-compatible 0, while evidence preserves null |
| `anomaly_score` | `anomaly_score` metadata | Inside hashed evidence |
| `attack_probability` | Audit metadata only | Inside hashed evidence |
| `temporal_risk` | Audit metadata only; null accepted | Inside hashed evidence |
| `flow_id`, `window_seconds` | Traceability and declared observation window | Inside hashed evidence |
| `model_version`, `schema_version` | Version audit | Inside hashed evidence |
| `quality_status` | Validity gate | Inside evidence for accepted valid/partial events |
| `feature_schema_version`, `calibration_version` | Optional additional version strings | Inside hashed evidence |

The receiver does not calculate the fusion weights, substitute classification confidence for attack probability, add temporal risk twice, or invent absent detector outputs. It accepts Member 2's final normalized risk. The other two raw risk fields and confidence are not extra scoring terms.

No `criticality`, `threshold`, `network_context` or arbitrary extra fields are accepted from Member 2. Criticality is administrator/registry owned; the existing network-context default is 0 until a separate trusted signal is implemented.

## Validation

- `schema_version` must be the literal string `1.0`.
- IDs must match `^[A-Za-z0-9-]{3,64}$` and already exist locally (imported from the ledger in blockchain mode). `IOT_001` is not silently changed to `IOT-001`. The gateway owns identity assignment; neither attack labels nor dataset row numbers establish identity.
- `event_id` must be a non-nil UUID. UUID spelling and timestamps are normalized for semantic payload comparison; JSON key ordering and omitted optional null fields do not produce a conflict.
- Risk and confidence values are finite numbers in [0,1]. Strings, booleans, NaN and Infinity are rejected.
- `behavior_risk` is required. A non-null risk is required for `valid` or `partial`. `invalid` quality is archived/rejected and never updates trust, even if a numeric risk is present.
- Optional detector fields may be omitted or null. Partial evidence is accepted only when Member 2 supplies a valid fused risk, and is marked `partial` in the audit. No confidence discount or fusion is added here.
- `observed_at` must be an ISO 8601 UTC string ending in `Z` or `+00:00`; optional fractions have 1-6 digits. Epoch numbers, naive timestamps and non-UTC offsets are rejected. Send the actual observation-window end time, not a rewritten timestamp that disguises delayed data.
- Default freshness: `received_at - observed_at <= 15 seconds`. Default future skew: observed time at most 2 seconds ahead. Both boundaries are inclusive.
- A new event must be strictly newer than the previous accepted observation for that device. Equal-time distinct events are rejected. Publish one device-level risk per ordered window; Member 2 must aggregate simultaneous flows deliberately before sending them.
- `flow_id` and version strings are nonblank, at most 128 characters. Prediction labels use Member 3's 64-character letters/digits/underscore/dot/colon/hyphen convention.
- `window_seconds` is a finite positive number, at most 3600. The receiver uses the declared window end for freshness; it does not rebuild flows from packet data.
- Maximum request body: 16 KiB. Event endpoint rate limit: 6000 authenticated requests/minute per service process, including retries. This is an admission limit, not a measured throughput result.

## Responses and retries

| Status | Meaning | Sender action |
|---|---|---|
| 202 | Trust update persisted and applied; `accepted: true` | Inspect `decision` and separate blockchain receipt |
| 202 + `duplicate: true` | Previously accepted identical event; no new scoring or ledger write | Treat as success; receipt may now show a newer delivery status |
| 400 | Bad score type/range, missing risk, malformed JSON, non-finite number or duplicate JSON key | Fix producer; do not retry unchanged |
| 401 | Missing/wrong credential or wrong service role | Correct credential; admin token is not AI token |
| 409 | UUID reused with different content, or new out-of-order event | Investigate; do not generate a new UUID to disguise the same rejected evidence |
| 413 / 415 | Body too large / unsupported content type | Fix request |
| 422 | Unsupported version, invalid device, timestamp, quality or other schema | Fix contract/mapping; stale observations remain audit evidence only |
| 429 | Request limit exceeded | Back off; bounded retries preserve exact event |
| 503 / other 5xx / transport timeout | Temporary storage/service failure or pending earlier ledger delivery | Bounded retry of the exact event; resolve previous outbox delivery if indicated |

A first successful body includes `event_id`, `accepted`, `device_id`, `reason: "trust_updated"`, `decision`, `duplicate: false`, and `blockchain` (null when disabled). The PDF's sample says `queued_for_trust_update`; this implementation processes synchronously after its durable write, so it returns `trust_updated` instead. 202 never means packet enforcement completed.

Accepted duplicates are checked before freshness, so a lost acknowledgment can be recovered after the TTL or after restart. They do not refresh the evidence age. A content conflict is never interpreted as a new observation. Fully parsed terminal rejections are stored with their UUID and repeated unchanged rejections receive the same status. Pending-ledger 503 is temporary and does not consume the event ID. Malformed/schema-invalid bodies are rejected before they can become accepted event records.

For durable delivery, Member 2 should persist its own pending event before sending and preserve it after an ambiguous timeout. The included sender shows bounded in-process retries, not a full durable AI queue. Do not replace old observation times to force stale data through the endpoint.

## Missing evidence and dashboard reads

An administrator/dashboard can request `GET /v1/devices/IOT-001/trust` with `TRUST_ADMIN_TOKEN`:

- `unknown`: no accepted v1 event is available. No current numeric score is asserted.
- `fresh`: latest accepted v1 evidence is within the permitted age.
- `stale`: latest accepted v1 evidence has expired. The historical decision remains visible; `current_trust_value` is null.
- `effective_action` is `hold` for unknown/stale evidence or an unconfirmed ledger delivery, unless the existing quarantine latch already requires `quarantine`.

`hold` is a policy recommendation. The unchanged Member 3 ledger will not automatically notice silence. The gateway/enforcement owner must poll this endpoint, treat unusable evidence conservatively, and implement the actual restriction. No missing-event synthetic risk is fed into the preserved scoring algorithm.
