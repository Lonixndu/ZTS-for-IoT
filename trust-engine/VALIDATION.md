# Validation report - v0.3.0

Executed on 19 October 2026 in the Linux workspace with Python 3.12.14, the unchanged versions in `constraints-lock.txt`, and Go 1.27.2. Windows instructions are supplied; a Windows host and GitHub Actions were not run here.

## Results

| Check | Result | What it establishes |
|---|---|---|
| Three source files opened | Passed | Both ZIP CRC checks passed; PDF has nine readable pages |
| Original starter baseline | 101 passed | A working reference before modifications |
| Updated Python suite, supplied bridge enabled | **153 passed** | Core regressions plus API, persistence, failure and contract cases |
| Python suite without external bridge source | 148 applicable tests; 5 optional bridge cases | The five supplied-bridge tests are skipped unless `BLOCKCHAIN_SOURCE_DIR` is set |
| Supplied Go `go test ./...` | Passed | Member 3's actual contract test suite; no source edits |
| Node gateway source syntax | Passed | Both `server.js` and `fabric.js` parse; no Fabric connection was made |
| Real HTTP integration | Passed | Updated API -> supplied bridge -> supplied Go mock ledger executing the real contract |
| Restart and retry in HTTP stack | Passed | Three accepted events remain three ledger events after duplicates/restart |
| Synthetic offline smoke | Completed; 240 decisions | Experiment pipeline runs; not an accuracy or production-performance result |
| Original algorithm preservation | Passed | Five core modules byte-identical; config changes only VERSION |

The original 101-test suite was retained, with API tests adapted for authentication and the durable store. New cases cover schema/score/UTC validation, partial evidence, model versions, ID mismatches, stale/future/out-of-order events, unknown devices, invalid quality, duplicate conflicts, concurrent identical retries, role separation, missing credentials, body/rate limits, restart restoration, transactional rollback, dropped responses, uncertain ledger delivery and safe sender retry behavior.

`validation/pytest.txt` contains the final pytest output. Its one known warning is Starlette's TestClient/httpx deprecation with the preserved dependency pins. `socksio==1.0.0` was additionally installed only in the verification environment because its managed SOCKS proxy configuration is read by Member 3's unchanged HTTP client; it is not a new mandatory project dependency.

## Real HTTP evidence

See `validation/http-stack.json` and reproduce with `scripts/verify_stack.py`.

| Risk sequence | Raw engine trust | Engine action | Exported ledger trust |
|---:|---:|---|---:|
| 0.10 | 0.90 | allow | 90.00 |
| 0.878 | 0.122 | quarantine | 12.20 |
| 0.01 | 0.99 | quarantine (latched) | 73.99 against threshold 74.00 |

Each event was submitted twice. The actual Go mock ledger contained exactly **three** trust events. After stopping and restarting the trust API with the same SQLite database, another identical retry did not create a fourth event. Evidence hashes in API receipts matched the actual Go records. Wrong credentials and stale timestamps were also rejected over HTTP.

The Go mock executes contractapi and the supplied smart-contract methods with a fake ledger/identity. It is stronger evidence than a connector double, but it does not reproduce a distributed Fabric network, endorsement/commit timing, real CA enrollment, production persistence, or packet enforcement.

## Synthetic experiment caution

The smoke command was:

```text
python simulation.py --devices-per-scenario 2 --rounds 10 --output results/validation-smoke
```

There were six synthetic attack devices and two benign devices. In this tiny run, adaptive logic caught six attack devices and quarantined one benign device; the static baseline caught zero attack devices and quarantined zero benign devices. The one-in-two benign false-positive result is a warning against generalizing from this smoke run. The crafted sequences and provisional parameters are not a held-out real dataset. See `validation/synthetic-smoke-summary.json` for the actual saved output. Timing values there are workspace compute timings, not live IoT, HTTP, blockchain or edge-device benchmarks.

## Research/deployment work still needed

- Joint agreement on the implemented API defaults, ID convention, quality rules and one ordered device window per event.
- Genuine Member 2 inference and calibration, feature parity with the training schema, and reliable gateway device attribution.
- Evaluation and ablations with separately held-out data, more devices/seeds and reported false positives/uncertainty.
- Real Fabric deployment and evidence-hash reconciliation under its actual commit behavior.
- Downstream consumption/enforcement of stale/unknown/hold status and actual gateway restrictions.
- A reviewed quarantine-release policy; the existing latch intentionally remains.
- Windows-host/Actions validation, TLS deployment, capacity and end-to-end latency measurements.

No automated GitHub push, PR, merge or deployment was performed.
