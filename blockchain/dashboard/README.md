# ZTIoT Trust Ledger dashboard (Member 3)

A Streamlit demo console for the blockchain component. It talks to the **bridge** (`127.0.0.1:8000`) with the API key, the same way Members 1, 2 and 4 do. The "Org1 vs Org2" page also **reads** both CouchDB world states. Only the "Tamper test" page **writes** to CouchDB directly, on purpose, to play an attacker.

## Pages

| Page | What it shows | Bridge call |
|---|---|---|
| Fleet overview | All devices: trust, threshold, ACTIVE / SUSPECT, chart | `GET /v1/devices/{id}` |
| Device detail | Trust over time, trust events, **verify the evidence hash**, raw record | `/history`, `/events` |
| Send trust value | Stand in for Member 1; the contract decides the status | `POST /v1/trust` |
| Member 1 trust engine | Runs `Trust Score/feed_trust.py` (real engine scores to the ledger), chart and summary | `POST /v1/trust` |
| Register / move device | Admin only; "access denied" when the connector runs as trustengine1 | `POST /v1/devices`, `PUT .../address` |
| Security tests | 9 requests that must be refused (401, 422, 400) | various |
| Member 4 IP lookup | IP in, device type and trust out | `GET /v1/devices/by-address/{ip}` |
| Org1 vs Org2 (CouchDB) | Both organisations' copies side by side, with a match check | CouchDB 5984 and 7984 (read only) |
| Tamper test | Step 1 edits Org1's CouchDB directly (fake trust). The page shows it is caught (Org1 differs from Org2 and from the blocks). Step 2 tries a real transaction (refused, or the new block overwrites the edit). Step 3 restores Org1 from Org2 | CouchDB 5984 (write), 7984, `/history`, `POST /v1/trust` |

## Install (once)

```bash
cd ~/ztiot && source venv/bin/activate
pip install -r dashboard/requirements.txt
```

## Run

The network, connector and bridge must be running first (see the demo file).

```bash
cd ~/ztiot && source venv/bin/activate
export BRIDGE_API_KEY=dev-key
cd dashboard && streamlit run app.py
```

Open **http://127.0.0.1:8501** in Firefox on the VM. Stop it with Ctrl+C.

Run it from the `dashboard` folder so the settings in `.streamlit/config.toml` apply (local address only, SLIIT navy theme).

## Notes

- The API key and CouchDB login can be changed in the sidebar under **Connection settings**. Defaults: `dev-key`, `admin` / `adminpw` (Fabric test network).
- The dashboard listens on `127.0.0.1` only, so it is not reachable from other machines.
- The Member 1 page waits for every Fabric commit; 15 cycles for 24 devices take about 1 to 2 minutes. Tick **Offline** for a quick comparison without writing.
- Nothing on the Org1 vs Org2 page writes to the database.
- Tamper test: use it on the test network only, and press Step 3 (Restore) when you finish. If something goes wrong, `./network.sh down` and up again rebuilds everything.
