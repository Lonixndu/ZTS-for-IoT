# J26-CS-315: complete Windows, VS Code and GitHub setup

Prepared for Member 1's adaptive trust-scoring component, version 0.3.0, on 19 October 2026. You do not need to run the earlier setup instructions first. Follow this guide from Step 1.

The local demonstration runs on Windows in **Visual Studio Code**, with **PowerShell** terminals. You do not need the full Visual Studio IDE, Docker or a Fabric network to begin. Use the full `.venv\Scripts\python.exe` commands below; this avoids PowerShell activation-policy problems.

## 1. Install and check the tools

Install these from their official sites:

| Tool | What to select | Why it is needed |
|---|---|---|
| [Python for Windows](https://www.python.org/downloads/windows/) | A 64-bit Python **3.12** runtime; include the Python launcher | Runs your API, tests and demo with the tested Python minor version |
| [Visual Studio Code](https://code.visualstudio.com/) | Windows installer; enable PATH integration if offered | Edits, runs and debugs your component |
| [Git for Windows](https://git-scm.com/downloads/win) | Command-line Git, with Git Credential Manager | Downloads your existing repository and pushes your feature branch |
| Microsoft Python extension in VS Code | Publisher **Microsoft**, extension `ms-python.python` | Interpreter selection, testing and debugging |

Close and reopen PowerShell/VS Code after installing. Open PowerShell and check:

```powershell
py -3.12 --version
git --version
code --version
```

Each command should print a version. If `code` is unavailable, open VS Code from the Start menu and use **File > Open Folder** instead of the `code` commands below. If `py -3.12` cannot find Python, install/select the 3.12 runtime before proceeding. Python 3.12.14 was used for the Linux validation; the Windows commands and CI configuration are provided but have not been executed on your laptop.

## 2. Clone your existing GitHub repository

Your repository is `https://github.com/Lonixndu/ZTS-for-IoT.git`. A read-only check found `main` at `6304b7b6dec097e352e235988c86a859e1aff827`, with top-level `ai-engine`, `blockchain`, `federated-learning`, `integration`, `docs` and an empty placeholder `trust-engine` folder. No GitHub files or branches were changed during this review.

Run:

```powershell
New-Item -ItemType Directory -Force "C:\Research\J26-CS-315" | Out-Null
Set-Location "C:\Research\J26-CS-315"
git clone https://github.com/Lonixndu/ZTS-for-IoT.git
Set-Location ".\ZTS-for-IoT"
git remote -v
git status
git switch -c feature/adaptive-trust-integration
```

`clone` creates the local copy and connects `origin` to GitHub. `remote -v` checks the destination. `status` should show a clean working tree. `switch -c` creates your component branch so the group can review the change before merging.

If you already cloned this repository, do not clone over it. Open the existing folder, run `git status`, preserve any uncommitted work, and create the feature branch there. If the branch already exists, use `git switch feature/adaptive-trust-integration`.

Use this existing repository for the current request. Creating a second repository is not necessary.

## 3. Put the updated component into the correct folder

Download the updated ZIP from this chat and save it as `J26-CS-315-trust-engine-v0.3.0.zip` in Downloads. The archive contains one top-level folder, `trust-engine`.

```powershell
$trustZip = Join-Path $env:USERPROFILE "Downloads\J26-CS-315-trust-engine-v0.3.0.zip"
$trustStage = "C:\Research\J26-CS-315\updated-starter"
$trustRepo = "C:\Research\J26-CS-315\ZTS-for-IoT"
Expand-Archive -LiteralPath $trustZip -DestinationPath $trustStage

$existingTrustFiles = Get-ChildItem "$trustRepo\trust-engine" -Force | Where-Object { $_.Name -ne ".gitkeep" }
if ($existingTrustFiles) { throw "trust-engine already contains work. Stop here and compare it before copying." }
Get-ChildItem "$trustStage\trust-engine" -Force | Copy-Item -Destination "$trustRepo\trust-engine" -Recurse -Force
Set-Location "$trustRepo\trust-engine"
Get-Item .\main.py, .\requirements-dev.txt, .\START_HERE_WINDOWS.md
```

Change `$trustZip` if the downloaded name differs. Use a new empty staging folder if `updated-starter` already exists. The guard prevents accidental replacement of work added since the repository check. The resulting application path must be `ZTS-for-IoT\trust-engine\main.py`, not a second nested `trust-engine\trust-engine\main.py`.

Do not copy this component over `ai-engine` or `blockchain`. Keep Member 3's supplied ZIP as a separate reference for the exact-source tests below.

## 4. Open the component in VS Code

```powershell
Set-Location "C:\Research\J26-CS-315\ZTS-for-IoT\trust-engine"
code .
```

In VS Code, open **Terminal > New Terminal** and choose PowerShell. The terminal should be in the `trust-engine` folder. You can check with `Get-Location`. Git still recognizes the parent `ZTS-for-IoT` repository when you open just the component.

The included VS Code settings assume the component itself is the open workspace. If you open the entire repository instead, explicitly select the interpreter at `trust-engine\.venv\Scripts\python.exe` and set the terminal directory to `trust-engine`.

## 5. Create an isolated Python environment

In the component terminal:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pip check
```

The virtual environment keeps this project's packages separate from other projects. `requirements-dev.txt` installs the API dependencies and pytest, using the starter's exact pinned versions. `pip check` should report no broken requirements. Installation needs an internet connection.

Press **Ctrl+Shift+P**, choose **Python: Select Interpreter**, and select `trust-engine\.venv\Scripts\python.exe`. If it is missing, choose **Enter interpreter path** and browse to that file. The selected interpreter controls editing and debugging; the full executable commands still work regardless of terminal activation.

Do not commit the `.venv` folder. You do not need to change the machine-wide PowerShell execution policy.

## 6. Create private local settings

```powershell
.\.venv\Scripts\python.exe configure_local.py
```

This creates `.env` with two separate random credentials and safe local defaults. It refuses to overwrite an existing file. Keep `.env` private; it is excluded from Git.

| Setting | Initial value/use |
|---|---|
| `TRUST_SERVICE_TOKEN` | Generated token for Member 2's event sender |
| `TRUST_ADMIN_TOKEN` | Different generated token for registration, reads and retries |
| `TRUST_STATE_DB` | `results/trust_state.sqlite3`, for the standalone demonstration |
| `TRUST_EVENT_TTL_SECONDS` | 15; a prototype freshness limit |
| `TRUST_FUTURE_SKEW_SECONDS` | 2; permitted clock skew |
| `TRUST_ENABLE_LEGACY_EVALUATE` | `false`; use the new event API |
| `BLOCKCHAIN_ENABLED` | `false` until Step 11 |
| `BLOCKCHAIN_OUTBOX` | `results/integrated_state.sqlite3`, a separate combined state/outbox database |

`run_server.py` reads `.env`. Existing shell environment variables take priority; avoid keeping old `TRUST_*`/`BLOCKCHAIN_*` settings from another project in the same terminal. Settings use literal `KEY=VALUE` lines; no shell expressions are executed.

## 7. Run the tests before starting the API

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Without Member 3's source path, expect **148 passed and 5 skipped** for this version. The skipped tests need the actual supplied bridge. To include them, extract the separately supplied `blockchain(3).zip` into a fresh reference directory:

```powershell
$member3Zip = Join-Path $env:USERPROFILE "Downloads\blockchain(3).zip"
Expand-Archive -LiteralPath $member3Zip -DestinationPath "C:\Research\J26-CS-315\member3-reference"
$env:BLOCKCHAIN_SOURCE_DIR = "C:\Research\J26-CS-315\member3-reference\blockchain"
Test-Path "$env:BLOCKCHAIN_SOURCE_DIR\bridge\main.py"
.\.venv\Scripts\python.exe -m pytest -q
```

`Test-Path` must return `True`. Expect **153 passed**. Those five tests execute Member 3's real Python bridge with a simulated connector. They do not require running services or a Fabric network. One Starlette TestClient deprecation warning is known with the preserved pins; it does not fail the tests.

The repository's `blockchain` copy has the same Python bridge executable logic, with different documentation. The attached ZIP remains the source used for the reported validation. Do not overwrite the group's blockchain folder just to run these tests.

## 8. Start the API

In terminal A, from `trust-engine`:

```powershell
.\.venv\Scripts\python.exe run_server.py
```

Keep this terminal running. The engine listens on `http://127.0.0.1:8001`. You should see that application startup completed. In a browser, open:

- `http://127.0.0.1:8001/health` for status.
- `http://127.0.0.1:8001/docs` for the API documentation.

The health response should say version `0.3.0`, storage `sqlite-replayable`, and `blockchainEnabled: false`. In Swagger, **Authorize** offers two roles: use the AI service token for the event route and the admin token for other protected routes. Do not show credentials in presentation screenshots.

Use one worker. Do not launch a second copy against the same database. Stop the server with **Ctrl+C** when instructed. Restarting preserves the registry, history, event IDs and quarantine latch.

## 9. Run your first synthetic integration demonstration

Open terminal B in VS Code. Run:

```powershell
Set-Location "C:\Research\J26-CS-315\ZTS-for-IoT\trust-engine"
.\.venv\Scripts\python.exe demo_behavior_events.py --register local --device-id IOT-001
```

This registers a device at criticality 0.75 and sends three fresh Member 2-shaped events, each followed by an identical retry. It uses synthetic risk values; it does not execute the RF/AE/LSTM models.

| Step | BehaviorRisk | Original engine TrustScore | Expected first-run action |
|---|---:|---:|---|
| 1 | 0.10 | 0.90 (90/100) | allow |
| 2 | 0.878 | 0.122 (12.2/100) | quarantine |
| 3 | 0.01 | 0.99 (99/100) | quarantine, because the existing latch remains set |

Each identical retry should print `duplicate = True` and should not add another decision. An already quarantined device will remain quarantined if you rerun the demo. To show another independent run, use a new explicitly registered device such as `IOT-002`; do not erase an audit database to release a real device.

After more than 15 seconds without a new accepted event, the current-trust endpoint reports `stale`. It retains the historical decision and existing quarantine latch, and does not invent a new benign score.

## 10. Understand and exercise the Member 2 handoff

Agree with Member 2 and the gateway owner that the registered ID is exactly `IOT-001`, with a hyphen. `IOT_001` from the PDF is incompatible with Member 3's current validation. Do not infer IDs from an attack class or a shuffled dataset row.

Member 2 needs your event URL, the **AI service token only**, and `docs/MEMBER2_CONTRACT.md`. Exchange the token through your team's private channel; do not put it in source code or a commit. The admin token stays with you/dashboard administration. For a remote sender, `127.0.0.1` means their own machine; use the reachable HTTPS address of your service instead.

The following PowerShell example loads the local token without printing it, registers a fresh local device, and sends one event:

```powershell
Set-Location "C:\Research\J26-CS-315\ZTS-for-IoT\trust-engine"
$trustSettings = @{}
Get-Content .\.env | ForEach-Object {
    if ($_ -match '^(TRUST_[A-Z0-9_]+|BLOCKCHAIN_[A-Z0-9_]+)=(.*)$') {
        $trustSettings[$Matches[1]] = $Matches[2]
    }
}
$adminHeaders = @{ Authorization = "Bearer $($trustSettings['TRUST_ADMIN_TOKEN'])" }
$aiHeaders = @{ Authorization = "Bearer $($trustSettings['TRUST_SERVICE_TOKEN'])" }
$registration = @{ deviceId = 'IOT-003'; criticality = 0.75 } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8001/devices' -Headers $adminHeaders -ContentType 'application/json' -Body $registration

$behaviorEvent = [ordered]@{
    event_id = [guid]::NewGuid().ToString()
    schema_version = '1.0'
    device_id = 'IOT-003'
    flow_id = 'powershell-demo-1'
    observed_at = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.ffffffZ')
    model_version = 'synthetic-demo-v1'
    prediction = 'BenignTraffic'
    attack_probability = 0.01
    classification_confidence = 0.99
    anomaly_score = $null
    temporal_risk = $null
    behavior_risk = 0.10
    quality_status = 'valid'
    window_seconds = 5
} | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8001/v1/behavior-events' -Headers $aiHeaders -ContentType 'application/json' -Body $behaviorEvent
```

Repeat only the last `Invoke-RestMethod` command to test a duplicate. Keep `$behaviorEvent` unchanged. Creating a new UUID is a new event, not a retry. Create new timestamps only for genuinely new observations.

To inspect the current state and history:

```powershell
Invoke-RestMethod -Uri 'http://127.0.0.1:8001/v1/devices/IOT-003/trust' -Headers $adminHeaders | ConvertTo-Json -Depth 12
Invoke-RestMethod -Uri 'http://127.0.0.1:8001/devices/IOT-003/history' -Headers $adminHeaders | ConvertTo-Json -Depth 12
```

The receiver uses `behavior_risk` directly, maps `classification_confidence` to confidence metadata, and preserves attack probability, optional anomaly/temporal values and model versions. It does not replace your algorithm with the PDF's example weighted formula.

## 11. Connect Member 3 using his supplied Go mock ledger

This is a local integration test using the real Go contract behind Member 3's fake ledger stub. It is not a Fabric network, and it does not block packets. Keep the three services in separate terminals.

### 11a. Prepare the exact blockchain source and Go

Use the extracted reference directory from Step 7. Install Go from [go.dev/doc/install](https://go.dev/doc/install); the module declares Go 1.21 and was validated here with Go 1.27.2. Reopen terminals after installation.

Terminal L:

```powershell
Set-Location "C:\Research\J26-CS-315\member3-reference\blockchain\chaincode\ztiot-cc"
go version
go test ./...
go run ./cmd/mockledger
```

Keep this terminal open. The mock ledger listens on `127.0.0.1:3000`. Its state is in memory and is lost if you stop it. Its fixed mock transaction clock is separate from the real `observed_at` time in the AI evidence.

### 11b. Enable blockchain mode in the trust engine

Stop terminal A's trust server with Ctrl+C. In `trust-engine\.env`, set:

```text
BLOCKCHAIN_ENABLED=true
BLOCKCHAIN_URL=http://127.0.0.1:8000
BLOCKCHAIN_API_KEY=<your separate long random bridge key>
BLOCKCHAIN_OUTBOX=results/integrated_state.sqlite3
```

For your own local mock, generate the bridge key using:

```powershell
.\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(32))"
```

Copy that private value into `.env`. If connecting to Member 3's already-running service, use the key he supplies instead. Do not use either trust bearer token as the bridge key. The separate integrated database keeps local-only demonstration registrations from being mistaken for ledger imports.

### 11c. Start Member 3's unchanged Python bridge

Terminal B:

```powershell
$trustRoot = 'C:\Research\J26-CS-315\ZTS-for-IoT\trust-engine'
$trustSettings = @{}
Get-Content "$trustRoot\.env" | ForEach-Object {
    if ($_ -match '^(TRUST_[A-Z0-9_]+|BLOCKCHAIN_[A-Z0-9_]+)=(.*)$') {
        $trustSettings[$Matches[1]] = $Matches[2]
    }
}
$env:BRIDGE_API_KEY = $trustSettings['BLOCKCHAIN_API_KEY']
$env:CONNECTOR_URL = 'http://127.0.0.1:3000'
Set-Location 'C:\Research\J26-CS-315\member3-reference\blockchain'
& "$trustRoot\.venv\Scripts\python.exe" -m uvicorn bridge.main:app --host 127.0.0.1 --port 8000
```

This uses the same Python dependencies you installed for the trust engine. Keep it running. `http://127.0.0.1:8000/health` should report a reachable connector with `ledger: "mock"`.

### 11d. Register a device on the ledger, then import it

Terminal C, in `trust-engine`, load `.env` into `$trustSettings` using the block from Step 10. Then:

```powershell
$bridgeHeaders = @{ 'x-api-key' = $trustSettings['BLOCKCHAIN_API_KEY'] }
$ledgerDevice = @{
    device_id = 'IOT-001'
    device_type = 'camera'
    criticality = 4
    network_address = '192.168.10.44'
} | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8000/v1/devices' -Headers $bridgeHeaders -ContentType 'application/json' -Body $ledgerDevice
```

This simulated address is registry metadata; it does not require a physical device at that IP. Member 3 derives a simulated certificate hash if you omit `identity_hash`. A real deployment needs the real registered device identity.

Restart terminal A:

```powershell
Set-Location 'C:\Research\J26-CS-315\ZTS-for-IoT\trust-engine'
.\.venv\Scripts\python.exe run_server.py
```

Then in terminal C:

```powershell
.\.venv\Scripts\python.exe demo_behavior_events.py --register blockchain --device-id IOT-001
```

The demo calls `/devices/import`, normalizes ledger criticality 4 to `(4 - 1) / 4 = 0.75`, and sends fresh events. Expect `blockchain.status: "committed"` and a transaction ID for each accepted new event. Identical retries must not add ledger events.

Read the ledger record/events:

```powershell
Invoke-RestMethod -Uri 'http://127.0.0.1:8000/v1/devices/IOT-001' -Headers $bridgeHeaders | ConvertTo-Json -Depth 8
Invoke-RestMethod -Uri 'http://127.0.0.1:8000/v1/devices/IOT-001/events' -Headers $bridgeHeaders | ConvertTo-Json -Depth 8
```

The final status remains `SUSPECT` despite the last low-risk event, because your trust engine's existing quarantine latch is preserved. Its raw trust of 99/100 may differ from the policy-adjusted ledger value. The complete unadjusted score and projection are in local evidence; do not report the projection as the raw TrustScore.

If you stop/restart the mock ledger, its devices disappear while the engine's SQLite state remains. For a fresh mock experiment, preserve the previous database and select a new unused `BLOCKCHAIN_OUTBOX` filename, then re-register/import devices. Do not pair a reset mock ledger with old delivery state and claim continuity. Real Fabric persistence is different.

### 11e. Optional automated real-HTTP verification

This starts and stops its own services on temporary ports, uses an isolated database, and tests the actual supplied Go contract through the mock ledger:

```powershell
Set-Location 'C:\Research\J26-CS-315\member3-reference\blockchain\chaincode\ztiot-cc'
go build -o 'C:\Research\J26-CS-315\member3-reference\mockledger.exe' ./cmd/mockledger
Set-Location 'C:\Research\J26-CS-315\ZTS-for-IoT\trust-engine'
.\.venv\Scripts\python.exe scripts\verify_stack.py --blockchain-source 'C:\Research\J26-CS-315\member3-reference\blockchain' --mockledger-binary 'C:\Research\J26-CS-315\member3-reference\mockledger.exe'
```

Read `results/http-stack-check.json`. This includes duplicate handling, restart recovery, trust scaling, evidence hashes, stale-event rejection and the latch. It remains a mock-ledger integration result, not Fabric performance evidence.

## 12. Connect to Member 3's real deployment

Your trust-engine adapter already uses the supplied `/v1/devices/{id}`, `/v1/trust` and `/v1/devices/{id}/events` routes with `x-api-key`. To use his deployed bridge, stop your engine, set `BLOCKCHAIN_URL` to its reachable HTTPS origin, use his bridge key, choose a new state/outbox database for that environment, restart, and import his registered device ID.

Member 3 must supply the running Fabric network, channel/chaincode names, appropriate enrolled gateway identity, certificates and bridge URL. His Node connector requires Node >=22.12.0, `npm ci` in `blockchain/gateway`, and `gateway/.env` paths pointing to his actual credentials. Do not invent or copy another member's private signing key. His local connector should stay private to the bridge.

No complete Fabric network configuration or live credentials were provided for this task, so Fabric deployment, endorsement/commit behavior, firewall rules and actual gateway enforcement require the joint deployment check. The shipped guide does not claim that this has already happened.

For an AI sender on another computer, use your own TLS certificate and reachable service address. From the component folder, a direct Uvicorn TLS launch can be:

```powershell
.\.venv\Scripts\python.exe -m uvicorn main:application --factory --host 0.0.0.0 --port 8001 --workers 1 --ssl-certfile 'C:\Research\certs\trust-server.crt' --ssl-keyfile 'C:\Research\certs\trust-server.key'
```

Replace those paths with your real certificate/key; the sender must validate the certificate and use its matching host name. Only allow the agreed peer through your firewall. Do not disable certificate verification to make the integration appear successful. Local loopback commands in earlier steps need no TLS certificate.

## 13. Handle blockchain failures without double scoring

Load `$adminHeaders` as in Step 10, then inspect:

```powershell
Invoke-RestMethod -Uri 'http://127.0.0.1:8001/blockchain/status/IOT-001' -Headers $adminHeaders | ConvertTo-Json -Depth 8
```

- `committed`: the bridge returned a transaction receipt.
- `failed`: delivery failed before a confirmed commit; the trust decision is saved locally.
- `uncertain`: the request may have committed, but its receipt was lost.
- `pending`: saved but not yet completed.

After restoring connectivity, request reconciliation/retry:

```powershell
Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8001/blockchain/retry/IOT-001' -Headers $adminHeaders -ContentType 'application/json' -Body '{}'
```

For `uncertain`, the adapter first searches ledger events by evidence hash. It will not blindly resend an ambiguous transaction. If it returns 409 because no matching event is visible, inspect the ledger with Member 3 before considering `confirmUncertainRetry: true`; that explicit action can create a duplicate ledger event. There is no native bridge idempotency key in the supplied implementation.

While an earlier ledger delivery is unresolved, new v1 events for that device receive 503. An identical already-accepted event is still acknowledged without scoring again. The AI sender should use bounded retries and retain original timestamps; after the TTL it needs a genuinely new observation, not a fabricated fresh timestamp.

## 14. Commit and push your component branch

First stop any demonstration you no longer need. From the repository root, add the provided monorepo CI workflow:

```powershell
Set-Location 'C:\Research\J26-CS-315\ZTS-for-IoT'
New-Item -ItemType Directory -Force '.github\workflows' | Out-Null
if (Test-Path '.github\workflows\trust-engine.yml') { throw 'An existing trust-engine workflow needs review before replacement.' }
Copy-Item '.\trust-engine\integration\trust-engine-ci.yml' '.\.github\workflows\trust-engine.yml'
```

A workflow nested inside `trust-engine\.github` is not run by GitHub; the root-level copy above is the one used by this group repository. It configures Python tests on Windows and Ubuntu, including the repository's bridge source. Those hosted runs will happen after you push.

Set your commit identity if it is not already configured. Use your own name and GitHub email (or your GitHub-provided private commit email):

```powershell
git config user.name 'YOUR_NAME'
git config user.email 'YOUR_GITHUB_EMAIL'
git status --short
git add -- trust-engine .github/workflows/trust-engine.yml
git diff --cached --stat
git diff --cached --name-only
```

These settings apply to this repository. Review the staged filenames: they should be your component and workflow, with no `.env`, virtual environment, certificates, keys or SQLite databases. The component's ignore rules exclude these. Then:

```powershell
git commit -m "Integrate adaptive trust engine with AI events and blockchain bridge"
git push -u origin feature/adaptive-trust-integration
```

If Git Credential Manager opens a browser, sign in to your GitHub account. Do not put passwords or access tokens in the repository URL. If HTTPS prompts for a password instead, GitHub uses an appropriate personal access token rather than your account password; use the official credential-manager/PAT workflow.

Open your repository on GitHub, choose **Compare & pull request**, use base `main` and compare `feature/adaptive-trust-integration`, and review the diff and Actions results with the group. This guide does not merge the branch or push any changes for you.

For future work: run `git status`, edit, rerun the relevant tests, then `git add`, `git commit` and `git push`. Do not force-push over other members' work. If the remote has advanced, preserve your local work and fetch/review it before merging changes.

## 15. Keep evidence for PP1 and your logbook

Capture actual outputs from your own run:

1. `pytest` result, with the optional bridge tests enabled.
2. A successful fresh event response showing the device ID, risk, trust, threshold and decision.
3. The identical retry showing `duplicate: true`, with only one added history entry.
4. Current-trust status after evidence expires, showing `stale` and no invented current score.
5. A committed blockchain receipt and the corresponding ledger event/evidence hash.
6. The low-risk event after quarantine, showing the original latch is preserved.

Keep credentials out of screenshots. Label synthetic data, mock ledger and connector doubles accurately. Do not describe the illustrative 0.878 example or a two-device smoke run as validated AI accuracy or measured live-network performance.

For an offline synthetic smoke experiment:

```powershell
Set-Location 'C:\Research\J26-CS-315\ZTS-for-IoT\trust-engine'
.\.venv\Scripts\python.exe simulation.py --devices-per-scenario 2 --rounds 10 --output results\my-smoke
```

The checked smoke run included false positives; tune and evaluate on separated validation/test data before making research performance claims. Preserve the original algorithm parameters until a justified, documented experiment changes them.

## 16. Troubleshooting

| Symptom | What to check |
|---|---|
| `py` or Python 3.12 not found | Install/select the 3.12 runtime and reopen the terminal |
| `ModuleNotFoundError` | Use the component's `.venv\Scripts\python.exe`; rerun the pinned install |
| PowerShell blocks activation | Skip activation and use the full executable commands in this guide |
| 401 on event POST | Use `TRUST_SERVICE_TOKEN`, not admin or bridge credentials |
| 503 `required service credential` | Run `configure_local.py`; start via `run_server.py`; check stale shell variables |
| 422 device rejection | Use the same case-sensitive hyphenated ID and register/import it first |
| 422 stale/future event | Generate real UTC observation times, synchronize clocks, preserve retry timestamps |
| 409 duplicate conflict | The same UUID has different content; investigate the producer |
| 409 out of order | Another observation for the device has an equal/newer timestamp |
| 503 previous ledger delivery pending | Inspect and reconcile the outbox before sending new observations |
| API writer lock error | Stop the other engine process; use one worker; do not delete an active lock/database |
| Address/port already in use | Stop the conflicting demo; trust uses 8001, bridge 8000, mock 3000 |
| State/configuration mismatch | Preserve the old database; select a new path for a new mode/parameter experiment |
| Device disappeared after mock restart | Re-register it on the reset mock and start a new integrated experiment/database |
| `Using SOCKS proxy ... socksio` | If your environment uses a SOCKS proxy, install `httpx[socks]==0.28.1` in the venv; keep proxy/CA settings approved by your institution |
| Git push rejected / repository not found | Check `git remote -v`, account authentication and write access; do not force-push |
| Tests skip the bridge cases | Set `BLOCKCHAIN_SOURCE_DIR` to the folder containing `bridge/main.py` |
| Score recovers but action stays quarantine | This is the preserved latch, not a bug or an automatic release feature |

## Official setup references

- [Python virtual environments](https://docs.python.org/3.12/library/venv.html)
- [VS Code Python environments and interpreter selection](https://code.visualstudio.com/docs/python/environments)
- [GitHub: cloning a repository](https://docs.github.com/en/repositories/creating-and-managing-repositories/cloning-a-repository)
- [GitHub: adding locally hosted code](https://docs.github.com/en/migrations/importing-source-code/using-the-command-line-to-import-source-code/adding-locally-hosted-code-to-github)
- [Go installation](https://go.dev/doc/install)
