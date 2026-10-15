# ztiot - Blockchain trust ledger (PP1 code base)

Component: Blockchain and Smart Contract Policy Enforcement (J26-CS-315).

| Folder | What it is | Language |
|---|---|---|
| `chaincode/ztiot-cc` | Smart contract (DeviceContract, TrustContract), unit tests, mock ledger | Go |
| `gateway` | Client connector: signs and submits transactions to Fabric (127.0.0.1:3000) | Node.js 22 |
| `bridge` | Service interface for the other members, API key protected (port 8000) | Python 3.10+ |
| `simulator` | Device registration and trust value generator (stands in for Member 1) | Python |
| `scripts` | Peer CLI settings, trustengine identity, CLI smoke test | Bash |

Quick start on a laptop without Fabric (development only):

```bash
cd chaincode/ztiot-cc && go mod tidy && go test ./... -cover
go run ./cmd/mockledger                       # terminal 1
cd ~/ztiot && source venv/bin/activate
export BRIDGE_API_KEY=dev-key
uvicorn bridge.main:app --port 8000           # terminal 2
python simulator/register_devices.py --devices 24 --key dev-key
python simulator/generate_trust.py --scenario low_and_slow --key dev-key
```

On the Fabric network, replace the mock ledger with `cd gateway && npm start`.
The full step-by-step instructions are in the PP1 development guide.
