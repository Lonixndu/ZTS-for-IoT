import hashlib # SHA-256, used to make an identity hash for simulated devices
import hmac # compares the API key safely
import ipaddress # checks that an IP address is valid
import os # reads settings from environment variables
import re # regular expressions, used to check device IDs
from contextlib import asynccontextmanager # used to run code when the server starts and stops
from typing import Optional # marks a value that may be missing (None)
 
# Third-party libraries
import httpx # async HTTP client, used to call the connector
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field, field_validator
 
# Settings
 
# Address of the Node.js connector. Read from the environment, with a default.
CONNECTOR = os.getenv("CONNECTOR_URL", "http://127.0.0.1:3000")
 
# Shared secret that callers must send in the "x-api-key" header.
# It is read from the environment so it is never written in the code or in Git.
API_KEY = os.getenv("BRIDGE_API_KEY", "")
 
# Only these values are accepted. Anything else is rejected before it reaches
# the blockchain (allow-list input validation).
REASON_CODES = {"AI_ANOMALY", "POLICY_VIOLATION", "RECOVERY", "MANUAL"}
DEVICE_TYPES = {"camera", "sensor", "actuator", "gateway", "meter", "lock"}
 
# Device ID rule: letters, numbers and "-" only, 3 to 64 characters.
# ^ and $ mean the whole text must match, not only part of it.
DEVICE_ID = r"^[A-Za-z0-9-]{3,64}$"
 
# One shared HTTP client for the whole process. Creating a client per request
# costs about 50 ms (connection and TLS context set-up) and would cap
# throughput far below the 100 records per second target.
_client: Optional[httpx.AsyncClient] = None
 
@asynccontextmanager
async def lifespan(_app):
    # Code before "yield" runs once when the server starts.
    global _client
    _client = httpx.AsyncClient(
        base_url=CONNECTOR, timeout=30, # every request goes to the connector; give up after 30 s
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=50))  # reuse open connections
    yield # the server runs and handles requests here
    # Code after "yield" runs once when the server stops.
    await _client.aclose() # close the connections cleanly
 
 
# Create the web application. The title and version appear on the /docs page.
app = FastAPI(title="Trust ledger service interface", version="1.0", lifespan=lifespan)
 
# Security
 
def require_key(x_api_key: str = Header(default="")) -> None:
    # Every endpoint except /health needs the shared API key.
    # FastAPI reads the "x-api-key" request header into x_api_key.
    # If the server was started without a key, refuse everything (fail closed).
    # 503 = service unavailable: the server is not set up correctly.
    if not API_KEY:
        raise HTTPException(status_code=503, detail="server has no BRIDGE_API_KEY set")
 
    # compare_digest takes the same time whether the key is almost right or
    # completely wrong. A normal "==" stops at the first wrong character, and
    # an attacker could measure that time to guess the key (timing attack).
    if not hmac.compare_digest(x_api_key.encode(), API_KEY.encode()):
        raise HTTPException(status_code=401, detail="unauthorised") # 401 = wrong or missing key
 
 
def check_ipv4(value: str) -> str:
    # Accept only a real IPv4 address such as 192.168.10.44.
    try:
        ip = ipaddress.IPv4Address(value) # raises ValueError for text like "abc" or "300.1.1.1"
    except ValueError:
        raise ValueError("must be a valid IPv4 address such as 192.168.10.44")
    # Each device has one address index on the ledger, so one address must
    # always be written the same way or the lookup for Member 4 would fail.
    if str(ip) != value:
        raise ValueError("must be written in canonical form, without leading zeros")
    return value
 
 
def check_id(device_id: str) -> str:
    # DEVICE_ID[1:-1] removes the ^ and $ because fullmatch already checks the
    # whole string.
    if not re.fullmatch(DEVICE_ID[1:-1], device_id):
        raise HTTPException(status_code=400, detail="invalid device id") # 400 = bad request
    return device_id
 
# Request models
# Pydantic checks every JSON body against these classes before the endpoint
# code runs. A wrong type, a missing field or a value out of range is
# rejected automatically with error 422 and never reaches the blockchain.
 
class DeviceRegistration(BaseModel):
    # Body of POST /v1/devices
    device_id: str = Field(pattern=DEVICE_ID)                   
    device_type: str                                            
    criticality: int = Field(ge=1, le=5)                        
    network_address: str                                        
    identity_hash: Optional[str] = Field(default=None, pattern=r"^[0-9a-f]{64}$") 
 
    @field_validator("device_type")
    @classmethod
    def _type(cls, v):
        # Extra rule for device_type: only the allowed types.
        if v not in DEVICE_TYPES:
            raise ValueError(f"device_type must be one of {sorted(DEVICE_TYPES)}")
        return v
 
    @field_validator("network_address")
    @classmethod
    def _ip(cls, v):
        # Extra rule for network_address: a valid IPv4 address.
        return check_ipv4(v)
 
class TrustUpdate(BaseModel):
    # Body of POST /v1/trust (sent by Member 1's trust engine)
    device_id: str = Field(pattern=DEVICE_ID)
    trust_value: float = Field(ge=0, le=100) # new trust score, 0 to 100
    threshold: float = Field(ge=0, le=100)  # below this score the device is restricted
    reason_code: str # must be in REASON_CODES (checked below)
    attack_class: str = Field(default="", max_length=64, pattern=r"^[A-Za-z0-9_.:-]*$")  # optional label from Member 2
    confidence: float = Field(default=0.0, ge=0, le=1) # optional AI confidence, 0 to 1
    evidence: str = Field(default="", max_length=8192) # optional notes; length limit stops huge records
 
    @field_validator("reason_code")
    @classmethod
    def _reason(cls, v):
        # Extra rule for reason_code: only the allowed codes.
        if v not in REASON_CODES:
            raise ValueError(f"reason_code must be one of {sorted(REASON_CODES)}")
        return v
 
class AddressChange(BaseModel):
    # Body of PUT /v1/devices/{device_id}/address
    network_address: str
 
    @field_validator("network_address")
    @classmethod
    def _ip(cls, v):
        return check_ipv4(v)
 
# Connector calls
 
async def _call(method: str, path: str, json_body: Optional[dict] = None):
    # Send one request to the Node.js connector and return its JSON answer.
    # Every endpoint below uses this function, so errors are handled in one place.
    try:
        r = await _client.request(method, path, json=json_body)
    except httpx.HTTPError:
        # The connector is not running or did not answer in time.
        raise HTTPException(status_code=503, detail="ledger connector is not reachable")
 
    if r.status_code == 200:
        return r.json() # success: pass the ledger result back to the caller
 
    # The connector answered with an error. Try to read its error message.
    try:
        msg = r.json().get("error", "ledger request failed")
    except ValueError: # the answer was not JSON
        msg = "ledger request failed"
    # contract validation messages are safe to pass back; anything else is generic
    # 400 = the smart contract rejected the input, 404 = device not found.
    # Any other error becomes 502 (bad gateway) so internal details are not shown.
    code = r.status_code if r.status_code in (400, 404) else 502
    raise HTTPException(status_code=code, detail=msg)
 
# Endpoints
# dependencies=[Depends(require_key)] makes FastAPI run require_key() first.
# If the key is wrong, the endpoint code never runs.
 
@app.get("/health")
async def health():
    # Open endpoint (no key) so you can check quickly that the services are up.
    try:
        r = await _client.get("/health", timeout=5)
        return {"bridge": "ok", "connector": r.json()}
    except httpx.HTTPError:
        return {"bridge": "ok", "connector": "unreachable"}
 
 
@app.post("/v1/devices", dependencies=[Depends(require_key)])
async def register_device(body: DeviceRegistration):
    """Register a device. In production the identity hash is the SHA-256 of the
    device certificate; for simulated devices it is derived from the ID."""
    # Use the given hash, or make one from the device ID for simulated devices.
    identity = body.identity_hash or hashlib.sha256(f"sim-cert:{body.device_id}".encode()).hexdigest()
    # Python uses snake_case names; the connector and chaincode use camelCase.
    return await _call("POST", "/tx/register", {
        "deviceId": body.device_id,
        "deviceType": body.device_type,
        "criticality": body.criticality,
        "identityHash": identity,
        "networkAddress": body.network_address,
    })
 
@app.post("/v1/trust", dependencies=[Depends(require_key)])
async def record_trust(body: TrustUpdate):
    """Called by Member 1 on every evaluation cycle."""
    # Forward the trust score to the connector, which calls
    # TrustContract:RecordTrustValue on the ledger.
    return await _call("POST", "/tx/trust", {
        "deviceId": body.device_id,
        "trustValue": body.trust_value,
        "threshold": body.threshold,
        "attackClass": body.attack_class,
        "reasonCode": body.reason_code,
        "evidence": body.evidence,
        "confidence": body.confidence,
    })
 
# This route is placed before /v1/devices/{device_id} on purpose. FastAPI checks
# routes in order, so "by-address" is not mistaken for a device ID.
@app.get("/v1/devices/by-address/{address}", dependencies=[Depends(require_key)])
async def device_by_address(address: str):
    """Called by Member 4: send an IP address, receive the device type."""
    try:
        check_ipv4(address)
    except ValueError as exc:
        # check_ipv4 raises ValueError; turn it into an HTTP 400 answer.
        raise HTTPException(status_code=400, detail=str(exc))
    return await _call("GET", f"/query/by-address/{address}")
 
@app.put("/v1/devices/{device_id}/address", dependencies=[Depends(require_key)])
async def change_address(device_id: str, body: AddressChange):
    # Change a device's IP address (the ledger updates the address index too).
    check_id(device_id)
    return await _call("POST", "/tx/address", {"deviceId": device_id, "newAddress": body.network_address})
 
@app.get("/v1/devices/{device_id}", dependencies=[Depends(require_key)])
async def get_device(device_id: str):
    # Current record of one device: type, status, latest trust value and so on.
    check_id(device_id)# checked so the ID is safe to put in the connector URL
    return await _call("GET", f"/query/device/{device_id}")
 
@app.get("/v1/devices/{device_id}/history", dependencies=[Depends(require_key)])
async def device_history(device_id: str):
    # Every past version of the device record, from the ledger history.
    # This is the tamper-proof audit trail of trust changes.
    check_id(device_id)
    return await _call("GET", f"/query/history/{device_id}")
 
@app.get("/v1/devices/{device_id}/events", dependencies=[Depends(require_key)])
async def device_events(device_id: str):
    # The trust events recorded for the device (score, reason, attack class).
    check_id(device_id)
    return await _call("GET", f"/query/events/{device_id}")
 