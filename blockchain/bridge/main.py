"""
Service interface for the blockchain trust ledger.

This is what Members 1, 2 and 4 call. It validates every request, then
forwards it to the client connector (gateway/src/server.js) which signs and
submits the transaction to Fabric. During development the connector can be
replaced by the mock ledger (go run ./cmd/mockledger) with no change here.

Run:
    export BRIDGE_API_KEY="<long random string>"
    uvicorn bridge.main:app --host 0.0.0.0 --port 8000
"""
import hashlib
import hmac
import ipaddress
import os
import re
from contextlib import asynccontextmanager
from typing import Optional

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field, field_validator

CONNECTOR = os.getenv("CONNECTOR_URL", "http://127.0.0.1:3000")
API_KEY = os.getenv("BRIDGE_API_KEY", "")

REASON_CODES = {"AI_ANOMALY", "POLICY_VIOLATION", "RECOVERY", "MANUAL"}
DEVICE_TYPES = {"camera", "sensor", "actuator", "gateway", "meter", "lock"}
DEVICE_ID = r"^[A-Za-z0-9-]{3,64}$"

# One shared HTTP client for the whole process. Creating a client per request
# costs about 50 ms (connection and TLS context set-up) and would cap
# throughput far below the 100 records per second target.
_client: Optional[httpx.AsyncClient] = None


@asynccontextmanager
async def lifespan(_app):
    global _client
    _client = httpx.AsyncClient(
        base_url=CONNECTOR, timeout=30,
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=50))
    yield
    await _client.aclose()


app = FastAPI(title="Trust ledger service interface", version="1.0", lifespan=lifespan)


# ---------------------------------------------------------------- security

def require_key(x_api_key: str = Header(default="")) -> None:
    """Every endpoint except /health needs the shared API key."""
    if not API_KEY:
        raise HTTPException(status_code=503, detail="server has no BRIDGE_API_KEY set")
    if not hmac.compare_digest(x_api_key.encode(), API_KEY.encode()):
        raise HTTPException(status_code=401, detail="unauthorised")


def check_ipv4(value: str) -> str:
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        raise ValueError("must be a valid IPv4 address such as 192.168.10.44")
    if str(ip) != value:
        raise ValueError("must be written in canonical form, without leading zeros")
    return value


def check_id(device_id: str) -> str:
    if not re.fullmatch(DEVICE_ID[1:-1], device_id):
        raise HTTPException(status_code=400, detail="invalid device id")
    return device_id


# ---------------------------------------------------------------- models

class DeviceRegistration(BaseModel):
    device_id: str = Field(pattern=DEVICE_ID)
    device_type: str
    criticality: int = Field(ge=1, le=5)
    network_address: str
    identity_hash: Optional[str] = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @field_validator("device_type")
    @classmethod
    def _type(cls, v):
        if v not in DEVICE_TYPES:
            raise ValueError(f"device_type must be one of {sorted(DEVICE_TYPES)}")
        return v

    @field_validator("network_address")
    @classmethod
    def _ip(cls, v):
        return check_ipv4(v)


class TrustUpdate(BaseModel):
    device_id: str = Field(pattern=DEVICE_ID)
    trust_value: float = Field(ge=0, le=100)
    threshold: float = Field(ge=0, le=100)
    reason_code: str
    attack_class: str = Field(default="", max_length=64, pattern=r"^[A-Za-z0-9_.:-]*$")
    confidence: float = Field(default=0.0, ge=0, le=1)
    evidence: str = Field(default="", max_length=8192)

    @field_validator("reason_code")
    @classmethod
    def _reason(cls, v):
        if v not in REASON_CODES:
            raise ValueError(f"reason_code must be one of {sorted(REASON_CODES)}")
        return v


class AddressChange(BaseModel):
    network_address: str

    @field_validator("network_address")
    @classmethod
    def _ip(cls, v):
        return check_ipv4(v)


# ---------------------------------------------------------------- connector calls

async def _call(method: str, path: str, json_body: Optional[dict] = None):
    try:
        r = await _client.request(method, path, json=json_body)
    except httpx.HTTPError:
        raise HTTPException(status_code=503, detail="ledger connector is not reachable")
    if r.status_code == 200:
        return r.json()
    try:
        msg = r.json().get("error", "ledger request failed")
    except ValueError:
        msg = "ledger request failed"
    # contract validation messages are safe to pass back; anything else is generic
    code = r.status_code if r.status_code in (400, 404) else 502
    raise HTTPException(status_code=code, detail=msg)


# ---------------------------------------------------------------- endpoints

@app.get("/health")
async def health():
    try:
        r = await _client.get("/health", timeout=5)
        return {"bridge": "ok", "connector": r.json()}
    except httpx.HTTPError:
        return {"bridge": "ok", "connector": "unreachable"}


@app.post("/v1/devices", dependencies=[Depends(require_key)])
async def register_device(body: DeviceRegistration):
    """Register a device. In production the identity hash is the SHA-256 of the
    device certificate; for simulated devices it is derived from the ID."""
    identity = body.identity_hash or hashlib.sha256(f"sim-cert:{body.device_id}".encode()).hexdigest()
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
    return await _call("POST", "/tx/trust", {
        "deviceId": body.device_id,
        "trustValue": body.trust_value,
        "threshold": body.threshold,
        "attackClass": body.attack_class,
        "reasonCode": body.reason_code,
        "evidence": body.evidence,
        "confidence": body.confidence,
    })


@app.get("/v1/devices/by-address/{address}", dependencies=[Depends(require_key)])
async def device_by_address(address: str):
    """Called by Member 4: send an IP address, receive the device type."""
    try:
        check_ipv4(address)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return await _call("GET", f"/query/by-address/{address}")


@app.put("/v1/devices/{device_id}/address", dependencies=[Depends(require_key)])
async def change_address(device_id: str, body: AddressChange):
    check_id(device_id)
    return await _call("POST", "/tx/address", {"deviceId": device_id, "newAddress": body.network_address})


@app.get("/v1/devices/{device_id}", dependencies=[Depends(require_key)])
async def get_device(device_id: str):
    check_id(device_id)
    return await _call("GET", f"/query/device/{device_id}")


@app.get("/v1/devices/{device_id}/history", dependencies=[Depends(require_key)])
async def device_history(device_id: str):
    check_id(device_id)
    return await _call("GET", f"/query/history/{device_id}")


@app.get("/v1/devices/{device_id}/events", dependencies=[Depends(require_key)])
async def device_events(device_id: str):
    check_id(device_id)
    return await _call("GET", f"/query/events/{device_id}")
