"""Adapter for the supplied blockchain/bridge/main.py contract."""
from dataclasses import dataclass, field
from decimal import Decimal, ROUND_HALF_UP
import hashlib
import json
import math
import os
from typing import Annotated, Literal
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator
from device_state import ATTACK_CLASS_PATTERN

BRIDGE_ID_PATTERN = r"^[A-Za-z0-9-]{3,64}$"
BridgeId = Annotated[str, Field(pattern=BRIDGE_ID_PATTERN)]
REASON_MAP = {
    "TRUST_ACCEPTED": "MANUAL",
    "NEAR_BOUNDARY_MONITOR": "AI_ANOMALY",
    "BELOW_THRESHOLD": "AI_ANOMALY",
    "MISSING_BEHAVIOR_RISK": "POLICY_VIOLATION",
    "QUARANTINE_LATCHED": "POLICY_VIOLATION",
}


class LedgerDevice(BaseModel):
    model_config = ConfigDict(extra="ignore", allow_inf_nan=False)
    deviceId: BridgeId
    deviceType: Literal["camera", "sensor", "actuator", "gateway", "meter", "lock"]
    criticality: int = Field(ge=1, le=5, strict=True)
    networkAddress: IPvAnyAddress
    trustValue: float = Field(ge=0, le=100, strict=True)
    threshold: float = Field(ge=0, le=100, strict=True)
    status: Literal["ACTIVE", "SUSPECT"]

    @field_validator("networkAddress")
    @classmethod
    def ipv4_only(cls, value):
        if value.version != 4:
            raise ValueError("the supplied ledger supports IPv4 only")
        return value


class TrustUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    device_id: BridgeId
    trust_value: float = Field(ge=0, le=100, strict=True)
    threshold: float = Field(ge=0, le=100, strict=True)
    reason_code: Literal["AI_ANOMALY", "POLICY_VIOLATION", "RECOVERY", "MANUAL"]
    attack_class: str = Field(default="", pattern=ATTACK_CLASS_PATTERN, max_length=64)
    confidence: float = Field(default=0, ge=0, le=1, strict=True)
    evidence: str = Field(max_length=8192)

    @field_validator("evidence")
    @classmethod
    def evidence_byte_limit(cls, value):
        # The Python bridge checks characters; its Go contract checks bytes.
        if len(value.encode("utf-8")) > 8192:
            raise ValueError("evidence exceeds the chaincode's 8192-byte limit")
        return value


def normalize_criticality(level: int) -> float:
    if type(level) is not int or not 1 <= level <= 5:
        raise ValueError("ledger criticality must be an integer from 1 to 5")
    return (level - 1) / 4


def make_trust_update(decision: dict) -> dict:
    """Preserve the engine action after the chaincode's two-decimal rounding.

    The chaincode has no action/latch argument. Export effective trust below the
    threshold when a latched decision would otherwise reactivate the device.
    Retain the original score and exact reason in the evidence and local audit.
    """
    def percent(value):
        return (Decimal(str(value)) * 100).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    trust, threshold = percent(decision["trustValue"]), percent(decision["threshold"])
    adjusted = False
    if decision["action"] == "quarantine" and trust >= threshold:
        threshold = max(threshold, Decimal("0.01"))
        trust = threshold - Decimal("0.01")
        adjusted = True
    elif decision["action"] not in ("allow", "quarantine"):
        raise ValueError("unknown engine action")
    if (trust < threshold) != (decision["action"] == "quarantine"):
        raise ValueError("decision cannot be represented by the ledger policy")
    evidence = json.dumps({
        "format": "trust-engine-evidence-v1",
        "engineDecision": decision,
        "ledgerProjection": {
            "trustValue": float(trust), "threshold": float(threshold),
            "scale": "0-100", "policyAdjusted": adjusted,
        },
    }, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return TrustUpdate(
        device_id=decision["deviceId"], trust_value=float(trust), threshold=float(threshold),
        reason_code=REASON_MAP[decision["reasonCode"]],
        attack_class=decision.get("attackClass") or "",
        confidence=decision.get("confidence") if decision.get("confidence") is not None else 0.0,
        evidence=evidence,
    ).model_dump()


def evidence_hash(payload: dict) -> str:
    return hashlib.sha256(payload["evidence"].encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class BlockchainConfig:
    url: str = "http://127.0.0.1:8000"
    api_key: str = field(default="", repr=False)
    timeout_seconds: float = 40.0
    outbox_path: str = "results/blockchain_outbox.sqlite3"

    def __post_init__(self):
        parsed = urlsplit(self.url)
        if (parsed.scheme not in ("http", "https") or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path not in ("", "/")):
            raise ValueError("BLOCKCHAIN_URL must be an HTTP(S) origin without credentials or a path")
        if not self.api_key.strip():
            raise ValueError("BLOCKCHAIN_API_KEY is required in blockchain mode")
        if not math.isfinite(self.timeout_seconds) or self.timeout_seconds <= 0:
            raise ValueError("BLOCKCHAIN_TIMEOUT_SECONDS must be positive and finite")
        if not self.outbox_path.strip() or self.outbox_path == ":memory:":
            raise ValueError("BLOCKCHAIN_OUTBOX must name a persistent SQLite file")

    @classmethod
    def from_environment(cls):
        enabled = os.getenv("BLOCKCHAIN_ENABLED", "false").lower()
        if enabled in ("false", "0", "no"):
            return None
        if enabled not in ("true", "1", "yes"):
            raise ValueError("BLOCKCHAIN_ENABLED must be true or false")
        return cls(
            url=os.getenv("BLOCKCHAIN_URL", "http://127.0.0.1:8000"),
            api_key=os.getenv("BLOCKCHAIN_API_KEY", ""),
            timeout_seconds=float(os.getenv("BLOCKCHAIN_TIMEOUT_SECONDS", "40")),
            outbox_path=os.getenv("BLOCKCHAIN_OUTBOX", "results/blockchain_outbox.sqlite3"),
        )


class BridgeError(RuntimeError):
    def __init__(self, message, *, uncertain=False, status_code=None):
        super().__init__(message)
        self.uncertain = uncertain
        self.status_code = status_code


class BlockchainClient:
    def __init__(self, config: BlockchainConfig, *, transport=None):
        self._http = httpx.Client(
            base_url=config.url.rstrip("/"), timeout=config.timeout_seconds,
            headers={"x-api-key": config.api_key}, transport=transport,
            trust_env=False, follow_redirects=False,
        )

    def close(self):
        self._http.close()

    def _request(self, method, path, payload=None):
        writing = method == "POST"
        try:
            response = self._http.request(method, path, json=payload)
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout) as exc:
            raise BridgeError("could not connect to the blockchain bridge") from exc
        except httpx.HTTPError as exc:
            raise BridgeError("bridge response unavailable; check ledger events before retrying",
                              uncertain=writing) from exc
        if response.status_code != 200:
            known_rejection = response.status_code in (400, 401, 403, 404, 405, 422, 429)
            raise BridgeError(f"blockchain bridge returned HTTP {response.status_code}",
                              uncertain=writing and not known_rejection,
                              status_code=response.status_code)
        try:
            return response.json()
        except ValueError as exc:
            raise BridgeError("bridge returned invalid JSON", uncertain=writing) from exc

    def get_device(self, device_id: str) -> LedgerDevice:
        # Validate identifiers before putting them into a URL path.
        from pydantic import TypeAdapter
        TypeAdapter(BridgeId).validate_python(device_id)
        raw = self._request("GET", f"/v1/devices/{device_id}")
        try:
            device = LedgerDevice.model_validate(raw)
            if device.deviceId != device_id:
                raise ValueError("device id mismatch")
            return device
        except ValueError as exc:
            raise BridgeError("bridge returned an invalid device record") from exc

    def submit(self, payload: dict) -> str:
        payload = TrustUpdate.model_validate(payload).model_dump()
        result = self._request("POST", "/v1/trust", payload)
        if (not isinstance(result, dict) or result.get("status") != "committed"
                or not isinstance(result.get("txId"), str) or not result["txId"].strip()):
            raise BridgeError("bridge did not return a valid commit receipt", uncertain=True)
        return result["txId"]

    def find_commit(self, payload: dict) -> str | None:
        payload = TrustUpdate.model_validate(payload).model_dump()
        events = self._request("GET", f"/v1/devices/{payload['device_id']}/events")
        if not isinstance(events, list):
            raise BridgeError("bridge returned invalid trust events")
        fingerprint = evidence_hash(payload)
        matches = [e for e in events if isinstance(e, dict)
                   and e.get("deviceId") == payload["device_id"]
                   and e.get("evidenceHash") == fingerprint
                   and e.get("newValue") == payload["trust_value"]
                   and isinstance(e.get("eventId"), str) and e["eventId"]]
        if len(matches) > 1:
            raise BridgeError("multiple matching ledger events; review duplicate submissions")
        return matches[0]["eventId"] if matches else None
