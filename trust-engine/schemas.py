"""API contracts for the proposed AI input and blockchain decision output."""
from datetime import datetime, timezone
from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator

from device_state import ATTACK_CLASS_PATTERN
from blockchain_client import BridgeId

UnitFloat = Annotated[float, Field(ge=0.0, le=1.0, strict=True, allow_inf_nan=False)]
DeviceId = BridgeId  # One public identifier convention across all three members.


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class DeviceRegistration(Contract):
    deviceId: DeviceId
    criticality: UnitFloat = 0.5


class RiskRequest(Contract):
    deviceId: DeviceId
    BehaviorRisk: UnitFloat | None  # Explicit null invokes the conservative fallback.
    networkContext: UnitFloat = 0.0
    evidenceRef: str = Field(min_length=1, max_length=200)
    timestamp: AwareDatetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    attackClass: str | None = Field(default=None, pattern=ATTACK_CLASS_PATTERN, max_length=64)
    confidence: UnitFloat | None = None
    anomalyScore: UnitFloat | None = None

    @field_validator("evidenceRef")
    @classmethod
    def evidence_not_blank(cls, value):
        if not value.strip():
            raise ValueError("evidenceRef cannot be blank")
        return value


class DeviceImport(Contract):
    deviceId: BridgeId


class RetryDelivery(Contract):
    confirmUncertainRetry: bool = Field(default=False, strict=True)


class BlockchainReceipt(Contract):
    deliveryId: int
    status: Literal["pending", "committed", "failed", "uncertain"]
    txId: str | None
    error: str | None
    evidenceHash: str
    ledgerTrustValue: float = Field(ge=0, le=100)
    ledgerThreshold: float = Field(ge=0, le=100)
    ledgerReasonCode: str


class TrustDecision(Contract):
    deviceId: str
    mode: Literal["adaptive", "static"]
    timestamp: AwareDatetime
    trustValue: UnitFloat
    threshold: UnitFloat
    action: Literal["allow", "quarantine"]
    reasonCode: str
    evidenceRef: str
    BehaviorRisk: UnitFloat | None
    baselineRisk: UnitFloat
    isProbe: bool
    latencyMs: float = Field(ge=0, allow_inf_nan=False)
    features: dict[str, UnitFloat]
    attackClass: str | None = None
    confidence: UnitFloat | None = None
    anomalyScore: UnitFloat | None = None
    blockchain: BlockchainReceipt | None = None
    behaviorEvent: dict | None = None

