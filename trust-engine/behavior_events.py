"""Member 2 v1 contract: fused risk is an input, never recomputed here."""
from datetime import timedelta
import re
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator, model_validator

from blockchain_client import BridgeId
from device_state import ATTACK_CLASS_PATTERN, Observation
from schemas import Contract, UnitFloat

Nonblank = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^\S(?:.*\S)?$")]


class BehaviorEvent(Contract):
    event_id: UUID
    schema_version: Literal["1.0"]
    device_id: BridgeId
    flow_id: Nonblank
    observed_at: AwareDatetime
    model_version: Nonblank
    prediction: str = Field(min_length=1, max_length=64, pattern=ATTACK_CLASS_PATTERN)
    attack_probability: UnitFloat | None = None
    classification_confidence: UnitFloat | None = None
    anomaly_score: UnitFloat | None = None
    temporal_risk: UnitFloat | None = None
    behavior_risk: UnitFloat | None
    quality_status: Literal["valid", "partial", "invalid"]
    window_seconds: float = Field(gt=0, le=3600, strict=True, allow_inf_nan=False)
    feature_schema_version: Nonblank | None = None
    calibration_version: Nonblank | None = None

    @field_validator("observed_at", mode="before")
    @classmethod
    def utc_iso_string(cls, value):
        if not isinstance(value, str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)", value
        ):
            raise ValueError("observed_at must be an ISO 8601 UTC string ending in Z or +00:00")
        return value

    @field_validator("observed_at")
    @classmethod
    def utc_only(cls, value):
        if value.utcoffset() != timedelta(0):
            raise ValueError("observed_at must be UTC")
        return value

    @field_validator("event_id")
    @classmethod
    def nonzero_uuid(cls, value):
        if value.int == 0:
            raise ValueError("event_id must not be the nil UUID")
        return value

    @model_validator(mode="after")
    def quality_has_risk(self):
        if self.quality_status != "invalid" and self.behavior_risk is None:
            raise ValueError("valid/partial evidence requires a finite behavior_risk")
        return self

    def observation(self):
        return Observation(
            device_id=self.device_id, behavior_risk=self.behavior_risk,
            timestamp=self.observed_at, evidence_ref=f"behavior-event:{self.event_id}",
            network_context=0.0, attack_class=self.prediction,
            confidence=self.classification_confidence, anomaly_score=self.anomaly_score,
        )
