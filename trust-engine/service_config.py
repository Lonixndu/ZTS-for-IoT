"""Transport settings, separate from the unchanged research scoring parameters."""
from dataclasses import dataclass, field
import math
import os


@dataclass(frozen=True)
class ServiceConfig:
    service_token: str = field(default="", repr=False)
    admin_token: str = field(default="", repr=False)
    state_path: str = "results/trust_state.sqlite3"
    freshness_seconds: float = 15.0
    future_skew_seconds: float = 2.0
    max_body_bytes: int = 16384
    events_per_minute: int = 6000
    enable_legacy_evaluate: bool = False

    def __post_init__(self):
        for name in ("service_token", "admin_token"):
            value = getattr(self, name)
            if value and (len(value) < 32 or not value.isascii() or any(c.isspace() for c in value)):
                raise ValueError(f"{name} must be at least 32 ASCII characters without whitespace")
        if self.service_token and self.service_token == self.admin_token:
            raise ValueError("use different service and admin tokens")
        if not str(self.state_path).strip() or str(self.state_path) == ":memory:":
            raise ValueError("state_path must be a persistent SQLite file")
        for name in ("freshness_seconds", "future_skew_seconds"):
            value = getattr(self, name)
            if isinstance(value, bool) or not math.isfinite(value) or value < 0:
                raise ValueError(f"{name} must be nonnegative and finite")
        if self.freshness_seconds == 0:
            raise ValueError("freshness_seconds must be positive")
        for name in ("max_body_bytes", "events_per_minute"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 1:
                raise ValueError(f"{name} must be a positive integer")
        if type(self.enable_legacy_evaluate) is not bool:
            raise ValueError("enable_legacy_evaluate must be boolean")

    @classmethod
    def from_environment(cls):
        legacy = os.getenv("TRUST_ENABLE_LEGACY_EVALUATE", "false").lower()
        if legacy not in ("true", "false"):
            raise ValueError("TRUST_ENABLE_LEGACY_EVALUATE must be true or false")
        return cls(
            service_token=os.getenv("TRUST_SERVICE_TOKEN", ""),
            admin_token=os.getenv("TRUST_ADMIN_TOKEN", ""),
            state_path=os.getenv("TRUST_STATE_DB", "results/trust_state.sqlite3"),
            freshness_seconds=float(os.getenv("TRUST_EVENT_TTL_SECONDS", "15")),
            future_skew_seconds=float(os.getenv("TRUST_FUTURE_SKEW_SECONDS", "2")),
            max_body_bytes=int(os.getenv("TRUST_MAX_BODY_BYTES", "16384")),
            events_per_minute=int(os.getenv("TRUST_EVENTS_PER_MINUTE", "6000")),
            enable_legacy_evaluate=legacy == "true",
        )
