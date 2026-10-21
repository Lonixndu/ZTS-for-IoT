"""Authenticated trust API: Member 2 -> persistent engine -> Member 3 bridge."""
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
import sqlite3
from threading import RLock

from fastapi import FastAPI, HTTPException, Query
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from api_boundary import BoundaryMiddleware
from behavior_events import BehaviorEvent
from blockchain_client import BlockchainClient, BlockchainConfig, BridgeError, normalize_criticality
from blockchain_outbox import BlockchainOutbox, UncertainDelivery
from config import EngineConfig, VERSION
from device_state import Observation
from engine import DeviceNotFound, StaleObservation, TrustEngine
from event_store import EventStore, WriterLease, fingerprint
from schemas import DeviceImport, DeviceRegistration, RetryDelivery, RiskRequest, TrustDecision
from service_config import ServiceConfig


def create_app(config: EngineConfig | None = None, *, service_config: ServiceConfig | None = None,
               blockchain_config: BlockchainConfig | None = None, bridge_client=None, clock=None):
    config = config or EngineConfig()
    service = service_config or ServiceConfig.from_environment()
    now_utc = clock or (lambda: datetime.now(timezone.utc))
    bridge = bridge_client or (BlockchainClient(blockchain_config) if blockchain_config else None)
    if bridge is not None and blockchain_config is None:
        raise ValueError("a bridge client requires blockchain_config")
    path = blockchain_config.outbox_path if blockchain_config else service.state_path
    outbox = BlockchainOutbox(path) if blockchain_config else None
    journal = EventStore(path, config, outbox)
    operations = RLock()
    lease = WriterLease(path)
    engine = None

    @asynccontextmanager
    async def lifespan(app):
        nonlocal engine
        lease.acquire()
        try:
            engine = journal.restore()
            app.state.engine = engine
            yield
        finally:
            if bridge is not None:
                bridge.close()
            lease.release()

    app = FastAPI(title="J26-CS-315 Adaptive Trust Engine", version=VERSION, lifespan=lifespan)
    app.add_middleware(BoundaryMiddleware, config=service)
    app.state.outbox, app.state.journal, app.state.service_config = outbox, journal, service

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, exc):
        errors = exc.errors()
        detail = [{"loc": list(e["loc"]), "msg": e["msg"], "type": e["type"]} for e in errors]
        # Keep schema/device/version errors at 422; malformed numbers/JSON at 400.
        scores = {"attack_probability", "classification_confidence", "anomaly_score", "temporal_risk", "behavior_risk"}
        bad_score = any(any(part in scores for part in e["loc"] if isinstance(part, str)) for e in errors)
        status = 400 if request.url.path == "/v1/behavior-events" and bad_score else 422
        return JSONResponse(status_code=status, content={"detail": detail})

    @app.exception_handler(sqlite3.Error)
    async def storage_error(_request, _exc):
        return JSONResponse(status_code=503, content={"detail":
            "audit storage unavailable; retry the same event_id and check blockchain delivery status"})

    def require_bridge():
        if bridge is None:
            raise HTTPException(503, "blockchain mode is disabled")

    def register_seed(seed, metadata):
        if journal.registration(seed["device_id"]):
            raise HTTPException(409, "device already registered or restored")
        with journal.connect() as db:
            count = db.execute("SELECT COUNT(*) FROM registrations").fetchone()[0]
        if count >= config.max_devices:
            raise HTTPException(503, "device capacity reached")
        # Validate using the exact engine code before making the registration durable.
        TrustEngine(config=config).register_device(**seed)
        journal.register(seed, metadata)
        return engine.register_device(**seed)

    def receipt_for(decision):
        if not outbox:
            return None
        return outbox.receipt(outbox.for_decision(decision["deviceId"], decision["timestamp"]))

    def event_response(saved, *, duplicate):
        body = json.loads(saved["response_json"])
        body["duplicate"] = duplicate
        if body["accepted"]:
            body["blockchain"] = receipt_for(body["decision"])
        return JSONResponse(status_code=saved["http_status"], content=body)

    @app.get("/health")
    def health():
        return {"status": "ok" if service.service_token and service.admin_token else "credentials_missing",
                "version": VERSION, "mode": "adaptive", "storage": "sqlite-replayable",
                "blockchainEnabled": bridge is not None, "auditStorage": "sqlite",
                "bridgeConnectivity": "not-probed", "legacyEvaluateEnabled": service.enable_legacy_evaluate,
                "freshnessSeconds": service.freshness_seconds, "futureSkewSeconds": service.future_skew_seconds}

    @app.post("/devices", status_code=201)
    def register(payload: DeviceRegistration):
        if bridge is not None:
            raise HTTPException(409, "use /devices/import to load criticality from the blockchain")
        with operations:
            return register_seed({"device_id": payload.deviceId, "criticality": payload.criticality}, {"source": "local"})

    @app.post("/devices/import", status_code=201)
    def import_device(payload: DeviceImport):
        require_bridge()
        with operations:
            if journal.registration(payload.deviceId):
                raise HTTPException(409, "device already imported or restored")
            try:
                device = bridge.get_device(payload.deviceId)
                if outbox.latest(payload.deviceId):
                    raise HTTPException(409, "legacy outbox found without a registry; preserve it and use a new database")
                quarantined = device.status == "SUSPECT"
                metadata = {"source": "blockchain", "ledgerCriticality": device.criticality,
                            "deviceType": device.deviceType, "networkAddress": str(device.networkAddress)}
                result = register_seed({
                    "device_id": device.deviceId, "criticality": normalize_criticality(device.criticality),
                    "quarantined": quarantined, "initial_threshold": device.threshold / 100 if quarantined else None,
                    "initial_trust": device.trustValue / 100,
                }, metadata)
                return {**result, **metadata, "quarantined": quarantined, "resumedFromAudit": False}
            except BridgeError as exc:
                raise HTTPException(404 if exc.status_code == 404 else 502, str(exc)) from exc

    @app.post("/v1/behavior-events", status_code=202)
    def behavior_event(payload: BehaviorEvent):
        event = payload.model_dump(mode="json")
        with operations:
            saved = journal.lookup(payload.event_id)
            now = now_utc()
            if saved:
                if saved["fingerprint"] != fingerprint(event):
                    result = journal.reject(event, "event_id_content_conflict", now, 409, save_receipt=False)
                    return JSONResponse(status_code=409, content=result)
                return event_response(saved, duplicate=True)

            def reject(code, reason, *, permanent=True):
                result = journal.reject(event, reason, now, code, save_receipt=permanent)
                return JSONResponse(status_code=code, content=result,
                                    headers={"Retry-After": "2"} if code == 503 else None)

            try:
                state = engine.get_state(payload.device_id)
            except DeviceNotFound:
                return reject(422, "device_not_registered")
            age = (now - payload.observed_at).total_seconds()
            if age < -service.future_skew_seconds:
                return reject(422, "event_in_future")
            if age > service.freshness_seconds:
                return reject(422, "stale_event")
            if state.last_timestamp is not None and payload.observed_at <= state.last_timestamp:
                return reject(409, "out_of_order_event")
            if payload.quality_status == "invalid":
                return reject(422, "invalid_quality")
            if outbox and outbox.pending(payload.device_id):
                return reject(503, "previous_ledger_delivery_pending", permanent=False)
            try:
                journal.evaluate(engine, payload.observation(), event=event, now=now)
                if outbox:
                    outbox.deliver(bridge, payload.device_id)
                return event_response(journal.lookup(payload.event_id), duplicate=False)
            except OSError as exc:
                raise HTTPException(503, "decision audit unavailable; retry the same event_id") from exc

    @app.post("/evaluate", response_model=TrustDecision)
    def evaluate(payload: RiskRequest):
        if not service.enable_legacy_evaluate:
            raise HTTPException(403, "legacy evaluation is disabled; use /v1/behavior-events")
        with operations:
            if outbox and outbox.pending(payload.deviceId):
                raise HTTPException(409, "previous decision awaits ledger delivery; use /blockchain/retry/{device_id}")
            try:
                result = journal.evaluate(engine, Observation(
                    device_id=payload.deviceId, behavior_risk=payload.BehaviorRisk,
                    timestamp=payload.timestamp, evidence_ref=payload.evidenceRef,
                    network_context=payload.networkContext, attack_class=payload.attackClass,
                    confidence=payload.confidence, anomaly_score=payload.anomalyScore,
                ))
                if outbox:
                    result["blockchain"] = outbox.deliver(bridge, payload.deviceId)
                return result
            except DeviceNotFound as exc:
                raise HTTPException(404, "register or import the device first") from exc
            except StaleObservation as exc:
                raise HTTPException(409, str(exc)) from exc
            except OSError as exc:
                raise HTTPException(503, "decision audit unavailable; state not advanced") from exc

    @app.get("/devices/{device_id}/history", response_model=list[TrustDecision])
    def history(device_id: str, limit: int = Query(default=min(100, config.history_limit), ge=1, le=config.history_limit)):
        with operations:
            if journal.registration(device_id) is None:
                raise HTTPException(404, "device not found")
            return journal.history(device_id, limit)

    @app.get("/v1/devices/{device_id}/trust")
    def current_trust(device_id: str):
        with operations:
            try:
                state = engine.get_state(device_id)
            except DeviceNotFound as exc:
                raise HTTPException(404, "device not found") from exc
            rows = journal.history(device_id, 1)
            last = rows[0] if rows else None
            evidence = last.get("behaviorEvent") if last else None
            age = (now_utc() - datetime.fromisoformat(evidence["observed_at"].replace("Z", "+00:00"))).total_seconds() if evidence else None
            fresh = age is not None and -service.future_skew_seconds <= age <= service.freshness_seconds
            status = "fresh" if fresh else "stale" if evidence else "unknown"
            delivery = receipt_for(last) if last else None
            ledger_ready = bridge is None or (delivery is not None and delivery["status"] == "committed")
            effective = "quarantine" if state.quarantined else last["action"] if fresh and ledger_ready else "hold"
            return {"device_id": device_id, "evidence_status": status, "evidence_age_seconds": age,
                    "last_observed_at": evidence["observed_at"] if evidence else None,
                    "last_received_at": journal.lookup(evidence["event_id"])["received_at"] if evidence else None,
                    "current_trust_value": last["trustValue"] if fresh else None,
                    "usable_for_policy": fresh and ledger_ready, "effective_action": effective,
                    "last_decision": last, "blockchain": delivery,
                    "enforcement": "decision_only; downstream must enforce and poll freshness"}

    @app.get("/blockchain/status/{device_id}")
    def delivery_status(device_id: str):
        require_bridge()
        with operations:
            row = outbox.pending(device_id) or outbox.latest(device_id)
            if row is None:
                raise HTTPException(404, "no saved delivery for this device")
            return outbox.receipt(row)

    @app.post("/blockchain/retry/{device_id}")
    def retry_delivery(device_id: str, payload: RetryDelivery):
        require_bridge()
        with operations:
            if outbox.latest(device_id) is None:
                raise HTTPException(404, "no saved delivery for this device")
            try:
                return outbox.deliver(bridge, device_id, confirm_uncertain_retry=payload.confirmUncertainRetry)
            except UncertainDelivery as exc:
                raise HTTPException(409, str(exc)) from exc

    def openapi():
        from fastapi.openapi.utils import get_openapi
        if app.openapi_schema is None:
            schema = get_openapi(title=app.title, version=app.version, routes=app.routes)
            schema.setdefault("components", {})["securitySchemes"] = {
                "AIServiceBearer": {"type": "http", "scheme": "bearer", "description": "TRUST_SERVICE_TOKEN: Member 2 only"},
                "AdminBearer": {"type": "http", "scheme": "bearer", "description": "TRUST_ADMIN_TOKEN: registry, history, status and retries"},
            }
            for path, methods in schema["paths"].items():
                for method, operation in methods.items():
                    if method in ("get", "post", "put", "delete", "patch") and path != "/health":
                        name = "AIServiceBearer" if path == "/v1/behavior-events" else "AdminBearer"
                        operation["security"] = [{name: []}]
            app.openapi_schema = schema
        return app.openapi_schema
    app.openapi = openapi
    return app


def application():
    """Uvicorn factory: loading tests never opens the user's real database."""
    from local_config import load_local_env
    load_local_env()
    return create_app(blockchain_config=BlockchainConfig.from_environment())
