"""Optional contract checks against an unmodified teammate checkout.

Set BLOCKCHAIN_SOURCE_DIR to the folder containing bridge/main.py. These tests
run that real Python app with a connector double; they do NOT execute Go/Fabric.
"""
import asyncio
from decimal import Decimal, ROUND_HALF_UP
import importlib.util
import json
import os
from pathlib import Path

from tests.api_support import TestClient, create_app
import httpx
import pytest

from blockchain_client import BlockchainClient, BlockchainConfig, evidence_hash, make_trust_update


class ConnectorDouble:
    """Exercise actual bridge forwarding while keeping the ledger boundary explicit."""
    def __init__(self):
        self.devices = {}
        self.events = []
        self.requests = []
        self.lose_next_receipt = False

    def __call__(self, request):
        path = request.url.path
        body = json.loads(request.content) if request.method == "POST" else None
        self.requests.append((request.method, path, body))
        if path == "/tx/register":
            assert set(body) == {"deviceId", "deviceType", "criticality", "identityHash", "networkAddress"}
            self.devices[body["deviceId"]] = {**body, "trustValue": 100, "threshold": 70, "status": "ACTIVE"}
            return httpx.Response(200, json={"status": "committed", "txId": "registration-tx"})
        if path == "/tx/trust":
            assert set(body) == {"deviceId", "trustValue", "threshold", "attackClass",
                                 "reasonCode", "evidence", "confidence"}
            assert body["reasonCode"] in {"AI_ANOMALY", "MANUAL", "POLICY_VIOLATION", "RECOVERY"}
            assert len(body["evidence"].encode()) <= 8192
            dev = self.devices[body["deviceId"]]
            # Model the observed chaincode policy; this is not executing it.
            quantize = lambda x: float(Decimal(str(x)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))
            trust, threshold = quantize(body["trustValue"]), quantize(body["threshold"])
            dev.update(trustValue=trust, threshold=threshold,
                       status="SUSPECT" if trust < threshold else "ACTIVE")
            tx_id = f"trust-tx-{len(self.events) + 1}"
            self.events.append({"deviceId": body["deviceId"], "newValue": trust,
                                "eventId": tx_id, "evidenceHash": evidence_hash({"evidence": body["evidence"]})})
            if self.lose_next_receipt:
                self.lose_next_receipt = False
                raise httpx.ReadTimeout("simulated receipt loss", request=request)
            return httpx.Response(200, json={"status": "committed", "txId": tx_id})
        if path.startswith("/query/events/"):
            device_id = path.rsplit("/", 1)[1]
            return httpx.Response(200, json=[e for e in self.events if e["deviceId"] == device_id])
        if path.startswith("/query/device/"):
            device_id = path.rsplit("/", 1)[1]
            if device_id not in self.devices:
                return httpx.Response(404, json={"error": "not registered"})
            return httpx.Response(200, json=self.devices[device_id])
        if path == "/health":
            return httpx.Response(200, json={"status": "ok", "ledger": "test-double"})
        raise AssertionError(f"unexpected connector request: {path}")


@pytest.fixture
def actual_bridge(tmp_path, monkeypatch):
    source = os.getenv("BLOCKCHAIN_SOURCE_DIR")
    if not source:
        pytest.skip("set BLOCKCHAIN_SOURCE_DIR to test the supplied Python bridge")
    path = Path(source) / "bridge" / "main.py"
    assert path.is_file(), "BLOCKCHAIN_SOURCE_DIR must contain bridge/main.py"
    monkeypatch.setenv("BRIDGE_API_KEY", "contract-test-key")
    spec = importlib.util.spec_from_file_location("teammate_bridge_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    connector = ConnectorDouble()
    async_client = httpx.AsyncClient(base_url="http://connector.test", transport=httpx.MockTransport(connector))
    module._client = async_client
    # Intentionally bypass lifespan: it would replace the injected connector.
    bridge_api = TestClient(module.app)

    def to_actual_bridge(request):
        result = bridge_api.request(request.method, str(request.url), content=request.content,
                                    headers=dict(request.headers))
        return httpx.Response(result.status_code, content=result.content, headers=dict(result.headers))

    cfg = BlockchainConfig(url="http://bridge.test", api_key="contract-test-key",
                           outbox_path=str(tmp_path / "audit.sqlite3"))
    client = BlockchainClient(cfg, transport=httpx.MockTransport(to_actual_bridge))
    try:
        registered = bridge_api.post("/v1/devices", headers={"x-api-key": "contract-test-key"}, json={
            "device_id": "dev-001", "device_type": "camera", "criticality": 4,
            "network_address": "192.168.10.1"})
        assert registered.status_code == 200
        yield bridge_api, client, connector, cfg
    finally:
        client.close()
        bridge_api.close()
        asyncio.run(async_client.aclose())


def signal(step, risk):
    return {"deviceId": "dev-001", "BehaviorRisk": risk, "evidenceRef": f"contract-test:{step}",
            "timestamp": f"2026-10-17T01:00:{step:02d}Z", "attackClass": "SIMULATED", "confidence": 0.9}


def test_round_trip_through_supplied_bridge(actual_bridge):
    _, bridge, connector, cfg = actual_bridge
    with TestClient(create_app(blockchain_config=cfg, bridge_client=bridge)) as api:
        imported = api.post("/devices/import", json={"deviceId": "dev-001"})
        assert imported.status_code == 201
        assert imported.json()["criticality"] == 0.75
        for step, risk in enumerate((0.1, 0.95, 0.0), start=1):
            result = api.post("/evaluate", json=signal(step, risk))
            assert result.status_code == 200
            row = result.json()
            assert row["blockchain"]["status"] == "committed"
            assert connector.devices["dev-001"]["status"] == ("ACTIVE" if step == 1 else "SUSPECT")
        assert len(connector.events) == 3
        assert row["trustValue"] == 1.0
        assert row["blockchain"]["ledgerTrustValue"] < row["blockchain"]["ledgerThreshold"]
        sent = connector.requests[-1][2]
        assert sent["attackClass"] == "SIMULATED" and sent["confidence"] == 0.9
        assert sent["reasonCode"] == "POLICY_VIOLATION"


def test_uncertain_write_reconciles_through_real_events_endpoint(actual_bridge):
    _, bridge, connector, cfg = actual_bridge
    with TestClient(create_app(blockchain_config=cfg, bridge_client=bridge)) as api:
        api.post("/devices/import", json={"deviceId": "dev-001"})
        connector.lose_next_receipt = True
        response = api.post("/evaluate", json=signal(1, 0.1)).json()
        assert response["blockchain"]["status"] == "uncertain"
        retried = api.post("/blockchain/retry/dev-001", json={})
        assert retried.status_code == 200
        assert retried.json()["status"] == "committed"
        assert len(connector.events) == 1


def test_supplied_auth_and_validation_rules(actual_bridge):
    api, _, _, _ = actual_bridge
    assert api.get("/v1/devices/dev-001").status_code == 401
    base = {"device_id": "dev-001", "trust_value": 80, "threshold": 70, "reason_code": "MANUAL"}
    headers = {"x-api-key": "contract-test-key"}
    assert api.post("/v1/trust", headers=headers, json={**base, "reason_code": "TRUST_ACCEPTED"}).status_code == 422
    assert api.post("/v1/trust", headers=headers, json={**base, "attack_class": "bad label"}).status_code == 422


def test_missing_remote_device_does_not_register_locally(actual_bridge):
    _, bridge, _, cfg = actual_bridge
    app = create_app(blockchain_config=cfg, bridge_client=bridge)
    with TestClient(app) as api:
        assert api.post("/devices/import", json={"deviceId": "dev-999"}).status_code == 404
        assert api.post("/evaluate", json={**signal(1, 0.1), "deviceId": "dev-999"}).status_code == 404


def test_member2_event_round_trip_and_duplicate_through_actual_bridge(actual_bridge):
    from datetime import datetime, timezone
    from tests.api_support import SERVICE_HEADERS
    from tests.test_behavior_events import event
    _, bridge, connector, cfg = actual_bridge
    with TestClient(create_app(blockchain_config=cfg, bridge_client=bridge)) as api:
        assert api.post('/devices/import', json={'deviceId': 'dev-001'}).status_code == 201
        for risk in (0.1, 0.878, 0.01):
            value = event(device_id='dev-001', behavior_risk=risk,
                          prediction='DoS-SYN_Flood' if risk > 0.8 else 'BenignTraffic',
                          observed_at=datetime.now(timezone.utc).isoformat())
            response = api.post('/v1/behavior-events', json=value, headers=SERVICE_HEADERS)
            assert response.status_code == 202, response.text
            body = response.json()
            assert body['blockchain']['status'] == 'committed'
            count = len(connector.events)
            retry = api.post('/v1/behavior-events', json=value, headers=SERVICE_HEADERS)
            assert retry.status_code == 202 and retry.json()['duplicate']
            assert len(connector.events) == count
        assert len(connector.events) == 3
        assert connector.devices['dev-001']['status'] == 'SUSPECT'
        trust_posts = [body for _, path, body in connector.requests if path == '/tx/trust']
        attack = trust_posts[1]
        assert attack['trustValue'] == 12.2
        assert attack['confidence'] == 0.95 and attack['attackClass'] == 'DoS-SYN_Flood'
        evidence = json.loads(attack['evidence'])
        assert evidence['engineDecision']['behaviorEvent']['model_version'] == 'ai-0.3.0'
        assert evidence['engineDecision']['behaviorEvent']['classification_confidence'] == 0.95
        assert connector.events[1]['evidenceHash'] == evidence_hash({'evidence':attack['evidence']})
