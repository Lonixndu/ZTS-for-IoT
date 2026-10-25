from datetime import datetime, timezone
import json

from tests.api_support import TestClient, create_app
import httpx
import pytest

from blockchain_client import (BlockchainClient, BlockchainConfig, BridgeError, LedgerDevice,
                               evidence_hash, make_trust_update, normalize_criticality)
from blockchain_outbox import BlockchainOutbox
from config import EngineConfig, Weights
from device_state import Observation
from engine import TrustEngine


def decision(risk=0.1):
    engine = TrustEngine()
    engine.register_device("dev-001", 0.75)
    return engine.evaluate(Observation("dev-001", risk, datetime(2026, 10, 17, tzinfo=timezone.utc),
                                      "test:evidence", attack_class="Test.Attack", confidence=0.8)).to_dict()


def signal(step=1, **changes):
    return {"deviceId": "dev-001", "BehaviorRisk": 0.1, "evidenceRef": f"test:{step}",
            "timestamp": f"2026-10-17T00:00:{step:02d}Z", **changes}


class StubBridge:
    """Test double only; no Fabric execution is claimed by these tests."""
    def __init__(self):
        self.record = {"deviceId": "dev-001", "deviceType": "camera", "criticality": 4,
                       "networkAddress": "192.168.10.1", "trustValue": 100.0,
                       "threshold": 70.0, "status": "ACTIVE"}
        self.payloads = []
        self.failure = None
        self.confirmation = None

    def get_device(self, device_id):
        if device_id != self.record["deviceId"]:
            raise BridgeError("not registered", status_code=404)
        return LedgerDevice.model_validate(self.record)

    def submit(self, payload):
        self.payloads.append(payload)
        if self.failure:
            raise self.failure
        self.record.update(trustValue=payload["trust_value"], threshold=payload["threshold"],
                           status="SUSPECT" if payload["trust_value"] < payload["threshold"] else "ACTIVE")
        return f"tx-{len(self.payloads)}"

    def find_commit(self, payload):
        return self.confirmation

    def close(self):
        pass


@pytest.fixture
def integrated(tmp_path):
    bridge = StubBridge()
    cfg = BlockchainConfig(api_key="test-only-key", outbox_path=str(tmp_path / "audit.sqlite3"))
    app = create_app(log_path=None, blockchain_config=cfg, bridge_client=bridge)
    with TestClient(app) as client:
        response = client.post("/devices/import", json={"deviceId": "dev-001"})
        assert response.status_code == 201
        assert response.json()["criticality"] == 0.75
        yield client, bridge, app, cfg


@pytest.mark.parametrize("level,expected", [(1, 0), (2, 0.25), (3, 0.5), (4, 0.75), (5, 1)])
def test_criticality_conversion(level, expected):
    assert normalize_criticality(level) == expected


@pytest.mark.parametrize("level", [0, 6, 2.5, True, "4"])
def test_invalid_criticality(level):
    with pytest.raises(ValueError):
        normalize_criticality(level)


def test_wire_contract_and_original_evidence():
    original = decision()
    payload = make_trust_update(original)
    assert payload["trust_value"] == 90
    assert payload["threshold"] == 56
    assert payload["reason_code"] == "MANUAL"
    assert payload["attack_class"] == "Test.Attack"
    assert payload["confidence"] == 0.8
    assert set(payload) == {"device_id", "trust_value", "threshold", "reason_code",
                            "attack_class", "confidence", "evidence"}
    assert json.loads(payload["evidence"])["engineDecision"] == original


@pytest.mark.parametrize("trust,threshold,action", [
    (0.549999, 0.55, "quarantine"), (0.55, 0.55, "allow"),
    (0.550001, 0.55, "allow"), (1.0, 0.7, "quarantine"),
    (0.0, 0.0, "quarantine"), (0.1234499, 0.12345, "quarantine"),
])
def test_rounding_and_latching_preserve_enforcement(trust, threshold, action):
    row = decision()
    row.update(trustValue=trust, threshold=threshold, action=action)
    payload = make_trust_update(row)
    assert (payload["trust_value"] < payload["threshold"]) == (action == "quarantine")
    assert json.loads(payload["evidence"])["engineDecision"]["trustValue"] == trust


def test_client_authentication_and_commit_receipt():
    seen = []
    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"status": "committed", "txId": "real-shaped-receipt"})
    client = BlockchainClient(BlockchainConfig(api_key="test-only-key"), transport=httpx.MockTransport(handler))
    try:
        assert client.submit(make_trust_update(decision())) == "real-shaped-receipt"
        assert seen[0].url.path == "/v1/trust"
        assert seen[0].headers["x-api-key"] == "test-only-key"
    finally:
        client.close()


@pytest.mark.parametrize("code,uncertain", [(401, False), (422, False), (400, False), (503, True), (502, True)])
def test_rejections_differ_from_unknown_commits(code, uncertain):
    def handler(_request):
        return httpx.Response(code, text="sensitive upstream body must not be echoed")
    client = BlockchainClient(BlockchainConfig(api_key="test-only-key"), transport=httpx.MockTransport(handler))
    with pytest.raises(BridgeError) as err:
        client.submit(make_trust_update(decision()))
    assert err.value.uncertain == uncertain
    assert "sensitive" not in str(err.value)
    client.close()


def test_invalid_commit_receipt_is_uncertain():
    client = BlockchainClient(BlockchainConfig(api_key="test-only-key"),
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"ok": True})))
    with pytest.raises(BridgeError) as err:
        client.submit(make_trust_update(decision()))
    assert err.value.uncertain
    client.close()


def test_evidence_hash_reconciles_a_committed_event():
    payload = make_trust_update(decision())
    event = {"deviceId": "dev-001", "eventId": "tx-found", "evidenceHash": evidence_hash(payload),
             "newValue": payload["trust_value"]}
    client = BlockchainClient(BlockchainConfig(api_key="test-only-key"),
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json=[event])))
    assert client.find_commit(payload) == "tx-found"
    client.close()


def test_import_and_live_quarantine_projection(integrated):
    client, bridge, app, _ = integrated
    assert client.post("/devices", json={"deviceId": "dev-002"}).status_code == 409
    assert client.post("/devices/import", json={"deviceId": "bad_id"}).status_code == 422
    first = client.post("/evaluate", json=signal(1, attackClass="BENIGN", confidence=0.9)).json()
    assert first["blockchain"]["status"] == "committed"
    assert first["attackClass"] == "BENIGN"
    assert bridge.record["status"] == "ACTIVE"
    assert client.post("/evaluate", json=signal(2, BehaviorRisk=0.95)).json()["action"] == "quarantine"
    recovery = client.post("/evaluate", json=signal(3, BehaviorRisk=0.0)).json()
    assert recovery["trustValue"] == 1
    assert recovery["reasonCode"] == "QUARANTINE_LATCHED"
    assert recovery["blockchain"]["ledgerTrustValue"] < recovery["blockchain"]["ledgerThreshold"]
    assert bridge.record["status"] == "SUSPECT"
    assert len(app.state.engine.history("dev-001")) == 3


def test_failed_delivery_blocks_new_observations_then_retries_saved_record(integrated):
    client, bridge, app, _ = integrated
    bridge.failure = BridgeError("could not connect")
    result = client.post("/evaluate", json=signal()).json()
    assert result["blockchain"]["status"] == "failed"
    assert client.post("/evaluate", json=signal(2)).status_code == 409
    assert len(app.state.engine.history("dev-001")) == 1
    bridge.failure = None
    retried = client.post("/blockchain/retry/dev-001", json={}).json()
    assert retried["status"] == "committed"
    assert bridge.payloads[0] == bridge.payloads[1]
    assert len(app.state.engine.history("dev-001")) == 1
    assert client.post("/evaluate", json=signal(2)).status_code == 200


def test_unknown_commit_is_not_blindly_retried(integrated):
    client, bridge, _, _ = integrated
    bridge.failure = BridgeError("response timed out", uncertain=True)
    assert client.post("/evaluate", json=signal()).json()["blockchain"]["status"] == "uncertain"
    assert client.post("/blockchain/retry/dev-001", json={}).status_code == 409
    assert len(bridge.payloads) == 1
    bridge.confirmation = "tx-discovered"
    result = client.post("/blockchain/retry/dev-001", json={}).json()
    assert result["status"] == "committed"
    assert result["txId"] == "tx-discovered"
    assert len(bridge.payloads) == 1


def test_deliberate_retry_of_unknown_commit(integrated):
    client, bridge, _, _ = integrated
    bridge.failure = BridgeError("timed out", uncertain=True)
    client.post("/evaluate", json=signal())
    bridge.failure = None
    result = client.post("/blockchain/retry/dev-001", json={"confirmUncertainRetry": True}).json()
    assert result["status"] == "committed"
    assert len(bridge.payloads) == 2


def test_audit_failure_does_not_advance_engine(integrated, monkeypatch):
    client, bridge, app, _ = integrated
    def broken(_row, **_kwargs):
        raise OSError("disk unavailable")
    monkeypatch.setattr(app.state.outbox, "append", broken)
    assert client.post("/evaluate", json=signal()).status_code == 503
    assert app.state.engine.history("dev-001") == []
    assert bridge.payloads == []


def test_restart_preserves_pending_latch_and_replay_boundary(tmp_path):
    bridge = StubBridge()
    cfg = BlockchainConfig(api_key="test-only-key", outbox_path=str(tmp_path / "restart.sqlite3"))
    with TestClient(create_app(blockchain_config=cfg, bridge_client=bridge)) as client:
        client.post("/devices/import", json={"deviceId": "dev-001"})
        bridge.failure = BridgeError("no connection")
        client.post("/evaluate", json=signal(1, BehaviorRisk=0.95))
    # Restored automatically: no second import or lost adaptive history.
    restarted = create_app(blockchain_config=cfg, bridge_client=bridge)
    with TestClient(restarted) as second:
        assert restarted.state.engine.get_state("dev-001").quarantined
        assert second.post("/devices/import", json={"deviceId": "dev-001"}).status_code == 409
        assert second.post("/evaluate", json=signal(2)).status_code == 409
        bridge.failure = None
        assert second.post("/blockchain/retry/dev-001", json={}).json()["status"] == "committed"
        assert second.post("/evaluate", json=signal(1)).status_code == 409
        assert second.post("/evaluate", json=signal(2, BehaviorRisk=0.0)).json()["action"] == "quarantine"


def test_import_existing_suspect_stays_quarantined(tmp_path):
    bridge = StubBridge()
    bridge.record.update(status="SUSPECT", trustValue=20)
    cfg = BlockchainConfig(api_key="test-only-key", outbox_path=str(tmp_path / "outbox.sqlite3"))
    with TestClient(create_app(blockchain_config=cfg, bridge_client=bridge)) as client:
        assert client.post("/devices/import", json={"deviceId": "dev-001"}).json()["quarantined"]
        result = client.post("/evaluate", json=signal(BehaviorRisk=0)).json()
        assert result["action"] == "quarantine"
        assert bridge.record["status"] == "SUSPECT"


@pytest.mark.parametrize("label", ["bad label", "A" * 65, "bad/label"])
def test_invalid_ai_label_is_rejected_before_evaluation(integrated, label):
    client, bridge, app, _ = integrated
    assert client.post("/evaluate", json=signal(attackClass=label)).status_code == 422
    assert app.state.engine.history("dev-001") == []
    assert not bridge.payloads


def test_default_mode_needs_no_bridge_key(monkeypatch):
    monkeypatch.delenv("BLOCKCHAIN_ENABLED", raising=False)
    monkeypatch.delenv("BLOCKCHAIN_API_KEY", raising=False)
    assert BlockchainConfig.from_environment() is None
    monkeypatch.setenv("BLOCKCHAIN_ENABLED", "true")
    with pytest.raises(ValueError, match="BLOCKCHAIN_API_KEY"):
        BlockchainConfig.from_environment()


def test_key_is_not_in_config_repr():
    assert "secret-test-value" not in repr(BlockchainConfig(api_key="secret-test-value"))
