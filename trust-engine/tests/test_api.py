import csv
import json
from pathlib import Path

from tests.api_support import TestClient, create_app
import pytest

from config import EngineConfig


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(log_path=tmp_path / "api.csv")) as client:
        assert client.post("/devices", json={"deviceId": "sensor-1", "criticality": 0.5}).status_code == 201
        yield client


def payload(**changes):
    return {"deviceId": "sensor-1", "BehaviorRisk": 0.1,
            "evidenceRef": "test:1", "timestamp": "2026-10-17T00:00:01Z", **changes}


def test_health_contract_and_history(client):
    assert client.get("/health").json()["status"] == "ok"
    response = client.post("/evaluate", json=payload())
    assert response.status_code == 200
    result = response.json()
    assert result["action"] == "allow"
    assert {"deviceId", "trustValue", "threshold", "reasonCode", "evidenceRef", "timestamp"} <= result.keys()
    history = client.get("/devices/sensor-1/history").json()
    assert len(history) == 1
    assert history[0]["trustValue"] == result["trustValue"]


@pytest.mark.parametrize("risk", [-0.1, 1.1, "0.1", True])
def test_invalid_risk_422(client, risk):
    assert client.post("/evaluate", json=payload(BehaviorRisk=risk)).status_code == 422
    assert client.get("/devices/sensor-1/history").json() == []


def test_nan_rejected(client):
    body = json.dumps(payload()).replace('"BehaviorRisk": 0.1', '"BehaviorRisk": NaN')
    # A 422 response must not fail while serializing the non-finite rejected input.
    response = client.post("/evaluate", content=body, headers={"Content-Type": "application/json"})
    assert response.status_code == 422


def test_missing_field_differs_from_explicit_null(client):
    missing = payload()
    del missing["BehaviorRisk"]
    assert client.post("/evaluate", json=missing).status_code == 422
    response = client.post("/evaluate", json=payload(BehaviorRisk=None))
    assert response.status_code == 200
    assert response.json()["reasonCode"] == "MISSING_BEHAVIOR_RISK"
    assert response.json()["action"] == "quarantine"


@pytest.mark.parametrize("changes", [
    {"criticality": 0.0}, {"groundTruth": "benign"}, {"evidenceRef": "   "},
    {"timestamp": "2026-10-17T00:00:01"}, {"confidence": 2.0},
])
def test_invalid_or_extra_fields_rejected(client, changes):
    assert client.post("/evaluate", json=payload(**changes)).status_code == 422


def test_replay_and_duplicate_registration(client):
    assert client.post("/evaluate", json=payload()).status_code == 200
    assert client.post("/evaluate", json=payload()).status_code == 409
    assert client.post("/devices", json={"deviceId": "sensor-1"}).status_code == 409


def test_unknown_devices_and_invalid_history_limit(client):
    assert client.post("/evaluate", json=payload(deviceId="unknown")).status_code == 404
    assert client.get("/devices/unknown/history").status_code == 404
    assert client.get("/devices/sensor-1/history?limit=0").status_code == 422
    assert client.get("/devices/sensor-1/history?limit=10000").status_code == 422


def test_api_capacity_limit(tmp_path):
    with TestClient(create_app(EngineConfig(max_devices=1), tmp_path / "api.csv")) as client:
        assert client.post("/devices", json={"deviceId": "one"}).status_code == 201
        assert client.post("/devices", json={"deviceId": "two"}).status_code == 503


def test_durable_audit_preserves_input_and_history(tmp_path):
    app = create_app(log_path=tmp_path / "api.csv")
    with TestClient(app) as client:
        client.post("/devices", json={"deviceId": "sensor-1"})
        client.post("/evaluate", json=payload(evidenceRef="=test"))
        client.post("/evaluate", json=payload(timestamp="2026-10-17T00:00:02Z"))
        rows = app.state.journal.history("sensor-1", 100)
        assert len(rows) == 2
        assert rows[0]["evidenceRef"] == "=test"
        assert rows[0]["features"]["criticality"] == 0.5
    # CSV exports still use the supplied formula-escaping logger.
    from decision_logger import DecisionLogger
    log = tmp_path / "export.csv"
    for row in rows:
        DecisionLogger(log).append(row)
    with log.open(newline="") as stream:
        exported = list(csv.DictReader(stream))
    assert exported[0]["evidenceRef"] == "'=test"


def test_failed_log_returns_503_and_preserves_state(tmp_path, monkeypatch):
    app = create_app(log_path=tmp_path / "api.csv")
    with TestClient(app) as client:
        client.post("/devices", json={"deviceId": "sensor-1"})
        def broken(_row):
            raise OSError("disk unavailable")
        monkeypatch.setattr(app.state.journal, "append", broken)
        assert client.post("/evaluate", json=payload()).status_code == 503
        assert client.get("/devices/sensor-1/history").json() == []


def test_bundled_sample_can_be_evaluated(tmp_path):
    data = json.loads((Path(__file__).parents[1] / "data/sample_signals.json").read_text())
    with TestClient(create_app(log_path=tmp_path / "sample.csv")) as client:
        client.post("/devices", json={"deviceId": "sample", "criticality": data["criticality"]})
        for row in data["observations"]:
            assert client.post("/evaluate", json={"deviceId": "sample", **row}).status_code == 200

