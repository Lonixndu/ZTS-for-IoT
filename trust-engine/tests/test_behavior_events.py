"""Member 2 acceptance, security, persistence and failure-path tests."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import sqlite3
from uuid import uuid4

from fastapi.testclient import TestClient
import pytest

from blockchain_client import BlockchainConfig, BridgeError
from config import EngineConfig
from main import create_app
from service_config import ServiceConfig
from tests.api_support import ADMIN_HEADERS, ADMIN_TOKEN, SERVICE_HEADERS, SERVICE_TOKEN
from tests.test_blockchain import StubBridge


NOW = datetime(2026, 10, 19, 5, 0, 0, tzinfo=timezone.utc)


def event(**changes):
    return {
        'event_id': str(uuid4()), 'schema_version': '1.0', 'device_id': 'IOT-001',
        'flow_id': 'flow-0123', 'observed_at': NOW.isoformat(), 'model_version': 'ai-0.3.0',
        'prediction': 'BenignTraffic', 'attack_probability': 0.1,
        'classification_confidence': 0.95, 'anomaly_score': None, 'temporal_risk': None,
        'behavior_risk': 0.1, 'quality_status': 'valid', 'window_seconds': 5, **changes,
    }


def settings(tmp_path, **changes):
    return ServiceConfig(service_token=SERVICE_TOKEN, admin_token=ADMIN_TOKEN,
                         state_path=str(tmp_path / 'state.sqlite3'), **changes)


@pytest.fixture
def running(tmp_path):
    clock = [NOW]
    service = settings(tmp_path)
    app = create_app(service_config=service, clock=lambda: clock[0])
    with TestClient(app, headers=ADMIN_HEADERS) as client:
        assert client.post('/devices', json={'deviceId': 'IOT-001', 'criticality': 0.75}).status_code == 201
        yield client, app, clock, service


def post(client, value):
    return client.post('/v1/behavior-events', json=value, headers=SERVICE_HEADERS)


def test_field_mapping_and_original_algorithm(running):
    client, app, _, _ = running
    value = event(behavior_risk=0.878, prediction='DoS-SYN_Flood', attack_probability=0.92,
                  classification_confidence=0.95, anomaly_score=0.8)
    response = post(client, value)
    assert response.status_code == 202
    result = response.json()['decision']
    assert result['trustValue'] == pytest.approx(0.122)  # NOT the PDF's illustrative 59.66/100
    assert result['threshold'] == pytest.approx(0.64)
    assert result['action'] == 'quarantine'
    assert result['confidence'] == 0.95
    assert result['attackClass'] == 'DoS-SYN_Flood'
    assert result['anomalyScore'] == 0.8
    assert result['features']['network_context'] == 0
    assert result['behaviorEvent']['attack_probability'] == 0.92
    assert result['behaviorEvent']['model_version'] == 'ai-0.3.0'
    assert result['evidenceRef'] == f"behavior-event:{value['event_id']}"
    assert len(app.state.engine.history('IOT-001')) == 1


def test_identical_retry_before_freshness_and_conflicting_id(running):
    client, app, clock, _ = running
    value = event()
    first = post(client, value).json()
    clock[0] += timedelta(seconds=60)
    retry = post(client, value)
    assert retry.status_code == 202 and retry.json()['duplicate']
    assert retry.json()['decision'] == first['decision']
    assert len(app.state.engine.history('IOT-001')) == 1
    conflict = post(client, {**value, 'behavior_risk': 0.9})
    assert conflict.status_code == 409
    assert conflict.json()['reason'] == 'event_id_content_conflict'
    assert len(app.state.engine.history('IOT-001')) == 1
    assert client.get('/v1/devices/IOT-001/trust').json()['evidence_status'] == 'stale'


def test_concurrent_identical_events_count_once(running):
    client, app, _, _ = running
    value = event()
    with ThreadPoolExecutor(max_workers=8) as pool:
        responses = list(pool.map(lambda _: post(client, value), range(8)))
    assert all(r.status_code == 202 for r in responses)
    assert sum(not r.json()['duplicate'] for r in responses) == 1
    assert len(app.state.engine.history('IOT-001')) == 1


@pytest.mark.parametrize('changes,status', [
    ({'behavior_risk': -0.1}, 400), ({'behavior_risk': 1.01}, 400),
    ({'behavior_risk': '0.2'}, 400), ({'behavior_risk': True}, 400),
    ({'attack_probability': 2}, 400), ({'classification_confidence': False}, 400),
    ({'anomaly_score': -1}, 400), ({'temporal_risk': 2}, 400),
    ({'behavior_risk': None}, 422), ({'schema_version': '2.0'}, 422),
    ({'device_id': 'IOT_001'}, 422), ({'device_id': 'ab'}, 422),
    ({'device_id': 'IOT-001\n'}, 422), ({'event_id': 'not-a-uuid'}, 422),
    ({'observed_at': '2026-10-19T05:00:00'}, 422),
    ({'observed_at': '2026-10-19T10:30:00+05:30'}, 422),
    ({'observed_at': 1792386000}, 422), ({'window_seconds': 0}, 422),
    ({'window_seconds': True}, 422), ({'model_version': ' '}, 422),
    ({'prediction': 'invalid label'}, 422), ({'extra_field': 1}, 422),
])
def test_invalid_schema_does_not_change_state(running, changes, status):
    client, app, _, _ = running
    assert post(client, event(**changes)).status_code == status
    assert app.state.engine.history('IOT-001') == []


@pytest.mark.parametrize('bad_number', ['NaN', 'Infinity', '-Infinity', '1e999'])
def test_nonfinite_json(running, bad_number):
    client, app, _, _ = running
    raw = json.dumps(event()).replace('"behavior_risk": 0.1', f'"behavior_risk": {bad_number}')
    response = client.post('/v1/behavior-events', content=raw,
                           headers={**SERVICE_HEADERS, 'Content-Type': 'application/json'})
    assert response.status_code == 400
    assert app.state.engine.history('IOT-001') == []


def test_missing_risk_malformed_json_and_duplicate_keys(running):
    client, _, _, _ = running
    missing = event()
    del missing['behavior_risk']
    assert post(client, missing).status_code == 400
    for raw in ['{', '{"event_id":"a","event_id":"b"}']:
        assert client.post('/v1/behavior-events', content=raw,
            headers={**SERVICE_HEADERS, 'Content-Type': 'application/json'}).status_code == 400


@pytest.mark.parametrize('seconds,code,reason', [
    (-15.001, 422, 'stale_event'), (2.001, 422, 'event_in_future'),
])
def test_freshness_rejections_are_audited(running, seconds, code, reason):
    client, app, _, _ = running
    value = event(observed_at=(NOW + timedelta(seconds=seconds)).isoformat())
    response = post(client, value)
    assert response.status_code == code and response.json()['reason'] == reason
    assert post(client, value).json()['duplicate']
    with app.state.journal.connect() as db:
        assert db.execute('SELECT reason FROM rejections').fetchone()[0] == reason
    assert app.state.engine.history('IOT-001') == []


@pytest.mark.parametrize('seconds', [-15, 2])
def test_inclusive_clock_boundaries(running, seconds):
    client, _, _, _ = running
    assert post(client, event(observed_at=(NOW + timedelta(seconds=seconds)).isoformat())).status_code == 202


def test_out_of_order_unknown_device_and_invalid_quality(running):
    client, app, _, _ = running
    assert post(client, event()).status_code == 202
    assert post(client, event()).json()['reason'] == 'out_of_order_event'
    assert post(client, event(device_id='IOT-999')).status_code == 422
    assert post(client, event(quality_status='invalid', behavior_risk=None,
                             observed_at=(NOW + timedelta(seconds=1)).isoformat())).json()['reason'] == 'invalid_quality'
    assert len(app.state.engine.history('IOT-001')) == 1


def test_partial_optional_metadata_and_model_upgrade(running):
    client, app, clock, _ = running
    assert post(client, event(quality_status='partial')).status_code == 202
    clock[0] += timedelta(seconds=1)
    changed = event(model_version='ai-0.4.0', observed_at=clock[0].isoformat(),
                    feature_schema_version='ciciot-46-v1', calibration_version='cal-2',
                    attack_probability=None, temporal_risk=0.6)
    assert post(client, changed).status_code == 202
    rows = client.get('/devices/IOT-001/history').json()
    assert [r['behaviorEvent']['model_version'] for r in rows] == ['ai-0.3.0', 'ai-0.4.0']
    assert rows[-1]['trustValue'] == 0.9  # No second fusion or implicit confidence multiplier.


def test_evidence_unknown_fresh_stale_and_no_silent_zero(running):
    client, app, clock, _ = running
    initial = client.get('/v1/devices/IOT-001/trust').json()
    assert initial['evidence_status'] == 'unknown' and initial['effective_action'] == 'hold'
    assert initial['current_trust_value'] is None
    post(client, event())
    current = client.get('/v1/devices/IOT-001/trust').json()
    assert current['evidence_status'] == 'fresh' and current['effective_action'] == 'allow'
    clock[0] += timedelta(seconds=16)
    stale = client.get('/v1/devices/IOT-001/trust').json()
    assert stale['evidence_status'] == 'stale' and stale['effective_action'] == 'hold'
    assert not stale['usable_for_policy'] and stale['current_trust_value'] is None
    assert stale['last_decision']['trustValue'] == 0.9
    assert len(app.state.engine.history('IOT-001')) == 1


def test_auth_roles_fail_closed_and_legacy_disabled(running, tmp_path):
    client, _, _, _ = running
    assert client.post('/v1/behavior-events', json=event()).status_code == 401  # Admin is not the AI sender.
    assert client.post('/devices', headers=SERVICE_HEADERS, json={'deviceId': 'IOT-002'}).status_code == 401
    assert client.get('/v1/devices/IOT-001/trust', headers={'Authorization': ''}).status_code == 401
    assert client.get('/health', headers={'Authorization': ''}).status_code == 200
    legacy = {'deviceId': 'IOT-001', 'BehaviorRisk': 0.1, 'evidenceRef': 'test'}
    assert client.post('/evaluate', json=legacy).status_code == 403
    with TestClient(create_app(service_config=ServiceConfig(state_path=str(tmp_path/'missing.sqlite3')))) as unconfigured:
        assert unconfigured.post('/v1/behavior-events', json=event()).status_code == 503
        assert unconfigured.post('/devices', json={'deviceId':'IOT-001'}).status_code == 503


def test_body_size_and_rate_limit(tmp_path):
    app = create_app(service_config=settings(tmp_path, max_body_bytes=2048, events_per_minute=2), clock=lambda: NOW)
    with TestClient(app, headers=ADMIN_HEADERS) as client:
        client.post('/devices', json={'deviceId': 'IOT-001'})
        assert client.post('/v1/behavior-events', headers=SERVICE_HEADERS, content='x'*2049).status_code == 413
        assert post(client, event()).status_code == 202
        response = post(client, event())
        assert response.status_code == 429 and 'Retry-After' in response.headers


def test_restart_preserves_full_adaptive_state_and_dedup(tmp_path):
    service = settings(tmp_path)
    clock = [NOW]
    app = create_app(service_config=service, clock=lambda: clock[0])
    with TestClient(app, headers=ADMIN_HEADERS) as first:
        first.post('/devices', json={'deviceId':'IOT-001', 'criticality':0.75})
        for risk in [0.1]*5 + [0.35, 0.42]:
            value = event(behavior_risk=risk, observed_at=clock[0].isoformat())
            assert post(first, value).status_code == 202
            clock[0] += timedelta(seconds=1)
        before = app.state.engine.get_state('IOT-001')
    second_app = create_app(service_config=service, clock=lambda: clock[0])
    with TestClient(second_app, headers=ADMIN_HEADERS) as second:
        restored = second_app.state.engine.get_state('IOT-001')
        for attribute in ['threshold','history_pressure','probe_streak','previous_trust','quarantined',
                          'violations','near_boundary_events','last_timestamp','baseline_risks']:
            assert getattr(before, attribute) == getattr(restored, attribute)
        assert post(second, value).json()['duplicate']
        assert len(second.get('/devices/IOT-001/history').json()) == 7
        assert post(second, event(observed_at=clock[0].isoformat())).status_code == 202


def test_atomic_rollback_when_outbox_write_fails(tmp_path, monkeypatch):
    bridge = StubBridge()
    cfg = BlockchainConfig(api_key='test-key', outbox_path=str(tmp_path/'state.sqlite3'))
    app = create_app(service_config=settings(tmp_path), blockchain_config=cfg,
                     bridge_client=bridge, clock=lambda: NOW)
    with TestClient(app, headers=ADMIN_HEADERS) as client:
        client.post('/devices/import', json={'deviceId':'dev-001'})
        original = app.state.outbox.append
        def broken(*args, **kwargs):
            raise OSError('disk unavailable')
        monkeypatch.setattr(app.state.outbox, 'append', broken)
        value = event(device_id='dev-001')
        assert post(client, value).status_code == 503
        assert app.state.journal.lookup(value['event_id']) is None
        assert app.state.journal.history('dev-001', 10) == []
        assert app.state.engine.history('dev-001') == []
        assert not bridge.payloads
        monkeypatch.setattr(app.state.outbox, 'append', original)
        assert post(client, value).status_code == 202


def test_lost_response_retry_and_ledger_backpressure(tmp_path, monkeypatch):
    bridge = StubBridge()
    cfg = BlockchainConfig(api_key='test-key', outbox_path=str(tmp_path/'state.sqlite3'))
    app = create_app(service_config=settings(tmp_path), blockchain_config=cfg,
                     bridge_client=bridge, clock=lambda: NOW)
    with TestClient(app, headers=ADMIN_HEADERS) as client:
        client.post('/devices/import', json={'deviceId':'dev-001'})
        value = event(device_id='dev-001')
        bridge.failure = BridgeError('receipt lost', uncertain=True)
        first = post(client, value)
        assert first.status_code == 202
        assert first.json()['blockchain']['status'] == 'uncertain'
        assert post(client, value).json()['duplicate']
        assert len(bridge.payloads) == 1
        next_event = event(device_id='dev-001', observed_at=(NOW+timedelta(seconds=1)).isoformat())
        assert post(client, next_event).status_code == 503
        assert app.state.journal.lookup(next_event['event_id']) is None
        status = client.get('/v1/devices/dev-001/trust').json()
        assert status['effective_action'] == 'hold' and not status['usable_for_policy']
        bridge.confirmation = 'existing-transaction'
        assert client.post('/blockchain/retry/dev-001', json={}).json()['status'] == 'committed'
        bridge.failure = None
        assert post(client, next_event).status_code == 202
        assert len(app.state.engine.history('dev-001')) == 2


def test_reply_failure_after_commit_is_idempotent(running, monkeypatch):
    client, app, _, _ = running
    value = event()
    original = app.state.journal.evaluate
    def crash_after_commit(*args, **kwargs):
        original(*args, **kwargs)
        raise OSError('simulated lost response after successful commit')
    monkeypatch.setattr(app.state.journal, 'evaluate', crash_after_commit)
    assert post(client, value).status_code == 503
    assert post(client, value).json()['duplicate']
    assert len(app.state.engine.history('IOT-001')) == 1


def test_second_writer_and_config_drift_rejected(running):
    _, _, _, service = running
    with pytest.raises(RuntimeError, match='already has an API writer'):
        with TestClient(create_app(service_config=service)):
            pass
    with pytest.raises(ValueError, match='saved configuration differs'):
        create_app(EngineConfig(base_threshold=0.6), service_config=service)


def test_credentials_not_in_repr_and_distinct(tmp_path):
    service = settings(tmp_path)
    assert SERVICE_TOKEN not in repr(service) and ADMIN_TOKEN not in repr(service)
    with pytest.raises(ValueError):
        replace(service, admin_token=SERVICE_TOKEN)


def test_sender_retries_identical_payload_without_reinventing_event():
    import httpx
    from member2_sender import send_event
    sent, waits = [], []
    value = event()
    def handler(request):
        sent.append(json.loads(request.content))
        assert request.headers['Authorization'] == f'Bearer {SERVICE_TOKEN}'
        if len(sent) == 1:
            return httpx.Response(503, json={'detail':'temporarily unavailable'})
        return httpx.Response(202, json={'accepted':True})
    with httpx.Client(base_url='http://test', transport=httpx.MockTransport(handler)) as client:
        assert send_event(client, value, SERVICE_TOKEN, sleep=waits.append)['accepted']
    assert sent == [value, value] and waits == [0.5]


def test_sender_does_not_retry_conflicts_or_invalid_events():
    import httpx
    from member2_sender import send_event
    count = []
    def handler(request):
        count.append(1)
        return httpx.Response(409, json={'reason':'event_id_content_conflict'})
    with httpx.Client(base_url='http://test', transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(httpx.HTTPStatusError):
            send_event(client, event(), SERVICE_TOKEN)
    assert count == [1]


def test_maximum_metadata_fits_unchanged_bridge_evidence_limit(running):
    from blockchain_client import make_trust_update
    client, _, _, _ = running
    value = event(flow_id='x'*128, model_version='x'*128, feature_schema_version='x'*128,
                  calibration_version='x'*128, prediction='A'*64)
    response = post(client, value)
    assert response.status_code == 202
    wire = make_trust_update(response.json()['decision'])
    assert len(wire['evidence'].encode('utf-8')) < 8192


def test_openapi_documents_separate_credentials(running):
    client, _, _, _ = running
    schema = client.get('/openapi.json').json()
    assert schema['paths']['/v1/behavior-events']['post']['security'] == [{'AIServiceBearer':[]}]
    assert schema['paths']['/devices']['post']['security'] == [{'AdminBearer':[]}]
    assert SERVICE_TOKEN not in json.dumps(schema) and ADMIN_TOKEN not in json.dumps(schema)


def test_invalid_unicode_rejected_before_audit(running):
    client, app, _, _ = running
    value = event(model_version='\ud800')
    response = client.post('/v1/behavior-events', content=json.dumps(value),
                           headers={**SERVICE_HEADERS, 'Content-Type':'application/json'})
    assert response.status_code == 400
    assert app.state.engine.history('IOT-001') == []


def test_equivalent_utc_spelling_and_omitted_nulls_are_one_event(running):
    client, app, _, _ = running
    value = event()
    assert post(client, value).status_code == 202
    equivalent = {**value, 'observed_at':value['observed_at'].replace('+00:00','Z')}
    del equivalent['temporal_risk']
    del equivalent['anomaly_score']
    assert post(client, equivalent).json()['duplicate']
    assert len(app.state.engine.history('IOT-001')) == 1
