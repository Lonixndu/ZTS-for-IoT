"""Verify real HTTP integration with Member 3's unmodified Go mock ledger.
This executes Go chaincode through its fake stub, not a Fabric network.
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from uuid import uuid4
import httpx


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--blockchain-source', required=True)
    parser.add_argument('--mockledger-binary', required=True)
    parser.add_argument('--output', default='results/http-stack-check.json')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    source, binary = Path(args.blockchain_source).resolve(), Path(args.mockledger_binary).resolve()
    if not (source/'bridge/main.py').is_file() or not binary.is_file():
        parser.error('supply the folder containing bridge/main.py and a built mockledger executable')
    (root/'results').mkdir(exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='stack-check-', dir=root/'results'))
    ledger_port, bridge_port, engine_port = free_port(), free_port(), free_port()
    admin, sender, bridge_key = [secrets.token_urlsafe(32) for _ in range(3)]
    env = {**os.environ, 'BRIDGE_API_KEY':bridge_key, 'CONNECTOR_URL':f'http://127.0.0.1:{ledger_port}',
           'TRUST_ADMIN_TOKEN':admin, 'TRUST_SERVICE_TOKEN':sender, 'TRUST_ENABLE_LEGACY_EVALUATE':'false',
           'TRUST_EVENT_TTL_SECONDS':'15', 'TRUST_FUTURE_SKEW_SECONDS':'2',
           'BLOCKCHAIN_ENABLED':'true', 'BLOCKCHAIN_API_KEY':bridge_key,
           'BLOCKCHAIN_URL':f'http://127.0.0.1:{bridge_port}', 'BLOCKCHAIN_OUTBOX':str(work/'state.sqlite3')}
    processes, streams = [], []

    def start(name, command, cwd):
        stream = (work/f'{name}.log').open('wb')
        streams.append(stream)
        process = subprocess.Popen(command, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT)
        processes.append(process)
        return process

    def stop(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    def ready(url, process):
        deadline = time.monotonic()+30
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(f'service exited; see local logs in {work}')
            try:
                with httpx.Client(trust_env=False, timeout=1) as client:
                    if client.get(url+'/health').status_code == 200:
                        return
            except httpx.HTTPError:
                pass
            time.sleep(0.2)
        raise RuntimeError(f'service did not become ready: {url}')

    engine_command = [sys.executable, '-m', 'uvicorn', 'main:application', '--factory', '--host','127.0.0.1', '--port',str(engine_port)]
    checks = []
    try:
        ledger = start('ledger', [str(binary), '-addr', f'127.0.0.1:{ledger_port}'], source)
        ready(f'http://127.0.0.1:{ledger_port}', ledger)
        bridge = start('bridge', [sys.executable,'-m','uvicorn','bridge.main:app','--host','127.0.0.1','--port',str(bridge_port)], source)
        ready(f'http://127.0.0.1:{bridge_port}', bridge)
        engine = start('engine', engine_command, root)
        ready(f'http://127.0.0.1:{engine_port}', engine)
        with httpx.Client(base_url=f'http://127.0.0.1:{bridge_port}',headers={'x-api-key':bridge_key},trust_env=False,timeout=50) as chain, \
             httpx.Client(base_url=f'http://127.0.0.1:{engine_port}',headers={'Authorization':f'Bearer {admin}'},trust_env=False,timeout=50) as api:
            health = chain.get('/health').json()
            assert health['connector']['ledger'] == 'mock', health
            reg = chain.post('/v1/devices',json={'device_id':'IOT-001','device_type':'camera','criticality':4,'network_address':'192.168.10.44'})
            reg.raise_for_status()
            imported = api.post('/devices/import',json={'deviceId':'IOT-001'})
            assert imported.status_code == 201 and imported.json()['criticality'] == 0.75, imported.text
            checks.append('Go registration -> supplied bridge -> engine import')
            values = []
            for risk in [0.1,0.878,0.01]:
                value = {'event_id':str(uuid4()),'schema_version':'1.0','device_id':'IOT-001',
                         'flow_id':'synthetic-http-test','observed_at':datetime.now(timezone.utc).isoformat(),
                         'model_version':'synthetic-http-test-v1','prediction':'DoS-SYN_Flood' if risk > 0.8 else 'BenignTraffic',
                         'behavior_risk':risk,'attack_probability':risk,'classification_confidence':0.95,
                         'anomaly_score':None,'temporal_risk':None,'quality_status':'valid','window_seconds':5}
                response = api.post('/v1/behavior-events',json=value,headers={'Authorization':f'Bearer {sender}'})
                assert response.status_code == 202, response.text
                body=response.json()
                assert body['blockchain']['status'] == 'committed', body
                duplicate=api.post('/v1/behavior-events',json=value,headers={'Authorization':f'Bearer {sender}'})
                assert duplicate.status_code==202 and duplicate.json()['duplicate'], duplicate.text
                values.append(body)
            record=chain.get('/v1/devices/IOT-001').json()
            events=chain.get('/v1/devices/IOT-001/events').json()
            assert len(events)==3, events
            assert values[0]['decision']['action']=='allow'
            assert values[1]['blockchain']['ledgerTrustValue']==12.2
            assert values[2]['decision']['trustValue']==0.99 and values[2]['decision']['action']=='quarantine'
            assert record['status']=='SUSPECT' and record['trustValue'] < record['threshold']
            hashes={e['evidenceHash'] for e in events}
            assert all(v['blockchain']['evidenceHash'] in hashes for v in values)
            checks += ['Member 2 event -> engine -> bridge -> real Go chaincode in mock ledger',
                       'Risk 0.878 exports trust 12.2/100', 'Three identical retries create zero additional Go ledger events',
                       'Quarantine latch remains SUSPECT after lower risk', 'Evidence hashes agree with actual Go ledger events']
            stop(engine)
            engine=start('engine-restart',engine_command,root)
            ready(f'http://127.0.0.1:{engine_port}',engine)
            duplicate=api.post('/v1/behavior-events',json=value,headers={'Authorization':f'Bearer {sender}'})
            assert duplicate.status_code==202 and duplicate.json()['duplicate'],duplicate.text
            assert len(api.get('/devices/IOT-001/history').json())==3
            assert len(chain.get('/v1/devices/IOT-001/events').json())==3
            checks.append('Restart restores state and deduplication without another chain write')
            stale={**value,'event_id':str(uuid4()),'observed_at':(datetime.now(timezone.utc)-timedelta(seconds=30)).isoformat()}
            assert api.post('/v1/behavior-events',json=stale,headers={'Authorization':f'Bearer {sender}'}).status_code==422
            assert api.post('/v1/behavior-events',json=value,headers={'Authorization':'Bearer wrong'}).status_code==401
            checks += ['Stale event rejected over HTTP', 'Wrong AI credential rejected over HTTP']
            report={'status':'passed','executed_at_utc':datetime.now(timezone.utc).isoformat(),
                    'environment':'local HTTP; supplied Go mock ledger; NOT Hyperledger Fabric',
                    'checks':checks, 'engine_actions':[v['decision']['action'] for v in values],
                    'engine_trust_values':[v['decision']['trustValue'] for v in values],
                    'ledger_values':[v['blockchain']['ledgerTrustValue'] for v in values],
                    'ledger_event_count':len(events),
                    'bridge_sha256':hashlib.sha256((source/'bridge/main.py').read_bytes()).hexdigest()}
            output=Path(args.output).resolve()
            output.parent.mkdir(parents=True,exist_ok=True)
            output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
            print(json.dumps(report,indent=2))
    finally:
        for process in reversed(processes): stop(process)
        for stream in streams: stream.close()


if __name__=='__main__':
    main()
