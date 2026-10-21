"""Synthetic Member 2-shaped evidence; no trained AI model is executed."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from uuid import uuid4
import httpx
from local_config import load_local_env
from member2_sender import send_event


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', default='http://127.0.0.1:8001')
    parser.add_argument('--device-id', default='IOT-001')
    parser.add_argument('--register', choices=['local', 'blockchain', 'none'], default='local')
    args = parser.parse_args()
    load_local_env(Path(__file__).resolve().parent / '.env')
    admin, sender = os.getenv('TRUST_ADMIN_TOKEN', ''), os.getenv('TRUST_SERVICE_TOKEN', '')
    if not admin or not sender:
        parser.exit(1, 'Run configure_local.py first, or set both trust credentials.\n')
    headers = {'Authorization': f'Bearer {admin}'}
    try:
        with httpx.Client(base_url=args.url, timeout=50, trust_env=False, follow_redirects=False) as client:
            if args.register != 'none':
                path = '/devices/import' if args.register == 'blockchain' else '/devices'
                body = {'deviceId': args.device_id}
                if args.register == 'local':
                    body['criticality'] = 0.75
                result = client.post(path, json=body, headers=headers)
                if result.status_code == 409:
                    print('Device already exists. Prior history and any quarantine latch are preserved.')
                else:
                    result.raise_for_status()
            for step, risk in enumerate([0.1, 0.878, 0.01], start=1):
                value = {
                    'event_id': str(uuid4()), 'schema_version': '1.0', 'device_id': args.device_id,
                    'flow_id': f'synthetic-flow-{step}', 'observed_at': datetime.now(timezone.utc).isoformat(),
                    'model_version': 'synthetic-demo-v1',
                    'prediction': 'DoS-SYN_Flood' if risk > 0.8 else 'BenignTraffic',
                    'attack_probability': 0.92 if risk > 0.8 else 0.01,
                    'classification_confidence': 0.95, 'anomaly_score': 0.8 if risk > 0.8 else None,
                    'temporal_risk': None, 'behavior_risk': risk, 'quality_status': 'valid', 'window_seconds': 5,
                }
                result = send_event(client, value, sender)
                print(json.dumps(result, indent=2))
                duplicate = send_event(client, value, sender)
                print('Identical retry: duplicate =', duplicate['duplicate'])
                if result.get('blockchain') and result['blockchain']['status'] != 'committed':
                    parser.exit(1, 'Trust saved; ledger delivery unconfirmed. Use the retry instructions before sending another event.\n')
            current = client.get(f'/v1/devices/{args.device_id}/trust', headers=headers)
            current.raise_for_status()
            print(json.dumps(current.json(), indent=2))
    except httpx.HTTPStatusError as exc:
        parser.exit(1, f'HTTP {exc.response.status_code}: {exc.response.text}\n')
    except httpx.HTTPError:
        parser.exit(1, 'Request failed. Check the server and saved delivery status; preserve event IDs when retrying.\n')


if __name__ == '__main__':
    main()
