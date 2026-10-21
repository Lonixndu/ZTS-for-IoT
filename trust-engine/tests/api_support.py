"""Credentials and isolated database configuration for legacy regression tests."""
from pathlib import Path
from fastapi.testclient import TestClient as FastAPITestClient
from main import create_app as app_factory
from service_config import ServiceConfig

ADMIN_TOKEN = 'test-admin-token-000000000000000000000000000'
SERVICE_TOKEN = 'test-service-token-0000000000000000000000000'
ADMIN_HEADERS = {'Authorization': f'Bearer {ADMIN_TOKEN}'}
SERVICE_HEADERS = {'Authorization': f'Bearer {SERVICE_TOKEN}'}


class TestClient(FastAPITestClient):
    __test__ = False

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('headers', ADMIN_HEADERS)
        super().__init__(*args, **kwargs)


def create_app(config=None, log_path=None, *, blockchain_config=None, bridge_client=None, **kwargs):
    path = blockchain_config.outbox_path if blockchain_config else str(Path(log_path).with_suffix('.sqlite3'))
    service = ServiceConfig(service_token=SERVICE_TOKEN, admin_token=ADMIN_TOKEN,
                            state_path=path, enable_legacy_evaluate=True)
    return app_factory(config, service_config=service, blockchain_config=blockchain_config,
                       bridge_client=bridge_client, **kwargs)
