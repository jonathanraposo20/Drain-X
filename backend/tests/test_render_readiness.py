import importlib
from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import create_app
from tests.conftest import TEST_JWT_SECRET, TEST_SUPABASE_URL, create_test_token


def test_api_docs_enabled_in_development(monkeypatch):
    monkeypatch.setattr(settings, "ENVIRONMENT", "development")
    dev_app = create_app()
    client = TestClient(dev_app)

    assert client.get("/docs").status_code == 200
    assert client.get("/redoc").status_code == 200
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/").json()["docs_url"] == "/docs"


def test_api_docs_disabled_in_production(monkeypatch):
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "SUPABASE_AUTH_ENABLED", True)
    monkeypatch.setattr(settings, "SUPABASE_URL", TEST_SUPABASE_URL)
    monkeypatch.setattr(settings, "SUPABASE_SERVICE_ROLE_KEY", "sb_secret_prod_test_key_1234567890")
    monkeypatch.setattr(settings, "SUPABASE_JWT_SECRET", TEST_JWT_SECRET)
    monkeypatch.setattr(settings, "DEVICE_INGEST_API_KEY", "device-key-123456")
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "RATE_LIMIT_STORAGE_BACKEND", "database")
    monkeypatch.setattr(settings, "RATE_LIMIT_KEY_PEPPER", "0123456789abcdef0123456789abcdef")

    prod_app = create_app()
    client = TestClient(prod_app)
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 404
    assert client.get("/").json()["docs_url"] is None
    assert client.get("/api/v1/health/liveness").status_code == 200


def test_websockets_dependency_available_and_routes_connect(monkeypatch):
    from app.services.telemetry_stream_manager import telemetry_stream_manager
    from app.services.incident_stream_manager import incident_stream_manager

    ws_mod = importlib.import_module("websockets")
    uvicorn_mod = importlib.import_module("uvicorn")
    assert hasattr(ws_mod, "__version__")
    assert hasattr(uvicorn_mod, "__version__")

    monkeypatch.setattr(settings, "SUPABASE_AUTH_ENABLED", True)
    monkeypatch.setattr(settings, "SUPABASE_JWT_SECRET", TEST_JWT_SECRET)
    monkeypatch.setattr(settings, "SUPABASE_URL", TEST_SUPABASE_URL)
    telemetry_stream_manager._is_shutting_down = False
    telemetry_stream_manager._clients.clear()
    incident_stream_manager.reset_state()

    test_app = create_app()
    token = create_test_token(role="municipality", subject="ws-test-officer")
    client = TestClient(test_app)
    try:
        with client.websocket_connect("/api/v1/telemetry/stream") as ws:
            init_msg = ws.receive_json()
            assert init_msg["event_type"] == "INIT"
        with client.websocket_connect(
            "/api/v1/incidents/stream",
            headers={"Authorization": f"Bearer {token}"},
        ) as ws:
            init_msg = ws.receive_json()
            assert init_msg["event_type"] == "INIT"
    finally:
        telemetry_stream_manager._clients.clear()
        incident_stream_manager.reset_state()
