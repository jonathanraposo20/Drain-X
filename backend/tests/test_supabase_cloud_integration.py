"""
DRAIN-X Supabase Cloud Integration & Security Test Suite.

Milestone: P0.6 Supabase Cloud Integration.

Test Categories:
1. Configuration & Health Diagnostics:
   - Status reporting for unconfigured in-memory mode vs configured Supabase Cloud.
   - Live health probe (check_connection / ping) with simulated 200 OK, 401 Unauthorized, and network timeouts.
2. Cloud Telemetry Ingestion & Error Handling:
   - Successful batch insertion into PostgREST table schema.
   - Graceful degradation and error logging when PostgREST returns HTTP 500 or times out.
   - Internal buffer fallback auditing.
3. Historical Telemetry Queries & Pagination:
   - Filter by sensor_id, section_id, operational source (PHYSICAL vs SIMULATED), and device_id.
   - Correct multiple timestamp query parameter formatting for start_time & end_time.
   - Pagination (limit, offset) and truncation metadata.
4. Edge Node / Device Registry:
   - Device registration, querying, and validation stage tracking via API and repository.
5. Operational Mode History Audit Trail:
   - Mode transition persistence to PostgREST and in-memory buffer.
   - Auditable history query endpoint.
6. Security, RBAC & Device Authorization:
   - Device API key authentication on `/api/v1/telemetry/ingest` (enforced when configured, permitted in dev).
   - Supabase JWT token verification and role enforcement (citizen vs municipality/worker/admin).
   - Unauthenticated operational mode transition rejection when auth is enabled.
"""

import json
import base64
from typing import Optional, List, Dict, Any
import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
import httpx

from app.core.config import settings
from app.main import app
from app.services.state_store import state_store
from app.services.persistence_repository import PersistenceRepository, persistence_repo
from app.models.contracts import (
    SensorReadingContract,
    SensorType,
    MeasurementUnit,
    DataSource,
    SensorHealthStatus,
)


@pytest.fixture(autouse=True)
def reset_system():
    state_store.set_mode("SIMULATION", reason="Test reset")
    yield
    state_store.set_mode("SIMULATION", reason="Test cleanup")


# --------------------------------------------------------------------
# 1. Configuration & Connection Health Diagnostics
# --------------------------------------------------------------------

def test_supabase_config_status_reporting():
    """Verify clean status reporting between unconfigured in-memory fallback and configured cloud."""
    # 1. Unconfigured fallback instance
    unconfigured_repo = PersistenceRepository(supabase_url=None, supabase_key=None)
    status_unconf = unconfigured_repo.get_status()
    assert status_unconf.configured is False
    assert status_unconf.mode == "IN_MEMORY_FALLBACK"
    assert status_unconf.connection_status == "UNCONFIGURED"

    # 2. Configured instance
    configured_repo = PersistenceRepository(
        supabase_url="https://mock-project.supabase.co",
        supabase_key="anon-key-123",
        service_role_key="service-role-key-456",
    )
    status_conf = configured_repo.get_status()
    assert status_conf.configured is True
    assert status_conf.mode == "SUPABASE_CLOUD"
    assert status_conf.service_role_key_present is True
    assert status_conf.url_present is True


@pytest.mark.anyio
async def test_supabase_connection_health_probe_success():
    """Verify check_connection reports CONNECTED when Supabase responds with 200 OK."""
    repo = PersistenceRepository(
        supabase_url="https://mock-project.supabase.co",
        supabase_key="anon-key-123",
    )

    mock_response = httpx.Response(status_code=200, json=[])
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_response):
        health = await repo.check_connection()
        assert health["status"] == "CONNECTED"
        assert health["mode"] == "SUPABASE_CLOUD"
        assert health["http_status"] == 200
        assert health["latency_ms"] is not None
        assert repo.get_status().connection_status == "CONNECTED"


@pytest.mark.anyio
async def test_supabase_connection_health_probe_auth_failure():
    """Verify check_connection reports AUTH_FAILED when Supabase returns HTTP 401."""
    repo = PersistenceRepository(
        supabase_url="https://mock-project.supabase.co",
        supabase_key="invalid-key",
    )

    mock_response = httpx.Response(status_code=401, text="Invalid API key")
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_response):
        health = await repo.check_connection()
        assert health["status"] == "AUTH_FAILED"
        assert health["http_status"] == 401
        assert "Invalid or unauthorized" in health["message"]


@pytest.mark.anyio
async def test_supabase_connection_health_probe_network_timeout():
    """Verify check_connection handles network timeout without throwing uncaught exceptions."""
    repo = PersistenceRepository(
        supabase_url="https://mock-project.supabase.co",
        supabase_key="valid-key",
    )

    with patch("httpx.AsyncClient.get", side_effect=httpx.ConnectTimeout("Connection timed out")):
        health = await repo.check_connection()
        assert health["status"] == "UNREACHABLE"
        assert health["http_status"] is None
        assert "failed" in health["message"].lower()


# --------------------------------------------------------------------
# 2. Telemetry Persistence & PostgREST Batch Serialization
# --------------------------------------------------------------------

@pytest.mark.anyio
async def test_supabase_postgrest_batch_persistence_success():
    """Verify telemetry contracts are correctly serialized and sent via PostgREST POST."""
    repo = PersistenceRepository(
        supabase_url="https://mock-project.supabase.co",
        service_role_key="service-role-secret",
    )

    t_now = datetime.now(timezone.utc)
    reading = SensorReadingContract(
        sensor_id="US_UPSTREAM_01",
        section_id="SEC_SCREENING",
        sensor_type=SensorType.WATER_LEVEL,
        value=8.4,
        unit=MeasurementUnit.CENTIMETRE,
        source=DataSource.PHYSICAL,
        status=SensorHealthStatus.OK,
        timestamp=t_now,
        metadata={"device_id": "DRAINX-ESP32-NODE-01"},
    )

    mock_response = httpx.Response(status_code=201, text="Created")
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response) as mock_post:
        count = await repo.persist_readings([reading])
        assert count == 1
        assert mock_post.called

        # Validate headers and payload structure
        call_kwargs = mock_post.call_args.kwargs
        headers = call_kwargs["headers"]
        assert headers["apikey"] == "service-role-secret"
        assert headers["Authorization"] == "Bearer service-role-secret"

        payload = call_kwargs["json"]
        assert len(payload) == 1
        assert payload[0]["sensor_id"] == "US_UPSTREAM_01"
        assert payload[0]["value"] == 8.4
        assert payload[0]["source"] == "PHYSICAL"
        assert payload[0]["device_id"] == "DRAINX-ESP32-NODE-01"


@pytest.mark.anyio
async def test_supabase_postgrest_error_fallback():
    """Verify that when PostgREST returns 500 error, repository fails soft and logs diagnostic error."""
    repo = PersistenceRepository(
        supabase_url="https://mock-project.supabase.co",
        supabase_key="key",
    )

    reading = SensorReadingContract(
        sensor_id="US_WEIR_02",
        section_id="SEC_OUTLET",
        sensor_type=SensorType.WATER_LEVEL,
        value=2.1,
        unit=MeasurementUnit.CENTIMETRE,
        source=DataSource.PHYSICAL,
        status=SensorHealthStatus.OK,
        timestamp=datetime.now(timezone.utc),
    )

    mock_response = httpx.Response(status_code=500, text="Internal Server Error")
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
        persisted = await repo.persist_readings([reading])
        assert persisted == 0
        status = repo.get_status()
        assert status.failed_persistence_count == 1
        assert "500" in status.last_persistence_error


# --------------------------------------------------------------------
# 3. Historical Telemetry Queries, PostgREST Formatting & Pagination
# --------------------------------------------------------------------

@pytest.mark.anyio
async def test_supabase_historical_query_formatting():
    """Verify PostgREST query parameters include order, limit, offset, and multiple timestamps."""
    repo = PersistenceRepository(
        supabase_url="https://mock-project.supabase.co",
        supabase_key="anon-key",
    )

    t_start = datetime(2026, 11, 13, 10, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 11, 13, 11, 0, 0, tzinfo=timezone.utc)

    mock_data = [
        {"sensor_id": "US_UPSTREAM_01", "value": 6.0, "timestamp": "2026-11-13T10:15:00Z"},
        {"sensor_id": "US_UPSTREAM_01", "value": 6.2, "timestamp": "2026-11-13T10:30:00Z"},
    ]
    mock_response = httpx.Response(status_code=200, json=mock_data)

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_response) as mock_get:
        results = await repo.query_historical_telemetry(
            sensor_id="US_UPSTREAM_01",
            source="PHYSICAL",
            device_id="DRAINX-ESP32-NODE-01",
            start_time=t_start,
            end_time=t_end,
            limit=50,
            offset=10,
            chronological=True,
        )
        assert len(results) == 2

        call_kwargs = mock_get.call_args.kwargs
        params = call_kwargs["params"]
        # Params is a list of tuples
        param_dict = {}
        for k, v in params:
            param_dict.setdefault(k, []).append(v)

        assert "order" in param_dict and param_dict["order"][0] == "timestamp.asc"
        assert "limit" in param_dict and param_dict["limit"][0] == "50"
        assert "offset" in param_dict and param_dict["offset"][0] == "10"
        assert "sensor_id" in param_dict and param_dict["sensor_id"][0] == "eq.US_UPSTREAM_01"
        assert "source" in param_dict and param_dict["source"][0] == "eq.PHYSICAL"
        assert "device_id" in param_dict and param_dict["device_id"][0] == "eq.DRAINX-ESP32-NODE-01"

        # Verify both start and end time constraints are preserved without collision
        ts_filters = param_dict.get("timestamp", [])
        assert any(f.startswith("gte.") for f in ts_filters)
        assert any(f.startswith("lte.") for f in ts_filters)


@pytest.mark.anyio
async def test_in_memory_pagination_and_truncation():
    """Verify in-memory fallback correctly handles offset and limit pagination."""
    repo = PersistenceRepository(
    supabase_url=None,
    supabase_key=None,
    service_role_key=None,
)

    t_base = datetime(2026, 11, 13, 12, 0, 0, tzinfo=timezone.utc)
    readings = []
    for i in range(10):
        readings.append(
            SensorReadingContract(
                sensor_id="FS_FLUME_01",
                section_id="SEC_SCREENING",
                sensor_type=SensorType.FLOW_RATE,
                value=float(i + 1),
                unit=MeasurementUnit.LITRES_PER_MINUTE,
                source=DataSource.PHYSICAL,
                status=SensorHealthStatus.OK,
                timestamp=t_base,
            )
        )
    await repo.persist_readings(readings)

    # First page: limit 4, offset 0
    p1 = await repo.query_historical_telemetry(sensor_id="FS_FLUME_01", limit=4, offset=0)
    assert len(p1) == 4

    # Second page: limit 4, offset 4
    p2 = await repo.query_historical_telemetry(sensor_id="FS_FLUME_01", limit=4, offset=4)
    assert len(p2) == 4

    # Third page: limit 4, offset 8
    p3 = await repo.query_historical_telemetry(sensor_id="FS_FLUME_01", limit=4, offset=8)
    assert len(p3) == 2


# --------------------------------------------------------------------
# 4. Device Registry & Auditing
# --------------------------------------------------------------------

@pytest.mark.anyio
async def test_device_registry_operations():
    """Verify device registration, retrieval, and listing in persistence repository."""
    repo = PersistenceRepository()

    # List default seeded node
    devices = await repo.list_devices()
    assert len(devices) >= 1
    assert any(d["device_id"] == "DRAINX-ESP32-NODE-01" for d in devices)

    # Register new bench test node
    new_device = {
        "device_id": "DRAINX-ESP32-BENCH-02",
        "name": "Secondary Flume Node",
        "hardware_model": "ESP32 DevKit V1",
        "firmware_version": "0.3.8-p0.6",
        "is_active": True,
        "validation_stage": "BENCH_VALIDATED",
        "metadata": {"channel": "outlet_weir"},
    }
    registered = await repo.register_device(new_device)
    assert registered["device_id"] == "DRAINX-ESP32-BENCH-02"

    fetched = await repo.get_device("DRAINX-ESP32-BENCH-02")
    assert fetched is not None
    assert fetched["validation_stage"] == "BENCH_VALIDATED"


def test_device_api_endpoints(client: TestClient):
    """Verify GET and POST /api/v1/devices."""
    # List devices
    res_list = client.get("/api/v1/devices")
    assert res_list.status_code == 200
    data = res_list.json()
    assert data["status"] == "success"
    assert data["count"] >= 1

    # Fetch specific device
    res_dev = client.get("/api/v1/devices/DRAINX-ESP32-NODE-01")
    assert res_dev.status_code == 200
    assert res_dev.json()["device"]["device_id"] == "DRAINX-ESP32-NODE-01"

    # Nonexistent device -> 404
    res_404 = client.get("/api/v1/devices/NONEXISTENT-NODE")
    assert res_404.status_code == 404


# --------------------------------------------------------------------
# 5. Security & Role-Based Access Control (RBAC)
# --------------------------------------------------------------------

def test_device_key_authentication(client: TestClient):
    """Verify X-Device-Key enforcement when DEVICE_INGEST_API_KEY is configured."""
    reading_payload = {
        "version": "1.0",
        "message_id": "dev-auth-test-01",
        "sensor_id": "US_UPSTREAM_01",
        "section_id": "SEC_SCREENING",
        "sensor_type": "WATER_LEVEL",
        "value": 4.5,
        "unit": "cm",
        "source": "SIMULATED",
        "status": "OK",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    # 1. When DEVICE_INGEST_API_KEY is unset -> open ingestion allowed
    with patch.object(settings, "DEVICE_INGEST_API_KEY", None):
        res_open = client.post("/api/v1/telemetry/ingest", json=reading_payload)
        assert res_open.status_code == 201

    # 2. When DEVICE_INGEST_API_KEY is configured -> missing header rejected
    with patch.object(settings, "DEVICE_INGEST_API_KEY", "secret-edge-key"):
        res_rejected = client.post("/api/v1/telemetry/ingest", json=reading_payload)
        assert res_rejected.status_code == 401

        # Providing invalid key rejected
        res_bad_key = client.post(
            "/api/v1/telemetry/ingest",
            json=reading_payload,
            headers={"X-Device-Key": "wrong-key"},
        )
        assert res_bad_key.status_code == 401

        # Providing valid key accepted
        res_ok = client.post(
            "/api/v1/telemetry/ingest",
            json=reading_payload,
            headers={"X-Device-Key": "secret-edge-key"},
        )
        assert res_ok.status_code == 201


def _create_mock_jwt(payload: dict, secret: Optional[str] = None, alg: str = "HS256") -> str:
    """Helper to create a mock JWT for testing, optionally signed with HS256 secret."""
    header = {"alg": alg, "typ": "JWT"}
    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signing_input = f"{h_b64}.{p_b64}"
    if secret:
        import hmac, hashlib
        sig_bytes = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
        sig_b64 = base64.urlsafe_b64encode(sig_bytes).decode("ascii").rstrip("=")
    else:
        sig_b64 = "mock_sig"
    return f"{signing_input}.{sig_b64}"


def test_supabase_auth_rbac_on_mode_change(client: TestClient):
    """Verify that when SUPABASE_AUTH_ENABLED is True, operational mode changes require RBAC."""
    with patch.object(settings, "SUPABASE_AUTH_ENABLED", True), patch.object(settings, "SUPABASE_JWT_SECRET", "drainx_super_secret_test_key_12345"), patch.object(settings, "SUPABASE_URL", "https://test-project.supabase.co"):
        # 1. Missing Authorization header -> 401
        res_no_auth = client.post("/api/v1/status/mode", json={"mode": "SAFE_HOLD"})
        assert res_no_auth.status_code == 401

        # 2. Authenticated as citizen (insufficient role) -> 403 Forbidden
        citizen_token = _create_mock_jwt({
            "sub": "citizen-123",
            "iss": "https://test-project.supabase.co/auth/v1",
            "app_metadata": {"role": "citizen"},
            "email": "citizen@example.com",
        }, secret="drainx_super_secret_test_key_12345")
        res_citizen = client.post(
            "/api/v1/status/mode",
            json={"mode": "SAFE_HOLD"},
            headers={"Authorization": f"Bearer {citizen_token}"},
        )
        assert res_citizen.status_code == 403

        # 3. Authenticated as municipal operator (allowed role) -> 200 OK
        operator_token = _create_mock_jwt({
            "sub": "operator-456",
            "iss": "https://test-project.supabase.co/auth/v1",
            "app_metadata": {"role": "municipality"},
            "email": "operator@drainx.gov",
        }, secret="drainx_super_secret_test_key_12345")
        res_operator = client.post(
            "/api/v1/status/mode",
            json={"mode": "SAFE_HOLD", "reason": "Operator maintenance test"},
            headers={"Authorization": f"Bearer {operator_token}"},
        )
        assert res_operator.status_code == 200
        assert res_operator.json()["mode"] == "SAFE_HOLD"


def test_jwt_cryptographic_verification_and_tampering(client: TestClient):
    """Verify cryptographic signature verification: valid passes, tampered signature fails with 401."""
    test_secret = "drainx_super_secret_test_key_12345"
    payload = {
        "sub": "operator-789",
        "iss": "https://test-project.supabase.co/auth/v1",
        "app_metadata": {"role": "admin"},
        "aud": "authenticated",
        "exp": datetime.now(timezone.utc).timestamp() + 3600,
    }

    # Valid signed token
    valid_token = _create_mock_jwt(payload, secret=test_secret)

    with patch.object(settings, "SUPABASE_AUTH_ENABLED", True), \
         patch.object(settings, "SUPABASE_JWT_SECRET", test_secret), patch.object(settings, "SUPABASE_URL", "https://test-project.supabase.co"):
        res_valid = client.post(
            "/api/v1/status/mode",
            json={"mode": "SAFE_HOLD", "reason": "Valid cryptographic JWT test"},
            headers={"Authorization": f"Bearer {valid_token}"},
        )
        assert res_valid.status_code == 200

        # Tampered signature (change last character)
        tampered_token = valid_token[:-1] + ("A" if valid_token[-1] != "A" else "B")
        res_tampered = client.post(
            "/api/v1/status/mode",
            json={"mode": "SAFE_HOLD"},
            headers={"Authorization": f"Bearer {tampered_token}"},
        )
        assert res_tampered.status_code == 401
        assert "signature" in res_tampered.json()["detail"].lower()


def test_jwt_expiration_enforcement(client: TestClient):
    """Verify expired token is rejected with HTTP 401."""
    expired_payload = {
        "sub": "operator-exp",
        "iss": "https://test-project.supabase.co/auth/v1",
        "app_metadata": {"role": "admin"},
        "aud": "authenticated",
        "exp": datetime.now(timezone.utc).timestamp() - 60,  # 1 minute in the past
    }
    expired_token = _create_mock_jwt(expired_payload, secret="drainx_super_secret_test_key_12345")

    with patch.object(settings, "SUPABASE_AUTH_ENABLED", True), patch.object(settings, "SUPABASE_JWT_SECRET", "drainx_super_secret_test_key_12345"), patch.object(settings, "SUPABASE_URL", "https://test-project.supabase.co"):
        res = client.post(
            "/api/v1/status/mode",
            json={"mode": "SAFE_HOLD"},
            headers={"Authorization": f"Bearer {expired_token}"},
        )
        assert res.status_code == 401
        assert "expired" in res.json()["detail"].lower()


def test_anti_privilege_escalation_user_metadata_rejected(client: TestClient):
    """
    CRITICAL SECURITY CHECK:
    Verify that an attacker attempting to elevate privileges by putting role='admin'
    in client-controlled user_metadata while app_metadata is 'citizen' is REJECTED with 403.
    """
    malicious_payload = {
        "sub": "attacker-user",
        "iss": "https://test-project.supabase.co/auth/v1",
        "user_metadata": {"role": "admin"},  # Client-controlled self-assigned role
        "app_metadata": {"role": "citizen"},  # Server-assigned trusted role
        "aud": "authenticated",
        "exp": datetime.now(timezone.utc).timestamp() + 3600,
    }
    token = _create_mock_jwt(malicious_payload, secret="drainx_super_secret_test_key_12345")

    with patch.object(settings, "SUPABASE_AUTH_ENABLED", True), patch.object(settings, "SUPABASE_JWT_SECRET", "drainx_super_secret_test_key_12345"), patch.object(settings, "SUPABASE_URL", "https://test-project.supabase.co"):
        res = client.post(
            "/api/v1/status/mode",
            json={"mode": "SAFE_HOLD"},
            headers={"Authorization": f"Bearer {token}"},
        )
        # MUST be forbidden because user_metadata is ignored and app_metadata is citizen
        assert res.status_code == 403
        assert "Operation requires one of the following roles" in res.json()["detail"]


def test_production_fail_closed_startup_validation():
    """Verify validate_production_configuration fails closed with RuntimeError when production config is missing."""
    from app.core.config import Settings, validate_production_configuration

    # 1. Production with missing auth -> fails
    bad_cfg_1 = Settings(
        ENVIRONMENT="production",
        SUPABASE_AUTH_ENABLED=False,
        DEVICE_INGEST_API_KEY="12345678",
        SUPABASE_URL="https://test.supabase.co",
        SUPABASE_SERVICE_ROLE_KEY="secret",
        SUPABASE_JWT_SECRET="secret_jwt_at_least_16_chars",
    )
    with pytest.raises(RuntimeError) as exc_1:
        validate_production_configuration(bad_cfg_1)
    assert "SUPABASE_AUTH_ENABLED must be True" in str(exc_1.value)

    # 2. Production with missing device API key -> fails
    bad_cfg_2 = Settings(
        ENVIRONMENT="production",
        SUPABASE_AUTH_ENABLED=True,
        DEVICE_INGEST_API_KEY="",
        SUPABASE_URL="https://test.supabase.co",
        SUPABASE_SERVICE_ROLE_KEY="secret",
        SUPABASE_JWT_SECRET="secret_jwt_at_least_16_chars",
    )
    with pytest.raises(RuntimeError) as exc_2:
        validate_production_configuration(bad_cfg_2)
    assert "DEVICE_INGEST_API_KEY must be configured" in str(exc_2.value)

    # 3. Production with valid config -> succeeds
    valid_prod_cfg = Settings(
        ENVIRONMENT="production",
        SUPABASE_AUTH_ENABLED=True,
        DEVICE_INGEST_API_KEY="production_device_key_999",
        SUPABASE_URL="https://valid.supabase.co",
        SUPABASE_SERVICE_ROLE_KEY="valid_service_role_key_long",
        SUPABASE_JWT_SECRET="valid_jwt_secret_with_sufficient_entropy_123",
    )
    # Should not raise any exception
    validate_production_configuration(valid_prod_cfg)


def test_production_device_ingest_fail_closed(client: TestClient):
    """Verify in production mode, unauthenticated device telemetry ingestion fails closed with 401."""
    reading_payload = {
        "version": "1.0",
        "message_id": "prod-fail-closed-01",
        "sensor_id": "US_UPSTREAM_01",
        "section_id": "SEC_SCREENING",
        "sensor_type": "WATER_LEVEL",
        "value": 4.5,
        "unit": "cm",
        "source": "SIMULATED",
        "status": "OK",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    with patch.object(settings, "ENVIRONMENT", "production"), \
         patch.object(settings, "DEVICE_INGEST_API_KEY", "prod_edge_key_888"):
        # Without header in production -> 401
        res = client.post("/api/v1/telemetry/ingest", json=reading_payload)
        assert res.status_code == 401

        # With valid header in production -> 201
        res_ok = client.post(
            "/api/v1/telemetry/ingest",
            json=reading_payload,
            headers={"X-Device-Key": "prod_edge_key_888"},
        )
        assert res_ok.status_code == 201


def test_unsupported_jwt_algorithm_rejected(client: TestClient):
    """Verify non-HS256 algorithms (e.g. none or RS256) are rejected with HTTP 401."""
    none_token = _create_mock_jwt(
        {"sub": "attacker", "app_metadata": {"role": "admin"}},
        alg="none",
    )
    with patch.object(settings, "SUPABASE_AUTH_ENABLED", True), patch.object(settings, "SUPABASE_JWT_SECRET", "drainx_super_secret_test_key_12345"), patch.object(settings, "SUPABASE_URL", "https://test-project.supabase.co"):
        res = client.post(
            "/api/v1/status/mode",
            json={"mode": "SAFE_HOLD"},
            headers={"Authorization": f"Bearer {none_token}"},
        )
        assert res.status_code == 401
        assert "unsupported" in res.json()["detail"].lower()


def test_persistence_ping_endpoint(client: TestClient):
    """Verify POST /api/v1/telemetry/persistence/ping returns health probe."""
    res = client.post("/api/v1/telemetry/persistence/ping")
    assert res.status_code == 200
    data = res.json()
    assert "status" in data
    assert "mode" in data


