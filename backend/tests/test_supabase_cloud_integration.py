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
import re
from typing import Optional, List, Dict, Any
import pytest
from datetime import datetime, timezone, timedelta
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


def filter_mock_postgrest(all_records: List[Dict[str, Any]], params: Any) -> List[Dict[str, Any]]:
    """Helper to simulate PostgREST keyset filtering, offsets, and limits for unit testing."""
    param_dict = dict(params or [])
    limit_val = int(param_dict.get("limit", 1000))
    offset_val = int(param_dict.get("offset", 0))
    or_val = param_dict.get("or", "")

    records = list(all_records)
    if or_val:
        m_asc = re.match(r"\(timestamp\.gt\.(.+?),and\(timestamp\.eq\.\1,id\.gt\.(.+?)\)\)", or_val)
        m_desc = re.match(r"\(timestamp\.lt\.(.+?),and\(timestamp\.eq\.\1,id\.lt\.(.+?)\)\)", or_val)
        if m_asc:
            c_ts, c_id = m_asc.group(1), m_asc.group(2)
            records = [r for r in records if (r["timestamp"], str(r["id"])) > (c_ts, str(c_id))]
        elif m_desc:
            c_ts, c_id = m_desc.group(1), m_desc.group(2)
            records = [r for r in records if (r["timestamp"], str(r["id"])) < (c_ts, str(c_id))]
    elif offset_val > 0:
        records = records[offset_val:]
    return records[:limit_val]


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
        {"id": "rec_01", "sensor_id": "US_UPSTREAM_01", "value": 6.0, "timestamp": "2026-11-13T10:15:00Z"},
        {"id": "rec_02", "sensor_id": "US_UPSTREAM_01", "value": 6.2, "timestamp": "2026-11-13T10:30:00Z"},
    ]
    mock_response = httpx.Response(status_code=200, json=mock_data)
    mock_empty = httpx.Response(status_code=200, json=[])

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=[mock_response, mock_empty]) as mock_get:
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

        call_kwargs = mock_get.call_args_list[0].kwargs
        params = call_kwargs["params"]
        # Params is a list of tuples
        param_dict = {}
        for k, v in params:
            param_dict.setdefault(k, []).append(v)

        assert "order" in param_dict and param_dict["order"][0] == "timestamp.asc,id.asc"
        assert "limit" in param_dict and param_dict["limit"][0] == "50"
        assert "offset" in param_dict and param_dict["offset"][0] == "10"
        assert "sensor_id" in param_dict and param_dict["sensor_id"][0] == "eq.US_UPSTREAM_01"
        assert "source" in param_dict and param_dict["source"][0] == "in.(PHYSICAL,LIVE)"
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
        RATE_LIMIT_KEY_PEPPER="sufficiently_long_production_pepper_1234",
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


# --------------------------------------------------------------------
# 7. Phase 3.2.1: Supabase Bounded Pagination & Error Hardening
# --------------------------------------------------------------------

@pytest.mark.anyio
async def test_supabase_pagination_7200_records_over_multiple_pages():
    """Verify 7,200 records are fetched across 8 discrete pages of <= 1,000 records each."""
    repo = PersistenceRepository(
        supabase_url="https://mock-project.supabase.co",
        supabase_key="anon-key",
    )

    t0 = datetime(2026, 11, 13, 10, 0, 0, tzinfo=timezone.utc)
    table_10000 = [
        {
            "id": i,
            "sensor_id": "US_UPSTREAM_01",
            "value": 10.0 + i * 0.01,
            "timestamp": (t0 + timedelta(seconds=i)).isoformat(),
            "source": "PHYSICAL",
            "status": "OK",
            "unit": "cm",
        }
        for i in range(10000)
    ]

    # Simulated server dataset with 10,000 records
    def mock_get_handler(url, params=None, headers=None):
        param_dict = dict(params or [])
        limit_val = int(param_dict.get("limit", 1000))
        assert limit_val <= 1000, f"Page limit {limit_val} exceeded 1,000 record ceiling"
        slice_data = filter_mock_postgrest(table_10000, params)
        return httpx.Response(status_code=200, json=slice_data)

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=mock_get_handler) as mock_get:
        results = await repo.query_historical_telemetry(
            sensor_id="US_UPSTREAM_01",
            source="PHYSICAL",
            limit=7200,
            chronological=True,
        )

        assert len(results) == 7200
        # 7 full pages of 1,000 + 1 partial final page of 200 = 8 calls
        assert mock_get.call_count == 8

        # Verify ordering across page boundaries (page 1 boundary: record 999 to 1000)
        assert results[999]["id"] == 999
        assert results[1000]["id"] == 1000
        assert results[999]["timestamp"] < results[1000]["timestamp"]

        # Verify no duplicates
        ids = [r["id"] for r in results]
        assert len(ids) == len(set(ids))

        # Verify no skipped records
        assert ids == list(range(7200))


@pytest.mark.anyio
async def test_supabase_pagination_server_page_limit_and_filters():
    """Verify sensor, source, start_time, and end_time filters persist across every page."""
    repo = PersistenceRepository(
        supabase_url="https://mock-project.supabase.co",
        supabase_key="anon-key",
    )

    t_start = datetime(2026, 11, 13, 10, 0, 0, tzinfo=timezone.utc)
    t_end = datetime(2026, 11, 13, 12, 0, 0, tzinfo=timezone.utc)

    calls_received = []

    table_data = [
        {
            "id": i,
            "sensor_id": "US_UPSTREAM_01",
            "source": "PHYSICAL",
            "timestamp": (t_start + timedelta(seconds=i)).isoformat(),
        }
        for i in range(5000)
    ]

    def mock_get_handler(url, params=None, headers=None):
        param_list = params or []
        calls_received.append(param_list)
        slice_data = filter_mock_postgrest(table_data, param_list)
        return httpx.Response(status_code=200, json=slice_data)

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=mock_get_handler):
        results = await repo.query_historical_telemetry(
            sensor_id="US_UPSTREAM_01",
            source="PHYSICAL",
            start_time=t_start,
            end_time=t_end,
            limit=2500,
            chronological=True,
        )

        assert len(results) == 2500
        # 1000 + 1000 + 500 = 3 pages
        assert len(calls_received) == 3

        for call_params in calls_received:
            param_dict = dict(call_params)
            assert param_dict.get("sensor_id") == "eq.US_UPSTREAM_01"
            assert param_dict.get("source") == "in.(PHYSICAL,LIVE)"
            assert param_dict.get("order") == "timestamp.asc,id.asc"

            # Check timestamp filters
            ts_filters = [v for k, v in call_params if k == "timestamp"]
            assert any(f.startswith("gte.") for f in ts_filters)
            assert any(f.startswith("lte.") for f in ts_filters)


@pytest.mark.anyio
async def test_supabase_pagination_partial_and_empty_final_page():
    """Verify pagination terminates cleanly on partial or empty final page."""
    repo = PersistenceRepository(
        supabase_url="https://mock-project.supabase.co",
        supabase_key="anon-key",
    )
    t0 = datetime(2026, 11, 13, 10, 0, 0, tzinfo=timezone.utc)

    # 1. Partial final page: requested 2,500, but database only has 1,350 matching
    # Under Fix 4, non-empty partial page (350 records) continues until an empty page (0 records) or limit is reached.
    dataset_1350 = [
        {"id": i, "timestamp": (t0 + timedelta(seconds=i)).isoformat()}
        for i in range(1350)
    ]
    def mock_partial_page(url, params=None, headers=None):
        slice_data = filter_mock_postgrest(dataset_1350, params)
        return httpx.Response(status_code=200, json=slice_data)

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=mock_partial_page) as mock_get:
        results = await repo.query_historical_telemetry(sensor_id="US_UPSTREAM_01", limit=2500)
        assert len(results) == 1350
        # Page 1: 1000, Page 2: 350, Page 3: 0 (empty -> break) = 3 calls
        assert mock_get.call_count == 3

    # 2. Empty final page: table has exactly 1,000 records
    dataset_1000 = [
        {"id": i, "timestamp": (t0 + timedelta(seconds=i)).isoformat()}
        for i in range(1000)
    ]
    def mock_exact_page(url, params=None, headers=None):
        slice_data = filter_mock_postgrest(dataset_1000, params)
        return httpx.Response(status_code=200, json=slice_data)

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=mock_exact_page) as mock_get_exact:
        results = await repo.query_historical_telemetry(sensor_id="US_UPSTREAM_01", limit=2500)
        assert len(results) == 1000
        # Page 1: 1000 (fetch_count=1000), Page 2: 0 (fetch_count=1000, empty -> break) -> 2 calls
        assert mock_get_exact.call_count == 2


@pytest.mark.anyio
async def test_supabase_pagination_error_propagation_and_status():
    """Verify PostgREST errors raise RuntimeError with diagnostics and update last_persistence_error."""
    repo = PersistenceRepository(
        supabase_url="https://mock-project.supabase.co",
        supabase_key="anon-key",
    )

    # 1. HTTP 500 error raises RuntimeError
    mock_500 = httpx.Response(status_code=500, text="Internal Database Fault")
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_500):
        with pytest.raises(RuntimeError) as exc_info:
            await repo.query_historical_telemetry(sensor_id="US_UPSTREAM_01")
        assert "500" in str(exc_info.value)
        assert "Internal Database Fault" in str(exc_info.value)
        assert "500" in repo.get_status().last_persistence_error

    # 2. Network timeout raises RuntimeError
    with patch("httpx.AsyncClient.get", side_effect=httpx.ConnectTimeout("Gateway timed out")):
        with pytest.raises(RuntimeError) as exc_net:
            await repo.query_historical_telemetry(sensor_id="US_UPSTREAM_01")
        assert "Gateway timed out" in str(exc_net.value)
        assert "network error" in repo.get_status().last_persistence_error.lower()


def test_api_rollup_downstream_error_returns_502(client: TestClient):
    """Verify all 3 telemetry endpoints return generic 502 Bad Gateway without exposing internal DB error details."""
    repo = PersistenceRepository(
        supabase_url="https://mock-project.supabase.co",
        supabase_key="anon-key",
    )
    mock_500 = httpx.Response(status_code=500, text="Internal SQL syntax error in table public.sensor_readings at offset 0")

    with patch("app.api.v1.telemetry.persistence_repo", repo), patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_500):
        # 1. Rollup endpoint
        resp_rollup = client.get("/api/v1/telemetry/analytics/rollup?sensor_id=US_UPSTREAM_01")
        assert resp_rollup.status_code == 502
        assert resp_rollup.json()["detail"] == "Downstream database service unavailable"
        assert "sensor_readings" not in resp_rollup.json()["detail"]
        assert "SQL" not in resp_rollup.json()["detail"]

        # 2. Historical query endpoint
        resp_hist = client.get("/api/v1/telemetry/persistence/historical?sensor_id=US_UPSTREAM_01")
        assert resp_hist.status_code == 502
        assert resp_hist.json()["detail"] == "Downstream database service unavailable"
        assert "sensor_readings" not in resp_hist.json()["detail"]

        # 3. Trend endpoint
        resp_trend = client.get("/api/v1/telemetry/analytics/trend?sensor_id=US_UPSTREAM_01")
        assert resp_trend.status_code == 502
        assert resp_trend.json()["detail"] == "Downstream database service unavailable"
        assert "sensor_readings" not in resp_trend.json()["detail"]


@pytest.mark.anyio
async def test_supabase_pagination_identical_timestamps_across_page_boundaries():
    """Verify records sharing identical timestamps across page boundaries are neither duplicated nor skipped."""
    repo = PersistenceRepository(
        supabase_url="https://mock-project.supabase.co",
        supabase_key="anon-key",
    )
    repo.POSTGREST_PAGE_SIZE = 5

    # 10 records total.
    # Records 3, 4, 5, 6 share the identical timestamp!
    # Page boundary will fall between record index 4 and 5 (page 1: 0..4, page 2: 5..9).
    shared_ts = "2026-11-14T10:14:11.518167+00:00"
    all_table_data = [
        {"id": "rec_00", "timestamp": "2026-11-14T10:10:00.000000+00:00"},
        {"id": "rec_01", "timestamp": "2026-11-14T10:11:00.000000+00:00"},
        {"id": "rec_02", "timestamp": "2026-11-14T10:12:00.000000+00:00"},
        {"id": "rec_03", "timestamp": shared_ts},
        {"id": "rec_04", "timestamp": shared_ts},
        {"id": "rec_05", "timestamp": shared_ts},
        {"id": "rec_06", "timestamp": shared_ts},
        {"id": "rec_07", "timestamp": "2026-11-14T10:16:00.000000+00:00"},
        {"id": "rec_08", "timestamp": "2026-11-14T10:17:00.000000+00:00"},
        {"id": "rec_09", "timestamp": "2026-11-14T10:18:00.000000+00:00"},
    ]

    # Deterministic sorting simulator matching PostgREST: (timestamp asc, id asc)
    def mock_get_tiebreaker(url, params=None, headers=None):
        param_dict = dict(params or [])
        assert param_dict.get("order") == "timestamp.asc,id.asc", "Must use deterministic secondary sort key"
        slice_data = filter_mock_postgrest(all_table_data, params)
        return httpx.Response(status_code=200, json=slice_data)

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=mock_get_tiebreaker):
        results = await repo.query_historical_telemetry(limit=10, chronological=True)

        assert len(results) == 10
        result_ids = [r["id"] for r in results]

        # Verify zero duplicates
        assert len(result_ids) == len(set(result_ids))

        # Verify no skipped records across page boundary
        expected_ids = ["rec_00", "rec_01", "rec_02", "rec_03", "rec_04", "rec_05", "rec_06", "rec_07", "rec_08", "rec_09"]
        assert result_ids == expected_ids


@pytest.mark.anyio
async def test_supabase_pagination_limit_reached_before_dataset_exhaustion():
    """Verify query stops immediately when requested limit is reached without fetching remaining data."""
    repo = PersistenceRepository(
        supabase_url="https://mock-project.supabase.co",
        supabase_key="anon-key",
    )

    # Table has 50,000 records
    t0 = datetime(2026, 11, 13, 10, 0, 0, tzinfo=timezone.utc)
    dataset = [
        {"id": i, "timestamp": (t0 + timedelta(seconds=i)).isoformat()}
        for i in range(5000)
    ]
    call_counts = 0

    def mock_large_dataset(url, params=None, headers=None):
        nonlocal call_counts
        call_counts += 1
        slice_data = filter_mock_postgrest(dataset, params)
        return httpx.Response(status_code=200, json=slice_data)

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=mock_large_dataset):
        results = await repo.query_historical_telemetry(sensor_id="US_UPSTREAM_01", limit=1500)
        assert len(results) == 1500
        # Page 1: 1000, Page 2: 500 = 2 calls
        assert call_counts == 2


@pytest.mark.anyio
async def test_in_memory_fallback_unaffected_by_pagination_hardening():
    """Verify unconfigured in-memory fallback continues to slice internal buffer cleanly without HTTP calls."""
    repo = PersistenceRepository(
        supabase_url=None,
        supabase_key=None,
    )

    t0 = datetime(2026, 11, 13, 10, 0, 0, tzinfo=timezone.utc)
    readings = [
        SensorReadingContract(
            sensor_id="US_UPSTREAM_01",
            section_id="SEC_SCREENING_01",
            sensor_type=SensorType.WATER_LEVEL,
            value=5.0 + i,
            unit=MeasurementUnit.CENTIMETRE,
            source=DataSource.PHYSICAL,
            status=SensorHealthStatus.OK,
            timestamp=t0 + timedelta(seconds=i),
        )
        for i in range(100)
    ]
    await repo.persist_readings(readings)

    # Should fetch slice [10:30] directly from in-memory records
    results = await repo.query_historical_telemetry(
        sensor_id="US_UPSTREAM_01",
        limit=20,
        offset=10,
        chronological=True,
    )
    assert len(results) == 20
    assert results[0]["value"] == 15.0 # i=10
    assert results[-1]["value"] == 34.0 # i=29


# ==============================================================================
# CodeRabbit PR #4 Regression Tests (Fixes 1-6)
# ==============================================================================

def test_api_timezone_awareness_enforcement(client: TestClient):
    """
    Fix 1: Verify endpoints reject naive datetimes with HTTP 400 and require timezone offsets.
    """
    # 1. /telemetry/persistence/historical
    # Naive start_time
    r1 = client.get("/api/v1/telemetry/persistence/historical?start_time=2026-11-14T10:00:00")
    assert r1.status_code == 400
    assert "start_time must be timezone-aware" in r1.json()["detail"]

    # Naive end_time
    r2 = client.get("/api/v1/telemetry/persistence/historical?end_time=2026-11-14T10:00:00")
    assert r2.status_code == 400
    assert "end_time must be timezone-aware" in r2.json()["detail"]

    # Timezone-aware but start > end
    r3 = client.get(
        "/api/v1/telemetry/persistence/historical?start_time=2026-11-14T11:00:00Z&end_time=2026-11-14T10:00:00Z"
    )
    assert r3.status_code == 400
    assert "start_time must not be later than end_time" in r3.json()["detail"]

    # Valid timezone-aware bounds
    r4 = client.get(
        "/api/v1/telemetry/persistence/historical?start_time=2026-11-14T10:00:00Z&end_time=2026-11-14T11:00:00Z"
    )
    assert r4.status_code == 200

    # 2. /telemetry/analytics/rollup
    # Naive start_time
    r5 = client.get(
        "/api/v1/telemetry/analytics/rollup?sensor_id=US_UPSTREAM_01&start_time=2026-11-14T10:00:00"
    )
    assert r5.status_code == 400
    assert "start_time must be timezone-aware" in r5.json()["detail"]

    # Naive end_time
    r6 = client.get(
        "/api/v1/telemetry/analytics/rollup?sensor_id=US_UPSTREAM_01&end_time=2026-11-14T10:00:00"
    )
    assert r6.status_code == 400
    assert "end_time must be timezone-aware" in r6.json()["detail"]

    # Valid timezone-aware bounds
    r7 = client.get(
        "/api/v1/telemetry/analytics/rollup?sensor_id=US_UPSTREAM_01&start_time=2026-11-14T10:00:00Z&end_time=2026-11-14T11:00:00Z"
    )
    assert r7.status_code == 200


@pytest.mark.anyio
async def test_source_filtering_physical_includes_live_and_simulated_exact():
    """
    Fix 2: Verify querying PHYSICAL or LIVE matches both PHYSICAL and LIVE records,
    while SIMULATED remains exact-match.
    """
    repo = PersistenceRepository(supabase_url=None, supabase_key=None)

    t0 = datetime(2026, 11, 14, 10, 0, 0, tzinfo=timezone.utc)
    records = [
        SensorReadingContract(
            sensor_id="US_UPSTREAM_01",
            section_id="SEC_01",
            sensor_type=SensorType.WATER_LEVEL,
            value=10.0,
            unit=MeasurementUnit.CENTIMETRE,
            source=DataSource.PHYSICAL,
            status=SensorHealthStatus.OK,
            timestamp=t0,
        ),
        SensorReadingContract(
            sensor_id="US_UPSTREAM_01",
            section_id="SEC_01",
            sensor_type=SensorType.WATER_LEVEL,
            value=11.0,
            unit=MeasurementUnit.CENTIMETRE,
            source=DataSource.LIVE,
            status=SensorHealthStatus.OK,
            timestamp=t0 + timedelta(seconds=1),
        ),
        SensorReadingContract(
            sensor_id="US_UPSTREAM_01",
            section_id="SEC_01",
            sensor_type=SensorType.WATER_LEVEL,
            value=12.0,
            unit=MeasurementUnit.CENTIMETRE,
            source=DataSource.SIMULATED,
            status=SensorHealthStatus.OK,
            timestamp=t0 + timedelta(seconds=2),
        ),
    ]
    await repo.persist_readings(records)

    # 1. In-memory: Query PHYSICAL -> returns PHYSICAL and LIVE
    res_phys = await repo.query_historical_telemetry(source="PHYSICAL")
    assert len(res_phys) == 2
    sources_phys = {r["source"] for r in res_phys}
    assert sources_phys == {"PHYSICAL", "LIVE"}

    # 2. In-memory: Query LIVE -> returns PHYSICAL and LIVE
    res_live = await repo.query_historical_telemetry(source="LIVE")
    assert len(res_live) == 2
    sources_live = {r["source"] for r in res_live}
    assert sources_live == {"PHYSICAL", "LIVE"}

    # 3. In-memory: Query SIMULATED -> returns only SIMULATED
    res_sim = await repo.query_historical_telemetry(source="SIMULATED")
    assert len(res_sim) == 1
    assert res_sim[0]["source"] == "SIMULATED"

    # 4. PostgREST remote query parameter check
    repo_cloud = PersistenceRepository(
        supabase_url="https://mock-project.supabase.co",
        supabase_key="anon-key",
    )
    mock_resp = httpx.Response(status_code=200, json=[])

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp) as mock_get:
        await repo_cloud.query_historical_telemetry(source="PHYSICAL", limit=10)
        params = dict(mock_get.call_args.kwargs["params"])
        assert params.get("source") == "in.(PHYSICAL,LIVE)"

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp) as mock_get:
        await repo_cloud.query_historical_telemetry(source="LIVE", limit=10)
        params = dict(mock_get.call_args.kwargs["params"])
        assert params.get("source") == "in.(PHYSICAL,LIVE)"

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp) as mock_get:
        await repo_cloud.query_historical_telemetry(source="SIMULATED", limit=10)
        params = dict(mock_get.call_args.kwargs["params"])
        assert params.get("source") == "eq.SIMULATED"


@pytest.mark.anyio
async def test_malformed_json_response_handling_and_diagnostics():
    """
    Fix 3: Catch JSON decoding errors from PostgREST, chain RuntimeError,
    record diagnostic in _last_persistence_error, validate response is a list,
    and only clear _last_persistence_error when valid.
    """
    repo = PersistenceRepository(
        supabase_url="https://mock-project.supabase.co",
        supabase_key="anon-key",
    )

    # 1. PostgREST returns non-JSON raw HTML/text with 200 OK
    mock_bad_json = httpx.Response(status_code=200, text="<html>502 Bad Gateway from Cloudflare</html>")
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_bad_json):
        with pytest.raises(RuntimeError) as exc_info:
            await repo.query_historical_telemetry(limit=10)
        assert "malformed JSON" in str(exc_info.value)
        assert exc_info.value.__cause__ is not None  # chained exception
        assert "malformed JSON" in repo.get_status().last_persistence_error

    # 2. PostgREST returns JSON object instead of list
    mock_dict_json = httpx.Response(status_code=200, json={"code": "PGRST100", "message": "Unknown error"})
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_dict_json):
        with pytest.raises(RuntimeError) as exc_info:
            await repo.query_historical_telemetry(limit=10)
        assert "unexpected non-list data" in str(exc_info.value)
        assert "unexpected non-list data" in repo.get_status().last_persistence_error

    # 3. PostgREST returns valid list -> clears _last_persistence_error
    mock_valid_json = httpx.Response(status_code=200, json=[])
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_valid_json):
        results = await repo.query_historical_telemetry(limit=10)
        assert results == []
        assert repo.get_status().last_persistence_error is None


@pytest.mark.anyio
async def test_short_non_empty_pages_continue_until_limit_satisfied():
    """
    Fix 4: Verify pagination does NOT prematurely terminate when a page returns
    fewer records than fetch_count, continuing until limit is satisfied or page is empty.
    """
    repo = PersistenceRepository(
        supabase_url="https://mock-project.supabase.co",
        supabase_key="anon-key",
    )
    t0 = datetime(2026, 11, 14, 10, 0, 0, tzinfo=timezone.utc)

    # Server returns 3 pages of 50 records each for a requested limit of 150
    p1 = [{"id": f"p1_{i}", "timestamp": (t0 + timedelta(seconds=i)).isoformat()} for i in range(50)]
    p2 = [{"id": f"p2_{i}", "timestamp": (t0 + timedelta(seconds=50 + i)).isoformat()} for i in range(50)]
    p3 = [{"id": f"p3_{i}", "timestamp": (t0 + timedelta(seconds=100 + i)).isoformat()} for i in range(50)]

    responses = [
        httpx.Response(status_code=200, json=p1),
        httpx.Response(status_code=200, json=p2),
        httpx.Response(status_code=200, json=p3),
    ]

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=responses) as mock_get:
        results = await repo.query_historical_telemetry(limit=150)
        assert len(results) == 150
        assert mock_get.call_count == 3
        assert results[0]["id"] == "p1_0"
        assert results[49]["id"] == "p1_49"
        assert results[50]["id"] == "p2_0"
        assert results[99]["id"] == "p2_49"
        assert results[100]["id"] == "p3_0"
        assert results[149]["id"] == "p3_49"


@pytest.mark.anyio
async def test_keyset_pagination_descending_and_initial_offset():
    """
    Fix 5: Verify keyset pagination with descending order (chronological=False)
    and that initial offset is applied only on Page 1.
    """
    repo = PersistenceRepository(
        supabase_url="https://mock-project.supabase.co",
        supabase_key="anon-key",
    )
    repo.POSTGREST_PAGE_SIZE = 5

    t0 = datetime(2026, 11, 14, 10, 0, 0, tzinfo=timezone.utc)
    # 20 records in descending order
    dataset = [
        {
            "id": f"rec_{i:02d}",
            "timestamp": (t0 - timedelta(seconds=i)).isoformat(),
        }
        for i in range(20)
    ]

    calls_params = []
    def mock_desc_handler(url, params=None, headers=None):
        param_list = params or []
        calls_params.append(dict(param_list))
        slice_data = filter_mock_postgrest(dataset, param_list)
        return httpx.Response(status_code=200, json=slice_data)

    with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=mock_desc_handler):
        results = await repo.query_historical_telemetry(limit=10, offset=2, chronological=False)
        assert len(results) == 10
        # Call 1 should have offset=2, limit=5, order=timestamp.desc,id.desc
        assert calls_params[0]["offset"] == "2"
        assert calls_params[0]["order"] == "timestamp.desc,id.desc"
        assert "or" not in calls_params[0]

        # Call 2 should NOT have offset, but should have keyset filter 'or' with timestamp.lt
        assert "offset" not in calls_params[1]
        assert "or" in calls_params[1]
        assert "timestamp.lt." in calls_params[1]["or"]
        assert "id.lt." in calls_params[1]["or"]


@pytest.mark.anyio
async def test_in_memory_timezone_aware_and_safe_datetime_parsing():
    """
    Fix 6: In-memory fallback handles mixed timezone strings (+05:30, -04:00, Z),
    safely handles malformed timestamps without crashing, and sorts deterministically by (datetime, id).
    """
    repo = PersistenceRepository(supabase_url=None, supabase_key=None)

    # 10:00:00 UTC represented with different offsets:
    # 10:00:00Z = 10:00 UTC
    # 15:30:00+05:30 = 10:00 UTC
    # 06:00:00-04:00 = 10:00 UTC
    # 10:00:01Z = 10:00:01 UTC
    # corrupt = malformed
    readings = [
        {"id": "b_utc", "timestamp": "2026-11-14T10:00:00Z", "sensor_id": "US_01", "source": "PHYSICAL"},
        {"id": "a_ist", "timestamp": "2026-11-14T15:30:00+05:30", "sensor_id": "US_01", "source": "PHYSICAL"},
        {"id": "c_edt", "timestamp": "2026-11-14T06:00:00-04:00", "sensor_id": "US_01", "source": "PHYSICAL"},
        {"id": "d_later", "timestamp": "2026-11-14T10:00:01Z", "sensor_id": "US_01", "source": "PHYSICAL"},
        {"id": "e_corrupt", "timestamp": "not-a-valid-timestamp", "sensor_id": "US_01", "source": "PHYSICAL"},
    ]
    repo._in_memory_records = list(readings)

    # Query with exact time window [10:00:00Z, 10:00:00Z]
    t_exact = datetime(2026, 11, 14, 10, 0, 0, tzinfo=timezone.utc)
    results = await repo.query_historical_telemetry(
        sensor_id="US_01",
        start_time=t_exact,
        end_time=t_exact,
        chronological=True,
    )

    # Should match a_ist, b_utc, and c_edt because all 3 represent 10:00:00 UTC
    # e_corrupt is safely excluded; d_later is excluded (1 second later)
    assert len(results) == 3
    # Sorting tie-break by ID: a_ist, b_utc, c_edt
    assert [r["id"] for r in results] == ["a_ist", "b_utc", "c_edt"]

    # Sorting test with malformed record included (unbounded query):
    all_res = await repo.query_historical_telemetry(sensor_id="US_01", chronological=True)
    assert len(all_res) == 5
    # e_corrupt defaults to datetime.min so it appears first in ascending order
    assert all_res[0]["id"] == "e_corrupt"


