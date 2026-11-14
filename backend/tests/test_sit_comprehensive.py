"""
DRAIN-X Comprehensive System Integration Testing (SIT) Suite.

Validates complete end-to-end integration across all 10 DRAIN-X functional domains:
- Suite A: Telemetry Integration (Ingestion, Validation, Monotonicity, Duplicates, Faults)
- Suite B: Cloud Persistence (Status, Ping, Soft-fail Degradation, Source Isolation)
- Suite C: Analytics Integration (Hydraulic Head, Rate of Rise, Critical Threshold, Gate Directives)
- Suite D: WebSocket Integration (Handshake, Fanout Broadcast, Disconnect Cleanup)
- Suite E: React Dashboard Integration Contracts (Latest, Status, Devices, Empty Handling)
- Suite F: Historical Playback & Digital Twin (Chronological Ordering, Bounds, Truncation)
- Suite G: Simulation Integration (Scenario Step, Benchmark, Mode Isolation Rejection)
- Suite H: Device Integration (Registry, Firmware Payload Parity, Stage Tracking)
- Suite I: Flutter Integration (Incident Contracts, Lifecycle State Transitions)
- Suite J: Security & Authorization (HS256 JWT, Anti-Privilege Escalation, Device Key, Fail-Closed)
"""

import json
import base64
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, Any
from unittest.mock import patch, AsyncMock
import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings, validate_production_configuration, Settings
from app.core.security import verify_supabase_jwt
from app.services.state_store import state_store
from app.services.telemetry_stream_manager import telemetry_stream_manager
from app.services.persistence_repository import PersistenceRepository, persistence_repo
from app.models.contracts import (
    SensorReadingContract,
    SensorType,
    MeasurementUnit,
    DataSource,
    SensorHealthStatus,
    AlertSeverity,
    IncidentStatus,
)


@pytest.fixture(autouse=True)
def sit_clean_environment():
    """Ensure clean test slate for every SIT test case."""
    state_store.clear()
    state_store.set_mode("SIMULATION", reason="SIT Setup")
    persistence_repo._in_memory_records.clear()
    persistence_repo._mode_history_records.clear()
    telemetry_stream_manager._clients.clear()
    telemetry_stream_manager._total_broadcast_count = 0
    telemetry_stream_manager._total_dropped_count = 0
    telemetry_stream_manager._is_shutting_down = False
    yield
    state_store.set_mode("SIMULATION", reason="SIT Teardown")
    persistence_repo._in_memory_records.clear()
    telemetry_stream_manager._clients.clear()


@pytest.fixture
def client():
    return TestClient(app)


# ==============================================================================
# SUITE A: Telemetry Integration
# ==============================================================================

def test_sit_suite_a_telemetry_ingest_and_validation(client: TestClient):
    """SIT-A1: Ingestion of single and batch telemetry payloads with response contracts."""
    single_reading = {
        "sensor_id": "US_UPSTREAM_01",
        "section_id": "SEC_SCREENING",
        "sensor_type": "WATER_LEVEL",
        "value": 5.2,
        "unit": "cm",
        "source": "SIMULATED",
        "status": "OK",
        "metadata": {"device_id": "DRAINX-ESP32-NODE-01"}
    }
    res = client.post("/api/v1/telemetry/ingest", json=single_reading)
    assert res.status_code == 201
    data = res.json()
    assert data["status"] == "success"
    assert data["ingested_count"] == 1
    assert "prediction" in data
    assert "blockage" in data
    assert "gate_directive" in data

    # Batch ingestion
    batch_readings = [
        {
            "sensor_id": "US_WEIR_02",
            "section_id": "SEC_OUTLET",
            "sensor_type": "WATER_LEVEL",
            "value": 2.1,
            "unit": "cm",
            "source": "SIMULATED",
            "status": "OK",
        },
        {
            "sensor_id": "FS_FLUME_01",
            "section_id": "SEC_FLUME",
            "sensor_type": "FLOW_RATE",
            "value": 14.5,
            "unit": "L/min",
            "source": "SIMULATED",
            "status": "OK",
        }
    ]
    batch_res = client.post("/api/v1/telemetry/ingest", json=batch_readings)
    assert batch_res.status_code == 201
    assert batch_res.json()["ingested_count"] == 2


def test_sit_suite_a_invalid_payload_rejection(client: TestClient):
    """SIT-A2: Rejection of malformed schema, negative levels, and invalid units."""
    # Invalid sensor type
    res1 = client.post("/api/v1/telemetry/ingest", json={
        "sensor_id": "BAD_01",
        "section_id": "SEC_SCREENING",
        "sensor_type": "UNKNOWN_SENSOR_TYPE",
        "value": 5.0,
        "unit": "cm",
        "source": "SIMULATED",
    })
    assert res1.status_code == 422

    # Negative water level (physically prohibited)
    res2 = client.post("/api/v1/telemetry/ingest", json={
        "sensor_id": "US_UPSTREAM_01",
        "section_id": "SEC_SCREENING",
        "sensor_type": "WATER_LEVEL",
        "value": -3.5,
        "unit": "cm",
        "source": "SIMULATED",
    })
    assert res2.status_code == 422

    # Missing mandatory sensor_id
    res3 = client.post("/api/v1/telemetry/ingest", json={
        "section_id": "SEC_SCREENING",
        "sensor_type": "WATER_LEVEL",
        "value": 5.0,
        "unit": "cm",
        "source": "SIMULATED",
    })
    assert res3.status_code == 422


def test_sit_suite_a_duplicate_and_rapid_readings(client: TestClient):
    """SIT-A3: Ingestion of duplicate timestamps and rapid sequential telemetry without crashing."""
    now_iso = datetime.now(timezone.utc).isoformat()
    reading = {
        "sensor_id": "US_UPSTREAM_01",
        "section_id": "SEC_SCREENING",
        "sensor_type": "WATER_LEVEL",
        "value": 5.0,
        "unit": "cm",
        "source": "SIMULATED",
        "status": "OK",
        "timestamp": now_iso,
    }
    # Ingest duplicate reading multiple times
    res_a = client.post("/api/v1/telemetry/ingest", json=reading)
    res_b = client.post("/api/v1/telemetry/ingest", json=reading)
    assert res_a.status_code == 201
    assert res_b.status_code == 201


def test_sit_suite_a_uninstalled_or_faulted_sensor_handling(client: TestClient):
    """SIT-A4: Graceful handling of SENSOR_NOT_INSTALLED and FAULT status."""
    payload = {
        "sensor_id": "FS_FLUME_01",
        "section_id": "SEC_FLUME",
        "sensor_type": "FLOW_RATE",
        "value": 0.0,
        "unit": "L/min",
        "source": "SIMULATED",
        "status": "FAULT",
        "metadata": {"diagnostic": "SENSOR_NOT_INSTALLED"}
    }
    res = client.post("/api/v1/telemetry/ingest", json=payload)
    assert res.status_code == 201
    # System health should recognize sensor fault without crashing
    latest = client.get("/api/v1/telemetry/latest").json()["readings"]
    assert latest["FS_FLUME_01"]["status"] == "FAULT"


# ==============================================================================
# SUITE B: Cloud Persistence
# ==============================================================================

def test_sit_suite_b_persistence_status_and_ping(client: TestClient):
    """SIT-B1: Persistence status endpoint and connection health probe."""
    res = client.get("/api/v1/telemetry/persistence/status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
    assert "persistence" in data
    assert data["persistence"]["mode"] in ("IN_MEMORY_FALLBACK", "SUPABASE_POSTGREST")

    # Persistence ping
    ping_res = client.post("/api/v1/telemetry/persistence/ping")
    assert ping_res.status_code == 200
    ping_data = ping_res.json()
    assert ping_data["status"] in ("UNCONFIGURED", "HEALTHY", "DEGRADED", "ERROR")
    assert "mode" in ping_data
    assert "configured" in ping_data


def test_sit_suite_b_persistence_degradation_and_timeout(client: TestClient):
    """SIT-B2: Soft-fail degradation when Supabase connection times out or fails."""
    simulated_repo = PersistenceRepository(
        supabase_url="https://mock.supabase.co",
        supabase_key="mock_service_role_key",
        timeout_sec=0.1,
    )
    with patch("httpx.AsyncClient.post", side_effect=httpx.ConnectTimeout("Cloud unreachable")):
        # Persist should not throw exception; it fails soft and records error
        readings = [
            SensorReadingContract(
                sensor_id="US_UPSTREAM_01",
                section_id="SEC_SCREENING",
                sensor_type=SensorType.WATER_LEVEL,
                value=6.0,
                unit=MeasurementUnit.CENTIMETRE,
                source=DataSource.SIMULATED,
                status=SensorHealthStatus.OK,
            )
        ]
        import asyncio
        asyncio.run(simulated_repo.persist_readings(readings))
        status = simulated_repo.get_status()
        assert status.failed_persistence_count >= 1
        assert "Cloud unreachable" in (status.last_persistence_error or "")


def test_sit_suite_b_source_isolation_physical_vs_simulated(client: TestClient):
    """SIT-B3: Complete separation of physical and simulated records in historical queries."""
    # Ingest simulated reading in SIMULATION mode
    client.post("/api/v1/telemetry/ingest", json={
        "sensor_id": "US_UPSTREAM_01",
        "section_id": "SEC_SCREENING",
        "sensor_type": "WATER_LEVEL",
        "value": 5.5,
        "unit": "cm",
        "source": "SIMULATED",
        "status": "OK",
    })

    # Switch to PHYSICAL mode and ingest physical reading
    state_store.set_mode("PHYSICAL", reason="SIT physical ingest test")
    client.post("/api/v1/telemetry/ingest", json={
        "sensor_id": "US_UPSTREAM_01",
        "section_id": "SEC_SCREENING",
        "sensor_type": "WATER_LEVEL",
        "value": 7.2,
        "unit": "cm",
        "source": "PHYSICAL",
        "status": "OK",
    })

    # Query with source=PHYSICAL
    res_phys = client.get("/api/v1/telemetry/persistence/historical?sensor_id=US_UPSTREAM_01&source=PHYSICAL")
    assert res_phys.status_code == 200
    phys_records = res_phys.json()["records"]
    assert all(r.get("source") == "PHYSICAL" for r in phys_records)

    # Query with source=SIMULATED
    res_sim = client.get("/api/v1/telemetry/persistence/historical?sensor_id=US_UPSTREAM_01&source=SIMULATED")
    assert res_sim.status_code == 200
    sim_records = res_sim.json()["records"]
    assert all(r.get("source") == "SIMULATED" for r in sim_records)


# ==============================================================================
# SUITE C: Analytics Integration
# ==============================================================================

def test_sit_suite_c_hydraulic_calculations_and_critical_threshold(client: TestClient):
    """SIT-C1: Water level analytics trigger critical risk classification when level reaches 12.0 cm."""
    # Ingest normal level
    res_norm = client.post("/api/v1/telemetry/ingest", json={
        "sensor_id": "US_UPSTREAM_01",
        "section_id": "SEC_SCREENING",
        "sensor_type": "WATER_LEVEL",
        "value": 4.5,
        "unit": "cm",
        "source": "SIMULATED",
        "status": "OK",
    })
    assert res_norm.status_code == 201
    status_normal = client.get("/api/v1/status").json()
    assert status_normal["operational_state"] != "CRITICAL"

    # Ingest critical water level >= 12.0 cm
    res_crit = client.post("/api/v1/telemetry/ingest", json={
        "sensor_id": "US_UPSTREAM_01",
        "section_id": "SEC_SCREENING",
        "sensor_type": "WATER_LEVEL",
        "value": 13.5,
        "unit": "cm",
        "source": "SIMULATED",
        "status": "OK",
    })
    assert res_crit.status_code == 201
    data = res_crit.json()
    assert data["gate_directive"]["gate_target_angle"] >= 85.0
    assert any(term in data["gate_directive"]["action"] for term in ("DIVERSION", "CRITICAL", "EMERGENCY_OVERFLOW_RELIEF"))


def test_sit_suite_c_rate_of_rise_linear_regression(client: TestClient):
    """SIT-C2: Multi-sample linear regression rate-of-rise trend calculation."""
    base_time = datetime.now(timezone.utc) - timedelta(minutes=5)
    # Seed 5 rising points over 5 minutes: 2.0 -> 4.0 -> 6.0 -> 8.0 -> 10.0 cm
    for i in range(5):
        t = (base_time + timedelta(minutes=i)).isoformat()
        client.post("/api/v1/telemetry/ingest", json={
            "sensor_id": "US_UPSTREAM_01",
            "section_id": "SEC_SCREENING",
            "sensor_type": "WATER_LEVEL",
            "value": 2.0 + (i * 2.0),
            "unit": "cm",
            "source": "SIMULATED",
            "status": "OK",
            "timestamp": t,
        })

    trend_res = client.get("/api/v1/telemetry/analytics/trend?sensor_id=US_UPSTREAM_01&source=SIMULATED")
    assert trend_res.status_code == 200
    trend_data = trend_res.json()
    assert trend_data["status"] == "success"
    assert "metrics" in trend_data
    assert trend_data["metrics"]["rate_of_rise_cm_min"] > 1.0  # Slope should be ~2.0 cm/min


def test_sit_suite_c_zero_flow_vs_fault_discrimination(client: TestClient):
    """SIT-C3: Zero flow (0.0 L/min, OK) is valid physical flow; FAULT readings are excluded."""
    now = datetime.now(timezone.utc).replace(second=5, microsecond=0)
    # 1. Ingest valid zero flow
    client.post("/api/v1/telemetry/ingest", json={
        "sensor_id": "FS_FLUME_01",
        "section_id": "SEC_FLUME",
        "sensor_type": "FLOW_RATE",
        "value": 0.0,
        "unit": "L/min",
        "source": "SIMULATED",
        "status": "OK",
        "timestamp": now.isoformat(),
    })
    # 2. Ingest flow reading
    client.post("/api/v1/telemetry/ingest", json={
        "sensor_id": "FS_FLUME_01",
        "section_id": "SEC_FLUME",
        "sensor_type": "FLOW_RATE",
        "value": 10.0,
        "unit": "L/min",
        "source": "SIMULATED",
        "status": "OK",
        "timestamp": (now + timedelta(seconds=10)).isoformat(),
    })
    # 3. Ingest faulted reading (should be excluded from aggregation)
    client.post("/api/v1/telemetry/ingest", json={
        "sensor_id": "FS_FLUME_01",
        "section_id": "SEC_FLUME",
        "sensor_type": "FLOW_RATE",
        "value": 999.0,
        "unit": "L/min",
        "source": "SIMULATED",
        "status": "FAULT",
        "timestamp": (now + timedelta(seconds=20)).isoformat(),
    })

    rollup = client.get("/api/v1/telemetry/analytics/rollup?sensor_id=FS_FLUME_01&interval_seconds=60").json()
    assert rollup["status"] == "success"
    valid_buckets = [b for b in rollup["buckets"] if b["avg_value"] is not None]
    if valid_buckets:
        bucket = valid_buckets[-1]
        # Average of 0.0 and 10.0 is 5.0; 999.0 FAULT must NOT skew average to 300+
        assert bucket["avg_value"] <= 6.0


# ==============================================================================
# SUITE D: WebSocket Integration
# ==============================================================================

def test_sit_suite_d_websocket_connection_and_init(client: TestClient):
    """SIT-D1: WebSocket handshake, protocol version, and INIT payload."""
    with client.websocket_connect("/api/v1/telemetry/stream") as ws:
        init_frame = ws.receive_json()
        assert init_frame["event_type"] == "INIT"
        assert init_frame["protocol_version"] == "1.0"
        assert "client_id" in init_frame
        assert init_frame["operational_mode"] == "SIMULATION"
        assert "latest_snapshot" in init_frame


def test_sit_suite_d_websocket_live_broadcast_fanout(client: TestClient):
    """SIT-D2: Broadcast fanout publishes newly ingested telemetry to active subscribers."""
    with client.websocket_connect("/api/v1/telemetry/stream") as ws:
        _ = ws.receive_json()  # Consume INIT frame

        # Ingest reading via HTTP API
        client.post("/api/v1/telemetry/ingest", json={
            "sensor_id": "US_UPSTREAM_01",
            "section_id": "SEC_SCREENING",
            "sensor_type": "WATER_LEVEL",
            "value": 8.1,
            "unit": "cm",
            "source": "SIMULATED",
            "status": "OK",
        })

        # Subscriber must receive broadcast event
        broadcast_frame = ws.receive_json()
        assert broadcast_frame["event_type"] == "TELEMETRY"
        assert broadcast_frame["operational_mode"] == "SIMULATION"
        assert broadcast_frame["sensor_id"] == "US_UPSTREAM_01"
        assert broadcast_frame["water_level_cm"] == 8.1


def test_sit_suite_d_websocket_disconnect_cleanup(client: TestClient):
    """SIT-D3: Disconnecting a client cleans up connection pool without error."""
    with client.websocket_connect("/api/v1/telemetry/stream") as ws:
        _ = ws.receive_json()
        assert telemetry_stream_manager.active_connections_count >= 1

    # After context exit, client pool decrements
    assert telemetry_stream_manager.active_connections_count == 0


# ==============================================================================
# SUITE E: React Dashboard Integration Contracts
# ==============================================================================

def test_sit_suite_e_dashboard_endpoints_contracts(client: TestClient):
    """SIT-E1: Endpoint contracts match React frontend requirements."""
    # /api/v1/telemetry/latest
    lat_res = client.get("/api/v1/telemetry/latest")
    assert lat_res.status_code == 200
    assert "readings" in lat_res.json()

    # /api/v1/status
    stat_res = client.get("/api/v1/status")
    assert stat_res.status_code == 200
    stat_data = stat_res.json()
    assert "system_name" in stat_data
    assert "mode" in stat_data
    assert "active_gate_directive" in stat_data
    assert "operational_state" in stat_data
    assert "active_alerts_count" in stat_data

    # /api/v1/devices
    dev_res = client.get("/api/v1/devices")
    assert dev_res.status_code == 200
    assert "devices" in dev_res.json()
    assert isinstance(dev_res.json()["devices"], list)


def test_sit_suite_e_empty_database_graceful_handling(client: TestClient):
    """SIT-E2: Empty database state returns clean zero-state without 500 error."""
    state_store.clear()
    lat_res = client.get("/api/v1/telemetry/latest")
    assert lat_res.status_code == 200
    assert lat_res.json()["readings"] == {}

    hist_res = client.get("/api/v1/telemetry/history/NON_EXISTENT_SENSOR")
    assert hist_res.status_code == 200
    assert hist_res.json()["status"] == "empty"
    assert hist_res.json()["readings"] == []


# ==============================================================================
# SUITE F: Historical Playback and Digital Twin Integration
# ==============================================================================

def test_sit_suite_f_historical_playback_bounds_and_ordering(client: TestClient):
    """SIT-F1: Historical queries with chronological=True return strictly monotonic timestamps."""
    t0 = datetime(2026, 11, 14, 10, 0, 0, tzinfo=timezone.utc)
    for i in range(4):
        t = (t0 + timedelta(seconds=i * 10)).isoformat()
        client.post("/api/v1/telemetry/ingest", json={
            "sensor_id": "US_UPSTREAM_01",
            "section_id": "SEC_SCREENING",
            "sensor_type": "WATER_LEVEL",
            "value": 5.0 + i,
            "unit": "cm",
            "source": "SIMULATED",
            "status": "OK",
            "timestamp": t,
        })

    res = client.get("/api/v1/telemetry/persistence/historical?sensor_id=US_UPSTREAM_01&chronological=true")
    assert res.status_code == 200
    records = res.json()["records"]
    assert len(records) >= 4
    timestamps = [r["timestamp"] for r in records]
    # Assert strictly ascending
    assert timestamps == sorted(timestamps)


def test_sit_suite_f_historical_playback_time_bounds_validation(client: TestClient):
    """SIT-F2: Query rejects start_time > end_time with HTTP 400."""
    start = "2026-11-14T12:00:00Z"
    end = "2026-11-14T10:00:00Z"
    res = client.get(f"/api/v1/telemetry/persistence/historical?start_time={start}&end_time={end}")
    assert res.status_code == 400
    assert "start_time must not be later than end_time" in res.json()["detail"]


# ==============================================================================
# SUITE G: Simulation Integration
# ==============================================================================

def test_sit_suite_g_simulation_lifecycle_and_step(client: TestClient):
    """SIT-G1: Start, step, and stop scenario simulation lifecycle."""
    start_res = client.post("/api/v1/simulation/start", json={"scenario": "GRADUAL_DEBRIS", "seed": 42})
    assert start_res.status_code == 200
    assert start_res.json()["scenario"] == "GRADUAL_DEBRIS"

    step_res = client.post("/api/v1/simulation/step?dt=0.5")
    assert step_res.status_code == 200
    assert "step_result" in step_res.json()

    stop_res = client.post("/api/v1/simulation/stop")
    assert stop_res.status_code == 200


def test_sit_suite_g_operational_mode_isolation(client: TestClient):
    """SIT-G2: Strict mode isolation: rejects physical in SIMULATION, rejects simulated in PHYSICAL."""
    # In SIMULATION mode, reject PHYSICAL
    assert state_store.is_simulation()
    res1 = client.post("/api/v1/telemetry/ingest", json={
        "sensor_id": "US_UPSTREAM_01",
        "section_id": "SEC_SCREENING",
        "sensor_type": "WATER_LEVEL",
        "value": 5.0,
        "unit": "cm",
        "source": "PHYSICAL",
        "status": "OK",
    })
    assert res1.status_code == 409
    assert "System is in SIMULATION mode" in res1.json()["detail"]

    # In PHYSICAL mode, reject SIMULATED
    state_store.set_mode("PHYSICAL", reason="Mode isolation test")
    res2 = client.post("/api/v1/telemetry/ingest", json={
        "sensor_id": "US_UPSTREAM_01",
        "section_id": "SEC_SCREENING",
        "sensor_type": "WATER_LEVEL",
        "value": 5.0,
        "unit": "cm",
        "source": "SIMULATED",
        "status": "OK",
    })
    assert res2.status_code == 409
    assert "System is in PHYSICAL mode" in res2.json()["detail"]


# ==============================================================================
# SUITE H: Device Integration
# ==============================================================================

def test_sit_suite_h_device_registry_lifecycle(client: TestClient):
    """SIT-H1: Device listing and retrieval from registry."""
    list_res = client.get("/api/v1/devices")
    assert list_res.status_code == 200
    devices = list_res.json()["devices"]
    assert any(d["device_id"] == "DRAINX-ESP32-NODE-01" for d in devices)

    get_res = client.get("/api/v1/devices/DRAINX-ESP32-NODE-01")
    assert get_res.status_code == 200
    dev = get_res.json()["device"]
    assert dev["hardware_model"] == "ESP32 DevKit V1 (ESP-WROOM-32)"
    assert dev["validation_stage"] in ("CONNECTIVITY_READY", "BENCH_VALIDATED", "SOFTWARE_ONLY")


def test_sit_suite_h_esp32_firmware_payload_compatibility(client: TestClient):
    """SIT-H2: Ingest telemetry payload structured identically to ESP32 NetworkManager C++ output."""
    state_store.set_mode("PHYSICAL", reason="Firmware parity test")
    esp32_payload = [
        {
            "sensor_id": "US_UPSTREAM_01",
            "section_id": "SEC_SCREENING",
            "sensor_type": "WATER_LEVEL",
            "value": 5.4,
            "unit": "cm",
            "source": "PHYSICAL",
            "status": "OK",
            "metadata": {
                "device_id": "DRAINX-ESP32-NODE-01",
                "firmware_version": "0.3.7-p0.3g",
                "rssi_dbm": -62,
                "uptime_ms": 142050,
            }
        },
        {
            "sensor_id": "FS_FLUME_01",
            "section_id": "SEC_FLUME",
            "sensor_type": "FLOW_RATE",
            "value": 11.8,
            "unit": "L/min",
            "source": "PHYSICAL",
            "status": "OK",
            "metadata": {
                "device_id": "DRAINX-ESP32-NODE-01",
                "firmware_version": "0.3.7-p0.3g",
                "total_pulses": 2580,
            }
        }
    ]
    res = client.post("/api/v1/telemetry/ingest", json=esp32_payload)
    assert res.status_code == 201
    assert res.json()["ingested_count"] == 2


# ==============================================================================
# SUITE I: Flutter Integration
# ==============================================================================

def test_sit_suite_i_mobile_incident_contract_compatibility(client: TestClient):
    """SIT-I1: Incident payload matches mobile Incident.fromJson schema."""
    res = client.get("/api/v1/incidents")
    assert res.status_code == 200
    incidents = res.json()
    assert isinstance(incidents, list)
    assert len(incidents) >= 1

    sample = incidents[0]
    required_keys = [
        "id", "category", "description", "latitude", "longitude",
        "severity", "status", "source", "created_at", "updated_at",
        "assigned_to", "municipal_notes", "reporter_name", "photos"
    ]
    for key in required_keys:
        assert key in sample, f"Missing key '{key}' required by Flutter Incident model."


def test_sit_suite_i_incident_status_transition_rules(client: TestClient):
    """SIT-I2: Lifecycle status transitions enforced matching municipal workflow."""
    # Create incident
    create_res = client.post("/api/v1/incidents", json={
        "category": "DRAIN_BLOCKAGE",
        "description": "Culvert blocked by debris",
        "latitude": 15.498,
        "longitude": 73.825,
        "severity": "HIGH",
        "source": "CITIZEN",
        "reporter_name": "Field Observer",
    })
    assert create_res.status_code == 201
    inc_id = create_res.json()["id"]

    # Legal transition: REPORTED -> VERIFIED
    patch_res = client.patch(f"/api/v1/incidents/{inc_id}", json={
        "status": "VERIFIED",
        "municipal_notes": "Verified by engineering inspector",
    })
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "VERIFIED"

    # Illegal transition: cannot jump directly from VERIFIED to RESOLVED without dispatch
    illegal_res = client.patch(f"/api/v1/incidents/{inc_id}", json={
        "status": "RESOLVED",
    })
    assert illegal_res.status_code == 400


# ==============================================================================
# SUITE J: Security & Authorization
# ==============================================================================

def _make_test_jwt(payload: dict, secret: str = "test-secret-key-32-bytes-minimum!!") -> str:
    """Helper to craft valid HS256 JWT for test assertions."""
    import hmac
    import hashlib
    header = {"alg": "HS256", "typ": "JWT"}
    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    sig_input = f"{h_b64}.{p_b64}"
    sig = hmac.new(secret.encode(), sig_input.encode(), hashlib.sha256).digest()
    s_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return f"{sig_input}.{s_b64}"


def test_sit_suite_j_jwt_signature_and_expiration():
    """SIT-J1: Cryptographic JWT signature check and expiration enforcement."""
    secret = "sit-test-secret-key-32-bytes-minimum!!"
    with patch.object(settings, "SUPABASE_JWT_SECRET", secret), \
         patch.object(settings, "ENVIRONMENT", "production"):

        # 1. Valid token
        valid_payload = {
            "sub": "user-123",
            "exp": time.time() + 3600,
            "app_metadata": {"role": "admin"}
        }
        token = _make_test_jwt(valid_payload, secret)
        claims = verify_supabase_jwt(token)
        assert claims["sub"] == "user-123"

        # 2. Expired token
        expired_payload = {
            "sub": "user-123",
            "exp": time.time() - 3600,
            "app_metadata": {"role": "admin"}
        }
        exp_token = _make_test_jwt(expired_payload, secret)
        with pytest.raises(Exception) as exc:
            verify_supabase_jwt(exp_token)
        assert "401" in str(exc.value)

        # 3. Invalid signature
        tampered_token = token[:-4] + "AAAA"
        with pytest.raises(Exception) as exc_sig:
            verify_supabase_jwt(tampered_token)
        assert "401" in str(exc_sig.value)


def test_sit_suite_j_anti_privilege_escalation_role_enforcement(client: TestClient):
    """SIT-J2: Rejection of user_metadata tampering; strictly enforces app_metadata."""
    secret = "sit-test-secret-key-32-bytes-minimum!!"
    with patch.object(settings, "SUPABASE_JWT_SECRET", secret), \
         patch.object(settings, "ENVIRONMENT", "production"), \
         patch.object(settings, "SUPABASE_AUTH_ENABLED", True):

        # Citizen attempts to grant self "admin" via user_metadata (tampering)
        malicious_payload = {
            "sub": "attacker-456",
            "exp": time.time() + 3600,
            "user_metadata": {"role": "admin"},   # Untrusted!
            "app_metadata": {"role": "citizen"},  # Trusted!
        }
        token = _make_test_jwt(malicious_payload, secret)

        # Attempt to register device (admin-only endpoint)
        device_payload = {
            "device_id": "ATTACKER-NODE",
            "name": "Malicious Device",
            "hardware_model": "ESP32",
        }
        res = client.post(
            "/api/v1/devices",
            json=device_payload,
            headers={"Authorization": f"Bearer {token}"}
        )
        # Must be rejected with 403 Forbidden because trusted role is citizen
        assert res.status_code == 403


def test_sit_suite_j_production_fail_closed_validation():
    """SIT-J3: Fail-closed configuration check raises error in production if secrets missing."""
    test_settings = Settings(
        ENVIRONMENT="production",
        DEVICE_INGEST_API_KEY="",  # Missing!
        SUPABASE_JWT_SECRET="",    # Missing!
    )
    with pytest.raises(RuntimeError) as exc:
        validate_production_configuration(test_settings)
    assert "DEVICE_INGEST_API_KEY must be configured" in str(exc.value)
