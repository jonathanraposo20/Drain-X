"""
DRAIN-X Persistence Layer & Supabase Adapter Unit Tests.

Milestone: P0.4A Backend Architecture & Telemetry Persistence Foundation.

Validates:
1. Persistence status reporting (reports unconfigured when env vars absent, without crashing).
2. Non-blocking/graceful fallback when Supabase credentials are not provided.
3. Batch telemetry serialization into database record schema.
4. Operational mode separation: PHYSICAL vs SIMULATED records are stored and queried separately.
5. Ingestion of uninstalled sensor reading (persists value=0.0, status=FAULT, fault_code=SENSOR_NOT_INSTALLED).
6. Graceful handling of network timeout/exceptions during PostgREST calls (soft failure, 0 crashes).
7. End-to-end API compatibility with GET /api/v1/telemetry/persistence/status and historical query endpoints.
"""

import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
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
def clean_mode():
    state_store.set_mode("SIMULATION", reason="Persistence test setup")
    yield
    state_store.set_mode("SIMULATION", reason="Persistence test cleanup")


def test_persistence_status_unconfigured_default():
    """Verify that by default, persistence runs in IN_MEMORY_FALLBACK mode without crashing."""
    repo = PersistenceRepository(supabase_url=None, supabase_key=None)
    status = repo.get_status()
    assert status.configured is False
    assert status.mode == "IN_MEMORY_FALLBACK"
    assert status.target_table == "sensor_readings"



@pytest.mark.anyio
async def test_persistence_batch_storage_and_source_isolation():
    """Verify that physical and simulated telemetry can be stored and queried independently."""
    repo = PersistenceRepository(
        supabase_url=None,
        supabase_key=None,
        service_role_key=None,
    )

    t_now = datetime.now(timezone.utc)

    sim_reading = SensorReadingContract(
        sensor_id="US_UPSTREAM_01",
        section_id="SEC_SCREENING_01",
        sensor_type=SensorType.WATER_LEVEL,
        value=4.6,
        unit=MeasurementUnit.CENTIMETRE,
        source=DataSource.SIMULATED,
        status=SensorHealthStatus.OK,
        timestamp=t_now,
        metadata={"device_id": "DRAINX-SIM-NODE"}
    )

    phys_reading = SensorReadingContract(
        sensor_id="US_UPSTREAM_01",
        section_id="SEC_SCREENING_01",
        sensor_type=SensorType.WATER_LEVEL,
        value=12.2,
        unit=MeasurementUnit.CENTIMETRE,
        source=DataSource.PHYSICAL,
        status=SensorHealthStatus.OK,
        timestamp=t_now,
        metadata={"device_id": "DRAINX-ESP32-NODE-01"}
    )

    count = await repo.persist_readings([sim_reading, phys_reading])
    assert count == 2

    sim_results = await repo.query_historical_telemetry(
        sensor_id="US_UPSTREAM_01",
        source="SIMULATED"
    )
    assert len(sim_results) >= 1
    assert all(r["source"] == "SIMULATED" for r in sim_results)

    phys_results = await repo.query_historical_telemetry(
        sensor_id="US_UPSTREAM_01",
        source="PHYSICAL"
    )
    assert len(phys_results) >= 1
    assert all(r["source"] == "PHYSICAL" for r in phys_results)



@pytest.mark.anyio

async def test_persistence_handles_uninstalled_sensor():
    """Verify that uninstalled sensors are persisted with FAULT status and SENSOR_NOT_INSTALLED code."""
    repo = PersistenceRepository(
    supabase_url=None,
    supabase_key=None,
    service_role_key=None,
)

    uninstalled_reading = SensorReadingContract(
        sensor_id="FS_FLUME_01",
        section_id="SEC_SCREENING_01",
        sensor_type=SensorType.FLOW_RATE,
        value=0.0,
        unit=MeasurementUnit.LITRES_PER_MINUTE,
        source=DataSource.PHYSICAL,
        status=SensorHealthStatus.FAULT,
        timestamp=datetime.now(timezone.utc),
        metadata={
            "device_id": "DRAINX-ESP32-NODE-01",
            "is_valid": False,
            "fault_code": "SENSOR_NOT_INSTALLED",
            "validation_stage": "PARTIALLY_ASSEMBLED"
        }
    )

    count = await repo.persist_readings([uninstalled_reading])
    assert count == 1

    history = await repo.query_historical_telemetry(sensor_id="FS_FLUME_01", source="PHYSICAL")
    assert len(history) >= 1
    latest = history[0]
    assert latest["value"] == 0.0
    assert latest["status"] == "FAULT"
    assert latest["metadata"]["fault_code"] == "SENSOR_NOT_INSTALLED"


@pytest.mark.anyio
async def test_persistence_network_failure_is_soft_and_safe():
    """Verify that when a network failure occurs against Supabase URL, application does not crash."""
    # Point to an unreachable mock endpoint with aggressive 0.1s timeout
    failing_repo = PersistenceRepository(
        supabase_url="http://192.0.2.1:9999", # TEST-NET non-routable address
        supabase_key="mock_invalid_key",
        timeout_sec=0.1
    )
    assert failing_repo.is_configured is True

    test_reading = SensorReadingContract(
        sensor_id="US_UPSTREAM_01",
        section_id="SEC_SCREENING_01",
        sensor_type=SensorType.WATER_LEVEL,
        value=5.0,
        unit=MeasurementUnit.CENTIMETRE,
        source=DataSource.PHYSICAL,
        status=SensorHealthStatus.OK,
        timestamp=datetime.now(timezone.utc)
    )

    # Must return 0 persisted records instead of raising uncaught exception
    res = await failing_repo.persist_readings([test_reading])
    assert res == 0


def test_api_persistence_endpoints(client: TestClient):
    """Verify GET /api/v1/telemetry/persistence/status and historical query endpoints work."""
    # Status endpoint
    resp_status = client.get("/api/v1/telemetry/persistence/status")
    assert resp_status.status_code == 200
    data = resp_status.json()
    assert data["status"] == "success"
    assert "persistence" in data

    # Historical endpoint
    resp_hist = client.get("/api/v1/telemetry/persistence/historical?limit=10")
    assert resp_hist.status_code == 200
    hist_data = resp_hist.json()
    assert hist_data["status"] == "success"
    assert "records" in hist_data
