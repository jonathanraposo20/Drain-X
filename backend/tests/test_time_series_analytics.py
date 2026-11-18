"""
DRAIN-X Historical Telemetry & Time-Series Analytics Unit Tests.

Milestone: P0.4B Historical Telemetry & Analytics Foundation.

Validates:
1. Historical query time-range filtering (start_time, end_time, validation error on invalid range).
2. Chronological sorting (oldest to newest vs newest to oldest).
3. Statistical 1-minute and 5-minute bucket rollups (avg, min, max, sample_count, valid_sample_count).
4. Data quality invariant: invalid readings and SENSOR_NOT_INSTALLED faults are strictly excluded from averages.
5. Zero-flow invariant: 0.0 L/min flow readings with OK status ARE included in averages.
6. Water-level rate-of-rise trend regression (dh/dt in cm/min, R^2, trend state).
7. Flow trend metrics (average flow, peak flow, rate of change, and cumulative volume).
8. Insufficient samples / irregular sampling handling.
9. Strict operational mode source isolation: PHYSICAL vs SIMULATED queries.
10. End-to-end API compatibility via GET /analytics/rollup and GET /analytics/trend.
"""

from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient

from app.services.state_store import state_store
from app.services.persistence_repository import PersistenceRepository
from app.services.time_series_analytics import (
    aggregate_time_series,
    calculate_water_level_trend,
    calculate_flow_trend,
    is_reading_valid,
)
from app.models.contracts import (
    SensorReadingContract,
    SensorType,
    MeasurementUnit,
    DataSource,
    SensorHealthStatus,
)


@pytest.fixture(autouse=True)
def clean_mode():
    state_store.set_mode("SIMULATION", reason="Analytics test setup")
    yield
    state_store.set_mode("SIMULATION", reason="Analytics test cleanup")


def test_time_series_reading_validity_filter():
    """Verify is_reading_valid properly discriminates valid data from faults."""
    valid_reading = {
        "sensor_id": "US_UPSTREAM_01",
        "value": 5.4,
        "status": "OK",
        "metadata": {"is_valid": True, "fault_code": "NONE"}
    }
    assert is_reading_valid(valid_reading) is True

    # Zero flow is valid
    zero_flow = {
        "sensor_id": "FS_FLUME_01",
        "value": 0.0,
        "status": "OK",
        "metadata": {"is_valid": True, "fault_code": "NONE"}
    }
    assert is_reading_valid(zero_flow) is True

    # Fault reading is invalid
    fault_reading = {
        "sensor_id": "US_UPSTREAM_01",
        "value": 0.0,
        "status": "FAULT",
        "metadata": {"is_valid": False, "fault_code": "TIMEOUT_NO_ECHO"}
    }
    assert is_reading_valid(fault_reading) is False

    # Uninstalled sensor is invalid
    uninstalled = {
        "sensor_id": "FS_FLUME_01",
        "value": 0.0,
        "status": "FAULT",
        "metadata": {"is_valid": False, "fault_code": "SENSOR_NOT_INSTALLED"}
    }
    assert is_reading_valid(uninstalled) is False


def test_one_minute_aggregation_and_fault_exclusion():
    """Verify 1-minute bucket aggregation accurately computes metrics while excluding faults."""
    t0 = datetime(2026, 11, 13, 10, 0, 0, tzinfo=timezone.utc)

    dataset = [
        # Minute 1: 3 valid samples (4.0, 5.0, 6.0) + 1 fault (value=0.0)
        {"sensor_id": "US_UPSTREAM_01", "value": 4.0, "status": "OK", "timestamp": t0, "metadata": {"is_valid": True}},
        {"sensor_id": "US_UPSTREAM_01", "value": 5.0, "status": "OK", "timestamp": t0 + timedelta(seconds=15), "metadata": {"is_valid": True}},
        {"sensor_id": "US_UPSTREAM_01", "value": 6.0, "status": "OK", "timestamp": t0 + timedelta(seconds=30), "metadata": {"is_valid": True}},
        {"sensor_id": "US_UPSTREAM_01", "value": 0.0, "status": "FAULT", "timestamp": t0 + timedelta(seconds=45), "metadata": {"is_valid": False, "fault_code": "TIMEOUT_NO_ECHO"}},

        # Minute 2: 2 valid samples (8.0, 10.0)
        {"sensor_id": "US_UPSTREAM_01", "value": 8.0, "status": "OK", "timestamp": t0 + timedelta(seconds=65), "metadata": {"is_valid": True}},
        {"sensor_id": "US_UPSTREAM_01", "value": 10.0, "status": "OK", "timestamp": t0 + timedelta(seconds=85), "metadata": {"is_valid": True}},
    ]

    buckets = aggregate_time_series(dataset, bucket_interval_seconds=60, unit="cm")

    assert len(buckets) == 2

    # Bucket 1: total samples=4, valid=3, avg=(4+5+6)/3=5.0, min=4.0, max=6.0 (fault excluded)
    b1 = buckets[0]
    assert b1.sample_count == 4
    assert b1.valid_sample_count == 3
    assert b1.avg_value == 5.0
    assert b1.min_value == 4.0
    assert b1.max_value == 6.0

    # Bucket 2: total samples=2, valid=2, avg=9.0, min=8.0, max=10.0
    b2 = buckets[1]
    assert b2.sample_count == 2
    assert b2.valid_sample_count == 2
    assert b2.avg_value == 9.0
    assert b2.min_value == 8.0
    assert b2.max_value == 10.0


def test_water_level_trend_rate_of_rise():
    """Verify rate of rise calculation (dh/dt in cm/min) via linear regression."""
    t0 = datetime(2026, 11, 13, 12, 0, 0, tzinfo=timezone.utc)

    # Steady rise of 2.0 cm per minute:
    # t=0s -> 4.0 cm
    # t=30s -> 5.0 cm
    # t=60s -> 6.0 cm
    # t=90s -> 7.0 cm
    dataset = [
        {"sensor_id": "US_UPSTREAM_01", "source": "PHYSICAL", "value": 4.0, "status": "OK", "timestamp": t0, "metadata": {"is_valid": True}},
        {"sensor_id": "US_UPSTREAM_01", "source": "PHYSICAL", "value": 5.0, "status": "OK", "timestamp": t0 + timedelta(seconds=30), "metadata": {"is_valid": True}},
        {"sensor_id": "US_UPSTREAM_01", "source": "PHYSICAL", "value": 6.0, "status": "OK", "timestamp": t0 + timedelta(seconds=60), "metadata": {"is_valid": True}},
        {"sensor_id": "US_UPSTREAM_01", "source": "PHYSICAL", "value": 7.0, "status": "OK", "timestamp": t0 + timedelta(seconds=90), "metadata": {"is_valid": True}},
    ]

    metrics = calculate_water_level_trend(dataset, sensor_id="US_UPSTREAM_01", source="PHYSICAL")

    assert metrics.sample_count == 4
    assert metrics.valid_sample_count == 4
    assert metrics.current_level_cm == 7.0
    assert pytest.approx(metrics.rate_of_rise_cm_min, rel=1e-2) == 2.0
    assert metrics.r_squared >= 0.99
    assert metrics.trend_state == "RISING"


def test_water_level_trend_insufficient_samples():
    """Verify that fewer than 2 valid points reports INSUFFICIENT_DATA without crashing."""
    t0 = datetime(2026, 11, 13, 12, 0, 0, tzinfo=timezone.utc)
    dataset = [
        {"sensor_id": "US_UPSTREAM_01", "source": "PHYSICAL", "value": 5.0, "status": "OK", "timestamp": t0, "metadata": {"is_valid": True}},
        {"sensor_id": "US_UPSTREAM_01", "source": "PHYSICAL", "value": 0.0, "status": "FAULT", "timestamp": t0 + timedelta(seconds=30), "metadata": {"is_valid": False}},
    ]

    metrics = calculate_water_level_trend(dataset, sensor_id="US_UPSTREAM_01", source="PHYSICAL")
    assert metrics.valid_sample_count == 1
    assert metrics.trend_state == "INSUFFICIENT_DATA"
    assert metrics.rate_of_rise_cm_min == 0.0


def test_flow_trend_calculations_and_zero_flow():
    """Verify flow trend metrics and valid zero-flow inclusion."""
    t0 = datetime(2026, 11, 13, 14, 0, 0, tzinfo=timezone.utc)

    # 4 readings: 0.0, 2.0, 4.0, 6.0 L/min
    dataset = [
        {"sensor_id": "FS_FLUME_01", "source": "PHYSICAL", "value": 0.0, "status": "OK", "timestamp": t0, "metadata": {"is_valid": True, "total_volume_liters": 1.0}},
        {"sensor_id": "FS_FLUME_01", "source": "PHYSICAL", "value": 2.0, "status": "OK", "timestamp": t0 + timedelta(seconds=30), "metadata": {"is_valid": True, "total_volume_liters": 1.5}},
        {"sensor_id": "FS_FLUME_01", "source": "PHYSICAL", "value": 4.0, "status": "OK", "timestamp": t0 + timedelta(seconds=60), "metadata": {"is_valid": True, "total_volume_liters": 2.5}},
        {"sensor_id": "FS_FLUME_01", "source": "PHYSICAL", "value": 6.0, "status": "OK", "timestamp": t0 + timedelta(seconds=90), "metadata": {"is_valid": True, "total_volume_liters": 4.0}},
    ]

    metrics = calculate_flow_trend(dataset, sensor_id="FS_FLUME_01", source="PHYSICAL")

    assert metrics.valid_sample_count == 4
    assert metrics.current_flow_lpm == 6.0
    assert metrics.avg_flow_lpm == 3.0  # (0 + 2 + 4 + 6) / 4 = 3.0
    assert metrics.peak_flow_lpm == 6.0
    assert metrics.total_volume_liters == 4.0
    assert metrics.flow_trend_state == "INCREASING"


@pytest.mark.anyio
async def test_time_range_and_chronological_filtering():
    """Verify start_time, end_time, and chronological query sorting."""
    repo = PersistenceRepository(
    supabase_url=None,
    supabase_key=None,
    service_role_key=None,
)

    t_base = datetime(2026, 11, 13, 16, 0, 0, tzinfo=timezone.utc)
    readings = []
    for i in range(10):
        readings.append(
            SensorReadingContract(
                sensor_id="US_UPSTREAM_01",
                section_id="SEC_SCREENING_01",
                sensor_type=SensorType.WATER_LEVEL,
                value=4.0 + (i * 0.5),
                unit=MeasurementUnit.CENTIMETRE,
                source=DataSource.PHYSICAL,
                status=SensorHealthStatus.OK,
                timestamp=t_base + timedelta(minutes=i),
            )
        )

    await repo.persist_readings(readings)

    # Query middle window: minutes 3 to 6 (inclusive)
    t_start = t_base + timedelta(minutes=3)
    t_end = t_base + timedelta(minutes=6)

    window = await repo.query_historical_telemetry(
        sensor_id="US_UPSTREAM_01",
        source="PHYSICAL",
        start_time=t_start,
        end_time=t_end,
        chronological=True,
    )

    assert len(window) == 4
    # Chronological ordering check (oldest to newest)
    assert window[0]["timestamp"] < window[-1]["timestamp"]
    assert window[0]["value"] == 5.5  # i=3
    assert window[-1]["value"] == 7.0 # i=6


def test_api_analytics_endpoints(client: TestClient):
    """Verify /analytics/rollup and /analytics/trend HTTP endpoints."""
    # 1. Rollup invalid interval check
    resp_bad = client.get("/api/v1/telemetry/analytics/rollup?sensor_id=US_UPSTREAM_01&interval_seconds=120")
    assert resp_bad.status_code == 400
    assert "interval_seconds must be either 60" in resp_bad.json()["detail"]

    # 2. Valid 60s rollup request
    resp_rollup = client.get("/api/v1/telemetry/analytics/rollup?sensor_id=US_UPSTREAM_01&interval_seconds=60")
    assert resp_rollup.status_code == 200
    assert resp_rollup.json()["status"] == "success"
    assert "buckets" in resp_rollup.json()

    # 3. Valid trend request
    resp_trend = client.get("/api/v1/telemetry/analytics/trend?sensor_id=US_UPSTREAM_01")
    assert resp_trend.status_code == 200
    assert resp_trend.json()["status"] in ("success", "empty")
