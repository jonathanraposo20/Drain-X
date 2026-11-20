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


# ==============================================================================
# Phase 3.2: Five-Minute Rollup Reliability & Time-Series Hardening Regressions
# ==============================================================================

def test_one_hour_2hz_produces_12_five_minute_buckets():
    """Verify 7200 samples at 2 Hz (0.5s) over 1 hour produce exactly 12 complete 5-minute buckets."""
    t0 = datetime(2026, 11, 13, 12, 0, 0, tzinfo=timezone.utc)
    # 7200 samples: 1 sample every 0.5 seconds = exactly 3600 seconds = 1 hour
    # from 12:00:00.0 to 12:59:59.5
    readings = [
        {
            "sensor_id": "US_UPSTREAM_01",
            "value": 10.0 + (i % 50) * 0.1,
            "status": "OK",
            "timestamp": t0 + timedelta(milliseconds=i * 500),
            "metadata": {"is_valid": True},
        }
        for i in range(7200)
    ]

    buckets = aggregate_time_series(readings, bucket_interval_seconds=300, unit="cm")

    assert len(buckets) == 12
    for idx, b in enumerate(buckets):
        assert b.sample_count == 600
        assert b.valid_sample_count == 600
        expected_start = t0 + timedelta(minutes=idx * 5)
        assert b.bucket_start == expected_start
        assert b.bucket_end == expected_start + timedelta(seconds=300)
        assert b.min_value is not None
        assert b.max_value is not None
        assert b.avg_value is not None


def test_one_hour_1hz_produces_same_12_buckets():
    """Verify 3600 samples at 1 Hz (1.0s) over the same 1 hour produce identical 12 bucket boundaries."""
    t0 = datetime(2026, 11, 13, 12, 0, 0, tzinfo=timezone.utc)
    # 3600 samples: 1 sample every 1 second = 3600 seconds = 1 hour
    readings = [
        {
            "sensor_id": "US_UPSTREAM_01",
            "value": 10.0 + (i % 50) * 0.1,
            "status": "OK",
            "timestamp": t0 + timedelta(seconds=i),
            "metadata": {"is_valid": True},
        }
        for i in range(3600)
    ]

    buckets = aggregate_time_series(readings, bucket_interval_seconds=300, unit="cm")

    assert len(buckets) == 12
    for idx, b in enumerate(buckets):
        assert b.sample_count == 300
        assert b.valid_sample_count == 300
        expected_start = t0 + timedelta(minutes=idx * 5)
        assert b.bucket_start == expected_start
        assert b.bucket_end == expected_start + timedelta(seconds=300)


def test_utc_boundary_alignment():
    """Verify buckets strictly align to integer UTC epoch multiples of 300 seconds (clock minutes :00, :05, :10, etc.)."""
    # Sample starting mid-minute: 12:03:42
    t = datetime(2026, 11, 13, 12, 3, 42, tzinfo=timezone.utc)
    readings = [
        {"sensor_id": "US_UPSTREAM_01", "value": 5.0, "status": "OK", "timestamp": t, "metadata": {"is_valid": True}},
        {"sensor_id": "US_UPSTREAM_01", "value": 6.0, "status": "OK", "timestamp": t + timedelta(minutes=4), "metadata": {"is_valid": True}},
    ]

    buckets = aggregate_time_series(readings, bucket_interval_seconds=300, unit="cm")

    assert len(buckets) == 2
    # 12:03:42 falls in [12:00:00, 12:05:00)
    b0_start = buckets[0].bucket_start
    assert b0_start.minute == 0
    assert b0_start.second == 0
    assert int(b0_start.timestamp()) % 300 == 0

    # 12:07:42 falls in [12:05:00, 12:10:00)
    b1_start = buckets[1].bucket_start
    assert b1_start.minute == 5
    assert b1_start.second == 0
    assert int(b1_start.timestamp()) % 300 == 0


def test_partial_first_and_last_buckets():
    """Verify non-window-aligned datasets produce accurate partial first and last buckets without truncation."""
    # Data spans 10:02:15 to 10:17:45 (spans across 10:00:00-10:05:00, 10:05:00-10:10:00, 10:10:00-10:15:00, 10:15:00-10:20:00)
    t_start = datetime(2026, 11, 13, 10, 2, 15, tzinfo=timezone.utc)
    t_end = datetime(2026, 11, 13, 10, 17, 45, tzinfo=timezone.utc)

    # 1 sample every 30 seconds
    readings = []
    curr = t_start
    val = 1.0
    while curr <= t_end:
        readings.append({"sensor_id": "US_UPSTREAM_01", "value": val, "status": "OK", "timestamp": curr, "metadata": {"is_valid": True}})
        curr += timedelta(seconds=30)
        val += 0.5

    buckets = aggregate_time_series(readings, bucket_interval_seconds=300, unit="cm")

    assert len(buckets) == 4
    # First bucket: 10:00:00 to 10:05:00 (readings at :02:15, :02:45, :03:15, :03:45, :04:15, :04:45 -> 6 samples)
    assert buckets[0].bucket_start == datetime(2026, 11, 13, 10, 0, 0, tzinfo=timezone.utc)
    assert buckets[0].sample_count == 6

    # Last bucket: 10:15:00 to 10:20:00 (readings at :15:15, :15:45, :16:15, :16:45, :17:15, :17:45 -> 6 samples)
    assert buckets[-1].bucket_start == datetime(2026, 11, 13, 10, 15, 0, tzinfo=timezone.utc)
    assert buckets[-1].sample_count == 6


def test_sparse_sensor_data_no_fabricated_buckets():
    """Verify sparse sensor data does not generate fabricated empty intermediate buckets."""
    t0 = datetime(2026, 11, 13, 10, 1, 0, tzinfo=timezone.utc)  # Bucket 10:00:00
    t1 = datetime(2026, 11, 13, 10, 11, 0, tzinfo=timezone.utc) # Bucket 10:10:00 (10:05:00 is empty)

    dataset = [
        {"sensor_id": "US_UPSTREAM_01", "value": 5.0, "status": "OK", "timestamp": t0, "metadata": {"is_valid": True}},
        {"sensor_id": "US_UPSTREAM_01", "value": 5.2, "status": "OK", "timestamp": t1, "metadata": {"is_valid": True}},
    ]

    buckets = aggregate_time_series(dataset, bucket_interval_seconds=300, unit="cm")

    # Exactly 2 buckets - no empty fabricated bucket for 10:05
    assert len(buckets) == 2
    assert buckets[0].bucket_start == datetime(2026, 11, 13, 10, 0, 0, tzinfo=timezone.utc)
    assert buckets[1].bucket_start == datetime(2026, 11, 13, 10, 10, 0, tzinfo=timezone.utc)


def test_multiple_sensors_segregated_cleanly():
    """Verify multi-sensor datasets are cleanly partitioned without cross-sensor data mingling."""
    t0 = datetime(2026, 11, 13, 10, 1, 0, tzinfo=timezone.utc)

    mixed_dataset = [
        {"sensor_id": "US_UPSTREAM_01", "value": 12.0, "status": "OK", "timestamp": t0, "unit": "cm", "metadata": {"is_valid": True}},
        {"sensor_id": "FS_FLUME_01", "value": 45.0, "status": "OK", "timestamp": t0, "unit": "L/min", "metadata": {"is_valid": True}},
        {"sensor_id": "US_UPSTREAM_01", "value": 14.0, "status": "OK", "timestamp": t0 + timedelta(seconds=30), "unit": "cm", "metadata": {"is_valid": True}},
        {"sensor_id": "FS_FLUME_01", "value": 55.0, "status": "OK", "timestamp": t0 + timedelta(seconds=30), "unit": "L/min", "metadata": {"is_valid": True}},
    ]

    # 1. Unfiltered aggregation segregates both sensors
    all_buckets = aggregate_time_series(mixed_dataset, bucket_interval_seconds=300)
    assert len(all_buckets) == 2
    sensor_map = {b.sensor_id: b for b in all_buckets}
    assert "US_UPSTREAM_01" in sensor_map
    assert "FS_FLUME_01" in sensor_map
    assert sensor_map["US_UPSTREAM_01"].avg_value == 13.0
    assert sensor_map["US_UPSTREAM_01"].unit == "cm"
    assert sensor_map["FS_FLUME_01"].avg_value == 50.0
    assert sensor_map["FS_FLUME_01"].unit == "L/min"

    # 2. Filtered by sensor_id
    us_buckets = aggregate_time_series(mixed_dataset, bucket_interval_seconds=300, sensor_id="US_UPSTREAM_01")
    assert len(us_buckets) == 1
    assert us_buckets[0].sensor_id == "US_UPSTREAM_01"
    assert us_buckets[0].avg_value == 13.0


def test_physical_and_simulated_source_separation():
    """Verify physical and simulated telemetry streams are strictly isolated during rollup."""
    t0 = datetime(2026, 11, 13, 10, 1, 0, tzinfo=timezone.utc)

    dataset = [
        {"sensor_id": "US_UPSTREAM_01", "source": "PHYSICAL", "value": 10.0, "status": "OK", "timestamp": t0, "metadata": {"is_valid": True}},
        {"sensor_id": "US_UPSTREAM_01", "source": "SIMULATED", "value": 99.0, "status": "OK", "timestamp": t0 + timedelta(seconds=10), "metadata": {"is_valid": True}},
        {"sensor_id": "US_UPSTREAM_01", "source": "LIVE", "value": 12.0, "status": "OK", "timestamp": t0 + timedelta(seconds=20), "metadata": {"is_valid": True}},
    ]

    # Query PHYSICAL only (LIVE maps to PHYSICAL)
    phys_buckets = aggregate_time_series(dataset, bucket_interval_seconds=300, source="PHYSICAL")
    assert len(phys_buckets) == 1
    assert phys_buckets[0].sample_count == 2
    assert phys_buckets[0].avg_value == 11.0 # (10 + 12) / 2

    # Query SIMULATED only
    sim_buckets = aggregate_time_series(dataset, bucket_interval_seconds=300, source="SIMULATED")
    assert len(sim_buckets) == 1
    assert sim_buckets[0].sample_count == 1
    assert sim_buckets[0].avg_value == 99.0


def test_faulted_and_invalid_readings_excluded_from_stats():
    """Verify corrupted/faulted measurements are excluded from statistical metrics while counted in sample_count."""
    t0 = datetime(2026, 11, 13, 10, 0, 0, tzinfo=timezone.utc)

    dataset = [
        {"sensor_id": "US_UPSTREAM_01", "value": 10.0, "status": "OK", "timestamp": t0, "metadata": {"is_valid": True}},
        {"sensor_id": "US_UPSTREAM_01", "value": 20.0, "status": "OK", "timestamp": t0 + timedelta(seconds=30), "metadata": {"is_valid": True}},
        {"sensor_id": "US_UPSTREAM_01", "value": 0.0, "status": "FAULT", "timestamp": t0 + timedelta(seconds=60), "metadata": {"is_valid": False, "fault_code": "TIMEOUT_NO_ECHO"}},
        {"sensor_id": "US_UPSTREAM_01", "value": 999.0, "status": "FAULT", "timestamp": t0 + timedelta(seconds=90), "metadata": {"is_valid": False, "fault_code": "SPIKE_ANOMALY"}},
    ]

    buckets = aggregate_time_series(dataset, bucket_interval_seconds=300, unit="cm")

    assert len(buckets) == 1
    b = buckets[0]
    assert b.sample_count == 4
    assert b.valid_sample_count == 2
    assert b.min_value == 10.0
    assert b.max_value == 20.0
    assert b.avg_value == 15.0


def test_valid_zero_flow_preserved():
    """Verify 0.0 L/min flow readings with OK health status are strictly included in statistical metrics."""
    t0 = datetime(2026, 11, 13, 10, 0, 0, tzinfo=timezone.utc)

    dataset = [
        {"sensor_id": "FS_FLUME_01", "value": 0.0, "status": "OK", "timestamp": t0, "unit": "L/min", "metadata": {"is_valid": True}},
        {"sensor_id": "FS_FLUME_01", "value": 10.0, "status": "OK", "timestamp": t0 + timedelta(seconds=60), "unit": "L/min", "metadata": {"is_valid": True}},
    ]

    buckets = aggregate_time_series(dataset, bucket_interval_seconds=300, unit="L/min")

    assert len(buckets) == 1
    b = buckets[0]
    assert b.sample_count == 2
    assert b.valid_sample_count == 2
    assert b.min_value == 0.0
    assert b.max_value == 10.0
    assert b.avg_value == 5.0 # (0.0 + 10.0) / 2 = 5.0


@pytest.mark.anyio
async def test_large_historical_windows_bounded_and_truncated():
    """Verify historical queries support up to 10,000 samples and signal truncation when limit is reached."""
    repo = PersistenceRepository(
        supabase_url=None,
        supabase_key=None,
        service_role_key=None,
    )

    t0 = datetime(2026, 11, 13, 10, 0, 0, tzinfo=timezone.utc)
    # Persist 500 records
    readings = [
        SensorReadingContract(
            sensor_id="US_UPSTREAM_01",
            section_id="SEC_SCREENING_01",
            sensor_type=SensorType.WATER_LEVEL,
            value=5.0,
            unit=MeasurementUnit.CENTIMETRE,
            source=DataSource.PHYSICAL,
            status=SensorHealthStatus.OK,
            timestamp=t0 + timedelta(seconds=i),
        )
        for i in range(500)
    ]
    await repo.persist_readings(readings)

    # Query with a tight limit (50) to test truncation
    records = await repo.query_historical_telemetry(
        sensor_id="US_UPSTREAM_01",
        limit=50,
        chronological=True,
    )
    assert len(records) == 50

    # Query with higher limit up to 10000
    all_records = await repo.query_historical_telemetry(
        sensor_id="US_UPSTREAM_01",
        limit=10000,
        chronological=True,
    )
    assert len(all_records) == 500


def test_existing_60_second_rollups_remain_compatible():
    """Verify existing 60-second rollup semantics, schema, and calculations remain 100% backward-compatible."""
    t0 = datetime(2026, 11, 13, 10, 0, 0, tzinfo=timezone.utc)

    dataset = [
        {"sensor_id": "US_UPSTREAM_01", "value": 5.0, "status": "OK", "timestamp": t0 + timedelta(seconds=10), "metadata": {"is_valid": True}},
        {"sensor_id": "US_UPSTREAM_01", "value": 7.0, "status": "OK", "timestamp": t0 + timedelta(seconds=20), "metadata": {"is_valid": True}},
        {"sensor_id": "US_UPSTREAM_01", "value": 10.0, "status": "OK", "timestamp": t0 + timedelta(seconds=70), "metadata": {"is_valid": True}},
    ]

    buckets = aggregate_time_series(dataset, bucket_interval_seconds=60, unit="cm")

    assert len(buckets) == 2
    assert buckets[0].sample_count == 2
    assert buckets[0].avg_value == 6.0
    assert buckets[1].sample_count == 1
    assert buckets[1].avg_value == 10.0


def test_api_rollup_time_window_and_contract_compatibility(client: TestClient):
    """Verify GET /api/v1/telemetry/analytics/rollup handles time-window parameters and preserves the full contract."""
    # 1. Invalid time range (start_time > end_time) returns 400
    resp_invalid_range = client.get(
        "/api/v1/telemetry/analytics/rollup?"
        "sensor_id=US_UPSTREAM_01&"
        "start_time=2026-11-13T12:00:00Z&"
        "end_time=2026-11-13T11:00:00Z"
    )
    assert resp_invalid_range.status_code == 400
    assert "start_time must not be later than end_time" in resp_invalid_range.json()["detail"]

    # 2. 5-minute rollup with time window returns 200 and matches contract keys
    resp_5m = client.get(
        "/api/v1/telemetry/analytics/rollup?"
        "sensor_id=US_UPSTREAM_01&"
        "interval_seconds=300&"
        "start_time=2026-11-13T10:00:00Z&"
        "end_time=2026-11-13T11:00:00Z"
    )
    assert resp_5m.status_code == 200
    data = resp_5m.json()

    # Verify all expected response keys exist
    expected_keys = {
        "status",
        "sensor_id",
        "source",
        "interval_seconds",
        "dataset_sample_count",
        "is_dataset_truncated",
        "truncation_warning",
        "bucket_count",
        "buckets",
    }
    assert expected_keys.issubset(data.keys())
    assert data["status"] == "success"
    assert data["sensor_id"] == "US_UPSTREAM_01"
    assert data["interval_seconds"] == 300
    assert isinstance(data["buckets"], list)
