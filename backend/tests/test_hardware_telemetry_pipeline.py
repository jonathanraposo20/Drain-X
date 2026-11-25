import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from app.services.state_store import state_store
from app.models.contracts import (
    SensorReadingContract,
    SensorType,
    MeasurementUnit,
    DataSource,
    SensorHealthStatus,
    PredictionState,
    AlertSeverity,
)


@pytest.fixture(autouse=True)
def ensure_physical_mode():
    """Ensure the hardware telemetry test suite runs in PHYSICAL mode."""
    state_store.set_mode("PHYSICAL", reason="test_hardware_telemetry_pipeline execution")
    yield
    state_store.set_mode("SIMULATION", reason="test_hardware_telemetry_pipeline cleanup")


def test_physical_telemetry_ingest_executes_analytics(client: TestClient):
    """
    Verify POST /api/v1/telemetry runs analytics pipeline immediately upon ingest
    and returns accepted readings, predictions, blockage, and gate directives.
    """
    payload = {
        "sensor_id": "US_UPSTREAM_01",
        "section_id": "SEC_SCREENING",
        "sensor_type": "WATER_LEVEL",
        "value": 4.5,
        "unit": "cm",
        "source": "PHYSICAL",
        "status": "OK",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    response = client.post("/api/v1/telemetry", json=payload)
    assert response.status_code == 201

    data = response.json()
    assert data["status"] == "success"
    assert data["ingested_count"] == 1
    assert "message_id" in data
    assert "gate_directive" in data
    assert "prediction" in data

    directive = data["gate_directive"]
    assert directive["gate_target_angle"] == 0.0
    assert directive["action"] == "MAINTAIN_NORMAL"
    assert directive["risk_level"] == "INFO"


def test_batch_physical_telemetry_ingest(client: TestClient):
    """
    Verify batch ingestion of multi-sensor physical payload.
    """
    now = datetime.now(timezone.utc).isoformat()
    batch = [
        {
            "sensor_id": "US_UPSTREAM_01",
            "section_id": "SEC_SCREENING",
            "sensor_type": "WATER_LEVEL",
            "value": 5.2,
            "unit": "cm",
            "source": "PHYSICAL",
            "status": "OK",
            "timestamp": now,
        },
        {
            "sensor_id": "US_WEIR_02",
            "section_id": "SEC_OUTLET",
            "sensor_type": "WATER_LEVEL",
            "value": 1.2,
            "unit": "cm",
            "source": "PHYSICAL",
            "status": "OK",
            "timestamp": now,
        },
        {
            "sensor_id": "PUMP_INFLOW_01",
            "section_id": "SEC_INFLOW",
            "sensor_type": "FLOW_RATE",
            "value": 6.0,
            "unit": "L/min",
            "source": "PHYSICAL",
            "status": "OK",
            "timestamp": now,
        },
    ]

    response = client.post("/api/v1/telemetry", json=batch)
    assert response.status_code == 201
    data = response.json()
    assert data["ingested_count"] == 3

    # Check latest retrieval
    latest_resp = client.get("/api/v1/telemetry/latest")
    assert latest_resp.status_code == 200
    readings = latest_resp.json()["readings"]
    assert "US_UPSTREAM_01" in readings
    assert "US_WEIR_02" in readings
    assert "PUMP_INFLOW_01" in readings
    assert readings["US_UPSTREAM_01"]["source"] == "PHYSICAL"


def test_stable_water_depth_no_false_alarms(client: TestClient):
    """
    Verify that flat water levels yield STABLE prediction without false countdowns.
    """
    base_time = datetime.now(timezone.utc)
    for i in range(5):
        payload = {
            "sensor_id": "US_UPSTREAM_01",
            "section_id": "SEC_SCREENING",
            "sensor_type": "WATER_LEVEL",
            "value": 5.0,
            "unit": "cm",
            "source": "PHYSICAL",
            "status": "OK",
            "timestamp": (base_time + timedelta(seconds=i)).isoformat(),
        }
        resp = client.post("/api/v1/telemetry", json=payload)
        assert resp.status_code == 201

    final_data = resp.json()
    prediction = final_data["prediction"]
    assert prediction is not None
    assert prediction["state"] == "STABLE"
    assert prediction["ttc_seconds"] is None

    directive = final_data["gate_directive"]
    assert directive["gate_target_angle"] == 0.0
    assert directive["action"] == "MAINTAIN_NORMAL"


def test_rising_water_depth_triggers_ttc_and_diversion(client: TestClient):
    """
    Verify that rapidly rising physical readings compute TTC and trigger DIVERT_FLOW.
    """
    base_time = datetime.now(timezone.utc)
    # 8 consecutive readings rising fast: 6.0cm to 9.5cm in 7 seconds (dh/dt ~ 0.5 cm/s)
    # Remaining head to 12.0cm is 2.5cm -> TTC ~ 5 seconds <= 45s trigger
    for i in range(8):
        payload = {
            "sensor_id": "US_UPSTREAM_01",
            "section_id": "SEC_SCREENING",
            "sensor_type": "WATER_LEVEL",
            "value": round(6.0 + (i * 0.5), 2),
            "unit": "cm",
            "source": "PHYSICAL",
            "status": "OK",
            "timestamp": (base_time + timedelta(seconds=i)).isoformat(),
        }
        resp = client.post("/api/v1/telemetry", json=payload)
        assert resp.status_code == 201

    final_data = resp.json()
    prediction = final_data["prediction"]
    assert prediction is not None
    assert prediction["state"] == "ESTIMATING"
    assert prediction["ttc_seconds"] is not None
    assert prediction["ttc_seconds"] <= 45.0

    directive = final_data["gate_directive"]
    assert directive["gate_target_angle"] == 90.0
    assert directive["action"] == "DIVERT_FLOW"
    assert directive["risk_level"] == "HIGH"


def test_critical_overflow_triggers_emergency_relief(client: TestClient):
    """
    Verify that water level exceeding 12.0cm critical threshold commands EMERGENCY_OVERFLOW_RELIEF.
    """
    payload = {
        "sensor_id": "US_UPSTREAM_01",
        "section_id": "SEC_SCREENING",
        "sensor_type": "WATER_LEVEL",
        "value": 12.8,  # > 12.0 cm critical limit
        "unit": "cm",
        "source": "PHYSICAL",
        "status": "OK",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    resp = client.post("/api/v1/telemetry", json=payload)
    assert resp.status_code == 201
    data = resp.json()

    assert data["prediction"]["state"] == "OVERFLOW"
    assert data["prediction"]["ttc_seconds"] == 0.0

    directive = data["gate_directive"]
    assert directive["gate_target_angle"] == 90.0
    assert directive["action"] == "EMERGENCY_OVERFLOW_RELIEF"
    assert directive["risk_level"] == "CRITICAL"


def test_blockage_detection_from_differential_head(client: TestClient):
    """
    Verify that high upstream head relative to downstream weir diagnoses blockage
    and commands diversion gate deployment.
    """
    now = datetime.now(timezone.utc).isoformat()
    payload = [
        {
            "sensor_id": "US_UPSTREAM_01",
            "section_id": "SEC_SCREENING",
            "sensor_type": "WATER_LEVEL",
            "value": 9.5,
            "unit": "cm",
            "source": "PHYSICAL",
            "status": "OK",
            "timestamp": now,
        },
        {
            "sensor_id": "US_WEIR_02",
            "section_id": "SEC_OUTLET",
            "sensor_type": "WATER_LEVEL",
            "value": 0.8,
            "unit": "cm",
            "source": "PHYSICAL",
            "status": "OK",
            "timestamp": now,
        },
    ]

    resp = client.post("/api/v1/telemetry", json=payload)
    assert resp.status_code == 201
    data = resp.json()

    blockage = data["blockage"]
    assert blockage is not None
    assert blockage["probable_segment"] == "PRIMARY_SCREENING_NET"
    assert blockage["severity"] >= 0.55
    assert blockage["differential_head_cm"] > 2.0

    directive = data["gate_directive"]
    assert directive["gate_target_angle"] == 90.0
    assert directive["action"] == "DIVERT_FLOW"


def test_fault_detection_on_physical_telemetry(client: TestClient):
    """
    Verify that out-of-range sensor readings trigger fault detection and alerts.
    """
    payload = {
        "sensor_id": "US_UPSTREAM_01",
        "section_id": "SEC_SCREENING",
        "sensor_type": "WATER_LEVEL",
        "value": 25.0,  # Exceeds 16cm physical limit
        "unit": "cm",
        "source": "PHYSICAL",
        "status": "OK",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    resp = client.post("/api/v1/telemetry", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["active_alerts_count"] >= 1

    # Check alert endpoint
    alerts_resp = client.get("/api/v1/alerts?active_only=true")
    assert alerts_resp.status_code == 200
    alerts = alerts_resp.json()
    assert any(a["alert_type"] == "IMPLAUSIBLE_READING" for a in alerts)


def test_physical_telemetry_isolation_from_simulation(municipal_client: TestClient):
    """
    Verify that physical telemetry ingestion does not start or corrupt simulation scenarios.
    """
    payload = {
        "sensor_id": "US_UPSTREAM_01",
        "section_id": "SEC_SCREENING",
        "sensor_type": "WATER_LEVEL",
        "value": 4.0,
        "unit": "cm",
        "source": "PHYSICAL",
        "status": "OK",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    resp = municipal_client.post("/api/v1/telemetry", json=payload)
    assert resp.status_code == 201

    # Check simulation status is still not running an uncommanded scenario
    sim_status = municipal_client.get("/api/v1/simulation/state")
    assert sim_status.status_code == 200
    sim_data = sim_status.json()
    # Ingesting physical telemetry must not have launched a simulation scenario
    assert sim_data["active_scenario"] is None
    assert sim_data["is_running"] is False
