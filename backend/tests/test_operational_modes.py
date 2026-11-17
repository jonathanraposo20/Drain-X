import concurrent.futures
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from app.services.state_store import state_store
from app.services.fault_detector import fault_detector
from app.services.scenario_benchmark import scenario_runner
from app.services.intervention_engine import intervention_engine
from app.models.contracts import (
    SensorReadingContract,
    SensorType,
    MeasurementUnit,
    DataSource,
    SensorHealthStatus,
    OperationalMode,
    ActuatorDirectiveContract,
    BlockageEventContract,
    PredictionContract,
    PredictionState,
    AlertSeverity,
    ScenarioType,
)
from app.core.config import settings


def test_initial_mode_is_simulation(client: TestClient):
    """Verify system defaults to SIMULATION mode on startup."""
    response = client.get("/api/v1/status/mode")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["mode"] == "SIMULATION"
    assert data["is_simulation"] is True
    assert data["is_physical"] is False
    assert data["is_safe_hold"] is False


def test_explicit_mode_transitions_and_audit(admin_client: TestClient):
    """Verify explicit transitions across SIMULATION, PHYSICAL, SAFE_HOLD, and HARDWARE alias."""
    # 1. Switch to PHYSICAL
    resp = admin_client.post(
        "/api/v1/status/mode",
        json={"mode": "PHYSICAL", "reason": "Connecting physical bench flume ESP32"},
    )
    assert resp.status_code == 200
    assert resp.json()["mode"] == "PHYSICAL"
    assert state_store.is_physical() is True
    assert state_store.is_simulation() is False

    # 2. Switch to SAFE_HOLD
    resp = admin_client.post(
        "/api/v1/status/mode",
        json={"mode": "SAFE_HOLD", "reason": "Operator maintenance on downstream screen"},
    )
    assert resp.status_code == 200
    assert resp.json()["mode"] == "SAFE_HOLD"
    assert state_store.is_safe_hold() is True
    # Verify fail-safe directive is engaged immediately upon entering SAFE_HOLD
    directive = state_store.get_gate_directive()
    assert directive is not None
    assert directive.gate_target_angle == settings.SAFE_HOLD_GATE_ANGLE
    assert directive.action == "SAFE_HOLD_LOCK"
    assert directive.emergency_stop is True

    # 3. Switch to HARDWARE (legacy alias canonicalized to PHYSICAL)
    resp = admin_client.post(
        "/api/v1/status/mode",
        json={"mode": "HARDWARE", "reason": "Frontend legacy switch trigger"},
    )
    assert resp.status_code == 200
    assert resp.json()["mode"] == "PHYSICAL"
    assert state_store.mode == "PHYSICAL"
    assert state_store.is_physical() is True

    # 4. Switch back to SIMULATION
    resp = admin_client.post(
        "/api/v1/status/mode",
        json={"mode": "SIMULATION", "reason": "Returning to digital twin benchmark"},
    )
    assert resp.status_code == 200
    assert resp.json()["mode"] == "SIMULATION"
    assert state_store.is_simulation() is True

    # 5. Check auditable history ledger
    hist_resp = admin_client.get("/api/v1/status/mode/history")
    assert hist_resp.status_code == 200
    history = hist_resp.json()["history"]
    assert len(history) >= 4
    reasons = [h["reason"] for h in history]
    assert "Connecting physical bench flume ESP32" in reasons
    assert "Operator maintenance on downstream screen" in reasons


def test_hardware_canonicalization(admin_client: TestClient):
    """
    Verify HARDWARE is canonically normalized to PHYSICAL across stored mode,
    API response, status response, and mode history.
    """
    resp = admin_client.post("/api/v1/status/mode", json={"mode": "HARDWARE"})
    assert resp.status_code == 200
    assert resp.json()["mode"] == "PHYSICAL"
    assert state_store.mode == "PHYSICAL"

    # GET /status/mode
    mode_resp = admin_client.get("/api/v1/status/mode")
    assert mode_resp.json()["mode"] == "PHYSICAL"

    # GET /status
    status_resp = admin_client.get("/api/v1/status")
    assert status_resp.json()["mode"] == "PHYSICAL"

    # GET /status/mode/history
    hist_resp = admin_client.get("/api/v1/status/mode/history")
    last_record = hist_resp.json()["history"][-1]
    assert last_record["to_mode"] == "PHYSICAL"


def test_invalid_mode_transition_rejected(admin_client: TestClient):
    """Verify transitions to invalid modes are rejected with 400 Bad Request."""
    resp = admin_client.post(
        "/api/v1/status/mode",
        json={"mode": "UNSUPPORTED_MODE", "reason": "Invalid transition attempt"},
    )
    assert resp.status_code == 400
    assert "Invalid operational mode" in resp.json()["detail"]
    assert state_store.mode == "SIMULATION"


def test_physical_telemetry_rejected_in_simulation_mode(client: TestClient):
    """Verify physical telemetry is rejected with 409 Conflict when in SIMULATION mode."""
    state_store.set_mode("SIMULATION", reason="Test isolation")
    payload = {
        "sensor_id": "PHYS_US_01",
        "section_id": "SEC_SCREENING",
        "sensor_type": "WATER_LEVEL",
        "value": 7.5,
        "unit": "cm",
        "source": "PHYSICAL",
        "status": "OK",
    }
    resp = client.post("/api/v1/telemetry", json=payload)
    assert resp.status_code == 409
    assert "System is in SIMULATION mode" in resp.json()["detail"]

    # Ensure simulation history was not contaminated
    assert "PHYS_US_01" not in state_store.get_latest_readings()
    assert state_store.get_sensor_history("PHYS_US_01") == []


def test_simulated_telemetry_rejected_in_physical_mode(client: TestClient):
    """Verify simulated telemetry is rejected with 409 Conflict when in PHYSICAL mode."""
    state_store.set_mode("PHYSICAL", reason="Bench testing")
    payload = {
        "sensor_id": "SIM_US_01",
        "section_id": "SEC_SCREENING",
        "sensor_type": "WATER_LEVEL",
        "value": 5.0,
        "unit": "cm",
        "source": "SIMULATED",
        "status": "OK",
    }
    resp = client.post("/api/v1/telemetry", json=payload)
    assert resp.status_code == 409
    assert "System is in PHYSICAL mode" in resp.json()["detail"]

    # Ensure physical history was not contaminated
    assert "SIM_US_01" not in state_store.get_latest_readings()
    assert state_store.get_sensor_history("SIM_US_01") == []


def test_state_store_partition_isolation():
    """Verify state store partition separation at Python service level."""
    state_store.clear()
    state_store.set_mode("PHYSICAL", reason="Partition test")

    phys_reading = SensorReadingContract(
        sensor_id="BENCH_US_01",
        section_id="SEC_SCREENING",
        sensor_type=SensorType.WATER_LEVEL,
        value=6.2,
        unit=MeasurementUnit.CENTIMETRE,
        source=DataSource.PHYSICAL,
        status=SensorHealthStatus.OK,
    )
    sim_reading = SensorReadingContract(
        sensor_id="TWIN_US_01",
        section_id="SEC_SCREENING",
        sensor_type=SensorType.WATER_LEVEL,
        value=4.1,
        unit=MeasurementUnit.CENTIMETRE,
        source=DataSource.SIMULATED,
        status=SensorHealthStatus.OK,
    )

    # Ingest physical reading
    state_store.ingest_reading(phys_reading)
    assert "BENCH_US_01" in state_store._physical_latest_readings
    assert "BENCH_US_01" not in state_store._sim_latest_readings

    # Attempt to ingest simulated reading while in PHYSICAL mode
    state_store.ingest_reading(sim_reading)
    # Must NOT mutate physical state or active readings
    assert "TWIN_US_01" not in state_store._physical_latest_readings
    assert "TWIN_US_01" not in state_store.get_latest_readings()


def test_hardware_disconnection_does_not_auto_switch_mode(client: TestClient):
    """
    Verify that when hardware disconnects or stops updating in PHYSICAL mode,
    the system marks STALE_DATA / FAULT but DOES NOT automatically revert to SIMULATION.
    """
    state_store.clear()
    state_store.set_mode("PHYSICAL", reason="Hardware connection")

    # Ingest a physical reading
    payload = {
        "sensor_id": "PHYS_US_01",
        "section_id": "SEC_SCREENING",
        "sensor_type": "WATER_LEVEL",
        "value": 5.0,
        "unit": "cm",
        "source": "PHYSICAL",
        "status": "OK",
    }
    resp = client.post("/api/v1/telemetry", json=payload)
    assert resp.status_code == 201

    # Simulate sensor disconnection / fault status
    fault_payload = {
        "sensor_id": "PHYS_US_01",
        "section_id": "SEC_SCREENING",
        "sensor_type": "WATER_LEVEL",
        "value": 0.0,
        "unit": "cm",
        "source": "PHYSICAL",
        "status": "FAULT",
    }
    resp = client.post("/api/v1/telemetry", json=fault_payload)
    assert resp.status_code == 201

    # Run health evaluation
    fault_detector.evaluate_system_health()

    # The system mode must remain strictly PHYSICAL
    assert state_store.mode == "PHYSICAL"
    assert state_store.is_physical() is True
    assert state_store.is_simulation() is False


def test_safe_hold_mode_locks_actuation(client: TestClient):
    """Verify that in SAFE_HOLD mode, telemetry ingestion locks gate actuation to fail-safe angle."""
    state_store.set_mode("SAFE_HOLD", reason="Maintenance lock")

    # Ingest high water level physical telemetry that would normally trigger diversion
    payload = {
        "sensor_id": "US_UPSTREAM_01",
        "section_id": "SEC_SCREENING",
        "sensor_type": "WATER_LEVEL",
        "value": 14.5,  # High critical water depth
        "unit": "cm",
        "source": "PHYSICAL",
        "status": "OK",
    }
    resp = client.post("/api/v1/telemetry", json=payload)
    assert resp.status_code == 201
    data = resp.json()

    # Actuator directive must be locked to SAFE_HOLD fail-safe angle (0.0 deg)
    directive = data["gate_directive"]
    assert directive["gate_target_angle"] == settings.SAFE_HOLD_GATE_ANGLE
    assert directive["action"] == "SAFE_HOLD_LOCK"
    assert directive["emergency_stop"] is True
    assert "SAFE_HOLD active" in directive["reason"]


def test_safe_hold_directive_invariant_cannot_be_overwritten():
    """
    Verify thread-safe invariant: while mode is SAFE_HOLD, incoming non-SAFE_HOLD
    directives are strictly rejected by set_gate_directive().
    """
    state_store.clear()
    state_store.set_mode("SAFE_HOLD", reason="Operator fail-safe lock")

    safe_directive = state_store.get_gate_directive()
    assert safe_directive is not None
    assert safe_directive.action == "SAFE_HOLD_LOCK"
    assert safe_directive.gate_target_angle == settings.SAFE_HOLD_GATE_ANGLE

    # Attempt to inject a diversion directive (e.g. from delayed analytics calculation)
    violating_directive = ActuatorDirectiveContract(
        gate_target_angle=60.0,
        action="DIVERT_FLOW",
        reason="Late calculated flood intervention",
        risk_level=AlertSeverity.HIGH,
        emergency_stop=False,
    )
    state_store.set_gate_directive(violating_directive)

    # Invariant check: directive must remain SAFE_HOLD_LOCK with target 0.0 deg
    active_directive = state_store.get_gate_directive()
    assert active_directive.action == "SAFE_HOLD_LOCK"
    assert active_directive.gate_target_angle == settings.SAFE_HOLD_GATE_ANGLE
    assert active_directive.emergency_stop is True


def test_concurrent_ingestion_and_safe_hold_transition(admin_client: TestClient):
    """
    Verify concurrency safety: hammer telemetry ingestion and mode transition
    to SAFE_HOLD concurrently to ensure SAFE_HOLD_LOCK is never overwritten.
    """
    state_store.clear()
    state_store.set_mode("PHYSICAL", reason="Pre-load hardware mode")

    payload = {
        "sensor_id": "US_UPSTREAM_01",
        "section_id": "SEC_SCREENING",
        "sensor_type": "WATER_LEVEL",
        "value": 14.8,  # Triggers emergency diversion in normal mode
        "unit": "cm",
        "source": "PHYSICAL",
        "status": "OK",
    }

    def do_ingest():
        for _ in range(20):
            try:
                admin_client.post("/api/v1/telemetry", json=payload)
            except Exception:
                pass

    def do_transition():
        # Transition to SAFE_HOLD during concurrent ingestion
        admin_client.post("/api/v1/status/mode", json={"mode": "SAFE_HOLD", "reason": "Concurrent safe hold test"})

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        f_ingest = [executor.submit(do_ingest) for _ in range(4)]
        f_mode = [executor.submit(do_transition)]
        concurrent.futures.wait(f_ingest + f_mode)

    # In SAFE_HOLD mode, the authoritative directive must be SAFE_HOLD_LOCK
    assert state_store.mode == "SAFE_HOLD"
    final_directive = state_store.get_gate_directive()
    assert final_directive.action == "SAFE_HOLD_LOCK"
    assert final_directive.gate_target_angle == settings.SAFE_HOLD_GATE_ANGLE
    assert final_directive.emergency_stop is True


def test_simulation_analytics_cannot_influence_physical_gate_decisions():
    """
    Verify that active blockage and prediction generated in SIMULATION mode
    do NOT bleed into PHYSICAL mode or influence physical gate directives.
    """
    state_store.clear()
    state_store.set_mode("SIMULATION", reason="Run simulated flood")

    # In SIMULATION: record high blockage and critical prediction
    sim_blockage = BlockageEventContract(
        event_id="SIM_BLK_01",
        section_id="SEC_SCREENING",
        probable_segment="PRIMARY_SCREENING_NET",
        severity=0.95,
        confidence=0.90,
        differential_head_cm=8.5,
        is_active=True,
    )
    sim_prediction = PredictionContract(
        section_id="SEC_SCREENING",
        state=PredictionState.OVERFLOW,
        ttc_seconds=12.0,
    )
    state_store.record_blockage(sim_blockage)
    state_store.set_prediction(sim_prediction)

    # Verify simulation partition has the blockage
    assert state_store.get_active_blockage() is not None
    assert state_store.get_active_blockage().severity == 0.95
    assert state_store.get_prediction().state == PredictionState.OVERFLOW

    # Switch mode to PHYSICAL
    state_store.set_mode("PHYSICAL", reason="Operator switched to physical")

    # In PHYSICAL mode: active blockage and prediction must be None (isolated)
    assert state_store.get_active_blockage() is None
    assert state_store.get_prediction() is None

    # Compute physical gate directive: must NOT command diversion based on simulated blockage
    directive = intervention_engine.compute_gate_directive()
    assert directive.action == "MAINTAIN_NORMAL"
    assert directive.gate_target_angle == 0.0

    # Switch back to SIMULATION: verify simulation analytics are preserved (not erased)
    state_store.set_mode("SIMULATION", reason="Return to simulation")
    assert state_store.get_active_blockage() is not None
    assert state_store.get_active_blockage().severity == 0.95
    assert state_store.get_prediction().state == PredictionState.OVERFLOW


def test_simulation_start_and_step_reject_physical_mode(client: TestClient):
    """Verify POST /simulation/start and /simulation/step are rejected with 409 Conflict in PHYSICAL mode."""
    state_store.set_mode("PHYSICAL", reason="Physical bench active")

    # 1. POST /simulation/start
    resp_start = client.post("/api/v1/simulation/start", json={"scenario": "CLEAN_DRAINAGE", "seed": 42})
    assert resp_start.status_code == 409
    assert "Simulation cannot be started while in PHYSICAL mode" in resp_start.json()["detail"]

    # 2. POST /simulation/step
    resp_step = client.post("/api/v1/simulation/step?dt=0.5")
    assert resp_step.status_code == 409
    assert "Simulation cannot be stepped while in PHYSICAL mode" in resp_step.json()["detail"]

    # 3. Direct scenario_runner.step() call is inhibited
    step_res = scenario_runner.step(dt=0.5)
    assert step_res["status"] == "INHIBITED_NON_SIMULATION_MODE"


def test_simulation_start_and_step_reject_safe_hold_mode(client: TestClient):
    """Verify POST /simulation/start and /simulation/step are rejected with 409 Conflict in SAFE_HOLD mode."""
    state_store.set_mode("SAFE_HOLD", reason="Maintenance safe hold")

    # 1. POST /simulation/start
    resp_start = client.post("/api/v1/simulation/start", json={"scenario": "GRADUAL_DEBRIS", "seed": 42})
    assert resp_start.status_code == 409
    assert "Simulation cannot be started while in SAFE_HOLD mode" in resp_start.json()["detail"]

    # 2. POST /simulation/step
    resp_step = client.post("/api/v1/simulation/step?dt=0.5")
    assert resp_step.status_code == 409
    assert "Simulation cannot be stepped while in SAFE_HOLD mode" in resp_step.json()["detail"]


def test_simulation_behavior_remains_functional(client: TestClient):
    """Verify normal simulation functionality continues to work seamlessly in SIMULATION mode."""
    state_store.set_mode("SIMULATION", reason="Normal simulation verification")

    # Start CLEAN_DRAINAGE scenario
    resp_start = client.post("/api/v1/simulation/start", json={"scenario": "CLEAN_DRAINAGE", "seed": 42})
    assert resp_start.status_code == 200
    assert resp_start.json()["status"] == "success"

    # Step simulation
    resp_step = client.post("/api/v1/simulation/step?dt=0.5")
    assert resp_step.status_code == 200
    assert resp_step.json()["status"] == "success"

    # Ingest simulated telemetry
    payload = {
        "sensor_id": "US_UPSTREAM_01",
        "section_id": "SEC_SCREENING",
        "sensor_type": "WATER_LEVEL",
        "value": 5.0,
        "unit": "cm",
        "source": "SIMULATED",
        "status": "OK",
    }
    resp_telem = client.post("/api/v1/telemetry", json=payload)
    assert resp_telem.status_code == 201
    assert resp_telem.json()["status"] == "success"

    # Stop simulation
    resp_stop = client.post("/api/v1/simulation/stop")
    assert resp_stop.status_code == 200


def test_mode_transition_and_directive_synchronization():
    """Verify mode transitions and directive mutations are synchronized under lock."""
    state_store.clear()
    state_store.set_mode("SIMULATION", reason="Sync test init")

    # Concurrently perform set_mode and set_gate_directive
    def worker_set_mode(m: str):
        state_store.set_mode(m, reason=f"Switching to {m}")

    def worker_set_directive(angle: float):
        state_store.set_gate_directive(ActuatorDirectiveContract(
            gate_target_angle=angle,
            action="MAINTAIN_NORMAL",
            reason="Worker update",
        ))

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = []
        for i in range(25):
            futures.append(executor.submit(worker_set_mode, "PHYSICAL" if i % 2 == 0 else "SIMULATION"))
            futures.append(executor.submit(worker_set_directive, float(i)))
        concurrent.futures.wait(futures)

    # Post-concurrency sanity check
    assert state_store.mode in ("PHYSICAL", "SIMULATION")
    directive = state_store.get_gate_directive()
    assert directive is not None
    assert 0.0 <= directive.gate_target_angle <= 90.0
