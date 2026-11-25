import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app
from app.services.state_store import state_store
from tests.conftest import TEST_JWT_SECRET, TEST_SUPABASE_URL, create_test_token


SIMULATION_ENDPOINTS = [
    ("GET", "/api/v1/simulation/state", None),
    ("POST", "/api/v1/simulation/start", {"scenario": "GRADUAL_DEBRIS", "seed": 42}),
    ("POST", "/api/v1/simulation/stop", None),
    ("POST", "/api/v1/simulation/step?dt=0.5", None),
    ("POST", "/api/v1/simulation/inject_fault", {"fault_type": "WINCH_JAM", "sensor_id": "WINCH"}),
    ("POST", "/api/v1/simulation/mechanism/trigger", None),
    ("POST", "/api/v1/simulation/mechanism/reset", None),
]


def test_simulation_state_endpoint(municipal_client: TestClient):
    resp = municipal_client.get("/api/v1/simulation/state")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "success"
    assert "mechanism" in data
    assert "system" in data


def test_scenario_lifecycle_and_step(municipal_client: TestClient):
    # Start GRADUAL_DEBRIS scenario
    start_resp = municipal_client.post("/api/v1/simulation/start", json={"scenario": "GRADUAL_DEBRIS", "seed": 42})
    assert start_resp.status_code == 200
    assert start_resp.json()["scenario"] == "GRADUAL_DEBRIS"

    # Step simulation
    step_resp = municipal_client.post("/api/v1/simulation/step?dt=0.5")
    assert step_resp.status_code == 200
    step_data = step_resp.json()["step_result"]
    assert step_data["scenario"] == "GRADUAL_DEBRIS"
    assert "h1" in step_data

    # Stop simulation
    stop_resp = municipal_client.post("/api/v1/simulation/stop")
    assert stop_resp.status_code == 200


def test_fault_injection_endpoint(municipal_client: TestClient):
    resp = municipal_client.post(
        "/api/v1/simulation/inject_fault",
        json={"fault_type": "WINCH_JAM", "sensor_id": "WINCH"}
    )
    assert resp.status_code == 200
    assert "WINCH_JAM" in resp.json()["message"]


def test_manual_mechanism_trigger_and_reset(municipal_client: TestClient):
    # Reset first to ensure IDLE
    municipal_client.post("/api/v1/simulation/mechanism/reset")

    # Trigger cycle
    trig_resp = municipal_client.post("/api/v1/simulation/mechanism/trigger")
    assert trig_resp.status_code == 200
    assert "initiated" in trig_resp.json()["message"]

    # Reset
    reset_resp = municipal_client.post("/api/v1/simulation/mechanism/reset")
    assert reset_resp.status_code == 200


def test_halted_scenario_does_not_advance_on_step(municipal_client: TestClient):
    municipal_client.post(
        "/api/v1/simulation/start",
        json={"scenario": "GRADUAL_DEBRIS", "seed": 42},
    )
    municipal_client.post("/api/v1/simulation/step?dt=0.5")

    municipal_client.post("/api/v1/simulation/stop")
    halted_state = municipal_client.get("/api/v1/simulation/state").json()
    halted_time = halted_state["simulation_time_s"]

    step_resp = municipal_client.post("/api/v1/simulation/step?dt=1.0")
    assert step_resp.status_code == 200

    final_state = municipal_client.get("/api/v1/simulation/state").json()
    assert final_state["simulation_time_s"] == halted_time
    assert final_state["is_running"] is False


@pytest.mark.parametrize("method,path,payload", SIMULATION_ENDPOINTS)
def test_simulation_endpoints_reject_unauthenticated_when_auth_enabled(client: TestClient, monkeypatch, method, path, payload):
    monkeypatch.setattr(settings, "SUPABASE_AUTH_ENABLED", True)
    monkeypatch.setattr(settings, "SUPABASE_JWT_SECRET", TEST_JWT_SECRET)
    monkeypatch.setattr(settings, "SUPABASE_URL", TEST_SUPABASE_URL)

    resp = client.request(method, path, json=payload)
    assert resp.status_code == 401


@pytest.mark.parametrize("role", ["citizen", "worker"])
@pytest.mark.parametrize("method,path,payload", SIMULATION_ENDPOINTS)
def test_simulation_endpoints_reject_unauthorized_roles(client: TestClient, monkeypatch, role, method, path, payload):
    monkeypatch.setattr(settings, "SUPABASE_AUTH_ENABLED", True)
    monkeypatch.setattr(settings, "SUPABASE_JWT_SECRET", TEST_JWT_SECRET)
    monkeypatch.setattr(settings, "SUPABASE_URL", TEST_SUPABASE_URL)

    token = create_test_token(role=role, subject=f"test-{role}")
    resp = client.request(method, path, json=payload, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403


def test_simulation_endpoints_allow_admin_and_never_issue_physical_directives(admin_client: TestClient):
    assert state_store.is_simulation()
    before_audits = len(state_store.get_directive_audits())

    assert admin_client.get("/api/v1/simulation/state").status_code == 200
    assert admin_client.post("/api/v1/simulation/start", json={"scenario": "GRADUAL_DEBRIS", "seed": 7}).status_code == 200
    assert admin_client.post("/api/v1/simulation/step?dt=0.5").status_code == 200
    assert admin_client.post("/api/v1/simulation/mechanism/trigger").status_code == 200
    assert admin_client.post("/api/v1/simulation/mechanism/reset").status_code == 200
    assert admin_client.post("/api/v1/simulation/stop").status_code == 200

    audits = state_store.get_directive_audits()
    assert not any(getattr(a, "operational_mode", None) == "PHYSICAL" for a in audits)
