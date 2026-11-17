from fastapi.testclient import TestClient


def test_health_check(client: TestClient):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "uptime_seconds" in data
    assert "mode" in data


def test_system_status(client: TestClient):
    response = client.get("/api/v1/status")
    assert response.status_code == 200
    data = response.json()
    assert data["system_name"] == "DRAIN-X"
    assert data["mode"] in ("SIMULATION", "HARDWARE")


def test_mode_switch(admin_client: TestClient):
    # Switch to HARDWARE (canonically normalizes to PHYSICAL)
    response = admin_client.post("/api/v1/status/mode", json={"mode": "HARDWARE"})
    assert response.status_code == 200
    assert response.json()["mode"] == "PHYSICAL"

    # Switch back to SIMULATION
    response = admin_client.post("/api/v1/status/mode", json={"mode": "SIMULATION"})
    assert response.status_code == 200
    assert response.json()["mode"] == "SIMULATION"


def test_telemetry_ingest_and_retrieve(client: TestClient):
    payload = {
        "sensor_id": "TEST_US_01",
        "section_id": "SEC_SCREENING",
        "sensor_type": "WATER_LEVEL",
        "value": 6.8,
        "unit": "cm",
        "source": "SIMULATED",
        "status": "OK"
    }
    # Ingest
    response = client.post("/api/v1/telemetry", json=payload)
    assert response.status_code == 201
    assert response.json()["status"] == "success"

    # Retrieve latest
    latest_resp = client.get("/api/v1/telemetry/latest")
    assert latest_resp.status_code == 200
    latest_data = latest_resp.json()["readings"]
    assert "TEST_US_01" in latest_data
    assert latest_data["TEST_US_01"]["value"] == 6.8

    # Retrieve history
    hist_resp = client.get("/api/v1/telemetry/history/TEST_US_01")
    assert hist_resp.status_code == 200
    assert hist_resp.json()["count"] >= 1


def test_alert_lifecycle(client: TestClient):
    # Create alert
    payload = {
        "section_id": "SEC_INFLOW",
        "alert_type": "HIGH_SURGE",
        "message": "Abnormal sudden surge in inflow",
        "severity": "HIGH",
        "context_data": {"inflow_lpm": 18.5}
    }
    create_resp = client.post("/api/v1/alerts", json=payload)
    assert create_resp.status_code == 201
    alert_id = create_resp.json()["alert_id"]
    assert alert_id is not None

    # List active alerts
    list_resp = client.get("/api/v1/alerts?active_only=true")
    assert list_resp.status_code == 200
    alerts = list_resp.json()
    assert any(a["alert_id"] == alert_id for a in alerts)

    # Resolve alert
    resolve_resp = client.post(f"/api/v1/alerts/{alert_id}/resolve")
    assert resolve_resp.status_code == 200
    assert resolve_resp.json()["resolved"] is True
