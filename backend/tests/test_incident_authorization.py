"""
DRAIN-X P1.3.3 Incident Authorization Hardening Test Suite.

Verifies:
1. Unauthenticated mutation rejected with 401 when SUPABASE_AUTH_ENABLED=True.
2. Citizen role attempting PATCH /incidents/{id} rejected with 403 Forbidden.
3. Municipality role authorized for full triage, team assignment, and resolution.
4. Worker role assigned to incident can update status (e.g. to INVESTIGATING) and notes.
5. Worker role NOT assigned to incident (e.g. Team Beta vs Team Alpha) rejected with 403.
6. Worker role attempting to reassign team rejected with 403.
7. Worker role attempting to resolve incident rejected with 403.
8. Worker role attempting to reject incident rejected with 403.
9. Citizen reporting (POST /incidents) and photo upload remain open and functional.
10. Development bypass operates when auth is disabled in non-production environments.
"""

import base64
import hashlib
import hmac
import io
import json
import time
from typing import Any, Dict
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings
from app.models.contracts import IncidentCategory, IncidentSeverity, IncidentStatus
from app.services.state_store import state_store


TEST_JWT_SECRET = "incident-auth-test-secret-32-chars-long!"


def _craft_token(payload: Dict[str, Any], secret: str = TEST_JWT_SECRET) -> str:
    """Helper to craft signed HS256 JWT tokens with the test issuer."""
    payload = dict(payload)
    payload.setdefault("iss", "https://test-project.supabase.co/auth/v1")
    header = {"alg": "HS256", "typ": "JWT"}
    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signing_input = f"{h_b64}.{p_b64}"
    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    s_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return f"{signing_input}.{s_b64}"


@pytest.fixture
def auth_client():
    """Client with Supabase Auth enabled."""
    with patch.object(settings, "SUPABASE_AUTH_ENABLED", True), \
         patch.object(settings, "SUPABASE_JWT_SECRET", TEST_JWT_SECRET), \
         patch.object(settings, "SUPABASE_URL", "https://test-project.supabase.co"):
        yield TestClient(app)


@pytest.fixture
def dev_client():
    """Client with dev-bypass enabled (auth disabled, non-production)."""
    with patch.object(settings, "SUPABASE_AUTH_ENABLED", False), \
         patch.object(settings, "ENVIRONMENT", "development"):
        yield TestClient(app)


def test_unauthenticated_mutation_rejected_401(auth_client: TestClient):
    """Test 1: Unauthenticated mutation rejected with 401 when SUPABASE_AUTH_ENABLED=True."""
    response = auth_client.patch(
        "/api/v1/incidents/INC-DEMO-01",
        json={"municipal_notes": "Unauthenticated update attempt"}
    )
    assert response.status_code == 401
    assert "Authorization header" in response.json()["detail"]


def test_citizen_mutation_rejected_403(auth_client: TestClient):
    """Test 2: Authenticated Citizen token attempting PATCH /incidents/{id} rejected with 403."""
    token = _craft_token({
        "sub": "citizen-user-001",
        "exp": time.time() + 3600,
        "app_metadata": {"role": "citizen"},
        "aud": "authenticated",
    })
    headers = {"Authorization": f"Bearer {token}"}

    response = auth_client.patch(
        "/api/v1/incidents/INC-DEMO-01",
        headers=headers,
        json={"municipal_notes": "Citizen trying to edit incident notes"}
    )
    assert response.status_code == 403
    assert "Citizens are not authorized" in response.json()["detail"]


def test_municipality_authorized_triage_assignment_resolution(auth_client: TestClient):
    """Test 3: Authenticated Municipality token successfully updates status, assigns team, and resolves."""
    token = _craft_token({
        "sub": "muni-supervisor-001",
        "exp": time.time() + 3600,
        "app_metadata": {"role": "municipality"},
        "aud": "authenticated",
    })
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Create a fresh test incident
    create_resp = auth_client.post("/api/v1/incidents", json={
        "category": "DRAIN_BLOCKAGE",
        "description": "Culvert blocked near Panaji Market.",
        "latitude": 15.498,
        "longitude": 73.820,
        "severity": "HIGH",
    })
    assert create_resp.status_code == 201
    incident_id = create_resp.json()["id"]

    # 2. Municipality verifies and assigns
    patch1 = auth_client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers=headers,
        json={
            "status": "VERIFIED",
            "municipal_notes": "Verified via CCTV.",
        }
    )
    assert patch1.status_code == 200
    assert patch1.json()["status"] == "VERIFIED"

    patch2 = auth_client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers=headers,
        json={
            "status": "ASSIGNED",
            "assigned_to": "Team Alpha — Central Panaji Crew",
        }
    )
    assert patch2.status_code == 200
    assert patch2.json()["status"] == "ASSIGNED"
    assert "Team Alpha" in patch2.json()["assigned_to"]

    # 3. Transition to INVESTIGATING then RESOLVED
    patch3 = auth_client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers=headers,
        json={"status": "INVESTIGATING"}
    )
    assert patch3.status_code == 200

    patch4 = auth_client.patch(
        f"/api/v1/incidents/{incident_id}",
        headers=headers,
        json={
            "status": "RESOLVED",
            "municipal_notes": "Cleared and validated by municipality supervisor.",
        }
    )
    assert patch4.status_code == 200
    assert patch4.json()["status"] == "RESOLVED"


def test_assigned_worker_can_update_status_and_notes(auth_client: TestClient):
    """Test 4: Authenticated Worker assigned to incident can update status (e.g. to INVESTIGATING) and add notes."""
    # Worker belongs to Team Alpha
    token = _craft_token({
        "sub": "worker-user-alpha-01",
        "exp": time.time() + 3600,
        "app_metadata": {"role": "worker", "team": "Team Alpha"},
        "aud": "authenticated",
    })
    headers = {"Authorization": f"Bearer {token}"}

    # Create fresh incident assigned to Team Alpha
    create_resp = auth_client.post("/api/v1/incidents", json={
        "category": "WATERLOGGING",
        "description": "Heavy water accumulation at Miramar Circle.",
        "latitude": 15.485,
        "longitude": 73.810,
        "severity": "CRITICAL",
    })
    inc_id = create_resp.json()["id"]

    # Advance via state_store to ASSIGNED to Team Alpha
    from app.models.contracts import IncidentUpdateContract
    state_store.update_incident(inc_id, IncidentUpdateContract(status=IncidentStatus.VERIFIED))
    state_store.update_incident(inc_id, IncidentUpdateContract(status=IncidentStatus.ASSIGNED, assigned_to="Team Alpha — Miramar Unit"))

    # Worker updates to INVESTIGATING
    worker_patch = auth_client.patch(
        f"/api/v1/incidents/{inc_id}",
        headers=headers,
        json={
            "status": "INVESTIGATING",
            "municipal_notes": "Crew arrived on-site with pump truck.",
        }
    )
    assert worker_patch.status_code == 200
    assert worker_patch.json()["status"] == "INVESTIGATING"
    assert "pump truck" in worker_patch.json()["municipal_notes"]


def test_unassigned_worker_rejected_403(auth_client: TestClient):
    """Test 5: Authenticated Worker NOT assigned to incident (Team Beta vs Team Alpha) rejected with 403."""
    # Worker belongs to Team Beta
    token = _craft_token({
        "sub": "worker-user-beta-01",
        "exp": time.time() + 3600,
        "app_metadata": {"role": "worker", "team": "Team Beta"},
        "aud": "authenticated",
    })
    headers = {"Authorization": f"Bearer {token}"}

    # Incident assigned to Team Alpha
    create_resp = auth_client.post("/api/v1/incidents", json={
        "category": "DRAIN_OVERFLOW",
        "description": "Overflowing manhole near bus stand.",
        "latitude": 15.490,
        "longitude": 73.815,
        "severity": "HIGH",
    })
    inc_id = create_resp.json()["id"]
    from app.models.contracts import IncidentUpdateContract
    state_store.update_incident(inc_id, IncidentUpdateContract(status=IncidentStatus.VERIFIED))
    state_store.update_incident(inc_id, IncidentUpdateContract(status=IncidentStatus.ASSIGNED, assigned_to="Team Alpha — Panaji"))

    # Team Beta worker attempts update -> 403 Forbidden
    response = auth_client.patch(
        f"/api/v1/incidents/{inc_id}",
        headers=headers,
        json={"status": "INVESTIGATING"}
    )
    assert response.status_code == 403
    assert "only update incidents assigned to their crew" in response.json()["detail"]


def test_worker_cannot_reassign_incident_403(auth_client: TestClient):
    """Test 6: Authenticated Worker attempting to reassign incident rejected with 403."""
    token = _craft_token({
        "sub": "worker-user-alpha-02",
        "exp": time.time() + 3600,
        "app_metadata": {"role": "worker", "team": "Team Alpha"},
        "aud": "authenticated",
    })
    headers = {"Authorization": f"Bearer {token}"}

    create_resp = auth_client.post("/api/v1/incidents", json={
        "category": "DRAIN_BLOCKAGE",
        "description": "Grate blocked by debris.",
        "latitude": 15.492,
        "longitude": 73.818,
        "severity": "MEDIUM",
    })
    inc_id = create_resp.json()["id"]
    from app.models.contracts import IncidentUpdateContract
    state_store.update_incident(inc_id, IncidentUpdateContract(status=IncidentStatus.VERIFIED))
    state_store.update_incident(inc_id, IncidentUpdateContract(status=IncidentStatus.ASSIGNED, assigned_to="Team Alpha"))

    # Worker attempts reassigning to Team Beta
    response = auth_client.patch(
        f"/api/v1/incidents/{inc_id}",
        headers=headers,
        json={"assigned_to": "Team Beta"}
    )
    assert response.status_code == 403
    assert "not permitted to reassign" in response.json()["detail"]


def test_worker_cannot_resolve_incident_403(auth_client: TestClient):
    """Test 7: Authenticated Worker attempting to resolve incident rejected with 403."""
    token = _craft_token({
        "sub": "worker-user-alpha-03",
        "exp": time.time() + 3600,
        "app_metadata": {"role": "worker", "team": "Team Alpha"},
        "aud": "authenticated",
    })
    headers = {"Authorization": f"Bearer {token}"}

    create_resp = auth_client.post("/api/v1/incidents", json={
        "category": "DRAIN_BLOCKAGE",
        "description": "Blockage at St. Inez Creek.",
        "latitude": 15.491,
        "longitude": 73.822,
        "severity": "HIGH",
    })
    inc_id = create_resp.json()["id"]
    from app.models.contracts import IncidentUpdateContract
    state_store.update_incident(inc_id, IncidentUpdateContract(status=IncidentStatus.VERIFIED))
    state_store.update_incident(inc_id, IncidentUpdateContract(status=IncidentStatus.ASSIGNED, assigned_to="Team Alpha"))
    state_store.update_incident(inc_id, IncidentUpdateContract(status=IncidentStatus.INVESTIGATING))

    # Worker attempts resolving
    response = auth_client.patch(
        f"/api/v1/incidents/{inc_id}",
        headers=headers,
        json={"status": "RESOLVED"}
    )
    assert response.status_code == 403
    assert "Incident resolution requires municipal supervisor" in response.json()["detail"]


def test_worker_cannot_reject_incident_403(auth_client: TestClient):
    """Test 8: Authenticated Worker attempting to reject incident rejected with 403."""
    token = _craft_token({
        "sub": "worker-user-alpha-04",
        "exp": time.time() + 3600,
        "app_metadata": {"role": "worker", "team": "Team Alpha"},
        "aud": "authenticated",
    })
    headers = {"Authorization": f"Bearer {token}"}

    create_resp = auth_client.post("/api/v1/incidents", json={
        "category": "DRAIN_BLOCKAGE",
        "description": "Culvert blockage.",
        "latitude": 15.491,
        "longitude": 73.822,
        "severity": "LOW",
    })
    inc_id = create_resp.json()["id"]
    from app.models.contracts import IncidentUpdateContract
    state_store.update_incident(inc_id, IncidentUpdateContract(status=IncidentStatus.VERIFIED))
    state_store.update_incident(inc_id, IncidentUpdateContract(status=IncidentStatus.ASSIGNED, assigned_to="Team Alpha"))

    # Worker attempts rejecting
    response = auth_client.patch(
        f"/api/v1/incidents/{inc_id}",
        headers=headers,
        json={"status": "REJECTED"}
    )
    assert response.status_code == 403
    assert "Incident rejection requires municipal supervisor" in response.json()["detail"]


def test_citizen_reporting_and_photo_upload_remain_open(auth_client: TestClient):
    """Test 9: Citizen reporting (POST /incidents) and photo upload remain open and functional."""
    # Create incident without authorization header (public citizen report)
    create_resp = auth_client.post("/api/v1/incidents", json={
        "category": "WATERLOGGING",
        "description": "Water logging in front of local dispensary.",
        "latitude": 15.493,
        "longitude": 73.816,
        "severity": "MEDIUM",
        "source": "CITIZEN",
        "reporter_name": "Citizen User",
    })
    assert create_resp.status_code == 201
    inc_id = create_resp.json()["id"]

    # Upload a photo to the newly created incident
    from tests.conftest import create_test_image
    test_jpeg = create_test_image("JPEG")
    files = [("files", ("photo1.jpg", test_jpeg, "image/jpeg"))]
    upload_resp = auth_client.post(f"/api/v1/incidents/{inc_id}/photos", files=files)
    assert upload_resp.status_code == 200
    assert len(upload_resp.json()["photos"]) == 1


def test_auth_disabled_protected_mutation_fails_closed(dev_client: TestClient):
    """Protected routes must never silently impersonate an admin when auth is disabled."""
    create_resp = dev_client.post("/api/v1/incidents", json={
        "category": "DRAIN_BLOCKAGE",
        "description": "Dev mode test incident.",
        "latitude": 15.495,
        "longitude": 73.819,
        "severity": "LOW",
    })
    assert create_resp.status_code == 201
    inc_id = create_resp.json()["id"]

    patch_resp = dev_client.patch(
        f"/api/v1/incidents/{inc_id}",
        json={"status": "VERIFIED", "municipal_notes": "Must not bypass auth"},
    )
    assert patch_resp.status_code == 503
    assert "Authentication is disabled" in patch_resp.json()["detail"]
