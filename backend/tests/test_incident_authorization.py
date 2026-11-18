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
from app.models.contracts import (
    AssignmentType,
    IncidentCategory,
    IncidentResponseContract,
    IncidentSeverity,
    IncidentStatus,
    IncidentUpdateContract,
)
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


# ============================================================================
# P1.3.6.2.4 Hardening & Regression Test Suite
# ============================================================================

def _worker_headers(sub="worker-alpha-01", team="Team Alpha"):
    token = _craft_token({
        "sub": sub,
        "exp": time.time() + 3600,
        "app_metadata": {"role": "worker", "team": team},
        "aud": "authenticated",
    })
    return {"Authorization": f"Bearer {token}"}


def _muni_headers(sub="muni-supervisor-01"):
    token = _craft_token({
        "sub": sub,
        "exp": time.time() + 3600,
        "app_metadata": {"role": "municipality"},
        "aud": "authenticated",
    })
    return {"Authorization": f"Bearer {token}"}


def test_worker_submitting_null_internal_notes_rejected_403(auth_client: TestClient):
    """TASK 1: Worker submitting {"internal_notes": null} must be rejected with 403."""
    headers = _worker_headers()
    response = auth_client.patch(
        "/api/v1/incidents/INC-DEMO-01",
        headers=headers,
        json={"internal_notes": None},
    )
    assert response.status_code == 403
    assert "Field workers are not permitted to set internal municipal notes." in response.json()["detail"]


def test_worker_submitting_string_internal_notes_rejected_403(auth_client: TestClient):
    """TASK 1: Worker submitting {"internal_notes": "..."} must be rejected with 403."""
    headers = _worker_headers()
    response = auth_client.patch(
        "/api/v1/incidents/INC-DEMO-01",
        headers=headers,
        json={"internal_notes": "Worker unauthorized internal note."},
    )
    assert response.status_code == 403
    assert "Field workers are not permitted to set internal municipal notes." in response.json()["detail"]


def test_worker_submitting_verified_by_null_or_string_rejected_403(auth_client: TestClient):
    """TASK 1: Worker submitting verified_by (null or string) must be rejected with 403."""
    headers = _worker_headers()
    for val in (None, "Worker Self-Verification"):
        response = auth_client.patch(
            "/api/v1/incidents/INC-DEMO-01",
            headers=headers,
            json={"verified_by": val},
        )
        assert response.status_code == 403
        assert "verified_by" in response.json()["detail"]


def test_worker_submitting_rejection_reason_null_or_string_rejected_403(auth_client: TestClient):
    """TASK 1: Worker submitting rejection_reason (null or string) must be rejected with 403."""
    headers = _worker_headers()
    for val in (None, "Worker unauthorized rejection reason"):
        response = auth_client.patch(
            "/api/v1/incidents/INC-DEMO-01",
            headers=headers,
            json={"rejection_reason": val},
        )
        assert response.status_code == 403
        assert "rejection_reason" in response.json()["detail"]


def test_worker_submitting_assignment_fields_null_or_value_rejected_403(auth_client: TestClient):
    """TASK 1: Worker submitting any assignment field (null or non-null) must be rejected with 403."""
    headers = _worker_headers()
    test_cases = [
        ("assigned_to", None),
        ("assigned_to", "Team Beta"),
        ("assignment_type", None),
        ("assignment_type", "NONE"),
        ("assigned_team_id", None),
        ("assigned_team_id", "team-beta"),
        ("assigned_worker_id", None),
        ("assigned_worker_id", "worker-rogue"),
    ]
    for field_name, value in test_cases:
        response = auth_client.patch(
            "/api/v1/incidents/INC-DEMO-01",
            headers=headers,
            json={field_name: value},
        )
        assert response.status_code == 403
        assert "Field workers are not permitted to reassign incidents or modify assignment metadata." in response.json()["detail"]


def test_worker_omitting_protected_fields_legitimate_update_succeeds(auth_client: TestClient):
    """TASK 1: Legitimate worker operational update without protected fields succeeds with 200."""
    headers = _worker_headers()
    response = auth_client.patch(
        "/api/v1/incidents/INC-DEMO-01",
        headers=headers,
        json={
            "status": "INVESTIGATING",
            "municipal_notes": "Crew arrived on scene with jetting machine.",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "INVESTIGATING"
    assert "Crew arrived" in data["municipal_notes"]


def test_direct_statestore_worker_protected_fields_rejected():
    """TASK 2: Direct StateStore calls with actor_role='worker' reject all protected fields."""
    protected_cases = [
        {"assigned_to": None},
        {"assigned_to": "TEAM-OTHER"},
        {"assignment_type": AssignmentType.NONE},
        {"assigned_team_id": None},
        {"assigned_worker_id": None},
        {"internal_notes": None},
        {"internal_notes": "Direct worker internal note"},
        {"verified_by": None},
        {"verified_by": "Worker Self"},
        {"rejection_reason": None},
        {"rejection_reason": "Worker direct reject"},
    ]
    for kwargs in protected_cases:
        update_contract = IncidentUpdateContract(**kwargs)
        with pytest.raises(ValueError, match="Field workers are not permitted"):
            state_store.update_incident(
                incident_id="INC-DEMO-01",
                update=update_contract,
                actor_id="worker-01",
                actor_role="worker",
            )


def test_municipality_admin_can_update_and_clear_internal_notes(auth_client: TestClient):
    """TASK 2 & 5: Municipality can update and explicitly clear internal notes."""
    headers = _muni_headers()

    # Step 1: Set internal note
    resp1 = auth_client.patch(
        "/api/v1/incidents/INC-DEMO-01",
        headers=headers,
        json={"internal_notes": "Confidential supervisor notes #1234"},
    )
    assert resp1.status_code == 200
    assert resp1.json()["internal_notes"] == "Confidential supervisor notes #1234"

    # Step 2: Clear internal note explicitly by submitting null
    resp2 = auth_client.patch(
        "/api/v1/incidents/INC-DEMO-01",
        headers=headers,
        json={"internal_notes": None},
    )
    assert resp2.status_code == 200
    assert resp2.json()["internal_notes"] is None


def test_terminal_incident_immutability_api_and_store(auth_client: TestClient):
    """TASK 2 & 5: Resolved and rejected incidents are immutable via API (409) and StateStore (ValueError)."""
    muni = _muni_headers()

    # Create an incident
    create_resp = auth_client.post("/api/v1/incidents", json={
        "category": "DRAIN_BLOCKAGE",
        "description": "Terminal immutability test incident",
        "latitude": 15.495,
        "longitude": 73.819,
    })
    inc_id = create_resp.json()["id"]

    # Transition to REJECTED (terminal state) via supervisory endpoint
    rej_resp = auth_client.post(
        f"/api/v1/incidents/{inc_id}/reject",
        headers=muni,
        json={"reason": "Invalid or duplicate complaint"},
    )
    assert rej_resp.status_code == 200
    assert rej_resp.json()["status"] == "REJECTED"

    # Subsequent API PATCH must return 409 Conflict
    patch_resp = auth_client.patch(
        f"/api/v1/incidents/{inc_id}",
        headers=muni,
        json={"municipal_notes": "Attempt modification after reject"},
    )
    assert patch_resp.status_code == 409
    assert "Resolved or rejected incidents cannot be modified." in patch_resp.json()["detail"]

    # Direct StateStore call must raise ValueError
    with pytest.raises(ValueError, match="Cannot modify terminal incident"):
        state_store.update_incident(
            incident_id=inc_id,
            update=IncidentUpdateContract(municipal_notes="Store bypass attempt"),
            actor_id="supervisor-01",
            actor_role="municipality",
        )


def test_audit_and_persistence_state_isolation():
    """TASK 3 & 5: Verify autouse fixture cleanly isolates audit ledger and persistence counters."""
    from app.services.persistence_repository import persistence_repo

    # Check repository counters are cleanly reset at test start
    assert persistence_repo._total_persisted_count == 0
    assert persistence_repo._failed_persistence_count == 0
    assert persistence_repo._last_persistence_error is None
    assert persistence_repo._connection_status == "UNCONFIGURED"

    # Check device registry retains default device
    assert "DRAINX-ESP32-NODE-01" in persistence_repo._in_memory_devices

    # Check audit ledger in state store contains only the 4 freshly seeded demo incidents
    # and no leaked custom test incident IDs from previous tests.
    assert set(state_store._incident_audits.keys()) == {"INC-DEMO-01", "INC-DEMO-02", "INC-DEMO-03", "INC-DEMO-04"}
    assert len(state_store.get_incident_audits("INC-CUSTOM-LEAKED-TEST")) == 0


def test_supabase_constructor_fallback_scenarios(monkeypatch):
    """TASK 4 & 5: Verify all 6 constructor scenarios and cross-project credential protection."""
    from app.services.persistence_repository import PersistenceRepository

    # Configure mock settings
    monkeypatch.setattr(settings, "SUPABASE_URL", "https://default-project.supabase.co")
    monkeypatch.setattr(settings, "SUPABASE_KEY", "default-anon-key")
    monkeypatch.setattr(settings, "SUPABASE_SERVICE_ROLE_KEY", "default-service-role-key")

    # 1. No arguments: falls back to settings
    repo1 = PersistenceRepository()
    assert repo1._supabase_url == "https://default-project.supabase.co"
    assert repo1._supabase_key == "default-anon-key"
    assert repo1._supabase_service_role_key == "default-service-role-key"
    assert repo1.is_configured is True

    # 2. All arguments explicitly None: all disabled
    repo2 = PersistenceRepository(None, None, None)
    assert repo2._supabase_url == ""
    assert repo2._supabase_key == ""
    assert repo2._supabase_service_role_key == ""
    assert repo2.is_configured is False

    # 3. URL only (custom project): does NOT leak default project keys to custom URL
    repo3 = PersistenceRepository(supabase_url="https://custom-project.supabase.co")
    assert repo3._supabase_url == "https://custom-project.supabase.co"
    assert repo3._supabase_key == ""
    assert repo3._supabase_service_role_key == ""
    assert repo3.is_configured is False

    # 4. Public key only (custom key): does NOT attach custom key to default URL
    repo4 = PersistenceRepository(supabase_key="custom-anon-key")
    assert repo4._supabase_url == ""
    assert repo4._supabase_key == "custom-anon-key"
    assert repo4._supabase_service_role_key == ""
    assert repo4.is_configured is False

    # 5. Service-role key only (custom key): does NOT attach custom service key to default URL
    repo5 = PersistenceRepository(service_role_key="custom-service-role-key")
    assert repo5._supabase_url == ""
    assert repo5._supabase_key == ""
    assert repo5._supabase_service_role_key == "custom-service-role-key"
    assert repo5.is_configured is False

    # 6. Explicit empty strings
    repo6 = PersistenceRepository("", "")
    assert repo6._supabase_url == ""
    assert repo6._supabase_key == ""
    assert repo6._supabase_service_role_key == ""
    assert repo6.is_configured is False

    # 7. Coherent custom pairing: custom URL + custom key works properly
    repo7 = PersistenceRepository(
        supabase_url="https://custom.supabase.co",
        supabase_key="custom-key-123",
    )
    assert repo7._supabase_url == "https://custom.supabase.co"
    assert repo7._supabase_key == "custom-key-123"
    assert repo7.is_configured is True
        # 8. Disabling service-role key preserves default anon credentials.
    repo8 = PersistenceRepository(service_role_key=None)
    assert repo8._supabase_url == "https://default-project.supabase.co"
    assert repo8._supabase_key == "default-anon-key"
    assert repo8._supabase_service_role_key == ""
    assert repo8.is_configured is True

    # 9. Disabling anon key preserves default service-role credentials.
    repo9 = PersistenceRepository(supabase_key=None)
    assert repo9._supabase_url == "https://default-project.supabase.co"
    assert repo9._supabase_key == ""
    assert repo9._supabase_service_role_key == "default-service-role-key"
    assert repo9.is_configured is True

    # 10. Whitespace-normalized matching credentials retain the default URL.
    repo10 = PersistenceRepository(supabase_key=" default-anon-key ")
    assert repo10._supabase_url == "https://default-project.supabase.co"
    assert repo10._supabase_key == "default-anon-key"
    assert repo10._supabase_service_role_key == "default-service-role-key"
    assert repo10.is_configured is True
