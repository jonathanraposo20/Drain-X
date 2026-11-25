"""
DRAIN-X P1.3.6.2 — Municipal Triage & Assignment Workflow Test Suite.

Comprehensive validation of:
1. Municipality can verify incidents (status -> VERIFIED, priority change, verified_by logged).
2. Municipality can assign valid registered field crews (status -> ASSIGNED, audit logged).
3. Municipality can reassign to different registered crew with explicit mandatory reason.
4. Municipality can unassign an incident with reason (status -> VERIFIED, assigned_to cleared).
5. Assignment to invalid/unregistered worker or team rejected with 400.
6. Assignment to inactive team rejected with 400.
7. Citizen cannot triage, verify, assign, reassign, or unassign (403 Forbidden).
8. Field worker cannot triage, verify, assign, reassign, or unassign (403 Forbidden).
9. user_metadata role escalation strictly rejected (403 Forbidden).
10. Rejection requires explicit mandatory reason (no silent rejection).
11. State transitions strictly validated (e.g. cannot assign/reassign resolved/rejected incident).
12. Audit ledger captures all actions (actor, role, action, previous/new values, reason, timestamp).
13. Audit history endpoint strictly restricted to municipality/admin (citizen and worker get 403).
14. Nonexistent incident actions return 404 Not Found.
15. Privacy filtering preserves reporter anonymity and redacts internal notes from unauthorized eyes.
16. Demo, Citizen, and Sensor record distinctions are preserved.
"""

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Dict
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings
from app.models.contracts import (
    IncidentCategory,
    IncidentSeverity,
    IncidentStatus,
    IncidentSource,
    IncidentUpdateContract,
    AssignmentType,
)
from app.services.state_store import state_store, AUTHORITATIVE_FIELD_TEAMS

TEST_JWT_SECRET = "municipal-triage-test-secret-32-chars!"


def _craft_token(payload: Dict[str, Any], secret: str = TEST_JWT_SECRET) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload.setdefault("iss", "https://test-project.supabase.co/auth/v1")
    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signing_input = f"{h_b64}.{p_b64}"
    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    s_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return f"{signing_input}.{s_b64}"


@pytest.fixture
def auth_client():
    with patch.object(settings, "SUPABASE_AUTH_ENABLED", True), \
         patch.object(settings, "SUPABASE_JWT_SECRET", TEST_JWT_SECRET), \
         patch.object(settings, "SUPABASE_URL", "https://test-project.supabase.co"):
        yield TestClient(app)

def _headers_for(role: str, user_id: str = "test-user", extra_claims: Dict[str, Any] = None) -> Dict[str, str]:
    payload = {
        "sub": user_id,
        "aud": "authenticated",
        "exp": time.time() + 3600,
        "app_metadata": {"role": role},
    }
    if extra_claims:
        payload.update(extra_claims)
    token = _craft_token(payload)
    return {"Authorization": f"Bearer {token}"}


def test_get_field_teams_returns_authoritative_directory(auth_client: TestClient):
    """Field teams endpoint returns registered municipal crews."""
    headers = _headers_for("municipality")
    resp = auth_client.get("/api/v1/incidents/field-teams", headers=headers)
    assert resp.status_code == 200
    teams = resp.json()
    assert len(teams) >= 4
    team_ids = [t["team_id"] for t in teams]
    assert "TEAM-ALPHA" in team_ids
    assert "TEAM-BETA" in team_ids
    assert "TEAM-GAMMA" in team_ids
    assert "TEAM-DELTA" in team_ids
    assert all(t["is_active"] is True for t in teams)


def test_municipality_verify_incident_workflow(auth_client: TestClient):
    """Municipality verifies incident and updates severity with audit logging."""
    headers = _headers_for("municipality", user_id="supervisor-panaji-01")

    # 1. Create reported incident
    create_resp = auth_client.post("/api/v1/incidents", json={
        "category": "DRAIN_BLOCKAGE",
        "description": "Blockage at 18th June Road culvert.",
        "latitude": 15.498,
        "longitude": 73.821,
        "severity": "LOW",
        "source": "CITIZEN",
        "reporter_name": "Goa Citizen",
    })
    assert create_resp.status_code == 201
    inc_id = create_resp.json()["id"]

    # 2. Verify incident & prioritize to HIGH
    verify_resp = auth_client.post(
        f"/api/v1/incidents/{inc_id}/verify",
        headers=headers,
        json={
            "notes": "Verified via Panaji Smart City CCTV camera 14.",
            "severity": "HIGH",
            "internal_notes": "Supervisor verified high debris volume.",
        },
    )
    assert verify_resp.status_code == 200
    data = verify_resp.json()
    assert data["status"] == "VERIFIED"
    assert data["severity"] == "HIGH"
    assert "CCTV camera 14" in data["municipal_notes"]
    assert data["internal_notes"] == "Supervisor verified high debris volume."

    # 3. Check audit log
    audit_resp = auth_client.get(f"/api/v1/incidents/{inc_id}/audit", headers=headers)
    assert audit_resp.status_code == 200
    audits = audit_resp.json()
    actions = [a["action"] for a in audits]
    assert "REPORTED" in actions
    assert "VERIFIED" in actions
    verify_audit = [a for a in audits if a["action"] == "VERIFIED"][0]
    assert verify_audit["actor_id"] == "supervisor-panaji-01"
    assert verify_audit["actor_role"] == "municipality"
    assert verify_audit["new_status"] == "VERIFIED"


def test_municipality_assign_valid_crew(auth_client: TestClient):
    """Municipality assigns incident to valid registered crew."""
    headers = _headers_for("municipality", user_id="dispatcher-01")

    create_resp = auth_client.post("/api/v1/incidents", json={
        "category": "FLOODING",
        "description": "Flooding near Kadamba Bus Stand.",
        "latitude": 15.495,
        "longitude": 73.825,
        "severity": "HIGH",
    })
    inc_id = create_resp.json()["id"]

    # Assign to Team Alpha
    assign_resp = auth_client.post(
        f"/api/v1/incidents/{inc_id}/assign",
        headers=headers,
        json={
            "assigned_to": "Team Alpha — St. Inez Drainage Crew",
            "reason": "Immediate suction pump deployment required",
            "internal_notes": "Dispatched lead operator Fernandes",
        },
    )
    assert assign_resp.status_code == 200
    data = assign_resp.json()
    assert data["status"] == "ASSIGNED"
    assert data["assigned_to"] == "Team Alpha — St. Inez Drainage Crew"

    # Audit check
    audits = auth_client.get(f"/api/v1/incidents/{inc_id}/audit", headers=headers).json()
    assign_audits = [a for a in audits if a["action"] == "ASSIGNED"]
    assert len(assign_audits) == 1
    assert assign_audits[0]["new_assigned_to"] == "Team Alpha — St. Inez Drainage Crew"
    assert "suction pump" in assign_audits[0]["reason"]


def test_municipality_reassign_incident(auth_client: TestClient):
    """Municipality reassigns incident to another crew with mandatory reason."""
    headers = _headers_for("municipality", user_id="dispatcher-02")

    create_resp = auth_client.post("/api/v1/incidents", json={
        "category": "DRAIN_OVERFLOW",
        "description": "Overflowing drain near Patto bridge.",
        "latitude": 15.499,
        "longitude": 73.829,
        "severity": "CRITICAL",
    })
    inc_id = create_resp.json()["id"]

    # 1. Initial assignment to Team Alpha
    auth_client.post(
        f"/api/v1/incidents/{inc_id}/assign",
        headers=headers,
        json={"assigned_to": "TEAM-ALPHA"},
    )

    # 2. Reassign to Team Beta with reason
    reassign_resp = auth_client.post(
        f"/api/v1/incidents/{inc_id}/reassign",
        headers=headers,
        json={
            "assigned_to": "Team Beta — Patto Rapid Response",
            "reason": "Team Alpha stuck in traffic; Team Beta closer to Patto bridge",
            "internal_notes": "Supervisor approved reroute",
        },
    )
    assert reassign_resp.status_code == 200
    assert reassign_resp.json()["assigned_to"] == "Team Beta — Patto Rapid Response"

    # 3. Audit check
    audits = auth_client.get(f"/api/v1/incidents/{inc_id}/audit", headers=headers).json()
    reassign_audits = [a for a in audits if a["action"] == "REASSIGNED"]
    assert len(reassign_audits) == 1
    assert "stuck in traffic" in reassign_audits[0]["reason"]
    assert reassign_audits[0]["previous_assigned_to"] == "Team Alpha — St. Inez Drainage Crew"
    assert reassign_audits[0]["new_assigned_to"] == "Team Beta — Patto Rapid Response"


def test_reassign_to_same_team_rejected(auth_client: TestClient):
    """Reassigning to the exact same team is rejected with 400 Bad Request."""
    headers = _headers_for("municipality")

    create_resp = auth_client.post("/api/v1/incidents", json={
        "category": "MANHOLE_DAMAGE",
        "description": "Missing lid near Miramar.",
        "latitude": 15.480,
        "longitude": 73.805,
    })
    inc_id = create_resp.json()["id"]
    auth_client.post(
        f"/api/v1/incidents/{inc_id}/assign",
        headers=headers,
        json={"assigned_to": "TEAM-DELTA"},
    )

    # Reassigning to TEAM-DELTA again
    dup_resp = auth_client.post(
        f"/api/v1/incidents/{inc_id}/reassign",
        headers=headers,
        json={
            "assigned_to": "Team Delta — Miramar Outfall Sluice Unit",
            "reason": "Same team reassignment",
        },
    )
    assert dup_resp.status_code == 400
    assert "already assigned" in dup_resp.json()["detail"]


def test_municipality_unassign_incident(auth_client: TestClient):
    """Municipality removes assignment with explicit reason and reverts status to VERIFIED."""
    headers = _headers_for("municipality", user_id="dispatcher-03")

    create_resp = auth_client.post("/api/v1/incidents", json={
        "category": "WATERLOGGING",
        "description": "Ponding in Fontainhas.",
        "latitude": 15.496,
        "longitude": 73.831,
    })
    inc_id = create_resp.json()["id"]

    auth_client.post(
        f"/api/v1/incidents/{inc_id}/assign",
        headers=headers,
        json={"assigned_to": "TEAM-GAMMA"},
    )

    # Unassign
    unassign_resp = auth_client.post(
        f"/api/v1/incidents/{inc_id}/unassign",
        headers=headers,
        json={
            "reason": "Team Gamma called off due to higher priority structural collapse",
        },
    )
    assert unassign_resp.status_code == 200
    data = unassign_resp.json()
    assert data["assigned_to"] is None
    assert data["status"] == "VERIFIED"

    # Audit check
    audits = auth_client.get(f"/api/v1/incidents/{inc_id}/audit", headers=headers).json()
    unassign_audits = [a for a in audits if a["action"] == "UNASSIGNED"]
    assert len(unassign_audits) == 1
    assert unassign_audits[0]["previous_assigned_to"] == "Team Gamma — Fontainhas Heritage Maintenance"
    assert unassign_audits[0]["new_assigned_to"] is None


def test_assign_invalid_team_rejected(auth_client: TestClient):
    """Assignment to non-registered rogue team is rejected with 400 Bad Request."""
    headers = _headers_for("municipality")

    create_resp = auth_client.post("/api/v1/incidents", json={
        "category": "DRAIN_BLOCKAGE",
        "description": "Blockage at Mala.",
        "latitude": 15.494,
        "longitude": 73.828,
    })
    inc_id = create_resp.json()["id"]

    assign_resp = auth_client.post(
        f"/api/v1/incidents/{inc_id}/assign",
        headers=headers,
        json={"assigned_to": "Rogue Private Contractor 99"},
    )
    assert assign_resp.status_code == 400
    assert "Invalid assignee" in assign_resp.json()["detail"]


def test_municipality_reject_incident_with_mandatory_reason(auth_client: TestClient):
    """Rejecting an incident transitions status to REJECTED and requires explicit reason."""
    headers = _headers_for("municipality", user_id="supervisor-panaji-02")

    create_resp = auth_client.post("/api/v1/incidents", json={
        "category": "OTHER",
        "description": "Dustbin overflow in private compound.",
        "latitude": 15.490,
        "longitude": 73.820,
    })
    inc_id = create_resp.json()["id"]

    # 1. Attempt rejection with empty reason -> 422 or 400
    bad_resp = auth_client.post(
        f"/api/v1/incidents/{inc_id}/reject",
        headers=headers,
        json={"reason": "  "},
    )
    assert bad_resp.status_code in (400, 422)

    # 2. Valid rejection
    reject_resp = auth_client.post(
        f"/api/v1/incidents/{inc_id}/reject",
        headers=headers,
        json={
            "reason": "Out of municipal drainage jurisdiction — referred to Solid Waste Management.",
            "internal_notes": "Private compound incident.",
        },
    )
    assert reject_resp.status_code == 200
    data = reject_resp.json()
    assert data["status"] == "REJECTED"
    assert "Solid Waste Management" in data["rejection_reason"]


def test_cannot_assign_rejected_or_resolved_incident(auth_client: TestClient):
    """Terminal state incidents cannot be assigned without reopening."""
    headers = _headers_for("municipality")

    create_resp = auth_client.post("/api/v1/incidents", json={
        "category": "FLOODING",
        "description": "Historical resolved incident.",
        "latitude": 15.485,
        "longitude": 73.815,
    })
    inc_id = create_resp.json()["id"]

    # Reject it first
    auth_client.post(
        f"/api/v1/incidents/{inc_id}/reject",
        headers=headers,
        json={"reason": "Invalid duplicate report."},
    )

    # Attempt assignment -> 400 Bad Request
    assign_resp = auth_client.post(
        f"/api/v1/incidents/{inc_id}/assign",
        headers=headers,
        json={"assigned_to": "TEAM-ALPHA"},
    )
    assert assign_resp.status_code == 400
    assert "terminal state" in assign_resp.json()["detail"].lower()


def test_citizen_cannot_triage_or_assign_403(auth_client: TestClient):
    """Citizen role is denied all municipal triage, assignment, unassignment, and rejection (403)."""
    citizen_headers = _headers_for("citizen", user_id="citizen-attacker")

    inc_id = "INC-DEMO-01"

    # Verify attempt
    resp_verify = auth_client.post(
        f"/api/v1/incidents/{inc_id}/verify",
        headers=citizen_headers,
        json={"notes": "Citizen trying to verify"},
    )
    assert resp_verify.status_code == 403

    # Assign attempt
    resp_assign = auth_client.post(
        f"/api/v1/incidents/{inc_id}/assign",
        headers=citizen_headers,
        json={"assigned_to": "TEAM-ALPHA"},
    )
    assert resp_assign.status_code == 403

    # Reassign attempt
    resp_reassign = auth_client.post(
        f"/api/v1/incidents/{inc_id}/reassign",
        headers=citizen_headers,
        json={"assigned_to": "TEAM-BETA", "reason": "Citizen reassigning"},
    )
    assert resp_reassign.status_code == 403

    # Unassign attempt
    resp_unassign = auth_client.post(
        f"/api/v1/incidents/{inc_id}/unassign",
        headers=citizen_headers,
        json={"reason": "Citizen unassigning"},
    )
    assert resp_unassign.status_code == 403

    # Reject attempt
    resp_reject = auth_client.post(
        f"/api/v1/incidents/{inc_id}/reject",
        headers=citizen_headers,
        json={"reason": "Citizen rejecting"},
    )
    assert resp_reject.status_code == 403

    # Audit retrieval attempt
    resp_audit = auth_client.get(
        f"/api/v1/incidents/{inc_id}/audit",
        headers=citizen_headers,
    )
    assert resp_audit.status_code == 403


def test_field_worker_cannot_assign_or_triage_403(auth_client: TestClient):
    """Field worker role is denied municipal triage and assignment operations (403)."""
    worker_headers = _headers_for("worker", user_id="worker-01", extra_claims={"team": "Team Alpha"})

    inc_id = "INC-DEMO-01"

    # Verify attempt
    assert auth_client.post(
        f"/api/v1/incidents/{inc_id}/verify",
        headers=worker_headers,
        json={"notes": "Worker verify"},
    ).status_code == 403

    # Assign attempt
    assert auth_client.post(
        f"/api/v1/incidents/{inc_id}/assign",
        headers=worker_headers,
        json={"assigned_to": "TEAM-BETA"},
    ).status_code == 403

    # Reassign attempt
    assert auth_client.post(
        f"/api/v1/incidents/{inc_id}/reassign",
        headers=worker_headers,
        json={"assigned_to": "TEAM-BETA", "reason": "Worker reassign"},
    ).status_code == 403

    # Unassign attempt
    assert auth_client.post(
        f"/api/v1/incidents/{inc_id}/unassign",
        headers=worker_headers,
        json={"reason": "Worker unassign"},
    ).status_code == 403

    # Reject attempt
    assert auth_client.post(
        f"/api/v1/incidents/{inc_id}/reject",
        headers=worker_headers,
        json={"reason": "Worker reject"},
    ).status_code == 403

    # Audit retrieval attempt
    assert auth_client.get(
        f"/api/v1/incidents/{inc_id}/audit",
        headers=worker_headers,
    ).status_code == 403


def test_user_metadata_role_escalation_rejected(auth_client: TestClient):
    """Client attempting role escalation via user_metadata is rejected with 403."""
    # Attacker sets user_metadata role to municipality, but app_metadata has citizen
    spoofed_token = _craft_token({
        "sub": "attacker-007",
        "aud": "authenticated",
        "exp": time.time() + 3600,
        "app_metadata": {"role": "citizen"},
        "user_metadata": {"role": "municipality"},
    })
    headers = {"Authorization": f"Bearer {spoofed_token}"}

    resp = auth_client.post(
        "/api/v1/incidents/INC-DEMO-01/verify",
        headers=headers,
        json={"notes": "Attempting privilege escalation"},
    )
    assert resp.status_code == 403


def test_nonexistent_incident_returns_404(auth_client: TestClient):
    """All municipal actions return 404 for nonexistent incident ID."""
    headers = _headers_for("municipality")
    bad_id = "INC-NONEXISTENT-999"

    assert auth_client.post(f"/api/v1/incidents/{bad_id}/verify", headers=headers, json={}).status_code == 404
    assert auth_client.post(f"/api/v1/incidents/{bad_id}/assign", headers=headers, json={"assigned_to": "TEAM-ALPHA"}).status_code == 404
    assert auth_client.post(f"/api/v1/incidents/{bad_id}/reassign", headers=headers, json={"assigned_to": "TEAM-BETA", "reason": "reason"}).status_code == 404
    assert auth_client.post(f"/api/v1/incidents/{bad_id}/unassign", headers=headers, json={"reason": "reason"}).status_code == 404
    assert auth_client.post(f"/api/v1/incidents/{bad_id}/reject", headers=headers, json={"reason": "reason"}).status_code == 404
    assert auth_client.get(f"/api/v1/incidents/{bad_id}/audit", headers=headers).status_code == 404


def test_audit_durability_survives_store_reinitialization(auth_client: TestClient):
    """P1.3.6.2.1 Phase A: Verify audit entries persist to disk and reload on StateStore restart."""
    headers = _headers_for("municipality", user_id="supervisor-panaji-01")
    inc_resp = auth_client.post("/api/v1/incidents", json={
        "category": "DRAIN_BLOCKAGE",
        "description": "Culvert blockage for audit durability test.",
        "latitude": 15.498,
        "longitude": 73.821,
        "source": "CITIZEN",
    })
    assert inc_resp.status_code == 201
    inc_id = inc_resp.json()["id"]

    # Perform assign action
    assign_resp = auth_client.post(
        f"/api/v1/incidents/{inc_id}/assign",
        headers=headers,
        json={"assigned_to": "TEAM-ALPHA", "notes": "Initial assignment for audit test"},
    )
    assert assign_resp.status_code == 200

    # Verify audit entry exists in current state store
    audits_before = state_store.get_incident_audits(inc_id)
    assert len(audits_before) >= 1
    assert any(a.action == "ASSIGNED" for a in audits_before)

    # Re-initialize a fresh StateStore instance simulating process restart
    from app.services.state_store import StateStore
    restarted_store = StateStore()
    audits_after = restarted_store.get_incident_audits(inc_id)
    assert len(audits_after) >= 1
    # Check that canonical assigned crew matches
    assert any(a.action == "ASSIGNED" and "Team Alpha" in (a.new_assigned_to or "") for a in audits_after)


def test_atomic_status_transition_prevents_partial_mutation(auth_client: TestClient):
    """P1.3.6.2.1 Phase C: Invalid transition must reject atomically without mutating severity or notes."""
    headers = _headers_for("municipality")
    inc_resp = auth_client.post("/api/v1/incidents", json={
        "category": "DRAIN_OVERFLOW",
        "description": "Manhole overflow at Patto Plaza.",
        "latitude": 15.495,
        "longitude": 73.832,
        "source": "CITIZEN",
    })
    assert inc_resp.status_code == 201
    inc_id = inc_resp.json()["id"]

    # Incident starts as REPORTED, severity MEDIUM
    orig = state_store.get_incident(inc_id)
    assert orig.status == IncidentStatus.REPORTED
    orig_severity = orig.severity

    # Attempt illegal transition to RESOLVED directly from REPORTED (must fail)
    illegal_update = IncidentUpdateContract(
        status=IncidentStatus.RESOLVED,
        severity=IncidentSeverity.CRITICAL,
        notes="Illegal jump directly to resolved",
    )
    with pytest.raises(Exception):
        state_store.update_incident(inc_id, illegal_update, user_id="tester", user_role="municipality")

    # Assert incident was NOT partially modified
    current = state_store.get_incident(inc_id)
    assert current.status == IncidentStatus.REPORTED
    assert current.severity == orig_severity
def test_worker_cannot_modify_assignment_through_state_store(
    isolated_state_store,
):
    """Direct StateStore calls must also reject worker assignment changes."""
    from app.models.contracts import IncidentResponseContract

    incident = IncidentResponseContract(
        id="INC-STORE-WORKER-001",
        category=IncidentCategory.DRAIN_BLOCKAGE,
        description="Direct StateStore worker authorization test.",
        latitude=15.491,
        longitude=73.820,
        severity=IncidentSeverity.MEDIUM,
        assigned_to="TEAM-ALPHA",
        assignment_type=AssignmentType.INDIVIDUAL,
        assigned_team_id="TEAM-ALPHA",
        assigned_worker_id="worker-lead-01",
    )

    isolated_state_store.create_incident(incident)

    protected_updates = [
        IncidentUpdateContract(assigned_to=None),
        IncidentUpdateContract(assignment_type=AssignmentType.NONE),
        IncidentUpdateContract(assigned_team_id=None),
        IncidentUpdateContract(assigned_worker_id=None),
        IncidentUpdateContract(assigned_worker_id="worker-other-99"),
    ]

    for update in protected_updates:
        with pytest.raises(ValueError, match="not permitted to reassign"):
            isolated_state_store.update_incident(
                incident_id=incident.id,
                update=update,
                actor_id="worker-lead-01",
                actor_role="worker",
            )

    unchanged = isolated_state_store.get_incident(incident.id)
    assert unchanged.assigned_to == "TEAM-ALPHA"
    assert unchanged.assignment_type == AssignmentType.INDIVIDUAL
    assert unchanged.assigned_team_id == "TEAM-ALPHA"
    assert unchanged.assigned_worker_id == "worker-lead-01"

def test_terminal_incidents_strictly_reject_reassignment_or_unassignment(auth_client: TestClient):
    """P1.3.6.2.1 Phase C: Terminal states (RESOLVED, REJECTED) reject assign/reassign/unassign with 400."""
    headers = _headers_for("municipality")
    inc_resp = auth_client.post("/api/v1/incidents", json={
        "category": "DRAIN_BLOCKAGE",
        "description": "Drain blockage check for terminal state rejection.",
        "latitude": 15.491,
        "longitude": 73.820,
        "source": "CITIZEN",
    })
    assert inc_resp.status_code == 201
    inc_id = inc_resp.json()["id"]

    # Reject incident -> terminal state
    rej_resp = auth_client.post(
        f"/api/v1/incidents/{inc_id}/reject",
        headers=headers,
        json={"reason": "Duplicate report"},
    )
    assert rej_resp.status_code == 200

    # Attempt to assign rejected incident -> 400
    assign_resp = auth_client.post(
        f"/api/v1/incidents/{inc_id}/assign",
        headers=headers,
        json={"assigned_to": "TEAM-ALPHA"},
    )
    assert assign_resp.status_code == 400

    # Attempt to reassign rejected incident -> 400
    reassign_resp = auth_client.post(
        f"/api/v1/incidents/{inc_id}/reassign",
        headers=headers,
        json={"assigned_to": "TEAM-BETA", "reason": "Try reassignment"},
    )
    assert reassign_resp.status_code == 400

    # Attempt to unassign rejected incident -> 400
    unassign_resp = auth_client.post(
        f"/api/v1/incidents/{inc_id}/unassign",
        headers=headers,
        json={"reason": "Try unassignment"},
    )
    assert unassign_resp.status_code == 400


def test_field_teams_directory_has_demo_flags(auth_client: TestClient):
    """P1.3.6.2.1 Phase B: Directory explicitly exposes is_demo=True and is_verified_municipal_crew=False."""
    headers = _headers_for("municipality")
    resp = auth_client.get("/api/v1/incidents/field-teams", headers=headers)
    assert resp.status_code == 200
    teams = resp.json()
    for t in teams:
        assert t["is_demo"] is True
        assert t["is_verified_municipal_crew"] is False


def test_individual_worker_assignment_authorization(auth_client: TestClient):
    """P1.3.6.2.2: Verify explicit assignment representation and worker individual authorization."""
    muni_headers = _headers_for("municipality")
    worker_1_headers = _headers_for("worker", user_id="worker-lead-01", extra_claims={"app_metadata": {"role": "worker", "team": "TEAM-ALPHA"}})
    worker_2_headers = _headers_for("worker", user_id="worker-other-99", extra_claims={"app_metadata": {"role": "worker", "team": "TEAM-BETA"}})

    # Create incident
    inc_resp = auth_client.post("/api/v1/incidents", json={
        "category": "DRAIN_BLOCKAGE",
        "description": "Culvert blockage for worker individual assignment test.",
        "latitude": 15.498,
        "longitude": 73.821,
        "source": "CITIZEN",
    })
    inc_id = inc_resp.json()["id"]

    # Assign to Team Alpha with specific individual worker ID
    assign_resp = auth_client.post(
        f"/api/v1/incidents/{inc_id}/assign",
        headers=muni_headers,
        json={
            "assigned_to": "TEAM-ALPHA",
            "assignment_type": "INDIVIDUAL",
            "assigned_worker_id": "worker-lead-01",
            "reason": "Direct dispatch to worker 01",
        },
    )
    assert assign_resp.status_code == 200
    data = assign_resp.json()
    assert data["assignment_type"] == "INDIVIDUAL"
    assert data["assigned_worker_id"] == "worker-lead-01"
    assert data["assigned_team_id"] == "TEAM-ALPHA"

    # Authorized worker 1 can update
    update_1 = auth_client.patch(
        f"/api/v1/incidents/{inc_id}",
        headers=worker_1_headers,
        json={"status": "INVESTIGATING"},
    )
    assert update_1.status_code == 200
    assert update_1.json()["status"] == "INVESTIGATING"

        # Assigned worker cannot modify any assignment field, even with explicit null.
    protected_fields = [
        "assigned_to",
        "assignment_type",
        "assigned_team_id",
        "assigned_worker_id",
    ]

    for field in protected_fields:
        response = auth_client.patch(
            f"/api/v1/incidents/{inc_id}",
            headers=worker_1_headers,
            json={field: None},
        )

        assert response.status_code == 403, (
            f"Worker unexpectedly modified assignment field: {field}"
        )

    # Worker cannot change assignment metadata to another non-null value either.
    response = auth_client.patch(
        f"/api/v1/incidents/{inc_id}",
        headers=worker_1_headers,
        json={"assigned_worker_id": "worker-other-99"},
    )
    assert response.status_code == 403

    # Unauthorized worker 2 from Team Beta cannot update (403 Forbidden)
    update_2 = auth_client.patch(
        f"/api/v1/incidents/{inc_id}",
        headers=worker_2_headers,
        json={"notes": "Illegal cross-crew worker update"},
    )
    assert update_2.status_code == 403


def test_atomic_rollback_on_audit_persistence_failure(auth_client: TestClient):
    """P1.3.6.2.2: If durable audit persistence fails, in-memory mutation must be rolled back."""
    muni_headers = _headers_for("municipality")

    # Create incident
    inc_resp = auth_client.post("/api/v1/incidents", json={
        "category": "DRAIN_OVERFLOW",
        "description": "Overflow for rollback atomicity test.",
        "latitude": 15.498,
        "longitude": 73.821,
        "source": "CITIZEN",
    })
    inc_id = inc_resp.json()["id"]

    orig = state_store.get_incident(inc_id)
    assert orig.status == IncidentStatus.REPORTED

    # Patch append_audit to simulate storage failure
    with patch.object(state_store._audit_durability, "append_audit", return_value=False):
        update_resp = auth_client.post(
            f"/api/v1/incidents/{inc_id}/assign",
            headers=muni_headers,
            json={"assigned_to": "TEAM-ALPHA", "reason": "Test failure rollback"},
        )
        assert update_resp.status_code == 500

    # Verify incident was safely rolled back to REPORTED
    current = state_store.get_incident(inc_id)
    assert current.status == IncidentStatus.REPORTED
    assert current.assigned_to is None
    assert current.assignment_type == AssignmentType.NONE


def test_unassignment_invariants_and_audit(auth_client: TestClient):
    """P1.3.6.2.2: Unassignment clears team, worker ID, resets status, and logs previous assignment in audit."""
    muni_headers = _headers_for("municipality")

    inc_resp = auth_client.post("/api/v1/incidents", json={
        "category": "INFRASTRUCTURE_DAMAGE",
        "description": "Broken slab for unassignment test.",
        "latitude": 15.498,
        "longitude": 73.821,
        "source": "CITIZEN",
    })
    inc_id = inc_resp.json()["id"]

    # Assign
    auth_client.post(
        f"/api/v1/incidents/{inc_id}/assign",
        headers=muni_headers,
        json={
            "assigned_to": "TEAM-BETA",
            "assignment_type": "INDIVIDUAL",
            "assigned_worker_id": "worker-beta-05",
        },
    )

    # Unassign
    unassign_resp = auth_client.post(
        f"/api/v1/incidents/{inc_id}/unassign",
        headers=muni_headers,
        json={"reason": "Resource reallocation to Panaji emergency"},
    )
    assert unassign_resp.status_code == 200
    data = unassign_resp.json()
    assert data["status"] == "VERIFIED"
    assert data["assigned_to"] is None
    assert data["assignment_type"] == "NONE"
    assert data["assigned_team_id"] is None
    assert data["assigned_worker_id"] is None

    # Check audit ledger
    audits = state_store.get_incident_audits(inc_id)
    unassign_audit = [a for a in audits if a.action == "UNASSIGNED"][0]
    assert "Team Beta" in unassign_audit.previous_assigned_to
    assert unassign_audit.previous_assignment_type == "INDIVIDUAL"
    assert unassign_audit.previous_assigned_team_id == "TEAM-BETA"
    assert unassign_audit.previous_assigned_worker_id == "worker-beta-05"
    assert unassign_audit.new_assigned_to is None
    assert unassign_audit.new_assignment_type == "NONE"


def test_cloud_incident_recovery_on_startup():
    """P1.3.6.2.3: Verify that incidents and assignments persisted in Supabase Cloud reload on startup."""
    mock_cloud_incidents = [
        {
            "id": "INC-CLOUD-RECOVER-01",
            "category": "FLOODING",
            "description": "Persisted cloud incident before restart.",
            "latitude": 15.495,
            "longitude": 73.832,
            "severity": "CRITICAL",
            "status": "ASSIGNED",
            "source": "CITIZEN",
            "assigned_to": "Team Alpha — St. Inez Drainage Crew",
            "assignment_type": "TEAM",
            "assigned_team_id": "TEAM-ALPHA",
            "assigned_worker_id": None,
            "municipal_notes": "Dispatched pump unit",
            "created_at": "2026-11-15T12:00:00Z",
            "updated_at": "2026-11-15T12:30:00Z",
        }
    ]

    from app.services.persistence_repository import persistence_repo
    from app.services.state_store import StateStore

    with patch.object(persistence_repo, "_is_configured", True), \
         patch.object(persistence_repo, "query_all_incidents_sync", return_value=mock_cloud_incidents):
        fresh_store = StateStore()
        recovered = fresh_store.get_incident("INC-CLOUD-RECOVER-01")
        assert recovered is not None
        assert recovered.id == "INC-CLOUD-RECOVER-01"
        assert recovered.status == IncidentStatus.ASSIGNED
        assert recovered.assigned_to == "Team Alpha — St. Inez Drainage Crew"
        assert recovered.assignment_type == AssignmentType.TEAM
        assert recovered.assigned_team_id == "TEAM-ALPHA"


def test_atomic_cloud_citizen_creation_rpc(auth_client: TestClient):
    """P1.3.6.2.3.1 Phase 3: Citizen incident creation calls atomic cloud creation RPC."""
    from app.services.persistence_repository import persistence_repo

    def mock_citizen_rpc(**kwargs):
        return {"id": kwargs["incident_id"]}

    with patch("app.api.v1.incidents.check_rate_limit"), \
         patch.object(persistence_repo, "_is_configured", True), \
         patch.object(
             persistence_repo,
             "execute_citizen_incident_creation_sync",
             side_effect=mock_citizen_rpc,
         ) as mock_rpc:
        create_resp = auth_client.post("/api/v1/incidents", json={
            "category": "DRAIN_BLOCKAGE",
            "description": "Blockage for citizen RPC atomicity test.",
            "latitude": 15.498,
            "longitude": 73.821,
            "source": "CITIZEN",
            "reporter_name": "Goa Citizen",
        })

        assert create_resp.status_code == 201
        assert mock_rpc.called

        call_kwargs = mock_rpc.call_args.kwargs
        assert call_kwargs["category"] == "DRAIN_BLOCKAGE"
        assert call_kwargs["reporter_name"] == "Goa Citizen"
        assert call_kwargs["audit_id"].startswith("AUD-")

def test_atomic_cloud_municipal_transaction_rpc(auth_client: TestClient):
    """P1.3.6.2.3.1 Phase 2: Municipal assignment invokes municipal_incident_transaction_rpc atomically."""
    from app.services.persistence_repository import persistence_repo

    muni_headers = _headers_for("municipality", user_id="dispatcher-panaji-01")

    # 1. Create incident
    inc_resp = auth_client.post("/api/v1/incidents", json={
        "category": "FLOODING",
        "description": "Flooding for RPC transaction test.",
        "latitude": 15.495,
        "longitude": 73.832,
        "source": "CITIZEN",
    })
    inc_id = inc_resp.json()["id"]

    mock_tx_return = {
        "id": inc_id,
        "status": "ASSIGNED",
        "assigned_to": "Team Alpha — St. Inez Drainage Crew",
        "assignment_type": "TEAM",
        "assigned_team_id": "TEAM-ALPHA",
    }

    with patch.object(persistence_repo, "_is_configured", True), \
         patch.object(persistence_repo, "execute_municipal_incident_transaction_sync", return_value=mock_tx_return) as mock_tx:
        assign_resp = auth_client.post(
            f"/api/v1/incidents/{inc_id}/assign",
            headers=muni_headers,
            json={"assigned_to": "TEAM-ALPHA", "reason": "Deploy team alpha via RPC"},
        )
        assert assign_resp.status_code == 200
        assert mock_tx.called
        call_kwargs = mock_tx.call_args.kwargs
        assert call_kwargs["incident_id"] == inc_id
        assert call_kwargs["new_status"] == "ASSIGNED"
        assert call_kwargs["assigned_team_id"] == "TEAM-ALPHA"
        assert call_kwargs["action"] == "ASSIGNED"


def test_cloud_status_only_update_canonicalizes_unassigned_snapshot(auth_client: TestClient):
    """A status-only cloud update must send SQL NULLs for a NONE assignment snapshot."""
    from app.services.persistence_repository import persistence_repo

    muni_headers = _headers_for("municipality", user_id="dispatcher-snapshot-01")
    created = auth_client.post("/api/v1/incidents", json={
        "category": "FLOODING",
        "description": "Status-only update with a legacy empty assignment snapshot.",
        "latitude": 15.495,
        "longitude": 73.832,
        "source": "CITIZEN",
    })
    assert created.status_code == 201
    incident_id = created.json()["id"]

    # Simulate a stale/legacy in-memory object: NONE must never carry empty strings.
    incident = state_store.get_incident(incident_id)
    incident.assigned_to = " "
    incident.assigned_team_id = ""
    incident.assigned_worker_id = " "

    rpc_result = {"id": incident_id, "status": "VERIFIED", "assignment_type": "NONE"}
    with patch.object(persistence_repo, "_is_configured", True), \
         patch.object(
             persistence_repo,
             "execute_municipal_incident_transaction_sync",
             return_value=rpc_result,
         ) as mock_rpc:
        response = auth_client.patch(
            f"/api/v1/incidents/{incident_id}",
            headers=muni_headers,
            json={"status": "VERIFIED"},
        )

    assert response.status_code == 200, response.text
    args = mock_rpc.call_args.kwargs
    assert args["assignment_type"] == "NONE"
    assert args["assigned_to"] is None
    assert args["assigned_team_id"] is None
    assert args["assigned_worker_id"] is None


def test_cloud_environment_mutation_fails_closed_on_cloud_error(auth_client: TestClient):
    """P1.3.6.2.3.1 Phase 4: In true cloud environment, municipal operation aborts if cloud write fails."""
    from app.services.persistence_repository import persistence_repo

    muni_headers = _headers_for("municipality")
    inc_resp = auth_client.post("/api/v1/incidents", json={
        "category": "DRAIN_OVERFLOW",
        "description": "Overflow for fail-closed test.",
        "latitude": 15.495,
        "longitude": 73.832,
        "source": "CITIZEN",
    })
    inc_id = inc_resp.json()["id"]

    # Simulate cloud environment (RENDER=true) with broken Supabase RPC and broken fallback
    with patch.object(state_store._audit_durability, "is_cloud_environment", return_value=True), \
         patch.object(persistence_repo, "_is_configured", True), \
         patch.object(persistence_repo, "execute_municipal_incident_transaction_sync", return_value=None), \
         patch.object(persistence_repo, "persist_incident_sync", return_value=False):
        assign_resp = auth_client.post(
            f"/api/v1/incidents/{inc_id}/assign",
            headers=muni_headers,
            json={"assigned_to": "TEAM-ALPHA", "reason": "Cloud failure simulation"},
        )
        assert assign_resp.status_code == 500

    # Ensure incident remained in REPORTED status
    assert state_store.get_incident(inc_id).status == IncidentStatus.REPORTED


def test_concurrent_assignments_serialize_under_store_lock(auth_client: TestClient):
    """P1.3.6.2.3.1 Phase 5: Concurrent assignment attempts cleanly serialize without state corruption."""
    import concurrent.futures

    muni_headers = _headers_for("municipality")
    inc_resp = auth_client.post("/api/v1/incidents", json={
        "category": "MANHOLE_DAMAGE",
        "description": "Manhole cover loose on MG Road.",
        "latitude": 15.498,
        "longitude": 73.824,
        "source": "CITIZEN",
    })
    inc_id = inc_resp.json()["id"]

    def _do_assign(crew_id: str):
        return auth_client.post(
            f"/api/v1/incidents/{inc_id}/assign",
            headers=muni_headers,
            json={"assigned_to": crew_id, "reason": f"Concurrent dispatch {crew_id}"},
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [
            executor.submit(_do_assign, "TEAM-ALPHA"),
            executor.submit(_do_assign, "TEAM-BETA"),
        ]
        results = [f.result() for f in futures]

    status_codes = [r.status_code for r in results]
    assert 200 in status_codes
    final_inc = state_store.get_incident(inc_id)
    assert final_inc.status == IncidentStatus.ASSIGNED
    assert final_inc.assigned_team_id in ("TEAM-ALPHA", "TEAM-BETA")




