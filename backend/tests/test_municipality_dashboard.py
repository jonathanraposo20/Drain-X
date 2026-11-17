"""
DRAIN-X P1.3.6.1 Municipality Dashboard & Operations Queue Test Suite.

Verifies:
1. Server-side authorization for /api/v1/incidents/municipal/kpis:
   - Municipality role: 200 OK with accurate aggregated KPIs.
   - Admin role: 200 OK.
   - Citizen role: 403 Forbidden.
   - Worker role: 403 Forbidden.
   - Unauthenticated client: 401 Unauthorized (when auth enabled).
2. Server-side authorization for /api/v1/incidents/municipal/queue:
   - Municipality role: 200 OK with paginated queue.
   - Admin role: 200 OK.
   - Citizen role: 403 Forbidden.
   - Worker role: 403 Forbidden.
   - Unauthenticated client: 401 Unauthorized (when auth enabled).
3. Queue filtering:
   - Status, severity, category, assignment (UNASSIGNED, ASSIGNED, crew name).
4. Queue search:
   - Free text search across ID, description, crew, municipal notes.
5. Queue pagination:
   - Limit, offset, total_count, and has_more flag.
6. Data Privacy:
   - Phone and email redaction on public and municipal fields.
   - Internal notes protection.
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
    IncidentResponseContract,
)
from app.services.state_store import state_store


TEST_JWT_SECRET = "incident-auth-test-secret-32-chars-long!"


def _craft_token(payload: Dict[str, Any], secret: str = TEST_JWT_SECRET) -> str:
    """Helper to craft signed HS256 JWT tokens."""
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
    """Client with Supabase Auth enabled."""
    with patch.object(settings, "SUPABASE_AUTH_ENABLED", True), \
         patch.object(settings, "SUPABASE_JWT_SECRET", TEST_JWT_SECRET), \
         patch.object(settings, "SUPABASE_URL", "https://test-project.supabase.co"):
        yield TestClient(app)

def _token_headers(role: str, user_id: str = "test-user-id", team: str = None) -> Dict[str, str]:
    payload = {
        "sub": user_id,
        "aud": "authenticated",
        "exp": int(time.time()) + 3600,
        "app_metadata": {
            "role": role,
            **({"team": team} if team else {})
        },
    }
    return {"Authorization": f"Bearer {_craft_token(payload)}"}


def test_municipal_kpis_authorized_for_municipality_and_admin(auth_client):
    # Municipality
    muni_headers = _token_headers("municipality", "muni-officer-01")
    resp_muni = auth_client.get("/api/v1/incidents/municipal/kpis", headers=muni_headers)
    assert resp_muni.status_code == 200
    data = resp_muni.json()
    assert "total_incidents" in data
    assert "open_incidents" in data
    assert "critical_or_high_incidents" in data
    assert "unassigned_incidents" in data
    assert "assigned_incidents" in data
    assert "investigating_incidents" in data
    assert "resolved_incidents" in data
    assert "rejected_incidents" in data
    assert "by_category" in data
    assert "by_severity" in data
    assert "by_status" in data
    assert data["total_incidents"] >= 4

    # Admin
    admin_headers = _token_headers("admin", "admin-super-01")
    resp_admin = auth_client.get("/api/v1/incidents/municipal/kpis", headers=admin_headers)
    assert resp_admin.status_code == 200


def test_municipal_kpis_citizen_and_worker_forbidden(auth_client):
    citizen_headers = _token_headers("citizen", "citizen-01")
    resp_cit = auth_client.get("/api/v1/incidents/municipal/kpis", headers=citizen_headers)
    assert resp_cit.status_code == 403
    assert "Operation requires one of the following roles" in resp_cit.json()["detail"]

    worker_headers = _token_headers("worker", "worker-01", team="Team Alpha")
    resp_wrk = auth_client.get("/api/v1/incidents/municipal/kpis", headers=worker_headers)
    assert resp_wrk.status_code == 403


def test_municipal_kpis_unauthenticated_unauthorized(auth_client):
    resp = auth_client.get("/api/v1/incidents/municipal/kpis")
    assert resp.status_code == 401


def test_municipal_queue_authorized_for_municipality(auth_client):
    headers = _token_headers("municipality", "muni-officer-01")
    resp = auth_client.get("/api/v1/incidents/municipal/queue", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data
    assert "total_count" in data
    assert "limit" in data
    assert "offset" in data
    assert "has_more" in data
    assert isinstance(data["items"], list)
    assert data["total_count"] >= 4


def test_municipal_queue_citizen_and_worker_forbidden(auth_client):
    citizen_headers = _token_headers("citizen", "citizen-01")
    resp_cit = auth_client.get("/api/v1/incidents/municipal/queue", headers=citizen_headers)
    assert resp_cit.status_code == 403

    worker_headers = _token_headers("worker", "worker-01")
    resp_wrk = auth_client.get("/api/v1/incidents/municipal/queue", headers=worker_headers)
    assert resp_wrk.status_code == 403


def test_municipal_queue_status_and_severity_filters(auth_client):
    headers = _token_headers("municipality")

    # Filter status=RESOLVED
    resp = auth_client.get("/api/v1/incidents/municipal/queue?status=RESOLVED", headers=headers)
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert all(i["status"] == "RESOLVED" for i in items)
    assert any(i["id"] == "INC-DEMO-04" for i in items)

    # Filter severity=CRITICAL
    resp_crit = auth_client.get("/api/v1/incidents/municipal/queue?severity=CRITICAL", headers=headers)
    assert resp_crit.status_code == 200
    items_crit = resp_crit.json()["items"]
    assert all(i["severity"] == "CRITICAL" for i in items_crit)
    assert any(i["id"] == "INC-DEMO-01" for i in items_crit)


def test_municipal_queue_category_and_assignment_filters(auth_client):
    headers = _token_headers("municipality")

    # Category filter
    resp = auth_client.get("/api/v1/incidents/municipal/queue?category=WATERLOGGING", headers=headers)
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert all(i["category"] == "WATERLOGGING" for i in items)
    assert any(i["id"] == "INC-DEMO-02" for i in items)

    # Assignment filter: specific crew name
    resp_crew = auth_client.get("/api/v1/incidents/municipal/queue?assigned_to=Team Alpha", headers=headers)
    assert resp_crew.status_code == 200
    items_crew = resp_crew.json()["items"]
    assert all("Team Alpha" in (i["assigned_to"] or "") for i in items_crew)

    # Assignment filter: UNASSIGNED
    # Create an unassigned incident to verify
    unassigned = IncidentResponseContract(
        id="INC-TEST-UNASSIGNED",
        category=IncidentCategory.DRAIN_BLOCKAGE,
        description="Blocked inlet without assigned crew.",
        latitude=15.495,
        longitude=73.825,
        severity=IncidentSeverity.MEDIUM,
        status=IncidentStatus.REPORTED,
        assigned_to=None,
    )
    state_store.create_incident(unassigned)

    resp_unassigned = auth_client.get("/api/v1/incidents/municipal/queue?assigned_to=UNASSIGNED", headers=headers)
    assert resp_unassigned.status_code == 200
    items_un = resp_unassigned.json()["items"]
    assert any(i["id"] == "INC-TEST-UNASSIGNED" for i in items_un)
    assert all(not i.get("assigned_to") for i in items_un)


def test_municipal_queue_search(auth_client):
    headers = _token_headers("municipality")

    # Search for specific location or keyword
    resp = auth_client.get("/api/v1/incidents/municipal/queue?search=Inez", headers=headers)
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) >= 1
    assert any("Inez" in i["description"] or "Inez" in (i["assigned_to"] or "") for i in items)


def test_municipal_queue_pagination(auth_client):
    headers = _token_headers("municipality")

    # Limit to 2 items
    resp_p1 = auth_client.get("/api/v1/incidents/municipal/queue?limit=2&offset=0", headers=headers)
    assert resp_p1.status_code == 200
    p1_data = resp_p1.json()
    assert len(p1_data["items"]) == 2
    assert p1_data["limit"] == 2
    assert p1_data["offset"] == 0
    assert p1_data["has_more"] is True

    # Page 2
    resp_p2 = auth_client.get("/api/v1/incidents/municipal/queue?limit=2&offset=2", headers=headers)
    assert resp_p2.status_code == 200
    p2_data = resp_p2.json()
    assert len(p2_data["items"]) >= 1
    assert p2_data["offset"] == 2
    # Distinct items between page 1 and page 2
    p1_ids = {i["id"] for i in p1_data["items"]}
    p2_ids = {i["id"] for i in p2_data["items"]}
    assert p1_ids.isdisjoint(p2_ids)


def test_municipal_queue_data_privacy(auth_client):
    headers = _token_headers("municipality")

    # Add incident with personal email & phone in description and notes
    leak_test = IncidentResponseContract(
        id="INC-TEST-PRIVACY-MUNI",
        category=IncidentCategory.FLOODING,
        description="Citizen reported flood, contact citizen.leak@gmail.com or +919876543210 immediately.",
        latitude=15.491,
        longitude=73.811,
        severity=IncidentSeverity.HIGH,
        status=IncidentStatus.REPORTED,
        reporter_name="John Doe phone: 9876543210",
        assigned_to="Team Beta beta-lead@drainx.gov",
        municipal_notes="Dispatcher called +919876543210 for verification.",
        internal_notes="Confidential municipal supervisor notes.",
    )
    state_store.create_incident(leak_test)

    resp = auth_client.get("/api/v1/incidents/municipal/queue?search=INC-TEST-PRIVACY-MUNI", headers=headers)
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) == 1
    item = items[0]

    # Verify contact info sanitized
    assert "citizen.leak@gmail.com" not in item.get("assigned_to", "")
    assert "beta-lead@drainx.gov" not in item.get("assigned_to", "")
    assert "[EMAIL REDACTED]" in item.get("assigned_to", "")
    assert "+919876543210" not in item.get("municipal_notes", "")
    assert "[PHONE REDACTED]" in item.get("municipal_notes", "")


def test_municipal_kpis_separates_demo_and_genuine_incidents(auth_client):
    headers = _token_headers("municipality", "muni-officer-01")
    resp = auth_client.get("/api/v1/incidents/municipal/kpis", headers=headers)
    assert resp.status_code == 200
    data = resp.json()

    assert "demo_incidents_count" in data
    assert "genuine_incidents_count" in data
    assert "by_source" in data
    assert data["demo_incidents_count"] >= 4
    assert data["total_incidents"] == data["demo_incidents_count"] + data["genuine_incidents_count"]
    assert "DEMO" in data["by_source"]
    assert data["by_source"]["DEMO"] == data["demo_incidents_count"]


def test_search_privacy_oracle_closed(auth_client):
    """
    Verifies that search does not leak confidential data via side-channels:
    1. internal_notes is NEVER searchable by ANY role.
    2. municipal_notes and assigned_to are searchable ONLY by staff (municipality/admin).
    3. Public/citizen search matches only ID and sanitized description.
    """
    oracle_test = IncidentResponseContract(
        id="INC-ORACLE-TEST-01",
        category=IncidentCategory.MANHOLE_DAMAGE,
        description="Public hazard description of dislodged lid.",
        latitude=15.493,
        longitude=73.815,
        severity=IncidentSeverity.MEDIUM,
        status=IncidentStatus.REPORTED,
        assigned_to="Team Delta PrivateCrewTag99",
        municipal_notes="ClassifiedDispatchDirectiveXYZ",
        internal_notes="SecretSupervisoryAuditAlphaOmega",
    )
    state_store.create_incident(oracle_test)

    # 1. Public search for classified internal notes -> NOT found
    resp_pub_secret = auth_client.get("/api/v1/incidents?search=SecretSupervisoryAuditAlphaOmega")
    assert resp_pub_secret.status_code == 200
    assert not any(i["id"] == "INC-ORACLE-TEST-01" for i in resp_pub_secret.json())

    # 2. Staff queue search for classified internal notes -> NOT found (internal notes NEVER searchable)
    muni_headers = _token_headers("municipality")
    resp_staff_secret = auth_client.get("/api/v1/incidents/municipal/queue?search=SecretSupervisoryAuditAlphaOmega", headers=muni_headers)
    assert resp_staff_secret.status_code == 200
    assert not any(i["id"] == "INC-ORACLE-TEST-01" for i in resp_staff_secret.json()["items"])

    # 3. Public search for municipal notes -> NOT found (closes search oracle for unprivileged users)
    resp_pub_muni = auth_client.get("/api/v1/incidents?search=ClassifiedDispatchDirectiveXYZ")
    assert resp_pub_muni.status_code == 200
    assert not any(i["id"] == "INC-ORACLE-TEST-01" for i in resp_pub_muni.json())

    # 4. Public search for assigned crew tag -> NOT found
    resp_pub_crew = auth_client.get("/api/v1/incidents?search=PrivateCrewTag99")
    assert resp_pub_crew.status_code == 200
    assert not any(i["id"] == "INC-ORACLE-TEST-01" for i in resp_pub_crew.json())

    # 5. Staff search for municipal notes -> FOUND
    resp_staff_muni = auth_client.get("/api/v1/incidents/municipal/queue?search=ClassifiedDispatchDirectiveXYZ", headers=muni_headers)
    assert resp_staff_muni.status_code == 200
    assert any(i["id"] == "INC-ORACLE-TEST-01" for i in resp_staff_muni.json()["items"])

    # 6. Public search for description text -> FOUND
    resp_pub_desc = auth_client.get("/api/v1/incidents?search=dislodged")
    assert resp_pub_desc.status_code == 200
    assert any(i["id"] == "INC-ORACLE-TEST-01" for i in resp_pub_desc.json())


def test_public_incident_description_pii_sanitized(auth_client):
    """
    Verifies that citizen phone and email in incident descriptions are
    sanitized in public API responses.
    """
    pii_incident = IncidentResponseContract(
        id="INC-PII-DESC-TEST",
        category=IncidentCategory.FLOODING,
        description="Drain blocked near home, call citizen at +919123456789 or email resident.help@gmail.com for gate access.",
        latitude=15.491,
        longitude=73.811,
        severity=IncidentSeverity.HIGH,
        status=IncidentStatus.REPORTED,
        reporter_name="Jane Doe",
    )
    state_store.create_incident(pii_incident)

    # Public retrieval
    resp = auth_client.get("/api/v1/incidents/INC-PII-DESC-TEST")
    assert resp.status_code == 200
    data = resp.json()

    # Description must be sanitized
    assert "+919123456789" not in data["description"]
    assert "resident.help@gmail.com" not in data["description"]
    assert "[PHONE REDACTED]" in data["description"]
    assert "[EMAIL REDACTED]" in data["description"]
    # Reporter name redacted / suppressed for public
    assert data.get("reporter_name") is None
    # Internal notes not present
    assert data.get("internal_notes") is None


def test_kpi_terminal_state_handling_excludes_resolved_and_rejected(auth_client):
    """
    P1.3.6.1.2 Regression Test:
    Verifies that critical/high KPI calculations strictly exclude BOTH RESOLVED and REJECTED
    incidents, while continuing to count active CRITICAL and HIGH incidents accurately.
    """
    headers = _token_headers("municipality", "muni-lead-01")

    # Capture initial baseline
    base_resp = auth_client.get("/api/v1/incidents/municipal/kpis", headers=headers)
    assert base_resp.status_code == 200
    base = base_resp.json()

    # Deterministic cohort of 7 incidents covering all specified states:
    cohort = [
        # 1. Active CRITICAL (REPORTED) -> MUST count in open & crit/high
        IncidentResponseContract(
            id="INC-DET-01-ACT-CRIT",
            category=IncidentCategory.FLOODING,
            description="Active critical urban inundation.",
            latitude=15.491,
            longitude=73.811,
            severity=IncidentSeverity.CRITICAL,
            status=IncidentStatus.REPORTED,
            source=IncidentSource.CITIZEN,
            assigned_to=None,
        ),
        # 2. Active HIGH (INVESTIGATING) -> MUST count in open & crit/high
        IncidentResponseContract(
            id="INC-DET-02-ACT-HIGH",
            category=IncidentCategory.DRAIN_OVERFLOW,
            description="Active high severity overflow under investigation.",
            latitude=15.492,
            longitude=73.812,
            severity=IncidentSeverity.HIGH,
            status=IncidentStatus.INVESTIGATING,
            source=IncidentSource.CITIZEN,
            assigned_to="Team Beta — Patto Rapid Response",
        ),
        # 3. Active MEDIUM (ASSIGNED) -> MUST count in open, NOT in crit/high
        IncidentResponseContract(
            id="INC-DET-03-ACT-MED",
            category=IncidentCategory.DRAIN_BLOCKAGE,
            description="Active medium blockage assigned to maintenance.",
            latitude=15.493,
            longitude=73.813,
            severity=IncidentSeverity.MEDIUM,
            status=IncidentStatus.ASSIGNED,
            source=IncidentSource.CITIZEN,
            assigned_to="Team Gamma — Fontainhas Heritage Maintenance",
        ),
        # 4. RESOLVED CRITICAL -> Terminal: MUST NOT count in open or crit/high
        IncidentResponseContract(
            id="INC-DET-04-RES-CRIT",
            category=IncidentCategory.FLOODING,
            description="Resolved critical flooding from earlier storm.",
            latitude=15.494,
            longitude=73.814,
            severity=IncidentSeverity.CRITICAL,
            status=IncidentStatus.RESOLVED,
            source=IncidentSource.CITIZEN,
            assigned_to="Team Alpha — St. Inez Drainage Crew",
        ),
        # 5. REJECTED CRITICAL -> Terminal: MUST NOT count in open or crit/high
        IncidentResponseContract(
            id="INC-DET-05-REJ-CRIT",
            category=IncidentCategory.FLOODING,
            description="Spam report alleging critical flooding.",
            latitude=15.495,
            longitude=73.815,
            severity=IncidentSeverity.CRITICAL,
            status=IncidentStatus.REJECTED,
            source=IncidentSource.CITIZEN,
            assigned_to=None,
        ),
        # 6. RESOLVED HIGH -> Terminal: MUST NOT count in open or crit/high
        IncidentResponseContract(
            id="INC-DET-06-RES-HIGH",
            category=IncidentCategory.MANHOLE_DAMAGE,
            description="Resolved high hazard damaged lid replaced.",
            latitude=15.496,
            longitude=73.816,
            severity=IncidentSeverity.HIGH,
            status=IncidentStatus.RESOLVED,
            source=IncidentSource.CITIZEN,
            assigned_to="Team Delta — Miramar Outfall Sluice Unit",
        ),
        # 7. REJECTED HIGH -> Terminal: MUST NOT count in open or crit/high
        IncidentResponseContract(
            id="INC-DET-07-REJ-HIGH",
            category=IncidentCategory.INFRASTRUCTURE_DAMAGE,
            description="Duplicate report of high infrastructure damage.",
            latitude=15.497,
            longitude=73.817,
            severity=IncidentSeverity.HIGH,
            status=IncidentStatus.REJECTED,
            source=IncidentSource.CITIZEN,
            assigned_to=None,
        ),
    ]

    for inc in cohort:
        state_store.create_incident(inc)

    # Re-query KPIs after cohort insertion
    new_resp = auth_client.get("/api/v1/incidents/municipal/kpis", headers=headers)
    assert new_resp.status_code == 200
    updated = new_resp.json()

    # Exact differential assertions:
    # 1. Total incidents increases by all 7
    assert updated["total_incidents"] == base["total_incidents"] + 7

    # 2. Open incidents increases by exactly 3 (ACT-CRIT, ACT-HIGH, ACT-MED)
    # Neither RESOLVED (2) nor REJECTED (2) are counted in open items!
    assert updated["open_incidents"] == base["open_incidents"] + 3

    # 3. Critical/High incidents increases by exactly 2 (ACT-CRIT, ACT-HIGH)
    # Neither RESOLVED CRIT, REJECTED CRIT, RESOLVED HIGH, nor REJECTED HIGH inflate this metric!
    assert updated["critical_or_high_incidents"] == base["critical_or_high_incidents"] + 2

    # 4. Resolved count increases by exactly 2 (RES-CRIT, RES-HIGH)
    assert updated["resolved_incidents"] == base["resolved_incidents"] + 2

    # 5. Rejected count increases by exactly 2 (REJ-CRIT, REJ-HIGH)
    assert updated["rejected_incidents"] == base["rejected_incidents"] + 2

    # 6. Unassigned count increases by exactly 1 (ACT-CRIT is unassigned, REJ is terminal so ignored)
    assert updated["unassigned_incidents"] == base["unassigned_incidents"] + 1

    # 7. Assigned count increases by exactly 2 (ACT-HIGH assigned to Beta, ACT-MED assigned to Gamma; RES is terminal so ignored)
    assert updated["assigned_incidents"] == base["assigned_incidents"] + 2

    # 8. Investigating count increases by exactly 1 (ACT-HIGH)
    assert updated["investigating_incidents"] == base["investigating_incidents"] + 1

    # 9. Verify by_severity active distribution:
    assert updated["by_severity"]["CRITICAL"] == base["by_severity"]["CRITICAL"] + 1
    assert updated["by_severity"]["HIGH"] == base["by_severity"]["HIGH"] + 1
    assert updated["by_severity"]["MEDIUM"] == base["by_severity"]["MEDIUM"] + 1
