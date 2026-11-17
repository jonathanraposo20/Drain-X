"""
DRAIN-X P1.3.5.2 & P1.3.5.4 Backend Public Data Privacy Hardening Test Suite.

Verifies:
1. Anonymous public GET-by-ID does not expose reporter_name (asserts res.json()["reporter_name"] is None).
2. Anonymous public GET-by-ID does not leak reporter_id, email, phone, or private contact info.
3. Public incident listing (GET /api/v1/incidents) does not leak reporter_name across all returned records.
4. Citizen authenticated access does not leak unauthorized identity information.
5. Municipality and Admin access retains legitimate reporter_name needed for municipal triage.
6. Worker access privacy enforcement: worker role cannot access reporter_name.
7. Public municipal responses remain visible (assigned_to, status, municipal_notes, photos).
8. Anonymous incident tracking continues working with full tracking fidelity.
9. Internal municipal staff notes are confidential (redacted for public, citizen, and worker; visible to municipality/admin).
10. Field workers are forbidden from setting internal municipal notes (403 Forbidden).
11. Assignment information sanitization scrubs accidental personal contact details (email/phone) from public responses.
12. Photo upload is rejected on closed/resolved incidents (400 Bad Request).
13. Photo serving verifies registration and sets strict privacy/security headers (nosniff, Cache-Control).
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
from app.models.contracts import IncidentCategory, IncidentSeverity, IncidentStatus, IncidentSource
from app.services.state_store import state_store


TEST_JWT_SECRET = "incident-privacy-test-secret-32-chars-long!"


def _craft_token(payload: Dict[str, Any], secret: str = TEST_JWT_SECRET) -> str:
    """Helper to craft signed HS256 JWT tokens."""
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


@pytest.fixture(autouse=True)
def ensure_incidents():
    """Ensures test incident state with known reporter identities exists."""
    state_store.seed_demo_incidents()


def test_1_anonymous_public_get_by_id_redacts_reporter_name(auth_client: TestClient):
    """
    Test 1: Anonymous public GET-by-ID does not expose reporter_name.
    Asserts that reporter_name is None in the JSON response.
    """
    # Create an incident with a citizen's real name
    create_resp = auth_client.post("/api/v1/incidents", json={
        "category": "DRAIN_BLOCKAGE",
        "description": "Severe storm grate blockage on DB Marg.",
        "latitude": 15.498,
        "longitude": 73.825,
        "severity": "HIGH",
        "source": "CITIZEN",
        "reporter_name": "Maria Fernandes",
    })
    assert create_resp.status_code == 201
    inc_id = create_resp.json()["id"]

    # Public unauthenticated GET by ID
    response = auth_client.get(f"/api/v1/incidents/{inc_id}")
    assert response.status_code == 200
    data = response.json()

    assert data["id"] == inc_id
    assert data["reporter_name"] is None, "Public GET must redact reporter_name to None"


def test_2_anonymous_public_get_does_not_leak_reporter_id_or_contact(auth_client: TestClient):
    """
    Test 2: Anonymous public GET-by-ID does not leak reporter_id, email, phone, or private contact info.
    """
    response = auth_client.get("/api/v1/incidents/INC-DEMO-01")
    assert response.status_code == 200
    data = response.json()

    # Assert no sensitive identifier or contact fields exist in response
    assert "reporter_id" not in data, "reporter_id must never be exposed"
    assert "reporter_email" not in data, "reporter_email must never be exposed"
    assert "reporter_phone" not in data, "reporter_phone must never be exposed"
    assert "email" not in data
    assert "phone" not in data
    assert data.get("internal_notes") is None, "internal_notes must never be exposed publicly"
    assert data["reporter_name"] is None


def test_3_public_incident_listing_does_not_leak_reporter_names(auth_client: TestClient):
    """
    Test 3: Public incident listing (GET /api/v1/incidents) does not leak reporter_name across all returned records.
    """
    response = auth_client.get("/api/v1/incidents")
    assert response.status_code == 200
    items = response.json()
    assert len(items) >= 4, "Must retrieve seeded incidents"

    for incident in items:
        assert incident["reporter_name"] is None, (
            f"Incident {incident['id']} leaked reporter_name: {incident['reporter_name']}"
        )


def test_4_citizen_authenticated_access_does_not_leak_reporter_names(auth_client: TestClient):
    """
    Test 4: Citizen authenticated access does not leak unauthorized identity information.
    A citizen user querying another incident must still receive redacted reporter_name.
    """
    citizen_token = _craft_token({
        "sub": "citizen-user-12345",
        "exp": time.time() + 3600,
        "app_metadata": {"role": "citizen"},
        "aud": "authenticated",
    })
    headers = {"Authorization": f"Bearer {citizen_token}"}

    # Citizen querying single incident
    detail_resp = auth_client.get("/api/v1/incidents/INC-DEMO-01", headers=headers)
    assert detail_resp.status_code == 200
    assert detail_resp.json()["reporter_name"] is None

    # Citizen querying incident listing
    list_resp = auth_client.get("/api/v1/incidents", headers=headers)
    assert list_resp.status_code == 200
    for incident in list_resp.json():
        assert incident["reporter_name"] is None


def test_5_municipality_and_admin_retain_legitimate_reporter_name(auth_client: TestClient):
    """
    Test 5: Municipality and Admin roles retain legitimate reporter_name needed for municipal triage.
    """
    # 1. Test Municipality role
    muni_token = _craft_token({
        "sub": "muni-inspector-001",
        "exp": time.time() + 3600,
        "app_metadata": {"role": "municipality"},
        "aud": "authenticated",
    })
    muni_headers = {"Authorization": f"Bearer {muni_token}"}

    muni_resp = auth_client.get("/api/v1/incidents/INC-DEMO-01", headers=muni_headers)
    assert muni_resp.status_code == 200
    assert muni_resp.json()["reporter_name"] == "St. Inez Ward Committee"

    # Municipality listing retains all reporter names
    muni_list = auth_client.get("/api/v1/incidents", headers=muni_headers)
    assert muni_list.status_code == 200
    demo_01 = next(i for i in muni_list.json() if i["id"] == "INC-DEMO-01")
    assert demo_01["reporter_name"] == "St. Inez Ward Committee"

    # 2. Test Admin role
    admin_token = _craft_token({
        "sub": "admin-super-001",
        "exp": time.time() + 3600,
        "app_metadata": {"role": "admin"},
        "aud": "authenticated",
    })
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    admin_resp = auth_client.get("/api/v1/incidents/INC-DEMO-01", headers=admin_headers)
    assert admin_resp.status_code == 200
    assert admin_resp.json()["reporter_name"] == "St. Inez Ward Committee"


def test_6_worker_access_privacy_enforcement(auth_client: TestClient):
    """
    Test 6: Worker access privacy enforcement:
    Field workers receive operational task information but reporter_name is redacted.
    """
    worker_token = _craft_token({
        "sub": "worker-001",
        "exp": time.time() + 3600,
        "app_metadata": {"role": "worker", "team": "Team Alpha"},
        "aud": "authenticated",
    })
    headers = {"Authorization": f"Bearer {worker_token}"}

    # Worker querying incident
    detail_resp = auth_client.get("/api/v1/incidents/INC-DEMO-01", headers=headers)
    assert detail_resp.status_code == 200
    assert detail_resp.json()["reporter_name"] is None

    # Worker querying incident listing
    list_resp = auth_client.get("/api/v1/incidents", headers=headers)
    assert list_resp.status_code == 200
    for incident in list_resp.json():
        assert incident["reporter_name"] is None


def test_7_public_municipal_responses_remain_visible(auth_client: TestClient):
    """
    Test 7: Public municipal responses remain visible:
    assigned_to, status, municipal_notes, and photos remain accessible for public reassurance.
    """
    response = auth_client.get("/api/v1/incidents/INC-DEMO-04")
    assert response.status_code == 200
    data = response.json()

    assert data["id"] == "INC-DEMO-04"
    assert data["status"] == "RESOLVED"
    assert data["assigned_to"] == "Team Delta — Miramar Outfall Sluice Unit"
    assert "Grating slab repositioned" in data["municipal_notes"]
    assert isinstance(data["photos"], list)
    # But reporter name is redacted
    assert data["reporter_name"] is None


def test_8_anonymous_incident_tracking_continues_working(auth_client: TestClient):
    """
    Test 8: Anonymous incident tracking continues working:
    Citizens can track newly submitted reports by their unique incident ID without authentication.
    """
    # 1. Anonymous submission
    create_resp = auth_client.post("/api/v1/incidents", json={
        "category": "WATERLOGGING",
        "description": "Knee-deep water accumulating at commercial junction.",
        "latitude": 15.492,
        "longitude": 73.820,
        "severity": "CRITICAL",
        "source": "CITIZEN",
        "reporter_name": "Concerned Resident",
    })
    assert create_resp.status_code == 201
    created = create_resp.json()
    tracking_id = created["id"]
    assert tracking_id.startswith("INC-")

    # 2. Tracking report anonymously
    track_resp = auth_client.get(f"/api/v1/incidents/{tracking_id}")
    assert track_resp.status_code == 200
    tracked = track_resp.json()

    assert tracked["id"] == tracking_id
    assert tracked["category"] == "WATERLOGGING"
    assert tracked["status"] == "REPORTED"
    assert tracked["severity"] == "CRITICAL"
    assert tracked["latitude"] == 15.492
    assert tracked["longitude"] == 73.820
    assert tracked["description"] == "Knee-deep water accumulating at commercial junction."
    assert tracked["source"] == "CITIZEN"
    assert tracked["reporter_name"] is None, "Reporter name must be redacted on public lookup"
    assert tracked["assigned_to"] is None


def test_9_internal_notes_confidentiality(auth_client: TestClient):
    """
    Test 9: Internal municipal staff notes are confidential:
    - Saved by municipality/admin.
    - Excluded / None for public, citizen, and worker clients.
    - Retained for municipality/admin triage.
    """
    muni_token = _craft_token({
        "sub": "muni-supervisor-099",
        "exp": time.time() + 3600,
        "app_metadata": {"role": "municipality"},
        "aud": "authenticated",
    })
    muni_headers = {"Authorization": f"Bearer {muni_token}"}

    # Municipal supervisor patches internal notes
    patch_resp = auth_client.patch(
        "/api/v1/incidents/INC-DEMO-01",
        headers=muni_headers,
        json={
            "internal_notes": "CONFIDENTIAL: Suspected illegal dumping by restaurant; health inspector notified.",
            "municipal_notes": "Field inspection scheduled for 15:00.",
        },
    )
    assert patch_resp.status_code == 200
    muni_view = patch_resp.json()
    assert "Suspected illegal dumping" in muni_view["internal_notes"]

    # 1. Anonymous public GET: internal_notes must be None
    public_resp = auth_client.get("/api/v1/incidents/INC-DEMO-01")
    assert public_resp.status_code == 200
    assert public_resp.json()["internal_notes"] is None
    assert public_resp.json()["municipal_notes"] == "Field inspection scheduled for 15:00."

    # 2. Citizen authenticated GET: internal_notes must be None
    citizen_token = _craft_token({
        "sub": "citizen-002",
        "exp": time.time() + 3600,
        "app_metadata": {"role": "citizen"},
        "aud": "authenticated",
    })
    cit_resp = auth_client.get("/api/v1/incidents/INC-DEMO-01", headers={"Authorization": f"Bearer {citizen_token}"})
    assert cit_resp.status_code == 200
    assert cit_resp.json()["internal_notes"] is None

    # 3. Worker authenticated GET: internal_notes must be None
    worker_token = _craft_token({
        "sub": "worker-002",
        "exp": time.time() + 3600,
        "app_metadata": {"role": "worker", "team": "Team Alpha"},
        "aud": "authenticated",
    })
    worker_resp = auth_client.get("/api/v1/incidents/INC-DEMO-01", headers={"Authorization": f"Bearer {worker_token}"})
    assert worker_resp.status_code == 200
    assert worker_resp.json()["internal_notes"] is None

    # 4. Municipality GET: retains internal_notes
    muni_get_resp = auth_client.get("/api/v1/incidents/INC-DEMO-01", headers=muni_headers)
    assert muni_get_resp.status_code == 200
    assert "health inspector notified" in muni_get_resp.json()["internal_notes"]


def test_10_worker_forbidden_from_setting_internal_notes(auth_client: TestClient):
    """
    Test 10: Field workers are forbidden from setting internal municipal notes (403 Forbidden).
    """
    worker_token = _craft_token({
        "sub": "worker-alpha-lead",
        "exp": time.time() + 3600,
        "app_metadata": {"role": "worker", "team": "Team Alpha"},
        "aud": "authenticated",
    })
    headers = {"Authorization": f"Bearer {worker_token}"}

    response = auth_client.patch(
        "/api/v1/incidents/INC-DEMO-01",
        headers=headers,
        json={"internal_notes": "Worker attempting unauthorized supervisor note entry"}
    )
    assert response.status_code == 403
    assert "Field workers are not permitted to set internal municipal notes" in response.json()["detail"]


def test_11_assignment_contact_scrubbing_protects_personal_details(auth_client: TestClient):
    """
    Test 11: Assignment information does not leak personal contact details (emails, phone numbers).
    Accidental contact info in assigned_to or municipal_notes is scrubbed from public responses.
    """
    muni_token = _craft_token({
        "sub": "muni-lead-001",
        "exp": time.time() + 3600,
        "app_metadata": {"role": "municipality"},
        "aud": "authenticated",
    })
    muni_headers = {"Authorization": f"Bearer {muni_token}"}

    # Supervisor enters assignment with personal worker phone and email
    patch_resp = auth_client.patch(
        "/api/v1/incidents/INC-DEMO-01",
        headers=muni_headers,
        json={
            "assigned_to": "Team Alpha (Officer Ramesh: ramesh.naik@panaji.gov.in, Mobile: +91 98221 55555)",
            "municipal_notes": "Crew dispatched. Emergency contact: sup.patil@panaji.gov.in or +91 98220 11111.",
        },
    )
    assert patch_resp.status_code == 200

    # Public client queries incident: contact details MUST be scrubbed
    pub_resp = auth_client.get("/api/v1/incidents/INC-DEMO-01")
    assert pub_resp.status_code == 200
    pub_data = pub_resp.json()

    # Verify no raw email or phone leaked
    assert "ramesh.naik@panaji.gov.in" not in pub_data["assigned_to"]
    assert "+91 98221 55555" not in pub_data["assigned_to"]
    assert "[EMAIL REDACTED]" in pub_data["assigned_to"]
    assert "[PHONE REDACTED]" in pub_data["assigned_to"]

    assert "sup.patil@panaji.gov.in" not in pub_data["municipal_notes"]
    assert "+91 98220 11111" not in pub_data["municipal_notes"]
    assert "[EMAIL REDACTED]" in pub_data["municipal_notes"]
    assert "[PHONE REDACTED]" in pub_data["municipal_notes"]

    # Municipality client retains the full raw information for operations
    muni_get = auth_client.get("/api/v1/incidents/INC-DEMO-01", headers=muni_headers)
    assert muni_get.status_code == 200
    assert "ramesh.naik@panaji.gov.in" in muni_get.json()["assigned_to"]


def test_12_photo_upload_rejected_on_resolved_incident(auth_client: TestClient):
    """
    Test 12: Photo upload is rejected on closed/resolved incidents (400 Bad Request).
    Prevents post-resolution evidence tampering.
    """
    dummy_jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00\xff\xdb\x00C\x00" + (b"X" * 100)
    files = [("files", ("evidence_late.jpg", dummy_jpeg, "image/jpeg"))]

    # INC-DEMO-04 is in RESOLVED status
    response = auth_client.post("/api/v1/incidents/INC-DEMO-04/photos", files=files)
    assert response.status_code == 400
    assert "Cannot attach photos to an incident in 'RESOLVED' status" in response.json()["detail"]


def test_13_photo_serving_security_headers_and_unregistered_rejection(auth_client: TestClient):
    """
    Test 13: Photo access policy enforcement:
    - Successfully uploads and serves a registered photo with strict security headers (nosniff, Cache-Control).
    - Rejects unregistered photos or fabricated filenames with 404 Not Found.
    """
    # 1. Create an incident and upload a photo
    create_resp = auth_client.post("/api/v1/incidents", json={
        "category": "DRAIN_BLOCKAGE",
        "description": "Culvert blockage test photo policy.",
        "latitude": 15.495,
        "longitude": 73.822,
        "severity": "LOW",
    })
    inc_id = create_resp.json()["id"]

    from tests.conftest import create_test_image
    test_jpeg = create_test_image("JPEG")
    files = [("files", ("grate_block.jpg", test_jpeg, "image/jpeg"))]
    upload_resp = auth_client.post(f"/api/v1/incidents/{inc_id}/photos", files=files)
    assert upload_resp.status_code == 200
    photo_urls = upload_resp.json()["photos"]
    assert len(photo_urls) == 1
    photo_url = photo_urls[0]

    # 2. Retrieve the registered photo
    get_photo_resp = auth_client.get(photo_url)
    assert get_photo_resp.status_code == 200
    assert get_photo_resp.headers["content-type"] == "image/jpeg"
    assert get_photo_resp.headers["x-content-type-options"] == "nosniff"
    assert "public" in get_photo_resp.headers["cache-control"]
    assert len(get_photo_resp.content) > 0

    # 3. Unregistered photo filename (even if valid regex) returns 404
    unregistered_resp = auth_client.get("/api/v1/incidents/photos/INC-DEMO-01_99999999.jpg")
    assert unregistered_resp.status_code == 404
    assert "not found" in unregistered_resp.json()["detail"].lower()
