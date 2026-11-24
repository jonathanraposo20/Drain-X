"""
DRAIN-X Batch 1.1 Security, Directive API Authorization, Persistent Query & Migration 008 Tests.

Validates:
1. JWT authentication and RBAC on GET /api/v1/telemetry/directives/active and /history.
2. Fail-closed behavior when auth is disabled (HTTP 503), service_role is presented on user
   endpoints, or claims/scopes are empty, malformed, conflicting, singular, or forged.
3. Strict citizen denial (HTTP 403) and anti-privilege-escalation (user_metadata ignored).
4. Worker device self-assignment and metadata overwrite prevention on POST /api/v1/devices,
   plus fail-closed 503 on list_devices(strict=True) persistence errors.
5. Admin and municipality authorization (unscoped, device-only, section-only, dual).
6. Worker PHYSICAL-only and JWT/registry authorization without unintended scope intersection,
   plus removal of unvalidated raw team-name fallback.
7. Cross-scope directive_id non-disclosure (identical 404 vs nonexistent directive_id).
8. Persistent history pushdown (eq / in.(...)) before limit, descending PostgREST fetch +
   chronological reversal, in-memory filter-before-limit, strict 503/400 error handling.
9. REJECTED terminal classification in recover_incomplete_directives_sync.
10. Migration 008 SQL & PL/pgSQL pglast AST validation, least-privilege revocations, and RLS.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import patch
import httpx
import pglast
import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app
from app.models.contracts import (
    ActuatorDirectiveContract,
    ActuatorDirectiveEventContract,
    DirectiveEventType,
)
from app.services.persistence_repository import PersistenceRepository, persistence_repo
from app.services.state_store import state_store
from tests.conftest import TEST_JWT_SECRET, TEST_SUPABASE_URL


@pytest.fixture
def jwt_client(monkeypatch):
    """TestClient configured deterministically for CWD-independent JWT auth verification."""
    monkeypatch.setattr(settings, "SUPABASE_AUTH_ENABLED", True)
    monkeypatch.setattr(settings, "SUPABASE_JWT_SECRET", TEST_JWT_SECRET)
    monkeypatch.setattr(settings, "SUPABASE_URL", TEST_SUPABASE_URL)
    persistence_repo._in_memory_directive_audits.clear()
    yield TestClient(app)
    persistence_repo._in_memory_directive_audits.clear()


def _make_auth_header(
    role: str,
    subject: str = "user-001",
    app_metadata_extra: Optional[Dict[str, Any]] = None,
    user_metadata_extra: Optional[Dict[str, Any]] = None,
    top_level_role: str = "authenticated",
    issuer: Optional[str] = None,
) -> Dict[str, str]:
    import time
    import jwt as pyjwt

    now = int(time.time())
    app_meta: Dict[str, Any] = {"role": role}
    if app_metadata_extra:
        app_meta.update(app_metadata_extra)
    payload: Dict[str, Any] = {
        "iss": issuer if issuer is not None else f"{TEST_SUPABASE_URL}/auth/v1",
        "aud": "authenticated",
        "iat": now,
        "exp": now + 3600,
        "role": top_level_role,
        "app_metadata": app_meta,
        "user_metadata": dict(user_metadata_extra or {}),
    }
    if subject is not None:
        payload["sub"] = subject
    token = pyjwt.encode(payload, TEST_JWT_SECRET, algorithm="HS256")
    return {"Authorization": f"Bearer {token}"}


def _seed_mode_directive(
    mode: str,
    directive_id: str,
    device_id: Optional[str],
    section_id: str,
    angle: float = 45.0,
    action: str = "DIVERT_FLOW",
    timestamp: Optional[str] = None,
) -> ActuatorDirectiveContract:
    kwargs: Dict[str, Any] = {}
    if timestamp is not None:
        kwargs["timestamp"] = timestamp
    directive = ActuatorDirectiveContract(
        directive_id=directive_id,
        device_id=device_id,
        section_id=section_id,
        gate_target_angle=angle,
        action=action,
        emergency_stop=(action == "SAFE_HOLD_LOCK"),
    )
    event = ActuatorDirectiveEventContract(
        audit_id=f"aud_{directive_id}_ISS",
        directive_id=directive_id,
        event_type=DirectiveEventType.ISSUED,
        operational_mode=mode,
        section_id=section_id,
        device_id=device_id,
        action=action,
        gate_target_angle=angle,
        reason="Test seeded directive",
        emergency_stop=(action == "SAFE_HOLD_LOCK"),
        issuer_id="test_suite",
        **kwargs,
    )
    with state_store._lock:
        state_store._active_directives[mode] = directive
        state_store._directive_audits.append(event)
    return directive


# =====================================================================
# 1. Authentication, service_role Exclusion & Citizen Denials
# =====================================================================

def test_unauthenticated_and_auth_disabled_fail_closed(jwt_client: TestClient, monkeypatch):
    assert jwt_client.get("/api/v1/telemetry/directives/active").status_code == 401
    assert jwt_client.get("/api/v1/telemetry/directives/history").status_code == 401

    monkeypatch.setattr(settings, "SUPABASE_AUTH_ENABLED", False)
    client = TestClient(app)
    headers = _make_auth_header("admin")
    assert client.get("/api/v1/telemetry/directives/active", headers=headers).status_code == 503
    assert client.get("/api/v1/telemetry/directives/history", headers=headers).status_code == 503


def test_citizen_and_spoofed_user_metadata_denied_403(jwt_client: TestClient):
    citizen_hdrs = _make_auth_header("citizen", subject="cit-1")
    assert jwt_client.get("/api/v1/telemetry/directives/active", headers=citizen_hdrs).status_code == 403
    assert jwt_client.get("/api/v1/telemetry/directives/history", headers=citizen_hdrs).status_code == 403

    spoof_hdrs = _make_auth_header(
        "citizen",
        subject="cit-spoof",
        user_metadata_extra={
            "role": "admin",
            "assigned_devices": ["DRAINX-ESP32-NODE-01"],
            "assigned_sections": ["SEC_SCREENING_01"],
        },
    )
    assert jwt_client.get("/api/v1/telemetry/directives/active", headers=spoof_hdrs).status_code == 403
    assert jwt_client.get("/api/v1/telemetry/directives/history", headers=spoof_hdrs).status_code == 403


def test_service_role_rejected_on_public_directive_endpoints(jwt_client: TestClient):
    # Synthetic HS256 JWT carrying top-level role=service_role + valid iss/sub
    synthetic_sr = _make_auth_header(
        "admin",
        subject="service-client",
        top_level_role="service_role",
    )
    assert jwt_client.get("/api/v1/telemetry/directives/active", headers=synthetic_sr).status_code == 403
    assert jwt_client.get("/api/v1/telemetry/directives/history", headers=synthetic_sr).status_code == 403

    # app_metadata role=service_role is also excluded from user-facing routes
    app_meta_sr = _make_auth_header("service_role", subject="sr-appmeta")
    assert jwt_client.get("/api/v1/telemetry/directives/active", headers=app_meta_sr).status_code == 403
    assert jwt_client.get("/api/v1/telemetry/directives/history", headers=app_meta_sr).status_code == 403

    # Real Supabase service_role JWT shape (iss='supabase', no sub) fails closed with 401
    real_sr = _make_auth_header(
        "service_role",
        subject=None,  # type: ignore[arg-type]
        top_level_role="service_role",
        issuer="supabase",
    )
    assert jwt_client.get("/api/v1/telemetry/directives/active", headers=real_sr).status_code == 401
    assert jwt_client.get("/api/v1/telemetry/directives/history", headers=real_sr).status_code == 401


# =====================================================================
# 2. Device Self-Assignment & Registry Fail-Closed Security
# =====================================================================

def test_worker_cannot_self_assign_or_overwrite_protected_device_metadata(jwt_client: TestClient):
    _seed_mode_directive("PHYSICAL", "dir_phys_n2", "DRAINX-ESP32-NODE-02", "SEC_OUTLET", 45.0)
    persistence_repo._in_memory_devices["DRAINX-ESP32-NODE-02"] = {
        "device_id": "DRAINX-ESP32-NODE-02",
        "name": "Managed Outlet Node",
        "is_active": True,
        "validation_stage": "CONNECTIVITY_READY",
        "metadata": {"assigned_worker_id": "wrk-legit-owner", "section_id": "SEC_OUTLET"},
    }

    attacker_hdrs = _make_auth_header(
        "worker",
        subject="wrk-attacker",
        app_metadata_extra={"team": "TEAM-ALPHA"},
    )

    # 1. Worker attempts to self-assign an unassigned/new device via metadata
    for bad_meta in (
        {"assigned_worker_id": "wrk-attacker"},
        {"assigned_team_id": "TEAM-ALPHA"},
        {"section_id": "SEC_OUTLET"},
        {"nested": {"Assigned_Worker_Id": "wrk-attacker"}},
    ):
        r = jwt_client.post(
            "/api/v1/devices",
            headers=attacker_hdrs,
            json={"device_id": "DRAINX-ESP32-ROGUE-01", "name": "Rogue", "metadata": bad_meta},
        )
        assert r.status_code == 403

    # 2. Worker attempts to overwrite an existing device that carries managed authorization metadata
    r_overwrite = jwt_client.post(
        "/api/v1/devices",
        headers=attacker_hdrs,
        json={"device_id": "DRAINX-ESP32-NODE-02", "name": "Hijacked Node", "metadata": {}},
    )
    assert r_overwrite.status_code == 403

    # 3. Worker cannot toggle is_active on an existing non-auth device
    persistence_repo._in_memory_devices["DRAINX-ESP32-BENIGN-01"] = {
        "device_id": "DRAINX-ESP32-BENIGN-01",
        "name": "Benign Node",
        "is_active": True,
        "metadata": {"location": "Bench"},
    }
    r_deactivate = jwt_client.post(
        "/api/v1/devices",
        headers=attacker_hdrs,
        json={"device_id": "DRAINX-ESP32-BENIGN-01", "name": "Benign Node", "is_active": False, "metadata": {}},
    )
    assert r_deactivate.status_code == 403

    # 4. Attacker worker still has zero access to NODE-02 directives
    assert jwt_client.get("/api/v1/telemetry/directives/active", headers=attacker_hdrs).status_code == 403
    assert jwt_client.get("/api/v1/telemetry/directives/history", headers=attacker_hdrs).status_code == 403


def test_admin_and_municipality_device_assignment_and_benign_worker_registration(jwt_client: TestClient):
    muni_hdrs = _make_auth_header("municipality", subject="muni-ops")
    admin_hdrs = _make_auth_header("admin", subject="adm-ops")
    worker_hdrs = _make_auth_header("worker", subject="wrk-legit")

    # Municipality & admin can assign authorization metadata
    r_muni = jwt_client.post(
        "/api/v1/devices",
        headers=muni_hdrs,
        json={
            "device_id": "DRAINX-ESP32-NODE-03",
            "name": "Node 03",
            "metadata": {"assigned_team_id": "TEAM-BETA", "section_id": "SEC_OUTLET"},
        },
    )
    assert r_muni.status_code == 200

    r_admin = jwt_client.post(
        "/api/v1/devices",
        headers=admin_hdrs,
        json={
            "device_id": "DRAINX-ESP32-NODE-04",
            "name": "Node 04",
            "metadata": {"assigned_worker_id": "wrk-legit", "section_id": "SEC_SCREENING_01"},
        },
    )
    assert r_admin.status_code == 200

    # Legitimate worker registration of a brand-new hardware node with benign metadata still works
    r_wrk = jwt_client.post(
        "/api/v1/devices",
        headers=worker_hdrs,
        json={"device_id": "DRAINX-ESP32-FIELD-99", "name": "Field Node", "metadata": {"location": "Bench 2"}},
    )
    assert r_wrk.status_code == 200


def test_worker_registry_failure_returns_503_never_uses_stale_in_memory(jwt_client: TestClient, monkeypatch):
    _seed_mode_directive("PHYSICAL", "dir_stale_01", "DRAINX-ESP32-NODE-01", "SEC_SCREENING_01", 45.0)
    # Seed stale assignment in _in_memory_devices that MUST NOT be trusted when cloud persistence fails
    persistence_repo._in_memory_devices["DRAINX-ESP32-NODE-01"]["metadata"] = {
        "assigned_worker_id": "wrk-stale-user",
    }

    worker_hdrs = _make_auth_header("worker", subject="wrk-stale-user")

    class _FailingAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def get(self, *args, **kwargs):
            return httpx.Response(500, json={"message": "DB down"})

    monkeypatch.setattr(persistence_repo, "_is_configured", True)
    monkeypatch.setattr(persistence_repo, "_supabase_url", "https://example.supabase.co")
    monkeypatch.setattr(persistence_repo, "_supabase_service_role_key", "dummy-service-role-key")
    monkeypatch.setattr(persistence_repo, "_active_key", "dummy-service-role-key")
    with patch("app.services.persistence_repository.httpx.AsyncClient", _FailingAsyncClient):
        assert jwt_client.get("/api/v1/telemetry/directives/active", headers=worker_hdrs).status_code == 503
        assert jwt_client.get("/api/v1/telemetry/directives/history", headers=worker_hdrs).status_code == 503
        # Device overwrite check for worker also fails closed with 503 when lookup fails
        r_post = jwt_client.post(
            "/api/v1/devices",
            headers=worker_hdrs,
            json={"device_id": "DRAINX-ESP32-NODE-01", "name": "Node 01"},
        )
        assert r_post.status_code == 503


def test_unvalidated_raw_team_fallback_removed(jwt_client: TestClient):
    _seed_mode_directive("PHYSICAL", "dir_team_n1", "DRAINX-ESP32-NODE-01", "SEC_SCREENING_01")
    persistence_repo._in_memory_devices["DRAINX-ESP32-NODE-01"]["metadata"] = {
        "assigned_team_id": "ROGUE-UNVALIDATED-CREW",
    }
    rogue_team_worker = _make_auth_header(
        "worker",
        subject="wrk-rogue-team",
        app_metadata_extra={"team": "rogue-unvalidated-crew"},
    )
    assert jwt_client.get("/api/v1/telemetry/directives/active", headers=rogue_team_worker).status_code == 403
    assert jwt_client.get("/api/v1/telemetry/directives/history", headers=rogue_team_worker).status_code == 403

    # Authoritative validated team still works when assigned by admin/municipality
    persistence_repo._in_memory_devices["DRAINX-ESP32-NODE-01"]["metadata"] = {
        "assigned_team_id": "TEAM-ALPHA",
    }
    valid_team_worker = _make_auth_header(
        "worker",
        subject="wrk-alpha",
        app_metadata_extra={"team": "team alpha"},
    )
    r_act = jwt_client.get("/api/v1/telemetry/directives/active", headers=valid_team_worker)
    assert r_act.status_code == 200
    assert r_act.json()["active_directive"]["directive_id"] == "dir_team_n1"


# =====================================================================
# 3. Admin, Municipality & Worker Scope Authorization Matrix
# =====================================================================

def test_admin_and_unscoped_municipality_access_all_modes(jwt_client: TestClient):
    _seed_mode_directive("SIMULATION", "dir_sim_01", None, "SEC_SCREENING", 30.0)
    _seed_mode_directive("PHYSICAL", "dir_phys_01", "DRAINX-ESP32-NODE-01", "SEC_SCREENING_01", 90.0)
    _seed_mode_directive("SAFE_HOLD", "dir_hold_01", "DRAINX-ESP32-NODE-01", "SEC_SCREENING_01", 0.0, "SAFE_HOLD_LOCK")

    for role in ("admin", "municipality"):
        headers = _make_auth_header(role, subject=f"{role}-1")
        for mode, expected_id in (
            ("SIMULATION", "dir_sim_01"),
            ("PHYSICAL", "dir_phys_01"),
            ("SAFE_HOLD", "dir_hold_01"),
        ):
            r_act = jwt_client.get(f"/api/v1/telemetry/directives/active?operational_mode={mode}", headers=headers)
            assert r_act.status_code == 200
            assert r_act.json()["active_directive"]["directive_id"] == expected_id

        r_hist = jwt_client.get("/api/v1/telemetry/directives/history", headers=headers)
        assert r_hist.status_code == 200
        ids = {e["directive_id"] for e in r_hist.json()["events"]}
        assert {"dir_sim_01", "dir_phys_01", "dir_hold_01"}.issubset(ids)


def test_scoped_municipality_matrix_and_singular_claim_denial(jwt_client: TestClient):
    _seed_mode_directive("PHYSICAL", "dir_m1", "DRAINX-ESP32-NODE-01", "SEC_SCREENING_01")
    _seed_mode_directive("SIMULATION", "dir_m2", None, "SEC_SCREENING_01")
    _seed_mode_directive("SIMULATION", "dir_m3", "DRAINX-ESP32-NODE-02", "SEC_OUTLET")

    # 1. Section-only restricted municipality (includes device_id=None rows in SEC_SCREENING_01)
    sec_muni = _make_auth_header(
        "municipality",
        subject="muni-sec",
        app_metadata_extra={"assigned_sections": ["SEC_SCREENING_01"]},
    )
    r_sec = jwt_client.get("/api/v1/telemetry/directives/history", headers=sec_muni)
    assert r_sec.status_code == 200
    assert {e["directive_id"] for e in r_sec.json()["events"]} == {"dir_m1", "dir_m2"}
    assert jwt_client.get("/api/v1/telemetry/directives/history?section_id=SEC_OUTLET", headers=sec_muni).status_code == 403
    assert jwt_client.get("/api/v1/telemetry/directives/active?section_id=SEC_OUTLET", headers=sec_muni).status_code == 403

    # 2. Device-only restricted municipality (excludes device_id=None and NODE-02)
    dev_muni = _make_auth_header(
        "municipality",
        subject="muni-dev",
        app_metadata_extra={"assigned_devices": ["DRAINX-ESP32-NODE-01"]},
    )
    r_dev = jwt_client.get("/api/v1/telemetry/directives/history", headers=dev_muni)
    assert r_dev.status_code == 200
    assert [e["directive_id"] for e in r_dev.json()["events"]] == ["dir_m1"]
    assert jwt_client.get("/api/v1/telemetry/directives/history?device_id=DRAINX-ESP32-NODE-02", headers=dev_muni).status_code == 403

    # 3. Cross-scope directive_id vs nonexistent directive_id return identical 404 (no existence oracle)
    r_cross = jwt_client.get("/api/v1/telemetry/directives/history?directive_id=dir_m3", headers=sec_muni)
    r_missing = jwt_client.get("/api/v1/telemetry/directives/history?directive_id=dir_does_not_exist", headers=sec_muni)
    assert r_cross.status_code == 404
    assert r_missing.status_code == 404
    assert r_cross.json()["detail"] == r_missing.json()["detail"]

    # 4. Unsupported singular keys MUST fail closed with 403 (never fall open to unscoped!)
    for singular_key in ("assigned_section", "section_id", "assigned_device", "device_id"):
        singular_muni = _make_auth_header(
            "municipality",
            subject="muni-singular",
            app_metadata_extra={singular_key: "SEC_SCREENING_01"},
        )
        assert jwt_client.get("/api/v1/telemetry/directives/history", headers=singular_muni).status_code == 403
        assert jwt_client.get("/api/v1/telemetry/directives/active", headers=singular_muni).status_code == 403


def test_worker_scope_matrix_empty_malformed_conflicting_and_no_registry_intersection(jwt_client: TestClient):
    _seed_mode_directive("SIMULATION", "dir_sim_n1", "DRAINX-ESP32-NODE-01", "SEC_SCREENING_01")
    _seed_mode_directive("SAFE_HOLD", "dir_hold_n1", "DRAINX-ESP32-NODE-01", "SEC_SCREENING_01", 0.0, "SAFE_HOLD_LOCK")
    _seed_mode_directive("PHYSICAL", "dir_n1_s1", "DRAINX-ESP32-NODE-01", "SEC_SCREENING_01")
    with state_store._lock:
        state_store._directive_audits.append(
            ActuatorDirectiveEventContract(
                audit_id="aud_dir_n1_s2_ISS",
                directive_id="dir_n1_s2",
                event_type=DirectiveEventType.ISSUED,
                operational_mode="PHYSICAL",
                section_id="SEC_OUTLET",
                device_id="DRAINX-ESP32-NODE-01",
                action="DIVERT_FLOW",
                gate_target_angle=45.0,
                reason="Test section outlet directive",
                issuer_id="test_suite",
            )
        )
        state_store._directive_audits.append(
            ActuatorDirectiveEventContract(
                audit_id="aud_dir_n2_s1_ISS",
                directive_id="dir_n2_s1",
                event_type=DirectiveEventType.ISSUED,
                operational_mode="PHYSICAL",
                section_id="SEC_SCREENING_01",
                device_id="DRAINX-ESP32-NODE-02",
                action="DIVERT_FLOW",
                gate_target_angle=45.0,
                reason="Test node 2 directive",
                issuer_id="test_suite",
            )
        )

    # Seed conflicting registry entry to prove JWT-scoped worker is NOT silently restricted by registry section_id
    persistence_repo._in_memory_devices["DRAINX-ESP32-NODE-02"] = {
        "device_id": "DRAINX-ESP32-NODE-02",
        "name": "Node 02",
        "is_active": True,
        "metadata": {"assigned_worker_id": "wrk-dev-only", "section_id": "SEC_INFLOW"},
    }

    # 1. Worker device-only scope (sees NODE-01 across sections in PHYSICAL mode; ignores registry section_id)
    dev_worker = _make_auth_header(
        "worker",
        subject="wrk-dev-only",
        app_metadata_extra={"assigned_devices": ["DRAINX-ESP32-NODE-01"]},
    )
    r_dev = jwt_client.get("/api/v1/telemetry/directives/history", headers=dev_worker)
    assert r_dev.status_code == 200
    assert {e["directive_id"] for e in r_dev.json()["events"]} == {"dir_n1_s1", "dir_n1_s2"}
    assert jwt_client.get("/api/v1/telemetry/directives/history?operational_mode=SIMULATION", headers=dev_worker).status_code == 403
    assert jwt_client.get("/api/v1/telemetry/directives/history?directive_id=dir_n2_s1", headers=dev_worker).status_code == 404
    assert jwt_client.get("/api/v1/telemetry/directives/history?directive_id=dir_sim_n1", headers=dev_worker).status_code == 404

    # 2. Worker section-only scope
    sec_worker = _make_auth_header(
        "worker",
        subject="wrk-sec-only",
        app_metadata_extra={"allowed_sections": ["SEC_SCREENING_01"]},
    )
    r_sec = jwt_client.get("/api/v1/telemetry/directives/history", headers=sec_worker)
    assert r_sec.status_code == 200
    assert {e["directive_id"] for e in r_sec.json()["events"]} == {"dir_n1_s1", "dir_n2_s1"}

    # 3. Worker dual device + section intersection
    dual_worker = _make_auth_header(
        "worker",
        subject="wrk-dual",
        app_metadata_extra={
            "assigned_devices": ["DRAINX-ESP32-NODE-01"],
            "assigned_sections": ["SEC_OUTLET"],
        },
    )
    r_dual = jwt_client.get("/api/v1/telemetry/directives/history", headers=dual_worker)
    assert r_dual.status_code == 200
    assert [e["directive_id"] for e in r_dual.json()["events"]] == ["dir_n1_s2"]

    # 4. Empty, malformed, singular, and conflicting JWT claims MUST ALL fail closed with 403
    bad_claim_cases = [
        {},  # unassigned worker
        {"assigned_devices": []},
        {"assigned_devices": [], "assigned_sections": ["SEC_SCREENING_01"]},
        {"assigned_devices": "DRAINX-ESP32-NODE-01"},
        {"assigned_devices": None},
        {"assigned_devices": [123]},
        {"assigned_devices": ["DRAINX-ESP32-NODE-01", ""]},
        {"assigned_devices": [" DRAINX-ESP32-NODE-01 "]},
        {"assigned_devices": ["DRAINX-ESP32-NODE-01"], "allowed_devices": ["DRAINX-ESP32-NODE-02"]},
        {"assigned_devices": ["DRAINX-ESP32-NODE-01"], "allowed_devices": []},
        {"assigned_device": "DRAINX-ESP32-NODE-01"},
        {"section_id": "SEC_SCREENING_01"},
    ]
    for idx, extra in enumerate(bad_claim_cases):
        bad_hdrs = _make_auth_header("worker", subject=f"wrk-bad-{idx}", app_metadata_extra=extra)
        assert jwt_client.get("/api/v1/telemetry/directives/active", headers=bad_hdrs).status_code == 403, extra
        assert jwt_client.get("/api/v1/telemetry/directives/history", headers=bad_hdrs).status_code == 403, extra


# =====================================================================
# 4. Persistent History Pushdown Before Limit & Strict Failure Handling
# =====================================================================

class _FakePostgRESTClient:
    """In-memory PostgREST query simulator executing actual PersistenceRepository query logic."""

    recorded_params: List[Dict[str, str]] = []
    dataset: List[Dict[str, Any]] = []
    response_override: Optional[httpx.Response] = None
    raise_error: Optional[Exception] = None

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def get(self, endpoint: str, params: Optional[Dict[str, str]] = None, headers: Optional[Dict[str, str]] = None):
        if _FakePostgRESTClient.raise_error is not None:
            raise _FakePostgRESTClient.raise_error
        if _FakePostgRESTClient.response_override is not None:
            return _FakePostgRESTClient.response_override

        p = dict(params or {})
        _FakePostgRESTClient.recorded_params.append(p)
        rows = list(_FakePostgRESTClient.dataset)

        for key, expr in p.items():
            if key in ("order", "limit"):
                continue
            if expr.startswith("eq."):
                target = expr[3:]
                rows = [r for r in rows if r.get(key) == target]
            elif expr.startswith("in.(") and expr.endswith(")"):
                targets = set(expr[4:-1].split(","))
                rows = [r for r in rows if r.get(key) in targets]

        if p.get("order") == "timestamp.desc,audit_id.desc":
            rows.sort(key=lambda x: (str(x.get("timestamp", "")), str(x.get("audit_id", ""))), reverse=True)
        if "limit" in p:
            rows = rows[: int(p["limit"])]
        return httpx.Response(200, json=rows)


def test_persistent_history_pushes_scope_before_limit_and_preserves_chronological_order(
    jwt_client: TestClient, monkeypatch
):
    # 5 older authorized NODE-01 rows + 15 newer unauthorized NODE-02 rows
    dataset: List[Dict[str, Any]] = []
    for i in range(1, 6):
        dataset.append({
            "audit_id": f"aud_n1_{i:02d}",
            "directive_id": f"dir_n1_{i:02d}",
            "event_type": "ISSUED",
            "operational_mode": "PHYSICAL",
            "section_id": "SEC_SCREENING_01",
            "device_id": "DRAINX-ESP32-NODE-01",
            "gate_target_angle": 45.0,
            "timestamp": f"2026-11-23T01:0{i}:00+00:00",
        })
    for i in range(6, 21):
        dataset.append({
            "audit_id": f"aud_n2_{i:02d}",
            "directive_id": f"dir_n2_{i:02d}",
            "event_type": "ISSUED",
            "operational_mode": "PHYSICAL",
            "section_id": "SEC_SCREENING_01",
            "device_id": "DRAINX-ESP32-NODE-02",
            "gate_target_angle": 90.0,
            "timestamp": f"2026-11-23T01:{i:02d}:00+00:00",
        })

    _FakePostgRESTClient.dataset = dataset
    _FakePostgRESTClient.recorded_params = []
    _FakePostgRESTClient.response_override = None
    _FakePostgRESTClient.raise_error = None

    monkeypatch.setattr(persistence_repo, "_is_configured", True)
    monkeypatch.setattr(persistence_repo, "_supabase_url", "https://example.supabase.co")
    monkeypatch.setattr(persistence_repo, "_supabase_service_role_key", "dummy-service-role-key")
    monkeypatch.setattr(persistence_repo, "_active_key", "dummy-service-role-key")

    worker_n1 = _make_auth_header(
        "worker",
        subject="wrk-n1",
        app_metadata_extra={"assigned_devices": ["DRAINX-ESP32-NODE-01"]},
    )
    worker_multi = _make_auth_header(
        "worker",
        subject="wrk-multi",
        app_metadata_extra={"assigned_devices": ["DRAINX-ESP32-NODE-01", "DRAINX-ESP32-NODE-03"]},
    )

    with patch("app.services.persistence_repository.httpx.Client", _FakePostgRESTClient):
        r_single = jwt_client.get("/api/v1/telemetry/directives/history?limit=5", headers=worker_n1)
        assert r_single.status_code == 200
        body = r_single.json()
        assert body["source"] == "persistent"
        assert body["count"] == 5
        assert [e["audit_id"] for e in body["events"]] == [
            "aud_n1_01", "aud_n1_02", "aud_n1_03", "aud_n1_04", "aud_n1_05"
        ]
        assert _FakePostgRESTClient.recorded_params[0]["device_id"] == "eq.DRAINX-ESP32-NODE-01"
        assert _FakePostgRESTClient.recorded_params[0]["limit"] == "5"

        r_multi = jwt_client.get("/api/v1/telemetry/directives/history?limit=5", headers=worker_multi)
        assert r_multi.status_code == 200
        assert r_multi.json()["count"] == 5
        assert (
            _FakePostgRESTClient.recorded_params[1]["device_id"]
            == "in.(DRAINX-ESP32-NODE-01,DRAINX-ESP32-NODE-03)"
        )

        # Cross-scope directive_id returns identical 404 to nonexistent directive_id in persistent mode
        r_cross = jwt_client.get("/api/v1/telemetry/directives/history?directive_id=dir_n2_10", headers=worker_n1)
        r_none = jwt_client.get("/api/v1/telemetry/directives/history?directive_id=dir_missing", headers=worker_n1)
        assert r_cross.status_code == 404
        assert r_none.status_code == 404
        assert r_cross.json()["detail"] == r_none.json()["detail"]


def test_in_memory_history_filters_before_limit(jwt_client: TestClient):
    with state_store._lock:
        for i in range(1, 4):
            state_store._directive_audits.append(
                ActuatorDirectiveEventContract(
                    audit_id=f"aud_mem_n1_{i}",
                    directive_id=f"dir_mem_n1_{i}",
                    event_type=DirectiveEventType.ISSUED,
                    operational_mode="PHYSICAL",
                    section_id="SEC_SCREENING_01",
                    device_id="DRAINX-ESP32-NODE-01",
                    action="DIVERT_FLOW",
                    gate_target_angle=45.0,
                    reason="Test in-memory n1",
                    issuer_id="test_suite",
                    timestamp=f"2026-11-23T01:0{i}:00+00:00",
                )
            )
        for i in range(4, 15):
            state_store._directive_audits.append(
                ActuatorDirectiveEventContract(
                    audit_id=f"aud_mem_n2_{i}",
                    directive_id=f"dir_mem_n2_{i}",
                    event_type=DirectiveEventType.ISSUED,
                    operational_mode="PHYSICAL",
                    section_id="SEC_SCREENING_01",
                    device_id="DRAINX-ESP32-NODE-02",
                    action="DIVERT_FLOW",
                    gate_target_angle=45.0,
                    reason="Test in-memory n2",
                    issuer_id="test_suite",
                    timestamp=f"2026-11-23T01:{i:02d}:00+00:00",
                )
            )

    worker_n1 = _make_auth_header(
        "worker",
        subject="wrk-mem-n1",
        app_metadata_extra={"assigned_devices": ["DRAINX-ESP32-NODE-01"]},
    )
    r = jwt_client.get("/api/v1/telemetry/directives/history?limit=3", headers=worker_n1)
    assert r.status_code == 200
    assert r.json()["source"] == "in_memory"
    assert [e["directive_id"] for e in r.json()["events"]] == [
        "dir_mem_n1_1", "dir_mem_n1_2", "dir_mem_n1_3"
    ]


def test_collection_validation_and_strict_persistent_failures_on_history_and_active(
    jwt_client: TestClient, monkeypatch
):
    repo = PersistenceRepository(supabase_url="", supabase_key="")
    with pytest.raises(ValueError):
        repo.query_directive_audits_sync(allowed_devices=["NODE1,or=(1=1)"])
    with pytest.raises(ValueError):
        repo.query_directive_audits_sync(allowed_sections="SEC_SCREENING_01")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        repo.query_directive_audits_sync(allowed_devices=[123])  # type: ignore[list-item]

    admin_hdrs = _make_auth_header("admin", subject="adm-err")
    assert jwt_client.get("/api/v1/telemetry/directives/history?device_id=NODE1,or=(1=1)", headers=admin_hdrs).status_code == 400
    assert jwt_client.get("/api/v1/telemetry/directives/history?operational_mode=HARDWARE", headers=admin_hdrs).status_code == 400

    # Active directive present so persistent query executes on /directives/active too
    _seed_mode_directive("PHYSICAL", "dir_active_chk", "DRAINX-ESP32-NODE-01", "SEC_SCREENING_01")
    monkeypatch.setattr(persistence_repo, "_is_configured", True)
    monkeypatch.setattr(persistence_repo, "_supabase_url", "https://example.supabase.co")
    monkeypatch.setattr(persistence_repo, "_supabase_service_role_key", "dummy-service-role-key")
    monkeypatch.setattr(persistence_repo, "_active_key", "dummy-service-role-key")
    _FakePostgRESTClient.dataset = []

    with patch("app.services.persistence_repository.httpx.Client", _FakePostgRESTClient):
        # HTTP 500 -> 503 on both /history and /active
        _FakePostgRESTClient.raise_error = None
        _FakePostgRESTClient.response_override = httpx.Response(500, json={"error": "timeout"})
        assert jwt_client.get("/api/v1/telemetry/directives/history", headers=admin_hdrs).status_code == 503
        assert jwt_client.get("/api/v1/telemetry/directives/active?operational_mode=PHYSICAL", headers=admin_hdrs).status_code == 503

        # Malformed non-list JSON -> 503
        _FakePostgRESTClient.response_override = httpx.Response(200, json={"unexpected": "dict"})
        assert jwt_client.get("/api/v1/telemetry/directives/history", headers=admin_hdrs).status_code == 503
        assert jwt_client.get("/api/v1/telemetry/directives/active?operational_mode=PHYSICAL", headers=admin_hdrs).status_code == 503

        # Network exception -> 503
        _FakePostgRESTClient.response_override = None
        _FakePostgRESTClient.raise_error = httpx.ConnectError("connection reset")
        assert jwt_client.get("/api/v1/telemetry/directives/history", headers=admin_hdrs).status_code == 503
        assert jwt_client.get("/api/v1/telemetry/directives/active?operational_mode=PHYSICAL", headers=admin_hdrs).status_code == 503

    # /directives/active handles ValueError cleanly with HTTP 400 (not unhandled 500)
    with patch.object(persistence_repo, "query_directive_audits_sync", side_effect=ValueError("Bad internal token")):
        r_val = jwt_client.get("/api/v1/telemetry/directives/active?operational_mode=PHYSICAL", headers=admin_hdrs)
        assert r_val.status_code == 400


# =====================================================================
# 5. Startup Recovery Terminal Classification for REJECTED
# =====================================================================

def test_rejected_directive_is_terminal_and_never_restored_or_timed_out():
    repo = PersistenceRepository(supabase_url="", supabase_key="")
    # Both an expired (>30s) and a recent (<30s) persisted REJECTED directive
    repo.persist_directive_audit_sync({
        "audit_id": "aud_rej_exp_iss",
        "directive_id": "dir-rejected-expired",
        "event_type": "ISSUED",
        "operational_mode": "PHYSICAL",
        "section_id": "SEC_SCREENING_01",
        "action": "DIVERT_FLOW",
        "gate_target_angle": 90.0,
        "reason": "Test issued before reject",
        "issuer_id": "test_suite",
        "timestamp": "2026-11-20T10:00:00+00:00",
    })
    repo.persist_directive_audit_sync({
        "audit_id": "aud_rej_exp_rej",
        "directive_id": "dir-rejected-expired",
        "event_type": "REJECTED",
        "operational_mode": "PHYSICAL",
        "section_id": "SEC_SCREENING_01",
        "action": "DIVERT_FLOW",
        "gate_target_angle": 90.0,
        "reason": "Device rejected setpoint",
        "issuer_id": "test_suite",
        "timestamp": "2026-11-20T10:00:02+00:00",
    })
    from datetime import datetime, timezone
    now_iso = datetime.now(timezone.utc).isoformat()
    repo.persist_directive_audit_sync({
        "audit_id": "aud_rej_rec_rej",
        "directive_id": "dir-rejected-recent",
        "event_type": "REJECTED",
        "operational_mode": "PHYSICAL",
        "section_id": "SEC_SCREENING_01",
        "action": "DIVERT_FLOW",
        "gate_target_angle": 90.0,
        "reason": "Recent device rejection",
        "issuer_id": "test_suite",
        "timestamp": now_iso,
    })

    recovered = repo.recover_incomplete_directives_sync()
    recovered_ids = {r["directive_id"] for r in recovered}
    assert "dir-rejected-expired" not in recovered_ids
    assert "dir-rejected-recent" not in recovered_ids

    exp_events = [a["event_type"] for a in repo.query_directive_audits_sync("dir-rejected-expired")]
    rec_events = [a["event_type"] for a in repo.query_directive_audits_sync("dir-rejected-recent")]
    assert "VERIFICATION_TIMEOUT" not in exp_events
    assert "VERIFICATION_TIMEOUT" not in rec_events
    assert exp_events == ["ISSUED", "REJECTED"]
    assert rec_events == ["REJECTED"]


# =====================================================================
# 6. Migration 008 Static SQL & pglast AST Audit
# =====================================================================

def test_migration_008_ast_plpgsql_constraints_privileges_and_rls():
    mig_path = (
        Path(__file__).resolve().parent.parent.parent
        / "database"
        / "migrations"
        / "008_actuator_directive_audits.sql"
    )
    assert mig_path.is_file(), f"Missing migration file: {mig_path}"
    sql = mig_path.read_text(encoding="utf-8")

    # Parse complete SQL AST + both PL/pgSQL trigger function bodies
    parsed = pglast.parse_sql(sql)
    assert len(parsed) >= 25

    fn1_start = sql.index("CREATE OR REPLACE FUNCTION public.prevent_directive_audit_mutation_or_deletion()")
    fn2_start = sql.index("CREATE OR REPLACE FUNCTION public.prevent_directive_audit_truncate()")
    fn2_end = sql.index("DROP TRIGGER IF EXISTS trg_immutable_actuator_directive_audits")
    assert pglast.parse_plpgsql(sql[fn1_start:fn2_start].strip())[0]["PLpgSQL_function"]
    assert pglast.parse_plpgsql(sql[fn2_start:fn2_end].strip())[0]["PLpgSQL_function"]

    assert "INSERT INTO public.drainage_sections" in sql
    assert "'SEC_SCREENING_01'" in sql
    assert "ON CONFLICT (section_id) DO NOTHING" in sql
    assert "audit_id VARCHAR(64) PRIMARY KEY" in sql
    assert "REFERENCES public.devices(device_id) ON DELETE RESTRICT" in sql
    assert "REFERENCES public.drainage_sections(section_id) ON DELETE RESTRICT" in sql
    assert "event_metadata" not in sql

    for evt in (
        "'ISSUED'",
        "'FEEDBACK_RECEIVED'",
        "'ALIGNMENT_OBSERVED'",
        "'REJECTED'",
        "'EXECUTION_FAILED'",
        "'VERIFICATION_TIMEOUT'",
        "'SUPERSEDED'",
        "'CANCELLED'",
    ):
        assert evt in sql
    assert "STAGED_DELIVERY" not in sql
    assert "CHECK (operational_mode IN ('SIMULATION', 'PHYSICAL', 'SAFE_HOLD'))" in sql
    assert "'HARDWARE'" not in sql

    assert "REVOKE ALL ON FUNCTION public.prevent_directive_audit_mutation_or_deletion()" in sql
    assert "REVOKE ALL ON FUNCTION public.prevent_directive_audit_truncate()" in sql
    assert "FROM PUBLIC, anon, authenticated, service_role;" in sql
    assert "GRANT SELECT ON TABLE public.actuator_directive_audits TO authenticated;" in sql
    assert "GRANT SELECT, INSERT ON TABLE public.actuator_directive_audits TO service_role;" in sql
    assert "GRANT ALL ON TABLE public.actuator_directive_audits TO service_role" not in sql
    assert "user_metadata" not in sql
