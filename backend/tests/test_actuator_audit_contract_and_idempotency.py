"""
DRAIN-X Batch 2A Tests: Actuator Audit Persistence Contract, Deterministic IDs,
Duplicate/Conflict Verification & Service-Role Credential Enforcement.
"""

import base64
from datetime import datetime, timedelta, timezone
from decimal import Decimal
import json
import logging
import math
import re
from typing import Any, Dict, List, Optional
from unittest.mock import patch
import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.config import Settings, inspect_service_role_credential, settings, validate_production_configuration
from app.models.contracts import (
    ActuatorDirectiveContract,
    ActuatorDirectiveEventContract,
    AlertSeverity,
    DIRECTIVE_AUDIT_DB_COLUMNS,
    DataSource,
    DirectiveEventType,
    DirectiveIssuerType,
    MeasurementUnit,
    SensorHealthStatus,
    SensorReadingContract,
    SensorType,
    build_alignment_observed_audit_id,
    build_execution_failed_audit_id,
    build_feedback_received_audit_id,
    build_issued_audit_id,
    build_mode_cancellation_audit_id,
    build_reboot_cancellation_audit_id,
    build_rejected_audit_id,
    build_safe_hold_cancellation_audit_id,
    build_startup_cancellation_audit_id,
    build_superseded_audit_id,
    build_verification_timeout_audit_id,
    normalize_audit_timestamp_utc,
)
from app.services.actuator_digest import evaluate_alignment_consistency
from app.services.persistence_repository import (
    DirectiveAuditConflictError,
    PersistenceRepository,
    StorageError,
    StorageNotConfiguredError,
    _verify_immutable_directive_audit_match,
    persistence_repo,
    serialize_directive_audit_row,
)
from app.services.state_store import StateStore, state_store
from tests.conftest import TEST_JWT_SECRET, TEST_SUPABASE_URL, create_test_token


def _base_event_dict(**overrides: Any) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "audit_id": "aud_dir_test_01_ISS",
        "directive_id": "dir_test_01",
        "event_type": "ISSUED",
        "device_id": "DRAINX-ESP32-NODE-01",
        "section_id": "SEC_SCREENING_01",
        "operational_mode": "PHYSICAL",
        "directive_type": "DIVERSION_GATE",
        "action": "DIVERT_FLOW",
        "gate_target_angle": 45.0,
        "reason": "Predictive flood diversion required.",
        "risk_level": "HIGH",
        "emergency_stop": False,
        "measured_gate_angle": None,
        "measured_gate_state": None,
        "execution_divergence_deg": None,
        "issuer_type": "AUTOMATED_ENGINE",
        "issuer_id": "intervention_engine",
        "correlation_id": "corr-01",
        "device_session_epoch": 1,
        "baseline_device_sequence_number": 100,
        "device_sequence_number": None,
        "device_uptime_ms": None,
        "timestamp": "2026-11-23T12:00:00+00:00",
    }
    payload.update(overrides)
    return payload


# =====================================================================
# 1. Exact 23-Column Contract & Serialization Tests
# =====================================================================

def test_exact_23_column_serialization_and_commanded_vs_measured_separation():
    evt = ActuatorDirectiveEventContract(
        audit_id=build_feedback_received_audit_id("dir-abc-01", 2, 105),
        directive_id="dir-abc-01",
        event_type=DirectiveEventType.FEEDBACK_RECEIVED,
        device_id="DRAINX-ESP32-NODE-01",
        section_id="SEC_SCREENING_01",
        operational_mode="PHYSICAL",
        action="DIVERT_FLOW",
        gate_target_angle=45.0,
        reason="Intermediate telemetry feedback observed.",
        risk_level=AlertSeverity.HIGH,
        emergency_stop=False,
        measured_gate_angle=44.546,
        measured_gate_state="CLOSED",
        execution_divergence_deg=0.454,
        issuer_type=DirectiveIssuerType.AUTOMATED_ENGINE,
        issuer_id="intervention_engine",
        correlation_id="corr-fb-01",
        device_session_epoch=2,
        baseline_device_sequence_number=100,
        device_sequence_number=105,
        device_uptime_ms=105000,
        timestamp=datetime(2026, 11, 23, 12, 0, 5, tzinfo=timezone.utc),
    )

    row = serialize_directive_audit_row(evt)
    assert tuple(row.keys()) == DIRECTIVE_AUDIT_DB_COLUMNS
    assert len(row) == 23

    # Commanded setpoint preserved distinctly from physical feedback
    assert row["action"] == "DIVERT_FLOW"
    assert row["gate_target_angle"] == 45.0
    assert row["measured_gate_angle"] == 44.55  # NUMERIC(5,2) HALF_UP quantization
    assert row["measured_gate_state"] == "CLOSED"
    assert row["execution_divergence_deg"] == 0.45
    assert row["event_type"] == "FEEDBACK_RECEIVED"
    assert row["risk_level"] == "HIGH"
    assert row["issuer_type"] == "AUTOMATED_ENGINE"
    assert row["baseline_device_sequence_number"] == 100
    assert row["device_sequence_number"] == 105
    assert row["device_uptime_ms"] == 105000
    assert row["timestamp"].endswith("+00:00")


@pytest.mark.parametrize(
    "missing_field",
    [
        "audit_id",
        "directive_id",
        "event_type",
        "section_id",
        "operational_mode",
        "action",
        "gate_target_angle",
        "reason",
        "issuer_id",
    ],
)
def test_missing_mandatory_fields_rejected_without_fabrication(missing_field: str):
    payload = _base_event_dict()
    del payload[missing_field]
    with pytest.raises((ValidationError, ValueError)):
        serialize_directive_audit_row(payload)


@pytest.mark.parametrize(
    "legacy_field,legacy_val",
    [
        ("observed_sequence_number", 101),
        ("measured_angle", 45.0),
        ("measured_state", "OPEN"),
        ("angular_error", 0.5),
        ("settling_time_s", 1.2),
        ("failure_reason", "timeout"),
        ("event_metadata", {"gate_target_angle": 45.0}),
        ("unexpected_extra_column", "bad"),
    ],
)
def test_legacy_and_unknown_fields_strictly_rejected(legacy_field: str, legacy_val: Any):
    payload = _base_event_dict(**{legacy_field: legacy_val})
    with pytest.raises((ValidationError, ValueError)):
        ActuatorDirectiveEventContract.model_validate(payload)
    with pytest.raises(ValueError):
        serialize_directive_audit_row(payload)


def test_invalid_types_enums_ranges_and_naive_timestamps_rejected():
    bad_cases = [
        {"event_type": "STAGED_DELIVERY"},
        {"operational_mode": "HARDWARE"},
        {"measured_gate_state": "THROTTLED"},
        {"directive_type": "SLUICE_VALVE"},
        {"issuer_type": "EXTERNAL_SCRIPT"},
        {"risk_level": "FATAL"},
        {"gate_target_angle": True},
        {"gate_target_angle": float("nan")},
        {"gate_target_angle": float("inf")},
        {"gate_target_angle": 90.5},
        {"measured_gate_angle": False},
        {"measured_gate_angle": -0.1},
        {"execution_divergence_deg": 91.0},
        {"emergency_stop": "false"},
        {"device_session_epoch": True},
        {"device_session_epoch": -1},
        {"device_sequence_number": 4294967296},
        {"baseline_device_sequence_number": 12.5},
        {"device_uptime_ms": -5},
        {"timestamp": datetime(2026, 11, 23, 12, 0, 0)},  # naive datetime
        {"timestamp": "2026-11-23T12:00:00"},  # naive ISO string
        {"audit_id": ""},
        {"reason": "   "},
        {"action": " DIVERT_FLOW"},
    ]
    for patch_dict in bad_cases:
        with pytest.raises((ValidationError, ValueError)):
            serialize_directive_audit_row(_base_event_dict(**patch_dict))


# =====================================================================
# 2. Deterministic Audit IDs & Length Boundaries
# =====================================================================

def test_deterministic_audit_ids_distinctness_and_varchar64_bounds():
    d_id = "dir-12345"
    sup_id = "dir-67890"

    ids = {
        "issued": build_issued_audit_id(d_id),
        "can_startup": build_startup_cancellation_audit_id(d_id),
        "can_safehold": build_safe_hold_cancellation_audit_id(d_id),
        "can_mode_sim": build_mode_cancellation_audit_id(d_id, "SIMULATION"),
        "can_mode_phys": build_mode_cancellation_audit_id(d_id, "PHYSICAL"),
        "can_reboot": build_reboot_cancellation_audit_id(d_id, 3),
        "timeout": build_verification_timeout_audit_id(d_id),
        "superseded": build_superseded_audit_id(d_id, sup_id),
        "feedback": build_feedback_received_audit_id(d_id, 3, 42),
        "aligned": build_alignment_observed_audit_id(d_id, 3, 43),
        "failed": build_execution_failed_audit_id(d_id, 3, 44),
        "rejected_pre_obs": build_rejected_audit_id(d_id),
        "rejected_obs": build_rejected_audit_id(d_id, 3, 45),
    }

    assert ids["issued"] == "aud_dir-12345_ISS"
    assert ids["can_startup"] == "aud_dir-12345_CAN_STARTUP"
    assert ids["can_safehold"] == "aud_dir-12345_CAN_SAFEHOLD"
    assert build_mode_cancellation_audit_id(d_id, "SAFE_HOLD") == ids["can_safehold"]
    assert ids["timeout"] == "aud_dir-12345_TOUT"
    assert ids["feedback"] == "aud_dir-12345_FB_e3_s42"
    assert ids["aligned"] == "aud_dir-12345_ALN_e3_s43"
    assert ids["failed"] == "aud_dir-12345_FAIL_e3_s44"
    assert ids["can_reboot"] == "aud_dir-12345_CAN_RBT_e3"
    assert ids["superseded"].startswith("aud_dir-12345_SUP_")

    # All semantically different transitions have distinct IDs
    assert len(set(ids.values())) == len(ids)

    # Extreme worst-case boundaries: 36-char UUID + INT32 max epoch + UINT32 max sequence
    max_uuid = "550e8400-e29b-41d4-a716-446655440000"
    assert len(max_uuid) == 36
    max_ids = [
        build_issued_audit_id(max_uuid),
        build_startup_cancellation_audit_id(max_uuid),
        build_safe_hold_cancellation_audit_id(max_uuid),
        build_mode_cancellation_audit_id(max_uuid, "SIMULATION"),
        build_mode_cancellation_audit_id(max_uuid, "PHYSICAL"),
        build_reboot_cancellation_audit_id(max_uuid, 2147483647),
        build_verification_timeout_audit_id(max_uuid),
        build_superseded_audit_id(max_uuid, "660e8400-e29b-41d4-a716-446655440000"),
        build_feedback_received_audit_id(max_uuid, 2147483647, 4294967295),
        build_alignment_observed_audit_id(max_uuid, 2147483647, 4294967295),
        build_execution_failed_audit_id(max_uuid, 2147483647, 4294967295),
        build_rejected_audit_id(max_uuid),
        build_rejected_audit_id(max_uuid, 2147483647, 4294967295),
    ]
    for aid in max_ids:
        assert 1 <= len(aid) <= 64, aid
        assert re.match(r"^[A-Za-z0-9_.:-]{1,64}$", aid), aid

    # Different long directive_ids still produce distinct compacted IDs
    alt_uuid = "770e8400-e29b-41d4-a716-446655440000"
    assert build_execution_failed_audit_id(max_uuid, 2147483647, 4294967295) != (
        build_execution_failed_audit_id(alt_uuid, 2147483647, 4294967295)
    )

    with pytest.raises(ValueError):
        build_superseded_audit_id(d_id, d_id)
    with pytest.raises(ValueError):
        build_rejected_audit_id(d_id, device_session_epoch=1, device_sequence_number=None)


def test_statestore_emits_23_column_events_with_deterministic_ids():
    store = StateStore()
    store.clear()
    store.mode = "PHYSICAL"

    d1 = ActuatorDirectiveContract(
        directive_id="dir_ss_01",
        device_id="DRAINX-ESP32-NODE-01",
        section_id="SEC_SCREENING_01",
        gate_target_angle=45.0,
        action="DIVERT_FLOW",
        reason="Test flow diversion",
    )
    d2 = ActuatorDirectiveContract(
        directive_id="dir_ss_02",
        device_id="DRAINX-ESP32-NODE-01",
        section_id="SEC_SCREENING_01",
        gate_target_angle=90.0,
        action="EMERGENCY_OVERFLOW_RELIEF",
        reason="Supersede test",
    )
    store.set_gate_directive(d1)
    store.set_gate_directive(d2)
    store.set_mode("SAFE_HOLD", reason="Safety interlock triggered")

    events = store.flush_directive_audits_outbox()
    assert len(events) == 5  # d1 ISSUED, d1 SUPERSEDED, d2 ISSUED, d2 CANCELLED->SAFE_HOLD, SAFE_HOLD ISSUED
    rows = [serialize_directive_audit_row(e) for e in events]
    assert [r["audit_id"] for r in rows[:4]] == [
        build_issued_audit_id("dir_ss_01"),
        build_superseded_audit_id("dir_ss_01", "dir_ss_02"),
        build_issued_audit_id("dir_ss_02"),
        build_safe_hold_cancellation_audit_id("dir_ss_02"),
    ]
    for r in rows:
        assert tuple(r.keys()) == DIRECTIVE_AUDIT_DB_COLUMNS


# =====================================================================
# 3. Cloud Duplicate Verification, Conflict Rejection & Error Handling
# =====================================================================

def parse_postgrest_id_filter(expr: str) -> List[str]:
    """Parses `eq.<v>` / `in.(<v>,<v>)` PostgREST filters honoring double-quoted escaped values."""
    if expr.startswith("eq."):
        body = expr[3:]
        items = [body]
    elif expr.startswith("in.(") and expr.endswith(")"):
        body = expr[4:-1]
        items, cur, in_q, esc = [], "", False, False
        for ch in body:
            if esc:
                cur += ch
                esc = False
            elif in_q and ch == "\\":
                esc = True
            elif ch == '"':
                in_q = not in_q
                cur += ch
            elif ch == "," and not in_q:
                items.append(cur)
                cur = ""
            else:
                cur += ch
        items.append(cur)
    else:
        raise AssertionError(f"Unsupported filter: {expr}")
    out = []
    for item in items:
        if item.startswith('"') and item.endswith('"') and len(item) >= 2:
            item = item[1:-1]
        out.append(item)
    return out



class _FakeAuditPostgRESTClient:
    stored_by_id: Dict[str, Dict[str, Any]] = {}
    post_statuses: List[int] = []
    post_payloads: List[Any] = []
    get_params: List[Dict[str, str]] = []
    captured_headers: List[Dict[str, str]] = []
    force_post_status: Optional[int] = None
    force_post_json: Any = None
    force_get_status: Optional[int] = None
    force_get_json: Any = None
    raise_on_post: Optional[Exception] = None

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def post(self, endpoint: str, json: Any = None, headers: Optional[Dict[str, str]] = None):
        _FakeAuditPostgRESTClient.captured_headers.append(dict(headers or {}))
        _FakeAuditPostgRESTClient.post_payloads.append(json)
        if _FakeAuditPostgRESTClient.raise_on_post is not None:
            raise _FakeAuditPostgRESTClient.raise_on_post
        if _FakeAuditPostgRESTClient.force_post_status is not None:
            return httpx.Response(
                _FakeAuditPostgRESTClient.force_post_status,
                json=_FakeAuditPostgRESTClient.force_post_json
                if _FakeAuditPostgRESTClient.force_post_json is not None
                else {"error": "forced"},
            )
        inserted: List[Dict[str, Any]] = []
        for row in json:
            if row["audit_id"] not in _FakeAuditPostgRESTClient.stored_by_id:
                _FakeAuditPostgRESTClient.stored_by_id[row["audit_id"]] = dict(row)
                inserted.append(dict(row))
        return httpx.Response(201, json=inserted)

    def get(self, endpoint: str, params: Optional[Dict[str, str]] = None, headers: Optional[Dict[str, str]] = None):
        _FakeAuditPostgRESTClient.captured_headers.append(dict(headers or {}))
        if _FakeAuditPostgRESTClient.force_get_status is not None:
            return httpx.Response(
                _FakeAuditPostgRESTClient.force_get_status,
                json=_FakeAuditPostgRESTClient.force_get_json,
            )
        _FakeAuditPostgRESTClient.get_params.append(dict(params or {}))
        expr = (params or {}).get("audit_id", "")
        if expr:
            ids = parse_postgrest_id_filter(expr)
        else:
            ids = list(_FakeAuditPostgRESTClient.stored_by_id.keys())
        rows = [
            _FakeAuditPostgRESTClient.stored_by_id[aid]
            for aid in ids
            if aid in _FakeAuditPostgRESTClient.stored_by_id
        ]
        return httpx.Response(200, json=rows)


def _reset_fake_client():
    _FakeAuditPostgRESTClient.stored_by_id = {}
    _FakeAuditPostgRESTClient.post_statuses = []
    _FakeAuditPostgRESTClient.post_payloads = []
    _FakeAuditPostgRESTClient.get_params = []
    _FakeAuditPostgRESTClient.captured_headers = []
    _FakeAuditPostgRESTClient.force_post_status = None
    _FakeAuditPostgRESTClient.force_post_json = None
    _FakeAuditPostgRESTClient.force_get_status = None
    _FakeAuditPostgRESTClient.force_get_json = None
    _FakeAuditPostgRESTClient.raise_on_post = None


def test_cloud_duplicate_idempotent_match_and_conflict_rejection():
    _reset_fake_client()
    repo = PersistenceRepository(
        supabase_url="https://example.supabase.co",
        supabase_key="anon-public-key",
        service_role_key="srv-secret-key",
    )

    event_1 = _base_event_dict()

    with patch("app.services.persistence_repository.httpx.Client", _FakeAuditPostgRESTClient):
        # 1. Initial insert
        assert repo.persist_directive_audit_sync(event_1) is True
        assert set(_FakeAuditPostgRESTClient.post_payloads[0][0].keys()) == set(DIRECTIVE_AUDIT_DB_COLUMNS)

        # 2. Exact immutable duplicate (NUMERIC equivalence + equivalent instant in +05:30 offset) -> True
        dup_exact = _base_event_dict(
            gate_target_angle=45,
            timestamp="2026-11-23T17:30:00+05:30",
        )
        assert repo.persist_directive_audit_sync(dup_exact) is True

        # 3. 409 Conflict with exact match -> GET verifies and succeeds idempotently
        _FakeAuditPostgRESTClient.force_post_status = 409
        assert repo.persist_directive_audit_sync(dup_exact) is True
        _FakeAuditPostgRESTClient.force_post_status = None

        # 4. Same audit_id but differing timestamp -> MUST raise DirectiveAuditConflictError
        diff_ts_payload = _base_event_dict(timestamp="2026-11-23T12:05:00+00:00")
        with pytest.raises(DirectiveAuditConflictError, match="timestamp"):
            repo.persist_directive_audit_sync(diff_ts_payload)

        # 5. Same audit_id but altered immutable field -> raises DirectiveAuditConflictError!
        conflict_payload = _base_event_dict(gate_target_angle=90.0)
        with pytest.raises(DirectiveAuditConflictError):
            repo.persist_directive_audit_sync(conflict_payload)

        # Stored row remains completely untouched
        assert _FakeAuditPostgRESTClient.stored_by_id[event_1["audit_id"]]["gate_target_angle"] == 45.0
        assert _FakeAuditPostgRESTClient.stored_by_id[event_1["audit_id"]]["timestamp"] == "2026-11-23T12:00:00+00:00"


def test_intra_batch_duplicate_and_conflict_handling():
    repo = PersistenceRepository.create_isolated_in_memory()
    ev_a = _base_event_dict(audit_id="aud_dir_b_ISS", directive_id="dir_b")
    ev_a_dup = _base_event_dict(
        audit_id="aud_dir_b_ISS",
        directive_id="dir_b",
        timestamp="2026-11-23T17:30:00+05:30",  # Same UTC instant as 12:00:00+00:00
    )
    assert repo.persist_directive_audit_batch_sync([ev_a, ev_a_dup]) is True
    assert len(repo._in_memory_directive_audits) == 1

    ev_a_conflict = _base_event_dict(audit_id="aud_dir_b_ISS", directive_id="dir_b", action="SAFE_HOLD_LOCK")
    with pytest.raises(DirectiveAuditConflictError):
        repo.persist_directive_audit_batch_sync([ev_a, ev_a_conflict])

    ev_a_ts_conflict = _base_event_dict(
        audit_id="aud_dir_b_ISS", directive_id="dir_b", timestamp="2026-11-23T12:01:00+00:00"
    )
    with pytest.raises(DirectiveAuditConflictError, match="timestamp"):
        repo.persist_directive_audit_batch_sync([ev_a_ts_conflict])


def test_postgrest_errors_and_conflict_verify_failures():
    _reset_fake_client()
    repo = PersistenceRepository(
        supabase_url="https://example.supabase.co",
        supabase_key="",
        service_role_key="srv-secret-key",
    )
    ev = _base_event_dict()

    with patch("app.services.persistence_repository.httpx.Client", _FakeAuditPostgRESTClient):
        for status_code in (400, 401, 403, 500):
            _FakeAuditPostgRESTClient.force_post_status = status_code
            assert repo.persist_directive_audit_sync(ev, strict=False) is False
            with pytest.raises(StorageError):
                repo.persist_directive_audit_sync(ev, strict=True)

        # Malformed non-list JSON on 201
        _FakeAuditPostgRESTClient.force_post_status = 201
        _FakeAuditPostgRESTClient.force_post_json = {"unexpected": "dict"}
        assert repo.persist_directive_audit_sync(ev, strict=False) is False
        with pytest.raises(StorageError):
            repo.persist_directive_audit_sync(ev, strict=True)

        # Network exception
        _FakeAuditPostgRESTClient.force_post_status = None
        _FakeAuditPostgRESTClient.raise_on_post = httpx.ConnectError("network lost")
        assert repo.persist_directive_audit_sync(ev, strict=False) is False
        with pytest.raises(StorageError):
            repo.persist_directive_audit_sync(ev, strict=True)

        # Duplicate skipped by DB (201 []), but verification SELECT fails -> MUST fail closed (StorageError)
        _FakeAuditPostgRESTClient.raise_on_post = None
        _FakeAuditPostgRESTClient.force_post_status = 201
        _FakeAuditPostgRESTClient.force_post_json = []
        _FakeAuditPostgRESTClient.force_get_status = 500
        _FakeAuditPostgRESTClient.force_get_json = {"error": "select failed"}
        with pytest.raises(StorageError):
            repo.persist_directive_audit_sync(ev, strict=False)


# =====================================================================
# 4. Service-Role vs Anon Credentials Enforcement
# =====================================================================

def test_service_role_required_anon_key_rejected():
    anon_only_repo = PersistenceRepository(
        supabase_url="https://example.supabase.co",
        supabase_key="anon-only-key",
        service_role_key="",
    )
    assert anon_only_repo.is_configured is True
    assert anon_only_repo.is_storage_configured is False

    with pytest.raises(StorageNotConfiguredError):
        anon_only_repo.persist_directive_audit_sync(_base_event_dict())
    with pytest.raises(StorageNotConfiguredError):
        anon_only_repo.query_directive_audits_sync()

    # URL without any service_role key also fails closed
    url_only_repo = PersistenceRepository(
        supabase_url="https://example.supabase.co",
        supabase_key="",
        service_role_key="",
    )
    with pytest.raises(StorageNotConfiguredError):
        url_only_repo.persist_directive_audit_sync(_base_event_dict())

    # With both anon and service_role configured, ONLY service_role credential is sent
    _reset_fake_client()
    sr_repo = PersistenceRepository(
        supabase_url="https://example.supabase.co",
        supabase_key="anon-public-key",
        service_role_key="srv-secret-only-key",
    )
    with patch("app.services.persistence_repository.httpx.Client", _FakeAuditPostgRESTClient):
        assert sr_repo.persist_directive_audit_sync(_base_event_dict()) is True
    assert len(_FakeAuditPostgRESTClient.captured_headers) >= 1
    for hdrs in _FakeAuditPostgRESTClient.captured_headers:
        assert hdrs["apikey"] == "srv-secret-only-key"
        assert hdrs["Authorization"] == "Bearer srv-secret-only-key"
        assert "anon-public-key" not in hdrs.values()


# =====================================================================
# 5. Batch 2A.1 Remediation Tests (H-1, H-2, H-3, H-4, M-1, M-2)
# =====================================================================

def _make_unverified_jwt(payload: Dict[str, Any]) -> str:
    def _b64(obj: Dict[str, Any]) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return f"{_b64({'alg': 'HS256', 'typ': 'JWT'})}.{_b64(payload)}.fake-signature"


def test_h1_timestamp_immutability_and_missing_timestamp_rejection():
    repo = PersistenceRepository.create_isolated_in_memory()

    # Missing or None timestamp in raw dict MUST be rejected (never fabricated via utc_now)
    no_ts = _base_event_dict()
    del no_ts["timestamp"]
    with pytest.raises(ValueError, match="timestamp"):
        serialize_directive_audit_row(no_ts)

    none_ts = _base_event_dict(timestamp=None)
    with pytest.raises(ValueError, match="timestamp"):
        serialize_directive_audit_row(none_ts)

    # Insert base row with fractional microseconds
    base = _base_event_dict(
        audit_id="aud_h1_1_ISS",
        directive_id="h1_1",
        timestamp="2026-11-23T12:00:00.500000+00:00",
    )
    assert repo.persist_directive_audit_sync(base) is True

    # Identical UTC, lowercase z (whole second row), +05:30 equivalent, DB space-sep fractional string
    eq_offset = _base_event_dict(
        audit_id="aud_h1_1_ISS",
        directive_id="h1_1",
        timestamp="2026-11-23T17:30:00.5+05:30",
    )
    assert repo.persist_directive_audit_sync(eq_offset) is True

    # Database-returned PostgreSQL TIMESTAMPTZ string equivalence check
    serialized_base = serialize_directive_audit_row(base)
    pg_returned = dict(serialized_base)
    pg_returned["timestamp"] = "2026-11-23 12:00:00.5+00"
    _verify_immutable_directive_audit_match(pg_returned, serialized_base)

    # Lowercase 'z' normalization & sub-microsecond HALF_UP rounding vs microsecond
    assert normalize_audit_timestamp_utc("2026-11-23T12:00:00z") == datetime(
        2026, 11, 23, 12, 0, 0, tzinfo=timezone.utc
    )
    assert normalize_audit_timestamp_utc("2026-11-23T12:00:00.1234567+00:00") == datetime(
        2026, 11, 23, 12, 0, 0, 123457, tzinfo=timezone.utc
    )

    # Fractional 1-microsecond difference MUST raise conflict
    diff_us = _base_event_dict(
        audit_id="aud_h1_1_ISS",
        directive_id="h1_1",
        timestamp="2026-11-23T12:00:00.500001+00:00",
    )
    with pytest.raises(DirectiveAuditConflictError, match="timestamp"):
        repo.persist_directive_audit_sync(diff_us)

    # Deterministic timeout timestamp stability across repeated recovery calls
    old_issued = _base_event_dict(
        audit_id="aud_h1_rec_ISS",
        directive_id="h1_rec",
        timestamp="2026-11-20T10:00:00+00:00",
    )
    assert repo.persist_directive_audit_sync(old_issued) is True
    repo.recover_incomplete_directives_sync()
    events_1 = repo.query_directive_audits_sync("h1_rec")
    tout_ts_1 = [e["timestamp"] for e in events_1 if e["event_type"] == "VERIFICATION_TIMEOUT"]
    assert tout_ts_1 == ["2026-11-20T10:00:30+00:00"]
    # Manual duplicate submission of same deterministic timeout row succeeds idempotently
    tout_row = [e for e in events_1 if e["event_type"] == "VERIFICATION_TIMEOUT"][0]
    assert repo.persist_directive_audit_sync(tout_row) is True


def test_h2_service_role_credential_validation_and_secret_safety(monkeypatch, caplog):
    sr_jwt = _make_unverified_jwt({"role": "service_role", "iss": "supabase"})
    anon_jwt = _make_unverified_jwt({"role": "anon", "iss": "supabase"})
    auth_jwt = _make_unverified_jwt({"role": "authenticated", "iss": "supabase"})
    no_role_jwt = _make_unverified_jwt({"sub": "user-1", "iss": "supabase"})

    assert inspect_service_role_credential(sr_jwt, anon_jwt) == (True, None)
    assert inspect_service_role_credential("sb_secret_prod_xyz_123", "sb_publishable_abc") == (True, None)

    for bad_sr, anon in [
        (anon_jwt, None),
        (auth_jwt, None),
        (no_role_jwt, None),
        ("eyJmalformed", None),
        ("sb_publishable_123456", None),
        ("pk_live_123456", None),
        ("anon", None),
        ("same-secret-key", "same-secret-key"),
    ]:
        ok, msg = inspect_service_role_credential(bad_sr, anon)
        assert ok is False
        assert msg is not None
        if bad_sr != "anon":
            assert bad_sr not in msg

    # Repository accepts valid service_role JWT & supported sb_secret format
    valid_jwt_repo = PersistenceRepository(
        supabase_url="https://proj.supabase.co",
        supabase_key=anon_jwt,
        service_role_key=sr_jwt,
    )
    assert valid_jwt_repo.is_storage_configured is True
    assert valid_jwt_repo.directive_audit_cloud_mode() is True

    valid_secret_repo = PersistenceRepository(
        supabase_url="https://proj.supabase.co",
        supabase_key="sb_publishable_abc",
        service_role_key="sb_secret_srv_xyz",
    )
    assert valid_secret_repo.is_storage_configured is True
    assert valid_secret_repo.directive_audit_cloud_mode() is True

    # Repository rejects anon JWT, authenticated JWT, publishable key, identical keys, and partial configs
    for label, repo_bad in [
        ("anon_jwt", PersistenceRepository(supabase_url="https://proj.supabase.co", supabase_key="", service_role_key=anon_jwt)),
        ("auth_jwt", PersistenceRepository(supabase_url="https://proj.supabase.co", supabase_key="", service_role_key=auth_jwt)),
        ("pub_key", PersistenceRepository(supabase_url="https://proj.supabase.co", supabase_key="", service_role_key="sb_publishable_abc")),
        ("equal_keys", PersistenceRepository(supabase_url="https://proj.supabase.co", supabase_key="shared-secret", service_role_key="shared-secret")),
        ("url_only", PersistenceRepository(supabase_url="https://proj.supabase.co", supabase_key="", service_role_key="")),
        ("anon_no_url", PersistenceRepository(supabase_url="", supabase_key=anon_jwt, service_role_key="")),
        ("sr_no_url", PersistenceRepository(supabase_url="", supabase_key="", service_role_key=sr_jwt)),
    ]:
        assert repo_bad.is_storage_configured is False, label
        with pytest.raises(StorageNotConfiguredError) as exc_info:
            repo_bad.persist_directive_audit_sync(_base_event_dict())
        assert anon_jwt not in str(exc_info.value)
        assert auth_jwt not in str(exc_info.value)
        assert sr_jwt not in str(exc_info.value)

    # Conflicting constructor overrides fail closed instead of falling back to in-memory
    monkeypatch.setattr(settings, "SUPABASE_URL", "https://default.supabase.co")
    monkeypatch.setattr(settings, "SUPABASE_KEY", anon_jwt)
    monkeypatch.setattr(settings, "SUPABASE_SERVICE_ROLE_KEY", sr_jwt)
    conflict_repo = PersistenceRepository(supabase_key="foreign-anon-key-leak-test")
    assert conflict_repo.is_configured is False
    assert conflict_repo.is_storage_configured is False
    with pytest.raises(StorageNotConfiguredError, match="Conflicting Supabase configuration"):
        conflict_repo.persist_directive_audit_sync(_base_event_dict())

    # Production config rejects anon JWT / authenticated JWT / identical key without secret leakage
    base_prod = {
        "ENVIRONMENT": "production",
        "SUPABASE_AUTH_ENABLED": True,
        "SUPABASE_URL": "https://project.supabase.co",
        "SUPABASE_KEY": anon_jwt,
        "SUPABASE_SERVICE_ROLE_KEY": sr_jwt,
        "DEVICE_INGEST_API_KEY": "device-key-12345",
        "RATE_LIMIT_ENABLED": True,
        "RATE_LIMIT_STORAGE_BACKEND": "auto",
        "RATE_LIMIT_KEY_PEPPER": "0123456789abcdef0123456789abcdef",
        "_env_file": None,
    }
    validate_production_configuration(Settings(**base_prod))
    for bad_sr in (anon_jwt, auth_jwt, "sb_publishable_prod"):
        with pytest.raises(RuntimeError) as prod_exc:
            validate_production_configuration(Settings(**{**base_prod, "SUPABASE_SERVICE_ROLE_KEY": bad_sr}))
        assert bad_sr not in str(prod_exc.value)

    # Explicit test isolation works even if ENVIRONMENT == "production"
    with patch.object(settings, "ENVIRONMENT", "production"):
        isolated = PersistenceRepository.create_isolated_in_memory()
        assert isolated.directive_audit_cloud_mode() is False
        assert isolated.persist_directive_audit_sync(_base_event_dict()) is True
        unisolated_empty = PersistenceRepository(supabase_url="", supabase_key="", service_role_key="")
        with pytest.raises(StorageNotConfiguredError):
            unisolated_empty.directive_audit_cloud_mode()

    # Check no secrets leaked to logs
    assert sr_jwt not in caplog.text
    assert anon_jwt not in caplog.text
    assert "foreign-anon-key-leak-test" not in caplog.text


def test_h3_invalid_actuator_feedback_safety_and_telemetry_preservation(client: TestClient):
    # 1. evaluate_alignment_consistency boundary & invalid feedback matrix
    assert evaluate_alignment_consistency(45.0, -5.0, "CLOSED")[0] is False
    assert evaluate_alignment_consistency(45.0, 120.0, "OPEN")[0] is False
    assert evaluate_alignment_consistency(45.0, float("nan"), "CLOSED")[0] is False
    assert evaluate_alignment_consistency(45.0, float("inf"), "CLOSED")[0] is False
    assert evaluate_alignment_consistency(45.0, True, "CLOSED")[0] is False
    assert evaluate_alignment_consistency(45.0, 45.0, "UNKNOWN_STATE")[0] is False
    assert evaluate_alignment_consistency(45.0, 45.0, None)[0] is False
    ok_valid, _, err_valid = evaluate_alignment_consistency(45.0, 45.5, "CLOSED")
    assert ok_valid is True
    assert err_valid == 0.5

    # 2. Invalid feedback after settling window must NOT crash StateStore or lose raw telemetry
    store = StateStore()
    store.clear()
    store.mode = "PHYSICAL"

    for idx, (bad_angle, bad_state) in enumerate(
        [
            (-5.0, "CLOSED"),
            (120.0, "OPEN"),
            (float("nan"), "CLOSED"),
            (float("inf"), "OPEN"),
            (True, "CLOSED"),
            (45.0, "UNKNOWN_STATE"),
            (45.0, None),
        ],
        start=1,
    ):
        d_id = f"dir_h3_{idx}"
        directive = ActuatorDirectiveContract(
            directive_id=d_id,
            device_id="DRAINX-ESP32-NODE-01",
            gate_target_angle=45.0,
            action="DIVERT_FLOW",
            timestamp=datetime.now(timezone.utc) - timedelta(seconds=20),
        )
        store.set_gate_directive(directive)
        seq = idx * 10
        reading = SensorReadingContract(
            sensor_id="US_UPSTREAM_01",
            section_id="SEC_SCREENING_01",
            sensor_type=SensorType.WATER_LEVEL,
            value=6.0 + idx,
            unit=MeasurementUnit.CENTIMETRE,
            source=DataSource.PHYSICAL,
            status=SensorHealthStatus.OK,
            device_id="DRAINX-ESP32-NODE-01",
            sequence_number=seq,
            uptime_ms=seq * 1000,
            gate_angle_deg=None if isinstance(bad_angle, bool) else bad_angle,
            metadata={"gate_state": bad_state} if bad_state is not None else {},
        )
        if isinstance(bad_angle, bool):
            # Simulate malformed boolean metadata snapshot inside observation correlation
            reading.metadata["gate_angle_deg"] = bad_angle
            reading.gate_angle_deg = None

        store.ingest_reading(reading)
        obs_status, _ = store.process_telemetry_observation([reading])
        assert obs_status == "NEW"
        # Raw telemetry preserved intact in StateStore
        latest_r = store.get_latest_readings()["US_UPSTREAM_01"]
        assert latest_r.value == 6.0 + idx

        events = store.get_directive_audits(d_id)
        if bad_state is None:
            # Missing gate state: no alignment claimed, no crash
            assert [e.event_type for e in events] == [DirectiveEventType.ISSUED]
        else:
            fail_events = [e for e in events if e.event_type == DirectiveEventType.EXECUTION_FAILED]
            assert len(fail_events) == 1
            fe = fail_events[0]
            # Entire ledger event must serialize cleanly into Migration 008 schema
            row = serialize_directive_audit_row(fe)
            assert row["event_type"] == "EXECUTION_FAILED"
            if bad_state == "UNKNOWN_STATE":
                assert row["measured_gate_state"] is None
                assert row["measured_gate_angle"] == 45.0
                assert "UNKNOWN_STATE" in row["reason"]
            else:
                assert row["measured_gate_angle"] is None
                assert row["execution_divergence_deg"] is None

    # 3. End-to-end API POST /api/v1/telemetry continues cleanly with out-of-range / unknown gate feedback
    state_store.set_mode("PHYSICAL", reason="H-3 API test")
    resp_bad = client.post(
        "/api/v1/telemetry",
        json={
            "sensor_id": "US_UPSTREAM_01",
            "section_id": "SEC_SCREENING_01",
            "sensor_type": "WATER_LEVEL",
            "value": 5.5,
            "unit": "cm",
            "source": "PHYSICAL",
            "status": "OK",
            "device_id": "DRAINX-ESP32-NODE-01",
            "sequence_number": 900,
            "uptime_ms": 900000,
            "gate_angle_deg": 135.0,
            "metadata": {"gate_state": "BROKEN_STATE"},
        },
    )
    assert resp_bad.status_code == 201
    latest_api = state_store.get_latest_readings()["US_UPSTREAM_01"]
    assert latest_api.gate_angle_deg == 135.0
    assert latest_api.metadata["gate_state"] == "BROKEN_STATE"


def test_h4_cloud_mode_consistency_and_api_boundaries(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "SUPABASE_AUTH_ENABLED", True)
    monkeypatch.setattr(settings, "SUPABASE_JWT_SECRET", TEST_JWT_SECRET)
    monkeypatch.setattr(settings, "SUPABASE_URL", TEST_SUPABASE_URL)
    admin_hdrs = {"Authorization": f"Bearer {create_test_token(role='admin', subject='adm-h4')}"}

    # Misconfigured cloud: URL + anon key only (missing service_role key) -> reads and writes BOTH fail closed 503
    anon_jwt = _make_unverified_jwt({"role": "anon"})
    monkeypatch.setattr(persistence_repo, "_supabase_url", "https://example.supabase.co")
    monkeypatch.setattr(persistence_repo, "_supabase_key", anon_jwt)
    monkeypatch.setattr(persistence_repo, "_supabase_service_role_key", "")
    monkeypatch.setattr(persistence_repo, "_active_key", anon_jwt)
    monkeypatch.setattr(persistence_repo, "_is_configured", True)
    monkeypatch.setattr(persistence_repo, "_config_conflict_reason", None)

    assert client.get("/api/v1/telemetry/directives/active", headers=admin_hdrs).status_code == 503
    assert client.get("/api/v1/telemetry/directives/history", headers=admin_hdrs).status_code == 503

    r_ingest = client.post(
        "/api/v1/telemetry",
        json={
            "sensor_id": "US_UPSTREAM_01",
            "section_id": "SEC_SCREENING_01",
            "sensor_type": "WATER_LEVEL",
            "value": 5.0,
            "unit": "cm",
            "source": "SIMULATED",
            "status": "OK",
        },
    )
    assert r_ingest.status_code == 503


def test_m1_physical_directive_device_and_issuer_attribution(client: TestClient, monkeypatch):
    # 1. PHYSICAL directives attribute resolved device consistently & enforce device binding
    store = StateStore()
    store.clear()
    store.mode = "PHYSICAL"
    store.process_telemetry_observation([
        SensorReadingContract(
            sensor_id="US_UPSTREAM_01",
            section_id="SEC_SCREENING_01",
            sensor_type=SensorType.WATER_LEVEL,
            value=5.0,
            unit=MeasurementUnit.CENTIMETRE,
            source=DataSource.PHYSICAL,
            status=SensorHealthStatus.OK,
            device_id="DRAINX-ESP32-NODE-01",
            sequence_number=10,
            uptime_ms=10000,
            gate_angle_deg=0.0,
            metadata={"gate_state": "CLOSED"},
        )
    ])

    d_phys = ActuatorDirectiveContract(
        directive_id="dir_m1_phys_1",
        device_id=None,
        gate_target_angle=45.0,
        action="DIVERT_FLOW",
        reason="High head",
    )
    store.set_gate_directive(d_phys)
    assert d_phys.device_id == "DRAINX-ESP32-NODE-01"
    assert d_phys.baseline_device_sequence_number == 10
    assert d_phys.device_session_epoch == 0

    # Different device NODE-02 must NOT correlate against NODE-01's active directive
    store.process_telemetry_observation([
        SensorReadingContract(
            sensor_id="US_UPSTREAM_02",
            section_id="SEC_OUTLET",
            sensor_type=SensorType.WATER_LEVEL,
            value=5.0,
            unit=MeasurementUnit.CENTIMETRE,
            source=DataSource.PHYSICAL,
            status=SensorHealthStatus.OK,
            device_id="DRAINX-ESP32-NODE-02",
            sequence_number=50,
            uptime_ms=50000,
            gate_angle_deg=45.0,
            metadata={"gate_state": "CLOSED"},
        )
    ])
    assert store.get_active_directive("PHYSICAL") is not None

    # Repeated issuance of identical directive_id is idempotent (no duplicate/conflicting ISSUED row)
    d_repeat = ActuatorDirectiveContract(
        directive_id="dir_m1_phys_1",
        device_id="DRAINX-ESP32-NODE-01",
        gate_target_angle=45.0,
        action="DIVERT_FLOW",
        reason="High head",
    )
    store.set_gate_directive(d_repeat)
    assert len([e for e in store.get_directive_audits("dir_m1_phys_1") if e.event_type == DirectiveEventType.ISSUED]) == 1

    # Conflicting re-issuance of same directive_id raises ValueError cleanly
    with pytest.raises(ValueError, match="already issued"):
        store.set_gate_directive(
            ActuatorDirectiveContract(
                directive_id="dir_m1_phys_1",
                device_id="DRAINX-ESP32-NODE-01",
                gate_target_angle=90.0,
                action="DIVERT_FLOW",
                reason="Conflicting angle",
            )
        )

    # Correct device NODE-01 alignment observed -> same device_id across lifecycle
    store.process_telemetry_observation([
        SensorReadingContract(
            sensor_id="US_UPSTREAM_01",
            section_id="SEC_SCREENING_01",
            sensor_type=SensorType.WATER_LEVEL,
            value=5.0,
            unit=MeasurementUnit.CENTIMETRE,
            source=DataSource.PHYSICAL,
            status=SensorHealthStatus.OK,
            device_id="DRAINX-ESP32-NODE-01",
            sequence_number=11,
            uptime_ms=11000,
            gate_angle_deg=45.0,
            metadata={"gate_state": "CLOSED"},
        )
    ])
    audits = store.get_directive_audits("dir_m1_phys_1")
    assert [e.event_type for e in audits] == [
        DirectiveEventType.ISSUED,
        DirectiveEventType.ALIGNMENT_OBSERVED,
    ]
    assert {e.device_id for e in audits} == {"DRAINX-ESP32-NODE-01"}

    # 2. SIMULATION mode does NOT invent a physical device_id
    store_sim = StateStore()
    store_sim.clear()
    store_sim.mode = "SIMULATION"
    d_sim = ActuatorDirectiveContract(directive_id="dir_m1_sim_1", gate_target_angle=45.0, action="DIVERT_FLOW")
    store_sim.set_gate_directive(d_sim)
    assert d_sim.device_id is None
    assert store_sim.get_directive_audits("dir_m1_sim_1")[0].device_id is None

    # 3. Operator mode transition must require explicit issuer_id and record real JWT subject
    with pytest.raises(ValueError, match="issuer_id"):
        store_sim.set_mode("PHYSICAL", "Missing operator", issuer_type=DirectiveIssuerType.OPERATOR, issuer_id="  ")

    monkeypatch.setattr(settings, "SUPABASE_AUTH_ENABLED", True)
    monkeypatch.setattr(settings, "SUPABASE_JWT_SECRET", TEST_JWT_SECRET)
    monkeypatch.setattr(settings, "SUPABASE_URL", TEST_SUPABASE_URL)
    op_hdrs = {"Authorization": f"Bearer {create_test_token(role='municipality', subject='officer-42')}"}

    state_store.set_mode("PHYSICAL", reason="M-1 test init")
    state_store.set_gate_directive(
        ActuatorDirectiveContract(
            directive_id="dir_m1_api_cancel",
            device_id="DRAINX-ESP32-NODE-01",
            gate_target_angle=45.0,
            action="DIVERT_FLOW",
        )
    )
    resp_mode = client.post(
        "/api/v1/status/mode",
        json={"mode": "SAFE_HOLD", "reason": "Operator lock"},
        headers=op_hdrs,
    )
    assert resp_mode.status_code == 200
    cancel_evt = [
        e for e in state_store.get_directive_audits("dir_m1_api_cancel")
        if e.event_type == DirectiveEventType.CANCELLED
    ][0]
    assert cancel_evt.issuer_type == DirectiveIssuerType.OPERATOR
    assert cancel_evt.issuer_id == "officer-42"
    assert cancel_evt.device_id == "DRAINX-ESP32-NODE-01"
    safe_evt = [
        e for e in state_store.get_directive_audits()
        if e.event_type == DirectiveEventType.ISSUED and e.operational_mode == "SAFE_HOLD"
    ][-1]
    assert safe_evt.issuer_type == DirectiveIssuerType.SAFETY_INTERLOCK
    assert safe_evt.issuer_id == "safety_interlock"
    assert safe_evt.device_id == "DRAINX-ESP32-NODE-01"


def test_m2_numeric_5_2_quantization_consistency_and_boundaries():
    repo = PersistenceRepository.create_isolated_in_memory()

    cases = [
        (Decimal("45.004"), 45.0),
        (Decimal("45.005"), 45.01),
        (Decimal("1.005"), 1.01),
        (Decimal("2.675"), 2.68),
        (Decimal("89.995"), 90.0),
        (Decimal("45.0049999999999999"), 45.0),
        (-0.0, 0.0),
        (Decimal("-0.0"), 0.0),
    ]
    for idx, (raw_val, expected) in enumerate(cases):
        evt = ActuatorDirectiveEventContract(**_base_event_dict(
            audit_id=f"aud_m2_{idx}_ISS",
            directive_id=f"m2_{idx}",
            gate_target_angle=raw_val,
        ))
        assert evt.gate_target_angle == expected
        assert math.copysign(1.0, evt.gate_target_angle) > 0  # +0.0, never -0.0
        row = serialize_directive_audit_row(evt)
        assert row["gate_target_angle"] == expected
        assert math.copysign(1.0, row["gate_target_angle"]) > 0

    # Range check before quantization: >90.0 or <0.0 rejected even near boundary
    for out_of_bounds in (Decimal("90.004"), Decimal("-0.001")):
        with pytest.raises((ValidationError, ValueError)):
            serialize_directive_audit_row(_base_event_dict(gate_target_angle=out_of_bounds))

    # Decimal("45.0049999999999999") (45.00) must NOT collapse into Decimal("45.005") (45.01)
    assert repo.persist_directive_audit_sync(
        _base_event_dict(audit_id="aud_m2_diff_ISS", directive_id="m2_diff", gate_target_angle=Decimal("45.0049999999999999"))
    ) is True
    with pytest.raises(DirectiveAuditConflictError, match="gate_target_angle"):
        repo.persist_directive_audit_sync(
            _base_event_dict(audit_id="aud_m2_diff_ISS", directive_id="m2_diff", gate_target_angle=Decimal("45.005"))
        )


# =====================================================================
# 6. Batch 2A.2 Tests (M-3 persistence reliability, reboot isolation, deterministic timeouts)
# =====================================================================

def _iss_dict(i: int, **overrides: Any) -> Dict[str, Any]:
    return _base_event_dict(audit_id=f"aud_big_{i}_ISS", directive_id=f"big_{i}", **overrides)


def _cloud_repo(chunk_size: Optional[int] = None) -> PersistenceRepository:
    repo = PersistenceRepository(
        supabase_url="https://example.supabase.co",
        supabase_key="anon-public-key",
        service_role_key="srv-secret-key",
    )
    if chunk_size is not None:
        repo.directive_audit_verify_chunk_size = chunk_size
    return repo


def test_m3_postgrest_quoting_encoding_and_chunk_helpers():
    from app.services.persistence_repository import (
        _chunk_audit_ids,
        _format_audit_id_postgrest_filter,
        _quote_postgrest_value,
    )

    assert _quote_postgrest_value("aud_plain_ISS") == "aud_plain_ISS"
    assert _quote_postgrest_value("a,b") == '"a,b"'
    assert _quote_postgrest_value("x:y.z") == '"x:y.z"'
    assert _quote_postgrest_value("p(q)") == '"p(q)"'
    assert _quote_postgrest_value('q"uote') == '"q\\"uote"'
    assert _quote_postgrest_value("back\\slash") == '"back\\\\slash"'
    assert _quote_postgrest_value("sp ace") == '"sp ace"'
    for bad in ("", "line\nbreak", "nul\x00", None):
        with pytest.raises(ValueError):
            _quote_postgrest_value(bad)  # type: ignore[arg-type]

    assert _format_audit_id_postgrest_filter(["one"]) == "eq.one"
    assert _format_audit_id_postgrest_filter(["a", "b:c"]) == 'in.(a,"b:c")'
    with pytest.raises(ValueError):
        _format_audit_id_postgrest_filter([])

    # Round-trip through the test parser, including nasty characters
    nasty = ["a,b", 'q"uote', "p(q)", "x:y.z", "back\\slash", "plain"]
    assert parse_postgrest_id_filter(_format_audit_id_postgrest_filter(nasty)) == nasty

    # Chunking: empty, count-bounded, char-bounded, order-preserving
    assert _chunk_audit_ids([], 50, 3000) == []
    ids = [f"id_{i}" for i in range(120)]
    chunks = _chunk_audit_ids(ids, 50, 3000)
    assert [len(c) for c in chunks] == [50, 50, 20]
    assert [i for c in chunks for i in c] == ids
    char_chunks = _chunk_audit_ids(ids, 1000, 60)
    assert all(sum(len(i) + 1 for i in c) <= 60 for c in char_chunks)
    assert [i for c in char_chunks for i in c] == ids


def test_m3_cloud_preflight_chunking_merge_and_no_partial_write():
    _reset_fake_client()
    repo = _cloud_repo(chunk_size=25)
    batch = [_iss_dict(i) for i in range(120)]

    with patch("app.services.persistence_repository.httpx.Client", _FakeAuditPostgRESTClient):
        assert repo.persist_directive_audit_batch_sync(batch) is True
        assert len(_FakeAuditPostgRESTClient.stored_by_id) == 120
        assert len(_FakeAuditPostgRESTClient.post_payloads) == 1
        assert len(_FakeAuditPostgRESTClient.post_payloads[0]) == 120  # single bulk statement
        sizes = [len(parse_postgrest_id_filter(p["audit_id"])) for p in _FakeAuditPostgRESTClient.get_params]
        assert max(sizes) <= 25 and sum(sizes) == 120 and len(sizes) == 5  # chunked pre-flight

        # Identical resubmission: verified across all chunks, no further POST
        assert repo.persist_directive_audit_batch_sync(batch) is True
        assert len(_FakeAuditPostgRESTClient.post_payloads) == 1

        # New row FIRST + conflicting duplicate in the LAST chunk: no write must occur
        new_row = _iss_dict(500)
        conflicting = _iss_dict(110, gate_target_angle=90.0)
        with pytest.raises(DirectiveAuditConflictError, match="gate_target_angle"):
            repo.persist_directive_audit_batch_sync([new_row] + batch[:109] + [conflicting])
        assert "aud_big_500_ISS" not in _FakeAuditPostgRESTClient.stored_by_id
        assert len(_FakeAuditPostgRESTClient.post_payloads) == 1

        # Nullable-field conflict (corr-01 vs None) and timestamp mismatch also conflict pre-write
        with pytest.raises(DirectiveAuditConflictError, match="correlation_id"):
            repo.persist_directive_audit_batch_sync([_iss_dict(3, correlation_id=None)])
        with pytest.raises(DirectiveAuditConflictError, match="timestamp"):
            repo.persist_directive_audit_batch_sync([_iss_dict(4, timestamp="2026-11-23T12:00:00.000001+00:00")])
        assert len(_FakeAuditPostgRESTClient.post_payloads) == 1

        # Mixed new + identical duplicates posts ONLY the new rows
        assert repo.persist_directive_audit_batch_sync([_iss_dict(1), new_row, _iss_dict(2)]) is True
        assert [r["audit_id"] for r in _FakeAuditPostgRESTClient.post_payloads[-1]] == ["aud_big_500_ISS"]

    # Empty batch is a no-op
    assert repo.persist_directive_audit_batch_sync([]) is True


def test_m3_reserved_character_ids_roundtrip_through_cloud_filters():
    _reset_fake_client()
    repo = _cloud_repo(chunk_size=2)
    tricky = [
        _base_event_dict(audit_id="aud_dir:1.x_ISS", directive_id="dir:1.x"),
        _base_event_dict(audit_id="aud_dir.2_ISS", directive_id="dir.2"),
        _base_event_dict(audit_id="aud_dir-3:z_ISS", directive_id="dir-3:z"),
    ]
    with patch("app.services.persistence_repository.httpx.Client", _FakeAuditPostgRESTClient):
        assert repo.persist_directive_audit_batch_sync(tricky) is True
        assert repo.persist_directive_audit_batch_sync(tricky) is True
        assert len(_FakeAuditPostgRESTClient.post_payloads) == 1
        assert any('"aud_dir:1.x_ISS"' in p["audit_id"] for p in _FakeAuditPostgRESTClient.get_params)


def test_m3_post_flight_race_handling_and_verification_failures():
    class _RacingClient(_FakeAuditPostgRESTClient):
        racing_row: Optional[Dict[str, Any]] = None

        def post(self, endpoint, json=None, headers=None):
            row = _RacingClient.racing_row
            if row is not None and row["audit_id"] not in _FakeAuditPostgRESTClient.stored_by_id:
                _FakeAuditPostgRESTClient.stored_by_id[row["audit_id"]] = dict(row)
            return httpx.Response(201, json=[])

    _reset_fake_client()
    repo = _cloud_repo()
    ev = _base_event_dict()
    identical = serialize_directive_audit_row(ev)
    conflicting = serialize_directive_audit_row(_base_event_dict(gate_target_angle=90.0))

    with patch("app.services.persistence_repository.httpx.Client", _RacingClient):
        _RacingClient.racing_row = identical
        assert repo.persist_directive_audit_sync(ev) is True  # benign concurrent identical writer

        _reset_fake_client()
        _RacingClient.racing_row = conflicting
        # Documented residual: concurrent conflicting writer is detected post-flight and reported.
        with pytest.raises(DirectiveAuditConflictError):
            repo.persist_directive_audit_sync(ev)

        _reset_fake_client()
        _RacingClient.racing_row = None  # skipped by DB but never found -> fail closed
        with pytest.raises(StorageError, match="neither inserted nor found"):
            repo.persist_directive_audit_sync(ev)

    # Transport failure during verification fails closed (even with strict=False)
    _reset_fake_client()
    with patch("app.services.persistence_repository.httpx.Client", _FakeAuditPostgRESTClient):
        _FakeAuditPostgRESTClient.force_get_status = 200
        _FakeAuditPostgRESTClient.force_get_json = {"not": "a list"}
        with pytest.raises(StorageError):
            repo.persist_directive_audit_sync(ev, strict=False)


def test_m3_in_memory_conflicting_batch_does_not_partially_mutate():
    repo = PersistenceRepository.create_isolated_in_memory()
    existing = _iss_dict(1)
    assert repo.persist_directive_audit_sync(existing) is True
    snapshot = [dict(r) for r in repo._in_memory_directive_audits]

    new_row = _iss_dict(2)
    conflicting = _iss_dict(1, action="SAFE_HOLD_LOCK")
    with pytest.raises(DirectiveAuditConflictError):
        repo.persist_directive_audit_batch_sync([new_row, conflicting])
    assert repo._in_memory_directive_audits == snapshot

    # Intra-batch conflict is rejected before any mutation too
    with pytest.raises(DirectiveAuditConflictError):
        repo.persist_directive_audit_batch_sync([_iss_dict(7), _iss_dict(7, reason="different reason")])
    assert repo._in_memory_directive_audits == snapshot

    # Idempotent retry still works
    assert repo.persist_directive_audit_batch_sync([existing, new_row]) is True
    assert len(repo._in_memory_directive_audits) == 2


def test_m3_telemetry_ingest_persists_off_event_loop(client: TestClient, monkeypatch):
    import asyncio

    observed: Dict[str, Any] = {}

    def _fake_persist(events, *, strict=False):
        try:
            asyncio.get_running_loop()
            observed["on_event_loop"] = True
        except RuntimeError:
            observed["on_event_loop"] = False
        observed["count"] = len(events)
        return True

    monkeypatch.setattr(persistence_repo, "persist_directive_audit_batch_sync", _fake_persist)
    resp = client.post(
        "/api/v1/telemetry",
        json={
            "sensor_id": "US_UPSTREAM_01",
            "section_id": "SEC_SCREENING_01",
            "sensor_type": "WATER_LEVEL",
            "value": 5.0,
            "unit": "cm",
            "source": "SIMULATED",
            "status": "OK",
        },
    )
    assert resp.status_code == 201
    assert observed.get("count", 0) >= 1
    assert observed["on_event_loop"] is False  # blocking I/O ran in a worker thread


def _reboot(store: StateStore, device_id: str, epoch: int) -> None:
    with store._lock:
        store._cancel_active_directive_on_reboot_locked(device_id, epoch)


def _cancelled(store: StateStore, directive_id: str):
    return [e for e in store.get_directive_audits(directive_id) if e.event_type == DirectiveEventType.CANCELLED]


def test_a2_reboot_cancellation_device_isolation():
    node1, node2 = "DRAINX-ESP32-NODE-01", "DRAINX-ESP32-NODE-02"

    # 1 + 6. Matching physical device reboot cancels with correct attribution
    s = StateStore()
    s.clear()
    s.mode = "PHYSICAL"
    s.set_gate_directive(ActuatorDirectiveContract(
        directive_id="dir_rb_match", device_id=node1, gate_target_angle=45.0, action="DIVERT_FLOW"))
    _reboot(s, node1, 3)
    assert s.get_active_directive("PHYSICAL") is None
    evt = _cancelled(s, "dir_rb_match")
    assert len(evt) == 1
    assert evt[0].audit_id == build_reboot_cancellation_audit_id("dir_rb_match", 3)
    assert evt[0].device_id == node1
    assert evt[0].operational_mode == "PHYSICAL"
    assert evt[0].issuer_type == DirectiveIssuerType.SAFETY_INTERLOCK
    assert evt[0].issuer_id == "reboot_detector"
    assert evt[0].device_session_epoch == 3

    # 2. Different physical device reboot does not cancel
    s = StateStore()
    s.clear()
    s.mode = "PHYSICAL"
    s.set_gate_directive(ActuatorDirectiveContract(
        directive_id="dir_rb_other", device_id=node1, gate_target_angle=45.0, action="DIVERT_FLOW"))
    _reboot(s, node2, 1)
    assert s.get_active_directive("PHYSICAL") is not None
    assert _cancelled(s, "dir_rb_other") == []

    # 3. Unattributed directive (device_id None) is never cancelled, no fabricated fallback
    s = StateStore()
    s.clear()
    s.mode = "PHYSICAL"
    with s._lock:
        s._active_directives["PHYSICAL"] = ActuatorDirectiveContract(
            directive_id="dir_rb_unattr", gate_target_angle=45.0, action="DIVERT_FLOW")
    _reboot(s, node1, 1)
    assert s.get_active_directive("PHYSICAL") is not None
    assert _cancelled(s, "dir_rb_unattr") == []

    # 4. SIMULATION directives (unattributed or explicitly attributed) are never cancelled
    s = StateStore()
    s.clear()
    s.mode = "SIMULATION"
    s.set_gate_directive(ActuatorDirectiveContract(
        directive_id="dir_rb_sim", gate_target_angle=45.0, action="DIVERT_FLOW"))
    with s._lock:
        s._active_directives["PHYSICAL"] = None
    _reboot(s, node1, 1)
    assert s.get_active_directive("SIMULATION") is not None
    s.set_gate_directive(ActuatorDirectiveContract(
        directive_id="dir_rb_sim_dev", device_id=node1, gate_target_angle=45.0, action="DIVERT_FLOW"))
    _reboot(s, node1, 2)
    assert s.get_active_directive("SIMULATION").directive_id == "dir_rb_sim_dev"
    assert _cancelled(s, "dir_rb_sim_dev") == []

    # 5. SAFE_HOLD entered from SIMULATION has no attributable physical device -> not cancelled
    s = StateStore()
    s.clear()
    s.mode = "SIMULATION"
    s.set_mode("SAFE_HOLD", reason="no device")
    safe = s.get_active_directive("SAFE_HOLD")
    assert safe is not None and safe.device_id is None
    _reboot(s, node1, 1)
    assert s.get_active_directive("SAFE_HOLD") is not None
    assert _cancelled(s, safe.directive_id) == []

    # SAFE_HOLD entered from PHYSICAL carries the real device attribution and IS cancelled for that device only
    s = StateStore()
    s.clear()
    s.mode = "PHYSICAL"
    s.set_gate_directive(ActuatorDirectiveContract(
        directive_id="dir_rb_sh", device_id=node1, gate_target_angle=45.0, action="DIVERT_FLOW"))
    s.set_mode("SAFE_HOLD", reason="from physical")
    safe = s.get_active_directive("SAFE_HOLD")
    assert safe.device_id == node1
    _reboot(s, node2, 1)
    assert s.get_active_directive("SAFE_HOLD") is not None
    _reboot(s, node1, 2)
    assert s.get_active_directive("SAFE_HOLD") is None
    cancel = _cancelled(s, safe.directive_id)[0]
    assert cancel.device_id == node1 and cancel.operational_mode == "SAFE_HOLD"


def test_a2_runtime_and_recovery_timeout_timestamps_are_identical():
    from app.models.contracts import compute_verification_timeout_timestamp

    issued = datetime(2026, 11, 20, 10, 0, 0, 123456, tzinfo=timezone.utc)
    timeout_s = settings.ACTUATOR_VERIFICATION_TIMEOUT_SEC
    expected_ts = issued + timedelta(seconds=timeout_s)

    # Helper: offsets normalize to UTC; naive treated as UTC
    plus530 = datetime(2026, 11, 20, 15, 30, 0, 123456, tzinfo=timezone(timedelta(hours=5, minutes=30)))
    assert compute_verification_timeout_timestamp(plus530, timeout_s) == expected_ts
    assert compute_verification_timeout_timestamp(issued.replace(tzinfo=None), timeout_s) == expected_ts
    assert compute_verification_timeout_timestamp(plus530, timeout_s).utcoffset() == timedelta(0)

    store = StateStore()
    store.clear()
    store.mode = "PHYSICAL"
    store.set_gate_directive(ActuatorDirectiveContract(
        directive_id="dir_det_tout", device_id="DRAINX-ESP32-NODE-01",
        gate_target_angle=45.0, action="DIVERT_FLOW", timestamp=issued))
    issued_evt = store.flush_directive_audits_outbox()[0]
    assert issued_evt.event_type == DirectiveEventType.ISSUED

    timeouts = store.evaluate_verification_timeouts()
    assert len(timeouts) == 1
    runtime_evt = timeouts[0]
    assert runtime_evt.timestamp == expected_ts  # deterministic deadline, not wall clock
    assert store.evaluate_verification_timeouts() == []  # repeated evaluation is idempotent

    # Startup-recovery reconstruction from the persisted ISSUED row
    repo = PersistenceRepository.create_isolated_in_memory()
    assert repo.persist_directive_audit_sync(issued_evt) is True
    repo.recover_incomplete_directives_sync()
    recovered_rows = [
        r for r in repo.query_directive_audits_sync("dir_det_tout") if r["event_type"] == "VERIFICATION_TIMEOUT"
    ]
    assert len(recovered_rows) == 1
    # Identical 23-column representation
    assert recovered_rows[0] == serialize_directive_audit_row(runtime_evt)
    assert tuple(recovered_rows[0].keys()) == DIRECTIVE_AUDIT_DB_COLUMNS

    # Runtime event persisted after recovery is an idempotent duplicate (no conflict); recovery is repeatable
    assert repo.persist_directive_audit_sync(runtime_evt) is True
    repo.recover_incomplete_directives_sync()
    assert len(repo.query_directive_audits_sync("dir_det_tout")) == 2


# =====================================================================
# Batch 2C.1: Startup Recovery Correctness Tests
# =====================================================================

def test_2c1_startup_recovery_first_class_persisted_columns():
    repo = PersistenceRepository.create_isolated_in_memory()
    store = StateStore()
    store.clear()
    store.mode = "SIMULATION"

    rec_time = datetime.now(timezone.utc).isoformat()
    raw_record = {
        "audit_id": "aud_dir_2c1_col_ISS",
        "directive_id": "dir_2c1_col",
        "event_type": "ISSUED",
        "device_id": "SIM_ACTUATOR_01",
        "section_id": "SEC_OUTLET",
        "operational_mode": "SIMULATION",
        "directive_type": "DIVERSION_GATE",
        "action": "DIVERT_FLOW",
        "gate_target_angle": 45.0,
        "reason": "Test first class column recovery",
        "risk_level": "HIGH",
        "emergency_stop": False,
        "issuer_id": "operator_console",
        "correlation_id": "corr-2c1-col",
        "device_session_epoch": 5,
        "baseline_device_sequence_number": 42,
        "timestamp": rec_time,
    }
    assert repo.persist_directive_audit_sync(raw_record) is True

    recovered = repo.recover_incomplete_directives_sync()
    assert len(recovered) == 1
    rec = recovered[0]
    assert rec["directive_id"] == "dir_2c1_col"
    assert rec["gate_target_angle"] == 45.0
    assert rec["action"] == "DIVERT_FLOW"
    assert rec["section_id"] == "SEC_OUTLET"
    assert rec["operational_mode"] == "SIMULATION"
    assert rec["baseline_device_sequence_number"] == 42
    assert rec["device_session_epoch"] == 5
    assert rec["correlation_id"] == "corr-2c1-col"
    # Legacy fields must not exist
    assert "event_metadata" not in rec
    assert "observed_sequence_number" not in rec

    # Reconcile into state store
    directive = ActuatorDirectiveContract(
        directive_id=rec["directive_id"],
        device_id=rec.get("device_id"),
        section_id=rec["section_id"],
        operational_mode=rec["operational_mode"],
        directive_type=rec.get("directive_type", "DIVERSION_GATE"),
        action=rec["action"],
        gate_target_angle=rec["gate_target_angle"],
        reason=rec["reason"],
        risk_level=rec.get("risk_level", AlertSeverity.INFO),
        emergency_stop=rec.get("emergency_stop", False),
        correlation_id=rec.get("correlation_id"),
        device_session_epoch=rec.get("device_session_epoch"),
        baseline_device_sequence_number=rec.get("baseline_device_sequence_number"),
        timestamp=normalize_audit_timestamp_utc(rec["timestamp"]),
    )
    assert store.reconcile_recovered_directive(directive, DirectiveEventType(rec["event_type"])) is True
    active = store.get_active_directive("SIMULATION")
    assert active is not None
    assert active.directive_id == "dir_2c1_col"
    assert active.gate_target_angle == 45.0
    assert active.action == "DIVERT_FLOW"
    assert active.section_id == "SEC_OUTLET"
    assert active.operational_mode == "SIMULATION"
    assert active.baseline_device_sequence_number == 42
    assert active.device_session_epoch == 5
    assert active.correlation_id == "corr-2c1-col"


def test_2c1_missing_required_fields_fail_closed():
    repo = PersistenceRepository.create_isolated_in_memory()
    now_iso = datetime.now(timezone.utc).isoformat()

    # Incomplete records missing mandatory columns
    bad_missing_section = {
        "audit_id": "aud_bad_sec_ISS",
        "directive_id": "bad_sec",
        "event_type": "ISSUED",
        "operational_mode": "SIMULATION",
        "action": "DIVERT_FLOW",
        "gate_target_angle": 10.0,
        "reason": "Missing section",
        "timestamp": now_iso,
    }
    # Persist directly into raw in-memory store bypassing high-level contract validation
    repo._in_memory_directive_audits.append(bad_missing_section)

    recovered = repo.recover_incomplete_directives_sync()
    assert all(r.get("directive_id") != "bad_sec" for r in recovered)

    # State store reconciliation directly with missing fields fails closed
    store = StateStore()
    store.clear()
    store.mode = "SIMULATION"
    bad_dir = ActuatorDirectiveContract(
        directive_id="bad_dir",
        operational_mode=None,  # missing operational mode
        gate_target_angle=10.0,
        action="DIVERT_FLOW",
    )
    assert store.reconcile_recovered_directive(bad_dir, DirectiveEventType.ISSUED) is False
    assert store.get_active_directive("SIMULATION") is None


def test_2c1_recent_incomplete_physical_directive_becomes_cancelled():
    repo = PersistenceRepository.create_isolated_in_memory()
    recent_time = datetime.now(timezone.utc).isoformat()

    assert repo.persist_directive_audit_sync({
        "audit_id": "aud_phys_rec_ISS",
        "directive_id": "phys_rec",
        "event_type": "ISSUED",
        "device_id": "DRAINX-ESP32-NODE-01",
        "section_id": "SEC_SCREENING_01",
        "operational_mode": "PHYSICAL",
        "action": "DIVERT_FLOW",
        "gate_target_angle": 60.0,
        "reason": "Recent physical command",
        "issuer_id": "operator_console",
        "timestamp": recent_time,
    }) is True

    # Recovery must NOT return physical directive for reactivation
    recovered = repo.recover_incomplete_directives_sync()
    assert all(r.get("directive_id") != "phys_rec" for r in recovered)

    # Persisted ledger must contain deterministic CANCELLED event
    audits = repo.query_directive_audits_sync("phys_rec")
    event_types = [a["event_type"] for a in audits]
    assert event_types == ["ISSUED", "CANCELLED"]

    cancelled_event = audits[-1]
    assert cancelled_event["audit_id"] == build_startup_cancellation_audit_id("phys_rec")
    assert cancelled_event["event_type"] == "CANCELLED"
    assert cancelled_event["issuer_type"] == DirectiveIssuerType.SAFETY_INTERLOCK.value
    assert cancelled_event["issuer_id"] == "startup_recovery"
    assert "restarted while physical directive was pending" in cancelled_event["reason"]
    assert cancelled_event["device_id"] == "DRAINX-ESP32-NODE-01"
    assert cancelled_event["gate_target_angle"] == 60.0


def test_2c1_expired_physical_directive_becomes_verification_timeout():
    repo = PersistenceRepository.create_isolated_in_memory()
    expired_time = "2026-11-20T10:00:00+00:00"

    assert repo.persist_directive_audit_sync({
        "audit_id": "aud_phys_exp_ISS",
        "directive_id": "phys_exp",
        "event_type": "ISSUED",
        "device_id": "DRAINX-ESP32-NODE-01",
        "section_id": "SEC_SCREENING_01",
        "operational_mode": "PHYSICAL",
        "action": "DIVERT_FLOW",
        "gate_target_angle": 90.0,
        "reason": "Expired physical command",
        "issuer_id": "operator_console",
        "timestamp": expired_time,
    }) is True

    recovered = repo.recover_incomplete_directives_sync()
    assert all(r.get("directive_id") != "phys_exp" for r in recovered)

    audits = repo.query_directive_audits_sync("phys_exp")
    event_types = [a["event_type"] for a in audits]
    assert event_types == ["ISSUED", "VERIFICATION_TIMEOUT"]
    tout = audits[-1]
    assert tout["audit_id"] == build_verification_timeout_audit_id("phys_exp")
    assert tout["timestamp"] == "2026-11-20T10:00:30+00:00"


def test_2c1_neither_physical_case_becomes_active_after_restart():
    store = StateStore()
    store.clear()
    store.mode = "PHYSICAL"

    # Direct attempt to reconcile any physical directive on startup must be rejected
    phys_dir = ActuatorDirectiveContract(
        directive_id="dir_phys_no_active",
        device_id="DRAINX-ESP32-NODE-01",
        section_id="SEC_SCREENING_01",
        operational_mode="PHYSICAL",
        action="DIVERT_FLOW",
        gate_target_angle=45.0,
        reason="Physical attempt",
    )
    assert store.reconcile_recovered_directive(phys_dir, DirectiveEventType.ISSUED) is False
    assert store.get_active_directive("PHYSICAL") is None
    assert store.get_active_directive("SIMULATION") is None


def test_2c1_simulation_recovery_remains_isolated():
    store = StateStore()
    store.clear()
    store.mode = "PHYSICAL"

    sim_dir = ActuatorDirectiveContract(
        directive_id="dir_sim_isolated",
        section_id="SEC_SCREENING_01",
        operational_mode="SIMULATION",
        action="DIVERT_FLOW",
        gate_target_angle=30.0,
        reason="Simulation test",
    )
    # When store is in PHYSICAL mode, simulation recovery must NOT contaminate active directives
    assert store.reconcile_recovered_directive(sim_dir, DirectiveEventType.ISSUED) is False
    assert store.get_active_directive("PHYSICAL") is None
    assert store.get_active_directive("SIMULATION") is None

    # When store is in SIMULATION mode, simulation recovery succeeds into SIMULATION only
    store.mode = "SIMULATION"
    assert store.reconcile_recovered_directive(sim_dir, DirectiveEventType.ISSUED) is True
    assert store.get_active_directive("SIMULATION") is not None
    assert store.get_active_directive("SIMULATION").directive_id == "dir_sim_isolated"
    assert store.get_active_directive("PHYSICAL") is None


def test_2c1_safe_hold_handling_and_mode_isolation():
    store = StateStore()
    store.clear()
    store.mode = "SIMULATION"

    safe_dir = ActuatorDirectiveContract(
        directive_id="dir_safe_hold_rec",
        section_id="SEC_SCREENING_01",
        operational_mode="SAFE_HOLD",
        action="SAFE_HOLD_LOCK",
        emergency_stop=True,
        gate_target_angle=0.0,
        reason="Protective safe hold",
    )
    # When store is in SIMULATION mode, SAFE_HOLD directive does not become active
    assert store.reconcile_recovered_directive(safe_dir, DirectiveEventType.ISSUED) is False
    assert store.get_active_directive("SAFE_HOLD") is None

    # When store is transitioned to SAFE_HOLD, it reconciles cleanly
    store.set_mode("SAFE_HOLD", reason="Test safe hold recovery")
    assert store.reconcile_recovered_directive(safe_dir, DirectiveEventType.ISSUED) is True
    assert store.get_active_directive("SAFE_HOLD") is not None
    assert store.get_active_directive("SAFE_HOLD").directive_id == "dir_safe_hold_rec"


def test_2c1_repeated_startup_recovery_is_idempotent():
    repo = PersistenceRepository.create_isolated_in_memory()
    now_dt = datetime(2026, 11, 23, 12, 0, 0, tzinfo=timezone.utc)
    recent_ts = "2026-11-23T11:59:50+00:00"  # 10s old
    expired_ts = "2026-11-23T11:00:00+00:00"  # 1 hr old

    # 1. Physical recent (should CANCEL)
    repo.persist_directive_audit_sync({
        "audit_id": "aud_idemp_pr_ISS",
        "directive_id": "idemp_pr",
        "event_type": "ISSUED",
        "device_id": "DRAINX-ESP32-NODE-01",
        "section_id": "SEC_SCREENING_01",
        "operational_mode": "PHYSICAL",
        "action": "DIVERT_FLOW",
        "gate_target_angle": 45.0,
        "reason": "idemp test",
        "issuer_id": "operator_console",
        "timestamp": recent_ts,
    })
    # 2. Physical expired (should VERIFICATION_TIMEOUT)
    repo.persist_directive_audit_sync({
        "audit_id": "aud_idemp_pe_ISS",
        "directive_id": "idemp_pe",
        "event_type": "ISSUED",
        "device_id": "DRAINX-ESP32-NODE-01",
        "section_id": "SEC_SCREENING_01",
        "operational_mode": "PHYSICAL",
        "action": "DIVERT_FLOW",
        "gate_target_angle": 45.0,
        "reason": "idemp test",
        "issuer_id": "operator_console",
        "timestamp": expired_ts,
    })
    # 3. Simulation recent (should recover)
    repo.persist_directive_audit_sync({
        "audit_id": "aud_idemp_sr_ISS",
        "directive_id": "idemp_sr",
        "event_type": "ISSUED",
        "section_id": "SEC_SCREENING_01",
        "operational_mode": "SIMULATION",
        "action": "MAINTAIN_NORMAL",
        "gate_target_angle": 0.0,
        "reason": "idemp test",
        "issuer_id": "operator_console",
        "timestamp": recent_ts,
    })

    # Pass 1
    rec1 = repo.recover_incomplete_directives_sync(now=now_dt)
    assert len(rec1) == 1
    assert rec1[0]["directive_id"] == "idemp_sr"
    audits_pass1 = [dict(a) for a in repo._in_memory_directive_audits]

    # Pass 2 (immediate re-run)
    rec2 = repo.recover_incomplete_directives_sync(now=now_dt)
    assert len(rec2) == 1
    assert rec2[0]["directive_id"] == "idemp_sr"
    audits_pass2 = [dict(a) for a in repo._in_memory_directive_audits]

    # Zero duplicate audit events appended
    assert audits_pass1 == audits_pass2

    # Pass 3
    rec3 = repo.recover_incomplete_directives_sync(now=now_dt)
    assert len(rec3) == 1
    assert [dict(a) for a in repo._in_memory_directive_audits] == audits_pass1


def test_2c1_no_fabricated_hardware_execution_or_feedback():
    repo = PersistenceRepository.create_isolated_in_memory()
    now_dt = datetime(2026, 11, 23, 12, 0, 0, tzinfo=timezone.utc)
    recent_ts = "2026-11-23T11:59:50+00:00"

    repo.persist_directive_audit_sync({
        "audit_id": "aud_nofab_ISS",
        "directive_id": "nofab",
        "event_type": "ISSUED",
        "device_id": "DRAINX-ESP32-NODE-01",
        "section_id": "SEC_SCREENING_01",
        "operational_mode": "PHYSICAL",
        "action": "DIVERT_FLOW",
        "gate_target_angle": 45.0,
        "reason": "nofab test",
        "issuer_id": "operator_console",
        "timestamp": recent_ts,
    })

    repo.recover_incomplete_directives_sync(now=now_dt)
    audits = repo.query_directive_audits_sync("nofab")
    cancelled = [a for a in audits if a["event_type"] == "CANCELLED"][0]

    # Feedback fields must all be None (no fabrication of hardware movement)
    assert cancelled["measured_gate_angle"] is None
    assert cancelled["measured_gate_state"] is None
    assert cancelled["execution_divergence_deg"] is None
    assert cancelled["device_sequence_number"] is None
    assert cancelled["device_uptime_ms"] is None

    # Audit reason must state backend cancelled pending verification after restart
    assert "Backend restarted while physical directive was pending verification" in cancelled["reason"]
    # Must NOT claim servo stopped or gate reached physical position
    assert "servo stopped" not in cancelled["reason"].lower()
    assert "gate reached" not in cancelled["reason"].lower()
    assert "hardware executed" not in cancelled["reason"].lower()
