"""
Tier 2 Live Disposable PostgreSQL 18 Validation for Migration 008.

SAFETY INVARIANT:
  Reads ONLY DRAINX_TEST_POSTGRES_DSN (never DATABASE_URL) so live Supabase
  can never be contacted implicitly. Skips cleanly when unset.
"""

import importlib.util
import json
import os
import re
import urllib.parse
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch
import uuid
import httpx
import pytest

from tests.postgres_test_guard import resolve_test_postgres_dsn, validate_disposable_postgres_dsn

TEST_POSTGRES_DSN = resolve_test_postgres_dsn()
_HAS_PSYCOPG3 = importlib.util.find_spec("psycopg") is not None

if _HAS_PSYCOPG3:
    import psycopg

    PG_ERROR = psycopg.Error
else:
    PG_ERROR = RuntimeError

pytestmark = pytest.mark.skipif(
    not TEST_POSTGRES_DSN or not _HAS_PSYCOPG3,
    reason="Disposable local PostgreSQL validation requires DRAINX_TEST_POSTGRES_DSN and psycopg installed.",
)


def _open_conn():
    dsn = validate_disposable_postgres_dsn(TEST_POSTGRES_DSN)
    if not dsn:
        raise RuntimeError("DRAINX_TEST_POSTGRES_DSN is not configured.")
    return psycopg.connect(dsn, autocommit=False)


def _sqlstate(exc: BaseException) -> str | None:
    return getattr(exc, "sqlstate", None) or getattr(exc, "pgcode", None)


def _insert_audit_row(
    cur,
    *,
    audit_id: str | None = None,
    directive_id: str | None = None,
    event_type: str = "ISSUED",
    device_id: str | None = "DRAINX-ESP32-NODE-01",
    section_id: str = "SEC_SCREENING_01",
    operational_mode: str = "PHYSICAL",
    action: str = "DIVERT_FLOW",
    gate_target_angle: float = 90.0,
    measured_gate_angle: float | None = None,
    measured_gate_state: str | None = None,
    execution_divergence_deg: float | None = None,
    device_session_epoch: int | None = 1,
    baseline_seq: int | None = 10,
    device_seq: int | None = None,
    uptime_ms: int | None = None,
) -> tuple[str, str]:
    d_id = directive_id or f"dir_{uuid.uuid4().hex[:24]}"
    a_id = audit_id or f"aud_{d_id}_ISS"
    cur.execute(
        """
        INSERT INTO public.actuator_directive_audits (
            audit_id, directive_id, event_type, device_id, section_id,
            operational_mode, action, gate_target_angle, reason, risk_level,
            emergency_stop, measured_gate_angle, measured_gate_state,
            execution_divergence_deg, issuer_type, issuer_id,
            device_session_epoch, baseline_device_sequence_number,
            device_sequence_number, device_uptime_ms
        ) VALUES (
            %s, %s, %s, %s, %s,
            %s, %s, %s, %s, 'HIGH',
            false, %s, %s,
            %s, 'AUTOMATED_ENGINE', 'engine-01',
            %s, %s, %s, %s
        )
        """,
        (
            a_id, d_id, event_type, device_id, section_id,
            operational_mode, action, gate_target_angle, "Batch 1.1 PG verification",
            measured_gate_angle, measured_gate_state,
            execution_divergence_deg,
            device_session_epoch, baseline_seq, device_seq, uptime_ms,
        ),
    )
    return a_id, d_id


def test_pg_migration_008_fk_reconciliation_and_on_delete_restrict():
    conn = _open_conn()
    try:
        with conn.cursor() as cur:
            _, d_sec01 = _insert_audit_row(cur, section_id="SEC_SCREENING_01", operational_mode="PHYSICAL")
            _insert_audit_row(cur, section_id="SEC_SCREENING", device_id=None, operational_mode="SIMULATION")

            cur.execute(
                """
                INSERT INTO public.devices (device_id, name)
                VALUES ('DRAINX-ESP32-NODE-02', 'Secondary Node')
                ON CONFLICT (device_id) DO NOTHING
                """
            )

            cur.execute("SAVEPOINT sp_bad_sec")
            with pytest.raises(PG_ERROR) as exc_sec:
                _insert_audit_row(cur, section_id="SEC_DOES_NOT_EXIST")
            assert _sqlstate(exc_sec.value) == "23503"
            cur.execute("ROLLBACK TO SAVEPOINT sp_bad_sec")

            cur.execute("SAVEPOINT sp_bad_dev")
            with pytest.raises(PG_ERROR) as exc_dev:
                _insert_audit_row(cur, device_id="DRAINX-UNKNOWN-99")
            assert _sqlstate(exc_dev.value) == "23503"
            cur.execute("ROLLBACK TO SAVEPOINT sp_bad_dev")

            cur.execute("SAVEPOINT sp_del_dev")
            with pytest.raises(PG_ERROR) as exc_del_dev:
                cur.execute("DELETE FROM public.devices WHERE device_id = 'DRAINX-ESP32-NODE-01'")
            assert _sqlstate(exc_del_dev.value) == "23503"
            cur.execute("ROLLBACK TO SAVEPOINT sp_del_dev")

            cur.execute("SAVEPOINT sp_del_sec")
            with pytest.raises(PG_ERROR) as exc_del_sec:
                cur.execute("DELETE FROM public.drainage_sections WHERE section_id = 'SEC_SCREENING_01'")
            assert _sqlstate(exc_del_sec.value) == "23503"
            cur.execute("ROLLBACK TO SAVEPOINT sp_del_sec")

            assert d_sec01.startswith("dir_")
    finally:
        conn.rollback()
        conn.close()


def test_pg_migration_008_check_constraints_and_role_append_only_enforcement():
    conn = _open_conn()
    try:
        with conn.cursor() as cur:
            long_53_audit_id = "aud_" + ("a" * 32) + "_" + ("b" * 16)
            assert len(long_53_audit_id) == 53
            a_id, d_id = _insert_audit_row(
                cur,
                audit_id=long_53_audit_id,
                event_type="FEEDBACK_RECEIVED",
                measured_gate_angle=45.0,
                measured_gate_state="OPEN",
                execution_divergence_deg=2.5,
                device_seq=12,
                uptime_ms=14000,
            )
            _insert_audit_row(
                cur,
                audit_id=f"aud_{d_id}_REJ_ep1_s13",
                directive_id=d_id,
                event_type="REJECTED",
            )

            bad_cases = [
                {"event_type": "STAGED_DELIVERY"},
                {"operational_mode": "HARDWARE"},
                {"measured_gate_state": "THROTTLED"},
                {"gate_target_angle": 95.0},
                {"measured_gate_angle": -1.0},
                {"execution_divergence_deg": 91.0},
                {"device_session_epoch": -1},
                {"baseline_seq": 4294967296},
                {"device_seq": -1},
                {"uptime_ms": 4294967296},
                {"audit_id": "   "},
                {"action": "   "},
            ]
            for idx, kwargs in enumerate(bad_cases):
                cur.execute(f"SAVEPOINT sp_chk_{idx}")
                with pytest.raises(PG_ERROR) as exc_chk:
                    _insert_audit_row(cur, **kwargs)
                assert _sqlstate(exc_chk.value) == "23514", kwargs
                cur.execute(f"ROLLBACK TO SAVEPOINT sp_chk_{idx}")

            # 1. Owner/superuser role blocked by append-only triggers (42501)
            for idx, sql_stmt in enumerate([
                ("UPDATE public.actuator_directive_audits SET reason = 'tampered' WHERE audit_id = %s", (a_id,)),
                ("DELETE FROM public.actuator_directive_audits WHERE audit_id = %s", (a_id,)),
                ("TRUNCATE TABLE public.actuator_directive_audits", None),
            ]):
                cur.execute(f"SAVEPOINT sp_owner_mut_{idx}")
                with pytest.raises(PG_ERROR) as exc_mut:
                    if sql_stmt[1] is not None:
                        cur.execute(sql_stmt[0], sql_stmt[1])
                    else:
                        cur.execute(sql_stmt[0])
                assert _sqlstate(exc_mut.value) == "42501"
                assert "append-only" in str(exc_mut.value).lower()
                cur.execute(f"ROLLBACK TO SAVEPOINT sp_owner_mut_{idx}")

            # 2. service_role blocked at privilege layer AND even if grants were widened, triggers still block
            for idx, sql_stmt in enumerate([
                ("UPDATE public.actuator_directive_audits SET reason = 'sr' WHERE audit_id = %s", (a_id,)),
                ("DELETE FROM public.actuator_directive_audits WHERE audit_id = %s", (a_id,)),
                ("TRUNCATE TABLE public.actuator_directive_audits", None),
            ]):
                cur.execute(f"SAVEPOINT sp_sr_priv_{idx}")
                cur.execute("SET LOCAL ROLE service_role")
                with pytest.raises(PG_ERROR) as exc_sr:
                    if sql_stmt[1] is not None:
                        cur.execute(sql_stmt[0], sql_stmt[1])
                    else:
                        cur.execute(sql_stmt[0])
                assert _sqlstate(exc_sr.value) == "42501"
                cur.execute(f"ROLLBACK TO SAVEPOINT sp_sr_priv_{idx}")
                cur.execute("RESET ROLE")

                # Prove trigger defense-in-depth under service_role independently of table GRANTs
                cur.execute(f"SAVEPOINT sp_sr_trg_{idx}")
                cur.execute("GRANT UPDATE, DELETE, TRUNCATE ON TABLE public.actuator_directive_audits TO service_role")
                cur.execute("SET LOCAL ROLE service_role")
                with pytest.raises(PG_ERROR) as exc_sr_trg:
                    if sql_stmt[1] is not None:
                        cur.execute(sql_stmt[0], sql_stmt[1])
                    else:
                        cur.execute(sql_stmt[0])
                assert _sqlstate(exc_sr_trg.value) == "42501"
                assert "append-only" in str(exc_sr_trg.value).lower()
                cur.execute(f"ROLLBACK TO SAVEPOINT sp_sr_trg_{idx}")
                cur.execute("RESET ROLE")

            # 3. authenticated & anon roles blocked from INSERT, UPDATE, DELETE, TRUNCATE
            for role_name in ("authenticated", "anon"):
                for idx, sql_stmt in enumerate([
                    ("UPDATE public.actuator_directive_audits SET reason = 'auth'", None),
                    ("DELETE FROM public.actuator_directive_audits", None),
                    ("TRUNCATE TABLE public.actuator_directive_audits", None),
                ]):
                    cur.execute(f"SAVEPOINT sp_{role_name}_{idx}")
                    cur.execute(f"SET LOCAL ROLE {role_name}")
                    with pytest.raises(PG_ERROR) as exc_r:
                        cur.execute(sql_stmt[0])
                    assert _sqlstate(exc_r.value) == "42501"
                    cur.execute(f"ROLLBACK TO SAVEPOINT sp_{role_name}_{idx}")
                    cur.execute("RESET ROLE")

                cur.execute(f"SAVEPOINT sp_{role_name}_ins")
                cur.execute(f"SET LOCAL ROLE {role_name}")
                with pytest.raises(PG_ERROR) as exc_ins:
                    _insert_audit_row(cur, audit_id=f"aud_forbid_{role_name}")
                assert _sqlstate(exc_ins.value) == "42501"
                cur.execute(f"ROLLBACK TO SAVEPOINT sp_{role_name}_ins")
                cur.execute("RESET ROLE")
    finally:
        conn.rollback()
        conn.close()


def test_pg_migration_008_reapplication_idempotency():
    mig_path = (
        Path(__file__).resolve().parent.parent.parent
        / "database"
        / "migrations"
        / "008_actuator_directive_audits.sql"
    )
    sql = mig_path.read_text(encoding="utf-8")
    conn = _open_conn()
    try:
        with conn.cursor() as cur:
            # Strip outer BEGIN;/COMMIT; since psycopg manages the test transaction
            lines = [
                ln for ln in sql.splitlines()
                if ln.strip().upper() not in ("BEGIN;", "COMMIT;")
            ]
            cur.execute("\n".join(lines))
            cur.execute("SELECT COUNT(*) FROM public.drainage_sections WHERE section_id = 'SEC_SCREENING_01'")
            assert cur.fetchone()[0] == 1
    finally:
        conn.rollback()
        conn.close()


def test_pg_migration_008_privileges_and_full_rls_matrix():
    conn = _open_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    has_table_privilege('anon', 'public.actuator_directive_audits', 'SELECT'),
                    has_table_privilege('anon', 'public.actuator_directive_audits', 'INSERT'),
                    has_table_privilege('authenticated', 'public.actuator_directive_audits', 'SELECT'),
                    has_table_privilege('authenticated', 'public.actuator_directive_audits', 'INSERT'),
                    has_table_privilege('authenticated', 'public.actuator_directive_audits', 'UPDATE'),
                    has_table_privilege('authenticated', 'public.actuator_directive_audits', 'DELETE'),
                    has_table_privilege('service_role', 'public.actuator_directive_audits', 'SELECT'),
                    has_table_privilege('service_role', 'public.actuator_directive_audits', 'INSERT'),
                    has_table_privilege('service_role', 'public.actuator_directive_audits', 'UPDATE'),
                    has_table_privilege('service_role', 'public.actuator_directive_audits', 'DELETE'),
                    has_table_privilege('service_role', 'public.actuator_directive_audits', 'TRUNCATE'),
                    has_function_privilege('anon', 'public.prevent_directive_audit_mutation_or_deletion()', 'EXECUTE'),
                    has_function_privilege('authenticated', 'public.prevent_directive_audit_mutation_or_deletion()', 'EXECUTE'),
                    has_function_privilege('service_role', 'public.prevent_directive_audit_mutation_or_deletion()', 'EXECUTE'),
                    has_function_privilege('anon', 'public.prevent_directive_audit_truncate()', 'EXECUTE'),
                    has_function_privilege('authenticated', 'public.prevent_directive_audit_truncate()', 'EXECUTE'),
                    has_function_privilege('service_role', 'public.prevent_directive_audit_truncate()', 'EXECUTE')
                """
            )
            assert cur.fetchone() == (
                False, False,
                True, False, False, False,
                True, True, False, False, False,
                False, False, False,
                False, False, False,
            )

            cur.execute(
                """
                INSERT INTO public.devices (device_id, name)
                VALUES ('DRAINX-ESP32-NODE-02', 'Node 02')
                ON CONFLICT (device_id) DO NOTHING
                """
            )
            cur.execute("SET LOCAL ROLE service_role")
            _insert_audit_row(
                cur,
                audit_id="aud_rls_phys_node1_sec1",
                directive_id="dir_rls_1",
                device_id="DRAINX-ESP32-NODE-01",
                section_id="SEC_SCREENING_01",
                operational_mode="PHYSICAL",
            )
            _insert_audit_row(
                cur,
                audit_id="aud_rls_phys_node2_sec2",
                directive_id="dir_rls_2",
                device_id="DRAINX-ESP32-NODE-02",
                section_id="SEC_OUTLET",
                operational_mode="PHYSICAL",
            )
            _insert_audit_row(
                cur,
                audit_id="aud_rls_sim_sec1",
                directive_id="dir_rls_3",
                device_id=None,
                section_id="SEC_SCREENING_01",
                operational_mode="SIMULATION",
            )
            _insert_audit_row(
                cur,
                audit_id="aud_rls_hold_node1_sec1",
                directive_id="dir_rls_4",
                device_id="DRAINX-ESP32-NODE-01",
                section_id="SEC_SCREENING_01",
                operational_mode="SAFE_HOLD",
            )
            _insert_audit_row(
                cur,
                audit_id="aud_rls_phys_node1_sec2",
                directive_id="dir_rls_5",
                device_id="DRAINX-ESP32-NODE-01",
                section_id="SEC_OUTLET",
                operational_mode="PHYSICAL",
            )
            _insert_audit_row(
                cur,
                audit_id="aud_rls_phys_nulldev_sec1",
                directive_id="dir_rls_6",
                device_id=None,
                section_id="SEC_SCREENING_01",
                operational_mode="PHYSICAL",
            )

            # service_role sees all 6 seeded rows
            cur.execute("SELECT audit_id FROM public.actuator_directive_audits WHERE audit_id LIKE 'aud_rls_%'")
            all_ids = {r[0] for r in cur.fetchall()}
            assert all_ids == {
                "aud_rls_phys_node1_sec1",
                "aud_rls_phys_node2_sec2",
                "aud_rls_sim_sec1",
                "aud_rls_hold_node1_sec1",
                "aud_rls_phys_node1_sec2",
                "aud_rls_phys_nulldev_sec1",
            }
            cur.execute("RESET ROLE")

            def _query_as(role_name: str, jwt_claims: dict) -> set[str]:
                cur.execute(f"SET LOCAL ROLE {role_name}")
                cur.execute("SELECT set_config('request.jwt.claims', %s, true)", (json.dumps(jwt_claims),))
                cur.execute(
                    "SELECT audit_id FROM public.actuator_directive_audits WHERE audit_id LIKE 'aud_rls_%'"
                )
                rows = {r[0] for r in cur.fetchall()}
                cur.execute("RESET ROLE")
                return rows

            # anon denied
            cur.execute("SAVEPOINT sp_anon")
            with pytest.raises(PG_ERROR) as exc_anon:
                cur.execute("SET LOCAL ROLE anon")
                cur.execute("SELECT 1 FROM public.actuator_directive_audits LIMIT 1")
            assert _sqlstate(exc_anon.value) == "42501"
            cur.execute("ROLLBACK TO SAVEPOINT sp_anon")
            cur.execute("RESET ROLE")

            # missing app_metadata, citizen, user_metadata spoof -> 0 rows
            assert _query_as("authenticated", {}) == set()
            assert _query_as("authenticated", {"app_metadata": {"role": "citizen"}}) == set()
            assert _query_as(
                "authenticated",
                {"app_metadata": {"role": "citizen"}, "user_metadata": {"role": "admin"}},
            ) == set()

            # admin & unscoped municipality -> all 6 rows
            assert _query_as("authenticated", {"app_metadata": {"role": "admin"}}) == all_ids
            assert _query_as("authenticated", {"app_metadata": {"role": "municipality"}}) == all_ids

            # Restricted municipality: section-only, device-only, dual
            assert _query_as(
                "authenticated",
                {"app_metadata": {"role": "municipality", "assigned_sections": ["SEC_SCREENING_01"]}},
            ) == {"aud_rls_phys_node1_sec1", "aud_rls_sim_sec1", "aud_rls_hold_node1_sec1", "aud_rls_phys_nulldev_sec1"}

            assert _query_as(
                "authenticated",
                {"app_metadata": {"role": "municipality", "assigned_devices": ["DRAINX-ESP32-NODE-01"]}},
            ) == {"aud_rls_phys_node1_sec1", "aud_rls_hold_node1_sec1", "aud_rls_phys_node1_sec2"}

            assert _query_as(
                "authenticated",
                {
                    "app_metadata": {
                        "role": "municipality",
                        "assigned_devices": ["DRAINX-ESP32-NODE-01"],
                        "assigned_sections": ["SEC_OUTLET"],
                    }
                },
            ) == {"aud_rls_phys_node1_sec2"}

            # Restricted municipality: singular keys, empty, malformed, conflicting -> MUST fail closed (0 rows)
            for bad_muni in (
                {"role": "municipality", "assigned_section": "SEC_SCREENING_01"},
                {"role": "municipality", "section_id": "SEC_SCREENING_01"},
                {"role": "municipality", "assigned_device": "DRAINX-ESP32-NODE-01"},
                {"role": "municipality", "assigned_sections": []},
                {"role": "municipality", "assigned_sections": "SEC_SCREENING_01"},
                {"role": "municipality", "assigned_sections": ["SEC_SCREENING_01", 123]},
                {"role": "municipality", "assigned_sections": [" SEC_SCREENING_01 "]},
                {"role": "municipality", "assigned_devices": ["DRAINX-ESP32-NODE-01"], "allowed_devices": ["DRAINX-ESP32-NODE-02"]},
            ):
                assert _query_as("authenticated", {"app_metadata": bad_muni}) == set(), bad_muni

            # Worker positive matrix
            assert _query_as(
                "authenticated",
                {"app_metadata": {"role": "worker", "assigned_devices": ["DRAINX-ESP32-NODE-01"]}},
            ) == {"aud_rls_phys_node1_sec1", "aud_rls_phys_node1_sec2"}

            assert _query_as(
                "authenticated",
                {"app_metadata": {"role": "worker", "allowed_sections": ["SEC_SCREENING_01"]}},
            ) == {"aud_rls_phys_node1_sec1", "aud_rls_phys_nulldev_sec1"}

            assert _query_as(
                "authenticated",
                {
                    "app_metadata": {
                        "role": "worker",
                        "assigned_devices": ["DRAINX-ESP32-NODE-01"],
                        "assigned_sections": ["SEC_OUTLET"],
                    }
                },
            ) == {"aud_rls_phys_node1_sec2"}

            # Overlapping aliases intersect accurately
            assert _query_as(
                "authenticated",
                {
                    "app_metadata": {
                        "role": "worker",
                        "assigned_devices": ["DRAINX-ESP32-NODE-01", "DRAINX-ESP32-NODE-02"],
                        "allowed_devices": ["DRAINX-ESP32-NODE-02"],
                    }
                },
            ) == {"aud_rls_phys_node2_sec2"}

            # Worker fail-closed negative matrix (unassigned, user_metadata spoof, empty, malformed, conflicting, singular)
            for bad_wrk in (
                {"role": "worker"},
                {"role": "worker", "assigned_devices": []},
                {"role": "worker", "assigned_devices": [], "assigned_sections": ["SEC_SCREENING_01"]},
                {"role": "worker", "assigned_devices": "DRAINX-ESP32-NODE-01"},
                {"role": "worker", "assigned_devices": [123]},
                {"role": "worker", "assigned_devices": ["DRAINX-ESP32-NODE-01", ""]},
                {"role": "worker", "assigned_devices": [" DRAINX-ESP32-NODE-01 "]},
                {"role": "worker", "assigned_devices": ["DRAINX-ESP32-NODE-01"], "allowed_devices": ["DRAINX-ESP32-NODE-02"]},
                {"role": "worker", "assigned_device": "DRAINX-ESP32-NODE-01"},
                {"role": "worker", "section_id": "SEC_SCREENING_01"},
            ):
                assert _query_as(
                    "authenticated",
                    {"app_metadata": bad_wrk, "user_metadata": {"assigned_devices": ["DRAINX-ESP32-NODE-01"]}},
                ) == set(), bad_wrk
    finally:
        conn.rollback()
        conn.close()


def test_pg_migration_008_persistence_repository_serialization_and_idempotency():
    """
    Executes real PersistenceRepository 23-column serialization, batch insert,
    duplicate verification, conflict detection, and chronological query against
    live PostgreSQL 18.7 Migration 008 table as `service_role`.
    """
    from app.models.contracts import (
        ActuatorDirectiveEventContract,
        AlertSeverity,
        DIRECTIVE_AUDIT_DB_COLUMNS,
        DirectiveEventType,
        DirectiveIssuerType,
        build_alignment_observed_audit_id,
        build_execution_failed_audit_id,
        build_feedback_received_audit_id,
        build_issued_audit_id,
        build_reboot_cancellation_audit_id,
        build_rejected_audit_id,
        build_safe_hold_cancellation_audit_id,
        build_startup_cancellation_audit_id,
        build_superseded_audit_id,
        build_verification_timeout_audit_id,
    )
    from app.services.persistence_repository import (
        DirectiveAuditConflictError,
        PersistenceRepository,
        serialize_directive_audit_row,
    )

    def _to_json_cell(v):
        if isinstance(v, Decimal):
            return float(v)
        if isinstance(v, datetime):
            return v.isoformat()
        return v

    conn = _open_conn()
    try:
        get_calls: list = []

        def _parse_filter(expr: str):
            if expr.startswith("eq."):
                items = [expr[3:]]
            elif expr.startswith("in.(") and expr.endswith(")"):
                items, cur, in_q, esc = [], "", False, False
                for ch in expr[4:-1]:
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
                raise AssertionError(f"Unsupported filter {expr}")
            return [i[1:-1] if len(i) >= 2 and i.startswith('"') and i.endswith('"') else i for i in items]

        class _LivePGPostgRESTBridge:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def post(self, endpoint: str, json=None, headers=None):
                assert endpoint.endswith("/rest/v1/actuator_directive_audits")
                assert headers["Authorization"] == "Bearer pg18-service-role"
                inserted_rows = []
                with conn.cursor() as cur:
                    cur.execute("SET LOCAL ROLE service_role")
                    for payload_row in json:
                        cols = list(payload_row.keys())
                        assert tuple(cols) == DIRECTIVE_AUDIT_DB_COLUMNS
                        placeholders = ", ".join(["%s"] * len(cols))
                        col_sql = ", ".join(cols)
                        cur.execute(
                            f"""
                            INSERT INTO public.actuator_directive_audits ({col_sql})
                            VALUES ({placeholders})
                            ON CONFLICT (audit_id) DO NOTHING
                            RETURNING {", ".join(DIRECTIVE_AUDIT_DB_COLUMNS)}
                            """,
                            [payload_row[c] for c in cols],
                        )
                        rec = cur.fetchone()
                        if rec is not None:
                            inserted_rows.append(
                                {c: _to_json_cell(val) for c, val in zip(DIRECTIVE_AUDIT_DB_COLUMNS, rec)}
                            )
                    cur.execute("RESET ROLE")
                return httpx.Response(201, json=inserted_rows)

            def get(self, endpoint: str, params=None, headers=None):
                assert endpoint.endswith("/rest/v1/actuator_directive_audits")
                assert headers["Authorization"] == "Bearer pg18-service-role"
                p = dict(params or {})
                get_calls.append(dict(p))
                where_clauses = []
                sql_args = []
                for key, expr in p.items():
                    if key in ("select", "order", "limit"):
                        continue
                    values = _parse_filter(expr)
                    if expr.startswith("eq."):
                        where_clauses.append(f"{key} = %s")
                        sql_args.append(values[0])
                    elif expr.startswith("in.("):
                        where_clauses.append(f"{key} = ANY(%s)")
                        sql_args.append(values)
                where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
                order_sql = " ORDER BY timestamp DESC, audit_id DESC" if p.get("order") == "timestamp.desc,audit_id.desc" else ""
                limit_sql = f" LIMIT {int(p['limit'])}" if "limit" in p else ""
                with conn.cursor() as cur:
                    cur.execute("SET LOCAL ROLE service_role")
                    cur.execute(
                        f"SELECT {', '.join(DIRECTIVE_AUDIT_DB_COLUMNS)} FROM public.actuator_directive_audits{where_sql}{order_sql}{limit_sql}",
                        sql_args,
                    )
                    fetched = [
                        {c: _to_json_cell(val) for c, val in zip(DIRECTIVE_AUDIT_DB_COLUMNS, r)}
                        for r in cur.fetchall()
                    ]
                    cur.execute("RESET ROLE")
                return httpx.Response(200, json=fetched)

        repo = PersistenceRepository(
            supabase_url="https://pg18-local.test",
            supabase_key="",
            service_role_key="pg18-service-role",
        )

        dir_prefix = f"pg2a_{uuid.uuid4().hex[:10]}"
        d1 = f"{dir_prefix}_1"
        d2 = f"{dir_prefix}_2"
        d3 = f"{dir_prefix}_3"
        events = [
            ActuatorDirectiveEventContract(
                audit_id=build_issued_audit_id(d1),
                directive_id=d1,
                event_type=DirectiveEventType.ISSUED,
                device_id="DRAINX-ESP32-NODE-01",
                section_id="SEC_SCREENING_01",
                operational_mode="PHYSICAL",
                action="DIVERT_FLOW",
                gate_target_angle=45.0,
                reason="Initial issuance",
                risk_level=AlertSeverity.HIGH,
                issuer_type=DirectiveIssuerType.AUTOMATED_ENGINE,
                issuer_id="intervention_engine",
                device_session_epoch=1,
                baseline_device_sequence_number=10,
                timestamp="2026-11-23T12:00:01+00:00",
            ),
            ActuatorDirectiveEventContract(
                audit_id=build_feedback_received_audit_id(d1, 1, 11),
                directive_id=d1,
                event_type=DirectiveEventType.FEEDBACK_RECEIVED,
                device_id="DRAINX-ESP32-NODE-01",
                section_id="SEC_SCREENING_01",
                operational_mode="PHYSICAL",
                action="DIVERT_FLOW",
                gate_target_angle=45.0,
                reason="Actuator moving",
                risk_level=AlertSeverity.HIGH,
                measured_gate_angle=22.5,
                measured_gate_state="CLOSED",
                execution_divergence_deg=22.5,
                issuer_type=DirectiveIssuerType.AUTOMATED_ENGINE,
                issuer_id="intervention_engine",
                device_session_epoch=1,
                baseline_device_sequence_number=10,
                device_sequence_number=11,
                device_uptime_ms=11000,
                timestamp="2026-11-23T12:00:02+00:00",
            ),
            ActuatorDirectiveEventContract(
                audit_id=build_alignment_observed_audit_id(d1, 1, 12),
                directive_id=d1,
                event_type=DirectiveEventType.ALIGNMENT_OBSERVED,
                device_id="DRAINX-ESP32-NODE-01",
                section_id="SEC_SCREENING_01",
                operational_mode="PHYSICAL",
                action="DIVERT_FLOW",
                gate_target_angle=45.0,
                reason="Observed physical alignment",
                risk_level=AlertSeverity.HIGH,
                measured_gate_angle=45.5,
                measured_gate_state="CLOSED",
                execution_divergence_deg=0.5,
                issuer_type=DirectiveIssuerType.AUTOMATED_ENGINE,
                issuer_id="intervention_engine",
                device_session_epoch=1,
                baseline_device_sequence_number=10,
                device_sequence_number=12,
                device_uptime_ms=12000,
                timestamp="2026-11-23T12:00:03+00:00",
            ),
            ActuatorDirectiveEventContract(
                audit_id=build_rejected_audit_id(d2, 1, 13),
                directive_id=d2,
                event_type=DirectiveEventType.REJECTED,
                device_id="DRAINX-ESP32-NODE-01",
                section_id="SEC_SCREENING_01",
                operational_mode="PHYSICAL",
                action="DIVERT_FLOW",
                gate_target_angle=90.0,
                reason="Firmware SAFE_HOLD interlock rejected setpoint",
                risk_level=AlertSeverity.CRITICAL,
                measured_gate_angle=0.0,
                measured_gate_state="SAFE_HOLD",
                execution_divergence_deg=90.0,
                issuer_type=DirectiveIssuerType.SAFETY_INTERLOCK,
                issuer_id="safety_interlock",
                device_session_epoch=1,
                baseline_device_sequence_number=12,
                device_sequence_number=13,
                device_uptime_ms=13000,
                timestamp="2026-11-23T12:00:04+00:00",
            ),
            ActuatorDirectiveEventContract(
                audit_id=build_execution_failed_audit_id(d3, 1, 14),
                directive_id=d3,
                event_type=DirectiveEventType.EXECUTION_FAILED,
                device_id="DRAINX-ESP32-NODE-01",
                section_id="SEC_SCREENING_01",
                operational_mode="PHYSICAL",
                action="DIVERT_FLOW",
                gate_target_angle=90.0,
                reason="Settling timeout divergence",
                measured_gate_angle=5.0,
                measured_gate_state="CLOSED",
                execution_divergence_deg=85.0,
                issuer_type=DirectiveIssuerType.AUTOMATED_ENGINE,
                issuer_id="intervention_engine",
                device_session_epoch=1,
                baseline_device_sequence_number=13,
                device_sequence_number=14,
                device_uptime_ms=14000,
                timestamp="2026-11-23T12:00:05+00:00",
            ),
            ActuatorDirectiveEventContract(
                audit_id=build_verification_timeout_audit_id(f"{dir_prefix}_t"),
                directive_id=f"{dir_prefix}_t",
                event_type=DirectiveEventType.VERIFICATION_TIMEOUT,
                device_id=None,
                section_id="SEC_SCREENING",
                operational_mode="SIMULATION",
                action="DIVERT_FLOW",
                gate_target_angle=90.0,
                reason="Verification timeout after 30s",
                issuer_id="timeout_sweeper",
                timestamp="2026-11-23T12:00:06+00:00",
            ),
            ActuatorDirectiveEventContract(
                audit_id=build_superseded_audit_id(f"{dir_prefix}_s1", f"{dir_prefix}_s2"),
                directive_id=f"{dir_prefix}_s1",
                event_type=DirectiveEventType.SUPERSEDED,
                device_id="DRAINX-ESP32-NODE-01",
                section_id="SEC_SCREENING_01",
                operational_mode="PHYSICAL",
                action="MAINTAIN_NORMAL",
                gate_target_angle=0.0,
                reason="Superseded by newer directive",
                issuer_id="intervention_engine",
                timestamp="2026-11-23T12:00:07+00:00",
            ),
            ActuatorDirectiveEventContract(
                audit_id=build_startup_cancellation_audit_id(f"{dir_prefix}_c1"),
                directive_id=f"{dir_prefix}_c1",
                event_type=DirectiveEventType.CANCELLED,
                device_id="DRAINX-ESP32-NODE-01",
                section_id="SEC_SCREENING_01",
                operational_mode="PHYSICAL",
                action="DIVERT_FLOW",
                gate_target_angle=90.0,
                reason="Cancelled on backend startup",
                issuer_type=DirectiveIssuerType.SAFETY_INTERLOCK,
                issuer_id="startup_recovery",
                timestamp="2026-11-23T12:00:08+00:00",
            ),
            ActuatorDirectiveEventContract(
                audit_id=build_safe_hold_cancellation_audit_id(f"{dir_prefix}_c2"),
                directive_id=f"{dir_prefix}_c2",
                event_type=DirectiveEventType.CANCELLED,
                device_id="DRAINX-ESP32-NODE-01",
                section_id="SEC_SCREENING_01",
                operational_mode="PHYSICAL",
                action="DIVERT_FLOW",
                gate_target_angle=90.0,
                reason="Cancelled by SAFE_HOLD transition",
                emergency_stop=True,
                issuer_type=DirectiveIssuerType.OPERATOR,
                issuer_id="mode_transition",
                timestamp="2026-11-23T12:00:09+00:00",
            ),
            ActuatorDirectiveEventContract(
                audit_id=build_reboot_cancellation_audit_id(f"{dir_prefix}_c3", 2),
                directive_id=f"{dir_prefix}_c3",
                event_type=DirectiveEventType.CANCELLED,
                device_id="DRAINX-ESP32-NODE-01",
                section_id="SEC_SCREENING_01",
                operational_mode="PHYSICAL",
                action="DIVERT_FLOW",
                gate_target_angle=45.0,
                reason="Cancelled by confirmed device reboot",
                issuer_type=DirectiveIssuerType.SAFETY_INTERLOCK,
                issuer_id="reboot_detector",
                device_session_epoch=2,
                timestamp="2026-11-23T12:00:10+00:00",
            ),
        ]

        with patch("app.services.persistence_repository.httpx.Client", _LivePGPostgRESTBridge):
            assert repo.persist_directive_audit_batch_sync(events, strict=True) is True

            def _variant(event, **updates):
                """Validated copy (never model_copy(update=...), which bypasses validation)."""
                return ActuatorDirectiveEventContract(**{**event.model_dump(), **updates})

            # Exact duplicate re-submission with equivalent instant (+05:30) succeeds idempotently
            dup_event = _variant(
                events[0],
                timestamp=datetime(2026, 11, 23, 17, 30, 1, tzinfo=timezone(timedelta(hours=5, minutes=30))),
            )
            assert repo.persist_directive_audit_sync(dup_event, strict=True) is True

            # Differing timestamp with same audit_id MUST raise DirectiveAuditConflictError
            diff_ts_event = _variant(events[0], timestamp=datetime(2026, 11, 23, 12, 9, 0, tzinfo=timezone.utc))
            with pytest.raises(DirectiveAuditConflictError, match="timestamp"):
                repo.persist_directive_audit_sync(diff_ts_event, strict=True)

            # Microsecond-level timestamp mismatch also conflicts
            us_event = _variant(events[0], timestamp="2026-11-23T12:00:01.000001+00:00")
            with pytest.raises(DirectiveAuditConflictError, match="timestamp"):
                repo.persist_directive_audit_sync(us_event, strict=True)

            # Conflicting duplicate with same audit_id raises DirectiveAuditConflictError without mutation
            conflict_event = _variant(events[0], gate_target_angle=90.0)
            with pytest.raises(DirectiveAuditConflictError):
                repo.persist_directive_audit_sync(conflict_event, strict=True)

            # Query back via PersistenceRepository in chronological order and verify all 23 stored columns
            d1_rows = repo.query_directive_audits_sync(directive_id=d1, strict=True)
            assert [r["event_type"] for r in d1_rows] == [
                "ISSUED",
                "FEEDBACK_RECEIVED",
                "ALIGNMENT_OBSERVED",
            ]
            for expected_event, actual_row in zip(events[:3], d1_rows):
                assert tuple(actual_row.keys()) == DIRECTIVE_AUDIT_DB_COLUMNS
                assert actual_row["audit_id"] == expected_event.audit_id
                assert actual_row["directive_id"] == expected_event.directive_id
                assert actual_row["event_type"] == expected_event.event_type.value
                assert actual_row["device_id"] == expected_event.device_id
                assert actual_row["section_id"] == expected_event.section_id
                assert actual_row["operational_mode"] == expected_event.operational_mode
                assert actual_row["directive_type"] == expected_event.directive_type
                assert actual_row["action"] == expected_event.action
                assert float(actual_row["gate_target_angle"]) == expected_event.gate_target_angle
                assert actual_row["reason"] == expected_event.reason
                assert actual_row["risk_level"] == expected_event.risk_level.value
                assert actual_row["emergency_stop"] is expected_event.emergency_stop
                assert (
                    None
                    if actual_row["measured_gate_angle"] is None
                    else float(actual_row["measured_gate_angle"])
                ) == expected_event.measured_gate_angle
                assert actual_row["measured_gate_state"] == expected_event.measured_gate_state
                assert (
                    None
                    if actual_row["execution_divergence_deg"] is None
                    else float(actual_row["execution_divergence_deg"])
                ) == expected_event.execution_divergence_deg
                assert actual_row["issuer_type"] == expected_event.issuer_type.value
                assert actual_row["issuer_id"] == expected_event.issuer_id
                assert actual_row["correlation_id"] == expected_event.correlation_id
                assert actual_row["device_session_epoch"] == expected_event.device_session_epoch
                assert actual_row["baseline_device_sequence_number"] == expected_event.baseline_device_sequence_number
                assert actual_row["device_sequence_number"] == expected_event.device_sequence_number
                assert actual_row["device_uptime_ms"] == expected_event.device_uptime_ms
                assert datetime.fromisoformat(actual_row["timestamp"]).astimezone(timezone.utc) == expected_event.timestamp

            # Verify all remaining 7 inserted rows across the 10-event batch exist with all 23 columns
            for remaining_ev in events[3:]:
                fetched = repo.query_directive_audits_sync(directive_id=remaining_ev.directive_id, strict=True)
                assert len(fetched) == 1
                assert tuple(fetched[0].keys()) == DIRECTIVE_AUDIT_DB_COLUMNS
                assert fetched[0]["audit_id"] == remaining_ev.audit_id
                assert fetched[0]["event_type"] == remaining_ev.event_type.value

            # ---- Batch 2A.2: all 23 columns on all 10 rows / all 8 event types ----
            def _num(v):
                return None if v is None else float(v)

            seen_types = set()
            for ev in events:
                rows = [
                    r for r in repo.query_directive_audits_sync(directive_id=ev.directive_id, strict=True)
                    if r["audit_id"] == ev.audit_id
                ]
                assert len(rows) == 1, ev.audit_id
                row = rows[0]
                assert tuple(row.keys()) == DIRECTIVE_AUDIT_DB_COLUMNS
                expected = serialize_directive_audit_row(ev)
                for col in DIRECTIVE_AUDIT_DB_COLUMNS:
                    if col in ("gate_target_angle", "measured_gate_angle", "execution_divergence_deg"):
                        assert _num(row[col]) == _num(expected[col]), (ev.audit_id, col)
                    elif col == "timestamp":
                        assert datetime.fromisoformat(row[col]).astimezone(timezone.utc) == ev.timestamp
                    else:
                        assert row[col] == expected[col], (ev.audit_id, col)
                seen_types.add(ev.event_type)
            assert seen_types == set(DirectiveEventType)

            # ---- Nullable-field conflicts (value -> None and None -> value) ----
            feedback = events[1]
            for field_name, new_value in (
                ("device_id", None),
                ("measured_gate_angle", None),
                ("measured_gate_state", None),
                ("execution_divergence_deg", None),
                ("device_session_epoch", None),
                ("baseline_device_sequence_number", None),
                ("device_sequence_number", None),
                ("device_uptime_ms", None),
                ("correlation_id", "corr-injected"),
            ):
                with pytest.raises(DirectiveAuditConflictError, match=field_name):
                    repo.persist_directive_audit_sync(_variant(feedback, **{field_name: new_value}), strict=True)

            # ---- Mixed batch: new row + conflicting duplicate => no row written (pre-flight verification) ----
            fresh_id = f"{dir_prefix}_fresh"
            fresh = ActuatorDirectiveEventContract(
                audit_id=build_issued_audit_id(fresh_id),
                directive_id=fresh_id,
                event_type=DirectiveEventType.ISSUED,
                device_id="DRAINX-ESP32-NODE-01",
                section_id="SEC_SCREENING_01",
                operational_mode="PHYSICAL",
                action="DIVERT_FLOW",
                gate_target_angle=45.0,
                reason="Fresh row preceding conflicting duplicate",
                issuer_id="intervention_engine",
                timestamp="2026-11-23T12:30:00+00:00",
            )
            with pytest.raises(DirectiveAuditConflictError):
                repo.persist_directive_audit_batch_sync(
                    [fresh, _variant(events[0], gate_target_angle=90.0)], strict=True
                )
            assert repo.query_directive_audits_sync(directive_id=fresh_id, strict=True) == []
            # Retry without the conflicting row persists the new row idempotently
            assert repo.persist_directive_audit_batch_sync([fresh, events[0]], strict=True) is True
            assert len(repo.query_directive_audits_sync(directive_id=fresh_id, strict=True)) == 1

            # ---- Chunked verification across the whole 11-row batch (live SQL ANY() filters) ----
            repo.directive_audit_verify_chunk_size = 3
            get_calls.clear()
            assert repo.persist_directive_audit_batch_sync(list(events) + [fresh], strict=True) is True
            audit_filters = [c["audit_id"] for c in get_calls if "audit_id" in c]
            assert len(audit_filters) == 4  # ceil(11 / 3)
            assert sum(len(_parse_filter(f)) for f in audit_filters) == 11
            assert max(len(_parse_filter(f)) for f in audit_filters) <= 3
    finally:
        conn.rollback()
        conn.close()
