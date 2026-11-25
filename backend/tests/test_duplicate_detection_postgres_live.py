"""
Tier 2 Live PostgreSQL Concurrency & Security Integration Tests (Migration 007).

These tests require a real disposable PostgreSQL 15+ database with Migrations 001-007 applied
and a Python PostgreSQL driver (psycopg v3 or psycopg2) installed.
They are skipped automatically when no live PostgreSQL DSN or driver is configured.
"""

import importlib.util
import json
import os
import re
import threading
import time
import urllib.parse
import uuid

import pytest

_FORBIDDEN_PROD_HOST_SUFFIXES = (
    ".supabase.co",
    ".supabase.com",
    ".supabase.net",
    ".pooler.supabase.com",
)
_FORBIDDEN_PROD_PROJECT_REFS = ("xhdtceqcnsheoskmuwsv",)


def _extract_dsn_host(dsn: str) -> str:
    parsed = urllib.parse.urlparse(dsn)
    if parsed.hostname:
        return parsed.hostname.lower()
    m = re.search(r"(?:^|\s)host\s*=\s*['\"]?([^\s'\"]+)", dsn, re.IGNORECASE)
    return m.group(1).lower() if m else ""


def validate_disposable_postgres_dsn(dsn: str | None) -> str | None:
    """
    Fail-closed validator for live PostgreSQL integration tests.
    Never falls back to DATABASE_URL and rejects production Supabase hosts.
    """
    if not dsn or not dsn.strip():
        return None
    cleaned = dsn.strip()
    host = _extract_dsn_host(cleaned)
    lower_dsn = cleaned.lower()
    if any(host.endswith(suffix) or suffix.lstrip(".") == host for suffix in _FORBIDDEN_PROD_HOST_SUFFIXES):
        raise RuntimeError(
            f"Refusing to run live PostgreSQL test against Supabase host '{host}'. "
            "Use a disposable local PostgreSQL instance via DRAINX_TEST_POSTGRES_DSN."
        )
    if any(ref in lower_dsn for ref in _FORBIDDEN_PROD_PROJECT_REFS):
        raise RuntimeError(
            "Refusing to run live PostgreSQL test against known production project reference. "
            "Use a disposable local PostgreSQL instance via DRAINX_TEST_POSTGRES_DSN."
        )
    if not host:
        raise RuntimeError("Invalid DRAINX_TEST_POSTGRES_DSN: unable to determine target host.")
    return cleaned


def resolve_test_postgres_dsn() -> str | None:
    """Read ONLY DRAINX_TEST_POSTGRES_DSN (never DATABASE_URL)."""
    raw = os.getenv("DRAINX_TEST_POSTGRES_DSN")
    if not raw or not raw.strip():
        return None
    return validate_disposable_postgres_dsn(raw)


POSTGRES_DSN = resolve_test_postgres_dsn()
_HAS_PSYCOPG3 = importlib.util.find_spec("psycopg") is not None
_HAS_PSYCOPG2 = importlib.util.find_spec("psycopg2") is not None
_HAS_PG_DRIVER = _HAS_PSYCOPG3 or _HAS_PSYCOPG2

if _HAS_PSYCOPG3:
    import psycopg

    PG_DB_ERROR = psycopg.DatabaseError
elif _HAS_PSYCOPG2:
    import psycopg2

    PG_DB_ERROR = psycopg2.Error
else:
    PG_DB_ERROR = RuntimeError

pytestmark = pytest.mark.skipif(
    not POSTGRES_DSN or not _HAS_PG_DRIVER,
    reason=(
        "Tier 2 Live PostgreSQL concurrency tests require DRAINX_TEST_POSTGRES_DSN "
        "(never DATABASE_URL) and psycopg or psycopg2 installed."
    ),
)

EXPECTED_RPC_SIGNATURES = (
    "public.citizen_incident_creation_rpc(character varying,character varying,text,double precision,double precision,character varying,character varying,character varying,text[],character varying,character varying)",
    "public.claim_duplicate_scan_jobs_rpc(character varying,character varying,integer,integer)",
    "public.fetch_duplicate_candidates_rpc(character varying,double precision,integer,text[],boolean,boolean,integer)",
    "public.record_duplicate_candidates_rpc(character varying,character varying,jsonb,character varying)",
    "public.release_duplicate_scan_job_rpc(character varying,character varying,character varying,integer,boolean)",
    "public.reset_duplicate_scan_job_rpc(character varying,character varying,character varying,text)",
    "public.review_incident_duplicate_link_rpc(character varying,character varying,character varying,character varying,text,character varying,character varying,character varying,text,boolean,integer)",
)


def _open_pg_connection():
    dsn = validate_disposable_postgres_dsn(POSTGRES_DSN)
    if not dsn:
        raise RuntimeError("DRAINX_TEST_POSTGRES_DSN is not configured.")
    if _HAS_PSYCOPG3:
        import psycopg

        return psycopg.connect(dsn, autocommit=False)
    import psycopg2

    return psycopg2.connect(dsn)


def _extract_sqlstate(exc: BaseException) -> str | None:
    sqlstate = getattr(exc, "sqlstate", None) or getattr(exc, "pgcode", None)
    if not sqlstate and getattr(exc, "diag", None) is not None:
        sqlstate = getattr(exc.diag, "sqlstate", None)
    return str(sqlstate) if sqlstate else None


def _seed_test_incident(conn, inc_id: str, category: str = "FLOODING") -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT public.citizen_incident_creation_rpc(
                %s, %s, %s, %s, %s, %s, %s, %s, %s::text[], %s, %s
            )
            """,
            (
                inc_id,
                category,
                f"Live PG test incident {inc_id}",
                15.4920,
                73.8185,
                "HIGH",
                "CITIZEN",
                "Live PG Tester",
                [],
                f"AUD-{uuid.uuid4().hex[:16]}",
                "SIMULATION",
            ),
        )
    conn.commit()


def _drain_pending_outbox_jobs(conn) -> None:
    """Completes any leftover runnable outbox jobs via sanctioned RPCs so concurrency tests isolate cleanly."""
    with conn.cursor() as cur:
        while True:
            drain_lease = f"dup_lease_{uuid.uuid4().hex}"
            cur.execute("SELECT public.claim_duplicate_scan_jobs_rpc(%s, NULL, 50, 30)", (drain_lease,))
            claimed = cur.fetchone()[0]
            if not claimed:
                break
            for job in claimed:
                cur.execute(
                    "SELECT public.record_duplicate_candidates_rpc(%s, 'SIMULATION', '[]'::jsonb, %s)",
                    (job["incident_id"], drain_lease),
                )
    conn.commit()


def _create_suspected_link(conn, src_id: str, dst_id: str, link_id: str) -> None:
    lease = f"dup_lease_{uuid.uuid4().hex}"
    cand_payload = json.dumps(
        [
            {
                "link_id": link_id,
                "candidate_incident_id": dst_id,
                "distance_meters": 10.0,
                "time_delta_seconds": 5,
                "confidence_score": 0.900,
                "confidence_band": "HIGH",
                "match_reasons": ["CATEGORY_EXACT"],
            }
        ]
    )
    with conn.cursor() as cur:
        cur.execute("SELECT public.reset_duplicate_scan_job_rpc(%s, 'pg-setup', 'admin', 'setup')", (src_id,))
        cur.execute("SELECT public.claim_duplicate_scan_jobs_rpc(%s, %s, 1, 60)", (lease, src_id))
        claimed = cur.fetchone()[0]
        assert len(claimed) == 1
        cur.execute(
            "SELECT public.record_duplicate_candidates_rpc(%s, 'SIMULATION', %s::jsonb, %s)",
            (src_id, cand_payload, lease),
        )
    conn.commit()


class TestDuplicateDetectionPostgresLive:
    def test_migration_007_rls_and_privilege_boundaries(self):
        inc_id = f"PG-FK-{uuid.uuid4().hex[:8].upper()}"
        with _open_pg_connection() as conn:
            _seed_test_incident(conn, inc_id)
            try:
                with conn.cursor() as cur:
                    # 1. RLS enabled on both Migration 007 tables
                    cur.execute(
                        """
                        SELECT c.relname, c.relrowsecurity
                          FROM pg_catalog.pg_class c
                          JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                         WHERE n.nspname = 'public'
                           AND c.relname IN ('incident_duplicate_links', 'incident_duplicate_scan_jobs')
                         ORDER BY c.relname
                        """
                    )
                    rls_rows = cur.fetchall()
                    assert rls_rows == [
                        ("incident_duplicate_links", True),
                        ("incident_duplicate_scan_jobs", True),
                    ]

                    # 2. service_role: SELECT only on links, zero direct table access on scan_jobs
                    cur.execute(
                        """
                        SELECT
                            pg_catalog.has_table_privilege('service_role', 'public.incident_duplicate_links', 'SELECT'),
                            pg_catalog.has_table_privilege('service_role', 'public.incident_duplicate_links', 'INSERT'),
                            pg_catalog.has_table_privilege('service_role', 'public.incident_duplicate_links', 'UPDATE'),
                            pg_catalog.has_table_privilege('service_role', 'public.incident_duplicate_links', 'DELETE'),
                            pg_catalog.has_table_privilege('service_role', 'public.incident_duplicate_links', 'TRUNCATE'),
                            pg_catalog.has_table_privilege('service_role', 'public.incident_duplicate_scan_jobs', 'SELECT'),
                            pg_catalog.has_table_privilege('service_role', 'public.incident_duplicate_scan_jobs', 'INSERT'),
                            pg_catalog.has_table_privilege('service_role', 'public.incident_duplicate_scan_jobs', 'UPDATE'),
                            pg_catalog.has_table_privilege('service_role', 'public.incident_duplicate_scan_jobs', 'DELETE'),
                            pg_catalog.has_table_privilege('service_role', 'public.incident_duplicate_scan_jobs', 'TRUNCATE')
                        """
                    )
                    assert cur.fetchone() == (
                        True,
                        False,
                        False,
                        False,
                        False,
                        False,
                        False,
                        False,
                        False,
                        False,
                    )

                    # 3. PUBLIC, anon, and authenticated cannot access either table at all
                    for role_name in ("public", "anon", "authenticated"):
                        for tbl_name in ("public.incident_duplicate_links", "public.incident_duplicate_scan_jobs"):
                            for priv in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE"):
                                cur.execute(
                                    "SELECT pg_catalog.has_table_privilege(%s, %s, %s)",
                                    (role_name, tbl_name, priv),
                                )
                                assert cur.fetchone()[0] is False, f"{role_name} unexpectedly has {priv} on {tbl_name}"

                    # 4. All 7 RPC EXECUTE privileges: service_role only; PUBLIC, anon, authenticated denied
                    for sig in EXPECTED_RPC_SIGNATURES:
                        cur.execute("SELECT pg_catalog.to_regprocedure(%s)", (sig,))
                        assert cur.fetchone()[0] is not None, f"Missing RPC {sig}"

                        for denied_role in ("public", "anon", "authenticated"):
                            cur.execute(
                                "SELECT pg_catalog.has_function_privilege(%s, %s, 'EXECUTE')",
                                (denied_role, sig),
                            )
                            assert cur.fetchone()[0] is False, f"{denied_role} has EXECUTE on {sig}"

                        cur.execute(
                            "SELECT pg_catalog.has_function_privilege('service_role', %s, 'EXECUTE')",
                            (sig,),
                        )
                        assert cur.fetchone()[0] is True, f"service_role lacks EXECUTE on {sig}"

                    # 5. All 5 foreign keys to public.incidents enforce ON DELETE RESTRICT (confdeltype = 'r')
                    cur.execute(
                        """
                        SELECT pg_catalog.count(*),
                               pg_catalog.count(*) FILTER (WHERE con.confdeltype = 'r')
                          FROM pg_catalog.pg_constraint con
                          JOIN pg_catalog.pg_class rel ON con.conrelid = rel.oid
                          JOIN pg_catalog.pg_namespace rel_ns ON rel.relnamespace = rel_ns.oid
                          JOIN pg_catalog.pg_class frel ON con.confrelid = frel.oid
                          JOIN pg_catalog.pg_namespace frel_ns ON frel.relnamespace = frel_ns.oid
                         WHERE rel_ns.nspname = 'public'
                           AND rel.relname IN ('incident_duplicate_links', 'incident_duplicate_scan_jobs')
                           AND frel_ns.nspname = 'public'
                           AND frel.relname = 'incidents'
                           AND con.contype = 'f'
                        """
                    )
                    assert cur.fetchone() == (5, 5)

                    # Runtime RESTRICT check: deleting referenced incident fails with SQLSTATE 23503 (foreign_key_violation)
                    with pytest.raises(PG_DB_ERROR) as del_exc:
                        cur.execute("DELETE FROM public.incidents WHERE id = %s", (inc_id,))
                    assert _extract_sqlstate(del_exc.value) == "23503"
                    conn.rollback()
            finally:
                conn.rollback()
                _drain_pending_outbox_jobs(conn)

    def test_outbox_skip_locked_disjoint_claims_and_stale_worker_rejection(self):
        tag = uuid.uuid4().hex[:8].upper()
        inc_a = f"PG-OUTA-{tag}"
        inc_b = f"PG-OUTB-{tag}"
        lease_1 = f"dup_lease_{uuid.uuid4().hex}"
        lease_2 = f"dup_lease_{uuid.uuid4().hex}"
        lease_3 = f"dup_lease_{uuid.uuid4().hex}"
        lease_4 = f"dup_lease_{uuid.uuid4().hex}"

        with _open_pg_connection() as setup_conn:
            _drain_pending_outbox_jobs(setup_conn)
            _seed_test_incident(setup_conn, inc_a)
            _seed_test_incident(setup_conn, inc_b)

        barrier = threading.Barrier(2)
        results: dict[str, list[str]] = {}
        worker_errors: list[tuple[str, BaseException]] = []
        err_lock = threading.Lock()

        def worker(name: str, lease_owner: str):
            conn = _open_pg_connection()
            try:
                with conn.cursor() as cur:
                    barrier.wait(timeout=10)
                    cur.execute(
                        "SELECT public.claim_duplicate_scan_jobs_rpc(%s, NULL, 1, 5)",
                        (lease_owner,),
                    )
                    claimed = cur.fetchone()[0]
                    conn.commit()
                    results[name] = [r["incident_id"] for r in claimed]
            except BaseException as exc:
                conn.rollback()
                with err_lock:
                    worker_errors.append((name, exc))
            finally:
                conn.close()

        t1 = threading.Thread(target=worker, args=("w1", lease_1))
        t2 = threading.Thread(target=worker, args=("w2", lease_2))
        t1.start()
        t2.start()
        t1.join(timeout=15)
        t2.join(timeout=15)

        assert worker_errors == []
        assert len(results["w1"]) == 1
        assert len(results["w2"]) == 1
        assert set(results["w1"]).isdisjoint(set(results["w2"]))
        assert set(results["w1"]) | set(results["w2"]) == {inc_a, inc_b}

        target_inc = results["w1"][0]
        other_inc = results["w2"][0]

        with _open_pg_connection() as verify_conn:
            with verify_conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT incident_id, status, attempt_count, lease_owner, lease_expires_at
                      FROM public.incident_duplicate_scan_jobs
                     WHERE incident_id IN (%s, %s)
                     ORDER BY incident_id
                    """,
                    (inc_a, inc_b),
                )
                rows = {r[0]: r for r in cur.fetchall()}
                assert rows[target_inc][1] == "IN_PROGRESS"
                assert rows[target_inc][2] == 1
                assert rows[target_inc][3] == lease_1
                assert rows[other_inc][1] == "IN_PROGRESS"
                assert rows[other_inc][2] == 1
                assert rows[other_inc][3] == lease_2
            verify_conn.commit()

        # Wait for the 5-second lease to genuinely expire against PostgreSQL clock_timestamp()
        time.sleep(5.5)

        with _open_pg_connection() as reclaim_conn:
            with reclaim_conn.cursor() as cur:
                cur.execute(
                    "SELECT public.claim_duplicate_scan_jobs_rpc(%s, %s, 1, 60)",
                    (lease_3, target_inc),
                )
                reclaimed = cur.fetchone()[0]
                assert len(reclaimed) == 1
                assert reclaimed[0]["incident_id"] == target_inc
                assert reclaimed[0]["attempt_count"] == 2
                assert reclaimed[0]["lease_owner"] == lease_3
            reclaim_conn.commit()

        # Stale worker 1 with superseded/expired lease_1 cannot record or release
        with _open_pg_connection() as stale_conn:
            with stale_conn.cursor() as cur:
                with pytest.raises(PG_DB_ERROR) as stale_rec_exc:
                    cur.execute(
                        "SELECT public.record_duplicate_candidates_rpc(%s, 'SIMULATION', '[]'::jsonb, %s)",
                        (target_inc, lease_1),
                    )
                assert _extract_sqlstate(stale_rec_exc.value) == "P0412"
                stale_conn.rollback()

                cur.execute(
                    "SELECT public.release_duplicate_scan_job_rpc(%s, %s, 'STALE_WORKER', 30, FALSE)",
                    (target_inc, lease_1),
                )
                rel_res = cur.fetchone()[0]
                stale_conn.commit()
                assert rel_res["released"] is False
                assert rel_res["reason"] == "LEASE_NOT_OWNED_OR_EXPIRED"

        # Active lease_3 row remains intact and 0 links were written by stale worker
        with _open_pg_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT status, attempt_count, lease_owner
                      FROM public.incident_duplicate_scan_jobs
                     WHERE incident_id = %s
                    """,
                    (target_inc,),
                )
                assert cur.fetchone() == ("IN_PROGRESS", 2, lease_3)

                # Non-array JSONB p_candidates fails with 22023 even with active lease
                with pytest.raises(PG_DB_ERROR) as non_arr_exc:
                    cur.execute(
                        "SELECT public.record_duplicate_candidates_rpc(%s, 'SIMULATION', %s::jsonb, %s)",
                        (target_inc, '{"bad": true}', lease_3),
                    )
                assert _extract_sqlstate(non_arr_exc.value) == "22023"
                conn.rollback()

                # Active worker completes cleanly
                cur.execute(
                    "SELECT public.record_duplicate_candidates_rpc(%s, 'SIMULATION', '[]'::jsonb, %s)",
                    (target_inc, lease_3),
                )
                rec_ok = cur.fetchone()[0]
                assert rec_ok["status"] == "COMPLETED"

                # Finish other_inc cleanly so outbox stays clean
                cur.execute("SELECT public.claim_duplicate_scan_jobs_rpc(%s, %s, 1, 60)", (lease_4, other_inc))
                cur.execute(
                    "SELECT public.record_duplicate_candidates_rpc(%s, 'SIMULATION', '[]'::jsonb, %s)",
                    (other_inc, lease_4),
                )

                cur.execute(
                    """
                    SELECT status, lease_owner, lease_expires_at, completed_at IS NOT NULL
                      FROM public.incident_duplicate_scan_jobs
                     WHERE incident_id = %s
                    """,
                    (target_inc,),
                )
                assert cur.fetchone() == ("COMPLETED", None, None, True)
            conn.commit()

    def test_concurrent_same_link_confirm_vs_dismiss_real_pg_connections(self):
        tag = uuid.uuid4().hex[:8].upper()
        inc_1 = f"PG-R1-{tag}"
        inc_2 = f"PG-R2-{tag}"
        link_id = f"lnk_{uuid.uuid4().hex[:24]}"

        with _open_pg_connection() as setup_conn:
            _seed_test_incident(setup_conn, inc_1)
            _seed_test_incident(setup_conn, inc_2)
            _create_suspected_link(setup_conn, inc_1, inc_2, link_id)

        barrier = threading.Barrier(2)
        outcomes: list[tuple[str, str, str | None, tuple[str, str]]] = []
        lock = threading.Lock()

        def review_worker(target_status: str):
            aud_low = f"AUD1-{uuid.uuid4().hex[:16]}"
            aud_high = f"AUD2-{uuid.uuid4().hex[:16]}"
            conn = _open_pg_connection()
            try:
                with conn.cursor() as cur:
                    barrier.wait(timeout=10)
                    cur.execute(
                        """
                        SELECT public.review_incident_duplicate_link_rpc(
                            %s, %s, %s, 'municipality', 'Concurrent review check',
                            %s, %s, %s, NULL, FALSE, 0
                        )
                        """,
                        (
                            link_id,
                            target_status,
                            f"officer-{target_status}",
                            aud_low,
                            aud_high,
                            inc_1 if target_status == "CONFIRMED" else None,
                        ),
                    )
                    conn.commit()
                with lock:
                    outcomes.append((target_status, "COMMITTED", None, (aud_low, aud_high)))
            except PG_DB_ERROR as exc:
                sqlstate = _extract_sqlstate(exc)
                conn.rollback()
                if not sqlstate:
                    raise
                with lock:
                    outcomes.append((target_status, "FAILED", sqlstate, (aud_low, aud_high)))
            finally:
                conn.close()

        t_conf = threading.Thread(target=review_worker, args=("CONFIRMED",))
        t_dism = threading.Thread(target=review_worker, args=("DISMISSED",))
        t_conf.start()
        t_dism.start()
        t_conf.join(timeout=15)
        t_dism.join(timeout=15)

        winners = [o for o in outcomes if o[1] == "COMMITTED"]
        losers = [o for o in outcomes if o[1] == "FAILED"]
        assert len(winners) == 1
        assert len(losers) == 1
        assert losers[0][2] == "23514"

        winner_status = winners[0][0]
        winner_aud_low, winner_aud_high = winners[0][3]

        with _open_pg_connection() as verify_conn:
            with verify_conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT link_status, review_version, primary_incident_id, duplicate_incident_id
                      FROM public.incident_duplicate_links
                     WHERE link_id = %s
                    """,
                    (link_id,),
                )
                link_rows = cur.fetchall()
                assert len(link_rows) == 1
                expected_pri = inc_1 if winner_status == "CONFIRMED" else None
                expected_dup = inc_2 if winner_status == "CONFIRMED" else None
                assert link_rows[0] == (winner_status, 1, expected_pri, expected_dup)

                cur.execute(
                    """
                    SELECT audit_id, incident_id, action, previous_status, new_status
                      FROM public.incident_audits
                     WHERE incident_id IN (%s, %s)
                       AND action IN ('DUPLICATE_CONFIRMED', 'DUPLICATE_DISMISSED')
                     ORDER BY incident_id
                    """,
                    (inc_1, inc_2),
                )
                audit_rows = cur.fetchall()
                assert len(audit_rows) == 2
                expected_action = f"DUPLICATE_{winner_status}"
                assert {r[0] for r in audit_rows} == {winner_aud_low, winner_aud_high}
                assert all(r[2] == expected_action and r[3] is None and r[4] is None for r in audit_rows)

                cur.execute(
                    "SELECT id, status FROM public.incidents WHERE id IN (%s, %s) ORDER BY id",
                    (inc_1, inc_2),
                )
                inc_statuses = cur.fetchall()
                assert all(r[1] == "REPORTED" for r in inc_statuses)

    def test_concurrent_3way_cycle_and_single_confirmed_primary_real_pg(self):
        # Part A: 3-way concurrent cycle prevention
        tag = uuid.uuid4().hex[:8].upper()
        inc_a = f"PG-C1-{tag}"
        inc_b = f"PG-C2-{tag}"
        inc_c = f"PG-C3-{tag}"
        links: dict[tuple[str, str], str] = {}

        with _open_pg_connection() as setup_conn:
            for iid in (inc_a, inc_b, inc_c):
                _seed_test_incident(setup_conn, iid)
            for src, dst in ((inc_a, inc_b), (inc_b, inc_c), (inc_c, inc_a)):
                lid = f"lnk_{uuid.uuid4().hex[:24]}"
                links[(src, dst)] = lid
                _create_suspected_link(setup_conn, src, dst, lid)

        barrier_a = threading.Barrier(3)
        cycle_results: list[tuple[str, str, str | None]] = []
        lock = threading.Lock()

        def confirm_edge(lid: str, primary_id: str, collector: list, br: threading.Barrier):
            conn = _open_pg_connection()
            try:
                with conn.cursor() as cur:
                    br.wait(timeout=10)
                    cur.execute(
                        """
                        SELECT public.review_incident_duplicate_link_rpc(
                            %s, 'CONFIRMED', 'admin-cycle', 'admin', 'Concurrent cycle edge',
                            %s, %s, %s, NULL, FALSE, 0
                        )
                        """,
                        (lid, f"AUDL-{uuid.uuid4().hex[:16]}", f"AUDH-{uuid.uuid4().hex[:16]}", primary_id),
                    )
                    conn.commit()
                with lock:
                    collector.append((lid, "COMMITTED", None))
            except PG_DB_ERROR as exc:
                sqlstate = _extract_sqlstate(exc)
                conn.rollback()
                if not sqlstate:
                    raise
                with lock:
                    collector.append((lid, "REJECTED", sqlstate))
            finally:
                conn.close()

        threads_a = [
            threading.Thread(target=confirm_edge, args=(links[(inc_a, inc_b)], inc_a, cycle_results, barrier_a)),
            threading.Thread(target=confirm_edge, args=(links[(inc_b, inc_c)], inc_b, cycle_results, barrier_a)),
            threading.Thread(target=confirm_edge, args=(links[(inc_c, inc_a)], inc_c, cycle_results, barrier_a)),
        ]
        for t in threads_a:
            t.start()
        for t in threads_a:
            t.join(timeout=15)

        committed_a = [r for r in cycle_results if r[1] == "COMMITTED"]
        rejected_a = [r for r in cycle_results if r[1] == "REJECTED"]
        assert len(committed_a) == 2
        assert len(rejected_a) == 1
        assert rejected_a[0][2] == "23514"

        with _open_pg_connection() as verify_conn:
            with verify_conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT link_id, link_status, review_version, primary_incident_id, duplicate_incident_id
                      FROM public.incident_duplicate_links
                     WHERE link_id = ANY(%s)
                    """,
                    (list(links.values()),),
                )
                link_rows_a = cur.fetchall()
                confirmed_edges = {
                    r[4]: r[3]
                    for r in link_rows_a
                    if r[1] == "CONFIRMED"
                }
                suspected_a = [r for r in link_rows_a if r[1] == "SUSPECTED"]
                assert len(confirmed_edges) == 2
                assert len(suspected_a) == 1
                assert suspected_a[0][2] == 0 and suspected_a[0][3] is None and suspected_a[0][4] is None

                # Verify resulting confirmed graph is strictly acyclic
                for start_node in confirmed_edges:
                    seen = set()
                    curr = start_node
                    while curr in confirmed_edges:
                        assert curr not in seen
                        seen.add(curr)
                        curr = confirmed_edges[curr]

                # Strictly 4 review audits (2 committed links x 2 endpoints; zero from losing tx)
                cur.execute(
                    """
                    SELECT pg_catalog.count(*)
                      FROM public.incident_audits
                     WHERE incident_id = ANY(%s)
                       AND action = 'DUPLICATE_CONFIRMED'
                    """,
                    ([inc_a, inc_b, inc_c],),
                )
                assert cur.fetchone()[0] == 4

        # Part B: uq_dup_single_confirmed_primary concurrent enforcement (SQLSTATE 23505)
        dup_x = f"PG-DX-{tag}"
        pri_1 = f"PG-P1-{tag}"
        pri_2 = f"PG-P2-{tag}"
        lid_1 = f"lnk_{uuid.uuid4().hex[:24]}"
        lid_2 = f"lnk_{uuid.uuid4().hex[:24]}"

        with _open_pg_connection() as setup_conn:
            for iid in (dup_x, pri_1, pri_2):
                _seed_test_incident(setup_conn, iid)
            _create_suspected_link(setup_conn, dup_x, pri_1, lid_1)
            _create_suspected_link(setup_conn, dup_x, pri_2, lid_2)

        barrier_b = threading.Barrier(2)
        single_pri_results: list[tuple[str, str, str | None]] = []
        t_p1 = threading.Thread(target=confirm_edge, args=(lid_1, pri_1, single_pri_results, barrier_b))
        t_p2 = threading.Thread(target=confirm_edge, args=(lid_2, pri_2, single_pri_results, barrier_b))
        t_p1.start()
        t_p2.start()
        t_p1.join(timeout=15)
        t_p2.join(timeout=15)

        committed_b = [r for r in single_pri_results if r[1] == "COMMITTED"]
        rejected_b = [r for r in single_pri_results if r[1] == "REJECTED"]
        assert len(committed_b) == 1
        assert len(rejected_b) == 1
        assert rejected_b[0][2] == "23505"

        with _open_pg_connection() as verify_conn:
            with verify_conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT link_id, link_status, review_version, primary_incident_id, duplicate_incident_id
                      FROM public.incident_duplicate_links
                     WHERE link_id IN (%s, %s)
                    """,
                    (lid_1, lid_2),
                )
                rows_b = cur.fetchall()
                conf_b = [r for r in rows_b if r[1] == "CONFIRMED"]
                susp_b = [r for r in rows_b if r[1] == "SUSPECTED"]
                assert len(conf_b) == 1 and conf_b[0][2] == 1 and conf_b[0][4] == dup_x
                assert len(susp_b) == 1 and susp_b[0][2] == 0 and susp_b[0][4] is None

                cur.execute(
                    """
                    SELECT pg_catalog.count(*)
                      FROM public.incident_audits
                     WHERE incident_id = ANY(%s)
                       AND action = 'DUPLICATE_CONFIRMED'
                    """,
                    ([dup_x, pri_1, pri_2],),
                )
                assert cur.fetchone()[0] == 2
