import asyncio
import logging
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import httpx
import jwt
import pglast
import pytest
from fastapi import status

from app.core.config import settings
from app.main import app
from fastapi.testclient import TestClient
from app.models.contracts import (
    AssignmentType,
    CategoryMatchType,
    DuplicateConfidenceBand,
    DuplicateLinkContract,
    DuplicateLinkDetailContract,
    DuplicateLinkStatus,
    DuplicateQueueResponseContract,
    IncidentCategory,
    IncidentResponseContract,
    IncidentSeverity,
    IncidentSource,
    IncidentStatus,
    IncidentUpdateContract,
    MunicipalDuplicateIncidentSummaryContract,
    MunicipalDuplicateLinkContract,
)
from app.services.duplicate_detector import (
    DUPLICATE_SCAN_BACKOFF_SECONDS,
    are_provenances_compatible,
    calculate_haversine_distance_meters,
    canonicalize_incident_pair,
    compute_retry_backoff_seconds,
    determine_category_match_type,
    execute_claimed_cloud_scan,
    generate_duplicate_lease_owner,
    generate_duplicate_link_id,
    get_allowed_categories_for_prefilter,
    is_valid_coordinate,
    recover_pending_cloud_duplicate_scans,
    scan_incident_for_duplicates,
    score_incident_pair,
)
from app.services.persistence_repository import (
    PersistenceRepository,
    StorageConflictError,
    StorageError,
    StorageLeaseLostError,
    StorageNotFoundError,
    StorageValidationError,
)
from app.services.state_store import state_store

MIGRATION_007_PATH = (
    Path(__file__).resolve().parents[2]
    / "database"
    / "migrations"
    / "007_duplicate_incident_detection.sql"
)


# ---------------------------------------------------------------------
# 1. Geographic & Haversine Math Tests
# ---------------------------------------------------------------------

def test_coordinate_validation():
    assert is_valid_coordinate(15.4920, 73.8185) is True
    assert is_valid_coordinate(0.0, 0.0) is False
    assert is_valid_coordinate(0.00001, 0.00001) is False
    assert is_valid_coordinate(90.0, 180.0) is True
    assert is_valid_coordinate(-90.0, -180.0) is True
    assert is_valid_coordinate(90.1, 0.0) is False
    assert is_valid_coordinate(0.0, 180.1) is False
    assert is_valid_coordinate(None, 73.0) is False
    assert is_valid_coordinate(15.0, None) is False
    assert is_valid_coordinate(float("nan"), 73.0) is False
    assert is_valid_coordinate(15.0, float("inf")) is False


def test_haversine_distance_accuracy():
    d = calculate_haversine_distance_meters(15.4989, 73.8278, 15.4965, 73.8305)
    assert 300.0 < d < 800.0
    assert calculate_haversine_distance_meters(15.4920, 73.8185, 15.4920, 73.8185) == 0.0
    d_anti = calculate_haversine_distance_meters(0.01, 179.999, 0.01, -179.999)
    assert 200.0 < d_anti < 250.0


# ---------------------------------------------------------------------
# 2. Category Match & Allowlist Tests
# ---------------------------------------------------------------------

def test_category_matching():
    assert determine_category_match_type("FLOODING", "FLOODING") == CategoryMatchType.EXACT
    assert determine_category_match_type("FLOODING", "WATERLOGGING") == CategoryMatchType.RELATED
    assert determine_category_match_type("WATERLOGGING", "DRAIN_OVERFLOW") == CategoryMatchType.RELATED
    assert determine_category_match_type("DRAIN_BLOCKAGE", "MANHOLE_DAMAGE") == CategoryMatchType.RELATED
    assert determine_category_match_type("FLOODING", "DRAIN_BLOCKAGE") == CategoryMatchType.OTHER
    assert determine_category_match_type("OTHER", "FLOODING") == CategoryMatchType.OTHER


def test_prefilter_allowed_categories():
    water_cats = get_allowed_categories_for_prefilter("FLOODING", allow_related=True)
    assert set(water_cats) == {"FLOODING", "WATERLOGGING", "DRAIN_OVERFLOW"}

    exact_only = get_allowed_categories_for_prefilter("FLOODING", allow_related=False)
    assert exact_only == ["FLOODING"]

    infra_cats = get_allowed_categories_for_prefilter("DRAIN_BLOCKAGE", allow_related=True)
    assert set(infra_cats) == {"DRAIN_BLOCKAGE", "MANHOLE_DAMAGE", "INFRASTRUCTURE_DAMAGE"}


# ---------------------------------------------------------------------
# 3. Provenance & Operational Mode Compatibility Matrix
# ---------------------------------------------------------------------

def test_provenance_compatibility_rules():
    assert are_provenances_compatible("DEMO", "SIMULATION", "CITIZEN", "SIMULATION") is False
    assert are_provenances_compatible("CITIZEN", "SIMULATION", "DEMO", "SIMULATION") is False
    assert are_provenances_compatible("DEMO", "SIMULATION", "DEMO", "SIMULATION") is False

    assert are_provenances_compatible("CITIZEN", "SIMULATION", "CITIZEN", "PHYSICAL") is True
    assert are_provenances_compatible("CITIZEN", "SAFE_HOLD", "CITIZEN", "SIMULATION") is True

    assert are_provenances_compatible("CITIZEN", "SIMULATION", "SENSOR", "PHYSICAL", True) is True
    assert are_provenances_compatible("CITIZEN", "SIMULATION", "SENSOR", "SAFE_HOLD", True) is True
    assert are_provenances_compatible("CITIZEN", "SIMULATION", "SENSOR", "SIMULATION", True) is False

    assert are_provenances_compatible("SENSOR", "SIMULATION", "SENSOR", "SIMULATION") is True
    assert are_provenances_compatible("SENSOR", "SIMULATION", "SENSOR", "PHYSICAL") is False
    assert are_provenances_compatible("SENSOR", "PHYSICAL", "SENSOR", "SAFE_HOLD") is True


# ---------------------------------------------------------------------
# 4. Canonical Undirected Pair, Link ID Safety & Deterministic Scorer
# ---------------------------------------------------------------------

def test_canonical_pair_ordering_and_link_id_length_safety():
    low, high = canonicalize_incident_pair("INC-Z-002", "INC-A-001")
    assert (low, high) == ("INC-A-001", "INC-Z-002")
    assert canonicalize_incident_pair("INC-A-001", "INC-Z-002") == ("INC-A-001", "INC-Z-002")

    # Even with two max-length 32-char incident IDs, generated link_id stays <= 32 chars
    id_1 = "I" * 32
    id_2 = "J" * 32
    link_id = generate_duplicate_link_id()
    assert 5 <= len(link_id) <= 32

    now = datetime.now(timezone.utc)
    link = score_incident_pair(
        {
            "id": id_2,
            "category": "FLOODING",
            "description": "Overflow near school gate",
            "latitude": 15.4920,
            "longitude": 73.8185,
            "source": "CITIZEN",
            "origin_operational_mode": "PHYSICAL",
            "status": "REPORTED",
            "created_at": now,
        },
        {
            "id": id_1,
            "category": "FLOODING",
            "description": "Overflow near school gate",
            "latitude": 15.4921,
            "longitude": 73.8186,
            "source": "CITIZEN",
            "origin_operational_mode": "PHYSICAL",
            "status": "REPORTED",
            "created_at": now,
        },
    )
    assert link is not None
    assert len(link.link_id) <= 32
    assert link.incident_low_id == id_1
    assert link.incident_high_id == id_2
    assert link.link_status == DuplicateLinkStatus.SUSPECTED
    assert link.primary_incident_id is None
    assert link.duplicate_incident_id is None


def test_pair_scoring_exact_category_within_threshold():
    now = datetime.now(timezone.utc)
    inc_a = {
        "id": "INC-B",
        "category": "FLOODING",
        "description": "Severe flooding on road near church",
        "latitude": 15.4920,
        "longitude": 73.8185,
        "source": "CITIZEN",
        "origin_operational_mode": "PHYSICAL",
        "status": "REPORTED",
        "created_at": now - timedelta(minutes=10),
    }
    inc_b = {
        "id": "INC-A",
        "category": "FLOODING",
        "description": "Heavy road flooding near the church",
        "latitude": 15.4922,
        "longitude": 73.8187,
        "source": "CITIZEN",
        "origin_operational_mode": "PHYSICAL",
        "status": "REPORTED",
        "created_at": now,
    }

    link = score_incident_pair(inc_a, inc_b, detected_in_mode="PHYSICAL")
    assert link is not None
    assert link.incident_low_id == "INC-A"
    assert link.incident_high_id == "INC-B"
    assert link.link_status == DuplicateLinkStatus.SUSPECTED
    assert link.primary_incident_id is None
    assert link.duplicate_incident_id is None
    assert link.detected_in_mode == "PHYSICAL"
    assert link.confidence_score >= 0.80
    assert link.confidence_band == DuplicateConfidenceBand.HIGH
    assert link.distance_meters < 50.0


def test_pair_scoring_distance_cutoffs():
    now = datetime.now(timezone.utc)
    inc_a = {
        "id": "INC-A",
        "category": "FLOODING",
        "description": "Water overflow",
        "latitude": 15.4920,
        "longitude": 73.8185,
        "source": "CITIZEN",
        "created_at": now,
    }
    inc_far = {
        "id": "INC-B",
        "category": "FLOODING",
        "description": "Water overflow",
        "latitude": 15.4938,
        "longitude": 73.8185,
        "source": "CITIZEN",
        "created_at": now,
    }
    assert score_incident_pair(inc_a, inc_far) is None

    inc_rel_far = {
        "id": "INC-C",
        "category": "WATERLOGGING",
        "description": "Water logging",
        "latitude": 15.4928,
        "longitude": 73.8185,
        "source": "CITIZEN",
        "created_at": now,
    }
    assert score_incident_pair(inc_a, inc_rel_far) is None


# ---------------------------------------------------------------------
# 5. Migration 007 SQL AST, Schema & Security Contract Verification
# ---------------------------------------------------------------------

def test_migration_007_sql_ast_and_security_contracts():
    sql = MIGRATION_007_PATH.read_text(encoding="utf-8")

    # Full PostgreSQL parser check
    parsed = pglast.parse_sql(sql)
    assert len(parsed) >= 40

    # Parse every PL/pgSQL function and check default parameter ordering
    raw_splits = pglast.split(sql)
    func_ddls = [
        s.strip()
        for s in raw_splits
        if s.strip().upper().startswith("CREATE OR REPLACE FUNCTION")
    ]
    assert len(func_ddls) == 7

    seen_func_names: set[str] = set()
    for fn_sql in func_ddls:
        pglast.parse_plpgsql(fn_sql)
        assert "SECURITY DEFINER" in fn_sql
        assert "SET search_path = pg_catalog, public, pg_temp" in fn_sql
        stmt = pglast.parse_sql(fn_sql)[0].stmt
        func_name = stmt.funcname[-1].sval
        seen_func_names.add(func_name)

        # PostgreSQL rule: once a default parameter appears, every subsequent parameter must have a default
        seen_default = False
        for param in stmt.parameters or ():
            if param.defexpr is not None:
                seen_default = True
            else:
                assert not seen_default, f"{func_name} has required param after defaulted param"

    assert seen_func_names == {
        "citizen_incident_creation_rpc",
        "claim_duplicate_scan_jobs_rpc",
        "fetch_duplicate_candidates_rpc",
        "record_duplicate_candidates_rpc",
        "release_duplicate_scan_job_rpc",
        "reset_duplicate_scan_job_rpc",
        "review_incident_duplicate_link_rpc",
    }

    # Canonical table & security assertions
    assert 'COLLATE "C"' in sql
    assert "link_status VARCHAR(24) NOT NULL DEFAULT 'SUSPECTED'" in sql
    assert "CONSTRAINT uq_dup_canonical_pair UNIQUE (incident_low_id, incident_high_id)" in sql
    assert "CREATE UNIQUE INDEX IF NOT EXISTS uq_dup_single_confirmed_primary\n    ON public.incident_duplicate_links (duplicate_incident_id)\n    WHERE link_status = 'CONFIRMED';" in sql
    assert "ON DELETE RESTRICT" in sql
    assert "ON DELETE CASCADE" not in sql
    assert "REVOKE ALL ON TABLE public.incident_duplicate_links FROM PUBLIC, anon, authenticated, service_role;" in sql
    assert "REVOKE ALL ON TABLE public.incident_duplicate_scan_jobs FROM PUBLIC, anon, authenticated, service_role;" in sql
    assert "GRANT SELECT ON TABLE public.incident_duplicate_links TO service_role;" in sql
    assert "GRANT SELECT ON TABLE public.incident_duplicate_scan_jobs TO service_role;" not in sql

    # Outbox state machine & SQL candidate fixes
    assert "IN_PROGRESS" in sql and "FAILED_PERMANENT" in sql
    assert "chk_scan_job_lease_binding" in sql
    assert "FOR UPDATE SKIP LOCKED" in sql
    assert "ARRAY[30, 120, 600, 1800, 3600]" in sql
    assert "v_job.lease_expires_at <= v_now" in sql
    assert "USING ERRCODE = 'P0412';" in sql
    assert "p_candidates must be a JSON array when provided" in sql
    assert "v_fk_count <> 5 OR v_bad_fk_count > 0" in sql
    assert "NOTIFY pgrst, 'reload schema';" in sql
    assert "LEAST(" in sql and "GREATEST(" in sql
    assert "WHERE distance_meters <= v_radius_buf" in sql
    assert "ORDER BY distance_meters ASC, created_at ASC, id ASC" in sql
    assert "p_limit INT DEFAULT 200" in sql

    # Review RPC fixes
    assert "c.depth < 10" not in sql
    assert "DUPLICATE_OVERRIDE_CONFIRMED" in sql
    assert "DUPLICATE_OVERRIDE_DISMISSED" in sql
    assert "v_inc_primary.status = 'REJECTED'" in sql
    assert "v_link.review_version <> p_expected_version" in sql
    assert "value <> value" not in sql


# ---------------------------------------------------------------------
# 6. Local StateStore Canonical Pair, Rescan Preservation & Review Rules
# ---------------------------------------------------------------------

def test_reversed_pair_and_rescan_preserve_reviewed_decisions():
    inc1 = state_store.create_incident(
        IncidentResponseContract(
            id="INC-REV-01",
            category=IncidentCategory.FLOODING,
            description="Corner culvert overflowing onto road",
            latitude=15.4920,
            longitude=73.8185,
            severity=IncidentSeverity.HIGH,
            source=IncidentSource.CITIZEN,
        )
    )
    inc2 = state_store.create_incident(
        IncidentResponseContract(
            id="INC-REV-02",
            category=IncidentCategory.FLOODING,
            description="Corner culvert overflowing onto road",
            latitude=15.4921,
            longitude=73.8186,
            severity=IncidentSeverity.HIGH,
            source=IncidentSource.CITIZEN,
        )
    )

    res = scan_incident_for_duplicates(inc2.id, PersistenceRepository(supabase_url=None), state_store, settings)
    assert res.status == "COMPLETED"
    assert res.links_created == 1

    links = state_store.get_incident_duplicate_links(inc1.id)
    assert len(links) == 1
    link = links[0]
    assert link.incident_low_id == "INC-REV-01"
    assert link.incident_high_id == "INC-REV-02"
    assert link.link_status == DuplicateLinkStatus.SUSPECTED

    # Reversed pair attempt cannot insert a second link for (INC-REV-02, INC-REV-01)
    reversed_dup = DuplicateLinkContract(
        link_id=generate_duplicate_link_id(),
        incident_low_id="INC-REV-01",
        incident_high_id="INC-REV-02",
        link_status=DuplicateLinkStatus.SUSPECTED,
        detected_in_mode="SIMULATION",
        distance_meters=12.0,
        time_delta_seconds=1,
        confidence_score=0.90,
        confidence_band=DuplicateConfidenceBand.HIGH,
    )
    assert state_store.record_duplicate_link(reversed_dup) is False
    assert len(state_store.get_duplicate_links()) == 1

    # Confirm link selecting inc2 (newer) as primary, then rescan and ensure decision survives
    confirmed = state_store.review_duplicate_link(
        link_id=link.link_id,
        target_status="CONFIRMED",
        actor_id="officer-1",
        actor_role="municipality",
        reason="Dispatch verified inc2 is main report",
        primary_incident_id=inc2.id,
    )
    assert confirmed.primary_incident_id == inc2.id
    assert confirmed.duplicate_incident_id == inc1.id
    assert confirmed.review_version == 1

    res2 = scan_incident_for_duplicates(inc1.id, PersistenceRepository(supabase_url=None), state_store, settings)
    assert res2.links_created == 0
    surviving = state_store.get_incident_duplicate_links(inc1.id)[0]
    assert surviving.link_status == DuplicateLinkStatus.CONFIRMED
    assert surviving.primary_incident_id == inc2.id
    assert surviving.review_version == 1

    # Dismiss via override, then rescan and verify DISMISSED survives
    overridden = state_store.review_duplicate_link(
        link_id=link.link_id,
        target_status="DISMISSED",
        actor_id="supervisor-1",
        actor_role="admin",
        reason="Two opposite culverts across boulevard",
        override=True,
        expected_version=1,
    )
    assert overridden.link_status == DuplicateLinkStatus.DISMISSED
    assert overridden.primary_incident_id is None
    assert overridden.review_version == 2

    res3 = scan_incident_for_duplicates(inc2.id, PersistenceRepository(supabase_url=None), state_store, settings)
    assert res3.links_created == 0
    assert state_store.get_incident_duplicate_links(inc1.id)[0].link_status == DuplicateLinkStatus.DISMISSED


def test_statestore_review_optimistic_lock_rejected_primary_and_cycle_depth_gt_10():
    # Create a 12-incident chain: I00 -> I01 -> ... -> I11 (exceeds old depth < 10 limit)
    nodes = [f"INC-CYC-{i:02d}" for i in range(12)]
    for nid in nodes:
        state_store.create_incident(
            IncidentResponseContract(
                id=nid,
                category=IncidentCategory.FLOODING,
                description="Chain node",
                latitude=15.4920,
                longitude=73.8185,
                severity=IncidentSeverity.MEDIUM,
                source=IncidentSource.CITIZEN,
            )
        )

    for i in range(11):
        low, high = canonicalize_incident_pair(nodes[i], nodes[i + 1])
        link = DuplicateLinkContract(
            link_id=generate_duplicate_link_id(),
            incident_low_id=low,
            incident_high_id=high,
            link_status=DuplicateLinkStatus.SUSPECTED,
            detected_in_mode="SIMULATION",
            distance_meters=10.0,
            time_delta_seconds=5,
            confidence_score=0.90,
            confidence_band=DuplicateConfidenceBand.HIGH,
        )
        assert state_store.record_duplicate_link(link) is True
        # nodes[i] is duplicate of nodes[i+1]
        state_store.review_duplicate_link(
            link_id=link.link_id,
            target_status="CONFIRMED",
            actor_id="admin-1",
            actor_role="admin",
            reason="Linking long duplicate chain",
            primary_incident_id=nodes[i + 1],
        )

    # Confirming nodes[11] -> nodes[0] would close a 12-node cycle
    low_close, high_close = canonicalize_incident_pair(nodes[11], nodes[0])
    closing_link = DuplicateLinkContract(
        link_id=generate_duplicate_link_id(),
        incident_low_id=low_close,
        incident_high_id=high_close,
        link_status=DuplicateLinkStatus.SUSPECTED,
        detected_in_mode="SIMULATION",
        distance_meters=10.0,
        time_delta_seconds=5,
        confidence_score=0.90,
        confidence_band=DuplicateConfidenceBand.HIGH,
    )
    state_store.record_duplicate_link(closing_link)

    with pytest.raises(ValueError, match="circular dependency"):
        state_store.review_duplicate_link(
            link_id=closing_link.link_id,
            target_status="CONFIRMED",
            actor_id="admin-1",
            actor_role="admin",
            reason="Attempt cycle closure",
            primary_incident_id=nodes[0],
        )

    # Optimistic concurrency version mismatch fails
    with pytest.raises(ValueError, match="Version conflict"):
        state_store.review_duplicate_link(
            link_id=closing_link.link_id,
            target_status="DISMISSED",
            actor_id="admin-1",
            actor_role="admin",
            reason="Stale version dismissal",
            expected_version=99,
        )

    # Confirming a REJECTED primary incident fails
    rej = state_store.create_incident(
        IncidentResponseContract(
            id="INC-REJ-PRIM",
            category=IncidentCategory.FLOODING,
            description="Rejected spam",
            latitude=15.4920,
            longitude=73.8185,
            severity=IncidentSeverity.LOW,
            source=IncidentSource.CITIZEN,
            status=IncidentStatus.REJECTED,
        )
    )
    low_r, high_r = canonicalize_incident_pair(nodes[11], rej.id)
    rej_link = DuplicateLinkContract(
        link_id=generate_duplicate_link_id(),
        incident_low_id=low_r,
        incident_high_id=high_r,
        link_status=DuplicateLinkStatus.SUSPECTED,
        detected_in_mode="SIMULATION",
        distance_meters=5.0,
        time_delta_seconds=1,
        confidence_score=0.90,
        confidence_band=DuplicateConfidenceBand.HIGH,
    )
    state_store.record_duplicate_link(rej_link)
    with pytest.raises(ValueError, match="REJECTED"):
        state_store.review_duplicate_link(
            link_id=rej_link.link_id,
            target_status="CONFIRMED",
            actor_id="admin-1",
            actor_role="admin",
            reason="Attempt rejected primary",
            primary_incident_id=rej.id,
        )


def test_statestore_single_confirmed_primary_and_dual_audits():
    for iid in ("INC-PRI-A", "INC-PRI-B", "INC-DUP-C"):
        state_store.create_incident(
            IncidentResponseContract(
                id=iid,
                category=IncidentCategory.FLOODING,
                description="Drainage flood report",
                latitude=15.4920,
                longitude=73.8185,
                severity=IncidentSeverity.HIGH,
                source=IncidentSource.CITIZEN,
            )
        )

    low1, high1 = canonicalize_incident_pair("INC-DUP-C", "INC-PRI-A")
    link1 = DuplicateLinkContract(
        link_id=generate_duplicate_link_id(),
        incident_low_id=low1,
        incident_high_id=high1,
        link_status=DuplicateLinkStatus.SUSPECTED,
        detected_in_mode="SIMULATION",
        distance_meters=10.0,
        time_delta_seconds=10,
        confidence_score=0.90,
        confidence_band=DuplicateConfidenceBand.HIGH,
    )
    low2, high2 = canonicalize_incident_pair("INC-DUP-C", "INC-PRI-B")
    link2 = DuplicateLinkContract(
        link_id=generate_duplicate_link_id(),
        incident_low_id=low2,
        incident_high_id=high2,
        link_status=DuplicateLinkStatus.SUSPECTED,
        detected_in_mode="SIMULATION",
        distance_meters=12.0,
        time_delta_seconds=20,
        confidence_score=0.88,
        confidence_band=DuplicateConfidenceBand.HIGH,
    )
    state_store.record_duplicate_link(link1)
    state_store.record_duplicate_link(link2)

    confirmed = state_store.review_duplicate_link(
        link_id=link1.link_id,
        target_status="CONFIRMED",
        actor_id="muni-1",
        actor_role="municipality",
        reason="Primary A confirmed",
        primary_incident_id="INC-PRI-A",
        internal_notes="Verified from field team photo",
    )
    assert confirmed.review_version == 1

    # Verify dual audits recorded on both incidents with NULL status change and zero incident mutation
    assert state_store.get_incident("INC-DUP-C").status == IncidentStatus.REPORTED
    assert state_store.get_incident("INC-PRI-A").status == IncidentStatus.REPORTED
    audits_dup = [a for a in state_store.get_incident_audits("INC-DUP-C") if a.action == "DUPLICATE_CONFIRMED"]
    audits_pri = [a for a in state_store.get_incident_audits("INC-PRI-A") if a.action == "DUPLICATE_CONFIRMED"]
    assert len(audits_dup) == 1 and audits_dup[0].previous_status is None and audits_dup[0].new_status is None
    assert len(audits_pri) == 1 and audits_pri[0].previous_status is None and audits_pri[0].new_status is None

    # Repeat confirm without override fails (no silent success)
    with pytest.raises(ValueError, match="override is required"):
        state_store.review_duplicate_link(
            link_id=link1.link_id,
            target_status="CONFIRMED",
            actor_id="muni-2",
            actor_role="municipality",
            reason="Concurrent confirmation attempt",
            primary_incident_id="INC-PRI-A",
        )

    # Confirming INC-DUP-C against second primary INC-PRI-B fails
    with pytest.raises(ValueError, match="already confirmed as a duplicate"):
        state_store.review_duplicate_link(
            link_id=link2.link_id,
            target_status="CONFIRMED",
            actor_id="muni-2",
            actor_role="municipality",
            reason="Conflicting primary confirmation",
            primary_incident_id="INC-PRI-B",
        )

    # Override emits DUPLICATE_OVERRIDE_DISMISSED
    state_store.review_duplicate_link(
        link_id=link1.link_id,
        target_status="DISMISSED",
        actor_id="sup-1",
        actor_role="admin",
        reason="Separate locations confirmed on map",
        override=True,
        expected_version=1,
    )
    override_audits = [
        a for a in state_store.get_incident_audits("INC-DUP-C") if a.action == "DUPLICATE_OVERRIDE_DISMISSED"
    ]
    assert len(override_audits) == 1


# ---------------------------------------------------------------------
# 7. Mocked Cloud Orchestrator & Outbox Lease / Retry / Recovery Tests
# ---------------------------------------------------------------------

def test_cloud_orchestrator_mocked_happy_path_unique_lease_and_query_method():
    """MOCKED UNIT TEST: verifies query_incident_by_id_sync, unique lease tokens, and single claim."""
    lease_1 = generate_duplicate_lease_owner()
    lease_2 = generate_duplicate_lease_owner()
    assert lease_1 != lease_2
    assert re.match(r"^dup_lease_[a-f0-9]{32}$", lease_1)

    now = datetime.now(timezone.utc)
    mock_repo = MagicMock()
    mock_repo.is_configured = True
    mock_repo.is_storage_configured = True
    mock_repo.is_mock = False
    assert not hasattr(PersistenceRepository, "get_incident_by_id_sync")

    def fake_claim(lease_owner, incident_id=None, batch_size=10, lease_sec=60):
        return [{"incident_id": incident_id, "attempt_count": 1, "lease_owner": lease_owner}]

    mock_repo.claim_duplicate_scan_jobs_sync.side_effect = fake_claim
    mock_repo.query_incident_by_id_sync.return_value = {
        "id": "INC-CLOUD-NEW",
        "category": "FLOODING",
        "description": "Heavy water accumulation on 18th June road",
        "latitude": 15.4920,
        "longitude": 73.8185,
        "severity": "HIGH",
        "status": "REPORTED",
        "source": "CITIZEN",
        "origin_operational_mode": "PHYSICAL",
        "created_at": now.isoformat(),
    }
    mock_repo.fetch_duplicate_candidates_sync.return_value = {
        "source_incident": mock_repo.query_incident_by_id_sync.return_value,
        "candidates": [
            {
                "id": "INC-CLOUD-OLD",
                "category": "FLOODING",
                "description": "Heavy water accumulation on 18th June road",
                "latitude": 15.4921,
                "longitude": 73.8186,
                "severity": "HIGH",
                "status": "REPORTED",
                "source": "CITIZEN",
                "origin_operational_mode": "SIMULATION",
                "created_at": (now - timedelta(minutes=5)).isoformat(),
            }
        ],
    }
    mock_repo.record_duplicate_candidates_sync.return_value = {
        "incident_id": "INC-CLOUD-NEW",
        "status": "COMPLETED",
        "links_created": 1,
        "total_links": 1,
    }

    res = scan_incident_for_duplicates("INC-CLOUD-NEW", mock_repo, state_store, settings)
    assert res.status == "COMPLETED"
    assert res.candidates_found == 1
    assert res.links_created == 1
    assert mock_repo.claim_duplicate_scan_jobs_sync.call_count == 1
    claimed_lease = mock_repo.claim_duplicate_scan_jobs_sync.call_args.kwargs["lease_owner"]
    assert re.match(r"^dup_lease_[a-f0-9]{32}$", claimed_lease)
    mock_repo.query_incident_by_id_sync.assert_called_once_with("INC-CLOUD-NEW")
    assert mock_repo.record_duplicate_candidates_sync.call_args.kwargs["lease_owner"] == claimed_lease


def test_cloud_orchestrator_mocked_empty_claim_aborts_immediately():
    """MOCKED UNIT TEST: empty claim must abort without querying, fetching, or recording."""
    mock_repo = MagicMock()
    mock_repo.is_configured = True
    mock_repo.is_storage_configured = True
    mock_repo.is_mock = False
    mock_repo.claim_duplicate_scan_jobs_sync.return_value = []

    res = scan_incident_for_duplicates("INC-LOCKED", mock_repo, state_store, settings)
    assert res.status == "NOT_CLAIMED"
    mock_repo.query_incident_by_id_sync.assert_not_called()
    mock_repo.fetch_duplicate_candidates_sync.assert_not_called()
    mock_repo.record_duplicate_candidates_sync.assert_not_called()


def test_cloud_orchestrator_mocked_retry_backoff_stale_and_permanent_failures():
    """MOCKED UNIT TEST: verifies exponential backoff, missing incident permanent fail, and stale worker lease loss."""
    assert [compute_retry_backoff_seconds(i) for i in (1, 2, 3, 4, 5, 6)] == [30, 120, 600, 1800, 3600, 3600]
    assert DUPLICATE_SCAN_BACKOFF_SECONDS == (30, 120, 600, 1800, 3600)

    lease = generate_duplicate_lease_owner()
    mock_repo = MagicMock()

    # 1. Transient RPC error -> releases with attempt-indexed backoff (permanent=False)
    mock_repo.query_incident_by_id_sync.side_effect = RuntimeError("PostgREST timeout")
    mock_repo.release_duplicate_scan_job_sync.return_value = {"released": True, "status": "PENDING"}
    res_retry = execute_claimed_cloud_scan({"incident_id": "INC-1", "attempt_count": 2}, lease, mock_repo, settings)
    assert res_retry.status == "RETRY_SCHEDULED"
    rel_kwargs = mock_repo.release_duplicate_scan_job_sync.call_args.kwargs
    assert rel_kwargs["lease_owner"] == lease
    assert rel_kwargs["backoff_sec"] == 120
    assert rel_kwargs["permanent"] is False

    # 2. Genuine stale lease conflict (P0412 -> StorageLeaseLostError) -> LEASE_LOST without calling release!
    mock_repo.reset_mock()
    now = datetime.now(timezone.utc)
    mock_repo.query_incident_by_id_sync.side_effect = None
    mock_repo.query_incident_by_id_sync.return_value = {
        "id": "INC-2",
        "category": "FLOODING",
        "description": "flood",
        "latitude": 15.4920,
        "longitude": 73.8185,
        "source": "CITIZEN",
        "status": "REPORTED",
        "created_at": now.isoformat(),
    }
    mock_repo.fetch_duplicate_candidates_sync.return_value = {"source_incident": mock_repo.query_incident_by_id_sync.return_value, "candidates": []}
    mock_repo.record_duplicate_candidates_sync.side_effect = StorageLeaseLostError(
        "Processing lease is expired or no longer owned.", sqlstate="P0412", error_category="LEASE_LOST"
    )
    res_stale = execute_claimed_cloud_scan({"incident_id": "INC-2", "attempt_count": 1}, lease, mock_repo, settings)
    assert res_stale.status == "LEASE_LOST"
    mock_repo.release_duplicate_scan_job_sync.assert_not_called()

    # 3. Missing incident -> permanent release
    mock_repo.reset_mock()
    mock_repo.query_incident_by_id_sync.return_value = None
    mock_repo.release_duplicate_scan_job_sync.return_value = {"released": True, "status": "FAILED_PERMANENT"}
    res_perm = execute_claimed_cloud_scan({"incident_id": "INC-GONE", "attempt_count": 1}, lease, mock_repo, settings)
    assert res_perm.status == "FAILED_PERMANENT"
    assert mock_repo.release_duplicate_scan_job_sync.call_args.kwargs["permanent"] is True


def test_cloud_orchestrator_mocked_sqlstate_classification_and_retry():
    """MOCKED UNIT TEST: distinguishes P0412 lease loss, 23514 CHECK violation, 23505 unique conflict, and successful retry."""
    now = datetime.now(timezone.utc)
    base_inc = {
        "id": "INC-SQL",
        "category": "FLOODING",
        "description": "flood",
        "latitude": 15.4920,
        "longitude": 73.8185,
        "source": "CITIZEN",
        "status": "REPORTED",
        "created_at": now.isoformat(),
    }

    # 1. Check violation (SQLSTATE 23514) must permanently release instead of pretending LEASE_LOST
    lease_1 = generate_duplicate_lease_owner()
    mock_repo = MagicMock()
    mock_repo.query_incident_by_id_sync.return_value = base_inc
    mock_repo.fetch_duplicate_candidates_sync.return_value = {"source_incident": base_inc, "candidates": []}
    mock_repo.record_duplicate_candidates_sync.side_effect = StorageConflictError(
        "Constraint conflict", sqlstate="23514", error_category="CHECK_OR_STATE_CONFLICT"
    )
    mock_repo.release_duplicate_scan_job_sync.return_value = {"released": True, "status": "FAILED_PERMANENT"}

    res_check = execute_claimed_cloud_scan({"incident_id": "INC-SQL", "attempt_count": 1}, lease_1, mock_repo, settings)
    assert res_check.status == "FAILED_PERMANENT"
    mock_repo.release_duplicate_scan_job_sync.assert_called_once()
    assert mock_repo.release_duplicate_scan_job_sync.call_args.kwargs["permanent"] is True
    assert mock_repo.release_duplicate_scan_job_sync.call_args.kwargs["error_code"] == "CANDIDATE_CHECK_VIOLATION"

    # 2. Unique violation (SQLSTATE 23505) must schedule retry with backoff, then succeed on next attempt
    mock_repo.reset_mock()
    lease_2 = generate_duplicate_lease_owner()
    mock_repo.query_incident_by_id_sync.return_value = base_inc
    mock_repo.fetch_duplicate_candidates_sync.return_value = {"source_incident": base_inc, "candidates": []}
    mock_repo.record_duplicate_candidates_sync.side_effect = [
        StorageConflictError("Unique conflict", sqlstate="23505", error_category="UNIQUE_VIOLATION"),
        {"incident_id": "INC-SQL", "status": "COMPLETED", "links_created": 0, "total_links": 0},
    ]
    mock_repo.release_duplicate_scan_job_sync.return_value = {"released": True, "status": "PENDING"}

    res_uniq = execute_claimed_cloud_scan({"incident_id": "INC-SQL", "attempt_count": 1}, lease_2, mock_repo, settings)
    assert res_uniq.status == "RETRY_SCHEDULED"
    rel_kw = mock_repo.release_duplicate_scan_job_sync.call_args.kwargs
    assert rel_kw["permanent"] is False
    assert rel_kw["backoff_sec"] == 30
    assert rel_kw["error_code"] == "UNIQUE_VIOLATION"

    lease_3 = generate_duplicate_lease_owner()
    res_retry_ok = execute_claimed_cloud_scan({"incident_id": "INC-SQL", "attempt_count": 2}, lease_3, mock_repo, settings)
    assert res_retry_ok.status == "COMPLETED"


def test_cloud_sweeper_and_maintenance_single_claim_mocked(admin_client):
    """MOCKED UNIT TEST: sweeper and maintenance endpoint claim ONCE and isolate per-job errors."""
    now = datetime.now(timezone.utc)
    mock_repo = MagicMock()
    mock_repo.is_configured = True
    mock_repo.is_storage_configured = True
    mock_repo.is_mock = False

    def fake_claim(lease_owner, incident_id=None, batch_size=10, lease_sec=60):
        return [
            {"incident_id": "INC-BATCH-FAIL", "attempt_count": 1, "lease_owner": lease_owner},
            {"incident_id": "INC-BATCH-OK", "attempt_count": 1, "lease_owner": lease_owner},
        ]

    mock_repo.claim_duplicate_scan_jobs_sync.side_effect = fake_claim
    mock_repo.query_incident_by_id_sync.side_effect = [
        RuntimeError("Transient DB hiccup on first job"),
        {
            "id": "INC-BATCH-OK",
            "category": "FLOODING",
            "description": "flood",
            "latitude": 15.4920,
            "longitude": 73.8185,
            "source": "DEMO",
            "status": "REPORTED",
            "created_at": now.isoformat(),
        },
    ]
    mock_repo.release_duplicate_scan_job_sync.return_value = {"released": True, "status": "PENDING"}
    mock_repo.record_duplicate_candidates_sync.return_value = {"links_created": 0, "total_links": 0}

    summary = recover_pending_cloud_duplicate_scans(mock_repo, state_store, settings, batch_size=10, lease_sec=60)
    assert summary["claimed_jobs"] == 2
    assert summary["retry_scheduled_count"] == 1
    assert summary["completed_count"] == 1
    # Crucial: claim was invoked strictly ONCE (no re-claim inside executor!)
    assert mock_repo.claim_duplicate_scan_jobs_sync.call_count == 1
    mock_repo.reset_mock()

    # Maintenance API endpoint also uses single claim
    mock_repo.claim_duplicate_scan_jobs_sync.side_effect = lambda lease_owner, incident_id=None, batch_size=20, lease_sec=120: [
        {"incident_id": "INC-BATCH-OK", "attempt_count": 1, "lease_owner": lease_owner}
    ]
    mock_repo.query_incident_by_id_sync.side_effect = None
    mock_repo.query_incident_by_id_sync.return_value = {
        "id": "INC-BATCH-OK",
        "category": "FLOODING",
        "description": "flood",
        "latitude": 15.4920,
        "longitude": 73.8185,
        "source": "DEMO",
        "status": "REPORTED",
        "created_at": now.isoformat(),
    }

    with patch("app.api.v1.incidents.persistence_repo", mock_repo):
        resp = admin_client.post("/api/v1/incidents/maintenance/recover-duplicate-scans")
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json()["claimed_jobs"] == 1
    assert resp.json()["completed_count"] == 1
    assert mock_repo.claim_duplicate_scan_jobs_sync.call_count == 1


def test_repository_rpc_sqlstate_mapping_and_validation():
    repo = PersistenceRepository(
        supabase_url="https://mock.supabase.co",
        supabase_key="anon",
        service_role_key="service_role_secret",
    )

    def _mock_post(code, body):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = code
        resp.json.return_value = body
        return resp

    with patch("httpx.Client.post", return_value=_mock_post(404, {"code": "02000", "message": "not found SECRET_DB_MSG"})):
        with pytest.raises(StorageNotFoundError) as exc_nf:
            repo.reset_duplicate_scan_job_sync("INC-1", "admin-1", "admin")
        assert exc_nf.value.sqlstate == "02000"
        assert "SECRET_DB_MSG" not in str(exc_nf.value)
        assert "reset_duplicate_scan_job_rpc" not in str(exc_nf.value)

    with patch("httpx.Client.post", return_value=_mock_post(409, {"code": "P0412", "message": "stale lease SECRET_LEASE"})):
        with pytest.raises(StorageLeaseLostError) as exc_ll:
            repo.record_duplicate_candidates_sync("INC-1", "SIMULATION", [], "dup_lease_" + "a" * 32)
        assert exc_ll.value.sqlstate == "P0412"
        assert "SECRET_LEASE" not in str(exc_ll.value)

    with patch("httpx.Client.post", return_value=_mock_post(400, {"code": "23514", "message": "chk_dup_canonical_pair_order"})):
        with pytest.raises(StorageConflictError) as exc_chk:
            repo.record_duplicate_candidates_sync("INC-1", "SIMULATION", [], "dup_lease_" + "a" * 32)
        assert not isinstance(exc_chk.value, StorageLeaseLostError)
        assert exc_chk.value.sqlstate == "23514"
        assert "chk_dup_canonical_pair_order" not in str(exc_chk.value)

    with patch("httpx.Client.post", return_value=_mock_post(409, {"code": "23505", "message": "uq_dup_single_confirmed_primary"})):
        with pytest.raises(StorageConflictError) as exc_uniq:
            repo.record_duplicate_candidates_sync("INC-1", "SIMULATION", [], "dup_lease_" + "a" * 32)
        assert exc_uniq.value.sqlstate == "23505"
        assert "uq_dup_single_confirmed_primary" not in str(exc_uniq.value)

    with patch("httpx.Client.post", return_value=_mock_post(400, {"code": "23503", "message": "incidents_fkey"})):
        with pytest.raises(StorageValidationError) as exc_fk:
            repo.record_duplicate_candidates_sync("INC-1", "SIMULATION", [], "dup_lease_" + "a" * 32)
        assert exc_fk.value.sqlstate == "23503"
        assert "incidents_fkey" not in str(exc_fk.value)

    with patch("httpx.Client.post", return_value=_mock_post(403, {"code": "42501", "message": "forbidden SECRET_ROLE"})):
        with pytest.raises(PermissionError) as exc_perm:
            repo.review_incident_duplicate_link_sync(
                "lnk_12345", "CONFIRMED", "actor", "municipality", "valid reason", "AUD-1", "AUD-2", "INC-1"
            )
        assert "SECRET_ROLE" not in str(exc_perm.value)

    with pytest.raises(StorageValidationError):
        repo.claim_duplicate_scan_jobs_sync("bad_lease_owner")

    with pytest.raises(StorageValidationError):
        repo.reset_duplicate_scan_job_sync("INC-1", "worker-1", "worker")


# ---------------------------------------------------------------------
# 8. REST API Endpoints, Single Scan Outside Lock & Partial Cloud 503
# ---------------------------------------------------------------------

def test_post_incidents_scans_once_outside_lock_and_is_non_fatal(client, monkeypatch):
    monkeypatch.setattr(settings, "SUPABASE_AUTH_ENABLED", False)

    # First baseline incident
    resp1 = client.post(
        "/api/v1/incidents",
        json={
            "category": "FLOODING",
            "description": "Road submerged near church gate",
            "latitude": 15.4920,
            "longitude": 73.8185,
            "severity": "HIGH",
            "source": "CITIZEN",
        },
    )
    assert resp1.status_code == status.HTTP_201_CREATED

    scan_calls = []
    from app.services import duplicate_detector as dd_mod

    orig_scan = dd_mod.scan_incident_for_duplicates

    def _spy_scan(inc_id, repo, store, cfg=settings):
        # Verify state_store._lock was ALREADY released before scanning runs
        acquired = store._lock.acquire(blocking=False)
        assert acquired is True, "Duplicate scan must run OUTSIDE state_store._lock"
        if acquired:
            store._lock.release()
        scan_calls.append(inc_id)
        return orig_scan(inc_id, repo, store, cfg)

    with patch("app.services.duplicate_detector.scan_incident_for_duplicates", side_effect=_spy_scan):
        resp2 = client.post(
            "/api/v1/incidents",
            json={
                "category": "FLOODING",
                "description": "Road submerged near church gate",
                "latitude": 15.4921,
                "longitude": 73.8186,
                "severity": "HIGH",
                "source": "CITIZEN",
            },
        )
    assert resp2.status_code == status.HTTP_201_CREATED
    inc2_id = resp2.json()["id"]
    assert scan_calls == [inc2_id]

    # Scan failure must NOT break incident submission (returns 201 Created)
    with patch("app.services.duplicate_detector.scan_incident_for_duplicates", side_effect=RuntimeError("boom")):
        resp3 = client.post(
            "/api/v1/incidents",
            json={
                "category": "FLOODING",
                "description": "Third report nearby",
                "latitude": 15.4922,
                "longitude": 73.8187,
                "severity": "HIGH",
                "source": "CITIZEN",
            },
        )
    assert resp3.status_code == status.HTTP_201_CREATED


def test_api_municipal_duplicate_queue_rbac_and_partial_cloud_503(client, citizen_client, municipal_client, admin_client):
    resp = client.get("/api/v1/incidents/municipal/duplicates")
    assert resp.status_code in (status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN)

    resp = citizen_client.get("/api/v1/incidents/municipal/duplicates")
    assert resp.status_code == status.HTTP_403_FORBIDDEN

    resp = municipal_client.get("/api/v1/incidents/municipal/duplicates")
    assert resp.status_code == status.HTTP_200_OK
    data = resp.json()
    assert "items" in data and "suspected_count" in data and "confirmed_count" in data

    # Unconfigured local mode returns 503 on cloud-only maintenance recovery
    resp_unconf = admin_client.post("/api/v1/incidents/maintenance/recover-duplicate-scans")
    assert resp_unconf.status_code == status.HTTP_503_SERVICE_UNAVAILABLE

    # D-02 Partial cloud config (is_configured=True, is_storage_configured=False) must fail closed 503
    partial_repo = PersistenceRepository(
        supabase_url="https://partial.supabase.co",
        supabase_key="anon_key_only",
        service_role_key=None,
    )
    assert partial_repo.is_configured is True
    assert partial_repo.is_storage_configured is False
    with patch("app.api.v1.incidents.persistence_repo", partial_repo):
        assert municipal_client.get("/api/v1/incidents/municipal/duplicates").status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        assert (
            municipal_client.post(
                "/api/v1/incidents/municipal/duplicates/lnk_missing/confirm",
                json={"primary_incident_id": "INC-1", "reason": "valid reason"},
            ).status_code
            == status.HTTP_503_SERVICE_UNAVAILABLE
        )


def test_api_confirm_and_dismiss_endpoints(municipal_client):
    inc1 = state_store.create_incident(
        IncidentResponseContract(
            id="INC-API-01",
            category=IncidentCategory.FLOODING,
            description="Flooding 1 near church",
            latitude=15.4920,
            longitude=73.8185,
            severity=IncidentSeverity.HIGH,
            source=IncidentSource.CITIZEN,
        )
    )
    inc2 = state_store.create_incident(
        IncidentResponseContract(
            id="INC-API-02",
            category=IncidentCategory.FLOODING,
            description="Flooding 2 near church",
            latitude=15.4921,
            longitude=73.8186,
            severity=IncidentSeverity.HIGH,
            source=IncidentSource.CITIZEN,
        )
    )

    scan_resp = municipal_client.post(f"/api/v1/incidents/{inc2.id}/duplicates/scan")
    assert scan_resp.status_code == status.HTTP_200_OK
    assert scan_resp.json()["links_created"] == 1

    links = state_store.get_incident_duplicate_links(inc2.id)
    assert len(links) == 1
    link_id = links[0].link_id

    # Confirm choosing inc1 as primary
    resp = municipal_client.post(
        f"/api/v1/incidents/municipal/duplicates/{link_id}/confirm",
        json={
            "primary_incident_id": inc1.id,
            "reason": "Confirmed via on-site video call",
            "expected_version": 0,
        },
    )
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json()["link_status"] == "CONFIRMED"
    assert resp.json()["primary_incident_id"] == inc1.id
    assert resp.json()["review_version"] == 1

    # Reversal without override fails closed with 409 Conflict
    resp_fail = municipal_client.post(
        f"/api/v1/incidents/municipal/duplicates/{link_id}/dismiss",
        json={"reason": "Dismiss without override"},
    )
    assert resp_fail.status_code == status.HTTP_409_CONFLICT

    # Stale expected_version fails closed with 409 Conflict
    resp_stale = municipal_client.post(
        f"/api/v1/incidents/municipal/duplicates/{link_id}/dismiss",
        json={"reason": "Valid reason", "override": True, "expected_version": 0},
    )
    assert resp_stale.status_code == status.HTTP_409_CONFLICT

    # Reversal with override and matching expected_version succeeds
    resp_rev = municipal_client.post(
        f"/api/v1/incidents/municipal/duplicates/{link_id}/dismiss",
        json={
            "reason": "Supervisor confirmed separate sewer lines",
            "override": True,
            "expected_version": 1,
        },
    )
    assert resp_rev.status_code == status.HTTP_200_OK
    assert resp_rev.json()["link_status"] == "DISMISSED"
    assert resp_rev.json()["review_version"] == 2

    # Redundant override on already DISMISSED link returns HTTP 400 (matching SQL 22023)
    resp_redun = municipal_client.post(
        f"/api/v1/incidents/municipal/duplicates/{link_id}/dismiss",
        json={
            "reason": "Trying redundant dismiss override",
            "override": True,
            "expected_version": 2,
        },
    )
    assert resp_redun.status_code == status.HTTP_400_BAD_REQUEST


def test_api_error_sanitization_no_secret_or_sql_leakage(municipal_client, caplog):
    """S1-AUD-01: raw PostgREST bodies, secrets, RPC names, and SQL constraint details never leak in HTTP responses or logs."""
    repo = PersistenceRepository(
        supabase_url="https://mock.supabase.co",
        supabase_key="anon-key-public",
        service_role_key="TOP_SECRET_SERVICE_KEY_999",
    )

    secret_markers = (
        "TOP_SECRET_SERVICE_KEY_999",
        "SECRET_SQL_TOKEN_ABC",
        "uq_dup_single_confirmed_primary",
        "chk_dup_canonical_pair_order",
        "public.incident_duplicate_links",
        "review_incident_duplicate_link_rpc",
        "SELECT * FROM",
        "victim@example.com",
        "+91-9876543210",
        "RAW_UPSTREAM_HTML_BODY",
        "UNHANDLED_INTERNAL_DB_PASS",
    )

    scenarios = [
        (400, {"code": "22023", "message": "bad param SECRET_SQL_TOKEN_ABC on review_incident_duplicate_link_rpc"}, 400),
        (403, {"code": "42501", "message": "permission denied for public.incident_duplicate_links"}, 403),
        (404, {"code": "02000", "message": "not found SECRET_SQL_TOKEN_ABC"}, 404),
        (409, {"code": "23505", "message": "duplicate key violates uq_dup_single_confirmed_primary"}, 409),
        (409, {"code": "23514", "message": "violates chk_dup_canonical_pair_order SELECT * FROM"}, 409),
        (409, {"code": "P0412", "message": "lease expired SECRET_SQL_TOKEN_ABC"}, 409),
        (404, {"code": "PGRST202", "message": "Could not find review_incident_duplicate_link_rpc"}, 503),
        (500, None, 503),
    ]

    with caplog.at_level(logging.WARNING), patch("app.api.v1.incidents.persistence_repo", repo):
        for http_code, json_body, expected_status in scenarios:
            fake_resp = MagicMock(spec=httpx.Response)
            fake_resp.status_code = http_code
            if json_body is not None:
                fake_resp.json.return_value = json_body
                fake_resp.text = str(json_body)
            else:
                fake_resp.json.side_effect = ValueError("not json")
                fake_resp.text = "RAW_UPSTREAM_HTML_BODY victim@example.com +91-9876543210 SECRET_SQL_TOKEN_ABC"

            with patch("app.services.persistence_repository.httpx.Client") as mock_client_cls:
                mock_client_cls.return_value.__enter__.return_value.post.return_value = fake_resp
                resp = municipal_client.post(
                    "/api/v1/incidents/municipal/duplicates/lnk_12345/confirm",
                    json={"primary_incident_id": "INC-1", "reason": "Confirmed after call"},
                )
            assert resp.status_code == expected_status
            for marker in secret_markers:
                assert marker not in resp.text

        for sensitive_log in ("TOP_SECRET_SERVICE_KEY_999", "SECRET_SQL_TOKEN_ABC", "RAW_UPSTREAM_HTML_BODY", "victim@example.com"):
            assert sensitive_log not in caplog.text

        # Unexpected internal exception must return generic 500 with zero leak
        with patch.object(
            repo,
            "review_incident_duplicate_link_sync",
            side_effect=KeyError("UNHANDLED_INTERNAL_DB_PASS"),
        ):
            resp_500 = municipal_client.post(
                "/api/v1/incidents/municipal/duplicates/lnk_12345/dismiss",
                json={"reason": "Confirmed distinct event"},
            )
        assert resp_500.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
        for marker in secret_markers:
            assert marker not in resp_500.text
        assert "TOP_SECRET_SERVICE_KEY_999" not in caplog.text


def test_api_worker_and_municipality_rbac_enforcement(municipal_client, monkeypatch):
    """S1-AUD-08: worker denied 403 on all duplicate endpoints; municipality denied 403 on maintenance endpoint."""
    monkeypatch.setattr(settings, "SUPABASE_AUTH_ENABLED", True)
    monkeypatch.setattr(settings, "SUPABASE_JWT_SECRET", "drainx-test-secret-for-unit-tests-only-2026")
    monkeypatch.setattr(settings, "SUPABASE_URL", "https://test-project.supabase.co")

    now = int(time.time())
    worker_jwt = jwt.encode(
        {
            "sub": "worker-1",
            "iss": "https://test-project.supabase.co/auth/v1",
            "aud": "authenticated",
            "iat": now,
            "exp": now + 3600,
            "role": "authenticated",
            "app_metadata": {"role": "worker", "team": "TEAM-ALPHA"},
            "user_metadata": {},
        },
        "drainx-test-secret-for-unit-tests-only-2026",
        algorithm="HS256",
    )
    worker_headers = {"Authorization": f"Bearer {worker_jwt}"}
    with TestClient(app, headers=worker_headers) as worker_client:
        assert worker_client.get("/api/v1/incidents/municipal/duplicates").status_code == status.HTTP_403_FORBIDDEN
        assert (
            worker_client.post(
                "/api/v1/incidents/municipal/duplicates/lnk_12345/confirm",
                json={"primary_incident_id": "INC-DEMO-01", "reason": "Unauthorized worker confirm"},
            ).status_code
            == status.HTTP_403_FORBIDDEN
        )
        assert (
            worker_client.post(
                "/api/v1/incidents/municipal/duplicates/lnk_12345/dismiss",
                json={"reason": "Unauthorized worker dismiss"},
            ).status_code
            == status.HTTP_403_FORBIDDEN
        )
        assert worker_client.get("/api/v1/incidents/INC-DEMO-01/duplicates").status_code == status.HTTP_403_FORBIDDEN
        assert worker_client.post("/api/v1/incidents/INC-DEMO-01/duplicates/scan").status_code == status.HTTP_403_FORBIDDEN
        assert worker_client.post("/api/v1/incidents/maintenance/recover-duplicate-scans").status_code == status.HTTP_403_FORBIDDEN

    assert (
        municipal_client.post("/api/v1/incidents/maintenance/recover-duplicate-scans").status_code
        == status.HTTP_403_FORBIDDEN
    )


def test_kill_switch_rescan_maintenance_and_recovery_loop(admin_client, municipal_client, monkeypatch, caplog):
    """S1-AUD-07 & S1-AUD-08: kill-switch honors disabled flag without DB reset/claim, and recovery loop logs tracebacks & gates properly."""
    mock_repo = MagicMock()
    mock_repo.is_configured = True
    mock_repo.is_storage_configured = True
    mock_repo.is_mock = False
    mock_repo.query_incident_by_id_sync.return_value = {
        "id": "INC-KILL-01",
        "category": "FLOODING",
        "description": "Drain flood",
        "latitude": 15.4920,
        "longitude": 73.8185,
        "severity": "HIGH",
        "status": "REPORTED",
        "source": "CITIZEN",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    monkeypatch.setattr(settings, "DUPLICATE_DETECTION_ENABLED", False)
    with patch("app.api.v1.incidents.persistence_repo", mock_repo), patch(
        "app.services.persistence_repository.persistence_repo", mock_repo
    ):
        maint_resp = admin_client.post("/api/v1/incidents/maintenance/recover-duplicate-scans")
        assert maint_resp.status_code == status.HTTP_200_OK
        assert maint_resp.json()["status"] == "DISABLED"
        assert maint_resp.json()["claimed_jobs"] == 0
        mock_repo.claim_duplicate_scan_jobs_sync.assert_not_called()

        rescan_resp = municipal_client.post("/api/v1/incidents/INC-KILL-01/duplicates/scan")
        assert rescan_resp.status_code == status.HTTP_200_OK
        assert rescan_resp.json()["status"] == "DISABLED"
        mock_repo.reset_duplicate_scan_job_sync.assert_not_called()
        mock_repo.claim_duplicate_scan_jobs_sync.assert_not_called()

    # Recovery loop: partial cloud must not call recover; errors log structured diagnostics + traceback & stay cancellable
    monkeypatch.setattr(settings, "DUPLICATE_DETECTION_ENABLED", True)
    monkeypatch.setattr(settings, "DUPLICATE_SCAN_RECOVERY_INTERVAL_SEC", 1.0)
    from app.main import duplicate_scan_recovery_loop

    partial_repo = MagicMock()
    partial_repo.is_configured = True
    partial_repo.is_storage_configured = False
    partial_repo.is_mock = False

    async def _run_partial_and_error_cases():
        sleep_calls = 0

        async def _fast_sleep(_sec):
            nonlocal sleep_calls
            sleep_calls += 1
            if sleep_calls >= 2:
                raise asyncio.CancelledError()

        with patch("app.services.persistence_repository.persistence_repo", partial_repo), patch(
            "app.services.duplicate_detector.recover_pending_cloud_duplicate_scans"
        ) as mock_rec, patch("asyncio.sleep", side_effect=_fast_sleep):
            await duplicate_scan_recovery_loop()
            mock_rec.assert_not_called()

        cloud_repo = PersistenceRepository(
            supabase_url="https://mock.supabase.co",
            supabase_key="anon",
            service_role_key="TOP_SECRET_RECOVERY_SERVICE_KEY",
        )
        fake_claim_err = MagicMock(spec=httpx.Response)
        fake_claim_err.status_code = 500
        fake_claim_err.json.side_effect = ValueError("not json")
        fake_claim_err.text = "SECRET_RECOVERY_LEAK_TOKEN TOP_SECRET_RECOVERY_SERVICE_KEY"

        async def _run_recovery_with_claim_failure():
            sleep_calls = 0

            async def _fast_sleep_err(_sec):
                nonlocal sleep_calls
                sleep_calls += 1
                if sleep_calls >= 3:
                    raise asyncio.CancelledError()

            def _boom_claim(*args, **kwargs):
                # Trigger real _call_rpc_sync sanitization before raising to main recovery loop
                return cloud_repo.claim_duplicate_scan_jobs_sync("dup_lease_" + "b" * 32)

            with patch("app.services.persistence_repository.persistence_repo", cloud_repo), patch(
                "app.services.persistence_repository.httpx.Client"
            ) as mock_client_cls, patch(
                "app.services.duplicate_detector.recover_pending_cloud_duplicate_scans",
                side_effect=_boom_claim,
            ), patch("asyncio.sleep", side_effect=_fast_sleep_err):
                mock_client_cls.return_value.__enter__.return_value.post.return_value = fake_claim_err
                await duplicate_scan_recovery_loop()

        await _run_recovery_with_claim_failure()

    with caplog.at_level(logging.ERROR):
        asyncio.run(_run_partial_and_error_cases())

    assert "Duplicate scan recovery sweep failed" in caplog.text
    assert "Traceback" in caplog.text
    assert "SECRET_RECOVERY_LEAK_TOKEN" not in caplog.text
    assert "TOP_SECRET_RECOVERY_SERVICE_KEY" not in caplog.text


# ---------------------------------------------------------------------
# 10. Stage 2A (S1-AUD-03): Municipal Duplicate Queue Privacy Tests
# ---------------------------------------------------------------------

_FORBIDDEN_DUPLICATE_PII_KEYS = {
    "internal_notes",
    "reporter_name",
    "assigned_worker_id",
    "verified_by",
    "verified_at",
    "rejection_reason",
    "photos",
}


def _collect_dict_keys_recursive(obj) -> set[str]:
    keys: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            keys.add(str(k))
            keys.update(_collect_dict_keys_recursive(v))
    elif isinstance(obj, list):
        for item in obj:
            keys.update(_collect_dict_keys_recursive(item))
    return keys


def test_stage2a_duplicate_contracts_forbid_extra_pii_fields():
    from pydantic import ValidationError

    expected_summary_fields = {
        "id",
        "category",
        "description",
        "latitude",
        "longitude",
        "severity",
        "status",
        "source",
        "origin_operational_mode",
        "assigned_to",
        "assignment_type",
        "assigned_team_id",
        "municipal_notes",
        "photo_count",
        "created_at",
        "updated_at",
    }
    assert set(MunicipalDuplicateIncidentSummaryContract.model_fields.keys()) == expected_summary_fields

    expected_link_fields = {
        "link_id",
        "incident_low_id",
        "incident_high_id",
        "link_status",
        "primary_incident_id",
        "duplicate_incident_id",
        "detection_origin",
        "detected_in_mode",
        "distance_meters",
        "time_delta_seconds",
        "confidence_score",
        "confidence_band",
        "match_reasons",
        "review_version",
        "reviewed_by",
        "reviewed_role",
        "reviewed_at",
        "review_reason",
        "created_at",
        "updated_at",
    }
    assert set(MunicipalDuplicateLinkContract.model_fields.keys()) == expected_link_fields
    assert "internal_notes" not in MunicipalDuplicateLinkContract.model_fields
    assert DuplicateLinkDetailContract.model_fields["link"].annotation is MunicipalDuplicateLinkContract

    now = datetime.now(timezone.utc)
    base_summary = {
        "id": "INC-ALLOW-01",
        "category": IncidentCategory.FLOODING,
        "description": "Flooded junction",
        "latitude": 15.4920,
        "longitude": 73.8185,
        "severity": IncidentSeverity.HIGH,
        "status": IncidentStatus.REPORTED,
        "source": IncidentSource.CITIZEN,
        "created_at": now,
        "updated_at": now,
    }
    for forbidden_key, bad_val in (
        ("reporter_name", "Secret Citizen"),
        ("internal_notes", "Secret Staff Note"),
        ("assigned_worker_id", "worker-secret-1"),
        ("verified_by", "verifier-secret-1"),
        ("verified_at", now),
        ("rejection_reason", "Secret Rejection"),
        ("photos", ["/uploads/incidents/secret.jpg"]),
    ):
        with pytest.raises(ValidationError):
            MunicipalDuplicateIncidentSummaryContract(**base_summary, **{forbidden_key: bad_val})

    with pytest.raises(ValidationError):
        MunicipalDuplicateLinkContract(
            link_id="lnk_allow_01",
            incident_low_id="INC-ALLOW-01",
            incident_high_id="INC-ALLOW-02",
            distance_meters=12.5,
            time_delta_seconds=60,
            confidence_score=0.88,
            confidence_band=DuplicateConfidenceBand.HIGH,
            internal_notes="Must be rejected by extra=forbid",
        )


def test_stage2a_duplicate_queue_and_per_incident_lookup_privacy_local_and_review(municipal_client):
    SENTINEL_REPORTER_A = "SENTINEL_REPORTER_MARIA_99101"
    SENTINEL_REPORTER_B = "SENTINEL_REPORTER_RAVI_99102"
    SENTINEL_INC_NOTE_A = "SENTINEL_INCIDENT_INTERNAL_NOTE_88201"
    SENTINEL_INC_NOTE_B = "SENTINEL_INCIDENT_INTERNAL_NOTE_88202"
    SENTINEL_LINK_NOTE = "SENTINEL_LINK_INTERNAL_NOTE_77301"
    SENTINEL_OVERRIDE_LINK_NOTE = "SENTINEL_OVERRIDE_LINK_INTERNAL_NOTE_77302"
    SENTINEL_EMAIL_DESC = "citizen.alpha.991@drainx-sentinel.invalid"
    SENTINEL_EMAIL_ASSIGN = "dispatcher.beta.992@drainx-sentinel.invalid"
    SENTINEL_EMAIL_MUNI = "supervisor.gamma.993@drainx-sentinel.invalid"
    SENTINEL_EMAIL_REASON = "reviewer.delta.994@drainx-sentinel.invalid"
    SENTINEL_PHONE_DESC = "+91-9876543211"
    SENTINEL_PHONE_ASSIGN = "9876543212"
    SENTINEL_PHONE_MUNI = "+91 98765 43213"
    SENTINEL_PHONE_REASON = "+91-9876543214"
    SENTINEL_WORKER_ID = "SENTINEL_WORKER_UUID_66401"
    SENTINEL_VERIFIER = "SENTINEL_VERIFIER_55501"
    SENTINEL_REJECTION = "SENTINEL_REJECTION_REASON_44601"
    SENTINEL_PHOTO_PATH = "/uploads/incidents/sentinel_secret_photo_33701.jpg"

    all_sentinels = [
        SENTINEL_REPORTER_A,
        SENTINEL_REPORTER_B,
        SENTINEL_INC_NOTE_A,
        SENTINEL_INC_NOTE_B,
        SENTINEL_LINK_NOTE,
        SENTINEL_OVERRIDE_LINK_NOTE,
        SENTINEL_EMAIL_DESC,
        SENTINEL_EMAIL_ASSIGN,
        SENTINEL_EMAIL_MUNI,
        SENTINEL_EMAIL_REASON,
        SENTINEL_PHONE_DESC,
        SENTINEL_PHONE_ASSIGN,
        SENTINEL_PHONE_MUNI,
        SENTINEL_PHONE_REASON,
        SENTINEL_WORKER_ID,
        SENTINEL_VERIFIER,
        SENTINEL_REJECTION,
        SENTINEL_PHOTO_PATH,
    ]

    inc1 = state_store.create_incident(
        IncidentResponseContract(
            id="INC-PRIV-01",
            category=IncidentCategory.FLOODING,
            description=f"Severe storm drain flooding near market; call {SENTINEL_PHONE_DESC} or {SENTINEL_EMAIL_DESC}",
            latitude=15.4920,
            longitude=73.8185,
            severity=IncidentSeverity.HIGH,
            status=IncidentStatus.ASSIGNED,
            source=IncidentSource.CITIZEN,
            origin_operational_mode="SIMULATION",
            assigned_to=f"Team Alpha ({SENTINEL_EMAIL_ASSIGN} / {SENTINEL_PHONE_ASSIGN})",
            assignment_type=AssignmentType.TEAM,
            assigned_team_id="TEAM-ALPHA",
            assigned_worker_id=SENTINEL_WORKER_ID,
            municipal_notes=f"Pump crew dispatched; contact {SENTINEL_EMAIL_MUNI} at {SENTINEL_PHONE_MUNI}",
            internal_notes=SENTINEL_INC_NOTE_A,
            reporter_name=SENTINEL_REPORTER_A,
            verified_by=SENTINEL_VERIFIER,
            verified_at=datetime.now(timezone.utc),
            rejection_reason=SENTINEL_REJECTION,
            photos=[SENTINEL_PHOTO_PATH],
        )
    )
    inc2 = state_store.create_incident(
        IncidentResponseContract(
            id="INC-PRIV-02",
            category=IncidentCategory.FLOODING,
            description="Second citizen report at market storm drain",
            latitude=15.4921,
            longitude=73.8186,
            severity=IncidentSeverity.HIGH,
            status=IncidentStatus.REPORTED,
            source=IncidentSource.CITIZEN,
            origin_operational_mode="SIMULATION",
            reporter_name=SENTINEL_REPORTER_B,
            internal_notes=SENTINEL_INC_NOTE_B,
        )
    )

    scan_resp = municipal_client.post(f"/api/v1/incidents/{inc2.id}/duplicates/scan")
    assert scan_resp.status_code == status.HTTP_200_OK
    assert scan_resp.json()["links_created"] == 1

    stored_links = state_store.get_incident_duplicate_links(inc1.id)
    assert len(stored_links) == 1
    link_id = stored_links[0].link_id

    confirm_resp = municipal_client.post(
        f"/api/v1/incidents/municipal/duplicates/{link_id}/confirm",
        json={
            "primary_incident_id": inc1.id,
            "reason": f"Confirmed via supervisor {SENTINEL_EMAIL_REASON} call {SENTINEL_PHONE_REASON}",
            "internal_notes": SENTINEL_LINK_NOTE,
            "expected_version": 0,
        },
    )
    assert confirm_resp.status_code == status.HTTP_200_OK
    confirm_json = confirm_resp.json()
    assert _collect_dict_keys_recursive(confirm_json).isdisjoint(_FORBIDDEN_DUPLICATE_PII_KEYS)
    for sentinel in all_sentinels:
        assert sentinel not in confirm_resp.text
    assert "[EMAIL REDACTED]" in confirm_json["review_reason"]
    assert "[PHONE REDACTED]" in confirm_json["review_reason"]
    assert confirm_json["link_status"] == "CONFIRMED"
    assert confirm_json["primary_incident_id"] == inc1.id
    assert confirm_json["duplicate_incident_id"] == inc2.id
    assert confirm_json["review_version"] == 1

    queue_resp = municipal_client.get("/api/v1/incidents/municipal/duplicates?status=CONFIRMED&limit=10&offset=0")
    assert queue_resp.status_code == status.HTTP_200_OK
    queue_json = queue_resp.json()
    assert queue_json["total"] == 1
    assert queue_json["confirmed_count"] == 1
    assert len(queue_json["items"]) == 1
    assert _collect_dict_keys_recursive(queue_json).isdisjoint(_FORBIDDEN_DUPLICATE_PII_KEYS)
    for sentinel in all_sentinels:
        assert sentinel not in queue_resp.text

    per_inc_resp = municipal_client.get(f"/api/v1/incidents/{inc1.id}/duplicates")
    assert per_inc_resp.status_code == status.HTTP_200_OK
    per_inc_json = per_inc_resp.json()
    assert len(per_inc_json) == 1
    assert _collect_dict_keys_recursive(per_inc_json).isdisjoint(_FORBIDDEN_DUPLICATE_PII_KEYS)
    for sentinel in all_sentinels:
        assert sentinel not in per_inc_resp.text

    # Queue endpoint and per-incident lookup endpoint must enforce the identical schema and privacy policy
    assert per_inc_json[0] == queue_json["items"][0]

    item = queue_json["items"][0]
    link_obj = item["link"]
    assert link_obj["link_id"] == link_id
    assert link_obj["incident_low_id"] == inc1.id
    assert link_obj["incident_high_id"] == inc2.id
    assert link_obj["link_status"] == "CONFIRMED"
    assert link_obj["confidence_score"] > 0.0
    assert link_obj["confidence_band"] in {"HIGH", "MEDIUM", "LOW"}
    assert link_obj["distance_meters"] >= 0.0
    assert link_obj["time_delta_seconds"] >= 0
    assert "[EMAIL REDACTED]" in link_obj["review_reason"]
    assert "[PHONE REDACTED]" in link_obj["review_reason"]

    low_summary = item["incident_low"]
    assert low_summary["id"] == inc1.id
    assert low_summary["category"] == "FLOODING"
    assert low_summary["latitude"] == 15.4920
    assert low_summary["longitude"] == 73.8185
    assert low_summary["severity"] == "HIGH"
    assert low_summary["status"] == "ASSIGNED"
    assert low_summary["source"] == "CITIZEN"
    assert low_summary["origin_operational_mode"] == "SIMULATION"
    assert low_summary["assignment_type"] == "TEAM"
    assert low_summary["assigned_team_id"] == "TEAM-ALPHA"
    assert low_summary["photo_count"] == 1
    assert "[EMAIL REDACTED]" in low_summary["description"]
    assert "[PHONE REDACTED]" in low_summary["description"]
    assert "[EMAIL REDACTED]" in low_summary["assigned_to"]
    assert "[PHONE REDACTED]" in low_summary["assigned_to"]
    assert "[EMAIL REDACTED]" in low_summary["municipal_notes"]
    assert "[PHONE REDACTED]" in low_summary["municipal_notes"]
    assert item["primary_incident"] == low_summary
    assert item["duplicate_incident"] == item["incident_high"]

    dismiss_resp = municipal_client.post(
        f"/api/v1/incidents/municipal/duplicates/{link_id}/dismiss",
        json={
            "reason": f"Override dismissal by {SENTINEL_EMAIL_REASON} ({SENTINEL_PHONE_REASON})",
            "internal_notes": SENTINEL_OVERRIDE_LINK_NOTE,
            "override": True,
            "expected_version": 1,
        },
    )
    assert dismiss_resp.status_code == status.HTTP_200_OK
    dismiss_json = dismiss_resp.json()
    assert _collect_dict_keys_recursive(dismiss_json).isdisjoint(_FORBIDDEN_DUPLICATE_PII_KEYS)
    for sentinel in all_sentinels:
        assert sentinel not in dismiss_resp.text
    assert "[EMAIL REDACTED]" in dismiss_json["review_reason"]
    assert "[PHONE REDACTED]" in dismiss_json["review_reason"]
    assert dismiss_json["link_status"] == "DISMISSED"
    assert dismiss_json["review_version"] == 2

    # Underlying state_store records remain non-destructive
    stored_inc1 = state_store.get_incident(inc1.id)
    assert stored_inc1 is not None
    assert stored_inc1.reporter_name == SENTINEL_REPORTER_A
    assert stored_inc1.internal_notes == SENTINEL_INC_NOTE_A
    assert state_store.get_incident_duplicate_links(inc1.id)[0].internal_notes == SENTINEL_OVERRIDE_LINK_NOTE


def test_stage2a_duplicate_privacy_cloud_path_and_uuid_actor_preservation(municipal_client, admin_client):
    now_iso = datetime.now(timezone.utc).isoformat()
    SENTINEL_REPORTER = "SENTINEL_CLOUD_REPORTER_99501"
    SENTINEL_INC_NOTE = "SENTINEL_CLOUD_INC_INTERNAL_99502"
    SENTINEL_LINK_NOTE = "SENTINEL_CLOUD_LINK_INTERNAL_99503"
    SENTINEL_PHOTO = "/uploads/incidents/cloud_sentinel_photo_99504.jpg"
    SENTINEL_WORKER = "SENTINEL_CLOUD_WORKER_99505"
    SENTINEL_VERIFIER = "SENTINEL_CLOUD_VERIFIER_99506"
    SENTINEL_REJECTION = "SENTINEL_CLOUD_REJECTION_99507"
    SENTINEL_ACTOR_EMAIL = "actor.leak@drainx-sentinel.invalid"
    SENTINEL_TEXT_EMAIL = "cloud.citizen@drainx-sentinel.invalid"
    SENTINEL_TEXT_PHONE = "+91-9876543299"
    UUID_ACTOR_ID = "550e8400-e29b-41d4-a716-446655440000"

    cloud_sentinels = [
        SENTINEL_REPORTER,
        SENTINEL_INC_NOTE,
        SENTINEL_LINK_NOTE,
        SENTINEL_PHOTO,
        SENTINEL_WORKER,
        SENTINEL_VERIFIER,
        SENTINEL_REJECTION,
        SENTINEL_ACTOR_EMAIL,
        SENTINEL_TEXT_EMAIL,
        SENTINEL_TEXT_PHONE,
    ]

    raw_incidents = {
        "INC-CLD-01": {
            "id": "INC-CLD-01",
            "category": "FLOODING",
            "description": f"Cloud incident 1 {SENTINEL_TEXT_EMAIL} {SENTINEL_TEXT_PHONE}",
            "latitude": 15.4920,
            "longitude": 73.8185,
            "severity": "HIGH",
            "status": "ASSIGNED",
            "source": "CITIZEN",
            "origin_operational_mode": "PHYSICAL",
            "assigned_to": f"Crew Lead ({SENTINEL_TEXT_EMAIL} {SENTINEL_TEXT_PHONE})",
            "assignment_type": "TEAM",
            "assigned_team_id": "TEAM-BRAVO",
            "assigned_worker_id": SENTINEL_WORKER,
            "municipal_notes": f"Notes {SENTINEL_TEXT_PHONE}",
            "internal_notes": SENTINEL_INC_NOTE,
            "reporter_name": SENTINEL_REPORTER,
            "verified_by": SENTINEL_VERIFIER,
            "verified_at": now_iso,
            "rejection_reason": SENTINEL_REJECTION,
            "photos": [SENTINEL_PHOTO],
            "created_at": now_iso,
            "updated_at": now_iso,
        },
        "INC-CLD-02": {
            "id": "INC-CLD-02",
            "category": "FLOODING",
            "description": "Cloud incident 2",
            "latitude": 15.4921,
            "longitude": 73.8186,
            "severity": "HIGH",
            "status": "REPORTED",
            "source": "CITIZEN",
            "origin_operational_mode": "PHYSICAL",
            "reporter_name": SENTINEL_REPORTER,
            "internal_notes": SENTINEL_INC_NOTE,
            "photos": [],
            "created_at": now_iso,
            "updated_at": now_iso,
        },
    }

    raw_link_uuid = {
        "link_id": "lnk_cld_privacy_01",
        "incident_low_id": "INC-CLD-01",
        "incident_high_id": "INC-CLD-02",
        "link_status": "CONFIRMED",
        "primary_incident_id": "INC-CLD-01",
        "duplicate_incident_id": "INC-CLD-02",
        "detection_origin": "AUTOMATED",
        "detected_in_mode": "PHYSICAL",
        "distance_meters": 14.2,
        "time_delta_seconds": 90,
        "confidence_score": 0.91,
        "confidence_band": "HIGH",
        "match_reasons": ["Spatial proximity", "Exact category match"],
        "review_version": 1,
        "reviewed_by": UUID_ACTOR_ID,
        "reviewed_role": "municipality",
        "reviewed_at": now_iso,
        "review_reason": f"Confirmed by {SENTINEL_TEXT_EMAIL} / {SENTINEL_TEXT_PHONE}",
        "internal_notes": SENTINEL_LINK_NOTE,
        "created_at": now_iso,
        "updated_at": now_iso,
    }
    raw_link_email = {
        **raw_link_uuid,
        "link_id": "lnk_cld_privacy_02",
        "link_status": "DISMISSED",
        "primary_incident_id": None,
        "duplicate_incident_id": None,
        "reviewed_by": SENTINEL_ACTOR_EMAIL,
    }

    mock_repo = MagicMock()
    mock_repo.is_configured = True
    mock_repo.is_storage_configured = True
    mock_repo.is_mock = False
    mock_repo.query_duplicate_links_sync.side_effect = lambda **kwargs: (
        [raw_link_uuid, raw_link_email],
        2,
    )
    mock_repo.query_duplicate_link_counts_sync.return_value = {
        "SUSPECTED": 0,
        "CONFIRMED": 1,
        "DISMISSED": 1,
    }
    mock_repo.query_duplicate_links_for_incident_sync.return_value = [raw_link_uuid, raw_link_email]
    mock_repo.query_incident_by_id_sync.side_effect = lambda inc_id: raw_incidents.get(inc_id)
    mock_repo.query_incidents_by_ids_sync.side_effect = lambda inc_ids, **kwargs: {
        inc_id: raw_incidents[inc_id]
        for inc_id in inc_ids
        if inc_id in raw_incidents
    }
    mock_repo.review_incident_duplicate_link_sync.return_value = raw_link_uuid

    with patch("app.api.v1.incidents.persistence_repo", mock_repo), patch(
        "app.services.persistence_repository.persistence_repo", mock_repo
    ):
        for test_client in (municipal_client, admin_client):
            q_resp = test_client.get("/api/v1/incidents/municipal/duplicates")
            assert q_resp.status_code == status.HTTP_200_OK
            q_json = q_resp.json()
            assert _collect_dict_keys_recursive(q_json).isdisjoint(_FORBIDDEN_DUPLICATE_PII_KEYS)
            for s in cloud_sentinels:
                assert s not in q_resp.text

            # UUID reviewed_by must remain intact (not corrupted by phone regex); email actor must be redacted
            assert q_json["items"][0]["link"]["reviewed_by"] == UUID_ACTOR_ID
            assert q_json["items"][1]["link"]["reviewed_by"] == "[EMAIL REDACTED]"

            d_resp = test_client.get("/api/v1/incidents/INC-CLD-01/duplicates")
            assert d_resp.status_code == status.HTTP_200_OK
            d_json = d_resp.json()
            assert _collect_dict_keys_recursive(d_json).isdisjoint(_FORBIDDEN_DUPLICATE_PII_KEYS)
            for s in cloud_sentinels:
                assert s not in d_resp.text
            assert d_json == q_json["items"]

        c_resp = municipal_client.post(
            "/api/v1/incidents/municipal/duplicates/lnk_cld_privacy_01/confirm",
            json={
                "primary_incident_id": "INC-CLD-01",
                "reason": "Cloud confirmation check",
                "internal_notes": SENTINEL_LINK_NOTE,
            },
        )
        assert c_resp.status_code == status.HTTP_200_OK
        assert _collect_dict_keys_recursive(c_resp.json()).isdisjoint(_FORBIDDEN_DUPLICATE_PII_KEYS)
        for s in cloud_sentinels:
            assert s not in c_resp.text


def test_stage2a_citizen_and_worker_cannot_access_duplicate_metadata(client, citizen_client, municipal_client, monkeypatch):
    SENTINEL_LINK_NOTE = "SENTINEL_CITIZEN_WORKER_LINK_NOTE_99601"
    SENTINEL_REVIEW_REASON = "supervisor.secret.996@drainx-sentinel.invalid"

    inc1 = state_store.create_incident(
        IncidentResponseContract(
            id="INC-ACCESS-01",
            category=IncidentCategory.DRAIN_BLOCKAGE,
            description="Public blockage 1",
            latitude=15.4920,
            longitude=73.8185,
            severity=IncidentSeverity.MEDIUM,
            source=IncidentSource.CITIZEN,
        )
    )
    inc2 = state_store.create_incident(
        IncidentResponseContract(
            id="INC-ACCESS-02",
            category=IncidentCategory.DRAIN_BLOCKAGE,
            description="Public blockage 2",
            latitude=15.4921,
            longitude=73.8186,
            severity=IncidentSeverity.MEDIUM,
            source=IncidentSource.CITIZEN,
        )
    )
    assert municipal_client.post(f"/api/v1/incidents/{inc2.id}/duplicates/scan").status_code == status.HTTP_200_OK
    link_id = state_store.get_incident_duplicate_links(inc1.id)[0].link_id
    assert (
        municipal_client.post(
            f"/api/v1/incidents/municipal/duplicates/{link_id}/confirm",
            json={
                "primary_incident_id": inc1.id,
                "reason": f"Reviewed by {SENTINEL_REVIEW_REASON}",
                "internal_notes": SENTINEL_LINK_NOTE,
            },
        ).status_code
        == status.HTTP_200_OK
    )

    monkeypatch.setattr(settings, "SUPABASE_AUTH_ENABLED", True)
    monkeypatch.setattr(settings, "SUPABASE_JWT_SECRET", "drainx-test-secret-for-unit-tests-only-2026")
    monkeypatch.setattr(settings, "SUPABASE_URL", "https://test-project.supabase.co")
    now = int(time.time())
    worker_jwt = jwt.encode(
        {
            "sub": "worker-access-1",
            "iss": "https://test-project.supabase.co/auth/v1",
            "aud": "authenticated",
            "iat": now,
            "exp": now + 3600,
            "role": "authenticated",
            "app_metadata": {"role": "worker", "team": "TEAM-ALPHA"},
            "user_metadata": {},
        },
        "drainx-test-secret-for-unit-tests-only-2026",
        algorithm="HS256",
    )

    duplicate_meta_keys = {
        "link_id",
        "link_status",
        "duplicate_links",
        "confidence_score",
        "confidence_band",
        "primary_incident_id",
        "duplicate_incident_id",
        "match_reasons",
        "review_version",
    }

    with TestClient(app, headers={"Authorization": f"Bearer {worker_jwt}"}) as worker_client:
        # Unauthenticated client rejected from both duplicate endpoints
        assert client.get("/api/v1/incidents/municipal/duplicates").status_code in (
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN,
        )
        assert client.get(f"/api/v1/incidents/{inc1.id}/duplicates").status_code in (
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN,
        )

        # Citizen and worker denied 403 on both duplicate endpoints
        for non_muni_client in (citizen_client, worker_client):
            assert non_muni_client.get("/api/v1/incidents/municipal/duplicates").status_code == status.HTTP_403_FORBIDDEN
            assert non_muni_client.get(f"/api/v1/incidents/{inc1.id}/duplicates").status_code == status.HTTP_403_FORBIDDEN

        # Standard incident endpoints must never expose municipal duplicate metadata
        for reader_client in (client, citizen_client, worker_client):
            list_resp = reader_client.get("/api/v1/incidents")
            assert list_resp.status_code == status.HTTP_200_OK
            assert _collect_dict_keys_recursive(list_resp.json()).isdisjoint(duplicate_meta_keys)
            assert SENTINEL_LINK_NOTE not in list_resp.text
            assert SENTINEL_REVIEW_REASON not in list_resp.text

            detail_resp = reader_client.get(f"/api/v1/incidents/{inc1.id}")
            assert detail_resp.status_code == status.HTTP_200_OK
            assert _collect_dict_keys_recursive(detail_resp.json()).isdisjoint(duplicate_meta_keys)
            assert SENTINEL_LINK_NOTE not in detail_resp.text
            assert SENTINEL_REVIEW_REASON not in detail_resp.text


# ---------------------------------------------------------------------
# 11. Stage 2B (S1-AUD-06): Locking, Bulk Cloud Reads, Counts & HTTP 416
# ---------------------------------------------------------------------


def _make_raw_cloud_incident(
    inc_id: str,
    *,
    status_val: str = "REPORTED",
    description: str = "Cloud storm drain issue",
    notes: str = "",
    updated_at: Optional[datetime] = None,
    with_sentinels: bool = False,
) -> dict[str, object]:
    now_iso = (updated_at or datetime.now(timezone.utc)).isoformat()
    desc = (
        f"Cloud hazard {description} +91-9876543210 citizen.{inc_id}@drainx-sentinel.invalid"
        if with_sentinels
        else description
    )
    return {
        "id": inc_id,
        "category": "FLOODING",
        "description": desc,
        "latitude": 15.4920,
        "longitude": 73.8185,
        "severity": "HIGH",
        "status": status_val,
        "source": "CITIZEN",
        "origin_operational_mode": "PHYSICAL",
        "assigned_to": f"Crew {inc_id} crew.{inc_id}@drainx-sentinel.invalid" if with_sentinels else None,
        "assignment_type": "TEAM" if with_sentinels else "NONE",
        "assigned_team_id": "TEAM-ALPHA" if with_sentinels else None,
        "assigned_worker_id": f"SENTINEL_WORKER_{inc_id}" if with_sentinels else None,
        "municipal_notes": f"Dispatch +91-9876500000 {notes}".strip() if with_sentinels else notes,
        "internal_notes": f"SENTINEL_INC_NOTE_{inc_id}" if with_sentinels else None,
        "reporter_name": f"SENTINEL_REPORTER_{inc_id}" if with_sentinels else "Citizen Anonymous",
        "verified_by": f"SENTINEL_VERIFIER_{inc_id}" if with_sentinels else None,
        "verified_at": now_iso if with_sentinels else None,
        "rejection_reason": f"SENTINEL_REJ_{inc_id}" if with_sentinels else None,
        "photos": [f"/uploads/incidents/sentinel_{inc_id}.jpg"] if with_sentinels else [],
        "created_at": now_iso,
        "updated_at": now_iso,
    }


def _make_raw_cloud_link(
    link_id: str,
    low_id: str,
    high_id: str,
    *,
    link_status: str = "SUSPECTED",
    created_at: Optional[datetime] = None,
    with_sentinels: bool = False,
) -> dict[str, object]:
    now_iso = (created_at or datetime.now(timezone.utc)).isoformat()
    lo, hi = canonicalize_incident_pair(low_id, high_id)
    is_conf = link_status == "CONFIRMED"
    is_rev = link_status in ("CONFIRMED", "DISMISSED")
    return {
        "link_id": link_id,
        "incident_low_id": lo,
        "incident_high_id": hi,
        "link_status": link_status,
        "primary_incident_id": lo if is_conf else None,
        "duplicate_incident_id": hi if is_conf else None,
        "detection_origin": "AUTOMATED",
        "detected_in_mode": "PHYSICAL",
        "distance_meters": 15.0,
        "time_delta_seconds": 120,
        "confidence_score": 0.90,
        "confidence_band": "HIGH",
        "match_reasons": ["CATEGORY_EXACT"],
        "review_version": 1 if is_rev else 0,
        "reviewed_by": "550e8400-e29b-41d4-a716-446655440000" if is_rev else None,
        "reviewed_role": "municipality" if is_rev else None,
        "reviewed_at": now_iso if is_rev else None,
        "review_reason": (
            f"Reviewed review.{link_id}@drainx-sentinel.invalid +91-9876599999"
            if (is_rev and with_sentinels)
            else ("Confirmed" if is_rev else None)
        ),
        "internal_notes": f"SENTINEL_LINK_NOTE_{link_id}" if with_sentinels else None,
        "created_at": now_iso,
        "updated_at": now_iso,
    }


def test_stage2b_cloud_io_runs_outside_statestore_lock():
    """S1-AUD-06A: Cloud single and bulk incident queries never hold StateStore._lock during network I/O."""
    inc_id = "INC-LOCK-01"
    bulk_id = "INC-LOCK-02"
    raw_row_1 = _make_raw_cloud_incident(inc_id)
    raw_row_2 = _make_raw_cloud_incident(bulk_id)

    mock_repo = MagicMock()
    mock_repo.is_configured = True
    mock_repo.is_storage_configured = True

    # 1. Single incident read (get_incident(..., authoritative_cloud=True))
    single_entered = threading.Event()
    single_release = threading.Event()
    lock_free_observations: dict[str, bool] = {}

    def _blocking_single(target_id: str):
        single_entered.set()
        assert single_release.wait(timeout=5.0), "Timed out waiting to release single cloud read"
        return raw_row_1 if target_id == inc_id else None

    mock_repo.query_incident_by_id_sync.side_effect = _blocking_single
    mock_repo.query_incidents_by_ids_sync.side_effect = lambda ids, **kw: {
        i: raw_row_2 for i in ids if i == bulk_id
    }

    with patch("app.services.persistence_repository.persistence_repo", mock_repo):
        result_box: list[object] = []
        t1 = threading.Thread(
            target=lambda: result_box.append(
                state_store.get_incident(inc_id, authoritative_cloud=True)
            )
        )
        t1.start()
        assert single_entered.wait(timeout=5.0)

        # From a separate thread, StateStore._lock MUST be uncontended while Thread 1 is in cloud I/O
        def _probe_lock(label: str):
            acquired = state_store._lock.acquire(blocking=False)
            lock_free_observations[label] = acquired
            if acquired:
                state_store._lock.release()
            # Mode isolation + incident listing remain responsive while cloud read is in flight
            _ = state_store.get_incidents()
            ok, _ = state_store.set_mode("PHYSICAL", reason="Lock-free read check")
            assert ok is True

        t2 = threading.Thread(target=lambda: _probe_lock("single"))
        t2.start()
        t2.join(timeout=5.0)
        assert lock_free_observations["single"] is True
        assert state_store.is_physical() is True
        single_release.set()
        t1.join(timeout=5.0)

        assert len(result_box) == 1 and result_box[0] is not None
        assert result_box[0].id == inc_id
        state_store.set_mode("SIMULATION", reason="Restore simulation mode")

        # 2. Bulk incident read (get_incidents_by_ids(..., authoritative_cloud=True))
        bulk_entered = threading.Event()
        bulk_release = threading.Event()

        def _blocking_bulk(ids, **kwargs):
            bulk_entered.set()
            assert bulk_release.wait(timeout=5.0), "Timed out waiting to release bulk cloud read"
            return {i: raw_row_2 for i in ids if i == bulk_id}

        mock_repo.query_incident_by_id_sync.side_effect = None
        mock_repo.query_incidents_by_ids_sync.side_effect = _blocking_bulk

        bulk_box: list[object] = []
        t3 = threading.Thread(
            target=lambda: bulk_box.append(
                state_store.get_incidents_by_ids([bulk_id], authoritative_cloud=True)
            )
        )
        t3.start()
        assert bulk_entered.wait(timeout=5.0)

        t4 = threading.Thread(target=lambda: _probe_lock("bulk"))
        t4.start()
        t4.join(timeout=5.0)
        assert lock_free_observations["bulk"] is True
        assert state_store.is_physical() is True
        bulk_release.set()
        t3.join(timeout=5.0)

        assert bulk_box[0][bulk_id] is not None
        assert bulk_box[0][bulk_id].id == bulk_id
        state_store.set_mode("SIMULATION", reason="Restore simulation mode")


def test_stage2b_stale_cloud_read_does_not_overwrite_concurrent_local_update():
    """S1-AUD-06A: Stale cloud snapshots never overwrite newer concurrent local updates, while sequential authoritative reads win."""
    t0 = datetime(2026, 11, 22, 10, 0, 0, tzinfo=timezone.utc)
    inc = state_store.create_incident(
        IncidentResponseContract(
            id="INC-RACE-UPD",
            category=IncidentCategory.FLOODING,
            description="Initial report",
            latitude=15.4920,
            longitude=73.8185,
            severity=IncidentSeverity.MEDIUM,
            status=IncidentStatus.REPORTED,
            source=IncidentSource.CITIZEN,
            created_at=t0,
            updated_at=t0,
        )
    )
    stale_cloud_row = _make_raw_cloud_incident(
        inc.id,
        status_val="REPORTED",
        description="Initial report",
        notes="",
        updated_at=t0,
    )

    mock_repo = MagicMock()
    mock_repo.is_configured = True
    mock_repo.is_storage_configured = True
    mock_repo.execute_municipal_incident_transaction_sync.return_value = {"id": inc.id}

    single_entered = threading.Event()
    single_release = threading.Event()

    def _stale_single(target_id: str):
        single_entered.set()
        assert single_release.wait(timeout=5.0)
        return stale_cloud_row

    mock_repo.query_incident_by_id_sync.side_effect = _stale_single

    with patch("app.services.persistence_repository.persistence_repo", mock_repo):
        res_box: list[Optional[IncidentResponseContract]] = []
        t_read = threading.Thread(
            target=lambda: res_box.append(
                state_store.get_incident(inc.id, authoritative_cloud=True)
            )
        )
        t_read.start()
        assert single_entered.wait(timeout=5.0)

        updated = state_store.update_incident(
            inc.id,
            IncidentUpdateContract(
                status=IncidentStatus.VERIFIED,
                municipal_notes="Newer local update",
            ),
            actor_id="muni-race-1",
            actor_role="municipality",
            action_reason="Verify while cloud read in flight",
        )
        assert updated is not None and updated.status == IncidentStatus.VERIFIED
        single_release.set()
        t_read.join(timeout=5.0)

        # Newer local mutation must win against stale concurrent cloud read
        assert state_store._incidents[inc.id].status == IncidentStatus.VERIFIED
        assert state_store._incidents[inc.id].municipal_notes == "Newer local update"
        assert res_box[0] is not None
        assert res_box[0].status == IncidentStatus.VERIFIED

        # Now repeat via get_incidents_by_ids while another update occurs concurrently
        bulk_entered = threading.Event()
        bulk_release = threading.Event()

        def _stale_bulk(ids, **kwargs):
            bulk_entered.set()
            assert bulk_release.wait(timeout=5.0)
            return {inc.id: stale_cloud_row}

        mock_repo.query_incidents_by_ids_sync.side_effect = _stale_bulk
        bulk_res: list[dict[str, Optional[IncidentResponseContract]]] = []
        t_bulk = threading.Thread(
            target=lambda: bulk_res.append(
                state_store.get_incidents_by_ids([inc.id], authoritative_cloud=True)
            )
        )
        t_bulk.start()
        assert bulk_entered.wait(timeout=5.0)

        updated2 = state_store.update_incident(
            inc.id,
            IncidentUpdateContract(municipal_notes="Second concurrent local update"),
            actor_id="muni-race-2",
            actor_role="municipality",
            action_reason="Concurrent note update",
        )
        assert updated2 is not None
        bulk_release.set()
        t_bulk.join(timeout=5.0)

        assert state_store._incidents[inc.id].municipal_notes == "Second concurrent local update"
        assert bulk_res[0][inc.id].municipal_notes == "Second concurrent local update"

        # Without a concurrent mutation, authoritative_cloud=True updates local cache with newer cloud state
        t_cloud_newer = datetime(2026, 11, 22, 12, 0, 0, tzinfo=timezone.utc)
        newer_cloud_row = _make_raw_cloud_incident(
            inc.id,
            status_val="RESOLVED",
            notes="Authoritative cloud resolution",
            updated_at=t_cloud_newer,
        )
        mock_repo.query_incident_by_id_sync.side_effect = lambda target_id: newer_cloud_row
        auth_read = state_store.get_incident(inc.id, authoritative_cloud=True)
        assert auth_read is not None and auth_read.status == IncidentStatus.RESOLVED
        assert state_store._incidents[inc.id].status == IncidentStatus.RESOLVED


def test_stage2b_concurrent_incident_deletion_and_create_races():
    """S1-AUD-06A: Concurrent deletion is never resurrected by pre-delete cloud reads, and non-concurrent cloud deletions evict."""
    t0 = datetime(2026, 11, 22, 10, 0, 0, tzinfo=timezone.utc)
    inc_del_1 = state_store.create_incident(
        IncidentResponseContract(
            id="INC-DEL-01",
            category=IncidentCategory.FLOODING,
            description="To delete via delete_incident",
            latitude=15.4920,
            longitude=73.8185,
            severity=IncidentSeverity.MEDIUM,
            source=IncidentSource.CITIZEN,
            created_at=t0,
            updated_at=t0,
        )
    )
    inc_del_2 = state_store.create_incident(
        IncidentResponseContract(
            id="INC-DEL-02",
            category=IncidentCategory.FLOODING,
            description="To delete directly under lock",
            latitude=15.4921,
            longitude=73.8186,
            severity=IncidentSeverity.MEDIUM,
            source=IncidentSource.CITIZEN,
            created_at=t0,
            updated_at=t0,
        )
    )
    inc_evict = state_store.create_incident(
        IncidentResponseContract(
            id="INC-EVICT-03",
            category=IncidentCategory.FLOODING,
            description="Missing in cloud without concurrent local write",
            latitude=15.4922,
            longitude=73.8187,
            severity=IncidentSeverity.MEDIUM,
            source=IncidentSource.CITIZEN,
            created_at=t0,
            updated_at=t0,
        )
    )

    mock_repo = MagicMock()
    mock_repo.is_configured = True
    mock_repo.is_storage_configured = True

    entered = threading.Event()
    release = threading.Event()

    def _cloud_slow_fetch(ids, **kwargs):
        entered.set()
        assert release.wait(timeout=5.0)
        out = {}
        if inc_del_1.id in ids:
            out[inc_del_1.id] = _make_raw_cloud_incident(inc_del_1.id, updated_at=t0)
        if inc_del_2.id in ids:
            out[inc_del_2.id] = _make_raw_cloud_incident(inc_del_2.id, updated_at=t0)
        # INC-CREATE-04 and INC-EVICT-03 intentionally absent from cloud response
        return out

    def _cloud_single_fetch(tid: str):
        entered.set()
        assert release.wait(timeout=5.0)
        return _make_raw_cloud_incident(tid, updated_at=t0)

    mock_repo.query_incidents_by_ids_sync.side_effect = _cloud_slow_fetch
    mock_repo.query_incident_by_id_sync.side_effect = _cloud_single_fetch
    mock_repo.execute_citizen_incident_creation_sync.side_effect = (
        lambda **kw: {"id": kw["incident_id"]}
    )

    with patch("app.services.persistence_repository.persistence_repo", mock_repo):
        # Case A & B & C via bulk read
        box: list[dict[str, Optional[IncidentResponseContract]]] = []
        t_bulk = threading.Thread(
            target=lambda: box.append(
                state_store.get_incidents_by_ids(
                    [inc_del_1.id, inc_del_2.id, inc_evict.id, "INC-CREATE-04"],
                    authoritative_cloud=True,
                )
            )
        )
        t_bulk.start()
        assert entered.wait(timeout=5.0)

        assert state_store.delete_incident(inc_del_1.id) is True
        with state_store._lock:
            state_store._incidents.pop(inc_del_2.id, None)
        created_concurrent = state_store.create_incident(
            IncidentResponseContract(
                id="INC-CREATE-04",
                category=IncidentCategory.FLOODING,
                description="Created concurrently",
                latitude=15.4923,
                longitude=73.8188,
                severity=IncidentSeverity.MEDIUM,
                source=IncidentSource.CITIZEN,
            )
        )
        release.set()
        t_bulk.join(timeout=5.0)

        res_map = box[0]
        assert inc_del_1.id not in state_store._incidents
        assert inc_del_2.id not in state_store._incidents
        assert res_map[inc_del_1.id] is None
        assert res_map[inc_del_2.id] is None
        # Concurrent local create not evicted when cloud response lacked it
        assert "INC-CREATE-04" in state_store._incidents
        assert res_map["INC-CREATE-04"] is not None
        assert res_map["INC-CREATE-04"].id == created_concurrent.id
        # Non-concurrent cloud absence evicts stale local cache entry cleanly
        assert inc_evict.id not in state_store._incidents
        assert res_map[inc_evict.id] is None

        # Repeat deletion race via single get_incident
        entered.clear()
        release.clear()
        inc_del_single = state_store.create_incident(
            IncidentResponseContract(
                id="INC-DEL-SINGLE",
                category=IncidentCategory.FLOODING,
                description="Delete single race",
                latitude=15.4924,
                longitude=73.8189,
                severity=IncidentSeverity.MEDIUM,
                source=IncidentSource.CITIZEN,
                created_at=t0,
                updated_at=t0,
            )
        )
        s_box: list[Optional[IncidentResponseContract]] = []
        t_s = threading.Thread(
            target=lambda: s_box.append(
                state_store.get_incident(inc_del_single.id, authoritative_cloud=True)
            )
        )
        t_s.start()
        assert entered.wait(timeout=5.0)
        assert state_store.delete_incident(inc_del_single.id) is True
        release.set()
        t_s.join(timeout=5.0)
        assert inc_del_single.id not in state_store._incidents
        assert s_box[0] is None


def test_stage2b_cloud_duplicate_queue_bounded_bulk_requests_and_privacy(municipal_client):
    """S1-AUD-06B & S1-AUD-03: Queue uses bounded constant HTTP requests independent of N and enforces Stage 2A privacy."""
    cloud_repo = PersistenceRepository(
        supabase_url="https://mock.supabase.co",
        supabase_key="anon",
        service_role_key="TOP_SECRET_SERVICE_KEY_999",
    )

    def _run_queue_for_n(n_links: int, *, status_query: Optional[str] = None):
        links = []
        incidents_db: dict[str, dict[str, object]] = {}
        t_base = datetime(2026, 11, 22, 10, 0, 0, tzinfo=timezone.utc)

        for idx in range(n_links):
            lo_id = f"INC-B{n_links:02d}-{idx:03d}-A"
            hi_id = f"INC-B{n_links:02d}-{idx:03d}-B"
            links.append(
                _make_raw_cloud_link(
                    f"lnk_b{n_links:02d}_{idx:03d}",
                    lo_id,
                    hi_id,
                    link_status="CONFIRMED" if idx == 0 else "SUSPECTED",
                    created_at=t_base - timedelta(seconds=idx),
                    with_sentinels=True,
                )
            )
            incidents_db[lo_id] = _make_raw_cloud_incident(lo_id, with_sentinels=True)
            # Leave final incident missing from cloud to test partial unavailability safely
            if idx != (n_links - 1):
                incidents_db[hi_id] = _make_raw_cloud_incident(hi_id, with_sentinels=True)

        recorded_calls: list[tuple[str, str, dict[str, str], dict[str, str]]] = []

        class _FakeClient:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def get(self, url: str, headers=None, params=None):
                req_params = dict(params or {})
                req_headers = dict(headers or {})
                recorded_calls.append(("GET", url, req_params, req_headers))
                req = httpx.Request("GET", url, params=req_params, headers=req_headers)
                if url.endswith("/rest/v1/incident_duplicate_links"):
                    matched_links = links
                    if "link_status" in req_params:
                        target_st = req_params["link_status"].replace("eq.", "")
                        matched_links = [l for l in links if l["link_status"] == target_st]
                    return httpx.Response(
                        200,
                        json=matched_links,
                        headers={"Content-Range": f"0-{max(0, len(matched_links) - 1)}/{len(matched_links)}"},
                        request=req,
                    )
                if url.endswith("/rest/v1/incidents"):
                    in_expr = req_params.get("id", "")
                    assert in_expr.startswith("in.(") and in_expr.endswith(")")
                    wanted = set(in_expr[4:-1].split(",")) if len(in_expr) > 5 else set()
                    rows = [incidents_db[i] for i in sorted(wanted) if i in incidents_db]
                    return httpx.Response(200, json=rows, request=req)
                raise AssertionError(f"Unexpected URL: {url}")

            def head(self, url: str, headers=None, params=None):
                req_params = dict(params or {})
                req_headers = dict(headers or {})
                recorded_calls.append(("HEAD", url, req_params, req_headers))
                req = httpx.Request("HEAD", url, params=req_params, headers=req_headers)
                target_st = req_params.get("link_status", "").replace("eq.", "")
                cnt = sum(1 for l in links if l["link_status"] == target_st)
                return httpx.Response(200, headers={"Content-Range": f"*/{cnt}"}, request=req)

        with patch("app.api.v1.incidents.persistence_repo", cloud_repo), patch(
            "app.services.persistence_repository.persistence_repo", cloud_repo
        ), patch("app.services.persistence_repository.httpx.Client", _FakeClient):
            path = "/api/v1/incidents/municipal/duplicates?limit=50&offset=0"
            if status_query:
                path += f"&status={status_query}"
            resp = municipal_client.get(path)
            assert resp.status_code == status.HTTP_200_OK
            return resp, recorded_calls

    # Page of N=25 links (50 incident references, 1 missing incident)
    resp_25, calls_25 = _run_queue_for_n(25)
    body_25 = resp_25.json()
    assert len(body_25["items"]) == 25
    assert body_25["items"][-1]["incident_high"] is None
    assert body_25["items"][0]["incident_low"]["photo_count"] == 1
    assert _collect_dict_keys_recursive(body_25).isdisjoint(_FORBIDDEN_DUPLICATE_PII_KEYS)
    assert "SENTINEL_" not in resp_25.text
    assert "+91-9876543210" not in resp_25.text
    assert "drainx-sentinel.invalid" not in resp_25.text
    assert "[EMAIL REDACTED]" in resp_25.text
    assert "[PHONE REDACTED]" in resp_25.text

    assert sum(1 for m, u, _, _ in calls_25 if m == "GET" and u.endswith("/incident_duplicate_links")) == 1
    assert sum(1 for m, u, _, _ in calls_25 if m == "HEAD" and u.endswith("/incident_duplicate_links")) == 3
    assert sum(1 for m, u, _, _ in calls_25 if m == "GET" and u.endswith("/incidents")) == 1
    assert len(calls_25) == 5

    # Page of N=50 links (100 incident references) -> IDENTICAL 5-request bound (no N+1 scaling)
    resp_50, calls_50 = _run_queue_for_n(50)
    assert len(resp_50.json()["items"]) == 50
    assert sum(1 for m, u, _, _ in calls_50 if m == "GET" and u.endswith("/incidents")) == 1
    assert len(calls_50) == 5

    # Filtered queue reuses the page total for that status and skips one HEAD count (4 total requests)
    resp_filt, calls_filt = _run_queue_for_n(25, status_query="SUSPECTED")
    assert resp_filt.json()["total"] == 24
    assert resp_filt.json()["suspected_count"] == 24
    assert sum(1 for m, u, _, _ in calls_filt if m == "HEAD" and u.endswith("/incident_duplicate_links")) == 2
    assert len(calls_filt) == 4

    # Per-incident duplicates lookup with 10 links also uses a single bulk lookup for counterparts
    target_id = "INC-PER-TARGET"
    per_links = [
        _make_raw_cloud_link(f"lnk_per_{i:02d}", target_id, f"INC-PER-OTHER-{i:02d}", with_sentinels=True)
        for i in range(10)
    ]
    per_incidents = {target_id: _make_raw_cloud_incident(target_id, with_sentinels=True)}
    for i in range(10):
        oid = f"INC-PER-OTHER-{i:02d}"
        per_incidents[oid] = _make_raw_cloud_incident(oid, with_sentinels=True)

    per_calls: list[tuple[str, str]] = []

    class _PerIncClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def get(self, url: str, headers=None, params=None):
            per_calls.append((url, str(params)))
            req = httpx.Request("GET", url)
            if url.endswith("/rest/v1/incident_duplicate_links"):
                return httpx.Response(200, json=per_links, request=req)
            if "?id=eq." in url:
                return httpx.Response(200, json=[per_incidents[target_id]], request=req)
            if url.endswith("/rest/v1/incidents"):
                in_expr = (params or {}).get("id", "")
                wanted = in_expr[4:-1].split(",")
                assert target_id not in wanted  # Target was preloaded and excluded from bulk query
                return httpx.Response(
                    200,
                    json=[per_incidents[i] for i in wanted if i in per_incidents],
                    request=req,
                )
            raise AssertionError(f"Unexpected URL: {url}")

    with patch("app.api.v1.incidents.persistence_repo", cloud_repo), patch(
        "app.services.persistence_repository.persistence_repo", cloud_repo
    ), patch("app.services.persistence_repository.httpx.Client", _PerIncClient):
        per_resp = municipal_client.get(f"/api/v1/incidents/{target_id}/duplicates")
        assert per_resp.status_code == status.HTTP_200_OK
        assert len(per_resp.json()) == 10
        assert "SENTINEL_" not in per_resp.text
        # 1 single existence lookup + 1 links lookup + 1 bulk counterparts lookup = 3 requests total (NOT 12+!)
        assert len(per_calls) == 3

    # Verify query_incidents_by_ids_sync respects URL-length and count chunk bounds for 200 max-length 32-char IDs
    chunk_calls: list[int] = []
    long_ids = [f"INC_{i:028d}" for i in range(200)]

    class _ChunkClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def get(self, url: str, headers=None, params=None):
            in_expr = (params or {}).get("id", "")
            assert len(in_expr) <= 4010
            batch_ids = in_expr[4:-1].split(",")
            chunk_calls.append(len(batch_ids))
            req = httpx.Request("GET", url)
            return httpx.Response(
                200,
                json=[_make_raw_cloud_incident(bid) for bid in batch_ids],
                request=req,
            )

    with patch("app.services.persistence_repository.httpx.Client", _ChunkClient):
        chunked_rows = cloud_repo.query_incidents_by_ids_sync(long_ids)
        assert len(chunked_rows) == 200
        assert len(chunk_calls) <= 2


def test_stage2b_counts_accurate_above_1000_without_truncation(municipal_client):
    """S1-AUD-06C: Exact PostgreSQL counts work accurately above 1,000 without fetching all rows."""
    cloud_repo = PersistenceRepository(
        supabase_url="https://mock.supabase.co",
        supabase_key="anon",
        service_role_key="TOP_SECRET_SERVICE_KEY_999",
    )
    sample_link = _make_raw_cloud_link("lnk_big_01", "INC-BIG-01", "INC-BIG-02", link_status="SUSPECTED")
    observed_requests: list[tuple[str, str, dict[str, str], dict[str, str]]] = []

    class _LargeDatasetClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def get(self, url: str, headers=None, params=None):
            req_params = dict(params or {})
            req_headers = dict(headers or {})
            observed_requests.append(("GET", url, req_params, req_headers))
            req = httpx.Request("GET", url, params=req_params, headers=req_headers)
            if url.endswith("/rest/v1/incident_duplicate_links"):
                if req_params.get("link_status") == "eq.SUSPECTED":
                    return httpx.Response(206, json=[sample_link], headers={"Content-Range": "0-0/1250"}, request=req)
                return httpx.Response(206, json=[sample_link], headers={"Content-Range": "0-49/1900"}, request=req)
            if url.endswith("/rest/v1/incidents"):
                return httpx.Response(
                    200,
                    json=[
                        _make_raw_cloud_incident("INC-BIG-01"),
                        _make_raw_cloud_incident("INC-BIG-02"),
                    ],
                    request=req,
                )
            raise AssertionError(f"Unexpected GET {url}")

        def head(self, url: str, headers=None, params=None):
            req_params = dict(params or {})
            req_headers = dict(headers or {})
            observed_requests.append(("HEAD", url, req_params, req_headers))
            req = httpx.Request("HEAD", url, params=req_params, headers=req_headers)
            counts = {"eq.SUSPECTED": 1250, "eq.CONFIRMED": 430, "eq.DISMISSED": 220}
            cnt = counts[req_params["link_status"]]
            return httpx.Response(200, headers={"Content-Range": f"*/{cnt}"}, request=req)

    with patch("app.api.v1.incidents.persistence_repo", cloud_repo), patch(
        "app.services.persistence_repository.persistence_repo", cloud_repo
    ), patch("app.services.persistence_repository.httpx.Client", _LargeDatasetClient):
        resp = municipal_client.get("/api/v1/incidents/municipal/duplicates?limit=50&offset=0")
        assert resp.status_code == status.HTTP_200_OK
        data = resp.json()
        assert data["total"] == 1900
        assert data["suspected_count"] == 1250
        assert data["confirmed_count"] == 430
        assert data["dismissed_count"] == 220

        # Ensure no limit=1000 / Range=0-999 full-table scan occurred
        for _, _, _, hdrs in observed_requests:
            assert hdrs.get("Range") != "0-999"

        observed_requests.clear()
        resp_f = municipal_client.get("/api/v1/incidents/municipal/duplicates?status=SUSPECTED&limit=50&offset=0")
        assert resp_f.status_code == status.HTTP_200_OK
        df = resp_f.json()
        assert df["total"] == 1250
        assert df["suspected_count"] == 1250
        assert df["confirmed_count"] == 430
        assert df["dismissed_count"] == 220
        assert sum(1 for m, _, _, _ in observed_requests if m == "HEAD") == 2


def test_stage2b_pagination_empty_final_out_of_range_and_tie_breaking(municipal_client):
    """S1-AUD-06C & S1-AUD-06D: Deterministic tie-breaking prevents drops/duplicates across local and cloud pages."""
    # 1. Local pagination with 12 links sharing the exact same created_at timestamp
    same_ts = datetime(2026, 11, 22, 9, 30, 0, tzinfo=timezone.utc)
    expected_ids: list[str] = []
    for idx in range(12):
        lo = f"INC-TIE-L-{idx:02d}"
        hi = f"INC-TIE-H-{idx:02d}"
        for inc_id in (lo, hi):
            state_store.create_incident(
                IncidentResponseContract(
                    id=inc_id,
                    category=IncidentCategory.FLOODING,
                    description=f"Tie test {inc_id}",
                    latitude=15.4920,
                    longitude=73.8185,
                    severity=IncidentSeverity.MEDIUM,
                    source=IncidentSource.CITIZEN,
                    created_at=same_ts,
                    updated_at=same_ts,
                )
            )
        link_id = f"lnk_tie_{11 - idx:02d}"
        expected_ids.append(link_id)
        assert state_store.record_duplicate_link(
            DuplicateLinkContract(
                link_id=link_id,
                incident_low_id=lo,
                incident_high_id=hi,
                link_status=DuplicateLinkStatus.SUSPECTED,
                detected_in_mode="SIMULATION",
                distance_meters=10.0,
                time_delta_seconds=0,
                confidence_score=0.95,
                confidence_band=DuplicateConfidenceBand.HIGH,
                match_reasons=["CATEGORY_EXACT"],
                created_at=same_ts,
                updated_at=same_ts,
            )
        )

    p1 = municipal_client.get("/api/v1/incidents/municipal/duplicates?limit=5&offset=0").json()
    p2 = municipal_client.get("/api/v1/incidents/municipal/duplicates?limit=5&offset=5").json()
    p3 = municipal_client.get("/api/v1/incidents/municipal/duplicates?limit=5&offset=10").json()
    p4 = municipal_client.get("/api/v1/incidents/municipal/duplicates?limit=5&offset=15").json()

    assert [len(p1["items"]), len(p2["items"]), len(p3["items"]), len(p4["items"])] == [5, 5, 2, 0]
    collected = [
        item["link"]["link_id"]
        for page in (p1, p2, p3)
        for item in page["items"]
    ]
    assert collected == sorted(expected_ids)
    assert len(set(collected)) == 12
    assert p4["total"] == 12 and p4["suspected_count"] == 12

    # 2. Cloud pagination: empty page, final partial page, out-of-range HTTP 416 page, and order tie-breaker
    cloud_repo = PersistenceRepository(
        supabase_url="https://mock.supabase.co",
        supabase_key="anon",
        service_role_key="TOP_SECRET_SERVICE_KEY_999",
    )
    all_55 = [
        _make_raw_cloud_link(f"lnk_pg_{i:02d}", f"INC-PG-A-{i:02d}", f"INC-PG-B-{i:02d}", created_at=same_ts)
        for i in range(55)
    ]
    inc_lookup = {
        inc_id: _make_raw_cloud_incident(inc_id)
        for l in all_55
        for inc_id in (str(l["incident_low_id"]), str(l["incident_high_id"]))
    }
    scenario_total = 55
    incident_gets = 0
    observed_orders: list[str] = []

    class _PagingClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def get(self, url: str, headers=None, params=None):
            nonlocal incident_gets
            req = httpx.Request("GET", url)
            if url.endswith("/rest/v1/incident_duplicate_links"):
                observed_orders.append((params or {}).get("order", ""))
                rng = (headers or {}).get("Range", "0-19")
                start, end = [int(x) for x in rng.split("-")]
                dataset = all_55[:scenario_total]
                if scenario_total == 0 or start >= len(dataset):
                    return httpx.Response(416, headers={"Content-Range": f"*/{len(dataset)}"}, request=req)
                sliced = dataset[start : end + 1]
                return httpx.Response(
                    206,
                    json=sliced,
                    headers={"Content-Range": f"{start}-{start + len(sliced) - 1}/{len(dataset)}"},
                    request=req,
                )
            if url.endswith("/rest/v1/incidents"):
                incident_gets += 1
                in_expr = (params or {}).get("id", "")
                wanted = in_expr[4:-1].split(",")
                return httpx.Response(200, json=[inc_lookup[i] for i in wanted if i in inc_lookup], request=req)
            raise AssertionError(f"Unexpected GET {url}")

        def head(self, url: str, headers=None, params=None):
            req = httpx.Request("HEAD", url)
            target_st = (params or {}).get("link_status", "").replace("eq.", "")
            cnt = scenario_total if target_st == "SUSPECTED" else 0
            return httpx.Response(200, headers={"Content-Range": f"*/{cnt}"}, request=req)

    with patch("app.api.v1.incidents.persistence_repo", cloud_repo), patch(
        "app.services.persistence_repository.persistence_repo", cloud_repo
    ), patch("app.services.persistence_repository.httpx.Client", _PagingClient):
        # Final partial page: 55 total, limit=20, offset=40 -> 15 items
        final_resp = municipal_client.get("/api/v1/incidents/municipal/duplicates?limit=20&offset=40")
        assert final_resp.status_code == status.HTTP_200_OK
        assert len(final_resp.json()["items"]) == 15
        assert final_resp.json()["total"] == 55
        assert incident_gets == 1

        # Out-of-range page: offset=60 -> HTTP 416 */55 -> API HTTP 200 with empty items, total=55, 0 incident lookups
        incident_gets = 0
        oor_resp = municipal_client.get("/api/v1/incidents/municipal/duplicates?limit=20&offset=60")
        assert oor_resp.status_code == status.HTTP_200_OK
        assert oor_resp.json()["items"] == []
        assert oor_resp.json()["total"] == 55
        assert incident_gets == 0

        # Empty table returning HTTP 416 */0 at offset=0 -> API HTTP 200 with items=[], total=0
        scenario_total = 0
        empty_resp = municipal_client.get("/api/v1/incidents/municipal/duplicates?limit=20&offset=0")
        assert empty_resp.status_code == status.HTTP_200_OK
        assert empty_resp.json()["items"] == []
        assert empty_resp.json()["total"] == 0
        assert observed_orders and all(o == "created_at.desc,link_id.asc" for o in observed_orders)


def test_stage2b_http_416_contract_and_error_distinction(municipal_client):
    """S1-AUD-06D: Valid EOF/empty HTTP 416 returns empty page safely, while malformed 416 and other HTTP/network errors fail closed."""
    cloud_repo = PersistenceRepository(
        supabase_url="https://mock.supabase.co",
        supabase_key="anon",
        service_role_key="TOP_SECRET_SERVICE_KEY_999",
    )

    def _call_with_response(resp_or_exc, *, offset: int = 50, limit: int = 20):
        class _SingleRespClient:
            def __init__(self, *args, **kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def get(self, url: str, headers=None, params=None):
                if isinstance(resp_or_exc, Exception):
                    raise resp_or_exc
                return resp_or_exc

            def head(self, url: str, headers=None, params=None):
                if isinstance(resp_or_exc, Exception):
                    raise resp_or_exc
                req = httpx.Request("HEAD", url)
                return httpx.Response(200, headers={"Content-Range": "*/25"}, request=req)

        with patch("app.services.persistence_repository.httpx.Client", _SingleRespClient):
            return cloud_repo.query_duplicate_links_sync(limit=limit, offset=offset)

    # Valid HTTP 416 contracts
    assert _call_with_response(httpx.Response(416, headers={"Content-Range": "*/25"}), offset=50) == ([], 25)
    assert _call_with_response(httpx.Response(416, headers={"Content-Range": "*/0"}), offset=0) == ([], 0)
    assert _call_with_response(httpx.Response(416, headers={"Content-Range": "items */25"}), offset=50) == ([], 25)

    # Ambiguous/invalid HTTP 416 contracts must fail closed with StorageError (never silently return empty)
    for bad_416, bad_offset in (
        (httpx.Response(416, headers={}), 50),
        (httpx.Response(416, headers={"Content-Range": "*/*"}), 50),
        (httpx.Response(416, headers={"Content-Range": "*/100"}), 10),
    ):
        with pytest.raises(StorageError):
            _call_with_response(bad_416, offset=bad_offset)

    # Full page missing Content-Range must fail closed instead of silently reporting partial total
    with pytest.raises(StorageError):
        _call_with_response(
            httpx.Response(200, json=[{"link_id": f"lnk_{i:02d}"} for i in range(20)], headers={}),
            offset=0,
            limit=20,
        )

    # Unrelated HTTP / network failures remain strictly distinguishable from empty results
    with pytest.raises(StorageValidationError):
        _call_with_response(httpx.Response(400, text="bad range syntax"))
    for err_resp in (
        httpx.Response(401, text="unauthorized"),
        httpx.Response(403, text="forbidden"),
        httpx.Response(500, text="SECRET_DB_INTERNAL_ERROR"),
        httpx.Response(503, text="service unavailable"),
        httpx.ConnectTimeout("timeout"),
    ):
        with pytest.raises(StorageError):
            _call_with_response(err_resp)

    # Verify API layer maps malformed 416 and 500 to HTTP 503 and invalid status filter to HTTP 400 (not 200 empty)
    class _MalformedApi416Client:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def get(self, url: str, headers=None, params=None):
            return httpx.Response(416, headers={"Content-Range": "*/*"}, request=httpx.Request("GET", url))

    with patch("app.api.v1.incidents.persistence_repo", cloud_repo), patch(
        "app.services.persistence_repository.persistence_repo", cloud_repo
    ), patch("app.services.persistence_repository.httpx.Client", _MalformedApi416Client):
        bad_api_resp = municipal_client.get("/api/v1/incidents/municipal/duplicates?offset=50")
        assert bad_api_resp.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
        invalid_status_resp = municipal_client.get("/api/v1/incidents/municipal/duplicates?status=BOGUS")
        assert invalid_status_resp.status_code == status.HTTP_400_BAD_REQUEST


def test_stage2b_local_and_cloud_duplicate_queue_schema_parity(municipal_client):
    """S1-AUD-06: Local and cloud modes produce identical queue and per-incident JSON schemas across all pagination states."""
    t_base = datetime(2026, 11, 22, 8, 0, 0, tzinfo=timezone.utc)
    pair_specs = [
        ("lnk_par_01", "INC-PAR-01A", "INC-PAR-01B", "SUSPECTED", t_base),
        ("lnk_par_02", "INC-PAR-02A", "INC-PAR-02B", "CONFIRMED", t_base - timedelta(seconds=10)),
        ("lnk_par_03", "INC-PAR-03A", "INC-PAR-03B", "DISMISSED", t_base - timedelta(seconds=20)),
    ]

    raw_cloud_links: list[dict[str, object]] = []
    raw_cloud_incidents: dict[str, dict[str, object]] = {}

    for link_id, a_id, b_id, st, ts in pair_specs:
        for inc_id in (a_id, b_id):
            raw_inc = _make_raw_cloud_incident(
                inc_id,
                status_val="ASSIGNED" if st == "CONFIRMED" else "REPORTED",
                description=f"Parity {inc_id}",
                updated_at=ts,
                with_sentinels=True,
            )
            raw_inc["created_at"] = ts.isoformat()
            raw_cloud_incidents[inc_id] = raw_inc
            state_store.create_incident(IncidentResponseContract.model_validate(raw_inc))

        raw_lnk = _make_raw_cloud_link(link_id, a_id, b_id, link_status=st, created_at=ts, with_sentinels=True)
        raw_cloud_links.append(raw_lnk)
        assert state_store.record_duplicate_link(DuplicateLinkContract.model_validate(raw_lnk))

    queries = [
        "/api/v1/incidents/municipal/duplicates?limit=2&offset=0",
        "/api/v1/incidents/municipal/duplicates?limit=2&offset=2",
        "/api/v1/incidents/municipal/duplicates?limit=2&offset=10",
        "/api/v1/incidents/municipal/duplicates?status=CONFIRMED&limit=10&offset=0",
        "/api/v1/incidents/INC-PAR-01A/duplicates",
    ]
    local_responses = {q: municipal_client.get(q) for q in queries}
    for resp in local_responses.values():
        assert resp.status_code == status.HTTP_200_OK

    cloud_repo = PersistenceRepository(
        supabase_url="https://mock.supabase.co",
        supabase_key="anon",
        service_role_key="TOP_SECRET_SERVICE_KEY_999",
    )

    class _ParityClient:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def get(self, url: str, headers=None, params=None):
            req = httpx.Request("GET", url)
            req_params = dict(params or {})
            if url.endswith("/rest/v1/incident_duplicate_links"):
                if "or" in req_params:
                    matched = [
                        l for l in raw_cloud_links
                        if l["incident_low_id"] == "INC-PAR-01A" or l["incident_high_id"] == "INC-PAR-01A"
                    ]
                    return httpx.Response(200, json=matched, request=req)
                dataset = raw_cloud_links
                if "link_status" in req_params:
                    st = req_params["link_status"].replace("eq.", "")
                    dataset = [l for l in raw_cloud_links if l["link_status"] == st]
                start, end = [int(x) for x in (headers or {})["Range"].split("-")]
                if start >= len(dataset):
                    return httpx.Response(416, headers={"Content-Range": f"*/{len(dataset)}"}, request=req)
                sliced = dataset[start : end + 1]
                return httpx.Response(
                    206,
                    json=sliced,
                    headers={"Content-Range": f"{start}-{start + len(sliced) - 1}/{len(dataset)}"},
                    request=req,
                )
            if "?id=eq." in url:
                target_id = url.split("?id=eq.")[1].split("&")[0]
                row = raw_cloud_incidents.get(target_id)
                return httpx.Response(200, json=[row] if row else [], request=req)
            if url.endswith("/rest/v1/incidents"):
                wanted = req_params["id"][4:-1].split(",")
                return httpx.Response(
                    200,
                    json=[raw_cloud_incidents[i] for i in wanted if i in raw_cloud_incidents],
                    request=req,
                )
            raise AssertionError(f"Unexpected GET {url}")

        def head(self, url: str, headers=None, params=None):
            req = httpx.Request("HEAD", url)
            st = (params or {})["link_status"].replace("eq.", "")
            cnt = sum(1 for l in raw_cloud_links if l["link_status"] == st)
            return httpx.Response(200, headers={"Content-Range": f"*/{cnt}"}, request=req)

    # Clear local incident cache before cloud pass so hydration comes purely from cloud bulk lookup
    with state_store._lock:
        state_store._incidents.clear()
        state_store._duplicate_links.clear()

    with patch("app.api.v1.incidents.persistence_repo", cloud_repo), patch(
        "app.services.persistence_repository.persistence_repo", cloud_repo
    ), patch("app.services.persistence_repository.httpx.Client", _ParityClient):
        for q in queries:
            cloud_resp = municipal_client.get(q)
            assert cloud_resp.status_code == status.HTTP_200_OK
            assert cloud_resp.json() == local_responses[q].json()
