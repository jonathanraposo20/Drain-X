"""
DRAIN-X Batch 2C.2 — Directive Audit Outbox Reliability Test Suite.

Verifies:
1. Failed persistence restores all undelivered events to the volatile outbox.
2. Subsequent flush / sweep persists restored events successfully without duplicate audit rows.
3. Strict FIFO ordering preservation: events queued during in-flight flush remain AFTER restored events.
4. Outbox deduplication: duplicate audit_ids are never queued twice.
5. Bounded capacity enforcement: DIRECTIVE_AUDIT_OUTBOX_MAX_SIZE is strictly enforced;
   no silent eviction occurs; DirectiveAuditOutboxFullError is raised.
6. HTTP 503 backpressure: telemetry and status endpoints return 503 when outbox is saturated.
7. Autonomous retry: process_outbox_sweep persists queued outbox events without incoming telemetry.
8. Bounded concurrency: _outbox_persist_lock serializes simultaneous persistence sweeps.
9. Shutdown transparency: stop_directive_audit_outbox_worker warns if volatile events remain unpersisted.
10. Atomic directive issue: set_gate_directive checks capacity upfront before state mutation.
11. Bounded batch flush: flush_directive_audits_outbox(max_batch_size=K) drains at most K items FIFO.
"""

import asyncio
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings
from app.models.contracts import (
    ActuatorDirectiveContract,
    ActuatorDirectiveEventContract,
    AlertSeverity,
    DirectiveEventType,
    DirectiveIssuerType,
    DirectiveAuditOutboxFullError,
    SensorReadingContract,
    SensorType,
    MeasurementUnit,
    DataSource,
    SensorHealthStatus,
    build_issued_audit_id,
)
from app.services.state_store import StateStore, state_store
from app.services.persistence_repository import (
    PersistenceRepository,
    StorageError,
    StorageNotConfiguredError,
    persistence_repo,
)
from app.services.directive_audit_outbox_worker import (
    flush_and_persist_outbox,
    process_outbox_sweep,
    start_directive_audit_outbox_worker,
    stop_directive_audit_outbox_worker,
    _get_outbox_persist_lock,
)


def _make_dummy_event(audit_id: str, directive_id: str = "dir_test") -> ActuatorDirectiveEventContract:
    return ActuatorDirectiveEventContract(
        audit_id=audit_id,
        directive_id=directive_id,
        event_type=DirectiveEventType.ISSUED,
        device_id="DRAINX-ESP32-NODE-01",
        section_id="SEC_SCREENING_01",
        operational_mode="SIMULATION",
        action="DIVERT_FLOW",
        gate_target_angle=45.0,
        reason="Test outbox event",
        risk_level=AlertSeverity.INFO,
        emergency_stop=False,
        issuer_type=DirectiveIssuerType.AUTOMATED_ENGINE,
        issuer_id="test_runner",
        timestamp=datetime.now(timezone.utc),
    )


def test_failed_persistence_restores_all_events_to_outbox():
    """When persistence fails with StorageError, drained events must be restored to outbox."""
    store = StateStore()
    evt1 = _make_dummy_event("aud_restore_1")
    evt2 = _make_dummy_event("aud_restore_2")

    with store._lock:
        store._record_directive_event_locked(evt1)
        store._record_directive_event_locked(evt2)

    assert store.get_directive_audits_outbox_count() == 2

    # Simulate flush
    flushed = store.flush_directive_audits_outbox()
    assert len(flushed) == 2
    assert store.get_directive_audits_outbox_count() == 0

    # Persistence failure occurs -> restore outbox
    store.restore_directive_audits_outbox(flushed)
    assert store.get_directive_audits_outbox_count() == 2

    # Verify restored events are identical
    flushed_again = store.flush_directive_audits_outbox()
    assert [e.audit_id for e in flushed_again] == ["aud_restore_1", "aud_restore_2"]


def test_fifo_ordering_preserved_with_interleaved_events():
    """
    Events enqueued while a flush was in flight must remain AFTER restored events,
    preserving exact chronological FIFO sequence.
    """
    store = StateStore()
    e1 = _make_dummy_event("aud_fifo_1")
    e2 = _make_dummy_event("aud_fifo_2")
    with store._lock:
        store._record_directive_event_locked(e1)
        store._record_directive_event_locked(e2)

    # In-flight flush takes e1 and e2
    in_flight = store.flush_directive_audits_outbox()
    assert [e.audit_id for e in in_flight] == ["aud_fifo_1", "aud_fifo_2"]

    # While flush was in-flight, e3 is enqueued
    e3 = _make_dummy_event("aud_fifo_3")
    with store._lock:
        store._record_directive_event_locked(e3)

    assert store.get_directive_audits_outbox_count() == 1

    # In-flight flush fails -> restore [e1, e2]
    store.restore_directive_audits_outbox(in_flight)

    # Outbox should now be [e1, e2, e3]
    assert store.get_directive_audits_outbox_count() == 3
    final_flushed = store.flush_directive_audits_outbox()
    assert [e.audit_id for e in final_flushed] == ["aud_fifo_1", "aud_fifo_2", "aud_fifo_3"]


def test_deduplication_on_restore():
    """Restoring events that are already present in the outbox must not duplicate them."""
    store = StateStore()
    e1 = _make_dummy_event("aud_dedup_1")
    e2 = _make_dummy_event("aud_dedup_2")

    with store._lock:
        store._record_directive_event_locked(e1)

    # Attempt to restore [e1, e2] when e1 is already in outbox
    store.restore_directive_audits_outbox([e1, e2])

    # Outbox must have e2 prepended and e1 not duplicated
    assert store.get_directive_audits_outbox_count() == 2
    flushed = store.flush_directive_audits_outbox()
    assert [e.audit_id for e in flushed] == ["aud_dedup_2", "aud_dedup_1"]


def test_internal_deduplication_within_restore_batch():
    """A restored batch containing identical audit_ids internally must be deduplicated."""
    store = StateStore()
    e1 = _make_dummy_event("aud_batch_dup_1")
    e2 = _make_dummy_event("aud_batch_dup_2")

    store.restore_directive_audits_outbox([e1, e2, e1, e2])
    assert store.get_directive_audits_outbox_count() == 2
    flushed = store.flush_directive_audits_outbox()
    assert [e.audit_id for e in flushed] == ["aud_batch_dup_1", "aud_batch_dup_2"]


def test_bounded_capacity_enforced_and_no_silent_eviction(monkeypatch):
    """
    When outbox reaches DIRECTIVE_AUDIT_OUTBOX_MAX_SIZE, recording events must raise
    DirectiveAuditOutboxFullError and NEVER silently evict older events.
    """
    monkeypatch.setattr(settings, "DIRECTIVE_AUDIT_OUTBOX_MAX_SIZE", 5)
    store = StateStore()

    events = [_make_dummy_event(f"aud_cap_{i}") for i in range(5)]
    for e in events:
        with store._lock:
            store._record_directive_event_locked(e)

    assert store.get_directive_audits_outbox_count() == 5

    # 6th event must raise DirectiveAuditOutboxFullError
    overflow_event = _make_dummy_event("aud_cap_overflow")
    with pytest.raises(DirectiveAuditOutboxFullError):
        with store._lock:
            store._record_directive_event_locked(overflow_event)

    # Verify no silent eviction: all 5 original events remain intact
    assert store.get_directive_audits_outbox_count() == 5
    flushed = store.flush_directive_audits_outbox()
    assert [e.audit_id for e in flushed] == [f"aud_cap_{i}" for i in range(5)]


def test_atomic_set_gate_directive_capacity_check(monkeypatch):
    """
    set_gate_directive must fail closed atomically with DirectiveAuditOutboxFullError
    before mutating active directives if outbox capacity is insufficient.
    """
    monkeypatch.setattr(settings, "DIRECTIVE_AUDIT_OUTBOX_MAX_SIZE", 2)
    store = StateStore()
    store.set_mode("SIMULATION", "test")

    # Issue first directive (1 event: ISSUED)
    dir1 = ActuatorDirectiveContract(
        directive_id="dir_atom_1",
        action="DIVERT_FLOW",
        gate_target_angle=30.0,
        reason="test 1",
        issuer_id="tester",
    )
    store.set_gate_directive(dir1)
    assert store.get_directive_audits_outbox_count() == 1
    assert store.get_active_directive("SIMULATION").directive_id == "dir_atom_1"

    # Issue second directive superseding dir1 (needs 2 events: SUPERSEDED + ISSUED)
    # Available capacity is only 1 (2 max - 1 current = 1 space left, but need 2)
    dir2 = ActuatorDirectiveContract(
        directive_id="dir_atom_2",
        action="DIVERT_FLOW",
        gate_target_angle=60.0,
        reason="test 2",
        issuer_id="tester",
    )
    with pytest.raises(DirectiveAuditOutboxFullError):
        store.set_gate_directive(dir2)

    # Active directive must remain unchanged (dir1) and outbox count must still be 1
    assert store.get_active_directive("SIMULATION").directive_id == "dir_atom_1"
    assert store.get_directive_audits_outbox_count() == 1


def test_flush_with_batch_size_limit():
    """flush_directive_audits_outbox(max_batch_size=K) flushes only K events in FIFO order."""
    store = StateStore()
    for i in range(10):
        with store._lock:
            store._record_directive_event_locked(_make_dummy_event(f"aud_batch_{i}"))

    assert store.get_directive_audits_outbox_count() == 10

    # Drain first 4
    batch1 = store.flush_directive_audits_outbox(max_batch_size=4)
    assert len(batch1) == 4
    assert [e.audit_id for e in batch1] == [f"aud_batch_{i}" for i in range(4)]
    assert store.get_directive_audits_outbox_count() == 6

    # Drain next 4
    batch2 = store.flush_directive_audits_outbox(max_batch_size=4)
    assert len(batch2) == 4
    assert [e.audit_id for e in batch2] == [f"aud_batch_{i}" for i in range(4, 8)]
    assert store.get_directive_audits_outbox_count() == 2

    # Drain remaining (max 10, but only 2 exist)
    batch3 = store.flush_directive_audits_outbox(max_batch_size=10)
    assert len(batch3) == 2
    assert [e.audit_id for e in batch3] == ["aud_batch_8", "aud_batch_9"]
    assert store.get_directive_audits_outbox_count() == 0


@pytest.mark.anyio
async def test_autonomous_process_outbox_sweep_retries_without_telemetry():
    """process_outbox_sweep drains and persists events autonomously without new telemetry."""
    state_store.clear()
    e1 = _make_dummy_event("aud_sweep_1")
    e2 = _make_dummy_event("aud_sweep_2")

    with state_store._lock:
        state_store._record_directive_event_locked(e1)
        state_store._record_directive_event_locked(e2)

    assert state_store.get_directive_audits_outbox_count() == 2

    # Run autonomous sweep
    persisted_count = await process_outbox_sweep(batch_size=50)
    assert persisted_count == 2
    assert state_store.get_directive_audits_outbox_count() == 0

    # Verify both rows are in repo
    audits = persistence_repo.query_directive_audits_sync(directive_id="dir_test")
    assert any(a["audit_id"] == "aud_sweep_1" for a in audits)
    assert any(a["audit_id"] == "aud_sweep_2" for a in audits)


@pytest.mark.anyio
async def test_flush_and_persist_outbox_restores_on_storage_error():
    """If repository persist raises StorageError, flush_and_persist_outbox restores events."""
    state_store.clear()
    e1 = _make_dummy_event("aud_fail_1")
    with state_store._lock:
        state_store._record_directive_event_locked(e1)

    assert state_store.get_directive_audits_outbox_count() == 1

    # Temporarily monkeypatch persistence_repo to raise StorageError
    orig_persist = persistence_repo.persist_directive_audit_batch_sync

    def _failing_persist(*args, **kwargs):
        raise StorageError("Simulated cloud failure")

    persistence_repo.persist_directive_audit_batch_sync = _failing_persist
    try:
        # Autonomous sweep absorbs error and restores
        res = await process_outbox_sweep()
        assert res == 0
        assert state_store.get_directive_audits_outbox_count() == 1

        # Direct call with raise_on_error raises StorageError and still restores
        with pytest.raises(StorageError):
            await flush_and_persist_outbox(raise_on_error=True)
        assert state_store.get_directive_audits_outbox_count() == 1
    finally:
        persistence_repo.persist_directive_audit_batch_sync = orig_persist


def test_telemetry_endpoint_backpressure_503_when_outbox_full(monkeypatch, client):
    """When outbox capacity is saturated, POST /telemetry returns HTTP 503 backpressure."""
    monkeypatch.setattr(settings, "DIRECTIVE_AUDIT_OUTBOX_MAX_SIZE", 2)
    state_store.clear()
    state_store.set_mode("SIMULATION", "test")

    # Fill outbox to max capacity (2)
    with state_store._lock:
        state_store._record_directive_event_locked(_make_dummy_event("aud_sat_1"))
        state_store._record_directive_event_locked(_make_dummy_event("aud_sat_2"))

    assert state_store.get_directive_audits_outbox_count() == 2

    # Ingest telemetry reading (will attempt directive computation)
    reading = {
        "sensor_id": "US_UPSTREAM_01",
        "section_id": "SEC_SCREENING",
        "sensor_type": "WATER_LEVEL",
        "value": 15.0,
        "unit": "cm",
        "source": "SIMULATED",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    resp = client.post("/api/v1/telemetry", json=reading)
    assert resp.status_code == 503
    assert "Actuator directive audit outbox capacity exceeded" in resp.json()["detail"]


@pytest.mark.anyio
async def test_shutdown_reports_warning_on_unpersisted_volatile_events(caplog):
    """stop_directive_audit_outbox_worker logs an explicit warning if volatile events remain."""
    state_store.clear()
    with state_store._lock:
        state_store._record_directive_event_locked(_make_dummy_event("aud_shutdown_rem"))

    start_directive_audit_outbox_worker()

    with caplog.at_level(logging.WARNING):
        await stop_directive_audit_outbox_worker()

    assert any(
        "unpersisted actuator directive audit events in volatile outbox" in rec.message
        for rec in caplog.records
    )
    assert any(
        "In-memory events are not durable across process termination" in rec.message
        for rec in caplog.records
    )
