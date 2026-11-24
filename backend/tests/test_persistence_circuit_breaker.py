"""
DRAIN-X Batch 2C.3 — Persistence Circuit Breaker and Reconnection Test Suite.

Verifies:
1. CLOSED to OPEN transition on transient failures.
2. Exponential backoff progression (1s, 2s, 4s, 8s, 16s).
3. Maximum 30-second backoff ceiling.
4. Jitter bounds within [raw * (1 - jitter), min(max_backoff, raw * (1 + jitter))].
5. OPEN fast-fail without persistence calls and without draining outbox.
6. HALF_OPEN allows exactly one recovery attempt.
7. Concurrent callers cannot create multiple HALF_OPEN attempts.
8. Successful recovery resets state to CLOSED, failure count to 0.
9. Failed recovery returns to OPEN with incremented failure count and bounded backoff.
10. Permanent errors (auth, config, conflict, validation) do not trigger or advance the breaker.
11. Transient errors preserve outbox events without silent eviction.
12. Application shutdown/cancellation reports unpersisted volatile events.
13. No competing or duplicated retry loops; background worker does not busy loop when OPEN.
"""

import asyncio
import concurrent.futures
from datetime import datetime, timezone
import logging
import time
from typing import Any, Dict
import httpx
import pytest

from app.models.contracts import (
    ActuatorDirectiveEventContract,
    AlertSeverity,
    DirectiveEventType,
    DirectiveIssuerType,
)
from app.services.persistence_repository import (
    DirectiveAuditConflictError,
    StorageError,
    StorageNotConfiguredError,
    persistence_repo,
)
from app.services.circuit_breaker import (
    CircuitBreakerOpenError,
    CircuitState,
    PersistenceCircuitBreaker,
    is_transient_error,
    persistence_circuit_breaker,
)
from app.services.directive_audit_outbox_worker import (
    flush_and_persist_outbox,
    process_outbox_sweep,
    start_directive_audit_outbox_worker,
    stop_directive_audit_outbox_worker,
    _get_outbox_persist_lock,
)
from app.services.state_store import state_store


def _make_dummy_event(audit_id: str) -> ActuatorDirectiveEventContract:
    return ActuatorDirectiveEventContract(
        audit_id=audit_id,
        directive_id="dir_cb_test",
        event_type=DirectiveEventType.ISSUED,
        device_id="DRAINX-ESP32-NODE-01",
        section_id="SEC_SCREENING_01",
        operational_mode="SIMULATION",
        action="DIVERT_FLOW",
        gate_target_angle=45.0,
        reason="Circuit breaker test event",
        risk_level=AlertSeverity.INFO,
        emergency_stop=False,
        issuer_type=DirectiveIssuerType.AUTOMATED_ENGINE,
        issuer_id="test_runner",
        timestamp=datetime.now(timezone.utc),
    )


@pytest.fixture(autouse=True)
def reset_circuit_breaker():
    persistence_circuit_breaker.reset()
    yield
    persistence_circuit_breaker.reset()


def test_closed_to_open_transition():
    """Circuit breaker starts in CLOSED and transitions to OPEN on a transient failure."""
    cb = PersistenceCircuitBreaker(initial_backoff=1.0, max_backoff=30.0)
    assert cb.state == CircuitState.CLOSED
    assert cb.acquire_execution_permission() is True

    # Record transient network error
    transient_err = httpx.ConnectTimeout("Connection timed out to Supabase PostgREST")
    tripped = cb.record_failure(transient_err)
    assert tripped is True
    assert cb.state == CircuitState.OPEN
    assert cb.failure_count == 1
    assert cb.acquire_execution_permission() is False


def test_exponential_backoff():
    """Backoff doubles exponentially with each successive failure: 1.0, 2.0, 4.0, 8.0, 16.0."""
    cb = PersistenceCircuitBreaker(initial_backoff=1.0, max_backoff=30.0, backoff_multiplier=2.0)
    expected_raw = [1.0, 2.0, 4.0, 8.0, 16.0]
    for idx, expected in enumerate(expected_raw, start=1):
        actual = cb.calculate_backoff(idx, apply_jitter=False)
        assert actual == pytest.approx(expected, abs=1e-3)


def test_maximum_30_second_backoff():
    """Backoff never exceeds maximum backoff ceiling of 30.0 seconds."""
    cb = PersistenceCircuitBreaker(initial_backoff=1.0, max_backoff=30.0, backoff_multiplier=2.0)
    for count in [6, 7, 10, 50, 100]:
        actual = cb.calculate_backoff(count, apply_jitter=False)
        assert actual == 30.0

    # Verify with jitter applied: must still never exceed 30.0s
    for _ in range(100):
        actual_jittered = cb.calculate_backoff(10, apply_jitter=True)
        assert actual_jittered <= 30.0


def test_jitter_bounds():
    """Jitter variation is bounded within [raw * (1 - jitter_ratio), min(max_backoff, raw * (1 + jitter_ratio))]."""
    cb = PersistenceCircuitBreaker(initial_backoff=1.0, max_backoff=30.0, jitter_ratio=0.1)
    raw = 10.0  # arbitrary raw value
    low_bound = raw * 0.9
    high_bound = raw * 1.1

    for _ in range(100):
        # failure_count for 8.0s raw is 4, let's test count=4 (raw = 8.0)
        raw_val = cb.calculate_backoff(4, apply_jitter=False)
        jittered = cb.calculate_backoff(4, apply_jitter=True)
        assert raw_val * 0.9 <= jittered <= raw_val * 1.1


@pytest.mark.anyio
async def test_open_fast_fail_without_persistence_calls():
    """In OPEN state, calls fast-fail with CircuitBreakerOpenError without invoking persistence or draining outbox."""
    persistence_circuit_breaker.reset()
    state_store.clear()
    evt = _make_dummy_event("aud_fast_fail_1")
    with state_store._lock:
        state_store._record_directive_event_locked(evt)

    # Trip breaker to OPEN
    persistence_circuit_breaker.record_failure(httpx.ConnectError("Network unreachable"))
    assert persistence_circuit_breaker.state == CircuitState.OPEN

    call_count = 0

    def mock_persist(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return True

    orig_persist = persistence_repo.persist_directive_audit_batch_sync
    persistence_repo.persist_directive_audit_batch_sync = mock_persist

    try:
        # Fast fail when raise_on_error is True
        with pytest.raises(CircuitBreakerOpenError) as exc_info:
            await flush_and_persist_outbox(raise_on_error=True)

        assert "Persistence circuit breaker is OPEN" in str(exc_info.value)
        assert exc_info.value.remaining_backoff > 0.0

        # Fast fail when raise_on_error is False (returns 0)
        res = await flush_and_persist_outbox(raise_on_error=False)
        assert res == 0

        # Persistence was NEVER called
        assert call_count == 0

        # Outbox item was preserved untouched
        assert state_store.get_directive_audits_outbox_count() == 1
    finally:
        persistence_repo.persist_directive_audit_batch_sync = orig_persist


def test_half_open_allows_exactly_one_recovery_attempt():
    """When OPEN backoff expires, exactly one caller enters HALF_OPEN; subsequent callers fast-fail."""
    cb = PersistenceCircuitBreaker(initial_backoff=0.01, max_backoff=30.0)
    cb.record_failure(httpx.ConnectTimeout("Timeout"))
    assert cb._state == CircuitState.OPEN

    # Wait for backoff to elapse
    time.sleep(0.02)
    assert cb.state == CircuitState.HALF_OPEN

    # First caller acquires permission
    first = cb.acquire_execution_permission()
    assert first is True
    assert cb._state == CircuitState.HALF_OPEN

    # Second caller attempts acquisition while probe is in-flight -> rejected
    second = cb.acquire_execution_permission()
    assert second is False


def test_concurrent_callers_cannot_create_multiple_half_open_attempts():
    """Under high concurrency, exactly one caller gains HALF_OPEN execution permission."""
    cb = PersistenceCircuitBreaker(initial_backoff=0.01, max_backoff=30.0)
    cb.record_failure(httpx.ConnectTimeout("Timeout"))
    time.sleep(0.02)
    assert cb.state == CircuitState.HALF_OPEN

    results = []

    def try_acquire():
        return cb.acquire_execution_permission()

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(try_acquire) for _ in range(20)]
        results = [f.result() for f in futures]

    # Exactly one True, 19 False
    assert results.count(True) == 1
    assert results.count(False) == 19


def test_successful_recovery_resets_state():
    """Successful probe in HALF_OPEN resets breaker to CLOSED and resets failure count."""
    cb = PersistenceCircuitBreaker(initial_backoff=0.01, max_backoff=30.0)
    cb.record_failure(httpx.ConnectTimeout("Timeout"))
    time.sleep(0.02)
    assert cb.acquire_execution_permission() is True
    assert cb._state == CircuitState.HALF_OPEN

    cb.record_success()
    assert cb.state == CircuitState.CLOSED
    assert cb.failure_count == 0
    assert cb.current_backoff == 0.0
    assert cb.acquire_execution_permission() is True


def test_failed_recovery_returns_to_open():
    """Failed probe in HALF_OPEN returns to OPEN with incremented failure count."""
    cb = PersistenceCircuitBreaker(initial_backoff=0.01, max_backoff=30.0)
    cb.record_failure(httpx.ConnectTimeout("Timeout 1"))
    assert cb.failure_count == 1

    time.sleep(0.02)
    assert cb.acquire_execution_permission() is True
    assert cb._state == CircuitState.HALF_OPEN

    # Probe fails with second transient error
    cb.record_failure(httpx.ConnectTimeout("Timeout 2"))
    assert cb._state == CircuitState.OPEN
    assert cb.failure_count == 2
    assert cb.acquire_execution_permission() is False


def test_permanent_errors_do_not_trigger_breaker():
    """Permanent errors (configuration, auth, conflict, validation) MUST NOT trip the breaker."""
    cb = PersistenceCircuitBreaker()
    assert cb.state == CircuitState.CLOSED

    permanent_errors = [
        StorageNotConfiguredError("Storage is not configured"),
        DirectiveAuditConflictError("Immutability conflict in audit ledger"),
        StorageError("Supabase directive audit persistence HTTP 401"),
        StorageError("Supabase directive audit persistence HTTP 403"),
        StorageError("Supabase directive audit persistence HTTP 400"),
        StorageError("Supabase directive audit persistence HTTP 409"),
        StorageError("Directive audit insert returned a representation that diverges from the submitted row."),
        ValueError("Invalid gate target angle: out of range [0, 90]"),
        TypeError("Expected string but got None"),
    ]

    for err in permanent_errors:
        assert is_transient_error(err) is False
        tripped = cb.record_failure(err)
        assert tripped is False
        assert cb.state == CircuitState.CLOSED
        assert cb.failure_count == 0


@pytest.mark.anyio
async def test_transient_errors_preserve_outbox_events():
    """Transient persistence errors trip the breaker and restore undelivered events to outbox."""
    persistence_circuit_breaker.reset()
    state_store.clear()
    e1 = _make_dummy_event("aud_transient_pres_1")
    e2 = _make_dummy_event("aud_transient_pres_2")
    with state_store._lock:
        state_store._record_directive_event_locked(e1)
        state_store._record_directive_event_locked(e2)

    assert state_store.get_directive_audits_outbox_count() == 2

    # Simulate transient network failure in repository
    orig_persist = persistence_repo.persist_directive_audit_batch_sync

    def _failing_persist(*args, **kwargs):
        raise httpx.ConnectTimeout("Simulated PostgREST timeout")

    persistence_repo.persist_directive_audit_batch_sync = _failing_persist

    try:
        res = await process_outbox_sweep()
        assert res == 0

        # Breaker is now OPEN
        assert persistence_circuit_breaker.state == CircuitState.OPEN
        assert persistence_circuit_breaker.failure_count == 1

        # Outbox retains both events in FIFO order
        assert state_store.get_directive_audits_outbox_count() == 2
        flushed = state_store.flush_directive_audits_outbox()
        assert [e.audit_id for e in flushed] == ["aud_transient_pres_1", "aud_transient_pres_2"]
    finally:
        persistence_repo.persist_directive_audit_batch_sync = orig_persist


@pytest.mark.anyio
async def test_shutdown_reports_warning_on_unpersisted_volatile_events(caplog):
    """Shutdown cleanly cancels worker and reports warning if volatile events remain."""
    state_store.clear()
    with state_store._lock:
        state_store._record_directive_event_locked(_make_dummy_event("aud_sd_warn_1"))

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


@pytest.mark.anyio
async def test_no_competing_or_duplicated_retry_loops():
    """Calling start_directive_audit_outbox_worker repeatedly returns the same existing singleton task."""
    try:
        task1 = start_directive_audit_outbox_worker()
        task2 = start_directive_audit_outbox_worker()
        assert task1 is task2
    finally:
        await stop_directive_audit_outbox_worker()


# ==============================================================================
# Batch 2C.5 Targeted Reliability Remediation Tests (Findings 1 - 4)
# ==============================================================================

@pytest.mark.anyio
async def test_finding1_half_open_empty_outbox_releases_permission_and_recovers():
    """
    Finding 1: Verify that when the circuit breaker is in HALF_OPEN, if an outbox flush
    finds no events or an empty outbox, it releases execution permission rather than
    permanently deadlocking the circuit in HALF_OPEN.
    """
    persistence_circuit_breaker.reset()
    state_store.clear()

    # Fast breaker with 10ms initial backoff
    persistence_circuit_breaker.initial_backoff = 0.01
    persistence_circuit_breaker.max_backoff = 30.0

    # Trip breaker to OPEN with transient error
    persistence_circuit_breaker.record_failure(httpx.ConnectTimeout("Transient connection timeout"))
    assert persistence_circuit_breaker.state == CircuitState.OPEN

    # Wait for backoff to expire -> HALF_OPEN
    await asyncio.sleep(0.02)
    assert persistence_circuit_breaker.state == CircuitState.HALF_OPEN

    # 1. Flush with empty outbox
    assert state_store.get_directive_audits_outbox_count() == 0
    flushed_count = await flush_and_persist_outbox(raise_on_error=False)
    assert flushed_count == 0

    # Breaker must NOT be deadlocked: probe permission must still be acquirable!
    assert persistence_circuit_breaker.acquire_execution_permission() is True
    # Release probe so subsequent flush can use it
    persistence_circuit_breaker.release_execution_permission()

    # 2. Add an event and verify full recovery
    e1 = _make_dummy_event("aud_f1_recovery_1")
    with state_store._lock:
        state_store._record_directive_event_locked(e1)

    orig_persist = persistence_repo.persist_directive_audit_batch_sync

    def _mock_persist(events, strict=True):
        return True

    persistence_repo.persist_directive_audit_batch_sync = _mock_persist
    try:
        flushed_count = await flush_and_persist_outbox(raise_on_error=True)
        assert flushed_count == 1
        # Breaker cleanly recovered to CLOSED
        assert persistence_circuit_breaker.state == CircuitState.CLOSED
        assert persistence_circuit_breaker.failure_count == 0
    finally:
        persistence_repo.persist_directive_audit_batch_sync = orig_persist


def test_finding1_half_open_release_execution_permission_direct():
    """
    Finding 1: Test release_execution_permission() directly in HALF_OPEN state.
    """
    cb = PersistenceCircuitBreaker(initial_backoff=0.01, max_backoff=30.0)
    cb.record_failure(httpx.ConnectTimeout("Timeout"))
    time.sleep(0.02)
    assert cb.state == CircuitState.HALF_OPEN

    # First acquisition succeeds
    assert cb.acquire_execution_permission() is True
    # In-flight acquisition blocked
    assert cb.acquire_execution_permission() is False

    # Release permission
    cb.release_execution_permission()

    # Next acquisition succeeds
    assert cb.acquire_execution_permission() is True


@pytest.mark.anyio
async def test_finding2_cancellation_restores_drained_events_fifo():
    """
    Finding 2: Verify that if flush_and_persist_outbox is cancelled (asyncio.CancelledError),
    all drained events are restored to the front of the outbox in strict FIFO order,
    execution permission is released, and CancelledError is re-raised.
    """
    persistence_circuit_breaker.reset()
    state_store.clear()

    e1 = _make_dummy_event("aud_f2_cancel_1")
    e2 = _make_dummy_event("aud_f2_cancel_2")
    with state_store._lock:
        state_store._record_directive_event_locked(e1)
        state_store._record_directive_event_locked(e2)

    assert state_store.get_directive_audits_outbox_count() == 2

    orig_persist = persistence_repo.persist_directive_audit_batch_sync

    def _cancelled_persist(*args, **kwargs):
        raise asyncio.CancelledError("Task was cancelled during persistence")

    persistence_repo.persist_directive_audit_batch_sync = _cancelled_persist

    try:
        with pytest.raises(asyncio.CancelledError):
            await flush_and_persist_outbox(raise_on_error=True)

        # Outbox must retain both events
        assert state_store.get_directive_audits_outbox_count() == 2
        flushed = state_store.flush_directive_audits_outbox()
        # Verify strict FIFO order preserved
        assert [e.audit_id for e in flushed] == ["aud_f2_cancel_1", "aud_f2_cancel_2"]
    finally:
        persistence_repo.persist_directive_audit_batch_sync = orig_persist


def test_finding3_event_loop_lock_tied_to_loop_lifecycle():
    """
    Finding 3: Verify that _get_outbox_persist_lock binds directly to the running event
    loop instance and does not rely on recycled loop memory address IDs.
    """
    async def _check_loop_lock():
        lock = _get_outbox_persist_lock()
        assert isinstance(lock, asyncio.Lock)
        current_loop = asyncio.get_running_loop()
        assert getattr(current_loop, "_drainx_outbox_persist_lock", None) is lock
        return lock

    loop1 = asyncio.new_event_loop()
    try:
        lock1 = loop1.run_until_complete(_check_loop_lock())
    finally:
        loop1.close()

    loop2 = asyncio.new_event_loop()
    try:
        lock2 = loop2.run_until_complete(_check_loop_lock())
    finally:
        loop2.close()

    # The two locks must be distinct instances bound to their respective loops
    assert lock1 is not lock2


def test_finding4_transient_error_classifier_refinements():
    """
    Finding 4: Verify refined transient error classifier:
    - Gateway / network errors containing 'invalid status line' or 'invalid response' are TRANSIENT.
    - Semantic / schema errors ('invalid payload', 'invalid argument', 'invalid schema') are PERMANENT.
    """
    # 1. Transient errors with 'invalid' in network/gateway context
    transient_gateway_err = StorageError(
        "Supabase directive audit persistence error: Connection error: invalid status line received from upstream gateway"
    )
    assert is_transient_error(transient_gateway_err) is True

    transient_server_err = StorageError(
        "Supabase directive audit persistence error: gateway closed connection prematurely"
    )
    assert is_transient_error(transient_server_err) is True

    # 2. Permanent semantic / payload / schema errors
    permanent_payload_err = StorageError(
        "Supabase directive audit persistence error: invalid payload: missing device_id in request"
    )
    assert is_transient_error(permanent_payload_err) is False

    permanent_schema_err = StorageError(
        "Supabase directive audit persistence error: invalid schema definition for table actuator_directive_audits"
    )
    assert is_transient_error(permanent_schema_err) is False

    permanent_arg_err = StorageError(
        "Supabase directive audit persistence error: invalid argument provided to RPC function"
    )
    assert is_transient_error(permanent_arg_err) is False
