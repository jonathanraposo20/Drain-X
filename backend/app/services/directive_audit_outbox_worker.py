"""
DRAIN-X Directive Audit Outbox Reliability Worker.

Batch 2C.2: Autonomous background outbox drainer and retry owner.

Responsibilities:
1. Coordinates thread/task-safe draining and persistence of volatile outbox events
   via a single bounded lock (_outbox_persist_lock).
2. Autonomous periodic sweep loop that persists pending audit events even without
   incoming telemetry packets.
3. On network or database persistence failure, undelivered events are restored to
   the front of the outbox (FIFO) with deduplication by audit_id.
4. On process shutdown, signals worker cancellation and emits an explicit warning
   if unpersisted events remain in memory, acknowledging that volatile memory
   is not durable.
"""

import asyncio
import logging
from typing import Optional
import anyio

from app.core.config import settings
from app.models.contracts import (
    ActuatorDirectiveEventContract,
    DirectiveAuditOutboxFullError,
)
from app.services.state_store import state_store
from app.services.circuit_breaker import (
    persistence_circuit_breaker,
    CircuitBreakerOpenError,
    CircuitState,
)
from app.services.persistence_repository import (
    persistence_repo,
    DirectiveAuditConflictError,
    StorageError,
    StorageNotConfiguredError,
)

import threading

logger = logging.getLogger("drainx.directive_audit_outbox_worker")

def _get_outbox_persist_lock() -> asyncio.Lock:
    """Returns an asyncio.Lock bound directly to the current running event loop instance."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.Lock()
    lock = getattr(loop, "_drainx_outbox_persist_lock", None)
    if lock is None:
        lock = asyncio.Lock()
        setattr(loop, "_drainx_outbox_persist_lock", lock)
    return lock


_outbox_worker_task: Optional[asyncio.Task[None]] = None
_outbox_worker_stop = asyncio.Event()


async def flush_and_persist_outbox(
    raise_on_error: bool = False,
    max_batch_size: Optional[int] = None,
) -> int:
    """
    Synchronized flush and persistence of pending directive audit outbox events.
    Thread/task-safe via event-loop-scoped lock and persistence circuit breaker.
    If persistence fails, undelivered events are restored to the front of the outbox.
    Returns the count of successfully persisted events.
    """
    # 0. Fast-path: do not acquire circuit breaker probe if outbox is empty
    if state_store.get_directive_audits_outbox_count() == 0:
        return 0

    # 1. Fast-fail if the persistence circuit breaker is OPEN or busy in HALF_OPEN
    if not persistence_circuit_breaker.acquire_execution_permission():
        rem = persistence_circuit_breaker.get_remaining_backoff()
        logger.debug(
            "Persistence circuit breaker is %s; fast-failing outbox flush (rem=%.1fs).",
            persistence_circuit_breaker.state.value,
            rem,
        )
        if raise_on_error:
            raise CircuitBreakerOpenError(
                f"Persistence circuit breaker is {persistence_circuit_breaker.state.value}; fast-failing.",
                remaining_backoff=rem,
            )
        return 0

    lock = _get_outbox_persist_lock()
    async with lock:
        events = state_store.flush_directive_audits_outbox(max_batch_size=max_batch_size)
        if not events:
            persistence_circuit_breaker.release_execution_permission()
            return 0
        try:
            persisted = await anyio.to_thread.run_sync(
                lambda: persistence_repo.persist_directive_audit_batch_sync(events, strict=True)
            )
            persistence_circuit_breaker.record_success()
            return len(events)
        except asyncio.CancelledError:
            persistence_circuit_breaker.release_execution_permission()
            try:
                state_store.restore_directive_audits_outbox(events)
            except DirectiveAuditOutboxFullError:
                pass
            raise
        except DirectiveAuditConflictError as exc:
            # Immutability conflict indicates invalid state or tampering.
            # We do NOT restore conflicting events into the retry queue.
            persistence_circuit_breaker.record_failure(exc)
            logger.error(
                "Actuator directive audit immutability conflict rejected during outbox flush: %s",
                exc,
            )
            if raise_on_error:
                raise
            return 0
        except (StorageError, StorageNotConfiguredError) as exc:
            persistence_circuit_breaker.record_failure(exc)
            try:
                state_store.restore_directive_audits_outbox(events)
            except DirectiveAuditOutboxFullError:
                pass
            logger.warning(
                "Actuator directive audit persistence failed (%s); %d events restored to outbox.",
                exc.__class__.__name__,
                len(events),
            )
            if raise_on_error:
                raise
            return 0
        except Exception as exc:
            persistence_circuit_breaker.record_failure(exc)
            try:
                state_store.restore_directive_audits_outbox(events)
            except DirectiveAuditOutboxFullError:
                pass
            logger.error(
                "Unexpected error persisting directive audit outbox: %s",
                exc,
                exc_info=True,
            )
            if raise_on_error:
                raise
            return 0


async def process_outbox_sweep(batch_size: int = 50) -> int:
    """
    Performs one autonomous outbox sweep: drains up to batch_size events and persists them.
    Restores events on failure. Returns count of persisted events.
    """
    return await flush_and_persist_outbox(raise_on_error=False, max_batch_size=batch_size)


async def directive_audit_outbox_worker_loop():
    """
    Background worker loop that periodically drains and retries unpersisted
    actuator directive audit events from the volatile outbox.
    """
    while not _outbox_worker_stop.is_set():
        try:
            base_interval = getattr(settings, "DIRECTIVE_AUDIT_OUTBOX_RETRY_INTERVAL_SEC", 2.0)
            rem_backoff = persistence_circuit_breaker.get_remaining_backoff()
            # Bounded sleep: if breaker is OPEN, wait until backoff has elapsed instead of busy-looping
            interval = max(base_interval, rem_backoff)
            try:
                await asyncio.wait_for(_outbox_worker_stop.wait(), timeout=interval)
                break
            except asyncio.TimeoutError:
                pass

            if state_store.get_directive_audits_outbox_count() > 0:
                await process_outbox_sweep(batch_size=50)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.error("Error in directive audit outbox worker loop: %s", exc, exc_info=True)
            await asyncio.sleep(1.0)


def start_directive_audit_outbox_worker() -> Optional[asyncio.Task[None]]:
    """Starts the background outbox worker task if not already running."""
    global _outbox_worker_task, _outbox_worker_stop
    if _outbox_worker_task is not None and not _outbox_worker_task.done():
        return _outbox_worker_task

    _outbox_worker_stop = asyncio.Event()
    _outbox_worker_task = asyncio.create_task(
        directive_audit_outbox_worker_loop(),
        name="directive_audit_outbox_worker",
    )
    return _outbox_worker_task


async def stop_directive_audit_outbox_worker() -> None:
    """Stops the background outbox worker task and reports any remaining volatile events."""
    global _outbox_worker_task, _outbox_worker_stop
    task = _outbox_worker_task
    if task is None:
        return

    _outbox_worker_stop.set()
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    except Exception as exc:
        logger.error("Directive audit outbox worker task ended with error: %s", exc)
    finally:
        _outbox_worker_task = None

    # Check for unpersisted events on shutdown
    remaining = state_store.get_directive_audits_outbox_count()
    if remaining > 0:
        logger.warning(
            "Process shutdown with %d unpersisted actuator directive audit events in volatile outbox. "
            "In-memory events are not durable across process termination.",
            remaining,
        )
