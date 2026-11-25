"""
Automated recovery sweep for expired incident-photo storage cleanup operations.

Safety model (all deletion authority stays in Migration 005):
- Discovery (`query_expired_cleanup_operations_sync`) is read-only and only nominates operations.
- Every nominated operation is processed exclusively through
  `PersistenceRepository.execute_cleanup_recovery_workflow_sync`, which calls
  `claim_expired_cleanup_operation_rpc` (lease expiry, idempotency-key state and registry
  reference counts are re-validated under row locks on the database clock) and only deletes the
  `remaining_paths` returned by that RPC, reconciling each through `reconcile_storage_orphan_rpc`.
- Objects are never deleted because they are "old". Uncertain deletions are never counted as
  success. Nothing here bypasses the RPCs or falls back to in-memory behaviour.

Logging never includes object paths, signed URLs, tokens, incident content or exception text.
"""

import logging
import time
from typing import Any, Callable, Dict, List, Optional

from app.services.persistence_repository import StorageLeaseLostError

logger = logging.getLogger("drainx.storage_cleanup_recovery")

SYSTEM_RECOVERY_ACTOR_ID = "system_storage_cleanup_worker"
SYSTEM_RECOVERY_ACTOR_ROLE = "system"

_BACKOFF_BASE_SEC = 60.0
_BACKOFF_MAX_SEC = 3600.0
_BACKOFF_MAX_ENTRIES = 500
_DISCOVERY_WINDOW_MULTIPLIER = 4
_DISCOVERY_WINDOW_MAX = 100
_MAX_EXCLUDED_IDS = 30


class CleanupRecoveryBackoff:
    """
    Bounded in-process backoff so permanently failing / still-uncertain operations are not
    retried on every sweep and cannot starve other expired operations. It is advisory only:
    losing it (restart) merely means an operation is retried sooner; the database lease
    semantics remain the sole authority.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic):
        self._clock = clock
        self._entries: Dict[str, Dict[str, float]] = {}

    def active_ids(self) -> List[str]:
        now = self._clock()
        return sorted(cid for cid, e in self._entries.items() if e["next_at"] > now)

    def is_backed_off(self, cleanup_id: str) -> bool:
        entry = self._entries.get(cleanup_id)
        return entry is not None and entry["next_at"] > self._clock()

    def record_failure(self, cleanup_id: str) -> None:
        # Failure history is retained after a backoff window elapses so delays keep growing
        # (exponentially, capped) until the operation succeeds; the map itself is size-bounded.
        now = self._clock()
        entry = self._entries.get(cleanup_id)
        failures = int(entry["failures"]) + 1 if entry else 1
        delay = min(_BACKOFF_BASE_SEC * (2 ** min(failures - 1, 16)), _BACKOFF_MAX_SEC)
        if cleanup_id not in self._entries and len(self._entries) >= _BACKOFF_MAX_ENTRIES:
            oldest = min(self._entries, key=lambda k: self._entries[k]["next_at"])
            del self._entries[oldest]
        self._entries[cleanup_id] = {"failures": float(failures), "next_at": now + delay}

    def record_success(self, cleanup_id: str) -> None:
        self._entries.pop(cleanup_id, None)


def run_storage_cleanup_recovery_sweep(
    repo: Any,
    batch_size: int,
    backoff: Optional[CleanupRecoveryBackoff] = None,
    should_stop: Optional[Callable[[], bool]] = None,
    lease_sec: Optional[int] = None,
) -> Dict[str, int]:
    """
    Runs ONE bounded recovery sweep (blocking; call from a worker thread).

    Processes at most `batch_size` expired operations. A failure on one operation is isolated:
    it is counted, backed off, and the sweep continues with the next operation.
    `should_stop` is checked between operations so shutdown never starts new work.
    """
    backoff = backoff if backoff is not None else CleanupRecoveryBackoff()
    summary = {
        "discovered": 0,
        "processed": 0,
        "completed": 0,
        "already_confirmed": 0,
        "uncertain": 0,
        "lease_conflict": 0,
        "failed": 0,
        "backed_off_skipped": 0,
        "stopped_early": 0,
    }

    window = min(batch_size * _DISCOVERY_WINDOW_MULTIPLIER, _DISCOVERY_WINDOW_MAX)
    window = max(window, batch_size)
    candidates = repo.query_expired_cleanup_operations_sync(
        limit=window,
        exclude_cleanup_ids=backoff.active_ids()[:_MAX_EXCLUDED_IDS],
    )
    summary["discovered"] = len(candidates)

    for op in candidates:
        if summary["processed"] >= batch_size:
            break
        if should_stop is not None and should_stop():
            summary["stopped_early"] = 1
            break
        cleanup_id = op["cleanup_id"]
        if backoff.is_backed_off(cleanup_id):
            summary["backed_off_skipped"] += 1
            continue

        summary["processed"] += 1
        try:
            result = repo.execute_cleanup_recovery_workflow_sync(
                cleanup_id=cleanup_id,
                incident_id=op["incident_id"],
                idempotency_key=op["idempotency_key"],
                scope=op["scope"],
                recovery_actor_id=SYSTEM_RECOVERY_ACTOR_ID,
                recovery_actor_role=SYSTEM_RECOVERY_ACTOR_ROLE,
                lease_sec=lease_sec,
            )
        except StorageLeaseLostError as exc:
            summary["lease_conflict"] += 1
            backoff.record_failure(cleanup_id)
            logger.warning(
                "Storage cleanup recovery lease conflict (cleanup_id=%s, sqlstate=%s); will retry later.",
                cleanup_id,
                getattr(exc, "sqlstate", None) or "NONE",
            )
            continue
        except Exception as exc:  # isolate per-operation failure
            summary["failed"] += 1
            backoff.record_failure(cleanup_id)
            logger.warning(
                "Storage cleanup recovery failed (cleanup_id=%s, error_type=%s, sqlstate=%s, category=%s); "
                "continuing with remaining operations.",
                cleanup_id,
                exc.__class__.__name__,
                getattr(exc, "sqlstate", None) or "NONE",
                getattr(exc, "error_category", None) or "UNEXPECTED",
            )
            continue

        status = result.get("status") if isinstance(result, dict) else None
        if status == "CLEANUP_RECOVERY_COMPLETED":
            summary["completed"] += 1
            backoff.record_success(cleanup_id)
        elif status == "CLEANUP_ALREADY_CONFIRMED":
            summary["already_confirmed"] += 1
            backoff.record_success(cleanup_id)
        elif status == "CLEANUP_RECOVERY_PARTIAL_UNCERTAIN":
            # Uncertain storage deletion is NOT success; back off before re-attempting.
            summary["uncertain"] += 1
            backoff.record_failure(cleanup_id)
            logger.warning(
                "Storage cleanup recovery left %d uncertain object(s) (cleanup_id=%s).",
                len(result.get("uncertain_paths") or []),
                cleanup_id,
            )
        else:
            summary["failed"] += 1
            backoff.record_failure(cleanup_id)
            logger.warning(
                "Storage cleanup recovery returned unexpected status (cleanup_id=%s, status=%s).",
                cleanup_id,
                status if isinstance(status, str) and len(status) <= 64 else "INVALID",
            )

    logger.info(
        "Storage cleanup recovery sweep: discovered=%d processed=%d completed=%d already_confirmed=%d "
        "uncertain=%d lease_conflict=%d failed=%d backed_off_skipped=%d",
        summary["discovered"],
        summary["processed"],
        summary["completed"],
        summary["already_confirmed"],
        summary["uncertain"],
        summary["lease_conflict"],
        summary["failed"],
        summary["backed_off_skipped"],
    )
    return summary
