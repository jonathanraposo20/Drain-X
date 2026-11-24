"""
Phase 3 Milestone 1: automated expired storage-cleanup recovery worker.

IMPORTANT: every test here uses mocks / patched HTTP. None of them establish live Supabase
behaviour (discovery query semantics, RPC locking and reference checks are only proven by the
Migration 005 SQL and the separate live-cloud harness).
"""

import asyncio
import logging
import threading
from unittest.mock import MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

import app.main as main_module
from app.core.config import Settings, settings
from app.main import app
from app.services.persistence_repository import (
    PersistenceRepository,
    StorageError,
    StorageLeaseLostError,
    StorageValidationError,
)
from app.services.storage_cleanup_recovery import (
    SYSTEM_RECOVERY_ACTOR_ID,
    SYSTEM_RECOVERY_ACTOR_ROLE,
    CleanupRecoveryBackoff,
    run_storage_cleanup_recovery_sweep,
)

_ORIG_SLEEP = asyncio.sleep
_PATH_A = "INC-01/sha256_" + "a" * 64 + ".jpg"
_PATH_B_REFERENCED = "INC-01/sha256_" + "b" * 64 + ".jpg"


@pytest.fixture(autouse=True)
def _reset_worker_globals():
    main_module._storage_cleanup_stop.clear()
    main_module._storage_cleanup_task = None
    yield
    main_module._storage_cleanup_stop.clear()
    main_module._storage_cleanup_task = None


def _ops(n):
    return [
        {
            "cleanup_id": f"clean_{i:04d}",
            "incident_id": "INC-01",
            "idempotency_key": f"idem_key_{i:04d}",
            "scope": "incident_attachment",
        }
        for i in range(n)
    ]


def _cloud_repo_mock(configured=True):
    repo = MagicMock()
    repo.is_storage_configured = configured
    repo.is_mock = False
    return repo


def _real_cloud_repo():
    return PersistenceRepository(
        supabase_url="https://mock.supabase.co",
        supabase_key="anon",
        service_role_key="TOP_SECRET_CLEANUP_SERVICE_KEY",
    )


# ---------------------------------------------------------------------
# 1. Lifecycle: start / stop / single worker per process
# ---------------------------------------------------------------------
def test_worker_starts_stops_and_is_single_instance():
    async def scenario():
        t1 = main_module.start_storage_cleanup_recovery_task()
        t2 = main_module.start_storage_cleanup_recovery_task()
        assert t1 is t2, "a second worker must not be spawned in one process"
        await _ORIG_SLEEP(0)
        assert not t1.done()
        await main_module.stop_storage_cleanup_recovery_task()
        assert t1.done()
        assert t1.exception() is None
        assert main_module._storage_cleanup_task is None
        # Restart after stop yields a fresh live task.
        t3 = main_module.start_storage_cleanup_recovery_task()
        assert t3 is not t1 and not t3.done()
        await main_module.stop_storage_cleanup_recovery_task()

    asyncio.run(scenario())


def test_fastapi_lifespan_starts_and_stops_cleanup_worker():
    with TestClient(app) as client:
        task = main_module._storage_cleanup_task
        assert task is not None and not task.done()
        assert client.get("/api/v1/health").status_code in (200, 404)
    assert task.done()
    assert task.exception() is None
    assert main_module._storage_cleanup_task is None


# ---------------------------------------------------------------------
# 2/3. Periodic invocation, executed off the event loop thread
# ---------------------------------------------------------------------
def test_worker_invokes_sweep_periodically_off_event_loop_thread(monkeypatch):
    monkeypatch.setattr(settings, "STORAGE_CLEANUP_RECOVERY_INTERVAL_SEC", 5.0)
    monkeypatch.setattr(settings, "STORAGE_CLEANUP_RECOVERY_BATCH_SIZE", 7)
    repo = _cloud_repo_mock()
    loop_thread = threading.get_ident()
    sweep_threads = []
    sleeps = []

    def fake_sweep(**kwargs):
        sweep_threads.append(threading.get_ident())
        assert kwargs["batch_size"] == 7
        assert kwargs["repo"] is repo
        assert callable(kwargs["should_stop"])
        return {}

    async def fake_sleep(sec):
        sleeps.append(sec)
        if len(sleeps) >= 4:
            raise asyncio.CancelledError()
        await _ORIG_SLEEP(0)

    async def scenario():
        with patch("app.services.persistence_repository.persistence_repo", repo), patch(
            "app.services.storage_cleanup_recovery.run_storage_cleanup_recovery_sweep",
            side_effect=fake_sweep,
        ), patch("asyncio.sleep", side_effect=fake_sleep):
            await main_module.storage_cleanup_recovery_loop()

    asyncio.run(scenario())
    assert len(sweep_threads) == 3
    assert all(t != loop_thread for t in sweep_threads)
    assert all(s == 5.0 for s in sleeps[:3])


# ---------------------------------------------------------------------
# 4. Bounded batches
# ---------------------------------------------------------------------
def test_sweep_processes_at_most_batch_size_and_bounds_discovery():
    repo = MagicMock()
    repo.query_expired_cleanup_operations_sync.return_value = _ops(25)
    repo.execute_cleanup_recovery_workflow_sync.return_value = {
        "status": "CLEANUP_RECOVERY_COMPLETED"
    }
    summary = run_storage_cleanup_recovery_sweep(repo, batch_size=10)

    assert repo.execute_cleanup_recovery_workflow_sync.call_count == 10
    assert summary["processed"] == 10 and summary["completed"] == 10
    kwargs = repo.query_expired_cleanup_operations_sync.call_args.kwargs
    assert kwargs["limit"] == 40  # bounded window, never "all operations"
    assert kwargs["limit"] <= 100
    call = repo.execute_cleanup_recovery_workflow_sync.call_args_list[0].kwargs
    assert call["recovery_actor_id"] == SYSTEM_RECOVERY_ACTOR_ID
    assert call["recovery_actor_role"] == SYSTEM_RECOVERY_ACTOR_ROLE == "system"


def test_worker_uses_configured_batch_size(monkeypatch):
    monkeypatch.setattr(settings, "STORAGE_CLEANUP_RECOVERY_BATCH_SIZE", 3)
    repo = _cloud_repo_mock()
    repo.query_expired_cleanup_operations_sync.return_value = _ops(12)
    repo.execute_cleanup_recovery_workflow_sync.return_value = {
        "status": "CLEANUP_RECOVERY_COMPLETED"
    }
    sleeps = []

    async def fake_sleep(sec):
        sleeps.append(sec)
        if len(sleeps) >= 2:
            raise asyncio.CancelledError()

    async def scenario():
        with patch("app.services.persistence_repository.persistence_repo", repo), patch(
            "asyncio.sleep", side_effect=fake_sleep
        ):
            await main_module.storage_cleanup_recovery_loop()

    asyncio.run(scenario())
    assert repo.execute_cleanup_recovery_workflow_sync.call_count == 3


# ---------------------------------------------------------------------
# 5. Transient failure does not terminate the loop; secrets not logged
# ---------------------------------------------------------------------
def test_transient_failure_does_not_terminate_loop_and_logs_safely(caplog):
    calls = {"n": 0}
    sleeps = []

    def flaky_sweep(**kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise StorageError(
                f"boom {_PATH_A} TOP_SECRET_CLEANUP_SERVICE_KEY",
                sqlstate="08006",
                error_category="NETWORK",
            )
        return {}

    async def fake_sleep(sec):
        sleeps.append(sec)
        if len(sleeps) >= 5:
            raise asyncio.CancelledError()
        await _ORIG_SLEEP(0)

    async def scenario():
        with patch(
            "app.services.persistence_repository.persistence_repo", _cloud_repo_mock()
        ), patch(
            "app.services.storage_cleanup_recovery.run_storage_cleanup_recovery_sweep",
            side_effect=flaky_sweep,
        ), patch("asyncio.sleep", side_effect=fake_sleep):
            await main_module.storage_cleanup_recovery_loop()

    with caplog.at_level(logging.ERROR):
        asyncio.run(scenario())

    assert calls["n"] >= 2, "loop must survive the failure and run again"
    assert 5.0 in sleeps, "failure backoff sleep expected"
    assert "Storage cleanup recovery sweep failed" in caplog.text
    assert "StorageError" in caplog.text and "08006" in caplog.text
    assert "TOP_SECRET_CLEANUP_SERVICE_KEY" not in caplog.text
    assert _PATH_A not in caplog.text


# ---------------------------------------------------------------------
# 6. Cloud not configured / mock: no cleanup executed
# ---------------------------------------------------------------------
@pytest.mark.parametrize("configured,is_mock", [(False, False), (True, True)])
def test_unconfigured_or_mock_repo_never_runs_cleanup(configured, is_mock):
    repo = MagicMock()
    repo.is_storage_configured = configured
    repo.is_mock = is_mock
    sleeps = []

    async def fake_sleep(sec):
        sleeps.append(sec)
        if len(sleeps) >= 3:
            raise asyncio.CancelledError()

    async def scenario():
        with patch("app.services.persistence_repository.persistence_repo", repo), patch(
            "app.services.storage_cleanup_recovery.run_storage_cleanup_recovery_sweep"
        ) as mock_sweep, patch("asyncio.sleep", side_effect=fake_sleep):
            await main_module.storage_cleanup_recovery_loop()
            mock_sweep.assert_not_called()

    asyncio.run(scenario())
    repo.query_expired_cleanup_operations_sync.assert_not_called()
    repo.execute_cleanup_recovery_workflow_sync.assert_not_called()


# ---------------------------------------------------------------------
# 7. Shutdown: in-flight operation is not abandoned; no unhandled exception
# ---------------------------------------------------------------------
def test_shutdown_waits_for_in_flight_operation_and_raises_nothing():
    entered = threading.Event()
    release = threading.Event()
    seen = {"calls": 0, "stop_flag_after": None}

    def blocking_sweep(**kwargs):
        seen["calls"] += 1
        entered.set()
        assert release.wait(timeout=10)
        seen["stop_flag_after"] = kwargs["should_stop"]()
        return {}

    async def fake_sleep(sec):
        await _ORIG_SLEEP(0)

    async def scenario():
        with patch(
            "app.services.persistence_repository.persistence_repo", _cloud_repo_mock()
        ), patch(
            "app.services.storage_cleanup_recovery.run_storage_cleanup_recovery_sweep",
            side_effect=blocking_sweep,
        ), patch("asyncio.sleep", side_effect=fake_sleep):
            task = main_module.start_storage_cleanup_recovery_task()
            for _ in range(500):
                if entered.is_set():
                    break
                await _ORIG_SLEEP(0.01)
            assert entered.is_set()

            stopper = asyncio.create_task(main_module.stop_storage_cleanup_recovery_task())
            await _ORIG_SLEEP(0.1)
            assert not stopper.done(), "stop must wait for the in-flight sweep, not abandon it"
            release.set()
            await asyncio.wait_for(stopper, timeout=10)
            assert task.done() and task.exception() is None

    asyncio.run(scenario())
    assert seen["calls"] == 1
    assert seen["stop_flag_after"] is True, "in-flight sweep must observe the stop signal"


def test_sweep_stops_between_operations_when_stop_requested():
    repo = MagicMock()
    repo.query_expired_cleanup_operations_sync.return_value = _ops(5)
    stop = threading.Event()

    def execute(**kwargs):
        stop.set()
        return {"status": "CLEANUP_RECOVERY_COMPLETED"}

    repo.execute_cleanup_recovery_workflow_sync.side_effect = execute
    summary = run_storage_cleanup_recovery_sweep(repo, batch_size=5, should_stop=stop.is_set)
    assert repo.execute_cleanup_recovery_workflow_sync.call_count == 1
    assert summary["stopped_early"] == 1


# ---------------------------------------------------------------------
# 8. Lease / failure semantics and failure isolation
# ---------------------------------------------------------------------
def test_failed_operation_is_isolated_and_uncertain_is_not_success(caplog):
    repo = MagicMock()
    repo.query_expired_cleanup_operations_sync.return_value = _ops(5)
    outcomes = {
        "clean_0000": StorageLeaseLostError("lease", sqlstate="P0412"),
        "clean_0001": StorageError(f"leak {_PATH_A}", sqlstate="42501", error_category="RPC"),
        "clean_0002": {
            "status": "CLEANUP_RECOVERY_PARTIAL_UNCERTAIN",
            "uncertain_paths": [_PATH_A],
        },
        "clean_0003": {"status": "CLEANUP_ALREADY_CONFIRMED"},
        "clean_0004": {"status": "CLEANUP_RECOVERY_COMPLETED"},
    }

    def execute(**kwargs):
        out = outcomes[kwargs["cleanup_id"]]
        if isinstance(out, Exception):
            raise out
        return out

    repo.execute_cleanup_recovery_workflow_sync.side_effect = execute
    backoff = CleanupRecoveryBackoff(clock=lambda: 1000.0)
    with caplog.at_level(logging.INFO):
        summary = run_storage_cleanup_recovery_sweep(repo, batch_size=10, backoff=backoff)

    assert summary["processed"] == 5, "one failure must not prevent other operations"
    assert summary["lease_conflict"] == 1
    assert summary["failed"] == 1
    assert summary["uncertain"] == 1
    assert summary["already_confirmed"] == 1
    assert summary["completed"] == 1, "uncertain deletion must not count as completed"
    assert set(backoff.active_ids()) == {"clean_0000", "clean_0001", "clean_0002"}
    assert _PATH_A not in caplog.text
    assert "leak" not in caplog.text


def test_backed_off_operations_are_excluded_and_cannot_starve_others():
    now = {"t": 1000.0}
    backoff = CleanupRecoveryBackoff(clock=lambda: now["t"])
    backoff.record_failure("clean_0000")
    repo = MagicMock()
    # Discovery ignores the exclusion (defensive) and still returns the backed-off op first.
    repo.query_expired_cleanup_operations_sync.return_value = _ops(3)
    repo.execute_cleanup_recovery_workflow_sync.return_value = {
        "status": "CLEANUP_RECOVERY_COMPLETED"
    }
    summary = run_storage_cleanup_recovery_sweep(repo, batch_size=2, backoff=backoff)
    kwargs = repo.query_expired_cleanup_operations_sync.call_args.kwargs
    assert kwargs["exclude_cleanup_ids"] == ["clean_0000"]
    processed_ids = [
        c.kwargs["cleanup_id"] for c in repo.execute_cleanup_recovery_workflow_sync.call_args_list
    ]
    assert processed_ids == ["clean_0001", "clean_0002"]
    assert summary["backed_off_skipped"] == 1

    # Backoff grows exponentially (capped) and expires with the clock.
    backoff.record_failure("clean_0000")
    assert backoff.is_backed_off("clean_0000")
    now["t"] += 60 * 2 + 1
    assert not backoff.is_backed_off("clean_0000")


# ---------------------------------------------------------------------
# 9. Manual recovery endpoint preserved
# ---------------------------------------------------------------------
def test_manual_recovery_endpoint_still_functional(monkeypatch):
    from app.services.persistence_repository import persistence_repo

    monkeypatch.setattr(settings, "SUPABASE_AUTH_ENABLED", True)
    monkeypatch.setattr(settings, "SUPABASE_JWT_SECRET", "test_secret_32_bytes_minimum_length_required_here!!")
    monkeypatch.setattr(settings, "SUPABASE_URL", "https://example.supabase.co")

    client = TestClient(app)
    payload = {
        "cleanup_id": "clean_recovery_01",
        "incident_id": "INC-01",
        "idempotency_key": "recovery_key_12345",
        "scope": "incident_attachment",
        "lease_sec": 60,
    }
    with patch(
        "app.core.security.verify_supabase_jwt",
        return_value={"sub": "worker1", "role": "worker", "extracted_role": "worker"},
    ):
        assert (
            client.post(
                "/api/v1/incidents/maintenance/recover-storage-cleanup",
                json=payload,
                headers={"Authorization": "Bearer w"},
            ).status_code
            == 403
        )
    with patch(
        "app.core.security.verify_supabase_jwt",
        return_value={"sub": "admin_sub", "role": "admin", "extracted_role": "admin"},
    ), patch.object(
        persistence_repo,
        "execute_cleanup_recovery_workflow_sync",
        return_value={"status": "CLEANUP_RECOVERY_COMPLETED", "reconciled_count": 0},
    ) as mock_recovery:
        resp = client.post(
            "/api/v1/incidents/maintenance/recover-storage-cleanup",
            json=payload,
            headers={"Authorization": "Bearer a"},
        )
    assert resp.status_code == 200
    assert resp.json()["status"] == "CLEANUP_RECOVERY_COMPLETED"
    assert mock_recovery.call_args.kwargs["recovery_actor_id"] == "admin_sub"


# ---------------------------------------------------------------------
# 10. Referenced photos cannot be deleted through the automated worker
# ---------------------------------------------------------------------
def test_worker_deletes_only_rpc_authorized_paths_never_referenced_photo():
    repo = _real_cloud_repo()
    rpc_calls = []

    def fake_rpc(name, payload):
        rpc_calls.append(name)
        if name == "claim_expired_cleanup_operation_rpc":
            assert payload["p_recovery_actor_role"] == "system"
            assert payload["p_recovery_lease_owner"].startswith("rec_lease_")
            # DB authorizes only path A; B is still referenced (retained shared path).
            return {
                "status": "CLEANUP_RECOVERY_CLAIMED",
                "remaining_paths": [_PATH_A],
            }
        if name == "reconcile_storage_orphan_rpc":
            assert payload["p_object_path"] == _PATH_A
            return {"status": "RECONCILED", "object_path": _PATH_A}
        raise AssertionError(f"unexpected RPC {name}")

    deleted = []
    with patch.object(repo, "_call_rpc_sync", side_effect=fake_rpc), patch.object(
        repo, "delete_incident_photo", side_effect=lambda p, **kw: deleted.append(p) or True
    ), patch.object(
        repo, "query_expired_cleanup_operations_sync", return_value=_ops(1)
    ):
        summary = run_storage_cleanup_recovery_sweep(repo, batch_size=5)

    assert deleted == [_PATH_A]
    assert _PATH_B_REFERENCED not in deleted
    assert summary["completed"] == 1
    assert rpc_calls == [
        "claim_expired_cleanup_operation_rpc",
        "reconcile_storage_orphan_rpc",
    ]


def test_worker_never_deletes_when_claim_rpc_refuses():
    repo = _real_cloud_repo()
    refusal = StorageError("denied", sqlstate="42501", error_category="RPC")
    with patch.object(repo, "_call_rpc_sync", side_effect=refusal), patch.object(
        repo, "delete_incident_photo"
    ) as mock_delete, patch.object(
        repo, "query_expired_cleanup_operations_sync", return_value=_ops(2)
    ):
        summary = run_storage_cleanup_recovery_sweep(repo, batch_size=5)
    mock_delete.assert_not_called()
    assert summary["failed"] == 2


def test_uncertain_storage_delete_is_recorded_not_reconciled():
    repo = _real_cloud_repo()
    names = []

    def fake_rpc(name, payload):
        names.append(name)
        if name == "claim_expired_cleanup_operation_rpc":
            return {"status": "CLEANUP_RECOVERY_CLAIMED", "remaining_paths": [_PATH_A]}
        if name == "record_storage_cleanup_uncertain_rpc":
            return {"status": "UNCERTAIN"}
        raise AssertionError(f"unexpected RPC {name}")

    with patch.object(repo, "_call_rpc_sync", side_effect=fake_rpc), patch.object(
        repo, "delete_incident_photo", side_effect=StorageError("storage down")
    ), patch.object(repo, "query_expired_cleanup_operations_sync", return_value=_ops(1)):
        summary = run_storage_cleanup_recovery_sweep(repo, batch_size=5)

    assert "reconcile_storage_orphan_rpc" not in names
    assert "record_storage_cleanup_uncertain_rpc" in names
    assert summary["uncertain"] == 1 and summary["completed"] == 0


# ---------------------------------------------------------------------
# Discovery query (mock HTTP only)
# ---------------------------------------------------------------------
def _resp(status, body):
    r = MagicMock(spec=httpx.Response)
    r.status_code = status
    r.json.return_value = body
    return r


def test_discovery_query_is_read_only_bounded_and_filters_terminal_states():
    repo = _real_cloud_repo()
    good = _ops(1)[0]
    rows = [
        good,
        {"cleanup_id": "bad id!", "incident_id": "INC-01", "idempotency_key": "idem_key_9999", "scope": "s"},
        "not-a-dict",
    ]
    with patch("app.services.persistence_repository.httpx.Client") as cls:
        client = cls.return_value.__enter__.return_value
        client.get.return_value = _resp(200, rows)
        result = repo.query_expired_cleanup_operations_sync(
            limit=10, exclude_cleanup_ids=["clean_x1"]
        )
        client.post.assert_not_called()
        client.request.assert_not_called()
        client.delete.assert_not_called()
        args, kwargs = client.get.call_args
        assert args[0].endswith("/rest/v1/storage_cleanup_operations")
        params = dict(kwargs["params"])
        assert params["status"] == "in.(PENDING,PARTIAL,UNCERTAIN)"
        assert "CONFIRMED" not in params["status"] and "NO_OP" not in params["status"]
        assert params["expires_at"].startswith("lt.")
        assert params["limit"] == "10"
        assert params["order"] == "expires_at.asc,cleanup_id.asc"
        assert params["cleanup_id"] == "not.in.(clean_x1)"
        assert "select" in params and "*" not in params["select"]
    assert result == [good]


def test_discovery_query_validation_and_sanitized_errors():
    repo = _real_cloud_repo()
    for bad in (0, 101, True, "5"):
        with pytest.raises(StorageValidationError):
            repo.query_expired_cleanup_operations_sync(limit=bad)
    with pytest.raises(StorageValidationError):
        repo.query_expired_cleanup_operations_sync(limit=5, exclude_cleanup_ids=["a,b)"])

    with patch("app.services.persistence_repository.httpx.Client") as cls:
        client = cls.return_value.__enter__.return_value
        resp = _resp(500, None)
        resp.text = "TOP_SECRET_CLEANUP_SERVICE_KEY SQL DETAIL"
        client.get.return_value = resp
        with pytest.raises(StorageError) as exc:
            repo.query_expired_cleanup_operations_sync(limit=5)
        assert "TOP_SECRET" not in str(exc.value)
        client.get.return_value = _resp(403, None)
        with pytest.raises(StorageError) as exc2:
            repo.query_expired_cleanup_operations_sync(limit=5)
        assert exc2.value.error_category == "AUTH_ERROR"
        client.get.side_effect = httpx.ConnectError("TOP_SECRET net detail")
        with pytest.raises(StorageError) as exc3:
            repo.query_expired_cleanup_operations_sync(limit=5)
        assert "TOP_SECRET" not in str(exc3.value)


def test_discovery_requires_service_role_storage_configuration():
    from app.services.persistence_repository import StorageNotConfiguredError

    repo = PersistenceRepository(supabase_url="https://mock.supabase.co", supabase_key="anon")
    with pytest.raises(StorageNotConfiguredError):
        repo.query_expired_cleanup_operations_sync(limit=5)


# ---------------------------------------------------------------------
# Configuration bounds
# ---------------------------------------------------------------------
def test_configuration_defaults_and_bounds():
    assert settings.STORAGE_CLEANUP_RECOVERY_INTERVAL_SEC == 300.0
    assert settings.STORAGE_CLEANUP_RECOVERY_BATCH_SIZE == 10
    for field, bad in (
        ("STORAGE_CLEANUP_RECOVERY_INTERVAL_SEC", 4.9),
        ("STORAGE_CLEANUP_RECOVERY_INTERVAL_SEC", 86401.0),
        ("STORAGE_CLEANUP_RECOVERY_BATCH_SIZE", 0),
        ("STORAGE_CLEANUP_RECOVERY_BATCH_SIZE", 51),
    ):
        with pytest.raises(ValidationError):
            Settings(**{field: bad})
    Settings(STORAGE_CLEANUP_RECOVERY_INTERVAL_SEC=5.0, STORAGE_CLEANUP_RECOVERY_BATCH_SIZE=50)
