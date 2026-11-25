import asyncio
import logging
import threading
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

logger = logging.getLogger("drainx.main")

from app.core.config import settings, validate_production_configuration
from app.api.v1.router import api_v1_router
from app.services.state_store import state_store
from app.services.scenario_benchmark import scenario_runner
from app.services.telemetry_stream_manager import telemetry_stream_manager
from app.services.incident_stream_manager import incident_stream_manager
from app.services.directive_audit_outbox_worker import (
    start_directive_audit_outbox_worker,
    stop_directive_audit_outbox_worker,
)
from app.models.contracts import (
    SensorReadingContract,
    SensorType,
    MeasurementUnit,
    DataSource,
    SensorHealthStatus,
)


async def simulation_background_loop():
    """
    Background task to advance active scenario simulation in real-time.
    Explicitly guarded by operational mode: only runs when in SIMULATION mode.
    Cannot run or mutate state when in PHYSICAL or SAFE_HOLD mode.
    """
    while True:
        try:
            if state_store.is_simulation() and scenario_runner.is_running:
                scenario_runner.step(dt=0.5)
                if scenario_runner.last_step_telemetry:
                    await telemetry_stream_manager.broadcast_readings(
                        readings=scenario_runner.last_step_telemetry,
                        operational_mode=state_store.mode,
                    )
            await asyncio.sleep(0.5)
        except asyncio.CancelledError:
            break
        except Exception as e:
            # Prevent background loop from crashing
            await asyncio.sleep(1.0)


async def duplicate_scan_recovery_loop():
    """
    Background recovery task for stalled or un-scanned duplicate detection jobs.
    Runs periodically according to settings.DUPLICATE_SCAN_RECOVERY_INTERVAL_SEC.
    Uses anyio.to_thread.run_sync to avoid blocking the asyncio event loop.
    """
    import anyio
    from app.services.persistence_repository import persistence_repo
    from app.services.duplicate_detector import recover_pending_cloud_duplicate_scans

    while True:
        try:
            interval = getattr(settings, "DUPLICATE_SCAN_RECOVERY_INTERVAL_SEC", 30.0)
            await asyncio.sleep(interval)

            if not getattr(settings, "DUPLICATE_DETECTION_ENABLED", True):
                continue

            if persistence_repo.is_storage_configured and not getattr(persistence_repo, "is_mock", False):
                def _run_recovery():
                    return recover_pending_cloud_duplicate_scans(
                        repo=persistence_repo,
                        state_store=state_store,
                        current_settings=settings,
                        batch_size=10,
                        lease_sec=60,
                    )

                await anyio.to_thread.run_sync(_run_recovery)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.error(
                "Duplicate scan recovery sweep failed (error_type=%s, sqlstate=%s, category=%s); retrying after backoff.",
                exc.__class__.__name__,
                getattr(exc, "sqlstate", None) or "NONE",
                getattr(exc, "error_category", None) or "UNEXPECTED",
                exc_info=True,
            )
            await asyncio.sleep(5.0)


_storage_cleanup_stop = threading.Event()
_storage_cleanup_task: Optional["asyncio.Task[None]"] = None


async def storage_cleanup_recovery_loop():
    """
    Background recovery task for expired incident-photo storage cleanup operations.

    - Runs every settings.STORAGE_CLEANUP_RECOVERY_INTERVAL_SEC; one bounded batch per sweep
      (settings.STORAGE_CLEANUP_RECOVERY_BATCH_SIZE).
    - Blocking repository work runs via anyio.to_thread.run_sync (never on the event loop).
    - Skipped entirely unless cloud storage (service-role) is configured; no in-memory fallback.
    - Transient errors are logged (type/sqlstate/category only) and retried after backoff.
    - On shutdown the stop event prevents new operations from starting; the thread currently
      in flight is allowed to finish its in-progress operation (anyio threads are not abandoned).
    """
    import anyio
    from app.services.persistence_repository import persistence_repo
    from app.services.storage_cleanup_recovery import (
        CleanupRecoveryBackoff,
        run_storage_cleanup_recovery_sweep,
    )

    backoff = CleanupRecoveryBackoff()

    while True:
        try:
            await asyncio.sleep(settings.STORAGE_CLEANUP_RECOVERY_INTERVAL_SEC)

            if _storage_cleanup_stop.is_set():
                break

            if not persistence_repo.is_storage_configured or getattr(persistence_repo, "is_mock", False):
                continue

            def _run_sweep():
                return run_storage_cleanup_recovery_sweep(
                    repo=persistence_repo,
                    batch_size=settings.STORAGE_CLEANUP_RECOVERY_BATCH_SIZE,
                    backoff=backoff,
                    should_stop=_storage_cleanup_stop.is_set,
                )

            # Run the blocking sweep in a worker thread. The await is shielded because a plain
            # task.cancel() would otherwise abandon the thread mid-operation; on cancellation we
            # drain the in-flight sweep (which stops starting new operations via the stop event).
            work = asyncio.ensure_future(anyio.to_thread.run_sync(_run_sweep))
            try:
                await asyncio.shield(work)
            except asyncio.CancelledError:
                try:
                    await work
                except asyncio.CancelledError:
                    pass
                except Exception as drain_exc:
                    logger.error(
                        "Storage cleanup recovery in-flight sweep ended with error during shutdown (error_type=%s).",
                        drain_exc.__class__.__name__,
                    )
                break
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.error(
                "Storage cleanup recovery sweep failed (error_type=%s, sqlstate=%s, category=%s); retrying after backoff.",
                exc.__class__.__name__,
                getattr(exc, "sqlstate", None) or "NONE",
                getattr(exc, "error_category", None) or "UNEXPECTED",
            )
            try:
                await asyncio.sleep(5.0)
            except asyncio.CancelledError:
                break


def start_storage_cleanup_recovery_task() -> "asyncio.Task[None]":
    """Starts the cleanup recovery worker; returns the existing live task if already running."""
    global _storage_cleanup_task
    if _storage_cleanup_task is not None and not _storage_cleanup_task.done():
        return _storage_cleanup_task
    _storage_cleanup_stop.clear()
    _storage_cleanup_task = asyncio.create_task(storage_cleanup_recovery_loop())
    return _storage_cleanup_task


async def stop_storage_cleanup_recovery_task() -> None:
    """Signals stop, cancels and awaits the worker, swallowing only its cancellation."""
    global _storage_cleanup_task
    task = _storage_cleanup_task
    _storage_cleanup_stop.set()
    if task is None:
        return
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    except Exception as exc:
        logger.error("Storage cleanup recovery task ended with error: %s", exc.__class__.__name__)
    finally:
        _storage_cleanup_task = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application Lifespan Manager.
    Seeds initial baseline sensors and starts background simulation loop.
    Enforces production fail-closed configuration validation.
    """
    # Enforce strict fail-closed configuration validation in production
    validate_production_configuration(settings)

    if settings.SYSTEM_MODE == "SIMULATION":
        # Seed initial baseline state
        state_store.ingest_reading(
            SensorReadingContract(
                sensor_id="US_UPSTREAM_01",
                section_id="SEC_SCREENING",
                sensor_type=SensorType.WATER_LEVEL,
                value=4.8,
                unit=MeasurementUnit.CENTIMETRE,
                source=DataSource.SIMULATED,
                status=SensorHealthStatus.OK,
                metadata={"description": "Upstream water level before primary net"}
            )
        )
        state_store.ingest_reading(
            SensorReadingContract(
                sensor_id="US_WEIR_02",
                section_id="SEC_OUTLET",
                sensor_type=SensorType.WATER_LEVEL,
                value=1.5,
                unit=MeasurementUnit.CENTIMETRE,
                source=DataSource.SIMULATED,
                status=SensorHealthStatus.OK,
                metadata={"description": "Head over sharp-crested outlet weir"}
            )
        )
        state_store.ingest_reading(
            SensorReadingContract(
                sensor_id="PUMP_INFLOW_01",
                section_id="SEC_INFLOW",
                sensor_type=SensorType.FLOW_RATE,
                value=5.0,
                unit=MeasurementUnit.LITRES_PER_MINUTE,
                source=DataSource.SIMULATED,
                status=SensorHealthStatus.OK,
                metadata={"description": "Calibrated pump circulation inflow"}
            )
        )

    # Recover any incomplete actuator directives from persistence repository
    try:
        from app.services.persistence_repository import persistence_repo
        from app.models.contracts import (
            AlertSeverity,
            DirectiveEventType,
            DirectiveIssuerType,
            normalize_audit_timestamp_utc,
        )
        recovered = persistence_repo.recover_incomplete_directives_sync()
        for rec in recovered:
            d_id = rec.get("directive_id")
            section_id = rec.get("section_id")
            operational_mode = rec.get("operational_mode")
            action = rec.get("action")
            gate_target_angle = rec.get("gate_target_angle")
            reason = rec.get("reason")

            # Fail closed: reject rows missing any mandatory database column
            if (
                not d_id
                or not section_id
                or not operational_mode
                or action is None
                or gate_target_angle is None
                or reason is None
            ):
                logger.error(
                    "Actuator directive recovery failed closed: incomplete persisted record '%s' missing mandatory fields.",
                    d_id or "<missing_id>",
                )
                continue

            try:
                raw_ts = rec.get("timestamp")
                ts = normalize_audit_timestamp_utc(raw_ts) if raw_ts is not None else None
                if ts is None:
                    logger.error(
                        "Actuator directive recovery failed closed: directive '%s' has null timestamp.",
                        d_id,
                    )
                    continue

                directive = ActuatorDirectiveContract(
                    directive_id=d_id,
                    device_id=rec.get("device_id"),
                    section_id=section_id,
                    operational_mode=operational_mode,
                    directive_type=rec.get("directive_type", "DIVERSION_GATE"),
                    action=action,
                    gate_target_angle=float(gate_target_angle),
                    reason=reason,
                    risk_level=rec.get("risk_level", AlertSeverity.INFO),
                    emergency_stop=bool(rec.get("emergency_stop", False)),
                    issuer_type=rec.get("issuer_type", DirectiveIssuerType.AUTOMATED_ENGINE),
                    issuer_id=rec.get("issuer_id", "startup_recovery"),
                    correlation_id=rec.get("correlation_id"),
                    device_session_epoch=rec.get("device_session_epoch"),
                    baseline_device_sequence_number=rec.get("baseline_device_sequence_number"),
                    timestamp=ts,
                )
                event_type_raw = rec.get("event_type", "ISSUED")
                state_store.reconcile_recovered_directive(
                    directive, DirectiveEventType(event_type_raw)
                )
            except Exception as exc:
                logger.error(
                    "Actuator directive recovery failed closed for directive '%s': %s",
                    d_id,
                    exc,
                )
    except Exception as exc:
        logger.warning("Actuator directive recovery on startup error: %s", exc)

    # Start simulation worker, duplicate scan recovery, and directive audit outbox tasks
    sim_task = asyncio.create_task(simulation_background_loop())
    dup_task = asyncio.create_task(duplicate_scan_recovery_loop())
    start_storage_cleanup_recovery_task()
    start_directive_audit_outbox_worker()

    # Start incident stream manager heartbeat and set event loop
    loop = asyncio.get_running_loop()
    incident_stream_manager.set_loop(loop)
    incident_stream_manager.start_heartbeat()

    yield
    # Cleanup tasks
    await stop_directive_audit_outbox_worker()
    await stop_storage_cleanup_recovery_task()
    dup_task.cancel()
    try:
        await dup_task
    except asyncio.CancelledError:
        pass
    sim_task.cancel()
    try:
        await sim_task
    except asyncio.CancelledError:
        pass
    # Shutdown live incident stream manager and telemetry stream manager
    await incident_stream_manager.shutdown()
    await telemetry_stream_manager.shutdown()


# CORS Middleware configuration
def _get_cors_origins() -> list[str]:
    origins = list(settings.CORS_ORIGINS)
    if settings.ADDITIONAL_CORS_ORIGINS:
        extra = [o.strip() for o in settings.ADDITIONAL_CORS_ORIGINS.split(",") if o.strip()]
        for origin in extra:
            if origin not in origins:
                origins.append(origin)
    return origins


def create_app() -> FastAPI:
    """Create and configure the FastAPI application based on current settings."""
    is_prod = settings.ENVIRONMENT == "production"
    application = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        description="DRAIN-X Modular Monolith Backend: Authoritative state, simulation engine, and predictive monitoring.",
        lifespan=lifespan,
        docs_url=None if is_prod else "/docs",
        redoc_url=None if is_prod else "/redoc",
        openapi_url=None if is_prod else "/openapi.json",
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=_get_cors_origins(),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount API Routers
    application.include_router(api_v1_router, prefix=settings.API_V1_PREFIX)

    @application.get("/", tags=["Root"])
    async def root():
        return {
            "project": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "mode": state_store.mode,
            "docs_url": None if settings.ENVIRONMENT == "production" else "/docs",
            "api_v1": settings.API_V1_PREFIX,
        }

    return application


app = create_app()
