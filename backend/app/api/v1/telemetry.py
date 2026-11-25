import logging
from dataclasses import dataclass
from typing import List, Union, Optional, Dict, Any, Set, FrozenSet
from datetime import datetime, timezone
import asyncio
import anyio
from fastapi import APIRouter, Query, status, HTTPException, WebSocket, WebSocketDisconnect, Depends
from app.models.contracts import (
    SensorReadingContract,
    TelemetryIngestResponse,
    DataSource,
    ActuatorDirectiveContract,
    ActuatorDirectiveEventContract,
    ActuatorDirectiveResponseContract,
    AlertSeverity,
    DirectiveIssuerType,
    DirectiveAuditOutboxFullError,
    StreamInitMessage,
    TelemetryStreamEvent,
    utc_now,
)
from app.core.config import settings
from app.core.security import verify_device_key, require_roles
from app.services.state_store import state_store, validate_and_normalize_field_team
from app.services.fault_detector import fault_detector
from app.services.blockage_detector import blockage_detector
from app.services.prediction_engine import prediction_engine
from app.services.intervention_engine import intervention_engine
from app.services.persistence_repository import (
    persistence_repo,
    DirectiveAuditConflictError,
    StorageError,
    StorageNotConfiguredError,
)
from app.services.telemetry_stream_manager import telemetry_stream_manager
from app.services.directive_audit_outbox_worker import flush_and_persist_outbox
from app.services.circuit_breaker import CircuitBreakerOpenError
from app.services.time_series_analytics import (
    aggregate_time_series,
    calculate_water_level_trend,
    calculate_flow_trend,
)

logger = logging.getLogger("drainx.api.telemetry")

router = APIRouter(prefix="/telemetry", tags=["Telemetry"])


def _validate_timezone_bounds(start_time: Optional[datetime], end_time: Optional[datetime]) -> None:
    """
    Validates that query time bounds are timezone-aware and chronological.
    Rejects naive datetimes to avoid ambiguous server-local conversions.
    """
    if start_time is not None and (start_time.tzinfo is None or start_time.tzinfo.utcoffset(start_time) is None):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="start_time must be timezone-aware (e.g. ISO-8601 with UTC offset like 'Z' or '+00:00').",
        )
    if end_time is not None and (end_time.tzinfo is None or end_time.tzinfo.utcoffset(end_time) is None):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="end_time must be timezone-aware (e.g. ISO-8601 with UTC offset like 'Z' or '+00:00').",
        )
    if start_time and end_time and start_time > end_time:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="start_time must not be later than end_time.",
        )


@router.post("", response_model=TelemetryIngestResponse, status_code=status.HTTP_201_CREATED, summary="Ingest sensor reading(s)")
@router.post("/ingest", response_model=TelemetryIngestResponse, status_code=status.HTTP_201_CREATED, summary="Ingest sensor reading(s) (canonical alias)")
async def ingest_telemetry(
    payload: Union[SensorReadingContract, List[SensorReadingContract]],
    device_key: Optional[str] = Depends(verify_device_key),
):
    """
    Ingest validated sensor telemetry and immediately execute the analytics pipeline.
    Accepts either a single SensorReadingContract or a list of readings.
    Used by physical ESP32 adapters, simulation runners, and MQTT bridges alike.
    
    Processing steps:
    1. Store readings into thread-safe in-memory state store and circular history buffer.
    2. Evaluate individual reading plausibility, ranges, and spike faults.
    3. Evaluate system-level sensor health, staleness, and cross-consistency.
    4. Run hydraulic blockage detection and localization across monitored sections.
    5. Run Time-to-Critical (TTC) predictive linear regression.
    6. Compute real-time actuator directives (diversion gate angle & action).
    7. Return structured ingestion response with analytics snapshot.
    """
    readings = payload if isinstance(payload, list) else [payload]
    single_msg_id = payload.message_id if isinstance(payload, SensorReadingContract) else None

    # Strict operational mode validation: prevent cross-contamination
    if state_store.is_simulation() and any(r.source in (DataSource.PHYSICAL, DataSource.LIVE) for r in readings):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="System is in SIMULATION mode. Physical hardware telemetry rejected to prevent simulation contamination. Explicitly switch mode to PHYSICAL first.",
        )

    if state_store.is_physical() and any(r.source == DataSource.SIMULATED for r in readings):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="System is in PHYSICAL mode. Simulated telemetry rejected to prevent hardware state contamination. Explicitly switch mode to SIMULATION first.",
        )

    if state_store.is_safe_hold() and any(r.source == DataSource.SIMULATED for r in readings):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="System is in SAFE_HOLD mode. Simulated telemetry rejected.",
        )

    # 1. Store reading and validate plausibility
    for reading in readings:
        state_store.ingest_reading(reading)
        fault_detector.evaluate_reading(reading)

    try:
        # 1b. Observation session tracking, reboot candidate checks & partial-batch coalescing
        state_store.process_telemetry_observation(readings)

        # 2. System-level health and cross-consistency
        fault_detector.evaluate_system_health()

        # 3. Blockage detection and localization
        blockage = blockage_detector.evaluate()

        # 4. Predictive trend estimation & TTC
        prediction = prediction_engine.evaluate()

        # 5. Actuator & diversion gate directive
        inferred_device_id: Optional[str] = None
        for reading in readings:
            cand_dev = getattr(reading, "device_id", None)
            if not cand_dev and isinstance(reading.metadata, dict):
                cand_dev = reading.metadata.get("device_id")
            if isinstance(cand_dev, str) and cand_dev.strip():
                inferred_device_id = cand_dev.strip()
                break

        if state_store.is_safe_hold():
            directive = ActuatorDirectiveContract(
                device_id=inferred_device_id,
                gate_target_angle=settings.SAFE_HOLD_GATE_ANGLE,
                action="SAFE_HOLD_LOCK",
                reason=f"SAFE_HOLD active: automated actuation locked to fail-safe angle ({settings.SAFE_HOLD_GATE_ANGLE} deg).",
                risk_level=AlertSeverity.HIGH,
                emergency_stop=True,
                issuer_type=DirectiveIssuerType.SAFETY_INTERLOCK,
                issuer_id="safety_interlock",
            )
        else:
            directive = intervention_engine.compute_gate_directive()
            if state_store.is_physical() and directive.device_id is None and inferred_device_id is not None:
                directive.device_id = inferred_device_id
        state_store.set_gate_directive(directive)

        # 5b. Periodic check for verification timeouts & flush audit outbox
        state_store.evaluate_verification_timeouts()
    except DirectiveAuditOutboxFullError as exc:
        logger.error("Actuator directive audit outbox capacity exceeded: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Actuator directive audit outbox capacity exceeded; persistence backpressure applied.",
        ) from exc

    try:
        await flush_and_persist_outbox(raise_on_error=True)
    except StorageNotConfiguredError as exc:
        logger.error("Actuator directive audit persistence unavailable due to configuration error.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Persistent actuator directive audit store is misconfigured or unavailable.",
        ) from exc
    except DirectiveAuditConflictError as exc:
        logger.error("Actuator directive audit immutability conflict rejected.")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Actuator directive audit immutability conflict detected.",
        ) from exc
    except CircuitBreakerOpenError as exc:
        logger.warning(
            "Actuator directive audit persistence circuit breaker OPEN (remaining: %.1fs): %s",
            exc.remaining_backoff,
            exc,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Persistent actuator directive audit store is unavailable.",
        ) from exc
    except StorageError as exc:
        logger.error("Actuator directive audit persistence failed.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Persistent actuator directive audit store is unavailable.",
        ) from exc

    # 6. Active alert count
    active_alerts = len(state_store.get_alerts(active_only=True))

    # 7. Asynchronously trigger persistence to Supabase / repository
    await persistence_repo.persist_readings(readings)

    # 8. Broadcast newly ingested readings to live stream clients
    await telemetry_stream_manager.broadcast_readings(
        readings=readings,
        operational_mode=state_store.mode,
    )

    return TelemetryIngestResponse(
        status="success",
        ingested_count=len(readings),
        message_id=single_msg_id,
        prediction=prediction,
        blockage=blockage,
        active_alerts_count=active_alerts,
        gate_directive=directive,
        gate_command=directive,
    )


@router.get("/latest", summary="Get latest readings across all sensors")
async def get_latest_telemetry():
    """
    Returns the most recent reading from each active sensor.
    """
    return {
        "status": "success",
        "readings": state_store.get_latest_readings()
    }


_VALID_DIRECTIVE_MODES: FrozenSet[str] = frozenset({"SIMULATION", "PHYSICAL", "SAFE_HOLD"})

_CANONICAL_DEVICE_SCOPE_KEYS: tuple[str, ...] = ("assigned_devices", "allowed_devices")
_CANONICAL_SECTION_SCOPE_KEYS: tuple[str, ...] = ("assigned_sections", "allowed_sections")
_UNSUPPORTED_SINGULAR_SCOPE_KEYS: FrozenSet[str] = frozenset({
    "assigned_device",
    "allowed_device",
    "device_id",
    "assigned_section",
    "allowed_section",
    "section_id",
})


@dataclass(frozen=True)
class _DirectiveAccessScope:
    user_role: str
    allowed_modes: FrozenSet[str]
    allowed_devices: Optional[Set[str]]
    allowed_sections: Optional[Set[str]]

    @property
    def is_restricted(self) -> bool:
        return (
            self.allowed_modes != _VALID_DIRECTIVE_MODES
            or self.allowed_devices is not None
            or self.allowed_sections is not None
        )


def _extract_canonical_scope_set(
    app_meta: Dict[str, Any], keys: tuple[str, ...]
) -> Optional[Set[str]]:
    """
    Extracts canonical authorization scope arrays exclusively from trusted JWT app_metadata.
    Returns None when none of `keys` are present.
    Fails closed (returns an empty set) if any present key is empty, non-list, contains
    non-string/blank/untrimmed elements, or if multiple present aliases conflict (intersection empty).
    """
    present = [k for k in keys if k in app_meta]
    if not present:
        return None

    intersected: Optional[Set[str]] = None
    for k in present:
        raw_val = app_meta.get(k)
        if not isinstance(raw_val, list) or len(raw_val) == 0:
            return set()
        key_set: Set[str] = set()
        for item in raw_val:
            if not isinstance(item, str) or not item or item != item.strip():
                return set()
            key_set.add(item)
        if intersected is None:
            intersected = key_set
        else:
            intersected = intersected & key_set

    return intersected if intersected is not None else set()


def _worker_needs_registry_lookup(claims: Dict[str, Any]) -> bool:
    """Only fall back to device-registry assignment lookup when a worker has no JWT scope keys."""
    if claims.get("extracted_role") != "worker":
        return False
    app_meta = claims.get("app_metadata") if isinstance(claims.get("app_metadata"), dict) else {}
    has_scope_key = any(
        k in app_meta
        for k in (
            *_CANONICAL_DEVICE_SCOPE_KEYS,
            *_CANONICAL_SECTION_SCOPE_KEYS,
            *_UNSUPPORTED_SINGULAR_SCOPE_KEYS,
        )
    )
    return not has_scope_key


def _validate_directive_query_tokens(
    directive_id: Optional[str] = None,
    section_id: Optional[str] = None,
    device_id: Optional[str] = None,
) -> None:
    try:
        if directive_id is not None:
            persistence_repo._validate_directive_filter_token(directive_id, "directive_id", max_len=36)
        if section_id is not None:
            persistence_repo._validate_directive_filter_token(section_id, "section_id", max_len=64)
        if device_id is not None:
            persistence_repo._validate_directive_filter_token(device_id, "device_id", max_len=64)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


def _resolve_directive_access_scope(
    claims: Dict[str, Any],
    requested_mode: Optional[str] = None,
    requested_device_id: Optional[str] = None,
    requested_section_id: Optional[str] = None,
    devices_registry: Optional[List[Dict[str, Any]]] = None,
) -> _DirectiveAccessScope:
    """
    Resolves least-privilege directive access scope from canonical trusted JWT app_metadata claims
    (matching PostgreSQL Migration 008 RLS semantics) and, for workers lacking explicit JWT scopes,
    authoritative admin-managed device/team assignments.
    """
    if requested_mode is not None and requested_mode not in _VALID_DIRECTIVE_MODES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid operational_mode '{requested_mode}'. Allowed modes: {sorted(_VALID_DIRECTIVE_MODES)}.",
        )

    user_role = claims.get("extracted_role", "citizen")
    if user_role not in ("admin", "municipality", "worker"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Role is not authorized to access actuator directive records.",
        )

    app_meta = claims.get("app_metadata") if isinstance(claims.get("app_metadata"), dict) else {}

    if user_role == "admin":
        return _DirectiveAccessScope(
            user_role=user_role,
            allowed_modes=_VALID_DIRECTIVE_MODES,
            allowed_devices=None,
            allowed_sections=None,
        )

    if any(k in app_meta for k in _UNSUPPORTED_SINGULAR_SCOPE_KEYS):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unsupported singular scope claim in JWT app_metadata; use canonical array claims.",
        )

    if user_role == "municipality":
        allowed_modes = _VALID_DIRECTIVE_MODES
        allowed_devices = _extract_canonical_scope_set(app_meta, _CANONICAL_DEVICE_SCOPE_KEYS)
        allowed_sections = _extract_canonical_scope_set(app_meta, _CANONICAL_SECTION_SCOPE_KEYS)
        if (allowed_devices is not None and len(allowed_devices) == 0) or (
            allowed_sections is not None and len(allowed_sections) == 0
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Authorization scope claim is empty, malformed, or conflicting.",
            )
    else:
        # Worker: strictly PHYSICAL mode only and fail-closed unless validly assigned
        allowed_modes = frozenset({"PHYSICAL"})
        jwt_devices = _extract_canonical_scope_set(app_meta, _CANONICAL_DEVICE_SCOPE_KEYS)
        jwt_sections = _extract_canonical_scope_set(app_meta, _CANONICAL_SECTION_SCOPE_KEYS)
        has_jwt_scope = (jwt_devices is not None) or (jwt_sections is not None)

        if has_jwt_scope:
            if (jwt_devices is not None and len(jwt_devices) == 0) or (
                jwt_sections is not None and len(jwt_sections) == 0
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Field worker JWT scope claim is empty, malformed, or conflicting.",
                )
            allowed_devices = jwt_devices
            allowed_sections = jwt_sections
        else:
            reg_devices: Set[str] = set()
            user_id = str(claims.get("sub") or "").strip()
            worker_team = claims.get("extracted_team")
            worker_team_id: Optional[str] = None
            if isinstance(worker_team, str) and worker_team.strip():
                try:
                    team_obj = validate_and_normalize_field_team(worker_team)
                    worker_team_id = team_obj.team_id if team_obj else None
                except ValueError:
                    worker_team_id = None

            for dev in devices_registry or []:
                if not isinstance(dev, dict) or not dev.get("is_active", True):
                    continue
                dev_id = dev.get("device_id")
                meta = dev.get("metadata") if isinstance(dev.get("metadata"), dict) else {}
                assigned_worker = str(meta.get("assigned_worker_id") or "").strip()
                assigned_team = str(meta.get("assigned_team_id") or "").strip()

                matched = False
                if user_id and assigned_worker and assigned_worker == user_id:
                    matched = True
                elif worker_team_id and assigned_team:
                    try:
                        dev_team_obj = validate_and_normalize_field_team(assigned_team)
                        if dev_team_obj and dev_team_obj.team_id == worker_team_id:
                            matched = True
                    except ValueError:
                        matched = False

                if matched and isinstance(dev_id, str) and dev_id.strip():
                    reg_devices.add(dev_id.strip())

            if not reg_devices:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Field worker has no authorized physical device or section assignments.",
                )
            allowed_devices = reg_devices
            allowed_sections = None

    if requested_mode is not None and requested_mode not in allowed_modes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{user_role}' is not authorized for operational mode '{requested_mode}'.",
        )
    if requested_device_id is not None and allowed_devices is not None and requested_device_id not in allowed_devices:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Not authorized to access directive records for device '{requested_device_id}'.",
        )
    if requested_section_id is not None and allowed_sections is not None and requested_section_id not in allowed_sections:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Not authorized to access directive records for section '{requested_section_id}'.",
        )

    return _DirectiveAccessScope(
        user_role=user_role,
        allowed_modes=allowed_modes,
        allowed_devices=allowed_devices,
        allowed_sections=allowed_sections,
    )


def _is_directive_record_authorized(
    record_mode: Optional[str],
    record_device_id: Optional[str],
    record_section_id: Optional[str],
    scope: _DirectiveAccessScope,
) -> bool:
    if not record_mode or record_mode not in scope.allowed_modes:
        return False
    if scope.allowed_devices is not None:
        if not record_device_id or record_device_id not in scope.allowed_devices:
            return False
    if scope.allowed_sections is not None:
        if not record_section_id or record_section_id not in scope.allowed_sections:
            return False
    return True


def _extract_record_scope_fields(record: Union[Dict[str, Any], ActuatorDirectiveEventContract]) -> tuple[Optional[str], Optional[str], Optional[str]]:
    if isinstance(record, dict):
        return (
            record.get("operational_mode"),
            record.get("device_id"),
            record.get("section_id"),
        )
    return (
        record.operational_mode,
        record.device_id,
        record.section_id,
    )


@router.get("/directives/active", summary="Get active supervisory actuator directive")
async def get_active_directive(
    operational_mode: Optional[str] = Query(default=None, description="Optional mode filter (SIMULATION, PHYSICAL, SAFE_HOLD)"),
    section_id: Optional[str] = Query(default=None, description="Optional hydraulic section filter"),
    device_id: Optional[str] = Query(default=None, description="Optional physical device filter"),
    claims: Dict[str, Any] = Depends(require_roles(["admin", "municipality", "worker"])),
):
    """
    Returns the currently active unsettled supervisory directive and its latest lifecycle status,
    enforcing role, mode, device, and section authorization.
    """
    _validate_directive_query_tokens(section_id=section_id, device_id=device_id)
    devices_registry: Optional[List[Dict[str, Any]]] = None
    if _worker_needs_registry_lookup(claims):
        try:
            devices_registry = await persistence_repo.list_devices(strict=True)
        except RuntimeError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Device registry authorization store is unavailable.",
            ) from exc

    scope = _resolve_directive_access_scope(
        claims=claims,
        requested_mode=operational_mode,
        requested_device_id=device_id,
        requested_section_id=section_id,
        devices_registry=devices_registry,
    )

    target_mode = (
        operational_mode
        if operational_mode is not None
        else ("PHYSICAL" if scope.user_role == "worker" else state_store.mode)
    )
    active = state_store.get_active_directive(mode=target_mode)
    if active is not None:
        if section_id is not None and active.section_id != section_id:
            active = None
        elif device_id is not None and active.device_id != device_id:
            active = None
        elif not _is_directive_record_authorized(target_mode, active.device_id, active.section_id, scope):
            active = None

    try:
        use_cloud_audit = persistence_repo.directive_audit_cloud_mode()
    except StorageNotConfiguredError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Persistent actuator directive audit store is misconfigured or unavailable.",
        ) from exc

    latest_event = None
    if active is not None:
        if use_cloud_audit:
            try:
                raw_audits = await anyio.to_thread.run_sync(
                    lambda: persistence_repo.query_directive_audits_sync(
                        directive_id=active.directive_id,
                        operational_mode=target_mode,
                        section_id=section_id,
                        device_id=device_id,
                        allowed_sections=scope.allowed_sections,
                        allowed_devices=scope.allowed_devices,
                        limit=50,
                        strict=True,
                    )
                )
            except ValueError as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=str(exc),
                ) from exc
            except (StorageNotConfiguredError, RuntimeError) as exc:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Persistent actuator directive audit store is unavailable.",
                ) from exc
            authorized_audits = [
                r for r in raw_audits
                if _is_directive_record_authorized(*_extract_record_scope_fields(r), scope)
            ]
            latest_event = authorized_audits[-1] if authorized_audits else None
        else:
            raw_audits = state_store.get_directive_audits(directive_id=active.directive_id, limit=None)
            authorized_audits = [
                r for r in raw_audits
                if _is_directive_record_authorized(*_extract_record_scope_fields(r), scope)
            ]
            latest_event = authorized_audits[-1] if authorized_audits else None

    return {
        "status": "success",
        "active_directive": active,
        "latest_event": latest_event,
    }


@router.get("/directives/history", summary="Query supervisory actuator directive audit history")
async def get_directive_history(
    directive_id: Optional[str] = Query(default=None, description="Optional directive ID filter"),
    operational_mode: Optional[str] = Query(default=None, description="Optional operational mode filter (SIMULATION, PHYSICAL, SAFE_HOLD)"),
    section_id: Optional[str] = Query(default=None, description="Optional hydraulic section filter"),
    device_id: Optional[str] = Query(default=None, description="Optional device identifier filter"),
    limit: int = Query(default=100, ge=1, le=500),
    claims: Dict[str, Any] = Depends(require_roles(["admin", "municipality", "worker"])),
):
    """
    Returns immutable audit history for supervisory actuator directives from the persistent
    repository when configured (or in-memory store when unconfigured), pushing scope predicates
    down before limiting and enforcing defense-in-depth API authorization.
    """
    _validate_directive_query_tokens(directive_id=directive_id, section_id=section_id, device_id=device_id)
    devices_registry: Optional[List[Dict[str, Any]]] = None
    if _worker_needs_registry_lookup(claims):
        try:
            devices_registry = await persistence_repo.list_devices(strict=True)
        except RuntimeError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Device registry authorization store is unavailable.",
            ) from exc

    scope = _resolve_directive_access_scope(
        claims=claims,
        requested_mode=operational_mode,
        requested_device_id=device_id,
        requested_section_id=section_id,
        devices_registry=devices_registry,
    )

    effective_mode = operational_mode or ("PHYSICAL" if scope.user_role == "worker" else None)

    try:
        use_cloud_audit = persistence_repo.directive_audit_cloud_mode()
    except StorageNotConfiguredError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Persistent actuator directive audit store is misconfigured or unavailable.",
        ) from exc

    if use_cloud_audit:
        try:
            raw_events = await anyio.to_thread.run_sync(
                lambda: persistence_repo.query_directive_audits_sync(
                    directive_id=directive_id,
                    operational_mode=effective_mode,
                    section_id=section_id,
                    device_id=device_id,
                    allowed_sections=scope.allowed_sections,
                    allowed_devices=scope.allowed_devices,
                    limit=limit,
                    strict=True,
                )
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc
        except (StorageNotConfiguredError, RuntimeError) as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Persistent actuator directive audit store is unavailable.",
            ) from exc

        events = [
            r for r in raw_events
            if _is_directive_record_authorized(*_extract_record_scope_fields(r), scope)
            and (effective_mode is None or _extract_record_scope_fields(r)[0] == effective_mode)
            and (section_id is None or _extract_record_scope_fields(r)[2] == section_id)
            and (device_id is None or _extract_record_scope_fields(r)[1] == device_id)
        ]
        if directive_id is not None and not events:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Directive not found.",
            )

        return {
            "status": "success",
            "source": "persistent",
            "count": len(events),
            "events": events,
        }

    # Unconfigured / local in-memory fallback: filter by authorization scope BEFORE slicing limit
    raw_events = state_store.get_directive_audits(directive_id=directive_id, limit=None)
    filtered_events = [
        r for r in raw_events
        if _is_directive_record_authorized(*_extract_record_scope_fields(r), scope)
        and (effective_mode is None or _extract_record_scope_fields(r)[0] == effective_mode)
        and (section_id is None or _extract_record_scope_fields(r)[2] == section_id)
        and (device_id is None or _extract_record_scope_fields(r)[1] == device_id)
    ][-limit:]

    if directive_id is not None and not filtered_events:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Directive not found.",
        )

    return {
        "status": "success",
        "source": "in_memory",
        "count": len(filtered_events),
        "events": filtered_events,
    }


@router.get("/history/{sensor_id}", summary="Get rolling history for a specific sensor")
async def get_sensor_history(sensor_id: str, limit: int = Query(default=100, ge=1, le=500)):
    """
    Returns the rolling buffer of historical readings for a specific sensor.
    """
    history = state_store.get_sensor_history(sensor_id=sensor_id, limit=limit)
    if not history:
        return {
            "status": "empty",
            "sensor_id": sensor_id,
            "readings": []
        }
    return {
        "status": "success",
        "sensor_id": sensor_id,
        "count": len(history),
        "readings": history
    }


@router.get("/persistence/status", summary="Get status of telemetry persistence engine")
async def get_persistence_status():
    """
    Returns the operational configuration of the telemetry persistence repository.
    Reports whether live Supabase PostgREST synchronization is active or running
    in local in-memory fallback mode.
    """
    return {
        "status": "success",
        "persistence": persistence_repo.get_status().model_dump()
    }


@router.post("/persistence/ping", summary="Probe live Supabase connection health")
async def ping_persistence():
    """
    Sends a diagnostic health probe to the configured Supabase Cloud instance,
    measuring round-trip latency and verifying PostgREST responsiveness.
    """
    return await persistence_repo.check_connection()


@router.get("/persistence/historical", summary="Query persistent historical telemetry")
async def query_persistent_telemetry(
    sensor_id: Optional[str] = Query(default=None, description="Optional sensor identifier"),
    source: Optional[str] = Query(default=None, description="Operational source filter: PHYSICAL or SIMULATED"),
    section_id: Optional[str] = Query(default=None, description="Optional drainage section identifier"),
    device_id: Optional[str] = Query(default=None, description="Optional IoT edge node identifier"),
    start_time: Optional[datetime] = Query(default=None, description="ISO timestamp lower bound"),
    end_time: Optional[datetime] = Query(default=None, description="ISO timestamp upper bound"),
    limit: int = Query(default=100, ge=1, le=500, description="Max number of records (1-500)"),
    offset: int = Query(default=0, ge=0, description="Pagination record offset"),
    chronological: bool = Query(default=True, description="Order oldest first if true, newest first if false"),
):
    """
    Queries persistent historical sensor readings from Supabase (or in-memory repository fallback).
    Supports time-range, sensor, device, and operational mode filtering with limit/offset pagination.
    """
    _validate_timezone_bounds(start_time, end_time)

    try:
        records = await persistence_repo.query_historical_telemetry(
            sensor_id=sensor_id,
            source=source,
            section_id=section_id,
            device_id=device_id,
            start_time=start_time,
            end_time=end_time,
            limit=limit,
            offset=offset,
            chronological=chronological,
        )
    except RuntimeError as exc:
        logger.error("Persistent telemetry query failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Downstream database service unavailable",
        )
    is_truncated = (len(records) >= limit)
    return {
        "status": "success",
        "count": len(records),
        "limit": limit,
        "offset": offset,
        "sensor_id": sensor_id,
        "device_id": device_id,
        "source_filter": source,
        "chronological": chronological,
        "is_truncated": is_truncated,
        "truncation_warning": f"Historical query reached limit of {limit} records; additional records may exist in the selected time window." if is_truncated else None,
        "records": records,
    }


@router.get("/analytics/rollup", summary="Get 1-minute or 5-minute statistical rollups")
async def get_telemetry_rollups(
    sensor_id: str = Query(..., description="Target sensor ID (e.g. US_UPSTREAM_01, FS_FLUME_01)"),
    source: Optional[str] = Query(default=None, description="Operational source filter: PHYSICAL or SIMULATED"),
    interval_seconds: int = Query(default=60, description="Bucket interval in seconds (e.g. 60 or 300)"),
    start_time: Optional[datetime] = Query(default=None, description="Optional ISO timestamp lower bound"),
    end_time: Optional[datetime] = Query(default=None, description="Optional ISO timestamp upper bound"),
    limit: Optional[int] = Query(
        default=None,
        ge=1,
        le=10000,
        description=(
            "Max historical samples to aggregate (up to 10,000). "
            "For 5-minute rollups (interval_seconds=300), defaults to 3,600 samples "
            "(approximately 30 minutes at 2 Hz or one hour at 1 Hz). "
            "Explicit time windows or an explicit limit should be supplied for larger historical requests."
        ),
    ),
):
    """
    Computes statistical aggregations (avg, min, max, valid_count) across time buckets.
    Excludes invalid readings, sensor timeouts, and uninstalled hardware faults.
    Zero-flow is preserved as valid data.

    Bounded Query Defaults & Coverage:
    - 1-minute rollups (interval_seconds=60) default to 100 samples when unbounded.
    - 5-minute rollups (interval_seconds=300) default to 3,600 samples when unbounded,
      covering approximately 30 minutes at 2 Hz or one hour at 1 Hz.
    - Explicit time windows (start_time / end_time) automatically elevate the query ceiling
      to 10,000 samples. An explicit limit (up to 10,000) should be supplied for larger
      historical requests (e.g. limit=7200 for a full 1-hour window at 2 Hz).
    """
    if interval_seconds not in (60, 300):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="interval_seconds must be either 60 (1-minute) or 300 (5-minute).",
        )

    _validate_timezone_bounds(start_time, end_time)

    # Determine effective query limit:
    if limit is not None:
        query_limit = limit
    elif start_time or end_time:
        query_limit = 10000
    elif interval_seconds == 300:
        query_limit = 3600
    else:
        query_limit = 100

    try:
        raw_records = await persistence_repo.query_historical_telemetry(
            sensor_id=sensor_id,
            source=source,
            start_time=start_time,
            end_time=end_time,
            limit=query_limit,
            chronological=True,
        )
    except RuntimeError as exc:
        logger.error("Telemetry rollup query failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Downstream database service unavailable",
        )

    is_truncated = (len(raw_records) >= query_limit)
    unit = raw_records[0].get("unit", "cm") if raw_records else "cm"
    buckets = aggregate_time_series(
        raw_records,
        bucket_interval_seconds=interval_seconds,
        unit=unit,
        sensor_id=sensor_id,
        source=source,
    )

    return {
        "status": "success",
        "sensor_id": sensor_id,
        "source": source or "ALL",
        "interval_seconds": interval_seconds,
        "dataset_sample_count": len(raw_records),
        "is_dataset_truncated": is_truncated,
        "truncation_warning": "Requested limit reached; older historical readings may be omitted from rollup." if is_truncated else None,
        "bucket_count": len(buckets),
        "buckets": [b.model_dump() for b in buckets],
    }


@router.get("/analytics/trend", summary="Get rate of rise or flow trend metrics")
async def get_telemetry_trend(
    sensor_id: str = Query(..., description="Target sensor ID"),
    source: Optional[str] = Query(default=None, description="Operational source filter: PHYSICAL or SIMULATED"),
    limit: int = Query(default=60, ge=2, le=300, description="Number of recent samples to analyze"),
):
    """
    Computes trend analytics:
    - Water level: rate of rise/fall (cm/min) via timestamped linear regression.
    - Flow sensor: average flow, peak flow, rate of change (L/min per min), and total volume.
    Excludes invalid measurements and SENSOR_NOT_INSTALLED faults.
    """
    try:
        raw_records = await persistence_repo.query_historical_telemetry(
            sensor_id=sensor_id,
            source=source,
            limit=limit,
            chronological=True,
        )
    except RuntimeError as exc:
        logger.error("Telemetry trend query failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Downstream database service unavailable",
        )

    if not raw_records:
        return {
            "status": "empty",
            "sensor_id": sensor_id,
            "source": source or "ALL",
            "message": "No historical telemetry found for specified sensor.",
        }

    sensor_type = raw_records[0].get("sensor_type", "WATER_LEVEL")
    is_truncated = (len(raw_records) >= limit)
    if sensor_type == "FLOW_RATE" or raw_records[0].get("unit") in ("L/min", "lpm"):
        metrics = calculate_flow_trend(raw_records, sensor_id=sensor_id, source=source or "PHYSICAL")
    else:
        metrics = calculate_water_level_trend(raw_records, sensor_id=sensor_id, source=source or "PHYSICAL")

    return {
        "status": "success",
        "sensor_id": sensor_id,
        "sensor_type": sensor_type,
        "source": source or "ALL",
        "dataset_sample_count": len(raw_records),
        "is_dataset_truncated": is_truncated,
        "metrics": metrics.model_dump(),
    }


@router.get("/stream/status", summary="Get live telemetry stream metrics and active client count")
async def get_stream_status():
    """
    Returns observable telemetry stream manager metrics, including active WebSocket
    connections, queue utilization, and dropped frame counts.
    """
    return {
        "status": "success",
        "metrics": telemetry_stream_manager.get_metrics(),
    }


@router.websocket("/stream")
@router.websocket("/ws")
async def telemetry_websocket_stream(
    websocket: WebSocket,
    source: Optional[str] = Query(default=None, description="Operational source filter: PHYSICAL, SIMULATED, or omitted for ALL"),
    sensor_id: Optional[str] = Query(default=None, description="Optional sensor ID filter (e.g. US_UPSTREAM_01)"),
    token: Optional[str] = Query(default=None, description="Stream authentication token"),
):
    """
    Real-time telemetry stream WebSocket endpoint.
    
    Capabilities:
    - Bounded asynchronous queue per client prevents memory leaks.
    - Automatic snapshot on connect: current operational mode, validation stage, latest readings.
    - Client-side dynamic filtering: send {"action": "filter", "source": "PHYSICAL", "sensor_id": "..."}.
    - Bidirectional keepalive ping/pong: send {"action": "ping"} -> receives {"event_type": "PONG"}.
    - Safety invariant: Actuation/gate commands sent over stream are strictly rejected.
    """
    # 1. Verify stream authentication if enabled
    if not telemetry_stream_manager.verify_auth_token(token):
        logger.warning("Stream connection rejected: invalid authentication token.")
        await websocket.close(code=1008, reason="Unauthorized: invalid or missing stream token.")
        return

    # 2. Accept WebSocket handshake
    await websocket.accept()

    # 3. Register client subscription
    try:
        subscription = await telemetry_stream_manager.register_client(
            websocket=websocket,
            source_filter=source,
            sensor_filter=sensor_id,
        )
    except RuntimeError as exc:
        await websocket.close(code=1013, reason=str(exc))
        return

    # 4. Transmit connection initialization message and snapshot
    latest_readings = state_store.get_latest_readings()
    snapshot = {}
    for sid, reading in latest_readings.items():
        reading_source = reading.source.value if hasattr(reading.source, "value") else str(reading.source)
        if subscription.source_filter and reading_source != subscription.source_filter:
            continue
        if subscription.sensor_filter and sid != subscription.sensor_filter:
            continue
        snapshot[sid] = reading.model_dump(mode="json")

    init_msg = StreamInitMessage(
        event_type="INIT",
        protocol_version="1.0",
        client_id=subscription.client_id,
        connection_time=utc_now(),
        operational_mode=state_store.mode,
        hardware_validation_stage=getattr(state_store, "hardware_validation_stage", "INCREMENTAL_CONNECTIVITY"),
        latest_snapshot=snapshot,
        subscribed_source=subscription.source_filter,
        subscribed_sensor=subscription.sensor_filter,
        message="Connected to DRAIN-X live telemetry stream",
        stream_config={
            "max_queue_size": telemetry_stream_manager.max_queue_size,
            "ping_interval_sec": settings.WS_HEARTBEAT_INTERVAL_SEC,
        },
    )
    await websocket.send_json(init_msg.model_dump(mode="json"))

    # 5. Background queue consumer task for streaming events to client
    async def sender_worker():
        try:
            while not subscription.is_closed:
                payload = await subscription.queue.get()
                if payload is None or subscription.is_closed:
                    break
                await websocket.send_json(payload)
                subscription.queue.task_done()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f"Sender worker ended for client {subscription.client_id}: {e}")

    sender_task = asyncio.create_task(sender_worker())

    # 6. Listen for incoming client frames (ping, dynamic filter, command rejection)
    try:
        while True:
            data = await websocket.receive_json()
            if not isinstance(data, dict):
                await websocket.send_json({
                    "event_type": "ERROR",
                    "message": "Malformed message frame: JSON object required.",
                })
                continue

            action = data.get("action", "").lower()

            if action == "ping":
                await websocket.send_json({
                    "event_type": "PONG",
                    "timestamp": utc_now().isoformat(),
                    "client_id": subscription.client_id,
                })

            elif action == "filter":
                new_source = data.get("source")
                new_sensor = data.get("sensor_id")

                # Validate source filter input
                if new_source is not None:
                    clean_source = new_source.upper().strip() if new_source else None
                    if clean_source in ("PHYSICAL", "SIMULATED", None, ""):
                        subscription.source_filter = clean_source if clean_source else None
                    else:
                        await websocket.send_json({
                            "event_type": "ERROR",
                            "message": f"Invalid source filter '{new_source}'. Allowed: PHYSICAL, SIMULATED, or null.",
                        })
                        continue

                if new_sensor is not None:
                    subscription.sensor_filter = new_sensor.strip() if new_sensor else None

                await websocket.send_json({
                    "event_type": "FILTER_ACK",
                    "client_id": subscription.client_id,
                    "subscribed_source": subscription.source_filter,
                    "subscribed_sensor": subscription.sensor_filter,
                })

            elif action in ("command", "gate", "actuate", "override"):
                # Safety Guard: Actuation strictly forbidden on read-only stream
                logger.warning(
                    f"Forbidden actuation command attempted over telemetry stream by client {subscription.client_id}."
                )
                await websocket.send_json({
                    "event_type": "ERROR",
                    "message": "Telemetry stream is strictly read-only monitoring. Actuator commands are rejected.",
                })

            else:
                await websocket.send_json({
                    "event_type": "ERROR",
                    "message": f"Unrecognized action '{action}'. Supported: 'ping', 'filter'.",
                })

    except WebSocketDisconnect:
        logger.debug(f"Client {subscription.client_id} disconnected normally.")
    except Exception as exc:
        logger.debug(f"Client {subscription.client_id} stream error: {exc}")
    finally:
        subscription.is_closed = True
        sender_task.cancel()
        try:
            await sender_task
        except asyncio.CancelledError:
            pass
        await telemetry_stream_manager.unregister_client(subscription.client_id)

