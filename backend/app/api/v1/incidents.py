import asyncio
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import logging
from typing import Optional, Dict, Any, Tuple
from pydantic import BaseModel
from fastapi import APIRouter, HTTPException, Query, UploadFile, File, Header, Request, Response, Depends, status, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse

from app.services.persistence_repository import (
    persistence_repo,
    StorageError,
    StorageNotConfiguredError,
    StorageConflictError,
    StorageLeaseLostError,
    StorageValidationError,
    StorageNotFoundError,
    CANONICAL_V3_FILENAME_PATTERN,
    PHOTO_FILENAME_PATTERN,
    IDEMPOTENCY_KEY_PATTERN,
    ALLOWED_DUPLICATE_LINK_STATUSES,
    _validate_incident_id,
)

logger = logging.getLogger("drainx.incidents")

from app.core.config import settings
from app.core.security import get_current_user_claims, get_optional_user_claims, require_roles, verify_supabase_jwt
from app.services.rate_limiter import check_rate_limit, check_rate_limit_async, RateLimitAction
from app.services.incident_stream_manager import incident_stream_manager
from app.models.contracts import (
    IncidentCreateContract,
    IncidentUpdateContract,
    IncidentResponseContract,
    MunicipalKpiResponseContract,
    MunicipalQueueResponseContract,
    FieldTeamContract,
    IncidentAuditContract,
    IncidentVerifyRequest,
    IncidentAssignRequest,
    IncidentReassignRequest,
    IncidentUnassignRequest,
    IncidentRejectRequest,
    IncidentStatus,
    IncidentCategory,
    IncidentSeverity,
    IncidentSource,
    AssignmentType,
    DuplicateLinkContract,
    MunicipalDuplicateIncidentSummaryContract,
    MunicipalDuplicateLinkContract,
    DuplicateLinkDetailContract,
    DuplicateQueueResponseContract,
    DuplicateConfirmRequest,
    DuplicateDismissRequest,
    DuplicateScanResponseContract,
    DuplicateLinkStatus,
    IncidentStreamEventType,
)
from app.services.state_store import state_store, validate_and_normalize_field_team
from app.services.media_sanitizer import sanitize_and_clean_image, ImageProcessingError

router = APIRouter(prefix="/incidents", tags=["incidents"])

# Dedicated uploads directory for competition MVP local storage
UPLOAD_DIR = Path(__file__).resolve().parent.parent.parent.parent / "uploads" / "incidents"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_MIME_TYPES = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/webp": ".webp",
}


_EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
_PHONE_REGEX = re.compile(r"(\+?\d[\d -]{7,}\d)")
_UUID_REGEX = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def _sanitize_contact_info(text: Optional[str]) -> Optional[str]:
    """Redacts potential email addresses or phone numbers from publicly visible strings."""
    if not text:
        return text
    sanitized = _EMAIL_REGEX.sub("[EMAIL REDACTED]", text)
    sanitized = _PHONE_REGEX.sub("[PHONE REDACTED]", sanitized)
    return sanitized


def _filter_incident_for_role(
    incident: IncidentResponseContract,
    claims: Optional[Dict[str, Any]],
) -> IncidentResponseContract:
    """
    Enforces server-side incident privacy protection:
    - Municipality, Admin, Service Role: Full access to reporter identity, internal staff notes,
      and raw dispatch metadata for municipal operations.
    - Public / Unauthenticated, Citizen, Worker:
        * reporter_name: Redacted to None (protects citizen identity).
        * internal_notes: Redacted to None (protects internal staff/investigation remarks).
        * assigned_to: Sanitized to remove any accidental personal contact info (emails, phone numbers).
        * municipal_notes: Sanitized to remove any accidental personal contact info.
    Returns a safe non-destructive copy, preserving state_store data integrity.
    """
    user_role = claims.get("extracted_role", "citizen") if claims else "citizen"
    user_sub = claims.get("sub") if claims else None
    if claims:
        if claims.get("is_dev_bypass") and settings.ENVIRONMENT != "production":
            return incident
        if user_role in ["municipality", "admin", "service_role"]:
            return incident

    worker_id_val = None
    if user_role == "worker" and user_sub and incident.assigned_worker_id and user_sub.strip() == incident.assigned_worker_id.strip():
        worker_id_val = incident.assigned_worker_id

    return incident.model_copy(
        update={
            "reporter_name": None,
            "internal_notes": None,
            "verified_by": None,
            "assigned_to": _sanitize_contact_info(incident.assigned_to),
            "municipal_notes": _sanitize_contact_info(incident.municipal_notes),
            "description": _sanitize_contact_info(incident.description),
            "rejection_reason": _sanitize_contact_info(incident.rejection_reason),
            "assigned_worker_id": worker_id_val,
        }
    )


@router.websocket("/stream")
@router.websocket("/ws")
async def incident_websocket_stream(
    websocket: WebSocket,
    token: Optional[str] = Query(default=None, description="Supabase JWT bearer token"),
    last_seq_id: Optional[int] = Query(default=None, description="Optional last acknowledged event sequence number for replay"),
    last_instance_id: Optional[str] = Query(default=None, description="Optional process instance identifier for replay validation"),
):
    """
    Dedicated Backend-Authoritative Incident Real-Time Stream.
    Phase 3 Milestone 2B:
    - Cryptographic Supabase JWT verification on handshake.
    - Role-based authorization & projection (citizen, worker, municipality).
    - Monotonic process-local sequencing with bounded replay buffer.
    - Resync signaling on instance restart or buffer eviction.
    - Bounded per-client queues with slow-consumer backpressure disconnect.
    """
    auth_token = token
    if not auth_token:
        auth_header = websocket.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            auth_token = auth_header[7:].strip()

    if not auth_token:
        logger.warning("Incident stream connection rejected: missing authentication token.")
        await websocket.close(code=1008, reason="Unauthorized: missing token")
        return

    try:
        claims = verify_supabase_jwt(auth_token)
    except HTTPException as exc:
        logger.warning(f"Incident stream connection rejected: invalid JWT ({exc.detail})")
        await websocket.close(code=1008, reason=f"Unauthorized: {exc.detail}")
        return
    except Exception as exc:
        logger.warning(f"Incident stream connection rejected: verification error ({exc})")
        await websocket.close(code=1008, reason="Unauthorized: token verification failed")
        return

    user_role = claims.get("extracted_role", "citizen")
    if user_role not in ("citizen", "worker", "municipality", "admin", "service_role"):
        logger.warning(f"Incident stream rejected unrecognized role '{user_role}'")
        await websocket.close(code=1008, reason="Unauthorized: unrecognized role")
        return

    await websocket.accept()

    try:
        sub = await incident_stream_manager.register_client(websocket, claims)
    except RuntimeError as exc:
        await websocket.close(code=1013, reason=str(exc))
        return

    try:
        await incident_stream_manager.handle_handshake_and_replay(
            sub,
            last_seq_id=last_seq_id,
            last_instance_id=last_instance_id,
        )
    except Exception as exc:
        logger.warning(f"Handshake failed for incident stream client {sub.client_id}: {exc}")
        await incident_stream_manager.unregister_client(sub.client_id)
        return

    async def sender_worker():
        try:
            while not sub.is_closed:
                payload = await sub.queue.get()
                if payload is None or sub.is_closed:
                    break
                await websocket.send_json(payload)
                sub.queue.task_done()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f"Incident sender worker ended for client {sub.client_id}: {e}")

    sender_task = asyncio.create_task(sender_worker())

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
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "client_id": sub.client_id,
                })
            elif action == "replay":
                req_seq = data.get("last_seq_id")
                req_inst = data.get("last_instance_id")
                await incident_stream_manager.handle_handshake_and_replay(
                    sub,
                    last_seq_id=req_seq,
                    last_instance_id=req_inst,
                )
            elif action in ("command", "gate", "actuate", "override"):
                await websocket.send_json({
                    "event_type": "ERROR",
                    "message": "Incident stream is strictly read-only monitoring.",
                })
            else:
                await websocket.send_json({
                    "event_type": "ERROR",
                    "message": f"Unrecognized action '{action}'. Supported: 'ping', 'replay'.",
                })
    except WebSocketDisconnect:
        logger.debug(f"Incident stream client {sub.client_id} disconnected normally.")
    except Exception as exc:
        logger.debug(f"Incident stream client {sub.client_id} error: {exc}")
    finally:
        sub.is_closed = True
        sender_task.cancel()
        try:
            await sender_task
        except asyncio.CancelledError:
            pass
        await incident_stream_manager.unregister_client(sub.client_id)


@router.get("", response_model=list[IncidentResponseContract])
def get_incidents(
    status: Optional[IncidentStatus] = Query(None, description="Filter by incident status"),
    category: Optional[IncidentCategory] = Query(None, description="Filter by category"),
    severity: Optional[IncidentSeverity] = Query(None, description="Filter by severity level"),
    source: Optional[IncidentSource] = Query(None, description="Filter by reporting source"),
    assigned_to: Optional[str] = Query(None, description="Filter by assigned crew or UNASSIGNED/ASSIGNED"),
    search: Optional[str] = Query(None, description="Search term for ID, description, or crew"),
    limit: Optional[int] = Query(None, ge=1, le=200, description="Optional page limit"),
    offset: int = Query(0, ge=0, description="Optional page offset"),
    claims: Optional[Dict[str, Any]] = Depends(get_optional_user_claims),
) -> list[IncidentResponseContract]:
    """
    Retrieve all incidents, optionally filtered by status, category, severity, source, assignment, or search term.
    Returns incidents ordered chronologically (newest first).
    Applies privacy filtering to prevent leaking reporter names to unauthorized clients.
    Restricts search scope for public callers to prevent indirect data exposure or search oracles.
    """
    user_role = claims.get("extracted_role", "citizen") if claims else "citizen"
    is_staff = user_role in ["municipality", "admin", "service_role"] or (
        claims.get("is_dev_bypass") if claims else False
    )

    raw_incidents = state_store.get_incidents(
        status=status,
        category=category,
        severity=severity,
        source=source,
        assigned_to=assigned_to,
        search=search,
        limit=limit,
        offset=offset,
        is_staff_search=is_staff,
    )
    return [_filter_incident_for_role(item, claims) for item in raw_incidents]


@router.get("/municipal/kpis", response_model=MunicipalKpiResponseContract)
def get_municipal_kpis(
    claims: Dict[str, Any] = Depends(require_roles(["municipality", "admin", "service_role"])),
) -> MunicipalKpiResponseContract:
    """
    Retrieve real-time municipal operational KPIs aggregated across the authoritative incident population.
    Restricted strictly to municipality, admin, and service_role.
    Citizens and field workers are denied with 403 Forbidden.
    """
    kpis = state_store.get_incident_kpis()
    return MunicipalKpiResponseContract(**kpis)


@router.get("/municipal/queue", response_model=MunicipalQueueResponseContract)
def get_municipal_queue(
    status: Optional[IncidentStatus] = Query(None, description="Filter by incident status"),
    category: Optional[IncidentCategory] = Query(None, description="Filter by category"),
    severity: Optional[IncidentSeverity] = Query(None, description="Filter by severity level"),
    source: Optional[IncidentSource] = Query(None, description="Filter by reporting source"),
    assigned_to: Optional[str] = Query(None, description="Filter by assigned crew or UNASSIGNED/ASSIGNED"),
    search: Optional[str] = Query(None, description="Free-text search across ID, description, crew, notes"),
    start_date: Optional[datetime] = Query(None, description="Filter created on or after UTC datetime"),
    end_date: Optional[datetime] = Query(None, description="Filter created on or before UTC datetime"),
    limit: int = Query(50, ge=1, le=200, description="Items per page"),
    offset: int = Query(0, ge=0, description="Page offset"),
    claims: Dict[str, Any] = Depends(require_roles(["municipality", "admin", "service_role"])),
) -> MunicipalQueueResponseContract:
    """
    Operational queue for municipal dispatchers and supervisors.
    Provides server-side filtering, searching, and pagination.
    Restricted strictly to municipality, admin, and service_role.
    Citizens and field workers are denied with 403 Forbidden.
    """
    items, total_count = state_store.get_incidents_paginated(
        status=status,
        category=category,
        severity=severity,
        source=source,
        assigned_to=assigned_to,
        search=search,
        start_date=start_date,
        end_date=end_date,
        limit=limit,
        offset=offset,
        is_staff_search=True,
    )
    filtered_items = [
        item.model_copy(
            update={
                "reporter_name": None,
                "internal_notes": None,
                "assigned_to": _sanitize_contact_info(item.assigned_to),
                "municipal_notes": _sanitize_contact_info(item.municipal_notes),
                "description": _sanitize_contact_info(item.description),
            }
        )
        for item in items
    ]
    has_more = (offset + len(filtered_items)) < total_count
    return MunicipalQueueResponseContract(
        items=filtered_items,
        total_count=total_count,
        limit=limit,
        offset=offset,
        has_more=has_more,
    )


@router.post("", response_model=IncidentResponseContract, status_code=status.HTTP_201_CREATED)
def create_incident(
    payload: IncidentCreateContract,
    request: Request,
    claims: Optional[Dict[str, Any]] = Depends(get_optional_user_claims),
) -> IncidentResponseContract:
    """
    Submit a citizen or field-reported drainage incident.
    Initial status will automatically be set to REPORTED.
    Enforces citizen and anonymous creation rate limiting.
    Municipal and field-worker operations bypass the citizen limit.
    """
    check_rate_limit(RateLimitAction.INCIDENT_CREATE, claims, request=request)

    incident = IncidentResponseContract(
        category=payload.category,
        description=payload.description,
        latitude=payload.latitude,
        longitude=payload.longitude,
        severity=payload.severity,
        status=IncidentStatus.REPORTED,
        source=payload.source,
        reporter_name=payload.reporter_name or "Citizen Anonymous",
        photos=payload.photos,
    )
    created = state_store.create_incident(incident)
    try:
        from app.services.duplicate_detector import scan_incident_for_duplicates
        scan_incident_for_duplicates(created.id, persistence_repo, state_store, settings)
    except Exception as scan_err:
        logger.warning("Post-incident-creation duplicate scan failed non-fatally: %s", scan_err)

    try:
        incident_stream_manager.broadcast_incident_event(
            event_type=IncidentStreamEventType.INCIDENT_REPORTED,
            incident_id=created.id,
            action="CREATE",
            new_status=str(created.status),
            incident=created,
        )
    except Exception as stream_err:
        logger.warning("Failed to broadcast INCIDENT_REPORTED event non-fatally: %s", stream_err)

    return created


@router.get("/field-teams", response_model=list[FieldTeamContract])
def get_field_teams(
    claims: Optional[Dict[str, Any]] = Depends(get_optional_user_claims),
) -> list[FieldTeamContract]:
    """
    Retrieve authoritative registered municipal field crews and response teams.
    Open for municipal dispatchers, administrators, and field response crews.
    """
    return state_store.get_field_teams()


def _resolve_duplicate_cloud_mode() -> bool:
    """
    Returns True if full service-role cloud duplicate persistence is configured.
    Fails closed (HTTP 503) if partial cloud configuration is active without service-role key.
    Returns False only in unconfigured local dev / mock test mode.
    """
    is_mock = getattr(persistence_repo, "is_mock", False)
    if persistence_repo.is_storage_configured and not is_mock:
        return True
    if persistence_repo.is_configured and not is_mock:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Duplicate detection cloud persistence requires SUPABASE_SERVICE_ROLE_KEY.",
        )
    return False


def _raise_duplicate_http_error(exc: Exception) -> None:
    if isinstance(exc, HTTPException):
        raise exc

    sqlstate = getattr(exc, "sqlstate", None)
    error_category = getattr(exc, "error_category", None)
    exc_type = exc.__class__.__name__

    if isinstance(exc, StorageNotFoundError) or type(exc) is LookupError:
        logger.warning(
            "Duplicate endpoint not found: error_type=%s sqlstate=%s category=%s",
            exc_type,
            sqlstate or "NONE",
            error_category or "NOT_FOUND",
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Requested duplicate link or incident was not found.",
        )

    if isinstance(exc, StorageLeaseLostError):
        logger.warning(
            "Duplicate endpoint lease lost: error_type=%s sqlstate=%s category=%s",
            exc_type,
            sqlstate or "P0412",
            error_category or "LEASE_LOST",
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Duplicate scan lease is expired or no longer owned.",
        )

    if isinstance(exc, StorageConflictError):
        logger.warning(
            "Duplicate endpoint conflict: error_type=%s sqlstate=%s category=%s",
            exc_type,
            sqlstate or "NONE",
            error_category or "CONFLICT",
        )
        if sqlstate == "23505":
            detail_msg = "Operation conflicts with an existing confirmed duplicate relationship."
        elif sqlstate == "55P03":
            detail_msg = "Duplicate record is temporarily locked; please retry."
        else:
            detail_msg = "Duplicate operation conflicts with current link state, version, or constraints."
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail_msg)

    if isinstance(exc, PermissionError):
        logger.warning("Duplicate endpoint forbidden: error_type=%s", exc_type)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient privileges for this duplicate management operation.",
        )

    if isinstance(exc, StorageValidationError):
        logger.warning(
            "Duplicate endpoint validation failure: error_type=%s sqlstate=%s category=%s",
            exc_type,
            sqlstate or "NONE",
            error_category or "VALIDATION_ERROR",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid request parameters for duplicate management operation.",
        )

    if isinstance(exc, ValueError):
        lower = str(exc).lower()
        logger.warning("Duplicate endpoint value error classified internally (error_type=%s)", exc_type)
        if "redundant override" in lower:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Redundant override: link is already in the requested state.",
            )
        if "version conflict" in lower:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Version conflict: duplicate link was modified by another reviewer.",
            )
        if "circular dependency" in lower:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Confirmation rejected because it would create a circular duplicate chain.",
            )
        if "rejected" in lower:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Cannot confirm a rejected incident as the primary incident.",
            )
        if "already confirmed as a duplicate" in lower:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Incident is already confirmed as a duplicate of another primary incident.",
            )
        if "override" in lower or "already" in lower:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Duplicate link has already been reviewed; explicit override is required.",
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid duplicate management request.",
        )

    if isinstance(exc, (StorageNotConfiguredError, StorageError, RuntimeError)):
        logger.error(
            "Duplicate endpoint cloud service failure: error_type=%s sqlstate=%s category=%s",
            exc_type,
            sqlstate or "NONE",
            error_category or "SERVICE_UNAVAILABLE",
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Duplicate detection cloud service is temporarily unavailable.",
        )

    logger.error(
        "Duplicate endpoint unexpected internal failure: error_type=%s",
        exc_type,
        exc_info=True,
    )
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="An unexpected internal error occurred while processing the duplicate request.",
    )


def _sanitize_actor_identifier(actor_id: Optional[str]) -> Optional[str]:
    """Scrubs email/phone values from actor IDs while preserving valid UUIDs."""
    if not actor_id:
        return actor_id
    if _UUID_REGEX.match(actor_id.strip()):
        return actor_id
    return _sanitize_contact_info(actor_id)


def _build_duplicate_incident_summary(
    incident: Optional[IncidentResponseContract],
) -> Optional[MunicipalDuplicateIncidentSummaryContract]:
    """Projects an incident onto the strictly allowlisted municipal duplicate summary model."""
    if incident is None:
        return None
    return MunicipalDuplicateIncidentSummaryContract(
        id=incident.id,
        category=incident.category,
        description=_sanitize_contact_info(incident.description) or "",
        latitude=incident.latitude,
        longitude=incident.longitude,
        severity=incident.severity,
        status=incident.status,
        source=incident.source,
        origin_operational_mode=incident.origin_operational_mode,
        assigned_to=_sanitize_contact_info(incident.assigned_to),
        assignment_type=incident.assignment_type,
        assigned_team_id=incident.assigned_team_id,
        municipal_notes=_sanitize_contact_info(incident.municipal_notes),
        photo_count=len(incident.photos) if incident.photos else 0,
        created_at=incident.created_at,
        updated_at=incident.updated_at,
    )


def _build_municipal_duplicate_link(
    link: DuplicateLinkContract,
) -> MunicipalDuplicateLinkContract:
    """Projects an internal duplicate link onto the allowlisted municipal response model."""
    return MunicipalDuplicateLinkContract(
        link_id=link.link_id,
        incident_low_id=link.incident_low_id,
        incident_high_id=link.incident_high_id,
        link_status=link.link_status,
        primary_incident_id=link.primary_incident_id,
        duplicate_incident_id=link.duplicate_incident_id,
        detection_origin=link.detection_origin,
        detected_in_mode=link.detected_in_mode,
        distance_meters=link.distance_meters,
        time_delta_seconds=link.time_delta_seconds,
        confidence_score=link.confidence_score,
        confidence_band=link.confidence_band,
        match_reasons=[_sanitize_contact_info(reason) or "" for reason in (link.match_reasons or [])],
        review_version=link.review_version,
        reviewed_by=_sanitize_actor_identifier(link.reviewed_by),
        reviewed_role=link.reviewed_role,
        reviewed_at=link.reviewed_at,
        review_reason=_sanitize_contact_info(link.review_reason),
        created_at=link.created_at,
        updated_at=link.updated_at,
    )


def _build_municipal_duplicate_details_batch(
    links: list[DuplicateLinkContract],
    *,
    is_cloud: bool,
    preloaded_incidents: Optional[Dict[str, Optional[IncidentResponseContract]]] = None,
) -> list[DuplicateLinkDetailContract]:
    """
    Hydrates a page of duplicate links using a bounded bulk incident lookup
    and projects every entry through the Stage 2A allowlisted privacy models.
    """
    if not links:
        return []

    incidents_by_id: Dict[str, Optional[IncidentResponseContract]] = (
        dict(preloaded_incidents) if preloaded_incidents else {}
    )
    needed_ids: list[str] = []
    seen_ids: set[str] = set(incidents_by_id.keys())
    for link in links:
        for inc_id in (
            link.incident_low_id,
            link.incident_high_id,
            link.primary_incident_id,
            link.duplicate_incident_id,
        ):
            if inc_id and inc_id not in seen_ids:
                seen_ids.add(inc_id)
                needed_ids.append(inc_id)

    if needed_ids:
        fetched_map = state_store.get_incidents_by_ids(
            needed_ids,
            authoritative_cloud=is_cloud,
        )
        incidents_by_id.update(fetched_map)

    details: list[DuplicateLinkDetailContract] = []
    for link in links:
        low_inc = incidents_by_id.get(link.incident_low_id)
        high_inc = incidents_by_id.get(link.incident_high_id)
        pri_inc = incidents_by_id.get(link.primary_incident_id) if link.primary_incident_id else None
        dup_inc = incidents_by_id.get(link.duplicate_incident_id) if link.duplicate_incident_id else None
        details.append(
            DuplicateLinkDetailContract(
                link=_build_municipal_duplicate_link(link),
                incident_low=_build_duplicate_incident_summary(low_inc),
                incident_high=_build_duplicate_incident_summary(high_inc),
                primary_incident=_build_duplicate_incident_summary(pri_inc),
                duplicate_incident=_build_duplicate_incident_summary(dup_inc),
            )
        )
    return details


def _build_municipal_duplicate_detail(
    link: DuplicateLinkContract,
    *,
    is_cloud: bool,
) -> DuplicateLinkDetailContract:
    """Builds a single privacy-filtered duplicate link detail entry for municipal endpoints."""
    return _build_municipal_duplicate_details_batch([link], is_cloud=is_cloud)[0]


@router.get("/municipal/duplicates", response_model=DuplicateQueueResponseContract)
def get_duplicate_queue(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter links by status: SUSPECTED, CONFIRMED, DISMISSED"),
    limit: int = Query(50, ge=1, le=100, description="Page limit"),
    offset: int = Query(0, ge=0, description="Page offset"),
    claims: Dict[str, Any] = Depends(require_roles(["municipality", "admin", "service_role"])),
) -> DuplicateQueueResponseContract:
    """
    Authoritative municipal duplicate incident review queue.
    Returns allowlisted candidate links with privacy-filtered incident summaries
    hydrated in a bounded bulk lookup per page.
    Count semantics:
    - `total` reflects the exact matching population (filtered by `status` when supplied).
    - `suspected_count`, `confirmed_count`, `dismissed_count` reflect queue-wide counts per status.
    - In cloud mode, each count uses PostgreSQL `Prefer: count=exact` at query time (no 1,000-row
      truncation), rather than a single cross-HTTP snapshot; in local mode, all counts come from
      one atomic in-memory snapshot.
    Restricted to municipal operators, administrators, and service role.
    """
    is_cloud = _resolve_duplicate_cloud_mode()

    try:
        clean_status_filter: Optional[str] = None
        if status_filter is not None:
            clean_status_filter = status_filter.strip().upper()
            if clean_status_filter not in ALLOWED_DUPLICATE_LINK_STATUSES:
                raise StorageValidationError(
                    "status filter must be 'SUSPECTED', 'CONFIRMED', or 'DISMISSED'."
                )

        if is_cloud:
            raw_links, total = persistence_repo.query_duplicate_links_sync(
                link_status=clean_status_filter, limit=limit, offset=offset
            )
            known_counts = (
                {clean_status_filter: total}
                if clean_status_filter is not None
                else None
            )
            status_counts = persistence_repo.query_duplicate_link_counts_sync(
                known_status_counts=known_counts
            )
            link_contracts = [DuplicateLinkContract.model_validate(l) for l in raw_links]
            detail_items = _build_municipal_duplicate_details_batch(
                link_contracts,
                is_cloud=True,
            )
            return DuplicateQueueResponseContract(
                items=detail_items,
                total=total,
                suspected_count=status_counts["SUSPECTED"],
                confirmed_count=status_counts["CONFIRMED"],
                dismissed_count=status_counts["DISMISSED"],
            )

        all_links = state_store.get_duplicate_links()
        suspected_count = sum(1 for l in all_links if l.link_status == DuplicateLinkStatus.SUSPECTED)
        confirmed_count = sum(1 for l in all_links if l.link_status == DuplicateLinkStatus.CONFIRMED)
        dismissed_count = sum(1 for l in all_links if l.link_status == DuplicateLinkStatus.DISMISSED)

        filtered = (
            [l for l in all_links if l.link_status.value == clean_status_filter]
            if clean_status_filter is not None
            else all_links
        )
        total = len(filtered)
        slice_links = filtered[offset : offset + limit]

        detail_items = _build_municipal_duplicate_details_batch(
            slice_links,
            is_cloud=False,
        )
        return DuplicateQueueResponseContract(
            items=detail_items,
            total=total,
            suspected_count=suspected_count,
            confirmed_count=confirmed_count,
            dismissed_count=dismissed_count,
        )
    except Exception as exc:
        _raise_duplicate_http_error(exc)


def _execute_duplicate_link_review(
    link_id: str,
    target_status: str,
    claims: Dict[str, Any],
    reason: str,
    primary_incident_id: Optional[str],
    internal_notes: Optional[str],
    override: bool,
    expected_version: Optional[int],
) -> MunicipalDuplicateLinkContract:
    """Shared cloud/local execution path for duplicate link confirmation and dismissal."""
    user_role = claims.get("extracted_role", "municipality")
    actor_id = claims.get("sub", "municipal-supervisor")
    is_cloud = _resolve_duplicate_cloud_mode()

    try:
        if is_cloud:
            res = persistence_repo.review_incident_duplicate_link_sync(
                link_id=link_id,
                target_status=target_status,
                actor_id=actor_id,
                actor_role=user_role,
                reason=reason,
                audit_id_low=f"aud_{uuid.uuid4().hex[:24]}",
                audit_id_high=f"aud_{uuid.uuid4().hex[:24]}",
                primary_incident_id=primary_incident_id,
                internal_notes=internal_notes,
                override=override,
                expected_version=expected_version,
            )
            reviewed_link = _build_municipal_duplicate_link(DuplicateLinkContract.model_validate(res))
        else:
            reviewed_link = _build_municipal_duplicate_link(
                state_store.review_duplicate_link(
                    link_id=link_id,
                    target_status=target_status,
                    actor_id=actor_id,
                    actor_role=user_role,
                    reason=reason,
                    primary_incident_id=primary_incident_id,
                    internal_notes=internal_notes,
                    override=override,
                    expected_version=expected_version,
                )
            )

        try:
            incident_stream_manager.broadcast_incident_event(
                event_type=IncidentStreamEventType.DUPLICATE_REVIEWED,
                incident_id=reviewed_link.primary_incident_id or reviewed_link.secondary_incident_id,
                action=f"DUPLICATE_{target_status}",
                duplicate_link=reviewed_link,
                reason=reason,
            )
        except Exception as stream_err:
            logger.warning("Failed to broadcast DUPLICATE_REVIEWED event non-fatally: %s", stream_err)

        return reviewed_link
    except Exception as exc:
        _raise_duplicate_http_error(exc)


@router.post("/municipal/duplicates/{link_id}/confirm", response_model=MunicipalDuplicateLinkContract)
def confirm_duplicate_link(
    link_id: str,
    payload: DuplicateConfirmRequest,
    claims: Dict[str, Any] = Depends(require_roles(["municipality", "admin", "service_role"])),
) -> MunicipalDuplicateLinkContract:
    """
    Confirms a canonical duplicate incident link against a designated primary_incident_id.
    Validates expected_version, cycle prevention, supervisor override rules, and
    appends dual immutable audit records without mutating incident statuses or photos.
    """
    return _execute_duplicate_link_review(
        link_id=link_id,
        target_status="CONFIRMED",
        claims=claims,
        reason=payload.reason,
        primary_incident_id=payload.primary_incident_id,
        internal_notes=payload.internal_notes,
        override=payload.override,
        expected_version=payload.expected_version,
    )


@router.post("/municipal/duplicates/{link_id}/dismiss", response_model=MunicipalDuplicateLinkContract)
def dismiss_duplicate_link(
    link_id: str,
    payload: DuplicateDismissRequest,
    claims: Dict[str, Any] = Depends(require_roles(["municipality", "admin", "service_role"])),
) -> MunicipalDuplicateLinkContract:
    """
    Dismisses a canonical duplicate incident link.
    Validates expected_version, supervisor override rules if reversing prior decision,
    and appends dual immutable audit records.
    """
    return _execute_duplicate_link_review(
        link_id=link_id,
        target_status="DISMISSED",
        claims=claims,
        reason=payload.reason,
        primary_incident_id=None,
        internal_notes=payload.internal_notes,
        override=payload.override,
        expected_version=payload.expected_version,
    )


@router.post("/maintenance/recover-duplicate-scans")
def recover_duplicate_scans(
    claims: Dict[str, Any] = Depends(require_roles(["admin", "service_role"])),
) -> Dict[str, Any]:
    """
    Administrative maintenance endpoint to recover stalled duplicate scan jobs.
    Claims pending/expired jobs once from the durable outbox and passes each
    claimed job and its exact lease owner directly to the executor (no double-claim).
    Cloud-only endpoint; returns HTTP 503 if Supabase Cloud storage persistence is unconfigured.
    """
    is_cloud = _resolve_duplicate_cloud_mode()
    if not is_cloud:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Duplicate scan recovery requires configured Supabase Cloud persistence.",
        )

    if not settings.DUPLICATE_DETECTION_ENABLED:
        return {
            "status": "DISABLED",
            "lease_owner": None,
            "claimed_jobs": 0,
            "completed_count": 0,
            "retry_scheduled_count": 0,
            "failed_permanent_count": 0,
            "lease_lost_count": 0,
        }

    try:
        from app.services.duplicate_detector import recover_pending_cloud_duplicate_scans
        return recover_pending_cloud_duplicate_scans(
            repo=persistence_repo,
            state_store=state_store,
            current_settings=settings,
            batch_size=20,
            lease_sec=120,
        )
    except Exception as exc:
        _raise_duplicate_http_error(exc)


@router.get("/{incident_id}", response_model=IncidentResponseContract)
def get_incident(
    incident_id: str,
    claims: Optional[Dict[str, Any]] = Depends(get_optional_user_claims),
) -> IncidentResponseContract:
    """
    Retrieve a single incident by its unique tracking identifier.
    Applies privacy filtering to prevent leaking reporter names to unauthorized clients.
    """
    incident = state_store.get_incident(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found",
        )
    return _filter_incident_for_role(incident, claims)


def _is_worker_assigned_to_incident(
    claims: Dict[str, Any],
    incident: IncidentResponseContract,
) -> bool:
    """
    Verifies that a field worker is assigned to this specific incident.
    Checks:
    1. Direct individual worker assignment (assigned_worker_id == claims['sub']).
    2. Team membership assignment (assigned_team_id == worker's verified team from app_metadata).
    3. Canonical team name match for backward compatibility.
    Strictly enforces that only verified worker identities in claims with role='worker' are authorized.
    Never trusts client headers or mutable user_metadata.
    """
    if not incident.assigned_to or not incident.assigned_to.strip():
        return False

    if claims.get("extracted_role") != "worker":
        return False

    user_id = claims.get("sub")
    if not user_id:
        return False

    # 1. Individual assignment match
    if incident.assigned_worker_id and incident.assigned_worker_id.strip() == user_id.strip():
        return True

    if user_id.strip().lower() == incident.assigned_to.strip().lower():
        return True

    # 2. Verified team tenancy check
    worker_team = claims.get("extracted_team")
    if not worker_team:
        # Worker has no team affiliation in trusted app_metadata
        return False

    try:
        worker_team_obj = validate_and_normalize_field_team(worker_team)
        if incident.assigned_team_id and worker_team_obj:
            if incident.assigned_team_id == worker_team_obj.team_id:
                return True

        incident_team_obj = validate_and_normalize_field_team(incident.assigned_to)
        if worker_team_obj and incident_team_obj:
            return worker_team_obj.team_id == incident_team_obj.team_id
    except ValueError:
        return worker_team.strip().lower() == incident.assigned_to.strip().lower()

    return False


@router.post("/{incident_id}/verify", response_model=IncidentResponseContract)
def verify_incident(
    incident_id: str,
    payload: IncidentVerifyRequest,
    claims: Dict[str, Any] = Depends(require_roles(["municipality", "admin", "service_role"])),
) -> IncidentResponseContract:
    """
    Triage and verify an incident report.
    Transitions incident status to VERIFIED, optionally re-prioritizes severity,
    and logs durable municipal triage verification notes.
    """

    existing = state_store.get_incident(incident_id)
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found",
        )

    if existing.status in (IncidentStatus.RESOLVED, IncidentStatus.REJECTED):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot verify an incident in terminal state '{existing.status.value}'. Reopen incident first.",
        )

    user_role = claims.get("extracted_role", "municipality")
    actor_id = claims.get("sub", "municipal-supervisor")

    update_payload = IncidentUpdateContract(
        status=IncidentStatus.VERIFIED,
        severity=payload.severity or existing.severity,
        municipal_notes=payload.notes if payload.notes else existing.municipal_notes,
        internal_notes=payload.internal_notes if payload.internal_notes else existing.internal_notes,
        verified_by=actor_id,
    )

    try:
        updated = state_store.update_incident(
            incident_id=incident_id,
            update=update_payload,
            actor_id=actor_id,
            actor_role=user_role,
            action_reason="Incident verified by municipal supervisor",
            action_type="VERIFIED",
        )
        if not updated:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

        try:
            incident_stream_manager.broadcast_incident_event(
                event_type=IncidentStreamEventType.INCIDENT_TRIAGED,
                incident_id=updated.id,
                action="VERIFY",
                previous_status=str(existing.status),
                new_status=str(updated.status),
                incident=updated,
            )
        except Exception as stream_err:
            logger.warning("Failed to broadcast INCIDENT_TRIAGED event non-fatally: %s", stream_err)

        return _filter_incident_for_role(updated, claims)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/{incident_id}/assign", response_model=IncidentResponseContract)
def assign_incident(
    incident_id: str,
    payload: IncidentAssignRequest,
    claims: Dict[str, Any] = Depends(require_roles(["municipality", "admin", "service_role"])),
) -> IncidentResponseContract:
    """
    Assign an incident to an authoritative field response crew.
    Validates crew against the authoritative directory and advances unassigned incidents to ASSIGNED.
    """
    existing = state_store.get_incident(incident_id)
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found",
        )

    if existing.status in (IncidentStatus.RESOLVED, IncidentStatus.REJECTED):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot assign an incident in terminal state '{existing.status.value}'.",
        )

    try:
        team = validate_and_normalize_field_team(payload.assigned_to)
        if not team:
            raise ValueError("Field team assignee cannot be empty.")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    user_role = claims.get("extracted_role", "municipality")
    actor_id = claims.get("sub", "municipal-supervisor")

    # If currently REPORTED or VERIFIED, automatically transition to ASSIGNED
    new_status = IncidentStatus.ASSIGNED if existing.status in (IncidentStatus.REPORTED, IncidentStatus.VERIFIED) else existing.status

    # Distinguish team vs individual worker assignment
    assignment_type = payload.assignment_type or (AssignmentType.INDIVIDUAL if payload.assigned_worker_id else AssignmentType.TEAM)

    update_payload = IncidentUpdateContract(
        status=new_status,
        assigned_to=team.name,
        assignment_type=assignment_type,
        assigned_team_id=team.team_id,
        assigned_worker_id=payload.assigned_worker_id,
        internal_notes=payload.internal_notes if payload.internal_notes else existing.internal_notes,
    )

    try:
        updated = state_store.update_incident(
            incident_id=incident_id,
            update=update_payload,
            actor_id=actor_id,
            actor_role=user_role,
            action_reason=payload.reason or f"Dispatched to {team.name}",
            action_type="ASSIGNED",
        )
        if not updated:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

        try:
            incident_stream_manager.broadcast_incident_event(
                event_type=IncidentStreamEventType.INCIDENT_ASSIGNED,
                incident_id=updated.id,
                action="ASSIGN",
                previous_status=str(existing.status),
                new_status=str(updated.status),
                team_id=updated.assigned_team_id,
                worker_id=updated.assigned_worker_id,
                incident=updated,
                reason=payload.reason or f"Dispatched to {team.name}",
            )
        except Exception as stream_err:
            logger.warning("Failed to broadcast INCIDENT_ASSIGNED event non-fatally: %s", stream_err)

        return _filter_incident_for_role(updated, claims)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.post("/{incident_id}/reassign", response_model=IncidentResponseContract)
def reassign_incident(
    incident_id: str,
    payload: IncidentReassignRequest,
    claims: Dict[str, Any] = Depends(require_roles(["municipality", "admin", "service_role"])),
) -> IncidentResponseContract:
    """
    Reassign an already-assigned incident to a different field response crew.
    Requires an explicit operational reassignment reason.
    """
    existing = state_store.get_incident(incident_id)
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found",
        )

    if existing.status in (IncidentStatus.RESOLVED, IncidentStatus.REJECTED):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot reassign an incident in terminal state '{existing.status.value}'.",
        )

    if not existing.assigned_to or not existing.assigned_to.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incident is not currently assigned to any crew. Use assignment endpoint instead.",
        )

    if not payload.reason or not payload.reason.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reassignment requires an explicit operational reason.",
        )

    try:
        team = validate_and_normalize_field_team(payload.assigned_to)
        if not team:
            raise ValueError("Target field team cannot be empty.")
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    # Reject redundant reassignment to the exact same crew
    existing_team = validate_and_normalize_field_team(existing.assigned_to)
    if existing_team and existing_team.team_id == team.team_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Incident is already assigned to {team.name}.",
        )

    user_role = claims.get("extracted_role", "municipality")
    actor_id = claims.get("sub", "municipal-supervisor")

    assignment_type = payload.assignment_type or (AssignmentType.INDIVIDUAL if payload.assigned_worker_id else AssignmentType.TEAM)

    update_payload = IncidentUpdateContract(
        assigned_to=team.name,
        assignment_type=assignment_type,
        assigned_team_id=team.team_id,
        assigned_worker_id=payload.assigned_worker_id,
        internal_notes=payload.internal_notes if payload.internal_notes else existing.internal_notes,
    )

    try:
        updated = state_store.update_incident(
            incident_id=incident_id,
            update=update_payload,
            actor_id=actor_id,
            actor_role=user_role,
            action_reason=payload.reason,
            action_type="REASSIGNED",
        )
        if not updated:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

        previous_team_id = existing_team.team_id if existing_team else existing.assigned_team_id
        previous_worker_id = existing.assigned_worker_id

        try:
            incident_stream_manager.broadcast_incident_event(
                event_type=IncidentStreamEventType.INCIDENT_ASSIGNED,
                incident_id=updated.id,
                action="REASSIGN",
                previous_status=str(existing.status),
                new_status=str(updated.status),
                team_id=updated.assigned_team_id,
                worker_id=updated.assigned_worker_id,
                previous_assigned_team_id=previous_team_id,
                previous_assigned_worker_id=previous_worker_id,
                incident=updated,
                reason=payload.reason,
            )
        except Exception as stream_err:
            logger.warning("Failed to broadcast INCIDENT_ASSIGNED event non-fatally: %s", stream_err)

        return _filter_incident_for_role(updated, claims)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.post("/{incident_id}/unassign", response_model=IncidentResponseContract)
def unassign_incident(
    incident_id: str,
    payload: IncidentUnassignRequest,
    claims: Dict[str, Any] = Depends(require_roles(["municipality", "admin", "service_role"])),
) -> IncidentResponseContract:
    """
    Remove an existing crew assignment when operationally justified.
    Requires an explicit operational reason and reverts ASSIGNED incidents to VERIFIED.
    """
    existing = state_store.get_incident(incident_id)
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found",
        )

    if existing.status in (IncidentStatus.RESOLVED, IncidentStatus.REJECTED):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot unassign an incident in terminal state '{existing.status.value}'.",
        )

    if not existing.assigned_to or not existing.assigned_to.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incident is already unassigned.",
        )

    if not payload.reason or not payload.reason.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unassignment requires an explicit operational reason.",
        )

    user_role = claims.get("extracted_role", "municipality")
    actor_id = claims.get("sub", "municipal-supervisor")

    new_status = IncidentStatus.VERIFIED if existing.status == IncidentStatus.ASSIGNED else existing.status

    update_payload = IncidentUpdateContract(
        status=new_status,
        assigned_to="",
        assignment_type=AssignmentType.NONE,
        assigned_team_id="",
        assigned_worker_id="",
        internal_notes=payload.internal_notes if payload.internal_notes else existing.internal_notes,
    )

    try:
        updated = state_store.update_incident(
            incident_id=incident_id,
            update=update_payload,
            actor_id=actor_id,
            actor_role=user_role,
            action_reason=payload.reason,
            action_type="UNASSIGNED",
        )
        if not updated:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

        previous_team = validate_and_normalize_field_team(existing.assigned_to)
        previous_team_id = previous_team.team_id if previous_team else existing.assigned_team_id
        previous_worker_id = existing.assigned_worker_id

        try:
            incident_stream_manager.broadcast_incident_event(
                event_type=IncidentStreamEventType.INCIDENT_ASSIGNED,
                incident_id=updated.id,
                action="UNASSIGN",
                previous_status=str(existing.status),
                new_status=str(updated.status),
                team_id=None,
                worker_id=None,
                previous_assigned_team_id=previous_team_id,
                previous_assigned_worker_id=previous_worker_id,
                incident=updated,
                reason=payload.reason,
            )
        except Exception as stream_err:
            logger.warning("Failed to broadcast INCIDENT_ASSIGNED event non-fatally: %s", stream_err)

        return _filter_incident_for_role(updated, claims)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.post("/{incident_id}/reject", response_model=IncidentResponseContract)
def reject_incident(
    incident_id: str,
    payload: IncidentRejectRequest,
    claims: Dict[str, Any] = Depends(require_roles(["municipality", "admin", "service_role"])),
) -> IncidentResponseContract:
    """
    Reject an invalid, duplicate, or out-of-scope incident report.
    Requires an explicit mandatory operational reason (no silent rejection).
    """
    existing = state_store.get_incident(incident_id)
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found",
        )

    if existing.status in (IncidentStatus.RESOLVED, IncidentStatus.REJECTED):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot reject an incident in terminal state '{existing.status.value}'.",
        )

    if not payload.reason or not payload.reason.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Rejection requires an explicit operational reason.",
        )

    user_role = claims.get("extracted_role", "municipality")
    actor_id = claims.get("sub", "municipal-supervisor")

    update_payload = IncidentUpdateContract(
        status=IncidentStatus.REJECTED,
        rejection_reason=payload.reason.strip(),
        internal_notes=payload.internal_notes if payload.internal_notes else existing.internal_notes,
    )

    try:
        updated = state_store.update_incident(
            incident_id=incident_id,
            update=update_payload,
            actor_id=actor_id,
            actor_role=user_role,
            action_reason=payload.reason.strip(),
            action_type="REJECTED",
        )
        if not updated:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

        try:
            incident_stream_manager.broadcast_incident_event(
                event_type=IncidentStreamEventType.INCIDENT_REJECTED,
                incident_id=updated.id,
                action="REJECT",
                previous_status=str(existing.status),
                new_status=str(updated.status),
                incident=updated,
                reason=payload.reason.strip(),
            )
        except Exception as stream_err:
            logger.warning("Failed to broadcast INCIDENT_REJECTED event non-fatally: %s", stream_err)

        return _filter_incident_for_role(updated, claims)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/{incident_id}/audit", response_model=list[IncidentAuditContract])
def get_incident_audit_trail(
    incident_id: str,
    claims: Dict[str, Any] = Depends(require_roles(["municipality", "admin", "service_role"])),
) -> list[IncidentAuditContract]:
    """
    Retrieve chronological audit ledger for an incident.
    Restricted strictly to municipality, admin, and service_role.
    Citizens and workers are denied with 403 Forbidden.
    """
    try:
        existing = state_store.get_incident(incident_id)
    except Exception as exc:
        logger.error("Authoritative incident lookup failed during audit retrieval: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authoritative cloud incident service unavailable.",
        )
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found",
        )

    try:
        audits = state_store.get_incident_audits(incident_id)
    except Exception as exc:
        logger.error("Authoritative audit query failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authoritative cloud audit ledger unavailable.",
        )
    return audits


@router.get("/{incident_id}/duplicates", response_model=list[DuplicateLinkDetailContract])
def get_incident_duplicates(
    incident_id: str,
    claims: Dict[str, Any] = Depends(require_roles(["municipality", "admin", "service_role"])),
) -> list[DuplicateLinkDetailContract]:
    """
    Retrieve all allowlisted duplicate candidate links with privacy-filtered incident summaries
    for a specific incident under the same privacy policy as the municipal duplicate queue.
    Restricted to municipal operators, administrators, and service role.
    """
    is_cloud = _resolve_duplicate_cloud_mode()
    try:
        existing = state_store.get_incident(incident_id, authoritative_cloud=is_cloud)
    except Exception as exc:
        _raise_duplicate_http_error(exc)
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found",
        )

    try:
        if is_cloud:
            raw_links = persistence_repo.query_duplicate_links_for_incident_sync(incident_id)
            link_contracts = [DuplicateLinkContract.model_validate(l) for l in raw_links]
            return _build_municipal_duplicate_details_batch(
                link_contracts,
                is_cloud=True,
                preloaded_incidents={incident_id: existing},
            )
        links = state_store.get_incident_duplicate_links(incident_id)
        return _build_municipal_duplicate_details_batch(
            links,
            is_cloud=False,
            preloaded_incidents={incident_id: existing},
        )
    except Exception as exc:
        _raise_duplicate_http_error(exc)


@router.post("/{incident_id}/duplicates/scan", response_model=DuplicateScanResponseContract)
def trigger_incident_duplicate_scan(
    incident_id: str,
    claims: Dict[str, Any] = Depends(require_roles(["municipality", "admin", "service_role"])),
) -> DuplicateScanResponseContract:
    """
    Triggers an immediate on-demand duplicate detection scan for an incident.
    In cloud mode, resets any completed/failed outbox job (rejecting active leases)
    and executes a fresh single-claim scan.
    """
    is_cloud = _resolve_duplicate_cloud_mode()
    user_role = claims.get("extracted_role", "municipality")
    actor_id = claims.get("sub", "municipal-supervisor")

    try:
        existing = state_store.get_incident(incident_id, authoritative_cloud=is_cloud)
    except Exception as exc:
        _raise_duplicate_http_error(exc)
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found",
        )

    try:
        if not settings.DUPLICATE_DETECTION_ENABLED:
            return DuplicateScanResponseContract(
                incident_id=incident_id,
                status="DISABLED",
                candidates_found=0,
                links_created=0,
                total_links=0,
            )
        if is_cloud:
            persistence_repo.reset_duplicate_scan_job_sync(
                incident_id=incident_id,
                actor_id=actor_id,
                actor_role=user_role,
                reason="Manual municipal duplicate rescan",
            )
        from app.services.duplicate_detector import scan_incident_for_duplicates
        return scan_incident_for_duplicates(incident_id, persistence_repo, state_store, settings)
    except Exception as exc:
        _raise_duplicate_http_error(exc)


@router.patch("/{incident_id}", response_model=IncidentResponseContract)
def update_incident(
    incident_id: str,
    payload: IncidentUpdateContract,
    claims: Dict[str, Any] = Depends(get_current_user_claims),
) -> IncidentResponseContract:
    """
    Update an incident through the ordinary PATCH endpoint.

    Resolved and rejected incidents are immutable.
    Workers may update permitted operational fields but cannot modify
    assignment metadata, resolve/reject incidents, or set internal notes.
    """
    existing = state_store.get_incident(incident_id)
    if not existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found",
        )
    # Server-side authorization.
    user_role = claims.get("extracted_role", "citizen")
    is_dev_bypass = (
        claims.get("is_dev_bypass", False)
        and settings.ENVIRONMENT != "production"
    )

    if not is_dev_bypass:
        if user_role == "citizen":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Citizens are not authorized to triage, assign, or update incidents.",
            )

        elif user_role == "worker":
            if not _is_worker_assigned_to_incident(claims, existing):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Field workers may only update incidents assigned to their crew.",
                )

            # Reject assignment, internal notes, and supervisory fields even when explicitly supplied as null.
            protected_worker_fields = {
                "assigned_to",
                "assignment_type",
                "assigned_team_id",
                "assigned_worker_id",
                "internal_notes",
                "verified_by",
                "rejection_reason",
            }

            submitted_protected_fields = (
                payload.model_fields_set & protected_worker_fields
            )

            if submitted_protected_fields:
                violating_field = sorted(submitted_protected_fields)[0]
                if violating_field == "internal_notes":
                    detail_msg = "Field workers are not permitted to set internal municipal notes."
                elif violating_field in ("verified_by", "rejection_reason"):
                    detail_msg = f"Field workers are not permitted to modify supervisory field '{violating_field}'."
                else:
                    detail_msg = "Field workers are not permitted to reassign incidents or modify assignment metadata."

                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=detail_msg,
                )

            if payload.status == IncidentStatus.RESOLVED:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Incident resolution requires municipal supervisor or administrator authorization.",
                )

            if payload.status == IncidentStatus.REJECTED:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Incident rejection requires municipal supervisor or administrator authorization.",
                )

        elif user_role in ["municipality", "admin", "service_role"]:
            pass

        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user_role}' is not authorized to update incidents.",
            )
    # Terminal incidents are immutable for authorized roles too.
    if existing.status in (IncidentStatus.RESOLVED, IncidentStatus.REJECTED):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Resolved or rejected incidents cannot be modified.",
        )

    try:
        actor_id = claims.get("sub", "unknown") if claims else "unknown"

        updated = state_store.update_incident(
            incident_id=incident_id,
            update=payload,
            actor_id=actor_id,
            actor_role=user_role,
        )

        if not updated:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident with ID '{incident_id}' not found",
            )

        try:
            event_type = (
                IncidentStreamEventType.INCIDENT_RESOLVED
                if updated.status == IncidentStatus.RESOLVED
                else IncidentStreamEventType.INCIDENT_IN_PROGRESS
            )
            incident_stream_manager.broadcast_incident_event(
                event_type=event_type,
                incident_id=updated.id,
                action="UPDATE",
                previous_status=str(existing.status),
                new_status=str(updated.status),
                team_id=updated.assigned_team_id,
                worker_id=updated.assigned_worker_id,
                incident=updated,
            )
        except Exception as stream_err:
            logger.warning("Failed to broadcast update event non-fatally: %s", stream_err)

        return _filter_incident_for_role(updated, claims)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )



def _resolve_photo_actor(claims: Optional[Dict[str, Any]]) -> Tuple[str, str]:
    """
    Normalizes caller actor_id and actor_role according to INT-05:
    - citizen / unauthenticated (claims is None) -> ('citizen_anonymous', 'citizen')
    - municipal_officer / municipality -> (claims['sub'], 'municipal_officer')
    - field_worker / worker -> (claims['sub'], 'field_worker')
    - admin -> (claims['sub'], 'admin')
    - service_role / system -> (claims['sub'] or 'system', 'system')
    """
    if not claims:
        return "citizen_anonymous", "citizen"

    actor_id = claims.get("sub") or claims.get("id") or "anonymous"
    raw_role = (
        claims.get("extracted_role")
        or claims.get("role")
        or claims.get("user_metadata", {}).get("role")
        or claims.get("app_metadata", {}).get("role")
        or ""
    ).strip().lower()

    if raw_role in ("admin",):
        return actor_id, "admin"
    if raw_role in ("service_role", "system"):
        return actor_id, "system"
    if raw_role in ("municipality", "municipal_officer"):
        return actor_id, "municipal_officer"
    if raw_role in ("worker", "field_worker"):
        return actor_id, "field_worker"
    return actor_id, "citizen"


def _authorize_photo_retrieval(
    incident: IncidentResponseContract, claims: Optional[Dict[str, Any]]
) -> None:
    """
    Enforces authorization policy for photo evidence retrieval:
    1. REJECTED incidents: Only supervisors ('municipal_officer', 'admin', 'system') may view.
       All others (unauthenticated, citizens, workers) receive HTTP 404 to mask existence.
    2. Field workers: Must be assigned to the incident (assigned_worker_id, assigned_to, or team assignment).
       Unassigned workers receive HTTP 403 Forbidden.
    3. Citizens & Unauthenticated: Allowed for non-rejected incidents.
    """
    actor_id, actor_role = _resolve_photo_actor(claims)

    # Status-based restrictions
    if incident.status == IncidentStatus.REJECTED:
        if actor_role not in ("municipal_officer", "admin", "system"):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Photo not found.",
            )

    # Worker tenancy restriction
    if actor_role == "field_worker":
        is_assigned = (
            incident.assigned_worker_id == actor_id
            or incident.assigned_to == actor_id
            or (claims is not None and _is_worker_assigned_to_incident(claims, incident))
        )
        if not is_assigned:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Field workers may only access evidence for incidents assigned to them.",
            )


@router.post("/{incident_id}/photos", response_model=IncidentResponseContract)
async def upload_incident_photos(
    incident_id: str,
    request: Request,
    files: list[UploadFile] = File(..., description="Photographic evidence files (max 3 per incident, 5MB max each, JPEG/PNG/WebP)"),
    idempotency_key: Optional[str] = Header(None, alias="Idempotency-Key"),
    claims: Optional[Dict[str, Any]] = Depends(get_optional_user_claims),
) -> IncidentResponseContract:
    """
    Upload 1 to 3 photo evidence files for a specific incident.
    Validates MIME type, maximum 5MB size per file, and attaches safe relative URLs to the incident.
    In cloud mode, strictly enforces mandatory Idempotency-Key header, fail-closed partial config check,
    authoritative PostgreSQL incident lookup, and atomic RPC orchestration.
    """
    if not files or len(files) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one photo file must be provided.",
        )

    # D-02: Fail closed with HTTP 503 if database persistence is configured without Storage service-role key
    if persistence_repo.is_configured and not persistence_repo.is_storage_configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Cloud persistence is configured without service-role storage credentials. Local fallback is disabled.",
        )

    cloud_mode = bool(persistence_repo.is_storage_configured)

    # In cloud mode, Idempotency-Key header is strictly required
    if cloud_mode:
        if not idempotency_key or not idempotency_key.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Idempotency-Key header is required for photo uploads in cloud mode.",
            )
        clean_key = idempotency_key.strip()
        if not IDEMPOTENCY_KEY_PATTERN.match(clean_key):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Idempotency-Key format. Must be 8-64 alphanumeric characters, dots, underscores, or hyphens.",
            )
    else:
        clean_key = idempotency_key.strip() if idempotency_key else f"loc_key_{uuid.uuid4().hex}"

    # Enforce rate limiting on photo uploads before authoritative PostgreSQL lookup (RL-AUD-A-01, RL-AUD-11)
    # Evaluated before database queries to prevent PostgREST/PostgreSQL DoS via nonexistent incident IDs.
    await check_rate_limit_async(RateLimitAction.PHOTO_UPLOAD, claims, request=request)

    # D-02: In cloud mode, retrieve authoritative incident state from PostgreSQL; convert outages to HTTP 503
    if cloud_mode:
        try:
            incident = state_store.get_incident(incident_id, authoritative_cloud=True)
        except StorageValidationError as sve:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(sve))
        except Exception as exc:
            logger.error("Authoritative cloud incident query failed during upload: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authoritative cloud incident service unavailable.",
            )
    else:
        incident = state_store.get_incident(incident_id)

    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found",
        )

    if incident.status in [IncidentStatus.RESOLVED, IncidentStatus.REJECTED]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot attach photos to an incident in '{incident.status.value}' status.",
        )

    if len(incident.photos) + len(files) > settings.MAX_PHOTOS_PER_INCIDENT:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot exceed maximum limit of {settings.MAX_PHOTOS_PER_INCIDENT} photos per incident. Already attached: {len(incident.photos)}, attempting to add: {len(files)}.",
        )

    actor_id, actor_role = _resolve_photo_actor(claims)

    # Enforce worker tenancy
    if actor_role == "field_worker":
        is_assigned = (
            incident.assigned_worker_id == actor_id
            or incident.assigned_to == actor_id
            or (claims is not None and _is_worker_assigned_to_incident(claims, incident))
        )
        if not is_assigned:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Field workers may only upload evidence for incidents assigned to them.",
            )

    # Read and sanitize files; detect duplicate image content within the request
    seen_digests = set()
    sanitized_items = []

    for file in files:
        content_type = file.content_type or ""
        if content_type not in ALLOWED_MIME_TYPES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported image type '{content_type}'. Allowed types: JPEG, PNG, WebP.",
            )

        data = await file.read()
        if len(data) > settings.MAX_PHOTO_SIZE_BYTES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Image file exceeds maximum allowable size of 5 MB ({len(data)} bytes received).",
            )
        if len(data) == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Empty file upload is not permitted.",
            )

        try:
            clean_data, detected_mime, ext = sanitize_and_clean_image(data, content_type)
        except ImageProcessingError as ipe:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(ipe),
            )

        digest = hashlib.sha256(clean_data).hexdigest()
        if digest in seen_digests:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Duplicate image content within the same request is not permitted.",
            )
        seen_digests.add(digest)
        sanitized_items.append((file.filename or f"photo{ext}", clean_data, detected_mime, ext, digest))

    audit_id = f"AUD-{uuid.uuid4().hex[:12].upper()}"

    # Cloud mode upload orchestration
    if cloud_mode:
        prepared_for_cloud = [
            (f"sha256_{item[4]}{item[3]}", item[1], item[2])
            for item in sanitized_items
        ]
        try:
            updated_dict = persistence_repo.execute_photo_attachment_workflow_sync(
                incident_id=incident_id,
                files=prepared_for_cloud,
                idempotency_key=clean_key,
                actor_id=actor_id,
                actor_role=actor_role,
                audit_id=audit_id,
            )
            updated_contract = IncidentResponseContract.model_validate(updated_dict)
            with state_store._lock:
                state_store._incidents[incident_id] = updated_contract

            try:
                incident_stream_manager.broadcast_incident_event(
                    event_type=IncidentStreamEventType.INCIDENT_PHOTOS_ATTACHED,
                    incident_id=updated_contract.id,
                    action="ATTACH_PHOTOS",
                    new_status=str(updated_contract.status),
                    team_id=updated_contract.assigned_team_id,
                    worker_id=updated_contract.assigned_worker_id,
                    incident=updated_contract,
                )
            except Exception as stream_err:
                logger.warning("Failed to broadcast INCIDENT_PHOTOS_ATTACHED event non-fatally: %s", stream_err)

            return updated_contract
        except StorageValidationError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
        except StorageConflictError as e:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
        except (StorageNotConfiguredError, StorageError, RuntimeError) as e:
            logger.error("Cloud photo upload workflow failed: %s", e)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Storage operation failed: {str(e)}",
            )
        except Exception as e:
            logger.error("Cloud photo upload unexpected error: %s", e)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Storage operation failed: {str(e)}",
            )

    # Local fallback mode (only when cloud persistence is completely unconfigured)
    new_photo_urls: list[str] = []
    written_files: list[Path] = []
    for item in sanitized_items:
        ext = item[3]
        safe_name = f"{incident_id}_{uuid.uuid4().hex[:8]}{ext}"
        destination = UPLOAD_DIR / safe_name
        try:
            destination.write_bytes(item[1])
            written_files.append(destination)
        except Exception:
            for wf in written_files:
                wf.unlink(missing_ok=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to persist photographic evidence.",
            )
        new_photo_urls.append(f"/api/v1/incidents/photos/{safe_name}")

    try:
        updated = state_store.attach_incident_photos(
            incident_id=incident_id,
            new_photos=new_photo_urls,
            audit_id=audit_id,
            actor_id=actor_id,
            actor_role=actor_role,
            files_to_cleanup_on_failure=written_files,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Photo attachment failed: {str(exc)}",
        )

    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found",
        )

    try:
        incident_stream_manager.broadcast_incident_event(
            event_type=IncidentStreamEventType.INCIDENT_PHOTOS_ATTACHED,
            incident_id=updated.id,
            action="ATTACH_PHOTOS",
            new_status=str(updated.status),
            team_id=updated.assigned_team_id,
            worker_id=updated.assigned_worker_id,
            incident=updated,
        )
    except Exception as stream_err:
        logger.warning("Failed to broadcast INCIDENT_PHOTOS_ATTACHED event non-fatally: %s", stream_err)

    return updated


@router.get(
    "/{incident_id}/photos/{filename}",
    summary="Retrieve canonical incident photograph",
)
async def get_incident_scoped_photo(
    incident_id: str,
    filename: str,
    request: Request,
    claims: Optional[Dict[str, Any]] = Depends(get_optional_user_claims),
):
    """
    Canonical V3.1 incident-scoped photo retrieval.
    Enforces rate limiting prior to expensive PostgREST/Storage/disk access,
    authorization policy, durable membership verification, fail-closed cloud semantics,
    and strict privacy headers.
    """
    try:
        clean_inc_id = _validate_incident_id(incident_id)
    except StorageValidationError as sve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(sve),
        )

    if not CANONICAL_V3_FILENAME_PATTERN.match(filename) and not PHOTO_FILENAME_PATTERN.match(filename):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid photo filename structure.",
        )

    # D-02: Fail closed with HTTP 503 if database persistence is configured without Storage service-role key
    if persistence_repo.is_configured and not persistence_repo.is_storage_configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Cloud persistence is configured without service-role storage credentials. Local fallback is disabled.",
        )

    # Enforce rate limiting before expensive PostgREST queries, Storage downloads, or disk reads (RL-AUD-11)
    await check_rate_limit_async(RateLimitAction.PHOTO_RETRIEVE, claims, request=request)

    if persistence_repo.is_storage_configured:
        # D-02: Fetch authoritative incident row from PostgreSQL (never authorize from stale in-memory objects)
        try:
            inc_row = persistence_repo.query_incident_by_id_sync(clean_inc_id)
        except Exception as exc:
            logger.error("Authoritative cloud incident query failed during photo retrieval: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authoritative cloud incident verification unavailable.",
            )
        if not inc_row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident '{clean_inc_id}' not found.",
            )
        incident = IncidentResponseContract.model_validate(inc_row)
        with state_store._lock:
            state_store._incidents[clean_inc_id] = incident

        _authorize_photo_retrieval(incident, claims)

        canonical_path = f"{clean_inc_id}/{filename}"
        try:
            is_member = persistence_repo.verify_attached_photo_membership_sync(
                clean_inc_id, canonical_path, incident_row=inc_row
            )
        except StorageValidationError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Photo '{filename}' is not attached to incident '{clean_inc_id}'.",
            )
        except Exception as exc:
            logger.error("Durable photo membership verification failed: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Durable cloud photo membership verification unavailable.",
            )
        if not is_member:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Photo '{filename}' is not attached to incident '{clean_inc_id}'.",
            )

        try:
            downloaded = persistence_repo.download_incident_photo(canonical_path, incident_id=clean_inc_id)
        except Exception as exc:
            logger.error("Cloud photo download failed: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Cloud storage photo download unavailable.",
            )
        if not downloaded:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Photo '{filename}' not found in storage.",
            )
        content_bytes, content_type = downloaded
        response = Response(content=content_bytes, media_type=content_type)
    else:
        incident = state_store.get_incident(clean_inc_id)
        if not incident:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident '{clean_inc_id}' not found.",
            )

        _authorize_photo_retrieval(incident, claims)

        target = f"/api/v1/incidents/photos/{filename}"
        canonical_local = f"{clean_inc_id}/{filename}"
        accepted_entries = {filename, target, canonical_local}
        if not any(p in accepted_entries for p in incident.photos):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Photo '{filename}' not found on incident.",
            )
        file_path = (UPLOAD_DIR / filename).resolve()
        if not file_path.is_file():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Photo '{filename}' not found on disk.",
            )
        ext = file_path.suffix.lower()
        media_map = {
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".webp": "image/webp",
        }
        response = FileResponse(path=file_path, media_type=media_map.get(ext, "image/jpeg"))

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "private, no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Vary"] = "Authorization"
    return response


@router.get("/photos/{filename}", summary="Retrieve legacy incident photograph")
async def get_incident_photo(
    filename: str,
    request: Request,
    claims: Optional[Dict[str, Any]] = Depends(get_optional_user_claims),
):
    """
    Legacy filename-only photo retrieval route.
    SEC-DUR-06: Immediately rejects canonical sha256_ filenames (requires incident-scoped route).
    Enforces rate limiting prior to expensive PostgREST/Storage/disk access.
    Fails closed (404) on missing or ambiguous (>1) incident associations, and fails closed (503)
    on partial cloud configuration or PostgREST outage.
    """
    if filename.startswith("sha256_"):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Canonical incident photos must be retrieved via /api/v1/incidents/{incident_id}/photos/{filename}",
        )

    if not re.match(r"^[A-Za-z0-9_-]+\.(jpg|jpeg|png|webp)$", filename):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid filename structure or unsupported extension.",
        )

    # D-02: Fail closed with HTTP 503 if database persistence is configured without Storage service-role key
    if persistence_repo.is_configured and not persistence_repo.is_storage_configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Cloud persistence is configured without service-role storage credentials. Local fallback is disabled.",
        )

    # Enforce rate limiting before expensive PostgREST queries or disk lookups (RL-AUD-11)
    await check_rate_limit_async(RateLimitAction.PHOTO_RETRIEVE, claims, request=request)

    if persistence_repo.is_configured or persistence_repo.is_storage_configured:
        try:
            rows = persistence_repo.query_incidents_by_photo_entry_sync(filename)
        except Exception as exc:
            logger.error("Authoritative cloud legacy photo lookup failed: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authoritative cloud incident photo lookup unavailable.",
            )
        if len(rows) == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Photo '{filename}' not found.",
            )
        if len(rows) > 1:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Photo '{filename}' is ambiguous across multiple incidents.",
            )
        incident = IncidentResponseContract.model_validate(rows[0])
    else:
        matching_incidents = []
        target = f"/api/v1/incidents/photos/{filename}"
        accepted_entries = {filename, target}
        with state_store._lock:
            for inc in state_store._incidents.values():
                if any(p in accepted_entries for p in inc.photos):
                    matching_incidents.append(inc)
        if len(matching_incidents) == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Photo '{filename}' not found.",
            )
        if len(matching_incidents) > 1:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Photo '{filename}' is ambiguous across multiple incidents.",
            )
        incident = matching_incidents[0]

    _authorize_photo_retrieval(incident, claims)

    file_path = (UPLOAD_DIR / filename).resolve()
    upload_root = UPLOAD_DIR.resolve()
    try:
        file_path.relative_to(upload_root)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Path traversal forbidden.",
        )

    if not file_path.is_file():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Photo '{filename}' not found.",
        )

    ext = file_path.suffix.lower()
    media_map = {
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".webp": "image/webp",
    }
    response = FileResponse(path=file_path, media_type=media_map.get(ext, "image/jpeg"))

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "private, no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Vary"] = "Authorization"
    return response


class StorageCleanupRecoveryRequest(BaseModel):
    cleanup_id: str
    incident_id: str
    idempotency_key: str
    scope: str = "incident_attachment"
    lease_sec: int = 60


@router.post(
    "/maintenance/recover-storage-cleanup",
    summary="Recover expired storage cleanup operation",
)
async def recover_storage_cleanup(
    body: StorageCleanupRecoveryRequest,
    claims: Dict[str, Any] = Depends(require_roles(["admin", "service_role"])),
):
    """
    Admin/system maintenance endpoint to recover expired storage cleanup operations.
    Strictly derives recovery actor from authenticated claims; caller cannot supply actor identity.
    """
    actor_id, actor_role = _resolve_photo_actor(claims)
    if actor_role not in ("admin", "system"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin or system service-role may trigger cleanup recovery.",
        )

    try:
        result = persistence_repo.execute_cleanup_recovery_workflow_sync(
            cleanup_id=body.cleanup_id,
            incident_id=body.incident_id,
            idempotency_key=body.idempotency_key,
            scope=body.scope,
            recovery_actor_id=actor_id,
            recovery_actor_role=actor_role,
            lease_sec=body.lease_sec,
        )
        return result
    except StorageValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except StorageConflictError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except (StorageNotConfiguredError, StorageError, RuntimeError) as e:
        logger.error("Cleanup recovery failed: %s", e)
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e))
    except Exception as e:
        logger.error("Cleanup recovery unexpected error: %s", e)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
