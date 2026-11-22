import os
import re
import uuid
from datetime import datetime
from pathlib import Path
import hashlib
import logging
from typing import Optional, Dict, Any, Tuple
from pydantic import BaseModel
from fastapi import APIRouter, HTTPException, Query, UploadFile, File, Header, Response, Depends, status
from fastapi.responses import FileResponse

from app.services.persistence_repository import (
    persistence_repo,
    StorageError,
    StorageNotConfiguredError,
    StorageConflictError,
    StorageValidationError,
    CANONICAL_V3_FILENAME_PATTERN,
    PHOTO_FILENAME_PATTERN,
    IDEMPOTENCY_KEY_PATTERN,
    _validate_incident_id,
)

logger = logging.getLogger("drainx.incidents")

from app.core.config import settings
from app.core.security import get_current_user_claims, get_optional_user_claims, require_roles
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
    if claims:
        if claims.get("is_dev_bypass") and settings.ENVIRONMENT != "production":
            return incident
        user_role = claims.get("extracted_role", "citizen")
        if user_role in ["municipality", "admin", "service_role"]:
            return incident

    return incident.model_copy(
        update={
            "reporter_name": None,
            "internal_notes": None,
            "verified_by": None,
            "assigned_to": _sanitize_contact_info(incident.assigned_to),
            "municipal_notes": _sanitize_contact_info(incident.municipal_notes),
            "description": _sanitize_contact_info(incident.description),
            "rejection_reason": _sanitize_contact_info(incident.rejection_reason),
        }
    )


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
def create_incident(payload: IncidentCreateContract) -> IncidentResponseContract:
    """
    Submit a citizen or field-reported drainage incident.
    Initial status will automatically be set to REPORTED.
    """
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
    return state_store.create_incident(incident)


@router.get("/field-teams", response_model=list[FieldTeamContract])
def get_field_teams(
    claims: Optional[Dict[str, Any]] = Depends(get_optional_user_claims),
) -> list[FieldTeamContract]:
    """
    Retrieve authoritative registered municipal field crews and response teams.
    Open for municipal dispatchers, administrators, and field response crews.
    """
    return state_store.get_field_teams()


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
    return updated


@router.get(
    "/{incident_id}/photos/{filename}",
    summary="Retrieve canonical incident photograph",
)
async def get_incident_scoped_photo(
    incident_id: str,
    filename: str,
    claims: Optional[Dict[str, Any]] = Depends(get_optional_user_claims),
):
    """
    Canonical V3.1 incident-scoped photo retrieval.
    Enforces authorization policy, durable membership verification, fail-closed cloud semantics,
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
    claims: Optional[Dict[str, Any]] = Depends(get_optional_user_claims),
):
    """
    Legacy filename-only photo retrieval route.
    SEC-DUR-06: Immediately rejects canonical sha256_ filenames (requires incident-scoped route).
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
