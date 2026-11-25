"""
DRAIN-X Database Persistence Layer Interface & Supabase Cloud Client Adapter.

Milestone: P0.6 Supabase Cloud Integration.

Architecture Principles:
1. Non-invasive & Graceful Degradation:
   - If SUPABASE_URL / SUPABASE_KEY are unset or the cloud database is unreachable,
     the application runs in IN_MEMORY_FALLBACK mode with zero crashes.
   - Persistence operations fail soft and record diagnostic metadata without
     disrupting live telemetry ingestion or real-time analytics.
2. Direct HTTP REST Interface (No Heavy External SDK Required):
   - Uses `httpx` to communicate directly with Supabase PostgREST API (/rest/v1/).
3. Operational Mode Partitioning:
   - Readings are persisted with strict `source` classification ('PHYSICAL' vs 'SIMULATED').
   - Historical queries support source filtering so simulated runs never contaminate
     physical sensor archives.
4. Security & Role Boundaries:
   - Supports privileged `SUPABASE_SERVICE_ROLE_KEY` for backend ingestion bypassing RLS.
   - Never exposes service-role keys to clients or logs.
5. Device Registry & Auditing:
   - Full persistence for edge nodes (devices) and operational mode transition ledgers.
"""

import hashlib
import logging
import math
import uuid
import os
import re
import time
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple, Union
import urllib.parse
import httpx
from pydantic import BaseModel, ValidationError

from app.core.config import settings, inspect_service_role_credential
from app.models.contracts import (
    SensorReadingContract,
    DataSource,
    ActuatorDirectiveEventContract,
    DIRECTIVE_AUDIT_DB_COLUMNS,
    DIRECTIVE_AUDIT_IMMUTABLE_COLUMNS,
    DirectiveEventType,
    DirectiveIssuerType,
    build_startup_cancellation_audit_id,
    build_verification_timeout_audit_id,
    normalize_audit_timestamp_utc,
    quantize_numeric_5_2_decimal,
    compute_verification_timeout_timestamp,
)

logger = logging.getLogger("drainx.persistence")
_UNSET = object()


# ----------------------------------------------------------------------
# Storage Security & Boundary Exceptions
# ----------------------------------------------------------------------

class StorageError(RuntimeError):
    """Base exception for all Supabase Storage repository errors."""

    def __init__(
        self,
        message: str,
        *,
        sqlstate: Optional[str] = None,
        error_category: Optional[str] = None,
    ):
        super().__init__(message)
        self.sqlstate = sqlstate
        self.error_category = error_category


class StorageNotConfiguredError(StorageError):
    """Raised when Supabase Storage operations are invoked on an unconfigured repository."""
    pass


class StorageValidationError(StorageError):
    """Raised when input parameters (keys, paths, MIME types, TTLs) fail security validation."""
    pass


class StorageConflictError(StorageError):
    """Raised when attempting to upload an object that already exists (x-upsert: false)."""
    pass


class DirectiveAuditConflictError(StorageConflictError, ValueError):
    """Raised when a duplicate audit_id conflicts with an existing immutable directive audit row."""
    pass


class StorageLeaseLostError(StorageConflictError):
    """Raised when a worker lease is stale, expired, or no longer owned (SQLSTATE P0412)."""
    pass


class StorageNotFoundError(StorageError):
    """Raised when a requested storage object is not found."""
    pass


ALLOWED_STORAGE_MIME_TYPES: FrozenSet[str] = frozenset({
    "image/jpeg",
    "image/png",
    "image/webp",
})

ALLOWED_STORAGE_EXTENSIONS: FrozenSet[str] = frozenset({
    ".jpg",
    ".jpeg",
    ".png",
    ".webp",
})

ALLOWED_ACTOR_ROLES: FrozenSet[str] = frozenset({
    "citizen",
    "municipal_officer",
    "field_worker",
    "admin",
    "system",
})

STORAGE_MIME_TO_EXTENSIONS: Dict[str, FrozenSet[str]] = {
    "image/jpeg": frozenset({".jpg", ".jpeg"}),
    "image/png": frozenset({".png"}),
    "image/webp": frozenset({".webp"}),
}

MIN_SIGNED_URL_EXPIRY_SEC: int = 1
MAX_SIGNED_URL_EXPIRY_SEC: int = 3600
INCIDENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
AUDIT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
ACTOR_ID_PATTERN = re.compile(r"^[A-Za-z0-9_@.-]{1,128}$")
ACTOR_ROLE_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
PHOTO_FILENAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}\.(jpg|jpeg|png|webp)$", re.IGNORECASE)
CANONICAL_V3_FILENAME_PATTERN = re.compile(r"^sha256_[a-f0-9]{64}.(jpg|png|webp)$")
CANONICAL_V3_OBJECT_PATH_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,32}/sha256_[a-f0-9]{64}.(jpg|png|webp)$")
REQUEST_LEASE_PATTERN = re.compile(r"^req_lease_[a-f0-9]{32}$")
RECOVERY_LEASE_PATTERN = re.compile(r"^rec_lease_[a-f0-9]{32}$")
CLEANUP_OR_RECOVERY_LEASE_PATTERN = re.compile(r"^(?:req|rec)_lease_[a-f0-9]{32}$")
IDEMPOTENCY_KEY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{8,64}$")
CLEANUP_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
REQUEST_FINGERPRINT_PATTERN = re.compile(r"^[a-f0-9]{64}$")
BUCKET_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")
DUP_LEASE_PATTERN = re.compile(r"^dup_lease_[a-f0-9]{32}$")
DUP_LINK_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{5,32}$")
ALLOWED_DUPLICATE_REVIEW_ROLES: FrozenSet[str] = frozenset({"municipality", "admin", "service_role"})
ALLOWED_DUPLICATE_LINK_STATUSES: FrozenSet[str] = frozenset({"SUSPECTED", "CONFIRMED", "DISMISSED"})
ALLOWED_OPERATIONAL_MODES: FrozenSet[str] = frozenset({"SIMULATION", "PHYSICAL", "SAFE_HOLD"})

_CONTENT_RANGE_TOTAL_PATTERN = re.compile(
    r"^(?:[A-Za-z]+\s+)?(?:\*|\d+-\d+)/(\d+)$"
)


def _parse_postgrest_content_range_total(content_range: Optional[str]) -> Optional[int]:
    """Parses an exact non-negative total count from a PostgREST Content-Range header."""
    if not isinstance(content_range, str):
        return None
    cleaned = content_range.strip()
    if not cleaned:
        return None
    match = _CONTENT_RANGE_TOTAL_PATTERN.match(cleaned)
    if not match:
        return None
    total = int(match.group(1))
    return total if total >= 0 else None


def _validate_bucket_name(bucket: Optional[str]) -> str:
    target_bucket = bucket or settings.SUPABASE_STORAGE_BUCKET_INCIDENTS or "incident-evidence"
    if not isinstance(target_bucket, str) or target_bucket != target_bucket.strip():
        raise StorageValidationError("Bucket name cannot contain leading or trailing whitespace.")
    if not BUCKET_NAME_PATTERN.match(target_bucket):
        raise StorageValidationError(
            f"Invalid storage bucket name: '{target_bucket}'. Bucket name must be 3-63 lowercase alphanumeric characters or hyphens."
        )
    return target_bucket


def _validate_incident_id(incident_id: str) -> str:
    if not isinstance(incident_id, str):
        raise StorageValidationError("Incident ID must be a string.")
    if incident_id != incident_id.strip():
        raise StorageValidationError(f"Incident ID cannot contain leading or trailing whitespace: '{incident_id}'.")
    if not INCIDENT_ID_PATTERN.match(incident_id):
        raise StorageValidationError(
            f"Invalid incident ID '{incident_id}'. Must be alphanumeric with hyphens or underscores (1-32 chars matching database schema)."
        )
    return incident_id


def _validate_audit_id(audit_id: str) -> str:
    if not isinstance(audit_id, str):
        raise StorageValidationError("Audit ID must be a string.")
    if audit_id != audit_id.strip():
        raise StorageValidationError(f"Audit ID cannot contain leading or trailing whitespace: '{audit_id}'.")
    if not AUDIT_ID_PATTERN.match(audit_id):
        raise StorageValidationError(
            f"Invalid audit ID '{audit_id}'. Must be alphanumeric with hyphens or underscores (1-32 chars matching database schema)."
        )
    return audit_id


def _validate_actor(actor_id: str, actor_role: str) -> Tuple[str, str]:
    if not isinstance(actor_id, str):
        raise StorageValidationError("Actor ID must be a string.")
    if actor_id != actor_id.strip() or not actor_id:
        raise StorageValidationError("Actor ID cannot be empty or have leading/trailing whitespace.")
    if len(actor_id) > 128 or not ACTOR_ID_PATTERN.match(actor_id):
        raise StorageValidationError(
            f"Invalid actor ID '{actor_id}'. Must be 1-128 valid characters matching database schema."
        )

    if not isinstance(actor_role, str):
        raise StorageValidationError("Actor role must be a string.")
    if actor_role != actor_role.strip() or not actor_role:
        raise StorageValidationError("Actor role cannot be empty or have leading/trailing whitespace.")
    clean_role = actor_role.strip().lower()
    if clean_role not in ALLOWED_ACTOR_ROLES:
        raise StorageValidationError(
            f"Invalid actor role: '{actor_role}'. Must be exactly one of: {', '.join(sorted(ALLOWED_ACTOR_ROLES))}."
        )

    return actor_id, clean_role


def _validate_photo_id(photo_id: str, incident_id: str) -> str:
    if not isinstance(photo_id, str):
        raise StorageValidationError("Photo ID must be a string.")

    if photo_id != photo_id.strip():
        raise StorageValidationError(f"Photo ID cannot contain leading or trailing whitespace: '{photo_id}'.")
    if photo_id.startswith("/") or photo_id.endswith("/"):
        raise StorageValidationError(f"Noncanonical photo ID with leading or trailing slash rejected: '{photo_id}'.")
    if "\\" in photo_id:
        raise StorageValidationError(f"Noncanonical photo ID with backslashes rejected: '{photo_id}'.")
    if "%" in photo_id:
        raise StorageValidationError(f"Noncanonical encoded photo ID rejected: '{photo_id}'.")
    if ".." in photo_id or "\x00" in photo_id:
        raise StorageValidationError(f"Path traversal or malformed characters in photo ID: '{photo_id}'.")
    if "/" in photo_id:
        raise StorageValidationError(
            f"Noncanonical photo ID: '{photo_id}'. Must be a single filename without directory segments."
        )

    if photo_id.startswith("sha256_"):
        if not CANONICAL_V3_FILENAME_PATTERN.match(photo_id):
            raise StorageValidationError(
                f"Invalid canonical photo filename '{photo_id}'. Must match ^sha256_[a-f0-9]{{64}}.(jpg|png|webp)$."
            )
    else:
        if not PHOTO_FILENAME_PATTERN.match(photo_id):
            raise StorageValidationError(
                f"Invalid photo filename '{photo_id}'. Must be 1-64 alphanumeric/hyphen/underscore chars with .jpg, .jpeg, .png, or .webp extension."
            )
    return photo_id


def _validate_mime_type(content_type: str, filename: Optional[str] = None) -> str:
    if not isinstance(content_type, str):
        raise StorageValidationError("Content-Type must be a string.")

    clean_mime = content_type.strip().lower()
    if clean_mime not in ALLOWED_STORAGE_MIME_TYPES:
        raise StorageValidationError(
            f"Unsupported MIME type: '{content_type}'. Allowed MIME types: {', '.join(sorted(ALLOWED_STORAGE_MIME_TYPES))}."
        )

    if filename:
        ext = os.path.splitext(filename)[1].lower()
        allowed_exts = STORAGE_MIME_TO_EXTENSIONS.get(clean_mime, frozenset())
        if ext not in allowed_exts:
            raise StorageValidationError(
                f"File extension '{ext}' does not match Content-Type '{clean_mime}'. Allowed extensions: {', '.join(sorted(allowed_exts))}."
            )
    return clean_mime


def _validate_signed_url_expiry(expires_in: Optional[int]) -> int:
    if expires_in is None:
        ttl = settings.SUPABASE_STORAGE_SIGNED_URL_EXPIRY_SEC
    elif isinstance(expires_in, int) and not isinstance(expires_in, bool):
        ttl = expires_in
    else:
        raise StorageValidationError(
            f"Signed URL expiry must be an integer, got: {type(expires_in).__name__}."
        )

    if ttl < MIN_SIGNED_URL_EXPIRY_SEC or ttl > MAX_SIGNED_URL_EXPIRY_SEC:
        raise StorageValidationError(
            f"Signed URL expiry {ttl}s out of bounds. Must be between {MIN_SIGNED_URL_EXPIRY_SEC}s and {MAX_SIGNED_URL_EXPIRY_SEC}s."
        )
    return ttl


def _validate_object_path(
    path: str,
    target_bucket: str,
    expected_incident_id: Optional[str] = None,
) -> Tuple[str, str, str]:
    """
    Validates a canonical storage object key: 'incident_id/photo_id.ext'.
    Strictly rejects leading/trailing slashes, whitespace, backslashes, percent-encoding,
    traversal, directory prefixes, or noncanonical structures without silent normalization.
    Returns (canonical_path, incident_id, filename).
    """
    if not isinstance(path, str):
        raise StorageValidationError("Path must be a string.")

    if path != path.strip():
        raise StorageValidationError(f"Noncanonical path with leading or trailing whitespace rejected: '{path}'.")
    if path.startswith("/") or path.endswith("/"):
        raise StorageValidationError(f"Noncanonical path with leading or trailing slash rejected: '{path}'.")
    if "\\" in path:
        raise StorageValidationError(f"Noncanonical path with backslashes rejected: '{path}'.")
    if "%" in path:
        raise StorageValidationError(f"Noncanonical encoded path rejected: '{path}'.")
    if ".." in path or "\x00" in path or "//" in path:
        raise StorageValidationError(f"Path traversal or malformed characters in path: '{path}'.")

    parts = path.split("/")
    if len(parts) != 2:
        raise StorageValidationError(
            f"Noncanonical object key: '{path}'. Object keys must be in strict 'incident_id/filename.ext' format."
        )

    inc_id, filename = parts

    clean_inc_id = _validate_incident_id(inc_id)

    if expected_incident_id is not None and clean_inc_id != expected_incident_id:
        raise StorageValidationError(
            f"Cross-incident object access rejected: path incident '{clean_inc_id}' does not match expected '{expected_incident_id}'."
        )

    if filename.startswith("sha256_"):
        if not CANONICAL_V3_FILENAME_PATTERN.match(filename):
            raise StorageValidationError(
                f"Invalid canonical photo filename in path: '{filename}'. Must match ^sha256_[a-f0-9]{{64}}.(jpg|png|webp)$."
            )
    else:
        if not PHOTO_FILENAME_PATTERN.match(filename):
            raise StorageValidationError(
                f"Invalid photo filename in path: '{filename}'. Must be a single image filename with valid extension."
            )

    canonical_path = f"{clean_inc_id}/{filename}"
    return canonical_path, clean_inc_id, filename


def _validate_canonical_v3_object_path(
    path: str,
    expected_incident_id: Optional[str] = None,
) -> Tuple[str, str, str]:
    """
    Validates a canonical V3 storage object key: 'incident_id/sha256_<64hex>.(jpg|png|webp)'.
    Returns (canonical_path, incident_id, filename).
    """
    if not isinstance(path, str):
        raise StorageValidationError("Path must be a string.")
    if path != path.strip():
        raise StorageValidationError(f"Noncanonical path with whitespace: '{path}'.")
    if not CANONICAL_V3_OBJECT_PATH_PATTERN.match(path):
        raise StorageValidationError(
            f"Invalid canonical V3 object path '{path}'. Must match ^[A-Za-z0-9_-]{{1,32}}/sha256_[a-f0-9]{{64}}.(jpg|png|webp)$."
        )
    inc_id, filename = path.split("/")
    clean_inc_id = _validate_incident_id(inc_id)
    if expected_incident_id is not None and clean_inc_id != expected_incident_id:
        raise StorageValidationError(
            f"Cross-incident object access rejected: path incident '{clean_inc_id}' does not match expected '{expected_incident_id}'."
        )
    return f"{clean_inc_id}/{filename}", clean_inc_id, filename


class DatabaseConfigStatus(BaseModel):
    configured: bool
    url_present: bool
    key_present: bool
    service_role_key_present: bool
    mode: str
    target_table: str
    last_persistence_error: Optional[str] = None
    total_persisted_count: int = 0
    failed_persistence_count: int = 0
    connection_status: str = "UNKNOWN"
    last_ping_ms: Optional[float] = None


def _parse_record_datetime(ts_val: Any) -> Optional[datetime]:
    """
    Parses a timestamp value into a timezone-aware UTC datetime.
    Gracefully returns None for malformed, non-string, or empty timestamp values.
    """
    if isinstance(ts_val, datetime):
        if ts_val.tzinfo is None or ts_val.tzinfo.utcoffset(ts_val) is None:
            return ts_val.replace(tzinfo=timezone.utc)
        return ts_val
    if not isinstance(ts_val, str) or not ts_val.strip():
        return None
    try:
        clean_str = ts_val.strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_str)
        if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def _quantize_numeric_5_2(value: Optional[Union[int, float, Decimal]]) -> Optional[float]:
    """Quantizes NUMERIC(5, 2) angles/divergences consistently via Decimal without -0.0."""
    quantized = quantize_numeric_5_2_decimal(value, "numeric_5_2", allow_none=True)
    if quantized is None:
        return None
    if quantized == 0:
        return 0.0
    return float(quantized)


def serialize_directive_audit_row(
    audit: Union[ActuatorDirectiveEventContract, Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Validates and serializes an actuator directive audit event into the exact
    23 typed columns of public.actuator_directive_audits (Migration 008).
    Rejects missing required fields (including omitted timestamps in dict input)
    and legacy/unknown keys before persistence.
    """
    if isinstance(audit, ActuatorDirectiveEventContract):
        try:
            validated = ActuatorDirectiveEventContract.model_validate(audit.model_dump())
        except ValidationError as exc:
            raise ValueError(f"Invalid ActuatorDirectiveEventContract: {exc}") from exc
    elif isinstance(audit, dict):
        if "timestamp" not in audit or audit["timestamp"] is None:
            raise ValueError("Directive audit payload must explicitly include a timezone-aware 'timestamp'.")
        try:
            validated = ActuatorDirectiveEventContract.model_validate(audit)
        except ValidationError as exc:
            raise ValueError(f"Invalid directive audit payload: {exc}") from exc
    else:
        raise TypeError(
            f"Expected ActuatorDirectiveEventContract or dict, got {type(audit).__name__}"
        )

    ts_utc = validated.timestamp.astimezone(timezone.utc).isoformat()
    row: Dict[str, Any] = {
        "audit_id": validated.audit_id,
        "directive_id": validated.directive_id,
        "event_type": validated.event_type.value,
        "device_id": validated.device_id,
        "section_id": validated.section_id,
        "operational_mode": validated.operational_mode,
        "directive_type": validated.directive_type,
        "action": validated.action,
        "gate_target_angle": _quantize_numeric_5_2(validated.gate_target_angle),
        "reason": validated.reason,
        "risk_level": validated.risk_level.value,
        "emergency_stop": validated.emergency_stop,
        "measured_gate_angle": _quantize_numeric_5_2(validated.measured_gate_angle),
        "measured_gate_state": validated.measured_gate_state,
        "execution_divergence_deg": _quantize_numeric_5_2(validated.execution_divergence_deg),
        "issuer_type": validated.issuer_type.value,
        "issuer_id": validated.issuer_id,
        "correlation_id": validated.correlation_id,
        "device_session_epoch": validated.device_session_epoch,
        "baseline_device_sequence_number": validated.baseline_device_sequence_number,
        "device_sequence_number": validated.device_sequence_number,
        "device_uptime_ms": validated.device_uptime_ms,
        "timestamp": ts_utc,
    }
    if tuple(row.keys()) != DIRECTIVE_AUDIT_DB_COLUMNS:
        raise RuntimeError("Serialized directive audit keys do not match Migration 008 schema.")
    return row


_NUMERIC_5_2_FIELDS: FrozenSet[str] = frozenset({
    "gate_target_angle",
    "measured_gate_angle",
    "execution_divergence_deg",
})
_INT_AUDIT_FIELDS: FrozenSet[str] = frozenset({
    "device_session_epoch",
    "baseline_device_sequence_number",
    "device_sequence_number",
    "device_uptime_ms",
})


def _normalize_immutable_field_value(field_name: str, value: Any) -> Any:
    if value is None:
        return None
    if hasattr(value, "value"):
        value = value.value
    if field_name == "timestamp":
        try:
            return normalize_audit_timestamp_utc(value)
        except (ValueError, TypeError):
            return ("invalid_timestamp", type(value).__name__)
    if field_name in _NUMERIC_5_2_FIELDS:
        if isinstance(value, bool):
            return ("bool", value)
        try:
            if isinstance(value, Decimal):
                if not value.is_finite():
                    return ("non_finite", str(value))
                dec = value
            elif isinstance(value, int):
                dec = Decimal(value)
            elif isinstance(value, float):
                if not math.isfinite(value):
                    return ("non_finite", str(value))
                dec = Decimal(str(value))
            elif isinstance(value, str):
                dec = Decimal(value.strip())
                if not dec.is_finite():
                    return ("non_finite", value)
            else:
                return ("non_numeric", type(value).__name__)
            quantized = dec.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
            return Decimal("0.00") if quantized == 0 else quantized
        except (InvalidOperation, ValueError):
            return ("invalid_decimal", type(value).__name__)
    if field_name in _INT_AUDIT_FIELDS:
        if isinstance(value, bool):
            return ("bool", value)
        return int(value)
    if field_name == "emergency_stop":
        return value if isinstance(value, bool) else ("non_bool", value)
    if isinstance(value, str):
        return value
    return value


def _verify_immutable_directive_audit_match(
    existing: Dict[str, Any], incoming: Dict[str, Any]
) -> None:
    """
    Compares all 23 immutable columns (including UTC microsecond-normalized timestamp
    and nullable fields) of an existing ledger row against an incoming row.
    Raises DirectiveAuditConflictError on any divergence; never silently masks conflicts.
    """
    mismatched: List[str] = []
    for col in DIRECTIVE_AUDIT_IMMUTABLE_COLUMNS:
        ex_val = _normalize_immutable_field_value(col, existing.get(col))
        in_val = _normalize_immutable_field_value(col, incoming.get(col))
        if ex_val != in_val:
            mismatched.append(col)
    if mismatched:
        raise DirectiveAuditConflictError(
            f"Directive audit conflict for audit_id='{incoming.get('audit_id')}' on immutable field(s): {', '.join(mismatched)}"
        )


_POSTGREST_RESERVED_VALUE_CHARS = frozenset(',.:()"\\')


def _quote_postgrest_value(value: str) -> str:
    """
    Safely renders a value for a PostgREST filter. Values containing PostgREST reserved
    characters (, . : ( ) ") , backslashes or whitespace are double-quoted with backslash
    escaping; control characters are rejected outright. HTTP URL-encoding is applied
    afterwards by httpx when the value is passed through `params`.
    """
    if not isinstance(value, str) or not value:
        raise ValueError("PostgREST filter value must be a non-empty string.")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise ValueError("PostgREST filter value contains control characters.")
    if any(ch in _POSTGREST_RESERVED_VALUE_CHARS or ch.isspace() for ch in value):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return value


def _format_audit_id_postgrest_filter(audit_ids: Sequence[str]) -> str:
    if not audit_ids:
        raise ValueError("At least one audit_id is required for a PostgREST filter.")
    if len(audit_ids) == 1:
        return f"eq.{_quote_postgrest_value(audit_ids[0])}"
    return f"in.({','.join(_quote_postgrest_value(a) for a in audit_ids)})"


def _chunk_audit_ids(
    audit_ids: Sequence[str], max_ids: int, max_chars: int
) -> List[List[str]]:
    """Splits ids (preserving order) into chunks bounded by id count and rendered filter length."""
    chunks: List[List[str]] = []
    current: List[str] = []
    current_len = 0
    for a_id in audit_ids:
        piece_len = len(_quote_postgrest_value(a_id)) + 1
        if current and (len(current) >= max_ids or current_len + piece_len > max_chars):
            chunks.append(current)
            current, current_len = [], 0
        current.append(a_id)
        current_len += piece_len
    if current:
        chunks.append(current)
    return chunks


class PersistenceRepository:
    """
    Modular persistence client interfacing FastAPI with Supabase Cloud PostgREST.
    Operates in fallback/mock mode when unconfigured.
    """
    POSTGREST_PAGE_SIZE: int = 1000
    # Conservative bounds for directive-audit verification SELECTs (ids per request / rendered chars).
    DIRECTIVE_AUDIT_VERIFY_CHUNK_SIZE: int = 50
    DIRECTIVE_AUDIT_VERIFY_MAX_QUERY_CHARS: int = 3000

    def __init__(
        self,
        supabase_url: Any = _UNSET,
        supabase_key: Any = _UNSET,
        service_role_key: Any = _UNSET,
        timeout_sec: Optional[float] = None,
    ):
        # Resolve each configuration property independently:
        # - If argument is omitted (_UNSET), fall back to settings.
        # - If argument is explicitly None or empty string, treat as disabled/empty.
        # - Guard against cross-project mixing: if a custom URL is provided, do not
        #   implicitly leak default settings keys to that foreign URL; and vice-versa.
        if supabase_url is _UNSET:
            resolved_url = (settings.SUPABASE_URL or "").rstrip("/")
            url_from_settings = True
        elif supabase_url is None:
            resolved_url = ""
            url_from_settings = False
        else:
            resolved_url = str(supabase_url).rstrip("/")
            url_from_settings = False

        if supabase_key is _UNSET:
            if url_from_settings or (resolved_url and resolved_url == (settings.SUPABASE_URL or "").rstrip("/")):
                resolved_key = (settings.SUPABASE_KEY or "").strip()
            else:
                resolved_key = ""
            key_from_settings = True
        elif supabase_key is None:
            resolved_key = ""
            key_from_settings = False
        else:
            resolved_key = str(supabase_key).strip()
            key_from_settings = False

        if service_role_key is _UNSET:
            if url_from_settings or (resolved_url and resolved_url == (settings.SUPABASE_URL or "").rstrip("/")):
                resolved_service_key = (settings.SUPABASE_SERVICE_ROLE_KEY or "").strip()
            else:
                resolved_service_key = ""
            service_key_from_settings = True
        elif service_role_key is None:
            resolved_service_key = ""
            service_key_from_settings = False
        else:
            resolved_service_key = str(service_role_key).strip()
            service_key_from_settings = False

        # Cross-project mixing protection:
        # Only non-empty credential overrides should trigger this guard.
        # Explicit None/empty values disable a credential; they must not
        # accidentally disable the URL or another valid credential.
        settings_anon_key = (settings.SUPABASE_KEY or "").strip()
        settings_service_key = (
            settings.SUPABASE_SERVICE_ROLE_KEY or ""
        ).strip()
        config_conflict_reason: Optional[str] = None

        if (
            not key_from_settings
            and resolved_key
            and resolved_key != settings_anon_key
            and url_from_settings
        ):
            resolved_url = ""
            if service_key_from_settings:
                resolved_service_key = ""
            config_conflict_reason = (
                "Conflicting Supabase configuration: custom anon key override provided "
                "without matching SUPABASE_URL."
            )

        if (
            not service_key_from_settings
            and resolved_service_key
            and resolved_service_key != settings_service_key
            and url_from_settings
        ):
            resolved_url = ""
            if key_from_settings:
                resolved_key = ""
            config_conflict_reason = (
                "Conflicting Supabase configuration: custom service_role credential override "
                "provided without matching SUPABASE_URL."
            )

        self._supabase_url = resolved_url
        self._supabase_key = resolved_key
        self._supabase_service_role_key = resolved_service_key
        self._config_conflict_reason = config_conflict_reason
        self._explicit_in_memory_isolation = False

        resolved_timeout = timeout_sec if timeout_sec is not None else settings.PERSISTENCE_TIMEOUT_SEC
        if resolved_timeout is not None:
            if not (0.5 <= float(resolved_timeout) <= 20.0):
                raise ValueError(
                    f"Persistence repository timeout must be between 0.5 and 20.0 seconds, got {resolved_timeout}"
                )
        self._timeout_sec = float(resolved_timeout) if resolved_timeout is not None else 5.0

        self._active_key = (
            self._supabase_service_role_key or self._supabase_key
        )
        self._is_configured = bool(
            self._supabase_url and self._active_key
        )

        self._in_memory_records: List[Dict[str, Any]] = []
        self._mode_history_records: List[Dict[str, Any]] = []
        self._in_memory_directive_audits: List[Dict[str, Any]] = []
        self._in_memory_devices: Dict[str, Dict[str, Any]] = self._default_in_memory_devices()

        self._last_persistence_error: Optional[str] = None
        self._total_persisted_count: int = 0
        self._failed_persistence_count: int = 0
        self._connection_status: str = (
            "UNCONFIGURED"
            if not self._is_configured
            else "CONFIGURED_UNCHECKED"
        )
        self._last_ping_ms: Optional[float] = None

    @staticmethod
    def _default_in_memory_devices() -> Dict[str, Dict[str, Any]]:
        now_iso = datetime.now(timezone.utc).isoformat()
        return {
            "DRAINX-ESP32-NODE-01": {
                "device_id": "DRAINX-ESP32-NODE-01",
                "name": "Primary Flume ESP32 Node",
                "hardware_model": "ESP32 DevKit V1 (ESP-WROOM-32)",
                "firmware_version": "0.3.7-p0.3g",
                "is_active": True,
                "validation_stage": "CONNECTIVITY_READY",
                "last_seen_at": now_iso,
                "created_at": now_iso,
                "metadata": {"location": "Flume Primary Sump"},
            }
        }

    @classmethod
    def create_isolated_in_memory(cls, timeout_sec: float = 5.0) -> "PersistenceRepository":
        """Explicitly constructs an isolated in-memory repository for unit testing."""
        repo = cls(supabase_url="", supabase_key="", service_role_key="", timeout_sec=timeout_sec)
        repo._explicit_in_memory_isolation = True
        return repo

    def reset_in_memory_state(self) -> None:
        """Clears local in-memory buffers, directive audits, device registry, and counters."""
        self._in_memory_records.clear()
        self._mode_history_records.clear()
        self._in_memory_directive_audits.clear()
        self._in_memory_devices = self._default_in_memory_devices()
        self._total_persisted_count = 0
        self._failed_persistence_count = 0
        self._last_persistence_error = None
        self._connection_status = "UNCONFIGURED" if not self._is_configured else "CONFIGURED_UNCHECKED"
        self._last_ping_ms = None

    @property
    def is_configured(self) -> bool:
        return self._is_configured

    @property
    def is_storage_configured(self) -> bool:
        """
        True only when PostgREST URL and a validated SUPABASE_SERVICE_ROLE_KEY are
        configured without credential conflicts. Storage, rate-limit RPC, and directive
        audit ledger operations require validated service-role privileges.
        """
        if not self._is_configured or self._config_conflict_reason:
            return False
        if not (self._supabase_url or "").strip():
            return False
        valid_sr, _ = inspect_service_role_credential(
            self._supabase_service_role_key,
            self._supabase_key,
        )
        return valid_sr

    @property
    def upload_lease_sec(self) -> int:
        return 120

    @property
    def cleanup_lease_sec(self) -> int:
        return 60

    @property
    def supabase_url(self) -> str:
        return self._supabase_url

    def get_status(self) -> DatabaseConfigStatus:
        sr_valid, _ = inspect_service_role_credential(
            self._supabase_service_role_key,
            self._supabase_key,
        )
        return DatabaseConfigStatus(
            configured=self._is_configured,
            url_present=bool(self._supabase_url),
            key_present=bool(self._supabase_key),
            service_role_key_present=sr_valid,
            mode="SUPABASE_CLOUD" if self._is_configured else "IN_MEMORY_FALLBACK",
            target_table="sensor_readings",
            last_persistence_error=self._last_persistence_error,
            total_persisted_count=self._total_persisted_count,
            failed_persistence_count=self._failed_persistence_count,
            connection_status=self._connection_status,
            last_ping_ms=self._last_ping_ms,
        )

    def _get_headers(self, prefer: str = "return=minimal") -> Dict[str, str]:
        return {
            "apikey": self._active_key,
            "Authorization": f"Bearer {self._active_key}",
            "Content-Type": "application/json",
            "Prefer": prefer,
        }

    async def check_connection(self) -> Dict[str, Any]:
        """
        Probe Supabase Cloud PostgREST health and round-trip latency.
        """
        if not self._is_configured:
            self._connection_status = "UNCONFIGURED"
            return {
                "status": "UNCONFIGURED",
                "mode": "IN_MEMORY_FALLBACK",
                "message": "Supabase credentials not configured. Running in local in-memory mode.",
                "latency_ms": None,
                "configured": False,
            }

        endpoint = f"{self._supabase_url}/rest/v1/sensor_readings?select=count&limit=0"
        t_start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=self._timeout_sec) as client:
                resp = await client.get(
                    endpoint,
                    headers={
                        "apikey": self._active_key,
                        "Authorization": f"Bearer {self._active_key}",
                        "Prefer": "count=exact",
                    },
                )
                elapsed_ms = round((time.perf_counter() - t_start) * 1000.0, 2)
                self._last_ping_ms = elapsed_ms

                if resp.status_code in (200, 206):
                    self._connection_status = "CONNECTED"
                    self._last_persistence_error = None
                    return {
                        "status": "CONNECTED",
                        "mode": "SUPABASE_CLOUD",
                        "message": "Successfully connected to Supabase Cloud PostgREST.",
                        "latency_ms": elapsed_ms,
                        "http_status": resp.status_code,
                        "configured": True,
                    }
                elif resp.status_code in (401, 403):
                    self._connection_status = "AUTH_FAILED"
                    err_msg = f"HTTP {resp.status_code} - Invalid or unauthorized Supabase API key"
                    self._last_persistence_error = err_msg
                    return {
                        "status": "AUTH_FAILED",
                        "mode": "SUPABASE_CLOUD",
                        "message": err_msg,
                        "latency_ms": elapsed_ms,
                        "http_status": resp.status_code,
                        "configured": True,
                    }
                else:
                    self._connection_status = "UNREACHABLE"
                    err_msg = f"HTTP {resp.status_code}"
                    self._last_persistence_error = err_msg
                    return {
                        "status": "UNREACHABLE",
                        "mode": "SUPABASE_CLOUD",
                        "message": err_msg,
                        "latency_ms": elapsed_ms,
                        "http_status": resp.status_code,
                        "configured": True,
                    }
        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - t_start) * 1000.0, 2)
            self._last_ping_ms = elapsed_ms
            self._connection_status = "UNREACHABLE"
            err_msg = f"Network connection failed: {exc.__class__.__name__}"
            self._last_persistence_error = err_msg
            return {
                "status": "UNREACHABLE",
                "mode": "SUPABASE_CLOUD",
                "message": err_msg,
                "latency_ms": elapsed_ms,
                "http_status": None,
                "configured": True,
            }

    async def persist_readings(
        self, readings: List[SensorReadingContract]
    ) -> int:
        """
        Persist a batch of validated sensor telemetry readings to Supabase PostgREST.
        Falls back to internal buffer if Supabase is unconfigured or unreachable.
        """
        if not readings:
            return 0

        records = []
        for r in readings:
            device_id = None
            if r.metadata and isinstance(r.metadata, dict):
                device_id = r.metadata.get("device_id")

            records.append({
                "sensor_id": r.sensor_id,
                "section_id": r.section_id,
                "sensor_type": r.sensor_type.value,
                "value": float(r.value),
                "unit": r.unit.value,
                "source": r.source.value,
                "status": r.status.value,
                "timestamp": r.timestamp.isoformat(),
                "device_id": device_id,
                "metadata": r.metadata or {},
            })

        # Local buffer is maintained as fallback and secondary audit
        self._in_memory_records.extend(records)
        if len(self._in_memory_records) > 20000:
            self._in_memory_records = self._in_memory_records[-20000:]

        if not self._is_configured:
            self._total_persisted_count += len(records)
            return len(records)

        endpoint = f"{self._supabase_url}/rest/v1/sensor_readings"
        try:
            async with httpx.AsyncClient(timeout=self._timeout_sec) as client:
                resp = await client.post(
                    endpoint,
                    json=records,
                    headers=self._get_headers(),
                )
                if resp.status_code in (200, 201):
                    self._total_persisted_count += len(records)
                    self._last_persistence_error = None
                    self._connection_status = "CONNECTED"
                    return len(records)
                else:
                    err_msg = f"HTTP {resp.status_code}"
                    self._last_persistence_error = err_msg
                    self._failed_persistence_count += len(records)
                    logger.warning("Supabase persistence error: %s", err_msg)
                    return 0
        except Exception as exc:
            err_msg = str(exc)
            self._last_persistence_error = err_msg
            self._failed_persistence_count += len(records)
            logger.warning("Supabase persistence network error: %s", exc.__class__.__name__)
            return 0

    async def query_historical_telemetry(
        self,
        sensor_id: Optional[str] = None,
        source: Optional[str] = None,
        section_id: Optional[str] = None,
        device_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
        chronological: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Query historical telemetry with operational source, device, and time-range filtering.
        Supports pagination via limit & offset.
        """
        limit = max(1, min(limit, 10000))
        offset = max(0, offset)

        if not self._is_configured:
            results = list(self._in_memory_records)
            if sensor_id:
                results = [r for r in results if r.get("sensor_id") == sensor_id]
            if source:
                norm_source = str(source).upper()
                if norm_source in ("PHYSICAL", "LIVE"):
                    results = [r for r in results if str(r.get("source", "")).upper() in ("PHYSICAL", "LIVE")]
                else:
                    results = [r for r in results if str(r.get("source", "")).upper() == norm_source]
            if section_id:
                results = [r for r in results if r.get("section_id") == section_id]
            if device_id:
                results = [r for r in results if r.get("device_id") == device_id]
            if start_time:
                aware_start = start_time if (start_time.tzinfo and start_time.tzinfo.utcoffset(start_time)) else start_time.replace(tzinfo=timezone.utc)
                results = [
                    r for r in results
                    if _parse_record_datetime(r.get("timestamp")) is not None
                    and _parse_record_datetime(r.get("timestamp")) >= aware_start
                ]
            if end_time:
                aware_end = end_time if (end_time.tzinfo and end_time.tzinfo.utcoffset(end_time)) else end_time.replace(tzinfo=timezone.utc)
                results = [
                    r for r in results
                    if _parse_record_datetime(r.get("timestamp")) is not None
                    and _parse_record_datetime(r.get("timestamp")) <= aware_end
                ]

            def _in_memory_sort_key(rec: Dict[str, Any]) -> Tuple[datetime, str]:
                parsed_dt = _parse_record_datetime(rec.get("timestamp"))
                safe_dt = parsed_dt if parsed_dt is not None else datetime.min.replace(tzinfo=timezone.utc)
                safe_id = str(rec.get("id", ""))
                return (safe_dt, safe_id)

            results.sort(key=_in_memory_sort_key, reverse=not chronological)
            return results[offset : offset + limit]

        endpoint = f"{self._supabase_url}/rest/v1/sensor_readings"
        order_direction = "asc" if chronological else "desc"
        page_size = getattr(self, "POSTGREST_PAGE_SIZE", 1000)

        all_records: List[Dict[str, Any]] = []
        remaining_limit = limit
        cursor: Optional[Tuple[str, str]] = None

        headers = {
            "apikey": self._active_key,
            "Authorization": f"Bearer {self._active_key}",
            "Accept": "application/json",
        }

        async with httpx.AsyncClient(timeout=self._timeout_sec) as client:
            while remaining_limit > 0:
                fetch_count = min(remaining_limit, page_size)

                # Build query params as list of tuples to support multiple constraints
                query_params: List[Tuple[str, str]] = [
                    ("order", f"timestamp.{order_direction},id.{order_direction}"),
                    ("limit", str(fetch_count)),
                ]
                if cursor is None:
                    if offset > 0:
                        query_params.append(("offset", str(offset)))
                else:
                    c_ts, c_id = cursor
                    if chronological:
                        query_params.append(("or", f"(timestamp.gt.{c_ts},and(timestamp.eq.{c_ts},id.gt.{c_id}))"))
                    else:
                        query_params.append(("or", f"(timestamp.lt.{c_ts},and(timestamp.eq.{c_ts},id.lt.{c_id}))"))

                if sensor_id:
                    query_params.append(("sensor_id", f"eq.{sensor_id}"))
                if source:
                    norm_source = str(source).upper()
                    if norm_source in ("PHYSICAL", "LIVE"):
                        query_params.append(("source", "in.(PHYSICAL,LIVE)"))
                    else:
                        query_params.append(("source", f"eq.{source}"))
                if section_id:
                    query_params.append(("section_id", f"eq.{section_id}"))
                if device_id:
                    query_params.append(("device_id", f"eq.{device_id}"))
                if start_time:
                    query_params.append(("timestamp", f"gte.{start_time.isoformat()}"))
                if end_time:
                    query_params.append(("timestamp", f"lte.{end_time.isoformat()}"))

                try:
                    resp = await client.get(endpoint, params=query_params, headers=headers)
                except Exception as exc:
                    err_msg = f"Supabase query network error: {exc}"
                    self._last_persistence_error = err_msg
                    logger.warning("Supabase query network error: %s", exc.__class__.__name__)
                    raise RuntimeError(err_msg) from exc

                if resp.status_code != 200:
                    err_msg = f"Supabase query error: HTTP {resp.status_code} - {resp.text}"
                    self._last_persistence_error = err_msg
                    logger.warning("Supabase query error: HTTP %s", resp.status_code)
                    raise RuntimeError(err_msg)

                try:
                    page_data = resp.json()
                except Exception as exc:
                    err_msg = f"Supabase query returned malformed JSON: {exc.__class__.__name__}"
                    self._last_persistence_error = err_msg
                    logger.warning("Supabase query returned malformed JSON: %s", exc.__class__.__name__)
                    raise RuntimeError(err_msg) from exc

                if not isinstance(page_data, list):
                    err_msg = f"Supabase query returned unexpected non-list data: {type(page_data).__name__}"
                    self._last_persistence_error = err_msg
                    logger.warning("Supabase query returned unexpected non-list data: %s", type(page_data).__name__)
                    raise RuntimeError(err_msg)

                # Clear last error only after successful response decode and validation
                self._last_persistence_error = None

                if not page_data:
                    break

                all_records.extend(page_data)
                remaining_limit -= len(page_data)

                last_rec = page_data[-1]
                last_ts = last_rec.get("timestamp")
                last_id = str(last_rec.get("id", ""))
                if last_ts is not None:
                    cursor = (last_ts, last_id)
                else:
                    break

        return all_records

    async def persist_mode_transition(
        self,
        from_mode: str,
        to_mode: str,
        reason: str,
        operator_id: str = "SYSTEM",
    ) -> bool:
        """
        Persist an operational mode transition audit record.
        """
        record = {
            "from_mode": from_mode,
            "to_mode": to_mode,
            "reason": reason,
            "operator_id": operator_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._mode_history_records.append(record)
        if len(self._mode_history_records) > 500:
            self._mode_history_records = self._mode_history_records[-500:]

        if not self._is_configured:
            return True

        endpoint = f"{self._supabase_url}/rest/v1/operational_mode_history"
        try:
            async with httpx.AsyncClient(timeout=self._timeout_sec) as client:
                resp = await client.post(
                    endpoint,
                    json=[record],
                    headers=self._get_headers(),
                )
                return resp.status_code in (200, 201)
        except Exception as exc:
            logger.warning("Failed to persist mode history to Supabase: %s", exc.__class__.__name__)
            return False

    async def query_mode_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Query auditable mode transition history from Supabase or memory buffer.
        """
        limit = max(1, min(limit, 500))
        if not self._is_configured:
            return list(reversed(self._mode_history_records))[:limit]

        endpoint = f"{self._supabase_url}/rest/v1/operational_mode_history"
        params = {"order": "timestamp.desc", "limit": str(limit)}
        try:
            async with httpx.AsyncClient(timeout=self._timeout_sec) as client:
                resp = await client.get(
                    endpoint,
                    params=params,
                    headers={
                        "apikey": self._active_key,
                        "Authorization": f"Bearer {self._active_key}",
                        "Accept": "application/json",
                    },
                )
                if resp.status_code == 200:
                    return resp.json()
                return list(reversed(self._mode_history_records))[:limit]
        except Exception as exc:
            logger.warning("Supabase mode history query error: %s", exc.__class__.__name__)
            return list(reversed(self._mode_history_records))[:limit]

    async def register_device(self, device_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Register or update an IoT edge device in the devices registry.
        """
        device_id = device_data.get("device_id")
        if not device_id:
            raise ValueError("device_id is required")

        record = {
            "device_id": device_id,
            "name": device_data.get("name", device_id),
            "hardware_model": device_data.get("hardware_model", "ESP32 DevKit V1"),
            "firmware_version": device_data.get("firmware_version", "unknown"),
            "is_active": device_data.get("is_active", True),
            "validation_stage": device_data.get("validation_stage", "SOFTWARE_ONLY"),
            "last_seen_at": datetime.now(timezone.utc).isoformat(),
            "metadata": device_data.get("metadata", {}),
        }

        # Keep local memory updated
        self._in_memory_devices[device_id] = record

        if not self._is_configured:
            return record

        endpoint = f"{self._supabase_url}/rest/v1/devices"
        headers = self._get_headers(prefer="resolution=merge-duplicates,return=representation")
        try:
            async with httpx.AsyncClient(timeout=self._timeout_sec) as client:
                resp = await client.post(endpoint, json=[record], headers=headers)
                if resp.status_code in (200, 201):
                    returned = resp.json()
                    return returned[0] if returned else record
                logger.warning("Device registration Supabase error: HTTP %s", resp.status_code)
                return record
        except Exception as exc:
            logger.warning("Device registration network error: %s", exc.__class__.__name__)
            return record

    async def get_device(self, device_id: str, strict: bool = False) -> Optional[Dict[str, Any]]:
        """
        Retrieve device metadata by device_id.
        When `strict=True`, fails closed by propagating ValueError/RuntimeError on invalid IDs
        or cloud persistence errors instead of falling back to in-memory state.
        """
        if strict:
            self._validate_directive_filter_token(device_id, "device_id", max_len=64)

        if not self._is_configured:
            return self._in_memory_devices.get(device_id)

        endpoint = f"{self._supabase_url}/rest/v1/devices"
        params = {"device_id": f"eq.{device_id}"}
        try:
            async with httpx.AsyncClient(timeout=self._timeout_sec) as client:
                resp = await client.get(
                    endpoint,
                    params=params,
                    headers={
                        "apikey": self._active_key,
                        "Authorization": f"Bearer {self._active_key}",
                        "Accept": "application/json",
                    },
                )
                if resp.status_code == 200:
                    items = resp.json()
                    if not isinstance(items, list):
                        if strict:
                            raise RuntimeError("Supabase device lookup returned malformed non-list payload.")
                        logger.warning("Get device returned non-list payload.")
                        return self._in_memory_devices.get(device_id)
                    return items[0] if items else None
                if strict:
                    raise RuntimeError(f"Supabase device lookup failed with HTTP {resp.status_code}")
                return self._in_memory_devices.get(device_id)
        except RuntimeError:
            raise
        except Exception as exc:
            if strict:
                raise RuntimeError(f"Supabase device lookup error: {exc.__class__.__name__}") from exc
            logger.warning("Get device network error: %s", exc.__class__.__name__)
            return self._in_memory_devices.get(device_id)

    async def list_devices(self, strict: bool = False) -> List[Dict[str, Any]]:
        """
        List all registered IoT edge nodes.
        When `strict=True` and cloud persistence is configured, fails closed by raising
        RuntimeError rather than falling back to potentially stale in-memory assignments.
        """
        if not self._is_configured:
            return list(self._in_memory_devices.values())

        endpoint = f"{self._supabase_url}/rest/v1/devices"
        try:
            async with httpx.AsyncClient(timeout=self._timeout_sec) as client:
                resp = await client.get(
                    endpoint,
                    headers={
                        "apikey": self._active_key,
                        "Authorization": f"Bearer {self._active_key}",
                        "Accept": "application/json",
                    },
                )
                if resp.status_code == 200:
                    items = resp.json()
                    if not isinstance(items, list):
                        if strict:
                            raise RuntimeError("Supabase device registry returned malformed non-list payload.")
                        logger.warning("List devices returned non-list payload.")
                        return list(self._in_memory_devices.values())
                    return items
                if strict:
                    raise RuntimeError(f"Supabase device registry query failed with HTTP {resp.status_code}")
                return list(self._in_memory_devices.values())
        except RuntimeError:
            raise
        except Exception as exc:
            if strict:
                raise RuntimeError(f"Supabase device registry query error: {exc.__class__.__name__}") from exc
            logger.warning("List devices network error: %s", exc.__class__.__name__)
            return list(self._in_memory_devices.values())

    async def persist_incident_audit(self, audit_dict: Dict[str, Any]) -> bool:
        """
        Persist an incident operational audit record to Supabase incident_audits table.
        Gracefully degrades if table does not exist or Supabase is unconfigured in development.
        In cloud environments, logs explicit operational alerts on persistence failures.
        """
        if not self._is_configured:
            return True

        endpoint = f"{self._supabase_url}/rest/v1/incident_audits"
        try:
            async with httpx.AsyncClient(timeout=self._timeout_sec) as client:
                resp = await client.post(
                    endpoint,
                    json=[audit_dict],
                    headers=self._get_headers(prefer="resolution=merge-duplicates"),
                )
                if resp.status_code in (200, 201):
                    return True
                logger.warning("Supabase audit persistence HTTP %s", resp.status_code)
                return False
        except Exception as exc:
            logger.warning("Failed to persist audit to Supabase Cloud: %s", exc.__class__.__name__)
            return False


    def persist_incident_audit_sync(self, audit_dict: Dict[str, Any]) -> bool:
        """
        Synchronous variant of persist_incident_audit for atomic coordination in synchronous state store.
        Uses ignore-duplicates so retries cannot modify existing audit records.
        """
        if not self._is_configured:
            return True

        endpoint = f"{self._supabase_url}/rest/v1/incident_audits"
        try:
            with httpx.Client(timeout=self._timeout_sec) as client:
                resp = client.post(
                    endpoint,
                    json=[audit_dict],
                    headers=self._get_headers(prefer="resolution=ignore-duplicates"),
                )
                if resp.status_code in (200, 201):
                    return True
                logger.warning("Supabase synchronous audit persistence HTTP %s", resp.status_code)
                return False
        except Exception as exc:
            logger.warning("Supabase synchronous audit persistence network error: %s", exc.__class__.__name__)
            return False
    async def query_incident_audits(self, incident_id: str) -> List[Dict[str, Any]]:
        """
        Query incident audit ledger from Supabase Cloud.
        """
        if not self._is_configured:
            return []

        endpoint = f"{self._supabase_url}/rest/v1/incident_audits"
        params = {"incident_id": f"eq.{incident_id}", "order": "timestamp.asc"}

        try:
            async with httpx.AsyncClient(timeout=self._timeout_sec) as client:
                resp = await client.get(
                    endpoint,
                    params=params,
                    headers=self._get_headers(),
                )
                if resp.status_code == 200:
                    return resp.json()
                return []
        except Exception as exc:
            logger.warning("Supabase incident audit query error: %s", exc.__class__.__name__)
            return []

    def query_incident_audits_sync(
        self, incident_id: str, strict: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Synchronously query authoritative incident audit ledger from Supabase Cloud.
        When strict=True, fails closed by raising RuntimeError on query or network failure.
        """
        if not self._is_configured:
            return []

        clean_inc_id = _validate_incident_id(incident_id)
        endpoint = f"{self._supabase_url}/rest/v1/incident_audits"
        params = {"incident_id": f"eq.{clean_inc_id}", "order": "timestamp.asc"}
        try:
            with httpx.Client(timeout=self._timeout_sec) as client:
                resp = client.get(
                    endpoint,
                    params=params,
                    headers=self._get_headers(),
                )
                if resp.status_code == 200:
                    return resp.json()
                if strict:
                    raise RuntimeError(
                        f"Supabase synchronous incident audit query failed with HTTP {resp.status_code}"
                    )
                return []
        except Exception as exc:
            if strict:
                raise RuntimeError(
                    f"Supabase synchronous incident audit query error: {exc.__class__.__name__}"
                ) from exc
            logger.warning("Supabase synchronous incident audit query error: %s", exc.__class__.__name__)
            return []

    def directive_audit_cloud_mode(self) -> bool:
        """
        Single authoritative determination of whether directive audit reads and writes
        target cloud PostgreSQL. Distinguishes explicit in-memory test isolation from
        partial, conflicting, or invalid cloud credentials, and always fails closed.
        """
        if self._config_conflict_reason:
            raise StorageNotConfiguredError(self._config_conflict_reason)

        has_url = bool((self._supabase_url or "").strip())
        has_anon = bool((self._supabase_key or "").strip())
        has_service = bool((self._supabase_service_role_key or "").strip())

        if self._explicit_in_memory_isolation and not (
            self._is_configured or has_url or has_anon or has_service
        ):
            return False

        if not self._is_configured and not has_url and not has_anon and not has_service:
            if settings.ENVIRONMENT == "production":
                raise StorageNotConfiguredError(
                    "Production environment requires configured SUPABASE_URL and "
                    "SUPABASE_SERVICE_ROLE_KEY for actuator directive audit persistence."
                )
            return False

        if not has_url:
            raise StorageNotConfiguredError(
                "Partial Supabase configuration: credential provided without SUPABASE_URL."
            )

        valid_sr, sr_reason = inspect_service_role_credential(
            self._supabase_service_role_key,
            self._supabase_key,
        )
        if not valid_sr:
            raise StorageNotConfiguredError(
                f"Actuator directive audit ledger requires a valid SUPABASE_SERVICE_ROLE_KEY: {sr_reason}"
            )

        if not self._is_configured:
            raise StorageNotConfiguredError(
                "Actuator directive audit ledger configuration is disabled while cloud credentials remain set."
            )

        return True

    def _directive_audit_cloud_mode(self) -> bool:
        return self.directive_audit_cloud_mode()

    def persist_directive_audit_sync(
        self, audit: Union[ActuatorDirectiveEventContract, Dict[str, Any]], *, strict: bool = False
    ) -> bool:
        """Persists a single actuator directive audit event synchronously."""
        return self.persist_directive_audit_batch_sync([audit], strict=strict)

    def persist_directive_audit_batch_sync(
        self,
        audits: Sequence[Union[ActuatorDirectiveEventContract, Dict[str, Any]]],
        *,
        strict: bool = False,
    ) -> bool:
        """
        Persists a batch of actuator directive audit events synchronously using the exact
        23-column Migration 008 schema and explicit service_role credentials.
        Verifies all 23 immutable fields on any duplicate audit_id conflict before reporting success.
        """
        if not audits:
            return True

        serialized_rows = [serialize_directive_audit_row(a) for a in audits]

        # Intra-batch duplicate verification and deduplication
        deduped_by_id: Dict[str, Dict[str, Any]] = {}
        deduped_rows: List[Dict[str, Any]] = []
        for row in serialized_rows:
            a_id = row["audit_id"]
            if a_id in deduped_by_id:
                _verify_immutable_directive_audit_match(deduped_by_id[a_id], row)
            else:
                deduped_by_id[a_id] = row
                deduped_rows.append(row)

        use_cloud = self.directive_audit_cloud_mode()
        if not use_cloud:
            # In-memory storage: verify entire batch atomically before appending new rows
            rows_to_insert: List[Dict[str, Any]] = []
            for ad in deduped_rows:
                existing = next(
                    (rec for rec in self._in_memory_directive_audits if rec["audit_id"] == ad["audit_id"]),
                    None,
                )
                if existing is not None:
                    _verify_immutable_directive_audit_match(existing, ad)
                else:
                    rows_to_insert.append(dict(ad))
            self._in_memory_directive_audits.extend(rows_to_insert)
            return True

        endpoint = f"{self._supabase_url}/rest/v1/actuator_directive_audits"
        all_ids = [r["audit_id"] for r in deduped_rows]
        try:
            with httpx.Client(timeout=self._timeout_sec) as client:
                # Phase 1 (pre-flight): verify every already-persisted row across the COMPLETE batch
                # BEFORE any write, so a conflicting duplicate can never leave sibling rows committed.
                existing_by_id = self._fetch_directive_audits_by_ids(client, endpoint, all_ids)
                new_rows: List[Dict[str, Any]] = []
                for row in deduped_rows:
                    existing = existing_by_id.get(row["audit_id"])
                    if existing is None:
                        new_rows.append(row)
                    else:
                        _verify_immutable_directive_audit_match(existing, row)
                if not new_rows:
                    return True

                # Phase 2: single bulk INSERT (one PostgREST request == one SQL statement/transaction).
                headers = self._get_storage_headers(content_type="application/json")
                headers["Prefer"] = "resolution=ignore-duplicates,return=representation"
                resp = client.post(endpoint, json=new_rows, headers=headers)
                if resp.status_code in (200, 201):
                    returned = resp.json()
                    if not isinstance(returned, list):
                        self._failed_persistence_count += 1
                        self._last_persistence_error = "Supabase directive audit insert returned malformed non-list payload."
                        if strict:
                            raise StorageError(self._last_persistence_error)
                        logger.warning(self._last_persistence_error)
                        return False
                    new_by_id = {r["audit_id"]: r for r in new_rows}
                    inserted_ids = set()
                    for r in returned:
                        if isinstance(r, dict) and r.get("audit_id") in new_by_id:
                            try:
                                _verify_immutable_directive_audit_match(r, new_by_id[r["audit_id"]])
                            except DirectiveAuditConflictError as exc:
                                self._failed_persistence_count += 1
                                self._last_persistence_error = (
                                    "Directive audit insert returned a representation that diverges from the submitted row."
                                )
                                raise StorageError(self._last_persistence_error) from exc
                            inserted_ids.add(r["audit_id"])
                    missing_rows = [ad for ad in new_rows if ad["audit_id"] not in inserted_ids]
                elif resp.status_code == 409:
                    missing_rows = list(new_rows)
                else:
                    self._failed_persistence_count += 1
                    self._last_persistence_error = f"Supabase directive audit persistence HTTP {resp.status_code}"
                    logger.warning(self._last_persistence_error)
                    if strict:
                        raise StorageError(self._last_persistence_error)
                    return False

                if missing_rows:
                    # Phase 3 (post-flight): rows skipped by ignore-duplicates were inserted concurrently
                    # by another writer after pre-flight; verify them across all 23 columns.
                    raced = self._fetch_directive_audits_by_ids(
                        client, endpoint, [ad["audit_id"] for ad in missing_rows]
                    )
                    for incoming in missing_rows:
                        existing = raced.get(incoming["audit_id"])
                        if existing is None:
                            raise StorageError(
                                f"Directive audit '{incoming['audit_id']}' was neither inserted nor found for immutable verification."
                            )
                        _verify_immutable_directive_audit_match(existing, incoming)

                self._total_persisted_count += len(new_rows) - len(missing_rows)
                return True
        except (DirectiveAuditConflictError, StorageNotConfiguredError, ValueError, TypeError):
            raise
        except StorageError:
            raise
        except Exception as exc:
            self._failed_persistence_count += 1
            self._last_persistence_error = f"Supabase directive audit batch persistence error: {exc.__class__.__name__}"
            logger.warning("Supabase synchronous directive audit batch persistence error: %s", exc.__class__.__name__)
            if strict:
                raise StorageError(self._last_persistence_error) from exc
            return False

    def _fetch_directive_audits_by_ids(
        self, client: Any, endpoint: str, audit_ids: Sequence[str]
    ) -> Dict[str, Dict[str, Any]]:
        """
        Fetches existing directive audit rows for `audit_ids` using bounded, safely-quoted
        PostgREST filters and merges results across chunks. Any transport/HTTP/shape failure
        raises StorageError (fail closed) regardless of `strict`.
        """
        max_ids = int(getattr(self, "directive_audit_verify_chunk_size", self.DIRECTIVE_AUDIT_VERIFY_CHUNK_SIZE))
        max_chars = int(self.DIRECTIVE_AUDIT_VERIFY_MAX_QUERY_CHARS)
        if max_ids < 1:
            raise StorageError("Directive audit verification chunk size must be at least 1.")
        merged: Dict[str, Dict[str, Any]] = {}
        headers = self._get_storage_headers()
        for chunk in _chunk_audit_ids(list(audit_ids), max_ids, max_chars):
            chunk_set = set(chunk)
            try:
                resp = client.get(
                    endpoint,
                    params={"select": "*", "audit_id": _format_audit_id_postgrest_filter(chunk)},
                    headers=headers,
                )
            except httpx.HTTPError as exc:
                self._failed_persistence_count += 1
                self._last_persistence_error = (
                    f"Directive audit verification query error: {exc.__class__.__name__}"
                )
                raise StorageError(self._last_persistence_error) from exc
            if resp.status_code != 200:
                self._failed_persistence_count += 1
                self._last_persistence_error = (
                    f"Directive audit duplicate verification query failed with HTTP {resp.status_code}"
                )
                raise StorageError(self._last_persistence_error)
            try:
                rows = resp.json()
            except ValueError as exc:
                self._failed_persistence_count += 1
                self._last_persistence_error = "Directive audit duplicate verification query returned invalid JSON."
                raise StorageError(self._last_persistence_error) from exc
            if not isinstance(rows, list):
                self._failed_persistence_count += 1
                self._last_persistence_error = "Directive audit duplicate verification query returned malformed payload."
                raise StorageError(self._last_persistence_error)
            for r in rows:
                if isinstance(r, dict) and r.get("audit_id") in chunk_set:
                    merged[r["audit_id"]] = r
        return merged

    def _validate_directive_filter_token(self, value: str, field_name: str, max_len: int = 64) -> str:
        """Validates directive query filter tokens to prevent PostgREST query operator injection."""
        if not isinstance(value, str) or value != value.strip() or not value:
            raise ValueError(f"Invalid {field_name}: must be a non-empty trimmed string.")
        if not re.match(rf"^[A-Za-z0-9_.:-]{{1,{max_len}}}$", value):
            raise ValueError(f"Invalid {field_name}: contains disallowed characters or exceeds length {max_len}.")
        return value

    def _validate_directive_filter_collection(
        self, values: Any, field_name: str, max_len: int = 64
    ) -> List[str]:
        """Validates every element of a directive filter collection before constructing PostgREST predicates."""
        if isinstance(values, (str, bytes)):
            raise ValueError(f"Invalid {field_name}: must be a collection of strings.")
        try:
            iterator = iter(values)
        except TypeError as exc:
            raise ValueError(f"Invalid {field_name}: must be a collection of strings.") from exc
        validated = [
            self._validate_directive_filter_token(item, field_name, max_len=max_len)
            for item in iterator
        ]
        return sorted(set(validated))

    def query_directive_audits_sync(
        self,
        directive_id: Optional[str] = None,
        operational_mode: Optional[str] = None,
        section_id: Optional[str] = None,
        device_id: Optional[str] = None,
        limit: int = 100,
        strict: bool = False,
        allowed_sections: Optional[Iterable[str]] = None,
        allowed_devices: Optional[Iterable[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Queries actuator directive audit ledger synchronously with strict filter validation.
        Pushes optional `allowed_sections` and `allowed_devices` scope filters into the query
        before ordering and limiting.
        When configured for Supabase/PostgREST, queries the latest `limit` matching rows
        (ordered descending) and returns them in chronological ascending order.
        """
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1 or limit > 1000:
            raise ValueError(f"Invalid limit '{limit}': must be an integer between 1 and 1000.")

        clean_directive_id = (
            self._validate_directive_filter_token(directive_id, "directive_id", max_len=36)
            if directive_id is not None
            else None
        )
        clean_section_id = (
            self._validate_directive_filter_token(section_id, "section_id", max_len=64)
            if section_id is not None
            else None
        )
        clean_device_id = (
            self._validate_directive_filter_token(device_id, "device_id", max_len=64)
            if device_id is not None
            else None
        )
        clean_allowed_sections = (
            self._validate_directive_filter_collection(allowed_sections, "allowed_sections", max_len=64)
            if allowed_sections is not None
            else None
        )
        clean_allowed_devices = (
            self._validate_directive_filter_collection(allowed_devices, "allowed_devices", max_len=64)
            if allowed_devices is not None
            else None
        )
        clean_mode: Optional[str] = None
        if operational_mode is not None:
            if not isinstance(operational_mode, str) or operational_mode not in ALLOWED_OPERATIONAL_MODES:
                raise ValueError(
                    f"Invalid operational_mode '{operational_mode}'. Allowed: {sorted(ALLOWED_OPERATIONAL_MODES)}."
                )
            clean_mode = operational_mode

        # Fail closed before querying if an explicit allowlist is empty or excludes requested filter
        if clean_allowed_sections is not None:
            if not clean_allowed_sections:
                return []
            if clean_section_id is not None and clean_section_id not in clean_allowed_sections:
                return []
        if clean_allowed_devices is not None:
            if not clean_allowed_devices:
                return []
            if clean_device_id is not None and clean_device_id not in clean_allowed_devices:
                return []

        use_cloud = self._directive_audit_cloud_mode()
        if not use_cloud:
            records = list(self._in_memory_directive_audits)
            if clean_directive_id is not None:
                records = [r for r in records if r.get("directive_id") == clean_directive_id]
            if clean_mode is not None:
                records = [r for r in records if r.get("operational_mode") == clean_mode]
            if clean_section_id is not None:
                records = [r for r in records if r.get("section_id") == clean_section_id]
            elif clean_allowed_sections is not None:
                allowed_section_set = set(clean_allowed_sections)
                records = [r for r in records if r.get("section_id") in allowed_section_set]
            if clean_device_id is not None:
                records = [r for r in records if r.get("device_id") == clean_device_id]
            elif clean_allowed_devices is not None:
                allowed_device_set = set(clean_allowed_devices)
                records = [r for r in records if r.get("device_id") in allowed_device_set]
            records.sort(key=lambda x: (str(x.get("timestamp", "")), str(x.get("audit_id", ""))))
            return records[-limit:]

        endpoint = f"{self._supabase_url}/rest/v1/actuator_directive_audits"
        params: Dict[str, str] = {
            "order": "timestamp.desc,audit_id.desc",
            "limit": str(limit),
        }
        if clean_directive_id is not None:
            params["directive_id"] = f"eq.{clean_directive_id}"
        if clean_mode is not None:
            params["operational_mode"] = f"eq.{clean_mode}"
        if clean_section_id is not None:
            params["section_id"] = f"eq.{clean_section_id}"
        elif clean_allowed_sections is not None:
            if len(clean_allowed_sections) == 1:
                params["section_id"] = f"eq.{clean_allowed_sections[0]}"
            else:
                params["section_id"] = f"in.({','.join(clean_allowed_sections)})"
        if clean_device_id is not None:
            params["device_id"] = f"eq.{clean_device_id}"
        elif clean_allowed_devices is not None:
            if len(clean_allowed_devices) == 1:
                params["device_id"] = f"eq.{clean_allowed_devices[0]}"
            else:
                params["device_id"] = f"in.({','.join(clean_allowed_devices)})"

        try:
            with httpx.Client(timeout=self._timeout_sec) as client:
                resp = client.get(endpoint, params=params, headers=self._get_storage_headers())
                if resp.status_code == 200:
                    rows = resp.json()
                    if not isinstance(rows, list):
                        if strict:
                            raise RuntimeError("Supabase directive audit query returned malformed non-list payload.")
                        logger.warning("Supabase directive audit query returned non-list payload.")
                        return []
                    return list(reversed(rows))
                if strict:
                    raise RuntimeError(f"Supabase directive audit query failed with HTTP {resp.status_code}")
                logger.warning("Supabase directive audit query failed with HTTP %s", resp.status_code)
                return []
        except RuntimeError:
            raise
        except Exception as exc:
            if strict:
                raise RuntimeError(f"Supabase directive audit query error: {exc.__class__.__name__}") from exc
            logger.warning("Supabase directive audit query error: %s", exc.__class__.__name__)
            return []

    def recover_incomplete_directives_sync(self, now: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """
        Determines the latest event for each directive_id.
        Identifies every directive whose latest event is non-terminal (ISSUED, FEEDBACK_RECEIVED).
        Recovers each incomplete directive idempotently:
          - Validates required persisted fields; fails closed and skips invalid rows.
          - If expired (>= 30s): transitions to deterministic VERIFICATION_TIMEOUT and persists it.
          - If within deadline (< 30s) and operational_mode == 'PHYSICAL':
              An incomplete physical directive from a previous process must NEVER be reactivated.
              Transitions to deterministic CANCELLED (SAFETY_INTERLOCK, 'startup_recovery') and persists it.
          - If within deadline (< 30s) and non-PHYSICAL (SIMULATION / SAFE_HOLD):
              Returns directive dictionary for active state restoration.
        """
        all_audits = self.query_directive_audits_sync(limit=1000)
        if not all_audits:
            return []

        # Group by directive_id
        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for a in all_audits:
            d_id = a.get("directive_id")
            if d_id:
                grouped.setdefault(d_id, []).append(a)

        terminal_events = {
            "ALIGNMENT_OBSERVED",
            "REJECTED",
            "EXECUTION_FAILED",
            "VERIFICATION_TIMEOUT",
            "CANCELLED",
            "SUPERSEDED",
        }
        recovered_directives: List[Dict[str, Any]] = []

        now_utc = normalize_audit_timestamp_utc(now) if now is not None else datetime.now(timezone.utc)

        for d_id, events in grouped.items():
            def _recovery_sort_key(evt: Dict[str, Any]) -> Tuple[datetime, str]:
                try:
                    dt = normalize_audit_timestamp_utc(evt.get("timestamp"))
                except (ValueError, TypeError):
                    dt = datetime.min.replace(tzinfo=timezone.utc)
                return (dt, str(evt.get("audit_id", "")))

            sorted_events = sorted(events, key=_recovery_sort_key)
            latest = sorted_events[-1]
            latest_type = latest.get("event_type")

            if latest_type not in terminal_events:
                # Fail closed on missing/invalid mandatory columns
                sec_id = latest.get("section_id")
                op_mode = latest.get("operational_mode")
                act = latest.get("action")
                g_angle = latest.get("gate_target_angle")
                rsn = latest.get("reason")
                if not d_id or not sec_id or not op_mode or act is None or g_angle is None or rsn is None:
                    logger.error(
                        "recover_incomplete_directives_sync: incomplete directive '%s' missing mandatory columns; skipping.",
                        d_id or "<missing_id>",
                    )
                    continue

                latest_dt = None
                if latest.get("timestamp") is not None:
                    try:
                        latest_dt = normalize_audit_timestamp_utc(latest.get("timestamp"))
                    except (ValueError, TypeError):
                        latest_dt = None
                if latest_dt is None:
                    logger.error(
                        "recover_incomplete_directives_sync: directive '%s' has null/invalid timestamp; skipping.",
                        d_id,
                    )
                    continue

                issued_anchor = next(
                    (e for e in sorted_events if e.get("event_type") == "ISSUED"),
                    latest,
                )
                anchor_dt = None
                if issued_anchor.get("timestamp") is not None:
                    try:
                        anchor_dt = normalize_audit_timestamp_utc(issued_anchor.get("timestamp"))
                    except (ValueError, TypeError):
                        anchor_dt = None
                effective_anchor_dt = anchor_dt if anchor_dt is not None else latest_dt

                age_s = (now_utc - effective_anchor_dt).total_seconds()

                if age_s >= settings.ACTUATOR_VERIFICATION_TIMEOUT_SEC:
                    timeout_dt = compute_verification_timeout_timestamp(
                        effective_anchor_dt, settings.ACTUATOR_VERIFICATION_TIMEOUT_SEC
                    )
                    timeout_audit = {
                        "audit_id": build_verification_timeout_audit_id(d_id),
                        "directive_id": d_id,
                        "event_type": "VERIFICATION_TIMEOUT",
                        "device_id": latest.get("device_id"),
                        "section_id": sec_id,
                        "operational_mode": op_mode,
                        "directive_type": latest.get("directive_type", "DIVERSION_GATE"),
                        "action": act,
                        "gate_target_angle": g_angle,
                        "reason": (
                            f"Verification timeout after {settings.ACTUATOR_VERIFICATION_TIMEOUT_SEC:.0f}s "
                            "window without observed physical alignment."
                        ),
                        "risk_level": latest.get("risk_level", "INFO"),
                        "emergency_stop": latest.get("emergency_stop", False),
                        "measured_gate_angle": None,
                        "measured_gate_state": None,
                        "execution_divergence_deg": None,
                        "issuer_type": latest.get("issuer_type", "AUTOMATED_ENGINE"),
                        "issuer_id": latest.get("issuer_id"),
                        "correlation_id": latest.get("correlation_id"),
                        "device_session_epoch": latest.get("device_session_epoch"),
                        "baseline_device_sequence_number": latest.get("baseline_device_sequence_number"),
                        "device_sequence_number": None,
                        "device_uptime_ms": None,
                        "timestamp": timeout_dt.isoformat(),
                    }
                    self.persist_directive_audit_sync(timeout_audit)
                elif op_mode == "PHYSICAL":
                    # Recent incomplete PHYSICAL directive (< 30s):
                    # An incomplete PHYSICAL directive from a previous backend process must NEVER be reactivated.
                    # Create deterministic CANCELLED event with SAFETY_INTERLOCK and startup_recovery issuer.
                    cancel_ts = now_utc if now_utc > effective_anchor_dt else (effective_anchor_dt + timedelta(microseconds=1000))
                    cancel_audit = {
                        "audit_id": build_startup_cancellation_audit_id(d_id),
                        "directive_id": d_id,
                        "event_type": "CANCELLED",
                        "device_id": latest.get("device_id"),
                        "section_id": sec_id,
                        "operational_mode": "PHYSICAL",
                        "directive_type": latest.get("directive_type", "DIVERSION_GATE"),
                        "action": act,
                        "gate_target_angle": g_angle,
                        "reason": (
                            "Backend restarted while physical directive was pending verification; "
                            "cancelled pending directive to prevent unverified physical actuation."
                        ),
                        "risk_level": latest.get("risk_level", "INFO"),
                        "emergency_stop": latest.get("emergency_stop", False),
                        "measured_gate_angle": None,
                        "measured_gate_state": None,
                        "execution_divergence_deg": None,
                        "issuer_type": DirectiveIssuerType.SAFETY_INTERLOCK.value,
                        "issuer_id": "startup_recovery",
                        "correlation_id": latest.get("correlation_id"),
                        "device_session_epoch": latest.get("device_session_epoch"),
                        "baseline_device_sequence_number": latest.get("baseline_device_sequence_number"),
                        "device_sequence_number": None,
                        "device_uptime_ms": None,
                        "timestamp": cancel_ts.isoformat(),
                    }
                    self.persist_directive_audit_sync(cancel_audit)
                else:
                    recovered_directives.append(latest)

        return recovered_directives

    def query_incident_by_id_sync(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """
        Authoritative synchronous single incident lookup from PostgreSQL via PostgREST.
        Raises RuntimeError on cloud failure to enforce fail-closed semantics.
        """
        if not self._is_configured and not self.is_storage_configured:
            return None
        clean_inc_id = _validate_incident_id(incident_id)
        endpoint = f"{self._supabase_url}/rest/v1/incidents?id=eq.{clean_inc_id}&select=*"
        try:
            with httpx.Client(timeout=self._timeout_sec) as client:
                resp = client.get(endpoint, headers=self._get_headers())
                if resp.status_code == 200:
                    rows = resp.json()
                    if isinstance(rows, list) and len(rows) > 0:
                        return rows[0]
                    return None
                logger.error("Query incident by id failed with HTTP %s", resp.status_code)
                raise RuntimeError(f"PostgREST query incident failed with HTTP {resp.status_code}")
        except httpx.RequestError as exc:
            logger.error("Query incident by id network error: %s", exc.__class__.__name__)
            raise RuntimeError(f"PostgREST query incident network error: {exc.__class__.__name__}") from exc

    def query_incidents_by_ids_sync(
        self,
        incident_ids: Sequence[str],
        *,
        max_ids_per_chunk: int = 200,
        max_query_chars: int = 4000,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Authoritative synchronous bulk incident lookup from PostgreSQL via PostgREST `id=in.(...)`.
        Deduplicates and validates all IDs, splits into bounded URL-safe chunks (1 request for
        standard duplicate-queue pages up to 200 typical incident IDs), and raises StorageError
        on cloud failures to preserve fail-closed semantics.
        """
        if not isinstance(max_ids_per_chunk, int) or isinstance(max_ids_per_chunk, bool) or max_ids_per_chunk < 1:
            raise StorageValidationError("max_ids_per_chunk must be a positive integer.")
        if not isinstance(max_query_chars, int) or isinstance(max_query_chars, bool) or max_query_chars < 64:
            raise StorageValidationError("max_query_chars must be at least 64.")

        unique_ids = sorted({_validate_incident_id(inc_id) for inc_id in incident_ids if inc_id is not None})
        if not unique_ids:
            return {}
        if not self._is_configured and not self.is_storage_configured:
            return {}

        chunks: List[List[str]] = []
        current_chunk: List[str] = []
        current_len = 0
        for inc_id in unique_ids:
            added_len = len(inc_id) + (1 if current_chunk else 0)
            if current_chunk and (
                len(current_chunk) >= max_ids_per_chunk or (current_len + added_len) > max_query_chars
            ):
                chunks.append(current_chunk)
                current_chunk = [inc_id]
                current_len = len(inc_id)
            else:
                current_chunk.append(inc_id)
                current_len += added_len
        if current_chunk:
            chunks.append(current_chunk)

        endpoint = f"{self._supabase_url}/rest/v1/incidents"
        headers = (
            self._get_storage_headers(content_type="application/json")
            if self.is_storage_configured
            else self._get_headers()
        )
        results: Dict[str, Dict[str, Any]] = {}
        try:
            with httpx.Client(timeout=self._timeout_sec) as client:
                for chunk in chunks:
                    params = {
                        "id": f"in.({','.join(chunk)})",
                        "select": "*",
                    }
                    resp = client.get(endpoint, headers=headers, params=params)
                    if resp.status_code in (200, 206):
                        rows = resp.json()
                        if not isinstance(rows, list):
                            raise StorageError("PostgREST bulk incident query returned invalid JSON shape.")
                        for row in rows:
                            if isinstance(row, dict) and row.get("id"):
                                results[str(row["id"])] = row
                        continue
                    if resp.status_code in (401, 403):
                        raise StorageError(
                            f"PostgREST bulk incident query unauthorized: HTTP {resp.status_code}",
                            error_category="AUTH_ERROR",
                        )
                    logger.error("Bulk query incidents failed with HTTP %s", resp.status_code)
                    raise StorageError(f"PostgREST bulk incident query failed with HTTP {resp.status_code}")
            return results
        except StorageError:
            raise
        except httpx.RequestError as exc:
            logger.error("Bulk query incidents network error: %s", exc.__class__.__name__)
            raise StorageError(
                f"PostgREST bulk incident query network error: {exc.__class__.__name__}"
            ) from exc

    def query_incidents_by_photo_entry_sync(self, photo_name: str) -> List[Dict[str, Any]]:
        """
        Queries PostgreSQL incidents table for any incident containing the legacy photo entry
        (either '{filename}' or '/api/v1/incidents/photos/{filename}') in photos array.
        Used for legacy filename lookup without relying on StateStore in cloud mode.
        """
        if not self._is_configured and not self.is_storage_configured:
            return []
        clean_name = photo_name.strip()
        bare_name = clean_name.split("/")[-1]
        legacy_url = f"/api/v1/incidents/photos/{bare_name}"
        or_filter = f'(photos.cs.{{"{bare_name}"}},photos.cs.{{"{legacy_url}"}})'
        encoded_or = urllib.parse.quote(or_filter, safe="(),.")
        endpoint = f"{self._supabase_url}/rest/v1/incidents?or={encoded_or}&select=*"
        try:
            with httpx.Client(timeout=self._timeout_sec) as client:
                resp = client.get(endpoint, headers=self._get_headers())
                if resp.status_code == 200:
                    rows = resp.json()
                    if not isinstance(rows, list):
                        return []
                    accepted_entries = {bare_name, legacy_url}
                    matched: List[Dict[str, Any]] = []
                    for r in rows:
                        if isinstance(r, dict):
                            r_photos = r.get("photos")
                            if isinstance(r_photos, list):
                                if any(p in accepted_entries for p in r_photos):
                                    matched.append(r)
                            else:
                                matched.append(r)
                    return matched
                logger.error("Query incidents by photo entry failed with HTTP %s", resp.status_code)
                raise RuntimeError(f"PostgREST query incidents by photo entry failed with HTTP {resp.status_code}")
        except httpx.RequestError as exc:
            logger.error("Query incidents by photo entry network error: %s", exc.__class__.__name__)
            raise RuntimeError(f"PostgREST query incidents by photo entry network error: {exc.__class__.__name__}") from exc

    def verify_attached_photo_membership_sync(
        self,
        incident_id: str,
        photo_filename_or_path: str,
        incident_row: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Durable membership verification (SEC-DUR-01, D-01):
        Verifies both:
        1. The canonical object path is present in the incident's durable incidents.photos record.
        2. The storage_object_registry entry for object_path belongs to incident_id and has status = 'ATTACHED'.
        Explicitly rejects REGISTERED, CLEANUP_PENDING, DELETED, UNCERTAIN, or missing rows.
        """
        self._ensure_storage_configured()
        clean_inc_id = _validate_incident_id(incident_id)
        if "/" in photo_filename_or_path:
            canonical_path, _, _ = _validate_canonical_v3_object_path(
                photo_filename_or_path, expected_incident_id=clean_inc_id
            )
        else:
            clean_filename = _validate_photo_id(photo_filename_or_path, clean_inc_id)
            canonical_path, _, _ = _validate_canonical_v3_object_path(
                f"{clean_inc_id}/{clean_filename}", expected_incident_id=clean_inc_id
            )

        # 1. Verify durable membership in authoritative incidents.photos
        authoritative_inc = (
            incident_row
            if isinstance(incident_row, dict)
            else self.query_incident_by_id_sync(clean_inc_id)
        )
        if not authoritative_inc or not isinstance(authoritative_inc, dict):
            return False
        if authoritative_inc.get("id") and authoritative_inc.get("id") != clean_inc_id:
            return False
        inc_photos = authoritative_inc.get("photos")
        if not isinstance(inc_photos, list) or canonical_path not in inc_photos:
            return False

        # 2. Verify durable ATTACHED state in storage_object_registry using object_path column
        encoded_path = urllib.parse.quote(canonical_path, safe="")
        endpoint = (
            f"{self._supabase_url}/rest/v1/storage_object_registry"
            f"?incident_id=eq.{clean_inc_id}&object_path=eq.{encoded_path}&status=eq.ATTACHED"
            f"&select=object_path,incident_id,status"
        )
        try:
            with httpx.Client(timeout=self._timeout_sec) as client:
                resp = client.get(endpoint, headers=self._get_storage_headers())
                if resp.status_code == 200:
                    rows = resp.json()
                    if not isinstance(rows, list) or len(rows) != 1:
                        return False
                    reg_row = rows[0]
                    if not isinstance(reg_row, dict):
                        return False
                    reg_status = reg_row.get("status", "ATTACHED")
                    reg_inc_id = reg_row.get("incident_id", clean_inc_id)
                    reg_obj_path = reg_row.get("object_path", canonical_path)
                    return bool(
                        reg_status == "ATTACHED"
                        and reg_inc_id == clean_inc_id
                        and reg_obj_path == canonical_path
                    )
                logger.error("Verify attached photo membership failed with HTTP %s", resp.status_code)
                raise RuntimeError(f"PostgREST verify attached photo membership failed with HTTP {resp.status_code}")
        except httpx.RequestError as exc:
            logger.error("Verify attached photo membership network error: %s", exc.__class__.__name__)
            raise RuntimeError(f"PostgREST verify attached photo membership network error: {exc.__class__.__name__}") from exc


    def persist_incident_sync(self, incident_dict: Dict[str, Any]) -> bool:
        """
        Synchronously persists a newly reported or updated incident to Supabase PostgreSQL table.
        Uses HTTP Prefer: resolution=merge-duplicates for crash-safe idempotency.
        """
        if not self._is_configured:
            return True

        endpoint = f"{self._supabase_url}/rest/v1/incidents"
        try:
            with httpx.Client(timeout=self._timeout_sec) as client:
                resp = client.post(
                    endpoint,
                    json=[incident_dict],
                    headers=self._get_headers(prefer="resolution=merge-duplicates"),
                )
                if resp.status_code in (200, 201):
                    return True
                logger.warning("Supabase incident persistence HTTP %s", resp.status_code)
                return False
        except Exception as exc:
            logger.warning("Supabase incident persistence network error: %s", exc.__class__.__name__)
            return False

    def query_all_incidents_sync(self, page_size: int = 1000) -> List[Dict[str, Any]]:
        """
        Loads all persisted incidents from Supabase Cloud on backend startup.
        Uses Range header pagination to safely recover all records without silent truncation.
        """
        if not self._is_configured:
            return []

        all_records: List[Dict[str, Any]] = []
        offset = 0
        endpoint = f"{self._supabase_url}/rest/v1/incidents?order=created_at.desc"

        try:
            with httpx.Client(timeout=self._timeout_sec) as client:
                while True:
                    headers = self._get_headers()
                    headers["Range"] = f"{offset}-{offset + page_size - 1}"
                    resp = client.get(endpoint, headers=headers)
                    if resp.status_code not in (200, 206):
                        if resp.status_code != 416:  # 416 Range Not Satisfiable (end of dataset)
                            logger.warning("Supabase incident query returned HTTP %s", resp.status_code)
                        break
                    page = resp.json()
                    if not page:
                        break
                    all_records.extend(page)
                    if len(page) < page_size:
                        break
                    offset += page_size

            return all_records
        except Exception as exc:
            logger.warning("Supabase all incidents paginated query network error: %s", exc.__class__.__name__)
            return []

    def execute_municipal_incident_transaction_sync(
        self,
        incident_id: str,
        new_status: Optional[str],
        new_severity: Optional[str],
        assigned_to: Optional[str],
        assignment_type: Optional[str],
        assigned_team_id: Optional[str],
        assigned_worker_id: Optional[str],
        municipal_notes: Optional[str],
        internal_notes: Optional[str],
        rejection_reason: Optional[str],
        verified_by: Optional[str],
        actor_id: str,
        actor_role: str,
        action: str,
        reason: Optional[str],
        audit_id: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Executes the atomic municipal incident and audit transaction.
        Configured cloud failures raise instead of falling back to separate writes.
        """
        if not self._is_configured:
            return None

        endpoint = f"{self._supabase_url}/rest/v1/rpc/municipal_incident_transaction_rpc"
        payload = {
            "p_incident_id": incident_id,
            "p_new_status": new_status,
            "p_new_severity": new_severity,
            "p_assigned_to": assigned_to,
            "p_assignment_type": assignment_type,
            "p_assigned_team_id": assigned_team_id,
            "p_assigned_worker_id": assigned_worker_id,
            "p_municipal_notes": municipal_notes,
            "p_internal_notes": internal_notes,
            "p_rejection_reason": rejection_reason,
            "p_verified_by": verified_by,
            "p_actor_id": actor_id,
            "p_actor_role": actor_role,
            "p_action": action,
            "p_reason": reason,
            "p_audit_id": audit_id,
        }

        try:
            with httpx.Client(timeout=self._timeout_sec) as client:
                resp = client.post(
                    endpoint,
                    json=payload,
                    headers=self._get_headers(),
                )
                if resp.status_code != 200:
                    logger.error("Municipal incident RPC failed with HTTP %s", resp.status_code)
                    raise RuntimeError(
                        f"Municipal incident RPC failed with HTTP {resp.status_code}."
                    )

                result = resp.json()
                if not isinstance(result, dict) or result.get("id") != incident_id:
                    raise RuntimeError(
                        f"Municipal incident RPC returned an invalid response for '{incident_id}'."
                    )

                return result
        except Exception as exc:
            logger.error("Municipal incident RPC failed for incident %s", incident_id)
            raise RuntimeError(
                f"Atomic municipal cloud transaction failed for incident '{incident_id}'."
            ) from exc

    def execute_citizen_incident_creation_sync(
        self,
        incident_id: str,
        category: str,
        description: str,
        latitude: float,
        longitude: float,
        severity: str,
        source: str,
        reporter_name: str,
        photos: List[str],
        audit_id: str,
        origin_operational_mode: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Executes the atomic citizen incident creation RPC.

        The RPC atomically creates the incident and its initial audit record.

        Returns the persisted incident only after validating the response.
        Never falls back to separate incident and audit writes.

        Returns None only when Supabase is not configured. Callers must
        handle that case separately as local development mode.
        """
        if not self._is_configured:
            return None

        endpoint = (
            f"{self._supabase_url}/rest/v1/rpc/"
            "citizen_incident_creation_rpc"
        )

        payload = {
            "p_incident_id": incident_id,
            "p_category": category,
            "p_description": description,
            "p_latitude": latitude,
            "p_longitude": longitude,
            "p_severity": severity,
            "p_source": source,
            "p_reporter_name": reporter_name,
            "p_photos": photos,
            "p_audit_id": audit_id,
            "p_origin_operational_mode": origin_operational_mode,
        }

        try:
            with httpx.Client(timeout=self._timeout_sec) as client:
                resp = client.post(
                    endpoint,
                    json=payload,
                    headers=self._get_headers(),
                )

                if resp.status_code == 200:
                    try:
                        result = resp.json()
                    except ValueError as exc:
                        logger.error(
                            "Citizen incident RPC returned invalid JSON."
                        )
                        raise RuntimeError(
                            "Citizen incident RPC returned invalid JSON."
                        ) from exc

                    if (
                        not isinstance(result, dict)
                        or result.get("id") != incident_id
                    ):
                        logger.error(
                            "Citizen incident RPC returned an invalid "
                            "incident response for ID %s.",
                            incident_id,
                        )
                        raise RuntimeError(
                            "Citizen incident RPC did not confirm "
                            "the requested incident."
                        )

                    return result

                try:
                    error_body = resp.json()
                except ValueError:
                    error_body = {}

                error_code = (
                    error_body.get("code")
                    if isinstance(error_body, dict)
                    else None
                )

                if (
                    resp.status_code == 404
                    and error_code == "PGRST202"
                ):
                    logger.error(
                        "Citizen incident RPC is unavailable. "
                        "Refusing non-atomic persistence fallback."
                    )
                    raise RuntimeError(
                        "Citizen incident creation RPC is unavailable. "
                        "Check the Supabase function and PostgREST schema cache."
                    )

                logger.error(
                    "Supabase citizen creation RPC failed with HTTP %s",
                    resp.status_code,
                )

                raise RuntimeError(
                    f"Citizen incident RPC failed with HTTP {resp.status_code}."
                )

        except httpx.RequestError as exc:
            logger.error(
                "Citizen incident RPC network error: %s",
                exc.__class__.__name__,
            )
            raise RuntimeError(
                "Citizen incident RPC could not be reached."
            ) from exc

    def _ensure_storage_configured(self) -> None:
        """
        Ensures Supabase Storage is configured with required URL and validated service_role key.
        Private evidence and directive audit operations must NEVER execute under anon key.
        """
        if not self.is_storage_configured:
            if self._config_conflict_reason:
                detail = self._config_conflict_reason
            else:
                _, detail = inspect_service_role_credential(
                    self._supabase_service_role_key,
                    self._supabase_key,
                )
            raise StorageNotConfiguredError(
                f"Supabase Storage requires service-role credentials. {detail}"
            )

    def _get_storage_headers(
        self, content_type: Optional[str] = None
    ) -> Dict[str, str]:
        self._ensure_storage_configured()
        key = self._supabase_service_role_key.strip()
        headers = {
            "apikey": key,
            "Authorization": f"Bearer {key}",
        }
        if content_type:
            headers["Content-Type"] = content_type
        return headers

    def _validate_upload_arguments(
        self,
        incident_id: str,
        photo_id: str,
        file_bytes: bytes,
        content_type: str,
        bucket: Optional[str],
    ) -> Tuple[str, str, str, str]:
        self._ensure_storage_configured()
        target_bucket = _validate_bucket_name(bucket)
        clean_inc_id = _validate_incident_id(incident_id)
        clean_filename = _validate_photo_id(photo_id, clean_inc_id)
        clean_mime = _validate_mime_type(content_type, clean_filename)
        if not isinstance(file_bytes, (bytes, bytearray)) or len(file_bytes) == 0:
            raise StorageValidationError("File bytes must be non-empty binary data.")
        object_path = f"{clean_inc_id}/{clean_filename}"
        return target_bucket, clean_inc_id, object_path, clean_mime

    def _handle_storage_upload_error(
        self, resp: httpx.Response, target_bucket: str, object_path: str
    ) -> None:
        """
        Maps Supabase Storage upload responses to appropriate domain exceptions.
        HTTP 409 -> StorageConflictError.
        HTTP 400 with duplicate indicators -> StorageConflictError.
        Unrelated HTTP 400 and other non-2xx responses -> StorageError.
        Sanitizes logging to prevent token/payload leaks.
        """
        if resp.status_code == 409:
            raise StorageConflictError(
                f"Storage object already exists: '{object_path}'. Overwrite is prohibited."
            )

        if resp.status_code == 400:
            try:
                body = resp.json()
                if isinstance(body, dict):
                    err_val = str(body.get("error") or "").strip().lower()
                    msg_val = str(body.get("message") or "").strip().lower()
                    code_val = str(
                        body.get("statusCode") or body.get("code") or ""
                    ).strip().lower()
                    duplicate_indicators = (
                        "duplicate",
                        "duplicateobject",
                        "duplicate_object",
                        "alreadyexists",
                        "conflict",
                    )
                    if (
                        err_val in duplicate_indicators
                        or code_val in duplicate_indicators
                        or "already exists" in msg_val
                        or "duplicate" in msg_val
                    ):
                        raise StorageConflictError(
                            f"Storage object already exists: '{object_path}'. Overwrite is prohibited."
                        )
            except StorageConflictError:
                raise
            except Exception:
                pass

        logger.error(
            "Supabase Storage upload failed with HTTP %s for object %s/%s",
            resp.status_code,
            target_bucket,
            object_path,
        )
        raise StorageError(
            f"Supabase Storage upload failed with HTTP {resp.status_code}"
        )

    def _validate_and_format_signed_url(
        self,
        signed_url: str,
        expected_bucket: Optional[str] = None,
        expected_canonical_path: Optional[str] = None,
    ) -> str:
        """
        Validates scheme, origin, path structure, and canonical targets of signed URLs
        generated by Supabase Storage.

        Security constraints:
        1. Explicitly rejects any URL with a scheme unless it is an absolute URL
           matching the configured Supabase scheme and origin.
        2. Strictly rejects disallowed schemes (e.g. javascript:, data:, ftp:, file:, vbscript:),
           protocol-relative URLs (//), and malformed URLs.
        3. Only accepts relative paths adhering strictly to expected Supabase Storage
           signed-object format (/storage/v1/object/sign/...).
        4. Validates the resulting URL path (no traversal '..', backslashes, double slashes,
           or noncanonical segments) and verifies exact bucket and object path matching when provided.
        """
        if not isinstance(signed_url, str) or not signed_url.strip():
            raise StorageError("Supabase Storage returned empty signed URL response.")

        clean_url = signed_url.strip()

        # Reject protocol-relative URLs (e.g. //attacker.com/...)
        if clean_url.startswith("//"):
            raise StorageError(
                "Untrusted protocol-relative signed URL rejected."
            )

        # Reject explicit dangerous schemes before parsing
        lower_url = clean_url.lower()
        if lower_url.startswith((
            "javascript:",
            "data:",
            "ftp:",
            "file:",
            "vbscript:",
            "about:",
            "blob:",
        )):
            scheme_hint = clean_url.split(":", 1)[0] if ":" in clean_url else "unknown"
            raise StorageError(
                f"Disallowed signed URL scheme detected: '{scheme_hint}:'."
            )

        base_parts = urllib.parse.urlsplit(self._supabase_url)
        expected_scheme = base_parts.scheme.lower()
        expected_netloc = base_parts.netloc.lower()

        if expected_scheme not in ("http", "https") or not expected_netloc:
            raise StorageError("Configured Supabase URL lacks valid http/https scheme or host.")

        url_parts = urllib.parse.urlsplit(clean_url)

        if url_parts.scheme or url_parts.netloc:
            # Absolute URL: must have BOTH valid matching scheme AND matching host
            if not url_parts.scheme or not url_parts.netloc:
                raise StorageError(
                    "Untrusted signed URL with incomplete absolute origin."
                )
            if url_parts.scheme.lower() != expected_scheme:
                raise StorageError(
                    f"Untrusted signed URL scheme '{url_parts.scheme}'. Expected '{expected_scheme}'."
                )
            if url_parts.netloc.lower() != expected_netloc:
                raise StorageError(
                    f"Untrusted signed URL origin: '{url_parts.netloc}'. Expected '{expected_netloc}'."
                )
            resolved_url = clean_url
            resolved_parts = url_parts
        else:
            # Relative URL: must strictly match expected Supabase Storage signed object path format
            if clean_url.startswith("/storage/v1/object/sign/"):
                norm_rel = clean_url
            elif clean_url.startswith("/object/sign/"):
                norm_rel = f"/storage/v1{clean_url}"
            elif clean_url.startswith("object/sign/"):
                norm_rel = f"/storage/v1/{clean_url}"
            else:
                clean_path_only = clean_url.split("?", 1)[0].split("#", 1)[0]
                raise StorageError(
                    f"Invalid signed URL relative path format: '{clean_path_only}'. Expected '/storage/v1/object/sign/...' format."
                )

            resolved_url = f"{self._supabase_url.rstrip('/')}{norm_rel}"
            resolved_parts = urllib.parse.urlsplit(resolved_url)

            if (
                resolved_parts.scheme.lower() != expected_scheme
                or resolved_parts.netloc.lower() != expected_netloc
            ):
                raise StorageError(
                    f"Constructed signed URL origin mismatch: '{resolved_parts.netloc}'. Expected '{expected_netloc}'."
                )

        # Path validation:
        path = resolved_parts.path
        if not path.startswith("/storage/v1/object/sign/"):
            raise StorageError(
                f"Signed URL path '{path}' does not match expected '/storage/v1/object/sign/' prefix."
            )

        if (
            ".." in path
            or "\\" in path
            or "//" in path
            or "\x00" in path
            or "\r" in path
            or "\n" in path
            or "\t" in path
        ):
            raise StorageError(
                f"Noncanonical characters or traversal detected in signed URL path: '{path}'."
            )

        if expected_bucket and expected_canonical_path:
            expected_exact_path = (
                f"/storage/v1/object/sign/{expected_bucket}/{expected_canonical_path}"
            )
            if path != expected_exact_path:
                raise StorageError(
                    f"Signed URL path '{path}' does not match expected target object '{expected_exact_path}'."
                )

        return resolved_url

    async def upload_incident_photo(
        self,
        incident_id: str,
        photo_id: str,
        file_bytes: bytes,
        content_type: str,
        bucket: Optional[str] = None,
    ) -> str:
        """
        Uploads an incident photograph to Supabase Storage asynchronously.
        Enforces strict validation, no-overwrite (x-upsert: false), and explicit conflict detection.
        Returns the relative storage object path (e.g. 'incident_id/photo_id.ext').
        """
        target_bucket, clean_inc_id, object_path, clean_mime = (
            self._validate_upload_arguments(
                incident_id, photo_id, file_bytes, content_type, bucket
            )
        )

        endpoint = (
            f"{self._supabase_url}/storage/v1/object/{target_bucket}/{object_path}"
        )
        headers = self._get_storage_headers(content_type=clean_mime)
        headers["x-upsert"] = "false"

        try:
            async with httpx.AsyncClient(timeout=self._timeout_sec) as client:
                resp = await client.post(
                    endpoint, content=file_bytes, headers=headers
                )
                if resp.status_code in (200, 201):
                    logger.info(
                        "Uploaded incident photo: %s/%s",
                        target_bucket,
                        object_path,
                    )
                    return object_path

                self._handle_storage_upload_error(
                    resp, target_bucket, object_path
                )
        except httpx.RequestError as exc:
            logger.error(
                "Supabase Storage upload network error for object %s/%s: %s",
                target_bucket,
                object_path,
                exc.__class__.__name__,
            )
            raise StorageError(
                f"Supabase Storage upload network error: {exc.__class__.__name__}"
            ) from exc

    def upload_incident_photo_sync(
        self,
        incident_id: str,
        photo_id: str,
        file_bytes: bytes,
        content_type: str,
        bucket: Optional[str] = None,
    ) -> str:
        """
        Uploads an incident photograph to Supabase Storage synchronously.
        Enforces strict validation, no-overwrite (x-upsert: false), and explicit conflict detection.
        Returns the relative storage object path (e.g. 'incident_id/photo_id.ext').
        """
        target_bucket, clean_inc_id, object_path, clean_mime = (
            self._validate_upload_arguments(
                incident_id, photo_id, file_bytes, content_type, bucket
            )
        )

        endpoint = (
            f"{self._supabase_url}/storage/v1/object/{target_bucket}/{object_path}"
        )
        headers = self._get_storage_headers(content_type=clean_mime)
        headers["x-upsert"] = "false"

        try:
            with httpx.Client(timeout=self._timeout_sec) as client:
                resp = client.post(
                    endpoint, content=file_bytes, headers=headers
                )
                if resp.status_code in (200, 201):
                    logger.info(
                        "Uploaded incident photo: %s/%s",
                        target_bucket,
                        object_path,
                    )
                    return object_path

                self._handle_storage_upload_error(
                    resp, target_bucket, object_path
                )
        except httpx.RequestError as exc:
            logger.error(
                "Supabase Storage upload network error for object %s/%s: %s",
                target_bucket,
                object_path,
                exc.__class__.__name__,
            )
            raise StorageError(
                f"Supabase Storage upload network error: {exc.__class__.__name__}"
            ) from exc

    def create_signed_photo_url(
        self,
        path: str,
        expires_in: Optional[int] = None,
        bucket: Optional[str] = None,
        incident_id: Optional[str] = None,
    ) -> str:
        """
        Creates a temporary signed download URL for a private incident photo in Supabase Storage.
        Enforces strict object key validation, cross-incident isolation, and bounded TTL expiry.
        Returns the absolute signed URL string.
        """
        self._ensure_storage_configured()

        target_bucket = _validate_bucket_name(bucket)
        canonical_path, _, _ = _validate_object_path(
            path, target_bucket, expected_incident_id=incident_id
        )
        ttl = _validate_signed_url_expiry(expires_in)

        endpoint = f"{self._supabase_url}/storage/v1/object/sign/{target_bucket}/{canonical_path}"
        headers = self._get_storage_headers(content_type="application/json")
        payload = {"expiresIn": ttl}

        try:
            with httpx.Client(timeout=self._timeout_sec) as client:
                resp = client.post(endpoint, json=payload, headers=headers)
                if resp.status_code in (200, 201):
                    data = resp.json()
                    signed_rel_url = data.get("signedURL") or data.get(
                        "signedUrl"
                    )
                    if not signed_rel_url:
                        raise StorageError(
                            "Supabase Storage returned empty signed URL response."
                        )

                    logger.info(
                        "Generated signed photo URL for object %s/%s (expiry: %ss)",
                        target_bucket,
                        canonical_path,
                        ttl,
                    )
                    return self._validate_and_format_signed_url(
                        signed_rel_url,
                        expected_bucket=target_bucket,
                        expected_canonical_path=canonical_path,
                    )

                if resp.status_code == 404:
                    raise StorageNotFoundError(
                        f"Object not found in Supabase Storage: '{canonical_path}'."
                    )

                logger.error(
                    "Supabase Storage sign failed with HTTP %s for object %s/%s",
                    resp.status_code,
                    target_bucket,
                    canonical_path,
                )
                raise StorageError(
                    f"Supabase Storage sign failed with HTTP {resp.status_code}"
                )
        except httpx.RequestError as exc:
            logger.error(
                "Supabase Storage sign network error for object %s/%s: %s",
                target_bucket,
                canonical_path,
                exc.__class__.__name__,
            )
            raise StorageError(
                f"Supabase Storage sign network error: {exc.__class__.__name__}"
            ) from exc

    async def create_signed_photo_url_async(
        self,
        path: str,
        expires_in: Optional[int] = None,
        bucket: Optional[str] = None,
        incident_id: Optional[str] = None,
    ) -> str:
        """
        Creates a temporary signed download URL for a private incident photo asynchronously.
        Enforces strict object key validation, cross-incident isolation, and bounded TTL expiry.
        Returns the absolute signed URL string.
        """
        self._ensure_storage_configured()

        target_bucket = _validate_bucket_name(bucket)
        canonical_path, _, _ = _validate_object_path(
            path, target_bucket, expected_incident_id=incident_id
        )
        ttl = _validate_signed_url_expiry(expires_in)

        endpoint = f"{self._supabase_url}/storage/v1/object/sign/{target_bucket}/{canonical_path}"
        headers = self._get_storage_headers(content_type="application/json")
        payload = {"expiresIn": ttl}

        try:
            async with httpx.AsyncClient(timeout=self._timeout_sec) as client:
                resp = await client.post(
                    endpoint, json=payload, headers=headers
                )
                if resp.status_code in (200, 201):
                    data = resp.json()
                    signed_rel_url = data.get("signedURL") or data.get(
                        "signedUrl"
                    )
                    if not signed_rel_url:
                        raise StorageError(
                            "Supabase Storage returned empty signed URL response."
                        )

                    logger.info(
                        "Generated signed photo URL for object %s/%s (expiry: %ss)",
                        target_bucket,
                        canonical_path,
                        ttl,
                    )
                    return self._validate_and_format_signed_url(
                        signed_rel_url,
                        expected_bucket=target_bucket,
                        expected_canonical_path=canonical_path,
                    )

                if resp.status_code == 404:
                    raise StorageNotFoundError(
                        f"Object not found in Supabase Storage: '{canonical_path}'."
                    )

                logger.error(
                    "Supabase Storage sign failed with HTTP %s for object %s/%s",
                    resp.status_code,
                    target_bucket,
                    canonical_path,
                )
                raise StorageError(
                    f"Supabase Storage sign failed with HTTP {resp.status_code}"
                )
        except httpx.RequestError as exc:
            logger.error(
                "Supabase Storage sign network error for object %s/%s: %s",
                target_bucket,
                canonical_path,
                exc.__class__.__name__,
            )
            raise StorageError(
                f"Supabase Storage sign network error: {exc.__class__.__name__}"
            ) from exc

    def download_incident_photo(
        self,
        path: str,
        bucket: Optional[str] = None,
        incident_id: Optional[str] = None,
    ) -> Optional[Tuple[bytes, str]]:
        """
        Downloads an incident photo from Supabase Storage (authenticated).
        Returns (bytes, content_type) tuple on success, or None if not found (404).
        Enforces strict object key validation and cross-incident isolation.
        """
        self._ensure_storage_configured()

        target_bucket = _validate_bucket_name(bucket)
        canonical_path, _, _ = _validate_object_path(
            path, target_bucket, expected_incident_id=incident_id
        )

        endpoint = f"{self._supabase_url}/storage/v1/object/authenticated/{target_bucket}/{canonical_path}"
        headers = self._get_storage_headers()

        try:
            with httpx.Client(timeout=self._timeout_sec) as client:
                resp = client.get(endpoint, headers=headers)
                if resp.status_code == 200:
                    content_type = resp.headers.get(
                        "content-type", "application/octet-stream"
                    )
                    return resp.content, content_type
                if resp.status_code == 404:
                    logger.warning(
                        "Photo not found in Supabase Storage: %s/%s",
                        target_bucket,
                        canonical_path,
                    )
                    return None

                logger.error(
                    "Supabase Storage download failed with HTTP %s for object %s/%s",
                    resp.status_code,
                    target_bucket,
                    canonical_path,
                )
                raise StorageError(
                    f"Supabase Storage download failed with HTTP {resp.status_code}"
                )
        except httpx.RequestError as exc:
            logger.error(
                "Supabase Storage download network error for object %s/%s: %s",
                target_bucket,
                canonical_path,
                exc.__class__.__name__,
            )
            raise StorageError(
                f"Supabase Storage download network error: {exc.__class__.__name__}"
            ) from exc

    async def download_incident_photo_async(
        self,
        path: str,
        bucket: Optional[str] = None,
        incident_id: Optional[str] = None,
    ) -> Optional[Tuple[bytes, str]]:
        """
        Downloads an incident photo from Supabase Storage asynchronously.
        Returns (bytes, content_type) tuple on success, or None if not found (404).
        Enforces strict object key validation and cross-incident isolation.
        """
        self._ensure_storage_configured()

        target_bucket = _validate_bucket_name(bucket)
        canonical_path, _, _ = _validate_object_path(
            path, target_bucket, expected_incident_id=incident_id
        )

        endpoint = f"{self._supabase_url}/storage/v1/object/authenticated/{target_bucket}/{canonical_path}"
        headers = self._get_storage_headers()

        try:
            async with httpx.AsyncClient(timeout=self._timeout_sec) as client:
                resp = await client.get(endpoint, headers=headers)
                if resp.status_code == 200:
                    content_type = resp.headers.get(
                        "content-type", "application/octet-stream"
                    )
                    return resp.content, content_type
                if resp.status_code == 404:
                    logger.warning(
                        "Photo not found in Supabase Storage: %s/%s",
                        target_bucket,
                        canonical_path,
                    )
                    return None

                logger.error(
                    "Supabase Storage download failed with HTTP %s for object %s/%s",
                    resp.status_code,
                    target_bucket,
                    canonical_path,
                )
                raise StorageError(
                    f"Supabase Storage download failed with HTTP {resp.status_code}"
                )
        except httpx.RequestError as exc:
            logger.error(
                "Supabase Storage download network error for object %s/%s: %s",
                target_bucket,
                canonical_path,
                exc.__class__.__name__,
            )
            raise StorageError(
                f"Supabase Storage download network error: {exc.__class__.__name__}"
            ) from exc

    def delete_incident_photo(
        self,
        path: str,
        bucket: Optional[str] = None,
        incident_id: Optional[str] = None,
    ) -> bool:
        """
        Deletes exactly one validated incident photograph from Supabase Storage.
        Enforces strict single-object key validation; guarantees prefixes or neighboring objects are never deleted.
        Returns True if deleted or already absent (404).
        """
        self._ensure_storage_configured()

        target_bucket = _validate_bucket_name(bucket)
        canonical_path, _, _ = _validate_object_path(
            path, target_bucket, expected_incident_id=incident_id
        )

        endpoint = f"{self._supabase_url}/storage/v1/object/{target_bucket}"
        headers = self._get_storage_headers(content_type="application/json")
        payload = {"prefixes": [canonical_path]}

        try:
            with httpx.Client(timeout=self._timeout_sec) as client:
                resp = client.request(
                    "DELETE", endpoint, json=payload, headers=headers
                )
                if resp.status_code in (200, 204, 404):
                    logger.info(
                        "Deleted photo from Supabase Storage: %s/%s",
                        target_bucket,
                        canonical_path,
                    )
                    return True

                logger.error(
                    "Supabase Storage delete failed with HTTP %s for object %s/%s",
                    resp.status_code,
                    target_bucket,
                    canonical_path,
                )
                raise StorageError(
                    f"Supabase Storage delete failed with HTTP {resp.status_code}"
                )
        except httpx.RequestError as exc:
            logger.error(
                "Supabase Storage delete network error for object %s/%s: %s",
                target_bucket,
                canonical_path,
                exc.__class__.__name__,
            )
            raise StorageError(
                f"Supabase Storage delete network error: {exc.__class__.__name__}"
            ) from exc

    async def delete_incident_photo_async(
        self,
        path: str,
        bucket: Optional[str] = None,
        incident_id: Optional[str] = None,
    ) -> bool:
        """
        Deletes exactly one validated incident photograph from Supabase Storage asynchronously.
        Enforces strict single-object key validation; guarantees prefixes or neighboring objects are never deleted.
        Returns True if deleted or already absent (404).
        """
        self._ensure_storage_configured()

        target_bucket = _validate_bucket_name(bucket)
        canonical_path, _, _ = _validate_object_path(
            path, target_bucket, expected_incident_id=incident_id
        )

        endpoint = f"{self._supabase_url}/storage/v1/object/{target_bucket}"
        headers = self._get_storage_headers(content_type="application/json")
        payload = {"prefixes": [canonical_path]}

        try:
            async with httpx.AsyncClient(timeout=self._timeout_sec) as client:
                resp = await client.request(
                    "DELETE", endpoint, json=payload, headers=headers
                )
                if resp.status_code in (200, 204, 404):
                    logger.info(
                        "Deleted photo from Supabase Storage: %s/%s",
                        target_bucket,
                        canonical_path,
                    )
                    return True

                logger.error(
                    "Supabase Storage delete failed with HTTP %s for object %s/%s",
                    resp.status_code,
                    target_bucket,
                    canonical_path,
                )
                raise StorageError(
                    f"Supabase Storage delete failed with HTTP {resp.status_code}"
                )
        except httpx.RequestError as exc:
            logger.error(
                "Supabase Storage delete network error for object %s/%s: %s",
                target_bucket,
                canonical_path,
                exc.__class__.__name__,
            )
            raise StorageError(
                f"Supabase Storage delete network error: {exc.__class__.__name__}"
            ) from exc

    def attach_incident_photos_sync(
        self,
        incident_id: str,
        new_photos: List[str],
        audit_id: str,
        actor_id: str,
        actor_role: str,
    ) -> Dict[str, Any]:
        """
        Invokes public.attach_incident_photos_rpc to atomically attach photo paths
        to an incident and write the corresponding audit record.
        Enforces incident ID, audit ID, actor attribution, and photo path ownership validation.
        """
        self._ensure_storage_configured()

        clean_inc_id = _validate_incident_id(incident_id)
        clean_audit_id = _validate_audit_id(audit_id)
        clean_actor_id, clean_actor_role = _validate_actor(actor_id, actor_role)

        if not isinstance(new_photos, list) or len(new_photos) == 0:
            raise StorageValidationError(
                "At least one photo path must be provided."
            )

        target_bucket = _validate_bucket_name(None)
        validated_photos: List[str] = []
        for p in new_photos:
            c_path, _, _ = _validate_object_path(
                p, target_bucket, expected_incident_id=clean_inc_id
            )
            validated_photos.append(c_path)

        endpoint = (
            f"{self._supabase_url}/rest/v1/rpc/attach_incident_photos_rpc"
        )
        payload = {
            "p_incident_id": clean_inc_id,
            "p_new_photos": validated_photos,
            "p_audit_id": clean_audit_id,
            "p_actor_id": clean_actor_id,
            "p_actor_role": clean_actor_role,
        }

        try:
            with httpx.Client(timeout=self._timeout_sec) as client:
                resp = client.post(
                    endpoint,
                    json=payload,
                    headers=self._get_storage_headers(content_type="application/json"),
                )
                if resp.status_code == 200:
                    try:
                        return resp.json()
                    except ValueError as exc:
                        raise StorageError(
                            "Attach incident photos RPC returned invalid JSON."
                        ) from exc

                try:
                    error_body = resp.json()
                except ValueError:
                    error_body = {}

                error_code = (
                    error_body.get("code")
                    if isinstance(error_body, dict)
                    else None
                )

                if resp.status_code == 404 and error_code == "PGRST202":
                    raise StorageError(
                        "Attach incident photos RPC is unavailable. Check function and schema cache."
                    )

                logger.error(
                    "Supabase attach photos RPC failed with HTTP %s",
                    resp.status_code,
                )
                raise StorageError(
                    f"Attach incident photos RPC failed with HTTP {resp.status_code}"
                )
        except httpx.RequestError as exc:
            logger.error(
                "Attach incident photos RPC network error: %s",
                exc.__class__.__name__,
            )
            raise StorageError(
                f"Attach incident photos RPC network error: {exc.__class__.__name__}"
            ) from exc




    def _call_rpc_sync(self, rpc_name: str, payload: Dict[str, Any]) -> Any:
        self._ensure_storage_configured()
        endpoint = f"{self._supabase_url}/rest/v1/rpc/{rpc_name}"
        headers = self._get_storage_headers(content_type="application/json")
        try:
            with httpx.Client(timeout=self._timeout_sec) as client:
                resp = client.post(endpoint, json=payload, headers=headers)
                if resp.status_code == 200:
                    try:
                        return resp.json()
                    except ValueError as exc:
                        raise StorageError(
                            "Database service returned an invalid response payload.",
                            error_category="INVALID_JSON",
                        ) from exc

                try:
                    error_body = resp.json()
                except ValueError:
                    error_body = {}

                raw_code = (
                    error_body.get("code")
                    if isinstance(error_body, dict)
                    else None
                )
                error_code = str(raw_code).strip() if raw_code else ""

                logger.error(
                    "Database RPC error: rpc=%s http_status=%s sqlstate=%s",
                    rpc_name,
                    resp.status_code,
                    error_code or "UNKNOWN",
                )

                if resp.status_code == 404 and error_code == "PGRST202":
                    raise StorageError(
                        "Database service function is currently unavailable.",
                        sqlstate=error_code,
                        error_category="RPC_UNAVAILABLE",
                    )
                if error_code == "P0412":
                    raise StorageLeaseLostError(
                        "Processing lease is expired or no longer owned.",
                        sqlstate="P0412",
                        error_category="LEASE_LOST",
                    )
                if error_code == "02000":
                    raise StorageNotFoundError(
                        "Requested record was not found.",
                        sqlstate="02000",
                        error_category="NOT_FOUND",
                    )
                if error_code == "42501":
                    raise PermissionError(
                        "Operation is not permitted for the current credentials."
                    )
                if error_code == "23505":
                    raise StorageConflictError(
                        "Operation conflicts with an existing record.",
                        sqlstate="23505",
                        error_category="UNIQUE_VIOLATION",
                    )
                if error_code == "23514":
                    raise StorageConflictError(
                        "Operation conflicts with current record state or constraints.",
                        sqlstate="23514",
                        error_category="CHECK_OR_STATE_CONFLICT",
                    )
                if error_code == "55P03":
                    raise StorageConflictError(
                        "Resource is temporarily locked by another operation.",
                        sqlstate="55P03",
                        error_category="LOCK_CONFLICT",
                    )
                if resp.status_code == 409:
                    raise StorageConflictError(
                        "Operation conflicts with current resource state.",
                        sqlstate=error_code or None,
                        error_category="CONFLICT",
                    )
                if error_code == "22023":
                    raise StorageValidationError(
                        "Request parameters failed validation.",
                        sqlstate="22023",
                        error_category="VALIDATION_ERROR",
                    )
                if error_code in ("23503", "23001"):
                    raise StorageValidationError(
                        "Referenced record does not exist or cannot be modified.",
                        sqlstate=error_code,
                        error_category="FOREIGN_KEY_VIOLATION",
                    )

                raise StorageError(
                    "Database operation failed.",
                    sqlstate=error_code or None,
                    error_category="RPC_ERROR",
                )
        except httpx.RequestError as exc:
            logger.error(
                "Database RPC network error: rpc=%s error_type=%s",
                rpc_name,
                exc.__class__.__name__,
            )
            raise StorageError(
                "Database service is temporarily unreachable.",
                error_category="NETWORK_ERROR",
            ) from exc

    def reserve_photo_attachment_sync(
        self,
        idempotency_key: str,
        scope: str,
        actor_id: str,
        incident_id: str,
        request_fingerprint: str,
        object_paths: List[str],
        lease_owner: str,
        lease_sec: int = 60,
    ) -> Dict[str, Any]:
        self._ensure_storage_configured()
        if not IDEMPOTENCY_KEY_PATTERN.match(idempotency_key):
            raise StorageValidationError(f"Invalid idempotency key format: '{idempotency_key}'")
        clean_inc_id = _validate_incident_id(incident_id)
        clean_actor_id = actor_id.strip()
        if not ACTOR_ID_PATTERN.match(clean_actor_id):
            raise StorageValidationError(f"Invalid actor ID format: '{actor_id}'")
        if not REQUEST_FINGERPRINT_PATTERN.match(request_fingerprint):
            raise StorageValidationError(f"Invalid request fingerprint format: '{request_fingerprint}'")
        if not REQUEST_LEASE_PATTERN.match(lease_owner):
            raise StorageValidationError(f"Invalid lease owner format: '{lease_owner}'")
        if not (15 <= lease_sec <= 300):
            raise StorageValidationError(f"lease_sec must be between 15 and 300, got {lease_sec}")
        if not isinstance(object_paths, list) or len(object_paths) < 1 or len(object_paths) > 3:
            raise StorageValidationError("Between 1 and 3 photo paths required")

        validated_paths = []
        for p in object_paths:
            c_path, _, _ = _validate_canonical_v3_object_path(p, expected_incident_id=clean_inc_id)
            validated_paths.append(c_path)

        payload = {
            "p_idempotency_key": idempotency_key,
            "p_scope": scope,
            "p_actor_id": clean_actor_id,
            "p_incident_id": clean_inc_id,
            "p_request_fingerprint": request_fingerprint,
            "p_object_paths": validated_paths,
            "p_lease_owner": lease_owner,
            "p_lease_sec": lease_sec,
        }
        return self._call_rpc_sync("reserve_photo_attachment_rpc", payload)

    def verify_and_register_storage_object_sync(
        self,
        incident_id: str,
        idempotency_key: str,
        scope: str,
        lease_owner: str,
        object_path: str,
        verified_sha256: str,
        verified_mime: str,
    ) -> Dict[str, Any]:
        self._ensure_storage_configured()
        clean_inc_id = _validate_incident_id(incident_id)
        if not IDEMPOTENCY_KEY_PATTERN.match(idempotency_key):
            raise StorageValidationError(f"Invalid idempotency key format: '{idempotency_key}'")
        if not REQUEST_LEASE_PATTERN.match(lease_owner):
            raise StorageValidationError(f"Invalid lease owner format: '{lease_owner}'")
        c_path, _, _ = _validate_canonical_v3_object_path(object_path, expected_incident_id=clean_inc_id)
        if not re.match(r"^[a-f0-9]{64}$", verified_sha256):
            raise StorageValidationError(f"Invalid SHA-256 digest: '{verified_sha256}'")
        clean_mime = _validate_mime_type(verified_mime, os.path.basename(c_path))

        payload = {
            "p_incident_id": clean_inc_id,
            "p_idempotency_key": idempotency_key,
            "p_scope": scope,
            "p_lease_owner": lease_owner,
            "p_object_path": c_path,
            "p_verified_sha256": verified_sha256,
            "p_verified_mime": clean_mime,
        }
        return self._call_rpc_sync("verify_and_register_storage_object_rpc", payload)

    def finalize_photo_attachment_sync(
        self,
        incident_id: str,
        photos: List[str],
        audit_id: str,
        actor_id: str,
        actor_role: str,
        idempotency_key: str,
        scope: str,
        request_fingerprint: str,
        lease_owner: str,
    ) -> Dict[str, Any]:
        self._ensure_storage_configured()
        clean_inc_id = _validate_incident_id(incident_id)
        clean_audit_id = _validate_audit_id(audit_id)
        clean_actor_id, clean_actor_role = _validate_actor(actor_id, actor_role)
        if not IDEMPOTENCY_KEY_PATTERN.match(idempotency_key):
            raise StorageValidationError(f"Invalid idempotency key format: '{idempotency_key}'")
        if not REQUEST_FINGERPRINT_PATTERN.match(request_fingerprint):
            raise StorageValidationError(f"Invalid request fingerprint: '{request_fingerprint}'")
        if not REQUEST_LEASE_PATTERN.match(lease_owner):
            raise StorageValidationError(f"Invalid lease owner format: '{lease_owner}'")
        if not isinstance(photos, list) or len(photos) < 1 or len(photos) > 3:
            raise StorageValidationError("Between 1 and 3 photos required for finalization")

        validated_photos = []
        for p in photos:
            c_path, _, _ = _validate_canonical_v3_object_path(p, expected_incident_id=clean_inc_id)
            validated_photos.append(c_path)

        payload = {
            "p_incident_id": clean_inc_id,
            "p_photos": validated_photos,
            "p_audit_id": clean_audit_id,
            "p_actor_id": clean_actor_id,
            "p_actor_role": clean_actor_role,
            "p_idempotency_key": idempotency_key,
            "p_scope": scope,
            "p_request_fingerprint": request_fingerprint,
            "p_lease_owner": lease_owner,
        }
        return self._call_rpc_sync("finalize_photo_attachment_rpc", payload)

    def initiate_storage_cleanup_sync(
        self,
        cleanup_id: str,
        incident_id: str,
        idempotency_key: str,
        scope: str,
        lease_owner: str,
        object_paths: List[str],
        lease_sec: int = 60,
    ) -> Dict[str, Any]:
        self._ensure_storage_configured()
        if not CLEANUP_ID_PATTERN.match(cleanup_id):
            raise StorageValidationError(f"Invalid cleanup ID format: '{cleanup_id}'")
        clean_inc_id = _validate_incident_id(incident_id)
        if not IDEMPOTENCY_KEY_PATTERN.match(idempotency_key):
            raise StorageValidationError(f"Invalid idempotency key format: '{idempotency_key}'")
        if not CLEANUP_OR_RECOVERY_LEASE_PATTERN.match(lease_owner):
            raise StorageValidationError(f"Invalid cleanup lease owner format: '{lease_owner}'")
        if not (15 <= lease_sec <= 300):
            raise StorageValidationError(f"lease_sec must be between 15 and 300, got {lease_sec}")

        validated_paths = []
        for p in object_paths:
            c_path, _, _ = _validate_canonical_v3_object_path(p, expected_incident_id=clean_inc_id)
            validated_paths.append(c_path)

        payload = {
            "p_cleanup_id": cleanup_id,
            "p_incident_id": clean_inc_id,
            "p_idempotency_key": idempotency_key,
            "p_scope": scope,
            "p_lease_owner": lease_owner,
            "p_object_paths": validated_paths,
            "p_lease_sec": lease_sec,
        }
        return self._call_rpc_sync("initiate_storage_cleanup_rpc", payload)

    def confirm_storage_cleanup_sync(
        self,
        cleanup_id: str,
        incident_id: str,
        idempotency_key: str,
        scope: str,
        lease_owner: str,
        confirmed_paths: List[str],
    ) -> Dict[str, Any]:
        self._ensure_storage_configured()
        if not CLEANUP_ID_PATTERN.match(cleanup_id):
            raise StorageValidationError(f"Invalid cleanup ID format: '{cleanup_id}'")
        clean_inc_id = _validate_incident_id(incident_id)
        if not IDEMPOTENCY_KEY_PATTERN.match(idempotency_key):
            raise StorageValidationError(f"Invalid idempotency key format: '{idempotency_key}'")
        if not CLEANUP_OR_RECOVERY_LEASE_PATTERN.match(lease_owner):
            raise StorageValidationError(f"Invalid cleanup lease owner format: '{lease_owner}'")
        if not isinstance(confirmed_paths, list) or len(confirmed_paths) == 0 or len(confirmed_paths) > 3:
            raise StorageValidationError("At least one confirmed path (1 to 3) is required for cleanup confirmation.")

        validated_paths = []
        for p in confirmed_paths:
            c_path, _, _ = _validate_canonical_v3_object_path(p, expected_incident_id=clean_inc_id)
            validated_paths.append(c_path)

        payload = {
            "p_cleanup_id": cleanup_id,
            "p_incident_id": clean_inc_id,
            "p_idempotency_key": idempotency_key,
            "p_scope": scope,
            "p_lease_owner": lease_owner,
            "p_confirmed_paths": validated_paths,
        }
        return self._call_rpc_sync("confirm_storage_cleanup_rpc", payload)

    def record_storage_cleanup_uncertain_sync(
        self,
        cleanup_id: str,
        incident_id: str,
        idempotency_key: str,
        scope: str,
        lease_owner: str,
        uncertain_paths: List[str],
        error_detail: str,
    ) -> Dict[str, Any]:
        self._ensure_storage_configured()
        if not CLEANUP_ID_PATTERN.match(cleanup_id):
            raise StorageValidationError(f"Invalid cleanup ID format: '{cleanup_id}'")
        clean_inc_id = _validate_incident_id(incident_id)
        if not IDEMPOTENCY_KEY_PATTERN.match(idempotency_key):
            raise StorageValidationError(f"Invalid idempotency key format: '{idempotency_key}'")
        if not CLEANUP_OR_RECOVERY_LEASE_PATTERN.match(lease_owner):
            raise StorageValidationError(f"Invalid cleanup lease owner format: '{lease_owner}'")
        if not isinstance(uncertain_paths, list) or len(uncertain_paths) == 0:
            raise StorageValidationError("At least one uncertain path required")

        validated_paths = []
        for p in uncertain_paths:
            c_path, _, _ = _validate_canonical_v3_object_path(p, expected_incident_id=clean_inc_id)
            validated_paths.append(c_path)

        payload = {
            "p_cleanup_id": cleanup_id,
            "p_incident_id": clean_inc_id,
            "p_idempotency_key": idempotency_key,
            "p_scope": scope,
            "p_lease_owner": lease_owner,
            "p_uncertain_paths": validated_paths,
            "p_error_detail": error_detail,
        }
        return self._call_rpc_sync("record_storage_cleanup_uncertain_rpc", payload)

    def claim_expired_cleanup_operation_sync(
        self,
        cleanup_id: str,
        incident_id: str,
        idempotency_key: str,
        scope: str,
        recovery_actor_id: str,
        recovery_actor_role: str,
        recovery_lease_owner: str,
        lease_sec: int = 60,
    ) -> Dict[str, Any]:
        self._ensure_storage_configured()
        if not CLEANUP_ID_PATTERN.match(cleanup_id):
            raise StorageValidationError(f"Invalid cleanup ID format: '{cleanup_id}'")
        clean_inc_id = _validate_incident_id(incident_id)
        if not IDEMPOTENCY_KEY_PATTERN.match(idempotency_key):
            raise StorageValidationError(f"Invalid idempotency key format: '{idempotency_key}'")
        clean_actor_id = recovery_actor_id.strip()
        if not ACTOR_ID_PATTERN.match(clean_actor_id):
            raise StorageValidationError(f"Invalid recovery actor ID: '{recovery_actor_id}'")
        if recovery_actor_role not in ("admin", "system"):
            raise StorageValidationError(f"Invalid recovery actor role: '{recovery_actor_role}'. Must be admin or system.")
        if not RECOVERY_LEASE_PATTERN.match(recovery_lease_owner):
            raise StorageValidationError(f"Invalid recovery lease owner format: '{recovery_lease_owner}'")
        if not (15 <= lease_sec <= 300):
            raise StorageValidationError(f"lease_sec must be between 15 and 300, got {lease_sec}")

        payload = {
            "p_cleanup_id": cleanup_id,
            "p_incident_id": clean_inc_id,
            "p_idempotency_key": idempotency_key,
            "p_scope": scope,
            "p_recovery_actor_id": clean_actor_id,
            "p_recovery_actor_role": recovery_actor_role,
            "p_recovery_lease_owner": recovery_lease_owner,
            "p_lease_sec": lease_sec,
        }
        return self._call_rpc_sync("claim_expired_cleanup_operation_rpc", payload)

    def reconcile_storage_orphan_sync(
        self,
        cleanup_id: str,
        incident_id: str,
        idempotency_key: str,
        scope: str,
        object_path: str,
        recovery_actor_id: str,
        recovery_actor_role: str,
        recovery_lease_owner: str,
    ) -> Dict[str, Any]:
        self._ensure_storage_configured()
        if not CLEANUP_ID_PATTERN.match(cleanup_id):
            raise StorageValidationError(f"Invalid cleanup ID format: '{cleanup_id}'")
        clean_inc_id = _validate_incident_id(incident_id)
        if not IDEMPOTENCY_KEY_PATTERN.match(idempotency_key):
            raise StorageValidationError(f"Invalid idempotency key format: '{idempotency_key}'")
        c_path, _, _ = _validate_canonical_v3_object_path(object_path, expected_incident_id=clean_inc_id)
        clean_actor_id = recovery_actor_id.strip()
        if not ACTOR_ID_PATTERN.match(clean_actor_id):
            raise StorageValidationError(f"Invalid recovery actor ID: '{recovery_actor_id}'")
        if recovery_actor_role not in ("admin", "system"):
            raise StorageValidationError(f"Invalid recovery actor role: '{recovery_actor_role}'. Must be admin or system.")
        if not RECOVERY_LEASE_PATTERN.match(recovery_lease_owner):
            raise StorageValidationError(f"Invalid recovery lease owner format: '{recovery_lease_owner}'")

        payload = {
            "p_cleanup_id": cleanup_id,
            "p_incident_id": clean_inc_id,
            "p_idempotency_key": idempotency_key,
            "p_scope": scope,
            "p_object_path": c_path,
            "p_recovery_actor_id": clean_actor_id,
            "p_recovery_actor_role": recovery_actor_role,
            "p_recovery_lease_owner": recovery_lease_owner,
        }
        return self._call_rpc_sync("reconcile_storage_orphan_rpc", payload)

    def renew_or_takeover_lease_sync(
        self,
        idempotency_key: str,
        scope: str,
        incident_id: str,
        actor_id: str,
        request_fingerprint: str,
        incoming_lease_owner: str,
        lease_sec: int = 60,
    ) -> Dict[str, Any]:
        self._ensure_storage_configured()
        if not IDEMPOTENCY_KEY_PATTERN.match(idempotency_key):
            raise StorageValidationError(f"Invalid idempotency key format: '{idempotency_key}'")
        clean_inc_id = _validate_incident_id(incident_id)
        clean_actor_id = actor_id.strip()
        if not ACTOR_ID_PATTERN.match(clean_actor_id):
            raise StorageValidationError(f"Invalid actor ID: '{actor_id}'")
        if not REQUEST_FINGERPRINT_PATTERN.match(request_fingerprint):
            raise StorageValidationError(f"Invalid request fingerprint: '{request_fingerprint}'")
        if not REQUEST_LEASE_PATTERN.match(incoming_lease_owner):
            raise StorageValidationError(f"Invalid incoming lease owner format: '{incoming_lease_owner}'")
        if not (15 <= lease_sec <= 300):
            raise StorageValidationError(f"lease_sec must be between 15 and 300, got {lease_sec}")

        payload = {
            "p_idempotency_key": idempotency_key,
            "p_scope": scope,
            "p_incident_id": clean_inc_id,
            "p_actor_id": clean_actor_id,
            "p_request_fingerprint": request_fingerprint,
            "p_incoming_lease_owner": incoming_lease_owner,
            "p_lease_sec": lease_sec,
        }
        return self._call_rpc_sync("renew_or_takeover_lease_rpc", payload)

    def execute_photo_attachment_workflow_sync(
        self,
        incident_id: str,
        files: List[Tuple[str, bytes, str]],
        idempotency_key: str,
        actor_id: str,
        actor_role: str,
        audit_id: str,
        scope: str = "incident_attachment",
        lease_sec: Optional[int] = None,
        cleanup_lease_sec: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Executes complete Milestone 2 V3.1 photo upload orchestration:
        1. Validates inputs and uniqueness of content digests within the request.
        2. Computes canonical paths and deterministic request fingerprint.
        3. Calls reserve_photo_attachment_rpc using configured upload_lease_sec default.
        4. Uploads each photo with x-upsert: false; on HTTP 409 conflict, reads back, re-verifies MIME & SHA-256 digest.
        5. Registers verified object via verify_and_register_storage_object_rpc.
        6. Finalizes attachment via finalize_photo_attachment_rpc.
        7. On finalization timeout/lost response, initiates compensating cleanup (using cleanup_lease_sec default)
           and returns ALREADY_COMPLETED if finalization succeeded.
        8. On failure before finalization, cleans up newly uploaded unshared objects without deleting shared objects.
        """
        self._ensure_storage_configured()
        clean_inc_id = _validate_incident_id(incident_id)
        clean_audit_id = _validate_audit_id(audit_id)
        clean_actor_id, clean_actor_role = _validate_actor(actor_id, actor_role)

        effective_upload_lease_sec = (
            lease_sec if lease_sec is not None else self.upload_lease_sec
        )
        effective_cleanup_lease_sec = (
            cleanup_lease_sec if cleanup_lease_sec is not None else self.cleanup_lease_sec
        )

        if not isinstance(files, list) or len(files) == 0:
            raise StorageValidationError("At least one photo file must be provided.")
        if len(files) > 3:
            raise StorageValidationError("At most 3 photo files may be uploaded per request.")

        # Process digests and validate within-request uniqueness
        prepared = []
        digests_seen = set()
        for filename, file_bytes, content_type in files:
            clean_mime = _validate_mime_type(content_type, filename)
            digest = hashlib.sha256(file_bytes).hexdigest()
            if digest in digests_seen:
                raise StorageValidationError(f"Duplicate image content detected within request for {filename}.")
            digests_seen.add(digest)
            ext = os.path.splitext(filename)[1].lower()
            if not ext:
                ext = ".jpg" if clean_mime == "image/jpeg" else (".png" if clean_mime == "image/png" else ".webp")
            canonical_filename = f"sha256_{digest}{ext}"
            canonical_path = f"{clean_inc_id}/{canonical_filename}"
            prepared.append({
                "canonical_path": canonical_path,
                "canonical_filename": canonical_filename,
                "bytes": file_bytes,
                "mime": clean_mime,
                "digest": digest,
            })

        # Sort paths canonically
        prepared.sort(key=lambda x: x["canonical_path"])
        sorted_paths = [p["canonical_path"] for p in prepared]

        # Fingerprint
        fp_parts = [clean_actor_id.encode(), clean_inc_id.encode()] + [p.encode() for p in sorted_paths]
        request_fingerprint = hashlib.sha256(b":".join(fp_parts)).hexdigest()
        lease_owner = f"req_lease_{uuid.uuid4().hex}"

        # Level 1-3 Reservation
        reservation = self.reserve_photo_attachment_sync(
            idempotency_key=idempotency_key,
            scope=scope,
            actor_id=clean_actor_id,
            incident_id=clean_inc_id,
            request_fingerprint=request_fingerprint,
            object_paths=sorted_paths,
            lease_owner=lease_owner,
            lease_sec=effective_upload_lease_sec,
        )

        res_status = reservation.get("status")
        if res_status == "COMPLETED":
            logger.info("Idempotent replay of completed upload for key %s", idempotency_key)
            return reservation.get("response") or {}
        if res_status == "ACTIVE_LOCK":
            raise StorageConflictError("An upload operation is already in progress under this idempotency key.")
        if res_status == "CLEANUP_IN_FLIGHT":
            raise StorageConflictError("Cleanup is currently in progress for this idempotency key. Please retry shortly.")
        if res_status != "RESERVED":
            raise StorageError(f"Unexpected reservation status from database: {res_status}")

        uploaded_in_this_session = []
        try:
            for item in prepared:
                c_path = item["canonical_path"]
                c_bytes = item["bytes"]
                c_mime = item["mime"]
                c_digest = item["digest"]

                try:
                    self.upload_incident_photo_sync(
                        incident_id=clean_inc_id,
                        photo_id=item["canonical_filename"],
                        file_bytes=c_bytes,
                        content_type=c_mime,
                    )
                    uploaded_in_this_session.append(c_path)
                except StorageConflictError:
                    # Object already exists in Storage: read back and verify BOTH MIME and SHA-256 digest
                    downloaded = self.download_incident_photo(c_path, incident_id=clean_inc_id)
                    if not downloaded:
                        raise StorageError(f"Object {c_path} conflicted on upload but could not be downloaded for verification.")
                    dl_bytes, dl_mime = downloaded
                    try:
                        clean_dl_mime = _validate_mime_type(dl_mime, item["canonical_filename"])
                    except StorageValidationError as mime_exc:
                        raise StorageError(
                            f"Existing storage object {c_path} failed MIME verification: {str(mime_exc)}"
                        ) from mime_exc
                    if clean_dl_mime != c_mime:
                        raise StorageError(
                            f"Existing storage object {c_path} MIME '{clean_dl_mime}' does not match expected MIME '{c_mime}'."
                        )
                    dl_digest = hashlib.sha256(dl_bytes).hexdigest()
                    if dl_digest != c_digest:
                        raise StorageError(f"Existing storage object {c_path} failed SHA-256 verification against uploaded payload.")

                # Register object in registry
                self.verify_and_register_storage_object_sync(
                    incident_id=clean_inc_id,
                    idempotency_key=idempotency_key,
                    scope=scope,
                    lease_owner=lease_owner,
                    object_path=c_path,
                    verified_sha256=c_digest,
                    verified_mime=c_mime,
                )

            # Finalize attachment
            try:
                final_result = self.finalize_photo_attachment_sync(
                    incident_id=clean_inc_id,
                    photos=sorted_paths,
                    audit_id=clean_audit_id,
                    actor_id=clean_actor_id,
                    actor_role=clean_actor_role,
                    idempotency_key=idempotency_key,
                    scope=scope,
                    request_fingerprint=request_fingerprint,
                    lease_owner=lease_owner,
                )
                return final_result
            except Exception as final_exc:
                logger.warning(
                    "Finalization encountered error/timeout (%s). Initiating compensating check.",
                    final_exc.__class__.__name__,
                )
                cleanup_id = f"clean_{uuid.uuid4().hex}"
                cleanup_res = self.initiate_storage_cleanup_sync(
                    cleanup_id=cleanup_id,
                    incident_id=clean_inc_id,
                    idempotency_key=idempotency_key,
                    scope=scope,
                    lease_owner=lease_owner,
                    object_paths=sorted_paths,
                    lease_sec=effective_cleanup_lease_sec,
                )
                if cleanup_res.get("status") == "ALREADY_COMPLETED":
                    logger.info("Compensating check found finalization actually completed successfully.")
                    return cleanup_res.get("response") or {}

                # Not completed: proceed with cleanup of authorized paths
                self._execute_cleanup_deletion(
                    cleanup_id=cleanup_id,
                    incident_id=clean_inc_id,
                    idempotency_key=idempotency_key,
                    scope=scope,
                    lease_owner=lease_owner,
                    cleanup_res=cleanup_res,
                )
                raise final_exc

        except Exception as exc:
            # Failure prior to finalization: initiate cleanup
            cleanup_id = f"clean_{uuid.uuid4().hex}"
            try:
                cleanup_res = self.initiate_storage_cleanup_sync(
                    cleanup_id=cleanup_id,
                    incident_id=clean_inc_id,
                    idempotency_key=idempotency_key,
                    scope=scope,
                    lease_owner=lease_owner,
                    object_paths=sorted_paths,
                    lease_sec=effective_cleanup_lease_sec,
                )
                if cleanup_res.get("status") == "ALREADY_COMPLETED":
                    return cleanup_res.get("response") or {}
                self._execute_cleanup_deletion(
                    cleanup_id=cleanup_id,
                    incident_id=clean_inc_id,
                    idempotency_key=idempotency_key,
                    scope=scope,
                    lease_owner=lease_owner,
                    cleanup_res=cleanup_res,
                )
            except Exception as clean_exc:
                logger.error("Failed to execute cleanup after upload error: %s", clean_exc)
            raise exc

    def _execute_cleanup_deletion(
        self,
        cleanup_id: str,
        incident_id: str,
        idempotency_key: str,
        scope: str,
        lease_owner: str,
        cleanup_res: Dict[str, Any],
    ) -> None:
        delete_authorized = cleanup_res.get("delete_authorized_paths", []) or []
        confirmed = []
        uncertain = []
        last_error = "Unknown deletion error"
        for p in delete_authorized:
            try:
                self.delete_incident_photo(p, incident_id=incident_id)
                confirmed.append(p)
            except Exception as e:
                uncertain.append(p)
                last_error = f"{e.__class__.__name__}: {str(e)}"

        if confirmed:
            try:
                self.confirm_storage_cleanup_sync(
                    cleanup_id=cleanup_id,
                    incident_id=incident_id,
                    idempotency_key=idempotency_key,
                    scope=scope,
                    lease_owner=lease_owner,
                    confirmed_paths=confirmed,
                )
            except Exception as conf_exc:
                logger.error("Failed to confirm cleanup paths: %s", conf_exc)

        if uncertain:
            try:
                self.record_storage_cleanup_uncertain_sync(
                    cleanup_id=cleanup_id,
                    incident_id=incident_id,
                    idempotency_key=idempotency_key,
                    scope=scope,
                    lease_owner=lease_owner,
                    uncertain_paths=uncertain,
                    error_detail=last_error,
                )
            except Exception as rec_exc:
                logger.error("Failed to record uncertain cleanup paths: %s", rec_exc)

    def execute_cleanup_recovery_workflow_sync(
        self,
        cleanup_id: str,
        incident_id: str,
        idempotency_key: str,
        scope: str,
        recovery_actor_id: str,
        recovery_actor_role: str,
        lease_sec: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Executes recovery workflow for expired cleanup operations:
        1. Validates caller is admin or system.
        2. Claims expired cleanup lease via claim_expired_cleanup_operation_rpc.
        3. Deletes remaining authorized orphan objects from Storage, handling errors per object.
        4. Reconciles each confirmed deleted object via reconcile_storage_orphan_rpc.
        5. Records uncertain deletions via record_storage_cleanup_uncertain_rpc if any delete failed.
        """
        self._ensure_storage_configured()
        clean_inc_id = _validate_incident_id(incident_id)
        if recovery_actor_role not in ("admin", "system"):
            raise StorageValidationError(f"Recovery role must be admin or system, got: {recovery_actor_role}")
        effective_lease_sec = (
            lease_sec if lease_sec is not None else self.cleanup_lease_sec
        )
        recovery_lease_owner = f"rec_lease_{uuid.uuid4().hex}"

        claim_res = self.claim_expired_cleanup_operation_sync(
            cleanup_id=cleanup_id,
            incident_id=clean_inc_id,
            idempotency_key=idempotency_key,
            scope=scope,
            recovery_actor_id=recovery_actor_id,
            recovery_actor_role=recovery_actor_role,
            recovery_lease_owner=recovery_lease_owner,
            lease_sec=effective_lease_sec,
        )

        status = claim_res.get("status")
        if status == "CLEANUP_ALREADY_CONFIRMED":
            return claim_res

        if status != "CLEANUP_RECOVERY_CLAIMED":
            raise StorageError(f"Unexpected status from claim_expired_cleanup_operation: {status}")

        remaining_paths = claim_res.get("remaining_paths", []) or []
        reconciled = []
        uncertain_paths = []
        last_error = "Storage deletion failed during recovery"

        for p in remaining_paths:
            try:
                self.delete_incident_photo(p, incident_id=clean_inc_id)
            except Exception as del_exc:
                uncertain_paths.append(p)
                last_error = f"{del_exc.__class__.__name__}: {str(del_exc)}"
                logger.warning(
                    "Recovery storage deletion failed for %s (%s); recording uncertain and continuing.",
                    p,
                    last_error,
                )
                continue

            rec_res = self.reconcile_storage_orphan_sync(
                cleanup_id=cleanup_id,
                incident_id=clean_inc_id,
                idempotency_key=idempotency_key,
                scope=scope,
                object_path=p,
                recovery_actor_id=recovery_actor_id,
                recovery_actor_role=recovery_actor_role,
                recovery_lease_owner=recovery_lease_owner,
            )
            reconciled.append(rec_res)

        if uncertain_paths:
            self.record_storage_cleanup_uncertain_sync(
                cleanup_id=cleanup_id,
                incident_id=clean_inc_id,
                idempotency_key=idempotency_key,
                scope=scope,
                lease_owner=recovery_lease_owner,
                uncertain_paths=uncertain_paths,
                error_detail=last_error,
            )

        final_status = (
            "CLEANUP_RECOVERY_PARTIAL_UNCERTAIN"
            if uncertain_paths
            else "CLEANUP_RECOVERY_COMPLETED"
        )
        return {
            "status": final_status,
            "cleanup_id": cleanup_id,
            "reconciled_count": len(reconciled),
            "reconciled_objects": reconciled,
            "uncertain_paths": uncertain_paths,
        }

    def query_expired_cleanup_operations_sync(
        self,
        limit: int = 10,
        exclude_cleanup_ids: Optional[Sequence[str]] = None,
    ) -> List[Dict[str, str]]:
        """
        Read-only discovery of storage cleanup operations whose lease has expired and which are
        not yet terminal (status PENDING / PARTIAL / UNCERTAIN), oldest lease expiry first.

        This is a DISCOVERY helper only. It never deletes anything and never decides which
        objects may be deleted: every returned operation must still be claimed through
        `execute_cleanup_recovery_workflow_sync`, whose claim RPC re-validates lease expiry,
        idempotency-key state and registry reference counts under row locks on the database
        clock. The local-clock cutoff used here can therefore only affect WHEN an operation
        is noticed, never whether an object is deleted.

        Returns a list of dicts with keys cleanup_id, incident_id, idempotency_key, scope.
        Rows failing identifier validation are skipped. At most 100 rows are returned.
        """
        self._ensure_storage_configured()
        if not isinstance(limit, int) or isinstance(limit, bool) or not (1 <= limit <= 100):
            raise StorageValidationError("limit must be an integer between 1 and 100.")

        excluded: List[str] = []
        for cid in list(exclude_cleanup_ids or [])[:30]:
            if not isinstance(cid, str) or not CLEANUP_ID_PATTERN.match(cid):
                raise StorageValidationError("Invalid excluded cleanup ID format.")
            excluded.append(cid)

        cutoff = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        params: List[Tuple[str, str]] = [
            ("select", "cleanup_id,incident_id,idempotency_key,scope"),
            ("status", "in.(PENDING,PARTIAL,UNCERTAIN)"),
            ("expires_at", f"lt.{cutoff}"),
            ("order", "expires_at.asc,cleanup_id.asc"),
            ("limit", str(limit)),
        ]
        if excluded:
            params.append(("cleanup_id", f"not.in.({','.join(excluded)})"))

        endpoint = f"{self._supabase_url}/rest/v1/storage_cleanup_operations"
        headers = self._get_storage_headers(content_type="application/json")
        try:
            with httpx.Client(timeout=self._timeout_sec) as client:
                resp = client.get(endpoint, headers=headers, params=params)
        except httpx.RequestError as exc:
            raise StorageError(
                f"Expired cleanup discovery network error: {exc.__class__.__name__}"
            ) from exc

        if resp.status_code in (401, 403):
            raise StorageError(
                f"Expired cleanup discovery unauthorized: HTTP {resp.status_code}",
                error_category="AUTH_ERROR",
            )
        if resp.status_code != 200:
            raise StorageError(
                f"Expired cleanup discovery failed: HTTP {resp.status_code}"
            )
        try:
            rows = resp.json()
        except ValueError as exc:
            raise StorageError("Expired cleanup discovery returned invalid JSON.") from exc
        if not isinstance(rows, list):
            raise StorageError("Expired cleanup discovery returned invalid JSON shape.")

        result: List[Dict[str, str]] = []
        skipped = 0
        for row in rows[:limit]:
            if not isinstance(row, dict):
                skipped += 1
                continue
            cid = row.get("cleanup_id")
            inc = row.get("incident_id")
            key = row.get("idempotency_key")
            scope = row.get("scope")
            if (
                isinstance(cid, str) and CLEANUP_ID_PATTERN.match(cid)
                and isinstance(inc, str) and INCIDENT_ID_PATTERN.match(inc)
                and isinstance(key, str) and IDEMPOTENCY_KEY_PATTERN.match(key)
                and isinstance(scope, str) and re.match(r"^[A-Za-z0-9_.:-]{1,64}$", scope)
            ):
                result.append(
                    {
                        "cleanup_id": cid,
                        "incident_id": inc,
                        "idempotency_key": key,
                        "scope": scope,
                    }
                )
            else:
                skipped += 1
        if skipped:
            logger.warning(
                "Expired cleanup discovery skipped %d row(s) with invalid identifiers.", skipped
            )
        return result

    def check_and_increment_rate_limit_sync(
        self, key_hash: str, action: str, limit: int, window_sec: int
    ) -> Dict[str, Any]:
        """
        Executes atomic database rate limiting via RPC `check_and_increment_rate_limit_rpc`.
        Validates all RPC arguments prior to invoking PostgREST and requires service-role credentials.
        Returns dict containing:
            {
                "allowed": bool,
                "current_count": int,
                "limit": int,
                "remaining": int,
                "reset_after_sec": int,
                "retry_after_sec": int
            }
        Raises StorageValidationError on invalid arguments, or StorageError /
        StorageNotConfiguredError on connection failure/timeout.
        """
        self._ensure_storage_configured()
        if not isinstance(key_hash, str) or not REQUEST_FINGERPRINT_PATTERN.match(key_hash):
            raise StorageValidationError(
                "Invalid rate limit key hash: must be 64 lowercase hexadecimal characters."
            )
        clean_action = action.value if hasattr(action, "value") else action
        if not isinstance(clean_action, str) or clean_action not in (
            "incident_create",
            "photo_upload",
            "photo_retrieve",
        ):
            raise StorageValidationError("Invalid rate limit action.")
        if not isinstance(limit, int) or isinstance(limit, bool) or not (1 <= limit <= 100_000):
            raise StorageValidationError("Invalid rate limit max requests: must be between 1 and 100000.")
        if not isinstance(window_sec, int) or isinstance(window_sec, bool) or not (1 <= window_sec <= 2_592_000):
            raise StorageValidationError("Invalid rate limit window seconds: must be between 1 and 2592000.")

        payload = {
            "p_key_hash": key_hash,
            "p_action": clean_action,
            "p_limit": limit,
            "p_window_sec": window_sec,
        }
        return self._call_rpc_sync("check_and_increment_rate_limit_rpc", payload)

    def claim_duplicate_scan_jobs_sync(
        self,
        lease_owner: str,
        incident_id: Optional[str] = None,
        batch_size: int = 10,
        lease_sec: int = 60,
    ) -> List[Dict[str, Any]]:
        self._ensure_storage_configured()
        if not isinstance(lease_owner, str) or not DUP_LEASE_PATTERN.match(lease_owner.strip()):
            raise StorageValidationError(
                "lease_owner must match 'dup_lease_<32 lowercase hex characters>'."
            )
        if not isinstance(batch_size, int) or isinstance(batch_size, bool) or not (1 <= batch_size <= 100):
            raise StorageValidationError("batch_size must be an integer between 1 and 100.")
        if not isinstance(lease_sec, int) or isinstance(lease_sec, bool) or not (5 <= lease_sec <= 3600):
            raise StorageValidationError("lease_sec must be an integer between 5 and 3600.")
        clean_inc_id = _validate_incident_id(incident_id) if incident_id is not None else None

        payload = {
            "p_lease_owner": lease_owner.strip(),
            "p_incident_id": clean_inc_id,
            "p_batch_size": batch_size,
            "p_lease_sec": lease_sec,
        }
        res = self._call_rpc_sync("claim_duplicate_scan_jobs_rpc", payload)
        return res if isinstance(res, list) else []

    def fetch_duplicate_candidates_sync(
        self,
        incident_id: str,
        max_radius_m: float = 150.0,
        time_window_sec: int = 21600,
        allowed_categories: Optional[List[str]] = None,
        include_resolved: bool = False,
        match_citizen_physical_sensor: bool = True,
        limit: int = 200,
    ) -> Dict[str, Any]:
        self._ensure_storage_configured()
        clean_inc_id = _validate_incident_id(incident_id)
        if (
            not isinstance(max_radius_m, (int, float))
            or isinstance(max_radius_m, bool)
            or not (0.0 < float(max_radius_m) <= 10000.0)
        ):
            raise StorageValidationError("max_radius_m must be between 0 and 10000 meters.")
        if (
            not isinstance(time_window_sec, int)
            or isinstance(time_window_sec, bool)
            or not (60 <= time_window_sec <= 2_592_000)
        ):
            raise StorageValidationError("time_window_sec must be an integer between 60 and 2592000.")
        if not isinstance(limit, int) or isinstance(limit, bool) or not (1 <= limit <= 200):
            raise StorageValidationError("limit must be an integer between 1 and 200.")

        payload = {
            "p_incident_id": clean_inc_id,
            "p_max_radius_m": float(max_radius_m),
            "p_time_window_sec": time_window_sec,
            "p_allowed_categories": list(allowed_categories) if allowed_categories else [],
            "p_include_resolved": bool(include_resolved),
            "p_match_citizen_physical_sensor": bool(match_citizen_physical_sensor),
            "p_limit": limit,
        }
        res = self._call_rpc_sync("fetch_duplicate_candidates_rpc", payload)
        if not isinstance(res, dict):
            raise StorageError("fetch_duplicate_candidates_rpc returned invalid JSON shape.")
        return {
            "source_incident": res.get("source_incident"),
            "candidates": res.get("candidates") if isinstance(res.get("candidates"), list) else [],
        }

    def record_duplicate_candidates_sync(
        self,
        incident_id: str,
        detected_in_mode: str,
        candidates: List[Dict[str, Any]],
        lease_owner: str,
    ) -> Dict[str, Any]:
        self._ensure_storage_configured()
        clean_inc_id = _validate_incident_id(incident_id)
        clean_mode = (detected_in_mode or "").strip().upper()
        if clean_mode not in ALLOWED_OPERATIONAL_MODES:
            raise StorageValidationError(
                "detected_in_mode must be 'SIMULATION', 'PHYSICAL', or 'SAFE_HOLD'."
            )
        if not isinstance(lease_owner, str) or not DUP_LEASE_PATTERN.match(lease_owner.strip()):
            raise StorageValidationError(
                "lease_owner must match 'dup_lease_<32 lowercase hex characters>'."
            )
        if not isinstance(candidates, list):
            raise StorageValidationError("candidates must be a list.")

        payload = {
            "p_incident_id": clean_inc_id,
            "p_detected_in_mode": clean_mode,
            "p_candidates": candidates,
            "p_lease_owner": lease_owner.strip(),
        }
        res = self._call_rpc_sync("record_duplicate_candidates_rpc", payload)
        if not isinstance(res, dict):
            raise StorageError("record_duplicate_candidates_rpc returned invalid JSON shape.")
        return res

    def release_duplicate_scan_job_sync(
        self,
        incident_id: str,
        lease_owner: str,
        error_code: str,
        backoff_sec: Optional[int] = None,
        permanent: bool = False,
    ) -> Dict[str, Any]:
        self._ensure_storage_configured()
        clean_inc_id = _validate_incident_id(incident_id)
        if not isinstance(lease_owner, str) or not DUP_LEASE_PATTERN.match(lease_owner.strip()):
            raise StorageValidationError(
                "lease_owner must match 'dup_lease_<32 lowercase hex characters>'."
            )
        if not isinstance(error_code, str) or not error_code.strip():
            raise StorageValidationError("error_code must be a non-empty string.")
        if backoff_sec is not None and (
            not isinstance(backoff_sec, int)
            or isinstance(backoff_sec, bool)
            or not (1 <= backoff_sec <= 86400)
        ):
            raise StorageValidationError("backoff_sec must be between 1 and 86400 seconds.")

        payload = {
            "p_incident_id": clean_inc_id,
            "p_lease_owner": lease_owner.strip(),
            "p_error_code": error_code.strip()[:64],
            "p_backoff_sec": backoff_sec,
            "p_permanent": bool(permanent),
        }
        res = self._call_rpc_sync("release_duplicate_scan_job_rpc", payload)
        if not isinstance(res, dict):
            raise StorageError("release_duplicate_scan_job_rpc returned invalid JSON shape.")
        return res

    def reset_duplicate_scan_job_sync(
        self,
        incident_id: str,
        actor_id: str,
        actor_role: str,
        reason: str = "Manual duplicate scan job reset",
    ) -> Dict[str, Any]:
        self._ensure_storage_configured()
        clean_inc_id = _validate_incident_id(incident_id)
        if not isinstance(actor_id, str) or not actor_id.strip():
            raise StorageValidationError("actor_id must be a non-empty string.")
        clean_role = actor_role.strip().lower() if isinstance(actor_role, str) else ""
        if clean_role not in ALLOWED_DUPLICATE_REVIEW_ROLES:
            raise StorageValidationError(
                "actor_role must be 'municipality', 'admin', or 'service_role'."
            )

        payload = {
            "p_incident_id": clean_inc_id,
            "p_actor_id": actor_id.strip()[:128],
            "p_actor_role": clean_role,
            "p_reason": reason.strip()[:500] if isinstance(reason, str) and reason.strip() else "Manual duplicate scan job reset",
        }
        res = self._call_rpc_sync("reset_duplicate_scan_job_rpc", payload)
        if not isinstance(res, dict):
            raise StorageError("reset_duplicate_scan_job_rpc returned invalid JSON shape.")
        return res

    def review_incident_duplicate_link_sync(
        self,
        link_id: str,
        target_status: str,
        actor_id: str,
        actor_role: str,
        reason: str,
        audit_id_low: str,
        audit_id_high: str,
        primary_incident_id: Optional[str] = None,
        internal_notes: Optional[str] = None,
        override: bool = False,
        expected_version: Optional[int] = None,
    ) -> Dict[str, Any]:
        self._ensure_storage_configured()
        if not isinstance(link_id, str) or not DUP_LINK_ID_PATTERN.match(link_id.strip()):
            raise StorageValidationError("link_id must be 5-32 alphanumeric/underscore/hyphen characters.")
        clean_status = target_status.strip().upper() if isinstance(target_status, str) else ""
        if clean_status not in ("CONFIRMED", "DISMISSED"):
            raise StorageValidationError("target_status must be 'CONFIRMED' or 'DISMISSED'.")
        if not isinstance(actor_id, str) or not actor_id.strip():
            raise StorageValidationError("actor_id must be a non-empty string.")
        clean_role = actor_role.strip().lower() if isinstance(actor_role, str) else ""
        if clean_role not in ALLOWED_DUPLICATE_REVIEW_ROLES:
            raise StorageValidationError(
                "actor_role must be 'municipality', 'admin', or 'service_role' for duplicate review."
            )
        clean_reason = reason.strip() if isinstance(reason, str) else ""
        if len(clean_reason) < 3 or len(clean_reason) > 500:
            raise StorageValidationError("reason must be between 3 and 500 characters.")
        clean_audit_low = _validate_audit_id(audit_id_low)
        clean_audit_high = _validate_audit_id(audit_id_high)
        if clean_audit_low == clean_audit_high:
            raise StorageValidationError("audit_id_low and audit_id_high must be distinct.")
        clean_primary = (
            _validate_incident_id(primary_incident_id)
            if primary_incident_id is not None
            else None
        )
        if clean_status == "CONFIRMED" and not clean_primary:
            raise StorageValidationError("primary_incident_id is required when target_status is 'CONFIRMED'.")
        if expected_version is not None and (
            not isinstance(expected_version, int)
            or isinstance(expected_version, bool)
            or expected_version < 0
        ):
            raise StorageValidationError("expected_version must be a non-negative integer.")

        payload = {
            "p_link_id": link_id.strip(),
            "p_target_status": clean_status,
            "p_actor_id": actor_id.strip()[:128],
            "p_actor_role": clean_role,
            "p_reason": clean_reason,
            "p_audit_id_low": clean_audit_low,
            "p_audit_id_high": clean_audit_high,
            "p_primary_incident_id": clean_primary,
            "p_internal_notes": internal_notes.strip()[:1000] if isinstance(internal_notes, str) and internal_notes.strip() else None,
            "p_override": bool(override),
            "p_expected_version": expected_version,
        }
        res = self._call_rpc_sync("review_incident_duplicate_link_rpc", payload)
        if not isinstance(res, dict):
            raise StorageError("review_incident_duplicate_link_rpc returned invalid JSON shape.")
        return res

    def query_duplicate_links_sync(
        self,
        link_status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        Queries a deterministically ordered page (`created_at.desc,link_id.asc`) of duplicate
        links from PostgREST with `Prefer: count=exact`.

        HTTP 416 contract:
        - If Content-Range provides an exact total `N` and `offset >= N` (valid out-of-range page
          or empty dataset `*/0`), returns `([], N)`.
        - If Content-Range lacks an exact total or `offset < N` (malformed or invalid range error),
          raises StorageError instead of silently converting a failure into an empty result.
        """
        self._ensure_storage_configured()
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1 or limit > 100:
            raise StorageValidationError("limit must be an integer between 1 and 100.")
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise StorageValidationError("offset must be a non-negative integer.")

        endpoint = f"{self._supabase_url}/rest/v1/incident_duplicate_links"
        headers = self._get_storage_headers(content_type="application/json")
        headers["Prefer"] = "count=exact"
        headers["Range-Unit"] = "items"
        headers["Range"] = f"{offset}-{offset + limit - 1}"

        params: Dict[str, str] = {
            "select": "*",
            "order": "created_at.desc,link_id.asc",
        }
        if link_status is not None:
            clean_status = link_status.strip().upper()
            if clean_status not in ALLOWED_DUPLICATE_LINK_STATUSES:
                raise StorageValidationError(
                    "link_status must be 'SUSPECTED', 'CONFIRMED', or 'DISMISSED'."
                )
            params["link_status"] = f"eq.{clean_status}"

        try:
            with httpx.Client(timeout=self._timeout_sec) as client:
                resp = client.get(endpoint, headers=headers, params=params)
                if resp.status_code in (200, 206):
                    items = resp.json()
                    if not isinstance(items, list):
                        raise StorageError("Duplicate links query returned invalid JSON shape.")
                    exact_total = _parse_postgrest_content_range_total(resp.headers.get("Content-Range"))
                    if exact_total is not None:
                        return items, exact_total
                    if offset == 0 and len(items) < limit:
                        return items, len(items)
                    raise StorageError(
                        "Duplicate links query missing exact Content-Range total.",
                        error_category="RANGE_ERROR",
                    )
                if resp.status_code == 416:
                    exact_total = _parse_postgrest_content_range_total(resp.headers.get("Content-Range"))
                    if exact_total is None:
                        raise StorageError(
                            "Duplicate links query failed with HTTP 416 and missing exact Content-Range total.",
                            error_category="RANGE_ERROR",
                        )
                    if offset < exact_total:
                        raise StorageError(
                            "Duplicate links query rejected in-bounds range with HTTP 416.",
                            error_category="RANGE_ERROR",
                        )
                    return [], exact_total
                if resp.status_code == 400:
                    raise StorageValidationError(
                        "Duplicate links query rejected with HTTP 400.",
                        error_category="VALIDATION_ERROR",
                    )
                if resp.status_code in (401, 403):
                    raise StorageError(
                        f"Duplicate links query unauthorized: HTTP {resp.status_code}",
                        error_category="AUTH_ERROR",
                    )
                raise StorageError(f"Failed to query duplicate links: HTTP {resp.status_code}")
        except StorageError:
            raise
        except httpx.RequestError as exc:
            raise StorageError(f"Duplicate links query network error: {exc.__class__.__name__}") from exc

    def query_duplicate_link_counts_sync(
        self,
        *,
        known_status_counts: Optional[Dict[str, int]] = None,
    ) -> Dict[str, int]:
        """
        Computes exact PostgreSQL counts for SUSPECTED, CONFIRMED, and DISMISSED duplicate
        links using PostgREST HEAD queries with `Prefer: count=exact` (zero row payload,
        no 1,000-row cap). Reuses any pre-supplied status count to avoid duplicate requests.

        Concurrency note: each status count is an exact PostgreSQL `COUNT(*)` at query
        execution time rather than a single cross-HTTP snapshot.
        """
        self._ensure_storage_configured()
        endpoint = f"{self._supabase_url}/rest/v1/incident_duplicate_links"
        base_headers = self._get_storage_headers(content_type="application/json")
        base_headers["Prefer"] = "count=exact"

        counts: Dict[str, int] = {}
        try:
            with httpx.Client(timeout=self._timeout_sec) as client:
                for status_val in ("SUSPECTED", "CONFIRMED", "DISMISSED"):
                    if known_status_counts is not None and status_val in known_status_counts:
                        known_val = known_status_counts[status_val]
                        if isinstance(known_val, int) and not isinstance(known_val, bool) and known_val >= 0:
                            counts[status_val] = known_val
                            continue

                    resp = client.head(
                        endpoint,
                        headers=base_headers,
                        params={
                            "select": "link_id",
                            "link_status": f"eq.{status_val}",
                        },
                    )
                    if resp.status_code in (200, 206):
                        exact_count = _parse_postgrest_content_range_total(resp.headers.get("Content-Range"))
                        if exact_count is None:
                            raise StorageError(
                                "Duplicate link count query missing exact Content-Range total.",
                                error_category="RANGE_ERROR",
                            )
                        counts[status_val] = exact_count
                        continue
                    if resp.status_code == 416:
                        exact_count = _parse_postgrest_content_range_total(resp.headers.get("Content-Range"))
                        if exact_count == 0:
                            counts[status_val] = 0
                            continue
                        raise StorageError(
                            "Duplicate link count query failed with HTTP 416.",
                            error_category="RANGE_ERROR",
                        )
                    if resp.status_code in (401, 403):
                        raise StorageError(
                            f"Duplicate link count query unauthorized: HTTP {resp.status_code}",
                            error_category="AUTH_ERROR",
                        )
                    raise StorageError(f"Failed to count duplicate links: HTTP {resp.status_code}")
            return counts
        except StorageError:
            raise
        except httpx.RequestError as exc:
            raise StorageError(f"Duplicate link count query network error: {exc.__class__.__name__}") from exc

    def query_duplicate_links_for_incident_sync(
        self,
        incident_id: str,
    ) -> List[Dict[str, Any]]:
        self._ensure_storage_configured()
        clean_inc_id = _validate_incident_id(incident_id)
        endpoint = f"{self._supabase_url}/rest/v1/incident_duplicate_links"
        headers = self._get_storage_headers(content_type="application/json")
        params = {
            "select": "*",
            "or": f"(incident_low_id.eq.{clean_inc_id},incident_high_id.eq.{clean_inc_id})",
            "order": "created_at.desc,link_id.asc",
        }
        try:
            with httpx.Client(timeout=self._timeout_sec) as client:
                resp = client.get(endpoint, headers=headers, params=params)
                if resp.status_code in (200, 206):
                    rows = resp.json()
                    if not isinstance(rows, list):
                        raise StorageError("Incident duplicate links query returned invalid JSON shape.")
                    return rows
                if resp.status_code in (401, 403):
                    raise StorageError(
                        f"Incident duplicate links query unauthorized: HTTP {resp.status_code}",
                        error_category="AUTH_ERROR",
                    )
                raise StorageError(f"Failed to query duplicate links for incident: HTTP {resp.status_code}")
        except StorageError:
            raise
        except httpx.RequestError as exc:
            raise StorageError(f"Incident duplicate links query network error: {exc.__class__.__name__}") from exc


# Global persistence client instance
persistence_repo = PersistenceRepository()
