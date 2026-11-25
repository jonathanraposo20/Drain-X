import logging
import math
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from app.core.config import settings
from app.models.contracts import (
    CategoryMatchType,
    DuplicateConfidenceBand,
    DuplicateLinkContract,
    DuplicateLinkStatus,
    DuplicateScanResponseContract,
)
from app.services.persistence_repository import (
    StorageConflictError,
    StorageLeaseLostError,
    StorageValidationError,
)

logger = logging.getLogger(__name__)

EARTH_RADIUS_METERS: float = 6371000.0
DUPLICATE_SCAN_BACKOFF_SECONDS: tuple[int, ...] = (30, 120, 600, 1800, 3600)

WATER_RELATED_CATEGORIES: set[str] = {
    "FLOODING",
    "WATERLOGGING",
    "DRAIN_OVERFLOW",
}

INFRASTRUCTURE_RELATED_CATEGORIES: set[str] = {
    "DRAIN_BLOCKAGE",
    "MANHOLE_DAMAGE",
    "INFRASTRUCTURE_DAMAGE",
}


def _emit_duplicate_suspected_event(link: DuplicateLinkContract) -> None:
    """
    Emits DUPLICATE_SUSPECTED event after a genuinely new duplicate link is successfully persisted.
    Strictly authorized only for municipal officers, admins, and service_role.
    Fail-open: never raises or interferes with duplicate scan execution.
    """
    try:
        from app.services.incident_stream_manager import incident_stream_manager
        from app.models.contracts import IncidentStreamEventType, MunicipalDuplicateLinkContract

        band_val = link.confidence_band.value if hasattr(link.confidence_band, "value") else str(link.confidence_band)
        muni_link = MunicipalDuplicateLinkContract(
            link_id=link.link_id,
            incident_low_id=link.incident_low_id,
            incident_high_id=link.incident_high_id,
            primary_incident_id=link.primary_incident_id,
            duplicate_incident_id=link.duplicate_incident_id,
            detection_origin=link.detection_origin,
            detected_in_mode=link.detected_in_mode,
            distance_meters=link.distance_meters,
            time_delta_seconds=link.time_delta_seconds,
            confidence_score=link.confidence_score,
            confidence_band=link.confidence_band,
            match_reasons=link.match_reasons,
            link_status=link.link_status,
            created_at=link.created_at,
            reviewed_at=link.reviewed_at,
            reviewed_by=link.reviewed_by,
            reviewed_role=link.reviewed_role,
            review_reason=link.review_reason,
            review_version=link.review_version,
            updated_at=link.updated_at,
        )
        incident_stream_manager.broadcast_incident_event(
            event_type=IncidentStreamEventType.DUPLICATE_SUSPECTED,
            incident_id=link.incident_low_id,
            action="DUPLICATE_SUSPECTED",
            duplicate_link=muni_link,
            reason=f"Suspected duplicate link detected ({band_val} confidence, score={link.confidence_score:.2f})",
        )
    except Exception as exc:
        logger.warning("Failed to broadcast DUPLICATE_SUSPECTED non-fatally: %s", exc)


def generate_duplicate_lease_owner() -> str:
    """Generates a globally unique per-attempt lease token matching DB constraint."""
    return f"dup_lease_{uuid.uuid4().hex}"


def generate_duplicate_link_id() -> str:
    """Generates a collision-safe link ID strictly within VARCHAR(32)."""
    return f"lnk_{uuid.uuid4().hex[:24]}"


def canonicalize_incident_pair(id_a: str, id_b: str) -> tuple[str, str]:
    """
    Orders two distinct incident IDs deterministically using raw UTF-8 byte order
    (matching PostgreSQL COLLATE "C").
    """
    if id_a.encode("utf-8") < id_b.encode("utf-8"):
        return id_a, id_b
    return id_b, id_a


def compute_retry_backoff_seconds(attempt_count: int) -> int:
    """Returns exponential retry delay in seconds from the bounded backoff schedule."""
    idx = max(0, min(int(attempt_count) - 1, len(DUPLICATE_SCAN_BACKOFF_SECONDS) - 1))
    return DUPLICATE_SCAN_BACKOFF_SECONDS[idx]


def _normalize_operational_mode(mode: Any) -> str:
    raw = str(mode or "").strip().upper()
    if raw == "HARDWARE":
        return "PHYSICAL"
    if raw in ("SIMULATION", "PHYSICAL", "SAFE_HOLD"):
        return raw
    return "SIMULATION"


def _sanitize_error_code(exc: Exception) -> str:
    raw = exc.__class__.__name__ or "SCAN_ERROR"
    cleaned = re.sub(r"[^A-Za-z0-9_]+", "_", raw).strip("_").upper()
    return (cleaned or "SCAN_ERROR")[:64]


def _release_scan_for_retry(
    repo: Any,
    incident_id: str,
    lease_owner: str,
    attempt_count: int,
    error_code: str,
    sqlstate: Optional[str] = None,
) -> DuplicateScanResponseContract:
    backoff_sec = compute_retry_backoff_seconds(attempt_count)
    logger.warning(
        "Retryable duplicate scan failure for %s (attempt=%s, backoff=%ss, sqlstate=%s, code=%s)",
        incident_id,
        attempt_count,
        backoff_sec,
        sqlstate or "NONE",
        error_code,
    )
    final_status = "RETRY_SCHEDULED"
    try:
        rel_res = repo.release_duplicate_scan_job_sync(
            incident_id=incident_id,
            lease_owner=lease_owner,
            error_code=error_code,
            backoff_sec=backoff_sec,
            permanent=False,
        )
        if isinstance(rel_res, dict) and rel_res.get("status") == "FAILED_PERMANENT":
            final_status = "FAILED_PERMANENT"
    except Exception as rel_exc:
        logger.warning(
            "Failed to release duplicate scan job %s: %s",
            incident_id,
            rel_exc.__class__.__name__,
        )
    return DuplicateScanResponseContract(
        incident_id=incident_id,
        status=final_status,
        candidates_found=0,
        links_created=0,
        total_links=0,
    )


def is_valid_coordinate(lat: float | None, lon: float | None) -> bool:
    """
    Validates that latitude and longitude are non-null, finite numbers
    within legitimate geographic ranges, and not situated at Null Island (0, 0).
    """
    if lat is None or lon is None:
        return False
    if math.isnan(lat) or math.isinf(lat) or math.isnan(lon) or math.isinf(lon):
        return False
    if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
        return False
    if abs(lat) < 0.0001 and abs(lon) < 0.0001:
        return False
    return True


def calculate_haversine_distance_meters(
    lat1: float, lon1: float, lat2: float, lon2: float
) -> float:
    """
    Computes great-circle distance between two geographic coordinates in meters.
    """
    if not is_valid_coordinate(lat1, lon1) or not is_valid_coordinate(lat2, lon2):
        return float("inf")

    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = (
        math.sin(delta_phi / 2.0) ** 2
        + math.cos(phi1) * math.cos(phi2) * (math.sin(delta_lambda / 2.0) ** 2)
    )
    a = min(1.0, max(0.0, a))
    c = 2.0 * math.asin(math.sqrt(a))
    return EARTH_RADIUS_METERS * c


def determine_category_match_type(cat1: str, cat2: str) -> CategoryMatchType:
    """
    Determines category relationship: EXACT, RELATED, or OTHER.
    """
    c1 = (cat1 or "").upper()
    c2 = (cat2 or "").upper()
    if c1 == c2:
        return CategoryMatchType.EXACT
    if (c1 in WATER_RELATED_CATEGORIES and c2 in WATER_RELATED_CATEGORIES) or (
        c1 in INFRASTRUCTURE_RELATED_CATEGORIES and c2 in INFRASTRUCTURE_RELATED_CATEGORIES
    ):
        return CategoryMatchType.RELATED
    return CategoryMatchType.OTHER


def get_allowed_categories_for_prefilter(
    category: str, allow_related: bool = True
) -> list[str]:
    """
    Returns candidate category allowlist for database candidate pre-filtering.
    """
    c = (category or "").upper()
    if not allow_related:
        return [c]
    if c in WATER_RELATED_CATEGORIES:
        return sorted(list(WATER_RELATED_CATEGORIES))
    if c in INFRASTRUCTURE_RELATED_CATEGORIES:
        return sorted(list(INFRASTRUCTURE_RELATED_CATEGORIES))
    return [c]


def are_provenances_compatible(
    source_a: str,
    mode_a: str | None,
    source_b: str,
    mode_b: str | None,
    match_citizen_with_physical_sensor: bool = True,
) -> bool:
    """
    Enforces operational mode provenance and data segregation rules:
    - DEMO incidents never match CITIZEN or SENSOR.
    - CITIZEN incidents match CITIZEN across all operational modes.
    - SENSOR in SIMULATION matches ONLY other SENSOR in SIMULATION.
    - SENSOR in PHYSICAL/SAFE_HOLD matches SENSOR in PHYSICAL/SAFE_HOLD,
      and matches CITIZEN if match_citizen_with_physical_sensor is True.
    """
    sa = (source_a or "").upper()
    sb = (source_b or "").upper()
    ma = (mode_a or "").upper() if mode_a else None
    mb = (mode_b or "").upper() if mode_b else None

    if sa == "DEMO" or sb == "DEMO":
        return False

    if sa == "CITIZEN" and sb == "CITIZEN":
        return True

    if sa == "CITIZEN" and sb == "SENSOR":
        return match_citizen_with_physical_sensor and (mb in ("PHYSICAL", "SAFE_HOLD"))

    if sa == "SENSOR" and sb == "CITIZEN":
        return match_citizen_with_physical_sensor and (ma in ("PHYSICAL", "SAFE_HOLD"))

    if sa == "SENSOR" and sb == "SENSOR":
        if ma == "SIMULATION" or mb == "SIMULATION":
            return ma == "SIMULATION" and mb == "SIMULATION"
        return ma in ("PHYSICAL", "SAFE_HOLD") and mb in ("PHYSICAL", "SAFE_HOLD")

    return False


def calculate_text_similarity(text1: str | None, text2: str | None) -> float:
    """
    Computes token-level Jaccard similarity across descriptions.
    """
    t1 = (text1 or "").strip().lower()
    t2 = (text2 or "").strip().lower()
    if not t1 or not t2:
        return 0.0

    tokens1 = set(re.findall(r"\b\w+\b", t1))
    tokens2 = set(re.findall(r"\b\w+\b", t2))
    if not tokens1 or not tokens2:
        return 0.0

    intersection = len(tokens1 & tokens2)
    union = len(tokens1 | tokens2)
    if union == 0:
        return 0.0
    return float(intersection) / float(union)


def score_incident_pair(
    incident_a: dict[str, Any],
    incident_b: dict[str, Any],
    max_distance_exact: float = 150.0,
    max_distance_related: float = 75.0,
    max_distance_other: float = 50.0,
    time_window_sec: int = 21600,
    min_confidence_score: float = 0.55,
    match_citizen_with_physical_sensor: bool = True,
    detected_in_mode: str = "SIMULATION",
) -> Optional[DuplicateLinkContract]:
    """
    Authoritative deterministic scoring of two incidents.
    Returns a canonical undirected DuplicateLinkContract (status=SUSPECTED)
    if compatible and above threshold, or None if rejected.
    """
    id_a = incident_a.get("id")
    id_b = incident_b.get("id")
    if not id_a or not id_b or id_a == id_b:
        return None

    if incident_a.get("status") == "REJECTED" or incident_b.get("status") == "REJECTED":
        return None

    if not are_provenances_compatible(
        source_a=incident_a.get("source", ""),
        mode_a=incident_a.get("origin_operational_mode"),
        source_b=incident_b.get("source", ""),
        mode_b=incident_b.get("origin_operational_mode"),
        match_citizen_with_physical_sensor=match_citizen_with_physical_sensor,
    ):
        return None

    lat_a = incident_a.get("latitude")
    lon_a = incident_a.get("longitude")
    lat_b = incident_b.get("latitude")
    lon_b = incident_b.get("longitude")
    if not is_valid_coordinate(lat_a, lon_a) or not is_valid_coordinate(lat_b, lon_b):
        return None

    distance_meters = calculate_haversine_distance_meters(lat_a, lon_a, lat_b, lon_b)
    category_match = determine_category_match_type(
        incident_a.get("category", ""), incident_b.get("category", "")
    )

    if category_match == CategoryMatchType.EXACT:
        max_dist = max_distance_exact
        category_score = 1.0
    elif category_match == CategoryMatchType.RELATED:
        max_dist = max_distance_related
        category_score = 0.6
    else:
        max_dist = max_distance_other
        category_score = 0.2

    if distance_meters > max_dist:
        return None

    spatial_score = max(0.0, 1.0 - (distance_meters / max_dist))

    time_a = incident_a.get("created_at")
    time_b = incident_b.get("created_at")
    if isinstance(time_a, str):
        try:
            time_a = datetime.fromisoformat(time_a.replace("Z", "+00:00"))
        except Exception:
            time_a = datetime.now(timezone.utc)
    if isinstance(time_b, str):
        try:
            time_b = datetime.fromisoformat(time_b.replace("Z", "+00:00"))
        except Exception:
            time_b = datetime.now(timezone.utc)

    if not isinstance(time_a, datetime):
        time_a = datetime.now(timezone.utc)
    if not isinstance(time_b, datetime):
        time_b = datetime.now(timezone.utc)

    time_diff_sec = abs((time_a - time_b).total_seconds())
    if time_diff_sec > time_window_sec:
        return None

    temporal_score = max(0.0, 1.0 - (time_diff_sec / float(time_window_sec)))
    text_score = calculate_text_similarity(
        incident_a.get("description"), incident_b.get("description")
    )

    raw_confidence = (
        (0.45 * spatial_score)
        + (0.25 * temporal_score)
        + (0.20 * category_score)
        + (0.10 * text_score)
    )
    confidence_score = round(min(1.0, max(0.0, raw_confidence)), 3)

    if confidence_score < min_confidence_score:
        return None

    if confidence_score >= 0.80:
        confidence_band = DuplicateConfidenceBand.HIGH
    elif confidence_score >= 0.65:
        confidence_band = DuplicateConfidenceBand.MEDIUM
    else:
        confidence_band = DuplicateConfidenceBand.LOW

    low_id, high_id = canonicalize_incident_pair(str(id_a), str(id_b))

    return DuplicateLinkContract(
        link_id=generate_duplicate_link_id(),
        incident_low_id=low_id,
        incident_high_id=high_id,
        link_status=DuplicateLinkStatus.SUSPECTED,
        primary_incident_id=None,
        duplicate_incident_id=None,
        detection_origin="AUTOMATED",
        detected_in_mode=_normalize_operational_mode(detected_in_mode),
        distance_meters=round(distance_meters, 2),
        time_delta_seconds=int(round(time_diff_sec)),
        confidence_score=confidence_score,
        confidence_band=confidence_band,
        match_reasons=[f"CATEGORY_{category_match.value}"],
        review_version=0,
    )


def execute_claimed_cloud_scan(
    job: dict[str, Any],
    lease_owner: str,
    repo: Any,
    current_settings: Any = settings,
    detected_in_mode: str = "SIMULATION",
) -> DuplicateScanResponseContract:
    """
    Executes a single cloud duplicate scan for an ALREADY-CLAIMED outbox job.
    Uses the caller-supplied lease_owner token and NEVER re-claims the job.
    """
    incident_id = str(job.get("incident_id", "")).strip()
    attempt_count = int(job.get("attempt_count") or 1)
    clean_mode = _normalize_operational_mode(detected_in_mode)

    if not incident_id:
        return DuplicateScanResponseContract(
            incident_id="",
            status="FAILED_PERMANENT",
            candidates_found=0,
            links_created=0,
            total_links=0,
        )

    try:
        target = repo.query_incident_by_id_sync(incident_id)
        if not target:
            logger.warning("Target incident %s not found in persistence repository.", incident_id)
            try:
                repo.release_duplicate_scan_job_sync(
                    incident_id=incident_id,
                    lease_owner=lease_owner,
                    error_code="INCIDENT_NOT_FOUND",
                    permanent=True,
                )
            except Exception as rel_exc:
                logger.warning("Release after missing incident failed for %s: %s", incident_id, rel_exc)
            return DuplicateScanResponseContract(
                incident_id=incident_id,
                status="FAILED_PERMANENT",
                candidates_found=0,
                links_created=0,
                total_links=0,
            )

        target_dict = (
            target.model_dump()
            if hasattr(target, "model_dump")
            else (target.dict() if hasattr(target, "dict") else dict(target))
        )

        if target_dict.get("source") == "DEMO":
            rec_res = repo.record_duplicate_candidates_sync(
                incident_id=incident_id,
                detected_in_mode=clean_mode,
                candidates=[],
                lease_owner=lease_owner,
            )
            return DuplicateScanResponseContract(
                incident_id=incident_id,
                status="COMPLETED",
                candidates_found=0,
                links_created=int(rec_res.get("links_created", 0)),
                total_links=int(rec_res.get("total_links", 0)),
            )

        allowed_cats = get_allowed_categories_for_prefilter(
            target_dict.get("category", ""),
            allow_related=current_settings.DUPLICATE_ALLOW_RELATED_CATEGORIES,
        )

        fetch_res = repo.fetch_duplicate_candidates_sync(
            incident_id=incident_id,
            max_radius_m=current_settings.DUPLICATE_MAX_DISTANCE_METERS,
            time_window_sec=current_settings.DUPLICATE_TIME_WINDOW_SEC,
            allowed_categories=allowed_cats,
            include_resolved=current_settings.DUPLICATE_INCLUDE_RESOLVED,
            match_citizen_physical_sensor=current_settings.DUPLICATE_MATCH_CITIZEN_WITH_PHYSICAL_SENSOR,
            limit=200,
        )

        source_dict = (
            fetch_res.get("source_incident")
            if isinstance(fetch_res.get("source_incident"), dict)
            else target_dict
        )
        candidates = fetch_res.get("candidates") if isinstance(fetch_res.get("candidates"), list) else []

        scored_links: list[DuplicateLinkContract] = []
        for cand in candidates:
            cand_dict = (
                cand
                if isinstance(cand, dict)
                else (
                    cand.model_dump()
                    if hasattr(cand, "model_dump")
                    else (cand.dict() if hasattr(cand, "dict") else dict(cand))
                )
            )
            link = score_incident_pair(
                source_dict,
                cand_dict,
                max_distance_exact=current_settings.DUPLICATE_MAX_DISTANCE_METERS,
                max_distance_related=current_settings.DUPLICATE_RELATED_CATEGORY_MAX_DISTANCE_METERS,
                max_distance_other=current_settings.DUPLICATE_OTHER_CATEGORY_MAX_DISTANCE_METERS,
                time_window_sec=current_settings.DUPLICATE_TIME_WINDOW_SEC,
                min_confidence_score=current_settings.DUPLICATE_MIN_CONFIDENCE_SCORE,
                match_citizen_with_physical_sensor=current_settings.DUPLICATE_MATCH_CITIZEN_WITH_PHYSICAL_SENSOR,
                detected_in_mode=clean_mode,
            )
            if link:
                scored_links.append(link)

        scored_links.sort(
            key=lambda l: (
                -l.confidence_score,
                l.distance_meters,
                l.time_delta_seconds,
                l.incident_low_id,
                l.incident_high_id,
            )
        )
        capped_links = scored_links[: current_settings.DUPLICATE_MAX_CANDIDATES_PER_INCIDENT]

        candidates_payload = [
            {
                "link_id": l.link_id,
                "candidate_incident_id": (
                    l.incident_high_id if l.incident_low_id == incident_id else l.incident_low_id
                ),
                "detection_origin": l.detection_origin,
                "distance_meters": l.distance_meters,
                "time_delta_seconds": l.time_delta_seconds,
                "confidence_score": l.confidence_score,
                "confidence_band": l.confidence_band.value,
                "match_reasons": list(l.match_reasons),
            }
            for l in capped_links
        ]

        rec_res = repo.record_duplicate_candidates_sync(
            incident_id=incident_id,
            detected_in_mode=clean_mode,
            candidates=candidates_payload,
            lease_owner=lease_owner,
        )

        created_count = int(rec_res.get("links_created", 0))
        if created_count > 0:
            if created_count == len(capped_links):
                for link in capped_links:
                    _emit_duplicate_suspected_event(link)
            else:
                try:
                    existing_db = repo.query_duplicate_links_for_incident_sync(incident_id)
                    existing_by_pair = {
                        (l.get("incident_low_id"), l.get("incident_high_id")): l.get("link_id")
                        for l in existing_db
                    }
                    for link in capped_links:
                        pair = (link.incident_low_id, link.incident_high_id)
                        if pair in existing_by_pair and existing_by_pair[pair] == link.link_id:
                            _emit_duplicate_suspected_event(link)
                except Exception as query_err:
                    logger.warning("Failed to query created duplicate links: %s", query_err)

        return DuplicateScanResponseContract(
            incident_id=incident_id,
            status="COMPLETED",
            candidates_found=len(candidates),
            links_created=created_count,
            total_links=int(rec_res.get("total_links", 0)),
        )

    except StorageLeaseLostError as lease_exc:
        # Stale lease or lease lost to another worker: NEVER release the newer owner's lease
        logger.warning(
            "Duplicate scan lease conflict/lost for %s (lease=%s, sqlstate=%s)",
            incident_id,
            lease_owner,
            getattr(lease_exc, "sqlstate", None) or "P0412",
        )
        return DuplicateScanResponseContract(
            incident_id=incident_id,
            status="LEASE_LOST",
            candidates_found=0,
            links_created=0,
            total_links=0,
        )

    except StorageValidationError as val_exc:
        error_code = _sanitize_error_code(val_exc)
        logger.error("Permanent validation error scanning duplicate %s: %s", incident_id, error_code)
        try:
            repo.release_duplicate_scan_job_sync(
                incident_id=incident_id,
                lease_owner=lease_owner,
                error_code=error_code,
                permanent=True,
            )
        except Exception:
            pass
        return DuplicateScanResponseContract(
            incident_id=incident_id,
            status="FAILED_PERMANENT",
            candidates_found=0,
            links_created=0,
            total_links=0,
        )

    except StorageConflictError as conflict_exc:
        sqlstate = getattr(conflict_exc, "sqlstate", None)
        if sqlstate == "23514":
            logger.error(
                "Permanent check constraint conflict scanning duplicate %s (sqlstate=%s)",
                incident_id,
                sqlstate,
            )
            try:
                repo.release_duplicate_scan_job_sync(
                    incident_id=incident_id,
                    lease_owner=lease_owner,
                    error_code="CANDIDATE_CHECK_VIOLATION",
                    permanent=True,
                )
            except Exception as rel_exc:
                logger.warning(
                    "Failed to permanently release duplicate scan job %s: %s",
                    incident_id,
                    rel_exc.__class__.__name__,
                )
            return DuplicateScanResponseContract(
                incident_id=incident_id,
                status="FAILED_PERMANENT",
                candidates_found=0,
                links_created=0,
                total_links=0,
            )

        error_code = "UNIQUE_VIOLATION" if sqlstate == "23505" else _sanitize_error_code(conflict_exc)
        return _release_scan_for_retry(
            repo=repo,
            incident_id=incident_id,
            lease_owner=lease_owner,
            attempt_count=attempt_count,
            error_code=error_code,
            sqlstate=sqlstate,
        )

    except Exception as exc:
        return _release_scan_for_retry(
            repo=repo,
            incident_id=incident_id,
            lease_owner=lease_owner,
            attempt_count=attempt_count,
            error_code=_sanitize_error_code(exc),
            sqlstate=getattr(exc, "sqlstate", None),
        )


def _scan_cloud_incident(
    incident_id: str,
    repo: Any,
    cfg: Any,
    detected_in_mode: str = "SIMULATION",
) -> DuplicateScanResponseContract:
    lease_owner = generate_duplicate_lease_owner()
    jobs = repo.claim_duplicate_scan_jobs_sync(
        lease_owner=lease_owner,
        incident_id=incident_id,
        batch_size=1,
        lease_sec=30,
    )
    if not jobs:
        logger.info(
            "Duplicate scan job for %s could not be claimed (already completed, backoff pending, or leased); aborting.",
            incident_id,
        )
        return DuplicateScanResponseContract(
            incident_id=incident_id,
            status="NOT_CLAIMED",
            candidates_found=0,
            links_created=0,
            total_links=0,
        )

    claimed_job = jobs[0] if isinstance(jobs[0], dict) else {"incident_id": incident_id, "attempt_count": 1}
    exact_lease_owner = claimed_job.get("lease_owner") or lease_owner
    return execute_claimed_cloud_scan(
        job=claimed_job,
        lease_owner=exact_lease_owner,
        repo=repo,
        current_settings=cfg,
        detected_in_mode=detected_in_mode,
    )


def recover_pending_cloud_duplicate_scans(
    repo: Any,
    state_store: Any,
    current_settings: Any = settings,
    batch_size: int = 10,
    lease_sec: int = 60,
) -> dict[str, Any]:
    """
    Single-claim batch recovery for both the lifespan background sweeper
    and the admin maintenance endpoint. Never re-claims inside the executor.
    """
    if not getattr(current_settings, "DUPLICATE_DETECTION_ENABLED", True):
        return {
            "status": "DISABLED",
            "lease_owner": None,
            "claimed_jobs": 0,
            "completed_count": 0,
            "retry_scheduled_count": 0,
            "failed_permanent_count": 0,
            "lease_lost_count": 0,
        }

    lease_owner = generate_duplicate_lease_owner()
    jobs = repo.claim_duplicate_scan_jobs_sync(
        lease_owner=lease_owner,
        incident_id=None,
        batch_size=batch_size,
        lease_sec=lease_sec,
    )

    detected_in_mode = _normalize_operational_mode(getattr(state_store, "mode", "SIMULATION"))
    completed_count = 0
    retry_scheduled_count = 0
    failed_permanent_count = 0
    lease_lost_count = 0

    for job in jobs:
        try:
            job_dict = job if isinstance(job, dict) else {"incident_id": str(job), "attempt_count": 1}
            exact_lease = job_dict.get("lease_owner") or lease_owner
            res = execute_claimed_cloud_scan(
                job=job_dict,
                lease_owner=exact_lease,
                repo=repo,
                current_settings=current_settings,
                detected_in_mode=detected_in_mode,
            )
            if res.status == "COMPLETED":
                completed_count += 1
            elif res.status == "LEASE_LOST":
                lease_lost_count += 1
            elif res.status == "FAILED_PERMANENT":
                failed_permanent_count += 1
            else:
                retry_scheduled_count += 1
        except Exception as exc:
            retry_scheduled_count += 1
            logger.warning("Unexpected exception recovering duplicate scan job: %s", exc)

    return {
        "status": "COMPLETED",
        "lease_owner": lease_owner,
        "claimed_jobs": len(jobs),
        "completed_count": completed_count,
        "retry_scheduled_count": retry_scheduled_count,
        "failed_permanent_count": failed_permanent_count,
        "lease_lost_count": lease_lost_count,
    }


def scan_incident_for_duplicates(
    incident_id: str,
    repo: Any,
    state_store: Any,
    current_settings: Any = settings,
) -> DuplicateScanResponseContract:
    """
    Authoritative duplicate detection orchestrator.
    - Full cloud storage config: claims single job and executes RPC pipeline.
    - Partial cloud config (is_configured=True, is_storage_configured=False): fails closed (never falls back to local).
    - Local unconfigured dev mode: executes synchronous local StateStore scan using identical scorer.
    """
    if not current_settings.DUPLICATE_DETECTION_ENABLED:
        logger.info("Duplicate detection disabled by configuration; skipping scan for %s", incident_id)
        return DuplicateScanResponseContract(
            incident_id=incident_id,
            status="DISABLED",
            candidates_found=0,
            links_created=0,
            total_links=0,
        )

    detected_in_mode = _normalize_operational_mode(getattr(state_store, "mode", "SIMULATION"))
    is_mock_repo = getattr(repo, "is_mock", False) if repo is not None else False
    has_storage = bool(repo is not None and getattr(repo, "is_storage_configured", False) and not is_mock_repo)
    has_partial_cloud = bool(repo is not None and getattr(repo, "is_configured", False) and not has_storage and not is_mock_repo)

    if has_storage:
        return _scan_cloud_incident(
            incident_id=incident_id,
            repo=repo,
            cfg=current_settings,
            detected_in_mode=detected_in_mode,
        )

    if has_partial_cloud:
        logger.error(
            "Partial cloud configuration detected (SUPABASE_SERVICE_ROLE_KEY missing); skipping duplicate scan for %s without local fallback.",
            incident_id,
        )
        return DuplicateScanResponseContract(
            incident_id=incident_id,
            status="UNCONFIGURED_STORAGE",
            candidates_found=0,
            links_created=0,
            total_links=0,
        )

    return _scan_local_incident(
        incident_id=incident_id,
        state_store=state_store,
        cfg=current_settings,
        detected_in_mode=detected_in_mode,
    )


def _scan_local_incident(
    incident_id: str,
    state_store: Any,
    cfg: Any,
    detected_in_mode: str = "SIMULATION",
) -> DuplicateScanResponseContract:
    target = state_store.get_incident(incident_id)
    if not target:
        return DuplicateScanResponseContract(
            incident_id=incident_id,
            status="FAILED_PERMANENT",
            candidates_found=0,
            links_created=0,
            total_links=0,
        )

    target_dict = (
        target.model_dump()
        if hasattr(target, "model_dump")
        else (target.dict() if hasattr(target, "dict") else dict(target))
    )

    if target_dict.get("source") == "DEMO":
        return DuplicateScanResponseContract(
            incident_id=incident_id,
            status="COMPLETED",
            candidates_found=0,
            links_created=0,
            total_links=len(state_store.get_incident_duplicate_links(incident_id)),
        )

    all_incidents = state_store.get_incidents()
    candidates: list[dict[str, Any]] = []

    for inc in all_incidents:
        inc_dict = (
            inc.model_dump()
            if hasattr(inc, "model_dump")
            else (inc.dict() if hasattr(inc, "dict") else dict(inc))
        )
        if inc_dict.get("id") == incident_id:
            continue
        if inc_dict.get("status") == "REJECTED":
            continue
        if not cfg.DUPLICATE_INCLUDE_RESOLVED and inc_dict.get("status") == "RESOLVED":
            continue
        if inc_dict.get("source") == "DEMO":
            continue
        candidates.append(inc_dict)

    scored_links: list[DuplicateLinkContract] = []
    for cand in candidates:
        link = score_incident_pair(
            target_dict,
            cand,
            max_distance_exact=cfg.DUPLICATE_MAX_DISTANCE_METERS,
            max_distance_related=cfg.DUPLICATE_RELATED_CATEGORY_MAX_DISTANCE_METERS,
            max_distance_other=cfg.DUPLICATE_OTHER_CATEGORY_MAX_DISTANCE_METERS,
            time_window_sec=cfg.DUPLICATE_TIME_WINDOW_SEC,
            min_confidence_score=cfg.DUPLICATE_MIN_CONFIDENCE_SCORE,
            match_citizen_with_physical_sensor=cfg.DUPLICATE_MATCH_CITIZEN_WITH_PHYSICAL_SENSOR,
            detected_in_mode=detected_in_mode,
        )
        if link:
            scored_links.append(link)

    scored_links.sort(
        key=lambda l: (
            -l.confidence_score,
            l.distance_meters,
            l.time_delta_seconds,
            l.incident_low_id,
            l.incident_high_id,
        )
    )
    capped_links = scored_links[: cfg.DUPLICATE_MAX_CANDIDATES_PER_INCIDENT]

    created_count = 0
    for link in capped_links:
        if state_store.record_duplicate_link(link):
            created_count += 1
            _emit_duplicate_suspected_event(link)

    return DuplicateScanResponseContract(
        incident_id=incident_id,
        status="COMPLETED",
        candidates_found=len(candidates),
        links_created=created_count,
        total_links=len(state_store.get_incident_duplicate_links(incident_id)),
    )
