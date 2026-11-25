"""
DRAIN-X Rate Limiting & Abuse Protection Service.

Milestone: Phase 3 Production Rate Limiting & Abuse Protection (Stage A Hardened)

Architecture:
1. Authenticated & Anonymous Scopes:
   - Authenticated Incident Creation (POST /api/v1/incidents): 5 req / 15 min default.
   - Authenticated Photo Upload (POST /api/v1/incidents/{id}/photos): 10 req / 15 min default.
   - Authenticated Photo Retrieval (GET .../photos/{filename}): 60 req / 1 min default.
   - Anonymous Incident Creation: 5 req / 15 min default.
   - Anonymous Photo Upload: 5 req / 15 min default.
   - Anonymous Photo Retrieval: 30 req / 1 min default.
2. Verified & Hardened Identity Keying (HMAC-SHA256 + Distinct Namespaces):
   - Authenticated users: keyed to cryptographically verified JWT `sub` under `auth:<action>:<sub>`.
   - Anonymous callers: keyed to normalized ASGI peer IP (with optional right-to-left trusted-proxy
     X-Forwarded-For peeling and IPv6 /64 normalization) under `anon:<action>:<client_id>`.
   - Key hashes computed via HMAC-SHA256 with backend-only secret RATE_LIMIT_KEY_PEPPER.
   - Never trusts spoofed forwarding headers or client-controlled user_metadata.
   - Changing incident IDs or photo filenames does not bypass per-caller limits.
3. Fail-Closed Shared Persistence:
   - In production (ENVIRONMENT == 'production'), rate limiting must be enabled, HMAC pepper
     configured, service-role persistence configured, and memory backend forbidden.
   - If database persistence is unreachable, times out, or returns malformed data, fails closed
     with HTTP 503.
   - Local in-memory fallback is restricted strictly to non-production environments.
4. Privacy & Consistency:
   - HTTP 429 response includes Retry-After header (>= 1s) with small consistent error body.
   - Zero sensitive logging of raw IPs, user IDs, key hashes, forwarding headers, JWTs, or pepper.
"""

from dataclasses import dataclass
from enum import Enum, StrEnum
import hashlib
import hmac
import ipaddress
import logging
import math
import threading
import time
from typing import Any, Dict, Literal, Optional, Union

from fastapi import HTTPException, Request, status

from app.core.config import settings
from app.services.persistence_repository import persistence_repo

logger = logging.getLogger("drainx.rate_limiter")

_DEV_ONLY_FALLBACK_PEPPER = "drainx-dev-only-nonprod-rate-limit-pepper"

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


class RateLimitAction(StrEnum):
    INCIDENT_CREATE = "incident_create"
    PHOTO_UPLOAD = "photo_upload"
    PHOTO_RETRIEVE = "photo_retrieve"


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    current_count: int
    limit: int
    remaining: int
    reset_after_sec: int
    retry_after_sec: int


def _get_hmac_pepper() -> bytes:
    """
    Retrieves backend-only HMAC-SHA256 secret pepper bytes.
    In production, fails closed with HTTP 503 if pepper is missing or weak (< 16 chars).
    """
    pepper = (settings.RATE_LIMIT_KEY_PEPPER or "").strip()
    if settings.ENVIRONMENT == "production":
        if len(pepper) < 16:
            logger.error("Production rate limiting failed closed: RATE_LIMIT_KEY_PEPPER is missing or weak.")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Rate limit verification service unavailable.",
            )
        return pepper.encode("utf-8")

    if pepper:
        return pepper.encode("utf-8")
    return _DEV_ONLY_FALLBACK_PEPPER.encode("utf-8")


def compute_rate_limit_key_hash(
    action: str,
    identifier: str,
    namespace: Literal["auth", "anon"] = "auth",
) -> str:
    """
    Computes a keyed HMAC-SHA256 lowercase 64-hex digest with distinct namespaces
    (`auth:<action>:<sub>` or `anon:<action>:<normalized_client_id>`).
    Prevents rainbow-table reversal of IPv4 addresses and cross-namespace collisions.
    """
    if namespace not in ("auth", "anon"):
        raise ValueError(f"Invalid rate limit namespace: '{namespace}'.")
    action_str = action.value if isinstance(action, Enum) else str(action)
    namespaced = f"{namespace}:{action_str}:{identifier}"
    return hmac.new(_get_hmac_pepper(), namespaced.encode("utf-8"), hashlib.sha256).hexdigest()


def _parse_and_unwrap_ip(raw_ip: str) -> IPAddress:
    """
    Parses a single IP literal, rejecting zone IDs, ports, or malformed strings,
    and unwraps IPv4-mapped IPv6 addresses (e.g. ::ffff:203.0.113.5 -> 203.0.113.5).
    """
    clean = raw_ip.strip()
    if not clean or "%" in clean:
        raise ValueError("Empty or zone-qualified IP literal.")
    ip_obj = ipaddress.ip_address(clean)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        return ip_obj.ipv4_mapped
    return ip_obj


def _normalize_client_ip(ip_obj: IPAddress) -> str:
    """
    Normalizes client IP into a canonical key component:
    - IPv4 -> compressed dotted-quad string.
    - IPv6 -> /64 network prefix string (prevents SLAAC / interface-ID rotation bypass).
    """
    if isinstance(ip_obj, ipaddress.IPv6Address):
        net64 = ipaddress.IPv6Network((ip_obj, 64), strict=False)
        return f"{net64.network_address.compressed}/64"
    return ip_obj.compressed


def _is_trusted_proxy(ip_obj: IPAddress, trusted_nets: list[IPNetwork]) -> bool:
    return any(ip_obj.version == net.version and ip_obj in net for net in trusted_nets)


def extract_anonymous_client_identifier(request: Optional[Request]) -> str:
    """
    Extracts and normalizes a trustworthy anonymous client identifier from the ASGI Request.

    Security Rules:
    - Uses actual transport peer `request.client.host` by default.
    - Ignores `X-Forwarded-For`, `X-Real-IP`, and `Forwarded` unless the immediate peer IP
      matches configured `RATE_LIMIT_TRUSTED_PROXIES`.
    - When behind a trusted proxy, parses `X-Forwarded-For` right-to-left, stripping
      only consecutive trusted proxy hops, returning the rightmost untrusted client hop.
    - Fails closed with HTTP 503 if a trustworthy client IP cannot be determined.
    - Never logs raw IPs or raw forwarding headers.
    """
    if request is None or request.client is None or not request.client.host:
        logger.warning("Anonymous rate limit failed closed: missing ASGI client peer metadata.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rate limit verification service unavailable.",
        )

    raw_peer = str(request.client.host).strip()
    if settings.ENVIRONMENT != "production" and raw_peer == "testclient":
        raw_peer = "127.0.0.1"

    try:
        peer_ip = _parse_and_unwrap_ip(raw_peer)
    except ValueError:
        logger.warning("Anonymous rate limit failed closed: unparseable ASGI client peer.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rate limit verification service unavailable.",
        )

    trusted_nets: list[IPNetwork] = [
        ipaddress.ip_network(cidr, strict=False)
        for cidr in settings.RATE_LIMIT_TRUSTED_PROXIES
    ]

    if not trusted_nets or not _is_trusted_proxy(peer_ip, trusted_nets):
        return _normalize_client_ip(peer_ip)

    # Immediate peer is an explicitly trusted proxy: peel X-Forwarded-For right-to-left
    xff_values = request.headers.getlist("x-forwarded-for")
    combined_xff = ",".join(val for val in xff_values if val is not None)
    if not combined_xff.strip():
        logger.warning("Anonymous rate limit failed closed: trusted proxy request missing X-Forwarded-For.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rate limit verification service unavailable.",
        )

    hops = [part.strip() for part in combined_xff.split(",")]
    for raw_hop in reversed(hops):
        try:
            hop_ip = _parse_and_unwrap_ip(raw_hop)
        except ValueError:
            logger.warning("Anonymous rate limit failed closed: malformed X-Forwarded-For hop behind trusted proxy.")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Rate limit verification service unavailable.",
            )

        if _is_trusted_proxy(hop_ip, trusted_nets):
            continue
        return _normalize_client_ip(hop_ip)

    logger.warning("Anonymous rate limit failed closed: forwarding chain contained only trusted proxies.")
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Rate limit verification service unavailable.",
    )


class _InMemoryRateLimiter:
    """
    Thread-safe in-memory rate limiter strictly for non-production development/testing.
    Enforces atomic increment, fixed window resets, and bounded memory eviction.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # key_hash -> (window_start_sec, window_end_sec, request_count)
        self._store: Dict[str, tuple[float, float, int]] = {}
        self._last_cleanup_ts: float = 0.0

    def check_and_increment(
        self,
        key_hash: str,
        action: str,
        limit: int,
        window_sec: int,
        now_ts: Optional[float] = None,
    ) -> RateLimitResult:
        with self._lock:
            now = now_ts if now_ts is not None else time.time()

            # Bounded memory cleanup if table exceeds 5,000 entries (gated by time to avoid O(N) per-request scans)
            if len(self._store) > 5000 and (now - self._last_cleanup_ts >= 10.0):
                self._last_cleanup_ts = now
                expired = [k for k, v in self._store.items() if v[1] < now]
                for k in expired[:1000]:
                    self._store.pop(k, None)

            entry = self._store.get(key_hash)

            if entry is None:
                # First request in new window
                self._store[key_hash] = (now, now + window_sec, 1)
                return RateLimitResult(
                    allowed=True,
                    current_count=1,
                    limit=limit,
                    remaining=limit - 1,
                    reset_after_sec=window_sec,
                    retry_after_sec=0,
                )

            start, end, count = entry

            if now >= end:
                # Previous window expired; start new window
                self._store[key_hash] = (now, now + window_sec, 1)
                return RateLimitResult(
                    allowed=True,
                    current_count=1,
                    limit=limit,
                    remaining=limit - 1,
                    reset_after_sec=window_sec,
                    retry_after_sec=0,
                )

            if count < limit:
                # Within window, under limit: increment
                new_count = count + 1
                self._store[key_hash] = (start, end, new_count)
                reset_after = max(1, math.ceil(end - now))
                return RateLimitResult(
                    allowed=True,
                    current_count=new_count,
                    limit=limit,
                    remaining=limit - new_count,
                    reset_after_sec=reset_after,
                    retry_after_sec=0,
                )

            # Within window, limit reached/exceeded: do not increment
            reset_after = max(1, math.ceil(end - now))
            return RateLimitResult(
                allowed=False,
                current_count=count,
                limit=limit,
                remaining=0,
                reset_after_sec=reset_after,
                retry_after_sec=reset_after,
            )

    def clear(self) -> None:
        """Clears in-memory store (used for test isolation)."""
        with self._lock:
            self._store.clear()
            self._last_cleanup_ts = 0.0


# Global in-memory limiter instance for non-production environments
in_memory_rate_limiter = _InMemoryRateLimiter()


def check_rate_limit(
    action: str,
    claims: Optional[Dict[str, Any]],
    request: Optional[Request] = None,
    now_ts: Optional[float] = None,
) -> None:
    """
    Enforces production-grade rate limiting across DRAIN-X citizen and photo endpoints.

    Rules:
    - In production, RATE_LIMIT_ENABLED=False fails closed with HTTP 503 (never bypassed).
    - Anonymous callers (claims is None) are limited by normalized ASGI client IP under `anon:`
      namespace using HMAC-SHA256 with RATE_LIMIT_KEY_PEPPER.
    - Authenticated callers (claims is not None) verify non-empty `sub` and are limited under
      `auth:` namespace.
    - Bypasses citizen incident creation limit for municipal officers, field workers, admins, system.
    - Bypasses photo limits for admin and system actors.
    - Dispatches to PostgreSQL RPC `check_and_increment_rate_limit_rpc` in production/database mode.
    - Fails closed with HTTP 503 on store outage, missing credentials, or malformed RPC response.
    - Raises HTTP 429 Too Many Requests with `Retry-After` header when limit is exceeded.
    """
    is_production = (settings.ENVIRONMENT == "production")
    action_str = action.value if isinstance(action, Enum) else str(action)

    if not settings.RATE_LIMIT_ENABLED:
        if is_production:
            logger.error("Production rate limiting failed closed: RATE_LIMIT_ENABLED is False.")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Rate limit verification service unavailable.",
            )
        return

    if claims is None:
        client_id = extract_anonymous_client_identifier(request)
        if action_str == RateLimitAction.INCIDENT_CREATE:
            limit = settings.RATE_LIMIT_ANON_INCIDENT_CREATE_MAX
            window_sec = settings.RATE_LIMIT_ANON_INCIDENT_CREATE_WINDOW_SEC
        elif action_str == RateLimitAction.PHOTO_UPLOAD:
            limit = settings.RATE_LIMIT_ANON_PHOTO_UPLOAD_MAX
            window_sec = settings.RATE_LIMIT_ANON_PHOTO_UPLOAD_WINDOW_SEC
        elif action_str == RateLimitAction.PHOTO_RETRIEVE:
            limit = settings.RATE_LIMIT_ANON_PHOTO_RETRIEVE_MAX
            window_sec = settings.RATE_LIMIT_ANON_PHOTO_RETRIEVE_WINDOW_SEC
        else:
            logger.error("Unknown rate limit action requested: %s", action_str)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Unknown rate limit action.",
            )

        key_hash = compute_rate_limit_key_hash(action_str, client_id, namespace="anon")
    else:
        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub.strip():
            logger.warning("Rate limit verification rejected claims with missing or malformed 'sub'.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token missing required subject claim.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        actor_id = sub.strip()
        app_meta = claims.get("app_metadata")
        app_meta_role = app_meta.get("role") if isinstance(app_meta, dict) else ""
        actor_role = (
            claims.get("extracted_role")
            or claims.get("role")
            or app_meta_role
            or ""
        ).strip().lower()

        # Role-based exemptions
        # 1. Citizen incident reporting: Municipal officers, field workers, admins, and system are not throttled.
        if action_str == RateLimitAction.INCIDENT_CREATE:
            if actor_role in (
                "municipal_officer",
                "municipality",
                "municipal_admin",
                "field_worker",
                "worker",
                "admin",
                "super_admin",
                "system",
                "service_role",
            ):
                return

        # 2. Administrative / municipal operations on photo endpoints are not throttled.
        if action_str in (RateLimitAction.PHOTO_UPLOAD, RateLimitAction.PHOTO_RETRIEVE):
            if actor_role in (
                "municipal_officer",
                "municipality",
                "municipal_admin",
                "admin",
                "super_admin",
                "system",
                "service_role",
            ):
                return

        if action_str == RateLimitAction.INCIDENT_CREATE:
            limit = settings.RATE_LIMIT_INCIDENT_CREATE_MAX
            window_sec = settings.RATE_LIMIT_INCIDENT_CREATE_WINDOW_SEC
        elif action_str == RateLimitAction.PHOTO_UPLOAD:
            limit = settings.RATE_LIMIT_PHOTO_UPLOAD_MAX
            window_sec = settings.RATE_LIMIT_PHOTO_UPLOAD_WINDOW_SEC
        elif action_str == RateLimitAction.PHOTO_RETRIEVE:
            limit = settings.RATE_LIMIT_PHOTO_RETRIEVE_MAX
            window_sec = settings.RATE_LIMIT_PHOTO_RETRIEVE_WINDOW_SEC
        else:
            logger.error("Unknown rate limit action requested: %s", action_str)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Unknown rate limit action.",
            )

        key_hash = compute_rate_limit_key_hash(action_str, actor_id, namespace="auth")

    # Partial cloud configuration fail-closed check (RL-AUD-08)
    # If cloud persistence is configured without service-role storage credentials, fail closed.
    # Never silently fall back to in-memory under partial cloud configuration.
    if persistence_repo.is_configured and not persistence_repo.is_storage_configured:
        logger.error(
            "Rate limit check failed closed: Cloud persistence is configured without service-role storage credentials."
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rate limit verification service unavailable.",
        )

    # Persistence dispatch
    use_database = (
        is_production
        or settings.RATE_LIMIT_STORAGE_BACKEND == "database"
        or (settings.RATE_LIMIT_STORAGE_BACKEND == "auto" and persistence_repo.is_storage_configured)
    )

    if use_database:
        if not persistence_repo.is_storage_configured:
            logger.error("Rate limit check failed closed: Database persistence is not configured.")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Rate limit verification service unavailable.",
            )

        try:
            rpc_res = persistence_repo.check_and_increment_rate_limit_sync(
                key_hash=key_hash,
                action=action_str,
                limit=limit,
                window_sec=window_sec,
            )
            if not isinstance(rpc_res, dict):
                raise ValueError("Malformed RPC rate-limit payload: expected JSON object.")
            allowed = rpc_res.get("allowed")
            if not isinstance(allowed, bool):
                raise ValueError("Malformed RPC rate-limit payload: 'allowed' must be a strict boolean.")

            raw_current = rpc_res.get("current_count")
            if isinstance(raw_current, bool) or not isinstance(raw_current, (int, float)):
                raise ValueError("Malformed RPC rate-limit payload: 'current_count' must be a number.")

            raw_limit = rpc_res.get("limit")
            if isinstance(raw_limit, bool) or not isinstance(raw_limit, (int, float)):
                raise ValueError("Malformed RPC rate-limit payload: 'limit' must be a number.")

            raw_remaining = rpc_res.get("remaining")
            if isinstance(raw_remaining, bool) or not isinstance(raw_remaining, (int, float)):
                raise ValueError("Malformed RPC rate-limit payload: 'remaining' must be a number.")

            raw_reset = rpc_res.get("reset_after_sec")
            if isinstance(raw_reset, bool) or not isinstance(raw_reset, (int, float)) or int(raw_reset) < 1:
                raise ValueError("Malformed RPC rate-limit payload: 'reset_after_sec' must be an integer >= 1.")

            raw_retry = rpc_res.get("retry_after_sec")
            if isinstance(raw_retry, bool) or not isinstance(raw_retry, (int, float)):
                raise ValueError("Malformed RPC rate-limit payload: 'retry_after_sec' must be a number.")

            retry_val = int(raw_retry)
            if not allowed and retry_val < 1:
                retry_val = max(1, int(raw_reset))

            result = RateLimitResult(
                allowed=allowed,
                current_count=int(raw_current),
                limit=int(raw_limit),
                remaining=max(0, int(raw_remaining)),
                reset_after_sec=int(raw_reset),
                retry_after_sec=0 if allowed else retry_val,
            )
        except Exception as exc:
            logger.error("Rate limit PostgREST RPC invocation failed: %s", exc.__class__.__name__)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Rate limit verification service unavailable.",
            )
    else:
        # Local development / unit testing fallback
        result = in_memory_rate_limiter.check_and_increment(
            key_hash=key_hash,
            action=action_str,
            limit=limit,
            window_sec=window_sec,
            now_ts=now_ts,
        )

    if not result.allowed:
        retry_after = max(1, result.retry_after_sec)
        logger.warning(
            "Rate limit exceeded for action '%s'. Retry after %s seconds.",
            action_str,
            retry_after,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too Many Requests. Rate limit exceeded.",
            headers={"Retry-After": str(retry_after)},
        )


async def check_rate_limit_async(
    action: str,
    claims: Optional[Dict[str, Any]],
    request: Optional[Request] = None,
    now_ts: Optional[float] = None,
) -> None:
    """
    Asynchronous entry point for rate limiting in async endpoints (RL-AUD-11).
    Offloads synchronous PostgREST RPC network calls to a worker thread via
    anyio.to_thread.run_sync, preventing event-loop starvation during database slowdowns.
    """
    import anyio.to_thread
    await anyio.to_thread.run_sync(check_rate_limit, action, claims, request, now_ts)
