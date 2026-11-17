"""
DRAIN-X Authentication, Authorization, and Security Controls.

Milestones:
- P0.6.1 Cloud Provisioning & Security Validation
- P0.6.2.1 Authenticated Role-Based RLS Verification
- P0.7.1 Supabase JWT Verification Hardening (ES256 JWKS & HS256)

Security Principles Enforced:
1. Least Privilege & Fail-Closed:
   - In production (`ENVIRONMENT == 'production'`), unauthenticated requests or
     missing cryptographic verification keys immediately fail-closed with 401 / 500 responses.
   - Development bypasses are strictly disabled in production.
2. Device Authentication:
   - Authenticates physical IoT edge nodes (ESP32) on telemetry ingestion endpoints
     using `X-Device-Key`.
3. Cryptographic Supabase JWT Verification:
   - Modern Supabase ES256 tokens: Cryptographically verified using trusted JWKS
     fetched exclusively from `{SUPABASE_URL}/auth/v1/.well-known/jwks.json`.
   - Never loads arbitrary URLs from token headers (anti-SSRF / anti-key-spoofing).
   - Legacy/Symmetric HS256 tokens: Cryptographically verified with `SUPABASE_JWT_SECRET`
     when configured.
   - Strict algorithm allowlisting: ONLY "ES256" and "HS256" permitted; "none", "RS256",
     "RS512", etc. are rejected immediately with 401.
   - Expiration (`exp`), audience (`aud` if present), and issuer (`iss` if present) validation.
4. Role Integrity (Anti-Privilege Escalation):
   - Trusted user roles MUST originate from `app_metadata.role` (managed securely by
     backend/admin) or PostgreSQL role `service_role`.
   - Client-controlled `user_metadata` is EXPLICITLY REJECTED for role decisions to
     prevent self-escalation by authenticated users.
"""

import base64
import hashlib
import hmac
import json
import logging
import time
from typing import Any, Dict, List, Optional
import httpx
import jwt
from jwt.exceptions import PyJWTError, ExpiredSignatureError, InvalidSignatureError, InvalidIssuerError, InvalidAudienceError
from fastapi import Header, HTTPException, status, Depends
from app.core.config import settings

logger = logging.getLogger("drainx.security")

# Allowed algorithms set
ALLOWED_ALGORITHMS = ["ES256", "HS256"]

# Allowed audience values
ALLOWED_AUDIENCES = ["authenticated", "drainx"]

# In-memory JWKS cache: { "jwk_set": PyJWKSet, "fetched_at": float, "supabase_url": str }
_JWKS_CACHE: Dict[str, Any] = {
    "jwk_set": None,
    "fetched_at": 0.0,
    "supabase_url": None,
}


def clear_jwks_cache() -> None:
    """Helper for tests to invalidate the in-memory JWKS cache."""
    global _JWKS_CACHE
    _JWKS_CACHE = {
        "jwk_set": None,
        "fetched_at": 0.0,
        "supabase_url": None,
    }


def set_in_memory_jwks(jwks_data: Dict[str, Any], base_url: Optional[str] = None) -> None:
    """Helper for testing or offline injection of trusted JWKS keys."""
    global _JWKS_CACHE
    jwk_set = jwt.PyJWKSet.from_dict(jwks_data)
    _JWKS_CACHE = {
        "jwk_set": jwk_set,
        "fetched_at": time.time(),
        "supabase_url": (base_url or settings.SUPABASE_URL or "").rstrip("/"),
    }


async def verify_device_key(
    x_device_key: Optional[str] = Header(default=None, alias="X-Device-Key")
) -> Optional[str]:
    """
    Validates edge hardware device authentication.
    Used on `/api/v1/telemetry/ingest`.
    """
    configured_key = settings.DEVICE_INGEST_API_KEY
    is_prod = (settings.ENVIRONMENT == "production")

    if is_prod:
        # In production, device authentication is strictly mandatory (Fail-Closed)
        if not configured_key:
            logger.error("FATAL: In production mode, DEVICE_INGEST_API_KEY must be configured.")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Production configuration error: DEVICE_INGEST_API_KEY is not configured.",
            )
        if not x_device_key or not hmac.compare_digest(x_device_key, configured_key):
            logger.warning("Production telemetry ingestion rejected: invalid or missing X-Device-Key")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing X-Device-Key authentication header.",
                headers={"WWW-Authenticate": "ApiKey"},
            )
        return x_device_key

    # In development mode:
    if configured_key:
        if not x_device_key or not hmac.compare_digest(x_device_key, configured_key):
            logger.warning("Development telemetry ingestion rejected: invalid or missing X-Device-Key")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing X-Device-Key authentication header.",
                headers={"WWW-Authenticate": "ApiKey"},
            )
        return x_device_key

    # Open ingestion permitted in development/bench mode when key is unconfigured
    logger.debug("[DEV_MODE_SECURITY_BYPASS] Telemetry ingested without X-Device-Key authentication.")
    return x_device_key


def _get_jwks_url() -> Optional[str]:
    """
    Derives trusted JWKS endpoint strictly from configured SUPABASE_URL.
    Never accepts arbitrary endpoints from client headers.
    """
    if not settings.SUPABASE_URL:
        return None
    base_url = settings.SUPABASE_URL.rstrip("/")
    return f"{base_url}/auth/v1/.well-known/jwks.json"


def _fetch_trusted_jwk_set() -> Optional[jwt.PyJWKSet]:
    """
    Fetches and caches the trusted JWKS set from the configured Supabase URL.
    Returns PyJWKSet or None if unavailable/unconfigured.
    """
    global _JWKS_CACHE
    jwks_url = _get_jwks_url()
    if not jwks_url:
        return None

    now = time.time()
    cache_ttl = settings.SUPABASE_JWKS_CACHE_TTL_SEC
    cached_url = _JWKS_CACHE.get("supabase_url")

    # If valid in cache, return immediately
    if (
        _JWKS_CACHE.get("jwk_set") is not None
        and cached_url == settings.SUPABASE_URL.rstrip("/")
        and (now - _JWKS_CACHE.get("fetched_at", 0.0)) < cache_ttl
    ):
        return _JWKS_CACHE["jwk_set"]

    # Fetch from trusted endpoint
    try:
        with httpx.Client(timeout=settings.PERSISTENCE_TIMEOUT_SEC) as client:
            resp = client.get(jwks_url)
            if resp.status_code == 200:
                jwks_data = resp.json()
                jwk_set = jwt.PyJWKSet.from_dict(jwks_data)
                _JWKS_CACHE = {
                    "jwk_set": jwk_set,
                    "fetched_at": now,
                    "supabase_url": settings.SUPABASE_URL.rstrip("/"),
                }
                logger.info(f"Successfully refreshed Supabase JWKS from {jwks_url}")
                return jwk_set
            else:
                logger.warning(f"Failed to fetch JWKS from {jwks_url}: HTTP {resp.status_code}")
    except Exception as exc:
        logger.warning(f"Error fetching Supabase JWKS from {jwks_url}: {exc}")

    # Fallback to existing cached set if available despite network error
    if _JWKS_CACHE.get("jwk_set") is not None:
        logger.warning("Using stale in-memory JWKS cache due to fetch failure.")
        return _JWKS_CACHE["jwk_set"]

    return None


def verify_supabase_jwt(token: str) -> Dict[str, Any]:
    """
    Cryptographically verifies a Supabase JWT token.
    Enforces:
    - Strict algorithm allowlisting (ES256, HS256).
    - Cryptographic signature check (JWKS for ES256, SUPABASE_JWT_SECRET for HS256).
    - Audience validation (if aud is present, must be in ALLOWED_AUDIENCES).
    - Expiration (exp) validation.
    - Mandatory exact issuer validation against configured Supabase auth issuer.
    - Anti-privilege escalation (app_metadata only, never user_metadata).
    """
    try:
        unverified_headers = jwt.get_unverified_header(token)
    except Exception as exc:
        logger.warning(f"Malformed JWT header: {exc}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed authentication token or invalid signature.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    alg = unverified_headers.get("alg")
    kid = unverified_headers.get("kid")

    # 1. Strict algorithm allowlisting
    if alg not in ALLOWED_ALGORITHMS:
        logger.warning(f"Rejected unsupported JWT algorithm: {alg}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unsupported token algorithm '{alg}'. Only {ALLOWED_ALGORITHMS} are permitted.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload: Dict[str, Any] = {}

    # 2. Cryptographic signature check based on algorithm
    if alg == "ES256":
        jwk_set = _fetch_trusted_jwk_set()
        if not jwk_set:
            if settings.ENVIRONMENT == "production":
                logger.error("FATAL: In production, trusted Supabase JWKS could not be fetched for ES256 validation.")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Production configuration error: Trusted JWKS provider is unavailable.",
                )
            else:
                logger.warning("JWKS provider unavailable in development. Token rejected.")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Cryptographic verification failed: JWKS public keys are unavailable.",
                    headers={"WWW-Authenticate": "Bearer"},
                )

        if not kid:
            logger.warning("Rejected ES256 JWT: missing 'kid' in header.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token header missing required 'kid' for asymmetric verification.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        try:
            jwk_key = jwk_set[kid]
            signing_key = jwk_key.key
        except KeyError:
            logger.warning(f"Rejected ES256 JWT: unknown kid '{kid}'.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Token signed by unknown key id '{kid}'.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        try:
            payload = jwt.decode(
                token,
                signing_key,
                algorithms=["ES256"],
                options={"verify_signature": True, "verify_exp": True, "verify_aud": False, "verify_iss": False},
            )
        except ExpiredSignatureError:
            logger.warning("Rejected expired ES256 JWT token.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication token has expired.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except InvalidSignatureError:
            logger.warning("Rejected ES256 JWT with invalid cryptographic signature.")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token signature.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        except PyJWTError as jwt_err:
            logger.warning(f"Rejected ES256 JWT decoding error: {jwt_err}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Token validation failed: {jwt_err}",
                headers={"WWW-Authenticate": "Bearer"},
            )

    elif alg == "HS256":
        secret = settings.SUPABASE_JWT_SECRET
        if not secret:
            if settings.ENVIRONMENT == "production":
                logger.error("FATAL: In production, SUPABASE_JWT_SECRET must be configured for HS256 validation.")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Production configuration error: Token validation secret is missing for HS256.",
                )
            logger.error("HS256 token rejected: SUPABASE_JWT_SECRET is not configured.")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Authentication configuration error: JWT verification secret is unavailable.",
            )
        else:
            try:
                payload = jwt.decode(
                    token,
                    secret,
                    algorithms=["HS256"],
                    options={"verify_signature": True, "verify_exp": True, "verify_aud": False, "verify_iss": False},
                )
            except ExpiredSignatureError:
                logger.warning("Rejected expired HS256 JWT token.")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication token has expired.",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            except InvalidSignatureError:
                logger.warning("Rejected HS256 JWT with invalid cryptographic signature.")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token signature.",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            except PyJWTError as jwt_err:
                logger.warning(f"Rejected HS256 JWT decoding error: {jwt_err}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Token validation failed: {jwt_err}",
                    headers={"WWW-Authenticate": "Bearer"},
                )

    # 3. Audience validation (if present)
    aud = payload.get("aud")
    if aud:
        aud_list = aud if isinstance(aud, list) else [aud]
        if not any(a in ALLOWED_AUDIENCES for a in aud_list):
            logger.warning(f"Rejected JWT with invalid audience: {aud}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Token audience '{aud}' is not authorized for this platform.",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # 4. Mandatory exact issuer validation (fail closed)
    configured_supabase_url = settings.SUPABASE_URL
    iss = payload.get("iss")
    if not isinstance(configured_supabase_url, str) or not configured_supabase_url.strip():
        logger.error("JWT issuer validation failed: SUPABASE_URL is not configured.")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication configuration error: Supabase URL is missing.",
        )

    expected_iss = f"{configured_supabase_url.rstrip('/')}/auth/v1"
    if not isinstance(iss, str) or not iss.strip() or iss != expected_iss:
        logger.warning("Rejected JWT with missing, malformed, or mismatched issuer.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token issuer does not match the configured Supabase auth issuer.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 5. Required Subject Claim Validation
    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject.strip():
        logger.warning("Rejected JWT without a valid subject claim.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing required subject claim.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 6. Role Integrity Check (Anti-Privilege Escalation)
    # Strictly reject inspecting user_metadata: end-users can edit user_metadata!
    if payload.get("role") == "service_role":
        trusted_role = "service_role"
        trusted_team = None
    else:
        app_meta = payload.get("app_metadata")
        if isinstance(app_meta, dict):
            trusted_role = app_meta.get("role", "citizen")
            trusted_team = app_meta.get("team") or app_meta.get("assigned_team")
        else:
            trusted_role = "citizen"
            trusted_team = None

    payload["extracted_role"] = trusted_role
    payload["extracted_team"] = trusted_team
    return payload


async def get_current_user_claims(
    authorization: Optional[str] = Header(default=None)
) -> Dict[str, Any]:
    """
    Extracts and validates Supabase JWT token claims.
    """
    is_prod = (settings.ENVIRONMENT == "production")

    if not settings.SUPABASE_AUTH_ENABLED:
        logger.error("Authentication is disabled; protected endpoint access denied.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication is disabled. Protected endpoints are unavailable.",
        )

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header. Expected Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization.split(" ", 1)[1].strip()
    return verify_supabase_jwt(token)


async def get_optional_user_claims(
    authorization: Optional[str] = Header(default=None)
) -> Optional[Dict[str, Any]]:
    """
    Extracts and validates Supabase JWT token claims if Authorization header is provided.
    Returns None for unauthenticated public clients.
    Raises HTTPException 401 if Authorization header is present but malformed, expired, or invalid.
    """
    if not authorization:
        return None

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header. Expected Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header. Expected Bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return verify_supabase_jwt(token)


def require_roles(allowed_roles: List[str]):
    """
    FastAPI dependency factory enforcing role-based access control.
    """
    async def role_checker(claims: Dict[str, Any] = Depends(get_current_user_claims)) -> Dict[str, Any]:
        user_role = claims.get("extracted_role", "citizen")
        if user_role not in allowed_roles:
            logger.warning(
                f"Access forbidden: User with trusted role '{user_role}' attempted access to route requiring {allowed_roles}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation requires one of the following roles: {allowed_roles}",
            )
        return claims

    return role_checker
