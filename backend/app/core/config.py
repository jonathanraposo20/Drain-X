import base64
import ipaddress
import json
import re
from typing import Literal, Optional
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

AUTHORIZED_VERCEL_PREVIEW_ORIGIN_REGEX = (
    r"^https://drain-x(?:-[a-z0-9-]+)?-jonathanraposo673-4283\.vercel\.app$"
)


class Settings(BaseSettings):
    """
    DRAIN-X Core Application Settings.
    Loaded from environment variables or .env file.
    """
    APP_NAME: str = "DRAIN-X Predictive Drainage Intelligence"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: Literal["development", "production", "testing"] = "development"
    DEBUG: bool = True
    API_V1_PREFIX: str = "/api/v1"

    # System Operational Mode: SIMULATION, PHYSICAL, SAFE_HOLD (or HARDWARE legacy alias)
    SYSTEM_MODE: Literal["SIMULATION", "PHYSICAL", "SAFE_HOLD", "HARDWARE"] = "SIMULATION"

    # Configured safe posture for SAFE_HOLD mode (0.0 deg = fail-safe nominal drainage, no uncommanded actuation)
    SAFE_HOLD_GATE_ANGLE: float = 0.0

    # Server binding
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
    ]
    ADDITIONAL_CORS_ORIGINS: str | None = None  # Comma-separated extra allowed origins for staging/production
    CORS_ORIGIN_REGEX: str | None = None  # Optional strictly anchored HTTPS regex (e.g., AUTHORIZED_VERCEL_PREVIEW_ORIGIN_REGEX)

    # Database & Supabase Cloud Settings (Optional for local operation; falls back to in-memory)
    DATABASE_URL: str | None = None
    SUPABASE_URL: str | None = None
    SUPABASE_KEY: str | None = None  # Anon / Client key
    SUPABASE_SERVICE_ROLE_KEY: str | None = None  # Backend-only privileged key for persistence
    SUPABASE_AUTH_ENABLED: bool = False  # Set to True to enforce JWT authentication on protected routes
    SUPABASE_JWT_SECRET: str | None = None  # Secret for validating legacy/symmetric HS256 Supabase JWT signatures
    SUPABASE_JWKS_CACHE_TTL_SEC: int = 3600  # Cache duration for fetched Supabase Auth JWKS keys
    DEVICE_INGEST_API_KEY: str | None = None  # Optional API key for ESP32/Edge hardware authentication
    PERSISTENCE_TIMEOUT_SEC: float = 3.0  # HTTP timeout for Supabase PostgREST calls

    # MQTT Settings
    MQTT_BROKER_HOST: str = "localhost"
    MQTT_BROKER_PORT: int = 1883
    MQTT_CLIENT_ID: str = "drainx_backend_core"
    MQTT_TOPIC_PREFIX: str = "drainx/v1"

    # Telemetry Ingestion Thresholds (Configurable defaults)
    MAX_WATER_DEPTH_CM: float = 15.0
    CRITICAL_WATER_DEPTH_CM: float = 12.0
    SENSOR_STALE_TIMEOUT_SEC: float = 10.0

    # Live Telemetry Stream Settings (WebSocket / ASGI)
    WS_MAX_CONNECTIONS: int = 100
    WS_CLIENT_QUEUE_SIZE: int = 200
    WS_HEARTBEAT_INTERVAL_SEC: float = 30.0
    STREAM_AUTH_ENABLED: bool = False
    STREAM_AUTH_TOKEN: str | None = None

    # Dedicated Authoritative Incident Stream Settings (Milestone 2B)
    INCIDENT_WS_MAX_CONNECTIONS: int = 100
    INCIDENT_WS_CLIENT_QUEUE_SIZE: int = 100
    INCIDENT_WS_HEARTBEAT_INTERVAL_SEC: float = 15.0
    INCIDENT_WS_REPLAY_BUFFER_SIZE: int = 500

    # Photo Upload Settings (Competition MVP local storage)
    UPLOAD_DIR: str = "uploads/incidents"
    MAX_PHOTO_SIZE_BYTES: int = 5 * 1024 * 1024  # 5 MB
    MAX_PHOTOS_PER_INCIDENT: int = 3
    SUPABASE_STORAGE_BUCKET_INCIDENTS: str = "incident-evidence"
    SUPABASE_STORAGE_SIGNED_URL_EXPIRY_SEC: int = 300

    # Actuator Directive Ledger & Device Session Verification Settings
    ACTUATOR_VERIFICATION_TOLERANCE_DEG: float = 2.0
    ACTUATOR_SETTLING_TIMEOUT_SEC: float = 15.0
    ACTUATOR_VERIFICATION_TIMEOUT_SEC: float = 30.0
    DIRECTIVE_AUDIT_OUTBOX_MAX_SIZE: int = 500
    DIRECTIVE_AUDIT_OUTBOX_RETRY_INTERVAL_SEC: float = 2.0
    PERSISTENCE_CIRCUIT_BREAKER_INITIAL_BACKOFF_SEC: float = 1.0
    PERSISTENCE_CIRCUIT_BREAKER_MAX_BACKOFF_SEC: float = 30.0
    PERSISTENCE_CIRCUIT_BREAKER_BACKOFF_MULTIPLIER: float = 2.0
    PERSISTENCE_CIRCUIT_BREAKER_JITTER_RATIO: float = 0.1
    DEVICE_REBOOT_MIN_CONFIRM_PACKETS: int = 3
    DEVICE_REBOOT_MIN_CONFIRM_SPAN_S: float = 2.0
    DEVICE_REBOOT_CONFIRM_WINDOW_S: float = 20.0
    DEVICE_REBOOT_MAX_PACING_DRIFT_S: float = 4.0
    DEVICE_REBOOT_MIN_BOOT_SHIFT_S: float = 1.5
    DEVICE_REBOOT_MAX_HW_DELAY_S: float = 5.0
    DEVICE_UPTIME_ROLLOVER_WINDOW_MS: int = 300000  # 5 minutes
    DEVICE_SESSION_SEEN_CACHE_SIZE: int = 256

    # Duplicate Incident Detection Settings
    DUPLICATE_DETECTION_ENABLED: bool = True
    DUPLICATE_MAX_DISTANCE_METERS: float = 150.0
    DUPLICATE_RELATED_CATEGORY_MAX_DISTANCE_METERS: float = 75.0
    DUPLICATE_OTHER_CATEGORY_MAX_DISTANCE_METERS: float = 50.0
    DUPLICATE_TIME_WINDOW_SEC: int = 21600  # 6 hours
    DUPLICATE_ALLOW_RELATED_CATEGORIES: bool = True
    DUPLICATE_INCLUDE_RESOLVED: bool = False
    DUPLICATE_MATCH_CITIZEN_WITH_PHYSICAL_SENSOR: bool = True
    DUPLICATE_MIN_CONFIDENCE_SCORE: float = 0.550
    DUPLICATE_MAX_CANDIDATES_PER_INCIDENT: int = 10
    DUPLICATE_SCAN_RECOVERY_INTERVAL_SEC: float = 30.0

    # Automated expired storage-cleanup recovery (Migration 005 infrastructure)
    STORAGE_CLEANUP_RECOVERY_INTERVAL_SEC: float = 300.0
    STORAGE_CLEANUP_RECOVERY_BATCH_SIZE: int = 10

    # Rate Limiting & Abuse Protection Settings
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_INCIDENT_CREATE_MAX: int = 5
    RATE_LIMIT_INCIDENT_CREATE_WINDOW_SEC: int = 15 * 60  # 900 seconds (15 minutes)
    RATE_LIMIT_PHOTO_UPLOAD_MAX: int = 10
    RATE_LIMIT_PHOTO_UPLOAD_WINDOW_SEC: int = 15 * 60     # 900 seconds (15 minutes)
    RATE_LIMIT_PHOTO_RETRIEVE_MAX: int = 60
    RATE_LIMIT_PHOTO_RETRIEVE_WINDOW_SEC: int = 60        # 60 seconds (1 minute)
    RATE_LIMIT_STORAGE_BACKEND: Literal["auto", "database", "memory"] = "auto"

    # Anonymous Rate Limiting Settings (independent from authenticated citizen quotas)
    RATE_LIMIT_ANON_INCIDENT_CREATE_MAX: int = 5
    RATE_LIMIT_ANON_INCIDENT_CREATE_WINDOW_SEC: int = 15 * 60  # 900 seconds (15 minutes)
    RATE_LIMIT_ANON_PHOTO_UPLOAD_MAX: int = 5
    RATE_LIMIT_ANON_PHOTO_UPLOAD_WINDOW_SEC: int = 15 * 60     # 900 seconds (15 minutes)
    RATE_LIMIT_ANON_PHOTO_RETRIEVE_MAX: int = 30
    RATE_LIMIT_ANON_PHOTO_RETRIEVE_WINDOW_SEC: int = 60        # 60 seconds (1 minute)

    # Backend-only HMAC-SHA256 secret pepper for rate-limit key hashing (mandatory >= 16 chars in production)
    RATE_LIMIT_KEY_PEPPER: str | None = None

    # Explicit trusted reverse-proxy CIDR/IP allowlist (empty = ignore X-Forwarded-For/X-Real-IP/Forwarded)
    RATE_LIMIT_TRUSTED_PROXIES: list[str] = []

    @field_validator(
        "DUPLICATE_MAX_DISTANCE_METERS",
        "DUPLICATE_RELATED_CATEGORY_MAX_DISTANCE_METERS",
        "DUPLICATE_OTHER_CATEGORY_MAX_DISTANCE_METERS",
    )
    @classmethod
    def validate_duplicate_distances(cls, v: float) -> float:
        if v <= 0.0:
            raise ValueError("Duplicate distance threshold must be strictly positive.")
        if v > 10_000.0:
            raise ValueError("Duplicate distance threshold is unreasonably large (>10 km).")
        return v

    @field_validator("DUPLICATE_TIME_WINDOW_SEC")
    @classmethod
    def validate_duplicate_time_window(cls, v: int) -> int:
        if v < 60:
            raise ValueError("Duplicate time window must be at least 60 seconds.")
        if v > 86400 * 30:
            raise ValueError("Duplicate time window is unreasonably long (>30 days).")
        return v

    @field_validator("DUPLICATE_MIN_CONFIDENCE_SCORE")
    @classmethod
    def validate_duplicate_confidence(cls, v: float) -> float:
        if v < 0.0 or v > 1.0:
            raise ValueError("Duplicate minimum confidence score must be between 0.0 and 1.0.")
        return v

    @field_validator("DUPLICATE_MAX_CANDIDATES_PER_INCIDENT")
    @classmethod
    def validate_duplicate_max_candidates(cls, v: int) -> int:
        if v < 1 or v > 100:
            raise ValueError("Duplicate max candidates per incident must be between 1 and 100.")
        return v

    @field_validator("DUPLICATE_SCAN_RECOVERY_INTERVAL_SEC")
    @classmethod
    def validate_duplicate_recovery_interval(cls, v: float) -> float:
        if v < 1.0 or v > 3600.0:
            raise ValueError("Duplicate scan recovery interval must be between 1.0 and 3600.0 seconds.")
        return v

    @field_validator("STORAGE_CLEANUP_RECOVERY_INTERVAL_SEC")
    @classmethod
    def validate_storage_cleanup_recovery_interval(cls, v: float) -> float:
        if v < 5.0 or v > 86400.0:
            raise ValueError("Storage cleanup recovery interval must be between 5.0 and 86400.0 seconds.")
        return v

    @field_validator("STORAGE_CLEANUP_RECOVERY_BATCH_SIZE")
    @classmethod
    def validate_storage_cleanup_recovery_batch_size(cls, v: int) -> int:
        if v < 1 or v > 50:
            raise ValueError("Storage cleanup recovery batch size must be between 1 and 50.")
        return v

    @field_validator("INCIDENT_WS_MAX_CONNECTIONS")
    @classmethod
    def validate_incident_ws_max_connections(cls, v: int) -> int:
        if v < 1 or v > 1000:
            raise ValueError("Incident stream max connections must be between 1 and 1000.")
        return v

    @field_validator("INCIDENT_WS_CLIENT_QUEUE_SIZE")
    @classmethod
    def validate_incident_ws_queue_size(cls, v: int) -> int:
        if v < 10 or v > 1000:
            raise ValueError("Incident stream client queue size must be between 10 and 1000.")
        return v

    @field_validator("INCIDENT_WS_HEARTBEAT_INTERVAL_SEC")
    @classmethod
    def validate_incident_ws_heartbeat(cls, v: float) -> float:
        if v < 1.0 or v > 300.0:
            raise ValueError("Incident stream heartbeat interval must be between 1.0 and 300.0 seconds.")
        return v

    @field_validator("INCIDENT_WS_REPLAY_BUFFER_SIZE")
    @classmethod
    def validate_incident_ws_replay_buffer(cls, v: int) -> int:
        if v < 10 or v > 5000:
            raise ValueError("Incident stream replay buffer size must be between 10 and 5000.")
        return v

    @field_validator(
        "RATE_LIMIT_INCIDENT_CREATE_MAX",
        "RATE_LIMIT_PHOTO_UPLOAD_MAX",
        "RATE_LIMIT_PHOTO_RETRIEVE_MAX",
        "RATE_LIMIT_ANON_INCIDENT_CREATE_MAX",
        "RATE_LIMIT_ANON_PHOTO_UPLOAD_MAX",
        "RATE_LIMIT_ANON_PHOTO_RETRIEVE_MAX",
    )
    @classmethod
    def validate_rate_limit_max(cls, v: int) -> int:
        if v < 1:
            raise ValueError("Rate limit maximum requests must be at least 1.")
        if v > 100_000:
            raise ValueError("Rate limit maximum requests is unreasonably high (>100000).")
        return v

    @field_validator(
        "RATE_LIMIT_INCIDENT_CREATE_WINDOW_SEC",
        "RATE_LIMIT_PHOTO_UPLOAD_WINDOW_SEC",
        "RATE_LIMIT_PHOTO_RETRIEVE_WINDOW_SEC",
        "RATE_LIMIT_ANON_INCIDENT_CREATE_WINDOW_SEC",
        "RATE_LIMIT_ANON_PHOTO_UPLOAD_WINDOW_SEC",
        "RATE_LIMIT_ANON_PHOTO_RETRIEVE_WINDOW_SEC",
    )
    @classmethod
    def validate_rate_limit_window(cls, v: int) -> int:
        if v < 1:
            raise ValueError("Rate limit window must be at least 1 second.")
        if v > 86400 * 30:
            raise ValueError("Rate limit window is unreasonably long (>30 days).")
        return v

    @field_validator("CORS_ORIGIN_REGEX")
    @classmethod
    def _validate_cors_origin_regex(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        cleaned = v.strip()
        if not cleaned:
            return None
        if cleaned != AUTHORIZED_VERCEL_PREVIEW_ORIGIN_REGEX:
            raise ValueError(
                "CORS_ORIGIN_REGEX must exactly match the approved DRAIN-X Vercel preview origin pattern."
            )
        return cleaned

    @field_validator("RATE_LIMIT_TRUSTED_PROXIES", mode="before")
    @classmethod
    def validate_trusted_proxies(cls, v: object) -> list[str]:
        if v is None or v == "":
            return []
        if isinstance(v, str):
            raw_items = [item.strip() for item in v.split(",")]
        elif isinstance(v, (list, tuple, set)):
            raw_items = [str(item).strip() for item in v]
        else:
            raise ValueError("RATE_LIMIT_TRUSTED_PROXIES must be a list of CIDR strings or comma-separated string.")

        validated: list[str] = []
        for entry in raw_items:
            if not entry:
                continue
            net = ipaddress.ip_network(entry, strict=False)
            validated.append(str(net))
        return validated

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )


settings = Settings()


def _decode_unverified_jwt_json_segment(segment: str) -> Optional[dict]:
    """Decodes a base64url JWT JSON object segment without signature verification."""
    if not segment:
        return None
    try:
        padded = segment + ("=" * ((4 - len(segment) % 4) % 4))
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        obj = json.loads(decoded.decode("utf-8"))
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def inspect_service_role_credential(
    service_role_key: Optional[str],
    anon_key: Optional[str] = None,
) -> tuple[bool, Optional[str]]:
    """
    Configuration sanity check for SUPABASE_SERVICE_ROLE_KEY.

    Important: When the credential is shaped as a JWT, decoding its payload is ONLY
    a configuration sanity check to catch misplaced anon/authenticated tokens — it
    does NOT verify cryptographic JWT signatures or grant authentication trust.
    Returns (is_valid, sanitized_reason_without_secret_values).
    """
    if service_role_key is not None and not isinstance(service_role_key, str):
        return False, "SUPABASE_SERVICE_ROLE_KEY must be a string."
    if anon_key is not None and not isinstance(anon_key, str):
        anon_clean = ""
    else:
        anon_clean = (anon_key or "").strip()

    sr_clean = (service_role_key or "").strip()
    if not sr_clean:
        return False, "SUPABASE_SERVICE_ROLE_KEY is missing or empty."

    if any(ch.isspace() for ch in sr_clean):
        return False, "SUPABASE_SERVICE_ROLE_KEY must not contain internal whitespace."

    if anon_clean and sr_clean == anon_clean:
        return False, "SUPABASE_SERVICE_ROLE_KEY must not be identical to the anon/public SUPABASE_KEY."

    sr_lower = sr_clean.lower()
    if sr_lower.startswith(("sb_publishable_", "pk_")) or sr_lower in ("anon", "public", "authenticated"):
        return False, "SUPABASE_SERVICE_ROLE_KEY cannot be a publishable or anon/public client credential."

    dot_count = sr_clean.count(".")
    if dot_count == 2:
        header_seg, payload_seg, sig_seg = sr_clean.split(".")
        header_obj = _decode_unverified_jwt_json_segment(header_seg)
        if header_seg.startswith("eyJ") or header_obj is not None:
            if not payload_seg or not sig_seg:
                return False, "SUPABASE_SERVICE_ROLE_KEY appears to be a malformed JWT."
            payload_obj = _decode_unverified_jwt_json_segment(payload_seg)
            if payload_obj is None:
                return False, "SUPABASE_SERVICE_ROLE_KEY appears to be a malformed JWT."
            jwt_role = payload_obj.get("role")
            if jwt_role != "service_role":
                if isinstance(jwt_role, str) and jwt_role:
                    return False, (
                        f"SUPABASE_SERVICE_ROLE_KEY JWT declares role '{jwt_role}' "
                        "(expected 'service_role')."
                    )
                return False, "SUPABASE_SERVICE_ROLE_KEY JWT must declare role 'service_role'."
            return True, None
    elif sr_clean.startswith("eyJ"):
        return False, "SUPABASE_SERVICE_ROLE_KEY appears to be a malformed JWT."

    return True, None


def validate_production_configuration(cfg: Settings) -> None:
    """
    Validates that production environments fail closed if critical
    security, authentication, or persistence parameters are missing.
    Supports either:
    1. Modern asymmetric ES256 via trusted Supabase JWKS (requires SUPABASE_URL).
    2. Legacy symmetric HS256 (requires SUPABASE_JWT_SECRET >= 16 chars).
    """
    if cfg.ENVIRONMENT != "production":
        return

    supabase_url_clean = (cfg.SUPABASE_URL or "").strip()
    service_role_clean = (cfg.SUPABASE_SERVICE_ROLE_KEY or "").strip()
    supabase_key_clean = (cfg.SUPABASE_KEY or "").strip()
    pepper_clean = (cfg.RATE_LIMIT_KEY_PEPPER or "").strip()

    errors = []
    if not cfg.SUPABASE_AUTH_ENABLED:
        errors.append("SUPABASE_AUTH_ENABLED must be True in production.")
    if not cfg.DEVICE_INGEST_API_KEY or len(cfg.DEVICE_INGEST_API_KEY.strip()) < 8:
        errors.append("DEVICE_INGEST_API_KEY must be configured with at least 8 characters in production.")
    if not supabase_url_clean:
        errors.append("SUPABASE_URL must be configured in production.")
    if not service_role_clean and not supabase_key_clean:
        errors.append("SUPABASE_SERVICE_ROLE_KEY or SUPABASE_KEY must be configured in production.")

    # JWT Verification validation: Must have either SUPABASE_URL (for ES256 JWKS) or SUPABASE_JWT_SECRET (for HS256)
    has_jwks_provider = bool(supabase_url_clean.startswith("https://"))
    has_hs256_secret = bool(cfg.SUPABASE_JWT_SECRET and len(cfg.SUPABASE_JWT_SECRET.strip()) >= 16)

    if not has_jwks_provider and not has_hs256_secret:
        errors.append(
            "Production JWT verification requires either a valid HTTPS SUPABASE_URL (for ES256 JWKS) "
            "or a SUPABASE_JWT_SECRET with at least 16 characters (for HS256)."
        )

    # Production rate-limiting invariants (validated unconditionally regardless of RATE_LIMIT_ENABLED)
    if not cfg.RATE_LIMIT_ENABLED:
        errors.append("RATE_LIMIT_ENABLED must be True in production.")
    if cfg.RATE_LIMIT_STORAGE_BACKEND == "memory":
        errors.append(
            "RATE_LIMIT_STORAGE_BACKEND='memory' is unsafe and prohibited in production; "
            "must use shared database store."
        )
    if not supabase_url_clean or not service_role_clean:
        errors.append(
            "Production rate limiting requires non-empty SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY "
            "(anon SUPABASE_KEY cannot satisfy service-role rate-limit persistence)."
        )
    if service_role_clean:
        sr_valid, sr_reason = inspect_service_role_credential(service_role_clean, supabase_key_clean)
        if not sr_valid:
            errors.append(f"Invalid SUPABASE_SERVICE_ROLE_KEY in production: {sr_reason}")
    if len(pepper_clean) < 16:
        errors.append(
            "RATE_LIMIT_KEY_PEPPER must be configured with at least 16 non-whitespace characters in production."
        )

    if errors:
        error_msg = "FATAL PRODUCTION CONFIGURATION FAIL-CLOSED ERROR:\n - " + "\n - ".join(errors)
        raise RuntimeError(error_msg)

