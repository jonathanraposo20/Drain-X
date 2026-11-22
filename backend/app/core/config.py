import ipaddress
from typing import Literal
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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

    # Photo Upload Settings (Competition MVP local storage)
    UPLOAD_DIR: str = "uploads/incidents"
    MAX_PHOTO_SIZE_BYTES: int = 5 * 1024 * 1024  # 5 MB
    MAX_PHOTOS_PER_INCIDENT: int = 3
    SUPABASE_STORAGE_BUCKET_INCIDENTS: str = "incident-evidence"
    SUPABASE_STORAGE_SIGNED_URL_EXPIRY_SEC: int = 300

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
    if len(pepper_clean) < 16:
        errors.append(
            "RATE_LIMIT_KEY_PEPPER must be configured with at least 16 non-whitespace characters in production."
        )

    if errors:
        error_msg = "FATAL PRODUCTION CONFIGURATION FAIL-CLOSED ERROR:\n - " + "\n - ".join(errors)
        raise RuntimeError(error_msg)

