from typing import Literal
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

    errors = []
    if not cfg.SUPABASE_AUTH_ENABLED:
        errors.append("SUPABASE_AUTH_ENABLED must be True in production.")
    if not cfg.DEVICE_INGEST_API_KEY or len(cfg.DEVICE_INGEST_API_KEY.strip()) < 8:
        errors.append("DEVICE_INGEST_API_KEY must be configured with at least 8 characters in production.")
    if not cfg.SUPABASE_URL:
        errors.append("SUPABASE_URL must be configured in production.")
    if not cfg.SUPABASE_SERVICE_ROLE_KEY and not cfg.SUPABASE_KEY:
        errors.append("SUPABASE_SERVICE_ROLE_KEY or SUPABASE_KEY must be configured in production.")

    # JWT Verification validation: Must have either SUPABASE_URL (for ES256 JWKS) or SUPABASE_JWT_SECRET (for HS256)
    has_jwks_provider = bool(cfg.SUPABASE_URL and cfg.SUPABASE_URL.strip().startswith("https://"))
    has_hs256_secret = bool(cfg.SUPABASE_JWT_SECRET and len(cfg.SUPABASE_JWT_SECRET.strip()) >= 16)

    if not has_jwks_provider and not has_hs256_secret:
        errors.append(
            "Production JWT verification requires either a valid HTTPS SUPABASE_URL (for ES256 JWKS) "
            "or a SUPABASE_JWT_SECRET with at least 16 characters (for HS256)."
        )

    if errors:
        error_msg = "FATAL PRODUCTION CONFIGURATION FAIL-CLOSED ERROR:\n - " + "\n - ".join(errors)
        raise RuntimeError(error_msg)

