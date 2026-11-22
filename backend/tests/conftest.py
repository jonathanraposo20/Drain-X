
import io
import time
from datetime import datetime, timezone

import jwt
import pytest
from PIL import Image
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings
from app.services.state_store import state_store, StateStore


TEST_SUPABASE_URL = "https://test-project.supabase.co"
TEST_JWT_SECRET = "drainx-test-secret-for-unit-tests-only-2026"


def create_test_image(format="JPEG", color="blue", size=(10, 10)) -> bytes:
    """Generates valid synthetic image bytes for testing."""
    buf = io.BytesIO()
    mode = "RGB" if format.upper() == "JPEG" else "RGBA"
    img = Image.new(mode, size, color=color)
    img.save(buf, format=format)
    return buf.getvalue()


def create_test_token(role="admin", subject="test-admin"):
    """Create a cryptographically signed test JWT."""
    now = int(time.time())

    payload = {
        "sub": subject,
        "iss": f"{TEST_SUPABASE_URL}/auth/v1",
        "aud": "authenticated",
        "iat": now,
        "exp": now + 3600,
        "role": "authenticated",
        "app_metadata": {
            "role": role,
        },
        "user_metadata": {},
    }

    return jwt.encode(payload, TEST_JWT_SECRET, algorithm="HS256")


@pytest.fixture
def sample_jpeg_bytes():
    return create_test_image("JPEG")


@pytest.fixture
def sample_png_bytes():
    return create_test_image("PNG")


@pytest.fixture(autouse=True)
def reset_state_store(monkeypatch, tmp_path):
    """Reset application state and fully isolate global persistence repository and audit ledger."""
    from app.services.persistence_repository import persistence_repo
    from app.services.rate_limiter import in_memory_rate_limiter

    def _reset_persistence_repo():
        persistence_repo._in_memory_records.clear()
        persistence_repo._mode_history_records.clear()
        persistence_repo._in_memory_devices = {
            "DRAINX-ESP32-NODE-01": {
                "device_id": "DRAINX-ESP32-NODE-01",
                "name": "Primary Flume ESP32 Node",
                "hardware_model": "ESP32 DevKit V1 (ESP-WROOM-32)",
                "firmware_version": "0.3.7-p0.3g",
                "is_active": True,
                "validation_stage": "CONNECTIVITY_READY",
                "last_seen_at": datetime.now(timezone.utc).isoformat(),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "metadata": {"location": "Flume Primary Sump"},
            }
        }
        persistence_repo._total_persisted_count = 0
        persistence_repo._failed_persistence_count = 0
        persistence_repo._last_persistence_error = None
        persistence_repo._connection_status = "UNCONFIGURED"
        persistence_repo._last_ping_ms = None

    # Prevent tests from contacting Supabase unless they explicitly enable and mock cloud persistence.
    monkeypatch.setattr(persistence_repo, "_is_configured", False)
    monkeypatch.setattr(settings, "RATE_LIMIT_STORAGE_BACKEND", "memory")
    in_memory_rate_limiter.clear()

    # Isolate durable audit journal to temporary storage so tests never pollute or delete real audit files.
    test_audit_path = tmp_path / "test_incident_audits.jsonl"
    monkeypatch.setenv("DRAINX_AUDIT_LOG_PATH", str(test_audit_path))
    monkeypatch.setattr(state_store._audit_durability, "_file_path", test_audit_path)
    state_store._audit_durability._known_audit_ids.clear()

    # Clear in-memory state and repository buffers
    with state_store._lock:
        state_store._incident_audits.clear()
    state_store.clear()
    state_store.set_mode("SIMULATION", reason="Test reset")
    _reset_persistence_repo()

    yield

    in_memory_rate_limiter.clear()
    with state_store._lock:
        state_store._incident_audits.clear()
    state_store.clear()
    state_store.set_mode("SIMULATION", reason="Test teardown")
    state_store._audit_durability._known_audit_ids.clear()
    _reset_persistence_repo()


@pytest.fixture
def client():
    """Unauthenticated client for public and authentication tests."""
    return TestClient(app)


@pytest.fixture
def admin_client(monkeypatch):
    """Authenticated test client with a trusted admin JWT."""
    monkeypatch.setattr(settings, "SUPABASE_AUTH_ENABLED", True)
    monkeypatch.setattr(settings, "SUPABASE_JWT_SECRET", TEST_JWT_SECRET)
    monkeypatch.setattr(settings, "SUPABASE_URL", TEST_SUPABASE_URL)

    token = create_test_token(role="admin")

    return TestClient(
        app,
        headers={"Authorization": f"Bearer {token}"},
    )


@pytest.fixture
def isolated_state_store():
    """An isolated state store instance for testing."""
    return StateStore()

