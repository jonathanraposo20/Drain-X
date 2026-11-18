
import io
import time

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
def reset_state_store(monkeypatch):
    """Reset application state and isolate the global persistence repository."""
    from app.services.persistence_repository import persistence_repo

    # Prevent tests from contacting Supabase unless they explicitly enable
    # and mock cloud persistence.
    monkeypatch.setattr(persistence_repo, "_is_configured", False)

    # Clear repository buffers between tests.
    persistence_repo._in_memory_records.clear()
    persistence_repo._mode_history_records.clear()

    state_store.clear()
    state_store.set_mode("SIMULATION", reason="Test reset")

    yield

    state_store.clear()
    state_store.set_mode("SIMULATION", reason="Test teardown")

    persistence_repo._in_memory_records.clear()
    persistence_repo._mode_history_records.clear()


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

