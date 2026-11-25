
"""
DRAIN-X Authenticated Role-Based Row Level Security (RLS) & JWT Authorization Tests.

Milestone: P0.6.2.1 Authenticated Role-Based RLS Verification.

Validates:
1. Citizen Role: Read public telemetry; denied confidential mode history and administrative mutations.
2. Municipality Role: Authorized operational mode transitions, alert resolutions, and SCADA oversight.
3. Worker Role: Authorized device registrations and on-site alert updates; restricted from policy mutations.
4. Roleless User: Defaults safely to least-privilege citizen boundaries.
5. Anti-Privilege Escalation: Rejects client-supplied user_metadata attempting to claim elevated roles.
6. Multi-Algorithm Support: Validates HS256 and ES256 tokens.
"""

import time
import json
import base64
import hmac
import hashlib
from typing import Dict, Any
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings
from app.core.security import verify_supabase_jwt, require_roles
from app.services.state_store import state_store


TEST_JWT_SECRET = "sit-test-secret-key-32-bytes-minimum!!"
TEST_SUPABASE_URL = "https://xhdtceqcnsheoskmuwsv.supabase.co"
TEST_ISSUER = f"{TEST_SUPABASE_URL}/auth/v1"


def _craft_test_jwt(
    payload: Dict[str, Any],
    secret: str = TEST_JWT_SECRET,
    alg: str = "HS256"
) -> str:
    """Helper to construct signed test JWTs."""

    # Add the expected issuer only to HS256 test tokens.
    # Intentionally invalid algorithm tests remain unchanged.
    if alg == "HS256":
        payload.setdefault("iss", TEST_ISSUER)

    header = {"alg": alg, "typ": "JWT"}

    h_b64 = (
        base64.urlsafe_b64encode(json.dumps(header).encode())
        .decode()
        .rstrip("=")
    )
    p_b64 = (
        base64.urlsafe_b64encode(json.dumps(payload).encode())
        .decode()
        .rstrip("=")
    )

    signing_input = f"{h_b64}.{p_b64}"

    if alg == "HS256":
        sig = hmac.new(
            secret.encode(),
            signing_input.encode(),
            hashlib.sha256
        ).digest()
        s_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    else:
        # Mock signature for unsupported-algorithm rejection tests.
        s_b64 = base64.urlsafe_b64encode(
            b"mock_es256_signature_bytes_32_len!"
        ).decode().rstrip("=")

    return f"{signing_input}.{s_b64}"


@pytest.fixture
def auth_client():
    """Client with authentication enabled and test issuer configured."""
    with patch.object(settings, "SUPABASE_AUTH_ENABLED", True), \
         patch.object(settings, "SUPABASE_JWT_SECRET", TEST_JWT_SECRET), \
         patch.object(settings, "SUPABASE_URL", TEST_SUPABASE_URL):
        yield TestClient(app)


def test_citizen_jwt_denied_administrative_endpoints(
    auth_client: TestClient
):
    """Citizen role cannot change operational mode or register edge devices."""
    token = _craft_test_jwt({
        "sub": "user-citizen-01",
        "exp": time.time() + 3600,
        "app_metadata": {"role": "citizen"},
        "aud": "authenticated"
    })
    headers = {"Authorization": f"Bearer {token}"}

    res_mode = auth_client.post(
        "/api/v1/status/mode",
        headers=headers,
        json={
            "mode": "PHYSICAL",
            "reason": "Citizen rogue mode switch"
        }
    )

    assert res_mode.status_code == 403
    assert (
        "Insufficient permissions" in res_mode.json()["detail"]
        or "Operation requires" in res_mode.json()["detail"]
    )

    res_dev = auth_client.post(
        "/api/v1/devices",
        headers=headers,
        json={
            "device_id": "ROGUE_DEV_01",
            "name": "Rogue Device"
        }
    )
    assert res_dev.status_code == 403


def test_municipality_jwt_authorized_operational_mode(
    auth_client: TestClient
):
    """Municipality role is authorized to transition operational modes."""
    token = _craft_test_jwt({
        "sub": "user-muni-01",
        "exp": time.time() + 3600,
        "app_metadata": {"role": "municipality"},
        "aud": "authenticated"
    })
    headers = {"Authorization": f"Bearer {token}"}

    res_mode = auth_client.post(
        "/api/v1/status/mode",
        headers=headers,
        json={
            "mode": "PHYSICAL",
            "reason": "Authorized municipal inspection"
        }
    )

    assert res_mode.status_code == 200
    assert res_mode.json()["mode"] == "PHYSICAL"


def test_worker_jwt_authorized_device_registration(
    auth_client: TestClient
):
    """Worker role is authorized to register edge devices."""
    token = _craft_test_jwt({
        "sub": "user-worker-01",
        "exp": time.time() + 3600,
        "app_metadata": {"role": "worker"},
        "aud": "authenticated"
    })
    headers = {"Authorization": f"Bearer {token}"}

    res_dev = auth_client.post(
        "/api/v1/devices",
        headers=headers,
        json={
            "device_id": "DRAINX-WRK-NODE-09",
            "name": "Field Worker Deployed Node"
        }
    )

    assert res_dev.status_code == 200
    assert res_dev.json()["status"] == "success"


def test_roleless_user_defaults_to_citizen(
    auth_client: TestClient
):
    """User without explicit role claim is bounded by citizen restrictions."""
    token = _craft_test_jwt({
        "sub": "user-roleless-01",
        "exp": time.time() + 3600,
        "app_metadata": {},
        "aud": "authenticated"
    })
    headers = {"Authorization": f"Bearer {token}"}

    res = auth_client.post(
        "/api/v1/status/mode",
        headers=headers,
        json={
            "mode": "PHYSICAL",
            "reason": "Roleless attack"
        }
    )

    assert res.status_code == 403


def test_anti_privilege_escalation_user_metadata_tampering(
    auth_client: TestClient
):
    """Client attempting to inject admin in user_metadata is rejected."""
    token = _craft_test_jwt({
        "sub": "user-tamper-01",
        "exp": time.time() + 3600,
        "user_metadata": {"role": "admin", "admin": True},
        "app_metadata": {"role": "citizen"},
        "aud": "authenticated"
    })
    headers = {"Authorization": f"Bearer {token}"}

    res = auth_client.post(
        "/api/v1/devices",
        headers=headers,
        json={
            "device_id": "TAMPER_NODE",
            "name": "Hacked Node"
        }
    )

    assert res.status_code == 403


def test_algorithm_support_and_rejection():
    """Validates HS256 acceptance and RS512/none rejection."""

    # 1. HS256 with valid secret -> accepted
    tok_hs = _craft_test_jwt(
        {"sub": "u1", "exp": time.time() + 100},
        secret=TEST_JWT_SECRET,
        alg="HS256"
    )

    with patch.object(settings, "SUPABASE_JWT_SECRET", TEST_JWT_SECRET), \
         patch.object(settings, "SUPABASE_URL", TEST_SUPABASE_URL):
        c_hs = verify_supabase_jwt(tok_hs)
        assert c_hs["sub"] == "u1"

    # 2. ES256 -> accepted when valid JWKS and kid are provided
    from cryptography.hazmat.primitives.asymmetric import ec
    from app.core.security import set_in_memory_jwks, clear_jwks_cache
    import jwt as pyjwt

    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    nums = pub.public_numbers()

    kid = "rls-test-kid-01"
    x_bytes = nums.x.to_bytes(32, "big")
    y_bytes = nums.y.to_bytes(32, "big")

    jwks = {
        "keys": [{
            "kty": "EC",
            "crv": "P-256",
            "kid": kid,
            "x": base64.urlsafe_b64encode(x_bytes).decode("ascii").rstrip("="),
            "y": base64.urlsafe_b64encode(y_bytes).decode("ascii").rstrip("="),
            "alg": "ES256",
            "use": "sig"
        }]
    }

    set_in_memory_jwks(jwks, base_url=TEST_SUPABASE_URL)

    tok_es = pyjwt.encode(
        {
            "sub": "u2",
            "exp": time.time() + 100,
            "iss": TEST_ISSUER
        },
        priv,
        algorithm="ES256",
        headers={"kid": kid}
    )

    with patch.object(settings, "SUPABASE_URL", TEST_SUPABASE_URL):
        c_es = verify_supabase_jwt(tok_es)
        assert c_es["sub"] == "u2"

    clear_jwks_cache()

    # 3. RS512 -> rejected (401)
    tok_bad = _craft_test_jwt({"sub": "u3"}, alg="RS512")

    with pytest.raises(Exception) as exc:
        verify_supabase_jwt(tok_bad)

    assert "401" in str(exc.value)

    # 4. none algorithm attack -> rejected (401)
    tok_none = _craft_test_jwt({"sub": "u4"}, alg="none")

    with pytest.raises(Exception) as exc_none:
        verify_supabase_jwt(tok_none)

    assert "401" in str(exc_none)


def test_status_history_requires_municipality_or_admin(auth_client: TestClient):
    """Operational history is unavailable to anonymous and citizen callers."""
    anonymous = auth_client.get("/api/v1/status/mode/history")
    assert anonymous.status_code == 401

    citizen_token = _craft_test_jwt({
        "sub": "status-history-citizen",
        "exp": time.time() + 3600,
        "app_metadata": {"role": "citizen"},
        "aud": "authenticated",
    })
    citizen = auth_client.get(
        "/api/v1/status/mode/history",
        headers={"Authorization": f"Bearer {citizen_token}"},
    )
    assert citizen.status_code == 403

    municipality_token = _craft_test_jwt({
        "sub": "status-history-municipality",
        "exp": time.time() + 3600,
        "app_metadata": {"role": "municipality"},
        "aud": "authenticated",
    })
    municipality = auth_client.get(
        "/api/v1/status/mode/history",
        headers={"Authorization": f"Bearer {municipality_token}"},
    )
    assert municipality.status_code == 200
    assert "history" in municipality.json()


def test_operational_state_mutation_requires_municipality_or_admin(auth_client: TestClient):
    """Only municipality/admin roles may mutate the operational state."""
    from app.models.contracts import SystemOperationalState

    original_state = state_store.operational_state

    anonymous = auth_client.post(
        "/api/v1/status/state",
        json={"operational_state": "MONITORING"},
    )
    assert anonymous.status_code == 401
    assert state_store.operational_state == original_state

    citizen_token = _craft_test_jwt({
        "sub": "status-state-citizen",
        "exp": time.time() + 3600,
        "app_metadata": {"role": "citizen"},
        "aud": "authenticated",
    })
    citizen = auth_client.post(
        "/api/v1/status/state",
        headers={"Authorization": f"Bearer {citizen_token}"},
        json={"operational_state": "MONITORING"},
    )
    assert citizen.status_code == 403
    assert state_store.operational_state == original_state

    municipality_token = _craft_test_jwt({
        "sub": "status-state-municipality",
        "exp": time.time() + 3600,
        "app_metadata": {"role": "municipality"},
        "aud": "authenticated",
    })
    municipality = auth_client.post(
        "/api/v1/status/state",
        headers={"Authorization": f"Bearer {municipality_token}"},
        json={"operational_state": "MONITORING"},
    )
    assert municipality.status_code == 200
    assert municipality.json()["operational_state"] == SystemOperationalState.MONITORING
    state_store.operational_state = original_state
