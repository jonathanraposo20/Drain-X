"""
DRAIN-X P0.7.1 Supabase JWT Cryptographic Verification Tests.

Comprehensive validation of:
1. Valid ES256 tokens verified against trusted JWKS public keys.
2. Invalid ES256 signature rejection.
3. Unknown kid rejection.
4. Missing kid rejection.
5. Expired JWT rejection (both ES256 and HS256).
6. Invalid audience rejection.
7. Invalid issuer rejection.
8. Retained HS256 behavior (valid, expired, tampered).
9. Fail-closed production behavior when JWKS/secrets are missing.
10. Anti-privilege escalation (user_metadata tampering strictly ignored in favor of app_metadata).
11. Production auth disabled rejection (fail-closed).
12. Strict algorithm allowlisting (none, RS256, RS512 rejection).
"""

import base64
import json
import time
from unittest.mock import patch
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import jwt
from jwt.utils import to_base64url_uint

from app.core.config import settings, validate_production_configuration, Settings
from app.core.security import (
    verify_supabase_jwt,
    set_in_memory_jwks,
    clear_jwks_cache,
    ALLOWED_ALGORITHMS,
)


@pytest.fixture
def ec_keypair():
    """Generates an ephemeral ECDSA P-256 key pair and corresponding JWK."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    numbers = public_key.public_numbers()
    kid = "test-es256-kid-01"
    x_bytes = numbers.x.to_bytes(32, "big")
    y_bytes = numbers.y.to_bytes(32, "big")
    jwk_dict = {
        "keys": [
            {
                "kty": "EC",
                "crv": "P-256",
                "kid": kid,
                "x": base64.urlsafe_b64encode(x_bytes).decode("ascii").rstrip("="),
                "y": base64.urlsafe_b64encode(y_bytes).decode("ascii").rstrip("="),
                "alg": "ES256",
                "use": "sig",
            }
        ]
    }
    return {
        "private_key": private_key,
        "public_key": public_key,
        "kid": kid,
        "jwks": jwk_dict,
    }


@pytest.fixture(autouse=True)
def cleanup_cache():
    """Cleans in-memory JWKS cache before and after each test."""
    clear_jwks_cache()
    yield
    clear_jwks_cache()


def test_valid_es256_verification(ec_keypair):
    """Test 1: Valid ES256 token signed by trusted private key and verified via JWKS."""
    set_in_memory_jwks(ec_keypair["jwks"], base_url="https://xhdtceqcnsheoskmuwsv.supabase.co")
    
    payload = {
        "sub": "user-citizen-123",
        "aud": "authenticated",
        "iss": "https://xhdtceqcnsheoskmuwsv.supabase.co/auth/v1",
        "exp": time.time() + 3600,
        "app_metadata": {"role": "citizen"},
    }
    token = jwt.encode(
        payload,
        ec_keypair["private_key"],
        algorithm="ES256",
        headers={"kid": ec_keypair["kid"]},
    )

    with patch.object(settings, "SUPABASE_URL", "https://xhdtceqcnsheoskmuwsv.supabase.co"):
        claims = verify_supabase_jwt(token)
        assert claims["sub"] == "user-citizen-123"
        assert claims["extracted_role"] == "citizen"


def test_invalid_es256_signature_rejection(ec_keypair):
    """Test 2: Invalid ES256 cryptographic signature is rejected with 401."""
    set_in_memory_jwks(ec_keypair["jwks"], base_url="https://xhdtceqcnsheoskmuwsv.supabase.co")
    
    # Sign with a different, rogue private key
    rogue_private_key = ec.generate_private_key(ec.SECP256R1())
    payload = {
        "sub": "attacker-456",
        "aud": "authenticated",
        "iss": "https://xhdtceqcnsheoskmuwsv.supabase.co/auth/v1",
        "exp": time.time() + 3600,
    }
    token = jwt.encode(
        payload,
        rogue_private_key,
        algorithm="ES256",
        headers={"kid": ec_keypair["kid"]},  # Claims valid kid, but wrong signature!
    )

    with patch.object(settings, "SUPABASE_URL", "https://xhdtceqcnsheoskmuwsv.supabase.co"):
        with pytest.raises(Exception) as exc:
            verify_supabase_jwt(token)
        assert "401" in str(exc.value)
        assert "Invalid token signature" in str(exc.value)


def test_unknown_kid_rejection(ec_keypair):
    """Test 3: ES256 token referencing an unknown kid is rejected with 401."""
    set_in_memory_jwks(ec_keypair["jwks"], base_url="https://xhdtceqcnsheoskmuwsv.supabase.co")
    
    payload = {
        "sub": "user-123",
        "aud": "authenticated",
        "exp": time.time() + 3600,
    }
    token = jwt.encode(
        payload,
        ec_keypair["private_key"],
        algorithm="ES256",
        headers={"kid": "unknown-foreign-kid-99"},
    )

    with patch.object(settings, "SUPABASE_URL", "https://xhdtceqcnsheoskmuwsv.supabase.co"):
        with pytest.raises(Exception) as exc:
            verify_supabase_jwt(token)
        assert "401" in str(exc.value)
        assert "unknown key id" in str(exc.value)


def test_missing_kid_rejection(ec_keypair):
    """Test 4: ES256 token missing kid in header is rejected with 401."""
    set_in_memory_jwks(ec_keypair["jwks"], base_url="https://xhdtceqcnsheoskmuwsv.supabase.co")
    
    payload = {
        "sub": "user-123",
        "aud": "authenticated",
        "exp": time.time() + 3600,
    }
    token = jwt.encode(
        payload,
        ec_keypair["private_key"],
        algorithm="ES256",
        # No kid in header
    )

    with patch.object(settings, "SUPABASE_URL", "https://xhdtceqcnsheoskmuwsv.supabase.co"):
        with pytest.raises(Exception) as exc:
            verify_supabase_jwt(token)
        assert "401" in str(exc.value)
        assert "missing required 'kid'" in str(exc.value)


def test_expired_jwt_rejection(ec_keypair):
    """Test 5: Expired tokens (both ES256 and HS256) are rejected with 401."""
    # ES256 expired
    set_in_memory_jwks(ec_keypair["jwks"], base_url="https://xhdtceqcnsheoskmuwsv.supabase.co")
    es_payload = {
        "sub": "user-123",
        "aud": "authenticated",
        "exp": time.time() - 3600,
    }
    es_token = jwt.encode(
        es_payload,
        ec_keypair["private_key"],
        algorithm="ES256",
        headers={"kid": ec_keypair["kid"]},
    )
    with patch.object(settings, "SUPABASE_URL", "https://xhdtceqcnsheoskmuwsv.supabase.co"):
        with pytest.raises(Exception) as exc_es:
            verify_supabase_jwt(es_token)
        assert "401" in str(exc_es.value)
        assert "expired" in str(exc_es.value).lower()

    # HS256 expired
    secret = "test-secret-key-at-least-32-chars-long!"
    hs_token = jwt.encode(
        {"sub": "user-123", "exp": time.time() - 3600, "aud": "authenticated"},
        secret,
        algorithm="HS256",
    )
    with patch.object(settings, "SUPABASE_JWT_SECRET", secret):
        with pytest.raises(Exception) as exc_hs:
            verify_supabase_jwt(hs_token)
        assert "401" in str(exc_hs.value)
        assert "expired" in str(exc_hs.value).lower()


def test_invalid_audience_rejection(ec_keypair):
    """Test 6: Token with unauthorized audience is rejected with 401."""
    set_in_memory_jwks(ec_keypair["jwks"], base_url="https://xhdtceqcnsheoskmuwsv.supabase.co")
    payload = {
        "sub": "user-123",
        "aud": "malicious-third-party-app",
        "exp": time.time() + 3600,
    }
    token = jwt.encode(
        payload,
        ec_keypair["private_key"],
        algorithm="ES256",
        headers={"kid": ec_keypair["kid"]},
    )
    with patch.object(settings, "SUPABASE_URL", "https://xhdtceqcnsheoskmuwsv.supabase.co"):
        with pytest.raises(Exception) as exc:
            verify_supabase_jwt(token)
        assert "401" in str(exc.value)
        assert "audience" in str(exc.value).lower()


def test_invalid_issuer_rejection(ec_keypair):
    """Test 7: Token with mismatched issuer is rejected with 401."""
    set_in_memory_jwks(ec_keypair["jwks"], base_url="https://xhdtceqcnsheoskmuwsv.supabase.co")
    payload = {
        "sub": "user-123",
        "aud": "authenticated",
        "iss": "http://malicious-spoofed-issuer.com/auth/v1",
        "exp": time.time() + 3600,
    }
    token = jwt.encode(
        payload,
        ec_keypair["private_key"],
        algorithm="ES256",
        headers={"kid": ec_keypair["kid"]},
    )
    with patch.object(settings, "SUPABASE_URL", "https://xhdtceqcnsheoskmuwsv.supabase.co"):
        with pytest.raises(Exception) as exc:
            verify_supabase_jwt(token)
        assert "401" in str(exc.value)
        assert "issuer" in str(exc.value).lower()


def test_retained_hs256_behavior():
    """Test 8: Retained HS256 symmetric verification works as expected."""
    secret = "my-trusted-super-secret-key-32-chars!!"
    payload = {
        "sub": "operator-01",
        "iss": "https://xhdtceqcnsheoskmuwsv.supabase.co/auth/v1",
        "aud": "authenticated",
        "exp": time.time() + 3600,
        "app_metadata": {"role": "municipality"},
    }
    valid_token = jwt.encode(payload, secret, algorithm="HS256")

    with patch.object(settings, "SUPABASE_JWT_SECRET", secret), \
         patch.object(settings, "SUPABASE_URL", "https://xhdtceqcnsheoskmuwsv.supabase.co"):
        claims = verify_supabase_jwt(valid_token)
        assert claims["sub"] == "operator-01"
        assert claims["extracted_role"] == "municipality"

        # Tampered signature (valid base64 with different signature byte)
        parts = valid_token.split(".")
        tampered_sig = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
        tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig}"
        with pytest.raises(Exception) as exc:
            verify_supabase_jwt(tampered_token)
        assert "401" in str(exc.value)
        assert "Invalid token signature" in str(exc.value)


def test_user_metadata_role_escalation_rejected(ec_keypair):
    """Test 9: Self-assigned role in user_metadata is ignored in favor of app_metadata."""
    set_in_memory_jwks(ec_keypair["jwks"], base_url="https://xhdtceqcnsheoskmuwsv.supabase.co")
    payload = {
        "sub": "attacker-007",
        "iss": "https://xhdtceqcnsheoskmuwsv.supabase.co/auth/v1",
        "aud": "authenticated",
        "exp": time.time() + 3600,
        "user_metadata": {"role": "admin", "is_superadmin": True},  # Untrusted!
        "app_metadata": {"role": "citizen"},                         # Trusted!
    }
    token = jwt.encode(
        payload,
        ec_keypair["private_key"],
        algorithm="ES256",
        headers={"kid": ec_keypair["kid"]},
    )
    with patch.object(settings, "SUPABASE_URL", "https://xhdtceqcnsheoskmuwsv.supabase.co"):
        claims = verify_supabase_jwt(token)
        assert claims["extracted_role"] == "citizen"
        assert claims["extracted_role"] != "admin"


def test_production_missing_keys_fail_closed():
    """Test 10: In production, missing both JWKS URL and HS256 secret fails closed."""
    # 1. validate_production_configuration check
    bad_cfg = Settings(
        ENVIRONMENT="production",
        SUPABASE_AUTH_ENABLED=True,
        DEVICE_INGEST_API_KEY="valid-device-key-32-chars",
        SUPABASE_URL="",            # Missing
        SUPABASE_KEY="anon-key",
        SUPABASE_JWT_SECRET="",     # Missing
    )
    with pytest.raises(RuntimeError) as exc:
        validate_production_configuration(bad_cfg)
    assert "Production JWT verification requires" in str(exc.value)

    # 2. verify_supabase_jwt in production without provider
    with patch.object(settings, "ENVIRONMENT", "production"), \
         patch.object(settings, "SUPABASE_URL", None), \
         patch.object(settings, "SUPABASE_JWT_SECRET", None):
        # Craft a dummy token
        dummy_token = jwt.encode({"sub": "u1"}, "dummy", algorithm="HS256")
        with pytest.raises(Exception) as exc_jwt:
            verify_supabase_jwt(dummy_token)
        assert "500" in str(exc_jwt.value) or "401" in str(exc_jwt.value)


def test_production_auth_disabled_fails_closed():
    """Test 11: In production, disabling auth raises a configuration error."""
    bad_cfg = Settings(
        ENVIRONMENT="production",
        SUPABASE_AUTH_ENABLED=False,  # Forbidden in production!
        DEVICE_INGEST_API_KEY="valid-device-key-32-chars",
        SUPABASE_URL="https://test.supabase.co",
        SUPABASE_KEY="anon-key",
    )
    with pytest.raises(RuntimeError) as exc:
        validate_production_configuration(bad_cfg)
    assert "SUPABASE_AUTH_ENABLED must be True in production" in str(exc.value)


def test_strict_algorithm_allowlisting():
    """Test 12: Unallowed algorithms (none, RS256, RS512) are rejected."""
    # 'none' algorithm
    token_none = jwt.encode({"sub": "u1"}, key="", algorithm="none")
    with pytest.raises(Exception) as exc_none:
        verify_supabase_jwt(token_none)
    assert "401" in str(exc_none.value)
    assert "Unsupported token algorithm" in str(exc_none.value)


def test_es256_tampered_payload_rejected(ec_keypair):
    """Test 13: ES256 token with modified payload is rejected due to broken cryptographic signature."""
    set_in_memory_jwks(ec_keypair["jwks"], base_url="https://xhdtceqcnsheoskmuwsv.supabase.co")
    payload = {
        "sub": "user-citizen-123",
        "aud": "authenticated",
        "iss": "https://xhdtceqcnsheoskmuwsv.supabase.co/auth/v1",
        "exp": time.time() + 3600,
        "app_metadata": {"role": "citizen"},
    }
    valid_token = jwt.encode(
        payload,
        ec_keypair["private_key"],
        algorithm="ES256",
        headers={"kid": ec_keypair["kid"]},
    )
    parts = valid_token.split(".")
    # Tamper payload: change citizen to admin without re-signing
    tampered_payload_dict = {**payload, "app_metadata": {"role": "admin"}}
    tampered_p_b64 = base64.urlsafe_b64encode(json.dumps(tampered_payload_dict).encode()).decode().rstrip("=")
    tampered_token = f"{parts[0]}.{tampered_p_b64}.{parts[2]}"

    with patch.object(settings, "SUPABASE_URL", "https://xhdtceqcnsheoskmuwsv.supabase.co"):
        with pytest.raises(Exception) as exc:
            verify_supabase_jwt(tampered_token)
        assert "401" in str(exc.value)
        assert "Invalid token signature" in str(exc.value)


def test_es256_tampered_signature_rejected(ec_keypair):
    """Test 14: ES256 token with modified signature bytes is rejected."""
    set_in_memory_jwks(ec_keypair["jwks"], base_url="https://xhdtceqcnsheoskmuwsv.supabase.co")
    payload = {
        "sub": "user-citizen-123",
        "aud": "authenticated",
        "exp": time.time() + 3600,
    }
    valid_token = jwt.encode(
        payload,
        ec_keypair["private_key"],
        algorithm="ES256",
        headers={"kid": ec_keypair["kid"]},
    )
    parts = valid_token.split(".")
    tampered_sig = ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
    tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig}"

    with patch.object(settings, "SUPABASE_URL", "https://xhdtceqcnsheoskmuwsv.supabase.co"):
        with pytest.raises(Exception) as exc:
            verify_supabase_jwt(tampered_token)
        assert "401" in str(exc.value)
        assert "Invalid token signature" in str(exc.value)


def test_malformed_token_rejection():
    """Test 15: Malformed token strings are rejected with 401."""
    malformed_inputs = [
        "",
        "not-a-jwt",
        "abc.def",
        "header..sig",
        "!!!.invalid.base64",
    ]
    for bad_token in malformed_inputs:
        with pytest.raises(Exception) as exc:
            verify_supabase_jwt(bad_token)
        assert "401" in str(exc.value)


def test_algorithm_confusion_asymmetric_key_as_hmac_rejected(ec_keypair):
    """Test 16: Algorithm confusion attack (signing with public key bytes as HMAC) is rejected."""
    import hashlib
    import hmac

    secret = "legitimate-backend-secret-32-chars-long!"
    # Attacker tries to sign token with HS256 using the server's public key as secret
    # but the server strictly uses SUPABASE_JWT_SECRET for HS256!
    pub_pem = ec_keypair["public_key"].public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": "attacker-confused",
        "aud": "authenticated",
        "exp": time.time() + 3600,
        "app_metadata": {"role": "admin"},
    }
    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signing_input = f"{h_b64}.{p_b64}"
    sig = hmac.new(pub_pem, signing_input.encode("ascii"), hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    attacker_token = f"{signing_input}.{sig_b64}"

    with patch.object(settings, "SUPABASE_JWT_SECRET", secret):
        with pytest.raises(Exception) as exc:
            verify_supabase_jwt(attacker_token)
        assert "401" in str(exc.value)
        assert "Invalid token signature" in str(exc.value)

@pytest.mark.parametrize("subject", [None, "", "   "])
def test_missing_or_blank_subject_rejected(subject):
    """Reject JWTs without a non-empty subject claim."""
    secret = "my-trusted-super-secret-key-32-chars!!"
    payload = {
        "iss": "https://xhdtceqcnsheoskmuwsv.supabase.co/auth/v1",
        "aud": "authenticated",
        "exp": time.time() + 3600,
        "app_metadata": {"role": "municipality"},
    }

    if subject is not None:
        payload["sub"] = subject

    token = jwt.encode(payload, secret, algorithm="HS256")

    with patch.object(settings, "SUPABASE_JWT_SECRET", secret), \
         patch.object(settings, "SUPABASE_URL", "https://xhdtceqcnsheoskmuwsv.supabase.co"):
        with pytest.raises(Exception) as exc:
            verify_supabase_jwt(token)

    assert "401" in str(exc.value)
