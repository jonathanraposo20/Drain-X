"""
DRAIN-X Phase 3 Milestone: Rate Limiting & Abuse Protection Test Suite (Stage A Hardened).

Comprehensive offline verification of:
1. Authenticated & anonymous limits (POST /incidents, POST /photos, GET scoped & legacy photos).
2. Boundary enforcement, HTTP 429, Retry-After >= 1s, and non-leaking error body.
3. Window expiration and counter reset.
4. Independent counters across users, operations, and namespaces (auth: vs anon:).
5. Anti-tampering across incident IDs, filenames, and paths.
6. Spoofed forwarding headers (X-Forwarded-For, X-Real-IP, Forwarded), IPv4-mapped IPv6, IPv6 /64.
7. Trusted-proxy right-to-left X-Forwarded-For extraction and fail-closed peer checks.
8. Early rate-limit enforcement on photo retrieval BEFORE PostgREST / Storage downloads.
9. Simulated PostgreSQL MVCC concurrency: simultaneous first inserts & cleanup vs reset safety.
10. Store outage, timeout, and malformed RPC fail-closed HTTP 503 behavior.
11. Production config validation: rejects RATE_LIMIT_ENABLED=False, memory, missing service_role, weak pepper.
12. Municipal & field-worker workflows remain functional.
13. Invalid SQL RPC arguments fail safely (repository validation + PostgreSQL 22023 mapping).
14. Migration 006 AST/PLpgSQL parsing, CHECK constraints, and least-privilege grants.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import hmac as std_hmac
import io
import threading
from types import SimpleNamespace
from typing import Any, Dict, Optional
from unittest.mock import MagicMock, patch, PropertyMock

import pglast
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from starlette.datastructures import Headers

from app.main import app
from app.core.config import Settings, settings, validate_production_configuration
from app.services.rate_limiter import (
    check_rate_limit,
    compute_rate_limit_key_hash,
    extract_anonymous_client_identifier,
    in_memory_rate_limiter,
    RateLimitAction,
)
from app.services.persistence_repository import (
    PersistenceRepository,
    persistence_repo,
    StorageError,
    StorageValidationError,
)
from app.services.state_store import state_store

_VALID_PROD_PEPPER = "prod-hmac-pepper-strong-secret-2026"


@pytest.fixture(autouse=True)
def clean_rate_limiter():
    """Ensure in-memory rate limiter is wiped clean before and after every test."""
    in_memory_rate_limiter.clear()
    yield
    in_memory_rate_limiter.clear()


def _make_auth_claims(sub: str, role: str = "citizen") -> Dict[str, Any]:
    """Helper to mock verified Supabase JWT claims."""
    return {
        "sub": sub,
        "aud": "authenticated",
        "role": role,
        "extracted_role": role,
        "app_metadata": {"role": role},
    }


def _dummy_jpeg_bytes() -> bytes:
    """Returns a valid minimal JPEG image."""
    from PIL import Image
    buf = io.BytesIO()
    img = Image.new("RGB", (10, 10), color="blue")
    img.save(buf, format="JPEG")
    return buf.getvalue()


def _make_mock_request(
    peer_host: Optional[str] = "203.0.113.10",
    headers: Optional[list[tuple[str, str]]] = None,
) -> Any:
    """Constructs a lightweight Request-like object with ASGI peer host and headers."""
    client_obj = SimpleNamespace(host=peer_host, port=50000) if peer_host is not None else None
    raw_headers = [(k.lower().encode("latin-1"), v.encode("latin-1")) for k, v in (headers or [])]
    return SimpleNamespace(client=client_obj, headers=Headers(raw=raw_headers))


class SimulatedPostgresRateLimitStore:
    """
    Offline faithful simulator of Migration 006 (`check_and_increment_rate_limit_rpc`)
    modeling per-key row locking, atomic upsert on simultaneous first requests,
    clock advancement, and `ORDER BY window_end ASC` + `FOR UPDATE SKIP LOCKED` +
    outer expiration recheck cleanup under READ COMMITTED concurrency.
    """

    def __init__(self, initial_now: Optional[datetime] = None) -> None:
        self._lock = threading.Lock()
        self._rows: Dict[str, Dict[str, Any]] = {}
        self._locked_keys: set[str] = set()
        self.now: datetime = initial_now or datetime(2026, 11, 22, 12, 0, 0, tzinfo=timezone.utc)

    def seed_expired_row(self, key_hash: str, action: str, expired_ago_sec: int, count: int = 1) -> None:
        with self._lock:
            window_end = self.now - timedelta(seconds=expired_ago_sec)
            self._rows[key_hash] = {
                "rate_limit_key": key_hash,
                "action": action,
                "window_start": window_end - timedelta(seconds=900),
                "window_end": window_end,
                "request_count": count,
                "updated_at": window_end,
            }

    def rpc_check_and_increment(self, key_hash: str, action: str, limit: int, window_sec: int) -> Dict[str, Any]:
        with self._lock:
            now = self.now
            row = self._rows.get(key_hash)
            window_delta = timedelta(seconds=window_sec)
            if row is None:
                self._rows[key_hash] = {
                    "rate_limit_key": key_hash,
                    "action": action,
                    "window_start": now,
                    "window_end": now + window_delta,
                    "request_count": 1,
                    "updated_at": now,
                }
                raw_count = 1
                window_end = now + window_delta
            else:
                if now >= row["window_end"]:
                    row["action"] = action
                    row["window_start"] = now
                    row["window_end"] = now + window_delta
                    row["request_count"] = 1
                    row["updated_at"] = now
                    raw_count = 1
                elif row["request_count"] < limit:
                    row["action"] = action
                    row["request_count"] += 1
                    row["updated_at"] = now
                    raw_count = row["request_count"]
                else:
                    row["action"] = action
                    row["request_count"] = limit + 1
                    row["updated_at"] = now
                    raw_count = limit + 1
                window_end = row["window_end"]

            allowed = raw_count <= limit
            current_count = raw_count if allowed else limit
            remaining = (limit - current_count) if allowed else 0
            reset_after = max(1, min(window_sec, int((window_end - now).total_seconds() + 0.999999)))
            return {
                "allowed": allowed,
                "current_count": current_count,
                "limit": limit,
                "remaining": remaining,
                "reset_after_sec": reset_after,
                "retry_after_sec": 0 if allowed else reset_after,
            }

    def run_cleanup_with_concurrent_reset_race(
        self,
        contended_key: str,
        reset_action: str,
        limit: int,
        window_sec: int,
    ) -> int:
        """
        Models the exact READ COMMITTED race window:
        1. Cleanup snapshots candidate keys (`window_end < v_now - 1h ORDER BY window_end ASC LIMIT 50`).
        2. Before cleanup deletes `contended_key`, another transaction resets `contended_key` into an active window.
        3. Cleanup applies outer recheck `AND window_end < (v_now - INTERVAL '1 hour')` and skips active rows.
        Returns count of rows actually deleted.
        """
        with self._lock:
            cutoff = self.now - timedelta(hours=1)
            candidates = sorted(
                [r for r in self._rows.values() if r["window_end"] < cutoff and r["rate_limit_key"] not in self._locked_keys],
                key=lambda r: r["window_end"],
            )[:50]
            candidate_keys = [r["rate_limit_key"] for r in candidates]

            # Simulate concurrent transaction updating contended_key into an active window
            row = self._rows.get(contended_key)
            if row is not None:
                row["action"] = reset_action
                row["window_start"] = self.now
                row["window_end"] = self.now + timedelta(seconds=window_sec)
                row["request_count"] = 1
                row["updated_at"] = self.now

            # Outer DELETE rechecks `AND window_end < cutoff`
            deleted = 0
            for k in candidate_keys:
                current = self._rows.get(k)
                if current is not None and current["window_end"] < cutoff:
                    del self._rows[k]
                    deleted += 1
            return deleted


# ==============================================================================
# 1. Authenticated Rate Limiting Baseline (Create / Upload / Retrieve)
# ==============================================================================

def test_01_citizen_incident_creation_under_limit_reaches_limit_and_throttles():
    """
    Verify authenticated citizen incident creation permits 5 requests in 15 min
    and returns HTTP 429 on the 6th with Retry-After and clean error detail.
    """
    client = TestClient(app)
    citizen_claims = _make_auth_claims("citizen_test_01", role="citizen")

    payload = {
        "category": "DRAIN_BLOCKAGE",
        "description": "Blockage in storm drain near sector 4",
        "latitude": 15.2993,
        "longitude": 74.1240,
        "severity": "MEDIUM",
        "reporter_name": "Citizen One",
    }

    with patch("app.core.security.verify_supabase_jwt", return_value=citizen_claims):
        headers = {"Authorization": "Bearer citizen-valid-token"}

        for i in range(1, 6):
            resp = client.post("/api/v1/incidents", json=payload, headers=headers)
            assert resp.status_code == 201, f"Request {i} failed unexpectedly: {resp.text}"

        resp_6 = client.post("/api/v1/incidents", json=payload, headers=headers)
        assert resp_6.status_code == 429
        assert "Retry-After" in resp_6.headers
        assert 1 <= int(resp_6.headers["Retry-After"]) <= 900
        assert resp_6.json() == {"detail": "Too Many Requests. Rate limit exceeded."}


def test_02_photo_upload_under_limit_reaches_limit_and_throttles():
    """Verify authenticated photo uploads allow 10 requests in 15 min, 11th -> 429."""
    client = TestClient(app)
    citizen_claims = _make_auth_claims("citizen_uploader_02", role="citizen")

    create_resp = client.post(
        "/api/v1/incidents",
        json={
            "category": "DRAIN_OVERFLOW",
            "description": "Overflow on main street",
            "latitude": 15.2993,
            "longitude": 74.1240,
            "severity": "HIGH",
        },
    )
    inc_id = create_resp.json()["id"]
    photo_bytes = _dummy_jpeg_bytes()

    with patch("app.core.security.verify_supabase_jwt", return_value=citizen_claims):
        headers = {"Authorization": "Bearer citizen-token"}
        for i in range(1, 11):
            with state_store._lock:
                state_store._incidents[inc_id].photos = []
            files = [("files", (f"p_{i}.jpg", io.BytesIO(photo_bytes), "image/jpeg"))]
            resp = client.post(f"/api/v1/incidents/{inc_id}/photos", files=files, headers=headers)
            assert resp.status_code == 200, f"Upload {i} should succeed"

        with state_store._lock:
            state_store._incidents[inc_id].photos = []
        files = [("files", ("p_11.jpg", io.BytesIO(photo_bytes), "image/jpeg"))]
        resp_11 = client.post(f"/api/v1/incidents/{inc_id}/photos", files=files, headers=headers)
        assert resp_11.status_code == 429
        assert int(resp_11.headers["Retry-After"]) >= 1
        assert resp_11.json() == {"detail": "Too Many Requests. Rate limit exceeded."}


def test_03_photo_retrieval_under_limit_reaches_limit_and_throttles():
    """Verify authenticated photo retrieval allows 60 requests in 1 min, 61st -> 429."""
    client = TestClient(app)
    citizen_claims = _make_auth_claims("citizen_viewer_03", role="citizen")

    create_resp = client.post(
        "/api/v1/incidents",
        json={
            "category": "DRAIN_BLOCKAGE",
            "description": "Photo test incident",
            "latitude": 15.2993,
            "longitude": 74.1240,
            "severity": "LOW",
        },
    )
    inc_id = create_resp.json()["id"]

    photo_bytes = _dummy_jpeg_bytes()
    up_resp = client.post(
        f"/api/v1/incidents/{inc_id}/photos",
        files=[("files", ("test_pic.jpg", io.BytesIO(photo_bytes), "image/jpeg"))],
    )
    filename = up_resp.json()["photos"][0].split("/")[-1]

    with patch("app.core.security.verify_supabase_jwt", return_value=citizen_claims):
        headers = {"Authorization": "Bearer citizen-token"}
        for i in range(1, 61):
            resp = client.get(f"/api/v1/incidents/{inc_id}/photos/{filename}", headers=headers)
            assert resp.status_code == 200, f"Retrieval {i} should succeed"

        resp_61 = client.get(f"/api/v1/incidents/{inc_id}/photos/{filename}", headers=headers)
        assert resp_61.status_code == 429
        assert int(resp_61.headers["Retry-After"]) >= 1
        assert resp_61.json() == {"detail": "Too Many Requests. Rate limit exceeded."}


# ==============================================================================
# 2. Anonymous Rate Limiting & Bypass Resistance (RL-AUD-01)
# ==============================================================================

def test_04_twenty_consecutive_anonymous_incidents_throttled():
    """Stage A #1: 20 consecutive anonymous incident creations must NOT bypass limits."""
    client = TestClient(app, client=("203.0.113.10", 50000))
    payload = {
        "category": "DRAIN_BLOCKAGE",
        "description": "Anonymous storm drain clog",
        "latitude": 15.2993,
        "longitude": 74.1240,
        "severity": "MEDIUM",
    }

    statuses = []
    retry_headers = []
    for _ in range(20):
        resp = client.post("/api/v1/incidents", json=payload)
        statuses.append(resp.status_code)
        if resp.status_code == 429:
            retry_headers.append(int(resp.headers["Retry-After"]))
            assert resp.json() == {"detail": "Too Many Requests. Rate limit exceeded."}

    assert statuses[:5] == [201] * 5
    assert statuses[5:] == [429] * 15
    assert all(1 <= r <= 900 for r in retry_headers)


def test_05_anonymous_photo_uploads_and_retrieval_throttled():
    """
    Stage A #2: Anonymous photo uploads (5/15m) and retrieval across both scoped & legacy routes
    plus unmatched 404 probes (30/1m) are strictly throttled.
    """
    client = TestClient(app, client=("203.0.113.20", 50000))
    create_resp = client.post(
        "/api/v1/incidents",
        json={
            "category": "DRAIN_BLOCKAGE",
            "description": "Anon photo workflow",
            "latitude": 15.29,
            "longitude": 74.12,
            "severity": "LOW",
        },
    )
    assert create_resp.status_code == 201
    inc_id = create_resp.json()["id"]
    photo_bytes = _dummy_jpeg_bytes()

    # Upload: 5 allowed, 6th returns 429
    last_photo_url = None
    last_filename = None
    for i in range(1, 6):
        with state_store._lock:
            state_store._incidents[inc_id].photos = []
        resp = client.post(
            f"/api/v1/incidents/{inc_id}/photos",
            files=[("files", (f"anon_{i}.jpg", io.BytesIO(photo_bytes), "image/jpeg"))],
        )
        assert resp.status_code == 200
        last_photo_url = resp.json()["photos"][0]
        last_filename = last_photo_url.split("/")[-1]

    with state_store._lock:
        state_store._incidents[inc_id].photos = []
    resp_up_6 = client.post(
        f"/api/v1/incidents/{inc_id}/photos",
        files=[("files", ("anon_6.jpg", io.BytesIO(photo_bytes), "image/jpeg"))],
    )
    assert resp_up_6.status_code == 429
    assert int(resp_up_6.headers["Retry-After"]) >= 1

    # Retrieval: mix scoped (10), legacy (10), and unmatched 404 probes (10) -> 30 total; 31st -> 429
    assert last_photo_url is not None and last_filename is not None
    with state_store._lock:
        state_store._incidents[inc_id].photos = [last_photo_url]
    for _ in range(10):
        assert client.get(f"/api/v1/incidents/{inc_id}/photos/{last_filename}").status_code == 200
    for _ in range(10):
        assert client.get(f"/api/v1/incidents/photos/{last_filename}").status_code == 200
    for j in range(10):
        assert client.get(f"/api/v1/incidents/INC-NOPE-{j}/photos/missing_{j}.jpg").status_code == 404

    resp_probe_31 = client.get("/api/v1/incidents/INC-NOPE-31/photos/missing_31.jpg")
    assert resp_probe_31.status_code == 429
    assert int(resp_probe_31.headers["Retry-After"]) >= 1

    resp_legacy_32 = client.get(f"/api/v1/incidents/photos/{last_filename}")
    assert resp_legacy_32.status_code == 429


def test_06_spoofed_forwarding_headers_and_ipv6_rotation_cannot_bypass():
    """
    Stage A #3: With empty RATE_LIMIT_TRUSTED_PROXIES, X-Forwarded-For / X-Real-IP / Forwarded
    are ignored; IPv4-mapped IPv6 unwraps cleanly; IPv6 /64 normalization blocks interface rotation.
    """
    payload = {
        "category": "DRAIN_BLOCKAGE",
        "description": "Spoof attempt",
        "latitude": 15.29,
        "longitude": 74.12,
        "severity": "LOW",
    }

    with patch.object(settings, "RATE_LIMIT_TRUSTED_PROXIES", []):
        client = TestClient(app, client=("198.51.100.7", 50000))
        for _ in range(5):
            assert client.post("/api/v1/incidents", json=payload).status_code == 201

        # Spoofed forwarding headers must NOT reset or bypass limit
        spoofed_headers = {
            "X-Forwarded-For": "1.2.3.4",
            "X-Real-IP": "5.6.7.8",
            "Forwarded": "for=9.9.9.9",
        }
        r_spoof = client.post("/api/v1/incidents", json=payload, headers=spoofed_headers)
        assert r_spoof.status_code == 429

        # IPv4-mapped IPv6 from same host shares identical bucket -> 429
        req_v4_mapped = _make_mock_request("::ffff:198.51.100.7")
        with pytest.raises(Exception) as exc_mapped:
            check_rate_limit(RateLimitAction.INCIDENT_CREATE, None, request=req_v4_mapped)
        assert exc_mapped.value.status_code == 429

        # IPv6 /64 normalization: 5 from ::1 blocks ::beef in the same /64 prefix
        for idx in range(5):
            req_v6 = _make_mock_request(f"2001:db8:abcd:1234::{idx + 1:x}")
            check_rate_limit(RateLimitAction.INCIDENT_CREATE, None, request=req_v6)

        req_v6_rotate = _make_mock_request("2001:db8:abcd:1234:ffff:eeee:dddd:cccc")
        with pytest.raises(Exception) as exc_v6:
            check_rate_limit(RateLimitAction.INCIDENT_CREATE, None, request=req_v6_rotate)
        assert exc_v6.value.status_code == 429


def test_07_trusted_proxy_extraction_and_fail_closed_peer_validation():
    """
    Stage A #4: Right-to-left X-Forwarded-For peeling behind explicit RATE_LIMIT_TRUSTED_PROXIES,
    isolation of distinct proxied clients, and fail-closed HTTP 503 on untrustworthy peer data.
    """
    with patch.object(settings, "RATE_LIMIT_TRUSTED_PROXIES", ["10.0.0.0/8", "172.16.0.0/12"]):
        # Client spoofs leftmost 1.1.1.1 -> proxy 172.16.1.9 appends real 203.0.113.42 -> ingress 10.0.0.5
        for spoof_ip in ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"]:
            req = _make_mock_request(
                peer_host="10.0.0.5",
                headers=[("X-Forwarded-For", f"{spoof_ip}, 203.0.113.42, 172.16.1.9")],
            )
            check_rate_limit(RateLimitAction.INCIDENT_CREATE, None, request=req)

        # Even changing spoofed leftmost IP still hits real client 203.0.113.42 quota -> 429
        req_exceed = _make_mock_request(
            peer_host="10.0.0.5",
            headers=[("X-Forwarded-For", "9.9.9.9, 203.0.113.42, 172.16.1.9")],
        )
        with pytest.raises(Exception) as exc_proxy:
            check_rate_limit(RateLimitAction.INCIDENT_CREATE, None, request=req_exceed)
        assert exc_proxy.value.status_code == 429

        # Different real client behind same proxy succeeds
        req_other_client = _make_mock_request(
            peer_host="10.0.0.5",
            headers=[("X-Forwarded-For", "1.1.1.1, 203.0.113.99, 172.16.1.9")],
        )
        check_rate_limit(RateLimitAction.INCIDENT_CREATE, None, request=req_other_client)

        # Fail closed (503) if trusted proxy sends missing / malformed / proxy-only chain
        for bad_headers in [[], [("X-Forwarded-For", "not_an_ip, 172.16.1.9")], [("X-Forwarded-For", "10.1.1.1, 172.16.1.9")]]:
            bad_req = _make_mock_request(peer_host="10.0.0.5", headers=bad_headers)
            with pytest.raises(Exception) as exc_bad:
                extract_anonymous_client_identifier(bad_req)
            assert exc_bad.value.status_code == 503

    # Missing ASGI peer or production "testclient" literal must fail closed with 503
    with pytest.raises(Exception) as exc_none_req:
        extract_anonymous_client_identifier(None)
    assert exc_none_req.value.status_code == 503

    with patch.object(settings, "ENVIRONMENT", "production"):
        with pytest.raises(Exception) as exc_testclient_prod:
            extract_anonymous_client_identifier(_make_mock_request("testclient"))
        assert exc_testclient_prod.value.status_code == 503

    # Invalid CIDR rejected by Settings
    with pytest.raises(ValidationError):
        Settings(RATE_LIMIT_TRUSTED_PROXIES=["not-a-valid-cidr"], _env_file=None)


def test_08_authenticated_and_anonymous_quotas_remain_isolated():
    """
    Stage A #5: HMAC-SHA256 key hashing uses distinct auth:/anon: namespaces and pepper;
    exhausting anonymous quota never consumes authenticated quota from the same IP and vice versa.
    """
    with patch.object(settings, "RATE_LIMIT_KEY_PEPPER", _VALID_PROD_PEPPER):
        auth_hash = compute_rate_limit_key_hash(RateLimitAction.INCIDENT_CREATE, "203.0.113.10", namespace="auth")
        anon_hash = compute_rate_limit_key_hash(RateLimitAction.INCIDENT_CREATE, "203.0.113.10", namespace="anon")
        unsalted = hashlib.sha256(b"anon:incident_create:203.0.113.10").hexdigest()

        assert len(auth_hash) == 64 and len(anon_hash) == 64
        assert auth_hash != anon_hash
        assert anon_hash != unsalted
        expected_hmac = std_hmac.new(
            _VALID_PROD_PEPPER.encode("utf-8"),
            b"anon:incident_create:203.0.113.10",
            hashlib.sha256,
        ).hexdigest()
        assert anon_hash == expected_hmac

    # Exhaust anonymous limit from 203.0.113.10
    same_ip_client = TestClient(app, client=("203.0.113.10", 50000))
    payload = {
        "category": "DRAIN_BLOCKAGE",
        "description": "Namespace isolation test",
        "latitude": 15.29,
        "longitude": 74.12,
        "severity": "MEDIUM",
    }
    for _ in range(5):
        assert same_ip_client.post("/api/v1/incidents", json=payload).status_code == 201
    assert same_ip_client.post("/api/v1/incidents", json=payload).status_code == 429

    # Authenticated citizen from the exact same IP still has full 5-request quota
    auth_claims = _make_auth_claims("203.0.113.10", role="citizen")
    with patch("app.core.security.verify_supabase_jwt", return_value=auth_claims):
        for _ in range(5):
            r_auth = same_ip_client.post(
                "/api/v1/incidents",
                json=payload,
                headers={"Authorization": "Bearer auth-tok"},
            )
            assert r_auth.status_code == 201


# ==============================================================================
# 3. Early Retrieval Ordering Before Storage / DB Work (RL-AUD-03)
# ==============================================================================

def test_09_photo_retrieval_returns_429_before_storage_download_or_db_lookup():
    """
    Stage A #6: Verify BOTH scoped and legacy retrieval routes enforce rate limiting BEFORE
    PostgREST incident/membership lookups and BEFORE downloading bytes from Supabase Storage.
    """
    client = TestClient(app)
    citizen_claims = _make_auth_claims("citizen_throttled_09", role="citizen")
    canonical_fn = f"sha256_{'a' * 64}.jpg"
    rpc_deny = {
        "allowed": False,
        "current_count": 60,
        "limit": 60,
        "remaining": 0,
        "reset_after_sec": 42,
        "retry_after_sec": 42,
    }

    with patch("app.core.security.verify_supabase_jwt", return_value=citizen_claims), \
         patch.object(settings, "RATE_LIMIT_STORAGE_BACKEND", "database"), \
         patch.object(PersistenceRepository, "is_configured", new_callable=PropertyMock, return_value=True), \
         patch.object(PersistenceRepository, "is_storage_configured", new_callable=PropertyMock, return_value=True), \
         patch.object(persistence_repo, "check_and_increment_rate_limit_sync", return_value=rpc_deny), \
         patch.object(persistence_repo, "query_incident_by_id_sync") as mock_q_inc, \
         patch.object(persistence_repo, "verify_attached_photo_membership_sync") as mock_q_mem, \
         patch.object(persistence_repo, "download_incident_photo") as mock_dl, \
         patch.object(persistence_repo, "query_incidents_by_photo_entry_sync") as mock_q_legacy:

        headers = {"Authorization": "Bearer citizen-token"}

        # 1. Scoped cloud photo retrieval must return 429 with 0 DB/Storage calls
        r_scoped = client.get(f"/api/v1/incidents/INC-RL-06/photos/{canonical_fn}", headers=headers)
        assert r_scoped.status_code == 429
        assert r_scoped.headers["Retry-After"] == "42"
        assert mock_q_inc.call_count == 0
        assert mock_q_mem.call_count == 0
        assert mock_dl.call_count == 0

        # 2. Legacy cloud photo retrieval must return 429 with 0 legacy DB lookup calls
        r_legacy = client.get("/api/v1/incidents/photos/legacy_photo_01.jpg", headers=headers)
        assert r_legacy.status_code == 429
        assert r_legacy.headers["Retry-After"] == "42"
        assert mock_q_legacy.call_count == 0


# ==============================================================================
# 4. Window Reset, User/Op Isolation, Anti-Tampering, Identities
# ==============================================================================

def test_10_window_expiration_and_counter_reset():
    """Verify window expiration resets counters and Retry-After decreases cleanly."""
    citizen_claims = _make_auth_claims("citizen_reset_10")
    t0 = 1000000.0

    for _ in range(5):
        check_rate_limit(RateLimitAction.INCIDENT_CREATE, citizen_claims, now_ts=t0)

    with pytest.raises(Exception) as exc_info:
        check_rate_limit(RateLimitAction.INCIDENT_CREATE, citizen_claims, now_ts=t0 + 10)
    assert exc_info.value.status_code == 429
    assert exc_info.value.headers["Retry-After"] == "890"

    # At exact boundary t0 + 900.0, old window has expired (now >= end)
    check_rate_limit(RateLimitAction.INCIDENT_CREATE, citizen_claims, now_ts=t0 + 900.0)


def test_11_independent_limits_for_users_operations_and_tampered_paths():
    """Verify user isolation, operation isolation, and cross-incident upload sharing."""
    user_a = _make_auth_claims("user_alice_11")
    user_b = _make_auth_claims("user_bob_11")

    for _ in range(5):
        check_rate_limit(RateLimitAction.INCIDENT_CREATE, user_a)
    with pytest.raises(Exception) as exc_a:
        check_rate_limit(RateLimitAction.INCIDENT_CREATE, user_a)
    assert exc_a.value.status_code == 429

    # Distinct user & distinct operations untouched
    for _ in range(5):
        check_rate_limit(RateLimitAction.INCIDENT_CREATE, user_b)
    for _ in range(10):
        check_rate_limit(RateLimitAction.PHOTO_UPLOAD, user_a)

    # Cross-incident tampering cannot bypass upload limit
    client = TestClient(app)
    hopper = _make_auth_claims("citizen_hopper_11")
    photo_bytes = _dummy_jpeg_bytes()
    inc_ids = []
    for k in range(4):
        res = client.post(
            "/api/v1/incidents",
            json={
                "category": "DRAIN_BLOCKAGE",
                "description": f"Incident {k}",
                "latitude": 15.2,
                "longitude": 74.1,
                "severity": "LOW",
            },
        )
        inc_ids.append(res.json()["id"])

    with patch("app.core.security.verify_supabase_jwt", return_value=hopper):
        headers = {"Authorization": "Bearer hopper-token"}
        for inc_id, num in zip(inc_ids, [3, 3, 3, 1]):
            for _ in range(num):
                r = client.post(
                    f"/api/v1/incidents/{inc_id}/photos",
                    files=[("files", ("pic.jpg", io.BytesIO(photo_bytes), "image/jpeg"))],
                    headers=headers,
                )
                assert r.status_code == 200
        r_exceed = client.post(
            f"/api/v1/incidents/{inc_ids[3]}/photos",
            files=[("files", ("pic.jpg", io.BytesIO(photo_bytes), "image/jpeg"))],
            headers=headers,
        )
        assert r_exceed.status_code == 429


def test_12_invalid_and_missing_sub_identities_rejected_401():
    """Verify malformed JWT -> 401 and claims missing sub -> 401 before rate limiting."""
    client = TestClient(app)
    resp_bad_jwt = client.post(
        "/api/v1/incidents",
        json={
            "category": "DRAIN_BLOCKAGE",
            "description": "Invalid JWT",
            "latitude": 15.2,
            "longitude": 74.1,
            "severity": "LOW",
        },
        headers={"Authorization": "Bearer not-a-valid-token"},
    )
    assert resp_bad_jwt.status_code == 401

    with pytest.raises(Exception) as exc_no_sub:
        check_rate_limit(RateLimitAction.INCIDENT_CREATE, {"aud": "authenticated", "role": "citizen"})
    assert exc_no_sub.value.status_code == 401


# ==============================================================================
# 5. Concurrent First Requests & Concurrent Cleanup Safety (Stage A #7 & #8)
# ==============================================================================

def test_13_concurrent_cleanup_cannot_delete_active_counter():
    """
    Stage A #7: Verify Migration 006 cleanup preserves active/recently-reset counters
    under READ COMMITTED concurrency while reclaiming genuinely >1h-expired rows.
    """
    sim = SimulatedPostgresRateLimitStore()
    contended_key = compute_rate_limit_key_hash(RateLimitAction.INCIDENT_CREATE, "contended_user", namespace="auth")
    stale_key_1 = compute_rate_limit_key_hash(RateLimitAction.INCIDENT_CREATE, "stale_user_1", namespace="auth")
    stale_key_2 = compute_rate_limit_key_hash(RateLimitAction.INCIDENT_CREATE, "stale_user_2", namespace="auth")
    active_key = compute_rate_limit_key_hash(RateLimitAction.INCIDENT_CREATE, "active_user", namespace="auth")

    sim.seed_expired_row(contended_key, "incident_create", expired_ago_sec=7200, count=5)
    sim.seed_expired_row(stale_key_1, "incident_create", expired_ago_sec=10800, count=3)
    sim.seed_expired_row(stale_key_2, "incident_create", expired_ago_sec=7200, count=2)
    sim.seed_expired_row(active_key, "incident_create", expired_ago_sec=-300, count=1)  # active window_end in future

    deleted = sim.run_cleanup_with_concurrent_reset_race(
        contended_key=contended_key,
        reset_action="incident_create",
        limit=5,
        window_sec=900,
    )

    assert deleted == 2
    assert stale_key_1 not in sim._rows
    assert stale_key_2 not in sim._rows
    assert contended_key in sim._rows
    assert sim._rows[contended_key]["request_count"] == 1
    assert active_key in sim._rows


def test_14_concurrent_first_requests_do_not_lose_increments():
    """
    Stage A #8: Fire 10 simultaneous first-time requests through a threading.Barrier
    against both the DB RPC simulator and in-memory store; zero increments may be lost.
    """
    # 1. Shared DB simulator path (limit=5, 10 simultaneous first requests -> 5 x 201, 5 x 429)
    sim = SimulatedPostgresRateLimitStore()
    claims_db = _make_auth_claims("concurrent_first_db")
    barrier_db = threading.Barrier(10)

    def _db_worker():
        barrier_db.wait(timeout=5)
        try:
            check_rate_limit(RateLimitAction.INCIDENT_CREATE, claims_db)
            return 201
        except Exception as exc:
            return getattr(exc, "status_code", 500)

    with patch.object(settings, "RATE_LIMIT_STORAGE_BACKEND", "database"), \
         patch.object(PersistenceRepository, "is_storage_configured", new_callable=PropertyMock, return_value=True), \
         patch.object(persistence_repo, "check_and_increment_rate_limit_sync", side_effect=sim.rpc_check_and_increment):
        with ThreadPoolExecutor(max_workers=10) as ex:
            results_db = list(ex.map(lambda _: _db_worker(), range(10)))

    assert results_db.count(201) == 5, f"Lost/extra increments in DB path: {results_db}"
    assert results_db.count(429) == 5, f"Unexpected non-429 rejections: {results_db}"
    key_db = compute_rate_limit_key_hash(RateLimitAction.INCIDENT_CREATE, "concurrent_first_db", namespace="auth")
    assert sim._rows[key_db]["request_count"] >= 5

    # 2. Tight boundary limit=1 simultaneous first requests on in-memory store -> 1 x 201, 9 x 429
    claims_mem = _make_auth_claims("concurrent_first_mem")
    barrier_mem = threading.Barrier(10)

    def _mem_worker():
        barrier_mem.wait(timeout=5)
        try:
            check_rate_limit(RateLimitAction.INCIDENT_CREATE, claims_mem)
            return 201
        except Exception as exc:
            return getattr(exc, "status_code", 500)

    with patch.object(settings, "RATE_LIMIT_INCIDENT_CREATE_MAX", 1):
        with ThreadPoolExecutor(max_workers=10) as ex:
            results_mem = list(ex.map(lambda _: _mem_worker(), range(10)))

    assert results_mem.count(201) == 1
    assert results_mem.count(429) == 9


# ==============================================================================
# 6. Outages, Restarts & Production Config Rejection (Stage A #9-#12)
# ==============================================================================

def test_15_store_outage_and_malformed_rpc_fail_closed_503():
    """Verify DB timeout/error and malformed RPC responses fail closed with HTTP 503."""
    user = _make_auth_claims("citizen_outage_15")

    with patch.object(settings, "ENVIRONMENT", "production"), \
         patch.object(settings, "RATE_LIMIT_KEY_PEPPER", _VALID_PROD_PEPPER), \
         patch.object(PersistenceRepository, "is_storage_configured", new_callable=PropertyMock, return_value=True):

        with patch.object(persistence_repo, "check_and_increment_rate_limit_sync", side_effect=StorageError("timeout")):
            with pytest.raises(Exception) as exc_out:
                check_rate_limit(RateLimitAction.INCIDENT_CREATE, user)
            assert exc_out.value.status_code == 503

        # Malformed string "false" must NEVER coerce via bool("false") == True to fail open
        with patch.object(
            persistence_repo,
            "check_and_increment_rate_limit_sync",
            return_value={"allowed": "false", "current_count": 6, "limit": 5, "remaining": 0, "reset_after_sec": 60, "retry_after_sec": 60},
        ):
            with pytest.raises(Exception) as exc_mal:
                check_rate_limit(RateLimitAction.INCIDENT_CREATE, user)
            assert exc_mal.value.status_code == 503


def test_16_multi_instance_shared_store_and_restart_persistence():
    """Verify two separate simulated backend instances sharing one DB store preserve state across restart."""
    sim = SimulatedPostgresRateLimitStore()
    user = _make_auth_claims("citizen_restart_16")

    with patch.object(settings, "RATE_LIMIT_STORAGE_BACKEND", "database"), \
         patch.object(PersistenceRepository, "is_storage_configured", new_callable=PropertyMock, return_value=True), \
         patch.object(persistence_repo, "check_and_increment_rate_limit_sync", side_effect=sim.rpc_check_and_increment):
        # Instance A handles 5 requests then restarts (clear in-memory cache)
        for _ in range(5):
            check_rate_limit(RateLimitAction.INCIDENT_CREATE, user)
        in_memory_rate_limiter.clear()

        # Instance B / post-restart receives 6th request -> must still be throttled 429
        with pytest.raises(Exception) as exc_6:
            check_rate_limit(RateLimitAction.INCIDENT_CREATE, user)
        assert exc_6.value.status_code == 429
        assert int(exc_6.value.headers["Retry-After"]) >= 1


def test_17_production_rejects_disabled_memory_missing_service_role_and_weak_pepper():
    """
    Stage A #9, #10, #11, #12:
    Production validation must unconditionally reject:
    - RATE_LIMIT_ENABLED=False (even alongside memory backend)
    - RATE_LIMIT_STORAGE_BACKEND='memory'
    - Anon SUPABASE_KEY without SUPABASE_SERVICE_ROLE_KEY or whitespace-only credentials
    - Missing, empty, whitespace-only, or short (<16 chars) RATE_LIMIT_KEY_PEPPER
    """
    base_valid = {
        "ENVIRONMENT": "production",
        "SUPABASE_AUTH_ENABLED": True,
        "SUPABASE_URL": "https://project.supabase.co",
        "SUPABASE_SERVICE_ROLE_KEY": "srv-key-abcdefghijklmnopqrstuvwxyz",
        "DEVICE_INGEST_API_KEY": "device-key-12345",
        "RATE_LIMIT_ENABLED": True,
        "RATE_LIMIT_STORAGE_BACKEND": "auto",
        "RATE_LIMIT_KEY_PEPPER": _VALID_PROD_PEPPER,
        "_env_file": None,
    }

    # Valid production config must succeed
    validate_production_configuration(Settings(**base_valid))

    # Stage A #9: Production rejects disabled rate limiting (even with memory backend)
    with pytest.raises(RuntimeError) as exc_dis:
        validate_production_configuration(Settings(**{**base_valid, "RATE_LIMIT_ENABLED": False, "RATE_LIMIT_STORAGE_BACKEND": "memory"}))
    assert "RATE_LIMIT_ENABLED must be True in production" in str(exc_dis.value)
    assert "RATE_LIMIT_STORAGE_BACKEND='memory'" in str(exc_dis.value)

    # Runtime defense-in-depth if RATE_LIMIT_ENABLED=False in production
    with patch.object(settings, "ENVIRONMENT", "production"), \
         patch.object(settings, "RATE_LIMIT_ENABLED", False):
        with pytest.raises(Exception) as exc_rt_dis:
            check_rate_limit(RateLimitAction.INCIDENT_CREATE, _make_auth_claims("u_rt"))
        assert exc_rt_dis.value.status_code == 503

    # Stage A #10: Production rejects memory backend
    with pytest.raises(RuntimeError) as exc_mem:
        validate_production_configuration(Settings(**{**base_valid, "RATE_LIMIT_STORAGE_BACKEND": "memory"}))
    assert "RATE_LIMIT_STORAGE_BACKEND='memory'" in str(exc_mem.value)

    # Stage A #11: Anon SUPABASE_KEY cannot satisfy SUPABASE_SERVICE_ROLE_KEY requirement; whitespace rejected
    with pytest.raises(RuntimeError) as exc_anon_only:
        validate_production_configuration(Settings(**{**base_valid, "SUPABASE_SERVICE_ROLE_KEY": None, "SUPABASE_KEY": "anon-key-only"}))
    assert "SUPABASE_SERVICE_ROLE_KEY" in str(exc_anon_only.value)

    for ws_key in ["   ", ""]:
        with pytest.raises(RuntimeError):
            validate_production_configuration(Settings(**{**base_valid, "SUPABASE_SERVICE_ROLE_KEY": ws_key, "SUPABASE_KEY": "anon-key-only"}))
        with pytest.raises(RuntimeError):
            validate_production_configuration(Settings(**{**base_valid, "SUPABASE_URL": ws_key, "SUPABASE_JWT_SECRET": "a_very_long_hs256_secret_key"}))

    # Ensure config validation and PersistenceRepository.is_storage_configured agree on whitespace credentials
    ws_repo = PersistenceRepository(
        supabase_url="https://project.supabase.co",
        supabase_key="anon-key",
        service_role_key="   ",
    )
    assert ws_repo.is_storage_configured is False

    # Stage A #12: Missing or weak RATE_LIMIT_KEY_PEPPER rejected
    for bad_pepper in [None, "", "   ", "too-short-15chr"]:
        with pytest.raises(RuntimeError) as exc_pep:
            validate_production_configuration(Settings(**{**base_valid, "RATE_LIMIT_KEY_PEPPER": bad_pepper}))
        assert "RATE_LIMIT_KEY_PEPPER" in str(exc_pep.value)

        with patch.object(settings, "ENVIRONMENT", "production"), \
             patch.object(settings, "RATE_LIMIT_KEY_PEPPER", bad_pepper):
            with pytest.raises(Exception) as exc_rt_pep:
                check_rate_limit(RateLimitAction.INCIDENT_CREATE, _make_auth_claims("u_pep"))
            assert exc_rt_pep.value.status_code == 503

    # Invalid rate limits/windows rejected
    with pytest.raises(ValidationError):
        Settings(RATE_LIMIT_ANON_INCIDENT_CREATE_MAX=0, _env_file=None)
    with pytest.raises(ValidationError):
        Settings(RATE_LIMIT_ANON_PHOTO_RETRIEVE_WINDOW_SEC=0, _env_file=None)


# ==============================================================================
# 7. Municipal Exemptions, Invalid SQL RPC Inputs, Migration 006 AST & PLpgSQL
# ==============================================================================

def test_18_municipal_and_field_worker_workflows_bypass_citizen_limits():
    """Verify municipal officers, field workers, admins, and system bypass citizen creation limit."""
    for role in ["municipal_officer", "municipality", "field_worker", "worker", "admin", "system"]:
        claims = _make_auth_claims(f"priv_{role}", role=role)
        for _ in range(15):
            check_rate_limit(RateLimitAction.INCIDENT_CREATE, claims)


def test_19_invalid_sql_rpc_inputs_fail_safely():
    """
    Stage A #13: Invalid RPC arguments are rejected before HTTP with StorageValidationError,
    and PostgREST SQLSTATE 22023 responses map cleanly to StorageValidationError -> fail-closed 503.
    """
    repo = PersistenceRepository(
        supabase_url="https://test.supabase.co",
        supabase_key="anon-key",
        service_role_key="service-role-secret",
    )
    valid_hash = "a" * 64

    bad_inputs = [
        ("short", "incident_create", 5, 900),
        ("A" * 64, "incident_create", 5, 900),
        ("z" * 64, "incident_create", 5, 900),
        (valid_hash, "unknown_action", 5, 900),
        (valid_hash, "", 5, 900),
        (valid_hash, "incident_create", 0, 900),
        (valid_hash, "incident_create", True, 900),
        (valid_hash, "incident_create", 100001, 900),
        (valid_hash, "incident_create", 5, 0),
        (valid_hash, "incident_create", 5, False),
        (valid_hash, "incident_create", 5, 2592001),
    ]
    for kh, act, lim, win in bad_inputs:
        with pytest.raises(StorageValidationError):
            repo.check_and_increment_rate_limit_sync(kh, act, lim, win)

    # Simulate PostgREST returning SQLSTATE 22023 for invalid RPC parameters
    mock_resp = MagicMock()
    mock_resp.status_code = 400
    mock_resp.json.return_value = {"code": "22023", "message": "Invalid rate limit key hash."}

    with patch("app.services.persistence_repository.httpx.Client") as mock_client_cls:
        mock_client = mock_client_cls.return_value.__enter__.return_value
        mock_client.post.return_value = mock_resp
        with pytest.raises(StorageValidationError):
            repo.check_and_increment_rate_limit_sync(valid_hash, "incident_create", 5, 900)


def test_20_database_migration_006_ast_plpgsql_and_privileges():
    """Verify Migration 006 parses with BOTH pglast.parse_sql and pglast.parse_plpgsql and enforces least privilege."""
    from pathlib import Path
    mig_path = Path(__file__).resolve().parent.parent.parent / "database" / "migrations" / "006_rate_limiting.sql"
    assert mig_path.is_file(), f"Migration file missing: {mig_path}"
    sql = mig_path.read_text(encoding="utf-8")

    # 1. Both SQL and PL/pgSQL body must parse cleanly
    parsed = pglast.parse_sql(sql)
    assert len(parsed) == 9
    idx = sql.find("CREATE OR REPLACE FUNCTION")
    end = sql.find("REVOKE ALL ON FUNCTION")
    pl_ast = pglast.parse_plpgsql(sql[idx:end].strip())
    assert pl_ast and "PLpgSQL_function" in pl_ast[0]

    # 2. Atomic upsert, concurrency-safe cleanup, constraints, and least-privilege checks
    assert "ON CONFLICT (rate_limit_key) DO UPDATE" in sql
    assert "ORDER BY window_end ASC" in sql
    assert "FOR UPDATE SKIP LOCKED" in sql
    assert "AND window_end < (v_now - INTERVAL '1 hour')" in sql
    assert "USING ERRCODE = '22023'" in sql
    assert "chk_api_rate_limits_key_hex" in sql
    assert "chk_api_rate_limits_window_order" in sql
    assert "REVOKE ALL ON TABLE public.api_rate_limits FROM PUBLIC, anon, authenticated, service_role;" in sql
    assert "GRANT ALL ON TABLE public.api_rate_limits TO service_role" not in sql
    assert "REVOKE ALL ON FUNCTION public.check_and_increment_rate_limit_rpc" in sql
    assert "GRANT EXECUTE ON FUNCTION public.check_and_increment_rate_limit_rpc" in sql
    assert "SET search_path = pg_catalog, public, pg_temp" in sql


# ==============================================================================
# 8. Stage B Hardened Regression Tests (RL-AUD-A-01, RL-AUD-07..13)
# ==============================================================================

def test_21_repeated_nonexistent_incident_id_photo_uploads_throttled():
    """
    Stage B (RL-AUD-A-01): Repeated photo uploads with nonexistent incident IDs must consume
    quota and be throttled (HTTP 429) without generating unlimited database queries.
    """
    client = TestClient(app)
    nonexistent_id = "00000000-0000-0000-0000-000000000000"
    jpeg_bytes = _dummy_jpeg_bytes()

    # With anon limit = 5 req / 15 min
    # Requests 1..5 should fail with 404 (Incident not found) but consume quota
    with patch.object(state_store, "get_incident", wraps=state_store.get_incident) as spy_get_incident:
        for i in range(5):
            resp = client.post(
                f"/api/v1/incidents/{nonexistent_id}/photos",
                files=[("files", ("test.jpg", io.BytesIO(jpeg_bytes), "image/jpeg"))],
            )
            assert resp.status_code == 404, f"Request {i+1} expected 404, got {resp.status_code}"

        assert spy_get_incident.call_count == 5

        # Request 6 must be blocked by rate limiter with 429 BEFORE touching get_incident
        resp_blocked = client.post(
            f"/api/v1/incidents/{nonexistent_id}/photos",
            files=[("files", ("test.jpg", io.BytesIO(jpeg_bytes), "image/jpeg"))],
        )
        assert resp_blocked.status_code == 429
        assert resp_blocked.headers.get("Retry-After") is not None
        # Verify get_incident was NOT called a 6th time
        assert spy_get_incident.call_count == 5


def test_22_partial_cloud_config_fails_closed_in_rate_limiter():
    """
    Stage B (RL-AUD-08): Partial cloud configuration (is_configured=True, is_storage_configured=False)
    must fail closed with HTTP 503 and never silently fall back to in-memory.
    """
    with patch.object(persistence_repo, "_is_configured", True):
        with patch.object(persistence_repo, "_supabase_service_role_key", None):
            assert persistence_repo.is_configured is True
            assert persistence_repo.is_storage_configured is False

            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc_info:
                check_rate_limit(
                    RateLimitAction.INCIDENT_CREATE,
                    claims=None,
                    request=_make_mock_request("203.0.113.88"),
                )
            assert exc_info.value.status_code == 503
            assert "Rate limit verification service unavailable" in exc_info.value.detail


def test_23_rpc_response_strict_type_validation_fails_closed(monkeypatch):
    """
    Stage B (RL-AUD-09): Malformed RPC responses (string 'false', booleans as numbers, negative retry)
    must fail closed with HTTP 503 and never fail open.
    """
    from fastapi import HTTPException

    monkeypatch.setattr(settings, "RATE_LIMIT_STORAGE_BACKEND", "database")
    bad_payloads = [
        "not a dict",
        {"allowed": "false"},  # string boolean must not be coerced
        {"allowed": None},
        {"allowed": True, "current_count": "one"},  # string count
        {"allowed": True, "current_count": True},   # bool as int
        {"allowed": True, "limit": False},
        {"allowed": True, "remaining": True},
        {"allowed": True, "reset_after_sec": 0},    # reset must be >= 1
        {"allowed": False, "retry_after_sec": True},
    ]

    with patch.object(persistence_repo, "_is_configured", True):
        with patch.object(persistence_repo, "_supabase_url", "https://test.supabase.co"):
            with patch.object(persistence_repo, "_supabase_service_role_key", "valid-srv-key"):
                for bad_payload in bad_payloads:
                    with patch.object(
                        persistence_repo,
                        "check_and_increment_rate_limit_sync",
                        return_value=bad_payload,
                    ):
                        with pytest.raises(HTTPException) as exc_info:
                            check_rate_limit(
                                RateLimitAction.INCIDENT_CREATE,
                                claims=_make_auth_claims("citizen_bad_rpc", role="citizen"),
                            )
                        assert exc_info.value.status_code == 503


@pytest.mark.anyio
async def test_24_async_rate_limiter_offload():
    """
    Stage B (RL-AUD-11): check_rate_limit_async offloads blocking check to worker thread.
    """
    from app.services.rate_limiter import check_rate_limit_async
    import threading

    calling_thread_id = threading.get_ident()
    executed_thread_id = None

    def dummy_check(*args, **kwargs):
        nonlocal executed_thread_id
        executed_thread_id = threading.get_ident()

    with patch("app.services.rate_limiter.check_rate_limit", side_effect=dummy_check):
        await check_rate_limit_async(
            RateLimitAction.PHOTO_UPLOAD,
            claims=None,
            request=_make_mock_request("203.0.113.1"),
        )
        assert executed_thread_id is not None
        assert executed_thread_id != calling_thread_id, "Rate limit check must run in worker thread"


def test_25_in_memory_limiter_cleanup_efficiency():
    """
    Stage B (RL-AUD-13): _InMemoryRateLimiter does not scan the full store on every request
    when size exceeds 5,000 entries.
    """
    from app.services.rate_limiter import _InMemoryRateLimiter
    limiter = _InMemoryRateLimiter()

    # Pre-populate 5,100 keys
    for i in range(5100):
        limiter._store[f"key_{i}"] = (100.0, 200.0, 1)

    # Calling check_and_increment with now=150 should not clean up if not expired
    limiter.check_and_increment("new_key", "action", 10, 60, now_ts=150.0)
    assert len(limiter._store) == 5101
    assert limiter._last_cleanup_ts == 150.0

    # Advance now by 5s (< 10s interval) with expired keys
    limiter.check_and_increment("new_key_2", "action", 10, 60, now_ts=155.0)
    # Cleanup should have been skipped because < 10s elapsed
    assert limiter._last_cleanup_ts == 150.0


def test_26_legacy_photo_retrieval_rate_limited():
    """
    Stage B (RL-AUD-12): Legacy photo retrieval route (/api/v1/incidents/photos/{filename})
    enforces rate limiting prior to PostgREST query.
    """
    client = TestClient(app)
    # Anon limit for photo retrieve is 30 req / 60 sec
    # Send 30 requests
    for i in range(30):
        resp = client.get("/api/v1/incidents/photos/sample_photo.jpg")
        # 404 because photo doesn't exist, but consumes quota
        assert resp.status_code == 404, f"Request {i+1} got {resp.status_code}"

    # 31st request should be throttled with 429
    resp_blocked = client.get("/api/v1/incidents/photos/sample_photo.jpg")
    assert resp_blocked.status_code == 429
    assert resp_blocked.headers.get("Retry-After") is not None


def test_27_municipal_officers_exempt_on_photo_endpoints():
    """
    Stage B (RL-AUD-07): Municipal officers and municipal admins are exempt from photo
    upload and retrieval throttling during triage.
    """
    for role in ["municipal_officer", "municipality", "municipal_admin"]:
        claims = _make_auth_claims(f"officer_{role}", role=role)
        # 40 photo uploads (well over citizen limit of 10)
        for _ in range(40):
            check_rate_limit(RateLimitAction.PHOTO_UPLOAD, claims)

        # 80 photo retrieves (well over citizen limit of 60)
        for _ in range(80):
            check_rate_limit(RateLimitAction.PHOTO_RETRIEVE, claims)
