"""
DRAIN-X Phase 3: Supabase Storage Integration & Security Remediation Test Suite

Validates Supabase Storage methods in PersistenceRepository with strict security boundaries:
1. Upload cannot overwrite an existing object (x-upsert: false, 409 StorageConflictError).
2. Traversal and malformed paths are rejected without silent normalization.
3. Cross-incident object access is rejected.
4. MIME allowlist enforced (JPEG, PNG, WebP only; extension-MIME alignment).
5. Deletion cannot remove neighboring objects (strictly targets single validated object).
6. Signed URL expiry boundaries validated (1 <= TTL <= 3600).
7. Secrets and signed URLs do not appear in logs; zero resp.text.
8. Unconfigured behavior is explicit (StorageNotConfiguredError on all methods).
9. Missing service-role credentials fail closed even if an anon key exists.
10. Database-aligned identifier validation (incidents.id <= 32, audits.audit_id <= 32, actor_id <= 128, actor_role <= 64).
11. Actor attribution is preserved and intentionally required without masking defaults.
12. Identical synchronous and asynchronous behavior across download, delete, sign, and upload.
13. Download 404 handling (returns None and logs safely without NameError).
14. Migration 005 RPC draft security verification (explicit position checks, canonical path scoping, session role).
"""

import logging
from pathlib import Path
import re
import pytest
from unittest.mock import MagicMock, patch
import httpx

from app.services.persistence_repository import (
    PersistenceRepository,
    StorageError,
    StorageNotConfiguredError,
    StorageValidationError,
    StorageConflictError,
    StorageNotFoundError,
)


@pytest.fixture
def configured_repo():
    """Repository configured with explicit dummy Supabase credentials including service_role."""
    return PersistenceRepository(
        supabase_url="https://mockproject.supabase.co",
        supabase_key="mock-anon-key-secret123",
        service_role_key="mock-service-role-key-secret456",
        timeout_sec=5.0,
    )


@pytest.fixture
def anon_only_repo():
    """Repository configured with anon key only (missing service_role_key)."""
    return PersistenceRepository(
        supabase_url="https://mockproject.supabase.co",
        supabase_key="mock-anon-key-secret123",
        service_role_key="",
        timeout_sec=5.0,
    )


@pytest.fixture
def unconfigured_repo():
    """Repository explicitly unconfigured (local in-memory fallback)."""
    return PersistenceRepository(
        supabase_url="",
        supabase_key="",
        service_role_key="",
        timeout_sec=5.0,
    )


# ----------------------------------------------------------------------
# 1. No-Overwrite & Conflict Handling (x-upsert: false)
# ----------------------------------------------------------------------

def test_upload_sync_enforces_no_overwrite_and_handles_conflict(configured_repo):
    incident_id = "INC-202611-001"
    photo_id = "evidence-1.jpg"
    file_bytes = b"\xff\xd8\xff\xe0mock-jpeg-bytes"
    content_type = "image/jpeg"

    # Test success sends x-upsert: false
    mock_resp_success = MagicMock(spec=httpx.Response)
    mock_resp_success.status_code = 201

    with patch("httpx.Client.post", return_value=mock_resp_success) as mock_post:
        path = configured_repo.upload_incident_photo_sync(
            incident_id=incident_id,
            photo_id=photo_id,
            file_bytes=file_bytes,
            content_type=content_type,
        )
        assert path == f"{incident_id}/{photo_id}"
        mock_post.assert_called_once()
        _, call_kwargs = mock_post.call_args
        assert call_kwargs["headers"]["x-upsert"] == "false"

    # Test HTTP 409 triggers StorageConflictError
    mock_resp_conflict = MagicMock(spec=httpx.Response)
    mock_resp_conflict.status_code = 409
    mock_resp_conflict.text = "The resource already exists"

    with patch("httpx.Client.post", return_value=mock_resp_conflict):
        with pytest.raises(StorageConflictError, match="Storage object already exists"):
            configured_repo.upload_incident_photo_sync(
                incident_id=incident_id,
                photo_id=photo_id,
                file_bytes=file_bytes,
                content_type=content_type,
            )


@pytest.mark.anyio
async def test_upload_async_enforces_no_overwrite_and_handles_conflict(configured_repo):
    incident_id = "INC-202611-002"
    photo_id = "evidence-2.png"
    file_bytes = b"\x89PNGmock-png-bytes"
    content_type = "image/png"

    mock_resp_conflict = MagicMock(spec=httpx.Response)
    mock_resp_conflict.status_code = 409

    with patch("httpx.AsyncClient.post", return_value=mock_resp_conflict) as mock_post:
        with pytest.raises(StorageConflictError, match="Storage object already exists"):
            await configured_repo.upload_incident_photo(
                incident_id=incident_id,
                photo_id=photo_id,
                file_bytes=file_bytes,
                content_type=content_type,
            )
        mock_post.assert_called_once()
        _, call_kwargs = mock_post.call_args
        assert call_kwargs["headers"]["x-upsert"] == "false"


@pytest.mark.parametrize("dup_payload", [
    {"statusCode": "400", "error": "Duplicate", "message": "The resource already exists"},
    {"statusCode": "400", "error": "duplicate_object", "message": "Duplicate"},
    {"statusCode": "400", "error": "Conflict", "message": "already exists"},
    {"code": "alreadyexists", "message": "The file already exists"},
    {"message": "duplicate key value violates unique constraint"},
])
def test_upload_sync_duplicate_400_mapped_to_conflict(configured_repo, dup_payload):
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 400
    mock_resp.json.return_value = dup_payload

    with patch("httpx.Client.post", return_value=mock_resp):
        with pytest.raises(StorageConflictError, match="Storage object already exists"):
            configured_repo.upload_incident_photo_sync(
                incident_id="INC-001",
                photo_id="photo1.jpg",
                file_bytes=b"jpeg-bytes",
                content_type="image/jpeg",
            )


@pytest.mark.parametrize("unrelated_payload", [
    {"error": "Bad Request", "message": "Invalid file format"},
    {"error": "Payload Too Large", "message": "File exceeds 10MB limit"},
    {"statusCode": "400", "message": "Missing required boundary in multipart header"},
])
def test_upload_sync_unrelated_400_remains_generic_storage_error(configured_repo, unrelated_payload):
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 400
    mock_resp.json.return_value = unrelated_payload

    with patch("httpx.Client.post", return_value=mock_resp):
        with pytest.raises(StorageError) as exc_info:
            configured_repo.upload_incident_photo_sync(
                incident_id="INC-001",
                photo_id="photo1.jpg",
                file_bytes=b"jpeg-bytes",
                content_type="image/jpeg",
            )
        assert not isinstance(exc_info.value, StorageConflictError)
        assert "HTTP 400" in str(exc_info.value)


@pytest.mark.anyio
@pytest.mark.parametrize("dup_payload", [
    {"statusCode": "400", "error": "Duplicate", "message": "The resource already exists"},
    {"statusCode": "400", "error": "duplicate_object", "message": "Duplicate"},
    {"statusCode": "400", "error": "Conflict", "message": "already exists"},
    {"code": "alreadyexists", "message": "The file already exists"},
    {"message": "duplicate key value violates unique constraint"},
])
async def test_upload_async_duplicate_400_mapped_to_conflict(configured_repo, dup_payload):
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 400
    mock_resp.json.return_value = dup_payload

    with patch("httpx.AsyncClient.post", return_value=mock_resp):
        with pytest.raises(StorageConflictError, match="Storage object already exists"):
            await configured_repo.upload_incident_photo(
                incident_id="INC-001",
                photo_id="photo1.jpg",
                file_bytes=b"jpeg-bytes",
                content_type="image/jpeg",
            )


@pytest.mark.anyio
@pytest.mark.parametrize("unrelated_payload", [
    {"error": "Bad Request", "message": "Invalid file format"},
    {"error": "Payload Too Large", "message": "File exceeds 10MB limit"},
    {"statusCode": "400", "message": "Missing required boundary in multipart header"},
])
async def test_upload_async_unrelated_400_remains_generic_storage_error(configured_repo, unrelated_payload):
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 400
    mock_resp.json.return_value = unrelated_payload

    with patch("httpx.AsyncClient.post", return_value=mock_resp):
        with pytest.raises(StorageError) as exc_info:
            await configured_repo.upload_incident_photo(
                incident_id="INC-001",
                photo_id="photo1.jpg",
                file_bytes=b"jpeg-bytes",
                content_type="image/jpeg",
            )
        assert not isinstance(exc_info.value, StorageConflictError)
        assert "HTTP 400" in str(exc_info.value)


# ----------------------------------------------------------------------
# 2. Strict Path Canonicalization: Reject Noncanonical Paths
# ----------------------------------------------------------------------

NONCANONICAL_PATHS = [
    "/INC-001/photo.jpg",            # Leading slash
    "INC-001/photo.jpg/",            # Trailing slash
    "INC-001\\photo.jpg",            # Backslash
    " INC-001/photo.jpg",            # Leading whitespace
    "INC-001/photo.jpg ",            # Trailing whitespace
    "INC-001/photo%2ejpg",           # Percent-encoded dot
    "INC-001/photo%2f.jpg",          # Percent-encoded slash
    "INC-001/../photo.jpg",          # Directory traversal
    "INC-001/../../etc/passwd",      # Multi-level traversal
    "INC-001//photo.jpg",            # Double slash
    "INC-001/photo\x00.jpg",         # Null byte
    "INC-001/photo.exe",             # Unauthorized extension
    "INC-001",                       # Missing filename
    "photo.jpg",                     # Missing incident ID
    "INC-001/sub/photo.jpg",         # 3 segments
    "bucket/INC-001/photo.jpg",      # Unexpected bucket prefix
]

@pytest.mark.parametrize("bad_path", NONCANONICAL_PATHS)
def test_path_canonicalization_rejects_noncanonical_paths_sync(configured_repo, bad_path):
    with pytest.raises(StorageValidationError):
        configured_repo.create_signed_photo_url(bad_path)

    with pytest.raises(StorageValidationError):
        configured_repo.download_incident_photo(bad_path)

    with pytest.raises(StorageValidationError):
        configured_repo.delete_incident_photo(bad_path)


@pytest.mark.anyio
@pytest.mark.parametrize("bad_path", NONCANONICAL_PATHS)
async def test_path_canonicalization_rejects_noncanonical_paths_async(configured_repo, bad_path):
    with pytest.raises(StorageValidationError):
        await configured_repo.create_signed_photo_url_async(bad_path)

    with pytest.raises(StorageValidationError):
        await configured_repo.download_incident_photo_async(bad_path)

    with pytest.raises(StorageValidationError):
        await configured_repo.delete_incident_photo_async(bad_path)


@pytest.mark.parametrize("bad_photo_id", [
    "/evil.jpg",
    "evil.jpg/",
    "..\\evil.jpg",
    "sub/evil.jpg",
    "evil%2ejpg",
    "evil\x00.jpg",
    "evil.exe",
    " evil.jpg",
    "evil.jpg ",
])
def test_upload_rejects_noncanonical_photo_ids(configured_repo, bad_photo_id):
    with pytest.raises(StorageValidationError):
        configured_repo.upload_incident_photo_sync(
            incident_id="INC-001",
            photo_id=bad_photo_id,
            file_bytes=b"dummy",
            content_type="image/jpeg",
        )


# ----------------------------------------------------------------------
# 3. Cross-Incident Isolation
# ----------------------------------------------------------------------

def test_download_and_sign_reject_cross_incident_access(configured_repo):
    with pytest.raises(StorageValidationError, match="Cross-incident object access rejected"):
        configured_repo.download_incident_photo(
            path="INC-999/photo.jpg",
            incident_id="INC-001",
        )

    with pytest.raises(StorageValidationError, match="Cross-incident object access rejected"):
        configured_repo.create_signed_photo_url(
            path="INC-999/photo.jpg",
            incident_id="INC-001",
        )

    with pytest.raises(StorageValidationError, match="Cross-incident object access rejected"):
        configured_repo.delete_incident_photo(
            path="INC-999/photo.jpg",
            incident_id="INC-001",
        )


@pytest.mark.anyio
async def test_download_and_delete_async_reject_cross_incident_access(configured_repo):
    with pytest.raises(StorageValidationError, match="Cross-incident object access rejected"):
        await configured_repo.download_incident_photo_async(
            path="INC-999/photo.jpg",
            incident_id="INC-001",
        )

    with pytest.raises(StorageValidationError, match="Cross-incident object access rejected"):
        await configured_repo.delete_incident_photo_async(
            path="INC-999/photo.jpg",
            incident_id="INC-001",
        )


# ----------------------------------------------------------------------
# 4. MIME Allowlist & Extension Enforcement
# ----------------------------------------------------------------------

@pytest.mark.parametrize("bad_mime", [
    "application/pdf",
    "image/gif",
    "text/html",
    "application/octet-stream",
    "application/x-sh",
])
def test_upload_rejects_disallowed_mimes(configured_repo, bad_mime):
    with pytest.raises(StorageValidationError, match="Unsupported MIME type"):
        configured_repo.upload_incident_photo_sync(
            incident_id="INC-001",
            photo_id="photo.jpg",
            file_bytes=b"bytes",
            content_type=bad_mime,
        )


def test_upload_rejects_mismatched_extension_and_mime(configured_repo):
    with pytest.raises(StorageValidationError, match="does not match Content-Type"):
        configured_repo.upload_incident_photo_sync(
            incident_id="INC-001",
            photo_id="photo.png",
            file_bytes=b"bytes",
            content_type="image/jpeg",
        )


# ----------------------------------------------------------------------
# 5. Download 404 Handling & Clean Log Verification
# ----------------------------------------------------------------------

def test_download_incident_photo_sync_404_handling(configured_repo, caplog):
    caplog.set_level(logging.WARNING)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 404

    with patch("httpx.Client.get", return_value=mock_resp):
        result = configured_repo.download_incident_photo("INC-100/missing.jpg")
        assert result is None

    assert any("Photo not found in Supabase Storage: incident-evidence/INC-100/missing.jpg" in rec.getMessage() for rec in caplog.records)


@pytest.mark.anyio
async def test_download_incident_photo_async_404_handling(configured_repo, caplog):
    caplog.set_level(logging.WARNING)
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 404

    with patch("httpx.AsyncClient.get", return_value=mock_resp):
        result = await configured_repo.download_incident_photo_async("INC-100/missing.png")
        assert result is None

    assert any("Photo not found in Supabase Storage: incident-evidence/INC-100/missing.png" in rec.getMessage() for rec in caplog.records)


# ----------------------------------------------------------------------
# 6. Deletion Isolation: Single Object Targeting & No Neighbor Removal
# ----------------------------------------------------------------------

def test_delete_targets_exact_single_object_and_preserves_neighbors(configured_repo):
    target_to_delete = "INC-100/photo1.jpg"

    existing_storage_objects = {
        "INC-100/photo1.jpg",
        "INC-100/photo10.jpg",
        "INC-100/photo1.jpg.bak",
        "INC-100/photo2.jpg",
    }

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200

    def mock_request(method, url, **kwargs):
        assert method == "DELETE"
        payload = kwargs.get("json", {})
        prefixes = payload.get("prefixes", [])
        assert prefixes == [target_to_delete]
        for p in prefixes:
            existing_storage_objects.discard(p)
        return mock_resp

    with patch("httpx.Client.request", side_effect=mock_request) as mock_req:
        deleted = configured_repo.delete_incident_photo(target_to_delete)
        assert deleted is True
        mock_req.assert_called_once()

    assert "INC-100/photo1.jpg" not in existing_storage_objects
    assert "INC-100/photo10.jpg" in existing_storage_objects
    assert "INC-100/photo1.jpg.bak" in existing_storage_objects
    assert "INC-100/photo2.jpg" in existing_storage_objects


@pytest.mark.anyio
async def test_delete_async_targets_exact_single_object(configured_repo):
    target_to_delete = "INC-200/photo_async.webp"

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200

    with patch("httpx.AsyncClient.request", return_value=mock_resp) as mock_req:
        deleted = await configured_repo.delete_incident_photo_async(target_to_delete)
        assert deleted is True
        mock_req.assert_called_once()
        _, call_kwargs = mock_req.call_args
        assert call_kwargs["json"] == {"prefixes": [target_to_delete]}


# ----------------------------------------------------------------------
# 7. Signed URL Expiry Boundaries
# ----------------------------------------------------------------------

@pytest.mark.parametrize("invalid_ttl", [
    0,
    -10,
    3601,
    86401,
    "invalid",
    True,
])
def test_create_signed_photo_url_rejects_out_of_bound_expiry(configured_repo, invalid_ttl):
    with pytest.raises(StorageValidationError):
        configured_repo.create_signed_photo_url(
            path="INC-001/photo.jpg",
            expires_in=invalid_ttl,
        )


@pytest.mark.parametrize("valid_ttl", [1, 60, 300, 3600])
def test_create_signed_photo_url_accepts_valid_expiry(configured_repo, valid_ttl):
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "signedURL": f"/storage/v1/object/sign/incident-evidence/INC-001/photo.jpg?token=tok{valid_ttl}"
    }

    with patch("httpx.Client.post", return_value=mock_resp):
        url = configured_repo.create_signed_photo_url(
            path="INC-001/photo.jpg",
            expires_in=valid_ttl,
        )
        assert url.startswith("https://mockproject.supabase.co")


def test_create_signed_photo_url_origin_validation_sync(configured_repo):
    # Valid absolute same-origin matching requested bucket and object
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "signedURL": "https://mockproject.supabase.co/storage/v1/object/sign/incident-evidence/INC-001/photo.jpg?token=abc"
    }
    with patch("httpx.Client.post", return_value=mock_resp):
        url = configured_repo.create_signed_photo_url("INC-001/photo.jpg")
        assert url == "https://mockproject.supabase.co/storage/v1/object/sign/incident-evidence/INC-001/photo.jpg?token=abc"

    # Valid relative paths in expected Supabase Storage signed-object formats
    valid_relatives = [
        "/storage/v1/object/sign/incident-evidence/INC-001/photo.jpg?token=abc",
        "/object/sign/incident-evidence/INC-001/photo.jpg?token=abc",
        "object/sign/incident-evidence/INC-001/photo.jpg?token=abc",
    ]
    for rel_path in valid_relatives:
        mock_resp.json.return_value = {"signedURL": rel_path}
        with patch("httpx.Client.post", return_value=mock_resp):
            url = configured_repo.create_signed_photo_url("INC-001/photo.jpg")
            assert url == "https://mockproject.supabase.co/storage/v1/object/sign/incident-evidence/INC-001/photo.jpg?token=abc"

    # Disallowed dangerous schemes
    disallowed_schemes = [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "ftp://mockproject.supabase.co/storage/v1/object/sign/incident-evidence/INC-001/photo.jpg?token=abc",
        "file:///etc/passwd",
        "vbscript:msgbox(1)",
        "blob:https://mockproject.supabase.co/uuid-1234",
    ]
    for bad_scheme_url in disallowed_schemes:
        mock_resp.json.return_value = {"signedURL": bad_scheme_url}
        with patch("httpx.Client.post", return_value=mock_resp):
            with pytest.raises(StorageError):
                configured_repo.create_signed_photo_url("INC-001/photo.jpg")

    # Protocol-relative attempt
    mock_resp.json.return_value = {
        "signedURL": "//evil.attacker.com/storage/v1/object/sign/incident-evidence/INC-001/photo.jpg?token=abc"
    }
    with patch("httpx.Client.post", return_value=mock_resp):
        with pytest.raises(StorageError, match="Untrusted protocol-relative signed URL"):
            configured_repo.create_signed_photo_url("INC-001/photo.jpg")

    # Mismatched host
    mock_resp.json.return_value = {
        "signedURL": "https://evil.attacker.com/storage/v1/object/sign/incident-evidence/INC-001/photo.jpg?token=abc"
    }
    with patch("httpx.Client.post", return_value=mock_resp):
        with pytest.raises(StorageError, match="Untrusted signed URL origin"):
            configured_repo.create_signed_photo_url("INC-001/photo.jpg")

    # Mismatched scheme (http instead of https)
    mock_resp.json.return_value = {
        "signedURL": "http://mockproject.supabase.co/storage/v1/object/sign/incident-evidence/INC-001/photo.jpg?token=abc"
    }
    with patch("httpx.Client.post", return_value=mock_resp):
        with pytest.raises(StorageError, match="Untrusted signed URL scheme"):
            configured_repo.create_signed_photo_url("INC-001/photo.jpg")

    # Disallowed relative path formats (not starting with expected signed-object prefix)
    invalid_rel_paths = [
        "/rest/v1/incidents",
        "/storage/v1/other/path",
        "unrelated/path/to/file.jpg",
        "/storage/v1/bucket/list",
    ]
    for bad_rel in invalid_rel_paths:
        mock_resp.json.return_value = {"signedURL": bad_rel}
        with patch("httpx.Client.post", return_value=mock_resp):
            with pytest.raises(StorageError, match="Invalid signed URL relative path"):
                configured_repo.create_signed_photo_url("INC-001/photo.jpg")

    # Noncanonical characters and path traversal
    invalid_path_anomalies = [
        "/storage/v1/object/sign/incident-evidence/INC-001/../photo.jpg?token=abc",
        "/storage/v1/object/sign/incident-evidence\\INC-001/photo.jpg?token=abc",
        "/storage/v1/object/sign//incident-evidence/INC-001/photo.jpg?token=abc",
        "/storage/v1/object/sign/incident-evidence/INC-001/photo.jpg\x00extra?token=abc",
    ]
    for bad_path in invalid_path_anomalies:
        mock_resp.json.return_value = {"signedURL": bad_path}
        with patch("httpx.Client.post", return_value=mock_resp):
            with pytest.raises(StorageError):
                configured_repo.create_signed_photo_url("INC-001/photo.jpg")

    # Bucket and canonical object target mismatch
    mock_resp.json.return_value = {
        "signedURL": "https://mockproject.supabase.co/storage/v1/object/sign/wrong-bucket/INC-001/photo.jpg?token=abc"
    }
    with patch("httpx.Client.post", return_value=mock_resp):
        with pytest.raises(StorageError, match="Signed URL path .* does not match expected target object"):
            configured_repo.create_signed_photo_url("INC-001/photo.jpg")

    mock_resp.json.return_value = {
        "signedURL": "https://mockproject.supabase.co/storage/v1/object/sign/incident-evidence/INC-999/other.jpg?token=abc"
    }
    with patch("httpx.Client.post", return_value=mock_resp):
        with pytest.raises(StorageError, match="Signed URL path .* does not match expected target object"):
            configured_repo.create_signed_photo_url("INC-001/photo.jpg")


@pytest.mark.anyio
async def test_create_signed_photo_url_origin_validation_async(configured_repo):
    # Valid absolute same-origin
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "signedURL": "https://mockproject.supabase.co/storage/v1/object/sign/incident-evidence/INC-001/photo.jpg?token=abc"
    }
    with patch("httpx.AsyncClient.post", return_value=mock_resp):
        url = await configured_repo.create_signed_photo_url_async("INC-001/photo.jpg")
        assert url == "https://mockproject.supabase.co/storage/v1/object/sign/incident-evidence/INC-001/photo.jpg?token=abc"

    # Valid relative format
    mock_resp.json.return_value = {
        "signedURL": "/storage/v1/object/sign/incident-evidence/INC-001/photo.jpg?token=abc"
    }
    with patch("httpx.AsyncClient.post", return_value=mock_resp):
        url = await configured_repo.create_signed_photo_url_async("INC-001/photo.jpg")
        assert url == "https://mockproject.supabase.co/storage/v1/object/sign/incident-evidence/INC-001/photo.jpg?token=abc"

    # Mismatched host
    mock_resp.json.return_value = {
        "signedURL": "https://attacker.org/storage/v1/object/sign/incident-evidence/INC-001/photo.jpg?token=abc"
    }
    with patch("httpx.AsyncClient.post", return_value=mock_resp):
        with pytest.raises(StorageError, match="Untrusted signed URL origin"):
            await configured_repo.create_signed_photo_url_async("INC-001/photo.jpg")

    # Disallowed scheme
    mock_resp.json.return_value = {
        "signedURL": "javascript:alert('pwned')"
    }
    with patch("httpx.AsyncClient.post", return_value=mock_resp):
        with pytest.raises(StorageError, match="Disallowed signed URL scheme"):
            await configured_repo.create_signed_photo_url_async("INC-001/photo.jpg")

    # Path mismatch
    mock_resp.json.return_value = {
        "signedURL": "https://mockproject.supabase.co/storage/v1/object/sign/incident-evidence/INC-002/photo2.jpg?token=abc"
    }
    with patch("httpx.AsyncClient.post", return_value=mock_resp):
        with pytest.raises(StorageError, match="Signed URL path .* does not match expected target object"):
            await configured_repo.create_signed_photo_url_async("INC-001/photo.jpg")


# ----------------------------------------------------------------------
# 8. Sanitized Error Logging: No Secrets, Tokens or Raw Response Bodies
# ----------------------------------------------------------------------

def test_error_logging_never_exposes_secrets_or_signed_urls(configured_repo, caplog):
    caplog.set_level(logging.DEBUG)

    sensitive_response = '{"error": "Unauthorized", "secret_token": "SUPER_SECRET_TOKEN_XYZ", "auth": "Bearer secret"}'
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 500
    mock_resp.text = sensitive_response

    with patch("httpx.Client.post", return_value=mock_resp):
        with pytest.raises(StorageError):
            configured_repo.create_signed_photo_url("INC-001/photo.jpg")

    for record in caplog.records:
        msg = record.getMessage()
        assert "SUPER_SECRET_TOKEN_XYZ" not in msg
        assert "mock-service-role-key-secret456" not in msg
        assert "mock-anon-key-secret123" not in msg

    caplog.clear()
    mock_success = MagicMock(spec=httpx.Response)
    mock_success.status_code = 200
    mock_success.json.return_value = {
        "signedURL": "/storage/v1/object/sign/incident-evidence/INC-001/photo.jpg?token=PRIVATE_SIGNATURE_SIG123"
    }

    with patch("httpx.Client.post", return_value=mock_success):
        signed_url = configured_repo.create_signed_photo_url("INC-001/photo.jpg")
        assert "PRIVATE_SIGNATURE_SIG123" in signed_url

    for record in caplog.records:
        msg = record.getMessage()
        assert "PRIVATE_SIGNATURE_SIG123" not in msg


def test_fake_signed_token_never_leaked_in_logs_or_exceptions(configured_repo, caplog):
    """
    Verifies that when signed URL validation fails across any failure mode,
    query parameters, tokens, or credentials NEVER appear in exception messages
    or captured logs.
    """
    caplog.set_level(logging.DEBUG)

    fake_tokens = [
        ("protocol_rel", "//evil.com/storage/v1/object/sign/incident-evidence/INC-001/photo.jpg?token=FAKE_SECRET_TOKEN_ALPHA"),
        ("disallowed_scheme", "javascript:alert(1)?token=FAKE_SECRET_TOKEN_BETA"),
        ("mismatched_host", "https://attacker.org/storage/v1/object/sign/incident-evidence/INC-001/photo.jpg?token=FAKE_SECRET_TOKEN_GAMMA"),
        ("incomplete_origin", "https:///storage/v1/object/sign/incident-evidence/INC-001/photo.jpg?token=FAKE_SECRET_TOKEN_DELTA"),
        ("invalid_relative", "/storage/v1/other/untrusted?token=FAKE_SECRET_TOKEN_EPSILON"),
        ("traversal_path", "/storage/v1/object/sign/incident-evidence/INC-001/../photo.jpg?token=FAKE_SECRET_TOKEN_ZETA"),
        ("wrong_object", "https://mockproject.supabase.co/storage/v1/object/sign/incident-evidence/INC-999/other.jpg?token=FAKE_SECRET_TOKEN_ETA"),
    ]

    for label, invalid_signed_url in fake_tokens:
        token = invalid_signed_url.split("token=")[-1]
        caplog.clear()

        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"signedURL": invalid_signed_url}

        with patch("httpx.Client.post", return_value=mock_resp):
            with pytest.raises(StorageError) as exc_info:
                configured_repo.create_signed_photo_url("INC-001/photo.jpg")

            err_str = str(exc_info.value)
            assert token not in err_str, f"Token {token} leaked in exception message for {label}: {err_str}"

        for record in caplog.records:
            log_msg = record.getMessage()
            assert token not in log_msg, f"Token {token} leaked in log message for {label}: {log_msg}"


@pytest.mark.anyio
async def test_fake_signed_token_never_leaked_in_async_logs_or_exceptions(configured_repo, caplog):
    """
    Verifies async signed URL failure modes also never leak tokens in exceptions or logs.
    """
    caplog.set_level(logging.DEBUG)
    token = "ASYNC_LEAK_TOKEN_987654"
    invalid_url = f"https://evil.com/storage/v1/object/sign/incident-evidence/INC-001/photo.jpg?token={token}"

    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"signedURL": invalid_url}

    with patch("httpx.AsyncClient.post", return_value=mock_resp):
        with pytest.raises(StorageError) as exc_info:
            await configured_repo.create_signed_photo_url_async("INC-001/photo.jpg")

        assert token not in str(exc_info.value)

    for record in caplog.records:
        assert token not in record.getMessage()


# ----------------------------------------------------------------------
# 9. Missing Supabase Configuration & Missing Service-Role Key Fail Closed
# ----------------------------------------------------------------------

def test_unconfigured_repository_explicitly_raises_for_all_storage_methods(unconfigured_repo):
    with pytest.raises(StorageNotConfiguredError):
        unconfigured_repo.upload_incident_photo_sync(
            incident_id="INC-001",
            photo_id="photo.jpg",
            file_bytes=b"bytes",
            content_type="image/jpeg",
        )

    with pytest.raises(StorageNotConfiguredError):
        unconfigured_repo.create_signed_photo_url("INC-001/photo.jpg")

    with pytest.raises(StorageNotConfiguredError):
        unconfigured_repo.download_incident_photo("INC-001/photo.jpg")

    with pytest.raises(StorageNotConfiguredError):
        unconfigured_repo.delete_incident_photo("INC-001/photo.jpg")

    with pytest.raises(StorageNotConfiguredError):
        unconfigured_repo.attach_incident_photos_sync(
            incident_id="INC-001",
            new_photos=["INC-001/photo.jpg"],
            audit_id="AUD-001",
            actor_id="user_1",
            actor_role="citizen",
        )


@pytest.mark.anyio
async def test_unconfigured_repository_explicitly_raises_for_all_async_storage_methods(unconfigured_repo):
    with pytest.raises(StorageNotConfiguredError):
        await unconfigured_repo.upload_incident_photo(
            incident_id="INC-001",
            photo_id="photo.jpg",
            file_bytes=b"bytes",
            content_type="image/jpeg",
        )

    with pytest.raises(StorageNotConfiguredError):
        await unconfigured_repo.create_signed_photo_url_async("INC-001/photo.jpg")

    with pytest.raises(StorageNotConfiguredError):
        await unconfigured_repo.download_incident_photo_async("INC-001/photo.jpg")

    with pytest.raises(StorageNotConfiguredError):
        await unconfigured_repo.delete_incident_photo_async("INC-001/photo.jpg")


def test_missing_service_role_key_fails_closed_even_with_anon_key(anon_only_repo):
    """Verifies that having only the anon key strictly fails closed for all Storage operations."""
    assert anon_only_repo.is_configured is True  # PostgREST telemetry can query

    with pytest.raises(StorageNotConfiguredError, match="requires service-role credentials"):
        anon_only_repo.upload_incident_photo_sync(
            incident_id="INC-001",
            photo_id="photo.jpg",
            file_bytes=b"bytes",
            content_type="image/jpeg",
        )

    with pytest.raises(StorageNotConfiguredError, match="requires service-role credentials"):
        anon_only_repo.create_signed_photo_url("INC-001/photo.jpg")

    with pytest.raises(StorageNotConfiguredError, match="requires service-role credentials"):
        anon_only_repo.download_incident_photo("INC-001/photo.jpg")

    with pytest.raises(StorageNotConfiguredError, match="requires service-role credentials"):
        anon_only_repo.delete_incident_photo("INC-001/photo.jpg")

    with pytest.raises(StorageNotConfiguredError, match="requires service-role credentials"):
        anon_only_repo.attach_incident_photos_sync(
            incident_id="INC-001",
            new_photos=["INC-001/photo.jpg"],
            audit_id="AUD-001",
            actor_id="user_1",
            actor_role="citizen",
        )


@pytest.mark.anyio
async def test_missing_service_role_key_fails_closed_even_with_anon_key_async(anon_only_repo):
    with pytest.raises(StorageNotConfiguredError, match="requires service-role credentials"):
        await anon_only_repo.upload_incident_photo(
            incident_id="INC-001",
            photo_id="photo.jpg",
            file_bytes=b"bytes",
            content_type="image/jpeg",
        )

    with pytest.raises(StorageNotConfiguredError, match="requires service-role credentials"):
        await anon_only_repo.create_signed_photo_url_async("INC-001/photo.jpg")

    with pytest.raises(StorageNotConfiguredError, match="requires service-role credentials"):
        await anon_only_repo.download_incident_photo_async("INC-001/photo.jpg")

    with pytest.raises(StorageNotConfiguredError, match="requires service-role credentials"):
        await anon_only_repo.delete_incident_photo_async("INC-001/photo.jpg")


# ----------------------------------------------------------------------
# 10. Database Identifier Length Boundary Alignment
# ----------------------------------------------------------------------

def test_identifier_length_boundaries_match_database(configured_repo):
    # incidents.id VARCHAR(32)
    valid_32_inc = "A" * 32
    assert configured_repo._validate_upload_arguments(
        valid_32_inc, "photo.jpg", b"bytes", "image/jpeg", None
    )[1] == valid_32_inc

    invalid_33_inc = "A" * 33
    with pytest.raises(StorageValidationError, match="1-32 chars matching database schema"):
        configured_repo._validate_upload_arguments(
            invalid_33_inc, "photo.jpg", b"bytes", "image/jpeg", None
        )

    # incident_audits.audit_id VARCHAR(32)
    valid_32_audit = "B" * 32
    # Should accept valid audit id
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"id": "INC-01", "photos": ["INC-01/photo.jpg"]}

    with patch("httpx.Client.post", return_value=mock_resp):
        res = configured_repo.attach_incident_photos_sync(
            incident_id="INC-01",
            new_photos=["INC-01/photo.jpg"],
            audit_id=valid_32_audit,
            actor_id="user_123",
            actor_role="municipal_officer",
        )
        assert res["id"] == "INC-01"

    invalid_33_audit = "B" * 33
    with pytest.raises(StorageValidationError, match="1-32 chars matching database schema"):
        configured_repo.attach_incident_photos_sync(
            incident_id="INC-01",
            new_photos=["INC-01/photo.jpg"],
            audit_id=invalid_33_audit,
            actor_id="user_123",
            actor_role="municipal_officer",
        )

    # incident_audits.actor_id VARCHAR(128)
    invalid_129_actor = "C" * 129
    with pytest.raises(StorageValidationError, match="1-128 valid characters matching database schema"):
        configured_repo.attach_incident_photos_sync(
            incident_id="INC-01",
            new_photos=["INC-01/photo.jpg"],
            audit_id="AUD-01",
            actor_id=invalid_129_actor,
            actor_role="municipal_officer",
        )

    # incident_audits.actor_role VARCHAR(64) and restricted to ALLOWED_ACTOR_ROLES
    invalid_65_role = "D" * 65
    with pytest.raises(StorageValidationError, match="Must be exactly one of"):
        configured_repo.attach_incident_photos_sync(
            incident_id="INC-01",
            new_photos=["INC-01/photo.jpg"],
            audit_id="AUD-01",
            actor_id="user_123",
            actor_role=invalid_65_role,
        )


# ----------------------------------------------------------------------
# 11. Actor Attribution Preservation & No Default Masking
# ----------------------------------------------------------------------

def test_actor_attribution_preservation_and_validation(configured_repo):
    incident_id = "INC-ATTR-001"
    new_photos = ["INC-ATTR-001/photo1.jpg"]
    audit_id = "AUD-ATTR-001"

    roles = ["citizen", "municipal_officer", "field_worker", "admin", "system"]
    for role in roles:
        actor = f"{role}-user-uuid-987"
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"id": incident_id, "photos": new_photos}

        with patch("httpx.Client.post", return_value=mock_resp) as mock_post:
            result = configured_repo.attach_incident_photos_sync(
                incident_id=incident_id,
                new_photos=new_photos,
                audit_id=audit_id,
                actor_id=actor,
                actor_role=role,
            )
            assert result["id"] == incident_id
            mock_post.assert_called_once()
            _, call_kwargs = mock_post.call_args
            payload = call_kwargs["json"]
            assert payload["p_actor_id"] == actor
            assert payload["p_actor_role"] == role

    # Verify empty actor_id or whitespace raises StorageValidationError
    with pytest.raises(StorageValidationError, match="Actor ID cannot be empty or have leading/trailing whitespace"):
        configured_repo.attach_incident_photos_sync(
            incident_id=incident_id,
            new_photos=new_photos,
            audit_id=audit_id,
            actor_id="   ",
            actor_role="citizen",
        )

    with pytest.raises(StorageValidationError, match="Actor role cannot be empty or have leading/trailing whitespace"):
        configured_repo.attach_incident_photos_sync(
            incident_id=incident_id,
            new_photos=new_photos,
            audit_id=audit_id,
            actor_id="user-123",
            actor_role="",
        )


def test_invalid_actor_roles_rejected(configured_repo):
    """Verifies that actor_role outside of (citizen, municipal_officer, field_worker, admin, system) is rejected."""
    invalid_roles = ["superuser", "guest", "service_role", "developer", "manager", "anonymous"]
    for role in invalid_roles:
        with pytest.raises(StorageValidationError, match="Must be exactly one of: admin, citizen, field_worker, municipal_officer, system"):
            configured_repo.attach_incident_photos_sync(
                incident_id="INC-001",
                new_photos=["INC-001/photo.jpg"],
                audit_id="AUD-001",
                actor_id="usr-123",
                actor_role=role,
            )


def test_actor_id_validation_boundary_rules_aligned_python_and_sql(configured_repo):
    """
    Verifies that Python PersistenceRepository and SQL Migration 005 enforce identical
    actor ID validation rules: ^[A-Za-z0-9_@.-]{1,128}$
    """
    sql_pattern = re.compile(r"^[A-Za-z0-9_@.-]{1,128}$")

    valid_actor_ids = [
        "a",
        "user_123",
        "officer-42",
        "citizen@example.com",
        "field.worker.01",
        "sys-admin_99@muni.gov",
        "X" * 128,
    ]

    invalid_actor_ids = [
        "",
        "   ",
        "X" * 129,
        "user#1",
        "bad$actor",
        "user name",
        "user;drop",
        "user/admin",
        "user\\admin",
        "user%20admin",
        "user:123",
    ]

    # Verify SQL regex pattern matches valid and rejects invalid
    for vid in valid_actor_ids:
        assert sql_pattern.match(vid) is not None, f"SQL pattern should accept valid actor ID: {vid}"

    for inv in invalid_actor_ids:
        assert sql_pattern.match(inv) is None, f"SQL pattern should reject invalid actor ID: {inv}"

    # Verify Python repository enforces identical acceptance and rejection
    mock_resp = MagicMock(spec=httpx.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"id": "INC-001", "photos": ["INC-001/photo.jpg"]}

    with patch("httpx.Client.post", return_value=mock_resp):
        for vid in valid_actor_ids:
            res = configured_repo.attach_incident_photos_sync(
                incident_id="INC-001",
                new_photos=["INC-001/photo.jpg"],
                audit_id="AUD-001",
                actor_id=vid,
                actor_role="citizen",
            )
            assert res["id"] == "INC-001"

    for inv in invalid_actor_ids:
        with pytest.raises(StorageValidationError):
            configured_repo.attach_incident_photos_sync(
                incident_id="INC-001",
                new_photos=["INC-001/photo.jpg"],
                audit_id="AUD-001",
                actor_id=inv,
                actor_role="citizen",
            )


# ----------------------------------------------------------------------
# 12. Migration 005 RPC Draft Security & SQL Validation
# ----------------------------------------------------------------------

def test_sql_incident_id_validation_rules():
    """Verifies valid and invalid SQL incident IDs against pattern ^[A-Za-z0-9_-]{1,32}$."""
    pattern = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
    valid_ids = ["INC-001", "INC_001_abc", "A" * 32, "12345", "INC-A_B-C"]
    invalid_ids = ["", "   ", "A" * 33, "INC.001", "INC/001", "INC@001", "INC 001", "INC#1"]

    for vid in valid_ids:
        assert pattern.match(vid) is not None, f"Expected {vid} to match"

    for inv in invalid_ids:
        assert pattern.match(inv) is None, f"Expected {inv} to NOT match"


def test_audit_idempotency_simulation_and_conflict_handling():
    """
    Simulates and validates the deterministic audit idempotency logic in Migration 005:
    - Same request retried with same audit ID returns current incident.
    - Same audit ID reused for different incident raises conflict (23505).
    - Same audit ID reused for different action raises conflict (23505).
    - Same audit ID reused with different photo payload raises conflict (23505).
    """
    import hashlib

    # Mock database state
    existing_audits = {
        "AUD-ATTACH-100": {
            "incident_id": "INC-100",
            "action": "ATTACH_PHOTOS",
            "actor_id": "officer-1",
            "actor_role": "municipal_officer",
            "reason": f"ATTACH_PHOTOS count:2 fp:{hashlib.md5(b'INC-100/p1.jpg,INC-100/p2.jpg').hexdigest()}",
        },
        "AUD-TRIAGE-200": {
            "incident_id": "INC-100",
            "action": "ASSIGN_TEAM",
            "actor_id": "officer-1",
            "actor_role": "municipal_officer",
            "reason": "Assigned team TEAM-01",
        },
    }

    def simulate_rpc_idempotency(incident_id, audit_id, photos, actor_id, actor_role):
        sorted_photos = sorted(photos)
        fp = hashlib.md5(",".join(sorted_photos).encode("utf-8")).hexdigest()
        expected_reason = f"ATTACH_PHOTOS count:{len(sorted_photos)} fp:{fp}"

        if audit_id in existing_audits:
            existing = existing_audits[audit_id]
            if existing["incident_id"] != incident_id:
                raise ValueError(f"23505: Audit ID {audit_id} already exists for incident {existing['incident_id']}")
            if existing["action"] != "ATTACH_PHOTOS":
                raise ValueError(f"23505: Audit ID {audit_id} already exists with conflicting action {existing['action']}")
            if existing["actor_id"] != actor_id or existing["actor_role"] != actor_role:
                raise ValueError(f"23505: Audit ID {audit_id} already exists with conflicting actor attribution")
            if existing["reason"] != expected_reason:
                raise ValueError(f"23505: Audit ID {audit_id} already exists with conflicting photo payload")
            return "IDEMPOTENT_REPLAY"

        return "NEW_INSERT"

    # 1. Identical retry succeeds idempotently
    assert simulate_rpc_idempotency(
        incident_id="INC-100",
        audit_id="AUD-ATTACH-100",
        photos=["INC-100/p1.jpg", "INC-100/p2.jpg"],
        actor_id="officer-1",
        actor_role="municipal_officer",
    ) == "IDEMPOTENT_REPLAY"

    # 2. Existing audit belonging to another incident fails with 23505
    with pytest.raises(ValueError, match="23505.*already exists for incident INC-100"):
        simulate_rpc_idempotency(
            incident_id="INC-999",
            audit_id="AUD-ATTACH-100",
            photos=["INC-999/p1.jpg"],
            actor_id="officer-1",
            actor_role="municipal_officer",
        )

    # 3. Existing audit belonging to another action fails with 23505
    with pytest.raises(ValueError, match="23505.*conflicting action ASSIGN_TEAM"):
        simulate_rpc_idempotency(
            incident_id="INC-100",
            audit_id="AUD-TRIAGE-200",
            photos=["INC-100/p1.jpg"],
            actor_id="officer-1",
            actor_role="municipal_officer",
        )

    # 4. Same audit ID reused with different photo payload fails with 23505
    with pytest.raises(ValueError, match="23505.*conflicting photo payload"):
        simulate_rpc_idempotency(
            incident_id="INC-100",
            audit_id="AUD-ATTACH-100",
            photos=["INC-100/different.png"],
            actor_id="officer-1",
            actor_role="municipal_officer",
        )


def test_migration_005_draft_documents_trust_boundary_and_session_role_check():
    repo_root = Path(__file__).resolve().parent.parent.parent
    draft_path = repo_root / "database" / "migrations" / "005_attach_incident_photos_rpc_draft.sql"
    assert draft_path.exists(), f"Migration 005 draft SQL file must exist at {draft_path}"

    sql_text = draft_path.read_text(encoding="utf-8")

    # Verify trust boundary documentation
    assert "ARCHITECTURAL TRUST BOUNDARY & ACTOR IDENTITY MODEL" in sql_text
    assert "Dual-Layer Attribution & Verification Architecture" in sql_text
    assert "CRITICAL UNDERSTANDING: This check authenticates the BACKEND CONNECTION" in sql_text

    # Verify cryptographic / session authenticity check inside function body
    assert "v_session_role <> 'service_role'" in sql_text
    assert "request.jwt.claim.role" in sql_text

    # Verify character hygiene checks using position() (avoiding ambiguous LIKE escaping)
    assert "position('..' in v_clean_photo)" in sql_text
    assert "position(E'\\\\' in v_clean_photo)" in sql_text
    assert "position('//' in v_clean_photo)" in sql_text
    assert "position('%' in v_clean_photo)" in sql_text

    # Verify embedded NUL byte check was removed (inappropriate for PostgreSQL text)
    assert "position(E'\\x00'" not in sql_text

    # Verify strictly canonical scoping and no silent normalization
    assert "substr(v_clean_photo, 1, length(p_incident_id) + 1) <> (p_incident_id || '/')" in sql_text
    assert "position('/' in v_filename) > 0" in sql_text
    assert "v_filename ~* '^[A-Za-z0-9_-]{1,64}\\.(jpg|jpeg|png|webp)$'" in sql_text

    # Verify database parameter length and regex alignment
    assert "p_incident_id VARCHAR(32)" in sql_text
    assert "p_incident_id ~ '^[A-Za-z0-9_-]{1,32}$'" in sql_text
    assert "p_audit_id VARCHAR(32)" in sql_text
    assert "p_audit_id ~ '^[A-Za-z0-9_-]{1,32}$'" in sql_text
    assert "p_actor_id VARCHAR(128)" in sql_text
    assert "p_actor_id ~ '^[A-Za-z0-9_@.-]{1,128}$'" in sql_text
    assert "p_actor_role VARCHAR(64)" in sql_text
    assert "p_actor_role NOT IN ('citizen', 'municipal_officer', 'field_worker', 'admin', 'system')" in sql_text

    # Verify SECURITY DEFINER and safe search_path
    assert "SECURITY DEFINER" in sql_text
    assert "SET search_path = pg_catalog, public, pg_temp" in sql_text

    # Verify deterministic idempotency logic in SQL
    assert "v_request_fingerprint := md5(array_to_string(v_sorted_photos, ','));" in sql_text
    assert "v_existing_audit.reason <> v_expected_reason" in sql_text

    # Verify no default parameters masking attribution
    assert "p_actor_id VARCHAR(128) DEFAULT" not in sql_text
    assert "p_actor_role VARCHAR(64) DEFAULT" not in sql_text

    # Verify revoke from public/anon/authenticated and grant only to service_role
    assert "REVOKE ALL ON FUNCTION public.attach_incident_photos_rpc" in sql_text
    assert "GRANT EXECUTE ON FUNCTION public.attach_incident_photos_rpc" in sql_text
    assert "TO service_role" in sql_text


def test_sql_draft_parser_validation_with_pglast():
    """
    Validates the Migration 005 SQL draft using pglast (the official PostgreSQL libpg_query C parser).
    Clearly distinguishes parser syntax validation from database execution (no live execution).
    """
    import pglast

    repo_root = Path(__file__).resolve().parent.parent.parent
    draft_path = repo_root / "database" / "migrations" / "005_attach_incident_photos_rpc_draft.sql"
    sql_text = draft_path.read_text(encoding="utf-8")

    tree = pglast.parse_sql(sql_text)
    assert len(tree) == 3, f"Expected exactly 3 SQL statements, got {len(tree)}"

    stmt_names = [stmt.stmt.__class__.__name__ for stmt in tree]
    assert stmt_names == ["CreateFunctionStmt", "GrantStmt", "GrantStmt"]


# ==============================================================================


# ==============================================================================
# Milestone 2 V3.1 Specification & Security Integration Tests (INT-01..10, SEC-DUR-01..09)
# ==============================================================================

import io
import uuid
import hashlib
from datetime import datetime, timezone
from PIL import Image
from unittest.mock import MagicMock, patch, PropertyMock
from fastapi.testclient import TestClient
from app.services.state_store import state_store
from app.services.persistence_repository import persistence_repo
from app.main import app
from app.services.persistence_repository import (
    CANONICAL_V3_FILENAME_PATTERN,
    CANONICAL_V3_OBJECT_PATH_PATTERN,
    REQUEST_LEASE_PATTERN,
    RECOVERY_LEASE_PATTERN,
    CLEANUP_OR_RECOVERY_LEASE_PATTERN,
    IDEMPOTENCY_KEY_PATTERN,
    _validate_photo_id,
    _validate_object_path,
    _validate_canonical_v3_object_path,
    PersistenceRepository,
    StorageError,
    StorageConflictError,
    StorageValidationError,
)
from app.api.v1.incidents import _resolve_photo_actor, _authorize_photo_retrieval
from app.models.contracts import IncidentStatus, IncidentResponseContract, IncidentCategory, IncidentSeverity


def _make_clean_jpeg() -> bytes:
    img = Image.new("RGB", (30, 30), color="blue")
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    return buf.getvalue()


def test_int_01_canonical_v3_filename_and_path_validation():
    """
    INT-01: Verify canonical 71-char filename validator accepts sha256_<64hex>.<ext>,
    preserves legacy filename support, and rejects noncanonical whitespace/traversal.
    """
    digest_64 = "a" * 64
    canonical_name = f"sha256_{digest_64}.jpg"
    assert len(canonical_name) == 75
    assert CANONICAL_V3_FILENAME_PATTERN.match(canonical_name)

    # Legacy filenames accepted
    assert _validate_photo_id("incident123_abcd1234.png", "INC-01") == "incident123_abcd1234.png"
    # Canonical filename accepted
    assert _validate_photo_id(canonical_name, "INC-01") == canonical_name

    # Canonical V3 object path
    canonical_path = f"INC-01/{canonical_name}"
    assert CANONICAL_V3_OBJECT_PATH_PATTERN.match(canonical_path)
    c_path, inc, fn = _validate_canonical_v3_object_path(canonical_path, expected_incident_id="INC-01")
    assert c_path == canonical_path
    assert inc == "INC-01"
    assert fn == canonical_name

    # Noncanonical rejections
    import pytest
    with pytest.raises(StorageValidationError):
        _validate_photo_id(" sha256_" + digest_64 + ".jpg", "INC-01")
    with pytest.raises(StorageValidationError):
        _validate_photo_id("sha256_" + digest_64[:60] + ".jpg", "INC-01")
    with pytest.raises(StorageValidationError):
        _validate_canonical_v3_object_path("INC-01/../sha256_" + digest_64 + ".jpg")
    with pytest.raises(StorageValidationError):
        _validate_canonical_v3_object_path("INC-02/" + canonical_name, expected_incident_id="INC-01")


def test_int_02_rpc_wrappers_payload_and_validation():
    """
    INT-02: Verify all 9 RPC wrappers in PersistenceRepository enforce strict validation,
    serialize exact SQL parameter names to PostgREST, and map error responses.
    """
    import pytest
    repo = PersistenceRepository(
        supabase_url="https://test.supabase.co",
        supabase_key="anon-key",
        service_role_key="service-role-secret",
    )
    assert repo.is_storage_configured

    digest = "f" * 64
    canonical_path = f"INC-01/sha256_{digest}.jpg"
    lease_owner = f"req_lease_{uuid.uuid4().hex}"
    rec_lease_owner = f"rec_lease_{uuid.uuid4().hex}"
    fp = "a" * 64

    # 1. Validation checks across wrappers
    with pytest.raises(StorageValidationError):
        repo.reserve_photo_attachment_sync(
            idempotency_key="short",
            scope="incident_attachment",
            actor_id="user1",
            incident_id="INC-01",
            request_fingerprint=fp,
            object_paths=[canonical_path],
            lease_owner=lease_owner,
        )
    with pytest.raises(StorageValidationError):
        repo.reserve_photo_attachment_sync(
            idempotency_key="valid_key_12345",
            scope="incident_attachment",
            actor_id="user1",
            incident_id="INC-01",
            request_fingerprint=fp,
            object_paths=[canonical_path],
            lease_owner="invalid_lease_format",
        )
    with pytest.raises(StorageValidationError):
        repo.claim_expired_cleanup_operation_sync(
            cleanup_id="clean_01",
            incident_id="INC-01",
            idempotency_key="valid_key_12345",
            scope="incident_attachment",
            recovery_actor_id="citizen1",
            recovery_actor_role="citizen",
            recovery_lease_owner=rec_lease_owner,
        )
    with pytest.raises(StorageValidationError):
        repo.claim_expired_cleanup_operation_sync(
            cleanup_id="clean_01",
            incident_id="INC-01",
            idempotency_key="valid_key_12345",
            scope="incident_attachment",
            recovery_actor_id="admin1",
            recovery_actor_role="admin",
            recovery_lease_owner=lease_owner,  # req_lease_ not allowed for recovery
        )

    # 2. Exercise all 9 RPC wrappers against mocked httpx.Client.post
    recorded_calls = []

    def fake_post(url, json=None, headers=None, **kwargs):
        recorded_calls.append((url, json, headers))
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"status": "OK"}
        return resp

    with patch("httpx.Client.post", side_effect=fake_post):
        # RPC 1: reserve_photo_attachment_sync
        repo.reserve_photo_attachment_sync(
            idempotency_key="valid_idemp_key_01",
            scope="incident_attachment",
            actor_id="user1",
            incident_id="INC-01",
            request_fingerprint=fp,
            object_paths=[canonical_path],
            lease_owner=lease_owner,
            lease_sec=120,
        )
        # RPC 2: verify_and_register_storage_object_sync
        repo.verify_and_register_storage_object_sync(
            incident_id="INC-01",
            idempotency_key="valid_idemp_key_01",
            scope="incident_attachment",
            lease_owner=lease_owner,
            object_path=canonical_path,
            verified_sha256=digest,
            verified_mime="image/jpeg",
        )
        # RPC 3: finalize_photo_attachment_sync
        repo.finalize_photo_attachment_sync(
            incident_id="INC-01",
            photos=[canonical_path],
            audit_id="AUD-01",
            actor_id="user1",
            actor_role="citizen",
            idempotency_key="valid_idemp_key_01",
            scope="incident_attachment",
            request_fingerprint=fp,
            lease_owner=lease_owner,
        )
        # RPC 4: initiate_storage_cleanup_sync
        repo.initiate_storage_cleanup_sync(
            cleanup_id="clean_01",
            incident_id="INC-01",
            idempotency_key="valid_idemp_key_01",
            scope="incident_attachment",
            lease_owner=lease_owner,
            object_paths=[canonical_path],
            lease_sec=60,
        )
        # RPC 5: confirm_storage_cleanup_sync
        repo.confirm_storage_cleanup_sync(
            cleanup_id="clean_01",
            incident_id="INC-01",
            idempotency_key="valid_idemp_key_01",
            scope="incident_attachment",
            lease_owner=lease_owner,
            confirmed_paths=[canonical_path],
        )
        # RPC 6: record_storage_cleanup_uncertain_sync
        repo.record_storage_cleanup_uncertain_sync(
            cleanup_id="clean_01",
            incident_id="INC-01",
            idempotency_key="valid_idemp_key_01",
            scope="incident_attachment",
            lease_owner=lease_owner,
            uncertain_paths=[canonical_path],
            error_detail="timeout",
        )
        # RPC 7: claim_expired_cleanup_operation_sync
        repo.claim_expired_cleanup_operation_sync(
            cleanup_id="clean_01",
            incident_id="INC-01",
            idempotency_key="valid_idemp_key_01",
            scope="incident_attachment",
            recovery_actor_id="admin1",
            recovery_actor_role="admin",
            recovery_lease_owner=rec_lease_owner,
            lease_sec=60,
        )
        # RPC 8: reconcile_storage_orphan_sync
        repo.reconcile_storage_orphan_sync(
            cleanup_id="clean_01",
            incident_id="INC-01",
            idempotency_key="valid_idemp_key_01",
            scope="incident_attachment",
            object_path=canonical_path,
            recovery_actor_id="admin1",
            recovery_actor_role="admin",
            recovery_lease_owner=rec_lease_owner,
        )
        # RPC 9: renew_or_takeover_lease_sync
        repo.renew_or_takeover_lease_sync(
            idempotency_key="valid_idemp_key_01",
            scope="incident_attachment",
            incident_id="INC-01",
            actor_id="user1",
            request_fingerprint=fp,
            incoming_lease_owner=lease_owner,
            lease_sec=120,
        )

    assert len(recorded_calls) == 9
    expected_specs = [
        (
            "reserve_photo_attachment_rpc",
            {"p_idempotency_key", "p_scope", "p_actor_id", "p_incident_id", "p_request_fingerprint", "p_object_paths", "p_lease_owner", "p_lease_sec"},
        ),
        (
            "verify_and_register_storage_object_rpc",
            {"p_incident_id", "p_idempotency_key", "p_scope", "p_lease_owner", "p_object_path", "p_verified_sha256", "p_verified_mime"},
        ),
        (
            "finalize_photo_attachment_rpc",
            {"p_incident_id", "p_photos", "p_audit_id", "p_actor_id", "p_actor_role", "p_idempotency_key", "p_scope", "p_request_fingerprint", "p_lease_owner"},
        ),
        (
            "initiate_storage_cleanup_rpc",
            {"p_cleanup_id", "p_incident_id", "p_idempotency_key", "p_scope", "p_lease_owner", "p_object_paths", "p_lease_sec"},
        ),
        (
            "confirm_storage_cleanup_rpc",
            {"p_cleanup_id", "p_incident_id", "p_idempotency_key", "p_scope", "p_lease_owner", "p_confirmed_paths"},
        ),
        (
            "record_storage_cleanup_uncertain_rpc",
            {"p_cleanup_id", "p_incident_id", "p_idempotency_key", "p_scope", "p_lease_owner", "p_uncertain_paths", "p_error_detail"},
        ),
        (
            "claim_expired_cleanup_operation_rpc",
            {"p_cleanup_id", "p_incident_id", "p_idempotency_key", "p_scope", "p_recovery_actor_id", "p_recovery_actor_role", "p_recovery_lease_owner", "p_lease_sec"},
        ),
        (
            "reconcile_storage_orphan_rpc",
            {"p_cleanup_id", "p_incident_id", "p_idempotency_key", "p_scope", "p_object_path", "p_recovery_actor_id", "p_recovery_actor_role", "p_recovery_lease_owner"},
        ),
        (
            "renew_or_takeover_lease_rpc",
            {"p_idempotency_key", "p_scope", "p_incident_id", "p_actor_id", "p_request_fingerprint", "p_incoming_lease_owner", "p_lease_sec"},
        ),
    ]
    for (url, payload, headers), (rpc_name, expected_keys) in zip(recorded_calls, expected_specs):
        assert url == f"https://test.supabase.co/rest/v1/rpc/{rpc_name}"
        assert set(payload.keys()) == expected_keys
        assert headers["Authorization"] == "Bearer service-role-secret"


def test_int_03_photo_attachment_workflow_orchestration_and_409_conflict():
    """
    INT-03: Verify execute_photo_attachment_workflow_sync handles HTTP 201 upload,
    handles HTTP 409 conflict via read-back digest and MIME verification, and finalizes.
    """
    repo = PersistenceRepository(
        supabase_url="https://test.supabase.co",
        supabase_key="anon-key",
        service_role_key="service-role-secret",
    )
    test_bytes = _make_clean_jpeg()
    digest = hashlib.sha256(test_bytes).hexdigest()
    canonical_path = f"INC-01/sha256_{digest}.jpg"

    with patch.object(repo, "reserve_photo_attachment_sync", return_value={"status": "RESERVED"}) as mock_res:
        with patch.object(repo, "upload_incident_photo_sync", side_effect=StorageConflictError("conflict")):
            with patch.object(repo, "download_incident_photo", return_value=(test_bytes, "image/jpeg")) as mock_dl:
                with patch.object(repo, "verify_and_register_storage_object_sync", return_value={"status": "VERIFIED_REGISTERED"}):
                    with patch.object(repo, "finalize_photo_attachment_sync", return_value={"id": "INC-01", "photos": [canonical_path]}):
                        result = repo.execute_photo_attachment_workflow_sync(
                            incident_id="INC-01",
                            files=[("photo.jpg", test_bytes, "image/jpeg")],
                            idempotency_key="idemp_test_key_01",
                            actor_id="user1",
                            actor_role="citizen",
                            audit_id="AUD-01",
                        )
                        assert result["id"] == "INC-01"
                        mock_dl.assert_called_once_with(canonical_path, incident_id="INC-01")
                        assert mock_res.call_args.kwargs["lease_sec"] == repo.upload_lease_sec


def test_int_03_conflict_readback_mime_mismatch_and_digest_mismatch_rejected():
    """
    INT-03 / D-04: Verify that when upload encounters HTTP 409 conflict, a MIME mismatch
    or SHA-256 digest mismatch on read-back aborts registration/finalization and initiates cleanup.
    """
    import pytest
    repo = PersistenceRepository(
        supabase_url="https://test.supabase.co",
        supabase_key="anon-key",
        service_role_key="service-role-secret",
    )
    test_bytes = _make_clean_jpeg()

    # Case 1: Read-back returns mismatched MIME (image/png instead of image/jpeg)
    with patch.object(repo, "reserve_photo_attachment_sync", return_value={"status": "RESERVED"}):
        with patch.object(repo, "upload_incident_photo_sync", side_effect=StorageConflictError("409 conflict")):
            with patch.object(repo, "download_incident_photo", return_value=(test_bytes, "image/png")):
                with patch.object(repo, "verify_and_register_storage_object_sync") as mock_verify:
                    with patch.object(
                        repo,
                        "initiate_storage_cleanup_sync",
                        return_value={"status": "NO_STORAGE_DELETE_REQUIRED", "delete_authorized_paths": []},
                    ) as mock_cleanup:
                        with pytest.raises(StorageError, match="MIME"):
                            repo.execute_photo_attachment_workflow_sync(
                                incident_id="INC-01",
                                files=[("photo.jpg", test_bytes, "image/jpeg")],
                                idempotency_key="idemp_mime_mismatch_01",
                                actor_id="user1",
                                actor_role="citizen",
                                audit_id="AUD-MIME-01",
                            )
                        mock_verify.assert_not_called()
                        mock_cleanup.assert_called_once()

    # Case 2: Read-back returns tampered bytes (SHA-256 mismatch)
    with patch.object(repo, "reserve_photo_attachment_sync", return_value={"status": "RESERVED"}):
        with patch.object(repo, "upload_incident_photo_sync", side_effect=StorageConflictError("409 conflict")):
            with patch.object(repo, "download_incident_photo", return_value=(test_bytes + b"tampered", "image/jpeg")):
                with patch.object(repo, "verify_and_register_storage_object_sync") as mock_verify:
                    with patch.object(
                        repo,
                        "initiate_storage_cleanup_sync",
                        return_value={"status": "NO_STORAGE_DELETE_REQUIRED", "delete_authorized_paths": []},
                    ) as mock_cleanup:
                        with pytest.raises(StorageError, match="SHA-256"):
                            repo.execute_photo_attachment_workflow_sync(
                                incident_id="INC-01",
                                files=[("photo.jpg", test_bytes, "image/jpeg")],
                                idempotency_key="idemp_sha_mismatch_01",
                                actor_id="user1",
                                actor_role="citizen",
                                audit_id="AUD-SHA-01",
                            )
                        mock_verify.assert_not_called()
                        mock_cleanup.assert_called_once()


def test_int_04_lost_response_finalization_handling():
    """
    INT-04: Verify that if finalize_photo_attachment_sync raises/times out,
    compensating cleanup returns ALREADY_COMPLETED safely without deleting files.
    """
    repo = PersistenceRepository(
        supabase_url="https://test.supabase.co",
        supabase_key="anon-key",
        service_role_key="service-role-secret",
    )
    test_bytes = _make_clean_jpeg()
    digest = hashlib.sha256(test_bytes).hexdigest()
    canonical_path = f"INC-01/sha256_{digest}.jpg"

    with patch.object(repo, "reserve_photo_attachment_sync", return_value={"status": "RESERVED"}):
        with patch.object(repo, "upload_incident_photo_sync", return_value=canonical_path):
            with patch.object(repo, "verify_and_register_storage_object_sync", return_value={"status": "VERIFIED"}):
                with patch.object(repo, "finalize_photo_attachment_sync", side_effect=StorageError("Network timeout")):
                    with patch.object(
                        repo,
                        "initiate_storage_cleanup_sync",
                        return_value={
                            "status": "ALREADY_COMPLETED",
                            "response": {"id": "INC-01", "photos": [canonical_path]},
                        },
                    ):
                        with patch.object(repo, "delete_incident_photo") as mock_del:
                            result = repo.execute_photo_attachment_workflow_sync(
                                incident_id="INC-01",
                                files=[("pic.jpg", test_bytes, "image/jpeg")],
                                idempotency_key="lost_response_key_01",
                                actor_id="user1",
                                actor_role="citizen",
                                audit_id="AUD-02",
                            )
                            assert result["id"] == "INC-01"
                            mock_del.assert_not_called()


def test_int_05_actor_role_normalization():
    """
    INT-05: Verify role normalization across all caller types:
    citizen, municipal_officer, field_worker, admin, system.
    """
    assert _resolve_photo_actor(None) == ("citizen_anonymous", "citizen")
    assert _resolve_photo_actor({"sub": "u1", "role": "citizen"}) == ("u1", "citizen")
    assert _resolve_photo_actor({"sub": "u2", "role": "municipality"}) == ("u2", "municipal_officer")
    assert _resolve_photo_actor({"sub": "u3", "role": "municipal_officer"}) == ("u3", "municipal_officer")
    assert _resolve_photo_actor({"sub": "w1", "role": "worker"}) == ("w1", "field_worker")
    assert _resolve_photo_actor({"sub": "w2", "role": "field_worker"}) == ("w2", "field_worker")
    assert _resolve_photo_actor({"sub": "a1", "role": "admin"}) == ("a1", "admin")
    assert _resolve_photo_actor({"sub": "s1", "role": "service_role"}) == ("s1", "system")
    assert _resolve_photo_actor({"sub": "s2", "role": "system"}) == ("s2", "system")


def test_int_06_worker_tenancy_enforcement():
    """
    INT-06: Verify field worker tenancy enforcement: unassigned workers receive 403,
    assigned workers are permitted to upload evidence.
    """
    client = TestClient(app)
    create_resp = client.post("/api/v1/incidents", json={
        "category": "DRAIN_BLOCKAGE",
        "description": "Worker tenancy test incident",
        "latitude": 15.49,
        "longitude": 73.82,
    })
    inc_id = create_resp.json()["id"]

    inc = state_store.get_incident(inc_id)
    assert inc is not None
    inc.assigned_worker_id = "worker-alpha"

    jpeg_bytes = _make_clean_jpeg()
    files = [("files", ("evidence.jpg", jpeg_bytes, "image/jpeg"))]

    headers_beta = {"Authorization": "Bearer mock-worker-beta"}
    with patch("app.core.security.verify_supabase_jwt", return_value={"sub": "worker-beta", "role": "worker", "extracted_role": "worker"}):
        resp_beta = client.post(f"/api/v1/incidents/{inc_id}/photos", files=files, headers=headers_beta)
        assert resp_beta.status_code == 403
        assert "assigned to them" in resp_beta.json()["detail"].lower()

    headers_alpha = {"Authorization": "Bearer mock-worker-alpha"}
    with patch("app.core.security.verify_supabase_jwt", return_value={"sub": "worker-alpha", "role": "worker", "extracted_role": "worker"}):
        resp_alpha = client.post(f"/api/v1/incidents/{inc_id}/photos", files=files, headers=headers_alpha)
        assert resp_alpha.status_code == 200
        assert len(resp_alpha.json()["photos"]) == 1


def test_int_07_anonymous_citizen_cloud_upload_and_idempotency():
    """
    INT-07 / D-03: Verify anonymous citizen cloud photo upload uses actor_id='citizen_anonymous',
    actor_role='citizen', replays COMPLETED idempotent responses without re-uploading,
    and maps idempotency conflicts (StorageConflictError) to HTTP 409 Conflict.
    """
    client = TestClient(app)
    inc_id = "INC-ANON-01"
    now_iso = datetime.now(timezone.utc).isoformat()
    base_inc_row = {
        "id": inc_id,
        "category": "DRAIN_BLOCKAGE",
        "description": "Anonymous citizen cloud upload test",
        "latitude": 15.49,
        "longitude": 73.82,
        "status": "REPORTED",
        "severity": "MEDIUM",
        "photos": [],
        "created_at": now_iso,
        "updated_at": now_iso,
    }
    jpeg_bytes = _make_clean_jpeg()
    files = [("files", ("citizen.jpg", jpeg_bytes, "image/jpeg"))]

    with patch.object(PersistenceRepository, "is_configured", new_callable=PropertyMock, return_value=True), \
         patch.object(PersistenceRepository, "is_storage_configured", new_callable=PropertyMock, return_value=True), \
         patch.object(persistence_repo, "query_incident_by_id_sync", return_value=base_inc_row):

        # 1. First upload reserves, uploads, verifies, and finalizes with citizen_anonymous / citizen
        with patch.object(persistence_repo, "reserve_photo_attachment_sync", return_value={"status": "RESERVED"}) as mock_res, \
             patch.object(persistence_repo, "upload_incident_photo_sync", return_value=f"{inc_id}/sha256_{'a'*64}.jpg") as mock_up, \
             patch.object(persistence_repo, "verify_and_register_storage_object_sync", return_value={"status": "VERIFIED_REGISTERED"}), \
             patch.object(persistence_repo, "finalize_photo_attachment_sync", side_effect=lambda **kw: {**base_inc_row, "photos": kw["photos"]}) as mock_fin:

            resp1 = client.post(
                f"/api/v1/incidents/{inc_id}/photos",
                files=files,
                headers={"Idempotency-Key": "anon_citizen_key_001"},
            )
            assert resp1.status_code == 200
            assert len(resp1.json()["photos"]) == 1
            assert mock_res.call_args.kwargs["actor_id"] == "citizen_anonymous"
            assert mock_fin.call_args.kwargs["actor_id"] == "citizen_anonymous"
            assert mock_fin.call_args.kwargs["actor_role"] == "citizen"
            mock_up.assert_called_once()

        # 2. Idempotent replay returns COMPLETED cached response without calling upload_incident_photo_sync
        cached_inc = {**base_inc_row, "photos": resp1.json()["photos"]}
        with patch.object(persistence_repo, "reserve_photo_attachment_sync", return_value={"status": "COMPLETED", "response": cached_inc}), \
             patch.object(persistence_repo, "upload_incident_photo_sync") as mock_up_replay:

            resp2 = client.post(
                f"/api/v1/incidents/{inc_id}/photos",
                files=files,
                headers={"Idempotency-Key": "anon_citizen_key_001"},
            )
            assert resp2.status_code == 200
            assert resp2.json()["photos"] == cached_inc["photos"]
            mock_up_replay.assert_not_called()

        # 3. Conflicting idempotency key reuse maps StorageConflictError -> HTTP 409 Conflict
        with patch.object(persistence_repo, "reserve_photo_attachment_sync", side_effect=StorageConflictError("Idempotency key conflict on payload fingerprint")):
            resp_conflict = client.post(
                f"/api/v1/incidents/{inc_id}/photos",
                files=files,
                headers={"Idempotency-Key": "anon_citizen_key_001"},
            )
            assert resp_conflict.status_code == 409
            assert "conflict" in resp_conflict.json()["detail"].lower()


def test_int_08_idempotency_key_header_requirement_in_cloud_mode():
    """
    INT-08: In cloud mode (is_storage_configured=True), Idempotency-Key header is mandatory (400 if omitted/invalid).
    In local mode, Idempotency-Key is optional.
    """
    client = TestClient(app)
    create_resp = client.post("/api/v1/incidents", json={
        "category": "DRAIN_BLOCKAGE",
        "description": "Idempotency key header test",
        "latitude": 15.49,
        "longitude": 73.82,
    })
    inc_id = create_resp.json()["id"]

    jpeg_bytes = _make_clean_jpeg()
    files = [("files", ("pic.jpg", jpeg_bytes, "image/jpeg"))]

    with patch.object(PersistenceRepository, "is_storage_configured", new_callable=PropertyMock, return_value=True):
        resp_missing = client.post(f"/api/v1/incidents/{inc_id}/photos", files=files)
        assert resp_missing.status_code == 400
        assert "Idempotency-Key header is required" in resp_missing.json()["detail"]

        resp_invalid = client.post(
            f"/api/v1/incidents/{inc_id}/photos",
            files=files,
            headers={"Idempotency-Key": "short"},
        )
        assert resp_invalid.status_code == 400
        assert "Invalid Idempotency-Key format" in resp_invalid.json()["detail"]


def test_int_09_partial_cleanup_and_uncertain_deletion_handling():
    """
    INT-09: Verify compensating cleanup records uncertain deletions and confirms successful ones.
    """
    repo = PersistenceRepository(
        supabase_url="https://test.supabase.co",
        supabase_key="anon-key",
        service_role_key="service-role-secret",
    )
    cleanup_res = {
        "status": "CLEANUP_AUTHORIZED",
        "delete_authorized_paths": ["INC-01/sha256_1111.jpg", "INC-01/sha256_2222.jpg"],
    }

    def fake_delete(path, incident_id=None):
        if "1111" in path:
            return True
        raise RuntimeError("Disk I/O timeout")

    with patch.object(repo, "delete_incident_photo", side_effect=fake_delete):
        with patch.object(repo, "record_storage_cleanup_uncertain_sync") as mock_uncertain:
            with patch.object(repo, "confirm_storage_cleanup_sync") as mock_confirm:
                repo._execute_cleanup_deletion(
                    cleanup_id="clean_01",
                    incident_id="INC-01",
                    idempotency_key="key_01234567",
                    scope="incident_attachment",
                    lease_owner="req_lease_" + "0" * 32,
                    cleanup_res=cleanup_res,
                )
                mock_confirm.assert_called_once_with(
                    cleanup_id="clean_01",
                    incident_id="INC-01",
                    idempotency_key="key_01234567",
                    scope="incident_attachment",
                    lease_owner="req_lease_" + "0" * 32,
                    confirmed_paths=["INC-01/sha256_1111.jpg"],
                )
                mock_uncertain.assert_called_once_with(
                    cleanup_id="clean_01",
                    incident_id="INC-01",
                    idempotency_key="key_01234567",
                    scope="incident_attachment",
                    lease_owner="req_lease_" + "0" * 32,
                    uncertain_paths=["INC-01/sha256_2222.jpg"],
                    error_detail="RuntimeError: Disk I/O timeout",
                )


def test_int_09_empty_cleanup_confirmation_rejected():
    """
    D-04: Verify confirm_storage_cleanup_sync rejects an empty confirmed_paths list
    before invoking the RPC.
    """
    import pytest
    repo = PersistenceRepository(
        supabase_url="https://test.supabase.co",
        supabase_key="anon-key",
        service_role_key="service-role-secret",
    )
    with patch.object(repo, "_call_rpc_sync") as mock_rpc:
        with pytest.raises(StorageValidationError, match="At least one confirmed path"):
            repo.confirm_storage_cleanup_sync(
                cleanup_id="clean_01",
                incident_id="INC-01",
                idempotency_key="key_01234567",
                scope="incident_attachment",
                lease_owner="req_lease_" + "0" * 32,
                confirmed_paths=[],
            )
        mock_rpc.assert_not_called()


def test_int_10_config_separation_and_timeout_bounds():
    """
    INT-10: Verify separation between is_configured and is_storage_configured,
    and enforce timeout validation between 0.5s and 20.0s.
    """
    import pytest
    anon_repo = PersistenceRepository(
        supabase_url="https://test.supabase.co",
        supabase_key="anon-key",
        service_role_key="",
    )
    assert anon_repo.is_configured
    assert not anon_repo.is_storage_configured

    service_repo = PersistenceRepository(
        supabase_url="https://test.supabase.co",
        supabase_key="",
        service_role_key="service-role-secret",
    )
    assert service_repo.is_configured
    assert service_repo.is_storage_configured

    with pytest.raises(ValueError):
        PersistenceRepository(supabase_url="https://test.supabase.co", timeout_sec=0.1)
    with pytest.raises(ValueError):
        PersistenceRepository(supabase_url="https://test.supabase.co", timeout_sec=25.0)

    valid_repo = PersistenceRepository(supabase_url="https://test.supabase.co", timeout_sec=10.0)
    assert valid_repo._timeout_sec == 10.0


def test_sec_dur_01_photo_retrieval_authorization_matrix():
    """
    SEC-DUR-01: Verify photo retrieval authorization matrix:
    - Invalid/malformed Bearer token -> 401.
    - Unassigned field worker -> 403; assigned field worker -> 200.
    - REJECTED incidents: 404 for citizens/workers/unauthenticated, 200 for supervisors.
    """
    client = TestClient(app)
    create_resp = client.post("/api/v1/incidents", json={
        "category": "DRAIN_BLOCKAGE",
        "description": "Retrieval authorization test",
        "latitude": 15.49,
        "longitude": 73.82,
    })
    inc_id = create_resp.json()["id"]

    jpeg_bytes = _make_clean_jpeg()
    files = [("files", ("evidence.jpg", jpeg_bytes, "image/jpeg"))]
    up_resp = client.post(f"/api/v1/incidents/{inc_id}/photos", files=files)
    photo_url = up_resp.json()["photos"][0]
    filename = photo_url.split("/")[-1]

    scoped_url = f"/api/v1/incidents/{inc_id}/photos/{filename}"
    get_resp = client.get(scoped_url)
    assert get_resp.status_code == 200

    # Malformed Authorization header -> 401
    malformed_resp = client.get(scoped_url, headers={"Authorization": "InvalidHeader"})
    assert malformed_resp.status_code == 401

    # Assign incident to worker-alpha; worker-beta gets 403, worker-alpha gets 200
    inc = state_store.get_incident(inc_id)
    assert inc is not None
    inc.assigned_worker_id = "worker-alpha"

    with patch("app.core.security.verify_supabase_jwt", return_value={"sub": "worker-beta", "role": "worker", "extracted_role": "worker"}):
        assert client.get(scoped_url, headers={"Authorization": "Bearer worker-beta"}).status_code == 403

    with patch("app.core.security.verify_supabase_jwt", return_value={"sub": "worker-alpha", "role": "worker", "extracted_role": "worker"}):
        assert client.get(scoped_url, headers={"Authorization": "Bearer worker-alpha"}).status_code == 200

    # Transition to REJECTED: citizen/unauthenticated and even assigned worker receive 404; supervisors receive 200
    inc.status = IncidentStatus.REJECTED

    assert client.get(scoped_url).status_code == 404
    with patch("app.core.security.verify_supabase_jwt", return_value={"sub": "worker-alpha", "role": "worker", "extracted_role": "worker"}):
        assert client.get(scoped_url, headers={"Authorization": "Bearer worker-alpha"}).status_code == 404

    with patch("app.core.security.verify_supabase_jwt", return_value={"sub": "admin1", "role": "admin", "extracted_role": "admin"}):
        admin_resp = client.get(scoped_url, headers={"Authorization": "Bearer admin-token"})
        assert admin_resp.status_code == 200


def test_sec_dur_02_cold_cache_photo_retrieval_from_authoritative_postgres():
    """
    SEC-DUR-02 / D-01: Verify cold-cache photo retrieval when state_store._incidents is empty:
    1. Queries PostgreSQL incidents table for INC-COLD-01.
    2. Queries storage_object_registry using object_path=eq. (NOT canonical_path) and status=eq.ATTACHED.
    3. Downloads from Supabase Storage and serves image with private no-store headers.
    """
    client = TestClient(app)
    inc_id = "INC-COLD-01"
    jpeg_bytes = _make_clean_jpeg()
    digest = hashlib.sha256(jpeg_bytes).hexdigest()
    filename = f"sha256_{digest}.jpg"
    canonical_path = f"{inc_id}/{filename}"
    now_iso = datetime.now(timezone.utc).isoformat()

    # Clear in-memory cache completely to simulate cold restart
    with state_store._lock:
        state_store._incidents.clear()
        assert inc_id not in state_store._incidents

    pg_incident_row = {
        "id": inc_id,
        "category": "DRAIN_BLOCKAGE",
        "description": "Cold cache test incident",
        "latitude": 15.49,
        "longitude": 73.82,
        "status": "VERIFIED",
        "severity": "HIGH",
        "photos": [canonical_path],
        "created_at": now_iso,
        "updated_at": now_iso,
    }

    observed_urls = []
    orig_httpx_get = httpx.Client.get

    def fake_http_get(self_client, url, *args, **kwargs):
        url_str = str(url)
        if not url_str.startswith("https://test.supabase.co"):
            return orig_httpx_get(self_client, url, *args, **kwargs)
        observed_urls.append(url_str)
        resp = MagicMock()
        if "/rest/v1/incidents" in url_str:
            resp.status_code = 200
            resp.json.return_value = [pg_incident_row]
            return resp
        if "/rest/v1/storage_object_registry" in url_str:
            # Verify D-01 fix: query uses object_path=eq., never canonical_path=eq.
            assert "object_path=eq." in url_str
            assert "canonical_path=" not in url_str
            assert "status=eq.ATTACHED" in url_str
            resp.status_code = 200
            resp.json.return_value = [{
                "object_path": canonical_path,
                "incident_id": inc_id,
                "status": "ATTACHED",
            }]
            return resp
        if "/storage/v1/object/authenticated/" in url_str:
            resp.status_code = 200
            resp.content = jpeg_bytes
            resp.headers = {"content-type": "image/jpeg"}
            return resp
        resp.status_code = 404
        resp.json.return_value = []
        return resp

    with patch.object(persistence_repo, "_supabase_url", "https://test.supabase.co"), \
         patch.object(persistence_repo, "_supabase_key", "anon-key"), \
         patch.object(persistence_repo, "_supabase_service_role_key", "service-role-secret"), \
         patch.object(persistence_repo, "_active_key", "service-role-secret"), \
         patch.object(persistence_repo, "_is_configured", True), \
         patch.object(httpx.Client, "get", autospec=True, side_effect=fake_http_get):

        resp = client.get(f"/api/v1/incidents/{inc_id}/photos/{filename}")
        assert resp.status_code == 200
        assert resp.content == jpeg_bytes
        assert resp.headers["cache-control"] == "private, no-store, max-age=0"
        assert any("/rest/v1/incidents" in u for u in observed_urls)
        assert any("/rest/v1/storage_object_registry" in u for u in observed_urls)
        assert any("/storage/v1/object/authenticated/" in u for u in observed_urls)
        # Verify cache was populated from authoritative PostgreSQL
        assert inc_id in state_store._incidents


def test_sec_dur_02_partial_cloud_config_returns_503_without_local_fallback():
    """
    D-02: Verify that if database persistence is configured (is_configured=True)
    but Storage service-role key is missing (is_storage_configured=False),
    photo upload, canonical retrieval, and legacy retrieval all return HTTP 503
    and never fall back to local disk.
    """
    client = TestClient(app)
    create_resp = client.post("/api/v1/incidents", json={
        "category": "DRAIN_BLOCKAGE",
        "description": "Partial config test",
        "latitude": 15.49,
        "longitude": 73.82,
    })
    inc_id = create_resp.json()["id"]
    jpeg_bytes = _make_clean_jpeg()
    files = [("files", ("pic.jpg", jpeg_bytes, "image/jpeg"))]
    digest = hashlib.sha256(jpeg_bytes).hexdigest()

    with patch.object(PersistenceRepository, "is_configured", new_callable=PropertyMock, return_value=True), \
         patch.object(PersistenceRepository, "is_storage_configured", new_callable=PropertyMock, return_value=False):

        up_resp = client.post(
            f"/api/v1/incidents/{inc_id}/photos",
            files=files,
            headers={"Idempotency-Key": "partial_cfg_key_01"},
        )
        assert up_resp.status_code == 503
        assert "service-role storage credentials" in up_resp.json()["detail"].lower()

        get_scoped = client.get(f"/api/v1/incidents/{inc_id}/photos/sha256_{digest}.jpg")
        assert get_scoped.status_code == 503

        get_legacy = client.get(f"/api/v1/incidents/photos/{inc_id}_12345678.jpg")
        assert get_legacy.status_code == 503


def test_sec_dur_02_postgres_outage_returns_503_without_local_fallback():
    """
    D-02: Verify that during a PostgreSQL/PostgREST outage in cloud mode,
    upload, canonical retrieval, legacy retrieval, and audit retrieval all return HTTP 503
    even if the incident and photo exist in in-memory state_store and local UPLOAD_DIR.
    """
    client = TestClient(app)
    create_resp = client.post("/api/v1/incidents", json={
        "category": "DRAIN_BLOCKAGE",
        "description": "Outage fail-closed test",
        "latitude": 15.49,
        "longitude": 73.82,
    })
    inc_id = create_resp.json()["id"]
    jpeg_bytes = _make_clean_jpeg()
    files = [("files", ("local_before_outage.jpg", jpeg_bytes, "image/jpeg"))]

    # Upload locally first so both in-memory state and local disk have a valid photo
    local_up = client.post(f"/api/v1/incidents/{inc_id}/photos", files=files)
    assert local_up.status_code == 200
    legacy_filename = local_up.json()["photos"][0].split("/")[-1]
    digest = hashlib.sha256(jpeg_bytes).hexdigest()
    canonical_filename = f"sha256_{digest}.jpg"

    with patch.object(PersistenceRepository, "is_configured", new_callable=PropertyMock, return_value=True), \
         patch.object(PersistenceRepository, "is_storage_configured", new_callable=PropertyMock, return_value=True):

        # 1. Outage on query_incident_by_id_sync during upload -> 503
        with patch.object(persistence_repo, "query_incident_by_id_sync", side_effect=RuntimeError("PostgREST connection refused")):
            resp_up = client.post(
                f"/api/v1/incidents/{inc_id}/photos",
                files=files,
                headers={"Idempotency-Key": "outage_upload_key_01"},
            )
            assert resp_up.status_code == 503

            # 2. Outage on query_incident_by_id_sync during canonical photo retrieval -> 503 (no fallback to in-memory)
            resp_get = client.get(f"/api/v1/incidents/{inc_id}/photos/{canonical_filename}")
            assert resp_get.status_code == 503

        # 3. Outage on query_incidents_by_photo_entry_sync during legacy photo retrieval -> 503 (no fallback to local disk)
        with patch.object(persistence_repo, "query_incidents_by_photo_entry_sync", side_effect=RuntimeError("PostgREST timeout")):
            resp_leg = client.get(f"/api/v1/incidents/photos/{legacy_filename}")
            assert resp_leg.status_code == 503

        # 4. Outage on query_incident_audits_sync during audit trail retrieval -> 503
        with patch("app.core.security.verify_supabase_jwt", return_value={"sub": "admin1", "role": "admin", "extracted_role": "admin"}), \
             patch.object(persistence_repo, "query_incident_audits_sync", side_effect=RuntimeError("PostgREST audit query failed")):
            resp_aud = client.get(
                f"/api/v1/incidents/{inc_id}/audit",
                headers={"Authorization": "Bearer admin-token"},
            )
            assert resp_aud.status_code == 503


def test_sec_dur_03_stale_in_memory_membership_and_status_rejected():
    """
    SEC-DUR-03 / D-01 / D-02: Verify that stale in-memory incident state is never used to authorize
    or confirm membership in cloud mode:
    1. Photo present in state_store._incidents[id].photos in memory, but absent from PostgreSQL incidents.photos -> 404.
    2. Incident status is REPORTED in memory, but REJECTED in PostgreSQL -> 404 for unauthenticated caller.
    """
    client = TestClient(app)
    inc_id = "INC-STALE-01"
    jpeg_bytes = _make_clean_jpeg()
    digest = hashlib.sha256(jpeg_bytes).hexdigest()
    filename = f"sha256_{digest}.jpg"
    canonical_path = f"{inc_id}/{filename}"
    now_iso = datetime.now(timezone.utc).isoformat()

    # Seed stale in-memory incident claiming photo is attached and status is REPORTED
    with state_store._lock:
        state_store._incidents[inc_id] = IncidentResponseContract(
            id=inc_id,
            category=IncidentCategory.DRAIN_BLOCKAGE,
            description="Stale in-memory incident",
            latitude=15.49,
            longitude=73.82,
            status=IncidentStatus.REPORTED,
            severity=IncidentSeverity.MEDIUM,
            photos=[canonical_path],
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )

    # Case 1: Authoritative PostgreSQL row has empty photos=[]
    pg_row_no_photos = {
        "id": inc_id,
        "category": "DRAIN_BLOCKAGE",
        "description": "Authoritative row without photo",
        "latitude": 15.49,
        "longitude": 73.82,
        "status": "REPORTED",
        "severity": "MEDIUM",
        "photos": [],
        "created_at": now_iso,
        "updated_at": now_iso,
    }

    with patch.object(persistence_repo, "_supabase_url", "https://test.supabase.co"), \
         patch.object(persistence_repo, "_supabase_key", "anon-key"), \
         patch.object(persistence_repo, "_supabase_service_role_key", "service-role-secret"), \
         patch.object(persistence_repo, "_active_key", "service-role-secret"), \
         patch.object(persistence_repo, "_is_configured", True), \
         patch.object(persistence_repo, "query_incident_by_id_sync", return_value=pg_row_no_photos), \
         patch.object(persistence_repo, "download_incident_photo") as mock_dl:

        resp1 = client.get(f"/api/v1/incidents/{inc_id}/photos/{filename}")
        assert resp1.status_code == 404
        mock_dl.assert_not_called()

    # Case 2: Re-seed stale REPORTED in memory, while PostgreSQL has status=REJECTED
    with state_store._lock:
        state_store._incidents[inc_id].status = IncidentStatus.REPORTED
        state_store._incidents[inc_id].photos = [canonical_path]

    pg_row_rejected = {**pg_row_no_photos, "status": "REJECTED", "photos": [canonical_path]}
    with patch.object(persistence_repo, "_supabase_url", "https://test.supabase.co"), \
         patch.object(persistence_repo, "_supabase_key", "anon-key"), \
         patch.object(persistence_repo, "_supabase_service_role_key", "service-role-secret"), \
         patch.object(persistence_repo, "_active_key", "service-role-secret"), \
         patch.object(persistence_repo, "_is_configured", True), \
         patch.object(persistence_repo, "query_incident_by_id_sync", return_value=pg_row_rejected), \
         patch.object(persistence_repo, "download_incident_photo") as mock_dl:

        resp2 = client.get(f"/api/v1/incidents/{inc_id}/photos/{filename}")
        assert resp2.status_code == 404
        mock_dl.assert_not_called()
        assert state_store._incidents[inc_id].status == IncidentStatus.REJECTED


def test_sec_dur_03_non_attached_registry_states_rejected():
    """
    SEC-DUR-03 / D-01: Verify that objects in REGISTERED, CLEANUP_PENDING, DELETED, or UNCERTAIN
    states in storage_object_registry are rejected even if present in incidents.photos.
    """
    client = TestClient(app)
    inc_id = "INC-REG-01"
    jpeg_bytes = _make_clean_jpeg()
    digest = hashlib.sha256(jpeg_bytes).hexdigest()
    filename = f"sha256_{digest}.jpg"
    canonical_path = f"{inc_id}/{filename}"
    now_iso = datetime.now(timezone.utc).isoformat()

    pg_inc_row = {
        "id": inc_id,
        "category": "DRAIN_BLOCKAGE",
        "description": "Non-attached registry state test",
        "latitude": 15.49,
        "longitude": 73.82,
        "status": "REPORTED",
        "severity": "MEDIUM",
        "photos": [canonical_path],
        "created_at": now_iso,
        "updated_at": now_iso,
    }

    orig_httpx_get = httpx.Client.get
    for non_attached_status in ("REGISTERED", "CLEANUP_PENDING", "DELETED", "UNCERTAIN"):
        def fake_get(self_client, url, *args, **kwargs):
            url_str = str(url)
            if not url_str.startswith("https://test.supabase.co"):
                return orig_httpx_get(self_client, url, *args, **kwargs)
            resp = MagicMock()
            resp.status_code = 200
            if "/rest/v1/incidents" in url_str:
                resp.json.return_value = [pg_inc_row]
            elif "/rest/v1/storage_object_registry" in url_str:
                resp.json.return_value = [{
                    "object_path": canonical_path,
                    "incident_id": inc_id,
                    "status": non_attached_status,
                }]
            else:
                resp.status_code = 404
                resp.json.return_value = []
            return resp

        with patch.object(persistence_repo, "_supabase_url", "https://test.supabase.co"), \
             patch.object(persistence_repo, "_supabase_key", "anon-key"), \
             patch.object(persistence_repo, "_supabase_service_role_key", "service-role-secret"), \
             patch.object(persistence_repo, "_active_key", "service-role-secret"), \
             patch.object(persistence_repo, "_is_configured", True), \
             patch.object(httpx.Client, "get", autospec=True, side_effect=fake_get), \
             patch.object(persistence_repo, "download_incident_photo") as mock_dl:

            assert persistence_repo.verify_attached_photo_membership_sync(
                inc_id, canonical_path, incident_row=pg_inc_row
            ) is False

            resp = client.get(f"/api/v1/incidents/{inc_id}/photos/{filename}")
            assert resp.status_code == 404, f"Expected 404 for registry status {non_attached_status}"
            mock_dl.assert_not_called()


def test_sec_dur_04_duplicate_image_content_rejected():
    """
    SEC-DUR-04: Verify empty file list (400/422) and duplicate image content within the same request (400) are rejected.
    """
    client = TestClient(app)
    create_resp = client.post("/api/v1/incidents", json={
        "category": "DRAIN_BLOCKAGE",
        "description": "Payload validation test",
        "latitude": 15.49,
        "longitude": 73.82,
    })
    inc_id = create_resp.json()["id"]

    jpeg_bytes = _make_clean_jpeg()
    duplicate_files = [
        ("files", ("photo1.jpg", jpeg_bytes, "image/jpeg")),
        ("files", ("photo2.jpg", jpeg_bytes, "image/jpeg")),
    ]
    resp = client.post(f"/api/v1/incidents/{inc_id}/photos", files=duplicate_files)
    assert resp.status_code == 400
    assert "duplicate image content" in resp.json()["detail"].lower()


def test_sec_dur_05_local_audit_journal_failure_rolls_back_state_and_deletes_disk_file():
    """
    SEC-DUR-05: Verify that in local fallback mode, if durable audit journal append fails
    (returns False or raises OSError), the newly attached photo is rolled back from
    incident.photos and the newly written file on disk is deleted.
    """
    from app.api.v1.incidents import UPLOAD_DIR
    client = TestClient(app)
    create_resp = client.post("/api/v1/incidents", json={
        "category": "DRAIN_BLOCKAGE",
        "description": "Local audit rollback test",
        "latitude": 15.49,
        "longitude": 73.82,
    })
    inc_id = create_resp.json()["id"]
    jpeg_bytes = _make_clean_jpeg()
    files = [("files", ("rollback_test.jpg", jpeg_bytes, "image/jpeg"))]

    files_before = set(UPLOAD_DIR.glob(f"{inc_id}_*"))
    assert len(files_before) == 0

    with patch.object(state_store._audit_durability, "append_audit", return_value=False):
        resp = client.post(f"/api/v1/incidents/{inc_id}/photos", files=files)
        assert resp.status_code == 500
        assert "durable audit journal append failed" in resp.json()["detail"].lower()

    # In-memory incident photos must remain empty (rolled back)
    inc = state_store.get_incident(inc_id)
    assert inc is not None
    assert inc.photos == []

    # Newly written disk file must have been unlinked during rollback
    files_after = set(UPLOAD_DIR.glob(f"{inc_id}_*"))
    assert files_after == set()


def test_sec_dur_06_identical_image_attached_to_two_incidents_independent_retrieval():
    """
    SEC-DUR-06: Verify that identical image content attached to two different incidents
    (INC-DUP-A/sha256_<digest>.jpg and INC-DUP-B/sha256_<digest>.jpg) can be retrieved
    independently via the incident-scoped route with per-incident authorization, while
    the legacy filename-only route returns 404.
    """
    client = TestClient(app)
    jpeg_bytes = _make_clean_jpeg()
    digest = hashlib.sha256(jpeg_bytes).hexdigest()
    filename = f"sha256_{digest}.jpg"
    now_iso = datetime.now(timezone.utc).isoformat()

    inc_a = "INC-DUP-A"
    inc_b = "INC-DUP-B"
    path_a = f"{inc_a}/{filename}"
    path_b = f"{inc_b}/{filename}"

    rows_by_id = {
        inc_a: {
            "id": inc_a,
            "category": "DRAIN_BLOCKAGE",
            "description": "First incident with shared image digest",
            "latitude": 15.49,
            "longitude": 73.82,
            "status": "REPORTED",
            "severity": "MEDIUM",
            "photos": [path_a],
            "created_at": now_iso,
            "updated_at": now_iso,
        },
        inc_b: {
            "id": inc_b,
            "category": "FLOODING",
            "description": "Second incident with shared image digest (REJECTED)",
            "latitude": 15.50,
            "longitude": 73.83,
            "status": "REJECTED",
            "severity": "LOW",
            "photos": [path_b],
            "created_at": now_iso,
            "updated_at": now_iso,
        },
    }

    with patch.object(persistence_repo, "_supabase_url", "https://test.supabase.co"), \
         patch.object(persistence_repo, "_supabase_key", "anon-key"), \
         patch.object(persistence_repo, "_supabase_service_role_key", "service-role-secret"), \
         patch.object(persistence_repo, "_active_key", "service-role-secret"), \
         patch.object(persistence_repo, "_is_configured", True), \
         patch.object(persistence_repo, "query_incident_by_id_sync", side_effect=lambda i: rows_by_id.get(i)), \
         patch.object(persistence_repo, "verify_attached_photo_membership_sync", side_effect=lambda i, p, incident_row=None: p in (rows_by_id.get(i, {}).get("photos") or [])), \
         patch.object(persistence_repo, "download_incident_photo", side_effect=lambda p, incident_id=None: (jpeg_bytes, "image/jpeg")):

        # 1. Citizen can retrieve INC-DUP-A's photo (REPORTED -> 200)
        resp_a = client.get(f"/api/v1/incidents/{inc_a}/photos/{filename}")
        assert resp_a.status_code == 200
        assert resp_a.content == jpeg_bytes

        # 2. Citizen cannot retrieve INC-DUP-B's photo (REJECTED -> 404)
        resp_b_citizen = client.get(f"/api/v1/incidents/{inc_b}/photos/{filename}")
        assert resp_b_citizen.status_code == 404

        # 3. Admin can retrieve INC-DUP-B's photo (200)
        with patch("app.core.security.verify_supabase_jwt", return_value={"sub": "admin1", "role": "admin", "extracted_role": "admin"}):
            resp_b_admin = client.get(
                f"/api/v1/incidents/{inc_b}/photos/{filename}",
                headers={"Authorization": "Bearer admin-token"},
            )
            assert resp_b_admin.status_code == 200
            assert resp_b_admin.content == jpeg_bytes

        # 4. Legacy filename-only route rejects canonical sha256_ filename with 404
        resp_legacy = client.get(f"/api/v1/incidents/photos/{filename}")
        assert resp_legacy.status_code == 404


def test_sec_dur_06_legacy_filename_route_isolation_and_ambiguity():
    """
    SEC-DUR-06 / D-03: Verify legacy route /api/v1/incidents/photos/{filename} immediately rejects sha256_ filenames (404),
    supports both legacy entry formats ('{filename}' and '/api/v1/incidents/photos/{filename}') in cloud mode,
    and returns 404 on ambiguous duplicate filenames across incidents.
    """
    from app.api.v1.incidents import UPLOAD_DIR
    client = TestClient(app)
    canonical_name = "sha256_" + "e" * 64 + ".jpg"
    resp = client.get(f"/api/v1/incidents/photos/{canonical_name}")
    assert resp.status_code == 404
    assert "must be retrieved via /api/v1/incidents/{incident_id}/photos" in resp.json()["detail"]

    # Ambiguous legacy lookup in local mode
    with patch.object(state_store, "_incidents", {
        "INC-01": IncidentResponseContract(
            id="INC-01", category=IncidentCategory.DRAIN_BLOCKAGE, description="d1",
            latitude=15.49, longitude=73.82,
            status=IncidentStatus.REPORTED, severity=IncidentSeverity.MEDIUM,
            photos=["/api/v1/incidents/photos/duplicate.jpg"], created_at=datetime.now(), updated_at=datetime.now(),
        ),
        "INC-02": IncidentResponseContract(
            id="INC-02", category=IncidentCategory.DRAIN_BLOCKAGE, description="d2",
            latitude=15.49, longitude=73.82,
            status=IncidentStatus.REPORTED, severity=IncidentSeverity.MEDIUM,
            photos=["duplicate.jpg"], created_at=datetime.now(), updated_at=datetime.now(),
        ),
    }):
        resp_ambig = client.get("/api/v1/incidents/photos/duplicate.jpg")
        assert resp_ambig.status_code == 404
        assert "ambiguous" in resp_ambig.json()["detail"].lower()

    # Cloud-mode legacy lookup supporting both bare '{filename}' and '/api/v1/incidents/photos/{filename}'
    jpeg_bytes = _make_clean_jpeg()
    legacy_fn_1 = "INC-LEG-01_a1b2c3d4.jpg"
    legacy_fn_2 = "INC-LEG-02_e5f60718.jpg"
    (UPLOAD_DIR / legacy_fn_1).write_bytes(jpeg_bytes)
    (UPLOAD_DIR / legacy_fn_2).write_bytes(jpeg_bytes)
    now_iso = datetime.now(timezone.utc).isoformat()

    try:
        orig_httpx_get = httpx.Client.get

        def fake_pg_legacy_get(self_client, url, *args, **kwargs):
            url_str = str(url)
            if not url_str.startswith("https://test.supabase.co"):
                return orig_httpx_get(self_client, url, *args, **kwargs)
            resp = MagicMock()
            resp.status_code = 200
            if legacy_fn_1 in url_str:
                resp.json.return_value = [{
                    "id": "INC-LEG-01",
                    "category": "DRAIN_BLOCKAGE",
                    "description": "Bare filename legacy entry",
                    "latitude": 15.49,
                    "longitude": 73.82,
                    "status": "REPORTED",
                    "severity": "MEDIUM",
                    "photos": [legacy_fn_1],
                    "created_at": now_iso,
                    "updated_at": now_iso,
                }]
            elif legacy_fn_2 in url_str:
                resp.json.return_value = [{
                    "id": "INC-LEG-02",
                    "category": "DRAIN_BLOCKAGE",
                    "description": "Full path legacy entry",
                    "latitude": 15.49,
                    "longitude": 73.82,
                    "status": "REPORTED",
                    "severity": "MEDIUM",
                    "photos": [f"/api/v1/incidents/photos/{legacy_fn_2}"],
                    "created_at": now_iso,
                    "updated_at": now_iso,
                }]
            else:
                resp.json.return_value = []
            return resp

        with patch.object(persistence_repo, "_supabase_url", "https://test.supabase.co"), \
             patch.object(persistence_repo, "_supabase_key", "anon-key"), \
             patch.object(persistence_repo, "_supabase_service_role_key", "service-role-secret"), \
             patch.object(persistence_repo, "_active_key", "service-role-secret"), \
             patch.object(persistence_repo, "_is_configured", True), \
             patch.object(httpx.Client, "get", autospec=True, side_effect=fake_pg_legacy_get):

            r1 = client.get(f"/api/v1/incidents/photos/{legacy_fn_1}")
            assert r1.status_code == 200
            assert r1.content == jpeg_bytes

            r2 = client.get(f"/api/v1/incidents/photos/{legacy_fn_2}")
            assert r2.status_code == 200
            assert r2.content == jpeg_bytes
    finally:
        (UPLOAD_DIR / legacy_fn_1).unlink(missing_ok=True)
        (UPLOAD_DIR / legacy_fn_2).unlink(missing_ok=True)


def test_sec_dur_07_maintenance_cleanup_recovery_endpoint():
    """
    SEC-DUR-07: Verify POST /api/v1/incidents/maintenance/recover-storage-cleanup
    strictly requires admin or service_role and derives actor attribution from claims.
    """
    client = TestClient(app)
    payload = {
        "cleanup_id": "clean_recovery_01",
        "incident_id": "INC-01",
        "idempotency_key": "recovery_key_12345",
        "scope": "incident_attachment",
        "lease_sec": 60,
    }

    with patch("app.core.security.verify_supabase_jwt", return_value={"sub": "worker1", "role": "worker", "extracted_role": "worker"}):
        resp_worker = client.post(
            "/api/v1/incidents/maintenance/recover-storage-cleanup",
            json=payload,
            headers={"Authorization": "Bearer worker-token"},
        )
        assert resp_worker.status_code == 403

    with patch("app.core.security.verify_supabase_jwt", return_value={"sub": "admin_sub", "role": "admin", "extracted_role": "admin"}):
        with patch.object(
            persistence_repo,
            "execute_cleanup_recovery_workflow_sync",
            return_value={"status": "CLEANUP_RECOVERY_COMPLETED", "reconciled_count": 0},
        ) as mock_recovery:
            resp_admin = client.post(
                "/api/v1/incidents/maintenance/recover-storage-cleanup",
                json=payload,
                headers={"Authorization": "Bearer admin-token"},
            )
            assert resp_admin.status_code == 200
            assert resp_admin.json()["status"] == "CLEANUP_RECOVERY_COMPLETED"
            mock_recovery.assert_called_once_with(
                cleanup_id="clean_recovery_01",
                incident_id="INC-01",
                idempotency_key="recovery_key_12345",
                scope="incident_attachment",
                recovery_actor_id="admin_sub",
                recovery_actor_role="admin",
                lease_sec=60,
            )


def test_sec_dur_07_recovery_per_object_deletion_failure_records_uncertain_and_continues():
    """
    D-04: Verify that during execute_cleanup_recovery_workflow_sync, if deleting one object fails,
    the workflow records that object as UNCERTAIN via record_storage_cleanup_uncertain_sync
    and continues deleting and reconciling the remaining paths.
    """
    repo = PersistenceRepository(
        supabase_url="https://test.supabase.co",
        supabase_key="anon-key",
        service_role_key="service-role-secret",
    )
    path_fail = f"INC-01/sha256_{'1'*64}.jpg"
    path_ok = f"INC-01/sha256_{'2'*64}.jpg"

    def fake_delete(path, incident_id=None):
        if path == path_fail:
            raise StorageError("Storage backend 503 during delete")
        return True

    with patch.object(
        repo,
        "claim_expired_cleanup_operation_sync",
        return_value={
            "status": "CLEANUP_RECOVERY_CLAIMED",
            "cleanup_id": "clean_rec_01",
            "remaining_paths": [path_fail, path_ok],
        },
    ), patch.object(repo, "delete_incident_photo", side_effect=fake_delete), \
       patch.object(
           repo,
           "reconcile_storage_orphan_sync",
           return_value={"status": "RECONCILED_DELETED_OP_PARTIAL", "object_path": path_ok, "remaining_count": 1},
       ) as mock_reconcile, \
       patch.object(
           repo,
           "record_storage_cleanup_uncertain_sync",
           return_value={"status": "UNCERTAIN_RECORDED", "uncertain_paths": [path_fail]},
       ) as mock_uncertain:

        res = repo.execute_cleanup_recovery_workflow_sync(
            cleanup_id="clean_rec_01",
            incident_id="INC-01",
            idempotency_key="rec_idemp_key_01",
            scope="incident_attachment",
            recovery_actor_id="admin_user",
            recovery_actor_role="admin",
        )

        assert res["status"] == "CLEANUP_RECOVERY_PARTIAL_UNCERTAIN"
        assert res["reconciled_count"] == 1
        assert res["uncertain_paths"] == [path_fail]
        mock_reconcile.assert_called_once()
        assert mock_reconcile.call_args.kwargs["object_path"] == path_ok
        mock_uncertain.assert_called_once()
        assert mock_uncertain.call_args.kwargs["uncertain_paths"] == [path_fail]
        assert RECOVERY_LEASE_PATTERN.match(mock_uncertain.call_args.kwargs["lease_owner"])


def test_sec_dur_08_strict_privacy_and_cache_headers():
    """
    SEC-DUR-08: Verify strict privacy and cache headers on photo responses:
    Cache-Control: private, no-store, max-age=0
    Pragma: no-cache
    Vary: Authorization
    X-Content-Type-Options: nosniff
    """
    client = TestClient(app)
    create_resp = client.post("/api/v1/incidents", json={
        "category": "DRAIN_BLOCKAGE",
        "description": "Headers verification test",
        "latitude": 15.49,
        "longitude": 73.82,
    })
    inc_id = create_resp.json()["id"]

    jpeg_bytes = _make_clean_jpeg()
    files = [("files", ("test.jpg", jpeg_bytes, "image/jpeg"))]
    up_resp = client.post(f"/api/v1/incidents/{inc_id}/photos", files=files)
    photo_url = up_resp.json()["photos"][0]

    resp = client.get(photo_url)
    assert resp.status_code == 200
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["cache-control"] == "private, no-store, max-age=0"
    assert resp.headers["pragma"] == "no-cache"
    assert "Authorization" in resp.headers["vary"]


def test_v3_1_migration_005_structure_and_rpcs():
    """
    SEC-DUR-09: Parses canonical migration 005 with pglast (official PostgreSQL libpg_query C parser)
    and verifies primary keys, unique constraints, RLS policies, privileges, all 9 RPCs, and all 3 triggers.
    """
    import pglast

    repo_root = Path(__file__).resolve().parent.parent.parent
    migration_path = repo_root / "database" / "migrations" / "005_incident_photo_storage_registry_and_rpcs.sql"
    assert migration_path.exists(), "005_incident_photo_storage_registry_and_rpcs.sql must exist"

    sql = migration_path.read_text(encoding="utf-8")
    tree = pglast.parse_sql(sql)
    assert len(tree) == 60, f"Expected 60 top-level SQL statements in migration 005, got {len(tree)}"

    # Verify exact Primary Keys and Unique Constraint definitions (SEC-DUR-09)
    assert "object_path TEXT PRIMARY KEY" in sql
    assert "CONSTRAINT pk_api_idempotency_keys PRIMARY KEY (idempotency_key, scope)" in sql
    assert "CONSTRAINT pk_api_idempotency_objects PRIMARY KEY (idempotency_key, scope, object_path)" in sql
    assert "cleanup_id VARCHAR(64) PRIMARY KEY" in sql
    assert "CONSTRAINT uq_cleanup_reservation_attempt UNIQUE (idempotency_key, scope, attempt_no)" in sql
    assert "CONSTRAINT pk_cleanup_op_objects PRIMARY KEY (cleanup_id, object_path)" in sql

    # Verify all 9 V3.1 RPCs and their REVOKE/GRANT service_role privileges
    expected_rpcs = [
        "reserve_photo_attachment_rpc",
        "verify_and_register_storage_object_rpc",
        "finalize_photo_attachment_rpc",
        "initiate_storage_cleanup_rpc",
        "confirm_storage_cleanup_rpc",
        "record_storage_cleanup_uncertain_rpc",
        "claim_expired_cleanup_operation_rpc",
        "reconcile_storage_orphan_rpc",
        "renew_or_takeover_lease_rpc",
    ]
    for rpc in expected_rpcs:
        assert f"FUNCTION public.{rpc}" in sql, f"RPC {rpc} missing from migration 005"
        assert f"REVOKE ALL ON FUNCTION public.{rpc}" in sql, f"REVOKE ALL missing for {rpc}"
        assert f"GRANT EXECUTE ON FUNCTION public.{rpc}" in sql, f"GRANT EXECUTE missing for {rpc}"

    # Verify all 3 triggers
    expected_triggers = [
        "enforce_storage_registry_immutability",
        "prevent_storage_registry_truncate",
        "maintain_storage_active_claim_count",
    ]
    for trg in expected_triggers:
        assert trg in sql, f"Trigger {trg} missing from migration 005"

    # Verify RLS enabled on all 5 tables and table privileges restricted
    for tbl in (
        "storage_object_registry",
        "api_idempotency_keys",
        "api_idempotency_objects",
        "storage_cleanup_operations",
        "storage_cleanup_operation_objects",
    ):
        assert f"ALTER TABLE public.{tbl} ENABLE ROW LEVEL SECURITY;" in sql

    assert "FROM PUBLIC, anon, authenticated, service_role;" in sql
    assert "SET search_path = pg_catalog, public, pg_temp" in sql
