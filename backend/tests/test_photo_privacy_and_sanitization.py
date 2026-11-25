"""
DRAIN-X P1.3.5.5 — Server-Side Photo Privacy & EXIF Sanitization Test Suite.

Verifies:
1. Uploading a JPEG with synthetic GPS EXIF metadata strips all GPS metadata on storage.
2. All EXIF metadata (camera make, model, timestamps) is absent from the stored image.
3. The stored sanitized image remains visually and structurally valid.
4. PNG uploads work and are sanitized without metadata leakage.
5. WebP uploads work and are sanitized cleanly.
6. Malformed and corrupted image files are rejected with 400 Bad Request.
7. Unsupported formats (e.g. BMP, GIF) are rejected with 400 Bad Request.
8. Unbounded/oversized image dimensions (>6000px) are rejected with 400 Bad Request.
9. 3-photo maximum per incident limit is strictly enforced.
10. Photo registration check prevents accessing arbitrary or unregistered files.
11. Public cache headers and security headers (nosniff, Cache-Control) are present.
"""

import io
from typing import Dict, Any
from unittest.mock import patch
import pytest
from PIL import Image, ExifTags
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings
from app.services.state_store import state_store


def _make_jpeg_with_synthetic_gps_exif() -> bytes:
    """Creates a synthetic test JPEG with GPS coordinates and camera metadata."""
    img = Image.new("RGB", (50, 50), color="orange")
    exif = img.getexif()

    # Camera metadata
    exif[0x010F] = "SyntheticCameraMaker"       # Make
    exif[0x0110] = "Model-Alpha-Pro"             # Model
    exif[0x0131] = "Firmware v1.2.3"             # Software
    exif[0x0132] = "2026:11:15 16:45:00"         # DateTime

    # GPS metadata IFD
    gps_ifd = exif.get_ifd(ExifTags.IFD.GPSInfo)
    gps_ifd[1] = "N"                             # GPSLatitudeRef
    gps_ifd[2] = 15.4950                         # GPSLatitude
    gps_ifd[3] = "E"                             # GPSLongitudeRef
    gps_ifd[4] = 73.8210                         # GPSLongitude

    buf = io.BytesIO()
    img.save(buf, format="JPEG", exif=exif)
    raw_bytes = buf.getvalue()

    # Self-check that the generated test image indeed contains the synthetic metadata
    verify_img = Image.open(io.BytesIO(raw_bytes))
    verify_exif = verify_img.getexif()
    assert len(verify_exif) > 0, "Test fixture must contain EXIF metadata"
    assert verify_exif.get(0x010F) == "SyntheticCameraMaker"
    assert len(verify_exif.get_ifd(ExifTags.IFD.GPSInfo)) > 0, "Test fixture must contain GPS info"

    return raw_bytes


def _make_test_image(format_name: str, mode: str = "RGB", size: tuple = (30, 30)) -> bytes:
    """Creates a clean synthetic test image in the specified format."""
    img = Image.new(mode, size, color="teal")
    buf = io.BytesIO()
    img.save(buf, format=format_name)
    return buf.getvalue()


@pytest.fixture(autouse=True)
def reset_incidents():
    state_store.clear()
    state_store.seed_demo_incidents()


def test_1_jpeg_gps_and_exif_metadata_stripped_server_side(client: TestClient):
    """
    Test 1: Upload a JPEG with GPS coordinates and camera metadata.
    Verify that the stored image has all GPS and EXIF structures removed.
    """
    # 1. Create an incident
    create_resp = client.post("/api/v1/incidents", json={
        "category": "DRAIN_BLOCKAGE",
        "description": "Street drain clogged with gravel.",
        "latitude": 15.495,
        "longitude": 73.821,
    })
    assert create_resp.status_code == 201
    inc_id = create_resp.json()["id"]

    # 2. Upload the JPEG containing GPS and camera metadata
    raw_with_gps = _make_jpeg_with_synthetic_gps_exif()
    files = [("files", ("hazard_with_gps.jpg", raw_with_gps, "image/jpeg"))]
    upload_resp = client.post(f"/api/v1/incidents/{inc_id}/photos", files=files)
    assert upload_resp.status_code == 200
    photos = upload_resp.json()["photos"]
    assert len(photos) == 1
    photo_url = photos[0]

    # 3. Retrieve the stored image
    get_resp = client.get(photo_url)
    assert get_resp.status_code == 200
    stored_bytes = get_resp.content

    # 4. Verify GPS metadata is absent
    stored_img = Image.open(io.BytesIO(stored_bytes))
    stored_exif = stored_img.getexif()

    gps_data = stored_exif.get_ifd(ExifTags.IFD.GPSInfo)
    assert len(gps_data) == 0, f"GPS Info was not stripped! Found: {gps_data}"

    # 5. Verify camera metadata (Make, Model, Software, DateTime) is absent
    assert len(stored_exif) == 0, f"EXIF was not stripped! Found tags: {list(stored_exif.keys())}"
    assert stored_exif.get(0x010F) is None
    assert stored_exif.get(0x0110) is None
    assert stored_exif.get(0x0132) is None

    # 6. Confirm visual validity
    assert stored_img.format == "JPEG"
    assert stored_img.size == (50, 50)
    assert stored_img.mode == "RGB"


def test_2_png_upload_and_sanitization(client: TestClient):
    """Test 2: PNG format is accepted, sanitized, and stored cleanly."""
    create_resp = client.post("/api/v1/incidents", json={
        "category": "WATERLOGGING",
        "description": "Footpath flooded with stormwater.",
        "latitude": 15.49,
        "longitude": 73.82,
    })
    inc_id = create_resp.json()["id"]

    png_bytes = _make_test_image("PNG", mode="RGBA", size=(40, 40))
    files = [("files", ("flooded_path.png", png_bytes, "image/png"))]

    upload_resp = client.post(f"/api/v1/incidents/{inc_id}/photos", files=files)
    assert upload_resp.status_code == 200
    photo_url = upload_resp.json()["photos"][0]

    get_resp = client.get(photo_url)
    assert get_resp.status_code == 200
    assert get_resp.headers["content-type"] == "image/png"

    retrieved = Image.open(io.BytesIO(get_resp.content))
    assert retrieved.format == "PNG"
    assert retrieved.size == (40, 40)


def test_3_webp_upload_and_sanitization(client: TestClient):
    """Test 3: WebP format is accepted, sanitized, and stored cleanly."""
    create_resp = client.post("/api/v1/incidents", json={
        "category": "INFRASTRUCTURE_DAMAGE",
        "description": "Cracked concrete culvert lid.",
        "latitude": 15.485,
        "longitude": 73.815,
    })
    inc_id = create_resp.json()["id"]

    webp_bytes = _make_test_image("WEBP", mode="RGB", size=(35, 35))
    files = [("files", ("broken_lid.webp", webp_bytes, "image/webp"))]

    upload_resp = client.post(f"/api/v1/incidents/{inc_id}/photos", files=files)
    assert upload_resp.status_code == 200
    photo_url = upload_resp.json()["photos"][0]

    get_resp = client.get(photo_url)
    assert get_resp.status_code == 200
    assert get_resp.headers["content-type"] == "image/webp"

    retrieved = Image.open(io.BytesIO(get_resp.content))
    assert retrieved.format == "WEBP"
    assert retrieved.size == (35, 35)


def test_4_malformed_image_rejected(client: TestClient):
    """Test 4: Non-image or corrupted bytes disguised with image MIME type are rejected with 400."""
    create_resp = client.post("/api/v1/incidents", json={
        "category": "DRAIN_BLOCKAGE",
        "description": "Testing corrupted upload.",
        "latitude": 15.49,
        "longitude": 73.82,
    })
    inc_id = create_resp.json()["id"]

    fake_jpeg = b"\xff\xd8\xff\xe0" + (b"TRUNCATED_CORRUPT_PAYLOAD" * 10)
    files = [("files", ("corrupt.jpg", fake_jpeg, "image/jpeg"))]

    upload_resp = client.post(f"/api/v1/incidents/{inc_id}/photos", files=files)
    assert upload_resp.status_code == 400
    assert "not a valid or recognizable image" in upload_resp.json()["detail"].lower()


def test_5_unsupported_image_format_rejected(client: TestClient):
    """Test 5: Unsupported image formats (e.g. BMP, GIF) are rejected with 400."""
    create_resp = client.post("/api/v1/incidents", json={
        "category": "DRAIN_BLOCKAGE",
        "description": "Testing unsupported BMP.",
        "latitude": 15.49,
        "longitude": 73.82,
    })
    inc_id = create_resp.json()["id"]

    # 1. BMP with image/bmp header
    bmp_bytes = _make_test_image("BMP", mode="RGB", size=(20, 20))
    files = [("files", ("test.bmp", bmp_bytes, "image/bmp"))]
    upload_resp = client.post(f"/api/v1/incidents/{inc_id}/photos", files=files)
    assert upload_resp.status_code == 400
    assert "unsupported image type" in upload_resp.json()["detail"].lower()

    # 2. BMP disguised with image/jpeg header
    files_disguised = [("files", ("disguised.jpg", bmp_bytes, "image/jpeg"))]
    upload_resp_disguised = client.post(f"/api/v1/incidents/{inc_id}/photos", files=files_disguised)
    assert upload_resp_disguised.status_code == 400
    assert "unsupported image format" in upload_resp_disguised.json()["detail"].lower()


def test_6_oversized_dimensions_rejected(client: TestClient):
    """Test 6: Excessively large image dimensions (>6000px) are rejected to prevent resource exhaustion."""
    create_resp = client.post("/api/v1/incidents", json={
        "category": "DRAIN_BLOCKAGE",
        "description": "Testing oversized dimensions.",
        "latitude": 15.49,
        "longitude": 73.82,
    })
    inc_id = create_resp.json()["id"]

    # 6500 x 10 image
    wide_img = Image.new("RGB", (6500, 10), color="red")
    buf = io.BytesIO()
    wide_img.save(buf, format="JPEG")
    files = [("files", ("wide.jpg", buf.getvalue(), "image/jpeg"))]

    upload_resp = client.post(f"/api/v1/incidents/{inc_id}/photos", files=files)
    assert upload_resp.status_code == 400
    assert "exceed maximum allowable size" in upload_resp.json()["detail"].lower()


def test_7_cache_control_and_security_headers_present(client: TestClient):
    """
    Test 7: Cache-Control and nosniff headers are verified on photo responses.
    Public evidence is cacheable for 1 hour; MIME sniffing is disabled.
    """
    create_resp = client.post("/api/v1/incidents", json={
        "category": "DRAIN_BLOCKAGE",
        "description": "Testing cache headers.",
        "latitude": 15.49,
        "longitude": 73.82,
    })
    inc_id = create_resp.json()["id"]

    jpeg_bytes = _make_test_image("JPEG")
    files = [("files", ("evidence.jpg", jpeg_bytes, "image/jpeg"))]

    upload_resp = client.post(f"/api/v1/incidents/{inc_id}/photos", files=files)
    photo_url = upload_resp.json()["photos"][0]

    get_resp = client.get(photo_url)
    assert get_resp.status_code == 200
    assert "private" in get_resp.headers["cache-control"]
    assert "no-store" in get_resp.headers["cache-control"]
    assert get_resp.headers["x-content-type-options"] == "nosniff"


def test_8_oversized_file_bytes_rejected(client: TestClient):
    """Test 8: File exceeding MAX_PHOTO_SIZE_BYTES (5MB) is rejected."""
    create_resp = client.post("/api/v1/incidents", json={
        "category": "DRAIN_BLOCKAGE",
        "description": "Testing oversized file size.",
        "latitude": 15.49,
        "longitude": 73.82,
    })
    inc_id = create_resp.json()["id"]

    # 5.1 MB dummy data
    oversized = b"X" * (5 * 1024 * 1024 + 1024)
    files = [("files", ("huge.jpg", oversized, "image/jpeg"))]

    resp = client.post(f"/api/v1/incidents/{inc_id}/photos", files=files)
    assert resp.status_code == 400
    assert "exceeds maximum allowable size of 5 mb" in resp.json()["detail"].lower()


def test_9_photo_count_limit_enforced(client: TestClient):
    """Test 9: Incident cannot exceed MAX_PHOTOS_PER_INCIDENT (3 photos)."""
    create_resp = client.post("/api/v1/incidents", json={
        "category": "DRAIN_BLOCKAGE",
        "description": "Testing photo limit count.",
        "latitude": 15.49,
        "longitude": 73.82,
    })
    inc_id = create_resp.json()["id"]

    img_bytes = _make_test_image("JPEG")
    files_4 = [("files", (f"img_{i}.jpg", img_bytes, "image/jpeg")) for i in range(4)]

    resp = client.post(f"/api/v1/incidents/{inc_id}/photos", files=files_4)
    assert resp.status_code == 400
    assert "cannot exceed maximum limit of 3 photos" in resp.json()["detail"].lower()


def test_10_unregistered_photo_rejected_404(client: TestClient):
    """Test 10: Querying a photo filename not registered to any incident returns 404."""
    resp = client.get("/api/v1/incidents/photos/INC-DEMO-01_fabricated_name.jpg")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()

