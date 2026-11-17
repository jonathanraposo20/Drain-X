from fastapi.testclient import TestClient
import pytest


def test_get_seeded_demo_incidents(client: TestClient):
    response = client.get("/api/v1/incidents")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 4

    demo_ids = [item["id"] for item in data]
    assert "INC-DEMO-01" in demo_ids
    assert "INC-DEMO-02" in demo_ids
    assert "INC-DEMO-03" in demo_ids
    assert "INC-DEMO-04" in demo_ids

    inc1 = next(item for item in data if item["id"] == "INC-DEMO-01")
    assert inc1["category"] == "DRAIN_OVERFLOW"
    assert inc1["severity"] == "CRITICAL"
    assert inc1["status"] == "INVESTIGATING"
    assert inc1["source"] == "DEMO"
    assert "Team Alpha" in inc1["assigned_to"]


def test_create_citizen_incident(client: TestClient):
    payload = {
        "category": "DRAIN_BLOCKAGE",
        "description": "Large garbage bag and fallen branches blocking culvert entrance.",
        "latitude": 15.4950,
        "longitude": 73.8210,
        "severity": "HIGH",
        "source": "CITIZEN",
        "reporter_name": "Maria Fernandes",
    }
    response = client.post("/api/v1/incidents", json=payload)
    assert response.status_code == 201
    created = response.json()

    assert created["id"].startswith("INC-")
    assert created["category"] == "DRAIN_BLOCKAGE"
    assert created["description"] == payload["description"]
    assert created["latitude"] == 15.4950
    assert created["longitude"] == 73.8210
    assert created["severity"] == "HIGH"
    assert created["status"] == "REPORTED"
    assert created["source"] == "CITIZEN"
    assert created["reporter_name"] == "Maria Fernandes"
    assert created["assigned_to"] is None

    # Verify it now appears in the list
    list_resp = client.get("/api/v1/incidents")
    assert any(item["id"] == created["id"] for item in list_resp.json())


def test_create_incident_validation_errors(client: TestClient):
    # Short description
    res1 = client.post("/api/v1/incidents", json={
        "category": "WATERLOGGING",
        "description": "ab",
        "latitude": 15.5,
        "longitude": 73.8,
    })
    assert res1.status_code == 422

    # Invalid latitude
    res2 = client.post("/api/v1/incidents", json={
        "category": "WATERLOGGING",
        "description": "Waterlogging across road",
        "latitude": 95.0,
        "longitude": 73.8,
    })
    assert res2.status_code == 422

    # Invalid longitude
    res3 = client.post("/api/v1/incidents", json={
        "category": "WATERLOGGING",
        "description": "Waterlogging across road",
        "latitude": 15.5,
        "longitude": -190.0,
    })
    assert res3.status_code == 422


def test_get_incident_by_id(client: TestClient):
    # Existing demo incident
    response = client.get("/api/v1/incidents/INC-DEMO-01")
    assert response.status_code == 200
    assert response.json()["id"] == "INC-DEMO-01"

    # Nonexistent incident
    missing_response = client.get("/api/v1/incidents/INC-DOES-NOT-EXIST")
    assert missing_response.status_code == 404


def test_filter_incidents(client: TestClient):
    # Filter by status
    resp_investigating = client.get("/api/v1/incidents?status=INVESTIGATING")
    assert resp_investigating.status_code == 200
    items = resp_investigating.json()
    assert len(items) >= 1
    assert all(i["status"] == "INVESTIGATING" for i in items)

    # Filter by severity
    resp_critical = client.get("/api/v1/incidents?severity=CRITICAL")
    assert resp_critical.status_code == 200
    crit_items = resp_critical.json()
    assert len(crit_items) >= 1
    assert all(i["severity"] == "CRITICAL" for i in crit_items)

    # Filter by category
    resp_cat = client.get("/api/v1/incidents?category=DRAIN_OVERFLOW")
    assert resp_cat.status_code == 200
    cat_items = resp_cat.json()
    assert len(cat_items) >= 1
    assert all(i["category"] == "DRAIN_OVERFLOW" for i in cat_items)

    # Filter by source
    resp_demo = client.get("/api/v1/incidents?source=DEMO")
    assert resp_demo.status_code == 200
    assert all(i["source"] == "DEMO" for i in resp_demo.json())


def test_valid_incident_status_transitions(client: TestClient, admin_client: TestClient):
    # Create new incident
    create_resp = client.post("/api/v1/incidents", json={
        "category": "WATERLOGGING",
        "description": "Pedestrian underpass submerged under 30cm water.",
        "latitude": 15.4912,
        "longitude": 73.8245,
        "severity": "HIGH",
    })
    incident_id = create_resp.json()["id"]
    assert create_resp.json()["status"] == "REPORTED"

    # REPORTED -> VERIFIED
    patch1 = admin_client.patch(f"/api/v1/incidents/{incident_id}", json={
        "status": "VERIFIED",
        "municipal_notes": "Verified via CCTV camera stream.",
    })
    assert patch1.status_code == 200
    assert patch1.json()["status"] == "VERIFIED"
    assert "CCTV camera" in patch1.json()["municipal_notes"]

    # VERIFIED -> ASSIGNED
    patch2 = admin_client.patch(f"/api/v1/incidents/{incident_id}", json={
        "status": "ASSIGNED",
        "assigned_to": "Team Alpha — St. Inez Drainage Crew",
    })
    assert patch2.status_code == 200
    assert patch2.json()["status"] == "ASSIGNED"
    assert patch2.json()["assigned_to"] == "Team Alpha — St. Inez Drainage Crew"

    # ASSIGNED -> INVESTIGATING
    patch3 = admin_client.patch(f"/api/v1/incidents/{incident_id}", json={
        "status": "INVESTIGATING",
        "municipal_notes": "Team arrived with submersible pump.",
    })
    assert patch3.status_code == 200
    assert patch3.json()["status"] == "INVESTIGATING"

    # INVESTIGATING -> RESOLVED
    patch4 = admin_client.patch(f"/api/v1/incidents/{incident_id}", json={
        "status": "RESOLVED",
        "municipal_notes": "Water cleared; grate unclogged.",
    })
    assert patch4.status_code == 200
    assert patch4.json()["status"] == "RESOLVED"


def test_invalid_incident_status_transitions(client: TestClient, admin_client: TestClient):
    # Create new incident (status: REPORTED)
    create_resp = client.post("/api/v1/incidents", json={
        "category": "DRAIN_BLOCKAGE",
        "description": "Minor leaf block in residential ditch.",
        "latitude": 15.4880,
        "longitude": 73.8150,
        "severity": "LOW",
    })
    incident_id = create_resp.json()["id"]

    # REPORTED -> RESOLVED is NOT a valid direct transition
    invalid_patch = admin_client.patch(f"/api/v1/incidents/{incident_id}", json={
        "status": "RESOLVED",
    })
    assert invalid_patch.status_code == 400
    assert "Illegal status transition" in invalid_patch.json()["detail"]

    # Nonexistent incident returns 404
    missing_patch = admin_client.patch("/api/v1/incidents/INC-FAKE-999", json={
        "status": "VERIFIED",
    })
    assert missing_patch.status_code == 404


def test_upload_valid_incident_photos(client: TestClient):
    # 1. Create an incident
    create_resp = client.post("/api/v1/incidents", json={
        "category": "DRAIN_BLOCKAGE",
        "description": "Culvert blocked with leaves and plastic bottles.",
        "latitude": 15.4920,
        "longitude": 73.8240,
        "severity": "HIGH",
    })
    incident_id = create_resp.json()["id"]

    from tests.conftest import create_test_image
    # 2. Upload 2 photos (JPEG and PNG)
    test_jpeg = create_test_image("JPEG")
    test_png = create_test_image("PNG")

    files = [
        ("files", ("blockage_1.jpg", test_jpeg, "image/jpeg")),
        ("files", ("blockage_2.png", test_png, "image/png")),
    ]

    upload_resp = client.post(f"/api/v1/incidents/{incident_id}/photos", files=files)
    assert upload_resp.status_code == 200
    data = upload_resp.json()
    assert len(data["photos"]) == 2
    assert all(p.startswith("/api/v1/incidents/photos/") for p in data["photos"])

    # 3. Retrieve the photo via controlled GET endpoint
    photo_url = data["photos"][0]
    get_photo_resp = client.get(photo_url)
    assert get_photo_resp.status_code == 200
    assert get_photo_resp.headers["content-type"] == "image/jpeg"
    assert len(get_photo_resp.content) > 0


def test_upload_invalid_mime_type(client: TestClient):
    create_resp = client.post("/api/v1/incidents", json={
        "category": "WATERLOGGING",
        "description": "Street flooded.",
        "latitude": 15.49,
        "longitude": 73.82,
    })
    incident_id = create_resp.json()["id"]

    bad_file = [("files", ("notes.txt", b"This is not an image", "text/plain"))]
    resp = client.post(f"/api/v1/incidents/{incident_id}/photos", files=bad_file)
    assert resp.status_code == 400
    assert "Unsupported image type" in resp.json()["detail"]


def test_upload_oversized_image(client: TestClient):
    create_resp = client.post("/api/v1/incidents", json={
        "category": "WATERLOGGING",
        "description": "Street flooded.",
        "latitude": 15.49,
        "longitude": 73.82,
    })
    incident_id = create_resp.json()["id"]

    # 5MB + 1 byte
    oversized_data = b"X" * (5 * 1024 * 1024 + 1)
    file_payload = [("files", ("huge.jpg", oversized_data, "image/jpeg"))]
    resp = client.post(f"/api/v1/incidents/{incident_id}/photos", files=file_payload)
    assert resp.status_code == 400
    assert "exceeds maximum allowable size of 5 MB" in resp.json()["detail"]


def test_upload_more_than_three_images(client: TestClient):
    create_resp = client.post("/api/v1/incidents", json={
        "category": "WATERLOGGING",
        "description": "Street flooded.",
        "latitude": 15.49,
        "longitude": 73.82,
    })
    incident_id = create_resp.json()["id"]

    dummy_jpeg = b"\xff\xd8\xff\xe0" + (b"A" * 50)
    four_files = [
        ("files", (f"img_{i}.jpg", dummy_jpeg, "image/jpeg")) for i in range(4)
    ]
    resp = client.post(f"/api/v1/incidents/{incident_id}/photos", files=four_files)
    assert resp.status_code == 400
    assert "Cannot exceed maximum limit of 3 photos" in resp.json()["detail"]


def test_get_photo_security_validations(client: TestClient):
    # Path traversal attempt
    traversal_resp = client.get("/api/v1/incidents/photos/..%2F..%2Fsecret.jpg")
    assert traversal_resp.status_code in (400, 404)

    # Invalid extension
    bad_ext_resp = client.get("/api/v1/incidents/photos/script.sh")
    assert bad_ext_resp.status_code == 400

    # Nonexistent photo
    missing_resp = client.get("/api/v1/incidents/photos/nonexistent_photo_9999.jpg")
    assert missing_resp.status_code == 404

