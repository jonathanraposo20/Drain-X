import pytest
from fastapi.testclient import TestClient

from app.core.config import AUTHORIZED_VERCEL_PREVIEW_ORIGIN_REGEX, Settings, settings
from app.main import create_app


def _preflight(client: TestClient, origin: str):
    return client.options(
        "/api/v1/health/liveness",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Authorization,Content-Type",
        },
    )


def test_cors_allows_production_and_authorized_preview_rejects_untrusted(monkeypatch):
    monkeypatch.setattr(settings, "ADDITIONAL_CORS_ORIGINS", "https://drain-x.vercel.app")
    monkeypatch.setattr(settings, "CORS_ORIGIN_REGEX", AUTHORIZED_VERCEL_PREVIEW_ORIGIN_REGEX)

    client = TestClient(create_app())

    # 1. Exact production origin allowed with credentials
    prod_resp = _preflight(client, "https://drain-x.vercel.app")
    assert prod_resp.status_code == 200
    assert prod_resp.headers.get("access-control-allow-origin") == "https://drain-x.vercel.app"
    assert prod_resp.headers.get("access-control-allow-credentials") == "true"

    # 2. Authorized DRAIN-X Vercel preview origin allowed with credentials
    preview_origin = "https://drain-x-git-feat-phase-3-supabase-c83414-jonathanraposo673-4283.vercel.app"
    prev_resp = _preflight(client, preview_origin)
    assert prev_resp.status_code == 200
    assert prev_resp.headers.get("access-control-allow-origin") == preview_origin
    assert prev_resp.headers.get("access-control-allow-credentials") == "true"

    # 3. Unrelated Vercel deployments rejected
    for unrelated in [
        "https://other-project-jonathanraposo673-4283.vercel.app",
        "https://drain-x-git-main-otherteam.vercel.app",
        "https://drain-x.vercel.app.attacker.com",
    ]:
        resp = _preflight(client, unrelated)
        assert resp.status_code == 400
        assert "access-control-allow-origin" not in resp.headers

    # 4. Arbitrary malicious or insecure origins rejected
    for malicious in [
        "https://evil-example.com",
        "http://drain-x-git-main-jonathanraposo673-4283.vercel.app",
    ]:
        resp = _preflight(client, malicious)
        assert resp.status_code == 400
        assert "access-control-allow-origin" not in resp.headers


def test_cors_wildcard_is_rejected_and_stripped(monkeypatch):
    monkeypatch.setattr(settings, "ADDITIONAL_CORS_ORIGINS", "*,https://drain-x.vercel.app")
    monkeypatch.setattr(settings, "CORS_ORIGIN_REGEX", None)
    client = TestClient(create_app())

    evil_resp = _preflight(client, "https://evil-example.com")
    assert evil_resp.status_code == 400
    assert "access-control-allow-origin" not in evil_resp.headers

    with pytest.raises(ValueError, match="wildcard origin"):
        Settings(CORS_ORIGINS=["*"])
    with pytest.raises(ValueError, match="wildcard origin"):
        Settings(CORS_ORIGINS=["https://drain-x.vercel.app", " * "])

    with pytest.raises(ValueError, match="approved DRAIN-X"):
        Settings(CORS_ORIGIN_REGEX="*")
    with pytest.raises(ValueError, match="approved DRAIN-X"):
        Settings(CORS_ORIGIN_REGEX="https://drain-x.vercel.app")
    with pytest.raises(ValueError, match="approved DRAIN-X"):
        Settings(CORS_ORIGIN_REGEX=r"^https://.*\.vercel\.app$")
