import pytest

from app.models.contracts import (
    IncidentResponseContract,
    IncidentCategory,
    IncidentSeverity,
    IncidentSource,
)
from app.services.state_store import StateStore
from app.services.persistence_repository import persistence_repo


@pytest.fixture
def incident_store(monkeypatch):
    # Prevent constructor-time Supabase recovery requests.
    monkeypatch.setattr(
        persistence_repo,
        "query_all_incidents_sync",
        lambda: [],
    )

    store = StateStore()

    # Prevent test writes to the local audit journal.
    monkeypatch.setattr(
        store._audit_durability,
        "append_audit",
        lambda audit: None,
    )

    return store


@pytest.fixture
def citizen_incident():
    return IncidentResponseContract(
        id="INC-TEST-CITIZEN-PERSIST",
        category=IncidentCategory.DRAIN_BLOCKAGE,
        description="Test citizen-reported drainage blockage.",
        latitude=15.495,
        longitude=73.825,
        severity=IncidentSeverity.MEDIUM,
        source=IncidentSource.CITIZEN,
        reporter_name="Test Citizen",
    )


def configure_repository(monkeypatch):
    monkeypatch.setattr(persistence_repo, "_is_configured", True)



def test_missing_rpc_aborts_without_non_atomic_fallback(
    monkeypatch,
    incident_store,
    citizen_incident,
):
    configure_repository(monkeypatch)

    monkeypatch.setattr(
        persistence_repo,
        "execute_citizen_incident_creation_sync",
        lambda **kwargs: None,
    )

    incident_writes = []
    audit_writes = []

    monkeypatch.setattr(
        persistence_repo,
        "persist_incident_sync",
        lambda payload: incident_writes.append(payload) or True,
    )
    monkeypatch.setattr(
        persistence_repo,
        "persist_incident_audit_sync",
        lambda payload: audit_writes.append(payload) or True,
    )

    with pytest.raises(RuntimeError, match="not confirmed"):
        incident_store.create_incident(citizen_incident)

    assert incident_writes == []
    assert audit_writes == []
    assert citizen_incident.id not in incident_store._incidents



def test_unexpected_rpc_error_aborts_creation(
    monkeypatch,
    incident_store,
    citizen_incident,
):
    configure_repository(monkeypatch)

    def fail_rpc(**kwargs):
        raise RuntimeError("Unexpected Supabase RPC failure")

    monkeypatch.setattr(
        persistence_repo,
        "execute_citizen_incident_creation_sync",
        fail_rpc,
    )

    with pytest.raises(RuntimeError, match="Unexpected Supabase RPC failure"):
        incident_store.create_incident(citizen_incident)

    assert citizen_incident.id not in incident_store._incidents



def test_cloud_incident_rpc_failure_aborts_creation(
    monkeypatch,
    incident_store,
    citizen_incident,
):
    configure_repository(monkeypatch)

    def fail_rpc(**kwargs):
        raise RuntimeError("Citizen incident RPC unavailable")

    monkeypatch.setattr(
        persistence_repo,
        "execute_citizen_incident_creation_sync",
        fail_rpc,
    )

    monkeypatch.setattr(
        persistence_repo,
        "persist_incident_sync",
        lambda payload: pytest.fail("Non-atomic incident fallback called"),
    )
    monkeypatch.setattr(
        persistence_repo,
        "persist_incident_audit_sync",
        lambda payload: pytest.fail("Non-atomic audit fallback called"),
    )

    with pytest.raises(RuntimeError, match="RPC unavailable"):
        incident_store.create_incident(citizen_incident)

    assert citizen_incident.id not in incident_store._incidents

from app.services import persistence_repository as persistence_repository_module
import httpx


def mock_rpc_http(monkeypatch, response=None, error=None):
    class FakeClient:
        def __init__(self, timeout=None):
            self.timeout = timeout

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return False

        def post(self, *args, **kwargs):
            if error is not None:
                raise error
            return response

    monkeypatch.setattr(
        persistence_repository_module.httpx,
        "Client",
        FakeClient,
    )
    monkeypatch.setattr(persistence_repo, "_is_configured", True)
    monkeypatch.setattr(persistence_repo, "_supabase_url", "https://test.supabase.co")
    monkeypatch.setattr(persistence_repo, "_timeout_sec", 5)
    monkeypatch.setattr(
        persistence_repo,
        "_get_headers",
        lambda: {"apikey": "test-key"},
    )


def citizen_rpc_arguments():
    return {
        "incident_id": "INC-HTTP-TEST",
        "category": "DRAIN_BLOCKAGE",
        "description": "HTTP-level RPC test",
        "latitude": 15.495,
        "longitude": 73.825,
        "severity": "MEDIUM",
        "source": "CITIZEN",
        "reporter_name": "Test Citizen",
        "photos": [],
        "audit_id": "AUDIT-HTTP-TEST",
    }



def test_citizen_rpc_http_200_returns_response(monkeypatch):
    class FakeResponse:
        status_code = 200
        text = '{"id": "INC-HTTP-TEST"}'

        def json(self):
            return {"id": "INC-HTTP-TEST"}

    mock_rpc_http(monkeypatch, response=FakeResponse())

    result = persistence_repo.execute_citizen_incident_creation_sync(
        **citizen_rpc_arguments()
    )

    assert result["id"] == "INC-HTTP-TEST"




def test_citizen_rpc_pgrst202_raises_runtime_error(monkeypatch):
    class FakeResponse:
        status_code = 404
        text = '{"code": "PGRST202"}'

        def json(self):
            return {"code": "PGRST202"}

    mock_rpc_http(monkeypatch, response=FakeResponse())

    with pytest.raises(RuntimeError, match="RPC is unavailable"):
        persistence_repo.execute_citizen_incident_creation_sync(
            **citizen_rpc_arguments()
        )



def test_citizen_rpc_other_404_raises_runtime_error(monkeypatch):
    class FakeResponse:
        status_code = 404
        text = '{"code": "PGRST205"}'

        def json(self):
            return {"code": "PGRST205"}

    mock_rpc_http(monkeypatch, response=FakeResponse())

    with pytest.raises(RuntimeError, match="HTTP 404"):
        persistence_repo.execute_citizen_incident_creation_sync(
            **citizen_rpc_arguments()
        )


def test_citizen_rpc_http_500_raises_runtime_error(monkeypatch):
    class FakeResponse:
        status_code = 500
        text = "Internal Server Error"

        def json(self):
            return {"message": "Database failure"}

    mock_rpc_http(monkeypatch, response=FakeResponse())

    with pytest.raises(RuntimeError, match="HTTP 500"):
        persistence_repo.execute_citizen_incident_creation_sync(
            **citizen_rpc_arguments()
        )


def test_citizen_rpc_network_error_raises_runtime_error(monkeypatch):
    request = httpx.Request(
        "POST",
        "https://test.supabase.co/rest/v1/rpc/citizen_incident_creation_rpc",
    )
    network_error = httpx.ConnectError("Connection failed", request=request)

    mock_rpc_http(monkeypatch, error=network_error)

    with pytest.raises(RuntimeError, match="could not be reached"):
        persistence_repo.execute_citizen_incident_creation_sync(
            **citizen_rpc_arguments()
        )
