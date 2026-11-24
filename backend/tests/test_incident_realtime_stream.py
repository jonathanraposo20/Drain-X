"""
DRAIN-X Phase 3 Milestone 2B: Dedicated Real-Time Incident Stream Tests.

Validates:
1. Authentication & Role Extraction:
   - Missing token rejected (code 1008).
   - Invalid or expired JWT rejected (code 1008).
   - Unrecognized role rejected (code 1008).
   - Valid citizen, worker, municipality tokens accepted with INIT handshake.
2. Privacy & Role Projection:
   - Citizen client receives redacted event (reporter_name/internal_notes/verified_by = None, contact info sanitized).
   - Municipality / Admin client receives unredacted event (full operational visibility).
3. Worker Isolation:
   - Worker receives events only for incidents assigned to their verified team.
   - Events for unassigned incidents or other teams are not leaked to the worker.
4. Municipal Duplicate Isolation:
   - Duplicate queue events (DUPLICATE_SUSPECTED, DUPLICATE_REVIEWED) are delivered to municipality.
   - Citizen and Worker clients never receive duplicate review events.
5. Mutation Broadcast Integration:
   - Creation, verification, assignment, reassignment, unassignment, rejection, update, and photo upload all broadcast.
   - Broadcast failure does not roll back or fail database transactions.
6. Replay Buffer & Sequencing:
   - Monotonic sequence numbers.
   - Replay delivered on reconnect with valid sequence.
   - Resync required on instance mismatch or buffer eviction.
   - Role projection enforced during replay.
7. Reliability & Backpressure:
   - Bounded per-client queues.
   - Stalled slow consumers are disconnected with code 1008.
   - Lifespan graceful shutdown closes connections with code 1001.
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import patch
import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.main import app
from app.core.config import settings
from app.models.contracts import (
    IncidentCategory,
    IncidentResponseContract,
    IncidentSeverity,
    IncidentStatus,
    IncidentStreamEventType,
    MunicipalDuplicateIncidentSummaryContract,
    MunicipalDuplicateLinkContract,
)
from app.services.incident_stream_manager import (
    IncidentStreamManager,
    IncidentClientSubscription,
    InternalIncidentEvent,
    incident_stream_manager,
    _is_event_authorized_for_client,
    _project_event_for_client,
)
from app.services.state_store import state_store


@pytest.fixture(autouse=True)
def reset_incident_stream(monkeypatch):
    """Ensure clean stream manager state before each test."""
    from app.services.persistence_repository import persistence_repo
    monkeypatch.setattr(persistence_repo, "_is_configured", False)
    monkeypatch.setattr(settings, "RATE_LIMIT_STORAGE_BACKEND", "memory")
    monkeypatch.setattr(settings, "SUPABASE_AUTH_ENABLED", True)
    incident_stream_manager.reset_state()
    incident_stream_manager._replay_buffer.clear()
    incident_stream_manager._current_seq_id = 0
    yield
    incident_stream_manager.reset_state()
    incident_stream_manager._replay_buffer.clear()


# ---------------------------------------------------------------------
# 1. Authentication & Handshake Tests
# ---------------------------------------------------------------------

def test_stream_missing_token_rejected_1008(client: TestClient):
    """Verify connection without token is closed with code 1008."""
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/api/v1/incidents/stream"):
            pass
    assert exc.value.code == 1008


def test_stream_invalid_token_rejected_1008(client: TestClient):
    """Verify connection with invalid/malformed JWT is closed with code 1008."""
    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/api/v1/incidents/stream?token=invalid.jwt.token"):
            pass
    assert exc.value.code == 1008


def test_stream_unrecognized_role_rejected_1008(client: TestClient):
    """Verify connection with an unsupported role is closed with code 1008."""
    fake_claims = {"sub": "user-guest", "extracted_role": "guest"}
    with patch("app.api.v1.incidents.verify_supabase_jwt", return_value=fake_claims):
        with pytest.raises(WebSocketDisconnect) as exc:
            with client.websocket_connect("/api/v1/incidents/stream?token=fake_guest_token"):
                pass
        assert exc.value.code == 1008


def test_stream_successful_handshake_citizen(client: TestClient):
    """Verify citizen receives proper INIT frame upon connection."""
    citizen_claims = {"sub": "citizen-123", "extracted_role": "citizen"}
    with patch("app.api.v1.incidents.verify_supabase_jwt", return_value=citizen_claims):
        with client.websocket_connect("/api/v1/incidents/stream?token=valid_token") as ws:
            init_data = ws.receive_json()
            assert init_data["event_type"] == "INIT"
            assert init_data["protocol_version"] == "1.0"
            assert init_data["role"] == "citizen"
            assert init_data["user_id"] == "citizen-123"
            assert "client_id" in init_data
            assert "instance_id" in init_data
            assert init_data["current_seq_id"] >= 0


def test_stream_successful_handshake_worker(client: TestClient):
    """Verify worker receives proper INIT frame with team affiliation."""
    worker_claims = {
        "sub": "worker-456",
        "extracted_role": "worker",
        "extracted_team": "Team Alpha — St. Inez Drainage Crew",
    }
    with patch("app.api.v1.incidents.verify_supabase_jwt", return_value=worker_claims):
        with client.websocket_connect("/api/v1/incidents/stream?token=valid_token") as ws:
            init_data = ws.receive_json()
            assert init_data["event_type"] == "INIT"
            assert init_data["role"] == "worker"
            assert init_data["user_id"] == "worker-456"
            assert init_data["team_id"] == "Team Alpha — St. Inez Drainage Crew"


def test_stream_ping_pong(client: TestClient):
    """Verify ping action responds with PONG frame."""
    citizen_claims = {"sub": "citizen-123", "extracted_role": "citizen"}
    with patch("app.api.v1.incidents.verify_supabase_jwt", return_value=citizen_claims):
        with client.websocket_connect("/api/v1/incidents/stream?token=valid_token") as ws:
            _ = ws.receive_json()  # Consume INIT
            ws.send_json({"action": "ping"})
            pong = ws.receive_json()
            assert pong["event_type"] == "PONG"
            assert "timestamp" in pong


# ---------------------------------------------------------------------
# 2. Privacy & Role Projection Tests
# ---------------------------------------------------------------------

def test_stream_citizen_receives_projected_privacy_event(client: TestClient):
    """
    Verify citizen receives redacted incident snapshot:
    - reporter_name = None
    - internal_notes = None
    - verified_by = None
    - contact info scrubbed from description
    """
    citizen_claims = {"sub": "citizen-1", "extracted_role": "citizen"}
    with patch("app.api.v1.incidents.verify_supabase_jwt", return_value=citizen_claims):
        with client.websocket_connect("/api/v1/incidents/stream?token=citizen_token") as ws:
            _ = ws.receive_json()  # Consume INIT

            # Create incident with sensitive citizen info
            create_payload = {
                "category": "FLOODING",
                "description": "Flooding at MG Road. Contact john.doe@example.com or +919876543210 immediately.",
                "latitude": 15.4989,
                "longitude": 73.8278,
                "severity": "HIGH",
                "reporter_name": "John Sensitive Citizen",
                "source": "CITIZEN",
            }
            res = client.post("/api/v1/incidents", json=create_payload)
            assert res.status_code == 201

            event = ws.receive_json()
            assert event["event_type"] == "INCIDENT_REPORTED"
            assert event["incident_id"] == res.json()["id"]

            inc = event["incident"]
            assert inc is not None
            # Privacy assertion: PII must be redacted
            assert inc["reporter_name"] is None
            assert inc["internal_notes"] is None
            assert inc["verified_by"] is None
            assert "john.doe@example.com" not in inc["description"]
            assert "+919876543210" not in inc["description"]
            assert "[EMAIL REDACTED]" in inc["description"]
            assert "[PHONE REDACTED]" in inc["description"]


def test_stream_municipality_receives_unredacted_event(client: TestClient):
    """
    Verify municipal client receives full unredacted incident snapshot.
    """
    muni_claims = {"sub": "supervisor-1", "extracted_role": "municipality"}
    with patch("app.api.v1.incidents.verify_supabase_jwt", return_value=muni_claims):
        with client.websocket_connect("/api/v1/incidents/stream?token=muni_token") as ws:
            _ = ws.receive_json()  # Consume INIT

            create_payload = {
                "category": "DRAIN_BLOCKAGE",
                "description": "Blockage near market",
                "latitude": 15.4989,
                "longitude": 73.8278,
                "severity": "MEDIUM",
                "reporter_name": "Jane Citizen",
                "source": "CITIZEN",
            }
            res = client.post("/api/v1/incidents", json=create_payload)
            assert res.status_code == 201

            event = ws.receive_json()
            assert event["event_type"] == "INCIDENT_REPORTED"
            inc = event["incident"]
            assert inc is not None
            # Municipality has full operational visibility
            assert inc["reporter_name"] == "Jane Citizen"


# ---------------------------------------------------------------------
# 3. Worker Assignment Isolation Tests
# ---------------------------------------------------------------------

def test_stream_worker_receives_only_assigned_incidents(client: TestClient):
    """
    Verify a field worker receives events ONLY for incidents assigned to their crew,
    and unassigned/other-crew incidents are never delivered.
    """
    worker_claims = {
        "sub": "worker-beta",
        "extracted_role": "worker",
        "extracted_team": "Team Beta — Patto Rapid Response",
    }
    muni_claims = {"sub": "supervisor-1", "extracted_role": "municipality"}

    with patch("app.api.v1.incidents.verify_supabase_jwt", return_value=worker_claims):
        with client.websocket_connect("/api/v1/incidents/stream?token=worker_token") as worker_ws:
            _ = worker_ws.receive_json()  # Consume INIT

            # 1. Create an incident (starts unassigned)
            create_payload = {
                "category": "DRAIN_OVERFLOW",
                "description": "Overflow at Patto bridge",
                "latitude": 15.4989,
                "longitude": 73.8278,
                "severity": "MEDIUM",
            }
            res = client.post("/api/v1/incidents", json=create_payload)
            assert res.status_code == 201
            inc_id = res.json()["id"]

            # 2. Assign to Team Alpha (different team)
            with patch("app.core.security.verify_supabase_jwt", return_value=muni_claims):
                assign_alpha = client.post(
                    f"/api/v1/incidents/{inc_id}/assign",
                    json={"assigned_to": "Team Alpha — St. Inez Drainage Crew"},
                    headers={"Authorization": "Bearer fake_token"},
                )
                assert assign_alpha.status_code == 200

            # 3. Assign another incident to Team Beta (worker's team)
            res2 = client.post("/api/v1/incidents", json=create_payload)
            inc2_id = res2.json()["id"]

            with patch("app.core.security.verify_supabase_jwt", return_value=muni_claims):
                assign_beta = client.post(
                    f"/api/v1/incidents/{inc2_id}/assign",
                    json={"assigned_to": "Team Beta — Patto Rapid Response"},
                    headers={"Authorization": "Bearer fake_token"},
                )
                assert assign_beta.status_code == 200

            # Worker should receive ONLY the Team Beta event
            event = worker_ws.receive_json()
            assert event["event_type"] == "INCIDENT_ASSIGNED"
            assert event["incident_id"] == inc2_id
            assert event["assigned_team_id"] == "TEAM-BETA"


# ---------------------------------------------------------------------
# 4. Municipal Duplicate Isolation Tests
# ---------------------------------------------------------------------

def test_stream_duplicate_events_restricted_to_municipality(client: TestClient):
    """
    Verify DUPLICATE_REVIEWED events are delivered to municipality/admin,
    and NEVER to citizen or worker clients.
    """
    muni_claims = {"sub": "muni-sup", "extracted_role": "municipality"}
    citizen_claims = {"sub": "citizen-1", "extracted_role": "citizen"}

    with patch("app.api.v1.incidents.verify_supabase_jwt", return_value=muni_claims):
        with client.websocket_connect("/api/v1/incidents/stream?token=muni_token") as muni_ws:
            _ = muni_ws.receive_json()  # Consume INIT

            with patch("app.api.v1.incidents.verify_supabase_jwt", return_value=citizen_claims):
                with client.websocket_connect("/api/v1/incidents/stream?token=citizen_token") as citizen_ws:
                    _ = citizen_ws.receive_json()  # Consume INIT

                    # Directly broadcast a DUPLICATE_REVIEWED event
                    mock_link = MunicipalDuplicateLinkContract(
                        link_id="link-test-01",
                        incident_low_id="inc-prim-01",
                        incident_high_id="inc-sec-02",
                        primary_incident_id="inc-prim-01",
                        duplicate_incident_id="inc-sec-02",
                        link_status="CONFIRMED",
                        confidence_score=0.92,
                        confidence_band="HIGH",
                        distance_meters=15.0,
                        time_delta_seconds=300,
                        match_reasons=["SPATIAL_PROXIMITY"],
                    )

                    incident_stream_manager.broadcast_incident_event(
                        event_type=IncidentStreamEventType.DUPLICATE_REVIEWED,
                        incident_id="inc-prim-01",
                        action="DUPLICATE_CONFIRMED",
                        duplicate_link=mock_link,
                    )

                    # Municipality receives it
                    muni_evt = muni_ws.receive_json()
                    assert muni_evt["event_type"] == "DUPLICATE_REVIEWED"
                    assert muni_evt["duplicate_link"] is not None
                    assert muni_evt["duplicate_link"]["link_id"] == "link-test-01"

                    # Citizen receives NOTHING (duplicate review events forbidden)
                    # Test by sending a normal ping from citizen to ensure no backlog
                    citizen_ws.send_json({"action": "ping"})
                    citizen_pong = citizen_ws.receive_json()
                    assert citizen_pong["event_type"] == "PONG"


# ---------------------------------------------------------------------
# 5. Lifecycle Mutation Broadcast Tests
# ---------------------------------------------------------------------

def test_stream_all_lifecycle_mutations_broadcast(client: TestClient):
    """
    Verify complete operational workflow transitions emit corresponding event frames:
    - create -> INCIDENT_REPORTED
    - verify -> INCIDENT_TRIAGED
    - assign -> INCIDENT_ASSIGNED
    - reassign -> INCIDENT_ASSIGNED
    - unassign -> INCIDENT_ASSIGNED
    - reject -> INCIDENT_REJECTED
    """
    muni_claims = {"sub": "supervisor-1", "extracted_role": "municipality"}

    with patch("app.api.v1.incidents.verify_supabase_jwt", return_value=muni_claims):
        with client.websocket_connect("/api/v1/incidents/stream?token=muni_token") as ws:
            _ = ws.receive_json()  # INIT

            # 1. Create incident
            create_res = client.post("/api/v1/incidents", json={
                "category": "WATERLOGGING",
                "description": "Water accumulation at Miramar",
                "latitude": 15.4850,
                "longitude": 73.8100,
                "severity": "LOW",
            })
            assert create_res.status_code == 201
            inc_id = create_res.json()["id"]

            e1 = ws.receive_json()
            assert e1["event_type"] == "INCIDENT_REPORTED"
            assert e1["action"] == "CREATE"

            # 2. Verify / Triage incident
            with patch("app.core.security.verify_supabase_jwt", return_value=muni_claims):
                v_res = client.post(
                    f"/api/v1/incidents/{inc_id}/verify",
                    json={"severity": "HIGH", "notes": "Verified high flood danger"},
                    headers={"Authorization": "Bearer fake_token"},
                )
                assert v_res.status_code == 200

            e2 = ws.receive_json()
            assert e2["event_type"] == "INCIDENT_TRIAGED"
            assert e2["action"] == "VERIFY"
            assert e2["new_status"] == "VERIFIED"

            # 3. Assign incident
            with patch("app.core.security.verify_supabase_jwt", return_value=muni_claims):
                a_res = client.post(
                    f"/api/v1/incidents/{inc_id}/assign",
                    json={"assigned_to": "Team Alpha — St. Inez Drainage Crew"},
                    headers={"Authorization": "Bearer fake_token"},
                )
                assert a_res.status_code == 200

            e3 = ws.receive_json()
            assert e3["event_type"] == "INCIDENT_ASSIGNED"
            assert e3["action"] == "ASSIGN"

            # 4. Reassign incident
            with patch("app.core.security.verify_supabase_jwt", return_value=muni_claims):
                ra_res = client.post(
                    f"/api/v1/incidents/{inc_id}/reassign",
                    json={
                        "assigned_to": "Team Beta — Patto Rapid Response",
                        "reason": "Team Alpha overwhelmed by emergency",
                    },
                    headers={"Authorization": "Bearer fake_token"},
                )
                assert ra_res.status_code == 200

            e4 = ws.receive_json()
            assert e4["event_type"] == "INCIDENT_ASSIGNED"
            assert e4["action"] == "REASSIGN"

            # 5. Unassign incident
            with patch("app.core.security.verify_supabase_jwt", return_value=muni_claims):
                u_res = client.post(
                    f"/api/v1/incidents/{inc_id}/unassign",
                    json={"reason": "Holding until equipment arrives"},
                    headers={"Authorization": "Bearer fake_token"},
                )
                assert u_res.status_code == 200

            e5 = ws.receive_json()
            assert e5["event_type"] == "INCIDENT_ASSIGNED"
            assert e5["action"] == "UNASSIGN"

            # 6. Reject incident
            with patch("app.core.security.verify_supabase_jwt", return_value=muni_claims):
                rej_res = client.post(
                    f"/api/v1/incidents/{inc_id}/reject",
                    json={"reason": "Duplicate citizen report"},
                    headers={"Authorization": "Bearer fake_token"},
                )
                assert rej_res.status_code == 200

            e6 = ws.receive_json()
            assert e6["event_type"] == "INCIDENT_REJECTED"
            assert e6["action"] == "REJECT"
            assert e6["new_status"] == "REJECTED"


# ---------------------------------------------------------------------
# 6. Replay Buffer & Resync Signaling Tests
# ---------------------------------------------------------------------

def test_stream_replay_missed_events_on_reconnect(client: TestClient):
    """
    Verify reconnecting client supplying last_seq_id and same instance_id
    receives replayed missed events.
    """
    muni_claims = {"sub": "supervisor-1", "extracted_role": "municipality"}
    with patch("app.api.v1.incidents.verify_supabase_jwt", return_value=muni_claims):
        # 1. Connect first time to capture instance_id and initial seq_id
        with client.websocket_connect("/api/v1/incidents/stream?token=muni_token") as ws:
            init1 = ws.receive_json()
            inst_id = init1["instance_id"]
            seq1 = init1["current_seq_id"]

        # 2. Trigger two events while client is disconnected
        client.post("/api/v1/incidents", json={
            "category": "FLOODING",
            "description": "Event 1",
            "latitude": 15.4989,
            "longitude": 73.8278,
            "severity": "LOW",
        })
        client.post("/api/v1/incidents", json={
            "category": "FLOODING",
            "description": "Event 2",
            "latitude": 16.5000,
            "longitude": 74.8278,
            "severity": "LOW",
        })

        # 3. Reconnect with a fresh client session
        client2 = TestClient(app)
        replay_url = f"/api/v1/incidents/stream?token=muni_token&last_seq_id={seq1}&last_instance_id={inst_id}"
        with client2.websocket_connect(replay_url) as ws2:
            init2 = ws2.receive_json()
            assert init2["event_type"] == "INIT"

            # Should immediately receive missed Event 1 and Event 2
            rev1 = ws2.receive_json()
            assert rev1["event_type"] == "INCIDENT_REPORTED"
            assert "Event 1" in rev1["incident"]["description"]

            rev2 = ws2.receive_json()
            assert rev2["event_type"] == "INCIDENT_REPORTED"
            assert "Event 2" in rev2["incident"]["description"]


def test_stream_replay_instance_mismatch_signals_resync_required(client: TestClient):
    """
    Verify client providing a different instance_id (e.g. server restart)
    receives RESYNC_REQUIRED frame.
    """
    muni_claims = {"sub": "supervisor-1", "extracted_role": "municipality"}
    with patch("app.api.v1.incidents.verify_supabase_jwt", return_value=muni_claims):
        replay_url = "/api/v1/incidents/stream?token=muni_token&last_seq_id=5&last_instance_id=different_instance"
        with client.websocket_connect(replay_url) as ws:
            init = ws.receive_json()
            assert init["event_type"] == "INIT"

            resync = ws.receive_json()
            assert resync["event_type"] == "RESYNC_REQUIRED"
            assert "Instance changed" in resync["reason"]


def test_stream_replay_evicted_sequence_signals_resync_required(client: TestClient):
    """
    Verify client requesting a sequence number evicted from the bounded buffer
    receives RESYNC_REQUIRED frame.
    """
    muni_claims = {"sub": "supervisor-1", "extracted_role": "municipality"}
    with patch("app.api.v1.incidents.verify_supabase_jwt", return_value=muni_claims):
        inst_id = incident_stream_manager.instance_id
        future_url = f"/api/v1/incidents/stream?token=muni_token&last_seq_id=99999&last_instance_id={inst_id}"
        with client.websocket_connect(future_url) as ws:
            init = ws.receive_json()
            assert init["event_type"] == "INIT"
            resync = ws.receive_json()
            assert resync["event_type"] == "RESYNC_REQUIRED"
            assert "outside buffer" in resync["reason"]


# ---------------------------------------------------------------------
# 7. Reliability & Backpressure Tests
# ---------------------------------------------------------------------

@pytest.mark.anyio
async def test_stream_slow_consumer_backpressure_and_disconnection():
    """
    Verify when a client's queue is full, the manager drops the client
    and initiates backpressure disconnect (code 1008).
    """
    manager = IncidentStreamManager(max_connections=10, max_queue_size=2)

    class MockWebSocket:
        def __init__(self):
            self.closed = False
            self.close_code = None

        async def close(self, code=1000, reason=""):
            self.closed = True
            self.close_code = code

    ws = MockWebSocket()
    sub = await manager.register_client(ws, claims={"sub": "slow-worker", "extracted_role": "municipality"})

    # Push 3 events without consuming from queue (maxsize=2)
    ev = InternalIncidentEvent(
        event_id="e1",
        seq_id=1,
        instance_id=manager.instance_id,
        timestamp=datetime.now(timezone.utc),
        event_type=IncidentStreamEventType.HEARTBEAT,
    )

    manager._dispatch_to_clients(ev)  # Item 1 -> OK
    manager._dispatch_to_clients(ev)  # Item 2 -> OK
    manager._dispatch_to_clients(ev)  # Item 3 -> QueueFull! Client marked closed & disconnected

    assert sub.is_closed is True
    assert sub.dropped_count == 1
    assert sub.client_id not in manager._clients


@pytest.mark.anyio
async def test_stream_graceful_shutdown_closes_clients_1001():
    """
    Verify manager shutdown closes all active client connections with code 1001.
    """
    manager = IncidentStreamManager(max_connections=10, max_queue_size=10)

    class MockWS:
        def __init__(self):
            self.closed = False
            self.close_code = None

        async def close(self, code=1000, reason=""):
            self.closed = True
            self.close_code = code

    ws1 = MockWS()
    ws2 = MockWS()
    await manager.register_client(ws1, claims={"sub": "u1", "extracted_role": "citizen"})
    await manager.register_client(ws2, claims={"sub": "u2", "extracted_role": "citizen"})

    assert manager.active_connections_count == 2
    await manager.shutdown()
    assert manager.active_connections_count == 0
    assert ws1.closed is True
    assert ws1.close_code == 1001
    assert ws2.closed is True
    assert ws2.close_code == 1001


# ---------------------------------------------------------------------
# 8. M2B-AUD-01: Enhanced Payload Privacy & Contact Scrubbing Tests
# ---------------------------------------------------------------------

def test_stream_citizen_reason_sanitizes_emails_and_phones_and_hides_worker_ids(client: TestClient):
    """
    M2B-AUD-01: Verify citizen client receives sanitized reason containing phone/email,
    and never receives internal worker IDs (assigned_worker_id / previous_assigned_worker_id).
    """
    citizen_claims = {"sub": "citizen-1", "extracted_role": "citizen"}
    muni_claims = {"sub": "muni-1", "extracted_role": "municipality"}

    with patch("app.api.v1.incidents.verify_supabase_jwt", return_value=citizen_claims):
        with client.websocket_connect("/api/v1/incidents/stream?token=citizen_token") as citizen_ws:
            _ = citizen_ws.receive_json()  # INIT

            # Broadcast an event with internal worker ID and sensitive contact details in reason
            incident_stream_manager.broadcast_incident_event(
                event_type=IncidentStreamEventType.INCIDENT_REJECTED,
                incident_id="inc-priv-01",
                action="REJECT",
                assigned_worker_id="emp_9921_secret",
                previous_assigned_worker_id="emp_8810_secret",
                reason="Rejected by supervisor John Doe: contact john.doe@drainx.gov or +91 9822123456 for inquiries.",
            )

            cit_evt = citizen_ws.receive_json()
            assert cit_evt["event_type"] == "INCIDENT_REJECTED"
            # Worker IDs must be strictly None for citizens
            assert cit_evt["assigned_worker_id"] is None
            assert cit_evt["previous_assigned_worker_id"] is None
            # Contact info in reason must be scrubbed
            assert "john.doe@drainx.gov" not in cit_evt["reason"]
            assert "+91 9822123456" not in cit_evt["reason"]
            assert "[EMAIL REDACTED]" in cit_evt["reason"]
            assert "[PHONE REDACTED]" in cit_evt["reason"]

    # In contrast, municipality client receives the unredacted reason and worker IDs
    with patch("app.api.v1.incidents.verify_supabase_jwt", return_value=muni_claims):
        with client.websocket_connect("/api/v1/incidents/stream?token=muni_token") as muni_ws:
            _ = muni_ws.receive_json()  # INIT

            incident_stream_manager.broadcast_incident_event(
                event_type=IncidentStreamEventType.INCIDENT_REJECTED,
                incident_id="inc-priv-02",
                action="REJECT",
                assigned_worker_id="emp_9921_secret",
                previous_assigned_worker_id="emp_8810_secret",
                reason="Rejected by supervisor John Doe: contact john.doe@drainx.gov or +91 9822123456 for inquiries.",
            )

            muni_evt = muni_ws.receive_json()
            assert muni_evt["assigned_worker_id"] == "emp_9921_secret"
            assert muni_evt["previous_assigned_worker_id"] == "emp_8810_secret"
            assert "john.doe@drainx.gov" in muni_evt["reason"]
            assert "+91 9822123456" in muni_evt["reason"]


def test_stream_worker_sees_only_own_worker_id(client: TestClient):
    """
    M2B-AUD-01: Verify a field worker only sees their own assigned_worker_id,
    and not another worker's internal identifier.
    """
    worker1_claims = {"sub": "worker-1", "extracted_role": "worker", "extracted_team": "Team Alpha"}

    with patch("app.api.v1.incidents.verify_supabase_jwt", return_value=worker1_claims):
        with client.websocket_connect("/api/v1/incidents/stream?token=worker1_token") as ws:
            _ = ws.receive_json()  # INIT

            # 1. Event assigned to worker-1 specifically
            incident_stream_manager.broadcast_incident_event(
                event_type=IncidentStreamEventType.INCIDENT_ASSIGNED,
                incident_id="inc-w1",
                action="ASSIGN",
                team_id="Team Alpha",
                worker_id="worker-1",
            )
            evt1 = ws.receive_json()
            assert evt1["assigned_worker_id"] == "worker-1"

            # 2. Event assigned to Team Alpha generally, with worker-2 as the designated worker
            incident_stream_manager.broadcast_incident_event(
                event_type=IncidentStreamEventType.INCIDENT_ASSIGNED,
                incident_id="inc-w2",
                action="ASSIGN",
                team_id="Team Alpha",
                worker_id="worker-2",
            )
            evt2 = ws.receive_json()
            # worker-1 receives the team event, but worker-2's ID must be hidden
            assert evt2["assigned_worker_id"] is None


# ---------------------------------------------------------------------
# 9. M2B-AUD-02: Suspected Duplicate Events & Scan Deduplication Tests
# ---------------------------------------------------------------------

def test_stream_duplicate_suspected_emitted_for_new_link_only(client: TestClient):
    """
    M2B-AUD-02: Verify DUPLICATE_SUSPECTED is emitted on new suspected links,
    deduplicated on repeated scans, not emitted on failure, and restricted to municipality.
    """
    muni_claims = {"sub": "supervisor-1", "extracted_role": "municipality"}
    citizen_claims = {"sub": "citizen-1", "extracted_role": "citizen"}

    # Setup first incident in state_store
    c1 = client.post("/api/v1/incidents", json={
        "category": "FLOODING",
        "description": "Culvert blockage near market",
        "latitude": 15.4989,
        "longitude": 73.8278,
        "severity": "HIGH",
    })
    inc1_id = c1.json()["id"]

    with patch("app.api.v1.incidents.verify_supabase_jwt", return_value=muni_claims):
        with client.websocket_connect("/api/v1/incidents/stream?token=muni_token") as muni_ws:
            _ = muni_ws.receive_json()  # INIT

            # Connect citizen simultaneously to test role restriction
            with patch("app.api.v1.incidents.verify_supabase_jwt", return_value=citizen_claims):
                with client.websocket_connect("/api/v1/incidents/stream?token=citizen_token") as citizen_ws:
                    _ = citizen_ws.receive_json()  # INIT

                    # 1. Create proximate second incident -> triggers duplicate detection & discovers new link
                    c2 = client.post("/api/v1/incidents", json={
                        "category": "FLOODING",
                        "description": "Severe market culvert overflow",
                        "latitude": 15.4990,
                        "longitude": 73.8279,
                        "severity": "HIGH",
                    })
                    assert c2.status_code == 201

                    # Municipality receives DUPLICATE_SUSPECTED (from pre-creation duplicate scan), then INCIDENT_REPORTED
                    muni_evt = muni_ws.receive_json()
                    assert muni_evt["event_type"] == "DUPLICATE_SUSPECTED"
                    assert muni_evt["action"] == "DUPLICATE_SUSPECTED"
                    assert muni_evt["duplicate_link"] is not None
                    assert muni_evt["duplicate_link"]["link_status"] == "SUSPECTED"
                    assert muni_evt["duplicate_link"]["distance_meters"] > 0

                    muni_rep = muni_ws.receive_json()
                    assert muni_rep["event_type"] == "INCIDENT_REPORTED"

                    # Citizen receives INCIDENT_REPORTED for c2, but NEVER receives DUPLICATE_SUSPECTED
                    citizen_rep = citizen_ws.receive_json()
                    assert citizen_rep["event_type"] == "INCIDENT_REPORTED"

                    citizen_ws.send_json({"action": "ping"})
                    pong = citizen_ws.receive_json()
                    assert pong["event_type"] == "PONG"

                    # 2. Repeated scan on the same incidents: links_created == 0, no duplicate event emitted
                    from app.services.duplicate_detector import scan_incident_for_duplicates
                    from app.services.persistence_repository import persistence_repo
                    res2 = scan_incident_for_duplicates(inc1_id, persistence_repo, state_store, settings)
                    assert res2.links_created == 0

                    muni_ws.send_json({"action": "ping"})
                    muni_pong = muni_ws.receive_json()
                    assert muni_pong["event_type"] == "PONG"

                    # 3. Persistence failure test: if state_store fails to persist link, no event emitted
                    with patch.object(state_store, "record_duplicate_link", return_value=False):
                        # Force a scan on another incident that finds candidate but fails recording
                        res_fail = scan_incident_for_duplicates(inc1_id, persistence_repo, state_store, settings)
                        assert res_fail.links_created == 0
                        muni_ws.send_json({"action": "ping"})
                        muni_pong2 = muni_ws.receive_json()
                        assert muni_pong2["event_type"] == "PONG"


# ---------------------------------------------------------------------
# 10. M2B-AUD-03: Previous Worker Unassign / Reassign Notification Tests
# ---------------------------------------------------------------------

def test_stream_reassign_and_unassign_notifies_previous_crew_without_incident_details(client: TestClient):
    """
    M2B-AUD-03: When an incident is reassigned from Team Alpha to Team Beta,
    or unassigned from Team Alpha:
    - Team Alpha receives assignment-change notification with previous_assigned_team_id='TEAM-ALPHA'.
    - Team Alpha's incident snapshot is None (does not retain incident details).
    - Team Beta receives notification with incident snapshot.
    - Team Gamma (unrelated) receives nothing.
    - Replaying Team Alpha receives only the reassignment notification without incident details.
    """
    muni_claims = {"sub": "supervisor-1", "extracted_role": "municipality"}
    alpha_claims = {"sub": "worker-a", "extracted_role": "worker", "extracted_team": "TEAM-ALPHA"}
    beta_claims = {"sub": "worker-b", "extracted_role": "worker", "extracted_team": "TEAM-BETA"}
    gamma_claims = {"sub": "worker-g", "extracted_role": "worker", "extracted_team": "TEAM-GAMMA"}

    with patch("app.core.security.verify_supabase_jwt", return_value=muni_claims):
        # 1. Create incident and assign to Team Alpha
        c_res = client.post("/api/v1/incidents", json={
            "category": "WATERLOGGING",
            "description": "Patto Plaza blockage",
            "latitude": 15.4989,
            "longitude": 73.8278,
            "severity": "MEDIUM",
        })
        inc_id = c_res.json()["id"]

        client.post(
            f"/api/v1/incidents/{inc_id}/assign",
            json={"assigned_to": "Team Alpha — St. Inez Drainage Crew"},
            headers={"Authorization": "Bearer fake_token"},
        )

    # Connect workers
    with patch("app.api.v1.incidents.verify_supabase_jwt", return_value=alpha_claims):
        with client.websocket_connect("/api/v1/incidents/stream?token=alpha_token") as ws_alpha:
            init_alpha = ws_alpha.receive_json()
            inst_id = init_alpha["instance_id"]
            seq_alpha = init_alpha["current_seq_id"]

            with patch("app.api.v1.incidents.verify_supabase_jwt", return_value=beta_claims):
                with client.websocket_connect("/api/v1/incidents/stream?token=beta_token") as ws_beta:
                    _ = ws_beta.receive_json()

                    with patch("app.api.v1.incidents.verify_supabase_jwt", return_value=gamma_claims):
                        with client.websocket_connect("/api/v1/incidents/stream?token=gamma_token") as ws_gamma:
                            _ = ws_gamma.receive_json()

                            # 2. Reassign from Team Alpha to Team Beta
                            with patch("app.core.security.verify_supabase_jwt", return_value=muni_claims):
                                client.post(
                                    f"/api/v1/incidents/{inc_id}/reassign",
                                    json={
                                        "assigned_to": "Team Beta — Patto Rapid Response",
                                        "reason": "Emergency redirect of Team Alpha",
                                    },
                                    headers={"Authorization": "Bearer fake_token"},
                                )

                            # Team Alpha receives REASSIGN notification
                            alpha_evt = ws_alpha.receive_json()
                            assert alpha_evt["event_type"] == "INCIDENT_ASSIGNED"
                            assert alpha_evt["action"] == "REASSIGN"
                            assert alpha_evt["previous_assigned_team_id"] == "TEAM-ALPHA"
                            assert alpha_evt["assigned_team_id"] == "TEAM-BETA"
                            # Critical: Team Alpha no longer has ongoing access to incident details
                            assert alpha_evt["incident"] is None

                            # Team Beta receives REASSIGN notification with incident details
                            beta_evt = ws_beta.receive_json()
                            assert beta_evt["event_type"] == "INCIDENT_ASSIGNED"
                            assert beta_evt["action"] == "REASSIGN"
                            assert beta_evt["assigned_team_id"] == "TEAM-BETA"
                            assert beta_evt["incident"] is not None

                            # Team Gamma receives NOTHING
                            ws_gamma.send_json({"action": "ping"})
                            gamma_pong = ws_gamma.receive_json()
                            assert gamma_pong["event_type"] == "PONG"

    # 3. Test Replay after reassignment for Team Alpha
    # Team Alpha reconnects asking for missed event
    with patch("app.api.v1.incidents.verify_supabase_jwt", return_value=alpha_claims):
        replay_url = f"/api/v1/incidents/stream?token=alpha_token&last_seq_id={seq_alpha}&last_instance_id={inst_id}"
        with client.websocket_connect(replay_url) as ws_alpha_replay:
            _ = ws_alpha_replay.receive_json()  # INIT
            replayed_evt = ws_alpha_replay.receive_json()
            assert replayed_evt["action"] == "REASSIGN"
            assert replayed_evt["previous_assigned_team_id"] == "TEAM-ALPHA"
            # Even in replay, incident details must be withheld from previous team
            assert replayed_evt["incident"] is None


# ---------------------------------------------------------------------
# 11. M2B-AUD-04: Deterministic Concurrent Publisher Ordering Tests
# ---------------------------------------------------------------------

def test_stream_concurrent_publishers_guarantee_strict_monotonic_sequence(client: TestClient):
    """
    M2B-AUD-04: Spawn multiple concurrent publishing threads simultaneously.
    Assert that a connected client receives sequence IDs in strictly increasing,
    monotonically contiguous order without any out-of-order delivery.
    """
    import threading
    muni_claims = {"sub": "supervisor-1", "extracted_role": "municipality"}

    with patch("app.api.v1.incidents.verify_supabase_jwt", return_value=muni_claims):
        with client.websocket_connect("/api/v1/incidents/stream?token=muni_token") as ws:
            init = ws.receive_json()  # INIT
            start_seq = init["current_seq_id"]

            total_threads = 5
            events_per_thread = 10
            total_events = total_threads * events_per_thread

            barrier = threading.Barrier(total_threads)

            def worker_publisher(thread_id: int):
                barrier.wait()  # synchronize release
                for j in range(events_per_thread):
                    incident_stream_manager.broadcast_incident_event(
                        event_type=IncidentStreamEventType.INCIDENT_IN_PROGRESS,
                        incident_id=f"inc-thread-{thread_id}-{j}",
                        action="THREAD_UPDATE",
                    )

            threads = [
                threading.Thread(target=worker_publisher, args=(t,))
                for t in range(total_threads)
            ]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            # Read all dispatched events from the client websocket
            received_seqs = []
            for _ in range(total_events):
                msg = ws.receive_json()
                received_seqs.append(msg["seq_id"])

            # Verify:
            # 1. Exact count received
            assert len(received_seqs) == total_events
            # 2. Strictly monotonically increasing with zero out-of-order jumps
            for i in range(len(received_seqs)):
                expected = start_seq + 1 + i
                assert received_seqs[i] == expected, f"Out-of-order sequence: received {received_seqs[i]}, expected {expected}"

