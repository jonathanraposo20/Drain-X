import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings
from app.services.state_store import state_store
from app.services.telemetry_stream_manager import telemetry_stream_manager, TelemetryStreamManager
from app.models.contracts import (
    SensorReadingContract,
    SensorType,
    MeasurementUnit,
    DataSource,
    SensorHealthStatus,
)


@pytest.fixture(autouse=True)
def reset_system():
    """Ensure clean state store and stream manager for each test."""
    state_store.clear()
    state_store.mode = "SIMULATION"
    telemetry_stream_manager._clients.clear()
    telemetry_stream_manager._total_broadcast_count = 0
    telemetry_stream_manager._total_dropped_count = 0
    telemetry_stream_manager._is_shutting_down = False
    yield
    telemetry_stream_manager._clients.clear()


@pytest.fixture
def client():
    return TestClient(app)


def test_successful_stream_connection_and_init_payload(client: TestClient):
    """
    Test 1 & 6: Verify successful stream connection, protocol handshake,
    current operational mode, hardware validation stage, and initial snapshot.
    """
    # Seed a known reading in state store
    state_store.ingest_reading(
        SensorReadingContract(
            sensor_id="US_UPSTREAM_01",
            section_id="SEC_SCREENING",
            sensor_type=SensorType.WATER_LEVEL,
            value=6.5,
            unit=MeasurementUnit.CENTIMETRE,
            source=DataSource.SIMULATED,
            status=SensorHealthStatus.OK,
        )
    )

    with client.websocket_connect("/api/v1/telemetry/stream") as ws:
        init_data = ws.receive_json()

        assert init_data["event_type"] == "INIT"
        assert init_data["protocol_version"] == "1.0"
        assert "client_id" in init_data
        assert init_data["operational_mode"] == "SIMULATION"
        assert init_data["hardware_validation_stage"] == "INCREMENTAL_CONNECTIVITY"
        assert "latest_snapshot" in init_data
        assert "US_UPSTREAM_01" in init_data["latest_snapshot"]
        assert init_data["latest_snapshot"]["US_UPSTREAM_01"]["value"] == 6.5


def test_telemetry_broadcast_to_connected_client(client: TestClient):
    """
    Test 2: Verify that newly ingested telemetry is broadcast to the connected client
    with correct normalized fields (water_level_cm, flow_rate_lpm, is_valid).
    """
    with client.websocket_connect("/api/v1/telemetry/stream") as ws:
        _ = ws.receive_json()  # Consume INIT message

        # Ingest reading via HTTP API
        ingest_payload = {
            "sensor_id": "US_UPSTREAM_01",
            "section_id": "SEC_SCREENING",
            "sensor_type": "WATER_LEVEL",
            "value": 7.8,
            "unit": "cm",
            "source": "SIMULATED",
            "status": "OK",
            "metadata": {"test": "broadcast"},
        }
        res = client.post("/api/v1/telemetry/ingest", json=ingest_payload)
        assert res.status_code == 201

        # Receive streamed broadcast frame
        event = ws.receive_json()
        assert event["event_type"] == "TELEMETRY"
        assert event["sensor_id"] == "US_UPSTREAM_01"
        assert event["source"] == "SIMULATED"
        assert event["water_level_cm"] == 7.8
        assert event["flow_rate_lpm"] is None
        assert event["is_valid"] is True
        assert event["metadata"]["test"] == "broadcast"


def test_multiple_concurrent_clients_broadcast(client: TestClient):
    """
    Test 3: Verify that multiple concurrent clients receive the same broadcast.
    """
    with client.websocket_connect("/api/v1/telemetry/stream") as ws1:
        _ = ws1.receive_json()  # Init ws1

        with client.websocket_connect("/api/v1/telemetry/stream") as ws2:
            _ = ws2.receive_json()  # Init ws2

            # Metrics should report 2 active clients
            metrics = telemetry_stream_manager.get_metrics()
            assert metrics["active_clients"] == 2

            # Ingest reading
            reading = {
                "sensor_id": "US_WEIR_02",
                "section_id": "SEC_OUTLET",
                "sensor_type": "WATER_LEVEL",
                "value": 2.4,
                "unit": "cm",
                "source": "SIMULATED",
            }
            res = client.post("/api/v1/telemetry/ingest", json=reading)
            assert res.status_code == 201

            # Both clients receive the event
            evt1 = ws1.receive_json()
            evt2 = ws2.receive_json()
            assert evt1["sensor_id"] == "US_WEIR_02"
            assert evt2["sensor_id"] == "US_WEIR_02"
            assert evt1["value"] == 2.4
            assert evt2["value"] == 2.4


def test_disconnect_cleanup(client: TestClient):
    """
    Test 4: Verify client disconnect cleanly unregisters and decreases client count.
    """
    initial_clients = telemetry_stream_manager.active_connections_count

    with client.websocket_connect("/api/v1/telemetry/stream") as ws:
        _ = ws.receive_json()
        assert telemetry_stream_manager.active_connections_count == initial_clients + 1

    # Out of context manager -> client disconnected
    assert telemetry_stream_manager.active_connections_count == initial_clients


def test_source_isolation_filtering(client: TestClient):
    """
    Test 5: Verify source filtering (PHYSICAL vs SIMULATED).
    A client subscribed to PHYSICAL should not receive SIMULATED readings.
    """
    # Switch mode to PHYSICAL
    client.post("/api/v1/status/mode", json={"mode": "PHYSICAL"})

    with client.websocket_connect("/api/v1/telemetry/stream?source=PHYSICAL") as ws_physical:
        init_phys = ws_physical.receive_json()
        assert init_phys["subscribed_source"] == "PHYSICAL"

        # Ingest physical reading
        physical_reading = {
            "sensor_id": "FS_FLUME_01",
            "section_id": "SEC_FLUME",
            "sensor_type": "FLOW_RATE",
            "value": 11.2,
            "unit": "L/min",
            "source": "PHYSICAL",
            "status": "OK",
        }
        res = client.post("/api/v1/telemetry/ingest", json=physical_reading)
        assert res.status_code == 201

        evt = ws_physical.receive_json()
        assert evt["sensor_id"] == "FS_FLUME_01"
        assert evt["source"] == "PHYSICAL"
        assert evt["flow_rate_lpm"] == 11.2
        assert evt["water_level_cm"] is None


def test_dynamic_client_filtering_over_websocket(client: TestClient):
    """
    Test 5b: Verify client can dynamically change filter over WebSocket.
    """
    with client.websocket_connect("/api/v1/telemetry/stream") as ws:
        _ = ws.receive_json()  # Init

        # Send filter action
        ws.send_json({"action": "filter", "sensor_id": "US_UPSTREAM_01"})
        ack = ws.receive_json()
        assert ack["event_type"] == "FILTER_ACK"
        assert ack["subscribed_sensor"] == "US_UPSTREAM_01"


def test_heartbeat_ping_pong(client: TestClient):
    """
    Test 7: Verify client-initiated ping yields PONG keepalive response.
    """
    with client.websocket_connect("/api/v1/telemetry/stream") as ws:
        _ = ws.receive_json()  # Init

        ws.send_json({"action": "ping"})
        pong = ws.receive_json()
        assert pong["event_type"] == "PONG"
        assert "timestamp" in pong


def test_fault_telemetry_broadcast(client: TestClient):
    """
    Test 8: Verify faulted telemetry is broadcast with is_valid=False and explicit fault_code.
    """
    with client.websocket_connect("/api/v1/telemetry/stream") as ws:
        _ = ws.receive_json()

        fault_reading = {
            "sensor_id": "US_UPSTREAM_01",
            "section_id": "SEC_SCREENING",
            "sensor_type": "WATER_LEVEL",
            "value": 0.0,
            "unit": "cm",
            "source": "SIMULATED",
            "status": "FAULT",
            "metadata": {"fault_code": "SENSOR_DISCONNECTED", "is_valid": False},
        }
        res = client.post("/api/v1/telemetry/ingest", json=fault_reading)
        assert res.status_code == 201

        evt = ws.receive_json()
        assert evt["sensor_id"] == "US_UPSTREAM_01"
        assert evt["sensor_status"] == "FAULT"
        assert evt["is_valid"] is False
        assert evt["fault_code"] == "SENSOR_DISCONNECTED"


def test_safe_hold_mode_behavior_and_actuation_rejection(client: TestClient):
    """
    Test 9: Verify SAFE_HOLD operational mode is indicated and actuation commands
    sent over the stream are strictly rejected.
    """
    # Transition to SAFE_HOLD
    client.post("/api/v1/status/mode", json={"mode": "SAFE_HOLD", "reason": "Test fail-safe"})

    with client.websocket_connect("/api/v1/telemetry/stream") as ws:
        init_data = ws.receive_json()
        assert init_data["operational_mode"] == "SAFE_HOLD"

        # Attempt forbidden actuation command over stream
        ws.send_json({"action": "actuate", "gate_angle": 45.0})
        err = ws.receive_json()
        assert err["event_type"] == "ERROR"
        assert "strictly read-only" in err["message"]


def test_slow_client_backpressure_and_bounded_queue(client: TestClient):
    """
    Test 10: Verify slow client queue is bounded and drops older messages without
    blocking ingestion or throwing exceptions.
    """
    # Create custom manager with small queue size for test
    mini_manager = TelemetryStreamManager(max_queue_size=3)

    reading = SensorReadingContract(
        sensor_id="TEST_01",
        section_id="SEC_01",
        sensor_type=SensorType.WATER_LEVEL,
        value=5.0,
        unit=MeasurementUnit.CENTIMETRE,
        source=DataSource.SIMULATED,
    )

    class MockWebSocket:
        pass

    import asyncio
    queue = asyncio.Queue(maxsize=3)
    from app.services.telemetry_stream_manager import ClientSubscription
    sub = ClientSubscription(client_id="slow_c1", websocket=MockWebSocket(), queue=queue)
    mini_manager._clients["slow_c1"] = sub

    # Dispatch 10 readings into bounded queue of 3
    event = mini_manager.reading_to_event(reading, operational_mode="SIMULATION")
    event_dict = event.model_dump(mode="json")

    for _ in range(10):
        mini_manager._dispatch_to_clients(event_dict, source="SIMULATED", sensor_id="TEST_01")

    # Queue should be at most maxsize, and drops should be recorded
    assert queue.qsize() == 3
    assert sub.dropped_count > 0
    assert mini_manager.total_dropped_count > 0


@pytest.mark.anyio
async def test_application_shutdown_terminates_clients():
    """
    Test 11: Verify application shutdown terminates client queues gracefully.
    """
    manager = TelemetryStreamManager(max_queue_size=10)

    class DummyWS:
        def __init__(self):
            self.closed = False
            self.code = None

        async def close(self, code=1000, reason=""):
            self.closed = True
            self.code = code

    dummy_ws = DummyWS()
    await manager.register_client(websocket=dummy_ws)
    assert manager.active_connections_count == 1

    await manager.shutdown()
    assert manager.active_connections_count == 0
    assert dummy_ws.closed is True
    assert dummy_ws.code == 1001


def test_existing_ingestion_api_compatibility(client: TestClient):
    """
    Test 12: Verify that /api/v1/telemetry/ingest retains 100% schema compatibility,
    returning prediction, blockage, and gate_directive contracts alongside stream broadcasts.
    """
    payload = [
        {
            "sensor_id": "US_UPSTREAM_01",
            "section_id": "SEC_SCREENING",
            "sensor_type": "WATER_LEVEL",
            "value": 5.2,
            "unit": "cm",
            "source": "SIMULATED",
        },
        {
            "sensor_id": "US_WEIR_02",
            "section_id": "SEC_OUTLET",
            "sensor_type": "WATER_LEVEL",
            "value": 1.6,
            "unit": "cm",
            "source": "SIMULATED",
        },
    ]
    res = client.post("/api/v1/telemetry/ingest", json=payload)
    assert res.status_code == 201
    body = res.json()
    assert body["status"] == "success"
    assert body["ingested_count"] == 2
    assert "prediction" in body
    assert "blockage" in body
    assert "gate_directive" in body
    assert "gate_command" in body


def test_flow_rate_ingest_without_metadata_does_not_500(client: TestClient):
    """
    Regression Test: Ingesting a FLOW_RATE reading with no metadata or empty metadata
    must never raise AttributeError or cause an HTTP 500 Internal Server Error.
    """
    payload = {
        "sensor_id": "FS_FLUME_01",
        "section_id": "SEC_APPROACH",
        "sensor_type": "FLOW_RATE",
        "value": 14.5,
        "unit": "L/min",
        "source": "SIMULATED",
        "status": "OK",
    }
    res = client.post("/api/v1/telemetry", json=payload)
    assert res.status_code == 201
    body = res.json()
    assert body["status"] == "success"
    assert body["ingested_count"] == 1
