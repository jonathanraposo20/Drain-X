import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Any, Dict, List
from fastapi import WebSocket, WebSocketDisconnect

from app.core.config import settings
from app.models.contracts import (
    SensorReadingContract,
    SensorType,
    MeasurementUnit,
    DataSource,
    SensorHealthStatus,
    TelemetryStreamEvent,
    TelemetryStreamEventType,
    StreamInitMessage,
    utc_now,
)

logger = logging.getLogger("drainx.telemetry_stream")


@dataclass
class ClientSubscription:
    """
    State and bounded delivery queue for an active stream client.
    """
    client_id: str
    websocket: WebSocket
    queue: asyncio.Queue
    source_filter: Optional[str] = None  # "PHYSICAL", "SIMULATED", or None (ALL)
    sensor_filter: Optional[str] = None  # Specific sensor_id or None (ALL)
    connected_at: datetime = field(default_factory=utc_now)
    sent_count: int = 0
    dropped_count: int = 0
    is_closed: bool = False


class TelemetryStreamManager:
    """
    Centralized Real-Time Telemetry Stream Manager for DRAIN-X.
    
    Provides reliable, low-latency broadcasting of newly ingested physical
    and simulated telemetry to connected clients (e.g. Digital Twin, SCADA,
    mobile monitors).
    
    Architecture & Invariants:
    - Bounded per-client asynchronous queues prevent unbounded memory growth.
    - Non-blocking push semantics: slow or stalled clients drop older frames
      without ever blocking or delaying the core ingestion pipeline.
    - Strict operational source isolation: clients can selectively subscribe
      to PHYSICAL, SIMULATED, or ALL telemetry.
    - Read-only safety invariant: actuation and gate commands are strictly
      forbidden over the telemetry stream.
    - Independent of database persistence / Supabase configuration.
    - Graceful lifecycle management on connection loss or application shutdown.
    """

    def __init__(self, max_queue_size: Optional[int] = None, max_connections: Optional[int] = None):
        self.max_queue_size = max_queue_size or settings.WS_CLIENT_QUEUE_SIZE
        self.max_connections = max_connections or settings.WS_MAX_CONNECTIONS
        self._clients: Dict[str, ClientSubscription] = {}
        self._lock = asyncio.Lock()
        self._total_broadcast_count = 0
        self._total_dropped_count = 0
        self._is_shutting_down = False

    @property
    def active_connections_count(self) -> int:
        return len(self._clients)

    @property
    def total_broadcast_count(self) -> int:
        return self._total_broadcast_count

    @property
    def total_dropped_count(self) -> int:
        return self._total_dropped_count

    def verify_auth_token(self, token: Optional[str]) -> bool:
        """
        Validates stream authentication token if authentication is enabled.
        In bench / local dev mode (STREAM_AUTH_ENABLED=False), all connections pass.
        """
        if not settings.STREAM_AUTH_ENABLED:
            return True
        if not settings.STREAM_AUTH_TOKEN:
            return True
        return token == settings.STREAM_AUTH_TOKEN

    async def register_client(
        self,
        websocket: WebSocket,
        source_filter: Optional[str] = None,
        sensor_filter: Optional[str] = None,
    ) -> ClientSubscription:
        """
        Registers a new client connection with bounded queue and filter preferences.
        Enforces maximum concurrent connection limits.
        """
        if self._is_shutting_down:
            raise RuntimeError("Telemetry stream manager is shutting down.")

        async with self._lock:
            if len(self._clients) >= self.max_connections:
                logger.warning(
                    f"Max stream connections limit reached ({self.max_connections}). "
                    f"Rejecting new client."
                )
                raise RuntimeError(
                    f"Connection limit exceeded: maximum {self.max_connections} active clients allowed."
                )

            client_id = f"client_{uuid.uuid4().hex[:8]}"
            queue = asyncio.Queue(maxsize=self.max_queue_size)
            
            # Canonicalize source filter
            normalized_source = None
            if source_filter:
                sf = source_filter.upper().strip()
                if sf in ("PHYSICAL", "SIMULATED"):
                    normalized_source = sf

            subscription = ClientSubscription(
                client_id=client_id,
                websocket=websocket,
                queue=queue,
                source_filter=normalized_source,
                sensor_filter=sensor_filter.strip() if sensor_filter else None,
            )
            self._clients[client_id] = subscription
            logger.info(
                f"Stream client registered: {client_id} "
                f"(source_filter={normalized_source}, sensor_filter={sensor_filter}, "
                f"active_clients={len(self._clients)})"
            )
            return subscription

    async def unregister_client(self, client_id: str, reason: str = "Client disconnected") -> None:
        """
        Safely removes a disconnected client and releases resources.
        """
        async with self._lock:
            client = self._clients.pop(client_id, None)
            if client:
                client.is_closed = True
                logger.info(
                    f"Stream client unregistered: {client_id} ({reason}, "
                    f"sent={client.sent_count}, dropped={client.dropped_count}, "
                    f"remaining_clients={len(self._clients)})"
                )

    def reading_to_event(
        self,
        reading: SensorReadingContract,
        operational_mode: str,
        hardware_validation_stage: Optional[str] = None,
    ) -> TelemetryStreamEvent:
        """
        Converts an authoritative SensorReadingContract into a normalized
        TelemetryStreamEvent contract without fabricating missing values.
        """
        source_str = reading.source.value if isinstance(reading.source, Enum) else str(reading.source)
        sensor_status_str = reading.status.value if isinstance(reading.status, Enum) else str(reading.status)
        
        # Water level vs Flow rate extraction without fabrication
        metadata = reading.metadata or {}
        water_level_cm: Optional[float] = None
        flow_rate_lpm: Optional[float] = None
        cumulative_volume_liters: Optional[float] = None

        if reading.sensor_type == SensorType.WATER_LEVEL and reading.unit == MeasurementUnit.CENTIMETRE:
            water_level_cm = reading.value
        elif reading.sensor_type == SensorType.FLOW_RATE:
            flow_rate_lpm = reading.value
            cumulative_volume_liters = metadata.get("cumulative_volume_liters") or metadata.get("total_volume_liters")

        # Fault and validity extraction
        fault_code = metadata.get("fault_code")
        if not fault_code and reading.status == SensorHealthStatus.FAULT:
            fault_code = "SENSOR_FAULT"

        is_valid = bool(metadata.get("is_valid", reading.status != SensorHealthStatus.FAULT and not fault_code))
        
        val_stage = (
            metadata.get("validation_stage")
            or metadata.get("hardware_validation_stage")
            or hardware_validation_stage
        )

        return TelemetryStreamEvent(
            event_id=reading.message_id or str(uuid.uuid4()),
            event_type=TelemetryStreamEventType.TELEMETRY,
            timestamp=reading.timestamp,
            sensor_id=reading.sensor_id,
            section_id=reading.section_id,
            source=reading.source,
            operational_mode=operational_mode,
            sensor_type=reading.sensor_type,
            value=reading.value,
            unit=reading.unit.value if isinstance(reading.unit, Enum) else str(reading.unit),
            water_level_cm=water_level_cm,
            flow_rate_lpm=flow_rate_lpm,
            cumulative_volume_liters=cumulative_volume_liters,
            sensor_status=reading.status,
            is_valid=is_valid,
            fault_code=fault_code,
            hardware_validation_stage=val_stage,
            metadata=metadata,
        )

    async def broadcast_readings(
        self,
        readings: List[SensorReadingContract],
        operational_mode: Optional[str] = None,
        hardware_validation_stage: Optional[str] = None,
    ) -> int:
        """
        Converts and non-blockingly broadcasts a batch of sensor readings to all
        eligible connected clients.
        
        Returns the number of client frames successfully queued.
        """
        if not self._clients or not readings:
            return 0

        op_mode = operational_mode or "SIMULATION"
        delivered_frames = 0

        for reading in readings:
            event = self.reading_to_event(
                reading=reading,
                operational_mode=op_mode,
                hardware_validation_stage=hardware_validation_stage,
            )
            event_dict = event.model_dump(mode="json")
            source_val = event.source.value if isinstance(event.source, Enum) else str(event.source)
            sensor_id = event.sensor_id

            delivered = self._dispatch_to_clients(
                payload=event_dict,
                source=source_val,
                sensor_id=sensor_id,
            )
            delivered_frames += delivered
            self._total_broadcast_count += 1

        return delivered_frames

    async def broadcast_event(
        self,
        event_dict: Dict[str, Any],
        source: Optional[str] = None,
        sensor_id: Optional[str] = None,
    ) -> int:
        """
        Dispatches an arbitrary structured event (e.g. heartbeat, status update)
        to all eligible clients.
        """
        if not self._clients:
            return 0
        delivered = self._dispatch_to_clients(event_dict, source=source, sensor_id=sensor_id)
        self._total_broadcast_count += 1
        return delivered

    def _dispatch_to_clients(
        self,
        payload: Dict[str, Any],
        source: Optional[str] = None,
        sensor_id: Optional[str] = None,
    ) -> int:
        """
        Synchronous, non-blocking delivery into per-client bounded queues.
        Guarantees ingestion path is never blocked by slow consumers.
        """
        delivered = 0
        for client_id, client in list(self._clients.items()):
            if client.is_closed:
                continue

            # 1. Source isolation filter (normalizing LIVE and PHYSICAL as equivalent hardware streams)
            if client.source_filter and source:
                norm_filter = "PHYSICAL" if client.source_filter in ("PHYSICAL", "LIVE") else client.source_filter
                norm_source = "PHYSICAL" if source in ("PHYSICAL", "LIVE") else source
                if norm_filter != norm_source:
                    continue

            # 2. Sensor identifier filter
            if client.sensor_filter and sensor_id and client.sensor_filter != sensor_id:
                continue

            # 3. Non-blocking queue delivery with backpressure drop
            try:
                client.queue.put_nowait(payload)
                client.sent_count += 1
                delivered += 1
            except asyncio.QueueFull:
                # Slow client: evict oldest message to maintain real-time freshness
                try:
                    _ = client.queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                
                try:
                    client.queue.put_nowait(payload)
                    delivered += 1
                except asyncio.QueueFull:
                    pass

                client.dropped_count += 1
                self._total_dropped_count += 1
                if client.dropped_count == 1 or client.dropped_count % 100 == 0:
                    logger.warning(
                        f"Backpressure drop on slow client {client_id}: "
                        f"queue full ({self.max_queue_size}). "
                        f"Client dropped count: {client.dropped_count}."
                    )

        return delivered

    async def shutdown(self) -> None:
        """
        Gracefully terminates all client subscriptions on application shutdown.
        """
        self._is_shutting_down = True
        logger.info(f"Shutting down telemetry stream manager ({len(self._clients)} active clients)...")
        async with self._lock:
            clients_to_close = list(self._clients.values())
            self._clients.clear()

        for client in clients_to_close:
            client.is_closed = True
            try:
                await client.websocket.close(code=1001, reason="Server shutting down")
            except Exception:
                pass
        logger.info("Telemetry stream manager shutdown complete.")

    def get_metrics(self) -> Dict[str, Any]:
        """Returns observable telemetry stream health metrics."""
        return {
            "active_clients": len(self._clients),
            "max_connections": self.max_connections,
            "max_queue_size": self.max_queue_size,
            "total_broadcast_count": self._total_broadcast_count,
            "total_dropped_count": self._total_dropped_count,
            "is_shutting_down": self._is_shutting_down,
            "clients": [
                {
                    "client_id": c.client_id,
                    "source_filter": c.source_filter,
                    "sensor_filter": c.sensor_filter,
                    "connected_at": c.connected_at.isoformat(),
                    "sent_count": c.sent_count,
                    "dropped_count": c.dropped_count,
                    "queue_depth": c.queue.qsize(),
                }
                for c in self._clients.values()
            ],
        }


# Authoritative Stream Manager Singleton
telemetry_stream_manager = TelemetryStreamManager()
