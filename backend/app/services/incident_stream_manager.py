"""
Dedicated Backend-Authoritative Incident Real-Time Stream Manager for DRAIN-X.
Phase 3 Milestone 2B: Real-time incident updates, role-projected event fanout,
in-memory replay buffer, and safe backpressure isolation.

Invariants & Guarantees:
1. Complete architectural separation from high-frequency TelemetryStreamManager.
2. Independent cryptographic JWT authentication and role extraction on every connection.
3. Strict role-based authorization and projection:
   - Citizens receive redacted incident snapshots (reporter_name/internal_notes/verified_by = None).
   - Field workers receive events ONLY for incidents assigned to their verified team/ID.
   - Duplicate queue events (DUPLICATE_SUSPECTED, DUPLICATE_REVIEWED) are strictly restricted
     to municipal officers, admins, and service_role.
4. Process-local monotonic sequencing with bounded in-memory replay buffer.
5. Instance-aware reconnection: detects process restarts/replica mismatch and signals RESYNC_REQUIRED.
6. Non-blocking fire-and-forget publishing: broadcast errors never roll back or fail database transactions.
7. Bounded queues with slow-consumer disconnect policy (code 1008) to prevent memory growth.
8. Clean FastAPI lifespan integration with graceful shutdown (close code 1001).
"""

import asyncio
from collections import deque
from datetime import datetime, timezone
import logging
import threading
from typing import Any, Dict, List, Optional
import uuid

from fastapi import WebSocket, WebSocketDisconnect

from app.core.config import settings
from app.models.contracts import (
    IncidentResponseContract,
    IncidentStreamEvent,
    IncidentStreamEventType,
    IncidentStreamInitMessage,
    MunicipalDuplicateLinkContract,
)

logger = logging.getLogger("drainx.incident_stream")


class IncidentClientSubscription:
    """
    Represents an authenticated client WebSocket connection to the incident stream.
    """

    def __init__(
        self,
        client_id: str,
        websocket: WebSocket,
        queue: asyncio.Queue,
        role: str,
        user_id: str,
        team_id: Optional[str],
        claims: Dict[str, Any],
    ):
        self.client_id = client_id
        self.websocket = websocket
        self.queue = queue
        self.role = role
        self.user_id = user_id
        self.team_id = team_id
        self.claims = claims
        self.connected_at = datetime.now(timezone.utc)
        self.is_closed = False
        self.sent_count = 0
        self.dropped_count = 0


class InternalIncidentEvent:
    """
    Internal raw event stored in the process replay buffer before role projection.
    """

    def __init__(
        self,
        event_id: str,
        seq_id: int,
        instance_id: str,
        timestamp: datetime,
        event_type: IncidentStreamEventType,
        incident_id: Optional[str] = None,
        action: Optional[str] = None,
        previous_status: Optional[str] = None,
        new_status: Optional[str] = None,
        assigned_team_id: Optional[str] = None,
        assigned_worker_id: Optional[str] = None,
        previous_assigned_team_id: Optional[str] = None,
        previous_assigned_worker_id: Optional[str] = None,
        incident: Optional[IncidentResponseContract] = None,
        duplicate_link: Optional[MunicipalDuplicateLinkContract] = None,
        reason: Optional[str] = None,
    ):
        self.event_id = event_id
        self.seq_id = seq_id
        self.instance_id = instance_id
        self.timestamp = timestamp
        self.event_type = event_type
        self.incident_id = incident_id
        self.action = action
        self.previous_status = previous_status
        self.new_status = new_status
        self.assigned_team_id = assigned_team_id
        self.assigned_worker_id = assigned_worker_id
        self.previous_assigned_team_id = previous_assigned_team_id
        self.previous_assigned_worker_id = previous_assigned_worker_id
        self.incident = incident
        self.duplicate_link = duplicate_link
        self.reason = reason


def _is_event_authorized_for_client(
    raw_event: InternalIncidentEvent,
    sub: IncidentClientSubscription,
) -> bool:
    """
    Authorizes whether a client subscription is permitted to receive a specific event.
    """
    role = sub.role

    # 1. Municipal duplicate events: strictly municipality, admin, service_role
    if raw_event.event_type in (
        IncidentStreamEventType.DUPLICATE_SUSPECTED,
        IncidentStreamEventType.DUPLICATE_REVIEWED,
    ):
        return role in ("municipality", "admin", "service_role")

    # 2. Control events are always delivered
    if raw_event.event_type in (
        IncidentStreamEventType.HEARTBEAT,
        IncidentStreamEventType.RESYNC_REQUIRED,
    ):
        return True

    # 3. Municipality / Admin / Service Role receive all operational lifecycle events
    if role in ("municipality", "admin", "service_role"):
        return True

    # 4. Citizen receives all lifecycle events (payload will be redacted)
    if role == "citizen":
        return True

    # 5. Field Worker: ONLY authorized incidents relevant to the worker's assigned team
    if role == "worker":
        worker_team = sub.team_id
        worker_id = sub.user_id

        # Check newly assigned team / worker directly on the event
        if raw_event.assigned_team_id and worker_team:
            if raw_event.assigned_team_id.strip() == worker_team.strip():
                return True
        if raw_event.assigned_worker_id and worker_id:
            if raw_event.assigned_worker_id.strip() == worker_id.strip():
                return True

        # M2B-AUD-03: Notify previous assigned worker/team on reassignment or unassignment
        if raw_event.action in ("UNASSIGN", "REASSIGN"):
            if raw_event.previous_assigned_team_id and worker_team:
                if raw_event.previous_assigned_team_id.strip() == worker_team.strip():
                    return True
            if raw_event.previous_assigned_worker_id and worker_id:
                if raw_event.previous_assigned_worker_id.strip() == worker_id.strip():
                    return True

        # Check attached incident snapshot
        if raw_event.incident:
            inc = raw_event.incident
            if inc.assigned_team_id and worker_team and inc.assigned_team_id.strip() == worker_team.strip():
                return True
            if inc.assigned_worker_id and worker_id and inc.assigned_worker_id.strip() == worker_id.strip():
                return True
            if inc.assigned_to:
                clean_assigned = inc.assigned_to.strip().lower()
                if worker_team and clean_assigned == worker_team.strip().lower():
                    return True
                if worker_id and clean_assigned == worker_id.strip().lower():
                    return True

        # Not assigned to this worker or team: worker is not authorized to receive this event
        return False

    return False


def _project_event_for_client(
    raw_event: InternalIncidentEvent,
    sub: IncidentClientSubscription,
) -> IncidentStreamEvent:
    """
    Transforms an internal event into a strictly role-projected, PII-sanitized public frame.
    Reuses _filter_incident_for_role to guarantee zero data leakage.
    """
    from app.api.v1.incidents import _filter_incident_for_role, _sanitize_contact_info

    role = sub.role
    worker_team = sub.team_id
    worker_id = sub.user_id

    # M2B-AUD-03: A worker who was previously assigned must receive only the assignment-change
    # notification, not regain access to full incident details or future events.
    is_previous_worker_only = False
    if role == "worker" and raw_event.action in ("UNASSIGN", "REASSIGN"):
        matches_previous = False
        if raw_event.previous_assigned_team_id and worker_team and raw_event.previous_assigned_team_id.strip() == worker_team.strip():
            matches_previous = True
        if raw_event.previous_assigned_worker_id and worker_id and raw_event.previous_assigned_worker_id.strip() == worker_id.strip():
            matches_previous = True

        matches_current = False
        if raw_event.assigned_team_id and worker_team and raw_event.assigned_team_id.strip() == worker_team.strip():
            matches_current = True
        if raw_event.assigned_worker_id and worker_id and raw_event.assigned_worker_id.strip() == worker_id.strip():
            matches_current = True

        if matches_previous and not matches_current:
            is_previous_worker_only = True

    projected_incident = None
    if raw_event.incident is not None and not is_previous_worker_only:
        projected_incident = _filter_incident_for_role(raw_event.incident, sub.claims)

    projected_duplicate_link = None
    if role in ("municipality", "admin", "service_role"):
        projected_duplicate_link = raw_event.duplicate_link

    # M2B-AUD-01: Top-level worker ID projection
    # Never expose worker IDs to citizens.
    # For workers, do not expose other workers' identifiers unnecessarily.
    projected_assigned_worker_id = None
    projected_previous_assigned_worker_id = None
    if role in ("municipality", "admin", "service_role"):
        projected_assigned_worker_id = raw_event.assigned_worker_id
        projected_previous_assigned_worker_id = raw_event.previous_assigned_worker_id
    elif role == "worker":
        if worker_id and raw_event.assigned_worker_id and worker_id.strip() == raw_event.assigned_worker_id.strip():
            projected_assigned_worker_id = raw_event.assigned_worker_id
        if worker_id and raw_event.previous_assigned_worker_id and worker_id.strip() == raw_event.previous_assigned_worker_id.strip():
            projected_previous_assigned_worker_id = raw_event.previous_assigned_worker_id

    # M2B-AUD-01: Sanitize reason for citizen and worker clients to remove phone/email PII
    projected_reason = raw_event.reason
    if role in ("citizen", "worker") and projected_reason:
        projected_reason = _sanitize_contact_info(projected_reason)

    return IncidentStreamEvent(
        event_id=raw_event.event_id,
        seq_id=raw_event.seq_id,
        instance_id=raw_event.instance_id,
        timestamp=raw_event.timestamp,
        event_type=raw_event.event_type,
        incident_id=raw_event.incident_id,
        action=raw_event.action,
        previous_status=raw_event.previous_status,
        new_status=raw_event.new_status,
        assigned_team_id=raw_event.assigned_team_id,
        assigned_worker_id=projected_assigned_worker_id,
        previous_assigned_team_id=raw_event.previous_assigned_team_id,
        previous_assigned_worker_id=projected_previous_assigned_worker_id,
        incident=projected_incident,
        duplicate_link=projected_duplicate_link,
        reason=projected_reason,
    )


def _normalize_status(st: Any) -> Optional[str]:
    if st is None:
        return None
    if hasattr(st, "value"):
        return str(st.value)
    s = str(st)
    if s.startswith("IncidentStatus."):
        return s[len("IncidentStatus."):]
    return s


class IncidentStreamManager:
    """
    Centralized Real-Time Incident Stream Manager for DRAIN-X.
    Independent singleton responsible for authenticated client fanout, process sequencing,
    replay buffer management, and graceful shutdown.
    """

    def __init__(
        self,
        max_connections: Optional[int] = None,
        max_queue_size: Optional[int] = None,
        replay_buffer_size: Optional[int] = None,
        heartbeat_interval_sec: Optional[float] = None,
    ):
        self.max_connections = max_connections or getattr(settings, "INCIDENT_WS_MAX_CONNECTIONS", 100)
        self.max_queue_size = max_queue_size or getattr(settings, "INCIDENT_WS_CLIENT_QUEUE_SIZE", 100)
        self.replay_buffer_size = replay_buffer_size or getattr(settings, "INCIDENT_WS_REPLAY_BUFFER_SIZE", 500)
        self.heartbeat_interval_sec = heartbeat_interval_sec or getattr(settings, "INCIDENT_WS_HEARTBEAT_INTERVAL_SEC", 15.0)

        self._instance_id = f"inst_{uuid.uuid4().hex[:12]}"
        self._current_seq_id = 0
        self._replay_buffer: deque[InternalIncidentEvent] = deque(maxlen=self.replay_buffer_size)
        self._clients: Dict[str, IncidentClientSubscription] = {}
        self._lock = asyncio.Lock()
        self._publish_lock = threading.Lock()
        self._sync_lock = threading.RLock()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._is_shutting_down = False

        # Lock Hierarchy & Concurrency Architecture (M2B-AUD-04):
        # 1. _publish_lock (threading.Lock): Top-level publication serializer. Governs end-to-end
        #    ordering across concurrent publishing threads, ensuring client queue insertion order
        #    strictly matches monotonic sequence allocation and replay-buffer insertion.
        # 2. _sync_lock (threading.RLock): Inner buffer and sequence state lock. Protects in-memory
        #    _replay_buffer and _current_seq_id. Acquired briefly under _publish_lock during broadcast,
        #    or independently by readers (current_seq_id, handle_handshake_and_replay).
        # 3. _lock (asyncio.Lock): Async registration lock for client connection setup/teardown.
        # Strict hierarchy rule: _publish_lock -> _sync_lock (unidirectional, zero deadlock risk).

    @property
    def instance_id(self) -> str:
        return self._instance_id

    @property
    def current_seq_id(self) -> int:
        with self._sync_lock:
            return self._current_seq_id

    @property
    def active_connections_count(self) -> int:
        return len(self._clients)

    @property
    def oldest_buffered_seq_id(self) -> int:
        with self._sync_lock:
            if not self._replay_buffer:
                return self._current_seq_id
            return self._replay_buffer[0].seq_id

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Binds the active asyncio event loop for threadsafe cross-thread broadcasts."""
        self._loop = loop
        self._is_shutting_down = False

    def reset_state(self) -> None:
        """Resets stream manager state for testing or server reboot."""
        self._is_shutting_down = False
        self._clients.clear()

    def _get_loop(self) -> Optional[asyncio.AbstractEventLoop]:
        if self._loop is not None and not self._loop.is_closed():
            return self._loop
        try:
            loop = asyncio.get_running_loop()
            self._loop = loop
            return loop
        except RuntimeError:
            return None

    async def register_client(
        self,
        websocket: WebSocket,
        claims: Dict[str, Any],
    ) -> IncidentClientSubscription:
        """
        Registers a verified client connection after successful JWT authentication.
        Enforces maximum concurrent connection limit.
        """
        if self._is_shutting_down:
            raise RuntimeError("Incident stream manager is shutting down.")

        role = claims.get("extracted_role", "citizen")
        user_id = str(claims.get("sub") or "anonymous")
        team_id = claims.get("extracted_team")

        async with self._lock:
            if len(self._clients) >= self.max_connections:
                logger.warning(
                    f"Max incident stream connections reached ({self.max_connections}). Rejecting client."
                )
                raise RuntimeError(f"Connection limit reached: max {self.max_connections} active clients.")

            client_id = f"inc_client_{uuid.uuid4().hex[:8]}"
            queue = asyncio.Queue(maxsize=self.max_queue_size)
            subscription = IncidentClientSubscription(
                client_id=client_id,
                websocket=websocket,
                queue=queue,
                role=role,
                user_id=user_id,
                team_id=team_id,
                claims=claims,
            )
            self._clients[client_id] = subscription
            logger.info(
                f"Incident stream client connected: {client_id} (role={role}, user={user_id}, team={team_id}, "
                f"active_clients={len(self._clients)})"
            )
            return subscription

    async def unregister_client(self, client_id: str, reason: str = "Client disconnected") -> None:
        """Safely removes a disconnected client and cleans up subscription resources."""
        async with self._lock:
            sub = self._clients.pop(client_id, None)
            if sub:
                sub.is_closed = True
                logger.info(
                    f"Incident stream client disconnected: {client_id} ({reason}, "
                    f"sent={sub.sent_count}, dropped={sub.dropped_count}, remaining={len(self._clients)})"
                )

    async def handle_handshake_and_replay(
        self,
        subscription: IncidentClientSubscription,
        last_seq_id: Optional[int] = None,
        last_instance_id: Optional[str] = None,
    ) -> None:
        """
        Transmits the INIT message and securely evaluates client replay requests.
        Enforces instance matching, buffer presence, and role-based projection during replay.
        """
        current_seq = self.current_seq_id

        # 1. Send INIT handshake
        init_msg = IncidentStreamInitMessage(
            event_type="INIT",
            protocol_version="1.0",
            client_id=subscription.client_id,
            instance_id=self._instance_id,
            current_seq_id=current_seq,
            user_id=subscription.user_id,
            role=subscription.role,
            team_id=subscription.team_id,
            connection_time=datetime.now(timezone.utc),
            message="Connected to DRAIN-X authoritative incident stream",
            max_queue_size=self.max_queue_size,
            heartbeat_interval_sec=self.heartbeat_interval_sec,
        )
        await subscription.websocket.send_json(init_msg.model_dump(mode="json"))

        # 2. Evaluate Reconnect Replay if requested
        if last_seq_id is not None:
            # Case A: Instance mismatch (server restarted or routed to different replica)
            if last_instance_id != self._instance_id:
                logger.info(
                    f"Client {subscription.client_id} requested replay across different instance "
                    f"(client={last_instance_id}, server={self._instance_id}); signaling RESYNC_REQUIRED."
                )
                resync_event = IncidentStreamEvent(
                    event_id=f"evt_{uuid.uuid4().hex[:12]}",
                    seq_id=current_seq,
                    instance_id=self._instance_id,
                    timestamp=datetime.now(timezone.utc),
                    event_type=IncidentStreamEventType.RESYNC_REQUIRED,
                    reason=f"Instance changed (client={last_instance_id}, server={self._instance_id}). Full REST snapshot required.",
                )
                await subscription.websocket.send_json(resync_event.model_dump(mode="json"))
                return

            with self._sync_lock:
                oldest_seq = self.oldest_buffered_seq_id
                # Case B: Evicted sequence or invalid future sequence
                if last_seq_id < oldest_seq - 1 or last_seq_id > current_seq:
                    logger.info(
                        f"Client {subscription.client_id} sequence {last_seq_id} is outside buffer "
                        f"(oldest={oldest_seq}, current={current_seq}); signaling RESYNC_REQUIRED."
                    )
                    resync_event = IncidentStreamEvent(
                        event_id=f"evt_{uuid.uuid4().hex[:12]}",
                        seq_id=current_seq,
                        instance_id=self._instance_id,
                        timestamp=datetime.now(timezone.utc),
                        event_type=IncidentStreamEventType.RESYNC_REQUIRED,
                        reason=f"Requested sequence {last_seq_id} is outside buffer window [{oldest_seq}..{current_seq}].",
                    )
                    await subscription.websocket.send_json(resync_event.model_dump(mode="json"))
                    return

                # Case C: Valid sequence within replay buffer
                missed_events = [
                    ev for ev in self._replay_buffer if ev.seq_id > last_seq_id
                ]

            replayed_count = 0
            for raw_ev in missed_events:
                if _is_event_authorized_for_client(raw_ev, subscription):
                    projected = _project_event_for_client(raw_ev, subscription)
                    await subscription.websocket.send_json(projected.model_dump(mode="json"))
                    replayed_count += 1
                    subscription.sent_count += 1

            logger.info(
                f"Client {subscription.client_id} replay completed: delivered {replayed_count} "
                f"events from sequence {last_seq_id + 1} to {current_seq}."
            )

    def broadcast_incident_event(
        self,
        event_type: IncidentStreamEventType,
        incident: Optional[IncidentResponseContract] = None,
        incident_id: Optional[str] = None,
        action: Optional[str] = None,
        previous_status: Optional[str] = None,
        new_status: Optional[str] = None,
        assigned_team_id: Optional[str] = None,
        assigned_worker_id: Optional[str] = None,
        previous_assigned_team_id: Optional[str] = None,
        previous_assigned_worker_id: Optional[str] = None,
        team_id: Optional[str] = None,
        worker_id: Optional[str] = None,
        duplicate_link: Optional[MunicipalDuplicateLinkContract] = None,
        reason: Optional[str] = None,
    ) -> int:
        """
        Thread-safe, non-blocking broadcast method callable from both synchronous and
        asynchronous mutation endpoints.

        Guarantees (M2B-AUD-04):
        - Serializes publication order across concurrent threads via _publish_lock.
        - Advances process-local sequence monotonically under _sync_lock.
        - Appends to bounded replay buffer under _sync_lock.
        - Dispatches to client queues under _publish_lock (with _sync_lock released).
        - Preserves bounded queues and slow-consumer handling.
        """
        try:
            with self._publish_lock:
                with self._sync_lock:
                    self._current_seq_id += 1
                    seq_id = self._current_seq_id

                    target_incident_id = incident_id or (incident.id if incident else (
                        duplicate_link.primary_incident_id if duplicate_link else None
                    ))

                    target_team_id = team_id or assigned_team_id or (incident.assigned_team_id if incident else None)
                    target_worker_id = worker_id or assigned_worker_id or (incident.assigned_worker_id if incident else None)

                    raw_event = InternalIncidentEvent(
                        event_id=f"evt_{uuid.uuid4().hex[:12]}",
                        seq_id=seq_id,
                        instance_id=self._instance_id,
                        timestamp=datetime.now(timezone.utc),
                        event_type=event_type,
                        incident_id=target_incident_id,
                        action=action,
                        previous_status=_normalize_status(previous_status),
                        new_status=_normalize_status(new_status),
                        assigned_team_id=target_team_id,
                        assigned_worker_id=target_worker_id,
                        previous_assigned_team_id=previous_assigned_team_id,
                        previous_assigned_worker_id=previous_assigned_worker_id,
                        incident=incident,
                        duplicate_link=duplicate_link,
                        reason=reason,
                    )
                    self._replay_buffer.append(raw_event)

                # Fan out to active clients in strict publication order (holding _publish_lock, _sync_lock released)
                return self._dispatch_to_clients(raw_event)

        except Exception as exc:
            logger.warning(
                "Incident stream broadcast failed non-fatally (error=%s); persistence remains intact.",
                exc.__class__.__name__,
            )
            return 0

    def _dispatch_to_clients(self, raw_event: InternalIncidentEvent) -> int:
        """
        Synchronously fans out an internal event into per-client bounded queues
        with strict role authorization, projection, and slow-consumer disconnection.
        """
        delivered = 0
        stalled_clients: List[IncidentClientSubscription] = []

        for sub in list(self._clients.values()):
            if sub.is_closed:
                continue

            # 1. Verify client authorization for this event
            if not _is_event_authorized_for_client(raw_event, sub):
                continue

            # 2. Project event with strict role filtering
            projected = _project_event_for_client(raw_event, sub)
            payload = projected.model_dump(mode="json")

            # 3. Enforce bounded queue & slow-consumer disconnect policy
            try:
                sub.queue.put_nowait(payload)
                sub.sent_count += 1
                delivered += 1
            except asyncio.QueueFull:
                # Client consumer is stalled: apply backpressure disconnect policy
                sub.dropped_count += 1
                sub.is_closed = True
                stalled_clients.append(sub)
                logger.warning(
                    f"Slow incident consumer disconnected: client {sub.client_id} queue full ({self.max_queue_size})."
                )

        # Disconnect stalled clients asynchronously
        if stalled_clients:
            loop = self._get_loop()
            for stalled in stalled_clients:
                self._clients.pop(stalled.client_id, None)
                if loop and loop.is_running():
                    asyncio.run_coroutine_threadsafe(
                        stalled.websocket.close(code=1008, reason="Backpressure: client consumer stalled"),
                        loop,
                    )

        return delivered

    def start_heartbeat(self) -> None:
        """Starts periodic heartbeat keepalive loop if loop is running."""
        if self._heartbeat_task is None or self._heartbeat_task.done():
            loop = self._get_loop()
            if loop and loop.is_running():
                self._heartbeat_task = loop.create_task(self._heartbeat_loop())

    async def _heartbeat_loop(self) -> None:
        """Emits periodic HEARTBEAT frames to maintain connection freshness without advancing seq_id."""
        while not self._is_shutting_down:
            try:
                await asyncio.sleep(self.heartbeat_interval_sec)
                if self._is_shutting_down or not self._clients:
                    continue

                heartbeat_event = InternalIncidentEvent(
                    event_id=f"hb_{uuid.uuid4().hex[:8]}",
                    seq_id=self.current_seq_id,
                    instance_id=self._instance_id,
                    timestamp=datetime.now(timezone.utc),
                    event_type=IncidentStreamEventType.HEARTBEAT,
                    reason="Periodic incident stream keepalive",
                )
                with self._publish_lock:
                    self._dispatch_to_clients(heartbeat_event)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Incident stream heartbeat error: {e}")

    async def shutdown(self) -> None:
        """Gracefully disconnects all clients with code 1001 and cleans up tasks."""
        self._is_shutting_down = True
        logger.info(f"Shutting down incident stream manager ({len(self._clients)} active clients)...")

        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass

        async with self._lock:
            for sub in list(self._clients.values()):
                sub.is_closed = True
                try:
                    await sub.websocket.close(code=1001, reason="Server shutting down")
                except Exception:
                    pass
            self._clients.clear()
        logger.info("Incident stream manager shutdown complete.")


# Global Authoritative Incident Stream Manager Singleton
incident_stream_manager = IncidentStreamManager()
