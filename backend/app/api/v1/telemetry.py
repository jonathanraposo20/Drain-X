import logging
from typing import List, Union, Optional
from datetime import datetime, timezone
import asyncio
from fastapi import APIRouter, Query, status, HTTPException, WebSocket, WebSocketDisconnect, Depends
from app.models.contracts import (
    SensorReadingContract,
    TelemetryIngestResponse,
    DataSource,
    ActuatorDirectiveContract,
    AlertSeverity,
    StreamInitMessage,
    TelemetryStreamEvent,
    utc_now,
)
from app.core.config import settings
from app.core.security import verify_device_key
from app.services.state_store import state_store
from app.services.fault_detector import fault_detector
from app.services.blockage_detector import blockage_detector
from app.services.prediction_engine import prediction_engine
from app.services.intervention_engine import intervention_engine
from app.services.persistence_repository import persistence_repo
from app.services.telemetry_stream_manager import telemetry_stream_manager
from app.services.time_series_analytics import (
    aggregate_time_series,
    calculate_water_level_trend,
    calculate_flow_trend,
)

logger = logging.getLogger("drainx.api.telemetry")

router = APIRouter(prefix="/telemetry", tags=["Telemetry"])


@router.post("", response_model=TelemetryIngestResponse, status_code=status.HTTP_201_CREATED, summary="Ingest sensor reading(s)")
@router.post("/ingest", response_model=TelemetryIngestResponse, status_code=status.HTTP_201_CREATED, summary="Ingest sensor reading(s) (canonical alias)")
async def ingest_telemetry(
    payload: Union[SensorReadingContract, List[SensorReadingContract]],
    device_key: Optional[str] = Depends(verify_device_key),
):
    """
    Ingest validated sensor telemetry and immediately execute the analytics pipeline.
    Accepts either a single SensorReadingContract or a list of readings.
    Used by physical ESP32 adapters, simulation runners, and MQTT bridges alike.
    
    Processing steps:
    1. Store readings into thread-safe in-memory state store and circular history buffer.
    2. Evaluate individual reading plausibility, ranges, and spike faults.
    3. Evaluate system-level sensor health, staleness, and cross-consistency.
    4. Run hydraulic blockage detection and localization across monitored sections.
    5. Run Time-to-Critical (TTC) predictive linear regression.
    6. Compute real-time actuator directives (diversion gate angle & action).
    7. Return structured ingestion response with analytics snapshot.
    """
    readings = payload if isinstance(payload, list) else [payload]
    single_msg_id = payload.message_id if isinstance(payload, SensorReadingContract) else None

    # Strict operational mode validation: prevent cross-contamination
    if state_store.is_simulation() and any(r.source in (DataSource.PHYSICAL, DataSource.LIVE) for r in readings):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="System is in SIMULATION mode. Physical hardware telemetry rejected to prevent simulation contamination. Explicitly switch mode to PHYSICAL first.",
        )

    if state_store.is_physical() and any(r.source == DataSource.SIMULATED for r in readings):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="System is in PHYSICAL mode. Simulated telemetry rejected to prevent hardware state contamination. Explicitly switch mode to SIMULATION first.",
        )

    if state_store.is_safe_hold() and any(r.source == DataSource.SIMULATED for r in readings):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="System is in SAFE_HOLD mode. Simulated telemetry rejected.",
        )

    # 1. Store reading and validate plausibility
    for reading in readings:
        state_store.ingest_reading(reading)
        fault_detector.evaluate_reading(reading)

    # 2. System-level health and cross-consistency
    fault_detector.evaluate_system_health()

    # 3. Blockage detection and localization
    blockage = blockage_detector.evaluate()

    # 4. Predictive trend estimation & TTC
    prediction = prediction_engine.evaluate()

    # 5. Actuator & diversion gate directive
    if state_store.is_safe_hold():
        directive = ActuatorDirectiveContract(
            gate_target_angle=settings.SAFE_HOLD_GATE_ANGLE,
            action="SAFE_HOLD_LOCK",
            reason=f"SAFE_HOLD active: automated actuation locked to fail-safe angle ({settings.SAFE_HOLD_GATE_ANGLE} deg).",
            risk_level=AlertSeverity.HIGH,
            emergency_stop=True,
        )
    else:
        directive = intervention_engine.compute_gate_directive()
    state_store.set_gate_directive(directive)

    # 6. Active alert count
    active_alerts = len(state_store.get_alerts(active_only=True))

    # 7. Asynchronously trigger persistence to Supabase / repository
    await persistence_repo.persist_readings(readings)

    # 8. Broadcast newly ingested readings to live stream clients
    await telemetry_stream_manager.broadcast_readings(
        readings=readings,
        operational_mode=state_store.mode,
    )

    return TelemetryIngestResponse(
        status="success",
        ingested_count=len(readings),
        message_id=single_msg_id,
        prediction=prediction,
        blockage=blockage,
        active_alerts_count=active_alerts,
        gate_directive=directive,
        gate_command=directive,
    )


@router.get("/latest", summary="Get latest readings across all sensors")
async def get_latest_telemetry():
    """
    Returns the most recent reading from each active sensor.
    """
    return {
        "status": "success",
        "readings": state_store.get_latest_readings()
    }


@router.get("/history/{sensor_id}", summary="Get rolling history for a specific sensor")
async def get_sensor_history(sensor_id: str, limit: int = Query(default=100, ge=1, le=500)):
    """
    Returns the rolling buffer of historical readings for a specific sensor.
    """
    history = state_store.get_sensor_history(sensor_id=sensor_id, limit=limit)
    if not history:
        return {
            "status": "empty",
            "sensor_id": sensor_id,
            "readings": []
        }
    return {
        "status": "success",
        "sensor_id": sensor_id,
        "count": len(history),
        "readings": history
    }


@router.get("/persistence/status", summary="Get status of telemetry persistence engine")
async def get_persistence_status():
    """
    Returns the operational configuration of the telemetry persistence repository.
    Reports whether live Supabase PostgREST synchronization is active or running
    in local in-memory fallback mode.
    """
    return {
        "status": "success",
        "persistence": persistence_repo.get_status().model_dump()
    }


@router.post("/persistence/ping", summary="Probe live Supabase connection health")
async def ping_persistence():
    """
    Sends a diagnostic health probe to the configured Supabase Cloud instance,
    measuring round-trip latency and verifying PostgREST responsiveness.
    """
    return await persistence_repo.check_connection()


@router.get("/persistence/historical", summary="Query persistent historical telemetry")
async def query_persistent_telemetry(
    sensor_id: Optional[str] = Query(default=None, description="Optional sensor identifier"),
    source: Optional[str] = Query(default=None, description="Operational source filter: PHYSICAL or SIMULATED"),
    section_id: Optional[str] = Query(default=None, description="Optional drainage section identifier"),
    device_id: Optional[str] = Query(default=None, description="Optional IoT edge node identifier"),
    start_time: Optional[datetime] = Query(default=None, description="ISO timestamp lower bound"),
    end_time: Optional[datetime] = Query(default=None, description="ISO timestamp upper bound"),
    limit: int = Query(default=100, ge=1, le=500, description="Max number of records (1-500)"),
    offset: int = Query(default=0, ge=0, description="Pagination record offset"),
    chronological: bool = Query(default=True, description="Order oldest first if true, newest first if false"),
):
    """
    Queries persistent historical sensor readings from Supabase (or in-memory repository fallback).
    Supports time-range, sensor, device, and operational mode filtering with limit/offset pagination.
    """
    if start_time and end_time and start_time > end_time:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="start_time must not be later than end_time.",
        )

    records = await persistence_repo.query_historical_telemetry(
        sensor_id=sensor_id,
        source=source,
        section_id=section_id,
        device_id=device_id,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        offset=offset,
        chronological=chronological,
    )
    is_truncated = (len(records) >= limit)
    return {
        "status": "success",
        "count": len(records),
        "limit": limit,
        "offset": offset,
        "sensor_id": sensor_id,
        "device_id": device_id,
        "source_filter": source,
        "chronological": chronological,
        "is_truncated": is_truncated,
        "truncation_warning": f"Historical query reached limit of {limit} records; additional records may exist in the selected time window." if is_truncated else None,
        "records": records,
    }


@router.get("/analytics/rollup", summary="Get 1-minute or 5-minute statistical rollups")
async def get_telemetry_rollups(
    sensor_id: str = Query(..., description="Target sensor ID (e.g. US_UPSTREAM_01, FS_FLUME_01)"),
    source: Optional[str] = Query(default=None, description="Operational source filter: PHYSICAL or SIMULATED"),
    interval_seconds: int = Query(default=60, description="Bucket interval in seconds (e.g. 60 or 300)"),
    limit: int = Query(default=100, ge=1, le=500, description="Max historical samples to aggregate"),
):
    """
    Computes statistical aggregations (avg, min, max, valid_count) across time buckets.
    Excludes invalid readings, sensor timeouts, and uninstalled hardware faults.
    Zero-flow is preserved as valid data.
    """
    if interval_seconds not in (60, 300):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="interval_seconds must be either 60 (1-minute) or 300 (5-minute).",
        )

    raw_records = await persistence_repo.query_historical_telemetry(
        sensor_id=sensor_id,
        source=source,
        limit=limit,
        chronological=True,
    )

    is_truncated = (len(raw_records) >= limit)
    unit = raw_records[0].get("unit", "cm") if raw_records else "cm"
    buckets = aggregate_time_series(raw_records, bucket_interval_seconds=interval_seconds, unit=unit)

    return {
        "status": "success",
        "sensor_id": sensor_id,
        "source": source or "ALL",
        "interval_seconds": interval_seconds,
        "dataset_sample_count": len(raw_records),
        "is_dataset_truncated": is_truncated,
        "truncation_warning": "Requested limit reached; older historical readings may be omitted from rollup." if is_truncated else None,
        "bucket_count": len(buckets),
        "buckets": [b.model_dump() for b in buckets],
    }


@router.get("/analytics/trend", summary="Get rate of rise or flow trend metrics")
async def get_telemetry_trend(
    sensor_id: str = Query(..., description="Target sensor ID"),
    source: Optional[str] = Query(default=None, description="Operational source filter: PHYSICAL or SIMULATED"),
    limit: int = Query(default=60, ge=2, le=300, description="Number of recent samples to analyze"),
):
    """
    Computes trend analytics:
    - Water level: rate of rise/fall (cm/min) via timestamped linear regression.
    - Flow sensor: average flow, peak flow, rate of change (L/min per min), and total volume.
    Excludes invalid measurements and SENSOR_NOT_INSTALLED faults.
    """
    raw_records = await persistence_repo.query_historical_telemetry(
        sensor_id=sensor_id,
        source=source,
        limit=limit,
        chronological=True,
    )

    if not raw_records:
        return {
            "status": "empty",
            "sensor_id": sensor_id,
            "source": source or "ALL",
            "message": "No historical telemetry found for specified sensor.",
        }

    sensor_type = raw_records[0].get("sensor_type", "WATER_LEVEL")
    is_truncated = (len(raw_records) >= limit)
    if sensor_type == "FLOW_RATE" or raw_records[0].get("unit") in ("L/min", "lpm"):
        metrics = calculate_flow_trend(raw_records, sensor_id=sensor_id, source=source or "PHYSICAL")
    else:
        metrics = calculate_water_level_trend(raw_records, sensor_id=sensor_id, source=source or "PHYSICAL")

    return {
        "status": "success",
        "sensor_id": sensor_id,
        "sensor_type": sensor_type,
        "source": source or "ALL",
        "dataset_sample_count": len(raw_records),
        "is_dataset_truncated": is_truncated,
        "metrics": metrics.model_dump(),
    }


@router.get("/stream/status", summary="Get live telemetry stream metrics and active client count")
async def get_stream_status():
    """
    Returns observable telemetry stream manager metrics, including active WebSocket
    connections, queue utilization, and dropped frame counts.
    """
    return {
        "status": "success",
        "metrics": telemetry_stream_manager.get_metrics(),
    }


@router.websocket("/stream")
@router.websocket("/ws")
async def telemetry_websocket_stream(
    websocket: WebSocket,
    source: Optional[str] = Query(default=None, description="Operational source filter: PHYSICAL, SIMULATED, or omitted for ALL"),
    sensor_id: Optional[str] = Query(default=None, description="Optional sensor ID filter (e.g. US_UPSTREAM_01)"),
    token: Optional[str] = Query(default=None, description="Stream authentication token"),
):
    """
    Real-time telemetry stream WebSocket endpoint.
    
    Capabilities:
    - Bounded asynchronous queue per client prevents memory leaks.
    - Automatic snapshot on connect: current operational mode, validation stage, latest readings.
    - Client-side dynamic filtering: send {"action": "filter", "source": "PHYSICAL", "sensor_id": "..."}.
    - Bidirectional keepalive ping/pong: send {"action": "ping"} -> receives {"event_type": "PONG"}.
    - Safety invariant: Actuation/gate commands sent over stream are strictly rejected.
    """
    # 1. Verify stream authentication if enabled
    if not telemetry_stream_manager.verify_auth_token(token):
        logger.warning("Stream connection rejected: invalid authentication token.")
        await websocket.close(code=1008, reason="Unauthorized: invalid or missing stream token.")
        return

    # 2. Accept WebSocket handshake
    await websocket.accept()

    # 3. Register client subscription
    try:
        subscription = await telemetry_stream_manager.register_client(
            websocket=websocket,
            source_filter=source,
            sensor_filter=sensor_id,
        )
    except RuntimeError as exc:
        await websocket.close(code=1013, reason=str(exc))
        return

    # 4. Transmit connection initialization message and snapshot
    latest_readings = state_store.get_latest_readings()
    snapshot = {}
    for sid, reading in latest_readings.items():
        reading_source = reading.source.value if hasattr(reading.source, "value") else str(reading.source)
        if subscription.source_filter and reading_source != subscription.source_filter:
            continue
        if subscription.sensor_filter and sid != subscription.sensor_filter:
            continue
        snapshot[sid] = reading.model_dump(mode="json")

    init_msg = StreamInitMessage(
        event_type="INIT",
        protocol_version="1.0",
        client_id=subscription.client_id,
        connection_time=utc_now(),
        operational_mode=state_store.mode,
        hardware_validation_stage=getattr(state_store, "hardware_validation_stage", "INCREMENTAL_CONNECTIVITY"),
        latest_snapshot=snapshot,
        subscribed_source=subscription.source_filter,
        subscribed_sensor=subscription.sensor_filter,
        message="Connected to DRAIN-X live telemetry stream",
        stream_config={
            "max_queue_size": telemetry_stream_manager.max_queue_size,
            "ping_interval_sec": settings.WS_HEARTBEAT_INTERVAL_SEC,
        },
    )
    await websocket.send_json(init_msg.model_dump(mode="json"))

    # 5. Background queue consumer task for streaming events to client
    async def sender_worker():
        try:
            while not subscription.is_closed:
                payload = await subscription.queue.get()
                if payload is None or subscription.is_closed:
                    break
                await websocket.send_json(payload)
                subscription.queue.task_done()
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.debug(f"Sender worker ended for client {subscription.client_id}: {e}")

    sender_task = asyncio.create_task(sender_worker())

    # 6. Listen for incoming client frames (ping, dynamic filter, command rejection)
    try:
        while True:
            data = await websocket.receive_json()
            if not isinstance(data, dict):
                await websocket.send_json({
                    "event_type": "ERROR",
                    "message": "Malformed message frame: JSON object required.",
                })
                continue

            action = data.get("action", "").lower()

            if action == "ping":
                await websocket.send_json({
                    "event_type": "PONG",
                    "timestamp": utc_now().isoformat(),
                    "client_id": subscription.client_id,
                })

            elif action == "filter":
                new_source = data.get("source")
                new_sensor = data.get("sensor_id")

                # Validate source filter input
                if new_source is not None:
                    clean_source = new_source.upper().strip() if new_source else None
                    if clean_source in ("PHYSICAL", "SIMULATED", None, ""):
                        subscription.source_filter = clean_source if clean_source else None
                    else:
                        await websocket.send_json({
                            "event_type": "ERROR",
                            "message": f"Invalid source filter '{new_source}'. Allowed: PHYSICAL, SIMULATED, or null.",
                        })
                        continue

                if new_sensor is not None:
                    subscription.sensor_filter = new_sensor.strip() if new_sensor else None

                await websocket.send_json({
                    "event_type": "FILTER_ACK",
                    "client_id": subscription.client_id,
                    "subscribed_source": subscription.source_filter,
                    "subscribed_sensor": subscription.sensor_filter,
                })

            elif action in ("command", "gate", "actuate", "override"):
                # Safety Guard: Actuation strictly forbidden on read-only stream
                logger.warning(
                    f"Forbidden actuation command attempted over telemetry stream by client {subscription.client_id}."
                )
                await websocket.send_json({
                    "event_type": "ERROR",
                    "message": "Telemetry stream is strictly read-only monitoring. Actuator commands are rejected.",
                })

            else:
                await websocket.send_json({
                    "event_type": "ERROR",
                    "message": f"Unrecognized action '{action}'. Supported: 'ping', 'filter'.",
                })

    except WebSocketDisconnect:
        logger.debug(f"Client {subscription.client_id} disconnected normally.")
    except Exception as exc:
        logger.debug(f"Client {subscription.client_id} stream error: {exc}")
    finally:
        subscription.is_closed = True
        sender_task.cancel()
        try:
            await sender_task
        except asyncio.CancelledError:
            pass
        await telemetry_stream_manager.unregister_client(subscription.client_id)

