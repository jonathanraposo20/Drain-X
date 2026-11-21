"""
DRAIN-X Database Persistence Layer Interface & Supabase Cloud Client Adapter.

Milestone: P0.6 Supabase Cloud Integration.

Architecture Principles:
1. Non-invasive & Graceful Degradation:
   - If SUPABASE_URL / SUPABASE_KEY are unset or the cloud database is unreachable,
     the application runs in IN_MEMORY_FALLBACK mode with zero crashes.
   - Persistence operations fail soft and record diagnostic metadata without
     disrupting live telemetry ingestion or real-time analytics.
2. Direct HTTP REST Interface (No Heavy External SDK Required):
   - Uses `httpx` to communicate directly with Supabase PostgREST API (/rest/v1/).
3. Operational Mode Partitioning:
   - Readings are persisted with strict `source` classification ('PHYSICAL' vs 'SIMULATED').
   - Historical queries support source filtering so simulated runs never contaminate
     physical sensor archives.
4. Security & Role Boundaries:
   - Supports privileged `SUPABASE_SERVICE_ROLE_KEY` for backend ingestion bypassing RLS.
   - Never exposes service-role keys to clients or logs.
5. Device Registry & Auditing:
   - Full persistence for edge nodes (devices) and operational mode transition ledgers.
"""

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import httpx
from pydantic import BaseModel

from app.core.config import settings
from app.models.contracts import SensorReadingContract, DataSource

logger = logging.getLogger("drainx.persistence")
_UNSET = object()

class DatabaseConfigStatus(BaseModel):
    configured: bool
    url_present: bool
    key_present: bool
    service_role_key_present: bool
    mode: str
    target_table: str
    last_persistence_error: Optional[str] = None
    total_persisted_count: int = 0
    failed_persistence_count: int = 0
    connection_status: str = "UNKNOWN"
    last_ping_ms: Optional[float] = None


def _parse_record_datetime(ts_val: Any) -> Optional[datetime]:
    """
    Parses a timestamp value into a timezone-aware UTC datetime.
    Gracefully returns None for malformed, non-string, or empty timestamp values.
    """
    if isinstance(ts_val, datetime):
        if ts_val.tzinfo is None or ts_val.tzinfo.utcoffset(ts_val) is None:
            return ts_val.replace(tzinfo=timezone.utc)
        return ts_val
    if not isinstance(ts_val, str) or not ts_val.strip():
        return None
    try:
        clean_str = ts_val.strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_str)
        if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


class PersistenceRepository:
    """
    Modular persistence client interfacing FastAPI with Supabase Cloud PostgREST.
    Operates in fallback/mock mode when unconfigured.
    """
    POSTGREST_PAGE_SIZE: int = 1000

    def __init__(
        self,
        supabase_url: Any = _UNSET,
        supabase_key: Any = _UNSET,
        service_role_key: Any = _UNSET,
        timeout_sec: Optional[float] = None,
    ):
        # Resolve each configuration property independently:
        # - If argument is omitted (_UNSET), fall back to settings.
        # - If argument is explicitly None or empty string, treat as disabled/empty.
        # - Guard against cross-project mixing: if a custom URL is provided, do not
        #   implicitly leak default settings keys to that foreign URL; and vice-versa.
        if supabase_url is _UNSET:
            resolved_url = (settings.SUPABASE_URL or "").rstrip("/")
            url_from_settings = True
        elif supabase_url is None:
            resolved_url = ""
            url_from_settings = False
        else:
            resolved_url = str(supabase_url).rstrip("/")
            url_from_settings = False

        if supabase_key is _UNSET:
            if url_from_settings or resolved_url == (settings.SUPABASE_URL or "").rstrip("/"):
                resolved_key = (settings.SUPABASE_KEY or "").strip()
            else:
                resolved_key = ""
            key_from_settings = True
        elif supabase_key is None:
            resolved_key = ""
            key_from_settings = False
        else:
            resolved_key = str(supabase_key).strip()
            key_from_settings = False

        if service_role_key is _UNSET:
            if url_from_settings or resolved_url == (settings.SUPABASE_URL or "").rstrip("/"):
                resolved_service_key = (settings.SUPABASE_SERVICE_ROLE_KEY or "").strip()
            else:
                resolved_service_key = ""
            service_key_from_settings = True
        elif service_role_key is None:
            resolved_service_key = ""
            service_key_from_settings = False
        else:
            resolved_service_key = str(service_role_key).strip()
            service_key_from_settings = False

        # Cross-project mixing protection:
        # Only non-empty credential overrides should trigger this guard.
        # Explicit None/empty values disable a credential; they must not
        # accidentally disable the URL or another valid credential.
        settings_anon_key = (settings.SUPABASE_KEY or "").strip()
        settings_service_key = (
            settings.SUPABASE_SERVICE_ROLE_KEY or ""
        ).strip()

        if (
            not key_from_settings
            and resolved_key
            and resolved_key != settings_anon_key
            and url_from_settings
        ):
            resolved_url = ""
            if service_key_from_settings:
                resolved_service_key = ""

        if (
            not service_key_from_settings
            and resolved_service_key
            and resolved_service_key != settings_service_key
            and url_from_settings
        ):
            resolved_url = ""
            if key_from_settings:
                resolved_key = ""

        self._supabase_url = resolved_url
        self._supabase_key = resolved_key
        self._supabase_service_role_key = resolved_service_key

        self._timeout_sec = timeout_sec or settings.PERSISTENCE_TIMEOUT_SEC

        self._active_key = (
            self._supabase_service_role_key or self._supabase_key
        )
        self._is_configured = bool(
            self._supabase_url and self._active_key
        )

        self._in_memory_records: List[Dict[str, Any]] = []
        self._mode_history_records: List[Dict[str, Any]] = []
        self._in_memory_devices: Dict[str, Dict[str, Any]] = {
            "DRAINX-ESP32-NODE-01": {
                "device_id": "DRAINX-ESP32-NODE-01",
                "name": "Primary Flume ESP32 Node",
                "hardware_model": "ESP32 DevKit V1 (ESP-WROOM-32)",
                "firmware_version": "0.3.7-p0.3g",
                "is_active": True,
                "validation_stage": "CONNECTIVITY_READY",
                "last_seen_at": datetime.now(timezone.utc).isoformat(),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "metadata": {"location": "Flume Primary Sump"},
            }
        }

        self._last_persistence_error: Optional[str] = None
        self._total_persisted_count: int = 0
        self._failed_persistence_count: int = 0
        self._connection_status: str = (
            "UNCONFIGURED"
            if not self._is_configured
            else "CONFIGURED_UNCHECKED"
        )
        self._last_ping_ms: Optional[float] = None



    @property
    def is_configured(self) -> bool:
        return self._is_configured

    @property
    def supabase_url(self) -> str:
        return self._supabase_url

    def get_status(self) -> DatabaseConfigStatus:
        return DatabaseConfigStatus(
            configured=self._is_configured,
            url_present=bool(self._supabase_url),
            key_present=bool(self._supabase_key),
            service_role_key_present=bool(self._supabase_service_role_key),
            mode="SUPABASE_CLOUD" if self._is_configured else "IN_MEMORY_FALLBACK",
            target_table="sensor_readings",
            last_persistence_error=self._last_persistence_error,
            total_persisted_count=self._total_persisted_count,
            failed_persistence_count=self._failed_persistence_count,
            connection_status=self._connection_status,
            last_ping_ms=self._last_ping_ms,
        )

    def _get_headers(self, prefer: str = "return=minimal") -> Dict[str, str]:
        return {
            "apikey": self._active_key,
            "Authorization": f"Bearer {self._active_key}",
            "Content-Type": "application/json",
            "Prefer": prefer,
        }

    async def check_connection(self) -> Dict[str, Any]:
        """
        Probe Supabase Cloud PostgREST health and round-trip latency.
        """
        if not self._is_configured:
            self._connection_status = "UNCONFIGURED"
            return {
                "status": "UNCONFIGURED",
                "mode": "IN_MEMORY_FALLBACK",
                "message": "Supabase credentials not configured. Running in local in-memory mode.",
                "latency_ms": None,
                "configured": False,
            }

        endpoint = f"{self._supabase_url}/rest/v1/sensor_readings?select=count&limit=0"
        t_start = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=self._timeout_sec) as client:
                resp = await client.get(
                    endpoint,
                    headers={
                        "apikey": self._active_key,
                        "Authorization": f"Bearer {self._active_key}",
                        "Prefer": "count=exact",
                    },
                )
                elapsed_ms = round((time.perf_counter() - t_start) * 1000.0, 2)
                self._last_ping_ms = elapsed_ms

                if resp.status_code in (200, 206):
                    self._connection_status = "CONNECTED"
                    self._last_persistence_error = None
                    return {
                        "status": "CONNECTED",
                        "mode": "SUPABASE_CLOUD",
                        "message": "Successfully connected to Supabase Cloud PostgREST.",
                        "latency_ms": elapsed_ms,
                        "http_status": resp.status_code,
                        "configured": True,
                    }
                elif resp.status_code in (401, 403):
                    self._connection_status = "AUTH_FAILED"
                    err_msg = f"HTTP {resp.status_code} - Invalid or unauthorized Supabase API key"
                    self._last_persistence_error = err_msg
                    return {
                        "status": "AUTH_FAILED",
                        "mode": "SUPABASE_CLOUD",
                        "message": err_msg,
                        "latency_ms": elapsed_ms,
                        "http_status": resp.status_code,
                        "configured": True,
                    }
                else:
                    self._connection_status = "UNREACHABLE"
                    err_msg = f"HTTP {resp.status_code} - {resp.text}"
                    self._last_persistence_error = err_msg
                    return {
                        "status": "UNREACHABLE",
                        "mode": "SUPABASE_CLOUD",
                        "message": err_msg,
                        "latency_ms": elapsed_ms,
                        "http_status": resp.status_code,
                        "configured": True,
                    }
        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - t_start) * 1000.0, 2)
            self._last_ping_ms = elapsed_ms
            self._connection_status = "UNREACHABLE"
            err_msg = f"Network connection failed: {exc}"
            self._last_persistence_error = err_msg
            return {
                "status": "UNREACHABLE",
                "mode": "SUPABASE_CLOUD",
                "message": err_msg,
                "latency_ms": elapsed_ms,
                "http_status": None,
                "configured": True,
            }

    async def persist_readings(
        self, readings: List[SensorReadingContract]
    ) -> int:
        """
        Persist a batch of validated sensor telemetry readings to Supabase PostgREST.
        Falls back to internal buffer if Supabase is unconfigured or unreachable.
        """
        if not readings:
            return 0

        records = []
        for r in readings:
            device_id = None
            if r.metadata and isinstance(r.metadata, dict):
                device_id = r.metadata.get("device_id")

            records.append({
                "sensor_id": r.sensor_id,
                "section_id": r.section_id,
                "sensor_type": r.sensor_type.value,
                "value": float(r.value),
                "unit": r.unit.value,
                "source": r.source.value,
                "status": r.status.value,
                "timestamp": r.timestamp.isoformat(),
                "device_id": device_id,
                "metadata": r.metadata or {},
            })

        # Local buffer is maintained as fallback and secondary audit
        self._in_memory_records.extend(records)
        if len(self._in_memory_records) > 20000:
            self._in_memory_records = self._in_memory_records[-20000:]

        if not self._is_configured:
            self._total_persisted_count += len(records)
            return len(records)

        endpoint = f"{self._supabase_url}/rest/v1/sensor_readings"
        try:
            async with httpx.AsyncClient(timeout=self._timeout_sec) as client:
                resp = await client.post(
                    endpoint,
                    json=records,
                    headers=self._get_headers(),
                )
                if resp.status_code in (200, 201):
                    self._total_persisted_count += len(records)
                    self._last_persistence_error = None
                    self._connection_status = "CONNECTED"
                    return len(records)
                else:
                    err_msg = f"HTTP {resp.status_code} - {resp.text}"
                    self._last_persistence_error = err_msg
                    self._failed_persistence_count += len(records)
                    logger.warning(f"Supabase persistence error: {err_msg}")
                    return 0
        except Exception as exc:
            err_msg = str(exc)
            self._last_persistence_error = err_msg
            self._failed_persistence_count += len(records)
            logger.warning(f"Supabase persistence network error: {err_msg}")
            return 0

    async def query_historical_telemetry(
        self,
        sensor_id: Optional[str] = None,
        source: Optional[str] = None,
        section_id: Optional[str] = None,
        device_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
        chronological: bool = True,
    ) -> List[Dict[str, Any]]:
        """
        Query historical telemetry with operational source, device, and time-range filtering.
        Supports pagination via limit & offset.
        """
        limit = max(1, min(limit, 10000))
        offset = max(0, offset)

        if not self._is_configured:
            results = list(self._in_memory_records)
            if sensor_id:
                results = [r for r in results if r.get("sensor_id") == sensor_id]
            if source:
                norm_source = str(source).upper()
                if norm_source in ("PHYSICAL", "LIVE"):
                    results = [r for r in results if str(r.get("source", "")).upper() in ("PHYSICAL", "LIVE")]
                else:
                    results = [r for r in results if str(r.get("source", "")).upper() == norm_source]
            if section_id:
                results = [r for r in results if r.get("section_id") == section_id]
            if device_id:
                results = [r for r in results if r.get("device_id") == device_id]
            if start_time:
                aware_start = start_time if (start_time.tzinfo and start_time.tzinfo.utcoffset(start_time)) else start_time.replace(tzinfo=timezone.utc)
                results = [
                    r for r in results
                    if _parse_record_datetime(r.get("timestamp")) is not None
                    and _parse_record_datetime(r.get("timestamp")) >= aware_start
                ]
            if end_time:
                aware_end = end_time if (end_time.tzinfo and end_time.tzinfo.utcoffset(end_time)) else end_time.replace(tzinfo=timezone.utc)
                results = [
                    r for r in results
                    if _parse_record_datetime(r.get("timestamp")) is not None
                    and _parse_record_datetime(r.get("timestamp")) <= aware_end
                ]

            def _in_memory_sort_key(rec: Dict[str, Any]) -> Tuple[datetime, str]:
                parsed_dt = _parse_record_datetime(rec.get("timestamp"))
                safe_dt = parsed_dt if parsed_dt is not None else datetime.min.replace(tzinfo=timezone.utc)
                safe_id = str(rec.get("id", ""))
                return (safe_dt, safe_id)

            results.sort(key=_in_memory_sort_key, reverse=not chronological)
            return results[offset : offset + limit]

        endpoint = f"{self._supabase_url}/rest/v1/sensor_readings"
        order_direction = "asc" if chronological else "desc"
        page_size = getattr(self, "POSTGREST_PAGE_SIZE", 1000)

        all_records: List[Dict[str, Any]] = []
        remaining_limit = limit
        cursor: Optional[Tuple[str, str]] = None

        headers = {
            "apikey": self._active_key,
            "Authorization": f"Bearer {self._active_key}",
            "Accept": "application/json",
        }

        async with httpx.AsyncClient(timeout=self._timeout_sec) as client:
            while remaining_limit > 0:
                fetch_count = min(remaining_limit, page_size)

                # Build query params as list of tuples to support multiple constraints
                query_params: List[Tuple[str, str]] = [
                    ("order", f"timestamp.{order_direction},id.{order_direction}"),
                    ("limit", str(fetch_count)),
                ]
                if cursor is None:
                    if offset > 0:
                        query_params.append(("offset", str(offset)))
                else:
                    c_ts, c_id = cursor
                    if chronological:
                        query_params.append(("or", f"(timestamp.gt.{c_ts},and(timestamp.eq.{c_ts},id.gt.{c_id}))"))
                    else:
                        query_params.append(("or", f"(timestamp.lt.{c_ts},and(timestamp.eq.{c_ts},id.lt.{c_id}))"))

                if sensor_id:
                    query_params.append(("sensor_id", f"eq.{sensor_id}"))
                if source:
                    norm_source = str(source).upper()
                    if norm_source in ("PHYSICAL", "LIVE"):
                        query_params.append(("source", "in.(PHYSICAL,LIVE)"))
                    else:
                        query_params.append(("source", f"eq.{source}"))
                if section_id:
                    query_params.append(("section_id", f"eq.{section_id}"))
                if device_id:
                    query_params.append(("device_id", f"eq.{device_id}"))
                if start_time:
                    query_params.append(("timestamp", f"gte.{start_time.isoformat()}"))
                if end_time:
                    query_params.append(("timestamp", f"lte.{end_time.isoformat()}"))

                try:
                    resp = await client.get(endpoint, params=query_params, headers=headers)
                except Exception as exc:
                    err_msg = f"Supabase query network error: {exc}"
                    self._last_persistence_error = err_msg
                    logger.warning(err_msg)
                    raise RuntimeError(err_msg) from exc

                if resp.status_code != 200:
                    err_msg = f"Supabase query error: HTTP {resp.status_code} - {resp.text}"
                    self._last_persistence_error = err_msg
                    logger.warning(err_msg)
                    raise RuntimeError(err_msg)

                try:
                    page_data = resp.json()
                except Exception as exc:
                    err_msg = f"Supabase query returned malformed JSON: {exc}"
                    self._last_persistence_error = err_msg
                    logger.warning(err_msg)
                    raise RuntimeError(err_msg) from exc

                if not isinstance(page_data, list):
                    err_msg = f"Supabase query returned unexpected non-list data: {type(page_data)}"
                    self._last_persistence_error = err_msg
                    logger.warning(err_msg)
                    raise RuntimeError(err_msg)

                # Clear last error only after successful response decode and validation
                self._last_persistence_error = None

                if not page_data:
                    break

                all_records.extend(page_data)
                remaining_limit -= len(page_data)

                last_rec = page_data[-1]
                last_ts = last_rec.get("timestamp")
                last_id = str(last_rec.get("id", ""))
                if last_ts is not None:
                    cursor = (last_ts, last_id)
                else:
                    break

        return all_records

    async def persist_mode_transition(
        self,
        from_mode: str,
        to_mode: str,
        reason: str,
        operator_id: str = "SYSTEM",
    ) -> bool:
        """
        Persist an operational mode transition audit record.
        """
        record = {
            "from_mode": from_mode,
            "to_mode": to_mode,
            "reason": reason,
            "operator_id": operator_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._mode_history_records.append(record)
        if len(self._mode_history_records) > 500:
            self._mode_history_records = self._mode_history_records[-500:]

        if not self._is_configured:
            return True

        endpoint = f"{self._supabase_url}/rest/v1/operational_mode_history"
        try:
            async with httpx.AsyncClient(timeout=self._timeout_sec) as client:
                resp = await client.post(
                    endpoint,
                    json=[record],
                    headers=self._get_headers(),
                )
                return resp.status_code in (200, 201)
        except Exception as exc:
            logger.warning(f"Failed to persist mode history to Supabase: {exc}")
            return False

    async def query_mode_history(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Query auditable mode transition history from Supabase or memory buffer.
        """
        limit = max(1, min(limit, 500))
        if not self._is_configured:
            return list(reversed(self._mode_history_records))[:limit]

        endpoint = f"{self._supabase_url}/rest/v1/operational_mode_history"
        params = {"order": "timestamp.desc", "limit": str(limit)}
        try:
            async with httpx.AsyncClient(timeout=self._timeout_sec) as client:
                resp = await client.get(
                    endpoint,
                    params=params,
                    headers={
                        "apikey": self._active_key,
                        "Authorization": f"Bearer {self._active_key}",
                        "Accept": "application/json",
                    },
                )
                if resp.status_code == 200:
                    return resp.json()
                return list(reversed(self._mode_history_records))[:limit]
        except Exception as exc:
            logger.warning(f"Supabase mode history query error: {exc}")
            return list(reversed(self._mode_history_records))[:limit]

    async def register_device(self, device_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Register or update an IoT edge device in the devices registry.
        """
        device_id = device_data.get("device_id")
        if not device_id:
            raise ValueError("device_id is required")

        record = {
            "device_id": device_id,
            "name": device_data.get("name", device_id),
            "hardware_model": device_data.get("hardware_model", "ESP32 DevKit V1"),
            "firmware_version": device_data.get("firmware_version", "unknown"),
            "is_active": device_data.get("is_active", True),
            "validation_stage": device_data.get("validation_stage", "SOFTWARE_ONLY"),
            "last_seen_at": datetime.now(timezone.utc).isoformat(),
            "metadata": device_data.get("metadata", {}),
        }

        # Keep local memory updated
        self._in_memory_devices[device_id] = record

        if not self._is_configured:
            return record

        endpoint = f"{self._supabase_url}/rest/v1/devices"
        headers = self._get_headers(prefer="resolution=merge-duplicates,return=representation")
        try:
            async with httpx.AsyncClient(timeout=self._timeout_sec) as client:
                resp = await client.post(endpoint, json=[record], headers=headers)
                if resp.status_code in (200, 201):
                    returned = resp.json()
                    return returned[0] if returned else record
                logger.warning(f"Device registration Supabase error: HTTP {resp.status_code}")
                return record
        except Exception as exc:
            logger.warning(f"Device registration network error: {exc}")
            return record

    async def get_device(self, device_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve device metadata by device_id.
        """
        if not self._is_configured:
            return self._in_memory_devices.get(device_id)

        endpoint = f"{self._supabase_url}/rest/v1/devices"
        params = {"device_id": f"eq.{device_id}"}
        try:
            async with httpx.AsyncClient(timeout=self._timeout_sec) as client:
                resp = await client.get(
                    endpoint,
                    params=params,
                    headers={
                        "apikey": self._active_key,
                        "Authorization": f"Bearer {self._active_key}",
                        "Accept": "application/json",
                    },
                )
                if resp.status_code == 200:
                    items = resp.json()
                    return items[0] if items else None
                return self._in_memory_devices.get(device_id)
        except Exception as exc:
            logger.warning(f"Get device network error: {exc}")
            return self._in_memory_devices.get(device_id)

    async def list_devices(self) -> List[Dict[str, Any]]:
        """
        List all registered IoT edge nodes.
        """
        if not self._is_configured:
            return list(self._in_memory_devices.values())

        endpoint = f"{self._supabase_url}/rest/v1/devices"
        try:
            async with httpx.AsyncClient(timeout=self._timeout_sec) as client:
                resp = await client.get(
                    endpoint,
                    headers={
                        "apikey": self._active_key,
                        "Authorization": f"Bearer {self._active_key}",
                        "Accept": "application/json",
                    },
                )
                if resp.status_code == 200:
                    return resp.json()
                return list(self._in_memory_devices.values())
        except Exception as exc:
            logger.warning(f"List devices network error: {exc}")
            return list(self._in_memory_devices.values())

    async def persist_incident_audit(self, audit_dict: Dict[str, Any]) -> bool:
        """
        Persist an incident operational audit record to Supabase incident_audits table.
        Gracefully degrades if table does not exist or Supabase is unconfigured in development.
        In cloud environments, logs explicit operational alerts on persistence failures.
        """
        if not self._is_configured:
            return True

        endpoint = f"{self._supabase_url}/rest/v1/incident_audits"
        try:
            async with httpx.AsyncClient(timeout=self._timeout_sec) as client:
                resp = await client.post(
                    endpoint,
                    json=[audit_dict],
                    headers=self._get_headers(prefer="resolution=merge-duplicates"),
                )
                if resp.status_code in (200, 201):
                    return True
                logger.warning(f"Supabase audit persistence response HTTP {resp.status_code}: {resp.text}")
                return False
        except Exception as exc:
            logger.warning(f"Failed to persist audit to Supabase Cloud: {exc}")
            return False


    def persist_incident_audit_sync(self, audit_dict: Dict[str, Any]) -> bool:
        """
        Synchronous variant of persist_incident_audit for atomic coordination in synchronous state store.
        Uses ignore-duplicates so retries cannot modify existing audit records.
        """
        if not self._is_configured:
            return True

        endpoint = f"{self._supabase_url}/rest/v1/incident_audits"
        try:
            with httpx.Client(timeout=self._timeout_sec) as client:
                resp = client.post(
                    endpoint,
                    json=[audit_dict],
                    headers=self._get_headers(prefer="resolution=ignore-duplicates"),
                )
                if resp.status_code in (200, 201):
                    return True
                logger.warning(f"Supabase synchronous audit persistence HTTP {resp.status_code}: {resp.text}")
                return False
        except Exception as exc:
            logger.warning(f"Supabase synchronous audit persistence network error: {exc}")
            return False
    async def query_incident_audits(self, incident_id: str) -> List[Dict[str, Any]]:
        """
        Query incident audit ledger from Supabase Cloud.
        """
        if not self._is_configured:
            return []

        endpoint = f"{self._supabase_url}/rest/v1/incident_audits"
        params = {"incident_id": f"eq.{incident_id}", "order": "timestamp.asc"}

        try:
            async with httpx.AsyncClient(timeout=self._timeout_sec) as client:
                resp = await client.get(
                    endpoint,
                    params=params,
                    headers=self._get_headers(),
                )
                if resp.status_code == 200:
                    return resp.json()
                return []
        except Exception as exc:
            logger.warning(f"Supabase incident audit query error: {exc}")
            return []

    def query_incident_audits_sync(self, incident_id: str) -> List[Dict[str, Any]]:
        """
        Synchronously query authoritative incident audit ledger from Supabase Cloud.
        """
        if not self._is_configured:
            return []

        endpoint = f"{self._supabase_url}/rest/v1/incident_audits"
        params = {"incident_id": f"eq.{incident_id}", "order": "timestamp.asc"}
        try:
            with httpx.Client(timeout=self._timeout_sec) as client:
                resp = client.get(
                    endpoint,
                    params=params,
                    headers=self._get_headers(),
                )
                if resp.status_code == 200:
                    return resp.json()
                return []
        except Exception as exc:
            logger.warning(f"Supabase synchronous incident audit query error: {exc}")
            return []


    def persist_incident_sync(self, incident_dict: Dict[str, Any]) -> bool:
        """
        Synchronously persists a newly reported or updated incident to Supabase PostgreSQL table.
        Uses HTTP Prefer: resolution=merge-duplicates for crash-safe idempotency.
        """
        if not self._is_configured:
            return True

        endpoint = f"{self._supabase_url}/rest/v1/incidents"
        try:
            with httpx.Client(timeout=self._timeout_sec) as client:
                resp = client.post(
                    endpoint,
                    json=[incident_dict],
                    headers=self._get_headers(prefer="resolution=merge-duplicates"),
                )
                if resp.status_code in (200, 201):
                    return True
                logger.warning(f"Supabase incident persistence HTTP {resp.status_code}: {resp.text}")
                return False
        except Exception as exc:
            logger.warning(f"Supabase incident persistence network error: {exc}")
            return False

    def query_all_incidents_sync(self, page_size: int = 1000) -> List[Dict[str, Any]]:
        """
        Loads all persisted incidents from Supabase Cloud on backend startup.
        Uses Range header pagination to safely recover all records without silent truncation.
        """
        if not self._is_configured:
            return []

        all_records: List[Dict[str, Any]] = []
        offset = 0
        endpoint = f"{self._supabase_url}/rest/v1/incidents?order=created_at.desc"

        try:
            with httpx.Client(timeout=self._timeout_sec) as client:
                while True:
                    headers = self._get_headers()
                    headers["Range"] = f"{offset}-{offset + page_size - 1}"
                    resp = client.get(endpoint, headers=headers)
                    if resp.status_code not in (200, 206):
                        if resp.status_code != 416:  # 416 Range Not Satisfiable (end of dataset)
                            logger.warning(f"Supabase incident query returned HTTP {resp.status_code}")
                        break
                    page = resp.json()
                    if not page:
                        break
                    all_records.extend(page)
                    if len(page) < page_size:
                        break
                    offset += page_size

            return all_records
        except Exception as exc:
            logger.warning(f"Supabase all incidents paginated query network error: {exc}")
            return []

    def execute_municipal_incident_transaction_sync(
        self,
        incident_id: str,
        new_status: Optional[str],
        new_severity: Optional[str],
        assigned_to: Optional[str],
        assignment_type: Optional[str],
        assigned_team_id: Optional[str],
        assigned_worker_id: Optional[str],
        municipal_notes: Optional[str],
        internal_notes: Optional[str],
        rejection_reason: Optional[str],
        verified_by: Optional[str],
        actor_id: str,
        actor_role: str,
        action: str,
        reason: Optional[str],
        audit_id: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Executes the atomic municipal incident and audit transaction.
        Configured cloud failures raise instead of falling back to separate writes.
        """
        if not self._is_configured:
            return None

        endpoint = f"{self._supabase_url}/rest/v1/rpc/municipal_incident_transaction_rpc"
        payload = {
            "p_incident_id": incident_id,
            "p_new_status": new_status,
            "p_new_severity": new_severity,
            "p_assigned_to": assigned_to,
            "p_assignment_type": assignment_type,
            "p_assigned_team_id": assigned_team_id,
            "p_assigned_worker_id": assigned_worker_id,
            "p_municipal_notes": municipal_notes,
            "p_internal_notes": internal_notes,
            "p_rejection_reason": rejection_reason,
            "p_verified_by": verified_by,
            "p_actor_id": actor_id,
            "p_actor_role": actor_role,
            "p_action": action,
            "p_reason": reason,
            "p_audit_id": audit_id,
        }

        try:
            with httpx.Client(timeout=self._timeout_sec) as client:
                resp = client.post(
                    endpoint,
                    json=payload,
                    headers=self._get_headers(),
                )
                if resp.status_code != 200:
                    raise RuntimeError(
                        f"Municipal incident RPC failed with HTTP {resp.status_code}: {resp.text}"
                    )

                result = resp.json()
                if not isinstance(result, dict) or result.get("id") != incident_id:
                    raise RuntimeError(
                        f"Municipal incident RPC returned an invalid response for '{incident_id}'."
                    )

                return result
        except Exception as exc:
            logger.error("Municipal incident RPC failed for %s: %s", incident_id, exc)
            raise RuntimeError(
                f"Atomic municipal cloud transaction failed for incident '{incident_id}'."
            ) from exc

    def execute_citizen_incident_creation_sync(
        self,
        incident_id: str,
        category: str,
        description: str,
        latitude: float,
        longitude: float,
        severity: str,
        source: str,
        reporter_name: str,
        photos: List[str],
        audit_id: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Executes the atomic citizen incident creation RPC.

        The RPC atomically creates the incident and its initial audit record.

        Returns the persisted incident only after validating the response.
        Never falls back to separate incident and audit writes.

        Returns None only when Supabase is not configured. Callers must
        handle that case separately as local development mode.
        """
        if not self._is_configured:
            return None

        endpoint = (
            f"{self._supabase_url}/rest/v1/rpc/"
            "citizen_incident_creation_rpc"
        )

        payload = {
            "p_incident_id": incident_id,
            "p_category": category,
            "p_description": description,
            "p_latitude": latitude,
            "p_longitude": longitude,
            "p_severity": severity,
            "p_source": source,
            "p_reporter_name": reporter_name,
            "p_photos": photos,
            "p_audit_id": audit_id,
        }

        try:
            with httpx.Client(timeout=self._timeout_sec) as client:
                resp = client.post(
                    endpoint,
                    json=payload,
                    headers=self._get_headers(),
                )

                if resp.status_code == 200:
                    try:
                        result = resp.json()
                    except ValueError as exc:
                        logger.error(
                            "Citizen incident RPC returned invalid JSON."
                        )
                        raise RuntimeError(
                            "Citizen incident RPC returned invalid JSON."
                        ) from exc

                    if (
                        not isinstance(result, dict)
                        or result.get("id") != incident_id
                    ):
                        logger.error(
                            "Citizen incident RPC returned an invalid "
                            "incident response for ID %s.",
                            incident_id,
                        )
                        raise RuntimeError(
                            "Citizen incident RPC did not confirm "
                            "the requested incident."
                        )

                    return result

                try:
                    error_body = resp.json()
                except ValueError:
                    error_body = {}

                error_code = (
                    error_body.get("code")
                    if isinstance(error_body, dict)
                    else None
                )

                if (
                    resp.status_code == 404
                    and error_code == "PGRST202"
                ):
                    logger.error(
                        "Citizen incident RPC is unavailable. "
                        "Refusing non-atomic persistence fallback."
                    )
                    raise RuntimeError(
                        "Citizen incident creation RPC is unavailable. "
                        "Check the Supabase function and PostgREST schema cache."
                    )

                logger.error(
                    "Supabase citizen creation RPC failed: "
                    "HTTP %s, response: %s",
                    resp.status_code,
                    resp.text,
                )

                raise RuntimeError(
                    f"Citizen incident RPC failed with HTTP "
                    f"{resp.status_code}."
                )

        except httpx.RequestError as exc:
            logger.error(
                "Citizen incident RPC network error: %s",
                exc,
            )
            raise RuntimeError(
                "Citizen incident RPC could not be reached."
            ) from exc



# Global persistence client instance
persistence_repo = PersistenceRepository()
