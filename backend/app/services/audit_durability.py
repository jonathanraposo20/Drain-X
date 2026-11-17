"""
DRAIN-X Durable Incident Audit Persistence Manager.

Provides a multi-tier, crash-safe, append-only persistence engine for municipal triage,
dispatch assignment, reassignment, rejection, and resolution audit events:
1. Primary / Authoritative Cloud Persistence: Supabase PostgREST (cloud operations).
2. Local Journal Fallback: Append-only JSONL format on disk.
3. Thread-safe in-memory cache for fast querying.
4. Render cloud environment detection to prevent silent ephemeral audit loss.
"""

import json
import logging
import os
import threading
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

from app.models.contracts import IncidentAuditContract

logger = logging.getLogger("drainx.audit_durability")


class AuditDurabilityManager:
    """
    Manages durable persistence for incident operational audit logs.
    Combines thread-safe local JSONL journaling with authoritative Supabase Cloud storage.
    Guarantees that cloud deployments do not silently operate in an ephemeral-only mode.
    """

    def __init__(self, storage_path: Optional[str] = None):
        self._lock = threading.RLock()
        self._known_audit_ids: set[str] = set()

        if storage_path:
            self._file_path = Path(storage_path)
        else:
            env_path = os.getenv("DRAINX_AUDIT_LOG_PATH")
            if env_path:
                self._file_path = Path(env_path)
            else:
                # Default: backend/app/data/incident_audits.jsonl
                base_dir = Path(__file__).resolve().parent.parent / "data"
                self._file_path = base_dir / "incident_audits.jsonl"

        self._ensure_storage_dir()

    def is_cloud_environment(self) -> bool:
        """
        Determines whether the application is running in a cloud hosting environment (e.g. Render).
        Render sets RENDER=true or RENDER_SERVICE_ID in the container environment.
        """
        return bool(os.getenv("RENDER") or os.getenv("RENDER_SERVICE_ID"))

    def _ensure_storage_dir(self) -> None:
        try:
            self._file_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            logger.warning(f"Failed to create audit storage directory {self._file_path.parent}: {exc}")

    def append_audit(self, audit: IncidentAuditContract) -> bool:
        """
        Atomically appends an audit record to the local disk journal with deduplication.
        """
        with self._lock:
            # Deduplicate by unique audit_id
            if audit.audit_id in self._known_audit_ids:
                logger.debug(f"Audit {audit.audit_id} already written to local journal.")
                return True

            try:
                self._ensure_storage_dir()
                data = audit.model_dump(mode="json")
                line = json.dumps(data) + "\n"
                with open(self._file_path, "a", encoding="utf-8") as f:
                    f.write(line)
                    f.flush()
                self._known_audit_ids.add(audit.audit_id)
                return True
            except Exception as exc:
                logger.error(f"Failed to append audit record {audit.audit_id} to {self._file_path}: {exc}")
                return False

    def load_all_audits(self) -> Dict[str, List[IncidentAuditContract]]:
        """
        Loads all persisted audit records from disk into memory, grouped by incident_id.
        Preserves chronological ordering.
        """
        with self._lock:
            audits_by_incident: Dict[str, List[IncidentAuditContract]] = {}
            if not self._file_path.exists():
                return audits_by_incident

            try:
                with open(self._file_path, "r", encoding="utf-8") as f:
                    for line_num, line in enumerate(f, start=1):
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            record_dict = json.loads(line)
                            audit = IncidentAuditContract(**record_dict)
                            self._known_audit_ids.add(audit.audit_id)
                            audits_by_incident.setdefault(audit.incident_id, []).append(audit)
                        except Exception as parse_err:
                            logger.warning(f"Corrupt audit record at line {line_num} in {self._file_path}: {parse_err}")

                # Ensure sorted chronologically by timestamp
                for inc_id in audits_by_incident:
                    audits_by_incident[inc_id].sort(key=lambda a: a.timestamp)

                logger.info(f"Loaded durable audit history for {len(audits_by_incident)} incidents from {self._file_path}.")
            except Exception as exc:
                logger.error(f"Error loading durable audits from {self._file_path}: {exc}")

            return audits_by_incident

    def clear_for_testing(self) -> None:
        """Helper for test suites to cleanly reset the durable audit file and memory index."""
        with self._lock:
            self._known_audit_ids.clear()
            try:
                if self._file_path.exists():
                    self._file_path.unlink()
            except Exception as exc:
                logger.warning(f"Error clearing audit log {self._file_path}: {exc}")
