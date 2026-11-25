import time
import logging
import math
from collections import deque, OrderedDict
from datetime import datetime, timezone
from decimal import Decimal
import threading
from typing import Optional, Any, Sequence

from app.models.contracts import (
    SensorReadingContract,
    AlertContract,
    BlockageEventContract,
    PredictionContract,
    MechanismStatusContract,
    FaultEventContract,
    BenchmarkMetricsContract,
    SystemStatusContract,
    SystemOperationalState,
    AlertSeverity,
    ActuatorDirectiveContract,
    DirectiveEventType,
    DirectiveIssuerType,
    DirectiveAuditOutboxFullError,
    ActuatorDirectiveEventContract,
    StagedDeliveryEnvelope,
    ActuatorDirectiveResponseContract,
    build_issued_audit_id,
    build_mode_cancellation_audit_id,
    build_reboot_cancellation_audit_id,
    build_alignment_observed_audit_id,
    build_execution_failed_audit_id,
    build_verification_timeout_audit_id,
    build_superseded_audit_id,
    quantize_numeric_5_2_decimal,
    compute_verification_timeout_timestamp,
    IncidentResponseContract,
    IncidentUpdateContract,
    IncidentAuditContract,
    FieldTeamContract,
    IncidentStatus,
    IncidentCategory,
    IncidentSeverity,
    IncidentSource,
    AssignmentType,
    OperationalMode,
    ModeTransitionRecord,
    DataSource,
    validate_incident_status_transition,
    DuplicateLinkContract,
    DuplicateLinkStatus,
)
from app.core.config import settings
from app.services.audit_durability import AuditDurabilityManager
from app.services.actuator_digest import (
    VALID_FIRMWARE_GATE_STATES,
    canonicalize_value,
    compute_reading_digest,
    compute_aggregate_observation_digest,
    evaluate_alignment_consistency,
)

logger = logging.getLogger("drainx.state_store")


class ObservationRecord:
    """
    Coalesced physical observation record cached in DeviceObservationSession.
    """
    def __init__(
        self,
        sequence_number: int,
        uptime_ms: int,
        raw_readings: list[SensorReadingContract],
        sensor_digests: dict[str, str],
        firmware_version: Optional[str] = None,
        actuator_snapshot: Optional[dict[str, Any]] = None,
        aggregate_digest: str = "",
    ):
        self.sequence_number = sequence_number
        self.uptime_ms = uptime_ms
        self.raw_readings = list(raw_readings)
        self.sensor_digests = dict(sensor_digests)
        self.firmware_version = firmware_version
        self.actuator_snapshot = dict(actuator_snapshot or {})
        self.aggregate_digest = aggregate_digest
        self.first_seen_time = time.time()
        self.last_seen_time = self.first_seen_time


class RebootCandidate:
    """
    Candidate reboot tracking state machine.
    """
    def __init__(
        self,
        anchor_seq: int,
        anchor_uptime_ms: int,
        anchor_timestamp: float,
        observations: list[ObservationRecord],
        confirm_count: int = 1,
        first_observed_time: float = 0.0,
        last_observed_time: float = 0.0,
    ):
        self.anchor_seq = anchor_seq
        self.anchor_uptime_ms = anchor_uptime_ms
        self.anchor_timestamp = anchor_timestamp
        self.observations = list(observations)
        self.confirm_count = confirm_count
        self.first_observed_time = first_observed_time or time.time()
        self.last_observed_time = last_observed_time or self.first_observed_time


class DeviceObservationSession:
    """
    Tracks device sequence number progression, session epochs, and bounded seen-observation cache.
    """
    def __init__(self, device_id: str):
        self.device_id = device_id
        self.device_session_epoch: int = 0
        self.last_seen_seq: Optional[int] = None
        self.last_seen_uptime_ms: Optional[int] = None
        self.last_seen_timestamp: Optional[datetime] = None
        self.seen_observations: OrderedDict[tuple[int, int], ObservationRecord] = OrderedDict()
        self.pending_reboot_candidate: Optional[RebootCandidate] = None


def _normalize_utc_timestamp(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _is_timestamp_strictly_newer(
    candidate: Optional[datetime], current: Optional[datetime]
) -> bool:
    if candidate is None:
        return False
    if current is None:
        return True
    return _normalize_utc_timestamp(candidate) > _normalize_utc_timestamp(current)

# Directory of registered field response crews (explicitly classified as DEMO or MUNICIPAL)
AUTHORITATIVE_FIELD_TEAMS: list[FieldTeamContract] = [
    FieldTeamContract(
        team_id="TEAM-ALPHA",
        name="Team Alpha — St. Inez Drainage Crew",
        zone="St. Inez / Panaji Central",
        is_active=True,
        is_demo=True,
        is_verified_municipal_crew=False,
        capacity=4,
        contact_phone="+91-832-2420001",
    ),
    FieldTeamContract(
        team_id="TEAM-BETA",
        name="Team Beta — Patto Rapid Response",
        zone="Patto Commercial Plaza",
        is_active=True,
        is_demo=True,
        is_verified_municipal_crew=False,
        capacity=4,
        contact_phone="+91-832-2420002",
    ),
    FieldTeamContract(
        team_id="TEAM-GAMMA",
        name="Team Gamma — Fontainhas Heritage Maintenance",
        zone="Fontainhas Conservation Zone",
        is_active=True,
        is_demo=True,
        is_verified_municipal_crew=False,
        capacity=3,
        contact_phone="+91-832-2420003",
    ),
    FieldTeamContract(
        team_id="TEAM-DELTA",
        name="Team Delta — Miramar Outfall Sluice Unit",
        zone="Miramar Beach Outfall",
        is_active=True,
        is_demo=True,
        is_verified_municipal_crew=False,
        capacity=5,
        contact_phone="+91-832-2420004",
    ),
]


def validate_and_normalize_field_team(identifier: Optional[str]) -> Optional[FieldTeamContract]:
    """
    Validates an assignee or crew string against the authoritative field team directory.
    Rejects nonexistent, inactive, or unauthorized teams.
    Does NOT use substring matching.
    Returns the canonical FieldTeamContract, or None if unassigned.
    """
    if not identifier or not identifier.strip():
        return None

    raw = identifier.strip().lower()
    cleaned = raw.replace("[demo]", "").strip()

    # Exact check against team_id or canonical name (with or without [demo])
    for team in AUTHORITATIVE_FIELD_TEAMS:
        clean_team_name = team.name.lower().replace("[demo]", "").strip()
        if (
            raw == team.team_id.lower()
            or raw == team.name.lower()
            or cleaned == clean_team_name
            or raw == clean_team_name
        ):
            if not team.is_active:
                raise ValueError(f"Field team '{team.name}' is currently inactive and cannot receive assignments.")
            return team

    # Canonical short names ("team alpha", "team beta", "team gamma", "team delta")
    canonical_aliases = {
        "team alpha": "TEAM-ALPHA",
        "team beta": "TEAM-BETA",
        "team gamma": "TEAM-GAMMA",
        "team delta": "TEAM-DELTA",
    }
    # Check if raw matches prefix before em-dash or explicit canonical alias
    for alias, tid in canonical_aliases.items():
        if (
            cleaned == alias
            or cleaned.startswith(f"{alias} —")
            or cleaned.startswith(f"{alias} -")
            or raw == alias
            or raw.startswith(f"{alias} —")
            or raw.startswith(f"{alias} -")
        ):
            for team in AUTHORITATIVE_FIELD_TEAMS:
                if team.team_id == tid:
                    if not team.is_active:
                        raise ValueError(f"Field team '{team.name}' is currently inactive.")
                    return team

    raise ValueError(
        f"Invalid assignee '{identifier}'. Must match an authoritative registered field crew from the municipal directory."
    )


class StateStore:
    """
    Authoritative In-Memory State Store for DRAIN-X.
    Maintains active telemetry, rolling historical windows, active alerts,
    blockage events, predictions, fault events, mechanism state, and benchmarking results.
    Thread-safe and independent of external database availability.
    """
    def __init__(self, max_history_per_sensor: int = 300):
        self._lock = threading.RLock()
        self._start_time = time.time()
        self._max_history = max_history_per_sensor

        # Mode & State
        raw_mode = settings.SYSTEM_MODE
        self.mode = "PHYSICAL" if raw_mode == "HARDWARE" else raw_mode
        self.operational_state = SystemOperationalState.MONITORING
        self.hardware_validation_stage: str = "INCREMENTAL_CONNECTIVITY"
        self._mode_history: list[ModeTransitionRecord] = [
            ModeTransitionRecord(
                from_mode="INITIALIZATION",
                to_mode=self.mode,
                reason="System startup default configuration",
            )
        ]

        # Telemetry storage partitioned by source/mode to guarantee strict isolation
        self._sim_latest_readings: dict[str, SensorReadingContract] = {}
        self._sim_history: dict[str, deque[SensorReadingContract]] = {}

        self._physical_latest_readings: dict[str, SensorReadingContract] = {}
        self._physical_history: dict[str, deque[SensorReadingContract]] = {}

        self._safe_hold_latest_readings: dict[str, SensorReadingContract] = {}
        self._safe_hold_history: dict[str, deque[SensorReadingContract]] = {}

        # Derived Analytics Partitioned Storage
        # 1. Simulation Analytics Partition
        self._sim_alerts: dict[str, AlertContract] = {}
        self._sim_blockages: dict[str, BlockageEventContract] = {}
        self._sim_active_blockage: Optional[BlockageEventContract] = None
        self._sim_latest_prediction: Optional[PredictionContract] = None
        self._sim_latest_gate_directive: Optional[ActuatorDirectiveContract] = None
        self._sim_mechanism: MechanismStatusContract = MechanismStatusContract()
        self._sim_faults: dict[str, FaultEventContract] = {}

        # 2. Physical Analytics Partition
        self._physical_alerts: dict[str, AlertContract] = {}
        self._physical_blockages: dict[str, BlockageEventContract] = {}
        self._physical_active_blockage: Optional[BlockageEventContract] = None
        self._physical_latest_prediction: Optional[PredictionContract] = None
        self._physical_latest_gate_directive: Optional[ActuatorDirectiveContract] = None
        self._physical_mechanism: MechanismStatusContract = MechanismStatusContract()
        self._physical_faults: dict[str, FaultEventContract] = {}

        # 3. Safe Hold Directives (Immutable fail-safe posture)
        self._safe_hold_gate_directive: Optional[ActuatorDirectiveContract] = None

        # Faults & Benchmark
        self._active_scenario: Optional[str] = None
        self._latest_benchmark: Optional[BenchmarkMetricsContract] = None

        # Municipal & Citizen Incidents
        self._incidents: dict[str, IncidentResponseContract] = {}
        self._incident_versions: dict[str, int] = {}
        self._incidents_clear_generation: int = 0
        self._duplicate_links: dict[str, DuplicateLinkContract] = {}
        self._audit_durability = AuditDurabilityManager()
        self._incident_audits: dict[str, list[IncidentAuditContract]] = self._audit_durability.load_all_audits()

        # Device Observation Sessions for reboot inference and deduplication
        self._device_sessions: dict[str, DeviceObservationSession] = {}

        # Actuator Directive Lifecycle Ledger & Outbox
        self._directive_audits: list[ActuatorDirectiveEventContract] = []
        self._directive_audits_outbox: list[ActuatorDirectiveEventContract] = []
        self._ephemeral_delivery_buffer: deque[StagedDeliveryEnvelope] = deque(maxlen=1000)
        self._active_directives: dict[str, Optional[ActuatorDirectiveContract]] = {
            "SIMULATION": None,
            "PHYSICAL": None,
            "SAFE_HOLD": None,
        }

        self.seed_demo_incidents()
        self.recover_incidents_from_cloud()

    def _bump_incident_version_locked(self, incident_id: str) -> int:
        next_ver = self._incident_versions.get(incident_id, 0) + 1
        self._incident_versions[incident_id] = next_ver
        return next_ver

    def recover_incidents_from_cloud(self) -> None:
        """
        Loads persisted incidents from Supabase Cloud on backend startup.
        Ensures cloud-persisted incidents and assignments survive process restart.
        """
        try:
            from app.services.persistence_repository import persistence_repo
            if persistence_repo.is_configured:
                records = persistence_repo.query_all_incidents_sync()
                parsed: list[IncidentResponseContract] = []
                for rec in records:
                    try:
                        parsed.append(IncidentResponseContract(**rec))
                    except Exception as parse_err:
                        logger.warning(f"Failed to parse cloud incident record {rec.get('id')}: {parse_err}")
                if parsed:
                    with self._lock:
                        for inc in parsed:
                            self._incidents[inc.id] = inc
                            self._bump_incident_version_locked(inc.id)
                if records:
                    logger.info(f"Recovered {len(records)} authoritative incidents from Supabase Cloud.")
        except Exception as exc:
            logger.warning(f"Could not recover incidents from Supabase Cloud on startup: {exc}")

    def is_simulation(self) -> bool:
        return self.mode in (OperationalMode.SIMULATION, "SIMULATION")

    def is_physical(self) -> bool:
        return self.mode in (OperationalMode.PHYSICAL, "PHYSICAL")

    def is_safe_hold(self) -> bool:
        return self.mode in (OperationalMode.SAFE_HOLD, "SAFE_HOLD")

    def set_mode(
        self,
        new_mode: str,
        reason: str = "",
        *,
        issuer_type: Optional[DirectiveIssuerType] = None,
        issuer_id: Optional[str] = None,
    ) -> tuple[bool, str]:
        """
        Explicit, auditable operational mode transition.
        Allowed modes: SIMULATION, PHYSICAL, SAFE_HOLD, HARDWARE.
        HARDWARE alias is canonically normalized to PHYSICAL.
        In SAFE_HOLD mode, automated actuation is locked to the configured fail-safe angle.
        """
        valid_modes = {"SIMULATION", "PHYSICAL", "SAFE_HOLD", "HARDWARE"}
        if new_mode not in valid_modes:
            raise ValueError(f"Invalid operational mode '{new_mode}'. Allowed modes: {sorted(list(valid_modes))}")

        # Canonicalize HARDWARE alias to PHYSICAL
        if new_mode == "HARDWARE":
            new_mode = "PHYSICAL"

        clean_issuer_id = issuer_id.strip() if isinstance(issuer_id, str) else ""
        if issuer_type is not None:
            if isinstance(issuer_type, str) and not isinstance(issuer_type, DirectiveIssuerType):
                issuer_type = DirectiveIssuerType(issuer_type)
            if issuer_type == DirectiveIssuerType.OPERATOR and not clean_issuer_id:
                raise ValueError("OPERATOR mode transition requires an explicit non-empty issuer_id.")
            resolved_issuer_type = issuer_type
            resolved_issuer_id = clean_issuer_id or (
                "safety_interlock"
                if issuer_type == DirectiveIssuerType.SAFETY_INTERLOCK
                else "mode_transition"
            )
        else:
            if new_mode == "SAFE_HOLD":
                resolved_issuer_type = DirectiveIssuerType.SAFETY_INTERLOCK
                resolved_issuer_id = clean_issuer_id or "safety_interlock"
            else:
                resolved_issuer_type = DirectiveIssuerType.AUTOMATED_ENGINE
                resolved_issuer_id = clean_issuer_id or "mode_transition"

        with self._lock:
            old_mode = self.mode
            if old_mode == new_mode:
                return True, f"System already in mode {new_mode}"

            # Mode transition cancels active directive in old mode
            prev_directive = self._active_directives.get(old_mode)
            if prev_directive is not None:
                cancel_event = ActuatorDirectiveEventContract(
                    audit_id=build_mode_cancellation_audit_id(prev_directive.directive_id, new_mode),
                    directive_id=prev_directive.directive_id,
                    event_type=DirectiveEventType.CANCELLED,
                    device_id=prev_directive.device_id,
                    section_id=prev_directive.section_id,
                    operational_mode=old_mode,
                    action=prev_directive.action,
                    gate_target_angle=prev_directive.gate_target_angle,
                    reason=f"System operational mode transitioned from {old_mode} to {new_mode}.",
                    risk_level=prev_directive.risk_level,
                    emergency_stop=prev_directive.emergency_stop,
                    issuer_type=resolved_issuer_type,
                    issuer_id=resolved_issuer_id,
                    correlation_id=prev_directive.correlation_id,
                    device_session_epoch=prev_directive.device_session_epoch,
                    baseline_device_sequence_number=prev_directive.baseline_device_sequence_number,
                )
                self._record_directive_event_locked(cancel_event)
                self._active_directives[old_mode] = None

            self.mode = new_mode
            record = ModeTransitionRecord(
                from_mode=old_mode,
                to_mode=new_mode,
                reason=reason or f"Mode transition from {old_mode} to {new_mode}",
            )
            self._mode_history.append(record)

            # In SAFE_HOLD mode, guarantee fail-safe actuator directive
            if self.is_safe_hold():
                safe_device_id = (
                    prev_directive.device_id
                    if (old_mode == "PHYSICAL" and prev_directive is not None)
                    else None
                )
                safe_session = (
                    self._device_sessions.get(safe_device_id)
                    if safe_device_id is not None
                    else None
                )
                safe_epoch = safe_session.device_session_epoch if safe_session is not None else None
                safe_seq = safe_session.last_seen_seq if safe_session is not None else None

                safe_directive = ActuatorDirectiveContract(
                    device_id=safe_device_id,
                    baseline_device_sequence_number=safe_seq,
                    device_session_epoch=safe_epoch,
                    gate_target_angle=settings.SAFE_HOLD_GATE_ANGLE,
                    action="SAFE_HOLD_LOCK",
                    reason=f"SAFE_HOLD active: {record.reason}. Automated actuation locked to fail-safe angle ({settings.SAFE_HOLD_GATE_ANGLE} deg).",
                    risk_level=AlertSeverity.HIGH,
                    emergency_stop=True,
                    issuer_type=DirectiveIssuerType.SAFETY_INTERLOCK,
                    issuer_id="safety_interlock",
                )
                self._safe_hold_gate_directive = safe_directive
                self._active_directives["SAFE_HOLD"] = safe_directive
                issued_event = ActuatorDirectiveEventContract(
                    audit_id=build_issued_audit_id(safe_directive.directive_id),
                    directive_id=safe_directive.directive_id,
                    event_type=DirectiveEventType.ISSUED,
                    device_id=safe_directive.device_id,
                    section_id=safe_directive.section_id,
                    operational_mode="SAFE_HOLD",
                    action=safe_directive.action,
                    gate_target_angle=safe_directive.gate_target_angle,
                    reason=safe_directive.reason,
                    risk_level=safe_directive.risk_level,
                    emergency_stop=safe_directive.emergency_stop,
                    issuer_type=safe_directive.issuer_type,
                    issuer_id=safe_directive.issuer_id,
                    correlation_id=safe_directive.correlation_id,
                    device_session_epoch=safe_directive.device_session_epoch,
                    baseline_device_sequence_number=safe_directive.baseline_device_sequence_number,
                    timestamp=safe_directive.timestamp,
                )
                self._record_directive_event_locked(issued_event)

            return True, f"Successfully switched mode from {old_mode} to {new_mode}"

    def get_mode_history(self) -> list[dict]:
        with self._lock:
            return [r.model_dump() for r in self._mode_history]

    def clear(self, seed_incidents: bool = True) -> None:
        """Resets all stored telemetry, history, alerts, blockages, faults, mechanism state, incidents, and mode."""
        with self._lock:
            raw_mode = settings.SYSTEM_MODE
            self.mode = "PHYSICAL" if raw_mode == "HARDWARE" else raw_mode
            self.operational_state = SystemOperationalState.MONITORING
            self.hardware_validation_stage = "INCREMENTAL_CONNECTIVITY"

            self._sim_latest_readings.clear()
            self._sim_history.clear()
            self._sim_alerts.clear()
            self._sim_blockages.clear()
            self._sim_active_blockage = None
            self._sim_latest_prediction = None
            self._sim_latest_gate_directive = None
            self._sim_mechanism = MechanismStatusContract()
            self._sim_faults.clear()

            self._physical_latest_readings.clear()
            self._physical_history.clear()
            self._physical_alerts.clear()
            self._physical_blockages.clear()
            self._physical_active_blockage = None
            self._physical_latest_prediction = None
            self._physical_latest_gate_directive = None
            self._physical_mechanism = MechanismStatusContract()
            self._physical_faults.clear()

            self._safe_hold_latest_readings.clear()
            self._safe_hold_history.clear()
            self._safe_hold_gate_directive = None

            # Reset actuator directive lifecycle state and device observation sessions
            self._device_sessions.clear()
            self._directive_audits.clear()
            self._directive_audits_outbox.clear()
            self._ephemeral_delivery_buffer.clear()
            self._active_directives = {
                "SIMULATION": None,
                "PHYSICAL": None,
                "SAFE_HOLD": None,
            }

            self._active_scenario = None
            self._latest_benchmark = None
            self._incidents.clear()
            self._incident_versions.clear()
            self._incidents_clear_generation += 1
            self._duplicate_links.clear()
            if seed_incidents:
                self.seed_demo_incidents()

    def ingest_reading(self, reading: SensorReadingContract) -> None:
        with self._lock:
            sensor_id = reading.sensor_id

            if reading.metadata and ("validation_stage" in reading.metadata or "hardware_validation_stage" in reading.metadata):
                self.hardware_validation_stage = reading.metadata.get("validation_stage") or reading.metadata.get("hardware_validation_stage")

            # Strict operational partition routing
            if reading.source in (DataSource.PHYSICAL, DataSource.LIVE):
                # In PHYSICAL or SAFE_HOLD modes, physical telemetry updates the active hardware partition
                self._physical_latest_readings[sensor_id] = reading
                if sensor_id not in self._physical_history:
                    self._physical_history[sensor_id] = deque(maxlen=self._max_history)
                self._physical_history[sensor_id].append(reading)

                if self.is_safe_hold():
                    self._safe_hold_latest_readings[sensor_id] = reading
                    if sensor_id not in self._safe_hold_history:
                        self._safe_hold_history[sensor_id] = deque(maxlen=self._max_history)
                    self._safe_hold_history[sensor_id].append(reading)

            elif reading.source == DataSource.SIMULATED:
                # If the system is in PHYSICAL or SAFE_HOLD mode, the background simulation loop
                # MUST NOT mutate active physical or safe hold state.
                if self.is_physical() or self.is_safe_hold():
                    return

                self._sim_latest_readings[sensor_id] = reading
                if sensor_id not in self._sim_history:
                    self._sim_history[sensor_id] = deque(maxlen=self._max_history)
                self._sim_history[sensor_id].append(reading)

            else:
                # Other sources (e.g. REPLAY)
                if self.is_physical():
                    self._physical_latest_readings[sensor_id] = reading
                    if sensor_id not in self._physical_history:
                        self._physical_history[sensor_id] = deque(maxlen=self._max_history)
                    self._physical_history[sensor_id].append(reading)
                else:
                    self._sim_latest_readings[sensor_id] = reading
                    if sensor_id not in self._sim_history:
                        self._sim_history[sensor_id] = deque(maxlen=self._max_history)
                    self._sim_history[sensor_id].append(reading)

            # Automated threshold check for alerting
            if reading.unit.value == "cm" and reading.value >= settings.CRITICAL_WATER_DEPTH_CM:
                self.create_alert(
                    section_id=reading.section_id,
                    alert_type="CRITICAL_WATER_LEVEL",
                    severity=AlertSeverity.CRITICAL,
                    message=f"Water level on {reading.sensor_id} exceeded critical threshold: {reading.value:.1f} cm",
                    context_data={"sensor_id": sensor_id, "value": reading.value}
                )

    def get_latest_readings(self) -> dict[str, SensorReadingContract]:
        with self._lock:
            if self.is_physical():
                return dict(self._physical_latest_readings)
            elif self.is_safe_hold():
                if self._safe_hold_latest_readings:
                    return dict(self._safe_hold_latest_readings)
                return dict(self._physical_latest_readings)
            else:
                return dict(self._sim_latest_readings)

    def get_sensor_history(self, sensor_id: str, limit: int = 100) -> list[SensorReadingContract]:
        with self._lock:
            if self.is_physical():
                history_map = self._physical_history
            elif self.is_safe_hold():
                history_map = self._safe_hold_history if sensor_id in self._safe_hold_history else self._physical_history
            else:
                history_map = self._sim_history

            if sensor_id not in history_map:
                return []
            items = list(history_map[sensor_id])
            return items[-limit:]

    def create_alert(
        self,
        section_id: str,
        alert_type: str,
        message: str,
        severity: AlertSeverity = AlertSeverity.WARNING,
        context_data: dict | None = None
    ) -> AlertContract:
        with self._lock:
            alert_map = self._physical_alerts if (self.is_physical() or self.is_safe_hold()) else self._sim_alerts
            for alert in alert_map.values():
                if not alert.resolved and alert.section_id == section_id and alert.alert_type == alert_type:
                    return alert

            alert = AlertContract(
                section_id=section_id,
                alert_type=alert_type,
                severity=severity,
                message=message,
                context_data=context_data or {}
            )
            alert_map[alert.alert_id] = alert
            return alert

    def resolve_alert(self, alert_id: str) -> Optional[AlertContract]:
        with self._lock:
            alert_map = self._physical_alerts if (self.is_physical() or self.is_safe_hold()) else self._sim_alerts
            if alert_id in alert_map:
                alert = alert_map[alert_id]
                alert.resolved = True
                alert.resolved_at = datetime.now(timezone.utc)
                return alert
            return None

    def get_alerts(self, active_only: bool = True) -> list[AlertContract]:
        with self._lock:
            alert_map = self._physical_alerts if (self.is_physical() or self.is_safe_hold()) else self._sim_alerts
            if active_only:
                return [a for a in alert_map.values() if not a.resolved]
            return list(alert_map.values())

    def record_blockage(self, event: BlockageEventContract) -> None:
        with self._lock:
            if self.is_physical() or self.is_safe_hold():
                self._physical_blockages[event.event_id] = event
                if event.is_active:
                    self._physical_active_blockage = event
                elif self._physical_active_blockage and self._physical_active_blockage.event_id == event.event_id:
                    self._physical_active_blockage = None
            else:
                self._sim_blockages[event.event_id] = event
                if event.is_active:
                    self._sim_active_blockage = event
                elif self._sim_active_blockage and self._sim_active_blockage.event_id == event.event_id:
                    self._sim_active_blockage = None

    def get_active_blockage(self) -> Optional[BlockageEventContract]:
        with self._lock:
            if self.is_physical() or self.is_safe_hold():
                return self._physical_active_blockage
            return self._sim_active_blockage

    def clear_active_blockage(self) -> None:
        with self._lock:
            if self.is_physical() or self.is_safe_hold():
                if self._physical_active_blockage:
                    self._physical_active_blockage.is_active = False
                    self._physical_active_blockage = None
            else:
                if self._sim_active_blockage:
                    self._sim_active_blockage.is_active = False
                    self._sim_active_blockage = None

    def set_prediction(self, prediction: PredictionContract) -> None:
        with self._lock:
            if self.is_physical() or self.is_safe_hold():
                self._physical_latest_prediction = prediction
            else:
                self._sim_latest_prediction = prediction

    def get_prediction(self) -> Optional[PredictionContract]:
        with self._lock:
            if self.is_physical() or self.is_safe_hold():
                return self._physical_latest_prediction
            return self._sim_latest_prediction

    def _record_directive_event_locked(self, event: ActuatorDirectiveEventContract) -> None:
        """Appends an event to the internal audit history and outbox buffer."""
        max_size = getattr(settings, "DIRECTIVE_AUDIT_OUTBOX_MAX_SIZE", 500)
        if len(self._directive_audits_outbox) >= max_size:
            raise DirectiveAuditOutboxFullError(
                f"Directive audit outbox capacity ({max_size}) exceeded; applying backpressure."
            )
        self._directive_audits.append(event)
        self._directive_audits_outbox.append(event)

    def _cancel_active_directive_on_reboot_locked(self, device_id: str, new_epoch: int) -> None:
        """Cancels active directives for a device when an ESP32 reboot is confirmed."""
        for mode, directive in list(self._active_directives.items()):
            # Strict attribution: never fabricate a device ID. SIMULATION directives and
            # unattributed directives are never cancelled by a physical device reboot.
            if directive is not None and mode != "SIMULATION":
                d_id = directive.device_id
                if d_id is not None and d_id == device_id:
                    cancel_event = ActuatorDirectiveEventContract(
                        audit_id=build_reboot_cancellation_audit_id(directive.directive_id, new_epoch),
                        directive_id=directive.directive_id,
                        event_type=DirectiveEventType.CANCELLED,
                        device_id=device_id,
                        section_id=directive.section_id,
                        operational_mode=mode,
                        action=directive.action,
                        gate_target_angle=directive.gate_target_angle,
                        reason="Device reboot confirmed; active supervisory directive cancelled.",
                        risk_level=directive.risk_level,
                        emergency_stop=directive.emergency_stop,
                        issuer_type=DirectiveIssuerType.SAFETY_INTERLOCK,
                        issuer_id="reboot_detector",
                        correlation_id=directive.correlation_id,
                        device_session_epoch=new_epoch,
                        baseline_device_sequence_number=directive.baseline_device_sequence_number,
                    )
                    self._record_directive_event_locked(cancel_event)
                    self._active_directives[mode] = None

    def _insert_seen_observation(
        self, session: DeviceObservationSession, key: tuple[int, int], record: ObservationRecord
    ) -> None:
        """
        Inserts an observation into the bounded OrderedDict LRU cache (capacity 256).
        Evicts oldest entry using popitem(last=False) when over capacity.
        """
        session.seen_observations[key] = record
        session.seen_observations.move_to_end(key, last=True)
        while len(session.seen_observations) > settings.DEVICE_SESSION_SEEN_CACHE_SIZE:
            session.seen_observations.popitem(last=False)

    def process_telemetry_observation(
        self, readings: Sequence[SensorReadingContract]
    ) -> tuple[str, Optional[ObservationRecord]]:
        """
        Atomically ingests a batch of sensor readings under self._lock,
        enforcing device observation session tracking, reboot candidate state machine,
        observation coalescing, mixed partial-batch completion, and explicit OrderedDict LRU eviction.
        """
        if not readings:
            return ("EMPTY", None)

        with self._lock:
            def _get_dev(r: SensorReadingContract) -> str:
                if getattr(r, "device_id", None):
                    return r.device_id
                if r.metadata and "device_id" in r.metadata:
                    return str(r.metadata["device_id"])
                return "DRAINX-ESP32-NODE-01"

            def _get_seq(r: SensorReadingContract) -> Any:
                if getattr(r, "sequence_number", None) is not None:
                    return r.sequence_number
                if r.metadata and "sequence_number" in r.metadata:
                    return r.metadata["sequence_number"]
                return None

            def _get_uptime(r: SensorReadingContract) -> Any:
                if getattr(r, "uptime_ms", None) is not None:
                    return r.uptime_ms
                if r.metadata and "uptime_ms" in r.metadata:
                    return r.metadata["uptime_ms"]
                return None

            def _get_angle(r: SensorReadingContract) -> Optional[float]:
                if getattr(r, "gate_angle_deg", None) is not None:
                    return r.gate_angle_deg
                if r.metadata and "gate_angle_deg" in r.metadata:
                    return r.metadata["gate_angle_deg"]
                if r.metadata and "gate_angle" in r.metadata:
                    return r.metadata["gate_angle"]
                return None

            # 1. Device identity & session retrieval
            first_r = readings[0]
            device_id = _get_dev(first_r)
            if device_id not in self._device_sessions:
                self._device_sessions[device_id] = DeviceObservationSession(device_id=device_id)
            session = self._device_sessions[device_id]

            # 2. Strict core numeric validation
            seq_num = _get_seq(first_r)
            uptime_ms = _get_uptime(first_r)

            if seq_num is None or uptime_ms is None:
                return ("INVALID_NUMERIC", None)
            if isinstance(seq_num, bool) or isinstance(uptime_ms, bool):
                return ("INVALID_NUMERIC", None)
            if not isinstance(seq_num, int) or not isinstance(uptime_ms, int):
                return ("INVALID_NUMERIC", None)
            if seq_num < 0 or uptime_ms < 0:
                return ("INVALID_NUMERIC", None)

            # Ensure all readings in batch share device_id, sequence_number, and uptime_ms
            for r in readings:
                r_dev = _get_dev(r)
                if r_dev != device_id or _get_seq(r) != seq_num or _get_uptime(r) != uptime_ms:
                    return ("INVALID_BATCH", None)

            # 3. Extract sensor digests and metadata
            try:
                sensor_digests = {r.sensor_id: compute_reading_digest(r) for r in readings}
                agg_digest = compute_aggregate_observation_digest(readings)
            except Exception as exc:
                logger.warning("Error computing reading digest: %s", exc)
                return ("INVALID_DIGEST", None)

            firmware_ver = next(
                (r.metadata.get("firmware_version") for r in readings if r.metadata and "firmware_version" in r.metadata),
                None,
            )
            measured_angle = next((_get_angle(r) for r in readings if _get_angle(r) is not None), None)
            measured_state = next(
                (
                    r.metadata.get("gate_state") or r.metadata.get("measured_state")
                    for r in readings
                    if r.metadata and ("gate_state" in r.metadata or "measured_state" in r.metadata)
                ),
                None,
            )
            actuator_snapshot = {
                "measured_angle": measured_angle,
                "measured_state": measured_state,
            }

            obs_key = (seq_num, uptime_ms)

            # 4. Check if observation was already seen in session cache
            if obs_key in session.seen_observations:
                existing = session.seen_observations[obs_key]

                # (a) Check overlapping sensor digests
                for s_id, s_dig in sensor_digests.items():
                    if s_id in existing.sensor_digests:
                        if existing.sensor_digests[s_id] != s_dig:
                            # Conflicting overlapping sensor! Atomically reject merge.
                            return ("AMBIGUOUS_REGRESSION", None)

                # (b) Check firmware version consistency
                if firmware_ver and existing.firmware_version and firmware_ver != existing.firmware_version:
                    return ("AMBIGUOUS_REGRESSION", None)

                # (c) Check actuator snapshot consistency (safe against bool/NaN/non-numeric inputs)
                existing_angle = existing.actuator_snapshot.get("measured_angle")
                if measured_angle is not None and existing_angle is not None:
                    if (
                        isinstance(measured_angle, bool)
                        or isinstance(existing_angle, bool)
                        or not isinstance(measured_angle, (int, float, Decimal))
                        or not isinstance(existing_angle, (int, float, Decimal))
                    ):
                        if canonicalize_value(measured_angle) != canonicalize_value(existing_angle):
                            return ("AMBIGUOUS_REGRESSION", None)
                    else:
                        fa = float(measured_angle)
                        fb = float(existing_angle)
                        if not math.isfinite(fa) or not math.isfinite(fb):
                            if canonicalize_value(fa) != canonicalize_value(fb):
                                return ("AMBIGUOUS_REGRESSION", None)
                        elif abs(fa - fb) > 0.001:
                            return ("AMBIGUOUS_REGRESSION", None)
                if measured_state is not None and existing.actuator_snapshot.get("measured_state") is not None:
                    if measured_state != existing.actuator_snapshot["measured_state"]:
                        return ("AMBIGUOUS_REGRESSION", None)

                # All overlapping fields match!
                new_sensors = set(sensor_digests.keys()) - set(existing.sensor_digests.keys())
                if not new_sensors:
                    # Subset retransmission / Duplicate
                    session.seen_observations.move_to_end(obs_key, last=True)
                    existing.last_seen_time = time.time()
                    return ("DUPLICATE", existing)
                else:
                    # Partial batch completion! Merge new sensor entries
                    for r in readings:
                        if r.sensor_id in new_sensors:
                            existing.raw_readings.append(r)
                            existing.sensor_digests[r.sensor_id] = sensor_digests[r.sensor_id]
                    if firmware_ver and not existing.firmware_version:
                        existing.firmware_version = firmware_ver
                    if measured_angle is not None and existing.actuator_snapshot.get("measured_angle") is None:
                        existing.actuator_snapshot["measured_angle"] = measured_angle
                    if measured_state is not None and existing.actuator_snapshot.get("measured_state") is None:
                        existing.actuator_snapshot["measured_state"] = measured_state

                    # Recompute aggregate digest
                    existing.aggregate_digest = compute_aggregate_observation_digest(existing.raw_readings)
                    existing.last_seen_time = time.time()
                    session.seen_observations.move_to_end(obs_key, last=True)
                    return ("PARTIAL_BATCH_COMPLETION", existing)

            # 5. Observation is NOT yet in session cache
            new_record = ObservationRecord(
                sequence_number=seq_num,
                uptime_ms=uptime_ms,
                raw_readings=list(readings),
                sensor_digests=sensor_digests,
                firmware_version=firmware_ver,
                actuator_snapshot=actuator_snapshot,
                aggregate_digest=agg_digest,
            )

            # Check uint32 rollover
            is_rollover = (
                session.last_seen_uptime_ms is not None
                and session.last_seen_uptime_ms > (0xFFFFFFFF - settings.DEVICE_UPTIME_ROLLOVER_WINDOW_MS)
                and uptime_ms < settings.DEVICE_UPTIME_ROLLOVER_WINDOW_MS
            )

            if session.last_seen_seq is None:
                # First observation ever for this session
                session.last_seen_seq = seq_num
                session.last_seen_uptime_ms = uptime_ms
                session.last_seen_timestamp = datetime.now(timezone.utc)
                self._insert_seen_observation(session, obs_key, new_record)
                self._correlate_actuator_feedback_locked(
                    device_id, session.device_session_epoch, seq_num, measured_angle, measured_state, uptime_ms
                )
                return ("NEW", new_record)

            if seq_num > session.last_seen_seq or is_rollover:
                # Monotonic forward progression
                session.last_seen_seq = seq_num
                session.last_seen_uptime_ms = uptime_ms
                session.last_seen_timestamp = datetime.now(timezone.utc)
                self._insert_seen_observation(session, obs_key, new_record)

                # Clear expired reboot candidate
                if session.pending_reboot_candidate and (
                    time.time() - session.pending_reboot_candidate.first_observed_time > settings.DEVICE_REBOOT_CONFIRM_WINDOW_S
                ):
                    session.pending_reboot_candidate = None

                self._correlate_actuator_feedback_locked(
                    device_id, session.device_session_epoch, seq_num, measured_angle, measured_state, uptime_ms
                )
                return ("NEW", new_record)

            # Sequence or uptime regressed (seq_num <= session.last_seen_seq and not rollover)
            is_potential_reboot = (seq_num < session.last_seen_seq and uptime_ms < session.last_seen_uptime_ms)

            if is_potential_reboot:
                now_ts = time.time()
                cand = session.pending_reboot_candidate

                if cand is None or (now_ts - cand.first_observed_time > settings.DEVICE_REBOOT_CONFIRM_WINDOW_S):
                    cand = RebootCandidate(
                        anchor_seq=seq_num,
                        anchor_uptime_ms=uptime_ms,
                        anchor_timestamp=now_ts,
                        observations=[new_record],
                        confirm_count=1,
                        first_observed_time=now_ts,
                        last_observed_time=now_ts,
                    )
                    session.pending_reboot_candidate = cand
                else:
                    # Check if observation matches one already in candidate
                    match_cand_obs = next(
                        (o for o in cand.observations if o.sequence_number == seq_num and o.uptime_ms == uptime_ms),
                        None,
                    )
                    if match_cand_obs is not None:
                        # Staged reboot observation merge semantics
                        overlap_conflict = any(
                            match_cand_obs.sensor_digests.get(sid) != sdig
                            for sid, sdig in sensor_digests.items()
                            if sid in match_cand_obs.sensor_digests
                        )
                        if overlap_conflict:
                            return ("AMBIGUOUS_REGRESSION", None)
                        for r in readings:
                            if r.sensor_id not in match_cand_obs.sensor_digests:
                                match_cand_obs.raw_readings.append(r)
                                match_cand_obs.sensor_digests[r.sensor_id] = sensor_digests[r.sensor_id]
                        match_cand_obs.aggregate_digest = compute_aggregate_observation_digest(match_cand_obs.raw_readings)
                        # Repeated observation does not increment confirm_count
                    else:
                        if seq_num >= cand.anchor_seq and uptime_ms >= cand.anchor_uptime_ms:
                            wall_delta_s = now_ts - cand.first_observed_time
                            uptime_delta_s = (uptime_ms - cand.anchor_uptime_ms) / 1000.0
                            pacing_drift = abs(wall_delta_s - uptime_delta_s)
                            if pacing_drift <= settings.DEVICE_REBOOT_MAX_PACING_DRIFT_S:
                                cand.observations.append(new_record)
                                cand.confirm_count += 1
                                cand.last_observed_time = now_ts

                span_s = cand.last_observed_time - cand.first_observed_time
                if (
                    cand.confirm_count >= settings.DEVICE_REBOOT_MIN_CONFIRM_PACKETS
                    and span_s >= settings.DEVICE_REBOOT_MIN_CONFIRM_SPAN_S
                    and (now_ts - cand.first_observed_time) <= settings.DEVICE_REBOOT_CONFIRM_WINDOW_S
                ):
                    # REBOOT CONFIRMED
                    session.device_session_epoch += 1
                    session.last_seen_seq = cand.observations[-1].sequence_number
                    session.last_seen_uptime_ms = cand.observations[-1].uptime_ms
                    session.last_seen_timestamp = datetime.now(timezone.utc)
                    for obs in cand.observations:
                        self._insert_seen_observation(session, (obs.sequence_number, obs.uptime_ms), obs)
                    session.pending_reboot_candidate = None
                    self._cancel_active_directive_on_reboot_locked(device_id, session.device_session_epoch)
                    return ("REBOOT_CONFIRMED", new_record)
                else:
                    self._insert_seen_observation(session, obs_key, new_record)
                    return ("REBOOT_PENDING", new_record)

            # Delayed / Out of order packet
            self._insert_seen_observation(session, obs_key, new_record)
            return ("OUT_OF_ORDER", new_record)

    @staticmethod
    def _sanitize_nullable_feedback_angle(value: Any, field_name: str) -> Optional[float]:
        """Returns NUMERIC(5,2)-safe float in [0, 90] or None when invalid; never fabricates values."""
        if value is None:
            return None
        try:
            q = quantize_numeric_5_2_decimal(value, field_name, allow_none=True)
        except (ValueError, TypeError):
            return None
        if q is None:
            return None
        return 0.0 if q == 0 else float(q)

    def _correlate_actuator_feedback_locked(
        self,
        device_id: str,
        session_epoch: int,
        seq_num: int,
        measured_angle: Any,
        measured_state: Any,
        uptime_ms: Optional[int] = None,
    ) -> None:
        """Evaluates feedback against the active directive in the current operational mode."""
        directive = self._active_directives.get(self.mode)
        if directive is None:
            return

        # Target device check: refuse correlation from another device or against an unattributed baseline
        if directive.device_id is not None and directive.device_id != device_id:
            return
        if directive.device_id is None and (
            directive.device_session_epoch is not None
            or directive.baseline_device_sequence_number is not None
        ):
            return

        # Session epoch check: directive baseline epoch must match current observation epoch
        if directive.device_session_epoch is not None and directive.device_session_epoch != session_epoch:
            return

        # Sequence number check: observation must be newer than baseline
        if directive.baseline_device_sequence_number is not None and seq_num <= directive.baseline_device_sequence_number:
            return

        # Feedback completeness check: handle missing measured_angle or measured_state safely
        if measured_angle is None or measured_state is None:
            return

        is_aligned, reason, angular_error = evaluate_alignment_consistency(
            target_angle=directive.gate_target_angle,
            measured_angle=measured_angle,
            measured_state=measured_state,
            tolerance=settings.ACTUATOR_VERIFICATION_TOLERANCE_DEG,
        )

        elapsed_s = (datetime.now(timezone.utc) - directive.timestamp).total_seconds()

        if is_aligned:
            # Physical alignment observed
            event = ActuatorDirectiveEventContract(
                audit_id=build_alignment_observed_audit_id(directive.directive_id, session_epoch, seq_num),
                directive_id=directive.directive_id,
                event_type=DirectiveEventType.ALIGNMENT_OBSERVED,
                device_id=device_id,
                section_id=directive.section_id,
                operational_mode=self.mode,
                action=directive.action,
                gate_target_angle=directive.gate_target_angle,
                reason="Observed physical alignment with supervisory setpoint.",
                risk_level=directive.risk_level,
                emergency_stop=directive.emergency_stop,
                measured_gate_angle=measured_angle,
                measured_gate_state=measured_state,
                execution_divergence_deg=angular_error,
                issuer_type=directive.issuer_type,
                issuer_id=directive.issuer_id,
                correlation_id=directive.correlation_id,
                device_session_epoch=session_epoch,
                baseline_device_sequence_number=directive.baseline_device_sequence_number,
                device_sequence_number=seq_num,
                device_uptime_ms=uptime_ms,
            )
            self._record_directive_event_locked(event)
            self._active_directives[self.mode] = None
        else:
            if elapsed_s >= settings.ACTUATOR_SETTLING_TIMEOUT_SEC:
                # Sanitize invalid hardware measurements to None so ledger persistence never crashes
                safe_angle = self._sanitize_nullable_feedback_angle(measured_angle, "measured_gate_angle")
                safe_state = (
                    measured_state
                    if isinstance(measured_state, str) and measured_state in VALID_FIRMWARE_GATE_STATES
                    else None
                )
                safe_divergence = (
                    self._sanitize_nullable_feedback_angle(angular_error, "execution_divergence_deg")
                    if safe_angle is not None
                    else None
                )
                clean_reason = (reason or "").replace("\x00", "").strip()
                if not clean_reason:
                    clean_reason = (
                        f"Persistent divergence beyond {settings.ACTUATOR_SETTLING_TIMEOUT_SEC:.0f}s settling window."
                    )

                event = ActuatorDirectiveEventContract(
                    audit_id=build_execution_failed_audit_id(directive.directive_id, session_epoch, seq_num),
                    directive_id=directive.directive_id,
                    event_type=DirectiveEventType.EXECUTION_FAILED,
                    device_id=device_id,
                    section_id=directive.section_id,
                    operational_mode=self.mode,
                    action=directive.action,
                    gate_target_angle=directive.gate_target_angle,
                    reason=clean_reason,
                    risk_level=directive.risk_level,
                    emergency_stop=directive.emergency_stop,
                    measured_gate_angle=safe_angle,
                    measured_gate_state=safe_state,
                    execution_divergence_deg=safe_divergence,
                    issuer_type=directive.issuer_type,
                    issuer_id=directive.issuer_id,
                    correlation_id=directive.correlation_id,
                    device_session_epoch=session_epoch,
                    baseline_device_sequence_number=directive.baseline_device_sequence_number,
                    device_sequence_number=seq_num,
                    device_uptime_ms=uptime_ms,
                )
                self._record_directive_event_locked(event)
                self._active_directives[self.mode] = None

    def evaluate_verification_timeouts(self) -> list[ActuatorDirectiveEventContract]:
        """Checks for verification timeout (30s) across all active directives."""
        with self._lock:
            timeout_events = []
            now_dt = datetime.now(timezone.utc)
            for mode, directive in list(self._active_directives.items()):
                if directive is not None:
                    elapsed_s = (now_dt - directive.timestamp).total_seconds()
                    if elapsed_s >= settings.ACTUATOR_VERIFICATION_TIMEOUT_SEC:
                        evt = ActuatorDirectiveEventContract(
                            audit_id=build_verification_timeout_audit_id(directive.directive_id),
                            directive_id=directive.directive_id,
                            event_type=DirectiveEventType.VERIFICATION_TIMEOUT,
                            device_id=directive.device_id,
                            section_id=directive.section_id,
                            operational_mode=mode,
                            action=directive.action,
                            gate_target_angle=directive.gate_target_angle,
                            reason=f"Verification timeout after {settings.ACTUATOR_VERIFICATION_TIMEOUT_SEC:.0f}s window without observed physical alignment.",
                            risk_level=directive.risk_level,
                            emergency_stop=directive.emergency_stop,
                            issuer_type=directive.issuer_type,
                            issuer_id=directive.issuer_id,
                            correlation_id=directive.correlation_id,
                            device_session_epoch=directive.device_session_epoch,
                            baseline_device_sequence_number=directive.baseline_device_sequence_number,
                            timestamp=compute_verification_timeout_timestamp(
                                directive.timestamp, settings.ACTUATOR_VERIFICATION_TIMEOUT_SEC
                            ),
                        )
                        self._record_directive_event_locked(evt)
                        self._active_directives[mode] = None
                        timeout_events.append(evt)
            return timeout_events

    def set_gate_directive(self, directive: ActuatorDirectiveContract) -> None:
        """
        Thread-safe gate directive update with supervisory lifecycle tracking.
        SAFE_HOLD invariant: while in SAFE_HOLD, incoming non-SAFE_HOLD directives
        can NEVER replace the immutable fail-safe hold posture.
        """
        with self._lock:
            current_mode = self.mode
            if directive.operational_mode is None:
                directive.operational_mode = current_mode
            if self.is_safe_hold():
                if directive.action != "SAFE_HOLD_LOCK" or not directive.emergency_stop:
                    # Reject incoming operational directives to preserve fail-safe hold invariant
                    return

            # Resolve target device once per issuance; preserve SIMULATION without inventing hardware IDs
            raw_device_id = (
                directive.device_id.strip()
                if isinstance(directive.device_id, str) and directive.device_id.strip()
                else None
            )
            if current_mode == "PHYSICAL":
                resolved_device_id: Optional[str] = raw_device_id or "DRAINX-ESP32-NODE-01"
                directive.device_id = resolved_device_id
            else:
                resolved_device_id = raw_device_id
                directive.device_id = resolved_device_id

            # Guard against duplicate/conflicting ISSUED audit generation for the same directive_id
            existing_issued = next(
                (
                    evt
                    for evt in self._directive_audits
                    if evt.directive_id == directive.directive_id
                    and evt.event_type == DirectiveEventType.ISSUED
                ),
                None,
            )
            if existing_issued is not None:
                incoming_angle_q = quantize_numeric_5_2_decimal(directive.gate_target_angle, "gate_target_angle")
                existing_angle_q = quantize_numeric_5_2_decimal(
                    existing_issued.gate_target_angle, "gate_target_angle"
                )
                matches_core = (
                    existing_issued.section_id == directive.section_id
                    and existing_issued.device_id == resolved_device_id
                    and existing_issued.operational_mode == current_mode
                    and existing_issued.action == directive.action
                    and existing_angle_q == incoming_angle_q
                    and existing_issued.reason == (directive.reason or "").strip()
                    and existing_issued.risk_level == directive.risk_level
                    and existing_issued.emergency_stop == directive.emergency_stop
                    and existing_issued.issuer_type == directive.issuer_type
                    and existing_issued.issuer_id == directive.issuer_id
                    and existing_issued.correlation_id == directive.correlation_id
                    and (
                        directive.device_session_epoch is None
                        or directive.device_session_epoch == existing_issued.device_session_epoch
                    )
                    and (
                        directive.baseline_device_sequence_number is None
                        or directive.baseline_device_sequence_number == existing_issued.baseline_device_sequence_number
                    )
                )
                if matches_core:
                    directive.device_session_epoch = existing_issued.device_session_epoch
                    directive.baseline_device_sequence_number = existing_issued.baseline_device_sequence_number
                    return
                raise ValueError(
                    f"Directive '{directive.directive_id}' was already issued with conflicting attributes."
                )

            if self.is_safe_hold():
                self._safe_hold_gate_directive = directive

            # Check if previous active directive in current mode is being superseded
            prev_active = self._active_directives.get(current_mode)
            needed = 2 if (prev_active is not None and prev_active.directive_id != directive.directive_id) else 1
            max_size = getattr(settings, "DIRECTIVE_AUDIT_OUTBOX_MAX_SIZE", 500)
            if len(self._directive_audits_outbox) + needed > max_size:
                raise DirectiveAuditOutboxFullError(
                    f"Directive audit outbox capacity ({max_size}) exceeded; applying backpressure."
                )

            if prev_active is not None and prev_active.directive_id != directive.directive_id:
                supersede_event = ActuatorDirectiveEventContract(
                    audit_id=build_superseded_audit_id(prev_active.directive_id, directive.directive_id),
                    directive_id=prev_active.directive_id,
                    event_type=DirectiveEventType.SUPERSEDED,
                    device_id=prev_active.device_id,
                    section_id=prev_active.section_id,
                    operational_mode=current_mode,
                    action=prev_active.action,
                    gate_target_angle=prev_active.gate_target_angle,
                    reason=f"Superseded by newer directive {directive.directive_id}",
                    risk_level=prev_active.risk_level,
                    emergency_stop=prev_active.emergency_stop,
                    issuer_type=prev_active.issuer_type,
                    issuer_id=prev_active.issuer_id,
                    correlation_id=prev_active.correlation_id,
                    device_session_epoch=prev_active.device_session_epoch,
                    baseline_device_sequence_number=prev_active.baseline_device_sequence_number,
                )
                self._record_directive_event_locked(supersede_event)

            # Assign device baseline sequence number and session epoch only when a device identity is resolved
            if resolved_device_id is not None:
                session = self._device_sessions.get(resolved_device_id)
                if session is not None:
                    directive.baseline_device_sequence_number = session.last_seen_seq
                    directive.device_session_epoch = session.device_session_epoch

            # Store as active directive for this mode
            self._active_directives[current_mode] = directive
            if current_mode == "PHYSICAL":
                self._physical_latest_gate_directive = directive
            elif current_mode == "SIMULATION":
                self._sim_latest_gate_directive = directive

            # Record ISSUED event in append-only ledger
            issued_event = ActuatorDirectiveEventContract(
                audit_id=build_issued_audit_id(directive.directive_id),
                directive_id=directive.directive_id,
                event_type=DirectiveEventType.ISSUED,
                device_id=directive.device_id,
                section_id=directive.section_id,
                operational_mode=current_mode,
                action=directive.action,
                gate_target_angle=directive.gate_target_angle,
                reason=directive.reason,
                risk_level=directive.risk_level,
                emergency_stop=directive.emergency_stop,
                issuer_type=directive.issuer_type,
                issuer_id=directive.issuer_id,
                correlation_id=directive.correlation_id,
                device_session_epoch=directive.device_session_epoch,
                baseline_device_sequence_number=directive.baseline_device_sequence_number,
                timestamp=directive.timestamp,
            )
            self._record_directive_event_locked(issued_event)

            # Stage in delivery envelope buffer
            envelope = StagedDeliveryEnvelope(
                directive_id=directive.directive_id,
                gate_target_angle=directive.gate_target_angle,
                action=directive.action,
                emergency_stop=directive.emergency_stop,
                issued_timestamp=directive.timestamp,
            )
            self._ephemeral_delivery_buffer.append(envelope)

    def get_gate_directive(self) -> Optional[ActuatorDirectiveContract]:
        with self._lock:
            if self.is_safe_hold():
                return self._safe_hold_gate_directive
            elif self.is_physical():
                return self._physical_latest_gate_directive
            else:
                return self._sim_latest_gate_directive

    def get_active_directive(self, mode: Optional[str] = None) -> Optional[ActuatorDirectiveContract]:
        """Returns the currently active, unsettled directive in the specified or current mode."""
        with self._lock:
            m = mode or self.mode
            return self._active_directives.get(m)

    def get_directive_audits(
        self, directive_id: Optional[str] = None, limit: Optional[int] = 100
    ) -> list[ActuatorDirectiveEventContract]:
        """Retrieves in-memory directive audit events in chronological order."""
        with self._lock:
            if directive_id:
                events = [e for e in self._directive_audits if e.directive_id == directive_id]
            else:
                events = list(self._directive_audits)
            # Stable sort by timestamp only: events sharing a timestamp (coarse clock resolution)
            # retain true insertion/lifecycle order instead of alphabetical audit_id order.
            ordered = sorted(events, key=lambda x: x.timestamp)
            if limit is None:
                return ordered
            return ordered[-limit:]

    def flush_directive_audits_outbox(
        self, max_batch_size: Optional[int] = None
    ) -> list[ActuatorDirectiveEventContract]:
        """Flushes outbox events for database persistence in FIFO order."""
        with self._lock:
            if not self._directive_audits_outbox:
                return []
            if max_batch_size is None or max_batch_size >= len(self._directive_audits_outbox):
                flushed = list(self._directive_audits_outbox)
                self._directive_audits_outbox.clear()
                return flushed
            if max_batch_size <= 0:
                return []
            flushed = list(self._directive_audits_outbox[:max_batch_size])
            self._directive_audits_outbox = self._directive_audits_outbox[max_batch_size:]
            return flushed

    def restore_directive_audits_outbox(
        self, events: Sequence[ActuatorDirectiveEventContract]
    ) -> None:
        """
        Restores undelivered events back to the outbox upon persistence failure.
        - Deduplicates against existing events in the outbox by audit_id.
        - Prepends restored events ahead of newer events to preserve strict FIFO ordering.
        - Enforces bounded capacity; raises DirectiveAuditOutboxFullError if capacity exceeded.
        - Never silently evicts events.
        """
        if not events:
            return
        with self._lock:
            existing_ids = {e.audit_id for e in self._directive_audits_outbox}
            to_restore: list[ActuatorDirectiveEventContract] = []
            for e in events:
                if e.audit_id not in existing_ids:
                    existing_ids.add(e.audit_id)
                    to_restore.append(e)

            if not to_restore:
                return

            max_size = getattr(settings, "DIRECTIVE_AUDIT_OUTBOX_MAX_SIZE", 500)
            self._directive_audits_outbox = to_restore + self._directive_audits_outbox
            if len(self._directive_audits_outbox) > max_size:
                raise DirectiveAuditOutboxFullError(
                    f"Directive audit outbox capacity ({max_size}) exceeded after restoring "
                    f"{len(to_restore)} events; applying backpressure."
                )

    def get_directive_audits_outbox_count(self) -> int:
        """Returns the number of events currently queued in the volatile outbox."""
        with self._lock:
            return len(self._directive_audits_outbox)

    def reconcile_recovered_directive(
        self, directive: ActuatorDirectiveContract, latest_event_type: DirectiveEventType
    ) -> bool:
        """
        Reconciles recovered directives on startup with strict operational mode isolation:
        - Rejects terminal directives (only ISSUED / FEEDBACK_RECEIVED are eligible).
        - PHYSICAL directives must NEVER be reactivated across a backend restart.
        - SIMULATION directives are only restored into _active_directives["SIMULATION"]
          if the current process mode is SIMULATION.
        - SAFE_HOLD directives are only restored into _active_directives["SAFE_HOLD"]
          if the current process is in SAFE_HOLD.
        """
        with self._lock:
            if latest_event_type not in (DirectiveEventType.ISSUED, DirectiveEventType.FEEDBACK_RECEIVED):
                return False

            op_mode = directive.operational_mode
            if op_mode == "PHYSICAL":
                logger.warning(
                    "Reconciliation rejected physical directive '%s': physical directives must never be reactivated across backend restart.",
                    directive.directive_id,
                )
                return False

            if op_mode == "SIMULATION":
                if self.mode == "SIMULATION":
                    self._active_directives["SIMULATION"] = directive
                    self._sim_latest_gate_directive = directive
                    return True
                logger.warning(
                    "Reconciliation skipped simulation directive '%s': process mode is '%s'.",
                    directive.directive_id,
                    self.mode,
                )
                return False

            if op_mode == "SAFE_HOLD" or (directive.action == "SAFE_HOLD_LOCK" and directive.emergency_stop):
                if self.is_safe_hold():
                    self._active_directives["SAFE_HOLD"] = directive
                    self._safe_hold_gate_directive = directive
                    return True
                return False

            return False

    # Mechanism State
    def get_mechanism_status(self) -> MechanismStatusContract:
        with self._lock:
            if self.is_physical() or self.is_safe_hold():
                return self._physical_mechanism
            return self._sim_mechanism

    def update_mechanism_status(self, status: MechanismStatusContract) -> None:
        with self._lock:
            if self.is_physical() or self.is_safe_hold():
                self._physical_mechanism = status
            else:
                self._sim_mechanism = status

    # Faults
    def record_fault(self, fault: FaultEventContract) -> None:
        with self._lock:
            if self.is_physical() or self.is_safe_hold():
                self._physical_faults[fault.fault_id] = fault
            else:
                self._sim_faults[fault.fault_id] = fault

    def get_active_faults(self) -> list[FaultEventContract]:
        with self._lock:
            fault_map = self._physical_faults if (self.is_physical() or self.is_safe_hold()) else self._sim_faults
            return [f for f in fault_map.values() if f.active]

    def clear_faults(self) -> None:
        with self._lock:
            fault_map = self._physical_faults if (self.is_physical() or self.is_safe_hold()) else self._sim_faults
            for f in fault_map.values():
                f.active = False

    # Scenarios & Benchmarks
    def set_active_scenario(self, scenario_name: Optional[str]) -> None:
        with self._lock:
            self._active_scenario = scenario_name

    def get_active_scenario(self) -> Optional[str]:
        with self._lock:
            return self._active_scenario

    def set_benchmark_results(self, results: BenchmarkMetricsContract) -> None:
        with self._lock:
            self._latest_benchmark = results

    def get_benchmark_results(self) -> Optional[BenchmarkMetricsContract]:
        with self._lock:
            return self._latest_benchmark

    def get_system_status(self) -> SystemStatusContract:
        with self._lock:
            active_alerts = len(self.get_alerts(active_only=True))
            uptime = time.time() - self._start_time
            latest_readings = self.get_latest_readings()
            return SystemStatusContract(
                mode=self.mode,
                operational_state=self.operational_state,
                uptime_seconds=round(uptime, 1),
                active_alerts_count=active_alerts,
                last_heartbeat=datetime.now(timezone.utc),
                latest_readings=latest_readings,
                active_prediction=self.get_prediction(),
                active_blockage=self.get_active_blockage(),
                active_gate_directive=self.get_gate_directive(),
                mechanism=self.get_mechanism_status(),
                active_scenario=self._active_scenario if self.is_simulation() else None,
            )


    # Citizen & Municipal Incident Management
    def seed_demo_incidents(self) -> None:
        demo_items = [
            IncidentResponseContract(
                id="INC-DEMO-01",
                category=IncidentCategory.DRAIN_OVERFLOW,
                description="Severe storm runoff overflowing culvert embankment near St. Inez Church.",
                latitude=15.4920,
                longitude=73.8185,
                severity=IncidentSeverity.CRITICAL,
                status=IncidentStatus.INVESTIGATING,
                source=IncidentSource.DEMO,
                reporter_name="St. Inez Ward Committee",
                assigned_to="Team Alpha — St. Inez Drainage Crew",
                assignment_type=AssignmentType.TEAM,
                assigned_team_id="TEAM-ALPHA",
                municipal_notes="High-capacity dewatering pump dispatched to site.",
                origin_operational_mode="SIMULATION",
            ),
            IncidentResponseContract(
                id="INC-DEMO-02",
                category=IncidentCategory.WATERLOGGING,
                description="Street waterlogging of 20cm depth blocking pedestrian access near Patto Plaza commercial district.",
                latitude=15.4989,
                longitude=73.8342,
                severity=IncidentSeverity.HIGH,
                status=IncidentStatus.ASSIGNED,
                source=IncidentSource.DEMO,
                reporter_name="Patto Commercial Association",
                assigned_to="Team Beta — Patto Rapid Response",
                assignment_type=AssignmentType.TEAM,
                assigned_team_id="TEAM-BETA",
                municipal_notes="Suction tanker scheduled for 14:00 drain vacuuming.",
                origin_operational_mode="SIMULATION",
            ),
            IncidentResponseContract(
                id="INC-DEMO-03",
                category=IncidentCategory.DRAIN_BLOCKAGE,
                description="Accumulation of construction debris and plastic waste obstructing stone masonry drain along Rua 31 de Janeiro.",
                latitude=15.4965,
                longitude=73.8305,
                severity=IncidentSeverity.MEDIUM,
                status=IncidentStatus.VERIFIED,
                source=IncidentSource.DEMO,
                reporter_name="Fontainhas Heritage Watch",
                assigned_to="Team Gamma — Fontainhas Heritage Maintenance",
                assignment_type=AssignmentType.TEAM,
                assigned_team_id="TEAM-GAMMA",
                municipal_notes="Verified by municipal field inspector. Manual clearing required.",
                origin_operational_mode="SIMULATION",
            ),
            IncidentResponseContract(
                id="INC-DEMO-04",
                category=IncidentCategory.INFRASTRUCTURE_DAMAGE,
                description="Displaced concrete grating slab over main arterial drain box near Miramar Circle.",
                latitude=15.4835,
                longitude=73.8078,
                severity=IncidentSeverity.LOW,
                status=IncidentStatus.RESOLVED,
                source=IncidentSource.DEMO,
                reporter_name="Panaji Municipal Patrol",
                assigned_to="Team Delta — Miramar Outfall Sluice Unit",
                assignment_type=AssignmentType.TEAM,
                assigned_team_id="TEAM-DELTA",
                municipal_notes="Grating slab repositioned and secured with structural steel anchors.",
                origin_operational_mode="SIMULATION",
            ),
        ]
        with self._lock:
            for item in demo_items:
                if item.id not in self._incidents:
                    self._incidents[item.id] = item
                    self._bump_incident_version_locked(item.id)
                    # Seed corresponding audit history for demo inspection
                    self._incident_audits[item.id] = [
                        IncidentAuditContract(
                            incident_id=item.id,
                            actor_id=item.reporter_name or "panaji-citizen-seed",
                            actor_role="citizen",
                            action="REPORTED",
                            new_status=IncidentStatus.REPORTED.value,
                            new_severity=item.severity.value,
                            reason="Initial citizen hazard report submission",
                        )
                    ]
                    if item.status != IncidentStatus.REPORTED:
                        self._incident_audits[item.id].append(
                            IncidentAuditContract(
                                incident_id=item.id,
                                actor_id="muni-dispatcher-seed",
                                actor_role="municipality",
                                action="ASSIGNED" if item.assigned_to else "STATUS_CHANGE",
                                previous_status=IncidentStatus.REPORTED.value,
                                new_status=item.status.value,
                                new_assigned_to=item.assigned_to,
                                new_assignment_type=item.assignment_type.value,
                                new_assigned_team_id=item.assigned_team_id,
                                new_assigned_worker_id=item.assigned_worker_id,
                                reason=item.municipal_notes or "Operational state progression",
                            )
                        )



    def create_incident(self, incident: IncidentResponseContract) -> IncidentResponseContract:
        with self._lock:
            if not incident.origin_operational_mode:
                incident.origin_operational_mode = (
                    "SIMULATION" if self.is_simulation() else ("SAFE_HOLD" if self.is_safe_hold() else "PHYSICAL")
                )

            audit = IncidentAuditContract(
                incident_id=incident.id,
                actor_id=incident.reporter_name or "citizen",
                actor_role="citizen",
                action="REPORTED",
                new_status=incident.status.value,
                new_severity=incident.severity.value,
                reason="Initial hazard report submission",
            )

            from app.services.persistence_repository import persistence_repo

            # Configured cloud persistence must use the atomic RPC.
            # Never fall back to separate incident and audit writes.
            if persistence_repo.is_configured:
                cloud_res = persistence_repo.execute_citizen_incident_creation_sync(
                    incident_id=incident.id,
                    category=(
                        incident.category.value
                        if hasattr(incident.category, "value")
                        else str(incident.category)
                    ),
                    description=incident.description,
                    latitude=incident.latitude,
                    longitude=incident.longitude,
                    severity=(
                        incident.severity.value
                        if hasattr(incident.severity, "value")
                        else str(incident.severity)
                    ),
                    source=(
                        incident.source.value
                        if hasattr(incident.source, "value")
                        else str(incident.source)
                    ),
                    reporter_name=incident.reporter_name or "Citizen Anonymous",
                    photos=incident.photos,
                    audit_id=audit.audit_id,
                    origin_operational_mode=incident.origin_operational_mode,
                )

                if (
                    not isinstance(cloud_res, dict)
                    or cloud_res.get("id") != incident.id
                ):
                    raise RuntimeError(
                        "Citizen incident creation was not confirmed "
                        "by Supabase. Local incident creation aborted."
                    )

            # Only update local state after successful cloud persistence,
            # or when running without Supabase in local development.
            self._audit_durability.append_audit(audit)
            self._incidents[incident.id] = incident
            self._bump_incident_version_locked(incident.id)
            self._incident_audits[incident.id] = [audit]

            return incident

    def delete_incident(self, incident_id: str) -> bool:
        """Thread-safely removes an incident from memory and advances its mutation version."""
        with self._lock:
            existed = self._incidents.pop(incident_id, None) is not None
            self._bump_incident_version_locked(incident_id)
            return existed

    def _reconcile_cloud_incident_locked(
        self,
        incident_id: str,
        fetched: Optional[IncidentResponseContract],
        *,
        authoritative_cloud: bool,
        start_clear_gen: int,
        start_version: int,
        start_present: bool,
        start_updated_at: Optional[datetime],
    ) -> Optional[IncidentResponseContract]:
        """Reconciles a cloud-fetched incident against local state while holding self._lock."""
        if self._incidents_clear_generation != start_clear_gen:
            return self._incidents.get(incident_id)

        current_version = self._incident_versions.get(incident_id, 0)
        current_local = self._incidents.get(incident_id)
        current_updated_at = current_local.updated_at if current_local is not None else None

        concurrent_mutation = (
            current_version != start_version
            or (start_present and current_local is None)
            or (not start_present and current_local is not None)
            or (
                start_present
                and current_local is not None
                and start_updated_at is not None
                and current_updated_at is not None
                and current_updated_at != start_updated_at
            )
        )

        if concurrent_mutation:
            if current_local is None:
                return None
            if fetched is None:
                return current_local
            if _is_timestamp_strictly_newer(fetched.updated_at, current_local.updated_at):
                self._incidents[incident_id] = fetched
                self._bump_incident_version_locked(incident_id)
                return fetched
            return current_local

        if fetched is not None:
            self._incidents[incident_id] = fetched
            self._bump_incident_version_locked(incident_id)
            return fetched

        if authoritative_cloud and current_local is not None:
            self._incidents.pop(incident_id, None)
            self._bump_incident_version_locked(incident_id)
        return None

    def get_incident(
        self, incident_id: str, authoritative_cloud: bool = False
    ) -> Optional[IncidentResponseContract]:
        from app.services.persistence_repository import persistence_repo

        cloud_enabled = bool(
            persistence_repo.is_configured or persistence_repo.is_storage_configured
        )
        with self._lock:
            start_clear_gen = self._incidents_clear_generation
            start_version = self._incident_versions.get(incident_id, 0)
            local_incident = self._incidents.get(incident_id)
            start_present = local_incident is not None
            start_updated_at = (
                local_incident.updated_at if local_incident is not None else None
            )
            if not authoritative_cloud and local_incident is not None:
                return local_incident

        if not cloud_enabled:
            return local_incident if authoritative_cloud else None

        row = persistence_repo.query_incident_by_id_sync(incident_id)
        fetched = IncidentResponseContract.model_validate(row) if row else None

        with self._lock:
            return self._reconcile_cloud_incident_locked(
                incident_id,
                fetched,
                authoritative_cloud=authoritative_cloud,
                start_clear_gen=start_clear_gen,
                start_version=start_version,
                start_present=start_present,
                start_updated_at=start_updated_at,
            )

    def get_incidents_by_ids(
        self,
        incident_ids: Sequence[str],
        *,
        authoritative_cloud: bool = False,
    ) -> dict[str, Optional[IncidentResponseContract]]:
        """
        Bounded bulk incident resolution for duplicate queues.
        Captures local versions under self._lock, performs any required cloud bulk
        query completely outside self._lock, and reconciles under self._lock without
        allowing stale cloud rows to overwrite newer local mutations or resurrections.
        """
        unique_ids = list(dict.fromkeys(inc_id for inc_id in incident_ids if inc_id))
        if not unique_ids:
            return {}

        from app.services.persistence_repository import persistence_repo

        cloud_enabled = bool(
            persistence_repo.is_configured or persistence_repo.is_storage_configured
        )
        with self._lock:
            start_clear_gen = self._incidents_clear_generation
            snapshots: dict[
                str,
                tuple[int, bool, Optional[datetime], Optional[IncidentResponseContract]],
            ] = {}
            for inc_id in unique_ids:
                local_inc = self._incidents.get(inc_id)
                snapshots[inc_id] = (
                    self._incident_versions.get(inc_id, 0),
                    local_inc is not None,
                    local_inc.updated_at if local_inc is not None else None,
                    local_inc,
                )

            if not cloud_enabled:
                return {inc_id: snapshots[inc_id][3] for inc_id in unique_ids}

            ids_to_fetch = (
                unique_ids
                if authoritative_cloud
                else [inc_id for inc_id in unique_ids if snapshots[inc_id][3] is None]
            )

        if not ids_to_fetch:
            return {inc_id: snapshots[inc_id][3] for inc_id in unique_ids}

        raw_rows_by_id = persistence_repo.query_incidents_by_ids_sync(ids_to_fetch)
        if not isinstance(raw_rows_by_id, dict):
            raise RuntimeError("Bulk incident lookup returned invalid response shape.")

        fetched_by_id: dict[str, IncidentResponseContract] = {
            inc_id: IncidentResponseContract.model_validate(row)
            for inc_id, row in raw_rows_by_id.items()
            if row is not None
        }

        fetch_set = set(ids_to_fetch)
        with self._lock:
            resolved: dict[str, Optional[IncidentResponseContract]] = {}
            for inc_id in unique_ids:
                start_version, start_present, start_updated_at, local_inc = snapshots[inc_id]
                if inc_id not in fetch_set:
                    resolved[inc_id] = local_inc
                    continue
                resolved[inc_id] = self._reconcile_cloud_incident_locked(
                    inc_id,
                    fetched_by_id.get(inc_id),
                    authoritative_cloud=authoritative_cloud,
                    start_clear_gen=start_clear_gen,
                    start_version=start_version,
                    start_present=start_present,
                    start_updated_at=start_updated_at,
                )
            return resolved

    def get_incident_kpis(self) -> dict[str, Any]:
        """
        Calculates authoritative municipal incident KPIs across the entire incident population.
        Guarantees server-side consistency without relying on paginated client slices.
        """
        with self._lock:
            all_incidents = list(self._incidents.values())
            # Terminal states: both RESOLVED and REJECTED incidents are terminal
            # and MUST be excluded from active operational queues and open metrics.
            terminal_statuses = {
                IncidentStatus.RESOLVED,
                IncidentStatus.REJECTED,
                IncidentStatus.RESOLVED.value,
                IncidentStatus.REJECTED.value,
            }
            open_items = [
                i for i in all_incidents
                if i.status not in terminal_statuses
            ]

            by_cat: dict[str, int] = {cat.value: 0 for cat in IncidentCategory}
            for i in open_items:
                cat_val = i.category.value if hasattr(i.category, "value") else str(i.category)
                by_cat[cat_val] = by_cat.get(cat_val, 0) + 1

            by_sev: dict[str, int] = {sev.value: 0 for sev in IncidentSeverity}
            for i in open_items:
                sev_val = i.severity.value if hasattr(i.severity, "value") else str(i.severity)
                by_sev[sev_val] = by_sev.get(sev_val, 0) + 1

            by_st: dict[str, int] = {st.value: 0 for st in IncidentStatus}
            for i in all_incidents:
                st_val = i.status.value if hasattr(i.status, "value") else str(i.status)
                by_st[st_val] = by_st.get(st_val, 0) + 1

            demo_count = len([i for i in all_incidents if i.source == IncidentSource.DEMO or i.id.startswith("INC-DEMO")])
            genuine_count = len([i for i in all_incidents if i.source != IncidentSource.DEMO and not i.id.startswith("INC-DEMO")])

            by_src: dict[str, int] = {src.value: 0 for src in IncidentSource}
            for i in all_incidents:
                src_val = i.source.value if hasattr(i.source, "value") else str(i.source)
                by_src[src_val] = by_src.get(src_val, 0) + 1

            return {
                "total_incidents": len(all_incidents),
                "open_incidents": len(open_items),
                "critical_or_high_incidents": len([
                    i for i in open_items
                    if i.severity in (IncidentSeverity.CRITICAL, IncidentSeverity.HIGH, "CRITICAL", "HIGH")
                ]),
                "unassigned_incidents": len([
                    i for i in open_items
                    if not i.assigned_to or not i.assigned_to.strip()
                ]),
                "assigned_incidents": len([
                    i for i in open_items
                    if i.assigned_to and i.assigned_to.strip()
                ]),
                "investigating_incidents": len([
                    i for i in open_items
                    if i.status in (IncidentStatus.INVESTIGATING, IncidentStatus.INVESTIGATING.value)
                ]),
                "resolved_incidents": len([
                    i for i in all_incidents
                    if i.status in (IncidentStatus.RESOLVED, IncidentStatus.RESOLVED.value)
                ]),
                "rejected_incidents": len([
                    i for i in all_incidents
                    if i.status in (IncidentStatus.REJECTED, IncidentStatus.REJECTED.value)
                ]),
                "demo_incidents_count": demo_count,
                "genuine_incidents_count": genuine_count,
                "by_category": by_cat,
                "by_severity": by_sev,
                "by_status": by_st,
                "by_source": by_src,
            }

    def get_incidents_paginated(
        self,
        status: Optional[IncidentStatus] = None,
        category: Optional[IncidentCategory] = None,
        severity: Optional[IncidentSeverity] = None,
        source: Optional[IncidentSource] = None,
        assigned_to: Optional[str] = None,
        search: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
        is_staff_search: bool = False,
    ) -> tuple[list[IncidentResponseContract], int]:
        """
        Retrieves filtered and paginated incidents with total matching count.
        Enforces privacy-bounded search to eliminate side-channel reconnaissance.
        """
        with self._lock:
            incidents = list(self._incidents.values())

            if status:
                incidents = [i for i in incidents if i.status == status]
            if category:
                incidents = [i for i in incidents if i.category == category]
            if severity:
                incidents = [i for i in incidents if i.severity == severity]
            if source:
                incidents = [i for i in incidents if i.source == source]

            if assigned_to:
                norm_assigned = assigned_to.strip().upper()
                if norm_assigned == "UNASSIGNED":
                    incidents = [i for i in incidents if not i.assigned_to or not i.assigned_to.strip()]
                elif norm_assigned == "ASSIGNED":
                    incidents = [i for i in incidents if i.assigned_to and i.assigned_to.strip()]
                else:
                    target = assigned_to.strip().lower()
                    incidents = [i for i in incidents if target in (i.assigned_to or "").lower()]

            if search and search.strip():
                query = search.strip().lower()
                if is_staff_search:
                    # Authorized staff search across queue fields, but NEVER internal_notes
                    incidents = [
                        i for i in incidents
                        if query in i.id.lower()
                        or query in i.description.lower()
                        or query in (i.assigned_to or "").lower()
                        or query in (i.municipal_notes or "").lower()
                    ]
                else:
                    # Public / Citizen search: Strictly restricted to public ID and description
                    # Prevents side-channel reconnaissance on municipal notes or staff assignments
                    incidents = [
                        i for i in incidents
                        if query in i.id.lower()
                        or query in i.description.lower()
                    ]

            if start_date:
                sd = start_date if start_date.tzinfo else start_date.replace(tzinfo=timezone.utc)
                incidents = [i for i in incidents if i.created_at >= sd]

            if end_date:
                ed = end_date if end_date.tzinfo else end_date.replace(tzinfo=timezone.utc)
                incidents = [i for i in incidents if i.created_at <= ed]

            sorted_incidents = sorted(incidents, key=lambda x: x.created_at, reverse=True)
            total_count = len(sorted_incidents)
            paged = sorted_incidents[offset : offset + limit] if limit > 0 else sorted_incidents[offset:]
            return paged, total_count

    def get_incidents(
        self,
        status: Optional[IncidentStatus] = None,
        category: Optional[IncidentCategory] = None,
        severity: Optional[IncidentSeverity] = None,
        source: Optional[IncidentSource] = None,
        assigned_to: Optional[str] = None,
        search: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: Optional[int] = None,
        offset: int = 0,
        is_staff_search: bool = False,
    ) -> list[IncidentResponseContract]:
        with self._lock:
            paged, _ = self.get_incidents_paginated(
                status=status,
                category=category,
                severity=severity,
                source=source,
                assigned_to=assigned_to,
                search=search,
                start_date=start_date,
                end_date=end_date,
                limit=limit if limit is not None else len(self._incidents),
                offset=offset,
                is_staff_search=is_staff_search,
            )
            return paged

    def update_incident(
        self,
        incident_id: str,
        update: IncidentUpdateContract,
        actor_id: str = "system",
        actor_role: str = "system",
        action_reason: Optional[str] = None,
        action_type: Optional[str] = None,
    ) -> Optional[IncidentResponseContract]:
        with self._lock:
            incident = self._incidents.get(incident_id)
            if not incident:
                return None

            prev_status = incident.status.value
            prev_severity = incident.severity.value
            prev_assigned = incident.assigned_to
            prev_assignment_type = incident.assignment_type.value
            prev_assigned_team_id = incident.assigned_team_id
            prev_assigned_worker_id = incident.assigned_worker_id

            # Snapshot incident for atomic rollback in case of audit persistence failure
            incident_snapshot = incident.model_copy(deep=True)

            # Terminal incidents are completely immutable through ordinary updates.
            if incident.status in (
                IncidentStatus.RESOLVED,
                IncidentStatus.REJECTED,
            ):
                raise ValueError(
                    f"Cannot modify terminal incident '{incident.id}' "
                    f"in status '{incident.status.value}'."
                )
            # Workers cannot modify assignment metadata, internal notes, or supervisory fields through direct store calls.
            if actor_role == "worker":
                protected_worker_fields = {
                    "assigned_to",
                    "assignment_type",
                    "assigned_team_id",
                    "assigned_worker_id",
                    "internal_notes",
                    "verified_by",
                    "rejection_reason",
                }

                submitted_protected_fields = (
                    update.model_fields_set & protected_worker_fields
                )

                if submitted_protected_fields:
                    violating = sorted(submitted_protected_fields)[0]
                    if violating in ("assigned_to", "assignment_type", "assigned_team_id", "assigned_worker_id"):
                        raise ValueError(
                            "Field workers are not permitted to reassign incidents "
                            "or modify assignment metadata."
                        )
                    elif violating == "internal_notes":
                        raise ValueError("Field workers are not permitted to set internal municipal notes.")
                    else:
                        raise ValueError(f"Field workers are not permitted to modify supervisory field '{violating}'.")
            # 2. Pre-validate status transition before applying ANY field mutations (Atomic Protection)
            if update.status is not None and update.status != incident.status:
                if not validate_incident_status_transition(incident.status, update.status):
                    raise ValueError(
                        f"Illegal status transition from {incident.status.value} to {update.status.value}"
                    )

            status_changed = False
            severity_changed = False
            assignment_changed = False

            if update.severity is not None and update.severity != incident.severity:
                incident.severity = update.severity
                severity_changed = True

            if update.status is not None and update.status != incident.status:
                incident.status = update.status
                status_changed = True

            if update.assigned_to is not None and update.assigned_to != incident.assigned_to:
                incident.assigned_to = update.assigned_to if update.assigned_to.strip() else None
                assignment_changed = True

            if update.assignment_type is not None:
                incident.assignment_type = update.assignment_type

            if update.assigned_team_id is not None:
                incident.assigned_team_id = update.assigned_team_id if update.assigned_team_id.strip() else None

            if update.assigned_worker_id is not None:
                incident.assigned_worker_id = update.assigned_worker_id if update.assigned_worker_id.strip() else None

            # Canonicalize the complete assignment snapshot before persistence.
            # Legacy/in-memory records can contain empty strings or stale assignment
            # metadata even when their assignment type is NONE. The cloud RPC expects
            # NONE to mean every assignment field is SQL NULL.
            if incident.assignment_type == AssignmentType.NONE:
                incident.assigned_to = None
                incident.assigned_team_id = None
                incident.assigned_worker_id = None
            else:
                incident.assigned_to = incident.assigned_to.strip() if incident.assigned_to and incident.assigned_to.strip() else None
                incident.assigned_team_id = incident.assigned_team_id.strip() if incident.assigned_team_id and incident.assigned_team_id.strip() else None
                incident.assigned_worker_id = incident.assigned_worker_id.strip() if incident.assigned_worker_id and incident.assigned_worker_id.strip() else None

            if update.rejection_reason is not None:
                incident.rejection_reason = update.rejection_reason

            if update.verified_by is not None:
                incident.verified_by = update.verified_by
                incident.verified_at = datetime.now(timezone.utc)

            if update.municipal_notes is not None:
                incident.municipal_notes = update.municipal_notes

            if "internal_notes" in update.model_fields_set:
                incident.internal_notes = update.internal_notes

            if update.photos is not None:
                incident.photos = update.photos[:3]

            incident.updated_at = datetime.now(timezone.utc)

            # Record durable operational audit entry
            resolved_action = action_type
            if not resolved_action:
                if assignment_changed:
                    if not incident.assigned_to:
                        resolved_action = "UNASSIGNED"
                    elif prev_assigned:
                        resolved_action = "REASSIGNED"
                    else:
                        resolved_action = "ASSIGNED"
                elif update.status == IncidentStatus.VERIFIED and status_changed:
                    resolved_action = "VERIFIED"
                elif update.status == IncidentStatus.REJECTED and status_changed:
                    resolved_action = "REJECTED"
                elif update.status == IncidentStatus.RESOLVED and status_changed:
                    resolved_action = "RESOLVED"
                elif severity_changed:
                    resolved_action = "PRIORITIZED"
                elif status_changed:
                    resolved_action = f"STATUS_TO_{incident.status.value}"
                else:
                    resolved_action = "UPDATE"

            audit_entry = IncidentAuditContract(
                incident_id=incident.id,
                actor_id=actor_id,
                actor_role=actor_role,
                action=resolved_action,
                previous_status=prev_status if status_changed else None,
                new_status=incident.status.value if status_changed else None,
                previous_assigned_to=prev_assigned if assignment_changed else None,
                new_assigned_to=incident.assigned_to if assignment_changed else None,
                previous_assignment_type=prev_assignment_type if assignment_changed else None,
                new_assignment_type=incident.assignment_type.value if assignment_changed else None,
                previous_assigned_team_id=prev_assigned_team_id if assignment_changed else None,
                new_assigned_team_id=incident.assigned_team_id if assignment_changed else None,
                previous_assigned_worker_id=prev_assigned_worker_id if assignment_changed else None,
                new_assigned_worker_id=incident.assigned_worker_id if assignment_changed else None,
                previous_severity=prev_severity if severity_changed else None,
                new_severity=incident.severity.value if severity_changed else None,
                reason=action_reason or update.rejection_reason or update.municipal_notes,
                internal_notes=update.internal_notes,
                timestamp=incident.updated_at,
            )

            # In configured cloud mode, execute atomic PostgreSQL RPC transaction
            from app.services.persistence_repository import persistence_repo
            if persistence_repo.is_configured:
                rpc_result = persistence_repo.execute_municipal_incident_transaction_sync(
                    incident_id=incident.id,
                    new_status=incident.status.value if status_changed else None,
                    new_severity=incident.severity.value if severity_changed else None,
                    assigned_to=incident.assigned_to,
                    assignment_type=incident.assignment_type.value,
                    assigned_team_id=incident.assigned_team_id,
                    assigned_worker_id=incident.assigned_worker_id,
                    municipal_notes=incident.municipal_notes,
                    internal_notes=incident.internal_notes,
                    rejection_reason=incident.rejection_reason,
                    verified_by=incident.verified_by,
                    actor_id=actor_id,
                    actor_role=actor_role,
                    action=resolved_action,
                    reason=action_reason or update.rejection_reason or update.municipal_notes,
                    audit_id=audit_entry.audit_id,
                )
                if not isinstance(rpc_result, dict) or rpc_result.get("id") != incident.id:
                    self._incidents[incident_id] = incident_snapshot
                    raise RuntimeError(
                        f"Atomic municipal cloud transaction failed or returned an invalid incident "
                        f"for '{incident_id}'. Operation aborted."
                    )
            # Atomicity guarantee: Attempt durable local journal append
            append_ok = self._audit_durability.append_audit(audit_entry)
            if not append_ok:
                # Rollback incident state in memory so incident mutation and audit never diverge
                self._incidents[incident_id] = incident_snapshot
                logger.error(f"Audit append failed for incident {incident_id}. Rolled back in-memory mutation.")
                raise RuntimeError(f"Failed to record durable audit event for incident '{incident_id}'. Incident mutation was rolled back.")

            self._bump_incident_version_locked(incident_id)
            self._incident_audits.setdefault(incident.id, []).append(audit_entry)
            return incident

    def record_incident_audit(self, entry: IncidentAuditContract) -> None:
        """Appends a custom operational audit record to the incident's ledger and durable store."""
        with self._lock:
            self._incident_audits.setdefault(entry.incident_id, []).append(entry)
            self._audit_durability.append_audit(entry)

    def clear_audits_for_testing(self) -> None:
        """Cleanly wipes audit history for isolated unit testing."""
        with self._lock:
            self._incident_audits.clear()
            self._audit_durability.clear_for_testing()

    def get_incident_audits(self, incident_id: str) -> list[IncidentAuditContract]:
        """
        Returns chronological audit ledger for an incident.
        In cloud mode with configured Supabase, fetches authoritative records from Supabase Cloud
        outside self._lock. Falls back seamlessly to local in-memory/journal records.
        """
        from app.services.persistence_repository import persistence_repo
        if persistence_repo.is_configured:
            cloud_records = persistence_repo.query_incident_audits_sync(incident_id, strict=True)
            if cloud_records:
                parsed_audits = [IncidentAuditContract(**rec) for rec in cloud_records]
                return sorted(parsed_audits, key=lambda a: a.timestamp)
            return []

        with self._lock:
            audits = self._incident_audits.get(incident_id, [])
            return sorted(audits, key=lambda a: a.timestamp)

    def get_field_teams(self) -> list[FieldTeamContract]:
        """Returns registered authoritative field response crews."""
        return [t for t in AUTHORITATIVE_FIELD_TEAMS if t.is_active]

    def attach_incident_photos(
        self,
        incident_id: str,
        new_photos: list[str],
        audit_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        actor_role: Optional[str] = None,
        files_to_cleanup_on_failure: Optional[list[Any]] = None,
    ) -> Optional[IncidentResponseContract]:
        with self._lock:
            incident = self._incidents.get(incident_id)
            if incident is None:
                from app.services.persistence_repository import persistence_repo
                need_cloud_lookup = bool(
                    persistence_repo.is_configured or persistence_repo.is_storage_configured
                )
            else:
                need_cloud_lookup = False

        if need_cloud_lookup:
            fetched = self.get_incident(incident_id, authoritative_cloud=False)
            if not fetched:
                return None

        with self._lock:
            incident = self._incidents.get(incident_id)
            if not incident:
                return None

            added_photos: list[str] = []
            for p in new_photos:
                if len(incident.photos) >= 3:
                    break
                if p not in incident.photos:
                    incident.photos.append(p)
                    added_photos.append(p)

            incident.updated_at = datetime.now(timezone.utc)

            # Local durable audit append if actor attribution is provided
            if audit_id and actor_id and actor_role:
                audit_entry = IncidentAuditContract(
                    audit_id=audit_id,
                    incident_id=incident_id,
                    actor_id=actor_id,
                    actor_role=actor_role,
                    action="ATTACH_PHOTOS",
                    new_status=incident.status,
                    new_severity=incident.severity,
                    reason=f"ATTACH_PHOTOS count:{len(added_photos)}",
                    timestamp=datetime.now(timezone.utc),
                )
                try:
                    append_ok = self._audit_durability.append_audit(audit_entry)
                except Exception:
                    append_ok = False

                if not append_ok:
                    # Rollback photos from in-memory incident
                    for p in added_photos:
                        if p in incident.photos:
                            incident.photos.remove(p)
                    if files_to_cleanup_on_failure:
                        for f in files_to_cleanup_on_failure:
                            try:
                                if hasattr(f, "unlink"):
                                    f.unlink(missing_ok=True)
                            except Exception:
                                pass
                    raise RuntimeError("Durable audit journal append failed for photo attachment.")

                self._incident_audits.setdefault(incident_id, []).append(audit_entry)

            self._bump_incident_version_locked(incident_id)
            return incident

    def is_photo_registered(self, filename: str) -> bool:
        """Checks if a photo filename is associated with any incident in the store."""
        target = f"/api/v1/incidents/photos/{filename}"
        with self._lock:
            for inc in self._incidents.values():
                if target in inc.photos or any(p.endswith(filename) for p in inc.photos):
                    return True
        return False


    def clear_scenario_outputs(self) -> None:
        """Clear scenario-specific blockage, prediction, and actuator output state in the active partition."""
        with self._lock:
            if self.is_physical() or self.is_safe_hold():
                if self._physical_active_blockage:
                    self._physical_active_blockage.is_active = False
                self._physical_active_blockage = None
                self._physical_latest_prediction = None
                self._physical_latest_gate_directive = None
            else:
                if self._sim_active_blockage:
                    self._sim_active_blockage.is_active = False
                self._sim_active_blockage = None
                self._sim_latest_prediction = None
                self._sim_latest_gate_directive = None

    # Duplicate Incident Links Management
    def record_duplicate_link(self, link: DuplicateLinkContract) -> bool:
        """
        Stores a canonical undirected duplicate link in memory if the pair does
        not already exist (mirrors ON CONFLICT (incident_low_id, incident_high_id) DO NOTHING).
        Preserves all existing SUSPECTED, CONFIRMED, and DISMISSED records.
        """
        with self._lock:
            for existing in self._duplicate_links.values():
                if (
                    existing.incident_low_id == link.incident_low_id
                    and existing.incident_high_id == link.incident_high_id
                ):
                    return False
            self._duplicate_links[link.link_id] = link
            return True

    def get_duplicate_links(self, status: Optional[str] = None) -> list[DuplicateLinkContract]:
        """Returns all duplicate links in memory, optionally filtered by link_status."""
        with self._lock:
            links = list(self._duplicate_links.values())
            if status:
                clean_status = status.upper().strip()
                links = [
                    l for l in links
                    if l.link_status.value == clean_status or str(l.link_status) == clean_status
                ]
            return sorted(
                links,
                key=lambda l: (-_normalize_utc_timestamp(l.created_at).timestamp(), l.link_id),
            )

    def get_incident_duplicate_links(self, incident_id: str) -> list[DuplicateLinkContract]:
        """Returns all duplicate links involving incident_id (as low or high member)."""
        with self._lock:
            links = [
                l for l in self._duplicate_links.values()
                if l.incident_low_id == incident_id or l.incident_high_id == incident_id
            ]
            return sorted(
                links,
                key=lambda l: (-_normalize_utc_timestamp(l.created_at).timestamp(), l.link_id),
            )

    def review_duplicate_link(
        self,
        link_id: str,
        target_status: str,
        actor_id: str,
        actor_role: str,
        reason: str,
        primary_incident_id: Optional[str] = None,
        internal_notes: Optional[str] = None,
        override: bool = False,
        expected_version: Optional[int] = None,
    ) -> DuplicateLinkContract:
        """
        Reviews a canonical duplicate link in memory, mirroring Migration 007's
        review_incident_duplicate_link_rpc validation, optimistic locking, cycle
        detection, override enforcement, and atomic dual-incident audit appends.
        """
        with self._lock:
            link = self._duplicate_links.get(link_id)
            if not link:
                raise LookupError(f"Duplicate link '{link_id}' not found.")

            clean_status = (target_status or "").upper().strip()
            if clean_status not in ("CONFIRMED", "DISMISSED"):
                raise ValueError("Review action must be 'CONFIRMED' or 'DISMISSED'.")

            clean_role = (actor_role or "").lower().strip()
            if clean_role not in ("municipality", "admin", "service_role"):
                raise PermissionError(
                    "Unauthorized: duplicate review requires municipality, admin, or service_role credentials."
                )

            clean_reason = (reason or "").strip()
            if len(clean_reason) < 3 or len(clean_reason) > 500:
                raise ValueError("A mandatory review reason between 3 and 500 characters is required.")

            if expected_version is not None and link.review_version != expected_version:
                raise ValueError(
                    f"Version conflict on duplicate link {link_id}: expected {expected_version}, found {link.review_version}."
                )

            is_override = link.link_status != DuplicateLinkStatus.SUSPECTED
            if is_override and not override:
                raise ValueError(
                    f"Duplicate link {link_id} is already {link.link_status.value}; supervisor override is required to modify."
                )

            if is_override:
                if clean_status == "DISMISSED" and link.link_status == DuplicateLinkStatus.DISMISSED:
                    raise ValueError(f"Redundant override: link {link_id} is already DISMISSED.")
                if (
                    clean_status == "CONFIRMED"
                    and link.link_status == DuplicateLinkStatus.CONFIRMED
                    and link.primary_incident_id == primary_incident_id
                ):
                    raise ValueError(
                        f"Redundant override: link {link_id} is already CONFIRMED with primary {primary_incident_id}."
                    )

            inc_low = self._incidents.get(link.incident_low_id)
            inc_high = self._incidents.get(link.incident_high_id)
            if inc_low is None or inc_high is None:
                raise LookupError("One or both linked incidents no longer exist.")

            duplicate_id: Optional[str] = None
            if clean_status == "CONFIRMED":
                if not primary_incident_id:
                    raise ValueError("primary_incident_id is required when confirming a duplicate link.")
                if primary_incident_id == link.incident_low_id:
                    duplicate_id = link.incident_high_id
                    primary_inc = inc_low
                elif primary_incident_id == link.incident_high_id:
                    duplicate_id = link.incident_low_id
                    primary_inc = inc_high
                else:
                    raise ValueError(
                        f"Primary incident {primary_incident_id} does not belong to link {link_id}."
                    )

                if primary_inc.status == IncidentStatus.REJECTED:
                    raise ValueError(
                        f"Cannot confirm REJECTED incident {primary_incident_id} as primary incident."
                    )

                for existing_id, existing_link in self._duplicate_links.items():
                    if (
                        existing_id != link_id
                        and existing_link.duplicate_incident_id == duplicate_id
                        and existing_link.link_status == DuplicateLinkStatus.CONFIRMED
                    ):
                        raise ValueError(
                            f"Incident {duplicate_id} is already confirmed as a duplicate of another primary incident."
                        )

                # Unlimited-depth transitive cycle check over CONFIRMED edges
                curr: Optional[str] = primary_incident_id
                visited: set[str] = set()
                while curr:
                    if curr == duplicate_id:
                        raise ValueError(
                            f"Confirming {duplicate_id} as duplicate of {primary_incident_id} would create circular dependency."
                        )
                    if curr in visited:
                        break
                    visited.add(curr)
                    next_primary: Optional[str] = None
                    for eid, l in self._duplicate_links.items():
                        if (
                            eid != link_id
                            and l.duplicate_incident_id == curr
                            and l.link_status == DuplicateLinkStatus.CONFIRMED
                        ):
                            next_primary = l.primary_incident_id
                            break
                    curr = next_primary

            link_snapshot = link.model_copy(deep=True)
            now = datetime.now(timezone.utc)
            clean_notes = internal_notes.strip() if isinstance(internal_notes, str) and internal_notes.strip() else None

            link.link_status = DuplicateLinkStatus(clean_status)
            link.primary_incident_id = primary_incident_id if clean_status == "CONFIRMED" else None
            link.duplicate_incident_id = duplicate_id if clean_status == "CONFIRMED" else None
            link.review_version = link.review_version + 1
            link.reviewed_at = now
            link.reviewed_by = actor_id.strip()[:128]
            link.reviewed_role = clean_role
            link.review_reason = clean_reason
            link.internal_notes = clean_notes
            link.updated_at = now

            if is_override:
                audit_action = (
                    "DUPLICATE_OVERRIDE_CONFIRMED"
                    if clean_status == "CONFIRMED"
                    else "DUPLICATE_OVERRIDE_DISMISSED"
                )
            else:
                audit_action = (
                    "DUPLICATE_CONFIRMED"
                    if clean_status == "CONFIRMED"
                    else "DUPLICATE_DISMISSED"
                )

            structured_reason = (
                f"link={link_id};status={clean_status}"
                + (f";primary={primary_incident_id};duplicate={duplicate_id}" if clean_status == "CONFIRMED" else "")
                + f";reason={clean_reason}"
            )

            audit_low = IncidentAuditContract(
                incident_id=link.incident_low_id,
                actor_id=link.reviewed_by,
                actor_role=clean_role,
                action=audit_action,
                previous_status=None,
                new_status=None,
                reason=structured_reason,
                internal_notes=clean_notes,
                timestamp=now,
            )
            audit_high = IncidentAuditContract(
                incident_id=link.incident_high_id,
                actor_id=link.reviewed_by,
                actor_role=clean_role,
                action=audit_action,
                previous_status=None,
                new_status=None,
                reason=structured_reason,
                internal_notes=clean_notes,
                timestamp=now,
            )

            ok_low = self._audit_durability.append_audit(audit_low)
            ok_high = self._audit_durability.append_audit(audit_high) if ok_low else False
            if not (ok_low and ok_high):
                self._duplicate_links[link_id] = link_snapshot
                raise RuntimeError(
                    f"Failed to persist durable audit events for duplicate link '{link_id}'. Mutation rolled back."
                )

            self._incident_audits.setdefault(link.incident_low_id, []).append(audit_low)
            self._incident_audits.setdefault(link.incident_high_id, []).append(audit_high)
            return link

# Global singleton store instance
state_store = StateStore()

