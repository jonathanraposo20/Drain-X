import time
import logging
from collections import deque
from datetime import datetime, timezone
import threading
from typing import Optional, Any

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
)
from app.core.config import settings
from app.services.audit_durability import AuditDurabilityManager

logger = logging.getLogger("drainx.state_store")

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
        self._audit_durability = AuditDurabilityManager()
        self._incident_audits: dict[str, list[IncidentAuditContract]] = self._audit_durability.load_all_audits()
        self.seed_demo_incidents()
        self.recover_incidents_from_cloud()

    def recover_incidents_from_cloud(self) -> None:
        """
        Loads persisted incidents from Supabase Cloud on backend startup.
        Ensures cloud-persisted incidents and assignments survive process restart.
        """
        try:
            from app.services.persistence_repository import persistence_repo
            if persistence_repo.is_configured:
                records = persistence_repo.query_all_incidents_sync()
                for rec in records:
                    try:
                        inc = IncidentResponseContract(**rec)
                        self._incidents[inc.id] = inc
                    except Exception as parse_err:
                        logger.warning(f"Failed to parse cloud incident record {rec.get('id')}: {parse_err}")
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

    def set_mode(self, new_mode: str, reason: str = "") -> tuple[bool, str]:
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

        with self._lock:
            old_mode = self.mode
            if old_mode == new_mode:
                return True, f"System already in mode {new_mode}"

            self.mode = new_mode
            record = ModeTransitionRecord(
                from_mode=old_mode,
                to_mode=new_mode,
                reason=reason or f"Mode transition from {old_mode} to {new_mode}",
            )
            self._mode_history.append(record)

            # In SAFE_HOLD mode, guarantee fail-safe actuator directive
            if self.is_safe_hold():
                self._safe_hold_gate_directive = ActuatorDirectiveContract(
                    gate_target_angle=settings.SAFE_HOLD_GATE_ANGLE,
                    action="SAFE_HOLD_LOCK",
                    reason=f"SAFE_HOLD active: {record.reason}. Automated actuation locked to fail-safe angle ({settings.SAFE_HOLD_GATE_ANGLE} deg).",
                    risk_level=AlertSeverity.HIGH,
                    emergency_stop=True,
                )

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

            self._active_scenario = None
            self._latest_benchmark = None
            self._incidents.clear()
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

    def set_gate_directive(self, directive: ActuatorDirectiveContract) -> None:
        """
        Thread-safe gate directive update.
        SAFE_HOLD invariant: while in SAFE_HOLD, incoming non-SAFE_HOLD directives
        can NEVER replace the immutable fail-safe hold posture.
        """
        with self._lock:
            if self.is_safe_hold():
                if directive.action != "SAFE_HOLD_LOCK" or not directive.emergency_stop:
                    # Reject incoming operational directives to preserve fail-safe hold invariant
                    return
                self._safe_hold_gate_directive = directive
                return

            if self.is_physical():
                self._physical_latest_gate_directive = directive
            else:
                self._sim_latest_gate_directive = directive

    def get_gate_directive(self) -> Optional[ActuatorDirectiveContract]:
        with self._lock:
            if self.is_safe_hold():
                return self._safe_hold_gate_directive
            elif self.is_physical():
                return self._physical_latest_gate_directive
            else:
                return self._sim_latest_gate_directive

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
            ),
        ]
        with self._lock:
            for item in demo_items:
                if item.id not in self._incidents:
                    self._incidents[item.id] = item
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
            self._incident_audits[incident.id] = [audit]

            return incident




    def get_incident(
        self, incident_id: str, authoritative_cloud: bool = False
    ) -> Optional[IncidentResponseContract]:
        with self._lock:
            from app.services.persistence_repository import persistence_repo
            if authoritative_cloud and (
                persistence_repo.is_configured or persistence_repo.is_storage_configured
            ):
                row = persistence_repo.query_incident_by_id_sync(incident_id)
                if row:
                    fetched = IncidentResponseContract.model_validate(row)
                    self._incidents[incident_id] = fetched
                    return fetched
                self._incidents.pop(incident_id, None)
                return None

            incident = self._incidents.get(incident_id)
            if incident is not None:
                return incident
            if persistence_repo.is_configured or persistence_repo.is_storage_configured:
                row = persistence_repo.query_incident_by_id_sync(incident_id)
                if row:
                    fetched = IncidentResponseContract.model_validate(row)
                    self._incidents[incident_id] = fetched
                    return fetched
            return None

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

            # Unassignment clearing invariants:
            if update.assigned_to == "" or update.assigned_to is None and assignment_changed:
                incident.assignment_type = AssignmentType.NONE
                incident.assigned_team_id = None
                incident.assigned_worker_id = None

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
        In cloud mode with configured Supabase, fetches authoritative records from Supabase Cloud.
        Falls back seamlessly to local in-memory/journal records.
        """
        with self._lock:
            from app.services.persistence_repository import persistence_repo
            if persistence_repo.is_configured:
                cloud_records = persistence_repo.query_incident_audits_sync(incident_id, strict=True)
                if cloud_records:
                    parsed_audits = [IncidentAuditContract(**rec) for rec in cloud_records]
                    return sorted(parsed_audits, key=lambda a: a.timestamp)
                return []

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
            if not incident:
                from app.services.persistence_repository import persistence_repo
                if persistence_repo.is_configured:
                    row = persistence_repo.query_incident_by_id_sync(incident_id)
                    if row:
                        incident = IncidentResponseContract.model_validate(row)
                        self._incidents[incident_id] = incident
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

# Global singleton store instance
state_store = StateStore()

