import time
from collections import deque
from datetime import datetime, timezone
import threading
from typing import Optional

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
    IncidentStatus,
    IncidentCategory,
    IncidentSeverity,
    IncidentSource,
    OperationalMode,
    ModeTransitionRecord,
    DataSource,
    validate_incident_status_transition,
)
from app.core.config import settings


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
        self.seed_demo_incidents()

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
                municipal_notes="Grating slab repositioned and secured with structural steel anchors.",
            ),
        ]
        with self._lock:
            for item in demo_items:
                if item.id not in self._incidents:
                    self._incidents[item.id] = item

    def create_incident(self, incident: IncidentResponseContract) -> IncidentResponseContract:
        with self._lock:
            self._incidents[incident.id] = incident
            return incident

    def get_incident(self, incident_id: str) -> Optional[IncidentResponseContract]:
        with self._lock:
            return self._incidents.get(incident_id)

    def get_incidents(
        self,
        status: Optional[IncidentStatus] = None,
        category: Optional[IncidentCategory] = None,
        severity: Optional[IncidentSeverity] = None,
        source: Optional[IncidentSource] = None,
    ) -> list[IncidentResponseContract]:
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

            # Return sorted by created_at descending
            return sorted(incidents, key=lambda x: x.created_at, reverse=True)

    def update_incident(
        self, incident_id: str, update: IncidentUpdateContract
    ) -> Optional[IncidentResponseContract]:
        with self._lock:
            incident = self._incidents.get(incident_id)
            if not incident:
                return None

            if update.status is not None:
                if not validate_incident_status_transition(incident.status, update.status):
                    raise ValueError(
                        f"Illegal status transition from {incident.status.value} to {update.status.value}"
                    )
                incident.status = update.status

            if update.assigned_to is not None:
                incident.assigned_to = update.assigned_to

            if update.municipal_notes is not None:
                incident.municipal_notes = update.municipal_notes

            if update.photos is not None:
                incident.photos = update.photos[:3]

            incident.updated_at = datetime.now(timezone.utc)
            return incident

    def attach_incident_photos(
        self, incident_id: str, new_photos: list[str]
    ) -> Optional[IncidentResponseContract]:
        with self._lock:
            incident = self._incidents.get(incident_id)
            if not incident:
                return None
            for p in new_photos:
                if len(incident.photos) >= 3:
                    break
                if p not in incident.photos:
                    incident.photos.append(p)
            incident.updated_at = datetime.now(timezone.utc)
            return incident


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

