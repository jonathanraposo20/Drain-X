import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Literal, Optional, Any
from pydantic import BaseModel, Field, field_validator


class DataSource(str, Enum):
    PHYSICAL = "PHYSICAL"
    LIVE = "LIVE"
    SIMULATED = "SIMULATED"
    REPLAY = "REPLAY"
    OFFLINE = "OFFLINE"


class OperationalMode(str, Enum):
    SIMULATION = "SIMULATION"
    PHYSICAL = "PHYSICAL"
    SAFE_HOLD = "SAFE_HOLD"
    HARDWARE = "HARDWARE"  # Backward-compatible alias for PHYSICAL


class ModeTransitionRequest(BaseModel):
    mode: str = Field(..., description="Target operational mode: SIMULATION, PHYSICAL, SAFE_HOLD, or HARDWARE")
    reason: Optional[str] = Field(default="Manual operational mode transition", description="Auditable operator or automated trigger reason")


class ModeTransitionRecord(BaseModel):
    from_mode: str
    to_mode: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reason: str


class SensorHealthStatus(str, Enum):
    OK = "OK"
    DEGRADED = "DEGRADED"
    FAULT = "FAULT"
    CALIBRATING = "CALIBRATING"


class SensorType(str, Enum):
    WATER_LEVEL = "WATER_LEVEL"
    FLOW_RATE = "FLOW_RATE"
    TEMPERATURE = "TEMPERATURE"
    DEBRIS_PRESENCE = "DEBRIS_PRESENCE"
    GATE_ANGLE = "GATE_ANGLE"


class MeasurementUnit(str, Enum):
    CENTIMETRE = "cm"
    LITRES_PER_MINUTE = "L/min"
    DEGREES_CELSIUS = "degC"
    DEGREE = "deg"
    FLAG = "flag"


class SystemOperationalState(str, Enum):
    STANDBY = "STANDBY"
    MONITORING = "MONITORING"
    INTERVENING = "INTERVENING"
    FAULT = "FAULT"
    EMERGENCY_STOP = "EMERGENCY_STOP"


class AlertSeverity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PredictionState(str, Enum):
    STABLE = "STABLE"
    ESTIMATING = "ESTIMATING"
    OVERFLOW = "OVERFLOW"
    UNAVAILABLE = "UNAVAILABLE"


class MechanismState(str, Enum):
    IDLE = "IDLE"
    DEPLOYING_BACKUP_NET = "DEPLOYING_BACKUP_NET"
    HOISTING = "HOISTING"
    DISCHARGING = "DISCHARGING"
    LOWERING = "LOWERING"
    RETRACTING_BACKUP_NET = "RETRACTING_BACKUP_NET"
    JAMMED = "JAMMED"
    FAILED = "FAILED"


class FaultType(str, Enum):
    SENSOR_DISCONNECTED = "SENSOR_DISCONNECTED"
    STALE_DATA = "STALE_DATA"
    IMPLAUSIBLE_READING = "IMPLAUSIBLE_READING"
    COMMUNICATION_LOSS = "COMMUNICATION_LOSS"
    ACTUATOR_TIMEOUT = "ACTUATOR_TIMEOUT"
    FAILED_CYCLE = "FAILED_CYCLE"
    MECHANISM_JAM = "MECHANISM_JAM"
    SENSOR_INCONSISTENT = "SENSOR_INCONSISTENT"


class ScenarioType(str, Enum):
    CLEAN_DRAINAGE = "CLEAN_DRAINAGE"
    GRADUAL_DEBRIS = "GRADUAL_DEBRIS"
    SUDDEN_BLOCKAGE = "SUDDEN_BLOCKAGE"
    PARTIAL_BLOCKAGE = "PARTIAL_BLOCKAGE"
    INCREASING_INFLOW = "INCREASING_INFLOW"
    SENSOR_FAILURE = "SENSOR_FAILURE"
    COMM_FAILURE = "COMM_FAILURE"
    FAILED_CYCLE = "FAILED_CYCLE"
    SUCCESSFUL_INTERVENTION = "SUCCESSFUL_INTERVENTION"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SensorReadingContract(BaseModel):
    """
    Standardized sensor reading contract.
    Both simulated and physical telemetry MUST conform to this schema.
    """
    version: str = Field(default="1.0", description="Contract schema version")
    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    sensor_id: str = Field(..., min_length=2, max_length=64, description="Unique identifier of sensor")
    section_id: str = Field(..., min_length=2, max_length=64, description="Drainage section ID")
    sensor_type: SensorType
    value: float = Field(..., description="Measurement value in designated unit")
    unit: MeasurementUnit = Field(..., description="Explicit physical unit (cm, L/min, degC, etc.)")
    timestamp: datetime = Field(default_factory=utc_now, description="UTC ISO 8601 timestamp")
    source: DataSource = Field(default=DataSource.SIMULATED)
    status: SensorHealthStatus = Field(default=SensorHealthStatus.OK)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def ensure_timezone_aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v

    @field_validator("value")
    @classmethod
    def validate_non_negative_physical_readings(cls, v: float, info) -> float:
        sensor_type = info.data.get("sensor_type")
        if sensor_type in (SensorType.WATER_LEVEL, SensorType.FLOW_RATE):
            if v < 0:
                raise ValueError(f"Value for {sensor_type} cannot be negative: {v}")
        return v


class AlertContract(BaseModel):
    """
    System alert contract for abnormal conditions, thresholds, or hardware faults.
    """
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    section_id: str
    alert_type: str = Field(..., min_length=2, max_length=64)
    severity: AlertSeverity = Field(default=AlertSeverity.WARNING)
    timestamp: datetime = Field(default_factory=utc_now)
    message: str = Field(..., min_length=1)
    resolved: bool = Field(default=False)
    resolved_at: Optional[datetime] = None
    context_data: dict[str, Any] = Field(default_factory=dict)


class BlockageEventContract(BaseModel):
    """
    Blockage event diagnosis contract identifying restricted conduit segments.
    """
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    section_id: str
    probable_segment: str = Field(..., description="Identified restricted segment (e.g. PRIMARY_SCREENING_NET)")
    severity: float = Field(default=0.0, ge=0.0, le=1.0, description="Blockage severity fraction (0.0=clean, 1.0=complete)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Localization confidence score")
    differential_head_cm: float = Field(..., description="Excess differential head in cm")
    estimated_flow_drop_lpm: float = Field(default=0.0, description="Discharge drop in L/min")
    detected_at: datetime = Field(default_factory=utc_now)
    is_active: bool = Field(default=True)


class PredictionContract(BaseModel):
    """
    Time-to-Critical (TTC) and flood risk prediction contract.
    """
    prediction_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    section_id: str
    state: PredictionState = Field(default=PredictionState.STABLE)
    ttc_seconds: Optional[float] = Field(default=None, ge=0.0, description="Estimated time-to-critical overflow in seconds")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence metric of trend fit")
    rate_of_rise_cm_s: float = Field(default=0.0, description="Water-level trend dh/dt in cm/s")
    projected_level_cm: float = Field(default=0.0, description="Projected water level at critical horizon")
    predicted_at: datetime = Field(default_factory=utc_now)


class MechanismStatusContract(BaseModel):
    """
    Physical screening and waste extraction mechanism simulation status contract.
    """
    state: MechanismState = Field(default=MechanismState.IDLE)
    backup_net_angle_deg: float = Field(default=0.0, ge=0.0, le=90.0, description="Backup net angle (0=horizontal, 90=vertical)")
    tray_height_cm: float = Field(default=0.0, ge=0.0, description="Lifting platform position above channel bed")
    cycle_count: int = Field(default=0, ge=0)
    current_action: str = "Mechanism idle on drain bed"
    elapsed_in_state_s: float = 0.0
    is_jammed: bool = False
    is_fault: bool = False
    debris_retained_pct: float = Field(default=0.0, ge=0.0, le=100.0, description="Accumulated debris percentage on tray")
    last_cycle_completed_at: Optional[datetime] = None


class FaultEventContract(BaseModel):
    """
    Fault detection event contract.
    """
    fault_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_id: str = Field(..., description="Sensor or actuator ID experiencing fault")
    fault_type: FaultType
    severity: AlertSeverity = AlertSeverity.HIGH
    description: str
    detected_at: datetime = Field(default_factory=utc_now)
    active: bool = True
    context: dict[str, Any] = Field(default_factory=dict)


class BenchmarkMetricsContract(BaseModel):
    """
    Comparison metrics between DRAIN-X predictive system and simple threshold baseline.
    """
    scenario_name: str
    duration_s: float
    # DRAIN-X System Metrics
    detection_delay_s: Optional[float] = None
    false_alarms: int = 0
    missed_detections: int = 0
    prediction_rmse_s: Optional[float] = None
    intervention_success_rate_pct: float = 0.0
    time_above_critical_s: float = 0.0
    # Simple Threshold Baseline Metrics
    baseline_detection_delay_s: Optional[float] = None
    baseline_false_alarms: int = 0
    baseline_time_above_critical_s: float = 0.0
    # Comparative summary
    lead_time_advantage_s: float = 0.0
    overflow_reduction_pct: float = 0.0


class ActuatorDirectiveContract(BaseModel):
    """
    Actuator and gate directive computed by DRAIN-X decision engine for physical microcontrollers
    (ESP32) and simulated actuators.
    """
    gate_target_angle: float = Field(default=0.0, ge=0.0, le=90.0, description="Target diversion gate angle in degrees (0=closed, 90=diverted)")
    action: str = Field(default="MAINTAIN_NORMAL", description="Action code: MAINTAIN_NORMAL, DIVERT_FLOW, EMERGENCY_OVERFLOW_RELIEF, MONITOR_HIGH_WATER, SENSOR_FAULT_HOLD")
    reason: str = Field(default="Channel hydraulics and trends within nominal safe bounds.", description="Diagnostic explanation for actuator directive")
    risk_level: AlertSeverity = Field(default=AlertSeverity.INFO, description="Assessed operational risk severity")
    emergency_stop: bool = Field(default=False, description="Emergency stop flag if critical faults exist")
    timestamp: datetime = Field(default_factory=utc_now)


class TelemetryIngestResponse(BaseModel):
    """
    Structured response returned upon sensor telemetry ingestion.
    Provides immediate feedback on accepted readings, active blockage diagnosis,
    Time-to-Critical prediction, active alerts, and real-time actuator directives.
    """
    status: str = "success"
    ingested_count: int
    message_id: Optional[str] = None
    prediction: Optional[PredictionContract] = None
    blockage: Optional[BlockageEventContract] = None
    active_alerts_count: int = 0
    gate_directive: ActuatorDirectiveContract = Field(default_factory=ActuatorDirectiveContract)
    gate_command: ActuatorDirectiveContract = Field(default_factory=ActuatorDirectiveContract)


class SystemStatusContract(BaseModel):
    """
    Overall system health, operational mode, and sensor inventory contract.
    """
    system_name: str = "DRAIN-X"
    mode: OperationalMode | str = OperationalMode.SIMULATION
    operational_state: SystemOperationalState = SystemOperationalState.MONITORING
    uptime_seconds: float = 0.0
    active_alerts_count: int = 0
    last_heartbeat: datetime = Field(default_factory=utc_now)
    latest_readings: dict[str, SensorReadingContract] = Field(default_factory=dict)
    active_prediction: Optional[PredictionContract] = None
    active_blockage: Optional[BlockageEventContract] = None
    active_gate_directive: Optional[ActuatorDirectiveContract] = None
    mechanism: MechanismStatusContract = Field(default_factory=MechanismStatusContract)
    active_scenario: Optional[str] = None


class IncidentSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentCategory(str, Enum):
    FLOODING = "FLOODING"
    WATERLOGGING = "WATERLOGGING"
    DRAIN_BLOCKAGE = "DRAIN_BLOCKAGE"
    DRAIN_OVERFLOW = "DRAIN_OVERFLOW"
    MANHOLE_DAMAGE = "MANHOLE_DAMAGE"
    INFRASTRUCTURE_DAMAGE = "INFRASTRUCTURE_DAMAGE"
    OTHER = "OTHER"


class IncidentStatus(str, Enum):
    REPORTED = "REPORTED"
    VERIFIED = "VERIFIED"
    ASSIGNED = "ASSIGNED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    REJECTED = "REJECTED"


class IncidentSource(str, Enum):
    CITIZEN = "CITIZEN"
    SENSOR = "SENSOR"
    DEMO = "DEMO"


class IncidentCreateContract(BaseModel):
    """
    Payload for reporting an incident (by citizen, sensor alert, or field crew).
    """
    category: IncidentCategory
    description: str = Field(..., min_length=3, max_length=1000, description="Description of the drainage or flood hazard")
    latitude: float = Field(..., ge=-90.0, le=90.0, description="Geographic latitude coordinate")
    longitude: float = Field(..., ge=-180.0, le=180.0, description="Geographic longitude coordinate")
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    source: IncidentSource = IncidentSource.CITIZEN
    reporter_name: Optional[str] = Field(default="Citizen Anonymous", max_length=100)
    photos: list[str] = Field(default_factory=list, max_length=3, description="List of photo reference paths/URLs")


class IncidentUpdateContract(BaseModel):
    """
    Payload for updating an incident by municipal operators or field response crews.
    """
    status: Optional[IncidentStatus] = None
    assigned_to: Optional[str] = None
    municipal_notes: Optional[str] = None
    photos: Optional[list[str]] = None


class IncidentResponseContract(BaseModel):
    """
    Full incident record representation.
    """
    id: str = Field(default_factory=lambda: f"INC-{str(uuid.uuid4())[:8].upper()}")
    category: IncidentCategory
    description: str
    latitude: float
    longitude: float
    severity: IncidentSeverity
    status: IncidentStatus = IncidentStatus.REPORTED
    source: IncidentSource = IncidentSource.CITIZEN
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    assigned_to: Optional[str] = None
    municipal_notes: Optional[str] = ""
    reporter_name: Optional[str] = "Citizen Anonymous"
    photos: list[str] = Field(default_factory=list, description="List of uploaded photo references")


VALID_STATUS_TRANSITIONS: dict[IncidentStatus, set[IncidentStatus]] = {
    IncidentStatus.REPORTED: {
        IncidentStatus.VERIFIED,
        IncidentStatus.ASSIGNED,
        IncidentStatus.INVESTIGATING,
        IncidentStatus.REJECTED,
    },
    IncidentStatus.VERIFIED: {
        IncidentStatus.ASSIGNED,
        IncidentStatus.INVESTIGATING,
        IncidentStatus.REJECTED,
    },
    IncidentStatus.ASSIGNED: {
        IncidentStatus.INVESTIGATING,
        IncidentStatus.RESOLVED,
        IncidentStatus.REJECTED,
    },
    IncidentStatus.INVESTIGATING: {
        IncidentStatus.RESOLVED,
        IncidentStatus.REJECTED,
    },
    IncidentStatus.RESOLVED: {
        IncidentStatus.INVESTIGATING,
    },
    IncidentStatus.REJECTED: {
        IncidentStatus.REPORTED,
    },
}


def validate_incident_status_transition(current_status: IncidentStatus, new_status: IncidentStatus) -> bool:
    if current_status == new_status:
        return True
    allowed = VALID_STATUS_TRANSITIONS.get(current_status, set())
    return new_status in allowed


class TelemetryStreamEventType(str, Enum):
    INIT = "INIT"
    TELEMETRY = "TELEMETRY"
    HEARTBEAT = "HEARTBEAT"
    PONG = "PONG"
    FILTER_ACK = "FILTER_ACK"
    ERROR = "ERROR"


class TelemetryStreamEvent(BaseModel):
    """
    Standardized live telemetry stream broadcast event.
    Broadcast to connected WebSocket/SSE clients in real time.
    """
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: TelemetryStreamEventType = TelemetryStreamEventType.TELEMETRY
    timestamp: datetime = Field(default_factory=utc_now)
    sensor_id: str
    section_id: str
    source: DataSource
    operational_mode: str
    sensor_type: SensorType
    value: float
    unit: str
    water_level_cm: Optional[float] = None
    flow_rate_lpm: Optional[float] = None
    cumulative_volume_liters: Optional[float] = None
    sensor_status: SensorHealthStatus = SensorHealthStatus.OK
    is_valid: bool = True
    fault_code: Optional[str] = None
    hardware_validation_stage: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class StreamInitMessage(BaseModel):
    """
    Initialization handshake payload transmitted to newly connected stream clients.
    """
    event_type: str = "INIT"
    protocol_version: str = "1.0"
    client_id: str
    connection_time: datetime = Field(default_factory=utc_now)
    operational_mode: str
    hardware_validation_stage: Optional[str] = None
    latest_snapshot: dict[str, Any] = Field(default_factory=dict)
    subscribed_source: Optional[str] = None
    subscribed_sensor: Optional[str] = None
    message: str = "Connected to DRAIN-X live telemetry stream"
    stream_config: dict[str, Any] = Field(default_factory=dict)

