import hashlib
import math
import re
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_HALF_UP
from enum import Enum
from typing import Literal, Optional, Any
from pydantic import BaseModel, ConfigDict, Field, field_validator


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
    device_id: Optional[str] = Field(default=None, description="Edge device node identifier")
    sequence_number: Optional[int] = Field(default=None, description="Monotonic packet sequence number")
    uptime_ms: Optional[int] = Field(default=None, description="Device uptime in milliseconds")
    gate_angle_deg: Optional[float] = Field(default=None, description="Actuator gate angle in degrees")
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


class DirectiveAuditOutboxFullError(RuntimeError):
    """Raised when the volatile directive audit outbox reaches maximum capacity."""


class DirectiveEventType(str, Enum):
    ISSUED = "ISSUED"
    FEEDBACK_RECEIVED = "FEEDBACK_RECEIVED"
    ALIGNMENT_OBSERVED = "ALIGNMENT_OBSERVED"
    REJECTED = "REJECTED"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    VERIFICATION_TIMEOUT = "VERIFICATION_TIMEOUT"
    CANCELLED = "CANCELLED"
    SUPERSEDED = "SUPERSEDED"


class DirectiveIssuerType(str, Enum):
    AUTOMATED_ENGINE = "AUTOMATED_ENGINE"
    SAFETY_INTERLOCK = "SAFETY_INTERLOCK"
    OPERATOR = "OPERATOR"


DirectiveOperationalMode = Literal["SIMULATION", "PHYSICAL", "SAFE_HOLD"]
DirectiveMeasuredGateState = Literal["CLOSED", "OPEN", "SAFE_HOLD", "UNINITIALIZED"]

DIRECTIVE_AUDIT_DB_COLUMNS: tuple[str, ...] = (
    "audit_id",
    "directive_id",
    "event_type",
    "device_id",
    "section_id",
    "operational_mode",
    "directive_type",
    "action",
    "gate_target_angle",
    "reason",
    "risk_level",
    "emergency_stop",
    "measured_gate_angle",
    "measured_gate_state",
    "execution_divergence_deg",
    "issuer_type",
    "issuer_id",
    "correlation_id",
    "device_session_epoch",
    "baseline_device_sequence_number",
    "device_sequence_number",
    "device_uptime_ms",
    "timestamp",
)

DIRECTIVE_AUDIT_IMMUTABLE_COLUMNS: tuple[str, ...] = DIRECTIVE_AUDIT_DB_COLUMNS

_DIRECTIVE_ID_AUDIT_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,36}$")
_AUDIT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_LONG_FRAC_TS_RE = re.compile(
    r"^(?P<prefix>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})\.(?P<frac>\d{7,})(?P<tz>[+-]\d{2}(?::?\d{2})?)$"
)
_MAX_INT32 = 2147483647
_MAX_UINT32 = 4294967295


def normalize_audit_timestamp_utc(v: Any) -> datetime:
    """
    Parses and normalizes a directive audit timestamp into a UTC datetime at
    PostgreSQL TIMESTAMPTZ microsecond precision (rounding >6 fractional digits
    with ROUND_HALF_UP). Rejects None, naive timestamps, booleans, and numbers.
    """
    if v is None:
        raise ValueError("timestamp cannot be None.")
    if isinstance(v, datetime):
        dt = v
    elif isinstance(v, str):
        raw = v.strip()
        if not raw:
            raise ValueError("timestamp string cannot be empty.")
        if raw.endswith(("Z", "z")):
            raw = raw[:-1] + "+00:00"
        long_frac = _LONG_FRAC_TS_RE.match(raw)
        if long_frac:
            base = datetime.fromisoformat(f"{long_frac.group('prefix')}{long_frac.group('tz')}")
            us = int(
                (Decimal(f"0.{long_frac.group('frac')}") * Decimal("1000000")).quantize(
                    Decimal("1"), rounding=ROUND_HALF_UP
                )
            )
            dt = base + timedelta(microseconds=us)
        else:
            dt = datetime.fromisoformat(raw)
    else:
        raise ValueError(
            f"timestamp must be a timezone-aware datetime or ISO-8601 string, got {type(v).__name__}."
        )
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError("timestamp must be timezone-aware.")
    return dt.astimezone(timezone.utc)


def compute_verification_timeout_timestamp(issued_timestamp: Any, timeout_sec: float) -> datetime:
    """
    Deterministic VERIFICATION_TIMEOUT event timestamp shared by runtime evaluation and
    startup recovery: normalized-UTC(issued_timestamp) + timeout_sec. Naive datetimes are
    interpreted as UTC (matching ActuatorDirectiveContract's default-UTC semantics).
    """
    if isinstance(issued_timestamp, datetime) and (
        issued_timestamp.tzinfo is None or issued_timestamp.tzinfo.utcoffset(issued_timestamp) is None
    ):
        issued_timestamp = issued_timestamp.replace(tzinfo=timezone.utc)
    base = normalize_audit_timestamp_utc(issued_timestamp)
    return (base + timedelta(seconds=float(timeout_sec))).astimezone(timezone.utc)


def _validate_directive_id_for_audit(directive_id: str) -> str:
    if not isinstance(directive_id, str) or not directive_id or directive_id != directive_id.strip():
        raise ValueError("directive_id must be a non-empty trimmed string (1..36 chars).")
    if not _DIRECTIVE_ID_AUDIT_PATTERN.match(directive_id):
        raise ValueError(
            "directive_id must be 1..36 characters matching [A-Za-z0-9_.:-]."
        )
    return directive_id


def _validate_audit_nonneg_int(value: Any, name: str, max_val: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer, got {type(value).__name__}.")
    if value < 0 or value > max_val:
        raise ValueError(f"{name} must be between 0 and {max_val}, got {value}.")
    return value


def _compact_audit_id(directive_id: str, suffix: str) -> str:
    candidate = f"aud_{directive_id}_{suffix}"
    if len(candidate) <= 64:
        return candidate
    dir_hash = hashlib.sha256(directive_id.encode("utf-8")).hexdigest()[:16]
    compacted = f"audh_{dir_hash}_{suffix}"
    if len(compacted) > 64:
        raise ValueError(f"Deterministic audit_id exceeded 64 chars: {len(compacted)}")
    return compacted


def build_issued_audit_id(directive_id: str) -> str:
    d_id = _validate_directive_id_for_audit(directive_id)
    return f"aud_{d_id}_ISS"


def build_startup_cancellation_audit_id(directive_id: str) -> str:
    d_id = _validate_directive_id_for_audit(directive_id)
    return f"aud_{d_id}_CAN_STARTUP"


def build_safe_hold_cancellation_audit_id(directive_id: str) -> str:
    d_id = _validate_directive_id_for_audit(directive_id)
    return f"aud_{d_id}_CAN_SAFEHOLD"


def build_mode_cancellation_audit_id(directive_id: str, target_mode: str) -> str:
    d_id = _validate_directive_id_for_audit(directive_id)
    if target_mode == "SAFE_HOLD":
        return build_safe_hold_cancellation_audit_id(d_id)
    if target_mode not in ("SIMULATION", "PHYSICAL"):
        raise ValueError(f"Invalid target_mode '{target_mode}' for mode cancellation audit_id.")
    return f"aud_{d_id}_CAN_MODE_{target_mode}"


def build_reboot_cancellation_audit_id(directive_id: str, new_epoch: int) -> str:
    d_id = _validate_directive_id_for_audit(directive_id)
    epoch_val = _validate_audit_nonneg_int(new_epoch, "new_epoch", _MAX_INT32)
    return _compact_audit_id(d_id, f"CAN_RBT_e{epoch_val}")


def build_verification_timeout_audit_id(directive_id: str) -> str:
    d_id = _validate_directive_id_for_audit(directive_id)
    return f"aud_{d_id}_TOUT"


def build_superseded_audit_id(directive_id: str, superseded_by_directive_id: str) -> str:
    d_id = _validate_directive_id_for_audit(directive_id)
    sup_id = _validate_directive_id_for_audit(superseded_by_directive_id)
    if d_id == sup_id:
        raise ValueError("superseded_by_directive_id must differ from superseded directive_id.")
    sup_hash = hashlib.sha256(sup_id.encode("utf-8")).hexdigest()[:16]
    return f"aud_{d_id}_SUP_{sup_hash}"


def build_feedback_received_audit_id(
    directive_id: str, device_session_epoch: int, device_sequence_number: int
) -> str:
    d_id = _validate_directive_id_for_audit(directive_id)
    epoch_val = _validate_audit_nonneg_int(device_session_epoch, "device_session_epoch", _MAX_INT32)
    seq_val = _validate_audit_nonneg_int(device_sequence_number, "device_sequence_number", _MAX_UINT32)
    return _compact_audit_id(d_id, f"FB_e{epoch_val}_s{seq_val}")


def build_alignment_observed_audit_id(
    directive_id: str, device_session_epoch: int, device_sequence_number: int
) -> str:
    d_id = _validate_directive_id_for_audit(directive_id)
    epoch_val = _validate_audit_nonneg_int(device_session_epoch, "device_session_epoch", _MAX_INT32)
    seq_val = _validate_audit_nonneg_int(device_sequence_number, "device_sequence_number", _MAX_UINT32)
    return _compact_audit_id(d_id, f"ALN_e{epoch_val}_s{seq_val}")


def build_execution_failed_audit_id(
    directive_id: str, device_session_epoch: int, device_sequence_number: int
) -> str:
    d_id = _validate_directive_id_for_audit(directive_id)
    epoch_val = _validate_audit_nonneg_int(device_session_epoch, "device_session_epoch", _MAX_INT32)
    seq_val = _validate_audit_nonneg_int(device_sequence_number, "device_sequence_number", _MAX_UINT32)
    return _compact_audit_id(d_id, f"FAIL_e{epoch_val}_s{seq_val}")


def build_rejected_audit_id(
    directive_id: str,
    device_session_epoch: Optional[int] = None,
    device_sequence_number: Optional[int] = None,
) -> str:
    d_id = _validate_directive_id_for_audit(directive_id)
    if (device_session_epoch is None) != (device_sequence_number is None):
        raise ValueError(
            "device_session_epoch and device_sequence_number must both be provided or both omitted for REJECTED audit_id."
        )
    if device_session_epoch is None:
        return f"aud_{d_id}_REJ"
    epoch_val = _validate_audit_nonneg_int(device_session_epoch, "device_session_epoch", _MAX_INT32)
    seq_val = _validate_audit_nonneg_int(device_sequence_number, "device_sequence_number", _MAX_UINT32)
    return _compact_audit_id(d_id, f"REJ_e{epoch_val}_s{seq_val}")


class ActuatorDirectiveContract(BaseModel):
    """
    Actuator and gate directive computed by DRAIN-X decision engine for physical microcontrollers
    (ESP32) and simulated actuators. Open-loop supervisory directive with observable physical alignment.
    """
    directive_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Deterministic supervisory directive identifier")
    baseline_device_sequence_number: Optional[int] = Field(default=None, description="Sequence number of device at directive issue time")
    device_session_epoch: Optional[int] = Field(default=None, description="Device session epoch at directive issue time")
    section_id: str = Field(default="SEC_SCREENING_01", description="Monitored hydraulic section ID")
    device_id: Optional[str] = Field(default=None, description="Target device identifier")
    operational_mode: Optional[DirectiveOperationalMode] = Field(default=None, description="Operational mode when issued")
    directive_type: Literal["DIVERSION_GATE"] = Field(default="DIVERSION_GATE", description="Actuator directive class")
    gate_target_angle: float = Field(default=0.0, ge=0.0, le=90.0, description="Target diversion gate angle in degrees (0=closed, 90=diverted)")
    action: str = Field(default="MAINTAIN_NORMAL", description="Action code: MAINTAIN_NORMAL, DIVERT_FLOW, EMERGENCY_OVERFLOW_RELIEF, MONITOR_HIGH_WATER, SENSOR_FAULT_HOLD, SAFE_HOLD_LOCK")
    reason: str = Field(default="Channel hydraulics and trends within nominal safe bounds.", description="Diagnostic explanation for actuator directive")
    risk_level: AlertSeverity = Field(default=AlertSeverity.INFO, description="Assessed operational risk severity")
    emergency_stop: bool = Field(default=False, description="Emergency stop flag if critical faults exist")
    issuer_type: DirectiveIssuerType = Field(default=DirectiveIssuerType.AUTOMATED_ENGINE, description="Originating authority type")
    issuer_id: str = Field(default="intervention_engine", min_length=1, max_length=128, description="Originating authority identifier")
    correlation_id: Optional[str] = Field(default=None, max_length=64, description="Optional trace correlation identifier")
    timestamp: datetime = Field(default_factory=utc_now)


def quantize_numeric_5_2_decimal(
    v: Any, field_name: str, *, allow_none: bool = False
) -> Optional[Decimal]:
    """
    Validates a bounded angle/divergence value in [0, 90] and quantizes directly
    to PostgreSQL NUMERIC(5, 2) using Decimal arithmetic and ROUND_HALF_UP,
    normalizing -0.00 to 0.00 without lossy Decimal -> float conversion.
    """
    if v is None:
        if allow_none:
            return None
        raise ValueError(f"{field_name} is required.")
    if isinstance(v, bool):
        raise ValueError(f"{field_name} cannot be a boolean.")
    if isinstance(v, Decimal):
        if not v.is_finite():
            raise ValueError(f"{field_name} must be finite, got {v!r}.")
        dec = v
    elif isinstance(v, int):
        dec = Decimal(v)
    elif isinstance(v, float):
        if not math.isfinite(v):
            raise ValueError(f"{field_name} must be finite, got {v!r}.")
        dec = Decimal(str(v))
    else:
        raise ValueError(f"{field_name} must be numeric, got {type(v).__name__}.")

    if dec < Decimal("0") or dec > Decimal("90"):
        raise ValueError(f"{field_name} must be between 0.0 and 90.0 degrees, got {dec}.")

    quantized = dec.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    if quantized == 0:
        return Decimal("0.00")
    return quantized


def _reject_bool_coerce_finite_angle(v: Any, field_name: str, allow_none: bool = False) -> Optional[float]:
    quantized = quantize_numeric_5_2_decimal(v, field_name, allow_none=allow_none)
    if quantized is None:
        return None
    if quantized == 0:
        return 0.0
    return float(quantized)


def _reject_bool_coerce_bounded_int(v: Any, field_name: str, max_val: int) -> Optional[int]:
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError(f"{field_name} must be an integer, got {type(v).__name__}.")
    if v < 0 or v > max_val:
        raise ValueError(f"{field_name} must be between 0 and {max_val}, got {v}.")
    return v


def _validate_trimmed_text(
    v: Any, field_name: str, *, allow_none: bool = False, max_len: Optional[int] = None, strip_check: bool = True
) -> Optional[str]:
    if v is None:
        if allow_none:
            return None
        raise ValueError(f"{field_name} is required.")
    if not isinstance(v, str):
        raise ValueError(f"{field_name} must be a string, got {type(v).__name__}.")
    if not v.strip():
        raise ValueError(f"{field_name} cannot be empty or whitespace.")
    if strip_check and v != v.strip():
        raise ValueError(f"{field_name} cannot contain leading or trailing whitespace.")
    if max_len is not None and len(v) > max_len:
        raise ValueError(f"{field_name} exceeds maximum length {max_len}.")
    return v


class ActuatorDirectiveEventContract(BaseModel):
    """
    Immutable audit ledger record strictly aligned 1-to-1 with the 23 typed SQL columns
    of public.actuator_directive_audits in Migration 008.
    """
    model_config = ConfigDict(extra="forbid")

    audit_id: str = Field(..., description="Deterministic audit event identifier (VARCHAR 64)")
    directive_id: str = Field(..., description="Target supervisory directive identifier (VARCHAR 36)")
    event_type: DirectiveEventType = Field(..., description="Lifecycle transition event type")
    device_id: Optional[str] = Field(default=None, description="Physical device identifier associated with event")
    section_id: str = Field(..., description="Monitored hydraulic section identifier")
    operational_mode: DirectiveOperationalMode = Field(..., description="System operational mode when transition occurred")
    directive_type: Literal["DIVERSION_GATE"] = Field(default="DIVERSION_GATE", description="Actuator directive class")
    action: str = Field(..., description="Commanded action code")
    gate_target_angle: float = Field(..., description="Commanded diversion gate setpoint in degrees (0..90)")
    reason: str = Field(..., description="Diagnostic rationale for directive or lifecycle transition")
    risk_level: AlertSeverity = Field(default=AlertSeverity.INFO, description="Assessed operational risk severity")
    emergency_stop: bool = Field(default=False, description="Emergency stop flag")
    measured_gate_angle: Optional[float] = Field(default=None, description="Physical measured angle in degrees (0..90)")
    measured_gate_state: Optional[DirectiveMeasuredGateState] = Field(default=None, description="Firmware-reported gate state enum")
    execution_divergence_deg: Optional[float] = Field(default=None, description="Absolute angular deviation from target angle (0..90)")
    issuer_type: DirectiveIssuerType = Field(default=DirectiveIssuerType.AUTOMATED_ENGINE, description="Issuing entity category")
    issuer_id: str = Field(..., description="Issuing entity identifier")
    correlation_id: Optional[str] = Field(default=None, description="Optional trace correlation identifier")
    device_session_epoch: Optional[int] = Field(default=None, description="Observation session epoch of target device")
    baseline_device_sequence_number: Optional[int] = Field(default=None, description="Device sequence number at directive issue time")
    device_sequence_number: Optional[int] = Field(default=None, description="Sequence number observed in correlated feedback")
    device_uptime_ms: Optional[int] = Field(default=None, description="Hardware uptime counter in milliseconds")
    timestamp: datetime = Field(default_factory=utc_now, description="Timezone-aware UTC event recording timestamp")

    @field_validator("audit_id", mode="before")
    @classmethod
    def _validate_audit_id(cls, v: Any) -> str:
        val = _validate_trimmed_text(v, "audit_id", max_len=64)
        assert val is not None
        if not _AUDIT_ID_PATTERN.match(val):
            raise ValueError("audit_id contains disallowed characters; allowed [A-Za-z0-9_.:-].")
        return val

    @field_validator("directive_id", mode="before")
    @classmethod
    def _validate_directive_id(cls, v: Any) -> str:
        val = _validate_trimmed_text(v, "directive_id", max_len=36)
        assert val is not None
        if not _DIRECTIVE_ID_AUDIT_PATTERN.match(val):
            raise ValueError("directive_id contains disallowed characters; allowed [A-Za-z0-9_.:-].")
        return val

    @field_validator("device_id", "correlation_id", mode="before")
    @classmethod
    def _validate_optional_id(cls, v: Any, info) -> Optional[str]:
        return _validate_trimmed_text(v, info.field_name, allow_none=True, max_len=64)

    @field_validator("section_id", "action", mode="before")
    @classmethod
    def _validate_required_short_text(cls, v: Any, info) -> str:
        val = _validate_trimmed_text(v, info.field_name, max_len=64)
        assert val is not None
        return val

    @field_validator("reason", mode="before")
    @classmethod
    def _validate_reason(cls, v: Any) -> str:
        val = _validate_trimmed_text(v, "reason", strip_check=False)
        assert val is not None
        return val.strip()

    @field_validator("issuer_id", mode="before")
    @classmethod
    def _validate_issuer_id(cls, v: Any) -> str:
        val = _validate_trimmed_text(v, "issuer_id", max_len=128)
        assert val is not None
        return val

    @field_validator("emergency_stop", mode="before")
    @classmethod
    def _validate_emergency_stop(cls, v: Any) -> bool:
        if not isinstance(v, bool):
            raise ValueError(f"emergency_stop must be a boolean, got {type(v).__name__}.")
        return v

    @field_validator("gate_target_angle", mode="before")
    @classmethod
    def _validate_target_angle(cls, v: Any) -> float:
        val = _reject_bool_coerce_finite_angle(v, "gate_target_angle", allow_none=False)
        assert val is not None
        return val

    @field_validator("measured_gate_angle", "execution_divergence_deg", mode="before")
    @classmethod
    def _validate_optional_angles(cls, v: Any, info) -> Optional[float]:
        return _reject_bool_coerce_finite_angle(v, info.field_name, allow_none=True)

    @field_validator("device_session_epoch", mode="before")
    @classmethod
    def _validate_session_epoch(cls, v: Any) -> Optional[int]:
        return _reject_bool_coerce_bounded_int(v, "device_session_epoch", _MAX_INT32)

    @field_validator("baseline_device_sequence_number", "device_sequence_number", "device_uptime_ms", mode="before")
    @classmethod
    def _validate_uint32_counters(cls, v: Any, info) -> Optional[int]:
        return _reject_bool_coerce_bounded_int(v, info.field_name, _MAX_UINT32)

    @field_validator("timestamp", mode="before")
    @classmethod
    def _validate_timestamp(cls, v: Any) -> datetime:
        return normalize_audit_timestamp_utc(v)


class StagedDeliveryEnvelope(BaseModel):
    """
    Envelope staging an active supervisory directive for delivery
    upon edge microcontroller HTTP polling or telemetry ingestion response.
    """
    directive_id: str
    gate_target_angle: float
    action: str
    emergency_stop: bool
    issued_timestamp: datetime
    staged_timestamp: datetime = Field(default_factory=utc_now)


class ActuatorDirectiveResponseContract(BaseModel):
    """
    Structured query response for active and historical supervisory directives.
    """
    status: str = "success"
    active_directive: Optional[ActuatorDirectiveContract] = None
    events: list[ActuatorDirectiveEventContract] = Field(default_factory=list)


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


class AssignmentType(str, Enum):
    NONE = "NONE"
    TEAM = "TEAM"
    INDIVIDUAL = "INDIVIDUAL"


class IncidentUpdateContract(BaseModel):
    """
    Payload for updating an incident by municipal operators or field response crews.
    """
    status: Optional[IncidentStatus] = None
    severity: Optional[IncidentSeverity] = None
    assigned_to: Optional[str] = None
    assignment_type: Optional[AssignmentType] = None
    assigned_team_id: Optional[str] = None
    assigned_worker_id: Optional[str] = None
    municipal_notes: Optional[str] = None
    internal_notes: Optional[str] = None
    rejection_reason: Optional[str] = None
    verified_by: Optional[str] = None
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
    assignment_type: AssignmentType = AssignmentType.NONE
    assigned_team_id: Optional[str] = None
    assigned_worker_id: Optional[str] = None
    municipal_notes: Optional[str] = ""
    internal_notes: Optional[str] = None
    reporter_name: Optional[str] = "Citizen Anonymous"
    photos: list[str] = Field(default_factory=list, description="List of uploaded photo references")
    verified_at: Optional[datetime] = None
    verified_by: Optional[str] = None
    rejection_reason: Optional[str] = None
    origin_operational_mode: Optional[Literal["SIMULATION", "PHYSICAL", "SAFE_HOLD"]] = None


class FieldTeamContract(BaseModel):
    """
    Authoritative field crew and maintenance unit representation.
    Distinguishes demonstration/simulated crews from genuine municipal crews.
    """
    team_id: str
    name: str
    zone: str
    is_active: bool = True
    is_demo: bool = True
    is_verified_municipal_crew: bool = False
    capacity: int = 4
    contact_phone: Optional[str] = None


class IncidentAuditContract(BaseModel):
    """
    Durable, tamper-evident audit record capturing municipal triage,
    rejection, assignment, reassignment, and status transitions.
    """
    audit_id: str = Field(default_factory=lambda: f"AUD-{uuid.uuid4().hex[:8].upper()}")
    incident_id: str
    actor_id: str
    actor_role: str
    action: str  # REPORTED, VERIFIED, ASSIGNED, REASSIGNED, UNASSIGNED, PRIORITIZED, REJECTED, RESOLVED, STATUS_CHANGE
    previous_status: Optional[str] = None
    new_status: Optional[str] = None
    previous_assigned_to: Optional[str] = None
    new_assigned_to: Optional[str] = None
    previous_assignment_type: Optional[str] = None
    new_assignment_type: Optional[str] = None
    previous_assigned_team_id: Optional[str] = None
    new_assigned_team_id: Optional[str] = None
    previous_assigned_worker_id: Optional[str] = None
    new_assigned_worker_id: Optional[str] = None
    previous_severity: Optional[str] = None
    new_severity: Optional[str] = None
    reason: Optional[str] = None
    internal_notes: Optional[str] = None
    timestamp: datetime = Field(default_factory=utc_now)


class IncidentVerifyRequest(BaseModel):
    notes: Optional[str] = Field(default=None, max_length=1000)
    severity: Optional[IncidentSeverity] = None
    internal_notes: Optional[str] = Field(default=None, max_length=1000)


class IncidentAssignRequest(BaseModel):
    assigned_to: str = Field(..., min_length=2, max_length=128)
    assignment_type: Optional[AssignmentType] = None
    assigned_worker_id: Optional[str] = Field(default=None, max_length=128)
    reason: Optional[str] = Field(default="Municipal dispatch assignment", max_length=500)
    internal_notes: Optional[str] = Field(default=None, max_length=1000)
    is_demo_assignment: Optional[bool] = None


class IncidentReassignRequest(BaseModel):
    assigned_to: str = Field(..., min_length=2, max_length=128)
    assignment_type: Optional[AssignmentType] = None
    assigned_worker_id: Optional[str] = Field(default=None, max_length=128)
    reason: str = Field(..., min_length=3, max_length=500)
    internal_notes: Optional[str] = Field(default=None, max_length=1000)
    is_demo_assignment: Optional[bool] = None


class IncidentUnassignRequest(BaseModel):
    reason: str = Field(..., min_length=3, max_length=500)
    internal_notes: Optional[str] = Field(default=None, max_length=1000)


class IncidentRejectRequest(BaseModel):
    reason: str = Field(..., min_length=3, max_length=500)
    internal_notes: Optional[str] = Field(default=None, max_length=1000)


class MunicipalKpiResponseContract(BaseModel):
    """
    Server-side aggregated KPIs for municipal operational dashboard.
    Calculated strictly across the entire authoritative incident population.
    Clearly separates genuine field records from simulated demo seeds.
    """
    total_incidents: int
    open_incidents: int
    critical_or_high_incidents: int
    unassigned_incidents: int
    assigned_incidents: int
    investigating_incidents: int
    resolved_incidents: int
    rejected_incidents: int
    demo_incidents_count: int = 0
    genuine_incidents_count: int = 0
    by_category: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    by_source: dict[str, int] = Field(default_factory=dict)


class MunicipalQueueResponseContract(BaseModel):
    """
    Paginated operational incident queue response.
    """
    items: list[IncidentResponseContract]
    total_count: int
    limit: int
    offset: int
    has_more: bool


VALID_STATUS_TRANSITIONS: dict[IncidentStatus, set[IncidentStatus]] = {
    IncidentStatus.REPORTED: {
        IncidentStatus.VERIFIED,
        IncidentStatus.ASSIGNED,
        IncidentStatus.REJECTED,
    },
    IncidentStatus.VERIFIED: {
        IncidentStatus.ASSIGNED,
        IncidentStatus.REJECTED,
    },
    IncidentStatus.ASSIGNED: {
        IncidentStatus.INVESTIGATING,
        IncidentStatus.VERIFIED,
        IncidentStatus.REJECTED,
    },
    IncidentStatus.INVESTIGATING: {
        IncidentStatus.RESOLVED,
        IncidentStatus.ASSIGNED,
        IncidentStatus.REJECTED,
    },
    IncidentStatus.RESOLVED: set(),
    IncidentStatus.REJECTED: set(),
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


class DuplicateLinkStatus(str, Enum):
    SUSPECTED = "SUSPECTED"
    CONFIRMED = "CONFIRMED"
    DISMISSED = "DISMISSED"


class DuplicateConfidenceBand(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


DuplicateConfidenceLevel = DuplicateConfidenceBand


class CategoryMatchType(str, Enum):
    EXACT = "EXACT"
    RELATED = "RELATED"
    OTHER = "OTHER"


class DuplicateLinkContract(BaseModel):
    link_id: str = Field(..., min_length=5, max_length=32, description="Unique collision-safe link ID")
    incident_low_id: str = Field(..., description="Lexicographically smaller incident ID in canonical pair")
    incident_high_id: str = Field(..., description="Lexicographically larger incident ID in canonical pair")
    link_status: DuplicateLinkStatus = DuplicateLinkStatus.SUSPECTED
    primary_incident_id: Optional[str] = Field(default=None, description="Assigned primary incident ID when CONFIRMED")
    duplicate_incident_id: Optional[str] = Field(default=None, description="Assigned duplicate incident ID when CONFIRMED")
    detection_origin: Literal["AUTOMATED", "MANUAL"] = "AUTOMATED"
    detected_in_mode: Literal["SIMULATION", "PHYSICAL", "SAFE_HOLD"] = "SIMULATION"
    distance_meters: float = Field(..., ge=0.0)
    time_delta_seconds: int = Field(..., ge=0)
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    confidence_band: DuplicateConfidenceBand
    match_reasons: list[str] = Field(default_factory=list)
    review_version: int = Field(default=0, ge=0)
    reviewed_by: Optional[str] = None
    reviewed_role: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    review_reason: Optional[str] = None
    internal_notes: Optional[str] = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class MunicipalDuplicateIncidentSummaryContract(BaseModel):
    """
    Explicitly allowlisted incident summary for municipal duplicate review responses.
    Excludes reporter PII (reporter_name), internal staff notes (internal_notes),
    worker/verifier identities, rejection reasons, and raw photo references.
    """
    model_config = ConfigDict(extra="forbid")

    id: str
    category: IncidentCategory
    description: str
    latitude: float
    longitude: float
    severity: IncidentSeverity
    status: IncidentStatus
    source: IncidentSource
    origin_operational_mode: Optional[Literal["SIMULATION", "PHYSICAL", "SAFE_HOLD"]] = None
    assigned_to: Optional[str] = None
    assignment_type: AssignmentType = AssignmentType.NONE
    assigned_team_id: Optional[str] = None
    municipal_notes: Optional[str] = ""
    photo_count: int = Field(default=0, ge=0)
    created_at: datetime
    updated_at: datetime


class MunicipalDuplicateLinkContract(BaseModel):
    """
    Explicitly allowlisted duplicate link representation for municipal review responses.
    Excludes link-level internal_notes while preserving review state, scoring metadata,
    and concurrency version.
    """
    model_config = ConfigDict(extra="forbid")

    link_id: str = Field(..., min_length=5, max_length=32, description="Unique collision-safe link ID")
    incident_low_id: str = Field(..., description="Lexicographically smaller incident ID in canonical pair")
    incident_high_id: str = Field(..., description="Lexicographically larger incident ID in canonical pair")
    link_status: DuplicateLinkStatus = DuplicateLinkStatus.SUSPECTED
    primary_incident_id: Optional[str] = Field(default=None, description="Assigned primary incident ID when CONFIRMED")
    duplicate_incident_id: Optional[str] = Field(default=None, description="Assigned duplicate incident ID when CONFIRMED")
    detection_origin: Literal["AUTOMATED", "MANUAL"] = "AUTOMATED"
    detected_in_mode: Literal["SIMULATION", "PHYSICAL", "SAFE_HOLD"] = "SIMULATION"
    distance_meters: float = Field(..., ge=0.0)
    time_delta_seconds: int = Field(..., ge=0)
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    confidence_band: DuplicateConfidenceBand
    match_reasons: list[str] = Field(default_factory=list)
    review_version: int = Field(default=0, ge=0)
    reviewed_by: Optional[str] = None
    reviewed_role: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    review_reason: Optional[str] = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class DuplicateLinkDetailContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    link: MunicipalDuplicateLinkContract
    incident_low: Optional[MunicipalDuplicateIncidentSummaryContract] = None
    incident_high: Optional[MunicipalDuplicateIncidentSummaryContract] = None
    primary_incident: Optional[MunicipalDuplicateIncidentSummaryContract] = None
    duplicate_incident: Optional[MunicipalDuplicateIncidentSummaryContract] = None


class DuplicateQueueResponseContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[DuplicateLinkDetailContract]
    total: int
    suspected_count: int
    confirmed_count: int
    dismissed_count: int


class DuplicateConfirmRequest(BaseModel):
    primary_incident_id: str = Field(..., description="Target primary incident ID from the canonical pair")
    reason: str = Field(..., min_length=3, max_length=500, description="Mandatory review justification")
    internal_notes: Optional[str] = Field(default=None, max_length=1000)
    override: bool = Field(default=False, description="Explicit supervisor override flag")
    expected_version: Optional[int] = Field(default=None, ge=0, description="Optional optimistic concurrency version")


class DuplicateDismissRequest(BaseModel):
    reason: str = Field(..., min_length=3, max_length=500, description="Mandatory dismissal justification")
    internal_notes: Optional[str] = Field(default=None, max_length=1000)
    override: bool = Field(default=False, description="Explicit supervisor override flag")
    expected_version: Optional[int] = Field(default=None, ge=0, description="Optional optimistic concurrency version")


class DuplicateScanResponseContract(BaseModel):
    incident_id: str
    status: str
    candidates_found: int
    links_created: int
    total_links: int = 0
    scanned_at: datetime = Field(default_factory=utc_now)


# =====================================================================
# Milestone 2B: Real-Time Incident Stream Contracts
# =====================================================================

class IncidentStreamEventType(str, Enum):
    INCIDENT_REPORTED = "INCIDENT_REPORTED"
    INCIDENT_TRIAGED = "INCIDENT_TRIAGED"
    INCIDENT_ASSIGNED = "INCIDENT_ASSIGNED"
    INCIDENT_IN_PROGRESS = "INCIDENT_IN_PROGRESS"
    INCIDENT_RESOLVED = "INCIDENT_RESOLVED"
    INCIDENT_REJECTED = "INCIDENT_REJECTED"
    INCIDENT_PHOTOS_ATTACHED = "INCIDENT_PHOTOS_ATTACHED"
    DUPLICATE_SUSPECTED = "DUPLICATE_SUSPECTED"
    DUPLICATE_REVIEWED = "DUPLICATE_REVIEWED"
    HEARTBEAT = "HEARTBEAT"
    RESYNC_REQUIRED = "RESYNC_REQUIRED"


class IncidentStreamEvent(BaseModel):
    """
    Standardized real-time incident event frame.
    Strictly forbids unexpected fields and encapsulates role-projected data.
    """
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(..., description="Unique event identifier")
    seq_id: int = Field(..., ge=0, description="Process-local monotonically increasing sequence number")
    instance_id: str = Field(..., description="Process instance identifier for multi-replica detection")
    timestamp: datetime = Field(..., description="UTC ISO-8601 event timestamp")
    event_type: IncidentStreamEventType = Field(..., description="Lifecycle or stream control event type")
    incident_id: Optional[str] = Field(default=None, description="Target incident ID")
    action: Optional[str] = Field(default=None, description="Action triggering the event: CREATE, VERIFY, ASSIGN, etc.")
    previous_status: Optional[str] = Field(default=None, description="Previous status before transition")
    new_status: Optional[str] = Field(default=None, description="New status after transition")
    assigned_team_id: Optional[str] = Field(default=None, description="Assigned team identifier")
    assigned_worker_id: Optional[str] = Field(default=None, description="Assigned individual worker identifier")
    previous_assigned_team_id: Optional[str] = Field(default=None, description="Previous assigned team identifier")
    previous_assigned_worker_id: Optional[str] = Field(default=None, description="Previous assigned worker identifier")
    incident: Optional[IncidentResponseContract] = Field(default=None, description="Role-projected incident snapshot")
    duplicate_link: Optional[MunicipalDuplicateLinkContract] = Field(
        default=None, description="Municipal duplicate review details; strictly null for non-municipal roles"
    )
    reason: Optional[str] = Field(default=None, description="Optional informational or error message")


class IncidentStreamInitMessage(BaseModel):
    """
    Initial handshake payload delivered to a newly connected incident stream client.
    """
    model_config = ConfigDict(extra="forbid")

    event_type: str = Field(default="INIT", description="Protocol handshake type")
    protocol_version: str = Field(default="1.0", description="Incident stream protocol version")
    client_id: str = Field(..., description="Assigned client connection identifier")
    instance_id: str = Field(..., description="Process instance identifier")
    current_seq_id: int = Field(..., ge=0, description="Highest processed sequence number on this instance")
    user_id: str = Field(..., description="Verified user subject identifier")
    role: str = Field(..., description="Verified role: citizen, worker, municipality, admin, service_role")
    team_id: Optional[str] = Field(default=None, description="Verified worker team, if applicable")
    connection_time: datetime = Field(..., description="UTC timestamp of connection acceptance")
    message: str = Field(default="Connected to DRAIN-X authoritative incident stream")
    max_queue_size: int = Field(default=100)
    heartbeat_interval_sec: float = Field(default=15.0)

