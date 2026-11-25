"""
DRAIN-X Actuator Directive & Telemetry Canonical Digest Module.

Provides deterministic, type-tagged recursive dictionary canonicalization,
SHA-256 hash digests for individual sensor readings and aggregate observations,
and strict intermediate-angle physical alignment consistency evaluation.
"""

import math
import hashlib
import json
from decimal import Decimal
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
from app.models.contracts import SensorReadingContract


# Server-generated or ephemeral fields excluded from canonical digests
EXCLUDED_SERVER_FIELDS = frozenset({"message_id", "timestamp", "version"})

# Valid firmware gate states serialized by ESP32 firmware
VALID_FIRMWARE_GATE_STATES = frozenset({"CLOSED", "OPEN", "SAFE_HOLD", "UNINITIALIZED"})


def canonicalize_value(val: Any) -> Any:
    """
    Recursively canonicalizes a value for deterministic hashing and serialization.
    Preserves type distinctions:
      - bool -> ["bool", True|False] (must precede int check in Python)
      - int -> ["int", integer_value]
      - float ->
          if NaN -> ["non_finite", "NaN"]
          if +Inf -> ["non_finite", "+Inf"]
          if -Inf -> ["non_finite", "-Inf"]
          else -> ["float", normalized_float] (normalizes -0.0 to 0.0)
      - str -> ["str", string_value]
      - dict -> sorted string keys recursively canonicalized
      - list/tuple -> list of recursively canonicalized elements
      - None -> None
    """
    if val is None:
        return None

    # CRITICAL: In Python, bool is a subclass of int. Check bool first!
    if isinstance(val, bool):
        return ["bool", val]

    if isinstance(val, int):
        return ["int", val]

    if isinstance(val, float):
        if math.isnan(val):
            return ["non_finite", "NaN"]
        if math.isinf(val):
            return ["non_finite", "+Inf" if val > 0 else "-Inf"]
        # Normalize -0.0 to 0.0
        norm_float = 0.0 if val == 0.0 else val
        return ["float", norm_float]

    if isinstance(val, str):
        return ["str", val]

    if isinstance(val, dict):
        canonical_dict = {}
        for k in sorted(val.keys(), key=lambda x: str(x)):
            if not isinstance(k, str):
                raise TypeError(f"Dictionary keys must be strings, got {type(k).__name__}")
            canonical_dict[k] = canonicalize_value(val[k])
        return canonical_dict

    if isinstance(val, (list, tuple)):
        return [canonicalize_value(item) for item in val]

    # Fallback to string representation for enums or custom types
    if hasattr(val, "value"):
        return ["str", str(val.value)]

    return ["str", str(val)]


def _extract_reading_dict(reading: Union[SensorReadingContract, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Extracts a clean dictionary from a SensorReadingContract or dictionary,
    excluding server-generated metadata fields.
    """
    if isinstance(reading, SensorReadingContract):
        raw_dict = reading.model_dump()
    elif isinstance(reading, dict):
        raw_dict = dict(reading)
    else:
        raise TypeError(f"Expected SensorReadingContract or dict, got {type(reading).__name__}")

    # Remove server-generated metadata
    for field in EXCLUDED_SERVER_FIELDS:
        raw_dict.pop(field, None)

    # Normalize enum values
    if "source" in raw_dict and hasattr(raw_dict["source"], "value"):
        raw_dict["source"] = raw_dict["source"].value
    if "sensor_type" in raw_dict and hasattr(raw_dict["sensor_type"], "value"):
        raw_dict["sensor_type"] = raw_dict["sensor_type"].value

    return raw_dict


def compute_reading_digest(reading: Union[SensorReadingContract, Dict[str, Any]]) -> str:
    """
    Computes a deterministic SHA-256 hex digest for an individual sensor reading.
    Ignores server-generated fields (message_id, timestamp, version).
    """
    clean_dict = _extract_reading_dict(reading)
    canonical = canonicalize_value(clean_dict)
    serialized = json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def compute_aggregate_observation_digest(
    readings: Sequence[Union[SensorReadingContract, Dict[str, Any]]]
) -> str:
    """
    Computes a deterministic SHA-256 hex digest across an aggregate batch of readings.
    Sorts readings by (sensor_id, sensor_type) before hashing to ensure order independence.
    """
    cleaned_readings: List[Dict[str, Any]] = [_extract_reading_dict(r) for r in readings]

    def _sort_key(item: Dict[str, Any]) -> Tuple[str, str]:
        s_id = str(item.get("sensor_id", ""))
        s_type = str(item.get("sensor_type", ""))
        return (s_id, s_type)

    cleaned_readings.sort(key=_sort_key)
    canonical_list = [canonicalize_value(r) for r in cleaned_readings]

    serialized = json.dumps(
        canonical_list,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def evaluate_alignment_consistency(
    target_angle: float,
    measured_angle: Any,
    measured_state: Any,
    tolerance: float = 2.0,
) -> Tuple[bool, Optional[str], Optional[float]]:
    """
    Evaluates physical alignment consistency between a supervisory setpoint and measured feedback.

    Firmware alignment rules:
      - Endpoint 0.0 deg: requires measured_state == "CLOSED" and error <= tolerance.
      - Endpoint 90.0 deg: requires measured_state == "OPEN" and error <= tolerance.
      - Intermediate angles (0.0 < target < 90.0):
          Firmware commandAngle() updates _current_angle but does NOT update _state.
          Therefore, measured_state in ("CLOSED", "OPEN") is permitted.
          measured_state in ("SAFE_HOLD", "UNINITIALIZED") is strictly rejected.
          Requires error <= tolerance.

    Strict validation:
      - Reject Python booleans.
      - Reject non-finite floats (NaN, +Inf, -Inf).
      - Target angle must be in [0.0, 90.0].
      - Tolerance must be >= 0.0.
      - Measured state must be a recognized firmware enum string.

    Returns:
      (is_consistent, failure_reason_or_none, angular_error_or_none)
    """
    # 1. Type validation: reject booleans
    if isinstance(target_angle, bool) or isinstance(measured_angle, bool) or isinstance(tolerance, bool):
        return (False, "Boolean type rejected as numeric angle or tolerance", None)

    # 2. Numeric type validation
    if not isinstance(target_angle, (int, float, Decimal)):
        return (False, f"Non-numeric target angle: {type(target_angle).__name__}", None)
    if not isinstance(measured_angle, (int, float, Decimal)):
        return (False, f"Non-numeric measured angle: {type(measured_angle).__name__}", None)
    if not isinstance(tolerance, (int, float, Decimal)):
        return (False, f"Non-numeric tolerance: {type(tolerance).__name__}", None)

    t_angle = float(target_angle)
    m_angle = float(measured_angle)
    tol = float(tolerance)

    # 3. Finiteness validation
    if not (math.isfinite(t_angle) and math.isfinite(m_angle) and math.isfinite(tol)):
        return (False, "Non-finite numeric value (NaN or Inf) rejected", None)

    # 4. Range validation
    if not (0.0 <= t_angle <= 90.0):
        return (False, f"Target angle {t_angle} out of valid [0.0, 90.0] range", None)
    if not (0.0 <= m_angle <= 90.0):
        return (False, f"Measured angle {m_angle} out of valid [0.0, 90.0] range", None)
    if tol < 0.0:
        return (False, f"Negative tolerance {tol} rejected", None)

    # 5. Measured state validation
    if not isinstance(measured_state, str) or measured_state not in VALID_FIRMWARE_GATE_STATES:
        return (False, f"Invalid measured state: {measured_state!r}", None)

    # Actuator states SAFE_HOLD and UNINITIALIZED can never satisfy supervisory alignment
    if measured_state in ("SAFE_HOLD", "UNINITIALIZED"):
        return (False, f"Gate state '{measured_state}' cannot satisfy operational alignment", None)

    angular_error = abs(m_angle - t_angle)

    # 6. Endpoint 0.0 deg
    if t_angle == 0.0:
        if measured_state != "CLOSED":
            return (
                False,
                f"Endpoint 0.0 deg requires measured_state 'CLOSED', observed '{measured_state}'",
                angular_error,
            )
        if angular_error > tol:
            return (
                False,
                f"Angular error {angular_error:.2f} deg exceeds tolerance {tol:.2f} deg",
                angular_error,
            )
        return (True, None, angular_error)

    # 7. Endpoint 90.0 deg
    if t_angle == 90.0:
        if measured_state != "OPEN":
            return (
                False,
                f"Endpoint 90.0 deg requires measured_state 'OPEN', observed '{measured_state}'",
                angular_error,
            )
        if angular_error > tol:
            return (
                False,
                f"Angular error {angular_error:.2f} deg exceeds tolerance {tol:.2f} deg",
                angular_error,
            )
        return (True, None, angular_error)

    # 8. Intermediate angle (0.0 < target < 90.0)
    # commandAngle() updates _current_angle without changing _state
    if measured_state not in ("CLOSED", "OPEN"):
        return (
            False,
            f"Intermediate angle requires measured_state in ('CLOSED', 'OPEN'), observed '{measured_state}'",
            angular_error,
        )
    if angular_error > tol:
        return (
            False,
            f"Angular error {angular_error:.2f} deg exceeds tolerance {tol:.2f} deg",
            angular_error,
        )

    return (True, None, angular_error)
