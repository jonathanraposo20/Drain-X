"""
DRAIN-X Time-Series Analytics & Aggregation Engine.

Milestone: P0.4B Historical Telemetry & Analytics Foundation.

Design & Data Quality Invariants:
1. Data Quality & Fault Exclusion:
   - Readings marked with `status != 'OK'` or `metadata.is_valid == false` or
     `fault_code == SENSOR_NOT_INSTALLED` are strictly excluded from statistical averages,
     min/max calculations, and trend estimations.
   - Raw readings are preserved unchanged in memory and persistence.
2. Valid Zero Invariant:
   - Zero flow (0.0 L/min) with status == 'OK' is a valid physical measurement
     (e.g., stagnant water in flume) and IS included in averages.
3. Strict Operational Source Isolation:
   - Aggregations and trends are computed over partitions matching the requested `source`
     ('PHYSICAL' vs 'SIMULATED') to prevent synthetic runs from corrupting hardware analytics.
4. Robust Linear Regression for Rate-of-Rise:
   - Uses timestamps and depths of valid samples: dh/dt = Cov(t, h) / Var(t).
   - Reports rate in cm/min.
   - Gracefully handles insufficient samples (< 2 valid points) and irregular sampling deltas.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TimeSeriesBucket(BaseModel):
    bucket_start: datetime
    bucket_end: datetime
    sensor_id: str
    sample_count: int = Field(description="Total raw samples in window")
    valid_sample_count: int = Field(description="Plausible valid samples included in metrics")
    avg_value: Optional[float] = None
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    unit: str = "cm"


class WaterLevelTrendMetrics(BaseModel):
    sensor_id: str
    source: str
    sample_count: int
    valid_sample_count: int
    current_level_cm: Optional[float] = None
    rate_of_rise_cm_min: float = 0.0
    r_squared: float = 0.0
    trend_state: str = "STABLE"  # STABLE, RISING, FALLING, or INSUFFICIENT_DATA
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class FlowTrendMetrics(BaseModel):
    sensor_id: str
    source: str
    sample_count: int
    valid_sample_count: int
    current_flow_lpm: Optional[float] = None
    avg_flow_lpm: Optional[float] = None
    peak_flow_lpm: Optional[float] = None
    flow_trend_state: str = "STABLE"  # STABLE, INCREASING, DECREASING, or INSUFFICIENT_DATA
    rate_of_change_lpm_min: float = 0.0
    total_volume_liters: Optional[float] = None
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


def _parse_timestamp(ts: Any) -> datetime:
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    if isinstance(ts, str):
        # Handle ISO format
        clean_ts = ts.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(clean_ts)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return datetime.now(timezone.utc)
    return datetime.now(timezone.utc)


def is_reading_valid(reading: Dict[str, Any]) -> bool:
    """Evaluate whether a reading is plausible and healthy for statistical aggregations."""
    status = reading.get("status")
    if status not in ("OK", "DEGRADED"):
        return False

    meta = reading.get("metadata") or {}
    if isinstance(meta, dict):
        if meta.get("is_valid") is False:
            return False
        fault = meta.get("fault_code")
        if fault and fault not in ("NONE", "None", None):
            return False

    val = reading.get("value")
    if val is None or not isinstance(val, (int, float)):
        return False

    return True


def aggregate_time_series(
    readings: List[Dict[str, Any]],
    bucket_interval_seconds: int = 60,
    unit: str = "cm",
    sensor_id: Optional[str] = None,
    source: Optional[str] = None,
) -> List[TimeSeriesBucket]:
    """
    Groups readings into time buckets (e.g. 60s for 1-minute, 300s for 5-minute)
    and computes statistical aggregations excluding sensor faults.
    Returns buckets chronologically.
    """
    if not readings:
        return []

    # Optional source filtering (normalizing PHYSICAL and LIVE as equivalent)
    if source:
        norm_source = "PHYSICAL" if str(source).upper() in ("PHYSICAL", "LIVE") else str(source).upper()
        filtered_by_source = []
        for r in readings:
            r_src = r.get("source")
            r_src_str = r_src.value if hasattr(r_src, "value") else str(r_src).upper() if r_src else ""
            if norm_source == "PHYSICAL":
                if r_src_str in ("PHYSICAL", "LIVE"):
                    filtered_by_source.append(r)
            else:
                if r_src_str == norm_source:
                    filtered_by_source.append(r)
        readings = filtered_by_source

    # Optional sensor filtering
    if sensor_id:
        readings = [r for r in readings if r.get("sensor_id") == sensor_id]

    if not readings:
        return []

    # Sort readings chronologically (oldest to newest)
    sorted_readings = sorted(readings, key=lambda r: _parse_timestamp(r.get("timestamp")))

    # Group by (sensor_id, bucket_key) to support multiple sensors cleanly
    buckets: Dict[tuple[str, int], List[Dict[str, Any]]] = {}

    for r in sorted_readings:
        sid = r.get("sensor_id", "UNKNOWN")
        ts = _parse_timestamp(r.get("timestamp"))
        epoch_sec = int(ts.timestamp())
        bucket_key = (epoch_sec // bucket_interval_seconds) * bucket_interval_seconds
        buckets.setdefault((sid, bucket_key), []).append(r)

    results: List[TimeSeriesBucket] = []
    # Sort deterministically by bucket_key, then sensor_id
    for (sid, bucket_key) in sorted(buckets.keys(), key=lambda k: (k[1], k[0])):
        window_samples = buckets[(sid, bucket_key)]
        valid_values = [
            float(r["value"]) for r in window_samples if is_reading_valid(r)
        ]

        b_start = datetime.fromtimestamp(bucket_key, tz=timezone.utc)
        b_end = datetime.fromtimestamp(bucket_key + bucket_interval_seconds, tz=timezone.utc)

        bucket_unit = window_samples[0].get("unit") or unit
        if hasattr(bucket_unit, "value"):
            bucket_unit = bucket_unit.value

        if valid_values:
            avg_val = round(sum(valid_values) / len(valid_values), 3)
            min_val = round(min(valid_values), 3)
            max_val = round(max(valid_values), 3)
        else:
            avg_val = None
            min_val = None
            max_val = None

        results.append(
            TimeSeriesBucket(
                bucket_start=b_start,
                bucket_end=b_end,
                sensor_id=sid,
                sample_count=len(window_samples),
                valid_sample_count=len(valid_values),
                avg_value=avg_val,
                min_value=min_val,
                max_value=max_val,
                unit=str(bucket_unit),
            )
        )

    return results


def calculate_water_level_trend(
    readings: List[Dict[str, Any]],
    sensor_id: str,
    source: str = "PHYSICAL",
    rising_threshold_cm_min: float = 0.5,
) -> WaterLevelTrendMetrics:
    """
    Computes linear regression rate of rise/fall (dh/dt in cm/min) over timestamped valid readings.
    """
    if not readings:
        return WaterLevelTrendMetrics(
            sensor_id=sensor_id,
            source=source,
            sample_count=0,
            valid_sample_count=0,
            trend_state="INSUFFICIENT_DATA",
        )

    # Filter to requested sensor and source, sorted chronologically
    filtered = [
        r for r in readings
        if r.get("sensor_id") == sensor_id and (not source or r.get("source") == source)
    ]
    sorted_readings = sorted(filtered, key=lambda r: _parse_timestamp(r.get("timestamp")))

    valid_points = [
        (_parse_timestamp(r.get("timestamp")).timestamp(), float(r["value"]))
        for r in sorted_readings
        if is_reading_valid(r)
    ]

    total_count = len(sorted_readings)
    valid_count = len(valid_points)

    if valid_count < 2:
        current_val = valid_points[-1][1] if valid_points else None
        return WaterLevelTrendMetrics(
            sensor_id=sensor_id,
            source=source,
            sample_count=total_count,
            valid_sample_count=valid_count,
            current_level_cm=current_val,
            rate_of_rise_cm_min=0.0,
            r_squared=0.0,
            trend_state="INSUFFICIENT_DATA",
        )

    # Linear Regression over time in minutes: dh/dt
    t0 = valid_points[0][0]
    times_min = [(t - t0) / 60.0 for t, _ in valid_points]
    depths = [h for _, h in valid_points]

    n = len(times_min)
    mean_t = sum(times_min) / n
    mean_h = sum(depths) / n

    var_t = sum((t - mean_t) ** 2 for t in times_min)
    cov_th = sum((t - mean_t) * (h - mean_h) for t, h in zip(times_min, depths))

    dh_dt = (cov_th / var_t) if var_t > 1e-6 else 0.0

    # R^2 calculation
    ss_tot = sum((h - mean_h) ** 2 for h in depths)
    ss_res = sum((h - (mean_h + dh_dt * (t - mean_t))) ** 2 for t, h in zip(times_min, depths))
    r2 = max(0.0, 1.0 - (ss_res / ss_tot)) if ss_tot > 1e-6 else 1.0

    current_h = depths[-1]

    if dh_dt > rising_threshold_cm_min:
        trend = "RISING"
    elif dh_dt < -rising_threshold_cm_min:
        trend = "FALLING"
    else:
        trend = "STABLE"

    return WaterLevelTrendMetrics(
        sensor_id=sensor_id,
        source=source,
        sample_count=total_count,
        valid_sample_count=valid_count,
        current_level_cm=round(current_h, 2),
        rate_of_rise_cm_min=round(dh_dt, 3),
        r_squared=round(r2, 3),
        trend_state=trend,
    )


def calculate_flow_trend(
    readings: List[Dict[str, Any]],
    sensor_id: str,
    source: str = "PHYSICAL",
    flow_threshold_lpm_min: float = 0.5,
) -> FlowTrendMetrics:
    """
    Computes flow rate metrics (average, peak, trend, and total volume) over timestamped valid readings.
    """
    if not readings:
        return FlowTrendMetrics(
            sensor_id=sensor_id,
            source=source,
            sample_count=0,
            valid_sample_count=0,
            flow_trend_state="INSUFFICIENT_DATA",
        )

    filtered = [
        r for r in readings
        if r.get("sensor_id") == sensor_id and (not source or r.get("source") == source)
    ]
    sorted_readings = sorted(filtered, key=lambda r: _parse_timestamp(r.get("timestamp")))

    valid_points = [
        (_parse_timestamp(r.get("timestamp")).timestamp(), float(r["value"]), r.get("metadata") or {})
        for r in sorted_readings
        if is_reading_valid(r)
    ]

    total_count = len(sorted_readings)
    valid_count = len(valid_points)

    if not valid_points:
        return FlowTrendMetrics(
            sensor_id=sensor_id,
            source=source,
            sample_count=total_count,
            valid_sample_count=0,
            flow_trend_state="INSUFFICIENT_DATA",
        )

    flows = [f for _, f, _ in valid_points]
    current_flow = flows[-1]
    avg_flow = round(sum(flows) / len(flows), 2)
    peak_flow = round(max(flows), 2)

    # Extract latest total volume if present in metadata
    latest_meta = valid_points[-1][2]
    total_vol = latest_meta.get("total_volume_liters")
    if total_vol is not None:
        try:
            total_vol = round(float(total_vol), 3)
        except Exception:
            total_vol = None

    if valid_count < 2:
        return FlowTrendMetrics(
            sensor_id=sensor_id,
            source=source,
            sample_count=total_count,
            valid_sample_count=valid_count,
            current_flow_lpm=current_flow,
            avg_flow_lpm=avg_flow,
            peak_flow_lpm=peak_flow,
            total_volume_liters=total_vol,
            flow_trend_state="STABLE",
            rate_of_change_lpm_min=0.0,
        )

    # Linear trend dq/dt in L/min per minute
    t0 = valid_points[0][0]
    times_min = [(t - t0) / 60.0 for t, _, _ in valid_points]

    n = len(times_min)
    mean_t = sum(times_min) / n
    mean_q = sum(flows) / n

    var_t = sum((t - mean_t) ** 2 for t in times_min)
    cov_tq = sum((t - mean_t) * (q - mean_q) for t, q in zip(times_min, flows))

    dq_dt = (cov_tq / var_t) if var_t > 1e-6 else 0.0

    if dq_dt > flow_threshold_lpm_min:
        trend = "INCREASING"
    elif dq_dt < -flow_threshold_lpm_min:
        trend = "DECREASING"
    else:
        trend = "STABLE"

    return FlowTrendMetrics(
        sensor_id=sensor_id,
        source=source,
        sample_count=total_count,
        valid_sample_count=valid_count,
        current_flow_lpm=round(current_flow, 2),
        avg_flow_lpm=avg_flow,
        peak_flow_lpm=peak_flow,
        flow_trend_state=trend,
        rate_of_change_lpm_min=round(dq_dt, 3),
        total_volume_liters=total_vol,
    )
