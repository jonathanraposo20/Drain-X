"""
DRAIN-X Actuator Directive Audit Ledger & Device Session Verification Tests.

Validates:
1. Mixed partial-batch completion with identical overlap plus a new sensor.
2. Conflicting overlap rejects the entire merge atomically.
3. Firmware-version and actuator-snapshot conflicts reject merging.
4. Subset retransmission is classified as DUPLICATE.
5. Pending-reboot staged observations use identical merge semantics.
6. Recursive metadata canonicalization is key-order independent.
7. Boolean, integer, and float values remain type-distinct.
8. Float canonical fields normalize 0, 0.0, and -0.0.
9. NaN, positive infinity, and negative infinity receive distinct deterministic tags in metadata.
10. Invalid core numeric values cannot advance session state or correlate actuator feedback.
11. Aggregate digest is independent of sensor input order.
12. Partial-batch merge recomputes the same aggregate digest as a complete observation.
13. LRU capacity remains exactly 256 after insertion.
14. Touching an old observation makes it MRU and protects it from eviction.
15. Reboot inference, uptime rollover, replay protection, and candidate expiration.
16. Directive correlation occurs once and only for eligible active directives.
17. Terminal directives do not stop raw telemetry processing.
18. Startup recovery resolves incomplete directives idempotently.
"""

import math
import time
from datetime import datetime, timezone
import pytest

from app.models.contracts import (
    SensorReadingContract,
    SensorType,
    MeasurementUnit,
    DataSource,
    SensorHealthStatus,
    ActuatorDirectiveContract,
    DirectiveEventType,
    ActuatorDirectiveEventContract,
    AlertSeverity,
)
from app.services.actuator_digest import (
    canonicalize_value,
    compute_reading_digest,
    compute_aggregate_observation_digest,
    evaluate_alignment_consistency,
)
from app.services.state_store import StateStore
from app.services.persistence_repository import PersistenceRepository


def _make_reading(
    sensor_id: str = "US_UPSTREAM_01",
    sensor_type: SensorType = SensorType.WATER_LEVEL,
    value: float = 5.0,
    seq: int = 1,
    uptime_ms: int = 1000,
    device_id: str = "DRAINX-ESP32-NODE-01",
    gate_angle: float | None = 0.0,
    gate_state: str | None = "CLOSED",
    firmware_version: str | None = "0.3.7",
    metadata: dict | None = None,
) -> SensorReadingContract:
    meta = dict(metadata or {})
    if gate_state is not None:
        meta["gate_state"] = gate_state
    if firmware_version is not None:
        meta["firmware_version"] = firmware_version
    return SensorReadingContract(
        sensor_id=sensor_id,
        section_id="SEC_SCREENING_01",
        sensor_type=sensor_type,
        value=value,
        unit=MeasurementUnit.CENTIMETRE if sensor_type == SensorType.WATER_LEVEL else MeasurementUnit.LITRES_PER_MINUTE,
        source=DataSource.PHYSICAL,
        status=SensorHealthStatus.OK,
        device_id=device_id,
        sequence_number=seq,
        uptime_ms=uptime_ms,
        gate_angle_deg=gate_angle,
        metadata=meta,
    )


# =====================================================================
# Test 1: Mixed partial-batch completion
# =====================================================================
def test_mixed_partial_batch_completion_identical_overlap_plus_new_sensor():
    store = StateStore()
    store.clear()
    store.mode = "PHYSICAL"

    # First observation contains only WATER_LEVEL
    r1 = _make_reading(sensor_id="US_UPSTREAM_01", sensor_type=SensorType.WATER_LEVEL, seq=10, uptime_ms=5000)
    status1, obs1 = store.process_telemetry_observation([r1])
    assert status1 == "NEW"
    assert obs1 is not None
    assert len(obs1.sensor_digests) == 1
    assert "US_UPSTREAM_01" in obs1.sensor_digests

    # Second arrival has identical WATER_LEVEL plus new FLOW_RATE
    r1_repeat = _make_reading(sensor_id="US_UPSTREAM_01", sensor_type=SensorType.WATER_LEVEL, seq=10, uptime_ms=5000)
    r2_new = _make_reading(sensor_id="FS_FLUME_01", sensor_type=SensorType.FLOW_RATE, value=12.5, seq=10, uptime_ms=5000)

    status2, obs2 = store.process_telemetry_observation([r1_repeat, r2_new])
    assert status2 == "PARTIAL_BATCH_COMPLETION"
    assert obs2 is not None
    assert len(obs2.sensor_digests) == 2
    assert "US_UPSTREAM_01" in obs2.sensor_digests
    assert "FS_FLUME_01" in obs2.sensor_digests


# =====================================================================
# Test 2: Conflicting overlap rejects the entire merge atomically
# =====================================================================
def test_conflicting_overlap_rejects_entire_merge_atomically():
    store = StateStore()
    store.clear()
    store.mode = "PHYSICAL"

    # Initial reading with value=5.0
    r1 = _make_reading(sensor_id="US_UPSTREAM_01", value=5.0, seq=20, uptime_ms=8000)
    status1, obs1 = store.process_telemetry_observation([r1])
    assert status1 == "NEW"
    initial_digest = obs1.aggregate_digest

    # Conflicting reading for US_UPSTREAM_01 (value=8.0 instead of 5.0) plus new sensor
    r1_conflict = _make_reading(sensor_id="US_UPSTREAM_01", value=8.0, seq=20, uptime_ms=8000)
    r2_new = _make_reading(sensor_id="FS_FLUME_01", value=14.0, seq=20, uptime_ms=8000)

    status2, obs2 = store.process_telemetry_observation([r1_conflict, r2_new])
    assert status2 == "AMBIGUOUS_REGRESSION"
    assert obs2 is None

    # Stored observation must remain completely unchanged
    session = store._device_sessions["DRAINX-ESP32-NODE-01"]
    stored_obs = session.seen_observations[(20, 8000)]
    assert len(stored_obs.sensor_digests) == 1
    assert "FS_FLUME_01" not in stored_obs.sensor_digests
    assert stored_obs.aggregate_digest == initial_digest


# =====================================================================
# Test 3: Firmware-version and actuator-snapshot conflicts reject merging
# =====================================================================
def test_firmware_version_and_actuator_snapshot_conflicts_reject():
    store = StateStore()
    store.clear()
    store.mode = "PHYSICAL"

    # Initial reading with fw=0.3.7, angle=0.0, state=CLOSED
    r1 = _make_reading(sensor_id="US_UPSTREAM_01", seq=30, uptime_ms=9000, firmware_version="0.3.7", gate_angle=0.0, gate_state="CLOSED")
    status1, obs1 = store.process_telemetry_observation([r1])
    assert status1 == "NEW"

    # 1. Firmware version conflict
    r1_fw_diff = _make_reading(sensor_id="US_UPSTREAM_01", seq=30, uptime_ms=9000, firmware_version="0.4.0", gate_angle=0.0, gate_state="CLOSED")
    status_fw, _ = store.process_telemetry_observation([r1_fw_diff])
    assert status_fw == "AMBIGUOUS_REGRESSION"

    # 2. Actuator angle conflict
    r1_angle_diff = _make_reading(sensor_id="US_UPSTREAM_01", seq=30, uptime_ms=9000, firmware_version="0.3.7", gate_angle=45.0, gate_state="CLOSED")
    status_angle, _ = store.process_telemetry_observation([r1_angle_diff])
    assert status_angle == "AMBIGUOUS_REGRESSION"

    # 3. Actuator state conflict
    r1_state_diff = _make_reading(sensor_id="US_UPSTREAM_01", seq=30, uptime_ms=9000, firmware_version="0.3.7", gate_angle=0.0, gate_state="OPEN")
    status_state, _ = store.process_telemetry_observation([r1_state_diff])
    assert status_state == "AMBIGUOUS_REGRESSION"


# =====================================================================
# Test 4: Subset retransmission is classified as DUPLICATE
# =====================================================================
def test_subset_retransmission_is_classified_as_duplicate():
    store = StateStore()
    store.clear()
    store.mode = "PHYSICAL"

    r1 = _make_reading(sensor_id="US_UPSTREAM_01", seq=40, uptime_ms=10000)
    r2 = _make_reading(sensor_id="FS_FLUME_01", sensor_type=SensorType.FLOW_RATE, value=10.0, seq=40, uptime_ms=10000)
    status1, _ = store.process_telemetry_observation([r1, r2])
    assert status1 == "NEW"

    # Retransmit identical subset (only r1)
    status2, obs2 = store.process_telemetry_observation([r1])
    assert status2 == "DUPLICATE"
    assert obs2 is not None


# =====================================================================
# Test 5: Pending-reboot staged observations use identical merge semantics
# =====================================================================
def test_pending_reboot_staged_observations_identical_merge_semantics():
    store = StateStore()
    store.clear()
    store.mode = "PHYSICAL"

    # Establish baseline high-water
    r_high = _make_reading(seq=100, uptime_ms=50000)
    store.process_telemetry_observation([r_high])

    # Regress to potential reboot candidate
    r_reboot_1 = _make_reading(sensor_id="US_UPSTREAM_01", seq=1, uptime_ms=100)
    status_rb1, _ = store.process_telemetry_observation([r_reboot_1])
    assert status_rb1 == "REBOOT_PENDING"

    # Arrive with conflicting overlap on staged reboot observation
    r_reboot_1_conflict = _make_reading(sensor_id="US_UPSTREAM_01", value=99.0, seq=1, uptime_ms=100)
    status_conflict, _ = store.process_telemetry_observation([r_reboot_1_conflict])
    assert status_conflict == "AMBIGUOUS_REGRESSION"

    # Arrive with partial-batch completion on staged reboot observation
    r_reboot_1_flow = _make_reading(sensor_id="FS_FLUME_01", sensor_type=SensorType.FLOW_RATE, value=5.0, seq=1, uptime_ms=100)
    status_merge, _ = store.process_telemetry_observation([r_reboot_1, r_reboot_1_flow])
    session = store._device_sessions["DRAINX-ESP32-NODE-01"]
    cand = session.pending_reboot_candidate
    assert cand is not None
    assert len(cand.observations[0].sensor_digests) == 2
    # Repeated observation does not increment confirmation count
    assert cand.confirm_count == 1


# =====================================================================
# Test 6: Recursive metadata canonicalization is key-order independent
# =====================================================================
def test_recursive_metadata_canonicalization_key_order_independent():
    dict1 = {"b": 2, "a": 1, "nested": {"z": 9, "y": 8}}
    dict2 = {"nested": {"y": 8, "z": 9}, "a": 1, "b": 2}

    canon1 = canonicalize_value(dict1)
    canon2 = canonicalize_value(dict2)

    assert canon1 == canon2

    # Verify non-string key rejection
    with pytest.raises(TypeError):
        canonicalize_value({123: "invalid"})


# =====================================================================
# Test 7: Boolean, integer, and float values remain type-distinct
# =====================================================================
def test_bool_int_float_type_distinctness():
    val_bool = True
    val_int = 1
    val_float = 1.0

    c_bool = canonicalize_value(val_bool)
    c_int = canonicalize_value(val_int)
    c_float = canonicalize_value(val_float)

    assert c_bool == ["bool", True]
    assert c_int == ["int", 1]
    assert c_float == ["float", 1.0]

    assert c_bool != c_int
    assert c_int != c_float
    assert c_bool != c_float


# =====================================================================
# Test 8: Float canonical fields normalize 0, 0.0, and -0.0
# =====================================================================
def test_float_zero_normalization():
    zero_float = 0.0
    neg_zero_float = -0.0

    c_zero = canonicalize_value(zero_float)
    c_neg_zero = canonicalize_value(neg_zero_float)

    assert c_zero == ["float", 0.0]
    assert c_neg_zero == ["float", 0.0]
    assert c_zero == c_neg_zero


# =====================================================================
# Test 9: NaN, positive infinity, negative infinity receive distinct tags
# =====================================================================
def test_non_finite_float_tagging():
    nan_val = float("nan")
    pos_inf = float("inf")
    neg_inf = float("-inf")

    c_nan = canonicalize_value(nan_val)
    c_pos_inf = canonicalize_value(pos_inf)
    c_neg_inf = canonicalize_value(neg_inf)

    assert c_nan == ["non_finite", "NaN"]
    assert c_pos_inf == ["non_finite", "+Inf"]
    assert c_neg_inf == ["non_finite", "-Inf"]

    assert c_nan != c_pos_inf
    assert c_pos_inf != c_neg_inf


# =====================================================================
# Test 10: Invalid core numeric values cannot advance session or correlate
# =====================================================================
def test_invalid_core_numeric_values_rejected():
    store = StateStore()
    store.clear()
    store.mode = "PHYSICAL"

    # Target/measured angle consistency checks: boolean rejection
    is_ok, reason, _ = evaluate_alignment_consistency(True, 0.0, "CLOSED")
    assert not is_ok
    assert "Boolean" in reason

    is_ok, reason, _ = evaluate_alignment_consistency(0.0, False, "CLOSED")
    assert not is_ok
    assert "Boolean" in reason

    # Non-finite values
    is_ok, reason, _ = evaluate_alignment_consistency(float("nan"), 0.0, "CLOSED")
    assert not is_ok
    assert "Non-finite" in reason

    is_ok, reason, _ = evaluate_alignment_consistency(0.0, float("inf"), "CLOSED")
    assert not is_ok
    assert "Non-finite" in reason

    # Observation with boolean or invalid seq_num in reading
    r_bad = _make_reading(seq=1, uptime_ms=100)
    r_bad.sequence_number = True  # type: ignore
    status, obs = store.process_telemetry_observation([r_bad])
    assert status == "INVALID_NUMERIC"
    assert obs is None


# =====================================================================
# Test 11: Aggregate digest is independent of sensor input order
# =====================================================================
def test_aggregate_digest_sensor_input_order_independent():
    r1 = _make_reading(sensor_id="US_UPSTREAM_01", sensor_type=SensorType.WATER_LEVEL, value=4.5)
    r2 = _make_reading(sensor_id="FS_FLUME_01", sensor_type=SensorType.FLOW_RATE, value=12.0)

    digest_order1 = compute_aggregate_observation_digest([r1, r2])
    digest_order2 = compute_aggregate_observation_digest([r2, r1])

    assert digest_order1 == digest_order2


# =====================================================================
# Test 12: Partial-batch merge recomputes same aggregate digest as complete observation
# =====================================================================
def test_partial_batch_merge_recomputes_same_aggregate_digest():
    store1 = StateStore()
    store1.clear()
    store1.mode = "PHYSICAL"

    store2 = StateStore()
    store2.clear()
    store2.mode = "PHYSICAL"

    r1 = _make_reading(sensor_id="US_UPSTREAM_01", sensor_type=SensorType.WATER_LEVEL, value=4.5, seq=50, uptime_ms=20000)
    r2 = _make_reading(sensor_id="FS_FLUME_01", sensor_type=SensorType.FLOW_RATE, value=12.0, seq=50, uptime_ms=20000)

    # In store1: ingest complete batch simultaneously
    _, obs_complete = store1.process_telemetry_observation([r1, r2])

    # In store2: ingest r1 first, then r2 via partial batch completion
    store2.process_telemetry_observation([r1])
    _, obs_merged = store2.process_telemetry_observation([r1, r2])

    assert obs_complete.aggregate_digest == obs_merged.aggregate_digest


# =====================================================================
# Test 13: LRU capacity remains exactly 256 after insertion
# =====================================================================
def test_lru_capacity_bounded_at_256():
    store = StateStore()
    store.clear()
    store.mode = "PHYSICAL"

    # Insert 300 sequential observations
    for i in range(1, 301):
        r = _make_reading(seq=i, uptime_ms=i * 1000)
        store.process_telemetry_observation([r])

    session = store._device_sessions["DRAINX-ESP32-NODE-01"]
    assert len(session.seen_observations) == 256

    # Oldest 44 entries (1..44) should have been evicted
    assert (1, 1000) not in session.seen_observations
    assert (44, 44000) not in session.seen_observations
    assert (45, 45000) in session.seen_observations
    assert (300, 300000) in session.seen_observations


# =====================================================================
# Test 14: Touching an old observation makes it MRU and protects from eviction
# =====================================================================
def test_touching_old_observation_protects_from_eviction():
    store = StateStore()
    store.clear()
    store.mode = "PHYSICAL"

    # Insert 256 observations (seq 1..256)
    for i in range(1, 257):
        r = _make_reading(seq=i, uptime_ms=i * 1000)
        store.process_telemetry_observation([r])

    session = store._device_sessions["DRAINX-ESP32-NODE-01"]
    assert len(session.seen_observations) == 256
    assert (1, 1000) in session.seen_observations

    # Touch observation (1, 1000) via duplicate retransmission
    r_touch = _make_reading(seq=1, uptime_ms=1000)
    status, _ = store.process_telemetry_observation([r_touch])
    assert status == "DUPLICATE"

    # Now insert one more new observation (seq 257)
    r_new = _make_reading(seq=257, uptime_ms=257000)
    store.process_telemetry_observation([r_new])

    # Observation (1, 1000) must still be present because it was touched!
    assert (1, 1000) in session.seen_observations
    # Observation (2, 2000) should have been evicted instead
    assert (2, 2000) not in session.seen_observations


# =====================================================================
# Test 15: Reboot inference, uptime rollover, replay protection
# =====================================================================
def test_reboot_inference_and_uptime_rollover():
    store = StateStore()
    store.clear()
    store.mode = "PHYSICAL"

    # 1. Normal progression
    store.process_telemetry_observation([_make_reading(seq=10, uptime_ms=10000)])
    store.process_telemetry_observation([_make_reading(seq=20, uptime_ms=20000)])

    session = store._device_sessions["DRAINX-ESP32-NODE-01"]
    assert session.device_session_epoch == 0

    # 2. Sequence regression with simulated reboot candidate progression
    # Packet 1 of reboot candidate
    store.process_telemetry_observation([_make_reading(seq=1, uptime_ms=1000)])
    assert session.pending_reboot_candidate is not None
    assert session.device_session_epoch == 0

    # Simulate pacing with time.sleep or monkeypatching
    cand = session.pending_reboot_candidate
    cand.first_observed_time = time.time() - 3.0

    # Packet 2
    store.process_telemetry_observation([_make_reading(seq=2, uptime_ms=2000)])
    # Packet 3
    store.process_telemetry_observation([_make_reading(seq=3, uptime_ms=3000)])

    # REBOOT CONFIRMED: epoch increments to 1
    assert session.device_session_epoch == 1
    assert session.pending_reboot_candidate is None

    # 3. Uint32 uptime rollover check
    # Establish high uptime near 2^32 - 1
    session.last_seen_uptime_ms = 0xFFFFFFFF - 50000
    session.last_seen_seq = 500

    # New packet with rolled-over uptime (e.g. 5000) and higher sequence number
    r_rollover = _make_reading(seq=501, uptime_ms=5000)
    status_roll, _ = store.process_telemetry_observation([r_rollover])
    assert status_roll == "NEW"
    # Rollover must NOT increment epoch
    assert session.device_session_epoch == 1


# =====================================================================
# Test 16: Directive correlation occurs once and only for eligible directives
# =====================================================================
def test_directive_correlation_lifecycle_and_intermediate_angle():
    store = StateStore()
    store.clear()
    store.mode = "PHYSICAL"

    # Establish device baseline at seq 100
    store.process_telemetry_observation([_make_reading(seq=100, uptime_ms=100000)])

    # Issue supervisory directive: target intermediate angle 45.0 deg
    directive = ActuatorDirectiveContract(
        gate_target_angle=45.0,
        action="DIVERT_FLOW",
        reason="Test intermediate diversion",
        device_id="DRAINX-ESP32-NODE-01",
    )
    store.set_gate_directive(directive)

    assert directive.baseline_device_sequence_number == 100
    assert directive.device_session_epoch == 0
    assert store.get_active_directive("PHYSICAL") is not None

    # Feedback with older sequence number (seq 99) -> ignored
    store.process_telemetry_observation([
        _make_reading(seq=99, uptime_ms=99000, gate_angle=45.0, gate_state="OPEN")
    ])
    assert store.get_active_directive("PHYSICAL") is not None

    # Feedback with newer sequence number (seq 101) but misaligned angle (10.0 deg)
    store.process_telemetry_observation([
        _make_reading(seq=101, uptime_ms=101000, gate_angle=10.0, gate_state="CLOSED")
    ])
    assert store.get_active_directive("PHYSICAL") is not None

    # Feedback with newer sequence number (seq 102), measured angle 45.5 deg (within 2 deg tol), state CLOSED
    # commandAngle() does not change state, so CLOSED is valid for intermediate angles!
    store.process_telemetry_observation([
        _make_reading(seq=102, uptime_ms=102000, gate_angle=45.5, gate_state="CLOSED")
    ])

    # Directive should now be settled with ALIGNMENT_OBSERVED
    assert store.get_active_directive("PHYSICAL") is None
    audits = store.get_directive_audits(directive.directive_id)
    event_types = [a.event_type for a in audits]
    assert DirectiveEventType.ISSUED in event_types
    assert DirectiveEventType.ALIGNMENT_OBSERVED in event_types


# =====================================================================
# Test 17: Terminal directives do not stop raw telemetry processing
# =====================================================================
def test_terminal_directives_do_not_stop_raw_telemetry():
    store = StateStore()
    store.clear()
    store.mode = "PHYSICAL"

    directive = ActuatorDirectiveContract(gate_target_angle=0.0, action="MAINTAIN_NORMAL")
    store.set_gate_directive(directive)

    # Transition to ALIGNMENT_OBSERVED
    r_align = _make_reading(seq=1, uptime_ms=1000, gate_angle=0.0, gate_state="CLOSED")
    store.process_telemetry_observation([r_align])
    assert store.get_active_directive("PHYSICAL") is None

    # Subsequent raw telemetry continues to be stored and processed unconditionally
    r_subsequent = _make_reading(seq=2, uptime_ms=2000, value=7.2)
    store.ingest_reading(r_subsequent)
    status, obs = store.process_telemetry_observation([r_subsequent])
    assert status == "NEW"

    latest = store.get_latest_readings()
    assert "US_UPSTREAM_01" in latest
    assert latest["US_UPSTREAM_01"].value == 7.2


# =====================================================================
# Test 18: Startup recovery resolves incomplete directives idempotently
# =====================================================================
def test_startup_recovery_idempotency():
    repo = PersistenceRepository(supabase_url="", supabase_key="")

    # Incomplete directive 1: expired (> 30s)
    old_time = "2026-11-20T10:00:00+00:00"
    repo.persist_directive_audit_sync({
        "audit_id": "aud_dir-expired_ISS",
        "directive_id": "dir-expired",
        "event_type": "ISSUED",
        "operational_mode": "PHYSICAL",
        "section_id": "SEC_SCREENING_01",
        "action": "DIVERT_FLOW",
        "gate_target_angle": 90.0,
        "reason": "Expired directive test",
        "issuer_id": "test_suite",
        "timestamp": old_time,
    })

    # Incomplete directive 2: recent (< 30s)
    recent_time = datetime.now(timezone.utc).isoformat()
    repo.persist_directive_audit_sync({
        "audit_id": "aud_dir-recent_ISS",
        "directive_id": "dir-recent",
        "event_type": "ISSUED",
        "operational_mode": "SIMULATION",
        "section_id": "SEC_SCREENING_01",
        "action": "MAINTAIN_NORMAL",
        "gate_target_angle": 0.0,
        "reason": "Recent directive test",
        "issuer_id": "test_suite",
        "timestamp": recent_time,
    })

    # Run startup recovery sweep
    recovered = repo.recover_incomplete_directives_sync()

    # Expired directive must have been transitioned to VERIFICATION_TIMEOUT
    audits_expired = repo.query_directive_audits_sync("dir-expired")
    expired_types = [a["event_type"] for a in audits_expired]
    assert "VERIFICATION_TIMEOUT" in expired_types

    # Recent directive must be returned for active state restoration
    recent_recovered = [r for r in recovered if r["directive_id"] == "dir-recent"]
    assert len(recent_recovered) == 1

    # Idempotent re-run
    recovered_again = repo.recover_incomplete_directives_sync()
    assert len([r for r in recovered_again if r["directive_id"] == "dir-recent"]) == 1
