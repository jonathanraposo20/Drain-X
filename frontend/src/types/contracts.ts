export type DataSource = 'PHYSICAL' | 'LIVE' | 'SIMULATED' | 'REPLAY' | 'OFFLINE';

export type TelemetrySource = 'SIMULATED' | 'LIVE' | 'OFFLINE';

export type TelemetryConnectionState = 'LIVE' | 'SIMULATED' | 'OFFLINE' | 'STALE' | 'FAULT';

export type SensorHealthStatus = 'OK' | 'DEGRADED' | 'FAULT' | 'CALIBRATING';

export type SensorType = 
  | 'WATER_LEVEL'
  | 'FLOW_RATE'
  | 'TEMPERATURE'
  | 'DEBRIS_PRESENCE'
  | 'GATE_ANGLE';

export type MeasurementUnit = 'cm' | 'L/min' | 'degC' | 'deg' | 'flag';

export type SystemOperationalState =
  | 'STANDBY'
  | 'MONITORING'
  | 'INTERVENING'
  | 'FAULT'
  | 'EMERGENCY_STOP';

export type AlertSeverity = 'INFO' | 'WARNING' | 'HIGH' | 'CRITICAL';

export type PredictionState = 'STABLE' | 'ESTIMATING' | 'OVERFLOW' | 'UNAVAILABLE';

export type MechanismState =
  | 'IDLE'
  | 'DEPLOYING_BACKUP_NET'
  | 'HOISTING'
  | 'DISCHARGING'
  | 'LOWERING'
  | 'RETRACTING_BACKUP_NET'
  | 'JAMMED'
  | 'FAILED';

export type FaultType =
  | 'SENSOR_DISCONNECTED'
  | 'STALE_DATA'
  | 'IMPLAUSIBLE_READING'
  | 'COMMUNICATION_LOSS'
  | 'ACTUATOR_TIMEOUT'
  | 'FAILED_CYCLE'
  | 'MECHANISM_JAM'
  | 'SENSOR_INCONSISTENT';

export type ScenarioType =
  | 'CLEAN_DRAINAGE'
  | 'GRADUAL_DEBRIS'
  | 'SUDDEN_BLOCKAGE'
  | 'PARTIAL_BLOCKAGE'
  | 'INCREASING_INFLOW'
  | 'SENSOR_FAILURE'
  | 'COMM_FAILURE'
  | 'FAILED_CYCLE'
  | 'SUCCESSFUL_INTERVENTION';

export interface SensorReadingContract {
  version: string;
  message_id: string;
  sensor_id: string;
  section_id: string;
  sensor_type: SensorType;
  value: number;
  unit: MeasurementUnit;
  timestamp: string; // ISO 8601 UTC
  source: DataSource;
  status: SensorHealthStatus;
  metadata?: Record<string, unknown>;
}

export interface AlertContract {
  alert_id: string;
  section_id: string;
  alert_type: string;
  severity: AlertSeverity;
  timestamp: string;
  message: string;
  resolved: boolean;
  resolved_at?: string | null;
  context_data?: Record<string, unknown>;
}

export interface BlockageEventContract {
  event_id: string;
  section_id: string;
  probable_segment: string;
  severity: number;
  confidence: number;
  differential_head_cm: number;
  estimated_flow_drop_lpm: number;
  detected_at: string;
  is_active: boolean;
}

export interface PredictionContract {
  prediction_id: string;
  section_id: string;
  state: PredictionState;
  ttc_seconds?: number | null;
  confidence: number;
  rate_of_rise_cm_s: number;
  projected_level_cm?: number;
  predicted_at: string;
}

export interface MechanismStatusContract {
  state: MechanismState;
  backup_net_angle_deg: number;
  tray_height_cm: number;
  cycle_count: number;
  current_action: string;
  elapsed_in_state_s: number;
  is_jammed: boolean;
  is_fault: boolean;
  debris_retained_pct: number;
  last_cycle_completed_at?: string | null;
}

export interface FaultEventContract {
  fault_id: string;
  target_id: string;
  fault_type: FaultType;
  severity: AlertSeverity;
  description: string;
  detected_at: string;
  active: boolean;
  context?: Record<string, unknown>;
}

export interface BenchmarkMetricsContract {
  scenario_name: string;
  duration_s: number;
  detection_delay_s?: number | null;
  false_alarms: number;
  missed_detections: number;
  prediction_rmse_s?: number | null;
  intervention_success_rate_pct: number;
  time_above_critical_s: number;
  baseline_detection_delay_s?: number | null;
  baseline_false_alarms: number;
  baseline_time_above_critical_s: number;
  lead_time_advantage_s: number;
  overflow_reduction_pct: number;
}

export interface ActuatorDirectiveContract {
  gate_target_angle: number;
  action: string;
  reason: string;
  risk_level: AlertSeverity;
  emergency_stop: boolean;
  timestamp: string;
}

export interface TelemetryIngestResponse {
  status: string;
  ingested_count: number;
  message_id?: string | null;
  prediction?: PredictionContract | null;
  blockage?: BlockageEventContract | null;
  active_alerts_count: number;
  gate_directive: ActuatorDirectiveContract;
  gate_command: ActuatorDirectiveContract;
}

export interface SystemStatusContract {
  system_name: string;
  mode: 'SIMULATION' | 'HARDWARE';
  operational_state: SystemOperationalState;
  uptime_seconds: number;
  active_alerts_count: number;
  last_heartbeat: string;
  latest_readings: Record<string, SensorReadingContract>;
  active_prediction?: PredictionContract | null;
  active_blockage?: BlockageEventContract | null;
  active_gate_directive?: ActuatorDirectiveContract | null;
  mechanism: MechanismStatusContract;
  active_scenario?: string | null;
}

export type IncidentSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type IncidentCategory = 
  | 'FLOODING'
  | 'WATERLOGGING'
  | 'DRAIN_BLOCKAGE'
  | 'DRAIN_OVERFLOW'
  | 'MANHOLE_DAMAGE'
  | 'INFRASTRUCTURE_DAMAGE'
  | 'OTHER';

export type IncidentStatus = 
  | 'REPORTED'
  | 'VERIFIED'
  | 'ASSIGNED'
  | 'INVESTIGATING'
  | 'RESOLVED'
  | 'REJECTED';

export type IncidentSource = 'CITIZEN' | 'SENSOR' | 'DEMO';

export interface IncidentCreateContract {
  category: IncidentCategory;
  description: string;
  latitude: number;
  longitude: number;
  severity?: IncidentSeverity;
  source?: IncidentSource;
  reporter_name?: string;
  photos?: string[];
}

export interface IncidentUpdateContract {
  status?: IncidentStatus;
  assigned_to?: string;
  municipal_notes?: string;
  photos?: string[];
}

export interface IncidentResponseContract {
  id: string;
  category: IncidentCategory;
  description: string;
  latitude: number;
  longitude: number;
  severity: IncidentSeverity;
  status: IncidentStatus;
  source: IncidentSource;
  created_at: string;
  updated_at: string;
  assigned_to?: string | null;
  municipal_notes?: string | null;
  reporter_name?: string | null;
  photos?: string[];
}

export type StreamConnectionStatus =
  | 'CONNECTED'
  | 'RECONNECTING'
  | 'POLLING_FALLBACK'
  | 'DISCONNECTED'
  | 'ERROR';

export type TelemetryStreamEventType =
  | 'INIT'
  | 'TELEMETRY'
  | 'HEARTBEAT'
  | 'PONG'
  | 'FILTER_ACK'
  | 'ERROR';

export interface TelemetryStreamEvent {
  event_id: string;
  event_type: TelemetryStreamEventType;
  timestamp: string;
  sensor_id: string;
  section_id: string;
  source: DataSource;
  operational_mode: string;
  sensor_type: SensorType;
  value: number;
  unit: string;
  water_level_cm?: number | null;
  flow_rate_lpm?: number | null;
  cumulative_volume_liters?: number | null;
  sensor_status: SensorHealthStatus;
  is_valid: boolean;
  fault_code?: string | null;
  hardware_validation_stage?: string | null;
  metadata?: Record<string, unknown>;
}

export interface StreamInitMessage {
  event_type: 'INIT';
  protocol_version: string;
  client_id: string;
  connection_time: string;
  operational_mode: string;
  hardware_validation_stage?: string | null;
  latest_snapshot: Record<string, SensorReadingContract>;
  subscribed_source?: string | null;
  subscribed_sensor?: string | null;
  message: string;
  stream_config?: Record<string, unknown>;
}


