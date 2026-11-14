import React from 'react';
import {
  SensorReadingContract,
  ActuatorDirectiveContract,
} from '../types/contracts';
import {
  GitBranch,
  Radio,
  AlertTriangle,
  CheckCircle2,
  Activity,
  Zap,
  RotateCw,
  Sliders,
  ShieldAlert,
} from 'lucide-react';

export interface DiversionGateTwinProps {
  mode: 'SIMULATION' | 'HARDWARE';
  upstreamDepth: number; // h1 in cm
  weirHead: number; // hw in cm
  inflow: number; // Qin in L/min
  gateDirective?: ActuatorDirectiveContract | null;
  readings: Record<string, SensorReadingContract>;
  activeAlertsCount?: number;
  isFault?: boolean;
}

export type OperatorIndicator =
  | 'NORMAL'
  | 'DIVERSION REQUESTED'
  | 'DIVERTING'
  | 'DIVERTED'
  | 'RECOVERY'
  | 'FAULT';

export const DiversionGateTwin: React.FC<DiversionGateTwinProps> = ({
  mode,
  upstreamDepth,
  weirHead: _weirHead,
  inflow,
  gateDirective,
  readings,
  activeAlertsCount = 0,
  isFault = false,
}) => {
  // 1. Commanded Target Gate Directive
  const commandedAngle = gateDirective?.gate_target_angle ?? 0.0;
  const directiveAction = gateDirective?.action ?? 'MAINTAIN_NORMAL';
  const directiveReason =
    gateDirective?.reason ?? 'Channel hydraulics within nominal thresholds.';
  const riskLevel = gateDirective?.risk_level ?? 'INFO';
  const emergencyStop = gateDirective?.emergency_stop ?? false;

  // 2. Physical Feedback Sensor Inspection
  // Look for direct angle feedback (e.g. potentiometer or servo feedback)
  const feedbackReading = Object.values(readings).find(
    (r) => r.sensor_type === 'GATE_ANGLE' || r.unit === 'deg' || r.sensor_id.includes('GATE')
  );

  const hasFeedback = feedbackReading !== undefined && feedbackReading.status === 'OK';
  const measuredAngle: number | null = hasFeedback ? feedbackReading.value : null;

  // 3. Telemetry Freshness & Staleness Detection
  const latestTimestamp = Object.values(readings).reduce<number | null>((acc, r) => {
    const t = new Date(r.timestamp).getTime();
    return acc === null ? t : Math.max(acc, t);
  }, null);

  const now = Date.now();
  const ageSeconds = latestTimestamp ? Math.max(0, (now - latestTimestamp) / 1000) : null;
  const isStale = ageSeconds !== null && ageSeconds > 8.0;
  const isOffline = Object.keys(readings).length === 0 || ageSeconds === null || ageSeconds > 30.0;

  // 4. Derive Operator Indicator
  let operatorIndicator: OperatorIndicator = 'NORMAL';

  if (isFault || emergencyStop || (feedbackReading && feedbackReading.status === 'FAULT')) {
    operatorIndicator = 'FAULT';
  } else if (isOffline) {
    operatorIndicator = 'FAULT';
  } else if (commandedAngle > 0.0) {
    if (!hasFeedback) {
      // Directive commanded, but without physical feedback confirmation
      operatorIndicator = 'DIVERSION REQUESTED';
    } else if (measuredAngle !== null) {
      if (measuredAngle >= 85.0) {
        operatorIndicator = 'DIVERTED';
      } else if (measuredAngle > 5.0) {
        operatorIndicator = 'DIVERTING';
      } else {
        operatorIndicator = 'DIVERSION REQUESTED';
      }
    }
  } else {
    // Commanded angle is 0.0
    if (hasFeedback && measuredAngle !== null && measuredAngle > 5.0) {
      operatorIndicator = 'RECOVERY';
    } else if (upstreamDepth > 10.0) {
      operatorIndicator = 'RECOVERY';
    } else {
      operatorIndicator = 'NORMAL';
    }
  }

  // 5. Flow Calculations & Effective Gate Position
  // If physical feedback is available, use measured angle; otherwise use commanded angle for display
  const visualAngle = measuredAngle !== null ? measuredAngle : commandedAngle;
  const visualAngleClamped = Math.min(90.0, Math.max(0.0, visualAngle));
  const diversionFraction = visualAngleClamped / 90.0;
  const primaryFraction = 1.0 - diversionFraction;

  const primaryFlow = (inflow * primaryFraction).toFixed(1);
  const diversionFlow = (inflow * diversionFraction).toFixed(1);

  // SVG Geometry Calculation:
  // Hinge Pivot at (X=300, Y=220)
  // Arm Length = 140px (spans primary channel height from Y=220 to Y=80)
  const pivotX = 300;
  const pivotY = 220;
  const armLength = 140;

  // Actual/Visual Arm Tip coordinates
  const visualRad = (visualAngleClamped * Math.PI) / 180;
  const tipX = pivotX + armLength * Math.cos(visualRad);
  const tipY = pivotY - armLength * Math.sin(visualRad);

  // Commanded Target Arm Tip coordinates
  const cmdRad = (commandedAngle * Math.PI) / 180;
  const cmdTipX = pivotX + armLength * Math.cos(cmdRad);
  const cmdTipY = pivotY - armLength * Math.sin(cmdRad);

  // Color Coding
  const getIndicatorBadgeStyle = () => {
    switch (operatorIndicator) {
      case 'NORMAL':
        return 'bg-emerald-950/60 text-emerald-300 border-emerald-800';
      case 'DIVERSION REQUESTED':
        return 'bg-amber-950/60 text-amber-300 border-amber-700 animate-pulse';
      case 'DIVERTING':
        return 'bg-cyan-950/60 text-cyan-300 border-cyan-700 animate-pulse';
      case 'DIVERTED':
        return 'bg-indigo-950/60 text-indigo-300 border-indigo-700';
      case 'RECOVERY':
        return 'bg-blue-950/60 text-blue-300 border-blue-700';
      case 'FAULT':
        return 'bg-rose-950/60 text-rose-300 border-rose-800 animate-pulse';
    }
  };

  const getWaterColor = () => {
    if (upstreamDepth >= 12.0) return '#ef4444'; // Critical red
    if (upstreamDepth >= 10.0) return '#f59e0b'; // High amber
    return '#0284c7'; // Nominal blue
  };

  return (
    <div className="bg-slate-900 rounded border border-slate-800 shadow-xl p-4 sm:p-5 mb-6 overflow-hidden">
      {/* SCADA Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2 mb-3 pb-3 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2">
            <span
              className={`w-2 h-2 rounded-full ${
                isOffline
                  ? 'bg-rose-500 shadow-[0_0_8px_rgba(244,63,94,0.8)]'
                  : isStale
                  ? 'bg-amber-400 shadow-[0_0_8px_rgba(251,191,36,0.8)]'
                  : 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.8)] animate-pulse'
              }`}
            />
            <h2 className="text-xs font-mono font-bold text-slate-100 uppercase tracking-wider flex items-center gap-1.5">
              <GitBranch className="w-3.5 h-3.5 text-cyan-400" />
              PHYSICAL DIVERSION GATE // ACTUATOR & CHANNEL BIFURCATION TWIN
            </h2>
          </div>
          <p className="text-[11px] font-mono text-slate-400 mt-0.5">
            Microcontroller servo gate kinematics: bifurcation channel split, physical feedback
            verification, and active diversion state.
          </p>
        </div>

        {/* Header Indicators Bar */}
        <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
          {/* Mode Badge */}
          <span
            className={`px-2 py-0.5 rounded border text-[11px] font-bold ${
              mode === 'HARDWARE'
                ? 'bg-emerald-950/50 text-emerald-300 border-emerald-700'
                : 'bg-slate-800 text-slate-300 border-slate-700'
            }`}
          >
            {mode === 'HARDWARE' ? 'PHYSICAL HARDWARE' : 'SIMULATION MODE'}
          </span>

          {/* Telemetry Freshness Badge */}
          <span
            className={`px-2 py-0.5 rounded border text-[11px] font-bold flex items-center gap-1 ${
              isOffline
                ? 'bg-rose-950/60 text-rose-300 border-rose-800'
                : isStale
                ? 'bg-amber-950/50 text-amber-300 border-amber-700'
                : 'bg-emerald-950/40 text-emerald-400 border-emerald-800'
            }`}
          >
            <Radio className="w-3 h-3" />
            {isOffline
              ? 'OFFLINE'
              : isStale
              ? `STALE (${ageSeconds?.toFixed(0)}s)`
              : 'TELEMETRY LIVE'}
          </span>

          {/* Operator Indicator Badge */}
          <span
            data-testid="operator-indicator"
            className={`px-2.5 py-1 rounded border font-bold text-[11px] flex items-center gap-1.5 ${getIndicatorBadgeStyle()}`}
          >
            {operatorIndicator === 'FAULT' && <ShieldAlert className="w-3.5 h-3.5" />}
            {operatorIndicator === 'NORMAL' && <CheckCircle2 className="w-3.5 h-3.5" />}
            {operatorIndicator === 'DIVERTING' && <RotateCw className="w-3.5 h-3.5 animate-spin" />}
            {operatorIndicator === 'DIVERSION REQUESTED' && <Zap className="w-3.5 h-3.5" />}
            STATE: <span className="text-white">{operatorIndicator}</span>
          </span>
        </div>
      </div>

      {/* Industrial SVG Diagram Canvas */}
      <div className="w-full overflow-x-auto bg-[#070b12] rounded p-2 border border-slate-800/80">
        <svg
          viewBox="0 0 860 340"
          className="w-full h-auto min-w-[760px] select-none font-mono"
        >
          <defs>
            {/* Grid Pattern */}
            <pattern id="gateGrid" width="20" height="20" patternUnits="userSpaceOnUse">
              <path d="M 20 0 L 0 0 0 20" fill="none" stroke="#1e293b" strokeWidth="0.5" />
            </pattern>

            {/* Water Linear Gradients */}
            <linearGradient id="inflowGrad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor={getWaterColor()} stopOpacity="0.45" />
              <stop offset="100%" stopColor={getWaterColor()} stopOpacity="0.30" />
            </linearGradient>

            <linearGradient id="primaryFlowGrad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#0284c7" stopOpacity={0.4 * primaryFraction} />
              <stop offset="100%" stopColor="#0369a1" stopOpacity={0.25 * primaryFraction} />
            </linearGradient>

            <linearGradient id="diversionFlowGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#0d9488" stopOpacity={0.5 * diversionFraction} />
              <stop offset="100%" stopColor="#0f766e" stopOpacity={0.3 * diversionFraction} />
            </linearGradient>

            {/* Hatched Pattern for Open-Loop Command Arm */}
            <pattern id="openLoopHatch" width="8" height="8" patternTransform="rotate(45 0 0)" patternUnits="userSpaceOnUse">
              <line x1="0" y1="0" x2="0" y2="8" stroke="#f59e0b" strokeWidth="2" strokeOpacity="0.6" />
            </pattern>

            {/* Arrow Marker */}
            <marker id="arrowCyan" viewBox="0 0 10 10" refX="5" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#38bdf8" />
            </marker>
            <marker id="arrowTeal" viewBox="0 0 10 10" refX="5" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#2dd4bf" />
            </marker>
          </defs>

          {/* Grid Layer */}
          <rect x="0" y="0" width="860" height="340" fill="#070b12" />
          <rect x="0" y="0" width="860" height="340" fill="url(#gateGrid)" opacity="0.6" />

          {/* ======================================================== */}
          {/* WATER FLOW POLYGONS (Dynamic Fill)                      */}
          {/* ======================================================== */}

          {/* Upstream Water Body */}
          <polygon
            points="60,82 300,82 300,218 60,218"
            fill="url(#inflowGrad)"
          />

          {/* Primary Channel Water Body */}
          <polygon
            points="300,82 780,82 780,218 440,218 300,82"
            fill="url(#primaryFlowGrad)"
          />

          {/* Secondary Diversion Channel Water Body */}
          <polygon
            points="300,218 440,218 780,318 440,318"
            fill="url(#diversionFlowGrad)"
          />

          {/* ======================================================== */}
          {/* CHANNEL BOUNDARIES & WALLS (Concrete / Acrylic)         */}
          {/* ======================================================== */}

          {/* Upstream Top Wall */}
          <line x1="60" y1="80" x2="300" y2="80" stroke="#475569" strokeWidth="4" />
          {/* Upstream Bottom Wall */}
          <line x1="60" y1="220" x2="300" y2="220" stroke="#475569" strokeWidth="4" />

          {/* Primary Channel Top Wall (Continuous) */}
          <line x1="300" y1="80" x2="800" y2="80" stroke="#475569" strokeWidth="4" />
          {/* Channel Divider Wall (Between Primary and Diversion Branch) */}
          <line x1="440" y1="220" x2="800" y2="220" stroke="#475569" strokeWidth="4" />

          {/* Diversion Channel South Wall */}
          <line x1="300" y1="220" x2="440" y2="320" stroke="#475569" strokeWidth="3" strokeDasharray="3 3" />
          <line x1="440" y1="320" x2="800" y2="320" stroke="#475569" strokeWidth="4" />

          {/* ======================================================== */}
          {/* FLOW STREAMLINES & DIRECTION VECTORS                    */}
          {/* ======================================================== */}

          {/* Upstream Inflow Streamlines */}
          <g opacity="0.8">
            <line x1="80" y1="130" x2="260" y2="130" stroke="#38bdf8" strokeWidth="1.5" strokeDasharray="8 6" markerEnd="url(#arrowCyan)" />
            <line x1="80" y1="170" x2="260" y2="170" stroke="#38bdf8" strokeWidth="1.5" strokeDasharray="8 6" markerEnd="url(#arrowCyan)" />
          </g>

          {/* Primary Channel Streamlines (Dimmed as gate closes) */}
          {primaryFraction > 0.05 && (
            <g opacity={primaryFraction}>
              <line x1="330" y1="120" x2="680" y2="120" stroke="#38bdf8" strokeWidth="2" strokeDasharray="10 8" markerEnd="url(#arrowCyan)" />
              <line x1="330" y1="160" x2="680" y2="160" stroke="#38bdf8" strokeWidth="2" strokeDasharray="10 8" markerEnd="url(#arrowCyan)" />
              <line x1="460" y1="190" x2="680" y2="190" stroke="#38bdf8" strokeWidth="1.5" strokeDasharray="8 6" markerEnd="url(#arrowCyan)" />
            </g>
          )}

          {/* Diversion Channel Streamlines (Brightened as gate opens) */}
          {diversionFraction > 0.05 && (
            <g opacity={diversionFraction}>
              <path
                d="M 270,180 Q 340,240 500,260 L 700,270"
                fill="none"
                stroke="#2dd4bf"
                strokeWidth="2.5"
                strokeDasharray="10 8"
                markerEnd="url(#arrowTeal)"
              />
              <path
                d="M 280,200 Q 360,270 540,290 L 700,295"
                fill="none"
                stroke="#2dd4bf"
                strokeWidth="2"
                strokeDasharray="8 6"
                markerEnd="url(#arrowTeal)"
              />
            </g>
          )}

          {/* ======================================================== */}
          {/* SENSORS & INSTRUMENTATION OVERLAY                       */}
          {/* ======================================================== */}

          {/* Ultrasonic Water Level Sensor US_UPSTREAM_01 */}
          <g transform="translate(160, 25)">
            {/* Sensor Housing */}
            <rect x="0" y="0" width="36" height="22" rx="3" fill="#0f172a" stroke="#38bdf8" strokeWidth="1.5" />
            <circle cx="11" cy="11" r="5" fill="#1e293b" stroke="#38bdf8" strokeWidth="1" />
            <circle cx="25" cy="11" r="5" fill="#1e293b" stroke="#38bdf8" strokeWidth="1" />
            {/* Sensor Label */}
            <text x="18" y="-6" fill="#38bdf8" fontSize="9" textAnchor="middle" fontWeight="bold">
              US_UPSTREAM_01
            </text>
            <text x="18" y="34" fill="#94a3b8" fontSize="8" textAnchor="middle">
              h1: {upstreamDepth.toFixed(1)} cm
            </text>
            {/* Acoustic Beam Rays */}
            <line x1="8" y1="22" x2="2" y2="70" stroke="#38bdf8" strokeWidth="1" strokeDasharray="2 3" opacity="0.5" />
            <line x1="28" y1="22" x2="34" y2="70" stroke="#38bdf8" strokeWidth="1" strokeDasharray="2 3" opacity="0.5" />
          </g>

          {/* Water Depth Scale Gauge on Left Wall */}
          <g transform="translate(68, 85)">
            <rect x="0" y="0" width="12" height="130" fill="#0f172a" stroke="#334155" strokeWidth="1" />
            {/* Scaled Water Fill */}
            <rect
              x="2"
              y={128 - Math.min(128, (upstreamDepth / 15.0) * 128)}
              width="8"
              height={Math.min(128, (upstreamDepth / 15.0) * 128)}
              fill={getWaterColor()}
              opacity="0.8"
            />
            {/* Critical Flood Threshold Line (12.0 cm) */}
            <line x1="-5" y1={128 - (12.0 / 15.0) * 128} x2="18" y2={128 - (12.0 / 15.0) * 128} stroke="#ef4444" strokeWidth="1.5" strokeDasharray="3 2" />
            <text x="22" y={132 - (12.0 / 15.0) * 128} fill="#ef4444" fontSize="8" fontWeight="bold">
              CRIT: 12cm
            </text>
          </g>

          {/* ======================================================== */}
          {/* HINGED SERVO DIVERSION GATE (Mechanism)                 */}
          {/* ======================================================== */}

          {/* Angular Sector Arc (0 to 90 deg range indicator) */}
          <path
            d="M 440,220 A 140 140 0 0 0 300,80"
            fill="none"
            stroke="#334155"
            strokeWidth="1"
            strokeDasharray="3 3"
          />

          {/* Commanded Target Outline (if command differs from measured or no feedback) */}
          {(!hasFeedback || Math.abs(commandedAngle - (measuredAngle ?? 0)) > 2.0) && (
            <g>
              <line
                x1={pivotX}
                y1={pivotY}
                x2={cmdTipX}
                y2={cmdTipY}
                stroke="#38bdf8"
                strokeWidth="2.5"
                strokeDasharray="6 4"
                opacity="0.85"
              />
              <circle cx={cmdTipX} cy={cmdTipY} r="4" fill="#0284c7" stroke="#38bdf8" strokeWidth="1" />
              <text
                x={cmdTipX + (commandedAngle > 45 ? 10 : 8)}
                y={cmdTipY - 6}
                fill="#38bdf8"
                fontSize="9"
                fontWeight="bold"
              >
                TARGET: {commandedAngle.toFixed(0)}°
              </text>
            </g>
          )}

          {/* Physical Gate Leaf Arm */}
          <g>
            {hasFeedback ? (
              // Measured Physical Gate (Solid Arm)
              <g>
                <line
                  x1={pivotX}
                  y1={pivotY}
                  x2={tipX}
                  y2={tipY}
                  stroke="#f59e0b"
                  strokeWidth="6"
                  strokeLinecap="round"
                />
                <line
                  x1={pivotX}
                  y1={pivotY}
                  x2={tipX}
                  y2={tipY}
                  stroke="#fbbf24"
                  strokeWidth="2"
                  strokeLinecap="round"
                />
                <circle cx={tipX} cy={tipY} r="4" fill="#b45309" stroke="#f59e0b" strokeWidth="1" />
                <text
                  x={tipX + (visualAngleClamped > 45 ? 12 : 8)}
                  y={tipY + 12}
                  fill="#f59e0b"
                  fontSize="9"
                  fontWeight="bold"
                >
                  ACTUAL: {measuredAngle?.toFixed(1)}°
                </text>
              </g>
            ) : (
              // Open-Loop Command (No physical feedback sensor reported)
              <g>
                <line
                  x1={pivotX}
                  y1={pivotY}
                  x2={tipX}
                  y2={tipY}
                  stroke="#fbbf24"
                  strokeWidth="5"
                  strokeDasharray="5 3"
                  strokeLinecap="round"
                  opacity="0.9"
                />
                <circle cx={tipX} cy={tipY} r="4" fill="#070b12" stroke="#f59e0b" strokeWidth="2" />
                <text
                  x={tipX + (visualAngleClamped > 45 ? -10 : 10)}
                  y={tipY - 8}
                  fill="#f59e0b"
                  fontSize="9"
                  textAnchor={visualAngleClamped > 45 ? 'end' : 'start'}
                >
                  CMD: {commandedAngle.toFixed(0)}° (OPEN LOOP)
                </text>
              </g>
            )}

            {/* Hinge Pivot Assembly (Servo Motor Housing at Pivot) */}
            <circle cx={pivotX} cy={pivotY} r="14" fill="#0f172a" stroke="#64748b" strokeWidth="2" />
            <circle cx={pivotX} cy={pivotY} r="7" fill="#334155" stroke="#94a3b8" strokeWidth="1.5" />
            <circle cx={pivotX} cy={pivotY} r="3" fill="#f59e0b" />

            {/* Servo Label & Wire */}
            <text x={pivotX - 18} y={pivotY + 28} fill="#94a3b8" fontSize="8" fontWeight="bold">
              SERVO (SG90/MG996R)
            </text>
            <path d="M 300,234 L 300,260 L 260,260" fill="none" stroke="#64748b" strokeWidth="1.5" />
            <text x="250" y="263" fill="#64748b" fontSize="7" textAnchor="end">
              ESP32 PWM GPIO
            </text>
          </g>

          {/* ======================================================== */}
          {/* LABELS & OPERATIONAL ANNOTATIONS                         */}
          {/* ======================================================== */}

          {/* Inlet Flow Label */}
          <text x="70" y="70" fill="#38bdf8" fontSize="10" fontWeight="bold">
            INLET FLUME (Qin: {inflow.toFixed(1)} L/min)
          </text>

          {/* Primary Route Label */}
          <text x="790" y="72" fill="#38bdf8" fontSize="10" textAnchor="end" fontWeight="bold">
            PRIMARY DRAINAGE CHANNEL (CONTINUATION)
          </text>
          <text x="790" y="105" fill="#94a3b8" fontSize="9" textAnchor="end">
            FLOW: {primaryFlow} L/min ({(primaryFraction * 100).toFixed(0)}%)
          </text>

          {/* Secondary Diversion Route Label */}
          <text x="790" y="240" fill="#2dd4bf" fontSize="10" textAnchor="end" fontWeight="bold">
            SECONDARY DIVERSION CHANNEL
          </text>
          <text x="790" y="258" fill="#94a3b8" fontSize="9" textAnchor="end">
            FLOW: {diversionFlow} L/min ({(diversionFraction * 100).toFixed(0)}%)
          </text>
          <text x="790" y="274" fill="#64748b" fontSize="8" textAnchor="end">
            EMERGENCY OVERFLOW DETOUR
          </text>
        </svg>
      </div>

      {/* Telemetry & Diagnostic Status Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mt-4 pt-3 border-t border-slate-800 text-xs font-mono">
        {/* Command Directive Metric */}
        <div className="bg-slate-950/60 p-2.5 rounded border border-slate-800">
          <div className="text-[10px] text-slate-500 uppercase flex items-center justify-between">
            <span>COMMANDED ANGLE</span>
            <Sliders className="w-3 h-3 text-cyan-400" />
          </div>
          <div className="text-base font-bold text-slate-100 mt-1 flex items-baseline gap-1">
            <span data-testid="commanded-angle">{commandedAngle.toFixed(1)}°</span>
            <span className="text-[10px] text-cyan-400 font-normal">[{directiveAction}]</span>
          </div>
          <div className="text-[10px] text-slate-400 truncate mt-1">
            Reason: {directiveReason}
          </div>
        </div>

        {/* Physical Feedback Metric */}
        <div className="bg-slate-950/60 p-2.5 rounded border border-slate-800">
          <div className="text-[10px] text-slate-500 uppercase flex items-center justify-between">
            <span>PHYSICAL FEEDBACK</span>
            <Activity className="w-3 h-3 text-amber-400" />
          </div>
          <div className="text-base font-bold text-slate-100 mt-1 flex items-baseline gap-1">
            {hasFeedback ? (
              <>
                <span data-testid="measured-angle" className="text-amber-300">
                  {measuredAngle?.toFixed(1)}°
                </span>
                <span className="text-[10px] text-emerald-400 font-normal">[VERIFIED]</span>
              </>
            ) : (
              <span data-testid="measured-angle" className="text-slate-400 text-xs font-normal">
                NOT REPORTED (OPEN LOOP)
              </span>
            )}
          </div>
          <div className="text-[10px] text-slate-500 mt-1">
            {hasFeedback
              ? `Source: ${feedbackReading?.source} via ${feedbackReading?.sensor_id}`
              : 'Direct servo potentiometer feedback not detected'}
          </div>
        </div>

        {/* Flow Redistribution Ratio */}
        <div className="bg-slate-950/60 p-2.5 rounded border border-slate-800">
          <div className="text-[10px] text-slate-500 uppercase flex items-center justify-between">
            <span>FLOW SPLIT RATIO</span>
            <GitBranch className="w-3 h-3 text-teal-400" />
          </div>
          <div className="text-sm font-bold text-slate-100 mt-1 flex items-center justify-between">
            <span className="text-sky-300">MAIN: {(primaryFraction * 100).toFixed(0)}%</span>
            <span className="text-teal-300">DIVERT: {(diversionFraction * 100).toFixed(0)}%</span>
          </div>
          <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden flex mt-2">
            <div
              className="bg-sky-500 h-full transition-all duration-300"
              style={{ width: `${primaryFraction * 100}%` }}
            />
            <div
              className="bg-teal-400 h-full transition-all duration-300"
              style={{ width: `${diversionFraction * 100}%` }}
            />
          </div>
        </div>

        {/* Operational Safety & Verification Status */}
        <div className="bg-slate-950/60 p-2.5 rounded border border-slate-800">
          <div className="text-[10px] text-slate-500 uppercase flex items-center justify-between">
            <span>GATE OPERATION AUDIT</span>
            <ShieldAlert className="w-3 h-3 text-slate-400" />
          </div>
          <div className="text-[11px] font-bold mt-1">
            {hasFeedback ? (
              <span className="text-emerald-400 flex items-center gap-1">
                <CheckCircle2 className="w-3 h-3" /> CLOSED-LOOP VERIFIED
              </span>
            ) : (
              <span className="text-amber-400 flex items-center gap-1">
                <AlertTriangle className="w-3 h-3" /> COMMAND WITHOUT CONFIRMATION
              </span>
            )}
          </div>
          <div className="text-[10px] text-slate-400 mt-1">
            {riskLevel === 'CRITICAL' || riskLevel === 'HIGH' || activeAlertsCount > 0 ? (
              <span className="text-rose-400 font-bold">
                [HIGH RISK / ALERTS ACTIVE ({activeAlertsCount})]
              </span>
            ) : (
              <span>[NOMINAL MONITORING]</span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
