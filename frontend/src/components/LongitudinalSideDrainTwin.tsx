import React, { useState, useEffect, useCallback, useMemo } from 'react';
import {
  SensorReadingContract,
  ActuatorDirectiveContract,
  BlockageEventContract,
  MechanismStatusContract,
  PredictionContract,
  TelemetryConnectionState,
  TelemetrySource,
} from '../types/contracts';
import {
  RotateCw,
  Play,
  Pause,
  RefreshCw,
  Eye,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Activity,
  Layers,
  Zap,
  Box,
  Compass,
  Wifi,
  WifiOff,
  Clock,
  AlertTriangle,
  Radio,
} from 'lucide-react';

export type SimulationState =
  | 'NORMAL_FLOW'
  | 'DEBRIS_ACCUMULATION'
  | 'BLOCKAGE_DETECTED'
  | 'DIVERSION_OPENING'
  | 'DEBRIS_DIVERSION'
  | 'DIVERSION_CLOSING'
  | 'RECOVERY';

export type ViewPerspective = 'top' | 'iso' | 'side';

export interface LongitudinalSideDrainTwinProps {
  upstreamDepth: number; // cm
  inflow: number; // L/min
  weirHead?: number; // legacy prop compatibility
  mode?: 'SIMULATION' | 'HARDWARE' | 'PHYSICAL' | 'SAFE_HOLD';
  mechanism?: MechanismStatusContract;
  blockage?: BlockageEventContract | null;
  prediction?: PredictionContract | null;
  gateDirective?: ActuatorDirectiveContract | null;
  readings?: Record<string, SensorReadingContract>;
  activeAlertsCount?: number;
  hardwareValidationStage?: string | null;
  isDemoMode?: boolean;
}

interface DebrisParticle {
  id: number;
  x: number; // 0 to 80 cm (transverse across channel)
  y: number; // 0 to 50 cm (elevation)
  z: number; // 0 to 140 cm (longitudinal along channel, 140 = IN, 0 = OUT)
  vx: number;
  vy: number;
  vz: number;
  size: number;
  color: string;
  diverted: boolean;
  trapped: boolean;
}

export const LongitudinalSideDrainTwin: React.FC<LongitudinalSideDrainTwinProps> = ({
  upstreamDepth,
  inflow,
  weirHead: _weirHead,
  mode = 'SIMULATION',
  mechanism: _mechanism,
  blockage: _blockage,
  prediction: _prediction,
  gateDirective = null,
  readings = {},
  activeAlertsCount: _activeAlertsCount = 0,
  hardwareValidationStage = null,
  isDemoMode = false,
}) => {
  // Demonstration Mode toggle: default to isDemoMode or mode === 'SIMULATION'
  const [demoMode, setDemoMode] = useState<boolean>(isDemoMode || mode === 'SIMULATION');

  useEffect(() => {
    if (typeof isDemoMode === 'boolean') {
      setDemoMode(isDemoMode);
    }
  }, [isDemoMode]);

  // 1. Perspective & Camera State
  // Default is 'top' to allow direct verification against the authoritative top-view sketch
  const [viewPerspective, setViewPerspective] = useState<ViewPerspective>('top');
  const [azimuth, setAzimuth] = useState<number>(-90); // degrees (-90 = aligned with top-view sketch)
  const [tilt, setTilt] = useState<number>(88); // degrees (88 = orthogonal top-down plan)
  const [zoom, setZoom] = useState<number>(1.1);
  const [pan, setPan] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [dragMode, setDragMode] = useState<'orbit' | 'pan'>('orbit');

  // 2. Acrylic Viewing Panel Transparency & Dimension Overlays
  const [acrylicOpacity, setAcrylicOpacity] = useState<number>(0.35);
  const [showDimensions, setShowDimensions] = useState<boolean>(true);
  const [showCallouts, setShowCallouts] = useState<boolean>(true);

  // 3. Simulation State Machine
  const [simState, setSimState] = useState<SimulationState>('NORMAL_FLOW');
  const [isSimPaused, setIsSimPaused] = useState<boolean>(false);
  const [simSpeed, setSimSpeed] = useState<number>(1.0);
  const [accumulationRate, setAccumulationRate] = useState<'low' | 'med' | 'high'>('med');

  // Animated variables (Preserving actual physical prototype units in cm)
  const [simDoorAngle, setSimDoorAngle] = useState<number>(0.0); // 0 deg (closed / flush) to 90 deg (open)
  const [simWaterDepth, setSimWaterDepth] = useState<number>(upstreamDepth || 6.5);
  const [simBlockagePct, setSimBlockagePct] = useState<number>(0);

  // Debris Particles
  const [particles, setParticles] = useState<DebrisParticle[]>(() => initParticles(28));

  // 4. Telemetry Source & Hardware Connection Evaluation (P1.1 Abstraction)
  const physicalReadings = useMemo(() => {
    return Object.values(readings).filter(
      (r) => r.source === 'PHYSICAL' || r.source === 'LIVE'
    );
  }, [readings]);

  // Evaluate connection state: LIVE | SIMULATED | OFFLINE | STALE | FAULT
  const connectionState: TelemetryConnectionState = useMemo(() => {
    if (demoMode || mode === 'SIMULATION') {
      return 'SIMULATED';
    }

    if (physicalReadings.length === 0) {
      return 'OFFLINE';
    }

    const hasFault = physicalReadings.some((r) => r.status === 'FAULT');
    if (hasFault) {
      return 'FAULT';
    }

    const nowMs = Date.now();
    const timestamps = physicalReadings
      .map((r) => new Date(r.timestamp).getTime())
      .filter((t) => !isNaN(t));

    if (timestamps.length === 0) {
      return 'OFFLINE';
    }

    const newestTime = Math.max(...timestamps);
    const ageMs = nowMs - newestTime;

    if (ageMs > 30000) {
      // Exceeds offline threshold (30s): hardware is offline, do NOT retain misleading LIVE
      return 'OFFLINE';
    }

    if (ageMs > 15000) {
      // Exceeds freshness threshold (15s): stale
      return 'STALE';
    }

    return 'LIVE';
  }, [demoMode, mode, physicalReadings]);

  // Last-seen timestamp across all physical readings
  const lastSeenTimestamp = useMemo(() => {
    if (physicalReadings.length === 0) return null;
    const timestamps = physicalReadings
      .map((r) => new Date(r.timestamp).getTime())
      .filter((t) => !isNaN(t));
    if (timestamps.length === 0) return null;
    return new Date(Math.max(...timestamps)).toISOString();
  }, [physicalReadings]);

  // Radar Sensor (Water Level in cm)
  const radarReading = readings['RADAR_01'] || readings['US_UPSTREAM_01'];
  const isRadarPhysical = radarReading && (radarReading.source === 'PHYSICAL' || radarReading.source === 'LIVE');

  const radarTelemetry = useMemo(() => {
    if (connectionState === 'SIMULATED') {
      return {
        value: simWaterDepth,
        formatted: `${simWaterDepth.toFixed(1)} cm`,
        source: 'SIMULATED' as TelemetrySource,
        timestamp: new Date().toISOString(),
        status: 'OK',
        isAvailable: true,
      };
    }

    if (!isRadarPhysical || connectionState === 'OFFLINE') {
      return {
        value: null,
        formatted: 'UNAVAILABLE',
        source: 'OFFLINE' as TelemetrySource,
        timestamp: radarReading?.timestamp || null,
        status: radarReading?.status || 'DISCONNECTED',
        isAvailable: false,
      };
    }

    const readingAgeMs = Date.now() - new Date(radarReading.timestamp).getTime();
    const isStale = readingAgeMs > 15000;
    return {
      value: radarReading.value,
      formatted: `${radarReading.value.toFixed(1)} cm`,
      source: (isStale ? 'OFFLINE' : 'LIVE') as TelemetrySource,
      timestamp: radarReading.timestamp,
      status: radarReading.status === 'FAULT' ? 'FAULT' : isStale ? 'STALE' : radarReading.status,
      isAvailable: radarReading.status !== 'FAULT' && !isStale,
    };
  }, [connectionState, isRadarPhysical, radarReading, simWaterDepth]);

  // Flow Sensor (Qin in L/min)
  const flowReading = readings['FLOW_01'] || readings['FLOW_INFLOW_01'] || readings['PUMP_INFLOW_01'];
  const isFlowPhysical = flowReading && (flowReading.source === 'PHYSICAL' || flowReading.source === 'LIVE');

  const flowTelemetry = useMemo(() => {
    if (connectionState === 'SIMULATED') {
      return {
        flowRate: inflow,
        formattedFlow: `${inflow.toFixed(1)} L/min`,
        cumulativeVolumeLiters: 1240.5,
        source: 'SIMULATED' as TelemetrySource,
        timestamp: new Date().toISOString(),
        status: 'OK',
        isAvailable: true,
      };
    }

    if (!isFlowPhysical || connectionState === 'OFFLINE') {
      return {
        flowRate: null,
        formattedFlow: 'UNAVAILABLE',
        cumulativeVolumeLiters: null,
        source: 'OFFLINE' as TelemetrySource,
        timestamp: flowReading?.timestamp || null,
        status: flowReading?.status || 'DISCONNECTED',
        isAvailable: false,
      };
    }

    const readingAgeMs = Date.now() - new Date(flowReading.timestamp).getTime();
    const isStale = readingAgeMs > 15000;
    const metadata = (flowReading.metadata || {}) as Record<string, any>;
    const totalVol = (metadata.cumulative_volume_liters ?? metadata.total_volume_liters) as number | undefined;

    return {
      flowRate: flowReading.value,
      formattedFlow: `${flowReading.value.toFixed(1)} L/min`,
      cumulativeVolumeLiters: typeof totalVol === 'number' ? totalVol : null,
      source: (isStale ? 'OFFLINE' : 'LIVE') as TelemetrySource,
      timestamp: flowReading.timestamp,
      status: flowReading.status === 'FAULT' ? 'FAULT' : isStale ? 'STALE' : flowReading.status,
      isAvailable: flowReading.status !== 'FAULT' && !isStale,
    };
  }, [connectionState, isFlowPhysical, flowReading, inflow]);

  // Actuator State (DischargeKeeper)
  const gateReading = Object.values(readings).find(
    (r) => r.sensor_type === 'GATE_ANGLE' || r.unit === 'deg' || r.sensor_id.includes('GATE')
  );

  const positionFeedbackReading = Object.values(readings).find(
    (r) => (r.sensor_id.includes('POSITION_FEEDBACK') || (r.metadata as Record<string, any>)?.is_actual_position === true) &&
           (r.source === 'PHYSICAL' || r.source === 'LIVE')
  );
  const hasActualPositionFeedback = positionFeedbackReading !== undefined && positionFeedbackReading.status === 'OK';

  const commandedDoorAngle = useMemo(() => {
    if (connectionState === 'SIMULATED') {
      return simDoorAngle;
    }
    if (gateDirective && typeof gateDirective.gate_target_angle === 'number') {
      return gateDirective.gate_target_angle;
    }
    if (gateReading) {
      return gateReading.value;
    }
    return 0.0;
  }, [connectionState, simDoorAngle, gateDirective, gateReading]);

  const actualDoorAngle = useMemo(() => {
    if (connectionState === 'SIMULATED') {
      return simDoorAngle;
    }
    if (hasActualPositionFeedback && positionFeedbackReading) {
      return positionFeedbackReading.value;
    }
    return null; // Open-loop servo command is NOT physical position feedback!
  }, [connectionState, simDoorAngle, hasActualPositionFeedback, positionFeedbackReading]);

  // Effective door angle for canvas projection:
  const effectiveDoorAngle = useMemo(() => {
    if (connectionState === 'SIMULATED') {
      return simDoorAngle;
    }
    if (connectionState === 'OFFLINE') {
      return 0.0;
    }
    return actualDoorAngle !== null ? actualDoorAngle : commandedDoorAngle;
  }, [connectionState, simDoorAngle, actualDoorAngle, commandedDoorAngle]);

  const displayRadarLevelCm = radarTelemetry.value ?? (connectionState === 'SIMULATED' ? simWaterDepth : 0);

  // 5. Canvas Dimensions
  const svgWidth = 980;
  const svgHeight = 560;
  const originX = svgWidth / 2 + pan.x;
  const originY = svgHeight / 2 + pan.y;

  // 6. EXACT PHYSICAL DIMENSIONS FROM SHEET-METAL PROTOTYPE DRAWINGS (IN CM)
  // Overall Dimensions:
  // - Total Length: 140 cm (40 cm + 60 cm + 40 cm)
  // - Transverse Width: 80 cm
  // - Sheet-metal Wall Height: 50 cm
  // - Longitudinal Sections:
  //    * Section 1 (Right): 40 cm (Z from 100 cm to 140 cm) labeled 'IN'
  //    * Section 2 (Middle): 60 cm (Z from 40 cm to 100 cm)
  //      - Sub-partition at 30 cm (Z = 70 cm), dividing the 60 cm section into two 30 cm sections
  //    * Section 3 (Left): 40 cm (Z from 0 cm to 40 cm)
  // - Internal Dividing Longitudinal Partition:
  //    * Located along transverse X = 40 cm, dividing the 80 cm transverse width into:
  //      Primary Channel (X = 40 to 80 cm, width = 40 cm) and Side Diversion Channel (X = 0 to 40 cm, width = 40 cm)
  // - Hinged Diversion Door:
  //    * Pivot axis at X = 40 cm, Z = 70 cm (at the 30 cm internal section junction)
  //    * Door leaf length = 38 cm
  //    * Rotates around vertical hinge axis from 0° (flush along partition) to 90° (deflecting flow into diversion path)
  const TOTAL_LENGTH = 140; // cm
  const TOTAL_WIDTH = 80;   // cm
  const WALL_HEIGHT = 50;   // cm
  const PARTITION_X = 40;   // cm (internal divider: exact 40 cm / 40 cm transverse split)

  // Door kinematics in cm:
  const doorRad = (effectiveDoorAngle * Math.PI) / 180;
  // Fixed pivot at (X = PARTITION_X = 40 cm, Z = 70 cm)
  // 0 deg: closed along partition toward downstream (Z decreases, X = 40 cm)
  // 90 deg: open into primary channel (X increases toward 78 cm, Z = 70 cm)
  const doorLength = 38; // cm (spans across the 40 cm primary channel with 2 cm clearance at 90°)
  const doorPivotX = PARTITION_X; // 40 cm
  const doorPivotZ = 70; // cm
  const doorTipX = doorPivotX + doorLength * Math.sin(doorRad);
  const doorTipZ = doorPivotZ - doorLength * Math.cos(doorRad);
  const doorThickness = 1.6; // cm physical plate thickness
  const doorLeafHeight = 36; // cm vertical leaf height (fits inside 40 cm partition)

  // Door leaf normal vector for physical plate thickness:
  const normX = (doorThickness / 2) * Math.cos(doorRad);
  const normZ = (doorThickness / 2) * Math.sin(doorRad);

  // 4 corners of door leaf in plan (X, Z):
  const cHinge1: [number, number] = [doorPivotX - normX, doorPivotZ - normZ];
  const cHinge2: [number, number] = [doorPivotX + normX, doorPivotZ + normZ];
  const cTip2: [number, number] = [doorTipX + normX, doorTipZ + normZ];
  const cTip1: [number, number] = [doorTipX - normX, doorTipZ - normZ];

  // 7. 3D Projector Function (Model units in cm, centered at X=40, Y=25, Z=70)
  const project = useCallback(
    (x: number, y: number, z: number): [number, number] => {
      // Scale factor: pixels per cm
      const scale = zoom * 2.8;

      if (viewPerspective === 'top') {
        // Orthogonal 2D Top View matching sheet-metal layout sketch:
        // Horizontal screen axis: Longitudinal Z (from 0 on left to 140 on right)
        // Vertical screen axis: Transverse X (from 0 at top to 80 at bottom)
        const u = originX + (z - 70) * scale;
        const v = originY + (x - 40) * scale;
        return [u, v];
      }

      if (viewPerspective === 'side') {
        // True Orthogonal 2D Side Elevation Cutaway looking through transparent acrylic wall (X = 0):
        // Horizontal screen axis: Longitudinal Z (from 0 on left to 140 on right)
        // Vertical screen axis: Elevation Y (from 0 at bottom to 50 at top)
        const u = originX + (z - 70) * scale;
        const v = originY - (y - 25) * scale;
        return [u, v];
      }

      const azRad = (azimuth * Math.PI) / 180;
      const tiltRad = (tilt * Math.PI) / 180;

      const dx = x - 40;
      const dy = y - 25;
      const dz = z - 70;

      // Azimuth rotation around vertical Y axis
      const xr = dx * Math.cos(azRad) - dz * Math.sin(azRad);
      const zr = dx * Math.sin(azRad) + dz * Math.cos(azRad);
      const yr = dy;

      // Tilt rotation
      const yt = yr * Math.cos(tiltRad) - zr * Math.sin(tiltRad);

      const u = originX + scale * xr;
      const v = originY - scale * yt;

      return [u, v];
    },
    [viewPerspective, azimuth, tilt, zoom, originX, originY]
  );

  const toPoly = useCallback(
    (pts: [number, number, number][]) =>
      pts.map(([x, y, z]) => project(x, y, z).map((n) => n.toFixed(1)).join(',')).join(' '),
    [project]
  );

  // 8. Simulation Tick Loop
  useEffect(() => {
    if (isSimPaused) return;

    const interval = setInterval(() => {
      setSimState((currState) => {
        switch (currState) {
          case 'NORMAL_FLOW': {
            setSimDoorAngle((prev) => Math.max(0, prev - 3 * simSpeed));
            setSimBlockagePct((prev) => Math.max(0, prev - 2 * simSpeed));
            setSimWaterDepth((prev) => {
              const base = upstreamDepth || 6.2;
              return Math.max(base, prev - 0.2 * simSpeed);
            });
            if (Math.random() < (accumulationRate === 'high' ? 0.08 : accumulationRate === 'med' ? 0.04 : 0.02) * simSpeed) {
              return 'DEBRIS_ACCUMULATION';
            }
            return 'NORMAL_FLOW';
          }

          case 'DEBRIS_ACCUMULATION': {
            const step = (accumulationRate === 'high' ? 2.5 : accumulationRate === 'med' ? 1.5 : 0.8) * simSpeed;
            setSimBlockagePct((prev) => {
              const next = prev + step;
              if (next >= 48) return 48;
              return next;
            });
            setSimWaterDepth((prev) => Math.min(12.5, prev + 0.15 * simSpeed));
            if (simBlockagePct >= 40) {
              return 'BLOCKAGE_DETECTED';
            }
            return 'DEBRIS_ACCUMULATION';
          }

          case 'BLOCKAGE_DETECTED': {
            setSimBlockagePct(52);
            setSimWaterDepth((prev) => Math.min(13.8, prev + 0.1 * simSpeed));
            return 'DIVERSION_OPENING';
          }

          case 'DIVERSION_OPENING': {
            let done = false;
            setSimDoorAngle((prev) => {
              const next = prev + 5 * simSpeed;
              if (next >= 90) {
                done = true;
                return 90;
              }
              return next;
            });
            if (done || simDoorAngle >= 88) {
              return 'DEBRIS_DIVERSION';
            }
            return 'DIVERSION_OPENING';
          }

          case 'DEBRIS_DIVERSION': {
            setSimDoorAngle(90);
            let cleared = false;
            setSimBlockagePct((prev) => {
              const next = Math.max(0, prev - 4 * simSpeed);
              if (next <= 5) cleared = true;
              return next;
            });
            setSimWaterDepth((prev) => Math.max(6.2, prev - 0.4 * simSpeed));
            if (cleared) {
              return 'DIVERSION_CLOSING';
            }
            return 'DEBRIS_DIVERSION';
          }

          case 'DIVERSION_CLOSING': {
            let closed = false;
            setSimDoorAngle((prev) => {
              const next = Math.max(0, prev - 4 * simSpeed);
              if (next <= 2) {
                closed = true;
                return 0;
              }
              return next;
            });
            if (closed || simDoorAngle <= 2) {
              return 'RECOVERY';
            }
            return 'DIVERSION_CLOSING';
          }

          case 'RECOVERY': {
            setSimDoorAngle(0);
            setSimBlockagePct(0);
            setSimWaterDepth((prev) => {
              const base = upstreamDepth || 6.2;
              return Math.max(base, prev - 0.15 * simSpeed);
            });
            return 'NORMAL_FLOW';
          }

          default:
            return 'NORMAL_FLOW';
        }
      });

      // Update particle positions obeying physical sheet-metal boundaries
      setParticles((prev) =>
        prev.map((p) => {
          let { x, y, z, vx, vy, vz, diverted, trapped } = p;
          const flowSpeed = (1.8 + (inflow ? inflow / 10 : 0.8)) * simSpeed;

          if (simState === 'DEBRIS_ACCUMULATION' || simState === 'BLOCKAGE_DETECTED') {
            // Trapping zone at screen (Z around 70 to 80 cm, inside primary channel X = 38 to 80 cm)
            if (z <= 78 && z >= 68 && x >= PARTITION_X) {
              trapped = true;
              vz = 0;
              vx = (Math.random() - 0.5) * 0.1;
            } else if (!trapped) {
              z -= flowSpeed;
            }
          } else if (simState === 'DEBRIS_DIVERSION' || simState === 'DIVERSION_OPENING') {
            if (simDoorAngle > 25) {
              trapped = false;
              diverted = true;
              // Deflect toward side diversion channel (X < PARTITION_X) and downstream (Z < 70)
              vx = -2.2 * simSpeed;
              vz = -1.6 * simSpeed;
              x += vx;
              z += vz;
              // Prevent particle from penetrating outer sheet metal wall at X = 0
              if (x < 6) x = 6;
            } else {
              z -= flowSpeed;
            }
          } else {
            // Normal flow: particles pass along primary channel
            z -= flowSpeed;
            trapped = false;
            diverted = false;
          }

          // Respawn particles exiting downstream boundary (Z < 0)
          if (z < -10 || x < 0) {
            z = 135 + Math.random() * 5;
            x = 45 + Math.random() * 30; // spawn in IN region (primary side)
            y = 5 + Math.random() * 10;
            trapped = false;
            diverted = false;
          }

          return { ...p, x, y, z, vx, vy, vz, diverted, trapped };
        })
      );
    }, 50);

    return () => clearInterval(interval);
  }, [isSimPaused, simSpeed, accumulationRate, simBlockagePct, simDoorAngle, upstreamDepth, inflow, simState]);

  // Perspective Switcher
  const switchPerspective = (p: ViewPerspective) => {
    setViewPerspective(p);
    if (p === 'top') {
      setAzimuth(-90);
      setTilt(88);
      setZoom(1.1);
      setPan({ x: 0, y: 0 });
    } else if (p === 'iso') {
      setAzimuth(-145);
      setTilt(30);
      setZoom(1.0);
      setPan({ x: 0, y: 0 });
    } else if (p === 'side') {
      setAzimuth(0);
      setTilt(0);
      setZoom(1.15);
      setPan({ x: 0, y: 0 });
    }
  };

  // Mouse drag handling
  const handleMouseDown = (e: React.MouseEvent<SVGSVGElement>) => {
    setIsDragging(true);
    setDragStart({ x: e.clientX, y: e.clientY });
  };

  const handleMouseMove = (e: React.MouseEvent<SVGSVGElement>) => {
    if (!isDragging) return;
    const dx = e.clientX - dragStart.x;
    const dy = e.clientY - dragStart.y;
    setDragStart({ x: e.clientX, y: e.clientY });

    if (dragMode === 'orbit' && viewPerspective === 'iso') {
      setAzimuth((prev) => ((prev + dx * 0.5 + 180) % 360) - 180);
      setTilt((prev) => Math.min(88, Math.max(5, prev + dy * 0.4)));
    } else {
      setPan((prev) => ({ x: prev.x + dx, y: prev.y + dy }));
    }
  };

  const handleMouseUp = () => setIsDragging(false);

  // Water level in cm (clamped to wall height)
  const isWaterLevelAvailable = radarTelemetry.isAvailable;
  const waterDepthCm = isWaterLevelAvailable
    ? Math.min(WALL_HEIGHT - 4, Math.max(3, displayRadarLevelCm))
    : (connectionState === 'SIMULATED' ? Math.min(WALL_HEIGHT - 4, Math.max(3, simWaterDepth)) : 0);

  // Radar Sensor Coordinates: Mounted over centerline of primary channel at X = 60 cm, Y = 62 cm, Z = 70 cm
  const [radarScreenX, radarScreenY] = project(60, 62, 70);
  const [radarTargetX, radarTargetY] = project(60, waterDepthCm, 70);

  // DischargeKeeper Actuator Coordinates: Mounted on transverse crossbeam over hinge pin at X = PARTITION_X (40 cm), Y = 60 cm, Z = 70 cm
  const [dkScreenX, dkScreenY] = project(PARTITION_X, 60, 70);
  const [pivotScreenX, pivotScreenY] = project(doorPivotX, 0, doorPivotZ);

  const getStatusBadgeStyle = () => {
    switch (simState) {
      case 'NORMAL_FLOW':
        return 'bg-emerald-950/70 text-emerald-300 border-emerald-700';
      case 'DEBRIS_ACCUMULATION':
        return 'bg-amber-950/70 text-amber-300 border-amber-700';
      case 'BLOCKAGE_DETECTED':
        return 'bg-rose-950/80 text-rose-300 border-rose-600 animate-pulse';
      case 'DIVERSION_OPENING':
      case 'DEBRIS_DIVERSION':
        return 'bg-cyan-950/80 text-cyan-300 border-cyan-600 animate-pulse';
      case 'DIVERSION_CLOSING':
      case 'RECOVERY':
        return 'bg-blue-950/70 text-blue-300 border-blue-700';
    }
  };

  return (
    <div className="bg-slate-900 rounded border border-slate-800 shadow-2xl p-4 sm:p-5 mb-6 overflow-hidden select-none">
      {/* Mimic Header */}
      <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-3 mb-4 pb-3 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2 flex-wrap">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 shadow-[0_0_10px_rgba(34,211,238,0.9)] animate-pulse" />
            <h2 className="text-xs sm:text-sm font-mono font-bold text-slate-100 uppercase tracking-wider flex items-center gap-1.5">
              <Layers className="w-4 h-4 text-cyan-400" />
              PHYSICAL SHEET-METAL PROTOTYPE TWIN // TOP-VIEW &amp; 3D CUTAWAY
            </h2>
          </div>
          <p className="text-[11px] font-mono text-slate-400 mt-1">
            Faithful sheet-metal prototype geometry: 140 cm overall length (40 cm / 60 cm / 40 cm), 80 cm
            transverse width, 30 cm internal partition, rightmost 'IN' inlet region, hinged diversion door, and
            overhead radar monitoring.
          </p>
        </div>

        {/* Badges */}
        <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
          <span className="px-2.5 py-1 rounded bg-slate-800/90 text-cyan-300 border border-slate-700 text-[11px] font-semibold">
            PROTOTYPE: 140×80×50 CM (40|40 SPLIT)
          </span>

          <span
            data-testid="telemetry-source-badge"
            className={`px-2.5 py-1 rounded border text-[11px] font-bold flex items-center gap-1.5 ${
              connectionState === 'LIVE'
                ? 'bg-emerald-950/80 text-emerald-300 border-emerald-600'
                : connectionState === 'STALE'
                ? 'bg-amber-950/80 text-amber-300 border-amber-600'
                : connectionState === 'FAULT'
                ? 'bg-red-950/80 text-red-300 border-red-600'
                : connectionState === 'OFFLINE'
                ? 'bg-rose-950/80 text-rose-300 border-rose-600'
                : 'bg-slate-800 text-slate-300 border-slate-700'
            }`}
          >
            {connectionState === 'LIVE' ? (
              <>
                <Wifi className="w-3.5 h-3.5 text-emerald-400" />
                <span>LIVE (ESP32)</span>
              </>
            ) : connectionState === 'STALE' ? (
              <>
                <Clock className="w-3.5 h-3.5 text-amber-400" />
                <span>STALE (&gt;15s)</span>
              </>
            ) : connectionState === 'FAULT' ? (
              <>
                <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
                <span>HARDWARE FAULT</span>
              </>
            ) : connectionState === 'OFFLINE' ? (
              <>
                <WifiOff className="w-3.5 h-3.5 text-rose-400" />
                <span>HARDWARE OFFLINE</span>
              </>
            ) : (
              <>
                <Radio className="w-3.5 h-3.5 text-sky-400" />
                <span>SIMULATION MODE</span>
              </>
            )}
          </span>

          {hardwareValidationStage && (
            <span className="px-2.5 py-1 rounded bg-slate-800/90 text-amber-300 border border-amber-600/60 text-[11px] font-semibold">
              STAGE: {hardwareValidationStage}
            </span>
          )}

          <span className={`px-2.5 py-1 rounded border text-[11px] font-bold flex items-center gap-1.5 ${getStatusBadgeStyle()}`}>
            <Activity className="w-3.5 h-3.5" />
            STATE: {simState}
          </span>
        </div>
      </div>

      {/* Main Viewport */}
      <div className="relative w-full bg-[#05080f] rounded border border-slate-800/90 overflow-hidden shadow-inner">
        {/* View Mode Switcher Toolbar */}
        <div className="absolute top-3 left-3 z-10 flex flex-wrap items-center gap-1.5 bg-slate-900/95 backdrop-blur border border-slate-800 p-1.5 rounded shadow-lg text-[11px] font-mono">
          <span className="text-slate-400 px-1.5 font-bold uppercase text-[10px]">PERSPECTIVE:</span>
          <button
            onClick={() => switchPerspective('top')}
            className={`px-2.5 py-1 rounded flex items-center gap-1 transition ${
              viewPerspective === 'top'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-700 font-bold shadow-sm'
                : 'bg-slate-800 text-slate-400 hover:text-slate-200'
            }`}
            title="Orthogonal Top-Down Plan directly matching the sheet-metal sketch"
          >
            <Compass className="w-3.5 h-3.5 text-cyan-400" />
            <span>TOP VIEW (PLAN)</span>
          </button>
          <button
            onClick={() => switchPerspective('iso')}
            className={`px-2.5 py-1 rounded flex items-center gap-1 transition ${
              viewPerspective === 'iso'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-700 font-bold shadow-sm'
                : 'bg-slate-800 text-slate-400 hover:text-slate-200'
            }`}
            title="3D Isometric Axonometric Cutaway View"
          >
            <Box className="w-3.5 h-3.5 text-cyan-400" />
            <span>3D ISOMETRIC</span>
          </button>
          <button
            onClick={() => switchPerspective('side')}
            className={`px-2.5 py-1 rounded transition ${
              viewPerspective === 'side'
                ? 'bg-cyan-950 text-cyan-300 border border-cyan-700 font-bold shadow-sm'
                : 'bg-slate-800 text-slate-400 hover:text-slate-200'
            }`}
            title="Side Elevation Cutaway"
          >
            SIDE VIEW
          </button>

          <div className="w-[1px] h-4 bg-slate-700 mx-1" />

          {/* Demonstration Mode Switcher */}
          <button
            onClick={() => setDemoMode((prev) => !prev)}
            className={`px-2.5 py-0.5 rounded flex items-center gap-1 font-bold ${
              demoMode
                ? 'bg-sky-950 text-sky-300 border border-sky-600'
                : 'bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-700'
            }`}
            title="Toggle Demonstration Mode (Synthetic) vs Live Hardware Tracking"
          >
            <Radio className="w-3 h-3 text-cyan-400" />
            <span>{demoMode ? 'DEMO: ACTIVE' : 'HW TRACKING'}</span>
          </button>

          <div className="w-[1px] h-4 bg-slate-700 mx-1" />

          {/* Drag Mode (Orbit vs Pan) */}
          <button
            onClick={() => setDragMode((m) => (m === 'orbit' ? 'pan' : 'orbit'))}
            className={`px-2 py-0.5 rounded flex items-center gap-1 ${
              dragMode === 'orbit' ? 'bg-indigo-950 text-indigo-300 border border-indigo-700' : 'bg-amber-950 text-amber-300 border border-amber-700'
            }`}
            title="Switch Drag Interaction"
          >
            <RotateCw className="w-3 h-3" />
            <span>{dragMode.toUpperCase()}</span>
          </button>

          {/* Zoom */}
          <button
            onClick={() => setZoom((z) => Math.min(2.4, z + 0.1))}
            className="p-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700"
            title="Zoom In"
          >
            <ZoomIn className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => setZoom((z) => Math.max(0.6, z - 0.1))}
            className="p-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700"
            title="Zoom Out"
          >
            <ZoomOut className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => switchPerspective(viewPerspective)}
            className="p-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700"
            title="Reset Current Perspective"
          >
            <Maximize2 className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Acrylic & Overlays Toolbar (Top-Right) */}
        <div className="absolute top-3 right-3 z-10 flex items-center gap-2 bg-slate-900/95 backdrop-blur border border-slate-800 p-1.5 rounded shadow-lg text-[11px] font-mono">
          <div className="flex items-center gap-1.5">
            <Eye className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-slate-400 text-[10px]">ACRYLIC:</span>
            <button
              onClick={() => setAcrylicOpacity((o) => (o <= 0.2 ? 0.45 : o <= 0.5 ? 0.85 : 0.15))}
              className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700 hover:border-cyan-600 transition"
              title="Toggle Acrylic Front Panel Opacity"
            >
              {acrylicOpacity <= 0.2 ? 'CLEAR (15%)' : acrylicOpacity <= 0.5 ? 'SEMI (45%)' : 'TINTED (85%)'}
            </button>
          </div>

          <div className="w-[1px] h-4 bg-slate-700" />

          <button
            onClick={() => setShowDimensions((d) => !d)}
            className={`px-2 py-0.5 rounded text-[10px] ${
              showDimensions ? 'bg-cyan-950 text-cyan-300 border border-cyan-800' : 'bg-slate-800 text-slate-500'
            }`}
          >
            DIMENSIONS (CM)
          </button>

          <button
            onClick={() => setShowCallouts((c) => !c)}
            className={`px-2 py-0.5 rounded text-[10px] ${
              showCallouts ? 'bg-cyan-950 text-cyan-300 border border-cyan-800' : 'bg-slate-800 text-slate-500'
            }`}
          >
            LABELS
          </button>
        </div>

        {/* SVG Drawing Canvas */}
        <svg
          viewBox={`0 0 ${svgWidth} ${svgHeight}`}
          className="w-full h-auto cursor-grab active:cursor-grabbing font-mono select-none"
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
        >
          <defs>
            {/* Grid Pattern */}
            <pattern id="planGrid" width="20" height="20" patternUnits="userSpaceOnUse">
              <path d="M 20 0 L 0 0 0 20" fill="none" stroke="#1e293b" strokeWidth="0.4" strokeOpacity="0.35" />
            </pattern>

            {/* Sheet-Metal Galvanized Gradient */}
            <linearGradient id="sheetMetalGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#475569" />
              <stop offset="50%" stopColor="#334155" />
              <stop offset="100%" stopColor="#1e293b" />
            </linearGradient>

            {/* Water Gradients */}
            <linearGradient id="protoWaterGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#0284c7" stopOpacity="0.82" />
              <stop offset="60%" stopColor="#0369a1" stopOpacity="0.88" />
              <stop offset="100%" stopColor="#0c4a6e" stopOpacity="0.95" />
            </linearGradient>

            <linearGradient id="divertWaterGrad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#06b6d4" stopOpacity="0.8" />
              <stop offset="100%" stopColor="#0284c7" stopOpacity="0.85" />
            </linearGradient>

            {/* Radar Beam */}
            <linearGradient id="radarBeamGrad" x1="0%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.55" />
              <stop offset="50%" stopColor="#0284c7" stopOpacity="0.25" />
              <stop offset="100%" stopColor="#22d3ee" stopOpacity="0.05" />
            </linearGradient>

            {/* Acrylic Glass Sheen */}
            <linearGradient id="acrylicGlassGrad" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#38bdf8" stopOpacity={acrylicOpacity * 0.7} />
              <stop offset="50%" stopColor="#e0f2fe" stopOpacity={acrylicOpacity * 0.3} />
              <stop offset="100%" stopColor="#0284c7" stopOpacity={acrylicOpacity * 0.5} />
            </linearGradient>
          </defs>

          {/* Background Grid */}
          <rect x="0" y="0" width={svgWidth} height={svgHeight} fill="url(#planGrid)" />

          {/* Telemetry Status Banners inside Canvas */}
          {demoMode && (
            <g id="demoModeBanner" transform="translate(14, 26)">
              <rect x="0" y="0" width="280" height="22" rx="4" fill="#451a03" fillOpacity="0.85" stroke="#f59e0b" strokeWidth="1" />
              <text x="10" y="15" fill="#fef3c7" fontSize="10" fontWeight="bold" fontFamily="monospace">
                DEMONSTRATION MODE (SYNTHETIC)
              </text>
            </g>
          )}

          {connectionState === 'OFFLINE' && !demoMode && (
            <g id="hardwareOfflineBanner" transform="translate(14, 26)">
              <rect x="0" y="0" width="310" height="22" rx="4" fill="#450a0a" fillOpacity="0.85" stroke="#ef4444" strokeWidth="1" />
              <text x="10" y="15" fill="#fee2e2" fontSize="10" fontWeight="bold" fontFamily="monospace">
                HARDWARE OFFLINE (NO ESP32 CONNECTED)
              </text>
            </g>
          )}

          {/* ========================================================= */}
          {/* 1. SHEET-METAL BED / BASE PLATE (140 cm x 80 cm)          */}
          {/* ========================================================= */}
          <polygon
            points={toPoly([
              [0, 0, 0],
              [TOTAL_WIDTH, 0, 0],
              [TOTAL_WIDTH, 0, TOTAL_LENGTH],
              [0, 0, TOTAL_LENGTH],
            ])}
            fill="url(#sheetMetalGrad)"
            stroke="#64748b"
            strokeWidth="1.8"
          />

          {/* ========================================================= */}
          {/* 2. OUTER SHEET-METAL WALLS (50 cm height)                 */}
          {/* ========================================================= */}
          {/* Rear Wall (X = 80 cm, from Z = 0 to Z = 140 cm) */}
          <polygon
            points={toPoly([
              [TOTAL_WIDTH, 0, 0],
              [TOTAL_WIDTH, WALL_HEIGHT, 0],
              [TOTAL_WIDTH, WALL_HEIGHT, TOTAL_LENGTH],
              [TOTAL_WIDTH, 0, TOTAL_LENGTH],
            ])}
            fill="#334155"
            stroke="#64748b"
            strokeWidth="1.5"
          />

          {/* Left / Downstream End Wall (Z = 0 cm, from X = 0 to 80 cm) */}
          <polygon
            points={toPoly([
              [0, 0, 0],
              [TOTAL_WIDTH, 0, 0],
              [TOTAL_WIDTH, WALL_HEIGHT, 0],
              [0, WALL_HEIGHT, 0],
            ])}
            fill="#1e293b"
            stroke="#475569"
            strokeWidth="1.5"
          />

          {/* Right / Upstream Inlet Wall (Z = 140 cm, from X = 0 to 80 cm) with open inlet flume */}
          <polygon
            points={toPoly([
              [0, 0, TOTAL_LENGTH],
              [TOTAL_WIDTH, 0, TOTAL_LENGTH],
              [TOTAL_WIDTH, WALL_HEIGHT, TOTAL_LENGTH],
              [0, WALL_HEIGHT, TOTAL_LENGTH],
            ])}
            fill="#1e293b"
            stroke="#64748b"
            strokeWidth="1.5"
            fillOpacity="0.4"
          />

          {/* ========================================================= */}
          {/* 3. INTERNAL DIVIDING PANELS & SECTIONS (SKETCH FIDELITY)  */}
          {/* ========================================================= */}
          {/* Section dividing line at Z = 40 cm (Boundary between 40 cm Left and 60 cm Middle) */}
          <line
            x1={project(0, 0, 40)[0]}
            y1={project(0, 0, 40)[1]}
            x2={project(TOTAL_WIDTH, 0, 40)[0]}
            y2={project(TOTAL_WIDTH, 0, 40)[1]}
            stroke="#94a3b8"
            strokeWidth="2.0"
            strokeDasharray="4 2"
          />

          {/* Section dividing line at Z = 100 cm (Boundary between 60 cm Middle and 40 cm Right 'IN') */}
          <line
            x1={project(0, 0, 100)[0]}
            y1={project(0, 0, 100)[1]}
            x2={project(TOTAL_WIDTH, 0, 100)[0]}
            y2={project(TOTAL_WIDTH, 0, 100)[1]}
            stroke="#94a3b8"
            strokeWidth="2.0"
            strokeDasharray="4 2"
          />

          {/* Internal section divider at Z = 70 cm (The marked 30 cm internal partition inside middle section) */}
          <line
            x1={project(0, 0, 70)[0]}
            y1={project(0, 0, 70)[1]}
            x2={project(TOTAL_WIDTH, 0, 70)[0]}
            y2={project(TOTAL_WIDTH, 0, 70)[1]}
            stroke="#38bdf8"
            strokeWidth="2.2"
          />

          {/* Longitudinal Sheet-Metal Divider Partition Wall at X = 38 cm */}
          {/* Separates the Primary Channel (X = 38 to 80 cm) from the Side Diversion Section (X = 0 to 38 cm) */}
          <polygon
            points={toPoly([
              [PARTITION_X, 0, 40],
              [PARTITION_X, WALL_HEIGHT * 0.8, 40],
              [PARTITION_X, WALL_HEIGHT * 0.8, 100],
              [PARTITION_X, 0, 100],
            ])}
            fill="#334155"
            stroke="#94a3b8"
            strokeWidth="2.0"
          />

          {/* ========================================================= */}
          {/* 4. WATER FLOW BODY                                        */}
          {/* ========================================================= */}
          {/* Primary Channel Flow Body (from Z = 140 cm down to Z = 0 cm) */}
          <polygon
            points={toPoly([
              [PARTITION_X, waterDepthCm, 0],
              [TOTAL_WIDTH, waterDepthCm, 0],
              [TOTAL_WIDTH, waterDepthCm, TOTAL_LENGTH],
              [PARTITION_X, waterDepthCm, TOTAL_LENGTH],
            ])}
            fill="url(#protoWaterGrad)"
            stroke="#38bdf8"
            strokeWidth="1.2"
          />

          {/* Inflow from the 40 cm 'IN' region */}
          <polygon
            points={toPoly([
              [0, waterDepthCm * 0.9, 100],
              [PARTITION_X, waterDepthCm * 0.9, 100],
              [PARTITION_X, waterDepthCm * 0.9, TOTAL_LENGTH],
              [0, waterDepthCm * 0.9, TOTAL_LENGTH],
            ])}
            fill="url(#protoWaterGrad)"
            stroke="#38bdf8"
            strokeWidth="1.0"
            opacity="0.85"
          />

          {/* Diverted Water Layer in Side Ditch when Hinged Door Opens */}
          {effectiveDoorAngle > 10 && (
            <polygon
              points={toPoly([
                [0, waterDepthCm * 0.7, 0],
                [PARTITION_X, waterDepthCm * 0.7, 0],
                [PARTITION_X, waterDepthCm * 0.7, 70],
                [0, waterDepthCm * 0.7, 70],
              ])}
              fill="url(#divertWaterGrad)"
              stroke="#22d3ee"
              strokeWidth="1.2"
              opacity="0.9"
            />
          )}

          {/* Blue Flow Arrow along Primary Flow Path (Centerline at X = 60 cm) */}
          {(() => {
            const [p1x, p1y] = project(60, waterDepthCm + 0.8, 120);
            const [p2x, p2y] = project(60, waterDepthCm + 0.8, 20);
            const [alX, alY] = project(66, waterDepthCm + 0.8, 35);
            const [arX, arY] = project(54, waterDepthCm + 0.8, 35);

            return (
              <g>
                <line
                  x1={p1x}
                  y1={p1y}
                  x2={p2x}
                  y2={p2y}
                  stroke="#38bdf8"
                  strokeWidth="12"
                  strokeOpacity="0.4"
                  strokeLinecap="round"
                />
                <line
                  x1={p1x}
                  y1={p1y}
                  x2={p2x}
                  y2={p2y}
                  stroke="#0284c7"
                  strokeWidth="3.5"
                  strokeDasharray="10 5"
                />
                <polygon
                  points={`${p2x},${p2y} ${alX},${alY} ${arX},${arY}`}
                  fill="#38bdf8"
                  stroke="#0284c7"
                  strokeWidth="1.5"
                />
                <text
                  x={(p1x + p2x) / 2}
                  y={(p1y + p2y) / 2 - 10}
                  textAnchor="middle"
                  fill="#f0f9ff"
                  fontSize="12"
                  fontWeight="bold"
                >
                  Flow &rarr;
                </text>
              </g>
            );
          })()}

          {/* ========================================================= */}
          {/* 5. DEBRIS SCREENING & COLLECTION SECTION                  */}
          {/* ========================================================= */}
          {/* Horizontal Debris Collection Grate (400mm x 500mm / 40cm x 50cm) in Side Ditch */}
          <g id="sideDitchDebrisGrate">
            <polygon
              points={toPoly([
                [2, 0.8, 15],
                [PARTITION_X - 2, 0.8, 15],
                [PARTITION_X - 2, 0.8, 65],
                [2, 0.8, 65],
              ])}
              fill="#0f172a"
              fillOpacity="0.85"
              stroke="#f59e0b"
              strokeWidth="2.0"
            />
            {/* Longitudinal grid bars along Z */}
            {[0, 1, 2, 3, 4, 5].map((i) => {
              const xPos = 4 + i * 6;
              const [p1, p2] = [project(xPos, 0.8, 15), project(xPos, 0.8, 65)];
              return (
                <line
                  key={`grate-v-${i}`}
                  x1={p1[0]}
                  y1={p1[1]}
                  x2={p2[0]}
                  y2={p2[1]}
                  stroke="#f59e0b"
                  strokeWidth="1.2"
                  strokeOpacity="0.9"
                />
              );
            })}
            {/* Transverse grid bars across X */}
            {[0, 1, 2, 3, 4, 5, 6, 7].map((j) => {
              const zPos = 17 + j * 6.5;
              const [p1, p2] = [project(2, 0.8, zPos), project(PARTITION_X - 2, 0.8, zPos)];
              return (
                <line
                  key={`grate-h-${j}`}
                  x1={p1[0]}
                  y1={p1[1]}
                  x2={p2[0]}
                  y2={p2[1]}
                  stroke="#f59e0b"
                  strokeWidth="1.2"
                  strokeOpacity="0.9"
                />
              );
            })}
            {showCallouts && (
              (() => {
                // Projection-aware grate callout positioning:
                // In Top View: leader line extends from side ditch (X=20, Z=40) outside acrylic wall to X=-8, Z=40
                // In Iso View: leader line extends forward to X=-8, Y=14, Z=40
                // In Side View: badge is positioned inside the side ditch viewed through transparent acrylic panel at Z=28, Y=22, completely clear of bottom dimensions
                const targetZ = viewPerspective === 'side' ? 28 : 40;
                const [targetX, targetY] = project(PARTITION_X / 2, 0.8, targetZ);
                const [badgeAnchorX, badgeAnchorY] =
                  viewPerspective === 'top'
                    ? project(-8, 0.8, 40)
                    : viewPerspective === 'side'
                    ? project(0, 22, 28)
                    : project(-8, 14, 40);

                return (
                  <g id="grateCalloutBadge">
                    {/* Leader line with anchor dot on grate mesh */}
                    <line
                      x1={targetX}
                      y1={targetY}
                      x2={badgeAnchorX}
                      y2={badgeAnchorY}
                      stroke="#f59e0b"
                      strokeWidth="1.2"
                      strokeDasharray="2 2"
                    />
                    <circle cx={targetX} cy={targetY} r="3" fill="#f59e0b" />
                    <g transform={`translate(${badgeAnchorX - 65}, ${badgeAnchorY - 10})`}>
                      <rect
                        x="0"
                        y="0"
                        width="130"
                        height="20"
                        rx="3"
                        fill="#0f172a"
                        stroke="#f59e0b"
                        strokeWidth="1.2"
                      />
                      <text
                        x="65"
                        y="14"
                        textAnchor="middle"
                        fill="#fde68a"
                        fontSize="9"
                        fontWeight="bold"
                      >
                        Grate (400mm × 500mm)
                      </text>
                    </g>
                  </g>
                );
              })()
            )}
          </g>

          {/* Subsurface mesh screen at Z = 74 cm across the primary channel */}
          <g id="debrisScreenGrid">
            <polygon
              points={toPoly([
                [PARTITION_X + 2, 2, 74],
                [TOTAL_WIDTH - 2, 2, 74],
                [TOTAL_WIDTH - 2, 35, 74],
                [PARTITION_X + 2, 35, 74],
              ])}
              fill="#0f172a"
              fillOpacity="0.75"
              stroke="#f59e0b"
              strokeWidth="2.0"
            />
            {/* Mesh Wires */}
            {[0, 1, 2, 3, 4, 5].map((i) => {
              const xPos = PARTITION_X + 3 + i * 5.8;
              const [p1, p2] = [project(xPos, 2, 74), project(xPos, 35, 74)];
              return <line key={`wire-v-${i}`} x1={p1[0]} y1={p1[1]} x2={p2[0]} y2={p2[1]} stroke="#f59e0b" strokeWidth="1" strokeOpacity="0.85" />;
            })}
            {[0, 1, 2, 3].map((j) => {
              const yPos = 4 + j * 9;
              const [p1, p2] = [project(PARTITION_X + 2, yPos, 74), project(TOTAL_WIDTH - 2, yPos, 74)];
              return <line key={`wire-h-${j}`} x1={p1[0]} y1={p1[1]} x2={p2[0]} y2={p2[1]} stroke="#f59e0b" strokeWidth="1" strokeOpacity="0.85" />;
            })}
          </g>

          {/* ========================================================= */}
          {/* 6. HINGED DIVERSION DOOR (ROTATES AROUND FIXED HINGE PIN) */}
          {/* ========================================================= */}
          <g id="hingedDiversionDoor">
            {/* 6a. Fixed Stationary Hinge Axis Pin at (X = PARTITION_X = 40 cm, Z = 70 cm) */}
            {(() => {
              const [hBotX, hBotY] = project(doorPivotX, 0, doorPivotZ);
              const [hTopX, hTopY] = project(doorPivotX, WALL_HEIGHT * 0.85, doorPivotZ);
              return (
                <g id="fixedHingePin">
                  {/* Stationary Hinge Column */}
                  <line
                    x1={hBotX}
                    y1={hBotY}
                    x2={hTopX}
                    y2={hTopY}
                    stroke="#f59e0b"
                    strokeWidth="6"
                    strokeLinecap="round"
                  />
                  {/* Mechanical Mounting Knuckles */}
                  <circle cx={hBotX} cy={hBotY} r="5" fill="#f59e0b" stroke="#78350f" strokeWidth="1.5" />
                  <circle cx={hTopX} cy={hTopY} r="5" fill="#f59e0b" stroke="#78350f" strokeWidth="1.5" />
                </g>
              );
            })()}

            {/* 6b. Calibrated Protractor Arc on Channel Floor (Bed Y = 0.5 cm) */}
            {viewPerspective === 'top' && (
              <g id="doorProtractorArc">
                {(() => {
                  const r = 18;
                  const steps = [0, 15, 30, 45, 60, 75, 90];
                  const arcPts = steps.map((deg) => {
                    const rad = (deg * Math.PI) / 180;
                    return project(doorPivotX + r * Math.sin(rad), 0.5, doorPivotZ - r * Math.cos(rad));
                  });
                  const pathD = `M ${arcPts.map(([u, v]) => `${u.toFixed(1)},${v.toFixed(1)}`).join(' L ')}`;
                  return (
                    <g>
                      <path d={pathD} fill="none" stroke="#64748b" strokeWidth="1.2" strokeDasharray="2 2" />
                      {steps.filter((s) => s % 30 === 0 || s === 45).map((deg) => {
                        const rad = (deg * Math.PI) / 180;
                        const [p1x, p1y] = project(doorPivotX + (r - 2) * Math.sin(rad), 0.5, doorPivotZ - (r - 2) * Math.cos(rad));
                        const [p2x, p2y] = project(doorPivotX + (r + 2) * Math.sin(rad), 0.5, doorPivotZ - (r + 2) * Math.cos(rad));
                        return <line key={`tick-${deg}`} x1={p1x} y1={p1y} x2={p2x} y2={p2y} stroke="#94a3b8" strokeWidth="1.2" />;
                      })}
                    </g>
                  );
                })()}
              </g>
            )}

            {/* 6c. Rotating Physical Door Leaf (Plate thickness = 1.6 cm, Length = 38 cm) */}
            {/* Top View Plan Projection: 4-corner solid plate with visible thickness */}
            {viewPerspective === 'top' && (
              <polygon
                points={toPoly([
                  [cHinge1[0], 2, cHinge1[1]],
                  [cHinge2[0], 2, cHinge2[1]],
                  [cTip2[0], 2, cTip2[1]],
                  [cTip1[0], 2, cTip1[1]],
                ])}
                fill={effectiveDoorAngle > 15 ? '#0284c7' : '#1e293b'}
                stroke="#38bdf8"
                strokeWidth="2.0"
                className="transition-all duration-150"
              />
            )}

            {/* 3D Isometric Projection: Extruded 3D Door Prism */}
            {viewPerspective === 'iso' && (
              <g id="doorLeafIso">
                {/* Main Lateral Face */}
                <polygon
                  points={toPoly([
                    [cHinge1[0], 2, cHinge1[1]],
                    [cTip1[0], 2, cTip1[1]],
                    [cTip1[0], doorLeafHeight + 2, cTip1[1]],
                    [cHinge1[0], doorLeafHeight + 2, cHinge1[1]],
                  ])}
                  fill={effectiveDoorAngle > 15 ? '#0284c7' : '#1e293b'}
                  stroke="#38bdf8"
                  strokeWidth="2.0"
                />
                {/* Top Edge Face */}
                <polygon
                  points={toPoly([
                    [cHinge1[0], doorLeafHeight + 2, cHinge1[1]],
                    [cHinge2[0], doorLeafHeight + 2, cHinge2[1]],
                    [cTip2[0], doorLeafHeight + 2, cTip2[1]],
                    [cTip1[0], doorLeafHeight + 2, cTip1[1]],
                  ])}
                  fill="#38bdf8"
                  fillOpacity="0.5"
                  stroke="#7dd3fc"
                  strokeWidth="1.5"
                />
                {/* Outer Tip Face */}
                <polygon
                  points={toPoly([
                    [cTip1[0], 2, cTip1[1]],
                    [cTip2[0], 2, cTip2[1]],
                    [cTip2[0], doorLeafHeight + 2, cTip2[1]],
                    [cTip1[0], doorLeafHeight + 2, cTip1[1]],
                  ])}
                  fill="#0369a1"
                  stroke="#38bdf8"
                  strokeWidth="1.5"
                />
              </g>
            )}

            {/* Side View Elevation Projection: Projected Vertical Plate with physical thickness and high contrast */}
            {viewPerspective === 'side' && (() => {
              const allZ = [cHinge1[1], cHinge2[1], cTip1[1], cTip2[1]];
              const minZ = Math.min(...allZ);
              const maxZ = Math.max(...allZ);
              const spanZ = Math.max(doorThickness, maxZ - minZ);
              const midZ = (minZ + maxZ) / 2;
              const zLeft = midZ - spanZ / 2;
              const zRight = midZ + spanZ / 2;

              const [pBottomLeftU, pBottomLeftV] = project(doorPivotX, 2, zLeft);
              const [pBottomRightU, pBottomRightV] = project(doorPivotX, 2, zRight);
              const [pTopRightU, pTopRightV] = project(doorPivotX, doorLeafHeight + 2, zRight);
              const [pTopLeftU, pTopLeftV] = project(doorPivotX, doorLeafHeight + 2, zLeft);

              const isEngaged = effectiveDoorAngle > 15;
              return (
                <g id="sideViewDoorLeaf">
                  {/* Projected solid door plate body */}
                  <polygon
                    points={`${pBottomLeftU.toFixed(1)},${pBottomLeftV.toFixed(1)} ${pBottomRightU.toFixed(1)},${pBottomRightV.toFixed(1)} ${pTopRightU.toFixed(1)},${pTopRightV.toFixed(1)} ${pTopLeftU.toFixed(1)},${pTopLeftV.toFixed(1)}`}
                    fill={isEngaged ? '#0284c7' : '#334155'}
                    fillOpacity="0.9"
                    stroke="#38bdf8"
                    strokeWidth="2.0"
                  />
                  {/* Vertical highlight edge for metallic sheet-metal finish */}
                  <line
                    x1={pTopLeftU}
                    y1={pTopLeftV}
                    x2={pBottomLeftU}
                    y2={pBottomLeftV}
                    stroke="#7dd3fc"
                    strokeWidth="1.5"
                  />
                  <line
                    x1={pTopRightU}
                    y1={pTopRightV}
                    x2={pBottomRightU}
                    y2={pBottomRightV}
                    stroke="#7dd3fc"
                    strokeWidth="1.5"
                  />
                </g>
              );
            })()}

            {/* Door Leaf Stiffener Ribs */}
            {(viewPerspective !== 'side' || effectiveDoorAngle < 75) &&
              [0.33, 0.66].map((frac, idx) => {
                const mx = doorPivotX + (doorTipX - doorPivotX) * frac;
                const mz = doorPivotZ + (doorTipZ - doorPivotZ) * frac;
                const [r1, r2] = [project(mx, 2, mz), project(mx, doorLeafHeight + 2, mz)];
                return (
                  <line
                    key={`door-rib-${idx}`}
                    x1={r1[0]}
                    y1={r1[1]}
                    x2={r2[0]}
                    y2={r2[1]}
                    stroke="#7dd3fc"
                    strokeWidth="1.5"
                  />
                );
              })}

            {/* 6d. Door Angle Digital Readout Badge (Anchored cleanly at downstream partition edge, non-colliding) */}
            {(() => {
              const [pBadgeU, pBadgeV] = project(doorPivotX, 0, 22);
              return (
                <g transform={`translate(${pBadgeU}, ${pBadgeV})`}>
                  <rect
                    x="-46"
                    y="-10"
                    width="92"
                    height="20"
                    rx="3"
                    fill="#0f172a"
                    stroke={effectiveDoorAngle > 5 ? '#f59e0b' : '#38bdf8'}
                    strokeWidth="1.2"
                  />
                  <text
                    x="0"
                    y="4"
                    textAnchor="middle"
                    fill={effectiveDoorAngle > 5 ? '#f59e0b' : '#38bdf8'}
                    fontSize="9"
                    fontWeight="bold"
                  >
                    DOOR: {effectiveDoorAngle.toFixed(0)}°
                  </text>
                </g>
              );
            })()}
          </g>

          {/* ========================================================= */}
          {/* 7. DEBRIS PARTICLES (Simulated Trajectories)              */}
          {/* ========================================================= */}
          <g id="debrisParticles">
            {particles.map((p) => {
              const [px, py] = project(p.x, p.y, p.z);
              return (
                <g key={`particle-${p.id}`} transform={`translate(${px}, ${py})`}>
                  <circle
                    cx="0"
                    cy="0"
                    r={p.size}
                    fill={p.trapped ? '#ef4444' : p.diverted ? '#22d3ee' : p.color}
                    stroke="#0f172a"
                    strokeWidth="0.8"
                  />
                </g>
              );
            })}
          </g>

          {/* ========================================================= */}
          {/* 8. TRANSPARENT ACRYLIC FRONT VIEWING PANEL (Side wall)    */}
          {/* ========================================================= */}
          {viewPerspective !== 'top' && (
            <polygon
              points={toPoly([
                [0, 0, 0],
                [0, WALL_HEIGHT, 0],
                [0, WALL_HEIGHT, TOTAL_LENGTH],
                [0, 0, TOTAL_LENGTH],
              ])}
              fill="url(#acrylicGlassGrad)"
              stroke="#38bdf8"
              strokeWidth="2.2"
              strokeOpacity="0.9"
            />
          )}

          {/* ========================================================= */}
          {/* 9. OVERHEAD RADAR SENSOR & MEASUREMENT BEAM              */}
          {/* ========================================================= */}
          <g id="radarSensorAssembly">
            {/* Conical radar measurement beam hitting water surface */}
            {isWaterLevelAvailable || connectionState === 'SIMULATED' ? (
              <>
                <polygon
                  points={`${radarScreenX},${radarScreenY} ${radarTargetX - 22},${radarTargetY} ${radarTargetX + 22},${radarTargetY}`}
                  fill="url(#radarBeamGrad)"
                  stroke="#38bdf8"
                  strokeWidth="0.8"
                  strokeDasharray="4 2"
                  pointerEvents="none"
                />
                <ellipse
                  cx={radarTargetX}
                  cy={radarTargetY}
                  rx="20"
                  ry="6"
                  fill="none"
                  stroke="#22d3ee"
                  strokeWidth="1.5"
                  className="animate-pulse"
                />
              </>
            ) : (
              /* Standby / Unavailable indicator line (no echo) */
              <line
                x1={radarScreenX}
                y1={radarScreenY}
                x2={radarTargetX}
                y2={radarTargetY}
                stroke="#64748b"
                strokeWidth="1.2"
                strokeDasharray="3 3"
                strokeOpacity="0.6"
              />
            )}

            {/* Radar Sensor Cylinder */}
            <g transform={`translate(${radarScreenX}, ${radarScreenY})`}>
              <rect
                x="-14"
                y="-16"
                width="28"
                height="20"
                rx="3"
                fill="#1e293b"
                stroke="#38bdf8"
                strokeWidth="1.8"
              />
              <circle cx="0" cy="-5" r="3.5" fill="#38bdf8" className="animate-pulse" />
              <rect x="-10" y="4" width="20" height="4" rx="1" fill="#0284c7" />
            </g>

            {showCallouts && (
              (() => {
                // Projection-aware Radar Sensor Callout:
                // Top View: Upstream in open inlet region (X=60, Z=110) clear of door swing zone and IN badge
                // Side View: Dedicated elevation at Z=95, Y=68, completely below top dimension line (Y=86) and separated from DK
                // Iso View: Elevated at X=65, Y=82, Z=85
                const [rBadgeX, rBadgeY] =
                  viewPerspective === 'top'
                    ? project(60, 0, 110)
                    : viewPerspective === 'side'
                    ? project(0, 68, 95)
                    : project(65, 82, 85);

                return (
                  <g id="radarCallout">
                    <line
                      x1={radarScreenX}
                      y1={radarScreenY}
                      x2={rBadgeX}
                      y2={rBadgeY}
                      stroke="#38bdf8"
                      strokeWidth="1.2"
                      strokeDasharray="2 2"
                    />
                    <circle cx={radarScreenX} cy={radarScreenY} r="3" fill="#38bdf8" />
                    <g transform={`translate(${rBadgeX - 55}, ${rBadgeY - 11})`}>
                      <rect
                        x="0"
                        y="0"
                        width="110"
                        height="22"
                        rx="3"
                        fill="#0f172a"
                        stroke="#38bdf8"
                        strokeWidth="1.5"
                      />
                      <text
                        x="55"
                        y="15"
                        textAnchor="middle"
                        fill="#f0f9ff"
                        fontSize="10"
                        fontWeight="bold"
                      >
                        Radar Sensor
                      </text>
                    </g>
                  </g>
                );
              })()
            )}
          </g>

          {/* ========================================================= */}
          {/* 10. DISCHARGEKEEPER ACTUATOR MECHANISM                   */}
          {/* ========================================================= */}
          <g id="dischargeKeeperAssembly">
            {/* Structural Crossbeam over channel at Y = 60 cm */}
            <line
              x1={project(22, 60, 70)[0]}
              y1={project(22, 60, 70)[1]}
              x2={project(58, 60, 70)[0]}
              y2={project(58, 60, 70)[1]}
              stroke="#64748b"
              strokeWidth="3.5"
              strokeLinecap="round"
            />
            {/* Vertical Actuator Drive Linkage down to hinge pin top */}
            <line
              x1={dkScreenX}
              y1={dkScreenY}
              x2={pivotScreenX}
              y2={pivotScreenY - WALL_HEIGHT * 0.8}
              stroke="#f59e0b"
              strokeWidth="3.2"
              strokeLinecap="round"
            />

            {/* Actuator Enclosure Box */}
            <g transform={`translate(${dkScreenX}, ${dkScreenY})`}>
              <rect
                x="-18"
                y="-13"
                width="36"
                height="24"
                rx="3"
                fill="#0f172a"
                stroke="#f59e0b"
                strokeWidth="2.0"
              />
              <circle
                cx="-6"
                cy="-1"
                r="3"
                fill={effectiveDoorAngle > 5 ? '#22d3ee' : '#10b981'}
                className={effectiveDoorAngle > 5 ? 'animate-pulse' : ''}
              />
            </g>

            {showCallouts && (
              (() => {
                // Projection-aware DischargeKeeper Callout:
                // Top View: Offset toward side ditch at X=12, Z=70
                // Side View: Dedicated elevation at Z=45, Y=68, completely below top dimension line (Y=86) and separated from Radar (Z=95)
                // Iso View: Elevated at X=15, Y=82, Z=55
                const [dkBadgeX, dkBadgeY] =
                  viewPerspective === 'top'
                    ? project(12, 0, 70)
                    : viewPerspective === 'side'
                    ? project(0, 68, 45)
                    : project(15, 82, 55);

                return (
                  <g id="dischargeKeeperCallout">
                    <line
                      x1={dkScreenX}
                      y1={dkScreenY}
                      x2={dkBadgeX}
                      y2={dkBadgeY}
                      stroke="#f59e0b"
                      strokeWidth="1.2"
                      strokeDasharray="2 2"
                    />
                    <circle cx={dkScreenX} cy={dkScreenY} r="3" fill="#f59e0b" />
                    <g transform={`translate(${dkBadgeX - 60}, ${dkBadgeY - 11})`}>
                      <rect
                        x="0"
                        y="0"
                        width="120"
                        height="22"
                        rx="3"
                        fill="#0f172a"
                        stroke="#f59e0b"
                        strokeWidth="1.5"
                      />
                      <text
                        x="60"
                        y="15"
                        textAnchor="middle"
                        fill="#fde68a"
                        fontSize="10"
                        fontWeight="bold"
                      >
                        DischargeKeeper
                      </text>
                    </g>
                  </g>
                );
              })()
            )}
          </g>

          {/* ========================================================= */}
          {/* 11. EXACT DRAWING CAD DIMENSIONS & REGION LABELS         */}
          {/* ========================================================= */}
          {showDimensions && (
            <g id="cadDimensionsLayer" className="select-none font-mono">
              {/* Region Label 'IN' (inside clear primary channel inlet flume) */}
              {(() => {
                const inY = viewPerspective === 'side' ? 22 : viewPerspective === 'iso' ? 15 : 0;
                const [inU, inV] = project(60, inY, 125);
                return (
                  <g id="inletRegionLabel" transform={`translate(${inU}, ${inV})`}>
                    <rect
                      x="-22"
                      y="-13"
                      width="44"
                      height="26"
                      rx="3"
                      fill="#0f172a"
                      stroke="#38bdf8"
                      strokeWidth="2.0"
                    />
                    <text
                      x="0"
                      y="5"
                      textAnchor="middle"
                      fill="#38bdf8"
                      fontSize="14"
                      fontWeight="bold"
                      letterSpacing="0.1em"
                    >
                      IN
                    </text>
                  </g>
                );
              })()}

              {/* -------------------------------------------------------- */}
              {/* A. SIDE VIEW CAD DIMENSIONS (viewPerspective === 'side') */}
              {/* -------------------------------------------------------- */}
              {viewPerspective === 'side' ? (
                <g id="sideViewCadDimensions">
                  {/* Vertical Wall Height Dimension: 50 cm */}
                  {(() => {
                    const [h0U, h0V] = project(0, 0, -14);
                    const [h50U, h50V] = project(0, WALL_HEIGHT, -14);
                    const [w0U, w0V] = project(0, 0, 0);
                    const [w50U, w50V] = project(0, WALL_HEIGHT, 0);

                    return (
                      <g>
                        {/* Horizontal witness lines */}
                        <line x1={w0U} y1={w0V} x2={h0U - 4} y2={h0V} stroke="#64748b" strokeWidth="1.0" strokeDasharray="2 2" />
                        <line x1={w50U} y1={w50V} x2={h50U - 4} y2={h50V} stroke="#64748b" strokeWidth="1.0" strokeDasharray="2 2" />
                        {/* Dimension Line */}
                        <line x1={h0U} y1={h0V} x2={h50U} y2={h50V} stroke="#cbd5e1" strokeWidth="1.5" />
                        <line x1={h0U - 6} y1={h0V} x2={h0U + 6} y2={h0V} stroke="#cbd5e1" strokeWidth="1.5" />
                        <line x1={h50U - 6} y1={h50V} x2={h50U + 6} y2={h50V} stroke="#cbd5e1" strokeWidth="1.5" />
                        <text
                          x={h0U - 14}
                          y={(h0V + h50V) / 2 + 4}
                          textAnchor="end"
                          fill="#f8fafc"
                          fontSize="12"
                          fontWeight="bold"
                        >
                          50 cm
                        </text>
                      </g>
                    );
                  })()}

                  {/* Horizontal Overall Length Dimension: 140 cm on its own dedicated dimension line at Bottom */}
                  {(() => {
                    const [l0U, l0V] = project(0, -12, 0);
                    const [l140U, l140V] = project(0, -12, TOTAL_LENGTH);
                    const [w0U, w0V] = project(0, 0, 0);
                    const [w140U, w140V] = project(0, 0, TOTAL_LENGTH);

                    return (
                      <g id="sideOverallLength140cm">
                        {/* Vertical witness lines */}
                        <line x1={w0U} y1={w0V} x2={l0U} y2={l0V + 4} stroke="#64748b" strokeWidth="1.0" strokeDasharray="2 2" />
                        <line x1={w140U} y1={w140V} x2={l140U} y2={l140V + 4} stroke="#64748b" strokeWidth="1.0" strokeDasharray="2 2" />
                        {/* Dimension Line */}
                        <line x1={l0U} y1={l0V} x2={l140U} y2={l140V} stroke="#cbd5e1" strokeWidth="1.5" />
                        <line x1={l0U} y1={l0V - 6} x2={l0U} y2={l0V + 6} stroke="#cbd5e1" strokeWidth="1.5" />
                        <line x1={l140U} y1={l140V - 6} x2={l140U} y2={l140V + 6} stroke="#cbd5e1" strokeWidth="1.5" />
                        <text
                          x={(l0U + l140U) / 2}
                          y={l0V + 18}
                          textAnchor="middle"
                          fill="#f8fafc"
                          fontSize="12"
                          fontWeight="bold"
                        >
                          140 cm (TOTAL LENGTH)
                        </text>
                      </g>
                    );
                  })()}

                  {/* Top Longitudinal Sections: 40 cm | 60 cm | 40 cm elevated well above sensor assemblies at Y = 86 cm */}
                  {(() => {
                    const [p0U, p0V] = project(0, 86, 0);
                    const [p40U, p40V] = project(0, 86, 40);
                    const [p100U, p100V] = project(0, 86, 100);
                    const [p140U, p140V] = project(0, 86, 140);

                    const [w0U, w0V] = project(0, WALL_HEIGHT, 0);
                    const [w40U, w40V] = project(0, WALL_HEIGHT, 40);
                    const [w100U, w100V] = project(0, WALL_HEIGHT, 100);
                    const [w140U, w140V] = project(0, WALL_HEIGHT, 140);

                    return (
                      <g id="sideLongitudinalSections">
                        {/* Vertical witness lines from top rim up to dimension line */}
                        <line x1={w0U} y1={w0V} x2={p0U} y2={p0V} stroke="#64748b" strokeWidth="1.0" strokeDasharray="2 2" />
                        <line x1={w40U} y1={w40V} x2={p40U} y2={p40V} stroke="#64748b" strokeWidth="1.0" strokeDasharray="2 2" />
                        <line x1={w100U} y1={w100V} x2={p100U} y2={p100V} stroke="#64748b" strokeWidth="1.0" strokeDasharray="2 2" />
                        <line x1={w140U} y1={w140V} x2={p140U} y2={p140V} stroke="#64748b" strokeWidth="1.0" strokeDasharray="2 2" />

                        {/* Section 1: Left 40 cm */}
                        <line x1={p0U} y1={p0V} x2={p40U} y2={p40V} stroke="#cbd5e1" strokeWidth="1.5" />
                        <line x1={p0U} y1={p0V - 6} x2={p0U} y2={p0V + 6} stroke="#cbd5e1" strokeWidth="1.5" />
                        <line x1={p40U} y1={p40V - 6} x2={p40U} y2={p40V + 6} stroke="#cbd5e1" strokeWidth="1.5" />
                        <text x={(p0U + p40U) / 2} y={p0V - 10} textAnchor="middle" fill="#f8fafc" fontSize="12" fontWeight="bold">
                          40 cm
                        </text>

                        {/* Section 2: Middle 60 cm (Completely clear of Radar & DischargeKeeper at Y=60-68) */}
                        <line x1={p40U} y1={p40V} x2={p100U} y2={p100V} stroke="#cbd5e1" strokeWidth="1.5" />
                        <line x1={p100U} y1={p100V - 6} x2={p100U} y2={p100V + 6} stroke="#cbd5e1" strokeWidth="1.5" />
                        <text x={(p40U + p100U) / 2} y={p40V - 10} textAnchor="middle" fill="#f8fafc" fontSize="12" fontWeight="bold">
                          60 cm
                        </text>

                        {/* Section 3: Right 40 cm */}
                        <line x1={p100U} y1={p100V} x2={p140U} y2={p140V} stroke="#cbd5e1" strokeWidth="1.5" />
                        <line x1={p140U} y1={p140V - 6} x2={p140U} y2={p140V + 6} stroke="#cbd5e1" strokeWidth="1.5" />
                        <text x={(p100U + p140U) / 2} y={p100V - 10} textAnchor="middle" fill="#f8fafc" fontSize="12" fontWeight="bold">
                          40 cm
                        </text>
                      </g>
                    );
                  })()}

                  {/* Internal Subdivision: 30 cm on separate dimension line at Y = -28 cm (below 140 cm line) */}
                  {(() => {
                    const [b40U, b40V] = project(0, -28, 40);
                    const [b70U, b70V] = project(0, -28, 70);
                    const [w40U, w40V] = project(0, 0, 40);
                    const [w70U, w70V] = project(0, 0, 70);

                    return (
                      <g id="sideInternalSubdivision30cm">
                        {/* Witness lines extending down past the 140 cm dimension line */}
                        <line x1={w40U} y1={w40V} x2={b40U} y2={b40V} stroke="#64748b" strokeWidth="1.0" strokeDasharray="2 2" />
                        <line x1={w70U} y1={w70V} x2={b70U} y2={b70V} stroke="#64748b" strokeWidth="1.0" strokeDasharray="2 2" />
                        <line x1={b40U} y1={b40V} x2={b70U} y2={b70V} stroke="#38bdf8" strokeWidth="1.5" />
                        <line x1={b40U} y1={b40V - 6} x2={b40U} y2={b40V + 6} stroke="#38bdf8" strokeWidth="1.5" />
                        <line x1={b70U} y1={b70V - 6} x2={b70U} y2={b70V + 6} stroke="#38bdf8" strokeWidth="1.5" />
                        <text x={(b40U + b70U) / 2} y={b40V + 18} textAnchor="middle" fill="#38bdf8" fontSize="12" fontWeight="bold">
                          30 cm
                        </text>
                      </g>
                    );
                  })()}
                </g>
              ) : (
                /* -------------------------------------------------------- */
                /* B. TOP & ISO VIEW CAD DIMENSIONS                         */
                /* -------------------------------------------------------- */
                <g id="planIsoCadDimensions">
                  {/* Top Longitudinal Dimensions: 40 cm | 60 cm | 40 cm */}
                  {(() => {
                    const [p0U, p0V] = project(-14, 0, 0);
                    const [p40U, p40V] = project(-14, 0, 40);
                    const [p100U, p100V] = project(-14, 0, 100);
                    const [p140U, p140V] = project(-14, 0, 140);

                    const [b0U, b0V] = project(0, 0, 0);
                    const [b40U, b40V] = project(0, 0, 40);
                    const [b100U, b100V] = project(0, 0, 100);
                    const [b140U, b140V] = project(0, 0, 140);

                    return (
                      <g>
                        {/* Witness lines connecting physical vertices to dimension line */}
                        <line x1={b0U} y1={b0V} x2={p0U} y2={p0V} stroke="#64748b" strokeWidth="1.0" strokeDasharray="2 2" />
                        <line x1={b40U} y1={b40V} x2={p40U} y2={p40V} stroke="#64748b" strokeWidth="1.0" strokeDasharray="2 2" />
                        <line x1={b100U} y1={b100V} x2={p100U} y2={p100V} stroke="#64748b" strokeWidth="1.0" strokeDasharray="2 2" />
                        <line x1={b140U} y1={b140V} x2={p140U} y2={p140V} stroke="#64748b" strokeWidth="1.0" strokeDasharray="2 2" />

                        {/* Left 40 cm */}
                        <line x1={p0U} y1={p0V} x2={p40U} y2={p40V} stroke="#cbd5e1" strokeWidth="1.5" />
                        <line x1={p0U} y1={p0V - 6} x2={p0U} y2={p0V + 6} stroke="#cbd5e1" strokeWidth="1.5" />
                        <line x1={p40U} y1={p40V - 6} x2={p40U} y2={p40V + 6} stroke="#cbd5e1" strokeWidth="1.5" />
                        <text x={(p0U + p40U) / 2} y={(p0V + p40V) / 2 - 10} textAnchor="middle" fill="#f8fafc" fontSize="12" fontWeight="bold">
                          40 cm
                        </text>

                        {/* Middle 60 cm */}
                        <line x1={p40U} y1={p40V} x2={p100U} y2={p100V} stroke="#cbd5e1" strokeWidth="1.5" />
                        <line x1={p100U} y1={p100V - 6} x2={p100U} y2={p100V + 6} stroke="#cbd5e1" strokeWidth="1.5" />
                        <text x={(p40U + p100U) / 2} y={(p40V + p100V) / 2 - 10} textAnchor="middle" fill="#f8fafc" fontSize="12" fontWeight="bold">
                          60 cm
                        </text>

                        {/* Right 40 cm (Above IN region) */}
                        <line x1={p100U} y1={p100V} x2={p140U} y2={p140V} stroke="#cbd5e1" strokeWidth="1.5" />
                        <line x1={p140U} y1={p140V - 6} x2={p140U} y2={p140V + 6} stroke="#cbd5e1" strokeWidth="1.5" />
                        <text x={(p100U + p140U) / 2} y={(p100V + p140V) / 2 - 10} textAnchor="middle" fill="#f8fafc" fontSize="12" fontWeight="bold">
                          40 cm
                        </text>
                      </g>
                    );
                  })()}

                  {/* Internal Subdivision: 30 cm attached to physical boundary (Z=40) and hinge divider (Z=70) */}
                  {(() => {
                    const [b40U, b40V] = project(TOTAL_WIDTH + 14, 0, 40);
                    const [b70U, b70V] = project(TOTAL_WIDTH + 14, 0, 70);
                    const [w40U, w40V] = project(TOTAL_WIDTH, 0, 40);
                    const [w70U, w70V] = project(TOTAL_WIDTH, 0, 70);

                    return (
                      <g id="internalSubdivision30cm">
                        {/* Witness lines originating from exact physical endpoints */}
                        <line x1={w40U} y1={w40V} x2={b40U} y2={b40V} stroke="#64748b" strokeWidth="1.0" strokeDasharray="2 2" />
                        <line x1={w70U} y1={w70V} x2={b70U} y2={b70V} stroke="#64748b" strokeWidth="1.0" strokeDasharray="2 2" />

                        <line x1={b40U} y1={b40V} x2={b70U} y2={b70V} stroke="#38bdf8" strokeWidth="1.5" />
                        <line x1={b40U} y1={b40V - 6} x2={b40U} y2={b40V + 6} stroke="#38bdf8" strokeWidth="1.5" />
                        <line x1={b70U} y1={b70V - 6} x2={b70U} y2={b70V + 6} stroke="#38bdf8" strokeWidth="1.5" />
                        <text x={(b40U + b70U) / 2} y={(b40V + b70V) / 2 + 18} textAnchor="middle" fill="#38bdf8" fontSize="12" fontWeight="bold">
                          30 cm
                        </text>
                      </g>
                    );
                  })()}

                  {/* Transverse Width Dimensions: 80 cm on Left, 80 cm on Right, and 40 cm | 40 cm split */}
                  {(() => {
                    // Left 80 cm (Z = 0)
                    const [l0U, l0V] = project(0, 0, -14);
                    const [l80U, l80V] = project(TOTAL_WIDTH, 0, -14);
                    const [w0U, w0V] = project(0, 0, 0);
                    const [w80U, w80V] = project(TOTAL_WIDTH, 0, 0);

                    // Right 80 cm (Z = 140)
                    const [r0U, r0V] = project(0, 0, TOTAL_LENGTH + 14);
                    const [r40U, r40V] = project(PARTITION_X, 0, TOTAL_LENGTH + 14);
                    const [r80U, r80V] = project(TOTAL_WIDTH, 0, TOTAL_LENGTH + 14);
                    const [wr0U, wr0V] = project(0, 0, TOTAL_LENGTH);
                    const [wr40U, wr40V] = project(PARTITION_X, 0, TOTAL_LENGTH);
                    const [wr80U, wr80V] = project(TOTAL_WIDTH, 0, TOTAL_LENGTH);

                    return (
                      <g id="transverseDimensions">
                        {/* Left 80 cm witness lines */}
                        <line x1={w0U} y1={w0V} x2={l0U} y2={l0V} stroke="#64748b" strokeWidth="1.0" strokeDasharray="2 2" />
                        <line x1={w80U} y1={w80V} x2={l80U} y2={l80V} stroke="#64748b" strokeWidth="1.0" strokeDasharray="2 2" />
                        {/* Left 80 cm */}
                        <line x1={l0U} y1={l0V} x2={l80U} y2={l80V} stroke="#cbd5e1" strokeWidth="1.5" />
                        <line x1={l0U - 6} y1={l0V} x2={l0U + 6} y2={l0V} stroke="#cbd5e1" strokeWidth="1.5" />
                        <line x1={l80U - 6} y1={l80V} x2={l80U + 6} y2={l80V} stroke="#cbd5e1" strokeWidth="1.5" />
                        <text x={(l0U + l80U) / 2 - 16} y={(l0V + l80V) / 2 + 4} textAnchor="end" fill="#f8fafc" fontSize="12" fontWeight="bold">
                          80 cm
                        </text>

                        {/* Right 80 cm witness lines */}
                        <line x1={wr0U} y1={wr0V} x2={r0U} y2={r0V} stroke="#64748b" strokeWidth="1.0" strokeDasharray="2 2" />
                        <line x1={wr40U} y1={wr40V} x2={r40U} y2={r40V} stroke="#64748b" strokeWidth="1.0" strokeDasharray="2 2" />
                        <line x1={wr80U} y1={wr80V} x2={r80U} y2={r80V} stroke="#64748b" strokeWidth="1.0" strokeDasharray="2 2" />
                        {/* Right 80 cm overall line */}
                        <line x1={r0U} y1={r0V} x2={r80U} y2={r80V} stroke="#cbd5e1" strokeWidth="1.5" />
                        <line x1={r0U - 6} y1={r0V} x2={r0U + 6} y2={r0V} stroke="#cbd5e1" strokeWidth="1.5" />
                        <line x1={r40U - 4} y1={r40V} x2={r40U + 4} y2={r40V} stroke="#38bdf8" strokeWidth="1.5" />
                        <line x1={r80U - 6} y1={r80V} x2={r80U + 6} y2={r80V} stroke="#cbd5e1" strokeWidth="1.5" />
                        <text x={(r0U + r80U) / 2 + 16} y={(r0V + r80V) / 2 + 4} textAnchor="start" fill="#f8fafc" fontSize="12" fontWeight="bold">
                          80 cm
                        </text>
                      </g>
                    );
                  })()}
                </g>
              )}
            </g>
          )}
        </svg>

        {/* Real-time Telemetry & Sensor Readout Overlay (Bottom-Left) */}
        <div className="absolute bottom-3 left-3 z-10 bg-slate-950/85 backdrop-blur border border-slate-800 p-3 rounded-lg shadow-xl font-mono text-xs max-w-md">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2 mb-2">
            <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider flex items-center gap-1.5">
              <Zap className="w-3.5 h-3.5 text-cyan-400" />
              PHYSICAL DIGITAL TWIN TELEMETRY
            </span>
            <span
              data-testid="telemetry-badge-overlay"
              className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase ${
                connectionState === 'LIVE'
                  ? 'bg-emerald-950 text-emerald-300 border border-emerald-700'
                  : connectionState === 'SIMULATED'
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                  : connectionState === 'STALE'
                  ? 'bg-amber-950 text-amber-300 border border-amber-800'
                  : connectionState === 'FAULT'
                  ? 'bg-rose-950 text-rose-300 border border-rose-800'
                  : 'bg-slate-800 text-slate-400 border border-slate-700'
              }`}
            >
              {connectionState}
            </span>
          </div>

          <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-[11px]">
            <div>
              <span className="text-slate-400 block text-[9px] uppercase">
                RADAR WATER LEVEL [{radarTelemetry.source}]
              </span>
              {radarTelemetry.value !== null ? (
                <>
                  <span className="text-sm font-bold text-cyan-300">
                    {radarTelemetry.value.toFixed(1)} cm
                  </span>
                  <span className="text-[9px] text-slate-400 block">
                    {(radarTelemetry.value / 100).toFixed(3)} m depth
                  </span>
                </>
              ) : (
                <span className="text-xs font-bold text-slate-500 block">
                  UNAVAILABLE
                </span>
              )}
              {radarTelemetry.timestamp && (
                <span className="text-[8px] text-slate-500 block truncate">
                  T: {new Date(radarTelemetry.timestamp).toLocaleTimeString()}
                </span>
              )}
            </div>

            <div>
              <span className="text-slate-400 block text-[9px] uppercase">
                FLOW SENSOR [{flowTelemetry.source}]
              </span>
              {flowTelemetry.flowRate !== null ? (
                <>
                  <span className="text-sm font-bold text-cyan-300">
                    {flowTelemetry.formattedFlow}
                  </span>
                  {flowTelemetry.cumulativeVolumeLiters !== null && (
                    <span className="text-[9px] text-slate-400 block">
                      Vol: {flowTelemetry.cumulativeVolumeLiters.toFixed(1)} L
                    </span>
                  )}
                </>
              ) : (
                <span className="text-xs font-bold text-slate-500 block">
                  UNAVAILABLE
                </span>
              )}
              {flowTelemetry.timestamp && (
                <span className="text-[8px] text-slate-500 block truncate">
                  T: {new Date(flowTelemetry.timestamp).toLocaleTimeString()}
                </span>
              )}
            </div>

            <div>
              <span className="text-slate-400 block text-[9px] uppercase">HINGED DOOR ANGLE</span>
              <div className="flex items-baseline gap-1.5">
                <span className={`text-sm font-bold ${commandedDoorAngle > 5 ? 'text-amber-400' : 'text-slate-200'}`}>
                  {commandedDoorAngle.toFixed(1)}°
                </span>
                <span className="text-[9px] text-amber-500/80 font-semibold">(CMD)</span>
              </div>
              <span className="text-[9px] text-slate-400 block">
                ACTUAL: {actualDoorAngle !== null ? `${actualDoorAngle.toFixed(1)}°` : 'NOT MEASURED (NO SENSOR)'}
              </span>
              <span className="text-[9px] text-slate-500 block">
                {effectiveDoorAngle > 70 ? 'DIVERTING' : effectiveDoorAngle > 5 ? 'TRANSIT' : 'CLOSED (FLUSH)'}
              </span>
            </div>

            <div>
              <span className="text-slate-400 block text-[9px] uppercase">ACTUATOR STATUS</span>
              <span className="text-xs font-bold text-slate-200 block truncate">
                DischargeKeeper: {simState === 'DIVERSION_OPENING' || simState === 'DEBRIS_DIVERSION' ? 'ENGAGED' : 'STANDBY'}
              </span>
              <span className="text-[9px] text-slate-400 block">
                {connectionState === 'LIVE' ? 'HW: Connected' : demoMode ? 'Mode: Demonstration' : 'HW: Disconnected'}
              </span>
              <span className="text-[9px] text-slate-400 block">
                {effectiveDoorAngle > 0 ? 'Torque Commanded' : 'Zero Load'}
              </span>
            </div>

            <div className="col-span-2 pt-1 border-t border-slate-900 flex items-center justify-between">
              <div>
                <span className="text-slate-400 text-[9px] uppercase mr-2">SCREEN OCCLUSION (β):</span>
                <span
                  className={`text-xs font-bold ${
                    simBlockagePct > 45 ? 'text-rose-400' : simBlockagePct > 20 ? 'text-amber-400' : 'text-emerald-400'
                  }`}
                >
                  {simBlockagePct.toFixed(0)}%
                </span>
              </div>
              {lastSeenTimestamp && (
                <span className="text-[9px] text-slate-500 font-mono">
                  LAST SEEN: {new Date(lastSeenTimestamp).toLocaleTimeString()}
                </span>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Interactive Simulation Controls Panel */}
      <div className="mt-4 p-3.5 bg-slate-950/70 border border-slate-800 rounded font-mono text-xs">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => setIsSimPaused((p) => !p)}
              className={`px-3 py-1.5 rounded flex items-center gap-1.5 font-bold transition ${
                isSimPaused
                  ? 'bg-emerald-950 text-emerald-300 border border-emerald-700 hover:bg-emerald-900'
                  : 'bg-amber-950 text-amber-300 border border-amber-700 hover:bg-amber-900'
              }`}
            >
              {isSimPaused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
              <span>{isSimPaused ? 'RESUME SIM' : 'PAUSE SIM'}</span>
            </button>

            <button
              onClick={() => {
                setSimState('BLOCKAGE_DETECTED');
                setSimBlockagePct(55);
                setSimWaterDepth((prev) => Math.max(11.5, prev + 2.0));
              }}
              className="px-3.5 py-1.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-700 font-bold hover:bg-cyan-900 transition flex items-center gap-1.5 shadow-sm"
              title="Immediately initiate debris accumulation and hinged door diversion sequence"
            >
              <Zap className="w-3.5 h-3.5 text-cyan-400" />
              <span>TRIGGER DIVERSION EVENT</span>
            </button>

            <button
              onClick={() => {
                setSimState('NORMAL_FLOW');
                setSimDoorAngle(0);
                setSimBlockagePct(0);
                setSimWaterDepth(upstreamDepth || 6.2);
                setParticles(initParticles(28));
              }}
              className="px-3 py-1.5 rounded bg-slate-800 text-slate-300 border border-slate-700 hover:bg-slate-700 transition flex items-center gap-1.5"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>RESET SIMULATION</span>
            </button>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-1.5">
              <span className="text-slate-400 text-[11px]">RATE:</span>
              <div className="flex rounded border border-slate-700 overflow-hidden text-[10px]">
                {(['low', 'med', 'high'] as const).map((rate) => (
                  <button
                    key={rate}
                    onClick={() => setAccumulationRate(rate)}
                    className={`px-2 py-0.5 uppercase ${
                      accumulationRate === rate
                        ? 'bg-cyan-900 text-cyan-200 font-bold'
                        : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {rate}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex items-center gap-1.5">
              <span className="text-slate-400 text-[11px]">SPEED:</span>
              <div className="flex rounded border border-slate-700 overflow-hidden text-[10px]">
                {[0.5, 1.0, 2.0].map((s) => (
                  <button
                    key={s}
                    onClick={() => setSimSpeed(s)}
                    className={`px-2 py-0.5 ${
                      simSpeed === s
                        ? 'bg-cyan-900 text-cyan-200 font-bold'
                        : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    SIM {s}×
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Manual Sliders when Paused */}
        {isSimPaused && (
          <div className="mt-3 pt-3 border-t border-slate-800 grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
            <div>
              <div className="flex justify-between text-[11px] mb-1">
                <span className="text-slate-400">MANUAL HINGED DOOR ROTATION:</span>
                <span className="text-cyan-300 font-bold">{simDoorAngle.toFixed(0)}°</span>
              </div>
              <input
                type="range"
                min="0"
                max="90"
                step="1"
                value={simDoorAngle}
                onChange={(e) => setSimDoorAngle(parseFloat(e.target.value))}
                className="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-cyan-400"
              />
            </div>

            <div>
              <div className="flex justify-between text-[11px] mb-1">
                <span className="text-slate-400">MANUAL WATER LEVEL:</span>
                <span className="text-cyan-300 font-bold">{simWaterDepth.toFixed(1)} cm</span>
              </div>
              <input
                type="range"
                min="2"
                max="45"
                step="0.1"
                value={simWaterDepth}
                onChange={(e) => setSimWaterDepth(parseFloat(e.target.value))}
                className="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-cyan-400"
              />
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

// Particle generation helper inside sheet-metal prototype coordinates (cm)
function initParticles(count: number): DebrisParticle[] {
  const colors = ['#78350f', '#92400e', '#b45309', '#451a03', '#1e3a5f'];
  const particles: DebrisParticle[] = [];

  for (let i = 0; i < count; i++) {
    particles.push({
      id: i,
      x: 45 + Math.random() * 28, // inside primary channel (X = 38 to 80 cm)
      y: 5 + Math.random() * 10,
      z: 10 + (i / count) * 125, // along longitudinal length (0 to 140 cm)
      vx: (Math.random() - 0.5) * 0.2,
      vy: 0,
      vz: -1.8,
      size: 2.5 + Math.random() * 3.5,
      color: colors[i % colors.length],
      diverted: false,
      trapped: false,
    });
  }

  return particles;
}
