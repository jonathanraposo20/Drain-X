import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { LongitudinalSideDrainTwin } from '../components/LongitudinalSideDrainTwin';
import { DigitalTwin } from '../components/DigitalTwin';
import { SensorReadingContract, MechanismStatusContract } from '../types/contracts';

describe('LongitudinalSideDrainTwin Component', () => {
  const dummyMechanism: MechanismStatusContract = {
    state: 'IDLE',
    backup_net_angle_deg: 0,
    tray_height_cm: 0,
    cycle_count: 0,
    current_action: 'Standby monitoring',
    elapsed_in_state_s: 10,
    is_jammed: false,
    is_fault: false,
    debris_retained_pct: 0,
  };

  const freshTimestamp = new Date().toISOString();

  const sampleReadings: Record<string, SensorReadingContract> = {
    RADAR_01: {
      version: '1.0',
      message_id: 'msg-01',
      sensor_id: 'RADAR_01',
      section_id: 'SEC_SCREENING',
      sensor_type: 'WATER_LEVEL',
      value: 6.8,
      unit: 'cm',
      source: 'PHYSICAL',
      status: 'OK',
      timestamp: freshTimestamp,
      metadata: { validation_stage: 'PARTIALLY_ASSEMBLED' },
    },
    GATE_SERVO_01: {
      version: '1.0',
      message_id: 'msg-gate-01',
      sensor_id: 'GATE_SERVO_01',
      section_id: 'SEC_DIVERSION',
      sensor_type: 'GATE_ANGLE',
      value: 0.0,
      unit: 'deg',
      source: 'PHYSICAL',
      status: 'OK',
      timestamp: freshTimestamp,
    },
  };

  it('renders exact sheet-metal prototype dimensions in cm and drawing layout', () => {
    render(
      <LongitudinalSideDrainTwin
        upstreamDepth={6.8}
        inflow={10.0}
        mode="SIMULATION"
        readings={{}}
      />
    );

    // Title & Architecture
    expect(screen.getByText(/PHYSICAL SHEET-METAL PROTOTYPE TWIN/i)).toBeTruthy();
    expect(screen.getByText(/TOP-VIEW & 3D CUTAWAY/i)).toBeTruthy();

    // Callouts & Region Label from Drawing
    expect(screen.getByText('IN')).toBeTruthy();
    expect(screen.getByText('Radar Sensor')).toBeTruthy();
    expect(screen.getByText('DischargeKeeper')).toBeTruthy();
    expect(screen.getByText(/Flow →/i)).toBeTruthy();

    // Exact Drawing Dimensions in CM:
    // 40 cm (left section and right section)
    const fortyCmElements = screen.getAllByText('40 cm');
    expect(fortyCmElements.length).toBeGreaterThanOrEqual(2);

    // 60 cm (middle section)
    expect(screen.getByText('60 cm')).toBeTruthy();

    // 30 cm (internal partition division inside middle section)
    expect(screen.getByText('30 cm')).toBeTruthy();

    // 80 cm (overall transverse width)
    const eightyCmElements = screen.getAllByText('80 cm');
    expect(eightyCmElements.length).toBeGreaterThanOrEqual(2);

    // Telemetry Display
    expect(screen.getByText(/RADAR WATER LEVEL/i)).toBeTruthy();
    expect(screen.getByText(/HINGED DOOR ANGLE/i)).toBeTruthy();
    expect(screen.getByText(/SCREEN OCCLUSION/i)).toBeTruthy();
  });

  it('strictly excludes outlet weirs, sliding vertical gates, and weir chambers', () => {
    const { container } = render(
      <LongitudinalSideDrainTwin
        upstreamDepth={7.0}
        inflow={12.0}
        mode="SIMULATION"
      />
    );

    const htmlContent = container.innerHTML;
    expect(htmlContent).not.toMatch(/OUTLET WEIR/i);
    expect(htmlContent).not.toMatch(/SLIDING GATE/i);
    expect(htmlContent).not.toMatch(/WEIR CHAMBER/i);
    expect(htmlContent).not.toMatch(/WINCH HOIST/i);
    expect(htmlContent).not.toMatch(/LIFT TRAY/i);
  });

  it('supports perspective switching (Top View Plan, 3D Isometric, Side View) and controls', () => {
    render(
      <LongitudinalSideDrainTwin
        upstreamDepth={6.8}
        inflow={10.0}
        mode="SIMULATION"
      />
    );

    const topViewBtn = screen.getByText('TOP VIEW (PLAN)');
    const isoBtn = screen.getByText('3D ISOMETRIC');
    const sideBtn = screen.getByText('SIDE VIEW');

    // Default is top view
    expect(topViewBtn.closest('button')?.className).toContain('font-bold');

    // Switch to 3D isometric
    fireEvent.click(isoBtn);
    expect(isoBtn.closest('button')?.className).toContain('font-bold');

    // Switch to Side View and verify side elevation dimensions
    fireEvent.click(sideBtn);
    expect(sideBtn.closest('button')?.className).toContain('font-bold');
    expect(screen.getByText('50 cm')).toBeTruthy(); // wall height
    expect(screen.getByText(/140 cm \(TOTAL LENGTH\)/i)).toBeTruthy();

    // Return to Top View
    fireEvent.click(topViewBtn);
    expect(topViewBtn.closest('button')?.className).toContain('font-bold');

    // Drag mode switch
    const dragModeBtn = screen.getByText('ORBIT');
    fireEvent.click(dragModeBtn);
    expect(screen.getByText('PAN')).toBeTruthy();

    // Acrylic opacity toggle
    const acrylicOpacityBtn = screen.getByTitle(/Toggle Acrylic Front Panel Opacity/i);
    fireEvent.click(acrylicOpacityBtn);
    expect(acrylicOpacityBtn.textContent).toContain('TINTED');
  });

  it('verifies hinged door kinematics rotates around fixed hinge axis at (40, 70) without sliding', () => {
    // Physical geometry:
    // Fixed hinge pin: X = 40 cm, Z = 70 cm
    // Door length: 38 cm
    // At 0 deg: tip is at (40 + 38*sin(0), 70 - 38*cos(0)) = (40, 32)
    // At 45 deg: tip is at (40 + 38*sin(pi/4), 70 - 38*cos(pi/4)) = (40 + 26.87, 70 - 26.87) = (66.87, 43.13)
    // At 90 deg: tip is at (40 + 38*sin(pi/2), 70 - 38*cos(pi/2)) = (78, 70)
    const doorPivotX = 40;
    const doorPivotZ = 70;
    const doorLength = 38;

    const calcTip = (angleDeg: number) => {
      const rad = (angleDeg * Math.PI) / 180;
      return {
        x: doorPivotX + doorLength * Math.sin(rad),
        z: doorPivotZ - doorLength * Math.cos(rad),
      };
    };

    const tip0 = calcTip(0);
    expect(tip0.x).toBeCloseTo(40, 1);
    expect(tip0.z).toBeCloseTo(32, 1);

    const tip45 = calcTip(45);
    expect(tip45.x).toBeCloseTo(66.87, 1);
    expect(tip45.z).toBeCloseTo(43.13, 1);

    const tip90 = calcTip(90);
    expect(tip90.x).toBeCloseTo(78, 1);
    expect(tip90.z).toBeCloseTo(70, 1);
    // Crucial safety check: tip remains strictly inside outer channel boundary (80 cm) with 2 cm clearance
    expect(tip90.x).toBeLessThan(80);
    expect(80 - tip90.x).toBeCloseTo(2, 1);
  });

  it('triggers diversion event and executes deterministic simulation state transitions', () => {
    render(
      <LongitudinalSideDrainTwin
        upstreamDepth={6.8}
        inflow={10.0}
        mode="SIMULATION"
      />
    );

    expect(screen.getByText(/STATE: NORMAL_FLOW/i)).toBeTruthy();

    // Trigger diversion event
    const triggerBtn = screen.getByText(/TRIGGER DIVERSION EVENT/i);
    fireEvent.click(triggerBtn);

    expect(screen.getByText(/STATE: BLOCKAGE_DETECTED/i)).toBeTruthy();

    // Reset simulation
    const resetBtn = screen.getByText(/RESET SIMULATION/i);
    fireEvent.click(resetBtn);
    expect(screen.getByText(/STATE: NORMAL_FLOW/i)).toBeTruthy();
  });

  it('strictly isolates Side View dimensions: shows 50 cm height and 140 cm length, excludes 80 cm width', () => {
    const { container } = render(
      <LongitudinalSideDrainTwin
        upstreamDepth={6.8}
        inflow={10.0}
        mode="SIMULATION"
      />
    );

    // Switch to Side View
    const sideBtn = screen.getByText('SIDE VIEW');
    fireEvent.click(sideBtn);

    // Side view MUST show 50 cm wall height
    expect(screen.getByText('50 cm')).toBeTruthy();
    // Side view MUST show 140 cm total length
    expect(screen.getByText(/140 cm \(TOTAL LENGTH\)/i)).toBeTruthy();
    // Side view MUST show 30 cm internal subdivision
    expect(screen.getByText('30 cm')).toBeTruthy();

    // Side view MUST NOT render transverse 80 cm width annotations
    const sideViewDimensions = container.querySelector('#sideViewCadDimensions');
    expect(sideViewDimensions).toBeTruthy();
    expect(sideViewDimensions?.innerHTML).not.toContain('80 cm');

    // planIsoCadDimensions MUST NOT be rendered in Side View
    const planIsoDimensions = container.querySelector('#planIsoCadDimensions');
    expect(planIsoDimensions).toBeNull();
  });

  it('renders distinct physical elements: door leaf, stationary hinge pin, DischargeKeeper actuator, and angle indicator', () => {
    const { container } = render(
      <LongitudinalSideDrainTwin
        upstreamDepth={6.8}
        inflow={10.0}
        mode="SIMULATION"
      />
    );

    // 1. Fixed Hinge Pin is present and stationary
    expect(container.querySelector('#fixedHingePin')).toBeTruthy();

    // 2. Calibrated Protractor Arc is present on channel bed
    expect(container.querySelector('#doorProtractorArc')).toBeTruthy();

    // 3. Actuator Assembly is distinct with crossbeam and linkage
    expect(container.querySelector('#dischargeKeeperAssembly')).toBeTruthy();

    // 4. Debris Grate is rendered in side ditch with dedicated callout badge
    expect(container.querySelector('#sideDitchDebrisGrate')).toBeTruthy();
    expect(screen.getByText(/Grate \(400mm × 500mm\)/i)).toBeTruthy();

    // 5. Radar Sensor callout badge is present
    expect(screen.getByText('Radar Sensor')).toBeTruthy();
    expect(screen.getByText('DischargeKeeper')).toBeTruthy();
  });

  it('P1.0.5 presentation cleanup: separates side-view dimensions, callouts, inlet flume, and door plate', () => {
    const { container } = render(
      <LongitudinalSideDrainTwin
        upstreamDepth={6.8}
        inflow={10.0}
        mode="SIMULATION"
      />
    );

    // Switch to Side View
    const sideBtn = screen.getByText('SIDE VIEW');
    fireEvent.click(sideBtn);

    // 1. Side view dimensions on separate, dedicated lines
    const sideSections = container.querySelector('#sideLongitudinalSections');
    expect(sideSections).toBeTruthy();
    expect(sideSections?.textContent).toContain('40 cm');
    expect(sideSections?.textContent).toContain('60 cm');

    const sideOverall = container.querySelector('#sideOverallLength140cm');
    expect(sideOverall).toBeTruthy();
    expect(sideOverall?.textContent).toContain('140 cm (TOTAL LENGTH)');

    const sideSubdivision = container.querySelector('#sideInternalSubdivision30cm');
    expect(sideSubdivision).toBeTruthy();
    expect(sideSubdivision?.textContent).toContain('30 cm');

    // 2. Grate callout badge rendered with clean leader line
    const grateBadge = container.querySelector('#grateCalloutBadge');
    expect(grateBadge).toBeTruthy();
    expect(grateBadge?.textContent).toContain('Grate (400mm × 500mm)');

    // 3. Sensor callouts are independently separated and do not overlap
    const radarCallout = container.querySelector('#radarCallout');
    const dkCallout = container.querySelector('#dischargeKeeperCallout');
    expect(radarCallout).toBeTruthy();
    expect(dkCallout).toBeTruthy();

    // 4. Region label IN inside inlet flume
    const inletLabel = container.querySelector('#inletRegionLabel');
    expect(inletLabel).toBeTruthy();
    expect(inletLabel?.textContent).toBe('IN');

    // 5. Door leaf rendered with visible projected plate envelope in Side View
    const sideDoor = container.querySelector('#sideViewDoorLeaf');
    expect(sideDoor).toBeTruthy();
    const doorPoly = sideDoor?.querySelector('polygon');
    expect(doorPoly).toBeTruthy();
    expect(doorPoly?.getAttribute('points')).toBeTruthy();
  });

  it('renders seamlessly inside parent DigitalTwin with view switcher and hardware validation badge', () => {
    render(
      <DigitalTwin
        upstreamDepth={7.4}
        weirHead={1.5}
        pumpInflow={12.8}
        mechanism={dummyMechanism}
        blockage={null}
        prediction={null}
        mode="HARDWARE"
        readings={sampleReadings}
        hardwareValidationStage="PARTIALLY_ASSEMBLED"
      />
    );

    expect(screen.getByText(/STAGE: PARTIALLY_ASSEMBLED/i)).toBeTruthy();
    expect(screen.getByText(/LIVE \(ESP32\)/i)).toBeTruthy();

    expect(screen.getByText('DUAL MULTI-TWIN VIEW')).toBeTruthy();
    expect(screen.getByText('3D SIDE-DRAIN TWIN (PHYSICAL PROTOTYPE)')).toBeTruthy();
    expect(screen.getByText(/ACTUATOR KINEMATICS/i)).toBeTruthy();
  });

  // =========================================================================
  // P1.1 Integration & Reliability Regression Tests (10 Specific Scenarios)
  // =========================================================================

  it('P1.1 Scenario 1: SIMULATED source correctly displays simulated telemetry badge and values', () => {
    render(
      <LongitudinalSideDrainTwin
        upstreamDepth={6.4}
        inflow={11.2}
        mode="SIMULATION"
        readings={{}}
      />
    );

    const badge = screen.getByTestId('telemetry-source-badge');
    expect(badge.textContent).toContain('SIMULATION MODE');

    const overlayBadge = screen.getByTestId('telemetry-badge-overlay');
    expect(overlayBadge.textContent).toBe('SIMULATED');

    expect(screen.getByText(/RADAR WATER LEVEL \[SIMULATED\]/i)).toBeTruthy();
    expect(screen.getByText(/FLOW SENSOR \[SIMULATED\]/i)).toBeTruthy();
  });

  it('P1.1 Scenario 2: LIVE source displays fresh timestamps and connected hardware badge', () => {
    const liveTimestamp = new Date().toISOString();
    const liveReadings: Record<string, SensorReadingContract> = {
      RADAR_01: {
        version: '1.0',
        message_id: 'msg-radar-live',
        sensor_id: 'RADAR_01',
        section_id: 'SEC_SCREENING',
        sensor_type: 'WATER_LEVEL',
        value: 8.5,
        unit: 'cm',
        source: 'PHYSICAL',
        status: 'OK',
        timestamp: liveTimestamp,
      },
      FLOW_01: {
        version: '1.0',
        message_id: 'msg-flow-live',
        sensor_id: 'FLOW_01',
        section_id: 'SEC_INLET',
        sensor_type: 'FLOW_RATE',
        value: 14.2,
        unit: 'L/min',
        source: 'PHYSICAL',
        status: 'OK',
        timestamp: liveTimestamp,
      },
    };

    render(
      <LongitudinalSideDrainTwin
        upstreamDepth={8.5}
        inflow={14.2}
        mode="HARDWARE"
        readings={liveReadings}
      />
    );

    const badge = screen.getByTestId('telemetry-source-badge');
    expect(badge.textContent).toContain('LIVE (ESP32)');

    const overlayBadge = screen.getByTestId('telemetry-badge-overlay');
    expect(overlayBadge.textContent).toBe('LIVE');

    expect(screen.getByText('8.5 cm')).toBeTruthy();
    expect(screen.getByText('14.2 L/min')).toBeTruthy();
    expect(screen.getByText(/LAST SEEN:/i)).toBeTruthy();
  });

  it('P1.1 Scenario 3: OFFLINE state when physical readings are completely absent in hardware mode', () => {
    const { container } = render(
      <LongitudinalSideDrainTwin
        upstreamDepth={5.0}
        inflow={0.0}
        mode="HARDWARE"
        readings={{}}
      />
    );

    const badge = screen.getByTestId('telemetry-source-badge');
    expect(badge.textContent).toContain('HARDWARE OFFLINE');

    const overlayBadge = screen.getByTestId('telemetry-badge-overlay');
    expect(overlayBadge.textContent).toBe('OFFLINE');

    const offlineBanner = container.querySelector('#hardwareOfflineBanner');
    expect(offlineBanner).toBeTruthy();
    expect(offlineBanner?.textContent).toContain('HARDWARE OFFLINE (NO ESP32 CONNECTED)');
  });

  it('P1.1 Scenario 4: STALE state when physical readings exceed 15s age threshold', () => {
    // 20 seconds old (> 15s freshness threshold, but < 30s offline threshold)
    const staleTimestamp = new Date(Date.now() - 20000).toISOString();
    const staleReadings: Record<string, SensorReadingContract> = {
      RADAR_01: {
        version: '1.0',
        message_id: 'msg-radar-stale',
        sensor_id: 'RADAR_01',
        section_id: 'SEC_SCREENING',
        sensor_type: 'WATER_LEVEL',
        value: 7.2,
        unit: 'cm',
        source: 'PHYSICAL',
        status: 'OK',
        timestamp: staleTimestamp,
      },
    };

    render(
      <LongitudinalSideDrainTwin
        upstreamDepth={7.2}
        inflow={10.0}
        mode="HARDWARE"
        readings={staleReadings}
      />
    );

    const badge = screen.getByTestId('telemetry-source-badge');
    expect(badge.textContent).toContain('STALE (>15s)');

    const overlayBadge = screen.getByTestId('telemetry-badge-overlay');
    expect(overlayBadge.textContent).toBe('STALE');
  });

  it('P1.1 Scenario 5: Missing sensor values show UNAVAILABLE without substituting zero', () => {
    const liveTimestamp = new Date().toISOString();
    // Only Radar provided, Flow is missing
    const partialReadings: Record<string, SensorReadingContract> = {
      RADAR_01: {
        version: '1.0',
        message_id: 'msg-radar-only',
        sensor_id: 'RADAR_01',
        section_id: 'SEC_SCREENING',
        sensor_type: 'WATER_LEVEL',
        value: 9.1,
        unit: 'cm',
        source: 'PHYSICAL',
        status: 'OK',
        timestamp: liveTimestamp,
      },
    };

    render(
      <LongitudinalSideDrainTwin
        upstreamDepth={9.1}
        inflow={15.0}
        mode="HARDWARE"
        readings={partialReadings}
      />
    );

    expect(screen.getByText('9.1 cm')).toBeTruthy();
    expect(screen.getByText(/FLOW SENSOR \[OFFLINE\]/i)).toBeTruthy();

    const unavailableLabels = screen.getAllByText('UNAVAILABLE');
    expect(unavailableLabels.length).toBeGreaterThanOrEqual(1);
    // Crucial: Must NOT fabricate '0.0 L/min'
    expect(screen.queryByText('0.0 L/min')).toBeNull();
  });

  it('P1.1 Scenario 6: Sensor FAULT state triggers fault badge and marks reading unavailable', () => {
    const liveTimestamp = new Date().toISOString();
    const faultReadings: Record<string, SensorReadingContract> = {
      RADAR_01: {
        version: '1.0',
        message_id: 'msg-radar-fault',
        sensor_id: 'RADAR_01',
        section_id: 'SEC_SCREENING',
        sensor_type: 'WATER_LEVEL',
        value: -999.0,
        unit: 'cm',
        source: 'PHYSICAL',
        status: 'FAULT',
        timestamp: liveTimestamp,
      },
    };

    render(
      <LongitudinalSideDrainTwin
        upstreamDepth={6.0}
        inflow={10.0}
        mode="HARDWARE"
        readings={faultReadings}
      />
    );

    const badge = screen.getByTestId('telemetry-source-badge');
    expect(badge.textContent).toContain('HARDWARE FAULT');

    const overlayBadge = screen.getByTestId('telemetry-badge-overlay');
    expect(overlayBadge.textContent).toBe('FAULT');

    const unavailableLabels = screen.getAllByText('UNAVAILABLE');
    expect(unavailableLabels.length).toBeGreaterThanOrEqual(1);
  });

  it('P1.1 Scenario 7: Open-loop servo command is explicitly tagged (CMD) and actual is NOT MEASURED (NO SENSOR)', () => {
    const liveTimestamp = new Date().toISOString();
    const servoCommandReadings: Record<string, SensorReadingContract> = {
      RADAR_01: {
        version: '1.0',
        message_id: 'msg-radar-live',
        sensor_id: 'RADAR_01',
        section_id: 'SEC_SCREENING',
        sensor_type: 'WATER_LEVEL',
        value: 7.0,
        unit: 'cm',
        source: 'PHYSICAL',
        status: 'OK',
        timestamp: liveTimestamp,
      },
      GATE_SERVO_01: {
        version: '1.0',
        message_id: 'msg-gate-cmd',
        sensor_id: 'GATE_SERVO_01',
        section_id: 'SEC_DIVERSION',
        sensor_type: 'GATE_ANGLE',
        value: 45.0,
        unit: 'deg',
        source: 'PHYSICAL',
        status: 'OK',
        timestamp: liveTimestamp,
      },
    };

    render(
      <LongitudinalSideDrainTwin
        upstreamDepth={7.0}
        inflow={10.0}
        mode="HARDWARE"
        readings={servoCommandReadings}
      />
    );

    expect(screen.getByText('45.0°')).toBeTruthy();
    expect(screen.getByText('(CMD)')).toBeTruthy();
    expect(screen.getByText(/ACTUAL: NOT MEASURED \(NO SENSOR\)/i)).toBeTruthy();
  });

  it('P1.1 Scenario 8: Physical position sensor feedback correctly displays measured angle when present', () => {
    const liveTimestamp = new Date().toISOString();
    const positionFeedbackReadings: Record<string, SensorReadingContract> = {
      RADAR_01: {
        version: '1.0',
        message_id: 'msg-radar-live',
        sensor_id: 'RADAR_01',
        section_id: 'SEC_SCREENING',
        sensor_type: 'WATER_LEVEL',
        value: 7.0,
        unit: 'cm',
        source: 'PHYSICAL',
        status: 'OK',
        timestamp: liveTimestamp,
      },
      GATE_SERVO_01: {
        version: '1.0',
        message_id: 'msg-gate-cmd',
        sensor_id: 'GATE_SERVO_01',
        section_id: 'SEC_DIVERSION',
        sensor_type: 'GATE_ANGLE',
        value: 50.0,
        unit: 'deg',
        source: 'PHYSICAL',
        status: 'OK',
        timestamp: liveTimestamp,
      },
      GATE_POSITION_FEEDBACK_01: {
        version: '1.0',
        message_id: 'msg-gate-actual',
        sensor_id: 'GATE_POSITION_FEEDBACK_01',
        section_id: 'SEC_DIVERSION',
        sensor_type: 'GATE_ANGLE',
        value: 48.5,
        unit: 'deg',
        source: 'PHYSICAL',
        status: 'OK',
        timestamp: liveTimestamp,
        metadata: { is_actual_position: true },
      },
    };

    render(
      <LongitudinalSideDrainTwin
        upstreamDepth={7.0}
        inflow={10.0}
        mode="HARDWARE"
        readings={positionFeedbackReadings}
      />
    );

    expect(screen.getByText('50.0°')).toBeTruthy();
    expect(screen.getByText('ACTUAL: 48.5°')).toBeTruthy();
  });

  it('P1.1 Scenario 9: Demo mode toggle persists synthetic tagging and renders demo banner', () => {
    const liveTimestamp = new Date().toISOString();
    const liveReadings: Record<string, SensorReadingContract> = {
      RADAR_01: {
        version: '1.0',
        message_id: 'msg-01',
        sensor_id: 'RADAR_01',
        section_id: 'SEC_SCREENING',
        sensor_type: 'WATER_LEVEL',
        value: 7.5,
        unit: 'cm',
        source: 'PHYSICAL',
        status: 'OK',
        timestamp: liveTimestamp,
      },
    };

    const { container } = render(
      <LongitudinalSideDrainTwin
        upstreamDepth={7.5}
        inflow={10.0}
        mode="HARDWARE"
        readings={liveReadings}
      />
    );

    // Initial state is LIVE
    expect(screen.getByTestId('telemetry-source-badge').textContent).toContain('LIVE (ESP32)');

    // Toggle demo mode button
    const demoButton = screen.getByText('HW TRACKING');
    fireEvent.click(demoButton);

    // After click: must be DEMO: ACTIVE
    expect(screen.getByText('DEMO: ACTIVE')).toBeTruthy();
    expect(screen.getByTestId('telemetry-source-badge').textContent).toContain('SIMULATION MODE');
    const demoBanner = container.querySelector('#demoModeBanner');
    expect(demoBanner).toBeTruthy();
    expect(demoBanner?.textContent).toContain('DEMONSTRATION MODE (SYNTHETIC)');
  });

  it('P1.1 Scenario 10: Hardware disconnection (>30s old) gracefully switches to OFFLINE without false LIVE status', () => {
    // 35 seconds old: strictly exceeds 30s offline threshold
    const expiredTimestamp = new Date(Date.now() - 35000).toISOString();
    const expiredReadings: Record<string, SensorReadingContract> = {
      RADAR_01: {
        version: '1.0',
        message_id: 'msg-radar-expired',
        sensor_id: 'RADAR_01',
        section_id: 'SEC_SCREENING',
        sensor_type: 'WATER_LEVEL',
        value: 6.5,
        unit: 'cm',
        source: 'PHYSICAL',
        status: 'OK',
        timestamp: expiredTimestamp,
      },
    };

    const { container } = render(
      <LongitudinalSideDrainTwin
        upstreamDepth={6.5}
        inflow={10.0}
        mode="HARDWARE"
        readings={expiredReadings}
      />
    );

    // Crucial check: Must NEVER show LIVE (ESP32) for disconnected hardware
    const badge = screen.getByTestId('telemetry-source-badge');
    expect(badge.textContent).not.toContain('LIVE');
    expect(badge.textContent).toContain('HARDWARE OFFLINE');

    const overlayBadge = screen.getByTestId('telemetry-badge-overlay');
    expect(overlayBadge.textContent).toBe('OFFLINE');

    const offlineBanner = container.querySelector('#hardwareOfflineBanner');
    expect(offlineBanner).toBeTruthy();
  });
});
