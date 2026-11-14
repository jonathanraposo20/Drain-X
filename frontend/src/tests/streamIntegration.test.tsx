import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Header } from '../components/Header';
import { DigitalTwin } from '../components/DigitalTwin';
import { LiveTelemetryTable } from '../components/LiveTelemetryTable';
import { SensorReadingContract, MechanismStatusContract } from '../types/contracts';

describe('Digital Twin & UI Stream Integration', () => {
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

  const sampleReadings: Record<string, SensorReadingContract> = {
    US_UPSTREAM_01: {
      version: '1.0',
      message_id: 'msg-01',
      sensor_id: 'US_UPSTREAM_01',
      section_id: 'SEC_SCREENING',
      sensor_type: 'WATER_LEVEL',
      value: 7.4,
      unit: 'cm',
      source: 'PHYSICAL',
      status: 'OK',
      timestamp: new Date().toISOString(),
      metadata: { validation_stage: 'PARTIALLY_ASSEMBLED' },
    },
    FS_FLUME_01: {
      version: '1.0',
      message_id: 'msg-02',
      sensor_id: 'FS_FLUME_01',
      section_id: 'SEC_FLUME',
      sensor_type: 'FLOW_RATE',
      value: 12.8,
      unit: 'L/min',
      source: 'PHYSICAL',
      status: 'OK',
      timestamp: new Date().toISOString(),
      metadata: { validation_stage: 'PARTIALLY_ASSEMBLED' },
    },
  };

  it('renders Header with live stream status indicator and data freshness', () => {
    const { rerender } = render(
      <Header
        mode="HARDWARE"
        operationalState="MONITORING"
        activeAlertsCount={0}
        onToggleMode={vi.fn()}
        isToggling={false}
        streamStatus="CONNECTED"
        dataFreshnessSec={0.4}
      />
    );

    expect(screen.getByText(/STREAM: LIVE/i)).toBeTruthy();
    expect(screen.getByText(/<1s/i)).toBeTruthy();

    // Rerender in polling fallback mode
    rerender(
      <Header
        mode="HARDWARE"
        operationalState="MONITORING"
        activeAlertsCount={0}
        onToggleMode={vi.fn()}
        isToggling={false}
        streamStatus="POLLING_FALLBACK"
        dataFreshnessSec={2.1}
      />
    );

    expect(screen.getByText(/FALLBACK: HTTP/i)).toBeTruthy();
    expect(screen.getByText(/2s/i)).toBeTruthy();
  });

  it('renders DigitalTwin with hardware validation stage and physical source badge', () => {
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
  });

  it('renders LiveTelemetryTable with stream status badge', () => {
    render(
      <LiveTelemetryTable
        readings={sampleReadings}
        isLoading={false}
        error={null}
        onRefresh={vi.fn()}
        streamStatus="CONNECTED"
      />
    );

    expect(screen.getByText(/2 CHANNELS/i)).toBeTruthy();
    expect(screen.getByText(/WS STREAM/i)).toBeTruthy();
  });
});
