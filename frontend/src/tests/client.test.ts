import { describe, it, expect, vi, beforeEach } from 'vitest';
import { apiClient, ApiError } from '../api/client';

describe('API Client Abstraction', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('successfully fetches system status', async () => {
    const mockStatus = {
      system_name: 'DRAIN-X',
      mode: 'SIMULATION',
      operational_state: 'MONITORING',
      uptime_seconds: 45.2,
      active_alerts_count: 0,
      last_heartbeat: '2026-11-02T00:00:00Z',
      latest_readings: {},
      mechanism: {
        state: 'IDLE',
        backup_net_angle_deg: 0.0,
        tray_height_cm: 0.0,
        cycle_count: 0,
        current_action: 'Idle',
        elapsed_in_state_s: 0.0,
        is_jammed: false,
        is_fault: false,
        debris_retained_pct: 0.0,
      },
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockStatus,
    });

    const result = await apiClient.getStatus();
    expect(result.system_name).toBe('DRAIN-X');
    expect(result.mode).toBe('SIMULATION');
    expect(global.fetch).toHaveBeenCalledWith('/api/v1/status', expect.any(Object));
  });

  it('successfully fetches simulation state', async () => {
    const mockSim = {
      status: 'success',
      is_running: true,
      active_scenario: 'SUCCESSFUL_INTERVENTION',
      simulation_time_s: 24.5,
      system: {},
      mechanism: { state: 'HOISTING', tray_height_cm: 9.0 },
      blockage: { severity: 0.8 },
      prediction: { state: 'ESTIMATING', ttc_seconds: 28.0 },
      benchmark: { lead_time_advantage_s: 14.0 },
      active_faults: [],
    };

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => mockSim,
    });

    const result = await apiClient.getSimulationState();
    expect(result.is_running).toBe(true);
    expect(result.active_scenario).toBe('SUCCESSFUL_INTERVENTION');
    expect(result.mechanism.state).toBe('HOISTING');
  });

  it('successfully starts a scenario', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ status: 'success', scenario: 'GRADUAL_DEBRIS' }),
    });

    const result = await apiClient.startScenario('GRADUAL_DEBRIS', 42);
    expect(result.status).toBe('success');
    expect(result.scenario).toBe('GRADUAL_DEBRIS');
  });

  it('successfully triggers mechanism cycle', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ status: 'success', message: 'Cycle initiated' }),
    });

    const result = await apiClient.triggerMechanism();
    expect(result.status).toBe('success');
  });

  it('handles HTTP error responses gracefully with ApiError', async () => {
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 404,
      statusText: 'Not Found',
      json: async () => ({ detail: 'Resource not found' }),
    });

    await expect(apiClient.resolveAlert('non-existent-id')).rejects.toThrow(ApiError);
  });

  // REGRESSION TESTS: Response Body Stream Single-Consumption
  it('does NOT throw "body stream already read" when backend returns non-JSON error HTML (e.g. 502/500/404)', async () => {
    // Real Response object whose ReadableStream will throw TypeError if read more than once
    const htmlErrorBody = '<!DOCTYPE html><html><body>502 Bad Gateway from Render</body></html>';
    const realResponse = new Response(htmlErrorBody, {
      status: 502,
      statusText: 'Bad Gateway',
      headers: { 'Content-Type': 'text/html' },
    });

    global.fetch = vi.fn().mockResolvedValue(realResponse);

    try {
      await apiClient.getStatus();
      expect.fail('Should have thrown an ApiError');
    } catch (err) {
      expect(err).toBeInstanceOf(ApiError);
      const apiErr = err as ApiError;
      // Must preserve the actual HTTP status
      expect(apiErr.status).toBe(502);
      // Must NOT fail with stream already read error
      expect(apiErr.message).not.toContain('body stream already read');
      expect(apiErr.message).toContain('502 Bad Gateway');
      expect(apiErr.data).toBe(htmlErrorBody);
    }
  });

  it('preserves genuine HTTP status and extracts FastAPI error detail from JSON error', async () => {
    const errorJson = JSON.stringify({ detail: 'Unauthenticated or expired token' });
    const realResponse = new Response(errorJson, {
      status: 401,
      statusText: 'Unauthorized',
      headers: { 'Content-Type': 'application/json' },
    });

    global.fetch = vi.fn().mockResolvedValue(realResponse);

    try {
      await apiClient.getLatestTelemetry();
      expect.fail('Should have thrown an ApiError');
    } catch (err) {
      expect(err).toBeInstanceOf(ApiError);
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(401);
      expect(apiErr.message).toBe('Unauthenticated or expired token');
      expect(apiErr.data).toEqual({ detail: 'Unauthenticated or expired token' });
    }
  });

  it('handles empty response bodies (204 No Content or empty 200) without crashing', async () => {
    const noContentResponse = new Response(null, {
      status: 204,
      statusText: 'No Content',
    });

    global.fetch = vi.fn().mockResolvedValue(noContentResponse);

    const result = await apiClient.stopScenario();
    expect(result).toBeDefined();
    expect(typeof result).toBe('object');
  });

  it('handles empty error responses gracefully without stream errors', async () => {
    const emptyErrorResponse = new Response('', {
      status: 500,
      statusText: 'Internal Server Error',
    });

    global.fetch = vi.fn().mockResolvedValue(emptyErrorResponse);

    try {
      await apiClient.getStatus();
      expect.fail('Should have thrown an ApiError');
    } catch (err) {
      expect(err).toBeInstanceOf(ApiError);
      const apiErr = err as ApiError;
      expect(apiErr.status).toBe(500);
      expect(apiErr.message).toBe('Request failed: Internal Server Error');
    }
  });
});
