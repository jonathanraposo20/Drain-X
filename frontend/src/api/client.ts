import {
  SensorReadingContract,
  AlertContract,
  SystemStatusContract,
  ScenarioType,
  BenchmarkMetricsContract,
  MechanismStatusContract,
  BlockageEventContract,
  PredictionContract,
  FaultEventContract,
  TelemetryIngestResponse,
  IncidentResponseContract,
  IncidentCreateContract,
  IncidentUpdateContract,
} from '../types/contracts';

const RAW_API_BASE = import.meta.env.VITE_API_BASE_URL;
const API_BASE = RAW_API_BASE ? RAW_API_BASE.replace(/\/+$/, '') + '/api/v1' : '/api/v1';

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public data?: unknown
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

async function request<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE}${endpoint}`;
  let res: Response;
  try {
    res = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options?.headers,
      },
    });
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw new ApiError(0, err instanceof Error ? err.message : 'Network error');
  }

  // Consume response body exactly once
  let rawText = '';
  let parsedData: unknown = undefined;
  let bodyConsumed = false;

  if (typeof res.text === 'function') {
    try {
      rawText = await res.text();
      bodyConsumed = true;
    } catch {
      rawText = '';
    }
  }

  if (bodyConsumed) {
    if (rawText && rawText.trim().length > 0) {
      try {
        parsedData = JSON.parse(rawText);
      } catch {
        // Body is non-JSON text (e.g. HTML error page or plain text message)
        parsedData = rawText;
      }
    }
  } else if (typeof res.json === 'function') {
    // Fallback for custom mocks where only res.json is defined
    try {
      parsedData = await res.json();
    } catch {
      parsedData = undefined;
    }
  }

  if (!res.ok) {
    // Extract meaningful error message while preserving HTTP status
    let message = `Request failed: ${res.statusText || res.status}`;
    if (parsedData && typeof parsedData === 'object') {
      if ('detail' in parsedData && typeof (parsedData as Record<string, unknown>).detail === 'string') {
        message = (parsedData as Record<string, unknown>).detail as string;
      } else if ('message' in parsedData && typeof (parsedData as Record<string, unknown>).message === 'string') {
        message = (parsedData as Record<string, unknown>).message as string;
      }
    } else if (typeof parsedData === 'string' && parsedData.trim().length > 0) {
      message = parsedData.trim();
    }

    throw new ApiError(res.status, message, parsedData);
  }

  // Handle empty successful responses (e.g., 204 No Content or empty 200)
  if (parsedData === undefined || (typeof parsedData === 'string' && parsedData.trim().length === 0)) {
    return {} as T;
  }

  return parsedData as T;
}

export interface SimulationStateResponse {
  status: string;
  is_running: boolean;
  active_scenario: string | null;
  simulation_time_s: number;
  system: SystemStatusContract;
  mechanism: MechanismStatusContract;
  blockage: BlockageEventContract | null;
  prediction: PredictionContract | null;
  benchmark: BenchmarkMetricsContract | null;
  active_faults: FaultEventContract[];
}

export const apiClient = {
  async getHealth() {
    return request<{
      status: string;
      service: string;
      version: string;
      mode: string;
      uptime_seconds: number;
    }>('/health');
  },

  async getStatus(): Promise<SystemStatusContract> {
    return request<SystemStatusContract>('/status');
  },

  async setMode(mode: 'SIMULATION' | 'HARDWARE') {
    return request<{ status: string; mode: string; message: string }>('/status/mode', {
      method: 'POST',
      body: JSON.stringify({ mode }),
    });
  },

  async getLatestTelemetry(): Promise<{ status: string; readings: Record<string, SensorReadingContract> }> {
    return request<{ status: string; readings: Record<string, SensorReadingContract> }>('/telemetry/latest');
  },

  async getSensorHistory(sensorId: string, limit = 50): Promise<{ count: number; readings: SensorReadingContract[] }> {
    return request<{ count: number; readings: SensorReadingContract[] }>(`/telemetry/history/${sensorId}?limit=${limit}`);
  },

  async ingestTelemetry(payload: Partial<SensorReadingContract> | Partial<SensorReadingContract>[]): Promise<TelemetryIngestResponse> {
    return request<TelemetryIngestResponse>('/telemetry', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async getAlerts(activeOnly = true): Promise<AlertContract[]> {
    return request<AlertContract[]>(`/alerts?active_only=${activeOnly}`);
  },

  async resolveAlert(alertId: string): Promise<AlertContract> {
    return request<AlertContract>(`/alerts/${alertId}/resolve`, {
      method: 'POST',
    });
  },

  // Simulation & Digital Twin APIs
  async getSimulationState(): Promise<SimulationStateResponse> {
    return request<SimulationStateResponse>('/simulation/state');
  },

  async startScenario(scenario: ScenarioType, seed = 42) {
    return request<{ status: string; message: string; scenario: string }>('/simulation/start', {
      method: 'POST',
      body: JSON.stringify({ scenario, seed }),
    });
  },

  async stopScenario() {
    return request<{ status: string; message: string }>('/simulation/stop', {
      method: 'POST',
    });
  },

  async stepSimulation(dt = 0.5) {
    return request<{ status: string; step_result: Record<string, unknown> }>(`/simulation/step?dt=${dt}`, {
      method: 'POST',
    });
  },

  async injectFault(faultType: string, sensorId = 'US_UPSTREAM_01') {
    return request<{ status: string; message: string }>('/simulation/inject_fault', {
      method: 'POST',
      body: JSON.stringify({ fault_type: faultType, sensor_id: sensorId }),
    });
  },

  async triggerMechanism() {
    return request<{ status: string; message: string }>('/simulation/mechanism/trigger', {
      method: 'POST',
    });
  },

  async resetMechanism() {
    return request<{ status: string; message: string }>('/simulation/mechanism/reset', {
      method: 'POST',
    });
  },

  // Citizen & Municipal Incidents APIs
  async getIncidents(filters?: {
    status?: string;
    category?: string;
    severity?: string;
    source?: string;
  }): Promise<IncidentResponseContract[]> {
    const params = new URLSearchParams();
    if (filters?.status) params.append('status', filters.status);
    if (filters?.category) params.append('category', filters.category);
    if (filters?.severity) params.append('severity', filters.severity);
    if (filters?.source) params.append('source', filters.source);
    const queryString = params.toString() ? `?${params.toString()}` : '';
    return request<IncidentResponseContract[]>(`/incidents${queryString}`);
  },

  async createIncident(payload: IncidentCreateContract): Promise<IncidentResponseContract> {
    return request<IncidentResponseContract>('/incidents', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async updateIncident(id: string, payload: IncidentUpdateContract): Promise<IncidentResponseContract> {
    return request<IncidentResponseContract>(`/incidents/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    });
  },

  async queryHistoricalTelemetry(options: {
    sensor_id?: string;
    source?: 'PHYSICAL' | 'SIMULATED';
    section_id?: string;
    start_time?: string;
    end_time?: string;
    limit?: number;
    chronological?: boolean;
  } = {}): Promise<{
    status: string;
    count: number;
    sensor_id: string | null;
    source_filter: string | null;
    chronological: boolean;
    is_truncated?: boolean;
    truncation_warning?: string | null;
    records: SensorReadingContract[];
  }> {
    const params = new URLSearchParams();
    if (options.sensor_id) params.append('sensor_id', options.sensor_id);
    if (options.source) params.append('source', options.source);
    if (options.section_id) params.append('section_id', options.section_id);
    if (options.start_time) params.append('start_time', options.start_time);
    if (options.end_time) params.append('end_time', options.end_time);
    if (options.limit !== undefined) params.append('limit', String(options.limit));
    if (options.chronological !== undefined) params.append('chronological', String(options.chronological));

    const queryString = params.toString() ? `?${params.toString()}` : '';
    return request(`/telemetry/persistence/historical${queryString}`);
  },
};

export {
  TelemetryStreamClient,
  streamEventToReading,
  isReadingNewer,
  getWebSocketStreamUrl,
} from './streamClient';
export type { StreamClientOptions } from './streamClient';

