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
  FieldTeamContract,
  IncidentAuditContract,
  IncidentVerifyRequest,
  IncidentAssignRequest,
  IncidentReassignRequest,
  IncidentUnassignRequest,
  IncidentRejectRequest,
  MunicipalKpiResponseContract,
  MunicipalQueueResponseContract,
  MunicipalQueueFilters,
} from '../types/contracts';

const RAW_API_BASE = import.meta.env.VITE_API_BASE_URL;
const API_BASE = RAW_API_BASE ? RAW_API_BASE.replace(/\/+$/, '') + '/api/v1' : '/api/v1';

let currentAuthToken: string | null = null;
try {
  currentAuthToken = typeof localStorage !== 'undefined' ? localStorage.getItem('drainx_auth_token') : null;
} catch {
  currentAuthToken = null;
}

export const setAuthToken = (token: string | null) => {
  currentAuthToken = token;
  try {
    if (token) {
      localStorage.setItem('drainx_auth_token', token);
    } else {
      localStorage.removeItem('drainx_auth_token');
    }
  } catch {
    // Ignore storage issues in test/restricted environments
  }
};

export const getAuthToken = () => currentAuthToken;

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
  const authHeaders: Record<string, string> = {};
  if (currentAuthToken) {
    authHeaders['Authorization'] = `Bearer ${currentAuthToken}`;
  }
  try {
    res = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...authHeaders,
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

  async getMunicipalKpis(): Promise<MunicipalKpiResponseContract> {
    return request<MunicipalKpiResponseContract>('/incidents/municipal/kpis');
  },

  async getMunicipalQueue(filters?: MunicipalQueueFilters): Promise<MunicipalQueueResponseContract> {
    const params = new URLSearchParams();
    if (filters?.status && filters.status !== 'ALL') params.append('status', filters.status);
    if (filters?.category && filters.category !== 'ALL') params.append('category', filters.category);
    if (filters?.severity && filters.severity !== 'ALL') params.append('severity', filters.severity);
    if (filters?.source && filters.source !== 'ALL') params.append('source', filters.source);
    if (filters?.assigned_to && filters.assigned_to !== 'ALL') params.append('assigned_to', filters.assigned_to);
    if (filters?.search && filters.search.trim()) params.append('search', filters.search.trim());
    if (filters?.start_date) params.append('start_date', filters.start_date);
    if (filters?.end_date) params.append('end_date', filters.end_date);
    if (filters?.limit !== undefined) params.append('limit', String(filters.limit));
    if (filters?.offset !== undefined) params.append('offset', String(filters.offset));
    const queryString = params.toString() ? `?${params.toString()}` : '';
    return request<MunicipalQueueResponseContract>(`/incidents/municipal/queue${queryString}`);
  },

  async getFieldTeams(): Promise<FieldTeamContract[]> {
    return request<FieldTeamContract[]>('/incidents/field-teams');
  },

  async verifyIncident(id: string, payload: IncidentVerifyRequest): Promise<IncidentResponseContract> {
    return request<IncidentResponseContract>(`/incidents/${id}/verify`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async assignIncident(id: string, payload: IncidentAssignRequest): Promise<IncidentResponseContract> {
    return request<IncidentResponseContract>(`/incidents/${id}/assign`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async reassignIncident(id: string, payload: IncidentReassignRequest): Promise<IncidentResponseContract> {
    return request<IncidentResponseContract>(`/incidents/${id}/reassign`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async unassignIncident(id: string, payload: IncidentUnassignRequest): Promise<IncidentResponseContract> {
    return request<IncidentResponseContract>(`/incidents/${id}/unassign`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async rejectIncident(id: string, payload: IncidentRejectRequest): Promise<IncidentResponseContract> {
    return request<IncidentResponseContract>(`/incidents/${id}/reject`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  async getIncidentAudits(id: string): Promise<IncidentAuditContract[]> {
    return request<IncidentAuditContract[]>(`/incidents/${id}/audit`);
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

