import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MunicipalOperationsDashboard } from '../components/municipal/MunicipalOperationsDashboard';
import { apiClient, ApiError } from '../api/client';
import {
  MunicipalKpiResponseContract,
  MunicipalQueueResponseContract,
  FieldTeamContract,
  IncidentAuditContract,
} from '../types/contracts';

const mockKpis: MunicipalKpiResponseContract = {
  total_incidents: 12,
  open_incidents: 8,
  critical_or_high_incidents: 3,
  unassigned_incidents: 4,
  assigned_incidents: 4,
  investigating_incidents: 2,
  resolved_incidents: 3,
  rejected_incidents: 1,
  demo_incidents_count: 4,
  genuine_incidents_count: 8,
  by_category: {
    FLOODING: 3,
    WATERLOGGING: 2,
    DRAIN_BLOCKAGE: 3,
  },
  by_severity: {
    CRITICAL: 1,
    HIGH: 2,
    MEDIUM: 5,
  },
  by_status: {
    REPORTED: 2,
    VERIFIED: 2,
    ASSIGNED: 2,
    INVESTIGATING: 2,
    RESOLVED: 3,
    REJECTED: 1,
  },
  by_source: {
    DEMO: 4,
    CITIZEN: 8,
  },
};

const mockQueue: MunicipalQueueResponseContract = {
  items: [
    {
      id: 'INC-DEMO-01',
      category: 'DRAIN_OVERFLOW',
      description: 'Severe storm runoff overflowing culvert embankment near St. Inez Church.',
      latitude: 15.492,
      longitude: 73.8185,
      severity: 'CRITICAL',
      status: 'INVESTIGATING',
      source: 'DEMO',
      created_at: '2026-11-15T10:00:00Z',
      updated_at: '2026-11-15T10:30:00Z',
      assigned_to: 'Team Alpha — St. Inez Drainage Crew',
      municipal_notes: 'High-capacity dewatering pump dispatched.',
      photos: ['/api/v1/incidents/photos/sample1.jpg'],
    },
    {
      id: 'INC-DEMO-02',
      category: 'WATERLOGGING',
      description: 'Street waterlogging near Patto Plaza.',
      latitude: 15.4989,
      longitude: 73.8342,
      severity: 'HIGH',
      status: 'ASSIGNED',
      source: 'DEMO',
      created_at: '2026-11-15T09:00:00Z',
      updated_at: '2026-11-15T09:30:00Z',
      assigned_to: 'Team Beta — Patto Rapid Response',
      municipal_notes: 'Suction tanker scheduled.',
      photos: [],
    },
    {
      id: 'INC-DEMO-03',
      category: 'DRAIN_BLOCKAGE',
      description: 'Accumulation of debris blocking culvert.',
      latitude: 15.4965,
      longitude: 73.8305,
      severity: 'MEDIUM',
      status: 'REPORTED',
      source: 'CITIZEN',
      created_at: '2026-11-15T08:00:00Z',
      updated_at: '2026-11-15T08:00:00Z',
      assigned_to: null,
      municipal_notes: '',
      photos: [],
    },
  ],
  total_count: 3,
  limit: 15,
  offset: 0,
  has_more: false,
};

const mockFieldTeams: FieldTeamContract[] = [
  {
    team_id: 'TEAM-ALPHA',
    name: 'Team Alpha — St. Inez Drainage Crew',
    zone: 'St. Inez / Panaji Central',
    is_active: true,
    capacity: 4,
  },
  {
    team_id: 'TEAM-BETA',
    name: 'Team Beta — Patto Rapid Response',
    zone: 'Patto Commercial Plaza',
    is_active: true,
    capacity: 4,
  },
];

const mockAudits: IncidentAuditContract[] = [
  {
    audit_id: 'AUD-001',
    incident_id: 'INC-DEMO-01',
    actor_id: 'panaji-citizen',
    actor_role: 'citizen',
    action: 'REPORTED',
    new_status: 'REPORTED',
    timestamp: '2026-11-15T10:00:00Z',
  },
  {
    audit_id: 'AUD-002',
    incident_id: 'INC-DEMO-01',
    actor_id: 'supervisor-01',
    actor_role: 'municipality',
    action: 'ASSIGNED',
    new_assigned_to: 'Team Alpha — St. Inez Drainage Crew',
    reason: 'Initial crew dispatch',
    timestamp: '2026-11-15T10:05:00Z',
  },
];

describe('MunicipalOperationsDashboard', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(apiClient, 'getMunicipalKpis').mockResolvedValue(mockKpis);
    vi.spyOn(apiClient, 'getMunicipalQueue').mockResolvedValue(mockQueue);
    vi.spyOn(apiClient, 'getFieldTeams').mockResolvedValue(mockFieldTeams);
    vi.spyOn(apiClient, 'getIncidentAudits').mockResolvedValue(mockAudits);
    vi.spyOn(apiClient, 'verifyIncident').mockResolvedValue({
      ...mockQueue.items[2],
      status: 'VERIFIED',
    });
    vi.spyOn(apiClient, 'assignIncident').mockResolvedValue({
      ...mockQueue.items[2],
      status: 'ASSIGNED',
      assigned_to: 'Team Alpha — St. Inez Drainage Crew',
    });
    vi.spyOn(apiClient, 'reassignIncident').mockResolvedValue({
      ...mockQueue.items[0],
      assigned_to: 'Team Beta — Patto Rapid Response',
    });
    vi.spyOn(apiClient, 'unassignIncident').mockResolvedValue({
      ...mockQueue.items[0],
      assigned_to: null,
      status: 'VERIFIED',
    });
    vi.spyOn(apiClient, 'rejectIncident').mockResolvedValue({
      ...mockQueue.items[2],
      status: 'REJECTED',
      rejection_reason: 'Duplicate hazard report',
    });
  });

  it('renders dashboard heading, context, and authoritative KPI cards', async () => {
    render(<MunicipalOperationsDashboard />);

    expect(screen.getByText(/MUNICIPAL OPERATIONS & DISPATCH QUEUE/i)).toBeTruthy();
    expect(screen.getByText(/PANAJI DRAINAGE BASIN/i)).toBeTruthy();

    await waitFor(() => {
      // Total population
      expect(screen.getByText('12')).toBeTruthy();
      // Active open and Genuine count both have count 8
      expect(screen.getAllByText('8').length).toBeGreaterThanOrEqual(1);
      // Critical / High and Resolved both have count 3
      expect(screen.getAllByText('3').length).toBeGreaterThanOrEqual(2);
      // Awaiting Crew and Demo Seeds both have count 4
      expect(screen.getAllByText('4').length).toBeGreaterThanOrEqual(1);
      // Data integrity audit transparency
      expect(screen.getByText(/Genuine Field Incidents:/i)).toBeTruthy();
      expect(screen.getByText(/Simulated Demo Seeds:/i)).toBeTruthy();
    });

    expect(apiClient.getMunicipalKpis).toHaveBeenCalledTimes(1);
    expect(apiClient.getMunicipalQueue).toHaveBeenCalledTimes(1);
  });

  it('renders operational incident queue rows with status, severity, and assignments', async () => {
    render(<MunicipalOperationsDashboard />);

    await waitFor(() => {
      expect(screen.getByText('INC-DEMO-01')).toBeTruthy();
      expect(screen.getByText('INC-DEMO-02')).toBeTruthy();
      expect(screen.getByText('INC-DEMO-03')).toBeTruthy();
    });

    expect(screen.getAllByText('Team Alpha — St. Inez Drainage Crew').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('[UNASSIGNED]')).toBeTruthy();
    expect(screen.getByText('3 TOTAL')).toBeTruthy();
    expect(screen.getAllByText('[DEMO SEED]').length).toBe(2);
    expect(screen.getByText('[CITIZEN]')).toBeTruthy();
  });

  it('triggers search query filtering when input changes', async () => {
    render(<MunicipalOperationsDashboard />);

    await waitFor(() => {
      expect(screen.getByText('INC-DEMO-01')).toBeTruthy();
    });

    const searchInput = screen.getByPlaceholderText(/Search ticket ID/i);
    fireEvent.change(searchInput, { target: { value: 'Patto' } });

    await waitFor(() => {
      expect(apiClient.getMunicipalQueue).toHaveBeenCalledWith(
        expect.objectContaining({
          search: 'Patto',
        })
      );
    });
  });

  it('triggers status filter change', async () => {
    render(<MunicipalOperationsDashboard />);

    await waitFor(() => {
      expect(screen.getByText('INC-DEMO-01')).toBeTruthy();
    });

    const statusSelect = screen.getByDisplayValue('ALL STATUSES');
    fireEvent.change(statusSelect, { target: { value: 'INVESTIGATING' } });

    await waitFor(() => {
      expect(apiClient.getMunicipalQueue).toHaveBeenCalledWith(
        expect.objectContaining({
          status: 'INVESTIGATING',
        })
      );
    });
  });

  it('triggers source filter change', async () => {
    render(<MunicipalOperationsDashboard />);

    await waitFor(() => {
      expect(screen.getByText('INC-DEMO-01')).toBeTruthy();
    });

    const sourceSelect = screen.getByDisplayValue('ALL SOURCES');
    fireEvent.change(sourceSelect, { target: { value: 'CITIZEN' } });

    await waitFor(() => {
      expect(apiClient.getMunicipalQueue).toHaveBeenCalledWith(
        expect.objectContaining({
          source: 'CITIZEN',
        })
      );
    });
  });

  it('opens incident detail drawer on row click with coordinates, description, and triage workflows', async () => {
    render(<MunicipalOperationsDashboard />);

    await waitFor(() => {
      expect(screen.getByText('INC-DEMO-01')).toBeTruthy();
    });

    // Click on row
    fireEvent.click(screen.getByText('INC-DEMO-01'));

    await waitFor(() => {
      expect(screen.getByText(/SIMULATED DEMO RECORD/i)).toBeTruthy();
      expect(screen.getByText(/Severe storm runoff overflowing culvert/i)).toBeTruthy();
      expect(screen.getAllByText(/15\.4920, 73\.8185 \(Simulated\)/i).length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText('15.492000')).toBeTruthy();
      expect(screen.getByText('73.818500')).toBeTruthy();
      // Operational workflow sections are visible
      expect(screen.getByText(/MUNICIPAL TRIAGE & VERIFICATION/i)).toBeTruthy();
      expect(screen.getByText(/FIELD CREW ASSIGNMENT & DISPATCH/i)).toBeTruthy();
      expect(screen.getByText(/OPERATIONAL AUDIT TIMELINE/i)).toBeTruthy();
    });

    // Close button
    const closeBtn = screen.getByRole('button', { name: /CLOSE/i });
    fireEvent.click(closeBtn);

    await waitFor(() => {
      expect(screen.queryByText('15.492000')).toBeNull();
    });
  });

  it('allows verifying an unverified incident with notes and priority update', async () => {
    render(<MunicipalOperationsDashboard />);

    await waitFor(() => {
      expect(screen.getByText('INC-DEMO-03')).toBeTruthy();
    });

    // Open INC-DEMO-03 drawer
    fireEvent.click(screen.getByText('INC-DEMO-03'));

    await waitFor(() => {
      expect(screen.getByText('VERIFY INCIDENT')).toBeTruthy();
    });

    // Click VERIFY INCIDENT button
    fireEvent.click(screen.getByText('VERIFY INCIDENT'));

    await waitFor(() => {
      expect(apiClient.verifyIncident).toHaveBeenCalledWith(
        'INC-DEMO-03',
        expect.objectContaining({
          severity: 'MEDIUM',
        })
      );
    });
  });

  it('allows assigning an unassigned incident to a field crew', async () => {
    render(<MunicipalOperationsDashboard />);

    await waitFor(() => {
      expect(screen.getByText('INC-DEMO-03')).toBeTruthy();
    });

    fireEvent.click(screen.getByText('INC-DEMO-03'));

    await waitFor(() => {
      expect(screen.getByText('DISPATCH & ASSIGN CREW')).toBeTruthy();
    });

    fireEvent.click(screen.getByText('DISPATCH & ASSIGN CREW'));

    await waitFor(() => {
      expect(apiClient.assignIncident).toHaveBeenCalledWith(
        'INC-DEMO-03',
        expect.objectContaining({
          assigned_to: 'Team Alpha — St. Inez Drainage Crew',
        })
      );
    });
  });

  it('displays communication error banner on API failure without fabricating fallback data', async () => {
    vi.spyOn(apiClient, 'getMunicipalKpis').mockRejectedValue(new Error('Gateway timeout'));
    vi.spyOn(apiClient, 'getMunicipalQueue').mockRejectedValue(new Error('Gateway timeout'));

    render(<MunicipalOperationsDashboard />);

    await waitFor(() => {
      expect(screen.getByText(/COMMUNICATION FAILURE: Gateway timeout/i)).toBeTruthy();
    });

    expect(screen.queryByText('INC-DEMO-01')).toBeNull();
  });

  it('displays municipal authorization banner on HTTP 403 Forbidden', async () => {
    vi.spyOn(apiClient, 'getMunicipalKpis').mockRejectedValue(new ApiError(403, 'Permission denied'));

    render(<MunicipalOperationsDashboard />);

    await waitFor(() => {
      expect(screen.getByText(/MUNICIPAL ACCESS REQUIRED/i)).toBeTruthy();
    });
  });
});
