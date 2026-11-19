import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { CitizenReportModal } from '../components/gis/CitizenReportModal';
import { MunicipalOperationsPanel } from '../components/gis/MunicipalOperationsPanel';
import { UrbanGisDashboard } from '../components/gis/UrbanGisDashboard';
import { IncidentResponseContract, SystemStatusContract } from '../types/contracts';
import { apiClient } from '../api/client';

// Mock Leaflet MapContainer
vi.mock('react-leaflet', () => ({
  MapContainer: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="mock-map-container">{children}</div>
  ),
  TileLayer: () => <div data-testid="mock-tile-layer" />,
  Marker: ({ children, eventHandlers }: any) => (
    <div data-testid="mock-marker" onClick={eventHandlers?.click}>
      {children}
    </div>
  ),
  Polyline: ({ eventHandlers }: any) => (
    <div data-testid="mock-polyline" onClick={eventHandlers?.click} />
  ),
  Polygon: ({ eventHandlers }: any) => (
    <div data-testid="mock-polygon" onClick={eventHandlers?.click} />
  ),
  Popup: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="mock-popup">{children}</div>
  ),
  Tooltip: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="mock-tooltip">{children}</div>
  ),
  useMapEvents: (handlers: any) => handlers,
}));

const mockIncidents: IncidentResponseContract[] = [
  {
    id: 'INC-DEMO-01',
    category: 'DRAIN_OVERFLOW',
    description: 'Severe storm runoff overflowing culvert embankment near St. Inez Church.',
    latitude: 15.4920,
    longitude: 73.8185,
    severity: 'CRITICAL',
    status: 'INVESTIGATING',
    source: 'DEMO',
    created_at: new Date(Date.now() - 3600000).toISOString(),
    updated_at: new Date(Date.now() - 1800000).toISOString(),
    reporter_name: 'St. Inez Ward Committee',
    assigned_to: 'Team Alpha — St. Inez Drainage Crew',
    municipal_notes: 'Dewatering pump operating.',
  },
  {
    id: 'INC-DEMO-02',
    category: 'WATERLOGGING',
    description: 'Street waterlogging of 20cm depth blocking pedestrian access near Patto Plaza.',
    latitude: 15.4989,
    longitude: 73.8342,
    severity: 'HIGH',
    status: 'ASSIGNED',
    source: 'DEMO',
    created_at: new Date(Date.now() - 7200000).toISOString(),
    updated_at: new Date(Date.now() - 3600000).toISOString(),
    reporter_name: 'Patto Commercial Association',
    assigned_to: 'Team Beta — Patto Rapid Response',
    municipal_notes: 'Suction tanker scheduled.',
  },
  {
    id: 'INC-DEMO-03',
    category: 'DRAIN_BLOCKAGE',
    description: 'Accumulation of debris in heritage lane drain.',
    latitude: 15.4965,
    longitude: 73.8305,
    severity: 'MEDIUM',
    status: 'VERIFIED',
    source: 'DEMO',
    created_at: new Date(Date.now() - 10800000).toISOString(),
    updated_at: new Date(Date.now() - 7200000).toISOString(),
    reporter_name: 'Fontainhas Heritage Watch',
    assigned_to: null,
    municipal_notes: 'Inspection completed.',
  },
  {
    id: 'INC-DEMO-04',
    category: 'INFRASTRUCTURE_DAMAGE',
    description: 'Displaced concrete grating slab over main arterial drain.',
    latitude: 15.4835,
    longitude: 73.8078,
    severity: 'LOW',
    status: 'RESOLVED',
    source: 'DEMO',
    created_at: new Date(Date.now() - 86400000).toISOString(),
    updated_at: new Date(Date.now() - 43200000).toISOString(),
    reporter_name: 'Panaji Municipal Patrol',
    assigned_to: 'Team Delta — Miramar Outfall Sluice Unit',
    municipal_notes: 'Slab repaired.',
  },
];

describe('Citizen Reporting & Municipal Operations', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('CitizenReportModal', () => {
    it('renders form fields when open', () => {
      render(
        <CitizenReportModal
          isOpen={true}
          onClose={vi.fn()}
          onIncidentCreated={vi.fn()}
          isPickingOnMap={false}
          onToggleMapPick={vi.fn()}
        />
      );

      expect(screen.getByText(/CITIZEN DRAINAGE INCIDENT REPORT/i)).toBeTruthy();
      expect(screen.getByText(/Quick Geo-Location Presets/i)).toBeTruthy();
      expect(screen.getByText(/Hazard Category/i)).toBeTruthy();
      expect(screen.getByText(/Perceived Severity/i)).toBeTruthy();
      expect(screen.getByPlaceholderText(/Describe the drainage issue/i)).toBeTruthy();
      expect(screen.getByText(/Lodge Report/i)).toBeTruthy();
    });

    it('submits valid citizen report and displays confirmation banner', async () => {
      const mockCreatedIncident: IncidentResponseContract = {
        id: 'INC-TEST-99',
        category: 'WATERLOGGING',
        description: 'Road inundated under 15cm stagnant water.',
        latitude: 15.4950,
        longitude: 73.8210,
        severity: 'HIGH',
        status: 'REPORTED',
        source: 'CITIZEN',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        reporter_name: 'Citizen Anonymous',
        assigned_to: null,
        municipal_notes: '',
      };

      vi.spyOn(apiClient, 'createIncident').mockResolvedValue(mockCreatedIncident);
      const onCreated = vi.fn();

      render(
        <CitizenReportModal
          isOpen={true}
          onClose={vi.fn()}
          onIncidentCreated={onCreated}
          isPickingOnMap={false}
          onToggleMapPick={vi.fn()}
        />
      );

      const descInput = screen.getByPlaceholderText(/Describe the drainage issue/i);
      fireEvent.change(descInput, { target: { value: 'Road inundated under 15cm stagnant water.' } });

      const submitBtn = screen.getByText(/Lodge Report/i);
      fireEvent.click(submitBtn);

      await waitFor(() => {
        expect(apiClient.createIncident).toHaveBeenCalledTimes(1);
        expect(onCreated).toHaveBeenCalledWith(mockCreatedIncident);
        expect(screen.getByText(/Report Lodged Successfully/i)).toBeTruthy();
        expect(screen.getByText(/INC-TEST-99/i)).toBeTruthy();
      });
    });

    it('validates description length before submission', async () => {
      vi.spyOn(apiClient, 'createIncident');

      render(
        <CitizenReportModal
          isOpen={true}
          onClose={vi.fn()}
          onIncidentCreated={vi.fn()}
          isPickingOnMap={false}
          onToggleMapPick={vi.fn()}
        />
      );

      const descInput = screen.getByPlaceholderText(/Describe the drainage issue/i);
      fireEvent.change(descInput, { target: { value: 'ab' } });

      const submitBtn = screen.getByText(/Lodge Report/i);
      fireEvent.click(submitBtn);

      expect(screen.getByText(/Description must be at least 3 characters long/i)).toBeTruthy();
      expect(apiClient.createIncident).not.toHaveBeenCalled();
    });
  });

  describe('MunicipalOperationsPanel', () => {
    it('calculates correct operational KPIs', () => {
      render(
        <MunicipalOperationsPanel
          incidents={mockIncidents}
          onRefresh={vi.fn()}
          onUpdateIncident={vi.fn()}
        />
      );

      // Total tickets = 4
      expect(screen.getByText('4')).toBeTruthy();
      // Active / Open = 3 (INC-DEMO-01, 02, 03 are not resolved)
      expect(screen.getByText('3')).toBeTruthy();
      // High / Critical = 2, and Crews Dispatched = 2 (so text '2' appears twice)
      expect(screen.getAllByText('2').length).toBe(2);
      // Resolved = 1 (INC-DEMO-04)
      expect(screen.getByText('1')).toBeTruthy();
    });

    it('filters tickets by search query', () => {
      render(
        <MunicipalOperationsPanel
          incidents={mockIncidents}
          onRefresh={vi.fn()}
          onUpdateIncident={vi.fn()}
        />
      );

      expect(screen.getByText(/INC-DEMO-01/i)).toBeTruthy();
      expect(screen.getByText(/INC-DEMO-02/i)).toBeTruthy();

      const searchInput = screen.getByPlaceholderText(/Search ticket, desc, crew/i);
      fireEvent.change(searchInput, { target: { value: 'Patto' } });

      expect(screen.queryByText(/INC-DEMO-01/i)).toBeNull();
      expect(screen.getByText(/INC-DEMO-02/i)).toBeTruthy();
    });

    it('opens ticket inspector and updates lifecycle status and team assignment', async () => {
      const updatedIncident: IncidentResponseContract = {
        ...mockIncidents[0],
        status: 'RESOLVED',
        municipal_notes: 'Water cleared with pump.',
      };

      vi.spyOn(apiClient, 'updateIncident').mockResolvedValue(updatedIncident);
      const onUpdate = vi.fn();

      render(
        <MunicipalOperationsPanel
          incidents={mockIncidents}
          onRefresh={vi.fn()}
          onUpdateIncident={onUpdate}
        />
      );

      // Click manage on first ticket
      const manageButtons = screen.getAllByText('Manage');
      fireEvent.click(manageButtons[0]);

      expect(screen.getByText(/Ticket Inspector: INC-DEMO-01/i)).toBeTruthy();

      // Change status to RESOLVED (INVESTIGATING allows transition to RESOLVED)
      const statusSelect = screen.getByDisplayValue(/INVESTIGATING \(Current\)/i);
      fireEvent.change(statusSelect, { target: { value: 'RESOLVED' } });

      // Save Updates
      const saveBtn = screen.getByText(/Save Updates/i);
      fireEvent.click(saveBtn);

      await waitFor(() => {
        expect(apiClient.updateIncident).toHaveBeenCalledWith('INC-DEMO-01', {
          status: 'RESOLVED',
        });
        expect(onUpdate).toHaveBeenCalledWith(updatedIncident);
        expect(screen.getByText(/Ticket successfully updated/i)).toBeTruthy();
      });
    });

    it('renders Ticket Inspector modal in document.body via portal with z-[2000] and locks background scrolling', () => {
      expect(document.body.style.overflow).toBe('');

      render(
        <MunicipalOperationsPanel
          incidents={mockIncidents}
          onRefresh={vi.fn()}
          onUpdateIncident={vi.fn()}
        />
      );

      // Open modal
      const manageButtons = screen.getAllByText('Manage');
      fireEvent.click(manageButtons[0]);

      // Verify rendered directly into document.body with z-[2000]
      const modalBackdrop = document.body.querySelector('.fixed.inset-0.z-\\[2000\\]');
      expect(modalBackdrop).not.toBeNull();
      expect(document.body.style.overflow).toBe('hidden');

      // Modal header and content are visible
      expect(screen.getByText(/Ticket Inspector: INC-DEMO-01/i)).toBeTruthy();

      // Close modal via close button
      const closeBtn = screen.getByRole('button', { name: /Close Ticket Inspector/i });
      fireEvent.click(closeBtn);

      // Verify modal is removed and scroll is restored
      expect(screen.queryByText(/Ticket Inspector: INC-DEMO-01/i)).toBeNull();
      expect(document.body.style.overflow).toBe('');
    });

    it('closes modal and restores scrolling on Escape key or backdrop click', () => {
      render(
        <MunicipalOperationsPanel
          incidents={mockIncidents}
          onRefresh={vi.fn()}
          onUpdateIncident={vi.fn()}
        />
      );

      // 1. Test Escape key dismissal
      fireEvent.click(screen.getAllByText('Manage')[0]);
      expect(document.body.style.overflow).toBe('hidden');

      fireEvent.keyDown(window, { key: 'Escape' });
      expect(screen.queryByText(/Ticket Inspector: INC-DEMO-01/i)).toBeNull();
      expect(document.body.style.overflow).toBe('');

      // 2. Test backdrop click dismissal
      fireEvent.click(screen.getAllByText('Manage')[0]);
      expect(document.body.style.overflow).toBe('hidden');

      const modalBackdrop = document.body.querySelector('.fixed.inset-0.z-\\[2000\\]');
      expect(modalBackdrop).not.toBeNull();
      fireEvent.click(modalBackdrop!);

      expect(screen.queryByText(/Ticket Inspector: INC-DEMO-01/i)).toBeNull();
      expect(document.body.style.overflow).toBe('');
    });

    it('triggers onSelectOnMap and closes modal when Locate on GIS Map is clicked', () => {
      const onSelectOnMap = vi.fn();

      render(
        <MunicipalOperationsPanel
          incidents={mockIncidents}
          onRefresh={vi.fn()}
          onSelectOnMap={onSelectOnMap}
          onUpdateIncident={vi.fn()}
        />
      );

      fireEvent.click(screen.getAllByText('Manage')[0]);
      expect(screen.getByText(/Ticket Inspector: INC-DEMO-01/i)).toBeTruthy();

      const locateBtn = screen.getByText(/Locate on GIS Map/i);
      fireEvent.click(locateBtn);

      expect(onSelectOnMap).toHaveBeenCalledWith(mockIncidents[0]);
      expect(screen.queryByText(/Ticket Inspector: INC-DEMO-01/i)).toBeNull();
      expect(document.body.style.overflow).toBe('');
    });

    it('restores document body scroll when unmounted while modal is open', () => {
      const { unmount } = render(
        <MunicipalOperationsPanel
          incidents={mockIncidents}
          onRefresh={vi.fn()}
          onUpdateIncident={vi.fn()}
        />
      );

      fireEvent.click(screen.getAllByText('Manage')[0]);
      expect(document.body.style.overflow).toBe('hidden');

      unmount();
      expect(document.body.style.overflow).toBe('');
      expect(screen.queryByText(/Ticket Inspector: INC-DEMO-01/i)).toBeNull();
    });

    it('does not reopen modal when dismissed even if selectedIncidentId remains populated and incidents array refreshes', () => {
      const onClearSelectedIncident = vi.fn();
      const { rerender } = render(
        <MunicipalOperationsPanel
          incidents={mockIncidents}
          onRefresh={vi.fn()}
          selectedIncidentId="INC-DEMO-01"
          onUpdateIncident={vi.fn()}
          onClearSelectedIncident={onClearSelectedIncident}
        />
      );

      // Modal should open automatically on initial external selection
      expect(screen.getByText(/Ticket Inspector: INC-DEMO-01/i)).toBeTruthy();

      // Dismiss the modal
      const closeBtn = screen.getByRole('button', { name: /Close Ticket Inspector/i });
      fireEvent.click(closeBtn);

      expect(screen.queryByText(/Ticket Inspector: INC-DEMO-01/i)).toBeNull();
      expect(onClearSelectedIncident).toHaveBeenCalled();

      // Simulate background polling: new incidents array reference with same selectedIncidentId still populated
      const refreshedIncidents = mockIncidents.map((inc) => ({ ...inc }));
      rerender(
        <MunicipalOperationsPanel
          incidents={refreshedIncidents}
          onRefresh={vi.fn()}
          selectedIncidentId="INC-DEMO-01"
          onUpdateIncident={vi.fn()}
          onClearSelectedIncident={onClearSelectedIncident}
        />
      );

      // Must NOT reopen automatically after background polling
      expect(screen.queryByText(/Ticket Inspector: INC-DEMO-01/i)).toBeNull();
    });

    it('opens new inspector when a different incident is selected, and reopens same incident when intentionally re-selected', () => {
      const { rerender } = render(
        <MunicipalOperationsPanel
          incidents={mockIncidents}
          onRefresh={vi.fn()}
          selectedIncidentId="INC-DEMO-01"
          onUpdateIncident={vi.fn()}
        />
      );

      // 1. Initial selection opens INC-DEMO-01
      expect(screen.getByText(/Ticket Inspector: INC-DEMO-01/i)).toBeTruthy();

      // Close it
      fireEvent.click(screen.getByRole('button', { name: /Close Ticket Inspector/i }));
      expect(screen.queryByText(/Ticket Inspector: INC-DEMO-01/i)).toBeNull();

      // 2. Select another incident (INC-DEMO-02) -> opens INC-DEMO-02
      rerender(
        <MunicipalOperationsPanel
          incidents={mockIncidents}
          onRefresh={vi.fn()}
          selectedIncidentId="INC-DEMO-02"
          onUpdateIncident={vi.fn()}
        />
      );
      expect(screen.getByText(/Ticket Inspector: INC-DEMO-02/i)).toBeTruthy();

      // Close it
      fireEvent.click(screen.getByRole('button', { name: /Close Ticket Inspector/i }));
      expect(screen.queryByText(/Ticket Inspector: INC-DEMO-02/i)).toBeNull();

      // 3. Intentionally re-select INC-DEMO-01 (e.g. via map click transition through null or different id)
      rerender(
        <MunicipalOperationsPanel
          incidents={mockIncidents}
          onRefresh={vi.fn()}
          selectedIncidentId={null}
          onUpdateIncident={vi.fn()}
        />
      );
      rerender(
        <MunicipalOperationsPanel
          incidents={mockIncidents}
          onRefresh={vi.fn()}
          selectedIncidentId="INC-DEMO-01"
          onUpdateIncident={vi.fn()}
        />
      );
      expect(screen.getByText(/Ticket Inspector: INC-DEMO-01/i)).toBeTruthy();
    });

    it('keeps modal closed after Locate on GIS Map even when selectedIncidentId matches located ticket and incidents refreshes', () => {
      const onSelectOnMap = vi.fn();
      const { rerender } = render(
        <MunicipalOperationsPanel
          incidents={mockIncidents}
          onRefresh={vi.fn()}
          selectedIncidentId="INC-DEMO-01"
          onSelectOnMap={onSelectOnMap}
          onUpdateIncident={vi.fn()}
        />
      );

      expect(screen.getByText(/Ticket Inspector: INC-DEMO-01/i)).toBeTruthy();

      // Click Locate on GIS Map
      const locateBtn = screen.getByText(/Locate on GIS Map/i);
      fireEvent.click(locateBtn);

      expect(onSelectOnMap).toHaveBeenCalledWith(mockIncidents[0]);
      expect(screen.queryByText(/Ticket Inspector: INC-DEMO-01/i)).toBeNull();

      // Simulate parent keeping selectedIncidentId as INC-DEMO-01 and polling refreshing incidents
      const refreshedIncidents = [...mockIncidents];
      rerender(
        <MunicipalOperationsPanel
          incidents={refreshedIncidents}
          onRefresh={vi.fn()}
          selectedIncidentId="INC-DEMO-01"
          onSelectOnMap={onSelectOnMap}
          onUpdateIncident={vi.fn()}
        />
      );

      // Modal must remain closed
      expect(screen.queryByText(/Ticket Inspector: INC-DEMO-01/i)).toBeNull();
    });
  });

  describe('UrbanGisDashboard Integration', () => {
    const mockSystemStatus: SystemStatusContract = {
      system_name: 'DRAIN-X',
      mode: 'HARDWARE',
      operational_state: 'MONITORING',
      uptime_seconds: 120.5,
      active_alerts_count: 0,
      last_heartbeat: new Date().toISOString(),
      latest_readings: {},
      mechanism: {
        state: 'IDLE',
        backup_net_angle_deg: 0,
        tray_height_cm: 0,
        cycle_count: 0,
        current_action: 'Idle',
        elapsed_in_state_s: 0,
        is_jammed: false,
        is_fault: false,
        debris_retained_pct: 0,
      },
    };

    it('switches between Stations Inventory and Municipal Operations tabs', async () => {
      vi.spyOn(apiClient, 'getIncidents').mockResolvedValue(mockIncidents);

      render(
        <UrbanGisDashboard
          systemStatus={mockSystemStatus}
          readings={{}}
          activeAlertsCount={0}
          onNavigateToTwin={vi.fn()}
        />
      );

      // Default tab: Stations Inventory
      expect(screen.getByText(/MONITORING STATIONS INVENTORY/i)).toBeTruthy();

      // Switch to Municipal Operations tab
      const municipalTabBtn = screen.getByText(/MUNICIPAL OPERATIONS & CITIZEN REPORTS/i);
      fireEvent.click(municipalTabBtn);

      await waitFor(() => {
        expect(screen.getByText(/Total Tickets/i)).toBeTruthy();
        expect(screen.getByText(/Active \/ Open/i)).toBeTruthy();
      });
    });

    it('opens CitizenReportModal when REPORT DRAINAGE HAZARD button is clicked', async () => {
      vi.spyOn(apiClient, 'getIncidents').mockResolvedValue(mockIncidents);

      render(
        <UrbanGisDashboard
          systemStatus={mockSystemStatus}
          readings={{}}
          activeAlertsCount={0}
          onNavigateToTwin={vi.fn()}
        />
      );

      const reportHazardBtn = screen.getByText(/REPORT DRAINAGE HAZARD/i);
      fireEvent.click(reportHazardBtn);

      await waitFor(() => {
        expect(screen.getByText(/CITIZEN DRAINAGE INCIDENT REPORT/i)).toBeTruthy();
      });
    });
  });
});
