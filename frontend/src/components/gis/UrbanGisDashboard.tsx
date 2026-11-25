import React, { useState, useMemo, useEffect, useCallback } from 'react';
import {
  GisMonitoringStation,
  GisDrainageChannel,
  GisRiskZone,
  GisIncidentReport,
  GisLayerVisibility,
} from '../../types/gis';
import {
  SystemStatusContract,
  SensorReadingContract,
  AlertSeverity,
  IncidentResponseContract,
} from '../../types/contracts';
import {
  DEMO_STATIONS,
  DEMO_CHANNELS,
  DEMO_RISK_ZONES,
  DEMO_INCIDENTS,
} from './gisDemoData';
import { GisMap } from './GisMap';
import { StationDetailPanel } from './StationDetailPanel';
import { GisLegend } from './GisLegend';
import { CitizenReportModal } from './CitizenReportModal';
import { MunicipalOperationsPanel } from './MunicipalOperationsPanel';
import { apiClient } from '../../api/client';
import { useOptionalAuth } from '../../auth/AuthContext';
import { IncidentStreamClient } from '../../api/incidentStreamClient';
import {
  MapPin,
  Layers,
  Radio,
  ExternalLink,
  PlusCircle,
  Building2,
  Table,
} from 'lucide-react';

export interface UrbanGisDashboardProps {
  systemStatus: SystemStatusContract | null;
  readings: Record<string, SensorReadingContract>;
  activeAlertsCount: number;
  onNavigateToTwin: () => void;
}

export const UrbanGisDashboard: React.FC<UrbanGisDashboardProps> = ({
  systemStatus,
  readings,
  activeAlertsCount,
  onNavigateToTwin,
}) => {
  // Layer Visibility State
  const [visibility, setVisibility] = useState<GisLayerVisibility>({
    stations: true,
    channels: true,
    riskZones: true,
    incidents: true,
  });

  // Use the key-free OpenStreetMap layer by default to avoid CARTO API-key watermarks.
  const [tileProvider, setTileProvider] = useState<'carto_dark' | 'osm_standard'>('osm_standard');

  // Selected Entity State for Inspection Drawer
  const [selectedStation, setSelectedStation] = useState<GisMonitoringStation | null>(null);
  const [selectedChannel, setSelectedChannel] = useState<GisDrainageChannel | null>(null);
  const [selectedRiskZone, setSelectedRiskZone] = useState<GisRiskZone | null>(null);
  const [selectedIncident, setSelectedIncident] = useState<GisIncidentReport | null>(null);

  // Filter for station table
  const [stationFilter, setStationFilter] = useState<'ALL' | 'PHYSICAL' | 'AT_RISK'>('ALL');

  // Active Bottom View Tab
  const [activeBottomTab, setActiveBottomTab] = useState<'STATIONS' | 'MUNICIPAL'>('STATIONS');

  // Live Citizen & Municipal Incidents State
  const [liveIncidents, setLiveIncidents] = useState<IncidentResponseContract[]>([]);
  const [selectedLiveIncidentId, setSelectedLiveIncidentId] = useState<string | null>(null);

  // Citizen Report Modal & Map Picking State
  const [isCitizenModalOpen, setIsCitizenModalOpen] = useState(false);
  const [isPickingOnMap, setIsPickingOnMap] = useState(false);
  const [pickedCoordinates, setPickedCoordinates] = useState<{ lat: number; lng: number } | null>(null);

  // Fetch incidents from backend API
  const fetchIncidents = useCallback(async () => {
    try {
      const data = await apiClient.getIncidents();
      setLiveIncidents(data);
    } catch {
      // Fallback silently if offline or initial boot
    }
  }, []);

  useEffect(() => {
    fetchIncidents();
    const interval = setInterval(fetchIncidents, 6000);
    return () => clearInterval(interval);
  }, [fetchIncidents]);

  // Connect to authoritative incident real-time WebSocket stream when authenticated
  const auth = useOptionalAuth();
  const token = auth?.session?.access_token || null;

  useEffect(() => {
    if (!token) return;

    const stream = new IncidentStreamClient({
      token,
      onEvent: (event) => {
        if (event.incident) {
          setLiveIncidents((prev) => {
            const exists = prev.some((i) => i.id === event.incident!.id);
            if (exists) {
              return prev.map((i) => (i.id === event.incident!.id ? event.incident! : i));
            } else {
              return [event.incident!, ...prev];
            }
          });
        } else {
          fetchIncidents();
        }
      },
      onResyncRequired: () => {
        fetchIncidents();
      },
    });

    stream.connect();

    return () => {
      stream.disconnect();
    };
  }, [token, fetchIncidents]);

  // Handle new incident created
  const handleIncidentCreated = (newIncident: IncidentResponseContract) => {
    setLiveIncidents((prev) => [newIncident, ...prev.filter((i) => i.id !== newIncident.id)]);
    setSelectedLiveIncidentId(newIncident.id);
    setActiveBottomTab('MUNICIPAL');
  };

  // Handle incident update from operations panel
  const handleIncidentUpdated = (updatedIncident: IncidentResponseContract) => {
    setLiveIncidents((prev) =>
      prev.map((i) => (i.id === updatedIncident.id ? updatedIncident : i))
    );
  };

  // Merge live physical telemetry with Demo Stations
  const mergedStations = useMemo<GisMonitoringStation[]>(() => {
    return DEMO_STATIONS.map((st) => {
      if (st.station_id === 'STATION_PROTOTYPE_01') {
        const upReading = readings['US_UPSTREAM_01'];
        const pumpReading = readings['PUMP_INFLOW_01'];
        const currentDepth = upReading ? upReading.value : st.water_depth_cm;
        const discharge = pumpReading ? pumpReading.value : st.discharge_lpm;
        const pred = systemStatus?.active_prediction;

        let riskLevel: AlertSeverity = 'INFO';
        if (currentDepth >= st.critical_depth_cm) {
          riskLevel = 'CRITICAL';
        } else if (currentDepth >= st.critical_depth_cm - 2.0) {
          riskLevel = 'WARNING';
        } else if (pred?.state === 'ESTIMATING' && (pred?.ttc_seconds ?? 999) <= 45.0) {
          riskLevel = 'HIGH';
        }

        return {
          ...st,
          water_depth_cm: currentDepth,
          discharge_lpm: discharge,
          health: upReading?.status || 'OK',
          risk_level: riskLevel,
          prediction_state: pred?.state || 'STABLE',
          ttc_seconds: pred?.ttc_seconds || null,
          active_alerts_count: activeAlertsCount,
          last_updated: upReading?.timestamp || new Date().toISOString(),
          is_demo: false,
        };
      }
      return st;
    });
  }, [readings, systemStatus, activeAlertsCount]);

  // Keep selectedStation synced if prototype updates live
  const activeSelectedStation = useMemo(() => {
    if (!selectedStation) return null;
    return mergedStations.find((s) => s.station_id === selectedStation.station_id) || selectedStation;
  }, [selectedStation, mergedStations]);

  // Handle Selection Handlers (Exclusive selection across types)
  const handleSelectStation = (station: GisMonitoringStation) => {
    setSelectedStation(station);
    setSelectedChannel(null);
    setSelectedRiskZone(null);
    setSelectedIncident(null);
    setSelectedLiveIncidentId(null);
  };

  const handleSelectChannel = (channel: GisDrainageChannel) => {
    setSelectedChannel(channel);
    setSelectedStation(null);
    setSelectedRiskZone(null);
    setSelectedIncident(null);
    setSelectedLiveIncidentId(null);
  };

  const handleSelectRiskZone = (zone: GisRiskZone) => {
    setSelectedRiskZone(zone);
    setSelectedStation(null);
    setSelectedChannel(null);
    setSelectedIncident(null);
    setSelectedLiveIncidentId(null);
  };

  const handleSelectIncident = (incident: GisIncidentReport) => {
    setSelectedIncident(incident);
    setSelectedStation(null);
    setSelectedChannel(null);
    setSelectedRiskZone(null);
    setSelectedLiveIncidentId(null);
  };

  const handleSelectLiveIncident = (liveInc: IncidentResponseContract) => {
    if (selectedLiveIncidentId === liveInc.id) {
      setSelectedLiveIncidentId(null);
      setTimeout(() => {
        setSelectedLiveIncidentId(liveInc.id);
      }, 0);
    } else {
      setSelectedLiveIncidentId(liveInc.id);
    }
    setSelectedIncident(null);
    setSelectedStation(null);
    setSelectedChannel(null);
    setSelectedRiskZone(null);
    setActiveBottomTab('MUNICIPAL');
  };

  const clearSelection = () => {
    setSelectedStation(null);
    setSelectedChannel(null);
    setSelectedRiskZone(null);
    setSelectedIncident(null);
    setSelectedLiveIncidentId(null);
  };

  // Map coordinate click handler for citizen picking mode
  const handleMapClick = (coords: { lat: number; lng: number }) => {
    setPickedCoordinates(coords);
    setIsPickingOnMap(false);
    setIsCitizenModalOpen(true);
  };

  // Filtered station list for bottom overview
  const displayedStations = useMemo(() => {
    if (stationFilter === 'PHYSICAL') {
      return mergedStations.filter((s) => s.type === 'PHYSICAL_PROTOTYPE');
    }
    if (stationFilter === 'AT_RISK') {
      return mergedStations.filter(
        (s) => s.risk_level === 'HIGH' || s.risk_level === 'CRITICAL' || s.risk_level === 'WARNING'
      );
    }
    return mergedStations;
  }, [mergedStations, stationFilter]);

  // Statistics
  const physicalStation = mergedStations.find((s) => s.type === 'PHYSICAL_PROTOTYPE');
  const activeIncidentsCount = useMemo(() => {
    if (liveIncidents.length > 0) {
      return liveIncidents.filter((i) => i.status !== 'RESOLVED' && i.status !== 'REJECTED').length;
    }
    return DEMO_INCIDENTS.filter((i) => i.status !== 'RESOLVED').length;
  }, [liveIncidents]);

  return (
    <div className="space-y-5">
      {/* 1. Top SCADA Header & Actions */}
      <div className="bg-slate-900 border border-slate-800 rounded p-4 shadow-xl">
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-3">
          <div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 shadow-[0_0_8px_rgba(34,211,238,0.8)] animate-pulse" />
              <h2 className="text-sm font-mono font-bold text-slate-100 uppercase tracking-wider flex items-center gap-2">
                <MapPin className="w-4 h-4 text-cyan-400" />
                URBAN FLOOD INTELLIGENCE // GIS MONITORING SYSTEM (GOA)
              </h2>
            </div>
            <p className="text-xs font-mono text-slate-400 mt-1">
              Geospatial drainage monitoring, live citizen incident ticketing, and municipal field response across Panaji basin.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                setIsCitizenModalOpen(true);
                setIsPickingOnMap(false);
              }}
              className="px-3.5 py-1.5 rounded bg-amber-600/90 hover:bg-amber-500 border border-amber-400 text-white font-mono text-xs font-bold flex items-center gap-1.5 transition-colors shadow"
              title="Report flood, waterlogging, or drain blockage"
            >
              <PlusCircle className="w-4 h-4" />
              <span>REPORT DRAINAGE HAZARD</span>
            </button>

            <button
              onClick={onNavigateToTwin}
              className="px-3 py-1.5 rounded bg-cyan-950 hover:bg-cyan-900 border border-cyan-700 text-cyan-300 font-mono text-xs font-bold flex items-center gap-1.5 transition-colors shadow"
            >
              <span>SCADA DIGITAL TWIN</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Disclaimer / Model Distinction Notice */}
        <div className="mt-3 p-2.5 rounded bg-slate-950/80 border border-slate-800 text-[11px] font-mono text-slate-400 flex items-start gap-2">
          <Radio className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
          <span>
            <strong className="text-cyan-300">DATA SOURCE INTEGRATION NOTICE:</strong> Station 01
            (St. Inez Pilot Testbed) is linked directly to live DRAIN-X physical hardware telemetry.
            Citizen reports are submitted live to the municipal operations state store.
            Drainage channels and catchment flood polygons represent Panaji municipal models.
          </span>
        </div>
      </div>

      {/* 2. Operational KPI Summary Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {/* Physical Testbed Station */}
        <div
          onClick={() => physicalStation && handleSelectStation(physicalStation)}
          className="bg-slate-900/90 hover:bg-slate-850 cursor-pointer p-3 rounded border border-cyan-800/60 shadow transition-all"
        >
          <div className="text-[10px] font-mono text-cyan-400 uppercase font-bold flex items-center justify-between">
            <span>PHYSICAL TESTBED FLUME</span>
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
          </div>
          <div className="text-lg font-mono font-bold text-slate-100 mt-1">
            {physicalStation ? `${physicalStation.water_depth_cm.toFixed(1)} cm` : '--'}
          </div>
          <div className="text-[10px] font-mono text-slate-400 flex items-center justify-between mt-0.5">
            <span>Flow: {physicalStation?.discharge_lpm.toFixed(1)} L/m</span>
            <span className="text-cyan-300 underline text-[10px]">Inspect &rarr;</span>
          </div>
        </div>

        {/* Network Stations Count */}
        <div className="bg-slate-900/90 p-3 rounded border border-slate-800 shadow">
          <div className="text-[10px] font-mono text-slate-400 uppercase font-bold">
            MONITORED STATIONS
          </div>
          <div className="text-lg font-mono font-bold text-slate-100 mt-1">
            {mergedStations.length}{' '}
            <span className="text-xs text-slate-400 font-normal">
              (1 Live + {mergedStations.length - 1} Demo)
            </span>
          </div>
          <div className="text-[10px] font-mono text-emerald-400 mt-0.5">
            Panaji Basin &bull; St. Inez
          </div>
        </div>

        {/* Inundation Catchment Risk */}
        <div className="bg-slate-900/90 p-3 rounded border border-slate-800 shadow">
          <div className="text-[10px] font-mono text-slate-400 uppercase font-bold">
            HIGH INUNDATION ZONES
          </div>
          <div className="text-lg font-mono font-bold text-amber-400 mt-1">
            {DEMO_RISK_ZONES.filter((z) => z.risk_level === 'CRITICAL' || z.risk_level === 'HIGH').length}
            <span className="text-xs text-slate-400 font-normal"> / {DEMO_RISK_ZONES.length} modeled</span>
          </div>
          <div className="text-[10px] font-mono text-slate-500 mt-0.5">
            Fontainhas &amp; St. Inez Depressions
          </div>
        </div>

        {/* Citizen Incident Reports */}
        <div
          onClick={() => setActiveBottomTab('MUNICIPAL')}
          className="bg-slate-900/90 hover:bg-slate-850 cursor-pointer p-3 rounded border border-rose-900/60 shadow transition-all"
        >
          <div className="text-[10px] font-mono text-rose-400 uppercase font-bold flex items-center justify-between">
            <span>MUNICIPAL & CITIZEN TICKETS</span>
            <span className="text-[10px] text-cyan-300 underline">View Queue &rarr;</span>
          </div>
          <div className="text-lg font-mono font-bold text-rose-400 mt-1">
            {activeIncidentsCount} Active
            <span className="text-xs text-slate-400 font-normal">
              {' '}({liveIncidents.length > 0 ? liveIncidents.length : DEMO_INCIDENTS.length} total)
            </span>
          </div>
          <div className="text-[10px] font-mono text-slate-500 mt-0.5">
            Real-time citizen &amp; demo field tickets
          </div>
        </div>
      </div>

      {/* 3. Layer Visibility & Map Controls Toolbar */}
      <div className="bg-slate-900/90 border border-slate-800 rounded p-3 text-xs font-mono flex flex-wrap items-center justify-between gap-3 shadow">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-1.5 text-slate-400 uppercase font-bold text-[11px]">
            <Layers className="w-3.5 h-3.5 text-cyan-400" />
            <span>MAP LAYERS:</span>
          </div>

          {/* Stations Toggle */}
          <label className="flex items-center gap-1.5 cursor-pointer text-slate-300 hover:text-white select-none">
            <input
              type="checkbox"
              checked={visibility.stations}
              onChange={(e) => setVisibility({ ...visibility, stations: e.target.checked })}
              className="rounded bg-slate-800 border-slate-700 text-cyan-500 focus:ring-0"
            />
            <span>Monitoring Stations ({mergedStations.length})</span>
          </label>

          {/* Drainage Channels Toggle */}
          <label className="flex items-center gap-1.5 cursor-pointer text-slate-300 hover:text-white select-none">
            <input
              type="checkbox"
              checked={visibility.channels}
              onChange={(e) => setVisibility({ ...visibility, channels: e.target.checked })}
              className="rounded bg-slate-800 border-slate-700 text-sky-500 focus:ring-0"
            />
            <span>Drainage Network ({DEMO_CHANNELS.length})</span>
          </label>

          {/* Inundation Risk Zones Toggle */}
          <label className="flex items-center gap-1.5 cursor-pointer text-slate-300 hover:text-white select-none">
            <input
              type="checkbox"
              checked={visibility.riskZones}
              onChange={(e) => setVisibility({ ...visibility, riskZones: e.target.checked })}
              className="rounded bg-slate-800 border-slate-700 text-amber-500 focus:ring-0"
            />
            <span>Flood Risk Polygons ({DEMO_RISK_ZONES.length})</span>
          </label>

          {/* Citizen Incidents Toggle */}
          <label className="flex items-center gap-1.5 cursor-pointer text-slate-300 hover:text-white select-none">
            <input
              type="checkbox"
              checked={visibility.incidents}
              onChange={(e) => setVisibility({ ...visibility, incidents: e.target.checked })}
              className="rounded bg-slate-800 border-slate-700 text-rose-500 focus:ring-0"
            />
            <span>Incidents ({liveIncidents.length > 0 ? liveIncidents.length : DEMO_INCIDENTS.length})</span>
          </label>
        </div>

        {/* Tile Provider Switcher */}
        <div className="flex items-center gap-1.5 border border-slate-800 rounded bg-slate-950 p-1">
          <button
            onClick={() => setTileProvider('carto_dark')}
            className={`px-2 py-0.5 rounded text-[11px] transition-colors ${
              tileProvider === 'carto_dark'
                ? 'bg-cyan-950 text-cyan-300 font-bold border border-cyan-800'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            CARTO DARK
          </button>
          <button
            onClick={() => setTileProvider('osm_standard')}
            className={`px-2 py-0.5 rounded text-[11px] transition-colors ${
              tileProvider === 'osm_standard'
                ? 'bg-cyan-950 text-cyan-300 font-bold border border-cyan-800'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            OSM STANDARD
          </button>
        </div>
      </div>

      {/* 4. Main Interactive Map & Side Inspector Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Left/Center: Primary Leaflet Map Container */}
        <div className="lg:col-span-2 relative min-h-[520px]">
          <GisMap
            stations={mergedStations}
            channels={DEMO_CHANNELS}
            riskZones={DEMO_RISK_ZONES}
            incidents={DEMO_INCIDENTS}
            liveIncidents={liveIncidents}
            visibility={visibility}
            tileProvider={tileProvider}
            selectedStationId={activeSelectedStation?.station_id}
            selectedIncidentId={selectedLiveIncidentId || selectedIncident?.incident_id}
            isPickingLocation={isPickingOnMap}
            onMapClick={handleMapClick}
            onSelectStation={handleSelectStation}
            onSelectChannel={handleSelectChannel}
            onSelectRiskZone={handleSelectRiskZone}
            onSelectIncident={handleSelectIncident}
            onSelectLiveIncident={handleSelectLiveIncident}
          />

          {/* Floating Collapsible Legend */}
          <div className="absolute top-3 right-3 z-[1000]">
            <GisLegend />
          </div>
        </div>

        {/* Right: Technical Inspector Panel */}
        <div className="lg:col-span-1 space-y-4">
          <StationDetailPanel
            selectedStation={activeSelectedStation}
            selectedChannel={selectedChannel}
            selectedRiskZone={selectedRiskZone}
            selectedIncident={selectedIncident}
            onClose={clearSelection}
            onNavigateToTwin={onNavigateToTwin}
          />
        </div>
      </div>

      {/* 5. Bottom Tabs: Stations Telemetry vs Municipal Operations Panel */}
      <div className="bg-slate-900 border border-slate-800 rounded p-4 shadow-xl font-mono text-xs">
        {/* Tab Headers */}
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 mb-4 pb-3 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setActiveBottomTab('STATIONS')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded transition ${
                activeBottomTab === 'STATIONS'
                  ? 'bg-cyan-950 text-cyan-300 font-bold border border-cyan-700'
                  : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              <Table className="w-4 h-4" />
              <span>MONITORING STATIONS INVENTORY ({mergedStations.length})</span>
            </button>

            <button
              onClick={() => setActiveBottomTab('MUNICIPAL')}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded transition ${
                activeBottomTab === 'MUNICIPAL'
                  ? 'bg-indigo-950 text-indigo-300 font-bold border border-indigo-700'
                  : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
              }`}
            >
              <Building2 className="w-4 h-4" />
              <span>MUNICIPAL OPERATIONS & CITIZEN REPORTS ({liveIncidents.length})</span>
            </button>
          </div>

          {activeBottomTab === 'STATIONS' && (
            /* Filter Tabs for Stations */
            <div className="flex items-center gap-1 bg-slate-950 p-1 rounded border border-slate-800 text-[11px]">
              <button
                onClick={() => setStationFilter('ALL')}
                className={`px-2 py-0.5 rounded transition-colors ${
                  stationFilter === 'ALL'
                    ? 'bg-slate-800 text-slate-200 font-bold'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                ALL
              </button>
              <button
                onClick={() => setStationFilter('PHYSICAL')}
                className={`px-2 py-0.5 rounded transition-colors ${
                  stationFilter === 'PHYSICAL'
                    ? 'bg-cyan-950 text-cyan-300 font-bold border border-cyan-800'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                PHYSICAL ONLY
              </button>
              <button
                onClick={() => setStationFilter('AT_RISK')}
                className={`px-2 py-0.5 rounded transition-colors ${
                  stationFilter === 'AT_RISK'
                    ? 'bg-amber-950 text-amber-300 font-bold border border-amber-800'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                AT RISK / ELEVATED
              </button>
            </div>
          )}
        </div>

        {/* Tab 1: Stations Inventory Table */}
        {activeBottomTab === 'STATIONS' && (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-[10px] text-slate-400 uppercase">
                  <th className="py-2 px-2">Station</th>
                  <th className="py-2 px-2">Type / Source</th>
                  <th className="py-2 px-2">Depth (h1)</th>
                  <th className="py-2 px-2">Discharge</th>
                  <th className="py-2 px-2">TTC Prediction</th>
                  <th className="py-2 px-2">Risk Status</th>
                  <th className="py-2 px-2 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {displayedStations.map((st) => {
                  const isPhysical = st.type === 'PHYSICAL_PROTOTYPE';
                  const isSelected = activeSelectedStation?.station_id === st.station_id;

                  return (
                    <tr
                      key={st.station_id}
                      className={`hover:bg-slate-800/50 cursor-pointer transition-colors ${
                        isSelected ? 'bg-cyan-950/30' : ''
                      }`}
                      onClick={() => handleSelectStation(st)}
                    >
                      <td className="py-2 px-2 font-bold text-slate-200">
                        <div>{st.name}</div>
                        <div className="text-[10px] text-slate-500 font-normal">{st.location_name}</div>
                      </td>
                      <td className="py-2 px-2">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                            isPhysical
                              ? 'bg-cyan-950 text-cyan-300 border border-cyan-700'
                              : 'bg-slate-800 text-slate-400 border border-slate-700'
                          }`}
                        >
                          {isPhysical ? 'PHYSICAL TESTBED' : 'SIMULATED DEMO'}
                        </span>
                      </td>
                      <td className="py-2 px-2">
                        <span
                          className={`font-bold ${
                            st.water_depth_cm >= st.critical_depth_cm
                              ? 'text-rose-400'
                              : st.water_depth_cm >= st.critical_depth_cm - 2.0
                              ? 'text-amber-400'
                              : 'text-slate-200'
                          }`}
                        >
                          {st.water_depth_cm.toFixed(1)} cm
                        </span>
                      </td>
                      <td className="py-2 px-2 text-slate-300">{st.discharge_lpm.toFixed(1)} L/min</td>
                      <td className="py-2 px-2">
                        {st.ttc_seconds !== null && st.ttc_seconds !== undefined ? (
                          <span className="text-amber-300 font-bold">{st.ttc_seconds.toFixed(0)}s</span>
                        ) : (
                          <span className="text-slate-500">STABLE</span>
                        )}
                      </td>
                      <td className="py-2 px-2">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                            st.risk_level === 'CRITICAL'
                              ? 'bg-rose-950 text-rose-300 border border-rose-800'
                              : st.risk_level === 'HIGH'
                              ? 'bg-orange-950 text-orange-300 border border-orange-800'
                              : st.risk_level === 'WARNING'
                              ? 'bg-amber-950 text-amber-300 border border-amber-800'
                              : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                          }`}
                        >
                          {st.risk_level}
                        </span>
                      </td>
                      <td className="py-2 px-2 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleSelectStation(st);
                          }}
                          className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px]"
                        >
                          Locate
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Tab 2: Municipal Operations & Citizen Reports Panel */}
        {activeBottomTab === 'MUNICIPAL' && (
          <MunicipalOperationsPanel
            incidents={liveIncidents}
            onRefresh={fetchIncidents}
            selectedIncidentId={selectedLiveIncidentId}
            onUpdateIncident={handleIncidentUpdated}
            onSelectOnMap={(ticket) => {
              setSelectedLiveIncidentId(ticket.id);
            }}
            onClearSelectedIncident={() => {
              setSelectedLiveIncidentId(null);
            }}
          />
        )}
      </div>

      {/* Citizen Reporting Modal */}
      <CitizenReportModal
        isOpen={isCitizenModalOpen}
        onClose={() => setIsCitizenModalOpen(false)}
        onIncidentCreated={handleIncidentCreated}
        selectedCoordinates={pickedCoordinates}
        isPickingOnMap={isPickingOnMap}
        onToggleMapPick={(active) => {
          setIsPickingOnMap(active);
          if (active) {
            setIsCitizenModalOpen(false); // Close modal temporarily to allow clicking on the map
          }
        }}
      />
    </div>
  );
};
