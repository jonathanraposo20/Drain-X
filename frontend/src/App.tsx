import React, { useEffect, useState, useCallback, useRef } from 'react';
import { Header } from './components/Header';
import { DigitalTwin } from './components/DigitalTwin';
import { ScenarioControls } from './components/ScenarioControls';
import { BenchmarkingPanel } from './components/BenchmarkingPanel';
import { LiveTelemetryTable } from './components/LiveTelemetryTable';
import { AlertsPanel } from './components/AlertsPanel';
import { TelemetrySimulator } from './components/TelemetrySimulator';
import { UrbanGisDashboard } from './components/gis/UrbanGisDashboard';
import { HistoricalPlaybackDashboard } from './components/playback/HistoricalPlaybackDashboard';
import { MunicipalOperationsDashboard } from './components/municipal/MunicipalOperationsDashboard';
import {
  apiClient,
  SimulationStateResponse,
  TelemetryStreamClient,
  isReadingNewer,
} from './api/client';
import {
  SensorReadingContract,
  AlertContract,
  StreamConnectionStatus,
} from './types/contracts';

import { useAuth } from './auth/AuthContext';
import { LoginPanel } from './auth/LoginPanel';

export const App: React.FC = () => {
  const { session, user, role, loading, signOut } = useAuth();
  const [simState, setSimState] = useState<SimulationStateResponse | null>(null);
  const [readings, setReadings] = useState<Record<string, SensorReadingContract>>({});
  const [alerts, setAlerts] = useState<AlertContract[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isTogglingMode, setIsTogglingMode] = useState(false);
  const [resolvingAlertId, setResolvingAlertId] = useState<string | null>(null);
  const [dashboardView, setDashboardView] = useState<'SCADA_TWIN' | 'HISTORICAL_PLAYBACK' | 'GIS_FLOOD_MAP' | 'MUNICIPAL_OPERATIONS'>('SCADA_TWIN');
  const [streamStatus, setStreamStatus] = useState<StreamConnectionStatus>('DISCONNECTED');
  const [lastEventTime, setLastEventTime] = useState<Date | null>(null);
  const [dataFreshnessSec, setDataFreshnessSec] = useState<number | null>(null);

  const streamClientRef = useRef<TelemetryStreamClient | null>(null);

  // Background HTTP fetch for simulation analytics and alerts
  const fetchSimulationAndAlerts = useCallback(async () => {
    try {
      const [simRes, alertsRes] = await Promise.all([
        apiClient.getSimulationState(),
        apiClient.getAlerts(true),
      ]);
      setSimState(simRes);
      setAlerts(alertsRes || []);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to connect to backend');
    } finally {
      setIsLoading(false);
    }
  }, []);

  // HTTP Telemetry fallback query
  const fetchHttpTelemetry = useCallback(async () => {
    try {
      const telemetryRes = await apiClient.getLatestTelemetry();
      if (telemetryRes?.readings) {
        setReadings((prev) => ({
          ...prev,
          ...telemetryRes.readings,
        }));
        setLastEventTime(new Date());
      }
    } catch {
      // Ignored if handled elsewhere
    }
  }, []);

  // Complete fetch on manual reload
  const fetchData = useCallback(async () => {
    await Promise.all([fetchSimulationAndAlerts(), fetchHttpTelemetry()]);
  }, [fetchSimulationAndAlerts, fetchHttpTelemetry]);

  // Real-time WebSocket Stream Subscription
  useEffect(() => {
    const client = new TelemetryStreamClient({
      onInit: (initMsg) => {
        if (initMsg.latest_snapshot) {
          setReadings((prev) => ({
            ...prev,
            ...initMsg.latest_snapshot,
          }));
        }
        setLastEventTime(new Date());
        setIsLoading(false);
        setError(null);
      },
      onTelemetry: (reading) => {
        setReadings((prev) => {
          const existing = prev[reading.sensor_id];
          if (!isReadingNewer(existing, reading)) {
            return prev; // Discard stale/out-of-order reading
          }
          return {
            ...prev,
            [reading.sensor_id]: reading,
          };
        });
        setLastEventTime(new Date());
        setIsLoading(false);
      },
      onStatusChange: (status) => {
        setStreamStatus(status);
        if (status === 'POLLING_FALLBACK' || status === 'DISCONNECTED') {
          // Immediately trigger HTTP poll when WebSocket stream drops
          fetchHttpTelemetry();
        }
      },
      onError: () => {
        // Safe warning
      },
    });

    streamClientRef.current = client;
    client.connect();

    // Initial HTTP state sync
    fetchData();

    return () => {
      client.disconnect();
      streamClientRef.current = null;
    };
  }, [fetchData, fetchHttpTelemetry]);

  // Dynamic Polling Management:
  // - When streaming (CONNECTED): only poll simulation/alerts every 3.5s (telemetry is pushed in real-time)
  // - When disconnected or falling back: poll full telemetry + simulation every 1.5s
  useEffect(() => {
    const intervalMs = streamStatus === 'CONNECTED' ? 3500 : 1500;
    const interval = setInterval(() => {
      fetchSimulationAndAlerts();
      if (streamStatus !== 'CONNECTED') {
        fetchHttpTelemetry();
      }
    }, intervalMs);

    return () => clearInterval(interval);
  }, [streamStatus, fetchSimulationAndAlerts, fetchHttpTelemetry]);

  // Telemetry Freshness Tracker (1-second tick)
  useEffect(() => {
    const timer = setInterval(() => {
      if (lastEventTime) {
        setDataFreshnessSec(Math.max(0, (Date.now() - lastEventTime.getTime()) / 1000));
      }
    }, 1000);
    return () => clearInterval(timer);
  }, [lastEventTime]);

  const handleToggleMode = async () => {
    if (!simState?.system) return;
    setIsTogglingMode(true);
    try {
      const nextMode = simState.system.mode === 'SIMULATION' ? 'HARDWARE' : 'SIMULATION';
      await apiClient.setMode(nextMode);
      await fetchData();
    } catch (err) {
      alert(`Failed to switch mode: ${err instanceof Error ? err.message : 'Unknown error'}`);
    } finally {
      setIsTogglingMode(false);
    }
  };

  const handleResolveAlert = async (alertId: string) => {
    setResolvingAlertId(alertId);
    try {
      await apiClient.resolveAlert(alertId);
      await fetchData();
    } catch (err) {
      alert(`Failed to resolve alert: ${err instanceof Error ? err.message : 'Unknown error'}`);
    } finally {
      setResolvingAlertId(null);
    }
  };

  // Derive display values for Digital Twin
  const upstreamDepth = readings['US_UPSTREAM_01']?.value ?? 4.8;
  const weirHead = readings['US_WEIR_02']?.value ?? 1.2;
  const pumpInflow = readings['PUMP_INFLOW_01']?.value ?? readings['FS_FLUME_01']?.value ?? 5.0;

  const hardwareValidationStage =
    (readings['US_UPSTREAM_01']?.metadata?.validation_stage as string) ||
    (readings['FS_FLUME_01']?.metadata?.validation_stage as string) ||
    null;

  return (
    <div className="min-h-screen bg-[#080c16] text-slate-100 flex flex-col font-sans bg-scada-grid">
      <Header
        mode={simState?.system.mode || 'SIMULATION'}
        operationalState={simState?.system.operational_state || 'MONITORING'}
        activeAlertsCount={alerts.length}
        onToggleMode={handleToggleMode}
        isToggling={isTogglingMode}
        activeView={dashboardView}
        onChangeView={setDashboardView}
        streamStatus={streamStatus}
        dataFreshnessSec={dataFreshnessSec}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-3 sm:px-6 py-5">
        {/* Connection Failure Diagnostic Banner */}
        {error && (
          <div className="mb-5 p-3 rounded bg-rose-950/60 border border-rose-800 text-rose-300 font-mono text-xs flex items-center justify-between shadow-lg">
            <span>[BUS_DISCONNECT] Communication error with FastAPI server: {error}</span>
            <button
              onClick={fetchData}
              className="px-2.5 py-1 bg-rose-900 hover:bg-rose-800 text-rose-100 font-bold rounded text-[11px] border border-rose-700"
            >
              RECONNECT
            </button>
          </div>
        )}

        {/* Dynamic View Switch: GIS Map vs Historical Playback vs Municipal Queue vs SCADA Twin */}
       
{dashboardView === 'MUNICIPAL_OPERATIONS' ? (
  loading ? (
    <div className="p-8 text-center text-slate-400">
      Checking authentication...
    </div>
  ) : !session ? (
    <LoginPanel />
  ) : role !== 'municipality' && role !== 'admin' ? (
    <div className="p-8 text-center">
      <h2 className="text-xl font-bold text-red-400">
        Access Denied
      </h2>
      <p className="text-slate-400 mt-2">
        Your account does not have municipal permissions.
      </p>
      <button
        onClick={() => signOut()}
        className="mt-4 px-4 py-2 rounded-lg bg-slate-800 text-white hover:bg-slate-700"
      >
        Sign Out
      </button>
    </div>
  ) : (
    <div>
      <div className="flex justify-end items-center gap-3 mb-4 text-sm text-slate-400">
        <span>{user?.email} · {role}</span>
        <button
          onClick={() => signOut()}
          className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-white"
        >
          Sign Out
        </button>
      </div>
      <MunicipalOperationsDashboard />
    </div>
  )

        ) : dashboardView === 'GIS_FLOOD_MAP' ? (
          <UrbanGisDashboard
            systemStatus={simState?.system || null}
            readings={readings}
            activeAlertsCount={alerts.length}
            onNavigateToTwin={() => setDashboardView('SCADA_TWIN')}
          />
        ) : dashboardView === 'HISTORICAL_PLAYBACK' ? (
          <HistoricalPlaybackDashboard
            onReturnToLive={() => setDashboardView('SCADA_TWIN')}
          />
        ) : (
          <>
            {/* Centerpiece: Interactive SVG Digital Twin */}
            {simState && (
              <DigitalTwin
                upstreamDepth={upstreamDepth}
                weirHead={weirHead}
                pumpInflow={pumpInflow}
                mechanism={simState.mechanism}
                blockage={simState.blockage}
                prediction={simState.prediction}
                mode={simState.system.mode}
                gateDirective={simState.system.active_gate_directive}
                readings={readings}
                activeAlertsCount={alerts.length}
                hardwareValidationStage={hardwareValidationStage}
              />
            )}

            {/* Operator Console: Scenario Simulation & Overrides */}
            <ScenarioControls
              isRunning={simState?.is_running || false}
              activeScenario={simState?.active_scenario || null}
              onStateChanged={fetchData}
            />

            {/* Comparative Benchmarking Panel */}
            <BenchmarkingPanel benchmark={simState?.benchmark || null} />

            {/* Telemetry Ingest Stream and Active Diagnostics */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
              <div className="lg:col-span-2">
                <LiveTelemetryTable
                  readings={readings}
                  isLoading={isLoading}
                  error={error}
                  onRefresh={fetchData}
                  streamStatus={streamStatus}
                />
              </div>
              <div className="lg:col-span-1">
                <AlertsPanel
                  alerts={alerts}
                  onResolve={handleResolveAlert}
                  isResolving={resolvingAlertId}
                />
              </div>
            </div>

            {/* Protocol Ingestion Testbed */}
            <TelemetrySimulator onReadingIngested={fetchData} />
          </>
        )}
      </main>

      <footer className="bg-slate-900 border-t border-slate-800 py-3 text-center text-xs font-mono text-slate-500">
        DRAIN-X &bull; SCADA DIGITAL TWIN &bull; AUTOMATED PREDICTIVE DRAINAGE INTELLIGENCE &bull; PROVISIONAL SIMULATION
      </footer>
    </div>
  );
};

export default App;
