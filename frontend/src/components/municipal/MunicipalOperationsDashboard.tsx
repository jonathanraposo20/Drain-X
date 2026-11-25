import React, { useState, useEffect, useCallback } from 'react';
import {
  ClipboardList,
  AlertTriangle,
  Users,
  CheckCircle2,
  RefreshCw,
  Search,
  MapPin,
  Clock,
  ShieldAlert,
  Building2,
  Camera,
  X,
  Eye,
  AlertCircle,
  ChevronLeft,
  ChevronRight,
  Check,
  UserCheck,
  UserX,
  History,
  Send,
  AlertOctagon,
  CornerDownRight,
} from 'lucide-react';
import {
  IncidentResponseContract,
  IncidentStatus,
  IncidentSeverity,
  MunicipalKpiResponseContract,
  MunicipalQueueResponseContract,
  FieldTeamContract,
  IncidentAuditContract,
} from '../../types/contracts';
import { apiClient, ApiError } from '../../api/client';
import { useOptionalAuth } from '../../auth/AuthContext';
import { IncidentStreamClient } from '../../api/incidentStreamClient';

export const MUNICIPAL_FIELD_CREWS = [
  'Team Alpha — St. Inez Drainage Crew',
  'Team Beta — Patto Rapid Response',
  'Team Gamma — Fontainhas Heritage Maintenance',
  'Team Delta — Miramar Outfall Sluice Unit',
];

export const MunicipalOperationsDashboard: React.FC = () => {
  // KPIs & Queue Data
  const [kpis, setKpis] = useState<MunicipalKpiResponseContract | null>(null);
  const [queue, setQueue] = useState<MunicipalQueueResponseContract | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isUnauthorized, setIsUnauthorized] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  // Filters & Pagination State
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [assignmentFilter, setAssignmentFilter] = useState<string>('ALL');
  const [sourceFilter, setSourceFilter] = useState<string>('ALL');
  const [currentPage, setCurrentPage] = useState(0);
  const pageSize = 15;

  // Selected Incident Inspection Drawer & Triage State
  const [inspectedIncident, setInspectedIncident] = useState<IncidentResponseContract | null>(null);
  const [previewPhotoUrl, setPreviewPhotoUrl] = useState<string | null>(null);
  const [fieldTeams, setFieldTeams] = useState<FieldTeamContract[]>([]);
  const [incidentAudits, setIncidentAudits] = useState<IncidentAuditContract[]>([]);
  const [isLoadingAudits, setIsLoadingAudits] = useState(false);

  // Action / Mutation State
  const [isActionPending, setIsActionPending] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  // Action Inputs
  const [verifyNotes, setVerifyNotes] = useState('');
  const [verifySeverity, setVerifySeverity] = useState<IncidentSeverity>('MEDIUM');
  const [selectedAssignTeam, setSelectedAssignTeam] = useState<string>('');
  const [assignReason, setAssignReason] = useState<string>('');
  const [selectedReassignTeam, setSelectedReassignTeam] = useState<string>('');
  const [reassignReason, setReassignReason] = useState<string>('');
  const [unassignReason, setUnassignReason] = useState<string>('');
  const [rejectReason, setRejectReason] = useState<string>('');
  const [isConfirmingReject, setIsConfirmingReject] = useState(false);

  // Helper for coordinate verification and display integrity
  const formatCoordinates = (
    lat?: number | null,
    lng?: number | null,
    source?: string | null
  ): { text: string; isUnavailable: boolean; isSimulated: boolean } => {
    if (lat === null || lat === undefined || lng === null || lng === undefined || isNaN(lat) || isNaN(lng)) {
      return { text: 'Location unavailable', isUnavailable: true, isSimulated: false };
    }
    // Null island / unrecorded coordinate check: (0,0)
    if (Math.abs(lat) < 0.0001 && Math.abs(lng) < 0.0001) {
      return { text: 'Location unavailable', isUnavailable: true, isSimulated: false };
    }
    // Geographic boundary check
    if (lat < -90 || lat > 90 || lng < -180 || lng > 180) {
      return { text: 'Location unavailable', isUnavailable: true, isSimulated: false };
    }
    const isSimulated = source === 'DEMO';
    const base = `${lat.toFixed(4)}, ${lng.toFixed(4)}`;
    return {
      text: isSimulated ? `${base} (Simulated)` : base,
      isUnavailable: false,
      isSimulated,
    };
  };

  // Helper for data source transparency
  const getSourceBadge = (source?: string | null) => {
    switch (source) {
      case 'DEMO':
        return (
          <span className="px-1.5 py-0.5 rounded text-[10px] font-bold border bg-purple-950/90 text-purple-300 border-purple-600">
            [DEMO SEED]
          </span>
        );
      case 'SENSOR':
        return (
          <span className="px-1.5 py-0.5 rounded text-[10px] font-bold border bg-cyan-950/90 text-cyan-300 border-cyan-600">
            [SENSOR]
          </span>
        );
      case 'CITIZEN':
      default:
        return (
          <span className="px-1.5 py-0.5 rounded text-[10px] font-bold border bg-emerald-950/90 text-emerald-300 border-emerald-600">
            [CITIZEN]
          </span>
        );
    }
  };

  // Load KPIs and Queue from Authoritative Backend
  const loadDashboardData = useCallback(async (isManualRefresh = false) => {
    if (isManualRefresh) {
      setIsRefreshing(true);
    } else {
      setIsLoading(true);
    }
    setErrorMessage(null);
    setIsUnauthorized(false);

    try {
      // 1. Fetch Authoritative Server-Side KPIs
      let kpiData: MunicipalKpiResponseContract | null = null;
      try {
        kpiData = await apiClient.getMunicipalKpis();
        setKpis(kpiData);
      } catch (err) {
        if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
          setIsUnauthorized(true);
          setErrorMessage(err.message || 'Access denied: Municipal or administrator authorization required.');
          setIsLoading(false);
          setIsRefreshing(false);
          return;
        }
        throw err;
      }

      // 2. Fetch Filtered Operational Queue
      const queueData = await apiClient.getMunicipalQueue({
        status: statusFilter !== 'ALL' ? statusFilter : undefined,
        severity: severityFilter !== 'ALL' ? severityFilter : undefined,
        category: categoryFilter !== 'ALL' ? categoryFilter : undefined,
        assigned_to: assignmentFilter !== 'ALL' ? assignmentFilter : undefined,
        source: sourceFilter !== 'ALL' ? sourceFilter : undefined,
        search: searchQuery.trim() || undefined,
        limit: pageSize,
        offset: currentPage * pageSize,
      });

      setQueue(queueData);
      setLastUpdated(new Date());
    } catch (err) {
      if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
        setIsUnauthorized(true);
        setErrorMessage(err.message || 'Access denied: Municipal or administrator authorization required.');
      } else {
        const msg = err instanceof Error ? err.message : 'Failed to retrieve municipal dashboard data';
        setErrorMessage(msg);
      }
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  }, [statusFilter, severityFilter, categoryFilter, assignmentFilter, sourceFilter, searchQuery, currentPage, pageSize]);

  // Initial & Filter change trigger
  useEffect(() => {
    loadDashboardData();
  }, [loadDashboardData]);

  // Connect to authoritative incident real-time WebSocket stream when authenticated
  const auth = useOptionalAuth();
  const token = auth?.session?.access_token || null;

  useEffect(() => {
    if (!token) return;

    const stream = new IncidentStreamClient({
      token,
      onEvent: () => {
        loadDashboardData(true);
      },
      onResyncRequired: () => {
        loadDashboardData(true);
      },
    });

    stream.connect();

    return () => {
      stream.disconnect();
    };
  }, [token, loadDashboardData]);

  const handleClearFilters = () => {
    setSearchQuery('');
    setStatusFilter('ALL');
    setSeverityFilter('ALL');
    setCategoryFilter('ALL');
    setAssignmentFilter('ALL');
    setSourceFilter('ALL');
    setCurrentPage(0);
  };

  // Fetch registered field teams on mount
  useEffect(() => {
    apiClient
      .getFieldTeams()
      .then((teams) => {
        setFieldTeams(teams);
        if (teams.length > 0) {
          setSelectedAssignTeam(teams[0].name);
          setSelectedReassignTeam(teams[0].name);
        }
      })
      .catch(() => {
        setFieldTeams(
          MUNICIPAL_FIELD_CREWS.map((name, i) => ({
            team_id: `TEAM-${String.fromCharCode(65 + i)}`,
            name,
            zone: 'Panaji',
            is_active: true,
            capacity: 4,
          }))
        );
      });
  }, []);

  const loadIncidentAudits = useCallback(async (incidentId: string) => {
    setIsLoadingAudits(true);
    try {
      const audits = await apiClient.getIncidentAudits(incidentId);
      setIncidentAudits(audits);
    } catch {
      setIncidentAudits([]);
    } finally {
      setIsLoadingAudits(false);
    }
  }, []);

  const openInspectionDrawer = (incident: IncidentResponseContract) => {
    setInspectedIncident(incident);
    setVerifySeverity(incident.severity);
    setVerifyNotes(incident.municipal_notes || '');
    setActionError(null);
    setActionSuccess(null);
    setIsConfirmingReject(false);
    setRejectReason('');
    setUnassignReason('');
    setAssignReason('');
    setReassignReason('');
    if (fieldTeams.length > 0) {
      // Pick first team not matching existing
      const otherTeam = fieldTeams.find((t) => t.name !== incident.assigned_to) || fieldTeams[0];
      setSelectedAssignTeam(fieldTeams[0].name);
      setSelectedReassignTeam(otherTeam.name);
    }
    loadIncidentAudits(incident.id);
  };

  const handleVerify = async () => {
    if (!inspectedIncident) return;
    setIsActionPending(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      const updated = await apiClient.verifyIncident(inspectedIncident.id, {
        severity: verifySeverity,
        notes: verifyNotes.trim() || undefined,
      });
      setInspectedIncident(updated);
      setActionSuccess(`Incident ${updated.id} verified and updated.`);
      loadDashboardData();
      loadIncidentAudits(updated.id);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Verification failed.');
    } finally {
      setIsActionPending(false);
    }
  };

  const handleAssign = async () => {
    if (!inspectedIncident || !selectedAssignTeam) return;
    setIsActionPending(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      const updated = await apiClient.assignIncident(inspectedIncident.id, {
        assigned_to: selectedAssignTeam,
        reason: assignReason.trim() || undefined,
      });
      setInspectedIncident(updated);
      setActionSuccess(`Assigned to ${selectedAssignTeam}.`);
      setAssignReason('');
      loadDashboardData();
      loadIncidentAudits(updated.id);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Assignment failed.');
    } finally {
      setIsActionPending(false);
    }
  };

  const handleReassign = async () => {
    if (!inspectedIncident || !selectedReassignTeam || !reassignReason.trim()) {
      setActionError('Reassignment requires an explicit operational reason.');
      return;
    }
    setIsActionPending(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      const updated = await apiClient.reassignIncident(inspectedIncident.id, {
        assigned_to: selectedReassignTeam,
        reason: reassignReason.trim(),
      });
      setInspectedIncident(updated);
      setActionSuccess(`Reassigned to ${selectedReassignTeam}.`);
      setReassignReason('');
      loadDashboardData();
      loadIncidentAudits(updated.id);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Reassignment failed.');
    } finally {
      setIsActionPending(false);
    }
  };

  const handleUnassign = async () => {
    if (!inspectedIncident || !unassignReason.trim()) {
      setActionError('Unassignment requires an explicit operational reason.');
      return;
    }
    setIsActionPending(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      const updated = await apiClient.unassignIncident(inspectedIncident.id, {
        reason: unassignReason.trim(),
      });
      setInspectedIncident(updated);
      setActionSuccess(`Crew assignment removed. Incident reverted to VERIFIED.`);
      setUnassignReason('');
      loadDashboardData();
      loadIncidentAudits(updated.id);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Unassignment failed.');
    } finally {
      setIsActionPending(false);
    }
  };

  const handleReject = async () => {
    if (!inspectedIncident || !rejectReason.trim()) {
      setActionError('Rejection requires an explicit operational reason.');
      return;
    }
    setIsActionPending(true);
    setActionError(null);
    setActionSuccess(null);
    try {
      const updated = await apiClient.rejectIncident(inspectedIncident.id, {
        reason: rejectReason.trim(),
      });
      setInspectedIncident(updated);
      setActionSuccess(`Incident ${updated.id} rejected.`);
      setIsConfirmingReject(false);
      setRejectReason('');
      loadDashboardData();
      loadIncidentAudits(updated.id);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Rejection failed.');
    } finally {
      setIsActionPending(false);
    }
  };

  // Severity style helper with accessible high-contrast text and border
  const getSeverityBadge = (sev: IncidentSeverity) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-rose-950/90 text-rose-300 border-rose-600 font-bold';
      case 'HIGH':
        return 'bg-orange-950/90 text-orange-300 border-orange-600 font-bold';
      case 'MEDIUM':
        return 'bg-amber-950/90 text-amber-300 border-amber-600 font-semibold';
      case 'LOW':
      default:
        return 'bg-slate-800 text-slate-300 border-slate-600';
    }
  };

  // Status style helper
  const getStatusBadge = (st: IncidentStatus) => {
    switch (st) {
      case 'REPORTED':
        return 'bg-blue-950 text-blue-300 border-blue-600';
      case 'VERIFIED':
        return 'bg-purple-950 text-purple-300 border-purple-600';
      case 'ASSIGNED':
        return 'bg-indigo-950 text-indigo-300 border-indigo-600';
      case 'INVESTIGATING':
        return 'bg-amber-950 text-amber-300 border-amber-500';
      case 'RESOLVED':
        return 'bg-emerald-950 text-emerald-300 border-emerald-500';
      case 'REJECTED':
        return 'bg-slate-900 text-slate-400 border-slate-700';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-600';
    }
  };

  const totalPages = queue ? Math.ceil(queue.total_count / pageSize) : 0;

  return (
    <div className="space-y-5 font-mono text-xs">
      {/* 1. Header & Operational Context */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded shadow-md flex flex-col md:flex-row justify-between items-start md:items-center gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Building2 className="w-5 h-5 text-indigo-400" />
            <h2 className="text-base font-bold text-white tracking-wide uppercase">
              MUNICIPAL OPERATIONS &amp; DISPATCH QUEUE
            </h2>
            <span className="px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800 text-[10px] font-bold">
              PANAJI DRAINAGE BASIN
            </span>
          </div>
          <p className="text-slate-400 text-[11px] mt-0.5">
            Real-time urban stormwater hazard monitoring, civic triage, and crew dispatch status.
          </p>
        </div>

        <div className="flex items-center gap-3">
          {lastUpdated && (
            <div className="flex items-center gap-1.5 text-slate-400 text-[11px]">
              <Clock className="w-3.5 h-3.5 text-slate-500" />
              <span>SYNCED: {lastUpdated.toLocaleTimeString()}</span>
            </div>
          )}
          <button
            onClick={() => loadDashboardData(true)}
            disabled={isLoading || isRefreshing}
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 border border-slate-700 rounded flex items-center gap-1.5 transition-colors font-bold text-xs"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
            <span>REFRESH</span>
          </button>
        </div>
      </div>

      {/* 2. Unauthorized / Error Banners */}
      {isUnauthorized && (
        <div className="p-4 bg-amber-950/80 border border-amber-600 text-amber-200 rounded flex items-start gap-3">
          <ShieldAlert className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
          <div>
            <div className="font-bold text-sm text-white">MUNICIPAL ACCESS REQUIRED</div>
            <div className="text-[11px] text-amber-300 mt-1">
              The municipal dashboard and operational queue are restricted to verified municipal supervisors and administrators.
              Citizens and field workers are denied through server-side role validation.
            </div>
            <button
              onClick={() => loadDashboardData(false)}
              className="mt-3 px-3 py-1 bg-amber-900 hover:bg-amber-800 text-white rounded border border-amber-700 text-xs font-bold"
            >
              RE-VERIFY PERMISSIONS
            </button>
          </div>
        </div>
      )}

      {errorMessage && !isUnauthorized && (
        <div className="p-3 bg-rose-950/80 border border-rose-800 text-rose-300 rounded flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-rose-400" />
            <span>COMMUNICATION FAILURE: {errorMessage}</span>
          </div>
          <button
            onClick={() => loadDashboardData(false)}
            className="px-2.5 py-1 bg-rose-900 hover:bg-rose-800 text-white rounded text-xs font-bold border border-rose-700"
          >
            RETRY
          </button>
        </div>
      )}

      {/* 3. Server-Side KPI Metrics Banner */}
      {kpis && (
        <div className="space-y-2">
          <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
            <div className="p-3 bg-slate-900/90 border border-slate-800 rounded flex items-center space-x-3">
              <div className="p-2 bg-slate-800 rounded border border-slate-700 text-cyan-400">
                <ClipboardList className="w-5 h-5" />
              </div>
              <div>
                <div className="text-[10px] text-slate-400 uppercase tracking-tight">Total Incidents</div>
                <div className="text-xl font-bold text-white">{kpis.total_incidents}</div>
              </div>
            </div>

            <div className="p-3 bg-slate-900/90 border border-slate-800 rounded flex items-center space-x-3">
              <div className="p-2 bg-blue-950/60 rounded border border-blue-800 text-blue-400">
                <Clock className="w-5 h-5" />
              </div>
              <div>
                <div className="text-[10px] text-slate-400 uppercase tracking-tight">Active Open</div>
                <div className="text-xl font-bold text-blue-300">{kpis.open_incidents}</div>
              </div>
            </div>

            <div className="p-3 bg-slate-900/90 border border-slate-800 rounded flex items-center space-x-3">
              <div className="p-2 bg-rose-950/60 rounded border border-rose-800 text-rose-400">
                <AlertTriangle className="w-5 h-5" />
              </div>
              <div>
                <div className="text-[10px] text-slate-400 uppercase tracking-tight">Critical / High</div>
                <div className="text-xl font-bold text-rose-300">{kpis.critical_or_high_incidents}</div>
              </div>
            </div>

            <div className="p-3 bg-slate-900/90 border border-slate-800 rounded flex items-center space-x-3">
              <div className="p-2 bg-indigo-950/60 rounded border border-indigo-800 text-indigo-400">
                <Users className="w-5 h-5" />
              </div>
              <div>
                <div className="text-[10px] text-slate-400 uppercase tracking-tight">Awaiting Crew</div>
                <div className="text-xl font-bold text-indigo-300">{kpis.unassigned_incidents}</div>
              </div>
            </div>

            <div className="p-3 bg-slate-900/90 border border-slate-800 rounded flex items-center space-x-3">
              <div className="p-2 bg-emerald-950/60 rounded border border-emerald-800 text-emerald-400">
                <CheckCircle2 className="w-5 h-5" />
              </div>
              <div>
                <div className="text-[10px] text-slate-400 uppercase tracking-tight">Verified Resolved</div>
                <div className="text-xl font-bold text-emerald-300">{kpis.resolved_incidents}</div>
              </div>
            </div>
          </div>

          {/* Audit Integrity & Source Transparency Banner */}
          <div className="p-2.5 bg-slate-950/80 border border-slate-800 rounded flex flex-wrap items-center justify-between text-[11px] gap-2">
            <div className="flex items-center gap-4">
              <span className="text-slate-400 font-bold uppercase tracking-wider text-[10px]">Data Integrity Audit:</span>
              <span className="flex items-center gap-1.5 text-emerald-300">
                <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
                <span>Genuine Field Incidents: <strong className="font-mono text-white">{kpis.genuine_incidents_count ?? 0}</strong></span>
              </span>
              <span className="flex items-center gap-1.5 text-purple-300">
                <span className="w-2 h-2 rounded-full bg-purple-500"></span>
                <span>Simulated Demo Seeds: <strong className="font-mono text-white">{kpis.demo_incidents_count ?? 0}</strong></span>
              </span>
            </div>
            <div className="text-slate-500 text-[10px]">
              Demo seeds demarcated for audit transparency • Never confused with real citizen reports
            </div>
          </div>
        </div>
      )}

      {/* 4. Operational Search & Filter Bar */}
      <div className="p-3 bg-slate-900 border border-slate-800 rounded space-y-3">
        <div className="flex flex-col md:flex-row md:flex-wrap gap-2.5 items-stretch md:items-center">
          {/* Search Bar */}
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-400 absolute left-2.5 top-2.5" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setCurrentPage(0);
              }}
              placeholder="Search ticket ID, description, assigned crew, location..."
              className="w-full bg-slate-950 border border-slate-700 rounded pl-8 pr-8 py-2 text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 text-xs"
            />
            {searchQuery && (
              <button
                onClick={() => {
                  setSearchQuery('');
                  setCurrentPage(0);
                }}
                className="absolute right-2.5 top-2.5 text-slate-400 hover:text-white"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {/* Status Filter */}
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400 text-[11px] whitespace-nowrap">STATUS:</span>
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setCurrentPage(0);
              }}
              className="bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">ALL STATUSES</option>
              <option value="REPORTED">REPORTED</option>
              <option value="VERIFIED">VERIFIED</option>
              <option value="ASSIGNED">ASSIGNED</option>
              <option value="INVESTIGATING">INVESTIGATING</option>
              <option value="RESOLVED">RESOLVED</option>
              <option value="REJECTED">REJECTED</option>
            </select>
          </div>

          {/* Severity Filter */}
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400 text-[11px] whitespace-nowrap">SEVERITY:</span>
            <select
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value);
                setCurrentPage(0);
              }}
              className="bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">ALL SEVERITIES</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>

          {/* Category Filter */}
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400 text-[11px] whitespace-nowrap">CATEGORY:</span>
            <select
              value={categoryFilter}
              onChange={(e) => {
                setCategoryFilter(e.target.value);
                setCurrentPage(0);
              }}
              className="bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">ALL CATEGORIES</option>
              <option value="FLOODING">FLOODING</option>
              <option value="WATERLOGGING">WATERLOGGING</option>
              <option value="DRAIN_BLOCKAGE">DRAIN_BLOCKAGE</option>
              <option value="DRAIN_OVERFLOW">DRAIN_OVERFLOW</option>
              <option value="MANHOLE_DAMAGE">MANHOLE_DAMAGE</option>
              <option value="INFRASTRUCTURE_DAMAGE">INFRASTRUCTURE_DAMAGE</option>
              <option value="OTHER">OTHER</option>
            </select>
          </div>

          {/* Assignment Filter */}
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400 text-[11px] whitespace-nowrap">CREW:</span>
            <select
              value={assignmentFilter}
              onChange={(e) => {
                setAssignmentFilter(e.target.value);
                setCurrentPage(0);
              }}
              className="bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">ALL ASSIGNMENTS</option>
              <option value="UNASSIGNED">UNASSIGNED ONLY</option>
              <option value="ASSIGNED">ANY CREW ASSIGNED</option>
              {MUNICIPAL_FIELD_CREWS.map((c) => (
                <option key={c} value={c}>{c}</option>
              ))}
            </select>
          </div>

          {/* Source Filter */}
          <div className="flex items-center gap-1.5 shrink-0">
            <span className="text-slate-400 text-[11px] whitespace-nowrap">SOURCE:</span>
            <select
              value={sourceFilter}
              onChange={(e) => {
                setSourceFilter(e.target.value);
                setCurrentPage(0);
              }}
              className="w-28 max-w-full bg-slate-950 border border-slate-700 rounded px-2 py-1.5 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">ALL SOURCES</option>
              <option value="CITIZEN">CITIZEN</option>
              <option value="DEMO">DEMO SEED</option>
              <option value="SENSOR">SENSOR</option>
            </select>
          </div>

          {/* Reset Filters */}
          {(searchQuery || statusFilter !== 'ALL' || severityFilter !== 'ALL' || categoryFilter !== 'ALL' || assignmentFilter !== 'ALL' || sourceFilter !== 'ALL') && (
            <button
              onClick={handleClearFilters}
              className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 text-xs flex items-center gap-1 shrink-0"
            >
              <X className="w-3.5 h-3.5" />
              <span>RESET</span>
            </button>
          )}
        </div>
      </div>

      {/* 5. Incident Queue Table */}
      <div className="bg-slate-900 border border-slate-800 rounded overflow-hidden shadow-md">
        <div className="px-4 py-2.5 bg-slate-950/70 border-b border-slate-800 flex justify-between items-center">
          <div className="flex items-center gap-2">
            <span className="font-bold text-slate-200">OPERATIONAL INCIDENTS QUEUE</span>
            {queue && (
              <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 text-[10px]">
                {queue.total_count} TOTAL
              </span>
            )}
          </div>
          {queue && (
            <div className="text-[11px] text-slate-400">
              Showing page {currentPage + 1} of {Math.max(1, totalPages)}
            </div>
          )}
        </div>

        {isLoading ? (
          <div className="p-12 text-center text-slate-400 flex flex-col items-center justify-center gap-2">
            <RefreshCw className="w-6 h-6 animate-spin text-cyan-400" />
            <span>Loading authoritative municipal queue...</span>
          </div>
        ) : !queue || queue.items.length === 0 ? (
          <div className="p-12 text-center text-slate-400 space-y-2">
            <AlertCircle className="w-8 h-8 text-slate-500 mx-auto" />
            <div className="font-bold text-slate-300">NO INCIDENTS MATCHING FILTERS</div>
            <p className="text-slate-500 text-xs max-w-sm mx-auto">
              No municipal tickets found matching the specified search query or status criteria.
            </p>
            <button
              onClick={handleClearFilters}
              className="mt-2 px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded border border-slate-700 text-xs"
            >
              CLEAR ACTIVE FILTERS
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/40 text-slate-400 text-[11px]">
                  <th className="py-2.5 px-3">TICKET ID</th>
                  <th className="py-2.5 px-3">SOURCE</th>
                  <th className="py-2.5 px-3">CATEGORY</th>
                  <th className="py-2.5 px-3">SEVERITY</th>
                  <th className="py-2.5 px-3">STATUS</th>
                  <th className="py-2.5 px-3">LOCATION / GPS</th>
                  <th className="py-2.5 px-3">ASSIGNED CREW</th>
                  <th className="py-2.5 px-3">REPORTED</th>
                  <th className="py-2.5 px-3">EVIDENCE</th>
                  <th className="py-2.5 px-3 text-right">ACTION</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {queue.items.map((ticket) => {
                  const coordInfo = formatCoordinates(ticket.latitude, ticket.longitude, ticket.source);
                  return (
                    <tr
                      key={ticket.id}
                      onClick={() => openInspectionDrawer(ticket)}
                      className="hover:bg-slate-800/50 cursor-pointer transition-colors"
                    >
                      <td className="py-2.5 px-3 font-mono font-bold text-cyan-400">
                        {ticket.id}
                      </td>
                      <td className="py-2.5 px-3">
                        {getSourceBadge(ticket.source)}
                      </td>
                      <td className="py-2.5 px-3 font-semibold text-slate-200">
                        {ticket.category}
                      </td>
                      <td className="py-2.5 px-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] border ${getSeverityBadge(ticket.severity)}`}>
                          {ticket.severity}
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] border font-bold ${getStatusBadge(ticket.status)}`}>
                          {ticket.status}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-300">
                        <div className="flex items-center gap-1">
                          <MapPin className="w-3 h-3 text-slate-500 shrink-0" />
                          <span className={`font-mono text-[11px] ${coordInfo.isUnavailable ? 'text-amber-400/90 italic' : coordInfo.isSimulated ? 'text-purple-300' : ''}`}>
                            {coordInfo.text}
                          </span>
                        </div>
                      </td>
                    <td className="py-2.5 px-3">
                      {ticket.assigned_to ? (
                        <span className="text-indigo-300 font-semibold">{ticket.assigned_to}</span>
                      ) : (
                        <span className="text-amber-400/90 italic font-mono text-[11px]">[UNASSIGNED]</span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 text-slate-400 text-[11px]">
                      {new Date(ticket.created_at).toLocaleString([], {
                        month: 'short',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit',
                      })}
                    </td>
                    <td className="py-2.5 px-3">
                      {ticket.photos && ticket.photos.length > 0 ? (
                        <span className="flex items-center gap-1 text-cyan-300 bg-cyan-950/60 border border-cyan-800 px-1.5 py-0.5 rounded text-[10px]">
                          <Camera className="w-3 h-3" />
                          <span>{ticket.photos.length}</span>
                        </span>
                      ) : (
                        <span className="text-slate-600">—</span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          openInspectionDrawer(ticket);
                        }}
                        className="p-1 hover:bg-slate-700 text-slate-400 hover:text-cyan-300 rounded transition-colors"
                        title="Inspect ticket details"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Bar */}
        {queue && totalPages > 1 && (
          <div className="p-3 bg-slate-950/80 border-t border-slate-800 flex justify-between items-center text-xs">
            <div className="text-slate-400">
              Showing {currentPage * pageSize + 1}–{Math.min(queue.total_count, (currentPage + 1) * pageSize)} of {queue.total_count} tickets
            </div>
            <div className="flex items-center gap-1.5">
              <button
                onClick={() => setCurrentPage((p) => Math.max(0, p - 1))}
                disabled={currentPage === 0}
                className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-300 rounded border border-slate-700 flex items-center gap-1"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
                <span>PREV</span>
              </button>
              <span className="px-2 font-mono text-slate-300">
                {currentPage + 1} / {totalPages}
              </span>
              <button
                onClick={() => setCurrentPage((p) => Math.min(totalPages - 1, p + 1))}
                disabled={currentPage >= totalPages - 1}
                className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-300 rounded border border-slate-700 flex items-center gap-1"
              >
                <span>NEXT</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* 6. Incident Details Drawer / Modal */}
      {inspectedIncident && (
        <div className="fixed inset-0 z-50 bg-black/75 flex justify-end">
          <div className="w-full max-w-xl bg-slate-900 border-l border-slate-800 h-full overflow-y-auto flex flex-col shadow-2xl">
            {/* Drawer Header */}
            <div className="p-4 bg-slate-950 border-b border-slate-800 flex justify-between items-start sticky top-0 z-10">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-base font-bold text-cyan-400">
                    {inspectedIncident.id}
                  </span>
                  {getSourceBadge(inspectedIncident.source)}
                  <span className={`px-2 py-0.5 rounded text-[10px] border ${getSeverityBadge(inspectedIncident.severity)}`}>
                    {inspectedIncident.severity}
                  </span>
                  <span className={`px-2 py-0.5 rounded text-[10px] border ${getStatusBadge(inspectedIncident.status)}`}>
                    {inspectedIncident.status}
                  </span>
                </div>
                <div className="text-slate-400 text-xs mt-1 font-semibold">
                  {inspectedIncident.category}
                </div>
              </div>
              <button
                onClick={() => setInspectedIncident(null)}
                className="p-1 hover:bg-slate-800 text-slate-400 hover:text-white rounded"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Drawer Content */}
            <div className="p-5 space-y-4 flex-1">
              {/* Simulated Demo Warning Banner */}
              {(inspectedIncident.source === 'DEMO' || inspectedIncident.id.includes('DEMO')) && (
                <div className="p-3 bg-purple-950/80 border border-purple-600 rounded flex items-start gap-2.5 text-purple-200">
                  <AlertTriangle className="w-4 h-4 text-purple-400 shrink-0 mt-0.5" />
                  <div>
                    <div className="font-bold text-xs uppercase tracking-wide">SIMULATED DEMO RECORD</div>
                    <div className="text-[11px] text-purple-300 mt-0.5">
                      This incident is a pre-seeded synthetic test record for operational demonstration. Coordinates and reports do not represent a genuine physical event.
                    </div>
                  </div>
                </div>
              )}

              {/* Description */}
              <div className="space-y-1">
                <label className="text-[11px] font-bold text-slate-400 uppercase">Description</label>
                <div className="p-3 bg-slate-950 border border-slate-800 rounded text-slate-200 leading-relaxed text-xs">
                  {inspectedIncident.description}
                </div>
              </div>

              {/* Geographic Coordinates & Location */}
              {(() => {
                const coordInfo = formatCoordinates(inspectedIncident.latitude, inspectedIncident.longitude, inspectedIncident.source);
                return (
                  <div className="space-y-2">
                    <div className="p-2.5 bg-slate-950 border border-slate-800 rounded flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <MapPin className="w-4 h-4 text-slate-500 shrink-0" />
                        <span className={`font-mono text-xs font-bold ${coordInfo.isUnavailable ? 'text-amber-400 italic' : coordInfo.isSimulated ? 'text-purple-300' : 'text-slate-100'}`}>
                          {coordInfo.text}
                        </span>
                      </div>
                      <span className="text-[10px] text-slate-500 font-mono">
                        {coordInfo.isUnavailable ? '[UNRECORDED]' : coordInfo.isSimulated ? '[SIMULATED REFERENCE]' : '[VERIFIED GPS]'}
                      </span>
                    </div>
                    {!coordInfo.isUnavailable && (
                      <div className="grid grid-cols-2 gap-3">
                        <div className="p-2 bg-slate-950 border border-slate-800 rounded">
                          <div className="text-[10px] text-slate-400 uppercase">Latitude</div>
                          <div className="text-xs font-mono text-slate-200 font-bold">{inspectedIncident.latitude.toFixed(6)}</div>
                        </div>
                        <div className="p-2 bg-slate-950 border border-slate-800 rounded">
                          <div className="text-[10px] text-slate-400 uppercase">Longitude</div>
                          <div className="text-xs font-mono text-slate-200 font-bold">{inspectedIncident.longitude.toFixed(6)}</div>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })()}

              {/* Timestamps */}
              <div className="grid grid-cols-2 gap-3">
                <div className="p-2.5 bg-slate-950 border border-slate-800 rounded">
                  <div className="text-[10px] text-slate-400 uppercase">Reported At</div>
                  <div className="text-xs font-mono text-slate-300">
                    {new Date(inspectedIncident.created_at).toLocaleString()}
                  </div>
                </div>
                <div className="p-2.5 bg-slate-950 border border-slate-800 rounded">
                  <div className="text-[10px] text-slate-400 uppercase">Last Updated</div>
                  <div className="text-xs font-mono text-slate-300">
                    {new Date(inspectedIncident.updated_at).toLocaleString()}
                  </div>
                </div>
              </div>

              {/* Assignment & Notes */}
              <div className="space-y-3">
                <div className="space-y-1">
                  <label className="text-[11px] font-bold text-slate-400 uppercase">Assigned Field Crew</label>
                  <div className="p-2.5 bg-slate-950 border border-slate-800 rounded text-slate-200 font-semibold text-xs">
                    {inspectedIncident.assigned_to || (
                      <span className="text-amber-400 italic font-normal">[No Crew Assigned Yet]</span>
                    )}
                  </div>
                </div>

                <div className="space-y-1">
                  <label className="text-[11px] font-bold text-slate-400 uppercase">Municipal Dispatch Remarks</label>
                  <div className="p-2.5 bg-slate-950 border border-slate-800 rounded text-slate-300 text-xs">
                    {inspectedIncident.municipal_notes || (
                      <span className="text-slate-500 italic">[No municipal notes recorded]</span>
                    )}
                  </div>
                </div>

                {/* Confidential Internal Staff Notes */}
                <div className="space-y-1">
                  <div className="flex items-center justify-between">
                    <label className="text-[11px] font-bold text-slate-400 uppercase">Internal Staff Notes</label>
                    <span className="text-[10px] text-amber-400 font-bold border border-amber-800 bg-amber-950/70 px-1 rounded">
                      CONFIDENTIAL STAFF NOTE
                    </span>
                  </div>
                  <div className="p-2.5 bg-slate-950 border border-slate-800 rounded text-xs font-mono">
                    {inspectedIncident.internal_notes ? (
                      <span className="text-amber-200">{inspectedIncident.internal_notes}</span>
                    ) : (
                      <span className="text-slate-500 italic">None recorded. Note: Internal remarks are never searchable or exposed publicly.</span>
                    )}
                  </div>
                </div>
              </div>

              {/* Citizen Photographic Evidence */}
              <div className="space-y-1.5 pt-2 border-t border-slate-800">
                <div className="flex items-center justify-between">
                  <label className="text-[11px] font-bold text-slate-400 uppercase flex items-center gap-1.5">
                    <Camera className="w-4 h-4 text-cyan-400" />
                    <span>Photographic Evidence ({inspectedIncident.photos?.length || 0})</span>
                  </label>
                </div>

                {inspectedIncident.photos && inspectedIncident.photos.length > 0 ? (
                  <div className="grid grid-cols-3 gap-2">
                    {inspectedIncident.photos.map((photoPath, idx) => {
                      const fullPhotoUrl = photoPath.startsWith('http')
                        ? photoPath
                        : photoPath.startsWith('/')
                        ? photoPath
                        : `/${photoPath}`;
                      return (
                        <div
                          key={idx}
                          onClick={() => setPreviewPhotoUrl(fullPhotoUrl)}
                          className="relative aspect-video bg-slate-950 border border-slate-800 rounded overflow-hidden cursor-pointer group hover:border-cyan-500 transition-colors"
                        >
                          <img
                            src={fullPhotoUrl}
                            alt={`Evidence #${idx + 1}`}
                            className="w-full h-full object-cover group-hover:scale-105 transition-transform"
                            onError={(e) => {
                              // If image fails, fallback to clean placeholder
                              (e.target as HTMLElement).style.display = 'none';
                            }}
                          />
                          <div className="absolute inset-0 bg-black/40 opacity-0 group-hover:opacity-100 flex items-center justify-center transition-opacity">
                            <Eye className="w-4 h-4 text-white" />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div className="p-3 bg-slate-950 border border-slate-800 rounded text-slate-500 italic text-[11px]">
                    No photographic evidence attached to this ticket.
                  </div>
                )}
              </div>

              {/* Action Feedback Banners */}
              {actionError && (
                <div className="p-3 bg-rose-950/80 border border-rose-600 rounded text-rose-200 text-xs flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
                    <span>{actionError}</span>
                  </div>
                  <button onClick={() => setActionError(null)} className="text-rose-400 hover:text-white">
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
              )}

              {actionSuccess && (
                <div className="p-3 bg-emerald-950/80 border border-emerald-600 rounded text-emerald-200 text-xs flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    <span>{actionSuccess}</span>
                  </div>
                  <button onClick={() => setActionSuccess(null)} className="text-emerald-400 hover:text-white">
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
              )}

              {/* Terminal State Notice vs Active Triage Workflows */}
              {inspectedIncident.status === 'RESOLVED' || inspectedIncident.status === 'REJECTED' ? (
                <div className="p-3 bg-slate-950 border border-slate-800 rounded flex items-start gap-2.5 text-slate-400">
                  <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  <div className="text-[11px]">
                    <strong className="text-slate-300">TERMINAL TICKET STATUS:</strong> This incident is in terminal state ({inspectedIncident.status}).
                    Operational triage, reassignments, and notes are finalized for audit preservation.
                    {inspectedIncident.rejection_reason && (
                      <div className="mt-1 text-rose-300 font-mono">
                        Rejection Reason: {inspectedIncident.rejection_reason}
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="space-y-4 pt-2 border-t border-slate-800">
                  {/* Triage Action 1: Verification & Prioritization */}
                  <div className="p-3 bg-slate-950 border border-slate-800 rounded space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-200 uppercase tracking-wide flex items-center gap-1.5">
                        <CheckCircle2 className="w-4 h-4 text-purple-400" />
                        <span>MUNICIPAL TRIAGE &amp; VERIFICATION</span>
                      </span>
                      {inspectedIncident.status === 'VERIFIED' && (
                        <span className="text-[10px] text-purple-400 font-bold border border-purple-800 bg-purple-950/70 px-1.5 py-0.5 rounded">
                          VERIFIED
                        </span>
                      )}
                    </div>

                    <div className="grid grid-cols-2 gap-2">
                      <div>
                        <label className="text-[10px] text-slate-400 uppercase font-semibold">Priority Severity</label>
                        <select
                          value={verifySeverity}
                          onChange={(e) => setVerifySeverity(e.target.value as IncidentSeverity)}
                          className="w-full mt-1 bg-slate-900 border border-slate-700 rounded px-2 py-1.5 text-slate-200 text-xs font-mono"
                        >
                          <option value="LOW">LOW</option>
                          <option value="MEDIUM">MEDIUM</option>
                          <option value="HIGH">HIGH</option>
                          <option value="CRITICAL">CRITICAL</option>
                        </select>
                      </div>
                      <div>
                        <label className="text-[10px] text-slate-400 uppercase font-semibold">Current State</label>
                        <div className="mt-1 px-2 py-1.5 bg-slate-900 border border-slate-700 rounded text-slate-300 text-xs font-mono">
                          {inspectedIncident.status}
                        </div>
                      </div>
                    </div>

                    <div>
                      <label className="text-[10px] text-slate-400 uppercase font-semibold">Triage / Verification Notes</label>
                      <input
                        type="text"
                        value={verifyNotes}
                        onChange={(e) => setVerifyNotes(e.target.value)}
                        placeholder="e.g. CCTV verified, heavy silt at culvert..."
                        className="w-full mt-1 bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 text-xs"
                      />
                    </div>

                    <div className="flex justify-end">
                      <button
                        onClick={handleVerify}
                        disabled={isActionPending}
                        className="px-3 py-1.5 bg-purple-900 hover:bg-purple-800 disabled:opacity-50 text-purple-100 rounded border border-purple-700 font-bold text-xs flex items-center gap-1.5 transition-colors"
                      >
                        <Check className="w-3.5 h-3.5" />
                        <span>{inspectedIncident.status === 'VERIFIED' ? 'UPDATE VERIFICATION' : 'VERIFY INCIDENT'}</span>
                      </button>
                    </div>
                  </div>

                  {/* Triage Action 2: Field Crew Assignment / Reassignment / Unassignment */}
                  <div className="p-3 bg-slate-950 border border-slate-800 rounded space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-slate-200 uppercase tracking-wide flex items-center gap-1.5">
                        <Users className="w-4 h-4 text-indigo-400" />
                        <span>FIELD CREW ASSIGNMENT &amp; DISPATCH</span>
                      </span>
                      {inspectedIncident.assigned_to ? (
                        <span className="text-[10px] text-indigo-300 font-bold border border-indigo-700 bg-indigo-950/80 px-1.5 py-0.5 rounded">
                          ASSIGNED
                        </span>
                      ) : (
                        <span className="text-[10px] text-amber-400 font-bold border border-amber-800 bg-amber-950/80 px-1.5 py-0.5 rounded">
                          UNASSIGNED
                        </span>
                      )}
                    </div>

                    {/* Demonstration Crew Notice */}
                    <div className="p-2 bg-purple-950/40 border border-purple-800/60 rounded text-[10px] text-purple-300 flex items-start gap-1.5">
                      <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5 text-purple-400" />
                      <span>Notice: Available field response crews are demonstration units for operational modeling. Real municipal assignments require verified field worker directory registration.</span>
                    </div>

                    {inspectedIncident.assigned_to ? (
                      /* Crew Reassignment & Unassignment Workflow */
                      <div className="space-y-3">
                        <div className="p-2.5 bg-indigo-950/60 border border-indigo-800 rounded flex justify-between items-center text-xs">
                          <div>
                            <span className="text-[10px] text-indigo-400 uppercase font-semibold block">CURRENT ACTIVE CREW</span>
                            <span className="font-bold text-indigo-200">{inspectedIncident.assigned_to}</span>
                          </div>
                        </div>

                        {/* Reassign Sub-form */}
                        <div className="p-2.5 bg-slate-900/80 border border-slate-800 rounded space-y-2">
                          <label className="text-[10px] text-slate-400 uppercase font-semibold block">
                            Reassign to Different Crew (Requires Mandatory Reason)
                          </label>
                          <select
                            value={selectedReassignTeam}
                            onChange={(e) => setSelectedReassignTeam(e.target.value)}
                            className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 text-xs"
                          >
                            {fieldTeams.map((t) => (
                              <option key={t.team_id} value={t.name}>
                                {t.name} ({t.zone})
                              </option>
                            ))}
                          </select>
                          <input
                            type="text"
                            value={reassignReason}
                            onChange={(e) => setReassignReason(e.target.value)}
                            placeholder="Operational reason for reassignment (mandatory)..."
                            className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 text-xs"
                          />
                          <div className="flex justify-end gap-2">
                            <button
                              onClick={handleReassign}
                              disabled={isActionPending || !reassignReason.trim()}
                              className="px-3 py-1.5 bg-indigo-900 hover:bg-indigo-800 disabled:opacity-40 text-indigo-100 rounded border border-indigo-700 font-bold text-xs flex items-center gap-1.5 transition-colors"
                            >
                              <UserCheck className="w-3.5 h-3.5" />
                              <span>REASSIGN CREW</span>
                            </button>
                          </div>
                        </div>

                        {/* Unassign Sub-form */}
                        <div className="p-2.5 bg-slate-900/80 border border-slate-800 rounded space-y-2">
                          <label className="text-[10px] text-slate-400 uppercase font-semibold block">
                            Remove Crew Assignment (Requires Mandatory Reason)
                          </label>
                          <input
                            type="text"
                            value={unassignReason}
                            onChange={(e) => setUnassignReason(e.target.value)}
                            placeholder="Operational reason for unassignment (mandatory)..."
                            className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 text-xs"
                          />
                          <div className="flex justify-end">
                            <button
                              onClick={handleUnassign}
                              disabled={isActionPending || !unassignReason.trim()}
                              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-amber-300 rounded border border-amber-800 font-bold text-xs flex items-center gap-1.5 transition-colors"
                            >
                              <UserX className="w-3.5 h-3.5" />
                              <span>REMOVE ASSIGNMENT</span>
                            </button>
                          </div>
                        </div>
                      </div>
                    ) : (
                      /* Initial Crew Assignment Workflow */
                      <div className="space-y-2">
                        <label className="text-[10px] text-slate-400 uppercase font-semibold block">Select Field Crew</label>
                        <select
                          value={selectedAssignTeam}
                          onChange={(e) => setSelectedAssignTeam(e.target.value)}
                          className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 text-xs"
                        >
                          {fieldTeams.map((t) => (
                            <option key={t.team_id} value={t.name}>
                              {t.name} ({t.zone})
                            </option>
                          ))}
                        </select>
                        <input
                          type="text"
                          value={assignReason}
                          onChange={(e) => setAssignReason(e.target.value)}
                          placeholder="Optional dispatch instruction or urgency notes..."
                          className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 text-xs"
                        />
                        <div className="flex justify-end">
                          <button
                            onClick={handleAssign}
                            disabled={isActionPending || !selectedAssignTeam}
                            className="px-3 py-1.5 bg-indigo-900 hover:bg-indigo-800 disabled:opacity-40 text-indigo-100 rounded border border-indigo-700 font-bold text-xs flex items-center gap-1.5 transition-colors"
                          >
                            <Send className="w-3.5 h-3.5" />
                            <span>DISPATCH &amp; ASSIGN CREW</span>
                          </button>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Triage Action 3: Incident Rejection */}
                  <div className="p-3 bg-slate-950 border border-rose-950 rounded space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-rose-300 uppercase tracking-wide flex items-center gap-1.5">
                        <AlertOctagon className="w-4 h-4 text-rose-400" />
                        <span>REJECT INCIDENT</span>
                      </span>
                    </div>
                    {!isConfirmingReject ? (
                      <div className="flex justify-between items-center text-xs">
                        <span className="text-slate-400 text-[11px]">
                          Marks report invalid, duplicate, or out-of-jurisdiction.
                        </span>
                        <button
                          onClick={() => setIsConfirmingReject(true)}
                          className="px-3 py-1.5 bg-rose-950/70 hover:bg-rose-900 text-rose-200 border border-rose-700 rounded font-bold text-xs transition-colors"
                        >
                          REJECT TICKET
                        </button>
                      </div>
                    ) : (
                      <div className="p-2.5 bg-rose-950/40 border border-rose-800 rounded space-y-2">
                        <label className="text-[10px] text-rose-300 uppercase font-semibold block">
                          Mandatory Operational Rejection Reason
                        </label>
                        <input
                          type="text"
                          value={rejectReason}
                          onChange={(e) => setRejectReason(e.target.value)}
                          placeholder="e.g. Duplicate report, private compound, false alarm..."
                          className="w-full bg-slate-950 border border-rose-700 rounded px-2.5 py-1.5 text-slate-200 text-xs"
                        />
                        <div className="flex justify-end gap-2">
                          <button
                            onClick={() => {
                              setIsConfirmingReject(false);
                              setRejectReason('');
                            }}
                            className="px-2.5 py-1 bg-slate-800 text-slate-300 rounded text-xs"
                          >
                            CANCEL
                          </button>
                          <button
                            onClick={handleReject}
                            disabled={isActionPending || !rejectReason.trim()}
                            className="px-3 py-1 bg-rose-700 hover:bg-rose-600 disabled:opacity-40 text-white rounded font-bold text-xs"
                          >
                            CONFIRM REJECTION
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Operational Audit Trail Timeline */}
              <div className="space-y-2 pt-3 border-t border-slate-800">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-slate-200 uppercase tracking-wide flex items-center gap-1.5 text-xs">
                    <History className="w-4 h-4 text-cyan-400" />
                    <span>OPERATIONAL AUDIT TIMELINE ({incidentAudits.length})</span>
                  </span>
                  <button
                    onClick={() => inspectedIncident && loadIncidentAudits(inspectedIncident.id)}
                    className="text-[10px] text-cyan-400 hover:underline flex items-center gap-1"
                  >
                    <RefreshCw className={`w-3 h-3 ${isLoadingAudits ? 'animate-spin' : ''}`} />
                    <span>REFRESH</span>
                  </button>
                </div>

                {isLoadingAudits ? (
                  <div className="p-3 bg-slate-950 border border-slate-800 rounded text-center text-slate-400 text-xs">
                    Loading audit records...
                  </div>
                ) : incidentAudits.length === 0 ? (
                  <div className="p-3 bg-slate-950 border border-slate-800 rounded text-slate-500 italic text-[11px]">
                    No audit history logged for this incident yet.
                  </div>
                ) : (
                  <div className="space-y-2">
                    {incidentAudits.map((audit) => (
                      <div
                        key={audit.audit_id}
                        className="p-2.5 bg-slate-950 border border-slate-800/80 rounded space-y-1 font-mono text-[11px]"
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-cyan-950 text-cyan-300 border border-cyan-700">
                              {audit.action}
                            </span>
                            <span className="text-slate-400 font-sans text-[11px]">
                              by <strong className="text-slate-200">{audit.actor_id}</strong> ({audit.actor_role})
                            </span>
                          </div>
                          <span className="text-slate-500 text-[10px]">
                            {new Date(audit.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                          </span>
                        </div>

                        {(audit.previous_status || audit.new_status) && (
                          <div className="text-slate-300 text-[10px] flex items-center gap-1">
                            <CornerDownRight className="w-3 h-3 text-slate-500" />
                            <span>Status: {audit.previous_status || 'Initial'} ➔ <strong className="text-cyan-300">{audit.new_status}</strong></span>
                          </div>
                        )}

                        {(audit.previous_assigned_to || audit.new_assigned_to) && (
                          <div className="text-slate-300 text-[10px] flex items-center gap-1">
                            <CornerDownRight className="w-3 h-3 text-slate-500" />
                            <span>Crew: {audit.previous_assigned_to || 'None'} ➔ <strong className="text-indigo-300">{audit.new_assigned_to || 'None'}</strong></span>
                          </div>
                        )}

                        {(audit.previous_severity || audit.new_severity) && audit.previous_severity !== audit.new_severity && (
                          <div className="text-slate-300 text-[10px] flex items-center gap-1">
                            <CornerDownRight className="w-3 h-3 text-slate-500" />
                            <span>Severity: {audit.previous_severity} ➔ <strong className="text-orange-300">{audit.new_severity}</strong></span>
                          </div>
                        )}

                        {audit.reason && (
                          <div className="text-slate-400 italic text-[10px] pl-4">
                            Reason: "{audit.reason}"
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Drawer Footer */}
            <div className="p-4 bg-slate-950 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setInspectedIncident(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded border border-slate-700 font-bold text-xs"
              >
                CLOSE
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Full Photo Preview Modal */}
      {previewPhotoUrl && (
        <div
          className="fixed inset-0 z-60 bg-black/90 flex items-center justify-center p-4"
          onClick={() => setPreviewPhotoUrl(null)}
        >
          <div className="relative max-w-3xl w-full bg-slate-900 border border-slate-800 rounded overflow-hidden p-2">
            <button
              onClick={() => setPreviewPhotoUrl(null)}
              className="absolute top-3 right-3 p-1.5 bg-black/60 hover:bg-black/90 text-white rounded-full z-10"
            >
              <X className="w-5 h-5" />
            </button>
            <img
              src={previewPhotoUrl}
              alt="Evidence Full Preview"
              className="w-full max-h-[80vh] object-contain rounded"
            />
          </div>
        </div>
      )}
    </div>
  );
};

