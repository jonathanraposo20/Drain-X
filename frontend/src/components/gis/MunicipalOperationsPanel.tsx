import React, { useState, useMemo, useEffect, useCallback } from 'react';
import { createPortal } from 'react-dom';
import {
  IncidentResponseContract,
  IncidentStatus,
  IncidentSeverity,
  IncidentUpdateContract,
} from '../../types/contracts';
import { apiClient } from '../../api/client';
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
  Save,
  X,
  Camera,
  Image as ImageIcon,
} from 'lucide-react';

export const MUNICIPAL_FIELD_TEAMS = [
  'Team Alpha — St. Inez Drainage Crew',
  'Team Beta — Patto Rapid Response',
  'Team Gamma — Fontainhas Heritage Maintenance',
  'Team Delta — Miramar Outfall Sluice Unit',
];

const VALID_STATUS_TRANSITIONS: Record<IncidentStatus, IncidentStatus[]> = {
  REPORTED: ['VERIFIED', 'ASSIGNED', 'INVESTIGATING', 'REJECTED'],
  VERIFIED: ['ASSIGNED', 'INVESTIGATING', 'REJECTED'],
  ASSIGNED: ['INVESTIGATING', 'RESOLVED', 'REJECTED'],
  INVESTIGATING: ['RESOLVED', 'REJECTED'],
  RESOLVED: ['INVESTIGATING'],
  REJECTED: ['REPORTED'],
};

interface MunicipalOperationsPanelProps {
  incidents: IncidentResponseContract[];
  onRefresh: () => void;
  onSelectOnMap?: (incident: IncidentResponseContract) => void;
  selectedIncidentId?: string | null;
  onUpdateIncident: (updated: IncidentResponseContract) => void;
  onClearSelectedIncident?: () => void;
}

export const MunicipalOperationsPanel: React.FC<MunicipalOperationsPanelProps> = ({
  incidents,
  onRefresh,
  onSelectOnMap,
  selectedIncidentId,
  onUpdateIncident,
  onClearSelectedIncident,
}) => {
  // Filters
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [sourceFilter, setSourceFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  // Selected Incident for Management Modal / Drawer
  const [activeTicket, setActiveTicket] = useState<IncidentResponseContract | null>(null);
  const [newStatus, setNewStatus] = useState<IncidentStatus | ''>('');
  const [newAssignedTo, setNewAssignedTo] = useState<string>('');
  const [newNotes, setNewNotes] = useState<string>('');
  const [isUpdating, setIsUpdating] = useState(false);
  const [updateError, setUpdateError] = useState<string | null>(null);
  const [updateSuccess, setUpdateSuccess] = useState<string | null>(null);

  // Track last opened and explicitly dismissed incident IDs
  const prevSelectedIncidentIdRef = React.useRef<string | null>(null);
  const dismissedIncidentIdRef = React.useRef<string | null>(null);

  // Sync activeTicket if selected externally (e.g. from map click)
  useEffect(() => {
    if (!selectedIncidentId) {
      prevSelectedIncidentIdRef.current = null;
      dismissedIncidentIdRef.current = null;
      return;
    }

    // Do not reopen if this incident was already dismissed while selectedIncidentId remains unchanged,
    // or if it has already been opened for this exact selectedIncidentId.
    if (
      selectedIncidentId === dismissedIncidentIdRef.current ||
      selectedIncidentId === prevSelectedIncidentIdRef.current
    ) {
      return;
    }

    const match = incidents.find((i) => i.id === selectedIncidentId);
    if (match) {
      handleOpenTicket(match);
      prevSelectedIncidentIdRef.current = selectedIncidentId;
      dismissedIncidentIdRef.current = null;
    }
  }, [selectedIncidentId, incidents]);

  // Handle opening ticket drawer
  const handleOpenTicket = (ticket: IncidentResponseContract) => {
    setActiveTicket(ticket);
    setNewStatus(ticket.status);
    setNewAssignedTo(ticket.assigned_to || '');
    setNewNotes(ticket.municipal_notes || '');
    setUpdateError(null);
    setUpdateSuccess(null);
    prevSelectedIncidentIdRef.current = ticket.id;
    dismissedIncidentIdRef.current = null;
  };

  const handleCloseTicket = useCallback(
    (isLocatingOnMap: boolean | unknown = false) => {
      setActiveTicket(null);
      setUpdateError(null);
      setUpdateSuccess(null);
      if (selectedIncidentId) {
        dismissedIncidentIdRef.current = selectedIncidentId;
      }
      if (isLocatingOnMap !== true) {
        onClearSelectedIncident?.();
      }
    },
    [selectedIncidentId, onClearSelectedIncident]
  );

  // Prevent background scrolling and handle Escape key while Ticket Inspector modal is open
  useEffect(() => {
    if (!activeTicket) return;
    if (typeof document === 'undefined') return;

    const originalOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        handleCloseTicket();
      }
    };

    window.addEventListener('keydown', handleKeyDown);

    return () => {
      document.body.style.overflow = originalOverflow;
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [activeTicket, handleCloseTicket]);

  // KPI Calculations
  const kpis = useMemo(() => {
    const total = incidents.length;
    const open = incidents.filter(
      (i) => i.status !== 'RESOLVED' && i.status !== 'REJECTED'
    ).length;
    const criticalOrHigh = incidents.filter(
      (i) => (i.severity === 'CRITICAL' || i.severity === 'HIGH') && i.status !== 'RESOLVED'
    ).length;
    const assigned = incidents.filter((i) => !!i.assigned_to && i.status !== 'RESOLVED').length;
    const resolved = incidents.filter((i) => i.status === 'RESOLVED').length;

    return { total, open, criticalOrHigh, assigned, resolved };
  }, [incidents]);

  // Filtered List
  const filteredIncidents = useMemo(() => {
    return incidents.filter((item) => {
      if (statusFilter !== 'ALL' && item.status !== statusFilter) return false;
      if (sourceFilter !== 'ALL' && item.source !== sourceFilter) return false;
      if (severityFilter !== 'ALL' && item.severity !== severityFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesId = item.id.toLowerCase().includes(q);
        const matchesDesc = item.description.toLowerCase().includes(q);
        const matchesReporter = (item.reporter_name || '').toLowerCase().includes(q);
        const matchesAssigned = (item.assigned_to || '').toLowerCase().includes(q);
        if (!matchesId && !matchesDesc && !matchesReporter && !matchesAssigned) return false;
      }
      return true;
    });
  }, [incidents, statusFilter, sourceFilter, severityFilter, searchQuery]);

  // Save Ticket Updates
  const handleSaveUpdate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activeTicket) return;

    setUpdateError(null);
    setUpdateSuccess(null);
    setIsUpdating(true);

    try {
      const payload: IncidentUpdateContract = {};
      if (newStatus && newStatus !== activeTicket.status) {
        payload.status = newStatus as IncidentStatus;
      }
      if (newAssignedTo !== (activeTicket.assigned_to || '')) {
        payload.assigned_to = newAssignedTo;
      }
      if (newNotes !== (activeTicket.municipal_notes || '')) {
        payload.municipal_notes = newNotes;
      }

      if (Object.keys(payload).length === 0) {
        setUpdateSuccess('No changes to save.');
        setIsUpdating(false);
        return;
      }

      const updated = await apiClient.updateIncident(activeTicket.id, payload);
      setActiveTicket(updated);
      onUpdateIncident(updated);
      setUpdateSuccess('Ticket successfully updated.');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to update ticket';
      setUpdateError(msg);
    } finally {
      setIsUpdating(false);
    }
  };

  // Severity style helper
  const getSeverityBadge = (sev: IncidentSeverity) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-rose-950/80 text-rose-300 border-rose-600';
      case 'HIGH':
        return 'bg-orange-950/80 text-orange-300 border-orange-600';
      case 'MEDIUM':
        return 'bg-amber-950/80 text-amber-300 border-amber-600';
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
        return 'bg-slate-900 text-slate-500 border-slate-700';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-600';
    }
  };

  const allowedNextStatuses = activeTicket
    ? [activeTicket.status, ...(VALID_STATUS_TRANSITIONS[activeTicket.status] || [])]
    : [];

  return (
    <div className="space-y-4 font-mono text-xs">
      {/* 1. Municipal Operations KPI Banner */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div className="p-3 bg-slate-900/90 border border-slate-800 rounded flex items-center space-x-3">
          <div className="p-2 bg-slate-800 rounded border border-slate-700 text-cyan-400">
            <ClipboardList className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[10px] text-slate-400 uppercase">Total Tickets</div>
            <div className="text-xl font-bold text-white">{kpis.total}</div>
          </div>
        </div>

        <div className="p-3 bg-slate-900/90 border border-slate-800 rounded flex items-center space-x-3">
          <div className="p-2 bg-blue-950 rounded border border-blue-800 text-blue-400">
            <Clock className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[10px] text-slate-400 uppercase">Active / Open</div>
            <div className="text-xl font-bold text-blue-300">{kpis.open}</div>
          </div>
        </div>

        <div className="p-3 bg-slate-900/90 border border-slate-800 rounded flex items-center space-x-3">
          <div className="p-2 bg-rose-950 rounded border border-rose-800 text-rose-400">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[10px] text-slate-400 uppercase">High / Critical</div>
            <div className="text-xl font-bold text-rose-400">{kpis.criticalOrHigh}</div>
          </div>
        </div>

        <div className="p-3 bg-slate-900/90 border border-slate-800 rounded flex items-center space-x-3">
          <div className="p-2 bg-indigo-950 rounded border border-indigo-800 text-indigo-400">
            <Users className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[10px] text-slate-400 uppercase">Crews Dispatched</div>
            <div className="text-xl font-bold text-indigo-300">{kpis.assigned}</div>
          </div>
        </div>

        <div className="p-3 bg-slate-900/90 border border-slate-800 rounded flex items-center space-x-3">
          <div className="p-2 bg-emerald-950 rounded border border-emerald-800 text-emerald-400">
            <CheckCircle2 className="w-5 h-5" />
          </div>
          <div>
            <div className="text-[10px] text-slate-400 uppercase">Resolved</div>
            <div className="text-xl font-bold text-emerald-400">{kpis.resolved}</div>
          </div>
        </div>
      </div>

      {/* 2. Filter Bar & Search */}
      <div className="p-3 bg-slate-900/80 border border-slate-800 rounded flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          {/* Status Filter */}
          <div className="flex items-center space-x-1">
            <span className="text-[10px] text-slate-400 uppercase">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-200 focus:outline-none"
            >
              <option value="ALL">All Statuses</option>
              <option value="REPORTED">REPORTED</option>
              <option value="VERIFIED">VERIFIED</option>
              <option value="ASSIGNED">ASSIGNED</option>
              <option value="INVESTIGATING">INVESTIGATING</option>
              <option value="RESOLVED">RESOLVED</option>
              <option value="REJECTED">REJECTED</option>
            </select>
          </div>

          {/* Severity Filter */}
          <div className="flex items-center space-x-1">
            <span className="text-[10px] text-slate-400 uppercase">Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-200 focus:outline-none"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          {/* Source Filter */}
          <div className="flex items-center space-x-1">
            <span className="text-[10px] text-slate-400 uppercase">Origin:</span>
            <select
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-200 focus:outline-none"
            >
              <option value="ALL">All Sources</option>
              <option value="CITIZEN">Citizen Report</option>
              <option value="DEMO">Demonstration</option>
              <option value="SENSOR">Automated Sensor</option>
            </select>
          </div>
        </div>

        {/* Search & Refresh */}
        <div className="flex items-center space-x-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2 top-2 text-slate-500" />
            <input
              type="text"
              placeholder="Search ticket, desc, crew..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="bg-slate-950 border border-slate-700 rounded pl-7 pr-2 py-1 text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 text-xs w-48"
            />
          </div>
          <button
            onClick={onRefresh}
            className="flex items-center space-x-1 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 text-xs transition"
            title="Refresh Incident Feed"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* 3. Incidents Queue Table */}
      <div className="bg-slate-900/90 border border-slate-800 rounded overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/90 text-slate-400 border-b border-slate-800 text-[10px] uppercase tracking-wider">
              <tr>
                <th className="py-2.5 px-3">Ticket ID</th>
                <th className="py-2.5 px-3">Category & Hazard</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3">Assigned Field Crew</th>
                <th className="py-2.5 px-3">Reporter</th>
                <th className="py-2.5 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {filteredIncidents.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 italic">
                    No incidents match current filter criteria.
                  </td>
                </tr>
              ) : (
                filteredIncidents.map((ticket) => (
                  <tr
                    key={ticket.id}
                    className={`hover:bg-slate-800/50 transition cursor-pointer ${
                      activeTicket?.id === ticket.id ? 'bg-cyan-950/30 border-l-2 border-cyan-400' : ''
                    }`}
                    onClick={() => handleOpenTicket(ticket)}
                  >
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <div className="font-bold text-cyan-300">{ticket.id}</div>
                      <div className="text-[10px]">
                        {ticket.source === 'CITIZEN' ? (
                          <span className="text-emerald-400 font-semibold">[CITIZEN]</span>
                        ) : (
                          <span className="text-slate-500">[DEMO]</span>
                        )}
                      </div>
                    </td>

                    <td className="py-2.5 px-3 max-w-xs">
                      <div className="font-semibold text-white truncate">
                        {ticket.category.replace(/_/g, ' ')}
                      </div>
                      <div className="text-[11px] text-slate-400 truncate">
                        {ticket.description}
                      </div>
                      <div className="text-[10px] text-slate-500 flex items-center space-x-1 mt-0.5">
                        <MapPin className="w-3 h-3 text-slate-500" />
                        <span>
                          {ticket.latitude.toFixed(4)}°N, {ticket.longitude.toFixed(4)}°E
                        </span>
                      </div>
                    </td>

                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(
                          ticket.severity
                        )}`}
                      >
                        {ticket.severity}
                      </span>
                    </td>

                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getStatusBadge(
                          ticket.status
                        )}`}
                      >
                        {ticket.status}
                      </span>
                    </td>

                    <td className="py-2.5 px-3 whitespace-nowrap">
                      {ticket.assigned_to ? (
                        <span className="text-indigo-300 font-medium">{ticket.assigned_to}</span>
                      ) : (
                        <span className="text-slate-600 italic">Unassigned</span>
                      )}
                    </td>

                    <td className="py-2.5 px-3 whitespace-nowrap text-slate-400 text-[11px]">
                      {ticket.reporter_name || 'Citizen Anonymous'}
                    </td>

                    <td className="py-2.5 px-3 text-right whitespace-nowrap">
                      <div className="flex items-center justify-end space-x-1.5">
                        {onSelectOnMap && (
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              onSelectOnMap(ticket);
                            }}
                            className="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded border border-slate-700 text-[11px] transition"
                            title="Locate on Map"
                          >
                            Map
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleOpenTicket(ticket);
                          }}
                          className="px-2.5 py-1 bg-cyan-900/60 hover:bg-cyan-800/80 text-cyan-200 rounded border border-cyan-700 text-[11px] font-bold transition"
                        >
                          Manage
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* 4. Ticket Management Modal / Drawer via Portal */}
      {activeTicket &&
        typeof document !== 'undefined' &&
        document.body &&
        createPortal(
          <div
            className="fixed inset-0 z-[2000] flex items-center justify-center bg-black/75 backdrop-blur-sm p-3 sm:p-4 overflow-y-auto"
            onClick={(e) => {
              if (e.target === e.currentTarget) {
                handleCloseTicket();
              }
            }}
          >
            <div
              className="relative w-full max-w-xl bg-slate-900 border border-slate-700 rounded-lg shadow-2xl flex flex-col max-h-[90vh] font-mono text-xs my-auto overflow-hidden"
              onClick={(e) => e.stopPropagation()}
            >
              {/* Modal Header */}
              <div className="flex items-center justify-between px-4 py-3 bg-slate-800/90 border-b border-slate-700 shrink-0">
                <div className="flex items-center space-x-2">
                  <span className="text-cyan-400 font-bold uppercase tracking-wider">
                    Ticket Inspector: {activeTicket.id}
                  </span>
                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${getStatusBadge(
                      activeTicket.status
                    )}`}
                  >
                    {activeTicket.status}
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => handleCloseTicket()}
                  className="text-slate-400 hover:text-white transition-colors p-1 rounded hover:bg-slate-800"
                  title="Close"
                  aria-label="Close Ticket Inspector"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Modal Content */}
              <form onSubmit={handleSaveUpdate} className="flex flex-col flex-1 min-h-0 overflow-hidden">
                {/* Scrollable Form Body */}
                <div className="p-4 sm:p-5 space-y-4 overflow-y-auto flex-1">
                  {updateError && (
                    <div className="p-3 bg-rose-950/70 border border-rose-500 rounded text-rose-200 text-xs flex items-center space-x-2">
                      <AlertTriangle className="w-4 h-4 shrink-0" />
                      <span>{updateError}</span>
                    </div>
                  )}
                  {updateSuccess && (
                    <div className="p-3 bg-emerald-950/70 border border-emerald-500 rounded text-emerald-200 text-xs flex items-center space-x-2">
                      <CheckCircle2 className="w-4 h-4 shrink-0" />
                      <span>{updateSuccess}</span>
                    </div>
                  )}

                  {/* Readonly Details */}
                  <div className="p-3 bg-slate-950 rounded border border-slate-800 space-y-2">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Category:</span>
                      <span className="text-white font-bold">{activeTicket.category}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Severity:</span>
                      <span
                        className={`px-1.5 py-0.2 rounded text-[10px] font-bold border ${getSeverityBadge(
                          activeTicket.severity
                        )}`}
                      >
                        {activeTicket.severity}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Reported By:</span>
                      <span className="text-slate-200">
                        {activeTicket.reporter_name || 'Citizen Anonymous'} ({activeTicket.source})
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Coordinates:</span>
                      <span className="text-cyan-300">
                        {activeTicket.latitude.toFixed(4)}°N, {activeTicket.longitude.toFixed(4)}°E
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-400 block mb-1">Description:</span>
                      <div className="p-2 bg-slate-900 rounded text-slate-300 border border-slate-800">
                        {activeTicket.description}
                      </div>
                    </div>

                    {/* Attached Photographic Evidence */}
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-slate-400 flex items-center space-x-1">
                          <Camera className="w-3.5 h-3.5 text-cyan-400" />
                          <span>Photographic Evidence:</span>
                        </span>
                        <span className="text-[10px] text-slate-500">
                          {activeTicket.photos && activeTicket.photos.length > 0
                            ? `${activeTicket.photos.length} image(s)`
                            : 'None'}
                        </span>
                      </div>

                      {activeTicket.photos && activeTicket.photos.length > 0 ? (
                        <div className="grid grid-cols-3 gap-2 mt-1.5">
                          {activeTicket.photos.map((photoUrl, idx) => (
                            <a
                              key={idx}
                              href={photoUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="group relative block aspect-video rounded overflow-hidden border border-slate-700 bg-slate-950 hover:border-cyan-500 transition shadow"
                              title="Click to inspect full resolution image"
                            >
                              <img
                                src={photoUrl}
                                alt={`Evidence ${idx + 1}`}
                                className="w-full h-full object-cover group-hover:scale-105 transition duration-200"
                              />
                              <div className="absolute inset-0 bg-black/40 opacity-0 group-hover:opacity-100 flex items-center justify-center transition">
                                <ImageIcon className="w-4 h-4 text-cyan-300" />
                              </div>
                            </a>
                          ))}
                        </div>
                      ) : (
                        <div className="p-2 bg-slate-900/60 rounded border border-slate-800/80 text-[11px] text-slate-500 italic flex items-center space-x-1.5">
                          <Camera className="w-3.5 h-3.5 text-slate-600 shrink-0" />
                          <span>No photographic evidence attached to this report.</span>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Status Machine Transition Selector */}
                  <div>
                    <label className="block text-[11px] text-slate-400 uppercase tracking-wider mb-1">
                      Lifecycle Status Transition
                    </label>
                    <select
                      value={newStatus}
                      onChange={(e) => setNewStatus(e.target.value as IncidentStatus)}
                      className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-500"
                    >
                      {allowedNextStatuses.map((st) => (
                        <option key={st} value={st}>
                          {st === activeTicket.status ? `${st} (Current)` : `→ Transition to ${st}`}
                        </option>
                      ))}
                    </select>
                    <p className="text-[10px] text-slate-500 mt-1">
                      Enforces municipal state machine: REPORTED → VERIFIED → ASSIGNED → INVESTIGATING → RESOLVED.
                    </p>
                  </div>

                  {/* Field Crew Assignment */}
                  <div>
                    <label className="block text-[11px] text-slate-400 uppercase tracking-wider mb-1">
                      Assign Field Worker / Response Unit
                    </label>
                    <select
                      value={newAssignedTo}
                      onChange={(e) => setNewAssignedTo(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-500"
                    >
                      <option value="">-- Unassigned --</option>
                      {MUNICIPAL_FIELD_TEAMS.map((team) => (
                        <option key={team} value={team}>
                          {team}
                        </option>
                      ))}
                    </select>
                  </div>

                  {/* Municipal Operational Notes */}
                  <div>
                    <label className="block text-[11px] text-slate-400 uppercase tracking-wider mb-1">
                      Municipal Dispatch & Resolution Notes
                    </label>
                    <textarea
                      rows={3}
                      placeholder="Record pump deployment, field observations, work order numbers, or resolution summary..."
                      value={newNotes}
                      onChange={(e) => setNewNotes(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-500 placeholder:text-slate-600 resize-none"
                    />
                  </div>
                </div>

                {/* Modal Actions Footer */}
                <div className="flex justify-between items-center px-4 py-3 sm:px-5 border-t border-slate-800 bg-slate-900 shrink-0">
                  {onSelectOnMap && (
                    <button
                      type="button"
                      onClick={() => {
                        if (activeTicket) {
                          onSelectOnMap(activeTicket);
                        }
                        handleCloseTicket(true);
                      }}
                      className="flex items-center space-x-1 text-cyan-400 hover:text-cyan-300 text-xs transition"
                    >
                      <MapPin className="w-3.5 h-3.5" />
                      <span>Locate on GIS Map</span>
                    </button>
                  )}
                  <div className="flex space-x-2 ml-auto">
                    <button
                      type="button"
                      onClick={() => handleCloseTicket()}
                      className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs transition border border-slate-700"
                    >
                      Close
                    </button>
                    <button
                      type="submit"
                      disabled={isUpdating}
                      className="flex items-center space-x-1.5 px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white font-bold rounded text-xs transition disabled:opacity-50"
                    >
                      <Save className="w-3.5 h-3.5" />
                      <span>{isUpdating ? 'Saving...' : 'Save Updates'}</span>
                    </button>
                  </div>
                </div>
              </form>
            </div>
          </div>,
          document.body
        )}
    </div>
  );
};
