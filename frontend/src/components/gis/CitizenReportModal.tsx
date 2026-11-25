import React, { useState } from 'react';
import {
  IncidentCategory,
  IncidentSeverity,
  IncidentCreateContract,
  IncidentResponseContract,
} from '../../types/contracts';
import { apiClient } from '../../api/client';
import { X, Send, CheckCircle, AlertCircle, Crosshair } from 'lucide-react';

interface CitizenReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  onIncidentCreated: (incident: IncidentResponseContract) => void;
  selectedCoordinates?: { lat: number; lng: number } | null;
  isPickingOnMap: boolean;
  onToggleMapPick: (active: boolean) => void;
}

const PANJIM_QUICK_LANDMARKS = [
  { name: 'St. Inez Creek Culvert', lat: 15.4925, lng: 73.8240 },
  { name: 'Patto Commercial Plaza', lat: 15.4989, lng: 73.8342 },
  { name: 'Fontainhas Heritage Lane', lat: 15.4965, lng: 73.8305 },
  { name: 'Miramar Coastal Outfall', lat: 15.4835, lng: 73.8078 },
];

export const CitizenReportModal: React.FC<CitizenReportModalProps> = ({
  isOpen,
  onClose,
  onIncidentCreated,
  selectedCoordinates,
  isPickingOnMap,
  onToggleMapPick,
}) => {
  const [category, setCategory] = useState<IncidentCategory>('DRAIN_BLOCKAGE');
  const [severity, setSeverity] = useState<IncidentSeverity>('MEDIUM');
  const [description, setDescription] = useState('');
  const [reporterName, setReporterName] = useState('');
  const [latitude, setLatitude] = useState<string>(
    selectedCoordinates ? selectedCoordinates.lat.toFixed(4) : '15.4925'
  );
  const [longitude, setLongitude] = useState<string>(
    selectedCoordinates ? selectedCoordinates.lng.toFixed(4) : '73.8240'
  );

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [createdIncident, setCreatedIncident] = useState<IncidentResponseContract | null>(null);

  // Sync coords if updated externally via map click
  React.useEffect(() => {
    if (selectedCoordinates) {
      setLatitude(selectedCoordinates.lat.toFixed(4));
      setLongitude(selectedCoordinates.lng.toFixed(4));
    }
  }, [selectedCoordinates]);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    const latNum = parseFloat(latitude);
    const lngNum = parseFloat(longitude);

    if (isNaN(latNum) || latNum < -90 || latNum > 90) {
      setErrorMessage('Please enter a valid latitude (-90 to 90).');
      return;
    }
    if (isNaN(lngNum) || lngNum < -180 || lngNum > 180) {
      setErrorMessage('Please enter a valid longitude (-180 to 180).');
      return;
    }
    if (description.trim().length < 3) {
      setErrorMessage('Description must be at least 3 characters long.');
      return;
    }

    setIsSubmitting(true);
    try {
      const payload: IncidentCreateContract = {
        category,
        description: description.trim(),
        latitude: latNum,
        longitude: lngNum,
        severity,
        source: 'CITIZEN',
        reporter_name: reporterName.trim() || 'Citizen Anonymous',
      };

      const result = await apiClient.createIncident(payload);
      setCreatedIncident(result);
      onIncidentCreated(result);
      onToggleMapPick(false);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to submit citizen report';
      setErrorMessage(msg);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleResetAndClose = () => {
    setCreatedIncident(null);
    setDescription('');
    setReporterName('');
    setErrorMessage(null);
    onToggleMapPick(false);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-[2000] flex items-center justify-center overflow-y-auto bg-black/75 backdrop-blur-sm p-3 sm:p-4">
      <div className="flex max-h-[calc(100dvh-1.5rem)] w-full max-w-lg flex-col overflow-hidden rounded-lg border border-slate-700 bg-slate-900 font-mono text-sm shadow-2xl sm:max-h-[calc(100dvh-2rem)]">
        {/* Header */}
        <div className="flex shrink-0 items-center justify-between border-b border-slate-700 bg-slate-800/90 px-4 py-3">
          <div className="flex items-center space-x-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse"></span>
            <h3 className="text-white font-bold tracking-wider text-sm uppercase">
              Citizen Drainage Incident Report
            </h3>
          </div>
          <button
            onClick={handleResetAndClose}
            className="text-slate-400 hover:text-white transition-colors"
            title="Close"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Success Confirmation View */}
        {createdIncident ? (
          <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain p-6 space-y-4">
            <div className="p-4 bg-emerald-950/60 border border-emerald-500/50 rounded-lg flex items-start space-x-3">
              <CheckCircle className="w-6 h-6 text-emerald-400 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <h4 className="text-emerald-300 font-bold">Report Lodged Successfully</h4>
                <p className="text-xs text-slate-300">
                  Your incident has been dispatched to Panaji Municipal Operations and pinned on the GIS map.
                </p>
                <div className="pt-2 text-xs font-mono space-y-1">
                  <div>
                    <span className="text-slate-400">Tracking Ticket: </span>
                    <strong className="text-cyan-300 font-bold">{createdIncident.id}</strong>
                  </div>
                  <div>
                    <span className="text-slate-400">Status: </span>
                    <span className="px-1.5 py-0.5 rounded bg-blue-900/60 text-blue-300 border border-blue-700 text-[10px] font-bold">
                      {createdIncident.status}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-400">Coordinates: </span>
                    <span className="text-white">
                      {createdIncident.latitude.toFixed(4)}°N, {createdIncident.longitude.toFixed(4)}°E
                    </span>
                  </div>
                </div>
              </div>
            </div>

            <div className="flex justify-end space-x-2 pt-2">
              <button
                type="button"
                onClick={() => {
                  setCreatedIncident(null);
                  setDescription('');
                }}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded border border-slate-600 text-xs transition"
              >
                Submit Another Report
              </button>
              <button
                type="button"
                onClick={handleResetAndClose}
                className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white font-bold rounded text-xs transition"
              >
                View on Operations Map
              </button>
            </div>
          </div>
        ) : (
          /* Form View */
          <form onSubmit={handleSubmit} className="flex min-h-0 flex-1 flex-col overflow-hidden">
            <div className="min-h-0 flex-1 space-y-4 overflow-y-auto overscroll-contain p-4 sm:p-5">
            {errorMessage && (
              <div className="p-3 bg-rose-950/70 border border-rose-500 rounded text-rose-200 text-xs flex items-center space-x-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{errorMessage}</span>
              </div>
            )}

            {/* Quick Landmark Buttons */}
            <div>
              <label className="block text-[11px] text-slate-400 uppercase tracking-wider mb-1.5">
                Quick Geo-Location Presets (Panaji, Goa)
              </label>
              <div className="grid grid-cols-2 gap-1.5">
                {PANJIM_QUICK_LANDMARKS.map((lm) => (
                  <button
                    key={lm.name}
                    type="button"
                    onClick={() => {
                      setLatitude(lm.lat.toFixed(4));
                      setLongitude(lm.lng.toFixed(4));
                    }}
                    className="text-left px-2 py-1.5 bg-slate-800/80 hover:bg-slate-700/80 border border-slate-700 rounded text-[11px] text-slate-300 hover:text-cyan-300 transition truncate"
                  >
                    📍 {lm.name}
                  </button>
                ))}
              </div>
            </div>

            {/* Coordinates and Map Picker Toggle */}
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-[11px] text-slate-400 uppercase tracking-wider mb-1">
                  Latitude (°N)
                </label>
                <input
                  type="number"
                  step="0.0001"
                  value={latitude}
                  onChange={(e) => setLatitude(e.target.value)}
                  required
                  className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-500"
                />
              </div>
              <div>
                <label className="block text-[11px] text-slate-400 uppercase tracking-wider mb-1">
                  Longitude (°E)
                </label>
                <input
                  type="number"
                  step="0.0001"
                  value={longitude}
                  onChange={(e) => setLongitude(e.target.value)}
                  required
                  className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            {/* Map Click Pick Mode Toggle */}
            <div className="flex items-center justify-between p-2.5 bg-slate-950/60 border border-slate-800 rounded">
              <div className="flex items-center space-x-2 text-xs text-slate-300">
                <Crosshair className={`w-4 h-4 ${isPickingOnMap ? 'text-amber-400 animate-spin' : 'text-slate-400'}`} />
                <span>
                  {isPickingOnMap
                    ? 'Map Click Mode ACTIVE — Click anywhere on the GIS map'
                    : 'Pin exact coordinates on Leaflet map'}
                </span>
              </div>
              <button
                type="button"
                onClick={() => onToggleMapPick(!isPickingOnMap)}
                className={`px-2.5 py-1 rounded text-[11px] font-bold border transition ${
                  isPickingOnMap
                    ? 'bg-amber-600/30 text-amber-300 border-amber-500'
                    : 'bg-slate-800 text-slate-300 border-slate-600 hover:border-slate-500'
                }`}
              >
                {isPickingOnMap ? 'Done Picking' : 'Pick on Map'}
              </button>
            </div>

            {/* Category & Severity */}
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-[11px] text-slate-400 uppercase tracking-wider mb-1">
                  Hazard Category
                </label>
                <select
                  value={category}
                  onChange={(e) => setCategory(e.target.value as IncidentCategory)}
                  className="w-full bg-slate-950 border border-slate-700 rounded px-2 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-500"
                >
                  <option value="DRAIN_BLOCKAGE">Drain Blockage</option>
                  <option value="DRAIN_OVERFLOW">Drain Overflow</option>
                  <option value="WATERLOGGING">Waterlogging</option>
                  <option value="FLOODING">Flooding</option>
                  <option value="MANHOLE_DAMAGE">Manhole Damage</option>
                  <option value="INFRASTRUCTURE_DAMAGE">Infrastructure Damage</option>
                  <option value="OTHER">Other Hazard</option>
                </select>
              </div>

              <div>
                <label className="block text-[11px] text-slate-400 uppercase tracking-wider mb-1">
                  Perceived Severity
                </label>
                <select
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value as IncidentSeverity)}
                  className="w-full bg-slate-950 border border-slate-700 rounded px-2 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-500"
                >
                  <option value="LOW">Low (Nuisance)</option>
                  <option value="MEDIUM">Medium (Pedestrian Impact)</option>
                  <option value="HIGH">High (Traffic Blocked / Inflow Risk)</option>
                  <option value="CRITICAL">Critical (Property / Inundation Danger)</option>
                </select>
              </div>
            </div>

            {/* Reporter Name */}
            <div>
              <label className="block text-[11px] text-slate-400 uppercase tracking-wider mb-1">
                Reporter Identifier (Optional)
              </label>
              <input
                type="text"
                placeholder="e.g. J. Coutinho, St. Inez Resident"
                value={reporterName}
                onChange={(e) => setReporterName(e.target.value)}
                maxLength={100}
                className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-500 placeholder:text-slate-600"
              />
            </div>

            {/* Description */}
            <div>
              <label className="block text-[11px] text-slate-400 uppercase tracking-wider mb-1">
                Hazard Description & Observations *
              </label>
              <textarea
                required
                rows={3}
                placeholder="Describe the drainage issue (e.g., choked curb grate, rising water depth, fallen tree branch in canal)..."
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded px-2.5 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-500 placeholder:text-slate-600 resize-none"
              />
            </div>

            </div>

            {/* Fixed form actions remain visible while the form fields scroll. */}
            <div className="flex shrink-0 justify-end space-x-2 border-t border-slate-800 bg-slate-900 px-4 py-3 sm:px-5">
              <button
                type="button"
                onClick={handleResetAndClose}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs transition"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isSubmitting}
                className="flex items-center space-x-1.5 px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white font-bold rounded text-xs transition disabled:opacity-50"
              >
                {isSubmitting ? (
                  <span>Submitting...</span>
                ) : (
                  <>
                    <Send className="w-3.5 h-3.5" />
                    <span>Lodge Report</span>
                  </>
                )}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};
