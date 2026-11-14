import React, { useState } from 'react';
import {
  MechanismStatusContract,
  BlockageEventContract,
  PredictionContract,
  ActuatorDirectiveContract,
  SensorReadingContract,
} from '../types/contracts';
import { GitBranch, Layers, Box } from 'lucide-react';
import { LongitudinalSideDrainTwin } from './LongitudinalSideDrainTwin';
import { DiversionGateTwin } from './DiversionGateTwin';

export interface DigitalTwinProps {
  upstreamDepth: number; // h1 in cm
  weirHead: number;      // hw in cm
  pumpInflow: number;    // Qin in L/min
  mechanism: MechanismStatusContract;
  blockage: BlockageEventContract | null;
  prediction: PredictionContract | null;
  mode?: 'SIMULATION' | 'HARDWARE' | 'PHYSICAL' | 'SAFE_HOLD';
  gateDirective?: ActuatorDirectiveContract | null;
  readings?: Record<string, SensorReadingContract>;
  activeAlertsCount?: number;
  hardwareValidationStage?: string | null;
  isDemoMode?: boolean;
}

export const DigitalTwin: React.FC<DigitalTwinProps> = ({
  upstreamDepth,
  weirHead,
  pumpInflow,
  mechanism,
  blockage,
  prediction,
  mode = 'SIMULATION',
  gateDirective = null,
  readings = {},
  activeAlertsCount = 0,
  hardwareValidationStage = null,
  isDemoMode = false,
}) => {
  const [activeView, setActiveView] = useState<'prototype' | 'gate' | 'dual'>('prototype');

  // Blockage severity fraction
  const blockageSeverity = blockage?.severity || (mechanism.debris_retained_pct / 100);

  return (
    <div className="space-y-6 mb-6">
      {/* SCADA Digital Twin View Switcher */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-900 border border-slate-800 px-4 py-2.5 rounded shadow">
        <div className="flex items-center gap-2">
          <Layers className="w-4 h-4 text-cyan-400" />
          <span className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider">
            SCADA TWIN DISPLAY MODE:
          </span>
        </div>
        <div className="flex items-center gap-1.5 font-mono text-xs">
          <button
            onClick={() => setActiveView('prototype')}
            className={`px-3 py-1 rounded transition-colors flex items-center gap-1.5 ${
              activeView === 'prototype'
                ? 'bg-cyan-950 text-cyan-300 font-bold border border-cyan-700 shadow-sm'
                : 'bg-slate-800/80 text-slate-400 hover:text-slate-200 border border-slate-700/60'
            }`}
          >
            <Box className="w-3.5 h-3.5" />
            <span>3D SIDE-DRAIN TWIN (PHYSICAL PROTOTYPE)</span>
          </button>
          <button
            onClick={() => setActiveView('gate')}
            className={`px-3 py-1 rounded transition-colors flex items-center gap-1.5 ${
              activeView === 'gate'
                ? 'bg-cyan-950 text-cyan-300 font-bold border border-cyan-700 shadow-sm'
                : 'bg-slate-800/80 text-slate-400 hover:text-slate-200 border border-slate-700/60'
            }`}
          >
            <GitBranch className="w-3.5 h-3.5" />
            <span>ACTUATOR KINEMATICS &amp; BIFURCATION</span>
          </button>
          <button
            onClick={() => setActiveView('dual')}
            className={`px-3 py-1 rounded transition-colors flex items-center gap-1.5 ${
              activeView === 'dual'
                ? 'bg-cyan-950 text-cyan-300 font-bold border border-cyan-700 shadow-sm'
                : 'bg-slate-800/80 text-slate-400 hover:text-slate-200 border border-slate-700/60'
            }`}
          >
            <span>DUAL MULTI-TWIN VIEW</span>
          </button>
        </div>
      </div>

      {/* 1. Authoritative 3D Longitudinal Side-Drain Physical Prototype Twin */}
      {(activeView === 'prototype' || activeView === 'dual') && (
        <LongitudinalSideDrainTwin
          upstreamDepth={upstreamDepth}
          inflow={pumpInflow}
          weirHead={weirHead}
          mode={mode}
          mechanism={mechanism}
          blockage={blockage}
          prediction={prediction}
          gateDirective={gateDirective}
          readings={readings}
          activeAlertsCount={activeAlertsCount}
          hardwareValidationStage={hardwareValidationStage}
          isDemoMode={isDemoMode}
        />
      )}

      {/* 2. Physical Diversion Gate Actuator Kinematics & Bifurcation Twin */}
      {(activeView === 'gate' || activeView === 'dual') && (
        <DiversionGateTwin
          mode={mode === 'SIMULATION' ? 'SIMULATION' : 'HARDWARE'}
          upstreamDepth={upstreamDepth}
          weirHead={weirHead}
          inflow={pumpInflow}
          gateDirective={gateDirective}
          readings={readings}
          activeAlertsCount={activeAlertsCount}
          isFault={mechanism.is_fault}
        />
      )}

      {/* High-Contrast SCADA Hydraulic & Prediction Status Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 mt-3 text-xs font-mono">
        <div className="p-2.5 rounded bg-slate-950/70 border border-slate-800">
          <span className="text-slate-400 block text-[10px] uppercase">Channel Water Level</span>
          <span className={`text-base font-bold ${upstreamDepth >= 11.0 ? 'text-amber-400' : 'text-cyan-300'}`}>
            {upstreamDepth.toFixed(1)} cm
          </span>
          <span className="text-[9px] text-slate-400 block mt-0.5">Overhead Radar Measurement</span>
        </div>

        <div className="p-2.5 rounded bg-slate-950/70 border border-slate-800">
          <span className="text-slate-400 block text-[10px] uppercase">Screen Occlusion (β)</span>
          <span
            className={`text-base font-bold ${
              blockageSeverity >= 0.55
                ? 'text-rose-400'
                : blockageSeverity >= 0.25
                ? 'text-amber-400'
                : 'text-emerald-400'
            }`}
          >
            {(blockageSeverity * 100).toFixed(0)}%
          </span>
          <span className="text-[9px] text-slate-400 block mt-0.5">
            {blockage ? `Excess Head: +${blockage.differential_head_cm.toFixed(1)}cm` : '400x500mm Screen Clean'}
          </span>
        </div>

        <div className="p-2.5 rounded bg-slate-950/70 border border-slate-800">
          <span className="text-slate-400 block text-[10px] uppercase">Prediction Horizon</span>
          <span
            className={`text-base font-bold ${
              prediction?.state === 'OVERFLOW'
                ? 'text-rose-400 animate-pulse'
                : prediction?.state === 'ESTIMATING'
                ? 'text-amber-400'
                : 'text-slate-200'
            }`}
          >
            {prediction?.state === 'OVERFLOW'
              ? 'OVERFLOW'
              : prediction?.state === 'ESTIMATING' &&
                prediction.ttc_seconds !== null &&
                prediction.ttc_seconds !== undefined
              ? `${prediction.ttc_seconds.toFixed(0)}s TTC`
              : 'STABLE'}
          </span>
          <span className="text-[9px] text-slate-400 block mt-0.5">
            Trend: {prediction?.rate_of_rise_cm_s ? `+${prediction.rate_of_rise_cm_s.toFixed(2)} cm/s` : 'Zero Rise'}
          </span>
        </div>

        <div className="p-2.5 rounded bg-slate-950/70 border border-slate-800">
          <span className="text-slate-400 block text-[10px] uppercase">Actuator Mechanism</span>
          <span className="font-semibold text-slate-200 text-xs truncate block" title={mechanism.current_action}>
            {mechanism.current_action || 'Standby monitoring'}
          </span>
          <span className="text-[9px] text-slate-400 block mt-0.5">
            DischargeKeeper &bull; Hinged Leaf Pivot
          </span>
        </div>
      </div>
    </div>
  );
};
