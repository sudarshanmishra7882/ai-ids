// ============================================================
// STATS PANEL — System Metrics Overview
// ============================================================

import React from 'react';
import { AlertLevel, Baseline, WindowStats } from '../types/ids';
import { Activity, Database, Wifi, Clock, Shield } from 'lucide-react';

interface StatsPanelProps {
  alertCounts: Record<AlertLevel, number>;
  baseline: Baseline;
  windowStats: WindowStats | null;
  totalLogs: number;
  isBusinessHours: boolean;
}



export const StatsPanel: React.FC<StatsPanelProps> = ({
  alertCounts,
  baseline,
  windowStats,
  totalLogs,
  isBusinessHours,
}) => {
  const total = Object.values(alertCounts).reduce((s, v) => s + v, 0);
  const highRate = total > 0 ? ((alertCounts.HIGH / total) * 100).toFixed(1) : '0.0';

  return (
    <div className="space-y-4">
      {/* Alert Summary */}
      <div className="bg-slate-900/60 rounded-xl border border-slate-700/50 p-4">
        <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">Alert Distribution</h3>
        <div className="grid grid-cols-3 gap-3">
          <div className="text-center">
            <div className="text-2xl font-black text-green-400 font-mono">{alertCounts.LOW}</div>
            <div className="text-xs text-green-600 font-mono">LOW</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-black text-amber-400 font-mono">{alertCounts.MEDIUM}</div>
            <div className="text-xs text-amber-600 font-mono">MEDIUM</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-black text-red-400 font-mono">{alertCounts.HIGH}</div>
            <div className="text-xs text-red-600 font-mono">HIGH</div>
          </div>
        </div>

        {/* Distribution bar */}
        {total > 0 && (
          <div className="mt-3 flex h-2 rounded-full overflow-hidden gap-0.5">
            <div className="bg-green-500 transition-all duration-700 rounded-l-full"
              style={{ width: `${(alertCounts.LOW / total) * 100}%` }} />
            <div className="bg-amber-500 transition-all duration-700"
              style={{ width: `${(alertCounts.MEDIUM / total) * 100}%` }} />
            <div className="bg-red-500 transition-all duration-700 rounded-r-full"
              style={{ width: `${(alertCounts.HIGH / total) * 100}%` }} />
          </div>
        )}
        <div className="flex justify-between text-xs font-mono text-slate-600 mt-1">
          <span>HIGH rate: {highRate}%</span>
          <span>{totalLogs} events</span>
        </div>
      </div>

      {/* Baseline Metrics */}
      <div className="bg-slate-900/60 rounded-xl border border-slate-700/50 p-4">
        <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">Behavioral Baseline</h3>
        <div className="space-y-3">
          {[
            {
              label: 'Avg Query Rate',
              value: `${baseline.avgQueryRate.toFixed(1)}/min`,
              icon: <Database className="w-3.5 h-3.5" />,
              color: 'text-blue-400',
            },
            {
              label: 'Avg Conn. Interval',
              value: `${baseline.avgInterval.toFixed(0)}ms`,
              icon: <Wifi className="w-3.5 h-3.5" />,
              color: 'text-cyan-400',
            },
            {
              label: 'Avg Packet Size',
              value: `${baseline.avgPacketSize.toFixed(0)}B`,
              icon: <Activity className="w-3.5 h-3.5" />,
              color: 'text-violet-400',
            },
            {
              label: 'Known IPs',
              value: `${baseline.knownIPs.length}`,
              icon: <Shield className="w-3.5 h-3.5" />,
              color: 'text-emerald-400',
            },
          ].map(m => (
            <div key={m.label} className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-slate-500">
                {m.icon}
                <span className="text-xs font-mono">{m.label}</span>
              </div>
              <span className={`text-xs font-mono font-bold ${m.color}`}>{m.value}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Window Stats */}
      {windowStats && (
        <div className="bg-slate-900/60 rounded-xl border border-slate-700/50 p-4">
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">60-sec Window</h3>
          <div className="space-y-3">
            {[
              {
                label: 'Interval Entropy',
                value: windowStats.intervalEntropy.toFixed(3),
                color: windowStats.intervalEntropy < 0.2 ? 'text-red-400' : 'text-slate-300',
                note: windowStats.intervalEntropy < 0.2 ? '⚠ BEACONING' : 'NORMAL',
                noteColor: windowStats.intervalEntropy < 0.2 ? 'text-red-400' : 'text-green-500',
              },
              {
                label: 'Ext. IP Freq.',
                value: `${(windowStats.externalIPFrequency * 100).toFixed(0)}%`,
                color: windowStats.externalIPFrequency > 0.5 ? 'text-orange-400' : 'text-slate-300',
                note: `${windowStats.uniqueExternalIPs.length} unique`,
                noteColor: 'text-slate-500',
              },
              {
                label: 'Avg Query Rate',
                value: `${windowStats.avgQueryRate.toFixed(1)}/min`,
                color: windowStats.avgQueryRate > 50 ? 'text-red-400' : 'text-slate-300',
                note: windowStats.avgQueryRate > 50 ? '⚠ SPIKE' : 'NORMAL',
                noteColor: windowStats.avgQueryRate > 50 ? 'text-red-400' : 'text-green-500',
              },
            ].map(m => (
              <div key={m.label} className="flex items-center justify-between">
                <span className="text-xs font-mono text-slate-500">{m.label}</span>
                <div className="flex items-center gap-2">
                  <span className={`text-xs font-mono font-bold ${m.color}`}>{m.value}</span>
                  <span className={`text-xs font-mono ${m.noteColor}`}>{m.note}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Time context */}
      <div className={`rounded-xl border p-4 flex items-center gap-3 ${
        isBusinessHours
          ? 'bg-blue-950/30 border-blue-500/30'
          : 'bg-orange-950/30 border-orange-500/30'
      }`}>
        <Clock className={`w-4 h-4 ${isBusinessHours ? 'text-blue-400' : 'text-orange-400'}`} />
        <div>
          <div className={`text-xs font-bold ${isBusinessHours ? 'text-blue-300' : 'text-orange-300'}`}>
            {isBusinessHours ? 'Business Hours' : 'Off-Hours Activity'}
          </div>
          <div className="text-xs text-slate-500 font-mono">
            {isBusinessHours ? 'FP threshold relaxed' : 'Risk amplification active'}
          </div>
        </div>
      </div>
    </div>
  );
};
