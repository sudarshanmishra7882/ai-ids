// ============================================================
// SIGNAL BREAKDOWN — Weighted Signal Weight Display
// ============================================================

import React from 'react';
import { AnomalySignal } from '../types/ids';
import { Radio, Database, Globe, UserX, Lock, Package } from 'lucide-react';

interface SignalBreakdownProps {
  signals: AnomalySignal[];
}

const SIGNAL_CONFIG = {
  BEACONING: {
    icon: Radio,
    label: 'Beaconing Pattern',
    color: 'text-orange-400',
    bg: 'bg-orange-900/30',
    border: 'border-orange-500/40',
    barColor: 'bg-orange-500',
  },
  DB_SPIKE: {
    icon: Database,
    label: 'DB Query Spike',
    color: 'text-red-400',
    bg: 'bg-red-900/30',
    border: 'border-red-500/40',
    barColor: 'bg-red-500',
  },
  UNKNOWN_IP: {
    icon: Globe,
    label: 'Unknown External IP',
    color: 'text-yellow-400',
    bg: 'bg-yellow-900/30',
    border: 'border-yellow-500/40',
    barColor: 'bg-yellow-500',
  },
  PRIVILEGED_MISUSE: {
    icon: UserX,
    label: 'Privileged Misuse',
    color: 'text-purple-400',
    bg: 'bg-purple-900/30',
    border: 'border-purple-500/40',
    barColor: 'bg-purple-500',
  },
  TLS_ANOMALY: {
    icon: Lock,
    label: 'TLS Fingerprint',
    color: 'text-blue-400',
    bg: 'bg-blue-900/30',
    border: 'border-blue-500/40',
    barColor: 'bg-blue-500',
  },
  PACKET_ANOMALY: {
    icon: Package,
    label: 'Packet Anomaly',
    color: 'text-cyan-400',
    bg: 'bg-cyan-900/30',
    border: 'border-cyan-500/40',
    barColor: 'bg-cyan-500',
  },
};

export const SignalBreakdown: React.FC<SignalBreakdownProps> = ({ signals }) => {
  const totalWeight = signals.filter(s => s.detected).reduce((s, sig) => s + sig.weight, 0);
  const maxWeight = signals.reduce((s, sig) => s + sig.weight, 0);

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Signal Weights</h3>
        <div className="text-xs font-mono text-slate-400">
          {totalWeight}/{maxWeight} pts
        </div>
      </div>

      {signals.map((signal) => {
        const cfg = SIGNAL_CONFIG[signal.type];
        const Icon = cfg.icon;
        const barWidth = (signal.weight / maxWeight) * 100;

        return (
          <div
            key={signal.type}
            className={`rounded-lg border p-3 transition-all duration-500 ${
              signal.detected
                ? `${cfg.bg} ${cfg.border}`
                : 'bg-slate-900/30 border-slate-700/30'
            }`}
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <Icon className={`w-4 h-4 ${signal.detected ? cfg.color : 'text-slate-600'}`} />
                <span className={`text-xs font-medium ${signal.detected ? cfg.color : 'text-slate-500'}`}>
                  {cfg.label}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className={`text-xs font-mono ${signal.detected ? cfg.color : 'text-slate-600'}`}>
                  +{signal.weight}
                </span>
                <span className={`text-xs px-1.5 py-0.5 rounded font-bold ${
                  signal.detected
                    ? 'bg-red-900/50 text-red-300 border border-red-500/40'
                    : 'bg-green-900/30 text-green-600 border border-green-700/30'
                }`}>
                  {signal.detected ? 'HIT' : 'OK'}
                </span>
              </div>
            </div>

            {/* Weight bar */}
            <div className="w-full bg-slate-800/60 rounded-full h-1.5">
              <div
                className={`h-1.5 rounded-full transition-all duration-700 ${signal.detected ? cfg.barColor : 'bg-slate-700'}`}
                style={{ width: signal.detected ? `${barWidth}%` : '0%' }}
              />
            </div>

            {/* Description */}
            <div className={`text-xs mt-1.5 font-mono leading-tight ${signal.detected ? 'text-slate-400' : 'text-slate-600'}`}>
              {signal.description.length > 80 ? signal.description.slice(0, 78) + '…' : signal.description}
            </div>
          </div>
        );
      })}
    </div>
  );
};
