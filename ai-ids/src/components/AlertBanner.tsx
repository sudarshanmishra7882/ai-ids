// ============================================================
// ALERT BANNER — Top-Level Risk Indicator
// ============================================================

import React from 'react';
import { AlertLevel, AttackPhase } from '../types/ids';
import { getPhaseLabel } from '../engine/idsEngine';
import { ShieldAlert, ShieldCheck, ShieldOff, Zap } from 'lucide-react';

interface AlertBannerProps {
  alert: AlertLevel;
  riskScore: number;
  confidence: number;
  attackPhase: AttackPhase;
  totalLogs: number;
  isRunning: boolean;
}

const configs = {
  LOW: {
    bg: 'from-green-950/80 to-green-900/40',
    border: 'border-green-500/50',
    text: 'text-green-300',
    accent: 'text-green-400',
    glow: 'shadow-green-500/20',
    icon: ShieldCheck,
    label: 'SECURE',
    pulse: 'bg-green-400',
  },
  MEDIUM: {
    bg: 'from-amber-950/80 to-amber-900/40',
    border: 'border-amber-500/50',
    text: 'text-amber-300',
    accent: 'text-amber-400',
    glow: 'shadow-amber-500/20',
    icon: ShieldOff,
    label: 'SUSPICIOUS',
    pulse: 'bg-amber-400',
  },
  HIGH: {
    bg: 'from-red-950/80 to-red-900/40',
    border: 'border-red-500/50',
    text: 'text-red-300',
    accent: 'text-red-400',
    glow: 'shadow-red-500/30',
    icon: ShieldAlert,
    label: 'THREAT DETECTED',
    pulse: 'bg-red-400',
  },
  CRITICAL: {
    bg: 'from-purple-950/80 to-purple-900/40',
    border: 'border-purple-500/50',
    text: 'text-purple-300',
    accent: 'text-purple-400',
    glow: 'shadow-purple-500/30',
    icon: Zap,
    label: 'CRITICAL BREACH',
    pulse: 'bg-purple-400',
  },
};

export const AlertBanner: React.FC<AlertBannerProps> = ({
  alert,
  riskScore,
  confidence,
  attackPhase,
  totalLogs,
  isRunning,
}) => {
  const cfg = configs[alert];
  const Icon = cfg.icon;

  return (
    <div className={`relative rounded-xl border bg-gradient-to-r ${cfg.bg} ${cfg.border} shadow-lg ${cfg.glow} p-5 overflow-hidden`}>
      {/* Animated background grid */}
      <div className="absolute inset-0 opacity-5"
        style={{
          backgroundImage: 'repeating-linear-gradient(0deg,transparent,transparent 24px,rgba(255,255,255,.3) 25px),repeating-linear-gradient(90deg,transparent,transparent 24px,rgba(255,255,255,.3) 25px)',
        }}
      />

      {/* Pulse indicator */}
      {isRunning && (
        <div className="absolute top-4 right-4 flex items-center gap-2">
          <span className={`relative flex h-3 w-3`}>
            <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${cfg.pulse} opacity-75`}></span>
            <span className={`relative inline-flex rounded-full h-3 w-3 ${cfg.pulse}`}></span>
          </span>
          <span className={`text-xs font-mono ${cfg.text} opacity-70`}>LIVE</span>
        </div>
      )}

      <div className="flex items-center gap-6">
        {/* Icon */}
        <div className={`p-3 rounded-xl border ${cfg.border} bg-black/30`}>
          <Icon className={`w-8 h-8 ${cfg.accent} ${alert === 'HIGH' || alert === 'CRITICAL' ? 'animate-pulse' : ''}`} />
        </div>

        {/* Main Info */}
        <div className="flex-1">
          <div className="flex items-center gap-3 mb-1">
            <span className={`text-2xl font-black tracking-widest ${cfg.accent}`}>{cfg.label}</span>
            <span className={`px-2 py-0.5 rounded-full text-xs font-bold border ${cfg.border} ${cfg.text} bg-black/30`}>
              {alert}
            </span>
          </div>
          <div className={`text-sm font-mono ${cfg.text} opacity-80`}>
            {getPhaseLabel(attackPhase)} · {totalLogs.toLocaleString()} events processed
          </div>
        </div>

        {/* Risk Score */}
        <div className="text-right">
          <div className={`text-5xl font-black font-mono ${cfg.accent}`}>{riskScore}</div>
          <div className={`text-xs ${cfg.text} opacity-60 mt-1`}>RISK SCORE / 100</div>
        </div>

        {/* Confidence */}
        <div className="text-right min-w-[90px]">
          <div className={`text-2xl font-bold font-mono ${cfg.accent}`}>{(confidence * 100).toFixed(0)}%</div>
          <div className={`text-xs ${cfg.text} opacity-60`}>CONFIDENCE</div>
          <div className="mt-2 w-full bg-black/40 rounded-full h-1.5">
            <div
              className={`h-1.5 rounded-full transition-all duration-700 ${alert === 'HIGH' ? 'bg-red-400' : alert === 'MEDIUM' ? 'bg-amber-400' : 'bg-green-400'}`}
              style={{ width: `${confidence * 100}%` }}
            />
          </div>
        </div>
      </div>
    </div>
  );
};
