// ============================================================
// RISK GAUGE — Animated Circular Risk Meter
// ============================================================

import React from 'react';
import { AlertLevel } from '../types/ids';

interface RiskGaugeProps {
  riskScore: number;
  alert: AlertLevel;
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({ riskScore, alert }) => {
  const radius = 70;
  const strokeWidth = 10;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference - (riskScore / 100) * circumference;

  const color = alert === 'CRITICAL' ? '#a855f7'
    : alert === 'HIGH' ? '#ef4444'
    : alert === 'MEDIUM' ? '#f59e0b'
    : '#22c55e';

  const bgColor = alert === 'CRITICAL' ? '#581c8730'
    : alert === 'HIGH' ? '#991b1b30'
    : alert === 'MEDIUM' ? '#92400e30'
    : '#14532d30';

  const zones = [
    { label: 'LOW', start: 0, end: 40, color: '#22c55e' },
    { label: 'MED', start: 40, end: 70, color: '#f59e0b' },
    { label: 'HIGH', start: 70, end: 88, color: '#ef4444' },
    { label: 'CRIT', start: 88, end: 100, color: '#a855f7' },
  ];

  return (
    <div className="flex flex-col items-center">
      <div className="relative" style={{ width: 180, height: 180 }}>
        {/* Background glow */}
        <div
          className="absolute inset-0 rounded-full blur-xl opacity-20 transition-all duration-1000"
          style={{ backgroundColor: color }}
        />

        <svg width="180" height="180" viewBox="0 0 180 180" className="transform -rotate-90">
          {/* Background track */}
          <circle
            cx="90" cy="90" r={radius}
            fill="none"
            stroke="#1e293b"
            strokeWidth={strokeWidth}
          />

          {/* Zone indicators */}
          {zones.map((zone) => {
            const startAngle = (zone.start / 100) * circumference;
            const endAngle = (zone.end / 100) * circumference;
            const segmentLength = endAngle - startAngle;
            return (
              <circle
                key={zone.label}
                cx="90" cy="90" r={radius}
                fill="none"
                stroke={zone.color}
                strokeWidth={strokeWidth - 4}
                strokeDasharray={`${segmentLength} ${circumference - segmentLength}`}
                strokeDashoffset={circumference - startAngle}
                opacity={0.25}
                strokeLinecap="butt"
              />
            );
          })}

          {/* Main progress arc */}
          <circle
            cx="90" cy="90" r={radius}
            fill="none"
            stroke={color}
            strokeWidth={strokeWidth}
            strokeDasharray={`${circumference}`}
            strokeDashoffset={dashOffset}
            strokeLinecap="round"
            className="transition-all duration-700"
            style={{ filter: `drop-shadow(0 0 6px ${color})` }}
          />
        </svg>

        {/* Center content */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <div
            className="text-4xl font-black font-mono transition-all duration-700"
            style={{ color }}
          >
            {riskScore}
          </div>
          <div className="text-xs text-slate-400 font-mono">RISK</div>
          <div
            className="text-xs font-bold mt-1 px-2 py-0.5 rounded-full"
            style={{ backgroundColor: bgColor, color }}
          >
            {alert}
          </div>
        </div>
      </div>

      {/* Zone Legend */}
      <div className="flex gap-3 mt-2">
        {zones.map(z => (
          <div key={z.label} className="flex items-center gap-1">
            <div className="w-2 h-2 rounded-full" style={{ backgroundColor: z.color }} />
            <span className="text-xs text-slate-500 font-mono">{z.label} {z.start}–{z.end}</span>
          </div>
        ))}
      </div>
    </div>
  );
};
