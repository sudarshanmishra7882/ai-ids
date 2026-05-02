// ============================================================
// NETWORK TOPOLOGY — Live Visual Network Map
// ============================================================

import React from 'react';
import { DetectionResult } from '../types/ids';

interface NetworkTopologyProps {
  latestResult: DetectionResult | null;
}

const NODE_SIZE = 36;

interface Node {
  id: string;
  x: number;
  y: number;
  label: string;
  type: 'core' | 'internal' | 'external' | 'threat';
  color: string;
  borderColor: string;
}

const NODES: Node[] = [
  { id: 'core', x: 300, y: 140, label: 'CORE\nROUTER', type: 'core', color: '#1e3a5f', borderColor: '#3b82f6' },
  { id: 'db', x: 160, y: 70, label: 'DB\nSERVER', type: 'internal', color: '#1a3a1a', borderColor: '#22c55e' },
  { id: 'app', x: 440, y: 70, label: 'APP\nSERVER', type: 'internal', color: '#1a3a1a', borderColor: '#22c55e' },
  { id: 'atm', x: 160, y: 210, label: 'ATM\nNODE', type: 'internal', color: '#1a3a1a', borderColor: '#22c55e' },
  { id: 'ws', x: 440, y: 210, label: 'WORK\nSTATN', type: 'internal', color: '#1a2a3a', borderColor: '#60a5fa' },
  { id: 'fw', x: 300, y: 260, label: 'FIRE\nWALL', type: 'core', color: '#2a1a00', borderColor: '#f59e0b' },
  { id: 'inet', x: 300, y: 340, label: 'INTERNET', type: 'external', color: '#1a1a2a', borderColor: '#6366f1' },
  { id: 'c2', x: 480, y: 340, label: 'C2\nSERVER', type: 'threat', color: '#2a0a0a', borderColor: '#ef4444' },
];

const EDGES = [
  { from: 'core', to: 'db' },
  { from: 'core', to: 'app' },
  { from: 'core', to: 'atm' },
  { from: 'core', to: 'ws' },
  { from: 'core', to: 'fw' },
  { from: 'fw', to: 'inet' },
];

function getNodeById(id: string): Node | undefined {
  return NODES.find(n => n.id === id);
}

export const NetworkTopology: React.FC<NetworkTopologyProps> = ({ latestResult }) => {
  const isAttacking = latestResult && latestResult.alert !== 'LOW';
  const activeEdge = isAttacking
    ? latestResult.signals.find(s => s.detected && s.type === 'UNKNOWN_IP')
      ? { from: 'ws', to: 'c2', alert: latestResult.alert }
      : latestResult.signals.find(s => s.detected && s.type === 'DB_SPIKE')
      ? { from: 'ws', to: 'db', alert: latestResult.alert }
      : null
    : null;

  const width = 580;
  const height = 400;

  return (
    <div className="bg-slate-900/60 rounded-xl border border-slate-700/50 p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Network Topology</h3>
        {isAttacking && (
          <span className="text-xs font-mono text-red-400 animate-pulse">⚠ THREAT PATH ACTIVE</span>
        )}
      </div>

      <div className="relative overflow-hidden rounded-lg bg-slate-950/50" style={{ height: 390 }}>
        <svg width="100%" height="100%" viewBox={`0 0 ${width} ${height}`} className="absolute inset-0">
          {/* Grid background */}
          <defs>
            <pattern id="netgrid" width="30" height="30" patternUnits="userSpaceOnUse">
              <path d="M 30 0 L 0 0 0 30" fill="none" stroke="#1e293b" strokeWidth="0.5" />
            </pattern>
            <filter id="glow-red">
              <feGaussianBlur stdDeviation="3" result="coloredBlur" />
              <feMerge><feMergeNode in="coloredBlur" /><feMergeNode in="SourceGraphic" /></feMerge>
            </filter>
            <filter id="glow-blue">
              <feGaussianBlur stdDeviation="2" result="coloredBlur" />
              <feMerge><feMergeNode in="coloredBlur" /><feMergeNode in="SourceGraphic" /></feMerge>
            </filter>
          </defs>
          <rect width={width} height={height} fill="url(#netgrid)" />

          {/* Static edges */}
          {EDGES.map(edge => {
            const from = getNodeById(edge.from);
            const to = getNodeById(edge.to);
            if (!from || !to) return null;
            return (
              <line
                key={`${edge.from}-${edge.to}`}
                x1={from.x} y1={from.y}
                x2={to.x} y2={to.y}
                stroke="#1e3a5f"
                strokeWidth={1.5}
                strokeDasharray="5 3"
              />
            );
          })}

          {/* Active threat edge */}
          {activeEdge && (() => {
            const from = getNodeById(activeEdge.from);
            const to = getNodeById(activeEdge.to);
            if (!from || !to) return null;
            const color = activeEdge.alert === 'HIGH' ? '#ef4444' : '#f59e0b';
            return (
              <g filter="url(#glow-red)">
                <line
                  x1={from.x} y1={from.y}
                  x2={to.x} y2={to.y}
                  stroke={color}
                  strokeWidth={2.5}
                  strokeDasharray="8 4"
                  className="animate-dash"
                  style={{ animation: 'dash 1s linear infinite' }}
                />
              </g>
            );
          })()}

          {/* C2 connection when attacking with unknown IP */}
          {isAttacking && latestResult?.signals.find(s => s.detected && s.type === 'UNKNOWN_IP') && (() => {
            const fw = getNodeById('fw');
            const c2 = getNodeById('c2');
            if (!fw || !c2) return null;
            return (
              <g filter="url(#glow-red)">
                <line
                  x1={fw.x} y1={fw.y}
                  x2={c2.x} y2={c2.y}
                  stroke="#ef4444"
                  strokeWidth={3}
                  strokeDasharray="6 3"
                  opacity={0.8}
                />
              </g>
            );
          })()}

          {/* Nodes */}
          {NODES.map(node => {
            const isC2 = node.id === 'c2';
            const isActive = isAttacking && (
              (latestResult?.signals.find(s => s.detected && s.type === 'UNKNOWN_IP') && isC2) ||
              (latestResult?.signals.find(s => s.detected && s.type === 'DB_SPIKE') && node.id === 'db')
            );

            return (
              <g key={node.id}>
                {/* Glow ring for active threat */}
                {isActive && (
                  <circle
                    cx={node.x} cy={node.y} r={NODE_SIZE / 2 + 8}
                    fill="none"
                    stroke="#ef4444"
                    strokeWidth={2}
                    opacity={0.4}
                    filter="url(#glow-red)"
                  />
                )}
                {/* Node circle */}
                <circle
                  cx={node.x} cy={node.y} r={NODE_SIZE / 2}
                  fill={node.color}
                  stroke={isActive ? '#ef4444' : node.borderColor}
                  strokeWidth={isActive ? 2.5 : 1.5}
                  filter={isActive ? 'url(#glow-red)' : undefined}
                />
                {/* Label */}
                {node.label.split('\n').map((line, li) => (
                  <text
                    key={li}
                    x={node.x} y={node.y + (li - 0.3) * 11}
                    textAnchor="middle"
                    dominantBaseline="middle"
                    fontSize={8}
                    fontFamily="monospace"
                    fontWeight="bold"
                    fill={isActive ? '#ef4444' : node.borderColor}
                  >
                    {line}
                  </text>
                ))}
              </g>
            );
          })}

          {/* Data flow particles when attacking */}
          {isAttacking && (
            <circle r="4" fill="#ef4444" opacity="0.8" filter="url(#glow-red)">
              <animateMotion dur="2s" repeatCount="indefinite" path="M 440 210 L 300 140 L 300 260 L 480 340" />
            </circle>
          )}
        </svg>

        {/* Legend */}
        <div className="absolute bottom-3 left-3 flex gap-3">
          {[
            { color: '#22c55e', label: 'Internal' },
            { color: '#3b82f6', label: 'Core' },
            { color: '#ef4444', label: 'Threat' },
          ].map(l => (
            <div key={l.label} className="flex items-center gap-1">
              <div className="w-2 h-2 rounded-full" style={{ backgroundColor: l.color }} />
              <span className="text-xs text-slate-500 font-mono">{l.label}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
