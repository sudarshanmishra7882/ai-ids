// ============================================================
// LIVE LOG FEED — Streaming Network Event Log Table
// ============================================================

import React, { useRef } from 'react';
import { DetectionResult } from '../types/ids';
import { format } from 'date-fns';

interface LiveLogFeedProps {
  history: DetectionResult[];
}

const ALERT_BADGE = {
  LOW: 'bg-green-900/50 text-green-400 border-green-500/40',
  MEDIUM: 'bg-amber-900/50 text-amber-400 border-amber-500/40',
  HIGH: 'bg-red-900/50 text-red-400 border-red-500/40',
  CRITICAL: 'bg-purple-900/50 text-purple-400 border-purple-500/40',
};

const ROW_BG = {
  LOW: 'hover:bg-green-950/20',
  MEDIUM: 'hover:bg-amber-950/20',
  HIGH: 'hover:bg-red-950/30 bg-red-950/10',
  CRITICAL: 'hover:bg-purple-950/30 bg-purple-950/10',
};

export const LiveLogFeed: React.FC<LiveLogFeedProps> = ({ history }) => {
  const bottomRef = useRef<HTMLDivElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  {/* Auto-scroll removed — free manual scrolling enabled */}

  const reversed = [...history].reverse().slice(0, 50);

  return (
    <div className="bg-slate-900/60 rounded-xl border border-slate-700/50 flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-700/50">
        <div>
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Live Event Log</h3>
          <p className="text-xs text-slate-500 font-mono">{history.length} events · streaming</p>
        </div>
        {/* Manual scroll — up/down navigation freely enabled */}
      </div>

      {/* Table header */}
      <div className="grid grid-cols-[64px_minmax(0,1fr)_minmax(0,1fr)_52px_56px_48px_68px_48px] gap-2 px-4 py-2 text-xs font-mono text-slate-600 uppercase tracking-wider border-b border-slate-800">
        <span className="truncate">Time</span>
        <span className="truncate">Source IP</span>
        <span className="truncate">Dest IP</span>
        <span className="truncate">Q/min</span>
        <span className="truncate">Pkt</span>
        <span className="truncate">Risk</span>
        <span className="truncate">Alert</span>
        <span className="truncate">Score</span>
      </div>

      {/* Log entries */}
      <div
        ref={containerRef}
        className="overflow-y-auto"
        style={{ maxHeight: 360 }}
      >
        {reversed.length === 0 ? (
          <div className="flex items-center justify-center h-24 text-slate-600 text-sm font-mono">
            Waiting for events…
          </div>
        ) : (
          reversed.map((entry, idx) => (
            <div
              key={entry.log.id}
              className={`grid grid-cols-[64px_minmax(0,1fr)_minmax(0,1fr)_52px_56px_48px_68px_48px] gap-2 px-4 py-2 text-xs font-mono border-b border-slate-800/50 transition-colors ${ROW_BG[entry.alert]} ${idx === 0 ? 'animate-pulse-once' : ''}`}
            >
              <span className="text-slate-500">
                {format(new Date(entry.log.timestamp), 'HH:mm:ss')}
              </span>
              <span className="text-slate-400 truncate">{entry.log.sourceIP}</span>
              <span className={`truncate ${entry.log.isExternalIP ? 'text-orange-400' : 'text-slate-400'}`}>
                {entry.log.destIP}
              </span>
              <span className={`${entry.log.queryFrequency > 100 ? 'text-red-400 font-bold' : 'text-slate-400'}`}>
                {entry.log.queryFrequency}
              </span>
              <span className={`${entry.log.packetSize > 1200 ? 'text-orange-400' : 'text-slate-400'}`}>
                {entry.log.packetSize}B
              </span>
              <span className={`font-bold ${
                entry.riskScore >= 70 ? 'text-red-400' :
                entry.riskScore >= 40 ? 'text-amber-400' : 'text-green-400'
              }`}>
                {entry.riskScore}
              </span>
              <span>
                <span className={`px-1.5 py-0.5 rounded text-xs font-bold border ${ALERT_BADGE[entry.alert]}`}>
                  {entry.alert}
                </span>
              </span>
              <span className="text-slate-500">
                {(entry.confidence * 100).toFixed(0)}%
              </span>
            </div>
          ))
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  );
};
