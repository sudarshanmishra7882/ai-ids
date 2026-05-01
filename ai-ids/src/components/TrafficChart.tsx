// ============================================================
// TRAFFIC CHART — Real-Time Timeline Visualization
// ============================================================

import React from 'react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, ReferenceLine
} from 'recharts';
import { TimelinePoint } from '../types/ids';

interface TrafficChartProps {
  timeline: TimelinePoint[];
}

const CustomTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null;
  const risk = payload.find((p: any) => p.dataKey === 'riskScore');
  const queries = payload.find((p: any) => p.dataKey === 'queryRate');

  return (
    <div className="bg-slate-900 border border-slate-700 rounded-lg p-3 text-xs font-mono shadow-2xl">
      <div className="text-slate-400 mb-2">{label}</div>
      {risk && (
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-red-400 inline-block" />
          <span className="text-slate-300">Risk: </span>
          <span style={{ color: risk.value >= 70 ? '#ef4444' : risk.value >= 40 ? '#f59e0b' : '#22c55e' }}
            className="font-bold">{risk.value}</span>
        </div>
      )}
      {queries && (
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-cyan-400 inline-block" />
          <span className="text-slate-300">Queries/min: </span>
          <span className="text-cyan-400 font-bold">{queries.value}</span>
        </div>
      )}
    </div>
  );
};

// Color the area based on risk
function getRiskColor(score: number): string {
  if (score >= 70) return '#ef4444';
  if (score >= 40) return '#f59e0b';
  return '#22c55e';
}

export const TrafficChart: React.FC<TrafficChartProps> = ({ timeline }) => {
  const hasData = timeline.length > 0;
  const lastRisk = timeline[timeline.length - 1]?.riskScore ?? 0;
  const areaColor = getRiskColor(lastRisk);

  return (
    <div className="bg-slate-900/60 rounded-xl border border-slate-700/50 p-4">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">Live Traffic Timeline</h3>
          <p className="text-xs text-slate-500 font-mono mt-0.5">Risk score & query rate — last 60 events</p>
        </div>
        <div className="flex items-center gap-4 text-xs font-mono">
          <span className="flex items-center gap-1.5 text-slate-400">
            <span className="w-3 h-0.5 bg-red-400 inline-block rounded" />
            Risk Score
          </span>
          <span className="flex items-center gap-1.5 text-slate-400">
            <span className="w-3 h-0.5 bg-cyan-400 inline-block rounded" />
            Query Rate
          </span>
        </div>
      </div>

      {!hasData ? (
        <div className="h-48 flex items-center justify-center text-slate-600 text-sm font-mono">
          Awaiting data stream…
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={200}>
          <AreaChart data={timeline} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor={areaColor} stopOpacity={0.3} />
                <stop offset="95%" stopColor={areaColor} stopOpacity={0.02} />
              </linearGradient>
              <linearGradient id="queryGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.25} />
                <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.02} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
            <XAxis
              dataKey="time"
              tick={{ fill: '#475569', fontSize: 10, fontFamily: 'monospace' }}
              tickLine={false}
              axisLine={false}
              interval="preserveStartEnd"
            />
            <YAxis
              tick={{ fill: '#475569', fontSize: 10, fontFamily: 'monospace' }}
              tickLine={false}
              axisLine={false}
              domain={[0, 'auto']}
            />
            <Tooltip content={<CustomTooltip />} />
            {/* Threshold lines */}
            <ReferenceLine y={70} stroke="#ef4444" strokeDasharray="4 4" strokeOpacity={0.5}
              label={{ value: 'HIGH', fill: '#ef4444', fontSize: 9, fontFamily: 'monospace' }} />
            <ReferenceLine y={40} stroke="#f59e0b" strokeDasharray="4 4" strokeOpacity={0.5}
              label={{ value: 'MED', fill: '#f59e0b', fontSize: 9, fontFamily: 'monospace' }} />
            <Area
              type="monotone"
              dataKey="queryRate"
              stroke="#06b6d4"
              strokeWidth={1.5}
              fill="url(#queryGrad)"
              dot={false}
              activeDot={{ r: 4, fill: '#06b6d4' }}
            />
            <Area
              type="monotone"
              dataKey="riskScore"
              stroke={areaColor}
              strokeWidth={2}
              fill="url(#riskGrad)"
              dot={false}
              activeDot={{ r: 5, fill: areaColor }}
            />
          </AreaChart>
        </ResponsiveContainer>
      )}
    </div>
  );
};
