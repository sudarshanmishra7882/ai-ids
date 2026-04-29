// ============================================================
// SENTINELS OF THE NETWORK — AI-Driven IDS Dashboard
// ============================================================

import React, { useState } from 'react';
import { useIDSEngine } from './hooks/useIDSEngine';
import { AlertBanner } from './components/AlertBanner';
import { RiskGauge } from './components/RiskGauge';
import { SignalBreakdown } from './components/SignalBreakdown';
import { ExplanationPanel } from './components/ExplanationPanel';
import { TrafficChart } from './components/TrafficChart';
import { LiveLogFeed } from './components/LiveLogFeed';
import { StatsPanel } from './components/StatsPanel';
import { AttackScenario } from './components/AttackScenario';
import { NetworkTopology } from './components/NetworkTopology';
import { APIPanel } from './components/APIPanel';
import { Shield, Radio, Eye, Activity, Terminal } from 'lucide-react';
import { format } from 'date-fns';

// ─── Null-safe defaults ────────────────────────────────────────
const EMPTY_SIGNALS = [
  { type: 'BEACONING' as const, weight: 30, detected: false, value: 0, baseline: 0.6, deviation: 0, description: 'Monitoring connection intervals…' },
  { type: 'DB_SPIKE' as const, weight: 40, detected: false, value: 0, baseline: 3.5, deviation: 0, description: 'Query rate within normal bounds' },
  { type: 'UNKNOWN_IP' as const, weight: 30, detected: false, value: 0, baseline: 0, deviation: 0, description: 'All IPs recognized' },
  { type: 'PRIVILEGED_MISUSE' as const, weight: 20, detected: false, value: 0, baseline: 5, deviation: 0, description: 'Privileged accounts nominal' },
  { type: 'TLS_ANOMALY' as const, weight: 25, detected: false, value: 0, baseline: 650, deviation: 0, description: 'TLS fingerprints recognized' },
  { type: 'PACKET_ANOMALY' as const, weight: 15, detected: false, value: 0, baseline: 650, deviation: 0, description: 'Packet sizes within baseline' },
];

export default function App() {
  const {
    state,
    latestResult,
    windowStats,
    apiResponse,
    isRunning,
    handleTriggerAttack,
    handleReset,
    handleToggleRunning,
  } = useIDSEngine();

  const [activeTab, setActiveTab] = useState<'dashboard' | 'topology' | 'api'>('dashboard');

  const currentAlert = latestResult?.alert ?? 'LOW';
  const currentRisk = latestResult?.riskScore ?? 0;
  const currentConfidence = latestResult?.confidence ?? 0;
  const currentSignals = latestResult?.signals ?? EMPTY_SIGNALS;
  const isHigh = currentAlert === 'HIGH';

  const isBusinessHours = (() => {
    const h = new Date().getHours();
    return h >= 8 && h < 18;
  })();

  return (
    <div
      className="min-h-screen"
      style={{ backgroundColor: '#0B0F17' }}
    >
      {/* ── High Alert Scanline Effect ─────────────────────── */}
      {isHigh && (
        <div
          className="fixed inset-0 pointer-events-none z-50 overflow-hidden"
          style={{ border: '2px solid rgba(239,68,68,0.4)' }}
        >
          <div
            className="absolute w-full h-0.5 opacity-20"
            style={{
              background: 'linear-gradient(to right, transparent, #ef4444, transparent)',
              animation: 'scanline 3s linear infinite',
            }}
          />
        </div>
      )}

      {/* ── Top Header ────────────────────────────────────── */}
      <header className="border-b border-slate-800 bg-slate-950/80 backdrop-blur-sm sticky top-0 z-40">
        <div className="max-w-[1600px] mx-auto px-4 py-3">
          <div className="flex items-center justify-between">
            {/* Logo */}
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-950 border border-blue-700/50">
                <Shield className="w-6 h-6 text-blue-400" />
              </div>
              <div>
                <h1 className="text-base font-black text-slate-100 tracking-tight">
                  SENTINELS <span className="text-blue-400">OF THE NETWORK</span>
                </h1>
                <p className="text-xs text-slate-500 font-mono">AI-Driven Intrusion Detection System · Banking Network</p>
              </div>
            </div>

            {/* Status bar */}
            <div className="flex items-center gap-4">
              {/* Live clock */}
              <div className="text-xs font-mono text-slate-400 bg-slate-900 px-3 py-1.5 rounded-lg border border-slate-700">
                <Clock />
              </div>

              {/* System status */}
              <div className="flex items-center gap-2 text-xs font-mono">
                <span className={`relative flex h-2 w-2`}>
                  <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
                    isRunning ? (isHigh ? 'bg-red-400' : 'bg-green-400') : 'bg-slate-400'
                  }`} />
                  <span className={`relative inline-flex rounded-full h-2 w-2 ${
                    isRunning ? (isHigh ? 'bg-red-400' : 'bg-green-400') : 'bg-slate-600'
                  }`} />
                </span>
                <span className={isRunning ? (isHigh ? 'text-red-400' : 'text-green-400') : 'text-slate-500'}>
                  {isRunning ? (isHigh ? 'THREAT ACTIVE' : 'MONITORING') : 'STANDBY'}
                </span>
              </div>

              {/* Alert badge */}
              <div className={`px-3 py-1.5 rounded-lg border text-xs font-black font-mono tracking-widest ${
                isHigh
                  ? 'bg-red-900/50 border-red-500/60 text-red-300 high-alert-pulse'
                  : currentAlert === 'MEDIUM'
                  ? 'bg-amber-900/40 border-amber-500/50 text-amber-300'
                  : 'bg-green-900/30 border-green-500/40 text-green-400'
              }`}>
                {currentAlert}
              </div>
            </div>
          </div>

          {/* Navigation tabs */}
          <div className="flex gap-1 mt-3">
            {[
              { id: 'dashboard', label: 'SOC Dashboard', icon: Activity },
              { id: 'topology', label: 'Network Map', icon: Radio },
              { id: 'api', label: 'API Monitor', icon: Terminal },
            ].map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as typeof activeTab)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                  activeTab === tab.id
                    ? 'bg-blue-900/40 border border-blue-500/40 text-blue-300'
                    : 'text-slate-500 hover:text-slate-300 hover:bg-slate-800/50'
                }`}
              >
                <tab.icon className="w-3.5 h-3.5" />
                {tab.label}
              </button>
            ))}
          </div>
        </div>
      </header>

      {/* ── Main Content ──────────────────────────────────── */}
      <main className="max-w-[1600px] mx-auto px-4 py-4">

        {/* ─── Alert Banner ─── */}
        <div className="mb-4">
          <AlertBanner
            alert={currentAlert}
            riskScore={currentRisk}
            confidence={currentConfidence}
            attackPhase={state.attackPhase}
            totalLogs={state.totalLogsProcessed}
            isRunning={isRunning}
          />
        </div>

        {/* ─── Dashboard Tab ─── */}
        {activeTab === 'dashboard' && (
          <div className="grid grid-cols-12 gap-4">

            {/* LEFT COLUMN — Controls + Stats */}
            <div className="col-span-12 lg:col-span-3 space-y-4">
              {/* Attack Scenario */}
              <AttackScenario
                mode={state.mode}
                attackPhase={state.attackPhase}
                onTriggerAttack={handleTriggerAttack}
                onReset={handleReset}
                isRunning={isRunning}
                onToggleRunning={handleToggleRunning}
              />

              {/* Stats */}
              <StatsPanel
                alertCounts={state.alertCounts}
                baseline={state.baseline}
                windowStats={windowStats}
                totalLogs={state.totalLogsProcessed}
                isBusinessHours={isBusinessHours}
              />
            </div>

            {/* CENTER COLUMN — Main Detection */}
            <div className="col-span-12 lg:col-span-6 space-y-4">

              {/* Risk Gauge + Signal Breakdown row */}
              <div className="grid grid-cols-5 gap-4">
                <div className="col-span-2 bg-slate-900/60 rounded-xl border border-slate-700/50 p-4 flex flex-col items-center justify-center">
                  <RiskGauge
                    riskScore={currentRisk}
                    alert={currentAlert}
                  />
                </div>
                <div className="col-span-3 bg-slate-900/60 rounded-xl border border-slate-700/50 p-4">
                  <SignalBreakdown signals={currentSignals} />
                </div>
              </div>

              {/* Traffic Chart */}
              <TrafficChart timeline={state.timeline} />

              {/* Explanation */}
              <ExplanationPanel
                explanation={latestResult?.explanation ?? 'System initializing. Press START to begin monitoring.'}
                reasons={latestResult?.reasons ?? []}
                alert={currentAlert}
                isolationScore={latestResult?.isolationScore ?? 0}
                correlationScore={latestResult?.correlationScore ?? 0}
                falsePositiveReduced={latestResult?.falsePositiveReduced ?? false}
                confidence={currentConfidence}
                threatCategory={latestResult?.threatCategory ?? 'Clean Traffic'}
                alternativeInterpretation={latestResult?.alternativeInterpretation ?? ''}
                temporalContext={latestResult?.temporalContext ?? ''}
                executiveSummary={latestResult?.executiveSummary ?? ''}
              />
            </div>

            {/* RIGHT COLUMN — Live Log */}
            <div className="col-span-12 lg:col-span-3 space-y-4">
              {/* Latest Event Details */}
              {latestResult && (
                <div className="bg-slate-900/60 rounded-xl border border-slate-700/50 p-4">
                  <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                    <Eye className="w-3.5 h-3.5" />
                    Latest Event
                  </h3>
                  <div className="space-y-2">
                    {[
                      { label: 'Source IP', value: latestResult.log.sourceIP, mono: true },
                      { label: 'Dest IP', value: latestResult.log.destIP, mono: true, highlight: latestResult.log.isExternalIP },
                      { label: 'TLS Print', value: latestResult.log.tlsFingerprint.slice(0, 12) + '…', mono: true },
                      { label: 'Conn Interval', value: `${latestResult.log.connectionInterval}ms`, mono: true },
                      { label: 'Query Rate', value: `${latestResult.log.queryFrequency}/min`, mono: true, alert: latestResult.log.queryFrequency > 50 },
                      { label: 'Packet Size', value: `${latestResult.log.packetSize}B`, mono: true },
                      { label: 'User', value: latestResult.log.userId, mono: true, alert: latestResult.log.isPrivileged },
                      { label: 'Session', value: `${latestResult.log.sessionDuration}s`, mono: true },
                    ].map(row => (
                      <div key={row.label} className="flex justify-between items-center py-1 border-b border-slate-800/50">
                        <span className="text-xs text-slate-500">{row.label}</span>
                        <span className={`text-xs ${row.mono ? 'font-mono' : ''} ${
                          row.alert ? 'text-red-400 font-bold' :
                          row.highlight ? 'text-orange-400' : 'text-slate-300'
                        }`}>
                          {row.value}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Live Log Feed */}
              <LiveLogFeed history={state.detectionHistory} />
            </div>
          </div>
        )}

        {/* ─── Network Map Tab ─── */}
        {activeTab === 'topology' && (
          <div className="grid grid-cols-12 gap-4">
            <div className="col-span-12 lg:col-span-8">
              <NetworkTopology latestResult={latestResult} />
            </div>
            <div className="col-span-12 lg:col-span-4 space-y-4">
              <AttackScenario
                mode={state.mode}
                attackPhase={state.attackPhase}
                onTriggerAttack={handleTriggerAttack}
                onReset={handleReset}
                isRunning={isRunning}
                onToggleRunning={handleToggleRunning}
              />
              <ExplanationPanel
                explanation={latestResult?.explanation ?? 'System initializing…'}
                reasons={latestResult?.reasons ?? []}
                alert={currentAlert}
                isolationScore={latestResult?.isolationScore ?? 0}
                correlationScore={latestResult?.correlationScore ?? 0}
                falsePositiveReduced={latestResult?.falsePositiveReduced ?? false}
                confidence={currentConfidence}
                threatCategory={latestResult?.threatCategory ?? 'Clean Traffic'}
                alternativeInterpretation={latestResult?.alternativeInterpretation ?? ''}
                temporalContext={latestResult?.temporalContext ?? ''}
                executiveSummary={latestResult?.executiveSummary ?? ''}
              />
            </div>
          </div>
        )}

        {/* ─── API Tab ─── */}
        {activeTab === 'api' && (
          <div className="grid grid-cols-12 gap-4">
            <div className="col-span-12 lg:col-span-8 space-y-4">
              {/* API Endpoint docs */}
              <div className="bg-slate-900/60 rounded-xl border border-slate-700/50 p-5">
                <h3 className="text-sm font-bold text-slate-300 mb-4 uppercase tracking-wider">API Endpoints</h3>
                <div className="space-y-3">
                  {[
                    { method: 'GET', path: '/api/data', desc: 'Real-time log + detection result (live feed)', active: true },
                    { method: 'POST', path: '/api/attack', desc: 'Trigger 5-phase APT attack scenario' },
                    { method: 'POST', path: '/api/normal', desc: 'Reset system to normal operation' },
                  ].map(ep => (
                    <div key={ep.path} className={`flex items-start gap-3 p-3 rounded-lg border ${
                      ep.active ? 'bg-blue-950/30 border-blue-500/30' : 'bg-slate-800/30 border-slate-700/30'
                    }`}>
                      <span className={`px-2 py-0.5 rounded text-xs font-bold font-mono ${
                        ep.method === 'GET' ? 'bg-green-900/50 text-green-400' : 'bg-amber-900/50 text-amber-400'
                      }`}>
                        {ep.method}
                      </span>
                      <div>
                        <div className="text-xs font-mono text-slate-200">{ep.path}</div>
                        <div className="text-xs text-slate-500 mt-0.5">{ep.desc}</div>
                      </div>
                      {ep.active && (
                        <span className="ml-auto text-xs text-blue-400 font-mono">● ACTIVE</span>
                      )}
                    </div>
                  ))}
                </div>
              </div>

              {/* Response schema */}
              <div className="bg-slate-900/60 rounded-xl border border-slate-700/50 p-5">
                <h3 className="text-sm font-bold text-slate-300 mb-4 uppercase tracking-wider">Response Schema</h3>
                <pre className="text-xs font-mono text-slate-400 bg-black/40 rounded-lg p-4 border border-slate-800 overflow-x-auto">{`{
  "log": {
    "id": "string",
    "timestamp": "number (unix ms)",
    "sourceIP": "string",
    "destIP": "string",
    "packetSize": "number (bytes)",
    "connectionInterval": "number (ms)",
    "tlsFingerprint": "string (JA3-like)",
    "userId": "string",
    "isPrivileged": "boolean",
    "queryFrequency": "number/min",
    "isExternalIP": "boolean"
  },
  "riskScore": "number (0-100)",
  "alert": "'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'",
  "confidence": "number (0-1)",
  "reasons": "string[]",
  "explanation": "string (human-readable AI explanation)",
  "signals": [
    {
      "type": "BEACONING | DB_SPIKE | UNKNOWN_IP | ...",
      "detected": "boolean",
      "weight": "number",
      "deviation": "number"
    }
  ],
  "meta": {
    "isolationForestScore": "number (0-1)",
    "correlationScore": "number",
    "falsePositiveReduced": "boolean",
    "windowSizeSeconds": 60,
    "baselineSamples": "number"
  }
}`}</pre>
              </div>

              {/* Live response */}
              <APIPanel
                apiResponse={apiResponse}
                endpoint="/api/data"
              />
            </div>

            <div className="col-span-12 lg:col-span-4 space-y-4">
              <AttackScenario
                mode={state.mode}
                attackPhase={state.attackPhase}
                onTriggerAttack={handleTriggerAttack}
                onReset={handleReset}
                isRunning={isRunning}
                onToggleRunning={handleToggleRunning}
              />
              <div className="bg-slate-900/60 rounded-xl border border-slate-700/50 p-4">
                <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">System Metrics</h3>
                <div className="space-y-2">
                  {[
                    { label: 'Response Time', value: '<1ms', color: 'text-green-400' },
                    { label: 'Window Size', value: '60s', color: 'text-blue-400' },
                    { label: 'Baseline Samples', value: state.baseline.samplesCollected, color: 'text-cyan-400' },
                    { label: 'Events Processed', value: state.totalLogsProcessed, color: 'text-violet-400' },
                    { label: 'Known IPs', value: state.baseline.knownIPs.length, color: 'text-emerald-400' },
                    { label: 'Known TLS', value: state.baseline.knownTLSFingerprints.length, color: 'text-teal-400' },
                  ].map(m => (
                    <div key={m.label} className="flex justify-between py-1.5 border-b border-slate-800/50">
                      <span className="text-xs text-slate-500 font-mono">{m.label}</span>
                      <span className={`text-xs font-mono font-bold ${m.color}`}>{m.value}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* ── Footer ─────────────────────────────────────────── */}
      <footer className="border-t border-slate-800 mt-8 py-3 text-center">
        <p className="text-xs text-slate-600 font-mono">
          SENTINELS OF THE NETWORK v2.0 · AI-Driven IDS · Banking Network Security Operations Center
          · <span className="text-slate-500">Explainable · Zero-Day Detection · Real-Time Correlation</span>
        </p>
      </footer>
    </div>
  );
}

// ─── Live Clock Component ──────────────────────────────────────
function Clock() {
  const [time, setTime] = React.useState(new Date());
  React.useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  return <>{format(time, 'HH:mm:ss · yyyy-MM-dd')}</>;
}
