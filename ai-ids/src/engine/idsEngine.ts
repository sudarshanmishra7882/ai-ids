// ============================================================
// IDS ENGINE v3.0 — Multi-Agent Orchestrator / Streaming Pipeline
// Pipeline: Packet Agent → Flow Agent → Behavior Agent → Risk Engine → Correlation
// ============================================================

import { SystemState, DetectionResult, TimelinePoint, AlertLevel, AttackPhase, BankingContext } from '../types/ids';
import { generateLog } from './dataGenerator';
import { INITIAL_BASELINE, updateBaseline, computeWindowStats } from './baselineEngine';
import { runAllDetectors, computeIsolationScore } from './anomalyDetector';
import { correlateSignals } from './correlationEngine';
import { runPacketAgent } from './agents/packetAgent';
import { runFlowAgent } from './agents/flowAgent';
import { runBehaviorAgent } from './agents/behaviorAgent';
import { accumulateRisk, createInitialRiskState } from './riskEngine';
import { format } from 'date-fns';

const WINDOW_SIZE_MS = 60_000;
const MAX_HISTORY = 200;
const MAX_TIMELINE = 60;
const ATTACK_PHASE_DURATIONS: Record<AttackPhase, number> = {
  0: 0,
  1: 8,
  2: 10,
  3: 8,
  4: 8,
  5: 0,
};

// ─── Extract Banking Context from Log ─────────────────────────
function extractBankingContext(log: import('../types/ids').NetworkLog): BankingContext {
  return {
    isATMReconciliation: log.isATMReconciliation,
    isSWIFTCommunication: log.isSWIFTCommunication,
    isMonthEndBatch: log.isMonthEndBatch,
    batchJobWindow: log.isATMReconciliation || log.isMonthEndBatch,
  };
}

// ─── Initial State Factory ────────────────────────────────────
export function createInitialState(): SystemState {
  return {
    mode: 'normal',
    attackPhase: 0,
    baseline: INITIAL_BASELINE,
    slidingWindow: [],
    detectionHistory: [],
    timeline: [],
    isRunning: false,
    totalLogsProcessed: 0,
    alertCounts: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
    lastUpdate: Date.now(),
    riskState: createInitialRiskState(),
    bankingContext: {
      isATMReconciliation: false,
      isSWIFTCommunication: false,
      isMonthEndBatch: false,
      batchJobWindow: false,
    },
  };
}

// ─── Process Single Log Entry ─────────────────────────────────
export function processLog(state: SystemState, timestamp: number): {
  newState: SystemState;
  result: DetectionResult;
} {
  // 1. Generate log
  const log = generateLog(timestamp, state.attackPhase);

  // 2. Maintain sliding window
  const newWindow = [
    ...state.slidingWindow.filter(l => l.timestamp >= timestamp - WINDOW_SIZE_MS),
    log,
  ].slice(-200);

  // 3. Compute window statistics
  const windowStats = computeWindowStats(newWindow, timestamp);

  // 4. Run legacy anomaly detectors (backward compatibility)
  const signals = runAllDetectors(log, state.baseline, windowStats, newWindow);

  // 5. RUN MULTI-AGENT PIPELINE (v3.0)
  const packetSignal = runPacketAgent(log, state.baseline, windowStats);
  const flowSignal = runFlowAgent(log, state.baseline, windowStats, newWindow);
  const behaviorSignal = runBehaviorAgent(log, state.baseline, windowStats);
  const agentSignals = [packetSignal, flowSignal, behaviorSignal];

  // 6. TIME-DECAYED RISK ACCUMULATION (v3.0)
  const isolationScore = computeIsolationScore(log, state.baseline, windowStats);
  const newRiskState = accumulateRisk(state.riskState, agentSignals, isolationScore, timestamp);

  // 7. Correlate signals into alert
  const detection = correlateSignals(
    log,
    signals,
    state.baseline,
    windowStats,
    state.attackPhase,
    agentSignals,
    newRiskState
  );

  const result: DetectionResult = {
    log,
    ...detection,
    agentSignals,
    riskState: newRiskState,
    bankingContext: extractBankingContext(log),
  };

  // 8. Update baseline
  const isAttackPhase = state.attackPhase >= 2;
  const newBaseline = updateBaseline(state.baseline, log, isAttackPhase);

  // 9. Update history
  const newHistory = [...state.detectionHistory, result].slice(-MAX_HISTORY);

  // 10. Update timeline
  const timePoint: TimelinePoint = {
    time: format(new Date(timestamp), 'HH:mm:ss'),
    riskScore: result.riskScore,
    queryRate: log.queryFrequency,
    packetSize: log.packetSize,
    alert: result.alert,
    timestamp,
  };
  const newTimeline = [...state.timeline, timePoint].slice(-MAX_TIMELINE);

  // 11. Update alert counts
  const newAlertCounts = { ...state.alertCounts };
  newAlertCounts[result.alert]++;

  // 12. Advance attack phase based on duration
  let newPhase = state.attackPhase;
  if (state.mode === 'attack' && state.attackPhase > 0 && state.attackPhase < 5) {
    const phaseCount = newHistory.filter(h => h.attackPhase === state.attackPhase).length;
    const phaseDuration = ATTACK_PHASE_DURATIONS[state.attackPhase];
    if (phaseCount >= phaseDuration) {
      newPhase = Math.min(state.attackPhase + 1, 5) as AttackPhase;
    }
  }


  const newState: SystemState = {
    ...state,
    baseline: newBaseline,
    slidingWindow: newWindow,
    detectionHistory: newHistory,
    timeline: newTimeline,
    totalLogsProcessed: state.totalLogsProcessed + 1,
    alertCounts: newAlertCounts,
    lastUpdate: timestamp,
    attackPhase: newPhase,
    riskState: newRiskState,
    bankingContext: extractBankingContext(log),
  };

  return { newState, result };
}

// ─── Trigger Attack Scenario ──────────────────────────────────
export function triggerAttack(state: SystemState): SystemState {
  return {
    ...state,
    mode: 'attack',
    attackPhase: 1,
    riskState: createInitialRiskState(),
  };
}

// ─── Reset to Normal ──────────────────────────────────────────
export function resetToNormal(state: SystemState): SystemState {
  return {
    ...state,
    mode: 'normal',
    attackPhase: 0,
    baseline: INITIAL_BASELINE,
    slidingWindow: [],
    riskState: createInitialRiskState(),
    bankingContext: {
      isATMReconciliation: false,
      isSWIFTCommunication: false,
      isMonthEndBatch: false,
      batchJobWindow: false,
    },
  };
}

// ─── Alert Color Mapping ──────────────────────────────────────
export function getAlertColor(alert: AlertLevel): string {
  switch (alert) {
    case 'HIGH': return '#ef4444';
    case 'MEDIUM': return '#f59e0b';
    case 'LOW': return '#22c55e';
    case 'CRITICAL': return '#7c3aed';
    default: return '#22c55e';
  }
}

export function getAlertBg(alert: AlertLevel): string {
  switch (alert) {
    case 'HIGH': return 'bg-red-900/40 border-red-500/60';
    case 'MEDIUM': return 'bg-amber-900/40 border-amber-500/60';
    case 'LOW': return 'bg-green-900/40 border-green-500/60';
    case 'CRITICAL': return 'bg-purple-900/40 border-purple-500/60';
    default: return 'bg-green-900/40 border-green-500/60';
  }
}

export function getAlertTextColor(alert: AlertLevel): string {
  switch (alert) {
    case 'HIGH': return 'text-red-400';
    case 'MEDIUM': return 'text-amber-400';
    case 'LOW': return 'text-green-400';
    case 'CRITICAL': return 'text-purple-400';
    default: return 'text-green-400';
  }
}

export function getPhaseLabel(phase: AttackPhase): string {
  switch (phase) {
    case 0: return 'Normal Operations';
    case 1: return 'Phase 1 — Baseline Collection';
    case 2: return 'Phase 2 — C2 Beaconing';
    case 3: return 'Phase 3 — DB Exfiltration';
    case 4: return 'Phase 4 — Lateral Movement';
    case 5: return 'Phase 5 — Full APT Attack';
    default: return 'Unknown';
  }
}
