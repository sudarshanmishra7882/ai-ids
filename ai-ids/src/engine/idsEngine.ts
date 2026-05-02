import { format } from 'date-fns';
import {
  AlertLevel,
  AttackPhase,
  BankingContext,
  DetectionResult,
  SystemState,
  TimelinePoint,
} from '../types/ids';
import { computeIsolationScore, runAllDetectors } from './anomalyDetector';
import { runBehaviorAgent } from './agents/behaviorAgent';
import { runCorrelationAgent } from './agents/correlationAgent';
import { runFlowAgent } from './agents/flowAgent';
import { runPacketAgent } from './agents/packetAgent';
import { runResponseAgent } from './agents/responseAgent';
import { computeWindowStats, getProfileLabel, INITIAL_BASELINE, inferBankingProfile, updateBaseline } from './baselineEngine';
import { generateLog } from './dataGenerator';
import { correlateSignals } from './correlationEngine';
import { accumulateRisk, createInitialRiskState } from './riskEngine';

const WINDOW_SIZE_MS = 60_000;
const MAX_HISTORY = 200;
const MAX_TIMELINE = 60;
const ATTACK_PHASE_DURATIONS: Record<AttackPhase, number> = {
  0: 0,
  1: 8,
  2: 10,
  3: 10,
  4: 9,
  5: 8,
};

function extractBankingContext(log: import('../types/ids').NetworkLog): BankingContext {
  const profile = inferBankingProfile(log);
  return {
    profile,
    profileLabel: getProfileLabel(profile),
    isATMReconciliation: log.isATMReconciliation,
    isSWIFTCommunication: log.isSWIFTCommunication,
    isMonthEndBatch: log.isMonthEndBatch,
    batchJobWindow: log.isATMReconciliation || log.isMonthEndBatch,
  };
}

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
    simulationTick: 0,
    phaseTick: 0,
    alertCounts: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },
    lastUpdate: Date.now(),
    riskState: createInitialRiskState(),
    bankingContext: {
      profile: 'DEFAULT',
      profileLabel: getProfileLabel('DEFAULT'),
      isATMReconciliation: false,
      isSWIFTCommunication: false,
      isMonthEndBatch: false,
      batchJobWindow: false,
    },
  };
}

export function processLog(
  state: SystemState,
  timestamp: number
): { newState: SystemState; result: DetectionResult } {
  const log = generateLog(timestamp, {
    mode: state.mode,
    attackPhase: state.attackPhase,
    phaseTick: state.phaseTick,
    totalTick: state.simulationTick,
  });

  const newWindow = [...state.slidingWindow.filter(entry => entry.timestamp >= timestamp - WINDOW_SIZE_MS), log].slice(-220);
  const windowStats = computeWindowStats(newWindow, timestamp);
  const signals = runAllDetectors(log, state.baseline, windowStats, newWindow);

  const packetSignal = runPacketAgent(log, state.baseline, windowStats);
  const flowSignal = runFlowAgent(log, state.baseline, windowStats, newWindow, packetSignal);
  const behaviorSignal = runBehaviorAgent(log, state.baseline, windowStats, flowSignal);
  const correlationSignal = runCorrelationAgent(
    log,
    state.baseline,
    windowStats,
    signals,
    [packetSignal, flowSignal, behaviorSignal],
    state.detectionHistory.map(item => ({
      alert: item.alert,
      attackClassification: item.attackClassification,
      riskScore: item.riskScore,
    })),
    state.riskState
  );

  const analysisSignals = [packetSignal, flowSignal, behaviorSignal, correlationSignal] as const;
  const isolationScore = computeIsolationScore(log, state.baseline, windowStats);
  const newRiskState = accumulateRisk(state.riskState, [...analysisSignals], isolationScore, timestamp);

  const detection = correlateSignals(
    log,
    signals,
    state.baseline,
    windowStats,
    state.attackPhase,
    [...analysisSignals],
    newRiskState,
    isolationScore
  );

  const responseSignal = runResponseAgent(
    detection.alert,
    detection.attackClassification,
    detection.riskState,
    log.sourceIP,
    log.destIP,
    log.userId,
    detection.agentBreakdown
  );

  const finalAgentSignals = [...analysisSignals, responseSignal];
  const result: DetectionResult = {
    log,
    ...detection,
    agentSignals: finalAgentSignals,
    agentBreakdown: {
      ...detection.agentBreakdown,
      RESPONSE: {
        score: responseSignal.score,
        confidence: responseSignal.confidence,
        detected: responseSignal.detected,
      },
    },
    riskState: detection.riskState,
    bankingContext: extractBankingContext(log),
    autoIsolationRecommended: Boolean(responseSignal.features.containmentRecommended),
  };

  const activeAttackPhase = state.mode === 'attack' && state.attackPhase >= 2;
  const newBaseline = updateBaseline(state.baseline, log, activeAttackPhase);
  const newHistory = [...state.detectionHistory, result].slice(-MAX_HISTORY);

  const timePoint: TimelinePoint = {
    time: format(new Date(timestamp), 'HH:mm:ss'),
    riskScore: result.riskScore,
    queryRate: log.queryFrequency,
    packetSize: log.packetSize,
    alert: result.alert,
    timestamp,
  };
  const newTimeline = [...state.timeline, timePoint].slice(-MAX_TIMELINE);

  const newAlertCounts = { ...state.alertCounts };
  newAlertCounts[result.alert] += 1;

  let newPhase = state.attackPhase;
  let newPhaseTick = state.phaseTick + 1;
  if (state.mode === 'attack' && state.attackPhase > 0 && state.attackPhase < 5) {
    const phaseDuration = ATTACK_PHASE_DURATIONS[state.attackPhase];
    if (newPhaseTick >= phaseDuration) {
      newPhase = Math.min(state.attackPhase + 1, 5) as AttackPhase;
      newPhaseTick = 0;
    }
  }

  const newState: SystemState = {
    ...state,
    baseline: newBaseline,
    slidingWindow: newWindow,
    detectionHistory: newHistory,
    timeline: newTimeline,
    totalLogsProcessed: state.totalLogsProcessed + 1,
    simulationTick: state.simulationTick + 1,
    phaseTick: newPhaseTick,
    alertCounts: newAlertCounts,
    lastUpdate: timestamp,
    attackPhase: newPhase,
    riskState: detection.riskState,
    bankingContext: extractBankingContext(log),
  };

  return { newState, result };
}

export function triggerAttack(state: SystemState): SystemState {
  return {
    ...state,
    mode: 'attack',
    attackPhase: 1,
    phaseTick: 0,
    riskState: createInitialRiskState(),
  };
}

export function resetToNormal(state: SystemState): SystemState {
  return {
    ...state,
    mode: 'normal',
    attackPhase: 0,
    baseline: INITIAL_BASELINE,
    slidingWindow: [],
    riskState: createInitialRiskState(),
    simulationTick: 0,
    phaseTick: 0,
    bankingContext: {
      profile: 'DEFAULT',
      profileLabel: getProfileLabel('DEFAULT'),
      isATMReconciliation: false,
      isSWIFTCommunication: false,
      isMonthEndBatch: false,
      batchJobWindow: false,
    },
  };
}

export function getAlertColor(alert: AlertLevel): string {
  switch (alert) {
    case 'HIGH':
      return '#ef4444';
    case 'MEDIUM':
      return '#f59e0b';
    case 'LOW':
      return '#22c55e';
    case 'CRITICAL':
      return '#7c3aed';
    default:
      return '#22c55e';
  }
}

export function getAlertBg(alert: AlertLevel): string {
  switch (alert) {
    case 'HIGH':
      return 'bg-red-900/40 border-red-500/60';
    case 'MEDIUM':
      return 'bg-amber-900/40 border-amber-500/60';
    case 'LOW':
      return 'bg-green-900/40 border-green-500/60';
    case 'CRITICAL':
      return 'bg-purple-900/40 border-purple-500/60';
    default:
      return 'bg-green-900/40 border-green-500/60';
  }
}

export function getAlertTextColor(alert: AlertLevel): string {
  switch (alert) {
    case 'HIGH':
      return 'text-red-400';
    case 'MEDIUM':
      return 'text-amber-400';
    case 'LOW':
      return 'text-green-400';
    case 'CRITICAL':
      return 'text-purple-400';
    default:
      return 'text-green-400';
  }
}

export function getPhaseLabel(phase: AttackPhase): string {
  switch (phase) {
    case 0:
      return 'Normal Operations';
    case 1:
      return 'Phase 1 - Baseline Collection';
    case 2:
      return 'Phase 2 - C2 Beaconing';
    case 3:
      return 'Phase 3 - DB Staging';
    case 4:
      return 'Phase 4 - Exfiltration';
    case 5:
      return 'Phase 5 - Full Correlated Attack';
    default:
      return 'Unknown';
  }
}
