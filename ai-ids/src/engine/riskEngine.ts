import { AgentSignal, AlertLevel, AttackClassification, RiskState } from '../types/ids';
import { clamp } from './statistics';

const DECAY_FACTOR = 0.935;
const MAX_ESCALATION_PER_TICK = 9;
const MAX_DEESCALATION_PER_TICK = -12;

function fuseAgentSignals(agentSignals: AgentSignal[]): { fused: number; agreement: number; meanConfidence: number } {
  if (agentSignals.length === 0) {
    return { fused: 0, agreement: 0, meanConfidence: 0 };
  }

  const weights: Record<AgentSignal['agent'], number> = {
    PACKET: 0.16,
    FLOW: 0.21,
    BEHAVIOR: 0.24,
    CORRELATION: 0.39,
    RESPONSE: 0,
  };

  let weighted = 0;
  let totalWeight = 0;
  let confidenceSum = 0;
  let detected = 0;

  agentSignals.forEach(signal => {
    const weight = weights[signal.agent];
    const confidenceBoost = 0.55 + signal.confidence * 0.45;
    weighted += signal.score * weight * confidenceBoost;
    totalWeight += weight;
    confidenceSum += signal.confidence;
    if (signal.detected) {
      detected += 1;
    }
  });

  return {
    fused: totalWeight > 0 ? weighted / totalWeight : 0,
    agreement: detected / agentSignals.length,
    meanConfidence: confidenceSum / agentSignals.length,
  };
}

export function accumulateRisk(
  currentRiskState: RiskState,
  agentSignals: AgentSignal[],
  isolationScore: number,
  timestamp: number
): RiskState {
  const { fused, agreement, meanConfidence } = fuseAgentSignals(agentSignals);
  const correlationSignal = agentSignals.find(signal => signal.agent === 'CORRELATION');
  const uncertainty = clamp((1 - meanConfidence) * 0.55 + (1 - agreement) * 0.45, 0.02, 0.7);

  let instantRisk = fused * 0.74 + isolationScore * 0.18;
  if (correlationSignal?.detected) {
    instantRisk += correlationSignal.score * 0.12;
  }
  instantRisk *= 1 - uncertainty * 0.24;
  instantRisk = clamp(instantRisk, 0, 1);

  const deltaMs = timestamp - currentRiskState.lastUpdate;
  const decayedRisk = currentRiskState.accumulatedRisk * Math.pow(DECAY_FACTOR, deltaMs / 1000);
  const targetRisk = instantRisk * 100;
  const rawDelta = targetRisk - decayedRisk;
  const boundedDelta = clamp(rawDelta, MAX_DEESCALATION_PER_TICK, MAX_ESCALATION_PER_TICK);
  const warmupFactor = correlationSignal?.detected || agreement >= 0.66 || decayedRisk > 28 ? 1 : 0.42;
  const escalationRate = boundedDelta * warmupFactor;
  const newAccumulated = clamp(decayedRisk + escalationRate, 0, 100);

  const confidence = clamp(
    0.22 +
      agreement * 0.28 +
      meanConfidence * 0.24 +
      instantRisk * 0.18 +
      (correlationSignal?.detected ? 0.08 : 0) -
      uncertainty * 0.1,
    0,
    0.99
  );

  return {
    currentScore: Math.round(targetRisk),
    accumulatedRisk: newAccumulated,
    decayFactor: DECAY_FACTOR,
    confidence,
    lastUpdate: timestamp,
    escalationRate,
    uncertainty,
  };
}

export function classifyAccumulatedRisk(riskState: RiskState, correlationDetected: boolean): AlertLevel {
  const score = riskState.accumulatedRisk;
  if (score >= 88 && correlationDetected && riskState.confidence >= 0.8) {
    return 'CRITICAL';
  }
  if (score >= 68) {
    return 'HIGH';
  }
  if (score >= 38) {
    return 'MEDIUM';
  }
  return 'LOW';
}

export function createInitialRiskState(): RiskState {
  return {
    currentScore: 0,
    accumulatedRisk: 0,
    decayFactor: DECAY_FACTOR,
    confidence: 0,
    lastUpdate: Date.now(),
    escalationRate: 0,
    uncertainty: 1,
  };
}

export function classifyAttack(agentSignals: AgentSignal[]): AttackClassification {
  const correlationSignal = agentSignals.find(signal => signal.agent === 'CORRELATION');
  if (correlationSignal?.classification) {
    return correlationSignal.classification;
  }
  const detected = agentSignals.filter(signal => signal.detected);
  if (detected.length === 0) return 'NONE';
  if (detected.some(signal => signal.signalType.includes('FLOW')) && detected.some(signal => signal.signalType.includes('PACKET'))) {
    return 'RECONNAISSANCE';
  }
  return 'SUSPICIOUS_ACTIVITY';
}
