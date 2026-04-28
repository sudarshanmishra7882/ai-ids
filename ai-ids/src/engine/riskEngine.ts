// ============================================================
// RISK ENGINE — Time-Decayed Risk Accumulation & Gradual Escalation
// Replaces instant scoring with realistic SOC risk modeling
// ============================================================

import { RiskState, AlertLevel, AgentSignal } from '../types/ids';

const DECAY_FACTOR = 0.92; // Risk decays 8% per tick (1s)
const ESCALATION_CAP = 20; // Max risk increase per tick
const HIGH_THRESHOLD = 70;
const MEDIUM_THRESHOLD = 40;

// ─── Compute Agent Weighted Fusion Score ──────────────────────
function fuseAgentSignals(agentSignals: AgentSignal[]): number {
  if (agentSignals.length === 0) return 0;
  const weights = { PACKET: 0.25, FLOW: 0.30, BEHAVIOR: 0.45 };
  let totalWeightedScore = 0;
  let totalWeight = 0;

  for (const signal of agentSignals) {
    const weight = weights[signal.agent] || 0.3;
    totalWeightedScore += signal.score * weight * (signal.detected ? 1.5 : 0.5);
    totalWeight += weight;
  }

  return totalWeight > 0 ? Math.min(totalWeightedScore / totalWeight, 1) : 0;
}

// ─── Time-Decayed Risk Accumulation ───────────────────────────
export function accumulateRisk(
  currentRiskState: RiskState,
  agentSignals: AgentSignal[],
  isolationScore: number,
  timestamp: number
): RiskState {
  const agentFusionScore = fuseAgentSignals(agentSignals);
  const detectedCount = agentSignals.filter(s => s.detected).length;
  const agreementFactor = detectedCount / agentSignals.length; // 0–1

  // Blend agent fusion (75%) with ML isolation score (15%) — capped at 1.0
  // Lower weights + higher jitter allow natural fluctuation instead of rigid 100
  const jitter = (Math.random() - 0.5) * 0.20; // ±10% noise for up/down movement
  const instantRisk = Math.min(Math.max(agentFusionScore * 0.75 + isolationScore * 0.15 + jitter, 0), 1.0);

  // Time decay: older risk fades
  const timeDelta = timestamp - currentRiskState.lastUpdate;
  const decayApplied = currentRiskState.accumulatedRisk * Math.pow(DECAY_FACTOR, timeDelta / 1000);

  // Gradual escalation: cap the increase per tick
  const rawDelta = instantRisk * 100 - decayApplied;
  const cappedDelta = Math.max(-40, Math.min(ESCALATION_CAP, rawDelta));
  
  // Agreement bonus: more agents agreeing = faster escalation (reduced to allow drops)
  const agreementBonus = detectedCount >= 2 ? agreementFactor * 4 : 0;
  
  const newAccumulated = Math.min(100, Math.max(0, decayApplied + cappedDelta + agreementBonus));

  // Confidence based on agent agreement and signal strength
  const agreementConfidence = agreementFactor * 0.6;
  const strengthConfidence = instantRisk * 0.3;
  const temporalConfidence = currentRiskState.escalationRate > 0 ? 0.1 : 0;
  const confidence = Math.min(agreementConfidence + strengthConfidence + temporalConfidence, 0.99);

  return {
    currentScore: Math.round(instantRisk * 100),
    accumulatedRisk: newAccumulated,
    decayFactor: DECAY_FACTOR,
    confidence,
    lastUpdate: timestamp,
    escalationRate: cappedDelta,
  };
}

// ─── Risk Classification (uses accumulated risk, not instant) ─
export function classifyAccumulatedRisk(riskState: RiskState): AlertLevel {
  const score = riskState.accumulatedRisk;
  if (score >= HIGH_THRESHOLD) return 'HIGH';
  if (score >= MEDIUM_THRESHOLD) return 'MEDIUM';
  return 'LOW';
}

// ─── Initialize Risk State ────────────────────────────────────
export function createInitialRiskState(): RiskState {
  return {
    currentScore: 0,
    accumulatedRisk: 0,
    decayFactor: DECAY_FACTOR,
    confidence: 0,
    lastUpdate: Date.now(),
    escalationRate: 0,
  };
}

// ─── Attack Classification from Agent Signals ─────────────────
export function classifyAttack(agentSignals: AgentSignal[]): string {
  const detected = agentSignals.filter(s => s.detected);
  const has = (type: string) => detected.some(s => s.signalType.includes(type));

  const classifications: string[] = [];

  if (has('BEACONING') || (has('SUSPICIOUS_FLOW') && has('ANOMALOUS_PACKET'))) {
    classifications.push('C2_BEACONING');
  }
  if (has('ANOMALOUS_BEHAVIOR') && has('SUSPICIOUS_FLOW')) {
    classifications.push('DATA_EXFILTRATION');
  }
  if (has('ANOMALOUS_BEHAVIOR') && has('PRIVILEGED')) {
    classifications.push('PRIVILEGED_ABUSE');
  }
  if (has('SUSPICIOUS_FLOW') && !has('ANOMALOUS_BEHAVIOR')) {
    classifications.push('RECONNAISSANCE');
  }

  if (classifications.length === 0 && detected.length > 0) {
    return 'SUSPICIOUS_ACTIVITY';
  }

  return classifications.length > 0 ? classifications[0] : 'NONE';
}
