// ============================================================
// RISK ENGINE v4.0 — Time-Decayed Risk Accumulation & Gradual Escalation
// Replaces instant scoring with realistic SOC risk modeling
// NO RANDOM JITTER — deterministic noise based on signal characteristics
// ============================================================

import { RiskState, AlertLevel, AgentSignal } from '../types/ids';

const DECAY_FACTOR = 0.92; // Risk decays 8% per tick (1s)
const ESCALATION_CAP = 8; // Max risk increase per tick (reduced for gradual build)
const HIGH_THRESHOLD = 70;
const MEDIUM_THRESHOLD = 40;

// ─── Compute Signal Entropy (deterministic noise source) ──────
function computeSignalEntropy(agentSignals: AgentSignal[]): number {
  if (agentSignals.length === 0) return 1;
  const scores = agentSignals.map(s => s.score);
  const mean = scores.reduce((a, b) => a + b, 0) / scores.length;
  if (mean === 0) return 1;
  
  // Coefficient of variation as entropy proxy
  const variance = scores.reduce((sum, s) => sum + Math.pow(s - mean, 2), 0) / scores.length;
  const stdDev = Math.sqrt(variance);
  const cv = stdDev / mean;
  
  // Normalize to 0-1 (higher = more chaotic/uncertain)
  return Math.min(1, cv * 2);
}

// ─── Compute Agent Weighted Fusion Score ──────────────────────
function fuseAgentSignals(agentSignals: AgentSignal[]): number {
  if (agentSignals.length === 0) return 0;
  const weights = { PACKET: 0.25, FLOW: 0.30, BEHAVIOR: 0.45, RESPONSE: 0.0 };
  let totalWeightedScore = 0;
  let totalWeight = 0;

  for (const signal of agentSignals) {
    const weight = weights[signal.agent] || 0.3;
    // Use confidence as multiplier — high confidence signals count more
    const confidenceMultiplier = 0.5 + signal.confidence * 0.5;
    totalWeightedScore += signal.score * weight * (signal.detected ? 1.5 : 0.5) * confidenceMultiplier;
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

  // ─── DETERMINISTIC NOISE (replaces random jitter) ─────────
  // Noise based on signal entropy: chaotic signals = more uncertainty
  const signalEntropy = computeSignalEntropy(agentSignals);
  // Low entropy (consistent signals) = confident, less noise
  // High entropy (chaotic signals) = uncertain, more noise
  const deterministicNoise = (signalEntropy - 0.5) * 0.08; // ±4% max noise
  
  // Also factor in agreement: more agents agreeing = less noise needed
  const agreementStability = (1 - agreementFactor) * 0.04; // Disagreement adds uncertainty
  const totalNoise = deterministicNoise + agreementStability;

  // Blend agent fusion (70%) with ML isolation score (20%) + noise (10%)
  const instantRisk = Math.min(Math.max(
    agentFusionScore * 0.70 + 
    isolationScore * 0.20 + 
    totalNoise, 
    0
  ), 1.0);

  // Time decay: older risk fades
  const timeDelta = timestamp - currentRiskState.lastUpdate;
  const decayApplied = currentRiskState.accumulatedRisk * Math.pow(DECAY_FACTOR, timeDelta / 1000);

  // ─── GRADUAL ESCALATION WITH WARM-UP PERIOD ─────────────────
  const rawDelta = instantRisk * 100 - decayApplied;
  
  // Cap the increase per tick for gradual build
  const cappedDelta = Math.max(-30, Math.min(ESCALATION_CAP, rawDelta));
  
  // Agreement bonus: more agents agreeing = faster escalation
  const agreementBonus = detectedCount >= 2 ? agreementFactor * 3 : 0;
  
  // Warm-up multiplier: risk builds slowly at first, then accelerates
  // If accumulated risk is already > 30, we're in "escalation mode"
  const isWarmedUp = currentRiskState.accumulatedRisk > 30;
  const hasStrongSignals = detectedCount >= 2 && instantRisk > 0.5;
  const warmUpMultiplier = (isWarmedUp || hasStrongSignals) ? 1.0 : 0.35;

  const newAccumulated = Math.min(100, Math.max(0, 
    decayApplied + 
    (cappedDelta + agreementBonus) * warmUpMultiplier
  ));

  // ─── CONFIDENCE CALCULATION ───────────────────────────────
  // Based on: agent agreement (40%), signal strength (30%), temporal consistency (20%), isolation score (10%)
  const agreementConfidence = agreementFactor * 0.4;
  const strengthConfidence = Math.min(instantRisk * 0.3, 0.3);
  const temporalConfidence = (isWarmedUp || hasStrongSignals) ? 0.2 : 0.05;
  const isolationConfidence = isolationScore * 0.1;
  const confidence = Math.min(agreementConfidence + strengthConfidence + temporalConfidence + isolationConfidence, 0.99);

  // Calculate actual escalation rate for tracking
  const escalationRate = (cappedDelta + agreementBonus) * warmUpMultiplier;

  return {
    currentScore: Math.round(instantRisk * 100),
    accumulatedRisk: newAccumulated,
    decayFactor: DECAY_FACTOR,
    confidence,
    lastUpdate: timestamp,
    escalationRate,
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
