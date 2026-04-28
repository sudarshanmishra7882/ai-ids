// ============================================================
// CORRELATION ENGINE v3.0 — Multi-Agent Alert Fusion
// Fuses Packet Agent → Flow Agent → Behavior Agent into unified threat
// ============================================================

import { AnomalySignal, AlertLevel, DetectionResult, NetworkLog, Baseline, WindowStats, AttackPhase, AgentSignal, RiskState } from '../types/ids';
import { computeIsolationScore } from './anomalyDetector';
import { classifyAccumulatedRisk, classifyAttack } from './riskEngine';

// ─── Risk Classification ──────────────────────────────────────
function classifyRisk(score: number): AlertLevel {
  if (score >= 70) return 'HIGH';
  if (score >= 40) return 'MEDIUM';
  return 'LOW';
}

// ─── False Positive Reduction ─────────────────────────────────
interface FPContext {
  isBusinessHours: boolean;
  isBatchJobTime: boolean;
  isATMReconciliation: boolean;
  isMonthEndBatch: boolean;
  multiSignalCount: number;
}

function reduceFalsePositives(
  rawScore: number,
  signals: AnomalySignal[],
  log: NetworkLog,
  context: FPContext
): { adjustedScore: number; reduced: boolean; reductionReasons: string[] } {
  let score = rawScore;
  let reduced = false;
  const reductionReasons: string[] = [];
  const detectedCount = signals.filter(s => s.detected).length;

  // Rule 1: Single-signal — never HIGH
  if (detectedCount === 1 && score >= 70) {
    score = Math.min(score, 65);
    reduced = true;
    reductionReasons.push('Single-signal anomaly — insufficient for HIGH classification');
  }

  // Rule 2: Business hours bonus
  if (log.isBusinessHours && detectedCount < 3) {
    const reduction = 10;
    score = Math.max(0, score - reduction);
    reduced = true;
    reductionReasons.push(`Business hours context — risk adjusted -${reduction} points`);
  }

  // Rule 3: ATM reconciliation window
  if (context.isATMReconciliation && signals.find(s => s.type === 'DB_SPIKE')?.detected) {
    const reduction = 20;
    score = Math.max(0, score - reduction);
    reduced = true;
    reductionReasons.push(`ATM reconciliation window (0-3 AM) — DB spike risk adjusted -${reduction} points`);
  }

  // Rule 4: Month-end batch
  if (context.isMonthEndBatch && detectedCount <= 2) {
    const reduction = 15;
    score = Math.max(0, score - reduction);
    reduced = true;
    reductionReasons.push(`Month-end batch processing — risk adjusted -${reduction} points`);
  }

  // Rule 5: Off-hours amplification
  if (!log.isBusinessHours && detectedCount >= 2) {
    const amplification = 10;
    score = Math.min(100, score + amplification);
    reductionReasons.push(`Off-hours anomaly — risk amplified +${amplification} points`);
  }

  return { adjustedScore: Math.round(score), reduced, reductionReasons };
}

// ─── Threat Category Classification ───────────────────────────
function classifyThreatCategory(signals: AnomalySignal[]): string {
  const detected = signals.filter(s => s.detected);
  const has = (type: string) => detected.some(s => s.type === type);
  if (has('BEACONING') && has('UNKNOWN_IP')) return 'Possible C2 Beaconing';
  if (has('BEACONING') && has('TLS_ANOMALY')) return 'TLS-Encrypted C2 Channel';
  if (has('DB_SPIKE') && has('PRIVILEGED_MISUSE')) return 'Privileged Data Exfiltration';
  if (has('PACKET_ANOMALY') && has('UNKNOWN_IP')) return 'Data Exfiltration Pattern';
  if (has('DB_SPIKE')) return 'Database Query Anomaly';
  if (has('UNKNOWN_IP')) return 'External Communication Anomaly';
  if (has('PRIVILEGED_MISUSE')) return 'Privileged Account Misuse';
  if (has('TLS_ANOMALY')) return 'Unknown TLS Fingerprint';
  if (has('PACKET_ANOMALY')) return 'Anomalous Packet Sizes';
  if (has('BEACONING')) return 'Periodic Beaconing Detected';
  return 'Clean Traffic';
}

// ─── Multi-Agent Correlation Chain ────────────────────────────
function generateCorrelationChain(
  agentSignals: AgentSignal[],
  riskState: RiskState,
  alert: AlertLevel
): string[] {
  const chain: string[] = [];
  const detectedAgents = agentSignals.filter(s => s.detected);

  chain.push(`Current risk level: ${riskState.accumulatedRisk.toFixed(0)} out of 100`);

  for (const signal of detectedAgents) {
    chain.push(`${signal.agent} check: ${signal.reasoning}`);
  }

  if (detectedAgents.length >= 2) {
    chain.push(`${detectedAgents.length} out of 3 security checks agree this looks suspicious`);
    chain.push(`Confidence level: ${(riskState.confidence * 100).toFixed(0)}%`);
  }

  if (alert === 'HIGH' || alert === 'CRITICAL') {
    chain.push(`Alert raised to ${alert} because the risk level crossed the danger threshold`);
  }

  return chain;
}

// ─── Alternative Interpretation ───────────────────────────────
function generateAlternativeInterpretation(
  signals: AnomalySignal[],
  _log: NetworkLog,
  alert: AlertLevel,
  bankingContext: { isATMReconciliation: boolean; isMonthEndBatch: boolean }
): string {
  if (alert === 'LOW') {
    return 'Everything looks normal. No signs of suspicious activity.';
  }
  const detected = signals.filter(s => s.detected);
  const has = (type: string) => detected.some(s => s.type === type);
  const alternatives: string[] = [];

  if (bankingContext.isATMReconciliation) {
    alternatives.push('the nightly ATM reconciliation process (normal overnight activity)');
  }
  if (bankingContext.isMonthEndBatch) {
    alternatives.push('month-end financial report generation');
  }
  if (has('BEACONING')) alternatives.push('an automated system check or server heartbeat');
  if (has('DB_SPIKE')) alternatives.push('a scheduled database backup or maintenance task');
  if (has('UNKNOWN_IP')) alternatives.push('a new cloud service or website the bank recently started using');
  if (has('PRIVILEGED_MISUSE')) alternatives.push('an administrator doing emergency maintenance');
  if (has('TLS_ANOMALY')) alternatives.push('a software update that changed the security signature');
  if (has('PACKET_ANOMALY')) alternatives.push('someone uploading a large file or running a backup');

  if (alternatives.length === 0) return 'No unusual activity detected.';
  return `This could be a security threat, but it might also just be ${alternatives.join(', or ')}. The more warning signs we see together, the more likely it is to be a real attack.`;
}

// ─── Temporal Context ─────────────────────────────────────────
function generateTemporalContext(windowStats: WindowStats, detectedCount: number, riskScore: number): string {
  const parts: string[] = [];
  const windowSec = Math.round(windowStats.timeSpan / 1000);
  parts.push(`In the last ${Math.max(windowSec, 60)} seconds, we monitored ${windowStats.totalPackets} network events`);
  if (detectedCount >= 2) {
    parts.push(`${detectedCount} warning signs appeared during this time`);
  }
  if (riskScore >= 70) {
    parts.push(`The danger level has been rising and is now at ${riskScore} out of 100`);
  } else if (riskScore >= 40) {
    parts.push(`The activity level is elevated at ${riskScore} out of 100`);
  } else {
    parts.push(`Activity is normal and within expected levels`);
  }
  if (windowStats.externalIPFrequency > 0) {
    parts.push(`${(windowStats.externalIPFrequency * 100).toFixed(0)}% of traffic went to external addresses`);
  }
  return parts.join('. ') + '.';
}

// ─── Executive Summary ────────────────────────────────────────
function generateExecutiveSummary(
  alert: AlertLevel,
  detectedCount: number,
  _riskScore: number,
  confidence: number,
  attackClassification: string
): string {
  const confidencePct = (confidence * 100).toFixed(0);
  if (alert === 'LOW') {
    return `Summary: Everything looks normal. The network is running safely. Confidence: ${confidencePct}%.`;
  }
  if (alert === 'CRITICAL') {
    const attackType = attackClassification.replace('_', ' ').toLowerCase();
    return `Summary: CRITICAL alert (${confidencePct}% confidence). We detected active ${attackType}. Immediate action recommended.`;
  }
  if (alert === 'HIGH') {
    let detail = 'a potential attack — ';
    if (detectedCount >= 3) detail += 'someone may be moving through the network and stealing data.';
    else if (detectedCount === 2) detail += 'repeated connections to an unknown server combined with unusual outbound traffic.';
    else detail += 'unusual behavior that needs review.';
    return `Summary: High-confidence warning (${confidencePct}%) indicating ${detail}`;
  }
  return `Summary: Medium-confidence observation (${confidencePct}%) with ${detectedCount} warning sign(s) — please investigate soon.`;
}

// ─── Explanation Engine ───────────────────────────────────────
function generateExplanation(
  signals: AnomalySignal[],
  riskScore: number,
  alert: AlertLevel,
  confidence: number,
  log: NetworkLog,
  _baseline: Baseline,
  agentSignals: AgentSignal[],
  correlationChain: string[]
): { explanation: string; reasons: string[] } {
  const detected = signals.filter(s => s.detected);
  const reasons: string[] = [];
  detected.forEach(s => reasons.push(s.description));

  if (detected.length === 0) {
    return {
      explanation: `Everything looks normal. Traffic from ${log.sourceIP} is behaving as expected. Current risk level: ${riskScore} out of 100. Confidence: ${(confidence * 100).toFixed(0)}%.`,
      reasons: ['No warning signs — network activity is normal'],
    };
  }

  const parts: string[] = [];
  parts.push(`Our security system found ${detected.length} unusual activity patterns coming from ${log.sourceIP}.`);

  // Agent reasoning in plain English
  for (const agent of agentSignals.filter(a => a.detected)) {
    parts.push(agent.reasoning);
  }

  // Causal chain
  if (correlationChain.length > 0) {
    parts.push(`Key finding: ${correlationChain[correlationChain.length - 1]}`);
  }

  if (alert === 'HIGH' || alert === 'CRITICAL') {
    parts.push(`These warning signs together suggest a possible cyberattack — our confidence is ${(confidence * 100).toFixed(0)}%.`);
  } else if (alert === 'MEDIUM') {
    parts.push(`We found ${detected.length} warning signs that should be checked. Confidence: ${(confidence * 100).toFixed(0)}%.`);
  } else {
    parts.push(`One minor warning sign detected — we will keep watching. Risk level: ${riskScore} out of 100.`);
  }

  return { explanation: parts.join(' '), reasons };
}

// ─── Legacy Confidence (backward compat) ──────────────────────
function computeLegacyConfidence(signals: AnomalySignal[], isolationScore: number, riskScore: number): number {
  const detectedCount = signals.filter(s => s.detected).length;
  const signalConfidence = Math.min(detectedCount / 4, 1.0);
  const scoreConfidence = riskScore / 100;
  return Math.min(0.4 * signalConfidence + 0.35 * scoreConfidence + 0.25 * isolationScore, 0.99);
}

// ─── Main Correlation Function ────────────────────────────────
export function correlateSignals(
  log: NetworkLog,
  signals: AnomalySignal[],
  baseline: Baseline,
  windowStats: WindowStats,
  attackPhase: AttackPhase,
  agentSignals?: AgentSignal[],
  riskState?: RiskState
): Omit<DetectionResult, 'log'> {
  const now = new Date(log.timestamp);
  const hour = now.getHours();

  // Legacy scoring
  const rawScore = signals.filter(s => s.detected).reduce((sum, s) => sum + s.weight, 0);
  const isolationScore = computeIsolationScore(log, baseline, windowStats);
  const blendedScore = Math.round(rawScore * 0.65 + isolationScore * 100 * 0.35);
  const detectedCount = signals.filter(s => s.detected).length;

  // Banking context
  const isBatchJobTime = hour >= 0 && hour < 3;
  const context: FPContext = {
    isBusinessHours: log.isBusinessHours,
    isBatchJobTime,
    isATMReconciliation: log.isATMReconciliation,
    isMonthEndBatch: log.isMonthEndBatch,
    multiSignalCount: detectedCount,
  };

  const { adjustedScore, reduced, reductionReasons } = reduceFalsePositives(
    blendedScore,
    signals,
    log,
    context
  );

  // Use risk engine state if available (v3.0), otherwise legacy
  const finalScore = riskState ? Math.round(riskState.accumulatedRisk) : Math.min(Math.max(adjustedScore, 0), 100);
  const alert = riskState ? classifyAccumulatedRisk(riskState) : classifyRisk(finalScore);
  const confidence = riskState ? riskState.confidence : computeLegacyConfidence(signals, isolationScore, finalScore);

  // Agent signals (default to empty if not provided)
  const agents = agentSignals || [];
  const correlationChain = riskState ? generateCorrelationChain(agents, riskState, alert) : [];
  const attackClassification = classifyAttack(agents);

  const { explanation, reasons } = generateExplanation(
    signals,
    finalScore,
    alert,
    confidence,
    log,
    baseline,
    agents,
    correlationChain
  );

  if (reduced && reductionReasons.length > 0) {
    reasons.push(...reductionReasons);
  }

  const threatCategory = classifyThreatCategory(signals);
  const alternativeInterpretation = generateAlternativeInterpretation(signals, log, alert, {
    isATMReconciliation: log.isATMReconciliation,
    isMonthEndBatch: log.isMonthEndBatch,
  });
  const temporalContext = generateTemporalContext(windowStats, detectedCount, finalScore);
  const executiveSummary = generateExecutiveSummary(alert, detectedCount, finalScore, confidence, attackClassification);

  return {
    riskScore: finalScore,
    alert,
    confidence,
    reasons,
    explanation,
    signals,
    isolationScore,
    correlationScore: rawScore,
    falsePositiveReduced: reduced,
    attackPhase,
    attackClassification: attackClassification as import('../types/ids').AttackClassification,
    threatCategory,
    alternativeInterpretation,
    temporalContext,
    executiveSummary,
    agentSignals: agents,
    agentBreakdown: {
      PACKET: { score: agents.find(a => a.agent === 'PACKET')?.score || 0, confidence: agents.find(a => a.agent === 'PACKET')?.confidence || 0, detected: agents.find(a => a.agent === 'PACKET')?.detected || false },
      FLOW: { score: agents.find(a => a.agent === 'FLOW')?.score || 0, confidence: agents.find(a => a.agent === 'FLOW')?.confidence || 0, detected: agents.find(a => a.agent === 'FLOW')?.detected || false },
      BEHAVIOR: { score: agents.find(a => a.agent === 'BEHAVIOR')?.score || 0, confidence: agents.find(a => a.agent === 'BEHAVIOR')?.confidence || 0, detected: agents.find(a => a.agent === 'BEHAVIOR')?.detected || false },
    },
    riskState: riskState || {
      currentScore: finalScore,
      accumulatedRisk: finalScore,
      decayFactor: 0.92,
      confidence,
      lastUpdate: Date.now(),
      escalationRate: 0,
    },
    bankingContext: {
      isATMReconciliation: log.isATMReconciliation,
      isSWIFTCommunication: log.isSWIFTCommunication,
      isMonthEndBatch: log.isMonthEndBatch,
      batchJobWindow: log.isATMReconciliation || log.isMonthEndBatch,
    },
    correlationChain,
  };
}
