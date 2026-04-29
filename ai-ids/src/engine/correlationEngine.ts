// ============================================================
// CORRELATION ENGINE v4.0 — Multi-Agent Alert Fusion & Threat Intelligence
// Fuses Packet Agent → Flow Agent → Behavior Agent → Correlation Agent
// Implements: Multi-signal fusion, temporal correlation, SOC-style reasoning
// ============================================================

import { AnomalySignal, AlertLevel, DetectionResult, NetworkLog, Baseline, WindowStats, AttackPhase, AgentSignal, RiskState } from '../types/ids';
import { computeIsolationScore } from './anomalyDetector';
import { classifyAccumulatedRisk, classifyAttack } from './riskEngine';

// ─── Multi-Signal Fusion Rules ────────────────────────────────
interface FusionRule {
  name: string;
  description: string;
  confidence: number;
  requiredSignals: string[];
  optionalSignals?: string[];
}

const FUSION_RULES: FusionRule[] = [
  {
    name: 'C2_BEACONING',
    description: 'Command & Control beaconing detected',
    confidence: 0.85,
    requiredSignals: ['BEACONING', 'UNKNOWN_IP'],
    optionalSignals: ['TLS_ANOMALY'],
  },
  {
    name: 'DATA_EXFILTRATION',
    description: 'Privileged data exfiltration pattern',
    confidence: 0.78,
    requiredSignals: ['DB_SPIKE', 'PRIVILEGED_MISUSE'],
    optionalSignals: ['PACKET_ANOMALY', 'UNKNOWN_IP'],
  },
  {
    name: 'LATERAL_MOVEMENT',
    description: 'Lateral movement with privileged escalation',
    confidence: 0.72,
    requiredSignals: ['PRIVILEGED_MISUSE', 'PACKET_ANOMALY'],
    optionalSignals: ['DB_SPIKE'],
  },
  {
    name: 'RECONNAISSANCE',
    description: 'Network reconnaissance activity',
    confidence: 0.65,
    requiredSignals: ['UNKNOWN_IP'],
    optionalSignals: ['BEACONING'],
  },
  {
    name: 'TLS_TUNNEL',
    description: 'Encrypted C2 tunnel via TLS anomaly',
    confidence: 0.70,
    requiredSignals: ['TLS_ANOMALY', 'BEACONING'],
    optionalSignals: ['UNKNOWN_IP'],
  },
];

// ─── Apply Fusion Rules ───────────────────────────────────────
function applyFusionRules(
  signals: AnomalySignal[],
  agentSignals: AgentSignal[]
): { matchedRules: FusionRule[]; fusionConfidence: number; fusionBoost: number } {
  const detectedTypes = signals.filter(s => s.detected).map(s => s.type);
  const matchedRules: FusionRule[] = [];
  let fusionConfidence = 0;
  let fusionBoost = 0;

  for (const rule of FUSION_RULES) {
    const hasRequired = rule.requiredSignals.every(req => detectedTypes.includes(req as any));
    const hasOptional = rule.optionalSignals 
      ? rule.optionalSignals.some(opt => detectedTypes.includes(opt as any))
      : false;

    if (hasRequired) {
      matchedRules.push(rule);
      const optionalBonus = hasOptional ? 0.1 : 0;
      fusionConfidence = Math.max(fusionConfidence, rule.confidence + optionalBonus);
      fusionBoost += 15;
    }
  }

  return { matchedRules, fusionConfidence, fusionBoost };
}

// ─── Temporal Correlation Analysis ────────────────────────────
function analyzeTemporalCorrelation(
  agentSignals: AgentSignal[],
  riskState: RiskState
): { temporalConfidence: number; temporalContext: string } {
  const detectedCount = agentSignals.filter(s => s.detected).length;
  const agreementFactor = detectedCount / agentSignals.length;
  
  const sustainedActivity = riskState.accumulatedRisk > 30 ? 0.3 : 0;
  const buildingPattern = riskState.escalationRate > 0 ? 0.2 : 0;
  
  const temporalConfidence = Math.min(0.5, sustainedActivity + buildingPattern + (agreementFactor * 0.2));
  
  let temporalContext = '';
  if (riskState.accumulatedRisk > 50) {
    temporalContext = `Sustained elevated risk over ${Math.round(riskState.accumulatedRisk / 10)}+ evaluation cycles.`;
  } else if (riskState.escalationRate > 0) {
    temporalContext = `Risk escalation detected — building threat pattern.`;
  } else {
    temporalContext = `No sustained threat pattern observed.`;
  }

  return { temporalConfidence, temporalContext };
}

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
  isSWIFTCommunication: boolean;
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
    reductionReasons.push('Single-signal anomaly — insufficient for HIGH classification (correlation requires ≥2 signals)');
  }

  // Rule 2: Business hours bonus
  if (log.isBusinessHours && detectedCount < 3) {
    const reduction = 12;
    score = Math.max(0, score - reduction);
    reduced = true;
    reductionReasons.push(`Business hours context (8AM-6PM) — risk adjusted -${reduction} points`);
  }

  // Rule 3: ATM reconciliation window (0-3 AM)
  if (context.isATMReconciliation && signals.find(s => s.type === 'DB_SPIKE')?.detected) {
    const reduction = 25;
    score = Math.max(0, score - reduction);
    reduced = true;
    reductionReasons.push(`ATM reconciliation window (0-3 AM) — DB spike risk adjusted -${reduction} points (expected batch behavior)`);
  }

  // Rule 4: SWIFT communication window
  if (context.isSWIFTCommunication && detectedCount <= 2) {
    const reduction = 18;
    score = Math.max(0, score - reduction);
    reduced = true;
    reductionReasons.push(`SWIFT communication window — low-frequency external traffic is expected`);
  }

  // Rule 5: Month-end batch
  if (context.isMonthEndBatch && detectedCount <= 2) {
    const reduction = 20;
    score = Math.max(0, score - reduction);
    reduced = true;
    reductionReasons.push(`Month-end batch processing (23:00-02:00) — risk adjusted -${reduction} points`);
  }

  // Rule 6: Off-hours amplification
  if (!log.isBusinessHours && detectedCount >= 2) {
    const amplification = 12;
    score = Math.min(100, score + amplification);
    reductionReasons.push(`Off-hours anomaly (${new Date(log.timestamp).getHours()}:00) — risk amplified +${amplification} points`);
  }

  return { adjustedScore: Math.round(score), reduced, reductionReasons };
}

// ─── Threat Category Classification ───────────────────────────
function classifyThreatCategory(
  signals: AnomalySignal[],
  matchedRules: FusionRule[]
): string {
  if (matchedRules.length > 0) {
    return matchedRules[0].description;
  }
  
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
  alert: AlertLevel,
  matchedRules: FusionRule[]
): string[] {
  const chain: string[] = [];
  const detectedAgents = agentSignals.filter(s => s.detected);

  chain.push(`Risk accumulation: ${riskState.accumulatedRisk.toFixed(1)} out of 100 (decay factor: ${riskState.decayFactor})`);

  for (const signal of detectedAgents) {
    chain.push(`${signal.agent} Agent: ${signal.reasoning}`);
  }

  if (matchedRules.length > 0) {
    chain.push(`FUSION: ${matchedRules[0].name} pattern detected (${(matchedRules[0].confidence * 100).toFixed(0)}% rule confidence)`);
  }

  if (detectedAgents.length >= 2) {
    chain.push(`CORRELATION: ${detectedAgents.length}/3 agents agree on suspicious activity`);
    chain.push(`Confidence: ${(riskState.confidence * 100).toFixed(0)}% (agreement + temporal + strength)`);
  } else if (detectedAgents.length === 1) {
    chain.push(`WARNING: Only 1/3 agents detected anomaly — insufficient for HIGH confidence`);
  }

  if (alert === 'HIGH' || alert === 'CRITICAL') {
    chain.push(`ESCALATION: ${alert} alert triggered — multi-signal fusion threshold crossed`);
  } else if (alert === 'MEDIUM') {
    chain.push(`ESCALATION: MEDIUM alert — single or weak multi-signal detection`);
  }

  return chain;
}

// ─── Alternative Interpretation ───────────────────────────────
function generateAlternativeInterpretation(
  signals: AnomalySignal[],
  alert: AlertLevel,
  bankingContext: { isATMReconciliation: boolean; isMonthEndBatch: boolean; isSWIFTCommunication: boolean }
): string {
  if (alert === 'LOW') {
    return 'Everything looks normal. No signs of suspicious activity.';
  }
  const detected = signals.filter(s => s.detected);
  const has = (type: string) => detected.some(s => s.type === type);
  const alternatives: string[] = [];

  if (bankingContext.isATMReconciliation) {
    alternatives.push('the nightly ATM reconciliation process (normal 0-3 AM batch activity)');
  }
  if (bankingContext.isMonthEndBatch) {
    alternatives.push('month-end financial report generation (expected 23:00-02:00 window)');
  }
  if (bankingContext.isSWIFTCommunication) {
    alternatives.push('scheduled SWIFT interbank communication (low-frequency, expected)');
  }
  if (has('BEACONING')) alternatives.push('an automated system health check or server heartbeat');
  if (has('DB_SPIKE')) alternatives.push('a scheduled database backup or maintenance task');
  if (has('UNKNOWN_IP')) alternatives.push('a new cloud service or CDN endpoint the bank recently onboarded');
  if (has('PRIVILEGED_MISUSE')) alternatives.push('an administrator performing emergency maintenance');
  if (has('TLS_ANOMALY')) alternatives.push('a software update that changed the TLS fingerprint');
  if (has('PACKET_ANOMALY')) alternatives.push('a large file upload or backup operation');

  if (alternatives.length === 0) return 'No unusual activity detected.';
  return `This could be a security threat, but it might also just be ${alternatives.join(', or ')}. The more warning signs we see together, the more likely it is to be a real attack.`;
}

// ─── Temporal Context ─────────────────────────────────────────
function generateTemporalContext(
  windowStats: WindowStats, 
  detectedCount: number, 
  riskScore: number,
  temporalAnalysis: { temporalConfidence: number; temporalContext: string }
): string {
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
  parts.push(temporalAnalysis.temporalContext);
  return parts.join('. ') + '.';
}

// ─── Executive Summary ────────────────────────────────────────
function generateExecutiveSummary(
  alert: AlertLevel,
  detectedCount: number,
  confidence: number,
  attackClassification: string,
  matchedRules: FusionRule[]
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
    if (matchedRules.length > 0) {
      detail += `${matchedRules[0].description} pattern confirmed.`;
    } else if (detectedCount >= 3) {
      detail += 'someone may be moving through the network and stealing data.';
    } else if (detectedCount === 2) {
      detail += 'repeated connections to an unknown server combined with unusual outbound traffic.';
    } else {
      detail += 'unusual behavior that needs review.';
    }
    return `Summary: High-confidence warning (${confidencePct}%) indicating ${detail}`;
  }
  return `Summary: Medium-confidence observation (${confidencePct}%) with ${detectedCount} warning sign(s) — please investigate soon.`;
}

// ─── SOC-Style Explanation Engine ─────────────────────────────
function generateExplanation(
  signals: AnomalySignal[],
  riskScore: number,
  alert: AlertLevel,
  confidence: number,
  log: NetworkLog,
  agentSignals: AgentSignal[],
  correlationChain: string[],
  matchedRules: FusionRule[]
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

  for (const agent of agentSignals.filter(a => a.detected)) {
    parts.push(agent.reasoning);
  }

  if (matchedRules.length > 0) {
    const rule = matchedRules[0];
    parts.push(`CORRELATION ENGINE: ${rule.description} pattern detected with ${(rule.confidence * 100).toFixed(0)}% rule confidence.`);
  }

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

  // Apply multi-signal fusion rules
  const agents = agentSignals || [];
  const { matchedRules, fusionConfidence, fusionBoost } = applyFusionRules(signals, agents);

  // Temporal correlation analysis
  const temporalAnalysis = riskState 
    ? analyzeTemporalCorrelation(agents, riskState)
    : { temporalConfidence: 0, temporalContext: '' };

  // Banking context
  const isBatchJobTime = hour >= 0 && hour < 3;
  const context: FPContext = {
    isBusinessHours: log.isBusinessHours,
    isBatchJobTime,
    isATMReconciliation: log.isATMReconciliation,
    isMonthEndBatch: log.isMonthEndBatch,
    isSWIFTCommunication: log.isSWIFTCommunication,
    multiSignalCount: detectedCount,
  };

  const { adjustedScore, reduced, reductionReasons } = reduceFalsePositives(
    blendedScore + fusionBoost,
    signals,
    log,
    context
  );

  // Use risk engine state if available (v4.0), otherwise legacy
  const finalScore = riskState ? Math.round(riskState.accumulatedRisk) : Math.min(Math.max(adjustedScore, 0), 100);
  const alert = riskState ? classifyAccumulatedRisk(riskState) : classifyRisk(finalScore);
  
  // Enhanced confidence with fusion and temporal analysis
  const baseConfidence = riskState ? riskState.confidence : computeLegacyConfidence(signals, isolationScore, finalScore);
  const confidence = Math.min(0.99, baseConfidence + (fusionConfidence * 0.1) + temporalAnalysis.temporalConfidence);

  const correlationChain = riskState ? generateCorrelationChain(agents, riskState, alert, matchedRules) : [];
  const attackClassification = classifyAttack(agents);

  const { explanation, reasons } = generateExplanation(
    signals,
    finalScore,
    alert,
    confidence,
    log,
    agents,
    correlationChain,
    matchedRules
  );

  if (reduced && reductionReasons.length > 0) {
    reasons.push(...reductionReasons);
  }

  const threatCategory = classifyThreatCategory(signals, matchedRules);
  const alternativeInterpretation = generateAlternativeInterpretation(signals, alert, {
    isATMReconciliation: log.isATMReconciliation,
    isMonthEndBatch: log.isMonthEndBatch,
    isSWIFTCommunication: log.isSWIFTCommunication,
  });
  const temporalContext = generateTemporalContext(windowStats, detectedCount, finalScore, temporalAnalysis);
  const executiveSummary = generateExecutiveSummary(alert, detectedCount, confidence, attackClassification, matchedRules);

  return {
    riskScore: finalScore,
    alert,
    confidence,
    reasons,
    explanation,
    signals,
    isolationScore,
    correlationScore: rawScore + fusionBoost,
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
      RESPONSE: { score: 0, confidence: 0, detected: false },
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
