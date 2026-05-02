import {
  AgentBreakdown,
  AgentSignal,
  AlertLevel,
  AnomalySignal,
  AttackClassification,
  BankingContext,
  Baseline,
  DetectionResult,
  NetworkLog,
  RiskState,
  WindowStats,
} from '../types/ids';
import { getProfileLabel, inferBankingProfile } from './baselineEngine';
import { computeClusterOutlierScore } from './clusteringEngine';
import { classifyAccumulatedRisk, classifyAttack } from './riskEngine';
import { matchSignatureRules } from './signatureEngine';
import { clamp } from './statistics';

function buildBankingContext(log: NetworkLog): BankingContext {
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

function getDetectedSignals(signals: AnomalySignal[]): AnomalySignal[] {
  return signals.filter(signal => signal.detected);
}

function scoreContextAdjustments(
  log: NetworkLog,
  detectedSignals: AnomalySignal[],
  classification: AttackClassification
): { adjustedRisk: number; reduced: boolean; reasons: string[] } {
  const reasons: string[] = [];
  let adjustment = 0;
  const signalCount = detectedSignals.length;
  const hasUnknownIp = detectedSignals.some(signal => signal.type === 'UNKNOWN_IP');
  const hasQuerySpike = detectedSignals.some(signal => signal.type === 'DB_SPIKE');

  if (signalCount > 0 && signalCount <= 1) {
    adjustment -= 12;
    reasons.push('Single-signal anomaly kept at low confidence until additional evidence appears.');
  }
  if (signalCount > 0 && log.isBusinessHours && signalCount < 3) {
    adjustment -= 8;
    reasons.push('Business-hours traffic lowers escalation unless signals correlate across layers.');
  }
  if (log.isATMReconciliation && hasQuerySpike && !hasUnknownIp) {
    adjustment -= 22;
    reasons.push('ATM reconciliation window explains elevated database throughput without raising high confidence.');
  }
  if (log.isMonthEndBatch && hasQuerySpike && !hasUnknownIp) {
    adjustment -= 18;
    reasons.push('Month-end batch profile suppresses query-driven alerts unless external indicators are present.');
  }
  if (log.isSWIFTCommunication && log.destIP === '203.45.12.88' && signalCount <= 2) {
    adjustment -= 16;
    reasons.push('Approved SWIFT gateway traffic reduces confidence for isolated external-IP anomalies.');
  }
  if (!log.isBusinessHours && signalCount >= 2) {
    adjustment += 10;
    reasons.push('Off-hours correlated activity increases analyst priority.');
  }
  if (classification === 'DATA_EXFILTRATION') {
    adjustment += 8;
  }
  if (classification === 'C2_BEACONING') {
    adjustment += 4;
  }

  return {
    adjustedRisk: adjustment,
    reduced: adjustment < 0,
    reasons,
  };
}

function mapThreatCategory(classification: AttackClassification, detectedSignals: AnomalySignal[]): string {
  switch (classification) {
    case 'C2_BEACONING':
      return 'Correlated C2 Beaconing';
    case 'DATA_EXFILTRATION':
      return 'Privileged Data Exfiltration';
    case 'LATERAL_MOVEMENT':
      return 'Lateral Movement / Staging';
    case 'PRIVILEGED_ABUSE':
      return 'Privileged Account Abuse';
    case 'RECONNAISSANCE':
      return 'Recon / External Discovery';
    case 'SUSPICIOUS_ACTIVITY':
      return 'Suspicious Multi-Signal Activity';
    default:
      return detectedSignals.length > 0 ? 'Low-Confidence Anomaly' : 'Clean Traffic';
  }
}

function deriveDetectionModes(
  detectedSignals: AnomalySignal[],
  attackClassification: AttackClassification,
  zeroDayScore: number,
  signatureMatches: string[]
): import('../types/ids').DetectionMode[] {
  const modes = new Set<import('../types/ids').DetectionMode>();

  if (signatureMatches.length > 0) {
    modes.add('SIGNATURE');
  }
  if (detectedSignals.length > 0) {
    modes.add('ANOMALY');
  }
  if (
    detectedSignals.some(signal => signal.type === 'DB_SPIKE' || signal.type === 'PRIVILEGED_MISUSE') ||
    attackClassification === 'LATERAL_MOVEMENT' ||
    attackClassification === 'PRIVILEGED_ABUSE'
  ) {
    modes.add('BEHAVIORAL');
  }
  if (signatureMatches.length === 0 && (zeroDayScore >= 0.55 || attackClassification === 'C2_BEACONING' || attackClassification === 'DATA_EXFILTRATION')) {
    modes.add('ZERO_DAY');
  }

  return [...modes];
}

function buildCorrelationChain(
  agentSignals: AgentSignal[],
  riskState: RiskState,
  detectedSignals: AnomalySignal[],
  classification: AttackClassification,
  contextAdjustments: string[]
): string[] {
  const chain: string[] = [];
  chain.push(
    `Risk state ${riskState.accumulatedRisk.toFixed(1)}/100, instant ${riskState.currentScore}/100, uncertainty ${(riskState.uncertainty * 100).toFixed(0)}%.`
  );

  agentSignals
    .filter(signal => signal.detected)
    .forEach(signal => chain.push(signal.reasoning));

  if (detectedSignals.length > 0) {
    chain.push(`Detected signal overlap: ${detectedSignals.map(signal => signal.type).join(' + ')}.`);
  }
  if (classification !== 'NONE') {
    chain.push(`Threat classification selected: ${classification}.`);
  }
  contextAdjustments.forEach(reason => chain.push(`Context control: ${reason}`));
  return chain;
}

function buildAlternativeInterpretation(log: NetworkLog, detectedSignals: AnomalySignal[]): string {
  if (detectedSignals.length === 0) {
    return 'Observed activity aligns with learned banking baselines.';
  }

  const alternatives: string[] = [];
  if (log.isATMReconciliation) {
    alternatives.push('nightly ATM reconciliation');
  }
  if (log.isMonthEndBatch) {
    alternatives.push('month-end finance batch processing');
  }
  if (log.isSWIFTCommunication && log.destIP === '203.45.12.88') {
    alternatives.push('approved SWIFT gateway messaging');
  }
  if (detectedSignals.some(signal => signal.type === 'TLS_ANOMALY')) {
    alternatives.push('a legitimate client TLS stack update');
  }
  if (detectedSignals.some(signal => signal.type === 'UNKNOWN_IP')) {
    alternatives.push('newly onboarded external infrastructure');
  }

  return alternatives.length > 0
    ? `Analyst note: the same pattern could also reflect ${alternatives.join(', ')} until more corroborating signals arrive.`
    : 'Analyst note: no strong benign explanation remains once the current signals are correlated.';
}

function buildTemporalContext(windowStats: WindowStats, riskScore: number, riskState: RiskState): string {
  const seconds = Math.max(60, Math.round(windowStats.timeSpan / 1000));
  const riskTrend = riskState.escalationRate > 0.5 ? 'rising' : riskState.escalationRate < -0.5 ? 'falling' : 'stable';
  return `Last ${seconds}s: ${windowStats.totalPackets} aggregated network events, ${(windowStats.externalIPFrequency * 100).toFixed(0)}% external traffic, interval entropy ${windowStats.intervalEntropy.toFixed(3)}, risk ${riskTrend} at ${riskScore}/100.`;
}

function buildExecutiveSummary(
  alert: AlertLevel,
  classification: AttackClassification,
  confidence: number,
  threatCategory: string,
  detectionModes: import('../types/ids').DetectionMode[]
): string {
  const pct = (confidence * 100).toFixed(0);
  if (alert === 'LOW') {
    return `Summary: telemetry is within expected limits. Confidence ${pct}%.`;
  }
  if (alert === 'MEDIUM') {
    return `Summary: medium-confidence anomaly cluster (${threatCategory}) requires analyst validation. Modes: ${detectionModes.join(', ')}. Confidence ${pct}%.`;
  }
  if (alert === 'HIGH') {
    return `Summary: high-confidence ${classification.replace(/_/g, ' ').toLowerCase()} pattern detected via ${detectionModes.join(', ')}. Confidence ${pct}%.`;
  }
  return `Summary: critical correlated intrusion pattern with sustained multi-agent agreement. Confidence ${pct}%.`;
}

function buildExplanation(
  log: NetworkLog,
  detectedSignals: AnomalySignal[],
  threatCategory: string,
  correlationSignal: AgentSignal | undefined,
  alert: AlertLevel,
  confidence: number,
  riskScore: number,
  signatureMatches: string[],
  clusterOutlierScore: number,
  nearestBehaviorCluster: string
): string {
  if (detectedSignals.length === 0) {
    return `Traffic from ${log.sourceIP} in ${log.networkSegment} matches the learned ${getProfileLabel(inferBankingProfile(log))} baseline. Telemetry from ${log.telemetrySources.join(', ')} shows no correlated anomaly chain; nearest behavior cluster is ${nearestBehaviorCluster} with outlier score ${(clusterOutlierScore * 100).toFixed(0)}%, and risk remains ${riskScore}/100 with ${(confidence * 100).toFixed(0)}% confidence.`;
  }

  const statements = detectedSignals.map(signal => signal.description);
  const correlationText = correlationSignal?.detected
    ? correlationSignal.reasoning.replace(/^CORRELATION AGENT:\s*/u, '')
    : 'Correlation did not yet find enough overlap for a high-confidence intrusion label.';

  return [
    `${threatCategory} observed from ${log.sourceIP} in ${log.networkSegment} targeting ${log.applicationLabel}.`,
    statements.join(' '),
    correlationText,
    signatureMatches.length > 0
      ? `Signature evidence: ${signatureMatches.join('; ')}.`
      : `No signature matched; clustering outlier score is ${(clusterOutlierScore * 100).toFixed(0)}% against nearest cluster ${nearestBehaviorCluster}, so classification is being driven by behavioral deviation and correlation.`,
    `Telemetry fused from ${log.telemetrySources.join(', ')}.`,
    `Current alert level is ${alert} with ${(confidence * 100).toFixed(0)}% confidence and accumulated risk ${riskScore}/100.`,
  ].join(' ');
}

function buildAgentBreakdown(agentSignals: AgentSignal[]): AgentBreakdown {
  const lookup = (agent: AgentSignal['agent']) => agentSignals.find(signal => signal.agent === agent);
  return {
    PACKET: {
      score: lookup('PACKET')?.score ?? 0,
      confidence: lookup('PACKET')?.confidence ?? 0,
      detected: lookup('PACKET')?.detected ?? false,
    },
    FLOW: {
      score: lookup('FLOW')?.score ?? 0,
      confidence: lookup('FLOW')?.confidence ?? 0,
      detected: lookup('FLOW')?.detected ?? false,
    },
    BEHAVIOR: {
      score: lookup('BEHAVIOR')?.score ?? 0,
      confidence: lookup('BEHAVIOR')?.confidence ?? 0,
      detected: lookup('BEHAVIOR')?.detected ?? false,
    },
    CORRELATION: {
      score: lookup('CORRELATION')?.score ?? 0,
      confidence: lookup('CORRELATION')?.confidence ?? 0,
      detected: lookup('CORRELATION')?.detected ?? false,
    },
    RESPONSE: {
      score: lookup('RESPONSE')?.score ?? 0,
      confidence: lookup('RESPONSE')?.confidence ?? 0,
      detected: lookup('RESPONSE')?.detected ?? false,
    },
  };
}

export function correlateSignals(
  log: NetworkLog,
  signals: AnomalySignal[],
  _baseline: Baseline,
  windowStats: WindowStats,
  attackPhase: number,
  agentSignals: AgentSignal[],
  riskState: RiskState,
  isolationScore: number
): Omit<DetectionResult, 'log'> {
  const detectedSignals = getDetectedSignals(signals);
  const correlationSignal = agentSignals.find(signal => signal.agent === 'CORRELATION');
  const attackClassification = classifyAttack(agentSignals);
  const contextAdjustments = scoreContextAdjustments(log, detectedSignals, attackClassification);
  const baseRisk = riskState.accumulatedRisk;
  const adjustedRisk = clamp(baseRisk + contextAdjustments.adjustedRisk, 0, 100);
  const agentDetections = agentSignals.filter(signal => signal.detected).length;
  const minimumVisibleRisk = agentDetections > 0
    ? Math.max(baseRisk * 0.6, correlationSignal?.detected ? baseRisk * 0.8 : 0)
    : baseRisk > 0
      ? Math.max(1, baseRisk * 0.35)
      : 0;
  const provisionalRisk = Math.max(adjustedRisk, minimumVisibleRisk);
  const derivedRiskState: RiskState = { ...riskState };

  let alert = classifyAccumulatedRisk(
    { ...derivedRiskState, accumulatedRisk: provisionalRisk },
    Boolean(correlationSignal?.detected)
  );
  if (detectedSignals.length <= 1 && alert === 'HIGH') {
    alert = 'MEDIUM';
  }

  const confidence = clamp(
    riskState.confidence +
      (correlationSignal?.detected ? 0.08 : -0.04) +
      detectedSignals.length * 0.03 -
      (contextAdjustments.reduced ? 0.05 : 0),
    0.08,
    0.99
  );
  const signatureMatches = matchSignatureRules(log);
  const { score: clusterOutlierScore, nearestCluster: nearestBehaviorCluster } = computeClusterOutlierScore(log, _baseline, windowStats);
  const zeroDayScore = clamp(
    signatureMatches.length === 0
      ? ((correlationSignal?.score ?? 0) * 0.35) +
        (detectedSignals.some(signal => signal.type === 'UNKNOWN_IP') ? 0.18 : 0) +
        (detectedSignals.some(signal => signal.type === 'TLS_ANOMALY') ? 0.12 : 0) +
        (detectedSignals.some(signal => signal.type === 'BEACONING') ? 0.12 : 0) +
        clusterOutlierScore * 0.23
      : 0.18,
    0,
    1
  );
  const detectionModes = deriveDetectionModes(detectedSignals, attackClassification, zeroDayScore, signatureMatches);
  const threatCategory = mapThreatCategory(attackClassification, detectedSignals);
  const reasons = detectedSignals.map(signal => signal.description).concat(contextAdjustments.reasons);
  const correlationChain = buildCorrelationChain(agentSignals, derivedRiskState, detectedSignals, attackClassification, contextAdjustments.reasons);
  const explanation = buildExplanation(
    log,
    detectedSignals,
    threatCategory,
    correlationSignal,
    alert,
    confidence,
    Math.round(provisionalRisk),
    signatureMatches,
    clusterOutlierScore,
    nearestBehaviorCluster
  );
  const temporalContext = buildTemporalContext(windowStats, Math.round(provisionalRisk), derivedRiskState);
  const alternativeInterpretation = buildAlternativeInterpretation(log, detectedSignals);
  const executiveSummary = buildExecutiveSummary(alert, attackClassification, confidence, threatCategory, detectionModes);

  return {
    riskScore: Math.round(provisionalRisk),
    alert,
    confidence,
    reasons,
    explanation,
    signals,
    agentSignals,
    isolationScore,
    correlationScore: Math.round(((correlationSignal?.score ?? 0) * 0.7 + (detectedSignals.length / 6) * 0.3) * 100),
    falsePositiveReduced: contextAdjustments.reduced,
    attackPhase: attackPhase as DetectionResult['attackPhase'],
    attackClassification,
    threatCategory,
    alternativeInterpretation,
    executiveSummary,
    temporalContext,
    agentBreakdown: buildAgentBreakdown(agentSignals),
    riskState: derivedRiskState,
    bankingContext: buildBankingContext(log),
    correlationChain,
    detectionModes,
    signatureMatches,
    zeroDayScore,
    clusterOutlierScore,
    nearestBehaviorCluster,
    autoIsolationRecommended: false,
  };
}
