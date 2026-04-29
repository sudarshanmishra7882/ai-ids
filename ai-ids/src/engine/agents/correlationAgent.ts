import {
  AgentSignal,
  AnomalySignal,
  AttackClassification,
  Baseline,
  NetworkLog,
  RiskState,
  WindowStats,
} from '../../types/ids';
import { clamp } from '../statistics';

function hasSignal(signals: AnomalySignal[], type: AnomalySignal['type']): boolean {
  return signals.some(signal => signal.type === type && signal.detected);
}

function classifyCorrelation(
  log: NetworkLog,
  signals: AnomalySignal[],
  packetSignal: AgentSignal,
  flowSignal: AgentSignal,
  behaviorSignal: AgentSignal
): AttackClassification {
  const beaconing = hasSignal(signals, 'BEACONING') || flowSignal.features.beaconScore > 0.6;
  const unknownIp = hasSignal(signals, 'UNKNOWN_IP');
  const tls = hasSignal(signals, 'TLS_ANOMALY');
  const querySpike = hasSignal(signals, 'DB_SPIKE') || behaviorSignal.features.queryDeviation > 2.2;
  const privileged = hasSignal(signals, 'PRIVILEGED_MISUSE') || log.isPrivileged;
  const packet = hasSignal(signals, 'PACKET_ANOMALY') || packetSignal.score > 0.58;

  if (beaconing && unknownIp && (tls || flowSignal.score > 0.62) && !querySpike) {
    return 'C2_BEACONING';
  }
  if (querySpike && packet && unknownIp && privileged) {
    return 'DATA_EXFILTRATION';
  }
  if (querySpike && privileged && !log.isExternalIP) {
    return 'LATERAL_MOVEMENT';
  }
  if (privileged && (querySpike || unknownIp)) {
    return 'PRIVILEGED_ABUSE';
  }
  if (unknownIp || flowSignal.score > 0.45) {
    return 'RECONNAISSANCE';
  }
  return 'NONE';
}

export function runCorrelationAgent(
  log: NetworkLog,
  baseline: Baseline,
  windowStats: WindowStats,
  signals: AnomalySignal[],
  upstreamSignals: [AgentSignal, AgentSignal, AgentSignal],
  history: { alert: string; attackClassification: AttackClassification; riskScore: number }[],
  previousRiskState: RiskState
): AgentSignal {
  const [packetSignal, flowSignal, behaviorSignal] = upstreamSignals;
  const detectedSignals = signals.filter(signal => signal.detected);
  const uniqueSignalCount = detectedSignals.length;
  const agentAgreement = upstreamSignals.filter(signal => signal.detected).length / upstreamSignals.length;
  const recentEscalations = history.slice(-6).filter(item => item.alert === 'MEDIUM' || item.alert === 'HIGH' || item.alert === 'CRITICAL').length;

  const beaconWeight = hasSignal(signals, 'BEACONING') ? 0.18 : 0;
  const endpointWeight = hasSignal(signals, 'UNKNOWN_IP') ? 0.17 : 0;
  const tlsWeight = hasSignal(signals, 'TLS_ANOMALY') ? 0.09 : 0;
  const queryWeight = hasSignal(signals, 'DB_SPIKE') ? 0.22 : 0;
  const privilegedWeight = hasSignal(signals, 'PRIVILEGED_MISUSE') ? 0.12 : 0;
  const packetWeight = hasSignal(signals, 'PACKET_ANOMALY') ? 0.14 : 0;
  const agentWeight = (packetSignal.score * 0.16) + (flowSignal.score * 0.24) + (behaviorSignal.score * 0.22);
  const temporalWeight = recentEscalations > 0 ? Math.min(0.14, recentEscalations * 0.025) : 0;
  const sustainedRiskWeight = previousRiskState.accumulatedRisk > 20 ? Math.min(0.12, previousRiskState.accumulatedRisk / 220) : 0;

  let score =
    beaconWeight +
    endpointWeight +
    tlsWeight +
    queryWeight +
    privilegedWeight +
    packetWeight +
    agentWeight +
    temporalWeight +
    sustainedRiskWeight;

  if ((log.isATMReconciliation || log.isMonthEndBatch) && uniqueSignalCount <= 2 && !hasSignal(signals, 'UNKNOWN_IP')) {
    score -= 0.18;
  }
  if (log.isSWIFTCommunication && log.destIP === '203.45.12.88' && uniqueSignalCount <= 2) {
    score -= 0.16;
  }
  if (uniqueSignalCount >= 3) {
    score += 0.14;
  } else if (uniqueSignalCount === 2) {
    score += 0.06;
  }

  const classification = classifyCorrelation(log, signals, packetSignal, flowSignal, behaviorSignal);
  if (classification === 'DATA_EXFILTRATION') {
    score += 0.08;
  } else if (classification === 'C2_BEACONING') {
    score += 0.05;
  }

  const finalScore = clamp(score, 0, 1);
  const confidence = clamp(0.4 + agentAgreement * 0.22 + uniqueSignalCount * 0.08 + temporalWeight + sustainedRiskWeight, 0.3, 0.98);
  const detected = finalScore >= 0.46 && (uniqueSignalCount >= 2 || previousRiskState.accumulatedRisk > 35);

  const reasoningParts: string[] = [];
  if (hasSignal(signals, 'DB_SPIKE')) {
    const dbSpike = signals.find(signal => signal.type === 'DB_SPIKE');
    reasoningParts.push(`query deviation ${dbSpike?.deviation.toFixed(2)}x baseline`);
  }
  if (hasSignal(signals, 'UNKNOWN_IP')) {
    const profile = baseline.destinationProfiles[log.destIP];
    reasoningParts.push(`destination ${log.destIP} has ${profile?.sightings ?? 0} prior sightings`);
  }
  if (hasSignal(signals, 'BEACONING')) {
    reasoningParts.push(`interval regularity suggests machine timing`);
  }
  if (recentEscalations > 0) {
    reasoningParts.push(`${recentEscalations} elevated observations persisted in the recent window`);
  }
  if ((log.isATMReconciliation || log.isMonthEndBatch) && uniqueSignalCount <= 2) {
    reasoningParts.push('banking context reduced confidence for otherwise expected batch behavior');
  } else if (uniqueSignalCount >= 2) {
    reasoningParts.push('multi-signal overlap increased correlation confidence');
  }

  return {
    agent: 'CORRELATION',
    signalType: detected ? 'CORRELATED_INTRUSION_PATTERN' : 'CORRELATION_NOMINAL',
    score: finalScore,
    confidence,
    detected,
    classification,
    correlatedSignals: detectedSignals.map(signal => signal.type),
    features: {
      uniqueSignalCount,
      agentAgreement,
      recentEscalations,
      previousRisk: previousRiskState.accumulatedRisk,
      externalFrequency: windowStats.externalIPFrequency,
    },
    reasoning: detected
      ? `CORRELATION AGENT: ${reasoningParts.join('; ')}. Classification=${classification}.`
      : `CORRELATION AGENT: Single-signal noise only; banking context and limited overlap keep confidence low.`,
  };
}
