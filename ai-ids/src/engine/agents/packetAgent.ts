import { AgentSignal, Baseline, NetworkLog, WindowStats } from '../../types/ids';
import { getExpectedValues } from '../baselineEngine';
import { clamp, percentile, safeRatio, zScore } from '../statistics';

export function runPacketAgent(
  log: NetworkLog,
  baseline: Baseline,
  _windowStats: WindowStats
): AgentSignal {
  const expected = getExpectedValues(baseline, log);
  const packetZ = zScore(log.packetSize, expected.packetSizeHistory);
  const flowZ = zScore(log.flowDuration, expected.flowDurationHistory);
  const packetPercentile = percentile(log.packetSize, expected.packetSizeHistory);
  const packetRatio = safeRatio(log.packetSize, expected.avgPacketSize);
  const flowRatio = safeRatio(log.flowDuration, expected.avgFlowDuration);

  let score =
    clamp(Math.abs(packetZ) / 4.2, 0, 1) * 0.42 +
    clamp(Math.abs(flowZ) / 4.0, 0, 1) * 0.28 +
    clamp((packetRatio - 1) / 1.4, 0, 1) * 0.18 +
    clamp((flowRatio - 1) / 2.2, 0, 1) * 0.12;

  if (log.isExternalIP && packetRatio > 1.7) {
    score = clamp(score + 0.14, 0, 1);
  }

  if ((log.isATMReconciliation || log.isMonthEndBatch) && !log.isExternalIP) {
    score *= 0.65;
  }

  const detected = score >= 0.58 || (log.isExternalIP && packetRatio > 1.8 && flowRatio > 2);
  const reasoningParts: string[] = [];

  if (Math.abs(packetZ) > 2) {
    reasoningParts.push(
      `packet size ${log.packetSize}B sits ${packetZ.toFixed(2)} sigma from the ${expected.label} baseline (${expected.avgPacketSize.toFixed(0)}B)`
    );
  }
  if (Math.abs(flowZ) > 2) {
    reasoningParts.push(
      `flow duration ${log.flowDuration}ms is ${flowZ.toFixed(2)} sigma from expected ${expected.avgFlowDuration.toFixed(0)}ms`
    );
  }
  if (log.isExternalIP && packetRatio > 1.7) {
    reasoningParts.push(`outbound packet volume is ${(packetRatio * 100).toFixed(0)}% of the normal profile and headed external`);
  }

  return {
    agent: 'PACKET',
    signalType: detected ? 'ANOMALOUS_PACKET_BEHAVIOR' : 'PACKETS_NOMINAL',
    score,
    confidence: clamp(0.46 + score * 0.44 + (detected ? 0.08 : 0), 0.25, 0.95),
    detected,
    features: {
      packetSizeZScore: packetZ,
      flowDurationZScore: flowZ,
      packetSizePercentile: packetPercentile,
      packetRatio,
      flowRatio,
      isExternal: log.isExternalIP ? 1 : 0,
    },
    correlatedSignals: detected ? ['PACKET_ANOMALY'] : [],
    reasoning: detected
      ? `PACKET AGENT: ${reasoningParts.join('; ')}.`
      : `PACKET AGENT: Packet size ${log.packetSize}B and flow duration ${log.flowDuration}ms remain within the ${expected.label} distribution.`,
  };
}
