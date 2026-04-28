// ============================================================
// PACKET AGENT — Layer 3/4 Network Anomaly Detection
// Analyzes packet sizes, flow durations, protocol behavior
// ============================================================

import { NetworkLog, Baseline, WindowStats, AgentSignal } from '../../types/ids';

// ─── Z-Score Calculation ──────────────────────────────────────
function computeZScore(value: number, history: number[]): number {
  if (history.length < 3) return 0;
  const mean = history.reduce((s, v) => s + v, 0) / history.length;
  const variance = history.reduce((s, v) => s + Math.pow(v - mean, 2), 0) / history.length;
  const stdDev = Math.sqrt(variance);
  if (stdDev === 0) return 0;
  return (value - mean) / stdDev;
}

// ─── Percentile Calculation ───────────────────────────────────
function computePercentile(value: number, history: number[]): number {
  if (history.length < 2) return 0;
  const sorted = [...history].sort((a, b) => a - b);
  const count = sorted.filter(v => v <= value).length;
  return count / sorted.length;
}

// ─── Packet Size Anomaly Detection ────────────────────────────
function analyzePacketSize(log: NetworkLog, baseline: Baseline): { zScore: number; percentile: number; anomaly: boolean } {
  const zScore = computeZScore(log.packetSize, baseline.packetSizeHistory);
  const percentile = computePercentile(log.packetSize, baseline.packetSizeHistory);
  // Flag if z-score > 2.5 (99th percentile) or extremely large packets with external destination
  const anomaly = Math.abs(zScore) > 2.5 || (log.packetSize > 1400 && log.isExternalIP);
  return { zScore, percentile, anomaly };
}

// ─── Flow Duration Anomaly Detection ──────────────────────────
function analyzeFlowDuration(log: NetworkLog, baseline: Baseline): { zScore: number; anomaly: boolean } {
  const history = baseline.knownIPs.map(() => baseline.avgFlowDuration); // simplified
  const zScore = computeZScore(log.flowDuration, history);
  const anomaly = Math.abs(zScore) > 2.0 || log.flowDuration > 20000;
  return { zScore, anomaly };
}

// ─── Main Packet Agent Entry Point ────────────────────────────
export function runPacketAgent(
  log: NetworkLog,
  baseline: Baseline,
  _windowStats: WindowStats
): AgentSignal {
  const packetAnalysis = analyzePacketSize(log, baseline);
  const flowAnalysis = analyzeFlowDuration(log, baseline);

  // Combine signals with weights
  const packetScore = Math.min(Math.abs(packetAnalysis.zScore) / 3, 1); // normalize 0–1
  const flowScore = Math.min(Math.abs(flowAnalysis.zScore) / 3, 1);
  const externalBonus = log.isExternalIP && packetAnalysis.anomaly ? 0.3 : 0;
  const totalScore = Math.min(packetScore * 0.6 + flowScore * 0.4 + externalBonus, 1);

  const detected = totalScore > 0.65 || packetAnalysis.anomaly || flowAnalysis.anomaly;

  const reasoningParts: string[] = [];
  if (packetAnalysis.anomaly) {
    reasoningParts.push(
      `Packet size ${log.packetSize}B is ${Math.abs(packetAnalysis.zScore).toFixed(1)}σ from baseline mean ` +
      `(${baseline.avgPacketSize.toFixed(0)}B), placing it at the ${(packetAnalysis.percentile * 100).toFixed(0)}th percentile`
    );
  }
  if (flowAnalysis.anomaly) {
    reasoningParts.push(
      `Flow duration ${log.flowDuration}ms exceeds normal thresholds for ${log.isExternalIP ? 'external' : 'internal'} traffic`
    );
  }
  if (log.isExternalIP && log.packetSize > 1200) {
    reasoningParts.push(`Large outbound packets (${log.packetSize}B) to external IP — possible exfiltration`);
  }

  return {
    agent: 'PACKET',
    signalType: detected ? 'ANOMALOUS_PACKET_BEHAVIOR' : 'PACKETS_NOMINAL',
    score: totalScore,
    confidence: Math.min(0.5 + totalScore * 0.4 + (detected ? 0.1 : 0), 0.95),
    detected,
    features: {
      packetSizeZScore: packetAnalysis.zScore,
      packetSizePercentile: packetAnalysis.percentile,
      flowDurationZScore: flowAnalysis.zScore,
      isExternal: log.isExternalIP ? 1 : 0,
      packetSize: log.packetSize,
    },
    reasoning: detected
      ? `PACKET AGENT: ${reasoningParts.join('; ')}.`
      : `PACKET AGENT: Packet size (${log.packetSize}B) and flow duration (${log.flowDuration}ms) within statistical norms. No layer-3 anomalies.`,
  };
}
