// ============================================================
// FLOW AGENT — Connection Pattern & Network Flow Analysis
// Analyzes beaconing, entropy, external IP reputation, intervals
// ============================================================

import { NetworkLog, Baseline, WindowStats, AgentSignal } from '../../types/ids';

// ─── Entropy-Based Beaconing Detection ───────────────────────
function analyzeBeaconing(windowStats: WindowStats, window: NetworkLog[]): { isBeaconing: boolean; entropy: number; stdDev: number; confidence: number } {
  const intervals = window.map(l => l.connectionInterval);
  const stdDev = computeStdDev(intervals);
  const entropy = windowStats.intervalEntropy;
  // Refined beaconing: low entropy + low std dev + minimum sample size
  const isBeaconing = intervals.length >= 5 && entropy < 0.25 && stdDev < 200;
  const confidence = isBeaconing
    ? Math.min(0.95, 0.6 + (0.25 - entropy) * 2 + (200 - stdDev) / 400)
    : 0;
  return { isBeaconing, entropy, stdDev, confidence };
}

// ─── External IP Reputation Scoring ───────────────────────────
function analyzeExternalIP(log: NetworkLog, baseline: Baseline, windowStats: WindowStats): { score: number; isUnknown: boolean; reputation: number } {
  const isUnknown = log.isExternalIP && !baseline.knownIPs.includes(log.destIP);
  // Reputation scoring based on frequency in window
  const freq = windowStats.externalIPFrequency;
  const uniqueCount = windowStats.uniqueExternalIPs.length;
  // Higher score = more suspicious
  const reputation = isUnknown
    ? 0.3 + freq * 0.5 + Math.min(uniqueCount * 0.05, 0.3)
    : 0;
  return {
    score: reputation,
    isUnknown,
    reputation,
  };
}

// ─── TLS Fingerprint Anomaly (Flow-Layer) ─────────────────────
function analyzeTLS(log: NetworkLog, baseline: Baseline): { isUnknown: boolean; score: number } {
  const isUnknown = !baseline.knownTLSFingerprints.includes(log.tlsFingerprint);
  const score = isUnknown ? 0.7 : 0;
  return { isUnknown, score };
}

// ─── Main Flow Agent Entry Point ──────────────────────────────
export function runFlowAgent(
  log: NetworkLog,
  baseline: Baseline,
  windowStats: WindowStats,
  window: NetworkLog[]
): AgentSignal {
  const beaconing = analyzeBeaconing(windowStats, window);
  const external = analyzeExternalIP(log, baseline, windowStats);
  const tls = analyzeTLS(log, baseline);

  // Weighted fusion: beaconing 0.4, external IP 0.35, TLS 0.25
  const totalScore = Math.min(
    (beaconing.isBeaconing ? beaconing.confidence * 0.4 : 0) +
    external.score * 0.35 +
    tls.score * 0.25,
    1
  );

  const detected = totalScore > 0.5 || beaconing.isBeaconing || (external.isUnknown && external.score > 0.5);

  const reasoningParts: string[] = [];
  if (beaconing.isBeaconing) {
    reasoningParts.push(
      `Beaconing detected — interval entropy ${beaconing.entropy.toFixed(3)} ` +
      `(threshold <0.25), std dev ${beaconing.stdDev.toFixed(0)}ms. ` +
      `Machine-generated traffic pattern consistent with C2 heartbeat.`
    );
  }
  if (external.isUnknown) {
    reasoningParts.push(
      `Unknown external IP ${log.destIP} — not in approved baseline ` +
      `(${baseline.knownIPs.length} known IPs). External frequency in window: ${(windowStats.externalIPFrequency * 100).toFixed(0)}%.`
    );
  }
  if (tls.isUnknown) {
    reasoningParts.push(
      `Unknown JA3 TLS fingerprint ${log.tlsFingerprint.slice(0, 12)}… — ` +
      `not in baseline (${baseline.knownTLSFingerprints.length} known prints).`
    );
  }

  return {
    agent: 'FLOW',
    signalType: detected ? 'SUSPICIOUS_FLOW_PATTERN' : 'FLOW_NOMINAL',
    score: totalScore,
    confidence: Math.min(0.5 + totalScore * 0.4 + (detected ? 0.1 : 0), 0.95),
    detected,
    features: {
      intervalEntropy: beaconing.entropy,
      intervalStdDev: beaconing.stdDev,
      externalIPFrequency: windowStats.externalIPFrequency,
      isUnknownIP: external.isUnknown ? 1 : 0,
      unknownTLS: tls.isUnknown ? 1 : 0,
    },
    reasoning: detected
      ? `FLOW AGENT: ${reasoningParts.join('; ')}`
      : `FLOW AGENT: Connection patterns appear organic. Interval entropy ${beaconing.entropy.toFixed(3)} indicates human-driven traffic. No beaconing or unknown endpoints detected.`,
  };
}

// ─── Helpers ──────────────────────────────────────────────────
function computeStdDev(values: number[]): number {
  if (values.length < 2) return 9999;
  const mean = values.reduce((s, v) => s + v, 0) / values.length;
  const variance = values.reduce((s, v) => s + Math.pow(v - mean, 2), 0) / values.length;
  return Math.sqrt(variance);
}
