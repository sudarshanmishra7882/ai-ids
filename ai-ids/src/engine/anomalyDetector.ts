// ============================================================
// ANOMALY DETECTION ENGINE — Statistical + ML-Inspired
// ============================================================

import { NetworkLog, Baseline, AnomalySignal, WindowStats } from '../types/ids';
import { computeDeviation } from './baselineEngine';

// ─── Thresholds ───────────────────────────────────────────────
const QUERY_SPIKE_THRESHOLD = 5.0;      // 5x baseline
const BEACONING_INTERVAL_THRESHOLD = 0.2; // entropy < 0.2 = beaconing
const BEACONING_STD_THRESHOLD = 150;    // std dev < 150ms = beaconing
const PACKET_SIZE_SPIKE = 3.0;          // 3x baseline packet size
const FLOW_DURATION_SPIKE = 4.0;        // 4x baseline flow duration

// ─── Signal Weight Definitions ────────────────────────────────
export const SIGNAL_WEIGHTS = {
  BEACONING: 30,
  DB_SPIKE: 40,
  UNKNOWN_IP: 30,
  PRIVILEGED_MISUSE: 20,
  TLS_ANOMALY: 25,
  PACKET_ANOMALY: 15,
};

// ─── Isolation Forest Score Simulation ───────────────────────
// Simulates the anomaly score of an Isolation Forest model.
// Features: query deviation, interval entropy, IP novelty, packet size
export function computeIsolationScore(
  log: NetworkLog,
  baseline: Baseline,
  windowStats: WindowStats
): number {
  const features = [
    // Query deviation (normalized 0–1)
    Math.min((log.queryFrequency / (baseline.avgQueryRate * QUERY_SPIKE_THRESHOLD)), 1.0),
    // Interval entropy inversion (low entropy = high score)
    1 - Math.min(windowStats.intervalEntropy, 1),
    // IP novelty
    baseline.knownIPs.includes(log.destIP) ? 0 : 0.8,
    // TLS fingerprint novelty
    baseline.knownTLSFingerprints.includes(log.tlsFingerprint) ? 0 : 0.7,
    // Packet size deviation
    Math.min(log.packetSize / (baseline.avgPacketSize * PACKET_SIZE_SPIKE), 1.0),
    // Flow duration deviation
    Math.min(log.flowDuration / (baseline.avgFlowDuration * FLOW_DURATION_SPIKE), 1.0),
    // External IP frequency (high = suspicious)
    Math.min(windowStats.externalIPFrequency * 2, 1.0),
    // Privileged user flag
    log.isPrivileged ? 0.6 : 0,
    // Off-hours flag
    !log.isBusinessHours ? 0.4 : 0,
  ];

  // Weighted average (simulating tree path length anomaly score)
  const weights = [0.25, 0.20, 0.15, 0.10, 0.08, 0.07, 0.07, 0.05, 0.03];
  const score = features.reduce((s, f, i) => s + f * weights[i], 0);
  return Math.min(score, 1.0);
}

// ─── Individual Signal Detectors ──────────────────────────────

/** Detect beaconing via interval entropy + standard deviation */
export function detectBeaconing(windowStats: WindowStats, window: NetworkLog[]): AnomalySignal {
  const intervals = window.map(l => l.connectionInterval);
  const stdDev = computeStdDev(intervals);
  const isBeaconing =
    windowStats.intervalEntropy < BEACONING_INTERVAL_THRESHOLD ||
    (stdDev < BEACONING_STD_THRESHOLD && window.length >= 3);

  return {
    type: 'BEACONING',
    weight: SIGNAL_WEIGHTS.BEACONING,
    detected: isBeaconing,
    value: windowStats.intervalEntropy,
    baseline: 0.6, // expected entropy for normal traffic
    deviation: isBeaconing ? (0.6 - windowStats.intervalEntropy) / 0.6 : 0,
    description: isBeaconing
      ? `Fixed-interval beaconing detected — entropy ${windowStats.intervalEntropy.toFixed(3)} (threshold: ${BEACONING_INTERVAL_THRESHOLD}), std dev: ${stdDev.toFixed(0)}ms`
      : `Traffic intervals appear organic (entropy: ${windowStats.intervalEntropy.toFixed(3)})`,
  };
}

/** Detect database query spikes */
export function detectDBSpike(log: NetworkLog, baseline: Baseline): AnomalySignal {
  const deviation = computeDeviation(log.queryFrequency, baseline.avgQueryRate);
  const detected = deviation >= QUERY_SPIKE_THRESHOLD;

  return {
    type: 'DB_SPIKE',
    weight: SIGNAL_WEIGHTS.DB_SPIKE,
    detected,
    value: log.queryFrequency,
    baseline: baseline.avgQueryRate,
    deviation,
    description: detected
      ? `DB query spike: ${log.queryFrequency}/min vs baseline ${baseline.avgQueryRate.toFixed(1)}/min (${deviation.toFixed(1)}x)`
      : `Query rate nominal: ${log.queryFrequency}/min (baseline: ${baseline.avgQueryRate.toFixed(1)}/min)`,
  };
}

/** Detect unknown external IP communication */
export function detectUnknownIP(log: NetworkLog, baseline: Baseline): AnomalySignal {
  const isUnknown = log.isExternalIP && !baseline.knownIPs.includes(log.destIP);

  return {
    type: 'UNKNOWN_IP',
    weight: SIGNAL_WEIGHTS.UNKNOWN_IP,
    detected: isUnknown,
    value: isUnknown ? 1 : 0,
    baseline: 0,
    deviation: isUnknown ? 1 : 0,
    description: isUnknown
      ? `Communication with unknown external IP: ${log.destIP} — not in approved list`
      : `Destination IP ${log.destIP} is within known safe list`,
  };
}

/** Detect privileged user anomalous activity */
export function detectPrivilegedMisuse(log: NetworkLog, windowStats: WindowStats): AnomalySignal {
  const detected =
    log.isPrivileged &&
    (log.queryFrequency > 20 || !log.isBusinessHours || windowStats.externalIPFrequency > 0.5);

  return {
    type: 'PRIVILEGED_MISUSE',
    weight: SIGNAL_WEIGHTS.PRIVILEGED_MISUSE,
    detected,
    value: log.isPrivileged ? log.queryFrequency : 0,
    baseline: 5,
    deviation: detected ? log.queryFrequency / 5 : 0,
    description: detected
      ? `Privileged user ${log.userId} exhibiting anomalous behavior — high query rate or off-hours access`
      : `Privileged user activity within normal parameters`,
  };
}

/** Detect TLS fingerprint anomalies (no decryption) */
export function detectTLSAnomaly(log: NetworkLog, baseline: Baseline): AnomalySignal {
  const isUnknownFingerprint = !baseline.knownTLSFingerprints.includes(log.tlsFingerprint);
  const isSmallPacket = log.packetSize < 150 && log.isExternalIP;
  const detected = isUnknownFingerprint || (isSmallPacket && log.isExternalIP);

  return {
    type: 'TLS_ANOMALY',
    weight: SIGNAL_WEIGHTS.TLS_ANOMALY,
    detected,
    value: log.packetSize,
    baseline: 650,
    deviation: isUnknownFingerprint ? 1 : 0,
    description: detected
      ? `TLS anomaly: ${isUnknownFingerprint ? `unknown JA3 fingerprint ${log.tlsFingerprint.slice(0, 8)}...` : `suspicious small encrypted packets (${log.packetSize}B)`}`
      : `TLS fingerprint recognized: ${log.tlsFingerprint.slice(0, 8)}...`,
  };
}

/** Detect packet size anomalies */
export function detectPacketAnomaly(log: NetworkLog, baseline: Baseline): AnomalySignal {
  const deviation = computeDeviation(log.packetSize, baseline.avgPacketSize);
  const detected = deviation >= PACKET_SIZE_SPIKE || (log.packetSize > 1400 && log.isExternalIP);

  return {
    type: 'PACKET_ANOMALY',
    weight: SIGNAL_WEIGHTS.PACKET_ANOMALY,
    detected,
    value: log.packetSize,
    baseline: baseline.avgPacketSize,
    deviation,
    description: detected
      ? `Large outbound packets detected: ${log.packetSize}B (baseline avg: ${baseline.avgPacketSize.toFixed(0)}B) — possible data exfiltration`
      : `Packet size within normal range: ${log.packetSize}B`,
  };
}

// ─── Helpers ──────────────────────────────────────────────────
function computeStdDev(values: number[]): number {
  if (values.length < 2) return 9999;
  const mean = values.reduce((s, v) => s + v, 0) / values.length;
  const variance = values.reduce((s, v) => s + Math.pow(v - mean, 2), 0) / values.length;
  return Math.sqrt(variance);
}

// ─── Run All Detectors ────────────────────────────────────────
export function runAllDetectors(
  log: NetworkLog,
  baseline: Baseline,
  windowStats: WindowStats,
  window: NetworkLog[]
): AnomalySignal[] {
  return [
    detectBeaconing(windowStats, window),
    detectDBSpike(log, baseline),
    detectUnknownIP(log, baseline),
    detectPrivilegedMisuse(log, windowStats),
    detectTLSAnomaly(log, baseline),
    detectPacketAnomaly(log, baseline),
  ];
}
