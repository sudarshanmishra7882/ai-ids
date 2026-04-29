// ============================================================
// BASELINE ENGINE v3.0 — Behavioral Modeling with EMA & History
// Adds: Exponential moving averages, historical windows for z-score
// ============================================================

import { NetworkLog, Baseline, WindowStats } from '../types/ids';

const WINDOW_SIZE = 60; // seconds
const MIN_SAMPLES = 5;
const HISTORY_MAX = 50; // max history entries for z-score

// ─── Initial Baseline (pre-learned from historical data) ──────
export const INITIAL_BASELINE: Baseline = {
  avgQueryRate: 3.5,
  avgInterval: 2200,
  knownIPs: [
    '10.0.1.12', '10.0.1.45', '10.0.2.33', '10.0.2.78',
    '10.0.3.11', '10.0.3.99', '192.168.1.5', '192.168.1.23',
    '192.168.2.10', '192.168.2.67', '172.16.0.5', '172.16.0.88',
    '203.45.12.88', '185.23.44.7', '91.108.4.160', '142.250.9.100',
    '52.84.21.196', '104.18.0.15', '8.8.8.8', '1.1.1.1',
  ],
  avgPacketSize: 650,
  avgFlowDuration: 420,
  knownTLSFingerprints: [
    'e7d705a3286e19ea42f587b344ee6865',
    'a0e9f5d64349fb13191bc781f81f42e1',
    '4d7a28d6f2263ed61de88ca66eb011e3',
    'cd08e31494f9531f560d64c695473da9',
    '6bea3f23ab2fc77d8e8e2fe6f73c3f5a',
  ],
  samplesCollected: 120,
  // v3.0: EMA and history
  queryRateEMA: 3.5,
  packetSizeEMA: 650,
  intervalEMA: 2200,
  queryRateHistory: [3, 4, 3, 5, 4, 3, 4, 5, 3, 4],
  packetSizeHistory: [600, 700, 650, 620, 680, 700, 650, 600, 720, 650],
  intervalHistory: [2000, 2500, 2200, 2100, 2300, 2400, 2200, 2100, 2300, 2200],
};

// ─── Update Baseline with New Observation ─────────────────────
export function updateBaseline(current: Baseline, log: NetworkLog, isAttack: boolean): Baseline {
  if (isAttack || current.samplesCollected < MIN_SAMPLES) {
    return current;
  }

  const alpha = 0.05; // exponential moving average factor
  const newSamples = current.samplesCollected + 1;

  // Update EMAs
  const queryRateEMA = current.queryRateEMA * (1 - alpha) + log.queryFrequency * alpha;
  const packetSizeEMA = current.packetSizeEMA * (1 - alpha) + log.packetSize * alpha;
  const intervalEMA = current.intervalEMA * (1 - alpha) + log.connectionInterval * alpha;

  // Update histories (capped)
  const queryRateHistory = [...current.queryRateHistory, log.queryFrequency].slice(-HISTORY_MAX);
  const packetSizeHistory = [...current.packetSizeHistory, log.packetSize].slice(-HISTORY_MAX);
  const intervalHistory = [...current.intervalHistory, log.connectionInterval].slice(-HISTORY_MAX);

  return {
    avgQueryRate: current.avgQueryRate * (1 - alpha) + log.queryFrequency * alpha,
    avgInterval: current.avgInterval * (1 - alpha) + log.connectionInterval * alpha,
    avgPacketSize: current.avgPacketSize * (1 - alpha) + log.packetSize * alpha,
    avgFlowDuration: current.avgFlowDuration * (1 - alpha) + log.flowDuration * alpha,
    knownIPs: current.knownIPs.includes(log.destIP)
      ? current.knownIPs
      : [...current.knownIPs.slice(-50), log.destIP],
    knownTLSFingerprints: current.knownTLSFingerprints.includes(log.tlsFingerprint)
      ? current.knownTLSFingerprints
      : [...current.knownTLSFingerprints, log.tlsFingerprint],
    samplesCollected: newSamples,
    queryRateEMA,
    packetSizeEMA,
    intervalEMA,
    queryRateHistory,
    packetSizeHistory,
    intervalHistory,
  };
}

// ─── Compute Sliding Window Statistics ────────────────────────
export function computeWindowStats(window: NetworkLog[], nowMs: number): WindowStats {
  const cutoff = nowMs - WINDOW_SIZE * 1000;
  const recent = window.filter(l => l.timestamp >= cutoff);

  if (recent.length === 0) {
    return {
      avgQueryRate: 0,
      avgInterval: 2200,
      intervalEntropy: 1,
      externalIPFrequency: 0,
      uniqueExternalIPs: [],
      totalPackets: 0,
      timeSpan: 0,
      packetSizeStdDev: 0,
      flowDurationStdDev: 0,
      queryRateZScore: 0,
      packetSizeZScore: 0,
    };
  }

  const avgQueryRate = recent.reduce((s, l) => s + l.queryFrequency, 0) / recent.length;
  const intervals = recent.map(l => l.connectionInterval);
  const avgInterval = intervals.reduce((s, v) => s + v, 0) / intervals.length;
  const intervalEntropy = computeEntropy(intervals);

  const packetSizes = recent.map(l => l.packetSize);
  const packetSizeStdDev = computeStdDev(packetSizes);
  const flowDurations = recent.map(l => l.flowDuration);
  const flowDurationStdDev = computeStdDev(flowDurations);

  const externalLogs = recent.filter(l => l.isExternalIP);
  const uniqueExternalIPs = [...new Set(externalLogs.map(l => l.destIP))];

  const timeSpan = recent.length > 1
    ? recent[recent.length - 1].timestamp - recent[0].timestamp
    : 0;

  return {
    avgQueryRate,
    avgInterval,
    intervalEntropy,
    externalIPFrequency: externalLogs.length / recent.length,
    uniqueExternalIPs,
    totalPackets: recent.length,
    timeSpan,
    packetSizeStdDev,
    flowDurationStdDev,
    queryRateZScore: 0, // computed per-log
    packetSizeZScore: 0, // computed per-log
  };
}

// ─── Shannon Entropy Calculation ──────────────────────────────
function computeEntropy(values: number[]): number {
  if (values.length <= 1) return 1;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min;
  if (range < 100) return Math.max(0, range / 1000);
  const bins = 8;
  const buckets = new Array(bins).fill(0);
  values.forEach(v => {
    const idx = Math.min(Math.floor(((v - min) / range) * bins), bins - 1);
    buckets[idx]++;
  });
  const total = values.length;
  let entropy = 0;
  buckets.forEach(count => {
    if (count > 0) {
      const p = count / total;
      entropy -= p * Math.log2(p);
    }
  });
  return entropy / Math.log2(bins);
}

// ─── Compute Deviation Ratio ──────────────────────────────────
export function computeDeviation(current: number, baseline: number): number {
  if (baseline === 0) return current > 0 ? 10 : 0;
  return current / baseline;
}

// ─── Standard Deviation ───────────────────────────────────────
function computeStdDev(values: number[]): number {
  if (values.length < 2) return 0;
  const mean = values.reduce((s, v) => s + v, 0) / values.length;
  const variance = values.reduce((s, v) => s + Math.pow(v - mean, 2), 0) / values.length;
  return Math.sqrt(variance);
}
