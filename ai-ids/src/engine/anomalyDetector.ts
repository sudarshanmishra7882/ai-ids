import { AnomalySignal, Baseline, NetworkLog, WindowStats } from '../types/ids';
import { getExpectedValues, inferBankingProfile } from './baselineEngine';
import { clamp, percentageDelta, safeRatio, standardDeviation, zScore } from './statistics';

const SIGNAL_WEIGHTS = {
  BEACONING: 24,
  DB_SPIKE: 28,
  UNKNOWN_IP: 20,
  PRIVILEGED_MISUSE: 14,
  TLS_ANOMALY: 16,
  PACKET_ANOMALY: 18,
} as const;

export { SIGNAL_WEIGHTS };

export function computeIsolationScore(
  log: NetworkLog,
  baseline: Baseline,
  windowStats: WindowStats
): number {
  const expected = getExpectedValues(baseline, log);
  const queryZ = Math.abs(zScore(log.queryFrequency, expected.queryRateHistory));
  const packetZ = Math.abs(zScore(log.packetSize, expected.packetSizeHistory));
  const flowZ = Math.abs(zScore(log.flowDuration, expected.flowDurationHistory));
  const intervalZ = Math.abs(zScore(log.connectionInterval, expected.intervalHistory));
  const destinationProfile = baseline.destinationProfiles[log.destIP];
  const noveltyScore = !destinationProfile
    ? 0.95
    : destinationProfile.sightings < 3
      ? 0.65
      : destinationProfile.reputationScore;
  const unknownTls = baseline.knownTLSFingerprints.includes(log.tlsFingerprint) ? 0 : 0.72;
  const contextPenalty = inferBankingProfile(log) === 'DEFAULT' ? 0 : 0.12;
  const signatureScore = log.signatureTag ? 0.85 : 0;

  const features = [
    clamp(queryZ / 4.5, 0, 1),
    clamp(packetZ / 4.0, 0, 1),
    clamp(flowZ / 4.0, 0, 1),
    clamp(intervalZ / 4.0, 0, 1),
    clamp(1 - windowStats.intervalEntropy, 0, 1),
    noveltyScore,
    unknownTls,
    clamp(windowStats.externalIPFrequency * 1.25, 0, 1),
    log.isPrivileged ? 0.35 : 0,
    log.isBusinessHours ? 0 : 0.18,
    contextPenalty,
    signatureScore,
  ];

  const weights = [0.16, 0.1, 0.08, 0.08, 0.12, 0.12, 0.08, 0.08, 0.05, 0.04, -0.06, 0.15];
  const score = features.reduce((sum, feature, index) => sum + feature * weights[index], 0);
  return clamp(score, 0, 1);
}

export function detectBeaconing(windowStats: WindowStats, window: NetworkLog[], log: NetworkLog): AnomalySignal {
  const pairWindow = window
    .filter(entry => entry.sourceIP === log.sourceIP && entry.destIP === log.destIP)
    .slice(-8);
  const intervals = pairWindow.map(entry => entry.connectionInterval);
  const stdDev = standardDeviation(intervals);
  const intervalMean = intervals.length > 0 ? intervals.reduce((sum, value) => sum + value, 0) / intervals.length : log.connectionInterval;
  const repeatability = intervalMean > 0 ? stdDev / intervalMean : 1;
  const detected = pairWindow.length >= 4 && repeatability < 0.12 && windowStats.intervalEntropy < 0.32;
  const baselineEntropy = 0.65;
  const deviation = detected ? safeRatio(baselineEntropy - windowStats.intervalEntropy, baselineEntropy) : 0;

  return {
    type: 'BEACONING',
    weight: SIGNAL_WEIGHTS.BEACONING,
    detected,
    value: windowStats.intervalEntropy,
    baseline: baselineEntropy,
    deviation,
    description: detected
      ? `Connection interval entropy collapsed to ${windowStats.intervalEntropy.toFixed(3)} with ${stdDev.toFixed(0)}ms pair variance across ${pairWindow.length} repeats, consistent with beacon timing.`
      : `Connection intervals remain irregular enough to resemble user-driven traffic (entropy ${windowStats.intervalEntropy.toFixed(3)}).`,
  };
}

export function detectDBSpike(log: NetworkLog, baseline: Baseline): AnomalySignal {
  const expected = getExpectedValues(baseline, log);
  const queryZ = zScore(log.queryFrequency, expected.queryRateHistory);
  const deviation = safeRatio(log.queryFrequency, expected.avgQueryRate);
  const detected = queryZ > 2.8 || deviation > 3.2;
  const delta = percentageDelta(log.queryFrequency, expected.avgQueryRate);

  return {
    type: 'DB_SPIKE',
    weight: SIGNAL_WEIGHTS.DB_SPIKE,
    detected,
    value: log.queryFrequency,
    baseline: expected.avgQueryRate,
    deviation,
    description: detected
      ? `Query rate exceeded the ${expected.label} baseline by ${delta.toFixed(0)}% (${log.queryFrequency}/min vs ${expected.avgQueryRate.toFixed(1)}/min, z=${queryZ.toFixed(2)}).`
      : `Query rate ${log.queryFrequency}/min remains within the ${expected.label} baseline (${expected.avgQueryRate.toFixed(1)}/min).`,
  };
}

export function detectUnknownIP(log: NetworkLog, baseline: Baseline): AnomalySignal {
  const destinationProfile = baseline.destinationProfiles[log.destIP];
  const noveltyScore = !destinationProfile
    ? 1
    : destinationProfile.sightings < 3
      ? 0.72
      : destinationProfile.reputationScore;
  const detected = log.isExternalIP && noveltyScore >= 0.55;
  const priorSightings = destinationProfile?.sightings ?? 0;

  return {
    type: 'UNKNOWN_IP',
    weight: SIGNAL_WEIGHTS.UNKNOWN_IP,
    detected,
    value: noveltyScore,
    baseline: 0.12,
    deviation: noveltyScore,
    description: detected
      ? `External destination ${log.destIP} has ${priorSightings} prior baseline sightings and a novelty score of ${(noveltyScore * 100).toFixed(0)}%.`
      : `Destination ${log.destIP} aligns with established communication history.`,
  };
}

export function detectPrivilegedMisuse(log: NetworkLog, baseline: Baseline): AnomalySignal {
  const expected = getExpectedValues(baseline, log);
  const contextualAdminWindow = log.isATMReconciliation || log.isMonthEndBatch;
  const queryDeviation = safeRatio(log.queryFrequency, expected.avgQueryRate);
  const suspiciousOffHours = log.isPrivileged && !log.isBusinessHours && !contextualAdminWindow;
  const burstAdmin = log.isPrivileged && queryDeviation > 1.9 && log.sessionDuration < 180;
  const externalPrivileged = log.isPrivileged && log.isExternalIP && !log.isSWIFTCommunication;
  const detected = suspiciousOffHours || burstAdmin || externalPrivileged;
  const severity = clamp((suspiciousOffHours ? 0.45 : 0) + (burstAdmin ? 0.35 : 0) + (externalPrivileged ? 0.3 : 0), 0, 1);

  return {
    type: 'PRIVILEGED_MISUSE',
    weight: SIGNAL_WEIGHTS.PRIVILEGED_MISUSE,
    detected,
    value: severity,
    baseline: 0.2,
    deviation: severity,
    description: detected
      ? `Privileged account ${log.userId} deviated from context norms via ${suspiciousOffHours ? 'off-hours access' : 'compressed session behavior'}${externalPrivileged ? ' and external communication' : ''}.`
      : `Privileged access pattern is consistent with the active banking context.`,
  };
}

export function detectTLSAnomaly(log: NetworkLog, baseline: Baseline): AnomalySignal {
  const destinationProfile = baseline.destinationProfiles[log.destIP];
  const unseenFingerprint = !baseline.knownTLSFingerprints.includes(log.tlsFingerprint);
  const rareDestination = !destinationProfile || destinationProfile.sightings < 3;
  const detected = unseenFingerprint && (log.isExternalIP || rareDestination);

  return {
    type: 'TLS_ANOMALY',
    weight: SIGNAL_WEIGHTS.TLS_ANOMALY,
    detected,
    value: unseenFingerprint ? 1 : 0,
    baseline: 0,
    deviation: unseenFingerprint ? 1 : 0,
    description: detected
      ? `Observed unseen JA3-style fingerprint ${log.tlsFingerprint.slice(0, 12)}... on ${log.destIP}, with no matching baseline history${log.signatureTag ? ` and Suricata/Zeek signature hit ${log.signatureTag}` : ''}.`
      : `TLS fingerprint ${log.tlsFingerprint.slice(0, 12)}... matches previously observed traffic.`,
  };
}

export function detectPacketAnomaly(log: NetworkLog, baseline: Baseline): AnomalySignal {
  const expected = getExpectedValues(baseline, log);
  const packetZ = Math.abs(zScore(log.packetSize, expected.packetSizeHistory));
  const flowZ = Math.abs(zScore(log.flowDuration, expected.flowDurationHistory));
  const ratio = safeRatio(log.packetSize, expected.avgPacketSize);
  const detected = packetZ > 2.6 || flowZ > 2.6 || (log.isExternalIP && ratio > 1.8);

  return {
    type: 'PACKET_ANOMALY',
    weight: SIGNAL_WEIGHTS.PACKET_ANOMALY,
    detected,
    value: log.packetSize,
    baseline: expected.avgPacketSize,
    deviation: ratio,
    description: detected
      ? `Packet volume ${log.packetSize}B and flow duration ${log.flowDuration}ms sit ${packetZ.toFixed(2)} sigma / ${flowZ.toFixed(2)} sigma away from the ${expected.label} baseline.`
      : `Packet size and flow duration remain within expected ${expected.label} ranges.`,
  };
}

export function runAllDetectors(
  log: NetworkLog,
  baseline: Baseline,
  windowStats: WindowStats,
  window: NetworkLog[]
): AnomalySignal[] {
  return [
    detectBeaconing(windowStats, window, log),
    detectDBSpike(log, baseline),
    detectUnknownIP(log, baseline),
    detectPrivilegedMisuse(log, baseline),
    detectTLSAnomaly(log, baseline),
    detectPacketAnomaly(log, baseline),
  ];
}
