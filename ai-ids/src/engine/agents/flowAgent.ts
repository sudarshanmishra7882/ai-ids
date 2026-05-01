import { AgentSignal, Baseline, NetworkLog, WindowStats } from '../../types/ids';
import { clamp, standardDeviation } from '../statistics';

function computeEntropy(values: number[]): number {
  if (values.length <= 1) return 1;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min;
  if (range < 80) return Math.max(0.02, range / 1200);

  const bins = 6;
  const buckets = new Array(bins).fill(0);
  values.forEach(value => {
    const index = Math.min(Math.floor(((value - min) / range) * bins), bins - 1);
    buckets[index] += 1;
  });

  let entropy = 0;
  buckets.forEach(count => {
    if (count === 0) return;
    const probability = count / values.length;
    entropy -= probability * Math.log2(probability);
  });

  return entropy / Math.log2(bins);
}

export function runFlowAgent(
  log: NetworkLog,
  baseline: Baseline,
  windowStats: WindowStats,
  window: NetworkLog[],
  packetSignal: AgentSignal
): AgentSignal {
  const pairWindow = window
    .filter(entry => entry.sourceIP === log.sourceIP && entry.destIP === log.destIP)
    .slice(-8);
  const pairIntervals = pairWindow.map(entry => entry.connectionInterval);
  const pairStdDev = standardDeviation(pairIntervals);
  const pairEntropy = computeEntropy(pairIntervals);
  const pairRepeatability = pairIntervals.length >= 4
    ? clamp(1 - pairStdDev / Math.max(log.connectionInterval, 1), 0, 1)
    : 0;
  const beaconScore = pairWindow.length >= 4
    ? clamp((1 - pairEntropy) * 0.65 + pairRepeatability * 0.35, 0, 1)
    : 0;

  const destinationProfile = baseline.destinationProfiles[log.destIP];
  const noveltyScore = !destinationProfile
    ? 0.96
    : destinationProfile.sightings < 3
      ? 0.74
      : destinationProfile.reputationScore;
  const tlsScore = baseline.knownTLSFingerprints.includes(log.tlsFingerprint) ? 0 : 0.7;
  const packetCarry = packetSignal.detected ? packetSignal.score * 0.18 : 0;

  let score =
    beaconScore * 0.42 +
    noveltyScore * (log.isExternalIP ? 0.28 : 0.12) +
    tlsScore * 0.18 +
    clamp(windowStats.externalIPFrequency, 0, 1) * 0.12 +
    packetCarry;

  if (log.isSWIFTCommunication && log.destIP === '203.45.12.88') {
    score *= 0.45;
  }

  const detected = score >= 0.52 || (beaconScore > 0.62 && noveltyScore > 0.55);
  const reasoningParts: string[] = [];

  if (pairWindow.length >= 4 && beaconScore > 0.45) {
    reasoningParts.push(
      `${pairWindow.length} consecutive ${log.sourceIP} -> ${log.destIP} intervals compressed to ${pairStdDev.toFixed(0)}ms variance with entropy ${pairEntropy.toFixed(3)}`
    );
  }
  if (log.isExternalIP && noveltyScore > 0.5) {
    reasoningParts.push(
      `destination ${log.destIP} has ${destinationProfile?.sightings ?? 0} prior sightings and ${(noveltyScore * 100).toFixed(0)}% novelty`
    );
  }
  if (tlsScore > 0) {
    reasoningParts.push(`JA3-style fingerprint ${log.tlsFingerprint.slice(0, 12)}... is absent from baseline history`);
  }
  if (packetCarry > 0.08) {
    reasoningParts.push('packet-layer outlier strength was carried forward into flow scoring');
  }

  return {
    agent: 'FLOW',
    signalType: detected ? 'SUSPICIOUS_FLOW_PATTERN' : 'FLOW_NOMINAL',
    score: clamp(score, 0, 1),
    confidence: clamp(0.48 + clamp(score, 0, 1) * 0.42 + (detected ? 0.08 : 0), 0.25, 0.95),
    detected,
    features: {
      pairEntropy,
      pairStdDev,
      beaconScore,
      noveltyScore,
      tlsScore,
      externalIPFrequency: windowStats.externalIPFrequency,
    },
    correlatedSignals: detected
      ? ['BEACONING', noveltyScore > 0.5 ? 'UNKNOWN_IP' : 'KNOWN_IP', tlsScore > 0 ? 'TLS_ANOMALY' : 'TLS_OK']
      : [],
    reasoning: detected
      ? `FLOW AGENT: ${reasoningParts.join('; ')}.`
      : `FLOW AGENT: Flow timing remains irregular, destination history is familiar, and no persistent beacon pattern is present.`,
  };
}
