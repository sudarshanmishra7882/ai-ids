import { Baseline, NetworkLog, WindowStats } from '../types/ids';
import { getExpectedValues, getProfileLabel, inferBankingProfile } from './baselineEngine';
import { clamp, standardDeviation } from './statistics';

function normalizedDistance(value: number, center: number, history: number[]): number {
  const spread = Math.max(standardDeviation(history), Math.max(center * 0.15, 1));
  return Math.abs(value - center) / spread;
}

export function computeClusterOutlierScore(
  log: NetworkLog,
  baseline: Baseline,
  windowStats: WindowStats
): { score: number; nearestCluster: string } {
  const activeProfile = getExpectedValues(baseline, log);
  const profileDistances = Object.values(baseline.contextProfiles).map(profile => {
    const distance =
      normalizedDistance(log.queryFrequency, profile.avgQueryRate, profile.queryRateHistory) * 0.34 +
      normalizedDistance(log.connectionInterval, profile.avgInterval, profile.intervalHistory) * 0.2 +
      normalizedDistance(log.packetSize, profile.avgPacketSize, profile.packetSizeHistory) * 0.18 +
      normalizedDistance(log.flowDuration, profile.avgFlowDuration, profile.flowDurationHistory) * 0.14 +
      clamp(windowStats.externalIPFrequency - (profile.profileType === 'SWIFT' ? 0.6 : 0.2), 0, 1) * 0.14;

    return {
      label: profile.label,
      distance,
    };
  });

  profileDistances.sort((left, right) => left.distance - right.distance);
  const nearest = profileDistances[0] ?? { label: getProfileLabel(inferBankingProfile(log)), distance: 0 };

  const activeDistance =
    normalizedDistance(log.queryFrequency, activeProfile.avgQueryRate, activeProfile.queryRateHistory) * 0.35 +
    normalizedDistance(log.connectionInterval, activeProfile.avgInterval, activeProfile.intervalHistory) * 0.18 +
    normalizedDistance(log.packetSize, activeProfile.avgPacketSize, activeProfile.packetSizeHistory) * 0.17 +
    normalizedDistance(log.flowDuration, activeProfile.avgFlowDuration, activeProfile.flowDurationHistory) * 0.12 +
    clamp(windowStats.externalIPFrequency, 0, 1) * 0.08 +
    (log.isExternalIP ? 0.05 : 0) +
    (!log.isBusinessHours ? 0.05 : 0);

  const clusterScore = clamp(Math.max(activeDistance, nearest.distance) / 5.5, 0, 1);
  return {
    score: clusterScore,
    nearestCluster: nearest.label,
  };
}
