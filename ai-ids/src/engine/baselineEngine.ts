import {
  Baseline,
  BankingProfileType,
  ContextBaseline,
  DestinationProfile,
  NetworkLog,
  WindowStats,
} from '../types/ids';
import { ema, mean, safeRatio, standardDeviation, zScore } from './statistics';

const WINDOW_SIZE_SECONDS = 60;
const MIN_SAMPLES = 8;
const HISTORY_MAX = 72;
const ALPHA = 0.05;

function createContextBaseline(
  profileType: BankingProfileType,
  label: string,
  seeds: {
    avgQueryRate: number;
    avgInterval: number;
    avgPacketSize: number;
    avgFlowDuration: number;
    queryHistory: number[];
    packetHistory: number[];
    intervalHistory: number[];
    flowHistory: number[];
  }
): ContextBaseline {
  return {
    label,
    profileType,
    avgQueryRate: seeds.avgQueryRate,
    avgInterval: seeds.avgInterval,
    avgPacketSize: seeds.avgPacketSize,
    avgFlowDuration: seeds.avgFlowDuration,
    queryRateEMA: seeds.avgQueryRate,
    packetSizeEMA: seeds.avgPacketSize,
    intervalEMA: seeds.avgInterval,
    flowDurationEMA: seeds.avgFlowDuration,
    queryRateHistory: seeds.queryHistory,
    packetSizeHistory: seeds.packetHistory,
    intervalHistory: seeds.intervalHistory,
    flowDurationHistory: seeds.flowHistory,
  };
}

function trustedDestinationProfile(profileType: BankingProfileType): DestinationProfile {
  return {
    firstSeen: Date.now() - 86_400_000,
    lastSeen: Date.now(),
    sightings: 50,
    reputationScore: 0.08,
    contexts: [profileType],
  };
}

export const INITIAL_BASELINE: Baseline = {
  avgQueryRate: 4.2,
  avgInterval: 2300,
  knownIPs: [
    '10.0.1.12',
    '10.0.1.45',
    '10.0.2.33',
    '10.0.2.78',
    '10.0.3.11',
    '10.0.3.99',
    '192.168.1.5',
    '192.168.1.23',
    '192.168.2.10',
    '192.168.2.67',
    '172.16.0.5',
    '172.16.0.88',
    '10.50.0.14',
    '10.50.0.21',
    '203.45.12.88',
    '185.23.44.7',
    '91.108.4.160',
    '142.250.9.100',
    '52.84.21.196',
    '104.18.0.15',
    '8.8.8.8',
    '1.1.1.1',
  ],
  avgPacketSize: 680,
  avgFlowDuration: 460,
  knownTLSFingerprints: [
    'e7d705a3286e19ea42f587b344ee6865',
    'a0e9f5d64349fb13191bc781f81f42e1',
    '4d7a28d6f2263ed61de88ca66eb011e3',
    'cd08e31494f9531f560d64c695473da9',
    '6bea3f23ab2fc77d8e8e2fe6f73c3f5a',
  ],
  samplesCollected: 180,
  queryRateEMA: 4.2,
  packetSizeEMA: 680,
  intervalEMA: 2300,
  flowDurationEMA: 460,
  queryRateHistory: [3, 4, 5, 4, 4, 6, 3, 5, 4, 4, 5, 3],
  packetSizeHistory: [610, 640, 690, 720, 650, 700, 740, 620, 660, 710, 680, 690],
  intervalHistory: [1900, 2200, 2100, 2600, 2400, 2000, 2500, 2300, 2700, 2100, 2250, 2350],
  flowDurationHistory: [280, 320, 410, 500, 560, 420, 470, 610, 380, 450, 520, 430],
  contextProfiles: {
    DEFAULT: createContextBaseline('DEFAULT', 'Retail / Office Traffic', {
      avgQueryRate: 4.2,
      avgInterval: 2300,
      avgPacketSize: 680,
      avgFlowDuration: 460,
      queryHistory: [3, 4, 5, 4, 4, 6, 3, 5, 4, 4, 5, 3],
      packetHistory: [610, 640, 690, 720, 650, 700, 740, 620, 660, 710, 680, 690],
      intervalHistory: [1900, 2200, 2100, 2600, 2400, 2000, 2500, 2300, 2700, 2100, 2250, 2350],
      flowHistory: [280, 320, 410, 500, 560, 420, 470, 610, 380, 450, 520, 430],
    }),
    ATM: createContextBaseline('ATM', 'ATM Reconciliation Window', {
      avgQueryRate: 215,
      avgInterval: 3800,
      avgPacketSize: 910,
      avgFlowDuration: 900,
      queryHistory: [180, 195, 205, 220, 230, 245, 210, 225, 240, 235, 215, 205],
      packetHistory: [820, 860, 910, 940, 980, 890, 870, 915, 950, 930, 885, 900],
      intervalHistory: [3200, 3400, 3600, 4100, 3900, 4300, 3500, 3700, 4000, 4200, 3550, 3650],
      flowHistory: [700, 760, 810, 950, 880, 920, 980, 845, 890, 970, 860, 910],
    }),
    SWIFT: createContextBaseline('SWIFT', 'SWIFT Gateway Traffic', {
      avgQueryRate: 2.2,
      avgInterval: 65_000,
      avgPacketSize: 620,
      avgFlowDuration: 950,
      queryHistory: [1, 2, 2, 3, 1, 2, 2, 1, 3, 2, 2, 1],
      packetHistory: [510, 560, 600, 640, 680, 610, 590, 630, 660, 620, 605, 615],
      intervalHistory: [48_000, 52_000, 61_000, 73_000, 69_000, 75_000, 58_000, 66_000, 71_000, 63_000, 59_000, 68_000],
      flowHistory: [760, 820, 880, 960, 1020, 980, 910, 995, 1040, 935, 870, 920],
    }),
    BATCH: createContextBaseline('BATCH', 'Month-End Batch Processing', {
      avgQueryRate: 470,
      avgInterval: 5200,
      avgPacketSize: 980,
      avgFlowDuration: 1400,
      queryHistory: [390, 410, 450, 480, 520, 540, 500, 470, 490, 510, 530, 460],
      packetHistory: [860, 900, 940, 990, 1010, 1030, 960, 980, 1005, 1040, 970, 995],
      intervalHistory: [4400, 4700, 4900, 5300, 5600, 5900, 5100, 5250, 5450, 5750, 5050, 5200],
      flowHistory: [1080, 1150, 1210, 1380, 1450, 1520, 1340, 1410, 1490, 1360, 1430, 1470],
    }),
  },
  destinationProfiles: {
    '10.0.3.99': trustedDestinationProfile('DEFAULT'),
    '10.50.0.14': trustedDestinationProfile('DEFAULT'),
    '10.50.0.21': trustedDestinationProfile('DEFAULT'),
    '203.45.12.88': trustedDestinationProfile('SWIFT'),
    '185.23.44.7': trustedDestinationProfile('DEFAULT'),
    '91.108.4.160': trustedDestinationProfile('DEFAULT'),
    '142.250.9.100': trustedDestinationProfile('DEFAULT'),
    '52.84.21.196': trustedDestinationProfile('DEFAULT'),
    '104.18.0.15': trustedDestinationProfile('DEFAULT'),
    '8.8.8.8': trustedDestinationProfile('DEFAULT'),
    '1.1.1.1': trustedDestinationProfile('DEFAULT'),
  },
};

export function inferBankingProfile(log: NetworkLog): BankingProfileType {
  if (log.isMonthEndBatch) return 'BATCH';
  if (log.isATMReconciliation) return 'ATM';
  if (log.isSWIFTCommunication) return 'SWIFT';
  return 'DEFAULT';
}

export function getProfileLabel(profile: BankingProfileType): string {
  return INITIAL_BASELINE.contextProfiles[profile].label;
}

export function getBaselineProfile(baseline: Baseline, log: NetworkLog): ContextBaseline {
  return baseline.contextProfiles[inferBankingProfile(log)];
}

export function getExpectedValues(
  baseline: Baseline,
  log: NetworkLog
): Pick<
  ContextBaseline,
  | 'avgQueryRate'
  | 'avgInterval'
  | 'avgPacketSize'
  | 'avgFlowDuration'
  | 'queryRateHistory'
  | 'packetSizeHistory'
  | 'intervalHistory'
  | 'flowDurationHistory'
  | 'label'
  | 'profileType'
> {
  const profile = getBaselineProfile(baseline, log);
  return {
    avgQueryRate: profile.avgQueryRate,
    avgInterval: profile.avgInterval,
    avgPacketSize: profile.avgPacketSize,
    avgFlowDuration: profile.avgFlowDuration,
    queryRateHistory: profile.queryRateHistory,
    packetSizeHistory: profile.packetSizeHistory,
    intervalHistory: profile.intervalHistory,
    flowDurationHistory: profile.flowDurationHistory,
    label: profile.label,
    profileType: profile.profileType,
  };
}

function updateContextProfile(profile: ContextBaseline, log: NetworkLog): ContextBaseline {
  return {
    ...profile,
    avgQueryRate: ema(profile.avgQueryRate, log.queryFrequency, ALPHA),
    avgInterval: ema(profile.avgInterval, log.connectionInterval, ALPHA),
    avgPacketSize: ema(profile.avgPacketSize, log.packetSize, ALPHA),
    avgFlowDuration: ema(profile.avgFlowDuration, log.flowDuration, ALPHA),
    queryRateEMA: ema(profile.queryRateEMA, log.queryFrequency, ALPHA),
    packetSizeEMA: ema(profile.packetSizeEMA, log.packetSize, ALPHA),
    intervalEMA: ema(profile.intervalEMA, log.connectionInterval, ALPHA),
    flowDurationEMA: ema(profile.flowDurationEMA, log.flowDuration, ALPHA),
    queryRateHistory: [...profile.queryRateHistory, log.queryFrequency].slice(-HISTORY_MAX),
    packetSizeHistory: [...profile.packetSizeHistory, log.packetSize].slice(-HISTORY_MAX),
    intervalHistory: [...profile.intervalHistory, log.connectionInterval].slice(-HISTORY_MAX),
    flowDurationHistory: [...profile.flowDurationHistory, log.flowDuration].slice(-HISTORY_MAX),
  };
}

function updateDestinationProfiles(baseline: Baseline, log: NetworkLog, profileType: BankingProfileType): Record<string, DestinationProfile> {
  const current = baseline.destinationProfiles[log.destIP];
  const updatedContexts = current?.contexts.includes(profileType)
    ? current.contexts
    : [...(current?.contexts ?? []), profileType];

  return {
    ...baseline.destinationProfiles,
    [log.destIP]: {
      firstSeen: current?.firstSeen ?? log.timestamp,
      lastSeen: log.timestamp,
      sightings: (current?.sightings ?? 0) + 1,
      reputationScore: current
        ? Math.max(0.02, current.reputationScore * 0.92)
        : log.isExternalIP
          ? 0.28
          : 0.12,
      contexts: updatedContexts,
    },
  };
}

export function updateBaseline(current: Baseline, log: NetworkLog, isAttack: boolean): Baseline {
  if (isAttack || current.samplesCollected < MIN_SAMPLES) {
    return current;
  }

  const profileType = inferBankingProfile(log);
  const updatedProfile = updateContextProfile(current.contextProfiles[profileType], log);

  return {
    ...current,
    avgQueryRate: ema(current.avgQueryRate, log.queryFrequency, ALPHA),
    avgInterval: ema(current.avgInterval, log.connectionInterval, ALPHA),
    avgPacketSize: ema(current.avgPacketSize, log.packetSize, ALPHA),
    avgFlowDuration: ema(current.avgFlowDuration, log.flowDuration, ALPHA),
    queryRateEMA: ema(current.queryRateEMA, log.queryFrequency, ALPHA),
    packetSizeEMA: ema(current.packetSizeEMA, log.packetSize, ALPHA),
    intervalEMA: ema(current.intervalEMA, log.connectionInterval, ALPHA),
    flowDurationEMA: ema(current.flowDurationEMA, log.flowDuration, ALPHA),
    queryRateHistory: [...current.queryRateHistory, log.queryFrequency].slice(-HISTORY_MAX),
    packetSizeHistory: [...current.packetSizeHistory, log.packetSize].slice(-HISTORY_MAX),
    intervalHistory: [...current.intervalHistory, log.connectionInterval].slice(-HISTORY_MAX),
    flowDurationHistory: [...current.flowDurationHistory, log.flowDuration].slice(-HISTORY_MAX),
    knownIPs: current.knownIPs.includes(log.destIP)
      ? current.knownIPs
      : [...current.knownIPs.slice(-80), log.destIP],
    knownTLSFingerprints: current.knownTLSFingerprints.includes(log.tlsFingerprint)
      ? current.knownTLSFingerprints
      : [...current.knownTLSFingerprints.slice(-20), log.tlsFingerprint],
    samplesCollected: current.samplesCollected + 1,
    contextProfiles: {
      ...current.contextProfiles,
      [profileType]: updatedProfile,
    },
    destinationProfiles: updateDestinationProfiles(current, log, profileType),
  };
}

export function computeWindowStats(window: NetworkLog[], nowMs: number): WindowStats {
  const cutoff = nowMs - WINDOW_SIZE_SECONDS * 1000;
  const recent = window.filter(entry => entry.timestamp >= cutoff);

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
      queryRateStdDev: 0,
      queryRateZScore: 0,
      packetSizeZScore: 0,
    };
  }

  const queryRates = recent.map(entry => entry.queryFrequency);
  const intervals = recent.map(entry => entry.connectionInterval);
  const packetSizes = recent.map(entry => entry.packetSize);
  const flowDurations = recent.map(entry => entry.flowDuration);
  const externalLogs = recent.filter(entry => entry.isExternalIP);
  const uniqueExternalIPs = [...new Set(externalLogs.map(entry => entry.destIP))];

  return {
    avgQueryRate: mean(queryRates),
    avgInterval: mean(intervals),
    intervalEntropy: computeEntropy(intervals),
    externalIPFrequency: safeRatio(externalLogs.length, recent.length),
    uniqueExternalIPs,
    totalPackets: recent.length,
    timeSpan: recent.length > 1 ? recent[recent.length - 1].timestamp - recent[0].timestamp : 0,
    packetSizeStdDev: standardDeviation(packetSizes),
    flowDurationStdDev: standardDeviation(flowDurations),
    queryRateStdDev: standardDeviation(queryRates),
    queryRateZScore: zScore(queryRates[queryRates.length - 1], queryRates.slice(0, -1)),
    packetSizeZScore: zScore(packetSizes[packetSizes.length - 1], packetSizes.slice(0, -1)),
  };
}

function computeEntropy(values: number[]): number {
  if (values.length <= 1) return 1;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min;

  if (range < 100) {
    return Math.max(0.02, range / 1200);
  }

  const bins = 8;
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
