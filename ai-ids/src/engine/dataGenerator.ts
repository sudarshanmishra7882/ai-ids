import { AttackPhase, NetworkLog, NetworkSegment, SystemMode, TelemetrySource } from '../types/ids';

export interface SimulationContext {
  mode: SystemMode;
  attackPhase: AttackPhase;
  phaseTick: number;
  totalTick: number;
}

const INTERNAL_IPS = [
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
];

const USER_WORKSTATIONS = ['10.0.1.12', '10.0.1.45', '10.0.2.33', '10.0.2.78'];
const DATABASE_HOSTS = ['10.0.3.99', '10.0.3.11'];
const NRB_ENDPOINTS = ['10.50.0.14', '10.50.0.21'];
const KNOWN_EXTERNAL_IPS = ['203.45.12.88', '185.23.44.7', '91.108.4.160', '142.250.9.100', '52.84.21.196', '104.18.0.15', '8.8.8.8', '1.1.1.1'];
const SUSPICIOUS_EXTERNAL_IPS = ['45.33.32.156', '185.220.101.1', '94.102.49.190', '23.129.64.131', '176.10.104.240', '199.87.154.255', '91.92.109.198'];
const EASTERN_EUROPE_IPS = ['185.220.101.1', '94.102.49.190', '91.92.109.198'];

const KNOWN_TLS = [
  'e7d705a3286e19ea42f587b344ee6865',
  'a0e9f5d64349fb13191bc781f81f42e1',
  '4d7a28d6f2263ed61de88ca66eb011e3',
  'cd08e31494f9531f560d64c695473da9',
  '6bea3f23ab2fc77d8e8e2fe6f73c3f5a',
];

const SUSPICIOUS_TLS = [
  'aaaa1234bbbb5678cccc9012dddd3456',
  'deadbeef12345678abcdef9876543210',
  '00112233445566778899aabbccddeeff',
];

const NORMAL_USERS = ['usr_alice', 'usr_bob', 'usr_carol', 'usr_dave', 'usr_eve'];
const PRIVILEGED_USERS = ['adm_root', 'adm_sysops', 'adm_dba'];
const PHASE_SPANS: Record<AttackPhase, number> = { 0: 1, 1: 8, 2: 10, 3: 10, 4: 9, 5: 8 };

let logCounter = 0;

function createSeededRng(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0;
    return state / 4294967296;
  };
}

function randomFrom<T>(items: T[], rng: () => number): T {
  return items[Math.floor(rng() * items.length)];
}

function randomBetween(min: number, max: number, rng: () => number): number {
  return min + (max - min) * rng();
}

function jitter(value: number, percentage: number, rng: () => number): number {
  const delta = value * percentage;
  return value + randomBetween(-delta, delta, rng);
}

function blend(start: number, end: number, progress: number): number {
  return start + (end - start) * progress;
}

function isBusinessHours(timestamp: number): boolean {
  const hour = new Date(timestamp).getHours();
  return hour >= 8 && hour < 18;
}

function inferNetworkSegment(sourceIP: string, context: { isATMReconciliation: boolean; isSWIFTCommunication: boolean; isMonthEndBatch: boolean }): NetworkSegment {
  if (context.isSWIFTCommunication || sourceIP.startsWith('172.16.')) return 'SWIFT_SUBNET';
  if (context.isATMReconciliation || sourceIP === '10.0.2.78') return 'ATM_SWITCH';
  if (context.isMonthEndBatch || DATABASE_HOSTS.includes(sourceIP)) return 'CORE_BANKING_PUMORI';
  return 'USER_LAN';
}

function inferApplicationLabel(segment: NetworkSegment): string {
  switch (segment) {
    case 'SWIFT_SUBNET':
      return 'SWIFT Messaging Gateway';
    case 'ATM_SWITCH':
      return 'ATM Reconciliation Switch';
    case 'CORE_BANKING_PUMORI':
      return 'Pumori+ Core Banking';
    case 'NRB_REGULATORY':
      return 'NRB Regulatory Link';
    default:
      return 'User Workstation Network';
  }
}

function buildTelemetrySources(segment: NetworkSegment, isPrivileged: boolean, isExternal: boolean): TelemetrySource[] {
  const sources: TelemetrySource[] = ['NetFlow/IPFIX', 'Zeek'];
  if (isExternal) {
    sources.push('Suricata');
  }
  if (isPrivileged) {
    sources.push('Windows Event Log');
  }
  if (segment === 'SWIFT_SUBNET') {
    sources.push('SWIFT Message Log');
  }
  if (segment === 'ATM_SWITCH') {
    sources.push('ATM Network Traffic');
  }
  sources.push('Syslog');
  return [...new Set(sources)];
}

function getBankingContext(timestamp: number): { isATMReconciliation: boolean; isSWIFTCommunication: boolean; isMonthEndBatch: boolean } {
  const date = new Date(timestamp);
  const hour = date.getHours();
  const day = date.getDate();
  const monthEnd = day >= 28 && day <= 31;

  return {
    isATMReconciliation: hour >= 0 && hour < 3,
    isSWIFTCommunication: hour === 2 || hour === 14,
    isMonthEndBatch: monthEnd && (hour >= 23 || hour < 2),
  };
}

function createBaseLog(
  timestamp: number,
  rng: () => number,
  id: string,
  overrides: Partial<NetworkLog> = {}
): NetworkLog {
  const banking = getBankingContext(timestamp);
  const destIP = overrides.destIP ?? (rng() < 0.76 ? randomFrom(INTERNAL_IPS, rng) : randomFrom(KNOWN_EXTERNAL_IPS, rng));
  const sourceIP = overrides.sourceIP ?? randomFrom(INTERNAL_IPS, rng);
  const external = !destIP.startsWith('10.') && !destIP.startsWith('192.168.') && !destIP.startsWith('172.16.');
  const sourceContext = {
    isATMReconciliation: overrides.isATMReconciliation ?? banking.isATMReconciliation,
    isSWIFTCommunication: overrides.isSWIFTCommunication ?? banking.isSWIFTCommunication,
    isMonthEndBatch: overrides.isMonthEndBatch ?? banking.isMonthEndBatch,
  };
  const networkSegment = overrides.networkSegment ?? inferNetworkSegment(sourceIP, sourceContext);
  const isPrivileged = overrides.isPrivileged ?? false;

  return {
    id,
    timestamp,
    sourceIP,
    destIP,
    packetSize: Math.round(overrides.packetSize ?? randomBetween(260, 1250, rng)),
    flowDuration: Math.round(overrides.flowDuration ?? randomBetween(120, 950, rng)),
    tlsFingerprint: overrides.tlsFingerprint ?? randomFrom(KNOWN_TLS, rng),
    connectionInterval: Math.round(overrides.connectionInterval ?? randomBetween(1200, 4200, rng)),
    userId: overrides.userId ?? randomFrom(NORMAL_USERS, rng),
    isPrivileged,
    loginTime: overrides.loginTime ?? timestamp - Math.round(randomBetween(90_000, 4_000_000, rng)),
    sessionDuration: Math.round(overrides.sessionDuration ?? randomBetween(240, 4200, rng)),
    dbQueryCount: Math.round(overrides.dbQueryCount ?? randomBetween(2, 12, rng)),
    queryFrequency: Math.round(overrides.queryFrequency ?? randomBetween(isBusinessHours(timestamp) ? 2 : 1, isBusinessHours(timestamp) ? 7 : 4, rng)),
    isExternalIP: overrides.isExternalIP ?? external,
    isBusinessHours: overrides.isBusinessHours ?? isBusinessHours(timestamp),
    networkSegment,
    applicationLabel: overrides.applicationLabel ?? inferApplicationLabel(networkSegment),
    telemetrySources: overrides.telemetrySources ?? buildTelemetrySources(networkSegment, isPrivileged, overrides.isExternalIP ?? external),
    signatureTag: overrides.signatureTag ?? null,
    ...banking,
    ...overrides,
  };
}

function generateATMReconciliationLog(timestamp: number, rng: () => number, id: string): NetworkLog {
  return createBaseLog(timestamp, rng, id, {
    sourceIP: '10.0.2.78',
    destIP: randomFrom(DATABASE_HOSTS, rng),
    userId: 'adm_sysops',
    isPrivileged: true,
    packetSize: Math.round(randomBetween(820, 980, rng)),
    flowDuration: Math.round(randomBetween(780, 1200, rng)),
    connectionInterval: Math.round(randomBetween(3200, 4400, rng)),
    dbQueryCount: Math.round(randomBetween(220, 320, rng)),
    queryFrequency: Math.round(randomBetween(180, 250, rng)),
    sessionDuration: Math.round(randomBetween(1500, 3000, rng)),
    networkSegment: 'ATM_SWITCH',
    applicationLabel: 'ATM Reconciliation Switch',
    telemetrySources: ['ATM Network Traffic', 'NetFlow/IPFIX', 'Syslog'],
    isATMReconciliation: true,
    isBusinessHours: false,
    isExternalIP: false,
  });
}

function generateSwiftLog(timestamp: number, rng: () => number, id: string): NetworkLog {
  return createBaseLog(timestamp, rng, id, {
    sourceIP: '172.16.0.5',
    destIP: '203.45.12.88',
    packetSize: Math.round(randomBetween(480, 720, rng)),
    flowDuration: Math.round(randomBetween(760, 1120, rng)),
    connectionInterval: Math.round(randomBetween(48_000, 82_000, rng)),
    queryFrequency: Math.round(randomBetween(1, 3, rng)),
    dbQueryCount: Math.round(randomBetween(1, 4, rng)),
    networkSegment: 'SWIFT_SUBNET',
    applicationLabel: 'SWIFT Messaging Gateway',
    telemetrySources: ['SWIFT Message Log', 'NetFlow/IPFIX', 'Zeek', 'Syslog'],
    isExternalIP: true,
    isSWIFTCommunication: true,
  });
}

function generateMonthEndBatchLog(timestamp: number, rng: () => number, id: string): NetworkLog {
  return createBaseLog(timestamp, rng, id, {
    sourceIP: '10.0.3.11',
    destIP: '10.0.3.99',
    userId: 'adm_dba',
    isPrivileged: true,
    packetSize: Math.round(randomBetween(900, 1080, rng)),
    flowDuration: Math.round(randomBetween(1180, 1600, rng)),
    connectionInterval: Math.round(randomBetween(4600, 5800, rng)),
    dbQueryCount: Math.round(randomBetween(520, 760, rng)),
    queryFrequency: Math.round(randomBetween(420, 560, rng)),
    sessionDuration: Math.round(randomBetween(1800, 3600, rng)),
    networkSegment: 'CORE_BANKING_PUMORI',
    applicationLabel: 'Pumori+ Core Banking Batch',
    telemetrySources: ['Windows Event Log', 'Syslog', 'NetFlow/IPFIX'],
    isMonthEndBatch: true,
    isBusinessHours: false,
    isExternalIP: false,
  });
}

function generateNRBRegulatoryLog(timestamp: number, rng: () => number, id: string): NetworkLog {
  return createBaseLog(timestamp, rng, id, {
    sourceIP: '10.0.3.11',
    destIP: randomFrom(NRB_ENDPOINTS, rng),
    packetSize: Math.round(randomBetween(340, 620, rng)),
    flowDuration: Math.round(randomBetween(420, 980, rng)),
    connectionInterval: Math.round(randomBetween(18_000, 42_000, rng)),
    userId: 'adm_sysops',
    isPrivileged: true,
    dbQueryCount: Math.round(randomBetween(8, 24, rng)),
    queryFrequency: Math.round(randomBetween(4, 12, rng)),
    sessionDuration: Math.round(randomBetween(600, 1800, rng)),
    networkSegment: 'NRB_REGULATORY',
    applicationLabel: 'NRB Regulatory Reporting Link',
    telemetrySources: ['Syslog', 'NetFlow/IPFIX', 'Zeek'],
    isExternalIP: false,
    isBusinessHours: true,
  });
}

function generateNormalLog(timestamp: number, rng: () => number, id: string): NetworkLog {
  const banking = getBankingContext(timestamp);
  const hour = new Date(timestamp).getHours();

  if (banking.isATMReconciliation && rng() < 0.35) {
    return generateATMReconciliationLog(timestamp, rng, id);
  }
  if (banking.isSWIFTCommunication && rng() < 0.18) {
    return generateSwiftLog(timestamp, rng, id);
  }
  if (banking.isMonthEndBatch && rng() < 0.25) {
    return generateMonthEndBatchLog(timestamp, rng, id);
  }
  if ((hour === 9 || hour === 16) && rng() < 0.16) {
    return generateNRBRegulatoryLog(timestamp, rng, id);
  }

  return createBaseLog(timestamp, rng, id);
}

function generateBeaconingLog(timestamp: number, rng: () => number, id: string, progress: number): NetworkLog {
  const suspiciousDest = progress < 0.45 && rng() < 0.3
    ? randomFrom(KNOWN_EXTERNAL_IPS, rng)
    : randomFrom(EASTERN_EUROPE_IPS, rng);

  return createBaseLog(timestamp, rng, id, {
    sourceIP: '172.16.0.5',
    destIP: suspiciousDest,
    packetSize: Math.round(jitter(blend(240, 96, progress), 0.18, rng)),
    flowDuration: Math.round(jitter(blend(420, 1250, progress), 0.12, rng)),
    connectionInterval: Math.round(jitter(blend(2200, 1000, progress), 0.04, rng)),
    tlsFingerprint: progress > 0.35 ? randomFrom(SUSPICIOUS_TLS, rng) : randomFrom(KNOWN_TLS, rng),
    userId: 'usr_bob',
    dbQueryCount: Math.round(randomBetween(2, 10, rng)),
    queryFrequency: Math.round(randomBetween(2, 6, rng)),
    sessionDuration: Math.round(randomBetween(1200, 3200, rng)),
    networkSegment: 'SWIFT_SUBNET',
    applicationLabel: 'SWIFT Messaging Gateway',
    telemetrySources: ['SWIFT Message Log', 'NetFlow/IPFIX', 'Zeek', 'Suricata', 'Syslog'],
    signatureTag: progress > 0.7 ? 'ET MALWARE Suspicious JA3 Beacon on SWIFT VLAN' : null,
    isExternalIP: true,
    isSWIFTCommunication: true,
    isBusinessHours: false,
  });
}

function generateDBStagingLog(timestamp: number, rng: () => number, id: string, progress: number): NetworkLog {
  return createBaseLog(timestamp, rng, id, {
    sourceIP: '172.16.0.5',
    destIP: '10.0.3.99',
    packetSize: Math.round(jitter(blend(620, 940, progress), 0.12, rng)),
    flowDuration: Math.round(jitter(blend(680, 2200, progress), 0.15, rng)),
    connectionInterval: Math.round(jitter(blend(1800, 1200, progress), 0.08, rng)),
    tlsFingerprint: randomFrom(KNOWN_TLS, rng),
    userId: 'adm_dba',
    isPrivileged: true,
    dbQueryCount: Math.round(jitter(blend(90, 210, progress), 0.08, rng)),
    queryFrequency: Math.round(jitter(blend(30, 220, progress), 0.1, rng)),
    sessionDuration: Math.round(jitter(blend(540, 45, progress), 0.22, rng)),
    networkSegment: 'CORE_BANKING_PUMORI',
    applicationLabel: 'Pumori+ Core Banking Database',
    telemetrySources: ['Windows Event Log', 'NetFlow/IPFIX', 'Syslog', 'Zeek'],
    signatureTag: null,
    isExternalIP: false,
    isSWIFTCommunication: true,
    isBusinessHours: false,
  });
}

function generateExfiltrationLog(timestamp: number, rng: () => number, id: string, progress: number): NetworkLog {
  return createBaseLog(timestamp, rng, id, {
    sourceIP: '172.16.0.5',
    destIP: randomFrom(EASTERN_EUROPE_IPS, rng),
    packetSize: Math.round(jitter(blend(920, 1490, progress), 0.08, rng)),
    flowDuration: Math.round(jitter(blend(2500, 14_500, progress), 0.12, rng)),
    connectionInterval: Math.round(jitter(blend(1300, 980, progress), 0.05, rng)),
    tlsFingerprint: randomFrom(SUSPICIOUS_TLS, rng),
    userId: 'adm_dba',
    isPrivileged: true,
    dbQueryCount: Math.round(jitter(blend(160, 240, progress), 0.09, rng)),
    queryFrequency: Math.round(jitter(blend(85, 230, progress), 0.08, rng)),
    sessionDuration: Math.round(jitter(blend(180, 35, progress), 0.18, rng)),
    networkSegment: 'SWIFT_SUBNET',
    applicationLabel: 'SWIFT Messaging Gateway',
    telemetrySources: ['SWIFT Message Log', 'NetFlow/IPFIX', 'Zeek', 'Suricata', 'Windows Event Log', 'Syslog'],
    signatureTag: progress > 0.45 ? 'CVE-2023-4966 style session hijack IOC' : 'ET TROJAN TLS Exfiltration Pattern',
    isExternalIP: true,
    isSWIFTCommunication: true,
    isBusinessHours: false,
  });
}

function generateFullAttackLog(timestamp: number, rng: () => number, id: string): NetworkLog {
  return createBaseLog(timestamp, rng, id, {
    sourceIP: '172.16.0.5',
    destIP: randomFrom(EASTERN_EUROPE_IPS, rng),
    packetSize: Math.round(randomBetween(1320, 1510, rng)),
    flowDuration: Math.round(randomBetween(8200, 18_000, rng)),
    connectionInterval: Math.round(randomBetween(940, 1040, rng)),
    tlsFingerprint: randomFrom(SUSPICIOUS_TLS, rng),
    userId: 'adm_dba',
    isPrivileged: true,
    loginTime: timestamp - Math.round(randomBetween(4000, 28_000, rng)),
    sessionDuration: Math.round(randomBetween(12, 80, rng)),
    dbQueryCount: Math.round(randomBetween(180, 240, rng)),
    queryFrequency: Math.round(randomBetween(195, 240, rng)),
    networkSegment: 'SWIFT_SUBNET',
    applicationLabel: 'SWIFT Messaging Gateway',
    telemetrySources: ['SWIFT Message Log', 'NetFlow/IPFIX', 'Zeek', 'Suricata', 'Windows Event Log', 'Syslog'],
    signatureTag: 'ET MALWARE Multi-stage C2 + Core Banking Access',
    isExternalIP: true,
    isSWIFTCommunication: true,
    isBusinessHours: false,
  });
}

function getPhaseProgress(phase: AttackPhase, phaseTick: number): number {
  const span = Math.max(PHASE_SPANS[phase], 1);
  return Math.min(1, Math.max(0, phaseTick / span));
}

function attackLikelihood(phase: AttackPhase, progress: number): number {
  switch (phase) {
    case 2:
      return 0.5 + progress * 0.25;
    case 3:
      return 0.62 + progress * 0.18;
    case 4:
      return 0.76 + progress * 0.16;
    case 5:
      return 0.9;
    default:
      return 0;
  }
}

export function generateLog(timestamp: number, context: SimulationContext): NetworkLog {
  const counter = ++logCounter;
  const seed = ((timestamp * 31) >>> 0) + ((context.attackPhase * 17) >>> 0) + ((context.phaseTick * 13) >>> 0) + ((context.totalTick * 7) >>> 0);
  const rng = createSeededRng(seed);
  const id = `log_${timestamp}_${context.attackPhase}_${counter}`;

  if (context.mode !== 'attack' || context.attackPhase <= 1) {
    return generateNormalLog(timestamp, rng, id);
  }

  const progress = getPhaseProgress(context.attackPhase, context.phaseTick);
  if (rng() > attackLikelihood(context.attackPhase, progress)) {
    return generateNormalLog(timestamp, rng, id);
  }

  switch (context.attackPhase) {
    case 2:
      return generateBeaconingLog(timestamp, rng, id, progress);
    case 3:
      return generateDBStagingLog(timestamp, rng, id, progress);
    case 4:
      return generateExfiltrationLog(timestamp, rng, id, progress);
    case 5:
      return generateFullAttackLog(timestamp, rng, id);
    default:
      return generateNormalLog(timestamp, rng, id);
  }
}

export { EASTERN_EUROPE_IPS, KNOWN_EXTERNAL_IPS, KNOWN_TLS, PRIVILEGED_USERS, SUSPICIOUS_EXTERNAL_IPS, SUSPICIOUS_TLS, USER_WORKSTATIONS };
