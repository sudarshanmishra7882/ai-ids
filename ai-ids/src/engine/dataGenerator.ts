// ============================================================
// DATA GENERATOR v3.0 — Multi-Agent Banking Network Simulation
// Adds: ATM reconciliation, SWIFT patterns, month-end batch,
// noise injection, gradual phase evolution
// ============================================================

import { NetworkLog, AttackPhase } from '../types/ids';

// ─── Deterministic PRNG (Mulberry32-inspired) ─────────────────
function createSeededRNG(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 4294967296;
  };
}

// ─── Known IP Pools ───────────────────────────────────────────
const INTERNAL_IPS = [
  '10.0.1.12', '10.0.1.45', '10.0.2.33', '10.0.2.78',
  '10.0.3.11', '10.0.3.99', '192.168.1.5', '192.168.1.23',
  '192.168.2.10', '192.168.2.67', '172.16.0.5', '172.16.0.88',
];

const KNOWN_EXTERNAL_IPS = [
  '203.45.12.88', '185.23.44.7', '91.108.4.160', '142.250.9.100',
  '52.84.21.196', '104.18.0.15', '8.8.8.8', '1.1.1.1',
];

const SUSPICIOUS_EXTERNAL_IPS = [
  '45.33.32.156', '185.220.101.1', '94.102.49.190', '23.129.64.131',
  '176.10.104.240', '199.87.154.255', '91.92.109.198',
];

// ─── Known TLS Fingerprints (JA3-like) ────────────────────────
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

// ─── User Pool ────────────────────────────────────────────────
const NORMAL_USERS = ['usr_alice', 'usr_bob', 'usr_carol', 'usr_dave', 'usr_eve'];
export const PRIVILEGED_USERS = ['adm_root', 'adm_sysops', 'adm_dba'];

let logCounter = 0;

function randomFrom<T>(arr: T[], rng: () => number): T {
  return arr[Math.floor(rng() * arr.length)];
}

function randomBetween(min: number, max: number, rng: () => number): number {
  return rng() * (max - min) + min;
}

function isBusinessHours(timestamp: number): boolean {
  const hour = new Date(timestamp).getHours();
  return hour >= 8 && hour < 18;
}

// ─── Banking Context Detection ────────────────────────────────
function getBankingContext(timestamp: number): { isATMReconciliation: boolean; isSWIFTCommunication: boolean; isMonthEndBatch: boolean } {
  const date = new Date(timestamp);
  const hour = date.getHours();
  const day = date.getDate();
  const isLastDayOfMonth = day >= 28 && day <= 31;

  // ATM reconciliation: 0-3 AM daily
  const isATMReconciliation = hour >= 0 && hour < 3;
  // SWIFT: low-frequency, typically during business hours but can be 24/7
  const isSWIFTCommunication = hour === 2 || hour === 14; // scheduled windows
  // Month-end batch: last 3 days of month, 11 PM - 2 AM
  const isMonthEndBatch = isLastDayOfMonth && (hour >= 23 || hour < 2);

  return { isATMReconciliation, isSWIFTCommunication, isMonthEndBatch };
}

// ─── Normal Traffic Generator ─────────────────────────────────
function generateNormalLog(timestamp: number, rng: () => number, id: string): NetworkLog {
  const sourceIP = randomFrom(INTERNAL_IPS, rng);
  const destIP = rng() < 0.7
    ? randomFrom(INTERNAL_IPS, rng)
    : randomFrom(KNOWN_EXTERNAL_IPS, rng);
  const userId = randomFrom(NORMAL_USERS, rng);
  const isExternal = !destIP.startsWith('10.') && !destIP.startsWith('192.168.') && !destIP.startsWith('172.16.');
  const banking = getBankingContext(timestamp);

  return {
    id,
    timestamp,
    sourceIP,
    destIP,
    packetSize: Math.round(randomBetween(200, 1400, rng)),
    flowDuration: Math.round(randomBetween(50, 800, rng)),
    tlsFingerprint: randomFrom(KNOWN_TLS, rng),
    connectionInterval: Math.round(randomBetween(800, 4000, rng)),
    userId,
    isPrivileged: false,
    loginTime: timestamp - Math.round(randomBetween(60000, 3600000, rng)),
    sessionDuration: Math.round(randomBetween(300, 3600, rng)),
    dbQueryCount: Math.round(randomBetween(1, 8, rng)),
    queryFrequency: Math.round(randomBetween(1, 5, rng)),
    isExternalIP: isExternal,
    isBusinessHours: isBusinessHours(timestamp),
    ...banking,
  };
}

// ─── Banking Pattern: ATM Reconciliation ──────────────────────
function generateATMReconciliationLog(timestamp: number, rng: () => number, id: string): NetworkLog {
  const base = generateNormalLog(timestamp, rng, id);
  return {
    ...base,
    userId: 'adm_sysops',
    isPrivileged: true,
    dbQueryCount: Math.round(randomBetween(200, 350, rng)),
    queryFrequency: Math.round(randomBetween(180, 280, rng)),
    isATMReconciliation: true,
    isBusinessHours: false,
  };
}

// ─── Banking Pattern: SWIFT Communication ─────────────────────
function generateSWIFTLog(timestamp: number, rng: () => number, id: string): NetworkLog {
  const base = generateNormalLog(timestamp, rng, id);
  return {
    ...base,
    destIP: '203.45.12.88', // SWIFT gateway
    packetSize: Math.round(randomBetween(400, 900, rng)),
    connectionInterval: Math.round(randomBetween(30000, 120000, rng)), // very infrequent
    queryFrequency: Math.round(randomBetween(1, 3, rng)),
    isSWIFTCommunication: true,
    isExternalIP: true,
  };
}

// ─── Banking Pattern: Month-End Batch ─────────────────────────
function generateMonthEndBatchLog(timestamp: number, rng: () => number, id: string): NetworkLog {
  const base = generateNormalLog(timestamp, rng, id);
  return {
    ...base,
    userId: 'adm_dba',
    isPrivileged: true,
    dbQueryCount: Math.round(randomBetween(500, 800, rng)),
    queryFrequency: Math.round(randomBetween(400, 600, rng)),
    sessionDuration: Math.round(randomBetween(1800, 3600, rng)),
    isMonthEndBatch: true,
    isBusinessHours: false,
  };
}

// ─── Attack Phase Generators ──────────────────────────────────

/** Phase 2: Beaconing starts — fixed short intervals */
function generateBeaconingLog(timestamp: number, _phase: AttackPhase, rng: () => number, id: string): NetworkLog {
  const base = generateNormalLog(timestamp, rng, id);
  const banking = getBankingContext(timestamp);
  return {
    ...base,
    ...banking,
    sourceIP: '10.0.1.45',
    destIP: '185.220.101.1',
    connectionInterval: 1000 + Math.round(randomBetween(-50, 50, rng)),
    packetSize: Math.round(randomBetween(60, 120, rng)),
    tlsFingerprint: randomFrom(SUSPICIOUS_TLS, rng),
    isExternalIP: true,
  };
}

/** Phase 3: DB Query Spike */
function generateDBSpikeLog(timestamp: number, phase: AttackPhase, rng: () => number, id: string): NetworkLog {
  const base = generateBeaconingLog(timestamp, phase, rng, id);
  return {
    ...base,
    userId: 'adm_dba',
    isPrivileged: true,
    dbQueryCount: Math.round(randomBetween(350, 450, rng)),
    queryFrequency: Math.round(randomBetween(300, 420, rng)),
    sessionDuration: Math.round(randomBetween(5, 30, rng)),
  };
}

/** Phase 4: External IP communication (data exfil) */
function generateExfiltrationLog(timestamp: number, phase: AttackPhase, rng: () => number, id: string): NetworkLog {
  const base = generateDBSpikeLog(timestamp, phase, rng, id);
  return {
    ...base,
    destIP: randomFrom(SUSPICIOUS_EXTERNAL_IPS, rng),
    packetSize: Math.round(randomBetween(1200, 1500, rng)),
    flowDuration: Math.round(randomBetween(5000, 15000, rng)),
    isExternalIP: true,
  };
}

/** Phase 5: Full correlated attack */
function generateFullAttackLog(timestamp: number, _phase: AttackPhase, rng: () => number, id: string): NetworkLog {
  const banking = getBankingContext(timestamp);
  return {
    id,
    timestamp,
    ...banking,
    sourceIP: '10.0.1.45',
    destIP: randomFrom(SUSPICIOUS_EXTERNAL_IPS, rng),
    packetSize: Math.round(randomBetween(1300, 1500, rng)),
    flowDuration: Math.round(randomBetween(8000, 20000, rng)),
    tlsFingerprint: randomFrom(SUSPICIOUS_TLS, rng),
    connectionInterval: 1000 + Math.round(randomBetween(-30, 30, rng)),
    userId: 'adm_dba',
    isPrivileged: true,
    loginTime: timestamp - Math.round(randomBetween(5000, 30000, rng)),
    sessionDuration: Math.round(randomBetween(10, 60, rng)),
    dbQueryCount: Math.round(randomBetween(380, 450, rng)),
    queryFrequency: Math.round(randomBetween(370, 430, rng)),
    isExternalIP: true,
    isBusinessHours: false,
  };
}

// ─── Noise Injection: Mix benign banking traffic ──────────────
function injectBankingNoise(timestamp: number, rng: () => number, id: string): NetworkLog | null {
  const banking = getBankingContext(timestamp);
  if (banking.isATMReconciliation && rng() < 0.3) {
    return generateATMReconciliationLog(timestamp, rng, id);
  }
  if (banking.isSWIFTCommunication && rng() < 0.15) {
    return generateSWIFTLog(timestamp, rng, id);
  }
  if (banking.isMonthEndBatch && rng() < 0.2) {
    return generateMonthEndBatchLog(timestamp, rng, id);
  }
  return null;
}

// ─── Phase-based dispatch with noise & gradual evolution ──────
export function generateLog(timestamp: number, phase: AttackPhase): NetworkLog {
  const currentCounter = ++logCounter;
  const seed = ((timestamp * 31) >>> 0) + ((phase * 17) >>> 0);
  const rng = createSeededRNG(seed);
  const id = `log_${timestamp}_${phase}_${currentCounter}`;

  // Noise injection: 20% chance of banking pattern during normal phases
  if ((phase === 0 || phase === 1) && rng() < 0.2) {
    const noise = injectBankingNoise(timestamp, rng, id);
    if (noise) return noise;
  }

  switch (phase) {
    case 0: return generateNormalLog(timestamp, rng, id);
    case 1: return generateNormalLog(timestamp, rng, id);
    case 2: return generateBeaconingLog(timestamp, phase, rng, id);
    case 3: return generateDBSpikeLog(timestamp, phase, rng, id);
    case 4: return generateExfiltrationLog(timestamp, phase, rng, id);
    case 5: return generateFullAttackLog(timestamp, phase, rng, id);
    default: return generateNormalLog(timestamp, rng, id);
  }
}
