export type AlertLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type SystemMode = 'normal' | 'attack' | 'idle';
export type AttackPhase = 0 | 1 | 2 | 3 | 4 | 5;
export type AgentType = 'PACKET' | 'FLOW' | 'BEHAVIOR' | 'CORRELATION' | 'RESPONSE';
export type BankingProfileType = 'DEFAULT' | 'ATM' | 'SWIFT' | 'BATCH';
export type NetworkSegment = 'USER_LAN' | 'SWIFT_SUBNET' | 'ATM_SWITCH' | 'CORE_BANKING_PUMORI' | 'NRB_REGULATORY';
export type TelemetrySource =
  | 'NetFlow/IPFIX'
  | 'Zeek'
  | 'Suricata'
  | 'Windows Event Log'
  | 'Syslog'
  | 'SWIFT Message Log'
  | 'ATM Network Traffic';
export type DetectionMode = 'SIGNATURE' | 'ANOMALY' | 'BEHAVIORAL' | 'ZERO_DAY';
export type AttackClassification =
  | 'C2_BEACONING'
  | 'DATA_EXFILTRATION'
  | 'LATERAL_MOVEMENT'
  | 'PRIVILEGED_ABUSE'
  | 'RECONNAISSANCE'
  | 'SUSPICIOUS_ACTIVITY'
  | 'NONE';

export interface NetworkLog {
  id: string;
  timestamp: number;
  sourceIP: string;
  destIP: string;
  packetSize: number;
  flowDuration: number;
  tlsFingerprint: string;
  connectionInterval: number;
  userId: string;
  isPrivileged: boolean;
  loginTime: number;
  sessionDuration: number;
  dbQueryCount: number;
  queryFrequency: number;
  isExternalIP: boolean;
  isBusinessHours: boolean;
  networkSegment: NetworkSegment;
  applicationLabel: string;
  telemetrySources: TelemetrySource[];
  signatureTag: string | null;
  isATMReconciliation: boolean;
  isSWIFTCommunication: boolean;
  isMonthEndBatch: boolean;
}

export interface ContextBaseline {
  label: string;
  profileType: BankingProfileType;
  avgQueryRate: number;
  avgInterval: number;
  avgPacketSize: number;
  avgFlowDuration: number;
  queryRateEMA: number;
  packetSizeEMA: number;
  intervalEMA: number;
  flowDurationEMA: number;
  queryRateHistory: number[];
  packetSizeHistory: number[];
  intervalHistory: number[];
  flowDurationHistory: number[];
}

export interface DestinationProfile {
  firstSeen: number;
  lastSeen: number;
  sightings: number;
  reputationScore: number;
  contexts: BankingProfileType[];
}

export interface Baseline {
  avgQueryRate: number;
  avgInterval: number;
  knownIPs: string[];
  avgPacketSize: number;
  avgFlowDuration: number;
  knownTLSFingerprints: string[];
  samplesCollected: number;
  queryRateEMA: number;
  packetSizeEMA: number;
  intervalEMA: number;
  flowDurationEMA: number;
  queryRateHistory: number[];
  packetSizeHistory: number[];
  intervalHistory: number[];
  flowDurationHistory: number[];
  contextProfiles: Record<BankingProfileType, ContextBaseline>;
  destinationProfiles: Record<string, DestinationProfile>;
}

export interface AnomalySignal {
  type: 'BEACONING' | 'DB_SPIKE' | 'UNKNOWN_IP' | 'PRIVILEGED_MISUSE' | 'TLS_ANOMALY' | 'PACKET_ANOMALY';
  weight: number;
  detected: boolean;
  value: number;
  baseline: number;
  deviation: number;
  description: string;
}

export interface AgentSignal {
  agent: AgentType;
  signalType: string;
  score: number;
  confidence: number;
  detected: boolean;
  features: Record<string, number>;
  reasoning: string;
  classification?: AttackClassification;
  correlatedSignals?: string[];
}

export type AgentBreakdown = Record<AgentType, { score: number; confidence: number; detected: boolean }>;

export interface RiskState {
  currentScore: number;
  accumulatedRisk: number;
  decayFactor: number;
  confidence: number;
  lastUpdate: number;
  escalationRate: number;
  uncertainty: number;
}

export interface BankingContext {
  profile: BankingProfileType;
  profileLabel: string;
  isATMReconciliation: boolean;
  isSWIFTCommunication: boolean;
  isMonthEndBatch: boolean;
  batchJobWindow: boolean;
}

export interface DetectionResult {
  log: NetworkLog;
  riskScore: number;
  alert: AlertLevel;
  confidence: number;
  reasons: string[];
  explanation: string;
  signals: AnomalySignal[];
  agentSignals: AgentSignal[];
  isolationScore: number;
  correlationScore: number;
  falsePositiveReduced: boolean;
  attackPhase?: AttackPhase;
  attackClassification: AttackClassification;
  threatCategory: string;
  alternativeInterpretation: string;
  executiveSummary: string;
  temporalContext: string;
  agentBreakdown: AgentBreakdown;
  riskState: RiskState;
  bankingContext: BankingContext;
  correlationChain: string[];
  detectionModes: DetectionMode[];
  signatureMatches: string[];
  zeroDayScore: number;
  clusterOutlierScore: number;
  nearestBehaviorCluster: string;
  autoIsolationRecommended: boolean;
}

export interface WindowStats {
  avgQueryRate: number;
  avgInterval: number;
  intervalEntropy: number;
  externalIPFrequency: number;
  uniqueExternalIPs: string[];
  totalPackets: number;
  timeSpan: number;
  packetSizeStdDev: number;
  flowDurationStdDev: number;
  queryRateStdDev: number;
  queryRateZScore: number;
  packetSizeZScore: number;
}

export interface TimelinePoint {
  time: string;
  riskScore: number;
  queryRate: number;
  packetSize: number;
  alert: AlertLevel;
  timestamp: number;
}

export interface SystemState {
  mode: SystemMode;
  attackPhase: AttackPhase;
  baseline: Baseline;
  slidingWindow: NetworkLog[];
  detectionHistory: DetectionResult[];
  timeline: TimelinePoint[];
  isRunning: boolean;
  totalLogsProcessed: number;
  simulationTick: number;
  phaseTick: number;
  alertCounts: Record<AlertLevel, number>;
  lastUpdate: number;
  riskState: RiskState;
  bankingContext: BankingContext;
}

export interface APIResponse {
  log: NetworkLog;
  riskScore: number;
  alert: AlertLevel;
  confidence: number;
  reasons: string[];
  explanation: string;
  signals: AnomalySignal[];
  timestamp: number;
  threatCategory: string;
  alternativeInterpretation: string;
  executiveSummary: string;
  temporalContext: string;
  agentBreakdown: AgentBreakdown;
  attackClassification: AttackClassification;
  correlationChain: string[];
  detectionModes: DetectionMode[];
  signatureMatches: string[];
  zeroDayScore: number;
  clusterOutlierScore: number;
  nearestBehaviorCluster: string;
  autoIsolationRecommended: boolean;
}
