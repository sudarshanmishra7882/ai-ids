// ============================================================
// SENTINELS OF THE NETWORK — AI-Driven IDS Type Definitions
// Multi-Agent Banking SOC Architecture v3.0
// ============================================================

export type AlertLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type SystemMode = 'normal' | 'attack' | 'idle';
export type AttackPhase = 0 | 1 | 2 | 3 | 4 | 5;
export type AgentType = 'PACKET' | 'FLOW' | 'BEHAVIOR' | 'RESPONSE';
export type AttackClassification = 'C2_BEACONING' | 'DATA_EXFILTRATION' | 'LATERAL_MOVEMENT' | 'PRIVILEGED_ABUSE' | 'RECONNAISSANCE' | 'NONE';
export type AgentBreakdown = Record<AgentType, { score: number; confidence: number; detected: boolean }>;

// ─── Raw Log Entry ───────────────────────────────────────────
export interface NetworkLog {
  id: string;
  timestamp: number;
  // Network Layer
  sourceIP: string;
  destIP: string;
  packetSize: number;
  flowDuration: number;
  tlsFingerprint: string;
  connectionInterval: number;
  // User Layer
  userId: string;
  isPrivileged: boolean;
  loginTime: number;
  sessionDuration: number;
  // Application Layer
  dbQueryCount: number;
  queryFrequency: number; // per minute
  // Computed
  isExternalIP: boolean;
  isBusinessHours: boolean;
  // Banking Context (v3.0)
  isATMReconciliation: boolean;
  isSWIFTCommunication: boolean;
  isMonthEndBatch: boolean;
}

// ─── Baseline Model ──────────────────────────────────────────
export interface Baseline {
  avgQueryRate: number;
  avgInterval: number;
  knownIPs: string[];
  avgPacketSize: number;
  avgFlowDuration: number;
  knownTLSFingerprints: string[];
  samplesCollected: number;
  // Time-decayed statistics (v3.0)
  queryRateEMA: number; // Exponential moving average
  packetSizeEMA: number;
  intervalEMA: number;
  // Historical windows for z-score
  queryRateHistory: number[];
  packetSizeHistory: number[];
  intervalHistory: number[];
}

// ─── Legacy Anomaly Signal (kept for compatibility) ───────────
export interface AnomalySignal {
  type: 'BEACONING' | 'DB_SPIKE' | 'UNKNOWN_IP' | 'PRIVILEGED_MISUSE' | 'TLS_ANOMALY' | 'PACKET_ANOMALY';
  weight: number;
  detected: boolean;
  value: number;
  baseline: number;
  deviation: number;
  description: string;
}

// ─── Multi-Agent Signal (v3.0) ───────────────────────────────
export interface AgentSignal {
  agent: AgentType;
  signalType: string;
  score: number; // 0–1 anomaly score
  confidence: number;
  detected: boolean;
  features: Record<string, number>;
  reasoning: string;
}

// ─── Risk Accumulation State (v3.0) ──────────────────────────
export interface RiskState {
  currentScore: number;
  accumulatedRisk: number; // time-decayed
  decayFactor: number; // typically 0.9
  confidence: number;
  lastUpdate: number;
  escalationRate: number;
}

// ─── Banking Context (v3.0) ──────────────────────────────────
export interface BankingContext {
  isATMReconciliation: boolean;
  isSWIFTCommunication: boolean;
  isMonthEndBatch: boolean;
  batchJobWindow: boolean;
}

// ─── Detection Result ─────────────────────────────────────────
export interface DetectionResult {
  log: NetworkLog;
  riskScore: number;
  alert: AlertLevel;
  confidence: number;
  reasons: string[];
  explanation: string;
  signals: AnomalySignal[];
  agentSignals: AgentSignal[]; // v3.0
  isolationScore: number;
  correlationScore: number;
  falsePositiveReduced: boolean;
  attackPhase?: AttackPhase;
  attackClassification: AttackClassification; // v3.0
  threatCategory: string;
  alternativeInterpretation: string;
  executiveSummary: string;
  temporalContext: string;
  agentBreakdown: AgentBreakdown; // v3.0
  riskState: RiskState; // v3.0
  bankingContext: BankingContext; // v3.0
  correlationChain: string[]; // v3.0 step-by-step reasoning
}

// ─── Sliding Window Stats ─────────────────────────────────────
export interface WindowStats {
  avgQueryRate: number;
  avgInterval: number;
  intervalEntropy: number;
  externalIPFrequency: number;
  uniqueExternalIPs: string[];
  totalPackets: number;
  timeSpan: number;
  // v3.0 additions
  packetSizeStdDev: number;
  flowDurationStdDev: number;
  queryRateZScore: number;
  packetSizeZScore: number;
}

// ─── Timeline Data Point ──────────────────────────────────────
export interface TimelinePoint {
  time: string;
  riskScore: number;
  queryRate: number;
  packetSize: number;
  alert: AlertLevel;
  timestamp: number;
}

// ─── System State ─────────────────────────────────────────────
export interface SystemState {
  mode: SystemMode;
  attackPhase: AttackPhase;
  baseline: Baseline;
  slidingWindow: NetworkLog[];
  detectionHistory: DetectionResult[];
  timeline: TimelinePoint[];
  isRunning: boolean;
  totalLogsProcessed: number;
  alertCounts: Record<AlertLevel, number>;
  lastUpdate: number;
  // v3.0 additions
  riskState: RiskState;
  bankingContext: BankingContext;
}

// ─── API Response ─────────────────────────────────────────────
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
  // v3.0 additions
  agentBreakdown: AgentBreakdown;
  attackClassification: AttackClassification;
  correlationChain: string[];
}
