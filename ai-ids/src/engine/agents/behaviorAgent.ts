// ============================================================
// BEHAVIOR AGENT — Application-Layer User & Query Analysis
// Analyzes query rates, privileged user behavior, session patterns
// ============================================================

import { NetworkLog, Baseline, WindowStats, AgentSignal } from '../../types/ids';

// ─── Z-Score for Query Rate ───────────────────────────────────
function computeQueryZScore(current: number, history: number[]): number {
  if (history.length < 3) return 0;
  const mean = history.reduce((s, v) => s + v, 0) / history.length;
  const variance = history.reduce((s, v) => s + Math.pow(v - mean, 2), 0) / history.length;
  const stdDev = Math.sqrt(variance);
  if (stdDev === 0) return 0;
  return (current - mean) / stdDev;
}

// ─── Query Spike Detection ────────────────────────────────────
function analyzeQueryBehavior(log: NetworkLog, baseline: Baseline): { zScore: number; deviation: number; isSpike: boolean } {
  const zScore = computeQueryZScore(log.queryFrequency, baseline.queryRateHistory);
  const deviation = baseline.avgQueryRate > 0 ? log.queryFrequency / baseline.avgQueryRate : 0;
  // Spike: z-score > 2.5 OR deviation > 5x baseline
  const isSpike = Math.abs(zScore) > 2.5 || deviation > 5.0;
  return { zScore, deviation, isSpike };
}

// ─── Privileged User Anomaly Detection ────────────────────────
function analyzePrivilegedUser(log: NetworkLog, windowStats: WindowStats): { score: number; reasons: string[] } {
  if (!log.isPrivileged) return { score: 0, reasons: [] };

  const reasons: string[] = [];
  let score = 0;

  // Off-hours privileged access
  if (!log.isBusinessHours) {
    score += 0.4;
    reasons.push(`Privileged user ${log.userId} accessing systems outside business hours (${new Date(log.timestamp).getHours()}:00)`);
  }

  // High query rate for privileged user
  if (log.queryFrequency > 50) {
    score += 0.35;
    reasons.push(`Privileged user query rate ${log.queryFrequency}/min exceeds admin threshold (50/min)`);
  }

  // Short session + high activity (lateral movement indicator)
  if (log.sessionDuration < 60 && log.dbQueryCount > 100) {
    score += 0.3;
    reasons.push(`Short session (${log.sessionDuration}s) with intense DB activity (${log.dbQueryCount} queries) — possible lateral movement`);
  }

  // External IP access while privileged
  if (log.isExternalIP && windowStats.externalIPFrequency > 0.3) {
    score += 0.25;
    reasons.push(`Privileged user communicating with external IPs at ${(windowStats.externalIPFrequency * 100).toFixed(0)}% frequency`);
  }

  return { score: Math.min(score, 1), reasons };
}

// ─── Session Pattern Analysis ─────────────────────────────────
function analyzeSession(log: NetworkLog): { isAnomalous: boolean; reason: string } {
  // Very short session with high activity
  if (log.sessionDuration < 30 && log.dbQueryCount > 50) {
    return {
      isAnomalous: true,
      reason: `Burst session: ${log.dbQueryCount} queries in ${log.sessionDuration}s`,
    };
  }
  // Long session with no activity (possible idle C2)
  if (log.sessionDuration > 3000 && log.dbQueryCount < 2) {
    return {
      isAnomalous: true,
      reason: `Idle long session (${(log.sessionDuration / 60).toFixed(0)}min) with minimal activity — possible C2 keepalive`,
    };
  }
  return { isAnomalous: false, reason: '' };
}

// ─── Main Behavior Agent Entry Point ──────────────────────────
export function runBehaviorAgent(
  log: NetworkLog,
  baseline: Baseline,
  windowStats: WindowStats
): AgentSignal {
  const queryAnalysis = analyzeQueryBehavior(log, baseline);
  const privilegedAnalysis = analyzePrivilegedUser(log, windowStats);
  const sessionAnalysis = analyzeSession(log);

  // Weighted fusion: query 0.45, privileged 0.35, session 0.2
  const queryScore = queryAnalysis.isSpike ? Math.min(Math.abs(queryAnalysis.zScore) / 4, 1) : 0;
  const privilegedScore = privilegedAnalysis.score;
  const sessionScore = sessionAnalysis.isAnomalous ? 0.6 : 0;

  const totalScore = Math.min(queryScore * 0.45 + privilegedScore * 0.35 + sessionScore * 0.2, 1);
  const detected = totalScore > 0.5 || queryAnalysis.isSpike || privilegedScore > 0.5;

  const reasoningParts: string[] = [];
  if (queryAnalysis.isSpike) {
    reasoningParts.push(
      `Query rate ${log.queryFrequency}/min is ${Math.abs(queryAnalysis.zScore).toFixed(1)}σ ` +
      `above moving average (baseline: ${baseline.avgQueryRate.toFixed(1)}/min, deviation: ${queryAnalysis.deviation.toFixed(1)}x)`
    );
  }
  if (privilegedAnalysis.reasons.length > 0) {
    reasoningParts.push(...privilegedAnalysis.reasons);
  }
  if (sessionAnalysis.isAnomalous) {
    reasoningParts.push(sessionAnalysis.reason);
  }

  return {
    agent: 'BEHAVIOR',
    signalType: detected ? 'ANOMALOUS_BEHAVIOR' : 'BEHAVIOR_NOMINAL',
    score: totalScore,
    confidence: Math.min(0.5 + totalScore * 0.4 + (detected ? 0.1 : 0), 0.95),
    detected,
    features: {
      queryZScore: queryAnalysis.zScore,
      queryDeviation: queryAnalysis.deviation,
      privilegedScore: privilegedScore,
      sessionDuration: log.sessionDuration,
      dbQueryCount: log.dbQueryCount,
      isPrivileged: log.isPrivileged ? 1 : 0,
    },
    reasoning: detected
      ? `BEHAVIOR AGENT: ${reasoningParts.join('; ')}.`
      : `BEHAVIOR AGENT: User ${log.userId} activity within norms. Query rate ${log.queryFrequency}/min (z-score: ${queryAnalysis.zScore.toFixed(2)}). Session duration ${log.sessionDuration}s. No behavioral anomalies.`,
  };
}
