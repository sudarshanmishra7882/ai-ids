import { AgentSignal, Baseline, NetworkLog, WindowStats } from '../../types/ids';
import { getExpectedValues } from '../baselineEngine';
import { clamp, percentageDelta, safeRatio, zScore } from '../statistics';

export function runBehaviorAgent(
  log: NetworkLog,
  baseline: Baseline,
  windowStats: WindowStats,
  flowSignal: AgentSignal
): AgentSignal {
  const expected = getExpectedValues(baseline, log);
  const queryZ = zScore(log.queryFrequency, expected.queryRateHistory);
  const queryDeviation = safeRatio(log.queryFrequency, expected.avgQueryRate);
  const queryScore = clamp(Math.max(queryDeviation - 1, 0) / 2.6 + Math.max(queryZ, 0) / 4.5, 0, 1);

  const maintenanceWindow = log.isATMReconciliation || log.isMonthEndBatch;
  let privilegedScore = 0;
  const privilegedReasons: string[] = [];

  if (log.isPrivileged && !log.isBusinessHours && !maintenanceWindow) {
    privilegedScore += 0.42;
    privilegedReasons.push(`privileged identity ${log.userId} operated outside approved admin windows`);
  }
  if (log.isPrivileged && queryDeviation > 1.8 && !maintenanceWindow) {
    privilegedScore += 0.28;
    privilegedReasons.push(`privileged query volume ran ${(queryDeviation * 100).toFixed(0)}% of baseline`);
  }
  if (log.isPrivileged && log.isExternalIP && !log.isSWIFTCommunication) {
    privilegedScore += 0.24;
    privilegedReasons.push(`privileged activity overlapped with external communications`);
  }

  const burstSession = log.sessionDuration < 120 && log.dbQueryCount > 80;
  const idleTunnel = log.sessionDuration > 2400 && log.dbQueryCount < 3 && flowSignal.score > 0.45;
  const sessionScore = burstSession ? 0.62 : idleTunnel ? 0.42 : 0;
  const upstreamCarry = flowSignal.detected ? flowSignal.score * 0.16 : 0;

  let score = queryScore * 0.46 + clamp(privilegedScore, 0, 1) * 0.32 + sessionScore * 0.16 + upstreamCarry;
  if (maintenanceWindow && !log.isExternalIP) {
    score *= 0.58;
  }

  const detected = score >= 0.52 || (queryScore > 0.55 && flowSignal.detected);
  const delta = percentageDelta(log.queryFrequency, expected.avgQueryRate);
  const reasoningParts: string[] = [];

  if (queryScore > 0.35) {
    reasoningParts.push(
      `query rate ${log.queryFrequency}/min is ${delta.toFixed(0)}% above the ${expected.label} baseline (z=${queryZ.toFixed(2)})`
    );
  }
  if (privilegedReasons.length > 0) {
    reasoningParts.push(...privilegedReasons);
  }
  if (burstSession) {
    reasoningParts.push(`session compressed ${log.dbQueryCount} queries into ${log.sessionDuration}s`);
  }
  if (idleTunnel) {
    reasoningParts.push(`long low-activity session overlaps with suspicious flow timing, consistent with C2 persistence`);
  }
  if (upstreamCarry > 0.08) {
    reasoningParts.push('upstream flow suspicion increased behavioral confidence');
  }

  return {
    agent: 'BEHAVIOR',
    signalType: detected ? 'ANOMALOUS_BEHAVIOR' : 'BEHAVIOR_NOMINAL',
    score: clamp(score, 0, 1),
    confidence: clamp(0.47 + clamp(score, 0, 1) * 0.43 + (detected ? 0.08 : 0), 0.24, 0.95),
    detected,
    features: {
      queryZScore: queryZ,
      queryDeviation,
      privilegedScore: clamp(privilegedScore, 0, 1),
      sessionScore,
      sessionDuration: log.sessionDuration,
      externalFrequency: windowStats.externalIPFrequency,
    },
    correlatedSignals: detected ? ['DB_SPIKE', log.isPrivileged ? 'PRIVILEGED_MISUSE' : 'USER_ACTIVITY'] : [],
    reasoning: detected
      ? `BEHAVIOR AGENT: ${reasoningParts.join('; ')}.`
      : `BEHAVIOR AGENT: Query volume, session timing, and privilege use match the ${expected.label} profile.`,
  };
}
