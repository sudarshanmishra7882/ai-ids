export function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

export function mean(values: number[]): number {
  if (values.length === 0) return 0;
  return values.reduce((sum, value) => sum + value, 0) / values.length;
}

export function standardDeviation(values: number[]): number {
  if (values.length < 2) return 0;
  const avg = mean(values);
  const variance = values.reduce((sum, value) => sum + Math.pow(value - avg, 2), 0) / values.length;
  return Math.sqrt(variance);
}

export function zScore(value: number, history: number[]): number {
  if (history.length < 3) return 0;
  const stdDev = standardDeviation(history);
  if (stdDev === 0) return 0;
  return (value - mean(history)) / stdDev;
}

export function percentile(value: number, history: number[]): number {
  if (history.length === 0) return 0;
  const sorted = [...history].sort((a, b) => a - b);
  const lessOrEqual = sorted.filter(item => item <= value).length;
  return lessOrEqual / sorted.length;
}

export function safeRatio(value: number, baseline: number): number {
  if (baseline <= 0) return value > 0 ? value : 0;
  return value / baseline;
}

export function ema(previous: number, current: number, alpha: number): number {
  return previous * (1 - alpha) + current * alpha;
}

export function percentageDelta(value: number, baseline: number): number {
  if (baseline <= 0) return value > 0 ? 100 : 0;
  return ((value - baseline) / baseline) * 100;
}
