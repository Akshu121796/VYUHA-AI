const CRITICALITY_WEIGHT: Record<string, number> = {
  low: 1.0,
  medium: 1.15,
  high: 1.3,
  critical: 1.5,
};

export function calculateRiskScore(
  cvssScore: number | undefined,
  criticality: string,
  isKev: boolean
): number {
  const base = cvssScore ?? 0;
  const weight = CRITICALITY_WEIGHT[criticality?.toLowerCase()] ?? 1.0;
  let score = base * weight;
  if (isKev) {
    score = Math.min(score * 1.4, 10.0);
  }
  return Math.round(Math.min(score, 10.0) * 100) / 100;
}