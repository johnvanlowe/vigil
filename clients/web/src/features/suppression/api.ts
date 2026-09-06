/**
 * Suppression candidates and policy promotion API client for Vigil.
 */

export interface SuppressionCandidate {
  match_reason: string;
  dismissal_count: number;
  last_dismissed_at: string;
  sample_finding_id?: string;
}

export async function fetchSuppressionCandidates(): Promise<SuppressionCandidate[]> {
  const response = await fetch('/api/v1/findings/suppression-candidates');
  if (!response.ok) {
    throw new Error('Failed to fetch suppression candidates');
  }
  return response.json();
}

export async function promoteSuppression(
  matchPattern: string,
  reason: string,
  ttlSeconds: number,
  promotedBy: string
): Promise<{ status: string; policy_id: string }> {
  const response = await fetch('/api/v1/policies/suppression', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      match_pattern: matchPattern,
      reason,
      ttl_seconds: ttlSeconds,
      promoted_by: promotedBy,
    }),
  });

  if (!response.ok) {
    throw new Error('Failed to promote suppression policy');
  }
  return response.json();
}
