/**
 * Citation replay and evidence query API for Vigil web console.
 */

export interface Citation {
  source: string;
  query: string;
  time_window: string;
  expected_result?: unknown;
}

export async function replayCitationQuery(citation: Citation): Promise<{ events: unknown[]; total: number }> {
  const response = await fetch('/api/v1/evidence/replay', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(citation),
  });

  if (!response.ok) {
    throw new Error(`Failed to replay citation query: ${response.statusText}`);
  }

  return response.json();
}
