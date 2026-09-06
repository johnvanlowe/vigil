/**
 * Verdicts API client for Vigil web console.
 * Every user action (confirm, dismiss, escalate, approve, reject) calls recordVerdict.
 */

export type VerdictAction = 'confirm' | 'dismiss' | 'escalate' | 'edit_severity' | 'approve' | 'reject';

export interface RecordVerdictPayload {
  finding_id: string;
  action: VerdictAction;
  actor: string;
  reason?: string;
  source?: string;
  new_severity?: string;
  loglm_provenance?: Record<string, unknown>;
  attack_mapping?: Array<Record<string, unknown>>;
  run_id?: string;
}

export async function recordVerdict(payload: RecordVerdictPayload): Promise<{ status: string; verdict: unknown }> {
  if ((payload.action === 'dismiss' || payload.action === 'reject') && (!payload.reason || !payload.reason.trim())) {
    throw new Error(`Reason is strictly required for action ${payload.action}`);
  }

  const response = await fetch('/api/v1/verdicts', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      ...payload,
      source: payload.source || 'ui',
    }),
  });

  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    throw new Error(errorBody.detail || `Failed to record verdict: ${response.statusText}`);
  }

  return response.json();
}
