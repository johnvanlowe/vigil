/**
 * Scorecard API client for fetching evaluation dryrun results and artifacts.
 */

export interface SOCBenchComparison {
  socbench_baseline_mtta_seconds: number;
  socbench_baseline_containment_rate: number;
  vigil_mtta_seconds: number;
  vigil_containment_rate: number;
  speedup_factor: number;
  notes: string;
}

export interface ScorecardData {
  scenario: string;
  run_id: string;
  disposition: string;
  gates_met: string[];
  elapsed_seconds: number;
  total_tokens: number;
  total_cost_usd: number;
  findings_count: number;
  socbench: SOCBenchComparison;
  artifact_hash?: string;
  provider: string;
  created_at: string;
}

export async function fetchLatestScorecard(): Promise<ScorecardData> {
  const response = await fetch('/api/v1/scorecard');
  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    throw new Error(errorBody.detail || `Failed to fetch scorecard: ${response.statusText}`);
  }
  return response.json();
}

export async function downloadScorecardPdf(artifactHash: string): Promise<void> {
  const response = await fetch(`/api/v1/artifacts/${artifactHash}/download`);
  if (!response.ok) {
    throw new Error(`Failed to download artifact: ${response.statusText}`);
  }
  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `scorecard-${artifactHash.slice(0, 8)}.pdf`;
  document.body.appendChild(a);
  a.click();
  a.remove();
}
