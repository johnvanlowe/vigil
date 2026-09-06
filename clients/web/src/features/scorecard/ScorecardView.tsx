import { useEffect, useState } from 'react';
import { fetchLatestScorecard, downloadScorecardPdf, type ScorecardData } from './api';

export default function ScorecardView() {
  const [scorecard, setScorecard] = useState<ScorecardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);

  useEffect(() => {
    fetchLatestScorecard()
      .then((data) => {
        setScorecard(data);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message || 'Failed to load scorecard');
        setLoading(false);
      });
  }, []);

  const handleExport = async () => {
    if (!scorecard?.artifact_hash) return;
    try {
      setExporting(true);
      await downloadScorecardPdf(scorecard.artifact_hash);
    } catch (err: any) {
      alert(`Export failed: ${err.message}`);
    } finally {
      setExporting(false);
    }
  };

  if (loading) {
    return (
      <div style={{ padding: '32px', color: '#888' }}>
        <h2>Loading evaluation scorecard...</h2>
      </div>
    );
  }

  if (error || !scorecard) {
    return (
      <div style={{ padding: '32px', color: '#ff5555' }}>
        <h2>Evaluation Scorecard Error</h2>
        <p>{error || 'No scorecard available. Run `./start.sh --dryrun` first.'}</p>
      </div>
    );
  }

  const { socbench } = scorecard;

  return (
    <div style={{ padding: '28px', maxWidth: '1000px', margin: '0 auto', color: '#e0e0e0' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <div>
          <h1 style={{ margin: '0 0 8px 0', fontSize: '24px', fontWeight: 600 }}>
            Evaluation Scorecard: <span style={{ color: '#64b5f6' }}>{scorecard.scenario}</span>
          </h1>
          <div style={{ fontSize: '13px', color: '#aaa' }}>
            Run ID: <code>{scorecard.run_id}</code> | Executed: {new Date(scorecard.created_at).toLocaleString()}
          </div>
        </div>
        <div>
          <button
            onClick={handleExport}
            disabled={exporting || !scorecard.artifact_hash}
            style={{
              padding: '8px 18px',
              backgroundColor: '#1976d2',
              color: '#fff',
              border: 'none',
              borderRadius: '4px',
              cursor: exporting ? 'not-allowed' : 'pointer',
              fontWeight: 500,
            }}
          >
            {exporting ? 'Exporting...' : 'Export as PDF'}
          </button>
        </div>
      </div>

      {/* Metrics Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginBottom: '28px' }}>
        <div style={{ background: '#1e222b', padding: '16px', borderRadius: '6px', border: '1px solid #2d3342' }}>
          <div style={{ fontSize: '12px', color: '#8b949e', textTransform: 'uppercase' }}>Disposition</div>
          <div style={{ fontSize: '18px', fontWeight: 600, color: '#4caf50', marginTop: '4px' }}>
            {scorecard.disposition.replace(/_/g, ' ')}
          </div>
        </div>
        <div style={{ background: '#1e222b', padding: '16px', borderRadius: '6px', border: '1px solid #2d3342' }}>
          <div style={{ fontSize: '12px', color: '#8b949e', textTransform: 'uppercase' }}>Elapsed Time</div>
          <div style={{ fontSize: '18px', fontWeight: 600, color: '#fff', marginTop: '4px' }}>
            {scorecard.elapsed_seconds.toFixed(1)}s
          </div>
        </div>
        <div style={{ background: '#1e222b', padding: '16px', borderRadius: '6px', border: '1px solid #2d3342' }}>
          <div style={{ fontSize: '12px', color: '#8b949e', textTransform: 'uppercase' }}>Total Tokens / Spend</div>
          <div style={{ fontSize: '18px', fontWeight: 600, color: '#fff', marginTop: '4px' }}>
            {scorecard.total_tokens.toLocaleString()} (${scorecard.total_cost_usd.toFixed(4)})
          </div>
        </div>
        <div style={{ background: '#1e222b', padding: '16px', borderRadius: '6px', border: '1px solid #2d3342' }}>
          <div style={{ fontSize: '12px', color: '#8b949e', textTransform: 'uppercase' }}>Findings Investigated</div>
          <div style={{ fontSize: '18px', fontWeight: 600, color: '#fff', marginTop: '4px' }}>
            {scorecard.findings_count}
          </div>
        </div>
      </div>

      {/* Gates Met */}
      <div style={{ background: '#1e222b', padding: '20px', borderRadius: '6px', border: '1px solid #2d3342', marginBottom: '28px' }}>
        <h3 style={{ margin: '0 0 12px 0', fontSize: '16px' }}>Quality & Verification Gates Passed</h3>
        <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
          {scorecard.gates_met.map((gate) => (
            <span
              key={gate}
              style={{
                backgroundColor: '#1b3a24',
                color: '#4caf50',
                border: '1px solid #2e7d32',
                padding: '4px 12px',
                borderRadius: '16px',
                fontSize: '13px',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
              }}
            >
              ✓ {gate}
            </span>
          ))}
        </div>
      </div>

      {/* SOCBench Baseline Comparison */}
      <div style={{ background: '#1e222b', padding: '20px', borderRadius: '6px', border: '1px solid #2d3342', marginBottom: '28px' }}>
        <h3 style={{ margin: '0 0 8px 0', fontSize: '16px' }}>SOCBench Benchmark Comparison</h3>
        <p style={{ margin: '0 0 16px 0', fontSize: '13px', color: '#8b949e' }}>{socbench.notes}</p>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '14px' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid #3b4252', color: '#8b949e', textAlign: 'left' }}>
              <th style={{ padding: '8px 12px' }}>Evaluation Metric</th>
              <th style={{ padding: '8px 12px' }}>Vigil (Autonomous)</th>
              <th style={{ padding: '8px 12px' }}>SOCBench Human Baseline</th>
              <th style={{ padding: '8px 12px' }}>Advantage</th>
            </tr>
          </thead>
          <tbody>
            <tr style={{ borderBottom: '1px solid #282e3d' }}>
              <td style={{ padding: '10px 12px' }}>Mean Time to Acknowledge (MTTA)</td>
              <td style={{ padding: '10px 12px', color: '#64b5f6', fontWeight: 600 }}>{socbench.vigil_mtta_seconds}s</td>
              <td style={{ padding: '10px 12px' }}>{socbench.socbench_baseline_mtta_seconds}s</td>
              <td style={{ padding: '10px 12px', color: '#4caf50' }}>{socbench.speedup_factor}x faster</td>
            </tr>
            <tr>
              <td style={{ padding: '10px 12px' }}>Containment & Triage Rate</td>
              <td style={{ padding: '10px 12px', color: '#64b5f6', fontWeight: 600 }}>{(socbench.vigil_containment_rate * 100).toFixed(0)}%</td>
              <td style={{ padding: '10px 12px' }}>{(socbench.socbench_baseline_containment_rate * 100).toFixed(0)}%</td>
              <td style={{ padding: '10px 12px', color: '#4caf50' }}>+{((socbench.vigil_containment_rate - socbench.socbench_baseline_containment_rate) * 100).toFixed(0)}% gain</td>
            </tr>
          </tbody>
        </table>
      </div>

      {/* Artifact Verification Footer */}
      {scorecard.artifact_hash && (
        <div style={{ fontSize: '12px', color: '#888', borderTop: '1px solid #2d3342', paddingTop: '16px' }}>
          Immutable Artifact SHA-256:{' '}
          <code style={{ color: '#ffb74d', wordBreak: 'break-all' }}>{scorecard.artifact_hash}</code>
        </div>
      )}
    </div>
  );
}
