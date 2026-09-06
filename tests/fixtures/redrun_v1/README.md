# TempoRange Red Run Fixture (redrun_v1)

## Overview
This fixture captures an authorized adversarial emulation run executed against the **TempoRange** synthetic digital twin environment using the ARTEMIS offensive engine with LLM reasoning routed through Bifrost.

## Execution Details
- **Environment**: `temporange` (isolated network twin, non-production)
- **Virtual Key**: Bifrost rate bucket `temporange-artemis-eval`
- **Techniques Emulated**:
  - `T1059.001`: PowerShell script execution
  - `T1003.001`: LSASS memory dump
  - `T1021.001`: Remote Desktop protocol lateral movement
  - `T1486`: Data encryption simulation
- **Reconstruction Output**:
  - Full per-step verdicts (`rule`, `loglm`, `both`, `missed`)
  - Candidates authored for detected gaps and validated through lint, replay, and judge gates
  - Promotion recorded in append-only Ledger under run `redrun_v1`
- **Anonymization**:
  - All internal hostnames normalized to generic targets (`srv-app-01`, `dc-01`, `ws-01`)
  - IP addresses mapped to RFC 1918 blocks (`10.10.x.x`)
  - Credentials and tokens scrubbed
