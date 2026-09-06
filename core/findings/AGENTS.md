# Findings & Verdicts Slice

## Purpose
Manages security findings, analyst/agent verdicts, lifecycle stage progression, and exportable JSON verdict archives.

## Components
- `verdicts.py`: Service for recording human and agent verdicts (`true_positive`, `false_positive`, `benign`).
- `lifecycle.py`: State transition engine emitting `stage_completed` events with actor attribution.
- `export.py`: Exports findings and disposition verdicts conforming to `verdict_export_v1.json`.

## Invariants
- Analyst confirmation of an agent verdict records as agent work plus one confirmation event.
- Every verdict and lifecycle change is appended to the immutable Ledger.

## Testing
Run unit tests:
```bash
pytest -o addopts="" tests/findings/
```
