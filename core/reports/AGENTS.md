# Reports & Attestation Slice

## Purpose
Generates auditable, deterministic executive reports, source citations, claim verifications, and quarterly CISO attestation packages.

## Components
- `citations.py`: Verifies assertion claims against raw telemetry and finding data.
- `checker.py`: Validates report factual consistency and eliminates unsupported claims.
- `attestation.py`: Compiles quarterly CISO attestation reports folding over the Ledger.

## Invariants
- Attestation reports over identical timeframes are 100% deterministic (reproducible SHA-256 hash).
- Generated reports are persisted as hash-addressed artifacts via `ArtifactService`.

## Testing
Run unit tests:
```bash
pytest -o addopts="" tests/reports/
```
