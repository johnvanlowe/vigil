# Artifacts Storage Slice

## Purpose
Provides immutable, hash-addressed content-addressable storage for evaluation scorecards, attestation reports, exported findings, and evidence blobs.

## Components
- `models.py`: SQLAlchemy `ArtifactModel` mapping SHA-256 hash to payload data and metadata.
- `service.py`: `ArtifactService` offering `put(data)` and `get(sha256)` operations.

## Invariants
- All artifacts are immutable and addressed by their SHA-256 digest (`artifact_hash`).
- Storing duplicate content returns the identical existing hash idempotently.
- Storing an artifact automatically records an auditable `artifact_created` event on the Ledger.

## Testing
Run unit tests:
```bash
pytest -o addopts="" tests/artifacts/test_artifacts.py
```
