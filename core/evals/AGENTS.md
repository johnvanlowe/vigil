# Evaluations Slice

## Purpose
Supports automated benchmarking, unattended dry runs against recorded attack fixtures, and SOCBench performance comparisons.

## Components
- `scorecard.py`: Data structure defining evaluation metrics, gates met, spend, and SOCBench baseline delta.
- `core/cli/dryrun.py`: Unattended evaluator CLI command running incident response fixtures.

## Invariants
- Dry runs execute unattended and emit an immutable scorecard artifact via `ArtifactService`.
- Benchmarks measure MTTA, speedup factor, containment rate, and cost compared to human SOC baselines.

## Testing
Run unit tests:
```bash
pytest -o addopts="" tests/evals/test_dryrun.py
```
