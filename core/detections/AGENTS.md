# Detections Slice

## Purpose
Manages the lifecycle of detection logic from reconstruction and candidate authoring through linting, replay validation, and coverage visualization.

## Components
- `reconstruction.py`: Maps telemetry and trace events to reconstructed attack timelines.
- `authoring.py`: Generates SIEM/Sigma/EQL/LogLM detection rules with test assertions.
- `validation/`: Performs static linting (`lint.py`) and dynamic telemetry replay (`replay.py`).
- `grounding_loglm.py`: Validates LogLM semantic prompt grounding against raw logs.
- `overlay.py` & `coverage.py`: Calculates and updates MITRE ATT&CK coverage matrices.

## Invariants
- Candidates must pass syntax linting and fixture replay before being submitted to the Judge.
- Promoted detections update the database `coverage_view` view with provenance metadata.

## Testing
Run unit tests:
```bash
pytest -o addopts="" tests/detections/
```
