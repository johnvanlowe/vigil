# ARTEMIS Integration Slice

## Purpose
Provides the adapter and contract interfaces for the ARTEMIS offensive simulation engine, enabling automated adversary emulation and telemetry capture.

## Components
- `adapter.py`: Implements `OffensiveEngineAdapter` to interact with ARTEMIS API or simulated sandbox.
- `contract.py`: Shared data classes (`OffensivePlan`, `ExecutionTrace`, `TelemetryBatch`).

## Invariants
- Execution against production environments is strictly prohibited.
- Requires authorized policy (`Policy(kind=offensive)`) and explicit target environment scope.
- Never hardcode credentials; tokens are resolved via Bifrost key management.

## Testing
Run unit tests:
```bash
pytest -o addopts="" tests/integrations/artemis/
```
