# Red Planner Agent Slice

## Purpose
Specialized planning agent responsible for synthesizing MITRE ATT&CK adversary execution plans, prioritizing unverified detection coverage gaps.

## Components
- `planner.py`: Implements `RedTeamPlanner` generating deterministic or LLM-augmented adversary plans.
- `__init__.py`: Package export interface.

## Invariants
- Operates strictly within assigned budget and rate constraints.
- Output plans conform to `OffensivePlan` schema with explicit technique IDs and rollback procedures.
- Every generated plan emits a `stage_completed` event to the Ledger.

## Testing
Run unit tests:
```bash
pytest -o addopts="" tests/agents/test_red_planner.py
```
