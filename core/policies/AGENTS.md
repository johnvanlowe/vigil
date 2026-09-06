# Policies Slice

## Purpose
Enforces operational governance across autonomy tiers, spending budgets, suppression rules, offensive safety limits, and response SLAs.

## Components
- `schema.py`: Pydantic models for `Policy` validation across all 5 supported kinds.
- `models.py`: SQLAlchemy `PolicyModel` persisting policy definitions and state.
- `service.py`: Policy lifecycle operations emitting auditable `policy_change` events.
- `suppression.py`: Noise suppression rule matching and active window checks.
- `sla.py`: SLA target evaluation and breach calculations.

## Invariants
- Changing any policy requires an authorized role and records actor identity and direction (`tighten`/`loosen`).
- The Ledger records every policy transition with SHA-256 integrity.

## Testing
Run unit tests:
```bash
pytest -o addopts="" tests/policies/
```
