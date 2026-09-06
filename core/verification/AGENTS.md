# Verification & Judge Slice

## Purpose
Provides authoritative evaluation of proposed detection candidates and investigation hypotheses against empirical evidence.

## Components
- `judge.py`: `JudgeService` scoring detection candidates across precision, recall, and false positive risk.
- `skills/judge/SKILL.md`: Autonomous agent skill interface for invocation within playbooks.

## Invariants
- Decisions are grounded strictly in replayed telemetry traces and empirical data.
- Emits pass/fail verdicts with structured reasoning and confidence scores.

## Testing
Run unit tests:
```bash
pytest -o addopts="" tests/verification/test_judge.py
```
