# Vigil Ledger Architecture and Convention (v1.0)

## Overview

The Vigil Ledger (`agent_events` table) is an append-only, durable audit trail recording every state change, verdict, plan, and governance action across all workflows and services.

## Event Schema Convention (v1)

1. **Schema Version**: Every writer appending to `agent_events` MUST include `"schema_version": 1` in the event payload.
2. **Schema Registry**: Every event kind is backed by a formal JSON Schema residing in `data/schemas/ledger/v1/<kind>.json`.
3. **PR Invariant**: Any pull request introducing a new event kind MUST include its corresponding JSON schema definition under `data/schemas/ledger/v1/` in the same PR.
4. **Automated Ratchet**: CI and local unit suites enforce schema presence for all declared and observed event kinds via `tests/ledger/test_schema_ratchet.py`.

## Core Event Kinds (v1.0)

- `reconstruction`: Verdicts mapping offensive attack steps to detections (`rule`, `loglm`, `both`, `missed`).
- `validation_verdict`: Detection candidate validation outcomes from syntax linting, replay backtesting, and Judge evaluation.
- `verdict`: Human or automated disposition on findings (confirm, dismiss, escalate, approve, reject).
- `policy_change`: Changes to governance policies (`tighten` or `loosen`) with mandatory audit attribution.
- `budget_exhausted`: Budget limit reached notification halting agent execution with fail-static posture.
- `promotion`: Promotion of validated detection candidate to customer-owned detection overlay.
- `red_plan`: Generated offensive emulation plan targeting coverage gaps and topology.

## Security and Role Grants

- **Application Role (`vigil_app`)**: Granted `INSERT` and `SELECT` on `agent_events`. No `UPDATE` or `DELETE` permissions are granted, guaranteeing append-only semantics at the database layer.
- **Migration Role (`vigil_admin`)**: Manages schema migrations and role administration.
- **Tamper Evidence**: Transactions compute `event_hash = sha256(prev_hash || canonical(payload))` under PostgreSQL advisory locks, establishing a cryptographically verifiable hash chain verified via `vigil ledger verify`.
