---
name: validate_detection
description: "Deterministic validation harness for detection candidates: lint, replay, and repair budget"
schema_version: 1
---

# Detection Validation Skill (`skill_validate_detection`)

## Overview
Evaluates proposed `DetectionCandidate` objects through deterministic validation gates:
1. **Linting**: Syntactic correctness and anti-brittleness rules (rejects literal IPs, hosts, users, subnets, providing rewrite guidance).
2. **Replay**: Backtests against captured telemetry to ensure target malicious activity is detected.
3. **Repair Budget**: Bounds automated rewrite cycles to prevent infinite looping.
4. **Ledger Audit**: Records each verdict as a `validation_verdict` event (schema v1).
