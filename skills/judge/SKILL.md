---
name: judge
description: Fresh-context independent review skill evaluating detection candidates and audit report claims
schema_version: 1
---

# The Judge Skill (`skill_judge`)

## Overview
An isolated, fresh-context review agent operating without contamination from prior authoring or orchestration context. Re-derives key claims, checks behavioral alignment, evaluates anti-brittleness, and independently verifies reproduction of query results.

## Capabilities
1. **Candidate Review**: Evaluates detection candidate rules for behavioral alignment, robustness against evasion, and absence of environment literals.
2. **Report Claim Verification**: Takes key claims and their replayable evidence queries, executes the queries in isolation, and rejects the report if evidence does not reproduce.
3. **Audit & Ledger Logging**: All judge verdicts are appended as durable Ledger events with schema version 1.
