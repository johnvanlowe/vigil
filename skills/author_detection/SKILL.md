---
name: author_detection
description: Synthesizes grounded behavioral detection candidates for coverage gaps
schema_version: 1
---

# Detection Authoring Skill (`skill_author_detection`)

## Overview
Given an identified detection gap (missed attack step or model-only signal), synthesizes a typed `DetectionCandidate` in the target format (defaulting to Sigma) grounded in available environment schema fields.

## Constraints & Protocol
- Model-agnostic execution via LLMRouter.
- Enforces strict grounding: no fields outside the environment's known schema.
- Rejects environmental literals (hardcoded IPs, hosts, users, subnets).
- Emits typed artifacts with `environment_id`, source gap, format, body, and rationale.
