---
name: reconstruction
description: Correlates red attack steps with security findings to emit detection verdicts
schema_version: 1
---

# Detection Reconstruction Skill (`skill_reconstruct`)

## Overview
Maps observed offensive attack steps from execution telemetry to security detections across rule and model (LogLM) layers, emitting structured `DetectionVerdict` objects (`rule`, `loglm`, `both`, `missed`).

## Protocol
- Cites verifiable evidence queries resolving to telemetry hits.
- Grounds verdicts in the target environment schema.
- Emits schema v1 `reconstruction` events to the Ledger.
