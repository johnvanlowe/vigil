# Architecture Decisions: Closed-Loop Detection Defaults (2026-09-05)

This document records the foundational defaults, constraints, and reversal costs established for the Vigil 1.0 closed-loop detection engineering architecture.

---

## Decision 1: Target Environment Scope
- **Decision**: Closed-loop emulation runs strictly against designated non-production environments (TempoRange digital twins or customer ranges). Production environments are strictly out of scope and rejected by safety gates unless an emergency operator override is signed.
- **Reversal Cost**: **High**. Permitting production target execution would require end-to-end blast-radius containment, non-destructive payload constraints, legal waivers, and real-time operational locks across all infrastructure tiers.

---

## Decision 2: Validation Evaluation Mode (Backtest-First)
- **Decision**: In Vigil 1.0, candidates are evaluated via deterministic linting, replay backtest against captured attack telemetry, and independent Judge review. Live-fire re-execution against synthetic variants is supported in test ranges, but candidate promotion requires passing backtest replay and quietness on a non-empty benign baseline.
- **Reversal Cost**: **Low**. Live-fire re-execution in isolated sandbox runners is already architected as a phase and can be made mandatory by policy without breaking the data model.

---

## Decision 3: Promotion Target & Customer-Owned Overlay
- **Decision**: Promoted detection rules are written directly to a customer-owned overlay (`customer_overlay` directory / repository), completely decoupled from upstream vendor detection rules (Sigma HQ, Splunk, Elastic, KQL). Promotion requires explicit human approval or an explicit pre-authorized policy (`Policy(kind=autonomy)`).
- **Automatic Demotion**: If a promoted rule exceeds a defined false-positive threshold in production, it is automatically demoted to candidate/review status with an auditable Ledger event.
- **Reversal Cost**: **Medium**. Changing overlay storage or promotion destinations requires updating the detection indexer and search registries.

---

## Decision 4: Termination & Halt Conditions
- **Decision**: The loop halts immediately upon:
  1. Exhaustion of the per-run or per-campaign dollar budget cap (`max_cost_usd`).
  2. Reaching the maximum cycle threshold (`max_cycles`).
  3. Operator interruption or refusal of an approval checkpoint.
  4. Consecutive zero-gap cycles indicating no viable adversarial paths remain on the current frontier.
- **Reversal Cost**: **Low**. Halt conditions are parameterized in `ClosedLoopConfig` and evaluated per cycle.

---

## Decision 5: Environment Keying (`environment_id`)
- **Decision**: All loop entities (plans, steps, trace records, verdicts, candidates, projections) are keyed by an explicit `environment_id: str`.
- **Reversal Cost**: **High**. Removing or refactoring `environment_id` would break multi-environment isolation, database indices, and Ledger partition queries.

---

## Decision 6: LogLM Seams & Graceful Degradation
- **Decision**: LogLM is integrated at two optional seams:
  1. *Reconstruction*: Classifying steps as `loglm` vs `rule` verdicts.
  2. *Authoring Grounding Assist*: Providing nearest-neighbor anomaly embeddings to author behavioral detection features.
  If LogLM or the LogLM MCP server is unconfigured, the loop degrades gracefully, relying on platform rule catalogs, telemetry schemas, and standard LLM authoring.
- **Reversal Cost**: **Low**. The abstraction decouples LogLM from loop execution logic via protocol boundaries.

---

## Decision 7: ARTEMIS Offensive Engine Packaging
- **Decision**: ARTEMIS is packaged as an external container pinned by image digest and managed via Docker/Kubernetes. The Python codebase does not vendor ARTEMIS code; interaction occurs strictly across the `OffensiveEngine` protocol and the Bifrost LLM gateway with strict no-egress enforcement.
- **Reversal Cost**: **Medium**. Replacing or swapping the offensive execution engine (e.g. to Caldera or custom harness) requires only implementing an adapter satisfying `OffensiveEngine`.

---

## Decision 8: Execution Mode (`run_kind: compose`)
- **Decision**: The closed loop runs under the existing `compose` workflow execution kind rather than introducing a new standalone run kind. Iteration across cycles occurs via re-invocation, preserving pure-fold projections between runs from the append-only Ledger (`agent_events`).
- **Reversal Cost**: **Low**. Introducing a dedicated scheduler or long-running worker daemon would be an additive feature.
