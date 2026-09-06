# Vigil 1.0 issues, paste-ready

**Repository:** `johnvanlowe/vigil`  ·  **Target branch:** `feat/vigil-closed-loop`  ·  **Milestone:** `v1.0.0`  ·  **Date:** Saturday, September 5, 2026

48 issues. This file is the same set `file-issues.sh` would create, in plain text, so any can be pasted into GitHub by hand. Each block gives the **title**, the **labels** to apply, and the **body** to paste. Format is my best estimate of the Vigil house style (grading preamble, Context with file citations, Acceptance checklist, Files, Blocked-by); it is not confirmed against the software factory's trigger. See the two notes below before filing.

---

## Before you file: two unknowns

1. **Factory trigger.** These carry `wave:*`, `lane:*`, `area:*`, `type:*` labels and the `v1.0.0` milestone. They do **not** carry a `factory:*` label, because the exact value that starts a factory run is unknown to me. If your factory keys on a label (for example `factory:ready`), an assignee, or a board column, add that signal or the issues will sit unread. One line to fix once you know it.  
2. **Where they live.** John's fork has Issues disabled. Enable it (Settings, General, Features, Issues) to file here, or file on `Vigil-SOC/vigil` and keep the Target-branch line so PRs still land on the branch.

**Order matters.** File and merge Wave 0 first; those are the contracts every Wave 1 issue writes against. Fire Wave 1 after Wave 0 merges. Wave 2 issues name the Wave 1 merge they need. Blocked-by lines below encode the dependencies.

**Loop lane note.** John's branch already has the loop scaffold. The loop issues below are written as build-from-scratch; before filing them, reconcile against `06-branch-review.md`, which lists what is already present and rewrites the loop lane as make-real-plus-tests. File the non-loop lanes as-is.

---

## Contents

**Wave 0** (6)

1. feat(ledger): event schema v1 and schema\_version convention  
   2. feat(loop): contract types for OffensiveEngine, AttackStep, DetectionVerdict, DetectionCandidate, ValidationRecord  
   3. feat(policies): single Policy model with kind enum  
   4. docs(metrics): metric names contract v1  
   5. docs(decisions): closed-loop defaults recorded (environment, live-fire, promotion target, halt, environment\_id, LogLM seams, ARTEMIS packaging, run kind)  
   6. feat(db): Alembic baseline at 0.5.0

**Wave 1** (36)

7. feat(integrations): ARTEMIS adapter behind OffensiveEngine, Bifrost-only, own virtual key  
   8. feat(agents): red planning role reading coverage gaps, topology, and LogLM history  
   9. feat(skills): reconstruction skill mapping attack steps to detection verdicts  
   10. feat(skills): authoring skill producing DetectionCandidate through LLMRouter  
   11. feat(detections): validation harness: lint (no IP/host/user/subnet literals), replay, repair budget  
   12. feat(skills): the Judge: fresh-context independent review skill (shared by detection validation and report checker)  
   13. feat(loglm): LogLM-grounded authoring for model-only gaps  
   14. feat(agents): author-or-defer checkpoint, up front policy and in-loop, gated by Policy(kind=autonomy)  
   15. feat(detections): promotion writes to a customer-owned overlay; automatic demotion above FP threshold  
   16. feat(database): coverage SQL view over reconstruction events with per-cycle missed count (the frontier)  
   17. test(loop): recorded red-run fixture (stub trace \+ telemetry) shared by tests and the dry run  
   18. feat(ledger): application role INSERT and SELECT only on agent\_events  
   19. feat(ledger): prev\_hash and event\_hash in the advisory-locked transaction; vigil ledger verify  
   20. feat(policies): policies table; migrate approval thresholds to Policy rows; changes are Ledger events  
   21. feat(artifacts): hash-addressed artifacts table; scorecards and reports write through it  
   22. feat(verdicts): canonical record\_verdict; every UI action emits a verdict event; reason required on dismiss and reject  
   23. feat(verdicts): suppression\_candidates view; promote button writes Policy(kind=suppression) with TTL; daemon honors it  
   24. feat(verdicts): vigil verdicts export \--since writes JSONL with anonymity filter  
   25. feat(reporter): evidence citations required to render final; citation resolves to a replayable query  
   26. feat(reports): report checker gate on hunt reports via skill\_judge  
   27. feat(responder): typed Action with confidence, blast radius, reversibility class, rollback plan, idempotency key  
   28. feat(metrics): Prometheus /metrics on api, daemon, worker against docs/metrics.md  
   29. feat(grafana): AI SOC health dashboard JSON and alert rules  
   30. feat(daemon): Policy(kind=budget) enforcement with fail-static degrade; budget\_exhausted event and metric  
   31. feat(auth): DEV\_MODE false in release images; dev clone keeps bypass behind a flag with a banner  
   32. feat(auth): forced credential rotation on first login; roles admin/analyst/viewer enforced at the route layer  
   33. ci(release): cosign-signed images  
   34. docs(security): supported versions and disclosure SLA  
   35. test(api): OpenAPI snapshot test on /api/v1  
   36. feat(workflows): WORKFLOW.md and SKILL.md frontmatter JSON Schema validation (warn in 1.0, fail in 2.0)  
   37. docs: deprecation policy  
   38. feat(dryrun): vigil dryrun runs incident response unattended against the recorded fixture and emits a scorecard artifact  
   39. docs(1.0): install in ten minutes, headless and MCP, policies, metrics, contributing; AGENTS.md per touched slice; persona-to-workflow map  
   40. feat(metrics): CISO series: work share by actor, throughput, MTTA/MTTD/MTTR, effectiveness, hours-returned estimate  
   41. feat(policies): Policy(kind=sla) with per-severity MTTA/MTTR/disposition targets and baseline minutes; breach counter  
   42. feat(grafana): CISO view dashboard

**Wave 2** (6)

43. feat(reports): vigil attest \--quarter writes the CISO attestation as a hash-addressed artifact  
    44. feat(workflows): closed-loop Playbook composing red planner, engine, reconstruction, authoring, validation, judge, promotion  
    45. ops(loop): first live red run in TempoRange; captured trace replaces the fixture  
    46. feat(dryrun): ./start.sh \--dryrun wrapper and scorecard view in the UI  
    47. feat(helm): HPA on the worker; external Postgres and Redis; 0.5 to 1.0 upgrade runbook  
    48. sec(rc1): security review: SSRF on provider URLs, prompt injection through tool results, desktop bundle secrets, dependency audit

---

# Wave 0

*Contracts. Merge before Wave 1 is fired.*

## 1\. feat(ledger): event schema v1 and schema\_version convention

**Labels:** `wave:0` `lane:contracts` `area:database` `area:architecture` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: small · Vigil context: Ledger · Lane: contracts · Good for: factory, one reviewer

**Context.** `agent_events` (run\_id, seq) is the substrate every 1.0 feature appends to. Six new event kinds land this week (reconstruction, validation\_verdict, verdict, policy\_change, budget\_exhausted, promotion). Without a published schema each PR invents its own payload shape. This PR is types and docs only; no behavior.

**Acceptance**

- [ ] `data/schemas/ledger/v1/` holds one JSON Schema per event kind, including the six new kinds, each with `schema_version: 1`  
- [ ] `docs/ledger.md` states the convention: every writer sets `schema_version`; new kinds need a schema file in the same PR  
- [ ] A ratchet test fails if an event kind is appended without a schema entry

**Files:** `data/schemas/ledger/v1/*.json`, `docs/ledger.md`, `tests/ledger/test_schema_ratchet.py` **Blocked by:** none. **Blocks:** every Wave 1 issue that appends events.

---

## 2\. feat(loop): contract types for OffensiveEngine, AttackStep, DetectionVerdict, DetectionCandidate, ValidationRecord

**Labels:** `wave:0` `lane:contracts` `area:integrations` `area:detections` `area:architecture` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: small · Vigil context: closed-loop design (Sep 4\) · Lane: contracts · Good for: factory

**Context.** The red/blue loop has three halves (red, reconstruction, authoring) that communicate through four typed objects named in the design. Publishing them first lets the adapter, planner, reconstruction, authoring, validation, coverage view, and dry-run scorecard be written in parallel. Types only.

**Acceptance**

- [ ] `OffensiveEngine` Protocol: `run(plan: RedPlan) -> RedRunResult` with action trace and captured telemetry references  
- [ ] Pydantic: `RedPlan`, `AttackStep`, `DetectionVerdict` (`rule | loglm | both | missed`, evidence citations), `DetectionCandidate`, `ValidationRecord` (lint, replay, judge, repair history)  
- [ ] `environment_id: str` on every object that is per environment  
- [ ] No behavior, no imports of any concrete engine

**Files:** `core/integrations/offensive/contract.py`, `core/detections/candidates.py`, `tests/loop/test_contract_types.py` **Blocked by:** none. **Blocks:** all lane:loop issues.

---

## 3\. feat(policies): single Policy model with kind enum

**Labels:** `wave:0` `lane:contracts` `area:architecture` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: small · Vigil context: approval domain thresholds · Lane: contracts · Good for: factory

**Context.** Governance decisions (autonomy tier per action class, budget caps, suppression rules, offensive authorization) are today scattered as settings and flags. One object with a `kind` enum gives them a stable identity and one Ledger event on change. Types only; the table and migration are a Wave 1 issue.

**Acceptance**

- [ ] `Policy` Pydantic model: `id`, `kind` in {autonomy, budget, suppression, offensive}, `scope` (action class, run\_kind, match, or environment\_id), `params: dict`, `ttl`, `promoted_by`, `created_at`  
- [ ] `PolicyChange` event payload with `direction` in {tighten, loosen}  
- [ ] Docstring states the ratchet: loosen requires a human actor and records a dwell

**Files:** `core/policies/schema.py`, `tests/policies/test_schema.py` **Blocked by:** ledger schema v1. **Blocks:** policies table, budget enforcement, suppression promotion, author-or-defer gates.

---

## 4\. docs(metrics): metric names contract v1

**Labels:** `wave:0` `lane:contracts` `area:observability` `type:docs`  ·  **Milestone:** `v1.0.0`

Coding: none · Lane: contracts · Good for: anyone

**Context.** The `/metrics` endpoint, the Grafana dashboard, HPA values, and alert rules are all written against the same series names. Agreeing on names first lets all four proceed in parallel. Draft attached to the plan; this issue lands it in-tree.

**Acceptance**

- [ ] `docs/metrics.md` lists every series with type, labels, and meaning, plus the six shipped alert rules  
- [ ] Names follow `vigil_` prefix, base units, `_total` on counters

**Files:** `docs/metrics.md` **Blocked by:** none. **Blocks:** /metrics endpoint, Grafana dashboard, budget enforcement metrics.

---

## 5\. docs(decisions): closed-loop defaults recorded (environment, live-fire, promotion target, halt, environment\_id, LogLM seams, ARTEMIS packaging, run kind)

**Labels:** `wave:0` `lane:contracts` `area:architecture` `type:docs`  ·  **Milestone:** `v1.0.0`

Coding: none · Lane: contracts · Good for: maintainers

**Context.** The Sep 4 design lists eight decisions that change the shape of the build. Each gets a default and a stated reversal cost so Wave 1 can start tonight.

**Acceptance**

- [ ] `docs/decisions/2026-09-05-loop-defaults.md` records: TempoRange / customer range, production out of scope; backtest-only in 1.0; promotion writes a customer-owned overlay, human or pre-authorized promotion, automatic demotion above an FP threshold; halt on budget cap, cycle cap, operator stop; `environment_id` string key; LogLM-optional seams are grounding assist and reconstruction verdict only; ARTEMIS as an external container pinned by digest; loop runs under `compose` with offensive tools approval-gated  
- [ ] Each entry names its reversal cost

**Files:** `docs/decisions/2026-09-05-loop-defaults.md` **Blocked by:** none. **Blocks:** ARTEMIS adapter shape, promotion write target.

---

## 6\. feat(db): Alembic baseline at 0.5.0

**Labels:** `wave:0` `lane:record` `area:database` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: small · Vigil context: `infra/` DB init · Lane: record · Good for: factory

**Context.** Four migrations land this week (grants, hash columns, policies, artifacts). They must apply in order on top of a baseline that matches 0.5.0. This is the first PR in the migration lane; the others rebase on it.

**Acceptance**

- [ ] Alembic configured; baseline revision reflects the 0.5.0 schema exactly (autogenerate diff is empty against a 0.5.0 database)  
- [ ] CI job restores a 0.5.0 dump and runs `alembic upgrade head`  
- [ ] `docs/upgrade.md` explains the migration path

**Files:** `infra/migrations/`, `alembic.ini`, `.github/workflows/migrate.yml`, `docs/upgrade.md` **Blocked by:** none. **Blocks:** grants, hash chain, policies table, artifacts table (serialized in that order).

---

# Wave 1

*Fire together after Wave 0 merges.*

## 7\. feat(integrations): ARTEMIS adapter behind OffensiveEngine, Bifrost-only, own virtual key

**Labels:** `wave:1` `lane:loop` `area:integrations` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: medium · Vigil context: closed-loop design §1, Vendor Slices · Lane: loop · Good for: factory \+ senior review

**Context.** ARTEMIS is driven by `python -m supervisor.supervisor --config-file <plan>.yaml`, runs Codex-based sub-agents that are OpenAI-compatible clients, and writes persistent per-run logs. The adapter compiles a `RedPlan` to that YAML, points the sub-agents at `${BIFROST_URL}/v1`, launches the pinned container, and returns the logs as the action trace. Unconfigured means absent.

**Acceptance**

- [ ] Satisfies `OffensiveEngine`; selected by config; `integrations.artemis.enabled` defaults false  
- [ ] Startup check fails the run if the sub-agents' base URL is not Bifrost (no-egress enforced, not assumed)  
- [ ] Uses a dedicated Bifrost virtual key on its own rate bucket; ARTEMIS retry set conservatively  
- [ ] Container pinned by digest; never vendored  
- [ ] Contract test passes against a stub engine, proving the loop is not ARTEMIS-bound  
- [ ] Plan and every executed step appended as Ledger events (schema v1)

**Files:** `core/integrations/artemis/{descriptor.py,adapter.py,tool.py}`, `tests/integrations/artemis/` **Blocked by:** loop contract types; loop decisions. **Do not touch:** `RUN_KINDS`, `core/llm/router`.

---

## 8\. feat(agents): red planning role reading coverage gaps, topology, and LogLM history

**Labels:** `wave:1` `lane:loop` `area:agents` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: medium · Vigil context: hunt lead arch (`threathunt.yaml`) · Lane: loop · Good for: factory

**Context.** An uninformed red plan wastes budget on covered techniques. The planner reads `detections.identify_gaps`, MITRE Analyst coverage, VStrike topology from `entity_context`, and a LogLM summary of what has been anomalous here, and emits a `RedPlan` in ATT\&CK terms biased toward the seams. Runs as a phase in a Compose Playbook; no new run kind.

**Acceptance**

- [ ] Emits `RedPlan` against the contract, never ARTEMIS specifics  
- [ ] Plan cites gap analysis and topology inputs; appended to `agent_events`  
- [ ] Behavior tests on context assembly (gaps present vs absent, LogLM present vs absent)  
- [ ] Offensive tools are approval-gated; execution is stop/pause by default

**Files:** `core/agents/red_planner/`, `tests/agents/test_red_planner.py` **Blocked by:** loop contract types. Parallel with the ARTEMIS adapter.

---

## 9\. feat(skills): reconstruction skill mapping attack steps to detection verdicts

**Labels:** `wave:1` `lane:loop` `area:detections` `area:skills` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: medium · Lane: loop · Good for: factory

**Context.** Reads a red action trace and the Findings the attack produced (including the `loglm` schema path), correlates each `AttackStep` to Findings, queries which rules matched, and emits a `DetectionVerdict` per step: rule, loglm, both, missed. Enumerates available sources and fields first so no verdict rests on a field the environment does not emit.

**Acceptance**

- [ ] One reconstruction event per step, schema v1, with evidence citations that resolve to replayable queries  
- [ ] `loglm` is a distinct verdict from `rule`; report separates the layers  
- [ ] Regression test on `missed` classification against the recorded fixture  
- [ ] Ships as an importable SKILL.md bundle exposed as `skill_reconstruct`

**Files:** `skills/reconstruction/SKILL.md`, `core/detections/reconstruction.py`, `tests/detections/test_reconstruction.py` **Blocked by:** loop contract types; recorded fixture (parallel; use a minimal inline trace until it lands).

---

## 10\. feat(skills): authoring skill producing DetectionCandidate through LLMRouter

**Labels:** `wave:1` `lane:loop` `area:detections` `area:skills` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: medium · Lane: loop · Good for: factory

**Context.** Given a gap (missed, or loglm-only where a portable rule is wanted), produce a `DetectionCandidate` in the target format (Sigma first) grounded in the format schema and the environment's available fields. A dedicated authoring role: tight prompt, narrow grants, separated from orchestration. Model-agnostic via LLMRouter.

**Acceptance**

- [ ] Skill imports as SKILL.md and appears as `skill_author_detection`  
- [ ] Candidate is a typed artifact with `environment_id`, source gap, format, body, rationale  
- [ ] Given format schema and field list as grounding; emits no unsupported field  
- [ ] Deactivating the skill removes the capability with no core residue

**Files:** `skills/author_detection/SKILL.md`, `core/detections/authoring.py`, `tests/detections/test_authoring.py` **Blocked by:** loop contract types.

---

## 11\. feat(detections): validation harness: lint (no IP/host/user/subnet literals), replay, repair budget

**Labels:** `wave:1` `lane:loop` `area:detections` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: medium · Lane: loop · Good for: factory

**Context.** Two of NVIDIA's six mechanisms as deterministic gates. Lint rejects syntax errors and any candidate keyed to a specific IP, host, user, or subnet, returning rewrite guidance. Replay runs the candidate against the captured attack telemetry; no match means rejection. Repairs are bounded by the existing budget mechanism. The independent review is the separate Judge skill.

**Acceptance**

- [ ] Candidate keyed to a literal host is rejected with rewrite guidance (regression test)  
- [ ] Candidate matching no captured activity is rejected (regression test)  
- [ ] Every verdict is a `ValidationRecord` and a Ledger event; repair attempts stop at the budget  
- [ ] Ships as `skill_validate_detection`

**Files:** `skills/validate_detection/SKILL.md`, `core/detections/validation/{lint.py,replay.py}`, `tests/detections/test_validation.py` **Blocked by:** loop contract types; recorded fixture.

---

## 12\. feat(skills): the Judge: fresh-context independent review skill (shared by detection validation and report checker)

**Labels:** `wave:1` `lane:loop` `lane:show-the-work` `area:agents` `area:skills` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: medium · Vigil context: hunt critic · Lane: loop and show-the-work · Good for: factory \+ senior review

**Context.** NVIDIA's independent review and the report checker from the detection-engineering design are the same pattern: a fresh-context role, isolated from the producing run's context, that re-derives key claims and rejects what does not hold. Build it once as a skill with two input shapes (a `DetectionCandidate`, or a report with its claims and queries) so both callers land in parallel.

**Acceptance**

- [ ] `skill_judge` accepts a candidate and returns behavioral alignment, robustness, multi-signal verdict  
- [ ] `skill_judge` accepts a report and re-runs the queries behind each key claim in context isolation via a separate LLM call; rejects if results do not reproduce (seeded fabricated-claim test)  
- [ ] Runs through LLMRouter; its cost is metered as its own run\_kind  
- [ ] Verdicts are Ledger events

**Files:** `skills/judge/SKILL.md`, `core/verification/judge.py`, `tests/verification/test_judge.py` **Blocked by:** loop contract types; ledger schema v1.

---

## 13\. feat(loglm): LogLM-grounded authoring for model-only gaps

**Labels:** `wave:1` `lane:loop` `area:detections` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: medium · Vigil context: pgvector `nearest_neighbors`, LogLM MCP · Lane: loop · Good for: factory

**Context.** When LogLM flagged a step no rule caught, the embedding neighborhood of the anomalous Finding tells the authoring agent which behavioral features separated attack from normal. That is exactly the signal the anti-brittleness lint demands. This is LogLM's most important job in the loop and one of its two optional seams.

**Acceptance**

- [ ] For a `loglm`\-only verdict, the candidate's features derive from the neighborhood, not environment literals; clears the behavioral lint (test)  
- [ ] When the LogLM MCP is absent, authoring proceeds without the grounding assist and says so in the rationale (test)

**Files:** `core/detections/grounding_loglm.py`, `tests/detections/test_grounding_loglm.py` **Blocked by:** authoring skill (parallel-safe: implement against its interface).

---

## 14\. feat(agents): author-or-defer checkpoint, up front policy and in-loop, gated by Policy(kind=autonomy)

**Labels:** `wave:1` `lane:loop` `area:agents` `area:response` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: small · Vigil context: checkpoint/resolution machinery · Lane: loop · Good for: factory

**Context.** For each gap the operator chooses author, defer, or accept with a reason, either as a run-level policy or per gap at a checkpoint. Promotion into the live set is human-granted or pre-authorized. Every choice is a recorded verdict event.

**Acceptance**

- [ ] In-loop gap raises a checkpoint answered by a resolution; the resolution is a verdict event with `action` in {author, defer, accept\_gap} and a reason  
- [ ] Up-front `Policy(kind=autonomy)` auto-authors above threshold and records the decision  
- [ ] Promotion is a recorded, human-granted (or pre-authorized) event

**Files:** `core/agents/loop_checkpoints.py`, `tests/agents/test_author_or_defer.py` **Blocked by:** Policy model; loop contract types.

---

## 15\. feat(detections): promotion writes to a customer-owned overlay; automatic demotion above FP threshold

**Labels:** `wave:1` `lane:loop` `area:detections` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: small · Lane: loop · Good for: factory

**Context.** Per the decisions doc: promoted detections go to a customer-owned overlay separate from upstream Sigma/Splunk/Elastic/KQL corpora. Promotion is human or pre-authorized. Demotion of a promoted rule that turns noisy is automatic above a false-positive threshold, the one permitted self-demotion.

**Acceptance**

- [ ] Overlay source registered in the detections domain; `search_detections` and coverage include it  
- [ ] `promote(candidate)` requires a human actor or a matching policy; writes a promotion event  
- [ ] A promoted rule exceeding the FP threshold is demoted with a Ledger event (test)

**Files:** `core/detections/overlay.py`, `tests/detections/test_overlay.py` **Blocked by:** loop decisions; validation harness (interface only).

---

## 16\. feat(database): coverage SQL view over reconstruction events with per-cycle missed count (the frontier)

**Labels:** `wave:1` `lane:loop` `area:database` `area:detections` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: small · Vigil context: Projections folded on read; \#727 · Lane: loop · Good for: factory

**Context.** Per environment: what has been attacked, coverage per technique by layer, open gaps with reasons, and missed steps per cycle. Computed on read, never stored. A SQL view is enough for 1.0; align column names with the episodic-memory epic rather than duplicating it.

**Acceptance**

- [ ] `coverage` view over `agent_events` reconstruction and promotion payloads, keyed by `environment_id`  
- [ ] Replay from the Ledger reproduces the view exactly (test)  
- [ ] Frontier (missed per cycle) exposed for `/metrics` and the scorecard

**Files:** `infra/migrations/<n>_coverage_view.py`, `core/detections/coverage.py`, `tests/detections/test_coverage_view.py` **Blocked by:** Alembic baseline; loop contract types. Coordinate with \#727.

---

## 17\. test(loop): recorded red-run fixture (stub trace \+ telemetry) shared by tests and the dry run

**Labels:** `wave:1` `lane:loop` `lane:evals` `area:detections` `type:test`  ·  **Milestone:** `v1.0.0`

Coding: small · Lane: loop and evals · Good for: factory

**Context.** Code across the loop and the dry run needs one realistic recorded red run before the first live one exists. Build a stub engine that emits a deterministic multi-step trace (recon, lateral movement, exfil) with matching telemetry rows, some covered by rules, some by LogLM-schema Findings, some missed. When Tuesday's real run lands, its captured trace replaces this fixture.

**Acceptance**

- [ ] `tests/fixtures/redrun_v1/` with trace, telemetry parquet/CSV, expected verdicts  
- [ ] Stub `OffensiveEngine` returning it  
- [ ] Used by reconstruction, validation, coverage view, and dryrun tests

**Files:** `tests/fixtures/redrun_v1/`, `core/integrations/offensive/stub.py` **Blocked by:** loop contract types.

---

## 18\. feat(ledger): application role INSERT and SELECT only on agent\_events

**Labels:** `wave:1` `lane:record` `area:database` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: small · Lane: record (migration 1 of 4\) · Good for: factory

**Context.** Append-only is currently a convention. Make it a grant: the application role can INSERT and SELECT `agent_events` and nothing else; migrations run under a separate role.

**Acceptance**

- [ ] Migration creates roles and grants; `services/*` connect as the app role  
- [ ] An UPDATE or DELETE from the app role fails at the database (regression test)  
- [ ] Documented in `docs/ledger.md`

**Files:** `infra/migrations/<n>_ledger_grants.py`, `core/db/roles.py`, `tests/ledger/test_grants.py` **Blocked by:** Alembic baseline. **Merge before:** hash chain.

---

## 19\. feat(ledger): prev\_hash and event\_hash in the advisory-locked transaction; vigil ledger verify

**Labels:** `wave:1` `lane:record` `area:database` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: small · Lane: record (migration 2 of 4\) · Good for: factory

**Context.** Tamper evidence. Compute `event_hash = sha256(prev_hash || canonical(payload))` inside the same transaction that assigns `seq`, so no caller can choose its position or its hash.

**Acceptance**

- [ ] Columns added; hash computed server-side in the existing locked path  
- [ ] `vigil ledger verify [--run-id]` walks chains; detects a tampered payload in a test DB  
- [ ] Verifies 100k events in under a minute  
- [ ] `vigil ledger show <run_id>` renders a timeline (this is the trace; no OTel in 1.0)

**Files:** `infra/migrations/<n>_ledger_hash.py`, `core/ledger/hash.py`, `core/cli/ledger.py`, `tests/ledger/test_hash_chain.py` **Blocked by:** ledger grants.

---

## 20\. feat(policies): policies table; migrate approval thresholds to Policy rows; changes are Ledger events

**Labels:** `wave:1` `lane:record` `area:database` `area:response` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: small · Lane: record (migration 3 of 4\) · Good for: factory

**Context.** The approval domain's auto-approve above 0.90 / review below 0.85 thresholds become the first `Policy(kind=autonomy)` rows. Thresholds are read from policy objects, not settings. Loosening records a dwell.

**Acceptance**

- [ ] `policies` table in its own module (not `database/models.py`)  
- [ ] Approval domain reads thresholds from policies (test)  
- [ ] Every change appends a `policy_change` event with `direction`; loosen requires a human actor

**Files:** `infra/migrations/<n>_policies.py`, `core/policies/{models.py,service.py}`, `tests/policies/` **Blocked by:** Policy model; hash chain.

---

## 21\. feat(artifacts): hash-addressed artifacts table; scorecards and reports write through it

**Labels:** `wave:1` `lane:record` `area:database` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: small · Lane: record (migration 4 of 4\) · Good for: factory

**Context.** Results must be immutable and addressable. No S3 in 1.0: a Postgres table `artifacts(hash, kind, run_id, supersedes, bytes, created_at)` and a Ledger event carrying the hash is enough.

**Acceptance**

- [ ] Identical bytes produce one row; a superseding artifact references its predecessor  
- [ ] Reporter and dryrun write through `artifacts.put()`; the Ledger stores the hash, not the bytes  
- [ ] `artifacts.get(hash)` returns the exact bytes (test)

**Files:** `infra/migrations/<n>_artifacts.py`, `core/artifacts/`, `tests/artifacts/` **Blocked by:** policies table (order only).

---

## 22\. feat(verdicts): canonical record\_verdict; every UI action emits a verdict event; reason required on dismiss and reject

**Labels:** `wave:1` `lane:verdicts` `area:findings` `area:frontend` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: medium · Lane: verdicts · Good for: factory (one PR owns the frontend wiring)

**Context.** Every human action is a label. Confirm, dismiss, escalate, edit severity, approve, reject each become a `verdict` event with actor, reason (enum plus free text), the finding's LogLM provenance, and its ATT\&CK mapping. Vigil already returns structured verdicts for findings that pass through triage; this makes it true for every action.

**Acceptance**

- [ ] One `record_verdict()` path; no UI action mutates a finding without it (test per action)  
- [ ] Dismiss and reject require a reason  
- [ ] `vigil_verdict_total{action,source}` incremented

**Files:** `core/findings/verdicts.py`, `services/api/routes/v1/verdicts.py` (new module), `clients/web/src/features/verdicts/`, `tests/findings/test_verdicts.py` **Blocked by:** ledger schema v1. **Owns:** all frontend action wiring this week.

---

## 23\. feat(verdicts): suppression\_candidates view; promote button writes Policy(kind=suppression) with TTL; daemon honors it

**Labels:** `wave:1` `lane:verdicts` `area:findings` `area:daemon` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: small · Lane: verdicts · Good for: factory

**Context.** Dismissals with the same reason on the same match fold into a candidate. A human promotes it (one button) into a suppression policy with a TTL. No automatic promotion in 1.0; the view plus the button is most of the value.

**Acceptance**

- [ ] SQL view: three consistent dismissals produce one candidate (test)  
- [ ] Promote writes `Policy(kind=suppression)` with match, reason, TTL, promoted\_by, as a Ledger event  
- [ ] Daemon skips findings matching an active, unexpired suppression; `vigil_suppressed_findings_total` incremented

**Files:** `infra/migrations/<n>_suppression_view.py`, `core/policies/suppression.py`, `services/daemon/suppression.py`, `clients/web/src/features/suppression/` **Blocked by:** record\_verdict; policies table.

---

## 24\. feat(verdicts): vigil verdicts export \--since writes JSONL with anonymity filter

**Labels:** `wave:1` `lane:verdicts` `area:findings` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: small · Lane: verdicts · Good for: factory

**Context.** Verdicts are labeled training examples that explain themselves. Export them for the flywheel under opt-in, withholding entities and rare shapes, and report what was withheld.

**Acceptance**

- [ ] `vigil verdicts export --since <ts> --out file.jsonl`  
- [ ] Filter strips hosts, users, IPs, subnets, case text; withholds shapes below a frequency threshold; prints a withheld-report  
- [ ] Round-trip test: exported rows validate against a published JSON Schema

**Files:** `core/cli/verdicts.py`, `core/findings/export.py`, `data/schemas/verdict_export_v1.json` **Blocked by:** record\_verdict.

---

## 25\. feat(reporter): evidence citations required to render final; citation resolves to a replayable query

**Labels:** `wave:1` `lane:show-the-work` `area:agents` `area:frontend` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: medium · Lane: show-the-work · Good for: factory

**Context.** Every claim cites evidence; every citation is a typed object (source, query, time window) that resolves to a replayable query. A report with an uncited claim renders as draft, never final.

**Acceptance**

- [ ] `Citation` type; Reporter output validated for citations per claim  
- [ ] Uncited report renders as draft (test)  
- [ ] Clicking a citation in the UI runs the query and shows the events

**Files:** `core/reports/citations.py`, `core/agents/reporter/`, `clients/web/src/features/citations/`, `tests/reports/test_citations.py` **Blocked by:** ledger schema v1.

---

## 26\. feat(reports): report checker gate on hunt reports via skill\_judge

**Labels:** `wave:1` `lane:show-the-work` `area:agents` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: small · Lane: show-the-work · Good for: factory

**Context.** The detection-engineering design's semi-deterministic checker: re-run the queries behind each key claim in context isolation and reject the report if results do not reproduce. Implemented by calling `skill_judge` with the report shape; this issue is the wiring and the gate.

**Acceptance**

- [ ] Hunt reports pass through the Judge before rendering final; rejection returns structured feedback  
- [ ] Gate scoped by `Policy(kind=autonomy)` so an operator can widen to investigation reports  
- [ ] Checker cost metered under its own run\_kind

**Files:** `core/reports/checker.py`, `tests/reports/test_checker.py` **Blocked by:** the Judge skill; citations.

---

## 27\. feat(responder): typed Action with confidence, blast radius, reversibility class, rollback plan, idempotency key

**Labels:** `wave:1` `lane:show-the-work` `area:response` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: small · Vigil context: approval domain · Lane: show-the-work · Good for: factory

**Context.** Every proposed action is inspectable and safe to retry. Irreversible actions route to approval regardless of confidence. Isolating a host twice is one isolation.

**Acceptance**

- [ ] `Action` Pydantic model with the five fields; reversibility in {reversible, irreversible}  
- [ ] Irreversible always routes to approval (test); reversible follows `Policy(kind=autonomy)`  
- [ ] Idempotency key dedupes repeated execution (test)

**Files:** `core/response/action.py`, `core/agents/responder/`, `tests/response/test_action.py` **Blocked by:** Policy model.

---

## 28\. feat(metrics): Prometheus /metrics on api, daemon, worker against docs/metrics.md

**Labels:** `wave:1` `lane:metrics` `area:observability` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: medium · Lane: metrics · Good for: factory

**Context.** The AI SOC is itself a system to be operated. Export every series in the contract. Spend series reconcile Bifrost usage per run\_id.

**Acceptance**

- [ ] Every series in `docs/metrics.md` present with the documented labels; a test diffs the contract against the exposition  
- [ ] `infra/prometheus/scrape.yml` and Helm annotations  
- [ ] No new global singletons; the registry is injected

**Files:** `core/metrics/`, `services/{api,daemon,worker}/metrics.py`, `infra/prometheus/scrape.yml`, `tests/metrics/test_contract.py` **Blocked by:** metric names contract.

---

## 29\. feat(grafana): AI SOC health dashboard JSON and alert rules

**Labels:** `wave:1` `lane:metrics` `area:observability` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: none (JSON attached to the plan) · Lane: metrics · Good for: anyone, under an hour

**Context.** Written against `docs/metrics.md`; 26 panels in six rows (health strip, cost and budgets, runs, verdicts and suppression, integrations, closed loop). Six alert rules.

**Acceptance**

- [ ] `infra/grafana/ai-soc-health.json` imports cleanly into Grafana 10+  
- [ ] Every panel shows data after one fixture dry run  
- [ ] `infra/prometheus/alerts.yml` carries the six rules from the contract

**Files:** `infra/grafana/ai-soc-health.json`, `infra/prometheus/alerts.yml`, `docs/metrics.md` **Blocked by:** metric names contract (not the endpoint).

---

## 30\. feat(daemon): Policy(kind=budget) enforcement with fail-static degrade; budget\_exhausted event and metric

**Labels:** `wave:1` `lane:metrics` `area:daemon` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: small · Lane: metrics · Good for: factory

**Context.** When budget is exhausted the daemon holds the last verified posture, queues and sheds, and never spins. This is the mechanism that makes flooding fail as an attack.

**Acceptance**

- [ ] Budget read from `Policy(kind=budget)` per run\_kind  
- [ ] Exhaustion halts the run with a `budget_exhausted` event and increments `vigil_budget_exhausted_total` (test)  
- [ ] Queue depth metric rises; nothing retries unbounded

**Files:** `services/daemon/budget.py`, `tests/daemon/test_budget.py` **Blocked by:** policies table; /metrics.

---

## 31\. feat(auth): DEV\_MODE false in release images; dev clone keeps bypass behind a flag with a banner

**Labels:** `wave:1` `lane:security` `area:auth` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: small · Lane: security · Good for: factory

**Acceptance**

- [ ] `ghcr.io/vigil-soc/vigil-backend:<tag>` boots with auth on; unauthenticated call rejected (test)  
- [ ] `./start.sh` in a clone still bypasses auth with a visible banner; `start.sh --auth` turns it on  
- [ ] `vigil auth bootstrap` for existing installs; migration note

**Files:** `services/api/auth/`, `infra/docker/`, `start.sh`, `docs/upgrade.md` **Blocked by:** none.

---

## 32\. feat(auth): forced credential rotation on first login; roles admin/analyst/viewer enforced at the route layer

**Labels:** `wave:1` `lane:security` `area:auth` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: small · Lane: security · Good for: factory

**Acceptance**

- [ ] Default `admin/admin123` cannot be used twice (test)  
- [ ] Roles are an enum; viewer cannot call any action tool (test); analyst cannot loosen policy  
- [ ] API keys carry a role; MCP consumers are bound by the same roles

**Files:** `services/api/auth/roles.py`, `tests/auth/` **Blocked by:** none. **Only PR allowed to edit existing route modules this week.**

---

## 33\. ci(release): cosign-signed images

**Labels:** `wave:1` `lane:release` `area:ci` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: small · Lane: release · Good for: anyone

**Acceptance**

- [ ] Release workflow signs backend and frontend images with cosign keyless  
- [ ] `cosign verify` documented in `docs/install.md`

**Files:** `.github/workflows/release.yml`, `docs/install.md` **Blocked by:** none.

---

## 34\. docs(security): supported versions and disclosure SLA

**Labels:** `wave:1` `lane:security` `area:docs` `type:docs`  ·  **Milestone:** `v1.0.0`

**Acceptance**

- [ ] SECURITY.md table: 1.0.x supported; 0.x best effort until 1.1  
- [ ] Disclosure SLA and contact

**Files:** `SECURITY.md`

---

## 35\. test(api): OpenAPI snapshot test on /api/v1

**Labels:** `wave:1` `lane:contracts` `area:api` `type:test`  ·  **Milestone:** `v1.0.0`

**Acceptance**

- [ ] Snapshot of the OpenAPI document committed; CI fails on diff unless the snapshot and CHANGELOG change in the same PR

**Files:** `tests/api/test_openapi_snapshot.py`, `tests/api/openapi.snapshot.json` **Blocked by:** none.

---

## 36\. feat(workflows): WORKFLOW.md and SKILL.md frontmatter JSON Schema validation (warn in 1.0, fail in 2.0)

**Labels:** `wave:1` `lane:contracts` `area:workflows` `area:skills` `type:feature`  ·  **Milestone:** `v1.0.0`

**Acceptance**

- [ ] `data/schemas/workflow_v1.json`, `data/schemas/skill_v1.json`  
- [ ] All built-in playbooks and the four loop skills validate; unknown keys warn  
- [ ] `scripts/create_workflow.py` emits v1

**Files:** `data/schemas/`, `core/workflows/validate.py`, `core/skills/validate.py` **Blocked by:** none.

---

## 37\. docs: deprecation policy

**Labels:** `wave:1` `lane:contracts` `area:docs` `type:docs`  ·  **Milestone:** `v1.0.0`

**Acceptance**

- [ ] `docs/deprecation.md`: one minor version warning, removal in the next major; applies to Ledger schema, WORKFLOW.md, SKILL.md, descriptors, `/api/v1`, MCP tool names, metric names

---

## 38\. feat(dryrun): vigil dryrun runs incident response unattended against the recorded fixture and emits a scorecard artifact

**Labels:** `wave:1` `lane:evals` `area:agents` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: medium · Lane: evals · Good for: factory

**Context.** Proof of value in fifteen minutes. Load the fixture, run the incident response workflow with no human, emit a scorecard (disposition, gates met, elapsed, tokens, dollars) as a hash-addressed artifact, compare to the SOCBench baseline.

**Acceptance**

- [ ] `vigil dryrun --scenario redrun_v1` completes on a laptop with a frontier key in under fifteen minutes; Ollama path documented with expected delta  
- [ ] Scorecard is a typed artifact; Ledger stores its hash  
- [ ] SOCBench baseline comparison included

**Files:** `core/cli/dryrun.py`, `core/evals/scorecard.py`, `tests/evals/test_dryrun.py` **Blocked by:** recorded fixture; artifacts table.

---

## 39\. docs(1.0): install in ten minutes, headless and MCP, policies, metrics, contributing; AGENTS.md per touched slice; persona-to-workflow map

**Labels:** `wave:1` `lane:docs` `area:docs` `type:docs`  ·  **Milestone:** `v1.0.0`

**Acceptance**

- [ ] `docs/install.md`, `docs/headless.md` (daemon, MCP server, roles on keys), `docs/policies.md`, `docs/metrics.md` linked, `docs/contributing.md`  
- [ ] `AGENTS.md` under every new slice (\< 60 lines each)  
- [ ] `docs/personas.md` maps evaluator, SOC tiers, threat teams, SRE, CISO, SOC leader, CFO to existing workflows and views

---

## 40\. feat(metrics): CISO series: work share by actor, throughput, MTTA/MTTD/MTTR, effectiveness, hours-returned estimate

**Labels:** `wave:1` `lane:metrics` `area:observability` `area:findings` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: medium · Lane: metrics · Good for: factory

**Context.** The CISO page asks who does the work, what it costs, how fast, and whether it is right. Every series is a fold over Ledger events so the page is auditable. Definitions in `docs/ciso-metrics.md`; series in the CISO section of `docs/metrics.md`. Key rule: a human confirming an agent output counts as agent work plus one confirmation event, never as human work.

**Acceptance**

- [ ] `stage_completed` events carry `actor` in {agent, human, policy}; `vigil_work_total{stage,actor}` exported  
- [ ] `vigil_findings_created_total`, `vigil_findings_dispositioned_total{disposition,actor}`, `vigil_escalations_total`, `vigil_actions_executed_total{action_class,reversibility,actor}`  
- [ ] Histograms: `vigil_mtta_seconds{severity,actor}`, `vigil_mttd_seconds{severity,basis=evidence|verified}`, `vigil_mttr_seconds`, `vigil_mtt_disposition_seconds`  
- [ ] `vigil_agent_dispositions_{confirmed,overturned}_total`, `vigil_eval_score{scenario,suite}`, `vigil_eval_hard_fail_total`  
- [ ] `vigil_hours_returned_estimate{stage}` from `Policy(kind=sla).params.baseline_minutes`, labeled estimate  
- [ ] Contract test diffs `docs/metrics.md` against the exposition

**Files:** `core/metrics/ciso.py`, `core/findings/lifecycle.py` (emits stage\_completed with actor), `tests/metrics/test_ciso_series.py` **Blocked by:** metric names contract; record\_verdict; Policy model.

---

## 41\. feat(policies): Policy(kind=sla) with per-severity MTTA/MTTR/disposition targets and baseline minutes; breach counter

**Labels:** `wave:1` `lane:metrics` `area:response` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: small · Lane: metrics · Good for: factory

**Acceptance**

- [ ] `kind=sla` added to the Policy enum; `params`: `targets{severity}{mtta,mttr,disposition}` seconds and `baseline_minutes{stage}`  
- [ ] `vigil_sla_target_seconds{sla,severity}` exported from the active policy; `vigil_sla_breach_total` incremented on breach  
- [ ] Changing a target is a `policy_change` event (moving the goalposts is visible)

**Files:** `core/policies/schema.py`, `core/policies/sla.py`, `tests/policies/test_sla.py` **Blocked by:** Policy model; policies table.

---

## 42\. feat(grafana): CISO view dashboard

**Labels:** `wave:1` `lane:metrics` `area:observability` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: none (JSON attached to the plan) · Lane: metrics · Good for: anyone

**Context.** 40 panels in six rows: headline (issues worked, agent share, spend, cost per issue, MTTA, SLA breaches, MTTD evidence vs verified, MTTR, overturn rate, known-answer score, ledger verified), who does the work, issues worked, SLA with policy targets drawn, effectiveness with provenance per panel, autonomy posture. Annotations for loosen events, budget exhaustion, hard fails.

**Acceptance**

- [ ] `infra/grafana/ciso-view.json` imports into Grafana 10+; every panel has data after a fixture dry run plus one red run  
- [ ] Every effectiveness panel's description names its provenance (proxy vs verified)

**Files:** `infra/grafana/ciso-view.json` **Blocked by:** metric names contract.

---

# Wave 2

*Each needs a specific Wave 1 merge, named in Blocked-by.*

## 43\. feat(reports): vigil attest \--quarter writes the CISO attestation as a hash-addressed artifact

**Labels:** `wave:2` `lane:show-the-work` `area:reports` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: small · Lane: show-the-work · Good for: factory

**Context.** The same folds as the CISO dashboard, run over a period from the Ledger (not from Prometheus), written as PDF and JSON: throughput, work share by stage, spend and cost per outcome, SLA attainment against the targets in force during the period, overturn and confirmation rates, known-answer scores, red-run detection share and frontier trend, every policy change with actor, and the Ledger verification result. Re-running it later must produce identical bytes.

**Acceptance**

- [ ] `vigil attest --from --to` (and `--quarter 2026Q4`) folds from `agent_events` and writes JSON \+ PDF through `artifacts.put()`  
- [ ] Deterministic: two runs over the same period produce the same hash (test)  
- [ ] Includes `vigil ledger verify` result for the period and lists every `policy_change` with actor and direction

**Files:** `core/cli/attest.py`, `core/reports/attestation.py`, `tests/reports/test_attestation.py` **Blocked by:** CISO series; artifacts table; hash chain.

---

## 44\. feat(workflows): closed-loop Playbook composing red planner, engine, reconstruction, authoring, validation, judge, promotion

**Labels:** `wave:2` `lane:loop` `area:workflows` `type:feature`  ·  **Milestone:** `v1.0.0`

Coding: small · Lane: loop · Good for: factory

**Context.** One cycle is one Compose run. Iteration is re-invocation (`vigil loop run --environment X`, or cron). No scheduler, no new run kind in 1.0.

**Acceptance**

- [ ] `workflows/closed-loop/WORKFLOW.md` with phases granting the offensive tool and the four skill tools; offensive phase approval-gated  
- [ ] Halts on budget cap, cycle cap, operator stop (tests)  
- [ ] Second invocation's plan context includes first cycle's promoted detections read from the coverage view (test on fixture)

**Files:** `workflows/closed-loop/WORKFLOW.md`, `core/cli/loop.py`, `tests/workflows/test_closed_loop.py` **Blocked by:** all four loop skills merged; ARTEMIS adapter or stub; coverage view.

---

## 45\. ops(loop): first live red run in TempoRange; captured trace replaces the fixture

**Labels:** `wave:2` `lane:loop` `area:integrations` `type:task`  ·  **Milestone:** `v1.0.0`

Coding: none · Lane: loop · Good for: a senior human, half a day

**Acceptance**

- [ ] Red-engine Bifrost virtual key issued on its own rate bucket  
- [ ] Authorized run against TempoRange only; trace and telemetry captured  
- [ ] Reconstruction produced per-step verdicts; at least one candidate cleared lint, replay, and judge and was promoted by a human  
- [ ] `tests/fixtures/redrun_v1/` replaced by the captured run (anonymized); tests still green

**Blocked by:** ARTEMIS adapter; reconstruction; validation; judge; promotion.

---

## 46\. feat(dryrun): ./start.sh \--dryrun wrapper and scorecard view in the UI

**Labels:** `wave:2` `lane:evals` `area:frontend` `type:feature`  ·  **Milestone:** `v1.0.0`

**Acceptance**

- [ ] `./start.sh --dryrun` runs `vigil dryrun` after boot and opens the scorecard  
- [ ] Scorecard renders in the UI and exports as PDF via artifacts

**Files:** `start.sh`, `clients/web/src/features/scorecard/` **Blocked by:** dryrun CLI; artifacts table. **Owns:** scorecard frontend.

---

## 47\. feat(helm): HPA on the worker; external Postgres and Redis; 0.5 to 1.0 upgrade runbook

**Labels:** `wave:2` `lane:release` `area:helm` `type:feature`  ·  **Milestone:** `v1.0.0`

**Acceptance**

- [ ] `values.yaml` HPA on CPU for the worker; annotations for Prometheus scrape  
- [ ] `docs/upgrade.md` runbook validated manually on one design-partner cluster

**Files:** `infra/helm/vigil/`, `docs/upgrade.md` **Blocked by:** /metrics (annotations only).

---

## 48\. sec(rc1): security review: SSRF on provider URLs, prompt injection through tool results, desktop bundle secrets, dependency audit

**Labels:** `wave:2` `lane:security` `area:security` `type:task`  ·  **Milestone:** `v1.0.0`

**Acceptance**

- [ ] Findings filed as `fix:` issues with regression tests, or accepted with a recorded Ledger note  
- [ ] Tool results are treated as data, never instructions, in every agent prompt (test with an injected instruction in a fixture finding)

**Blocked by:** rc1 cut.

---

