# Review: `feat/vigil-closed-loop`

Fork `johnvanlowe/vigil`, branch `feat/vigil-closed-loop`, head `d55ebde` (Sept 4 2026). Reviewer notes for the closed-loop detection-engineering implementation.

---

## Part 1: PR review

### Verdict

Strong. This lands the design faithfully and, on the seams that matter, encodes our principles in code rather than prose. The `OffensiveEngine` contract is engine-neutral with a stub for the not-bound test, the workflow is `run_kind: compose` as recommended, the validation lint rejects environment literals, both evaluation gates exist, and the MCP tool layer enforces the offensive safety gate. It should not merge as-is: one safety defect, one durability defect, and one authorization defect are blocking, and each is small and local. Approve after the three blocking items below.

### What is right, and worth keeping

The contract in `core/integrations/offensive_engine.py` is a clean deep module: a `Protocol`, a `StubOffensiveEngine`, and a name-keyed registry (`get_offensive_engine`) that lazy-imports the concrete adapter, so nothing in the loop imports ARTEMIS directly. This is exactly the boundary we wanted, and it makes the Caldera or bring-your-own path a config change.

The ARTEMIS adapter enforces the LLM-plane discipline we specified: `verify_no_egress` rejects public model hosts, the plan compiles to YAML pointing `base_url` at Bifrost `/v1`, and the spend path is isolated behind a dedicated `artemis-red-team` virtual key, an `artemis-offensive` rate bucket, and `max_retries=1`.

The MCP tool (`core/integrations/artemis/tool.py`) is the safety story done correctly: `artemis_execute_attack` calls `validate_environment` first, and absent a human pre-approval it creates an approval action and returns `pending_approval` with execution paused. The integration is a registered descriptor under category "Offensive Security" with a secret `api_key`, so it is optional and unconfigured-means-absent.

The validation harness (`core/detections/validation_harness.py`) implements the three gates: an anti-brittleness lint that rejects literal IPs (with loopback and broadcast exclusions), subnets, corp/local hostnames, and users; a replay that rejects on zero matches; and a fresh-context review gated on lint-and-replay with a bounded repair budget. `author_policy.py` enforces demote-yourself-only at `promote_candidate`, refusing promotion without human approval or an explicit pre-authorized policy. Test coverage tracks each part, including a LogLM-authoring test and a stub-engine contract test.

### Blocking

1. **The controller bypasses the offensive safety gate.** `ClosedLoopController.run_cycle` calls `self.engine.execute(plan)` directly on the adapter, skipping both `validate_environment` and the approval action that `tool.py` enforces. The gate exists and works on the MCP tool path the `WORKFLOW.md` declares; the Python controller path circumvents it. For a capability that can drive real offensive execution, an ungated code path is the one defect that cannot ship. See Issue 2\.  
     
2. **Ledger writes and the coverage fold do not use the durable, single-writer path.** Two problems with one root. First, `author_policy._append_ledger_event` reimplements the append in raw SQL as `SELECT MAX(seq)+1 ... INSERT` with no advisory lock, so two writers on one `run_id` can race the seq and collide on the `(run_id, seq)` primary key; the canonical Ledger takes an advisory lock precisely to prevent this. Second, `ClosedLoopController` keeps its own in-memory `events_journal` with a separate `seq` counter and folds the final coverage projection from that ephemeral list, not from `agent_events`, even though `coverage_projection.read_coverage_projection` already reads the durable table. The projection is therefore a fold over process memory that disappears on crash, parallel to and divergent from the real ledger. See Issue 1\.  
     
3. **Promotion authorization is hardcoded.** The controller calls `promote_candidate(pre_authorized=True, ...)` unconditionally, which satisfies the demote-yourself gate only by declaring itself pre-authorized on every promotion, collapsing the human-or-policy distinction to "always allowed." Promotion authorization must derive from config or policy, not a literal. Folded into Issue 2\.

### Non-blocking, address soon

Budget accounting counts only `exec_res.token_spend["cost_usd"]` and defaults it to a `0.005` stub, ignoring authoring, validation, and decider spend, so `max_cost_usd` cannot actually stop a real run. Gap confidence is hardcoded `0.95` at the triage call, so triage always auto-authors and the in-loop operator path is never exercised. `benign_baseline` defaults to empty, so the live-fire quiet-on-benign check is vacuous unless a caller supplies a corpus. `retrieve_loglm_neighborhood` is an explicit stub returning canned features rather than querying `nearest_neighbors`, and the reconstruction and replay matching are keyword-and-technique heuristics. `exec_res.status` is never inspected, so a `FAILED` or `STOPPED` execution proceeds to reconstruction. These are appropriate for a first cut but should be tracked; see Issue 3\.

### Nits

`initial_frontier` is hardcoded `1.0` rather than read from a pre-cycle projection, so frontier movement is not truly measured. `HaltReason.COMPLETED` is effectively unreachable, always overwritten by `MAX_CYCLES_REACHED` or a break reason. `ValidationHarness` is imported inside the gap loop, and a fresh `RedPlanner` is constructed each cycle. `NO_VIABLE_PATH` is asserted when a single cycle yields zero gaps, which conflates "this plan was fully caught" with "no attack path remains."

### Tests

The unit suite is the right shape: stub engine, harness gates, policy thresholds, coverage fold, reconstruction verdicts, and LogLM authoring each have a test. They are unit-level against in-memory fakes, so they will not catch the blocking items above, all of which live at integration seams (the ungated execute path, the unlocked ledger write, the projection source). Each issue below carries an acceptance test that closes that gap.

### Design decision to settle first

Decide whether the Compose `WORKFLOW.md` or the `ClosedLoopController` is the authoritative executor. Right now the loop exists twice: the workflow runs one gated cycle through MCP tools, the controller runs multiple ungated cycles in-process, and they diverge exactly on the safety and durability properties. Our design called for iteration by re-invocation with the coverage projection carrying state between runs, which favors the workflow as authoritative and the controller as a thin scheduler over it. Issues 1 and 2 both depend on this call.

---

## Part 2: Three gap issues

Drafted in the repo's house style for the software factory: grading preamble, context with file and line citations, acceptance as a checklist, files, blocked-by, and labels. Priority order is 1 then 2 then 3\.

### Issue 1

**fix(closed-loop): ledger integrity: canonical advisory-locked appends and a durable coverage fold**

> Coding · Vigil context: the closed loop's audit trail and coverage metric · Lane: correctness/durability · Good for: someone comfortable with the Ledger and Postgres advisory locks

**Context.** The closed loop must rest on the append-only Ledger the rest of Vigil relies on, but two paths in this branch sidestep it. `core/detections/author_policy.py::_append_ledger_event` reimplements the append in raw SQL (`SELECT COALESCE(MAX(seq),0)+1 ... INSERT`) with no advisory lock, so concurrent writers on one `run_id` can select the same `seq` and collide on the `(run_id, seq)` primary key; the canonical Ledger assigns `seq` server-side inside an advisory-locked transaction for exactly this reason. Separately, `core/workflows/closed_loop.py` maintains an in-memory `events_journal` with its own `seq = len(events_journal)+1` counter and computes the final projection with `fold_coverage_projection(self.events_journal, ...)`, a fold over process memory that is lost on crash and diverges from `agent_events`. A durable reader, `core/detections/coverage_projection.py::read_coverage_projection`, already exists and is unused by the controller.

**Acceptance.**

- [ ] All closed-loop appends (gap triage, reconstruction verdict, promotion, red plan) go through the canonical Ledger append path, or take the same advisory lock, so `seq` is assigned under contention without collision.  
- [ ] A concurrency test issues two simultaneous appends to one `run_id` and asserts monotonic, gapless `seq` with no primary-key error.  
- [ ] The controller stops maintaining a parallel `events_journal` seq space; the coverage projection is produced by `read_coverage_projection` (a fold over `agent_events`), not over an in-memory list.  
- [ ] A replay test reconstructs the same `CoverageProjection` from the persisted `agent_events` after the controller process exits.  
- [ ] Promotion events are durable (not best-effort `try/except`\-and-warn); a failed promotion write fails the promotion, it does not silently proceed.

**Files.** `core/detections/author_policy.py`, `core/workflows/closed_loop.py`, `core/detections/coverage_projection.py`, tests under `tests/unit/detections/` and `tests/unit/workflows/`.

**Blocked by.** The executor-authority decision (workflow vs controller).

**Labels.** `area:database`, `area:detections`, `type:bug`, `factory:needs-work`.

### Issue 2

**fix(closed-loop): enforce the offensive safety gate and policy-driven promotion in the controller path**

> Coding · Vigil context: the offensive execution and promotion governance · Lane: safety/correctness · Good for: someone who can trace the approval and integration seams

**Context.** The safety gate is implemented correctly in `core/integrations/artemis/tool.py`: `artemis_execute_attack` calls `validate_environment` and, absent human pre-approval, creates an approval action and returns `pending_approval` with execution paused. The `ClosedLoopController` bypasses that tool and calls `self.engine.execute(plan)` directly in `core/workflows/closed_loop.py::run_cycle`, so neither environment authorization nor approval is enforced on the controller path. The same method promotes with `promote_candidate(pre_authorized=True, ...)` hardcoded, which defeats `AuthoringPolicy.require_human_promotion` by asserting authorization on every call. Both are the same failure: a governance gate that exists is circumvented by the controller.

**Acceptance.**

- [ ] The controller executes offense only through the gated path: `validate_environment` is called before any execution, and an unauthorized or production environment is refused, matching `EnvironmentScope.is_target_authorized`.  
- [ ] Absent human approval or an explicit pre-authorized policy, offensive execution raises an approval checkpoint and halts the cycle rather than executing; a test asserts a run against an unapproved environment never reaches `engine.execute`.  
- [ ] Promotion authorization derives from config/policy, not a literal; `pre_authorized` is passed only when the operator set a pre-authorized promotion policy, and the default requires human approval.  
- [ ] A test asserts that under the default policy a validated candidate is not promoted without an approval, and that `require_human_promotion` cannot be bypassed by the controller.  
- [ ] `exec_res.status` is inspected; a `FAILED` or `STOPPED` execution is handled rather than flowing into reconstruction.

**Files.** `core/workflows/closed_loop.py`, `core/detections/author_policy.py`, tests under `tests/unit/workflows/` and `tests/unit/detections/`.

**Blocked by.** The executor-authority decision (workflow vs controller).

**Labels.** `area:agents`, `area:response`, `area:integrations`, `type:bug`, `factory:needs-work`.

### Issue 3

**Epic: ground the closed-loop heuristics in real detection, LogLM, and cost signals**

> Coding · Vigil context: fidelity of reconstruction, grounding, live-fire, and budget · Lane: fidelity · Good for: split into children, one PR each

**Context.** The loop's scaffolding is sound but several seams are first-cut heuristics that must be grounded before the coverage numbers mean anything. `core/detections/authoring.py::retrieve_loglm_neighborhood` returns canned features rather than querying `nearest_neighbors` over pgvector or the LogLM MCP surface. Reconstruction and replay in `core/detections/reconstruction.py` and `validation_harness.py` match on technique alignment plus keyword hits rather than real rule evaluation. `core/workflows/closed_loop.py` supplies an empty `benign_baseline` by default, so the live-fire quiet-on-benign check is vacuous, and it tallies only `exec_res.token_spend["cost_usd"]`, so `max_cost_usd` cannot stop a real run. Gap confidence is hardcoded `0.95` at the triage call, so the operator author-or-defer path is never exercised.

**Child scopes, one PR each.**

- [ ] Wire `retrieve_loglm_neighborhood` to real `nearest_neighbors` (pgvector / LogLM MCP), with a graceful no-LogLM degradation that still authors from telemetry.  
- [ ] Replace keyword replay with evaluation against the actual detection engine over captured telemetry; reject on genuine zero matches.  
- [ ] Require a non-empty benign corpus for live-fire, or skip promotion with a recorded reason when none is available; make quiet-on-benign meaningful.  
- [ ] Account for authoring, validation, and decider spend in the cycle cost so the budget halt is real; reconcile against the isolated red virtual key.  
- [ ] Derive gap confidence from the gap (LogLM score or severity) instead of a constant, so the in-loop operator path is reachable.

**Files.** `core/detections/authoring.py`, `core/detections/reconstruction.py`, `core/detections/validation_harness.py`, `core/detections/live_fire.py`, `core/workflows/closed_loop.py`, tests alongside each.

**Blocked by.** Issues 1 and 2 (build fidelity on a durable, gated base).

**Labels.** `type:epic`, `area:detections`, `factory:needs-work`.

---

## Part 3: `closed_loop.py`, line by line

A correctness pass over `core/workflows/closed_loop.py`. References are by construct.

**Module docstring.** Claims execution "via Compose re-invocation" and that offense is "approval-gated." Neither holds in this file: it is an in-process multi-cycle controller, and it calls the engine directly with no gate. The docstring describes the intended design; the code is a second, ungated implementation of it. This mismatch is the crux of the executor-authority decision.

**`ClosedLoopConfig`.** `policy` defaults to `AuthoringPolicy(default_action="auto_author")`, and `auto_author` defaults `True`, so the shipped default is fully autonomous authoring. Reasonable for a range, but it means the operator-choice path is never taken with the default config, which is why the hardcoded `confidence=0.95` below goes unnoticed. `benign_baseline` defaults empty, which quietly disables the live-fire benign check downstream.

**`ClosedLoopController.__init__`.** Constructs the engine via `get_offensive_engine(config.engine_name)`, correct and swappable. Instantiates the services with `run_id`, good. Initializes `events_journal: List` as an in-process record; this is the parallel seq space that Issue 1 removes.

**`run_cycle`, red planning.** A fresh `RedPlanner` is built each call though `self` holds none; harmless but wasteful. `seed=42 + cycle_number*17` is deterministic and varies per cycle, fine for reproducibility, though the fixed base means every run is identical, which is good for tests and questionable for a real campaign. The red-plan event is appended to `events_journal` with `seq = len(events_journal)+1`, the local counter that diverges from `agent_events`.

**`run_cycle`, execution.** `exec_res = await self.engine.execute(plan)` is the blocking safety defect: no `validate_environment`, no approval action, no `EnvironmentScope` check, unlike the MCP tool path. `exec_res.status` is then never inspected, so a `FAILED` or `PARTIAL` execution flows straight into reconstruction as if it had succeeded.

**`run_cycle`, reconstruction.** `reconstruct(...)` is called with `captured_telemetry` and the verdicts are appended to `events_journal`. Contract matches (`ReconstructionReport.gaps: List[Dict]`, `step_verdicts`). The verdicts are durable only if the reconstruction service also writes to `agent_events`; the controller's journal copy is not.

**`run_cycle`, gap loop.** `triage_gap(gap, confidence=0.95)` hardcodes confidence, so with the default policy every gap auto-authors; the checkpoint branch is dead under the default config, and a gap that triages to anything other than `AUTHOR_NOW` is silently skipped with no deferral handling in the controller. `ValidationHarness` is imported inside the loop, a style nit. `validate_candidate` then, only if `is_valid`, `evaluate_live_fire` with `benign_baseline_telemetry=self.config.benign_baseline`, which is empty by default, so the benign check has nothing to test against.

**`run_cycle`, promotion.** `promote_candidate(authorized_by="closed_loop_authorized_policy", pre_authorized=True)` hardcodes `pre_authorized=True`, defeating `require_human_promotion` on every promotion. This is the authorization defect. The promotion event is appended to `events_journal` only; the durable write in `author_policy` is best-effort and may silently fail. `candidates.append(candidate)` runs regardless of outcome, which is fine for reporting but means the returned list mixes promoted, rejected, and unvalidated candidates without a status filter (the `DetectionCandidate.status` carries it, so acceptable).

**`run_cycle`, cost.** `cycle_cost = float(exec_res.token_spend.get("cost_usd", 0.005))` counts only offensive spend and defaults to a stub value, so authoring, validation, and decider cost are invisible to the budget.

**`run`, budget checks.** Budget is checked at the top of the loop and again after adding cycle cost. Because `cycle_cost` undercounts, `BUDGET_EXCEEDED` will rarely fire on a real run. The double check is harmless.

**`run`, no-viable-path.** `if len(result.plan.steps) == 0 or len(result.reconstruction_report.gaps) == 0: NO_VIABLE_PATH`. Zero gaps in one cycle is labeled no-viable-path, which overstates it: it means this plan was fully caught, not that no path exists. A stricter terminator would require several consecutive zero-gap cycles or a plateau on the frontier metric. Zero plan steps as a terminator is reasonable.

**`run`, halt bookkeeping.** After the loop, `if len(cycle_results) >= max_cycles and halt_reason == COMPLETED: MAX_CYCLES_REACHED`. This makes `HaltReason.COMPLETED` effectively unreachable, since a full run without a break becomes `MAX_CYCLES_REACHED`. Not a bug, but the enum value is dead.

**`run`, frontier.** `initial_frontier = 1.0` is assumed rather than read from a pre-cycle projection, so `initial` vs `final` does not measure real movement. `final_projection = fold_coverage_projection(self.events_journal, environment_id)` folds the in-memory journal, not `agent_events`; swapping to `read_coverage_projection(environment_id)` (already present) both fixes durability and lets `initial_frontier` be a real pre-cycle read.

**Async and contracts.** Sync services (`reconstruction_svc`, `triage_svc`, `live_fire_svc`) are called without `await`; async ones (`assemble_context`, `author_candidate_for_gap`, `engine.execute`) are awaited. Consistent, and the call signatures line up with the modules as written. No error handling wraps `engine.execute` or authoring, so an exception aborts the whole run rather than the single cycle; a per-cycle try/except that records the failure and halts cleanly would be more robust.

**Summary.** The control flow is coherent and the module composes the pieces correctly. The defects are not in the orchestration logic but in what it skips: the safety gate, the durable ledger, and policy-driven promotion. Fixing the three, and preferably re-homing the loop as a thin scheduler over the gated Compose workflow, turns this from a convincing prototype into something shippable.  
