---
name: closed-loop
description: "Autonomous closed-loop detection engineering: threat-informed red team planning, offensive execution, telemetry reconstruction, gap triage, grounded authoring, deterministic validation, live-fire testing, and promotion."
use_case: "Continuous validation-first offensive-defensive engineering to harden representative environments and close detection seams."
run_kind: compose
trigger_examples:
  - "Run closed loop detection engineering on staging-range"
  - "Continuous offensive-defensive loop on digital twin"
  - "Verify detection posture and close gaps for ransomware techniques"
phases:
  - id: red-planning
    agent: red_planner
    name: "Context-Grounded Red Planning"
    tools: [identify_gaps, get_coverage_stats, search_detections, nearest_neighbors]
    instructions: |
      Synthesize a threat-informed, objective-driven AttackPlan grounded in:
      1. Current detection coverage and identify_gaps.
      2. Representative environment topology (VStrike assets and segments).
      3. LogLM anomaly history to probe dark seams.
      4. Avoid techniques already covered by freshly promoted detections from prior cycles.
      5. Emit an AttackPlan satisfying the OffensiveEngine protocol.

  - id: red-execution
    agent: investigator
    name: "Offensive Engine Execution"
    tools: [artemis_execute_attack, artemis_validate_target]
    instructions: |
      Execute the compiled AttackPlan via the offensive engine (ARTEMIS default):
      1. Verify environment authorization (must be non-production range/staging).
      2. Ensure no-egress constraints route all model reasoning through Bifrost.
      3. Request approval if un-authorized; execute and collect action trace and captured telemetry.

  - id: reconstruction
    agent: investigator
    name: "Detection Reconstruction"
    tools: [get_finding, list_findings, nearest_neighbors]
    instructions: |
      Correlate executed attack steps against telemetry and detection rules:
      1. Determine per-step detection verdict: detected_by_rule, detected_by_loglm, both, or missed.
      2. Distinguish LogLM anomalies as a first-class signal.
      3. Verify field grounding so no verdict relies on unemitted sensor attributes.
      4. Write per-step reconstruction verdicts with evidence citations to the Ledger.

  - id: gap-triage
    agent: investigator
    name: "Gap Triage & Author Choice"
    tools: [create_approval_action, list_approval_actions]
    instructions: |
      For each detected gap (missed or model-only):
      1. Apply authoring policy (auto-author above threshold, ask operator otherwise).
      2. Raise an approval checkpoint for human triage where required.
      3. Record decisions (author now, defer, or accept gap with reason) to the Ledger.

  - id: author-and-validate
    agent: investigator
    name: "Grounded Authoring & Validation"
    tools: [skill_detection_authoring, skill_detection_validation]
    instructions: |
      For chosen gaps, author candidate detections and pass through the validation harness:
      1. Ground behavioral features in real telemetry and LogLM embedding neighborhoods.
      2. Gate 1 (Lint): Verify syntax and reject any literal IPs, hosts, users, or subnets.
      3. Gate 2 (Replay): Backtest candidate against captured attack telemetry; reject if 0 matches.
      4. Gate 3 (Review): Independent judge role evaluates behavioral robustness.
      5. Bounded repair loop: iterate within repair budget on failure.

  - id: live-fire
    agent: investigator
    name: "Live-Fire Evaluation Gate"
    tools: [artemis_execute_attack]
    instructions: |
      Run the second evaluation gate before promotion:
      1. Reseeded retest: verify candidate fires on an independently seeded variant of the attack.
      2. Quiet-on-benign: verify candidate does not trigger false positives on benign baseline estate traffic.
      3. Reject any candidate that fails either live-fire check.

  - id: promotion
    agent: responder
    name: "Detection Promotion"
    tools: [create_approval_action]
    instructions: |
      Promote validated detections to the live detection library:
      1. Enforce demote-yourself-only: promotion requires human approval or pre-authorized policy.
      2. Record promotion event to the append-only Ledger.
      3. Update the coverage read-model for subsequent cycles.
---
