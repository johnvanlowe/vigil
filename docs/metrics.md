# Vigil Metrics Specification & Contract (v1.0)

## Metric Naming Principles

1. All Prometheus metrics are prefixed with `vigil_`.
2. Counters end in `_total`.
3. Gauges represent instantaneous state.
4. Histograms and duration metrics use base units of seconds (`_seconds`).
5. Currency spend uses USD (`_usd` or `_usd_total`).
6. Dimensions are represented via normalized labels.

---

## 1. System, Run & Spend Series

| Metric Name | Type | Labels | Description |
|---|---|---|---|
| `vigil_runs_active` | Gauge | `run_kind` | Number of currently executing workflow runs. |
| `vigil_runs_total` | Counter | `run_kind`, `status` | Total workflow runs initiated. |
| `vigil_run_duration_seconds` | Histogram | `run_kind` | Execution duration distribution of workflow runs in seconds. |
| `vigil_spend_usd_total` | Counter | `run_kind`, `model`, `virtual_key` | Cumulative token spend in USD reconciled from model providers. |
| `vigil_spend_budget_usd` | Gauge | `run_kind` | Current budget limit allocated for the run kind. |
| `vigil_budget_exhausted_total` | Counter | `run_kind` | Count of workflow runs halted due to budget exhaustion. |
| `vigil_queue_depth` | Gauge | `queue` | Number of tasks queued waiting for execution workers. |

---

## 2. Findings, Verdicts & Suppression Series

| Metric Name | Type | Labels | Description |
|---|---|---|---|
| `vigil_verdict_total` | Counter | `action`, `source` | Total verdicts recorded on findings (confirm, dismiss, escalate, etc.). |
| `vigil_suppressed_findings_total` | Counter | `match` | Total findings suppressed by active suppression policies. |
| `vigil_findings_created_total` | Counter | `source`, `severity` | Total security findings ingested. |
| `vigil_findings_dispositioned_total` | Counter | `disposition`, `actor` | Total findings dispositioned by human, agent, or policy. |
| `vigil_escalations_total` | Counter | `severity`, `actor` | Total cases escalated to higher tier or on-call. |
| `vigil_actions_executed_total` | Counter | `action_class`, `reversibility`, `actor` | Total response actions executed by reversibility class and actor. |

---

## 3. Closed-Loop Validation Series

| Metric Name | Type | Labels | Description |
|---|---|---|---|
| `vigil_closed_loop_cycles_total` | Counter | `environment_id`, `status` | Total adversarial validation cycles executed. |
| `vigil_closed_loop_frontier` | Gauge | `environment_id` | Count of open / missed detection gaps remaining (the frontier). |
| `vigil_closed_loop_rules_promoted_total` | Counter | `environment_id`, `format` | Total validated detection rules promoted to the customer overlay. |

---

## 4. CISO Series (Executive & Operational Performance)

| Metric Name | Type | Labels | Description |
|---|---|---|---|
| `vigil_work_total` | Counter | `stage`, `actor` | Work items completed by stage (triage, investigate, respond) and actor (agent, human, policy). |
| `vigil_mtta_seconds` | Histogram | `severity`, `actor` | Mean time to acknowledge findings in seconds. |
| `vigil_mttd_seconds` | Histogram | `severity`, `basis` | Mean time to detect (basis: `evidence` vs `verified`) in seconds. |
| `vigil_mttr_seconds` | Histogram | `severity` | Mean time to remediate/resolve findings in seconds. |
| `vigil_mtt_disposition_seconds` | Histogram | `severity` | Mean time to reach a final disposition in seconds. |
| `vigil_agent_dispositions_confirmed_total` | Counter | `stage` | Count of agent-recommended dispositions confirmed by human analysts. |
| `vigil_agent_dispositions_overturned_total` | Counter | `stage` | Count of agent-recommended dispositions overturned by human analysts. |
| `vigil_eval_score` | Gauge | `scenario`, `suite` | Benchmark evaluation score (0.0 to 1.0) on standard scenarios. |
| `vigil_eval_hard_fail_total` | Counter | `scenario`, `suite` | Count of critical safety or correctness violations during eval runs. |
| `vigil_hours_returned_estimate` | Gauge | `stage` | Estimated analyst hours saved based on baseline targets and completed agent work. |

---

## 5. SLA & Governance Series

| Metric Name | Type | Labels | Description |
|---|---|---|---|
| `vigil_sla_target_seconds` | Gauge | `sla`, `severity` | Target SLA threshold in seconds from active `Policy(kind=sla)`. |
| `vigil_sla_breach_total` | Counter | `sla`, `severity` | Total count of SLA breaches observed. |

---

## 6. Shipped Prometheus Alert Rules

```yaml
groups:
  - name: vigil_alerts
    rules:
      - alert: VigilBudgetExhaustedCritical
        expr: increase(vigil_budget_exhausted_total[5m]) > 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Vigil workflow budget exhausted; operations degraded to fail-static"

      - alert: VigilHighOverturnRate
        expr: rate(vigil_agent_dispositions_overturned_total[1h]) / (rate(vigil_agent_dispositions_confirmed_total[1h]) + rate(vigil_agent_dispositions_overturned_total[1h])) > 0.35
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "Agent verdict overturn rate exceeds 35% over 1 hour window"

      - alert: VigilSLABreached
        expr: increase(vigil_sla_breach_total[15m]) > 0
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Security finding MTTA/MTTR breached policy SLA target"

      - alert: VigilOffensiveSafetyFailure
        expr: increase(vigil_runs_total{run_kind="compose", status="failed"}[5m]) > 2
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Offensive loop execution failed safety gating or execution preconditions"

      - alert: VigilWorkerQueueBacklog
        expr: vigil_queue_depth > 100
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Worker task queue depth is critically backlogged"

      - alert: VigilLedgerTamperDetected
        expr: increase(vigil_eval_hard_fail_total{suite="ledger"}[1m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Cryptographic tamper detected on the Vigil agent_events ledger hash chain"
```
