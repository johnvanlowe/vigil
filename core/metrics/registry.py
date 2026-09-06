"""Prometheus metrics registry and definitions matching docs/metrics.md v1.0."""

from __future__ import annotations

from typing import Optional
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, REGISTRY


class VigilMetrics:
    """Injectable Prometheus metrics container for Vigil SOC."""

    def __init__(self, registry: Optional[CollectorRegistry] = None):
        self.registry = registry or CollectorRegistry(auto_describe=True)

        # 1. System, Run & Spend
        self.runs_active = Gauge(
            "vigil_runs_active",
            "Number of currently executing workflow runs",
            ["run_kind"],
            registry=self.registry,
        )
        self.runs_total = Counter(
            "vigil_runs_total",
            "Total workflow runs initiated",
            ["run_kind", "status"],
            registry=self.registry,
        )
        self.run_duration_seconds = Histogram(
            "vigil_run_duration_seconds",
            "Execution duration distribution of workflow runs in seconds",
            ["run_kind"],
            registry=self.registry,
        )
        self.spend_usd_total = Counter(
            "vigil_spend_usd_total",
            "Cumulative token spend in USD reconciled from model providers",
            ["run_kind", "model", "virtual_key"],
            registry=self.registry,
        )
        self.spend_budget_usd = Gauge(
            "vigil_spend_budget_usd",
            "Current budget limit allocated for the run kind",
            ["run_kind"],
            registry=self.registry,
        )
        self.budget_exhausted_total = Counter(
            "vigil_budget_exhausted_total",
            "Count of workflow runs halted due to budget exhaustion",
            ["run_kind"],
            registry=self.registry,
        )
        self.queue_depth = Gauge(
            "vigil_queue_depth",
            "Number of tasks queued waiting for execution workers",
            ["queue"],
            registry=self.registry,
        )

        # 2. Findings, Verdicts & Suppression
        self.verdict_total = Counter(
            "vigil_verdict_total",
            "Total verdicts recorded on findings (confirm, dismiss, escalate, etc.)",
            ["action", "source"],
            registry=self.registry,
        )
        self.suppressed_findings_total = Counter(
            "vigil_suppressed_findings_total",
            "Total findings suppressed by active suppression policies",
            ["match"],
            registry=self.registry,
        )
        self.findings_created_total = Counter(
            "vigil_findings_created_total",
            "Total security findings ingested",
            ["source", "severity"],
            registry=self.registry,
        )
        self.findings_dispositioned_total = Counter(
            "vigil_findings_dispositioned_total",
            "Total findings dispositioned by human, agent, or policy",
            ["disposition", "actor"],
            registry=self.registry,
        )
        self.escalations_total = Counter(
            "vigil_escalations_total",
            "Total cases escalated to higher tier or on-call",
            ["severity", "actor"],
            registry=self.registry,
        )
        self.actions_executed_total = Counter(
            "vigil_actions_executed_total",
            "Total response actions executed by reversibility class and actor",
            ["action_class", "reversibility", "actor"],
            registry=self.registry,
        )

        # 3. Closed-Loop Validation
        self.closed_loop_cycles_total = Counter(
            "vigil_closed_loop_cycles_total",
            "Total adversarial validation cycles executed",
            ["environment_id", "status"],
            registry=self.registry,
        )
        self.closed_loop_frontier = Gauge(
            "vigil_closed_loop_frontier",
            "Count of open / missed detection gaps remaining (the frontier)",
            ["environment_id"],
            registry=self.registry,
        )
        self.closed_loop_rules_promoted_total = Counter(
            "vigil_closed_loop_rules_promoted_total",
            "Total validated detection rules promoted to the customer overlay",
            ["environment_id", "format"],
            registry=self.registry,
        )

        # 4. CISO Series
        self.work_total = Counter(
            "vigil_work_total",
            "Work items completed by stage and actor",
            ["stage", "actor"],
            registry=self.registry,
        )
        self.mtta_seconds = Histogram(
            "vigil_mtta_seconds",
            "Mean time to acknowledge findings in seconds",
            ["severity", "actor"],
            registry=self.registry,
        )
        self.mttd_seconds = Histogram(
            "vigil_mttd_seconds",
            "Mean time to detect in seconds",
            ["severity", "basis"],
            registry=self.registry,
        )
        self.mttr_seconds = Histogram(
            "vigil_mttr_seconds",
            "Mean time to remediate/resolve findings in seconds",
            ["severity"],
            registry=self.registry,
        )
        self.mtt_disposition_seconds = Histogram(
            "vigil_mtt_disposition_seconds",
            "Mean time to reach a final disposition in seconds",
            ["severity"],
            registry=self.registry,
        )
        self.agent_dispositions_confirmed_total = Counter(
            "vigil_agent_dispositions_confirmed_total",
            "Count of agent-recommended dispositions confirmed by human analysts",
            ["stage"],
            registry=self.registry,
        )
        self.agent_dispositions_overturned_total = Counter(
            "vigil_agent_dispositions_overturned_total",
            "Count of agent-recommended dispositions overturned by human analysts",
            ["stage"],
            registry=self.registry,
        )
        self.eval_score = Gauge(
            "vigil_eval_score",
            "Benchmark evaluation score (0.0 to 1.0) on standard scenarios",
            ["scenario", "suite"],
            registry=self.registry,
        )
        self.eval_hard_fail_total = Counter(
            "vigil_eval_hard_fail_total",
            "Count of critical safety or correctness violations during eval runs",
            ["scenario", "suite"],
            registry=self.registry,
        )
        self.hours_returned_estimate = Gauge(
            "vigil_hours_returned_estimate",
            "Estimated analyst hours saved based on baseline targets and completed agent work",
            ["stage"],
            registry=self.registry,
        )

        # 5. SLA & Governance
        self.sla_target_seconds = Gauge(
            "vigil_sla_target_seconds",
            "Target SLA threshold in seconds from active Policy(kind=sla)",
            ["sla", "severity"],
            registry=self.registry,
        )
        self.sla_breach_total = Counter(
            "vigil_sla_breach_total",
            "Total count of SLA breaches observed",
            ["sla", "severity"],
            registry=self.registry,
        )


_DEFAULT_METRICS: Optional[VigilMetrics] = None


def get_metrics() -> VigilMetrics:
    """Get the default or injected VigilMetrics instance."""
    global _DEFAULT_METRICS
    if _DEFAULT_METRICS is None:
        _DEFAULT_METRICS = VigilMetrics()
    return _DEFAULT_METRICS


def set_metrics(metrics: VigilMetrics) -> None:
    """Explicitly inject a VigilMetrics instance."""
    global _DEFAULT_METRICS
    _DEFAULT_METRICS = metrics
