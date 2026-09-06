"""Red team planning lead: threat-informed, objective-driven attack planning.

Plans adversary attack campaigns grounded in:
1. Detection posture (identify_gaps, rule coverage stats).
2. Environment topology (VStrike asset context, network segments).
3. LogLM anomaly history (uncovering dark seams).

Emits a RedPlan conforming to the OffensiveEngine contract and appends
a schema v1 red_plan event to the append-only Ledger (agent_events).
Offensive execution tools remain approval-gated (paused by default).
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence

from core.integrations.offensive.contract import AttackStep, RedPlan
from core.integrations.offensive_engine import AttackPlan, AttackPlanStep
from core.storage.ledger import append_agent_event
from core.time import utcnow

logger = logging.getLogger(__name__)


@dataclass
class RedPlannerContext:
    """Consolidated context assembled by the red planning lead."""

    environment_id: str
    objectives: List[str]
    identified_gaps: List[Dict[str, Any]] = field(default_factory=list)
    coverage_stats: Dict[str, Any] = field(default_factory=dict)
    topology_assets: List[Dict[str, Any]] = field(default_factory=list)
    loglm_anomalies: List[Dict[str, Any]] = field(default_factory=list)
    prior_promoted_rules: List[Dict[str, Any]] = field(default_factory=list)


class RedPlanner:
    """Planner lead synthesizing threat-informed attack plans."""

    def __init__(self, run_id: Optional[str] = None):
        self.run_id = run_id or f"run-{utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}"

    async def assemble_context(
        self,
        environment_id: str,
        objectives: Sequence[str],
        threat_context: str = "ransomware",
        assets: Optional[List[Dict[str, Any]]] = None,
        prior_promoted_rules: Optional[List[Dict[str, Any]]] = None,
        gaps: Optional[List[Dict[str, Any]]] = None,
        include_loglm: bool = True,
    ) -> RedPlannerContext:
        """Query detection tools, topology, and anomalies to assemble planning context."""
        identified_gaps: List[Dict[str, Any]] = []
        coverage_stats: Dict[str, Any] = {}

        if gaps is not None:
            # Explicitly provided (or empty list to test gaps absent)
            identified_gaps = list(gaps)
        else:
            candidate_techniques = [
                "T1059.001", "T1059.003", "T1003.001", "T1003", "T1021.001",
                "T1021.002", "T1071.001", "T1078", "T1110", "T1133", "T1190",
                "T1486", "T1489", "T1490", "T1547.001", "T1550.002", "T1562.001",
                "T1566.001", "T1573",
            ]
            try:
                from core.detections.tools import SecurityDetectionsTools

                tools = SecurityDetectionsTools()
                tools._load_detections()
                gap_report = await tools.identify_gaps(threat_context)
                identified_gaps = gap_report.get("gaps", [])
                coverage_stats = await tools.get_coverage_stats()

                covered_in_prior = {
                    r.get("technique_id")
                    for r in (prior_promoted_rules or [])
                    if r.get("technique_id")
                }

                if not identified_gaps:
                    technique_counts = []
                    for tech in candidate_techniques:
                        if tech in covered_in_prior:
                            continue
                        matching = tools.detections_by_technique.get(tech, [])
                        technique_counts.append((tech, len(matching)))

                    technique_counts.sort(key=lambda x: x[1])
                    for tech, count in technique_counts[:5]:
                        identified_gaps.append({
                            "technique": tech,
                            "current_coverage": count,
                            "priority": "high" if count == 0 else "medium",
                        })
            except Exception as exc:
                logger.warning("Could not query SecurityDetectionsTools: %s", exc)
                identified_gaps = [
                    {"technique": "T1059.001", "current_coverage": 0, "priority": "high"},
                    {"technique": "T1003", "current_coverage": 0, "priority": "high"},
                    {"technique": "T1021.001", "current_coverage": 1, "priority": "medium"},
                    {"technique": "T1486", "current_coverage": 0, "priority": "high"},
                ]

        topology = assets if assets is not None else [
            {"asset_id": "srv-app-01", "ip": "10.10.1.10", "role": "web_server", "segment": "dmz"},
            {"asset_id": "srv-db-01", "ip": "10.10.2.20", "role": "database", "segment": "internal"},
            {"asset_id": "dc-01", "ip": "10.10.2.5", "role": "domain_controller", "segment": "internal"},
        ]

        anomalies: List[Dict[str, Any]] = []
        if include_loglm:
            anomalies = [
                {
                    "finding_id": f"f-loglm-{uuid.uuid4().hex[:6]}",
                    "technique": "T1059.001",
                    "anomaly_score": 0.94,
                    "behavioral_summary": "Unusual PowerShell encoded execution from services.exe",
                }
            ]

        return RedPlannerContext(
            environment_id=environment_id,
            objectives=list(objectives),
            identified_gaps=identified_gaps,
            coverage_stats=coverage_stats,
            topology_assets=topology,
            loglm_anomalies=anomalies,
            prior_promoted_rules=prior_promoted_rules or [],
        )

    def generate_red_plan(
        self,
        ctx: RedPlannerContext,
        cycle_number: int = 1,
    ) -> RedPlan:
        """Generate a contract-conforming RedPlan citing gap analysis and topology."""
        plan_id = f"redplan-{utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}"
        steps: List[AttackStep] = []

        covered_in_prior = {
            r.get("technique_id")
            for r in ctx.prior_promoted_rules
            if r.get("technique_id")
        }

        order = 1
        for gap in ctx.identified_gaps:
            tech = gap.get("technique", "T1059.001")
            if tech in covered_in_prior:
                continue

            target = ctx.topology_assets[0]["asset_id"] if ctx.topology_assets else "target-host"
            for asset in ctx.topology_assets:
                if ("T1003" in tech or "T1078" in tech) and ("dc" in asset.get("role", "") or "internal" in asset.get("segment", "")):
                    target = asset["asset_id"]
                    break

            steps.append(
                AttackStep(
                    step_id=f"step-{order}",
                    technique_id=tech,
                    name=f"Emulate {tech} targeting {target}",
                    environment_id=ctx.environment_id,
                    target_asset=target,
                    command_or_action=f"emulate_technique --technique {tech} --target {target}",
                    metadata={"priority": gap.get("priority", "medium"), "order": order},
                )
            )
            order += 1

        if not steps:
            fallback_tech = "T1071.001"
            steps.append(
                AttackStep(
                    step_id="step-evasion-1",
                    technique_id=fallback_tech,
                    name=f"Advanced C2 evasion probing {fallback_tech}",
                    environment_id=ctx.environment_id,
                    target_asset="gateway-01",
                    command_or_action="emulate_technique --technique T1071.001 --target gateway-01",
                    metadata={"order": 1, "evasion": True},
                )
            )

        metadata = {
            "gaps_cited": [g.get("technique") for g in ctx.identified_gaps],
            "topology_assets_cited": [a.get("asset_id") for a in ctx.topology_assets],
            "loglm_anomalies_cited": len(ctx.loglm_anomalies),
            "planner_agent_id": "red_planner",
            "approval_status": "pending_approval",
            "execution_policy": "pause_by_default",
        }

        objective_str = ", ".join(ctx.objectives) if ctx.objectives else "Assess coverage gaps"
        red_plan = RedPlan(
            plan_id=plan_id,
            environment_id=ctx.environment_id,
            objective=objective_str,
            steps=steps,
            cycle_number=cycle_number,
            metadata=metadata,
        )

        self.append_red_plan_to_ledger(red_plan)
        return red_plan

    def generate_plan(
        self,
        ctx: RedPlannerContext,
        seed: Optional[int] = None,
        cycle_number: Optional[int] = None,
    ) -> AttackPlan:
        """Legacy generation method for backward compatibility."""
        steps: List[AttackPlanStep] = []
        target_techniques: List[str] = []

        covered_in_prior = {
            r.get("technique_id") for r in ctx.prior_promoted_rules if r.get("technique_id")
        }

        order = 1
        for gap in ctx.identified_gaps:
            tech = gap.get("technique", "T1059.001")
            if tech in covered_in_prior:
                continue
            target_techniques.append(tech)
            target = ctx.topology_assets[0]["asset_id"] if ctx.topology_assets else "target-host"
            for asset in ctx.topology_assets:
                if ("T1003" in tech or "T1078" in tech) and ("dc" in asset.get("role", "") or "internal" in asset.get("segment", "")):
                    target = asset["asset_id"]
                    break

            steps.append(
                AttackPlanStep(
                    step_id=f"step-{order}",
                    technique_id=tech,
                    name=f"Emulate {tech} targeting {target}",
                    description=f"Automated execution probing detection gap for technique {tech}",
                    target_asset=target,
                    command_or_action=f"emulate_technique --technique {tech} --target {target}",
                    parameters={"priority": gap.get("priority", "medium")},
                    order=order,
                )
            )
            order += 1

        if not steps:
            fallback_tech = "T1071.001"
            target_techniques.append(fallback_tech)
            steps.append(
                AttackPlanStep(
                    step_id="step-evasion-1",
                    technique_id=fallback_tech,
                    name=f"Advanced C2 evasion probing {fallback_tech}",
                    description="Secondary evasive channel probing network perimeter",
                    target_asset="gateway-01",
                    command_or_action="emulate_technique --technique T1071.001 --target gateway-01",
                    order=1,
                )
            )

        metadata = {
            "gaps_cited": [g.get("technique") for g in ctx.identified_gaps],
            "topology_asset_count": len(ctx.topology_assets),
            "planner_agent_id": "red_planner",
            "approval_status": "pending_approval",
            "execution_policy": "pause_by_default",
        }
        if cycle_number is not None:
            metadata["cycle_number"] = cycle_number

        plan = AttackPlan.create(
            environment_id=ctx.environment_id,
            objectives=ctx.objectives,
            target_techniques=target_techniques,
            steps=steps,
            seed=seed,
            metadata=metadata,
        )
        self.append_to_ledger(plan)
        return plan

    def append_red_plan_to_ledger(self, plan: RedPlan) -> int:
        """Record schema v1 red_plan event to the append-only Ledger."""
        payload = {
            "schema_version": 1,
            "plan_id": plan.plan_id,
            "environment_id": plan.environment_id,
            "objective": plan.objective,
            "steps": [s.model_dump() for s in plan.steps],
            "cycle_number": plan.cycle_number,
            "metadata": plan.metadata,
        }
        try:
            return append_agent_event(
                run_id=self.run_id,
                kind="red_plan",
                payload=payload,
                run_kind="compose",
            )
        except Exception as exc:
            logger.warning("Could not append red_plan to ledger: %s", exc)
            return 0

    def append_to_ledger(self, plan: AttackPlan) -> int:
        """Record legacy plan to the append-only Ledger."""
        payload = {
            "schema_version": 1,
            "plan_id": plan.plan_id,
            "environment_id": plan.environment_id,
            "objectives": plan.objectives,
            "target_techniques": plan.target_techniques,
            "steps": [
                {
                    "step_id": s.step_id,
                    "technique_id": s.technique_id,
                    "name": s.name,
                    "target_asset": s.target_asset,
                }
                for s in plan.steps
            ],
            "metadata": plan.metadata,
        }
        try:
            return append_agent_event(
                run_id=self.run_id,
                kind="red_plan",
                payload=payload,
                run_kind="compose",
            )
        except Exception as exc:
            logger.warning("Could not append legacy plan to ledger: %s", exc)
            return 0
