"""Red team planning lead: threat-informed, objective-driven attack planning.

Plans adversary attack campaigns grounded in:
1. Detection posture (identify_gaps, rule coverage stats).
2. Environment topology (VStrike asset context, network segments).
3. LogLM anomaly history (uncovering dark seams).

Appends the plan and planned steps to the append-only Ledger (agent_events)
and emits an AttackPlan conforming to the OffensiveEngine protocol.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence

from core.integrations.offensive_engine import AttackPlan, AttackPlanStep
from core.storage.connection import get_db_manager
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
    ) -> RedPlannerContext:
        """Query detection tools, topology, and anomalies to assemble planning context."""
        gaps: List[Dict[str, Any]] = []
        coverage_stats: Dict[str, Any] = {}

        # Broader set of candidate MITRE ATT&CK techniques across key tactics
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
            gaps = gap_report.get("gaps", [])
            coverage_stats = await tools.get_coverage_stats()

            # If tool returns no gaps or empty context, find the thin-coverage techniques
            covered_in_prior = {
                r.get("technique_id") for r in (prior_promoted_rules or []) if r.get("technique_id")
            }

            if not gaps:
                technique_counts = []
                for tech in candidate_techniques:
                    if tech in covered_in_prior:
                        continue
                    matching = tools.detections_by_technique.get(tech, [])
                    technique_counts.append((tech, len(matching)))

                # Sort by lowest coverage first
                technique_counts.sort(key=lambda x: x[1])
                for tech, count in technique_counts[:5]:
                    gaps.append({
                        "technique": tech,
                        "current_coverage": count,
                        "priority": "high" if count == 0 else "medium",
                    })
        except Exception as exc:
            logger.warning("Could not query SecurityDetectionsTools: %s", exc)
            # Default threat-informed fallback gaps if detection repository is unindexed
            gaps = [
                {"technique": "T1059.001", "current_coverage": 0, "priority": "high"},
                {"technique": "T1003", "current_coverage": 0, "priority": "high"},
                {"technique": "T1021.001", "current_coverage": 1, "priority": "medium"},
                {"technique": "T1486", "current_coverage": 0, "priority": "high"},
            ]

        topology = assets or [
            {"asset_id": "srv-app-01", "ip": "10.10.1.10", "role": "web_server", "segment": "dmz"},
            {"asset_id": "srv-db-01", "ip": "10.10.2.20", "role": "database", "segment": "internal"},
            {"asset_id": "dc-01", "ip": "10.10.2.5", "role": "domain_controller", "segment": "internal"},
        ]

        # LogLM historical anomalies: simulated or queried from findings
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
            identified_gaps=gaps,
            coverage_stats=coverage_stats,
            topology_assets=topology,
            loglm_anomalies=anomalies,
            prior_promoted_rules=prior_promoted_rules or [],
        )

    def generate_plan(
        self,
        ctx: RedPlannerContext,
        seed: Optional[int] = None,
    ) -> AttackPlan:
        """Synthesize attack steps prioritizing coverage gaps and dark seams."""
        steps: List[AttackPlanStep] = []
        target_techniques: List[str] = []

        # Filter out techniques already covered by freshly promoted rules in prior cycles
        covered_in_prior = {
            r.get("technique_id") for r in ctx.prior_promoted_rules if r.get("technique_id")
        }

        order = 1
        for gap in ctx.identified_gaps:
            tech = gap.get("technique", "T1059.001")
            if tech in covered_in_prior:
                # Force onto harder path / next seam!
                continue

            target_techniques.append(tech)

            # Assign suitable target asset from topology
            target = ctx.topology_assets[0]["asset_id"] if ctx.topology_assets else "target-host"
            if "T1003" in tech or "T1078" in tech:
                # Target DC or DB if credential access
                for asset in ctx.topology_assets:
                    if "dc" in asset.get("role", "") or "internal" in asset.get("segment", ""):
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
            # Fallback evasive technique if all primary gaps were closed
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

        plan = AttackPlan.create(
            environment_id=ctx.environment_id,
            objectives=ctx.objectives,
            target_techniques=target_techniques,
            steps=steps,
            seed=seed,
            metadata={
                "gaps_cited": [g.get("technique") for g in ctx.identified_gaps],
                "topology_asset_count": len(ctx.topology_assets),
                "planner_agent_id": "red_planner",
            },
        )

        # Append plan creation to agent_events (Ledger)
        self.append_to_ledger(plan)
        return plan

    def append_to_ledger(self, plan: AttackPlan) -> None:
        """Record plan and steps to the append-only Ledger (agent_events table)."""
        now = utcnow()
        payload = {
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
            db = get_db_manager()
            with db.session_scope() as session:
                # Query next seq for this run_id
                query = session.execute(
                    """
                    SELECT COALESCE(MAX(seq), 0) + 1 FROM agent_events
                    WHERE run_id = CAST(:run_id AS uuid)
                    """,
                    {"run_id": self.run_id},
                )
                next_seq = query.scalar() or 1

                session.execute(
                    """
                    INSERT INTO agent_events (
                        run_id, seq, ts, run_kind, kind, payload, schema_version
                    ) VALUES (
                        CAST(:run_id AS uuid), :seq, :ts, :run_kind, :kind, CAST(:payload AS jsonb), :schema_version
                    )
                    """,
                    {
                        "run_id": self.run_id,
                        "seq": next_seq,
                        "ts": now,
                        "run_kind": "compose",
                        "kind": "red_plan",
                        "payload": json.dumps(payload),
                        "schema_version": 1,
                    },
                )
            logger.info("Recorded red_plan %s to Ledger for run %s (seq=%d)", plan.plan_id, self.run_id, next_seq)
        except Exception as exc:
            logger.warning("Could not write red_plan to agent_events table: %s", exc)
