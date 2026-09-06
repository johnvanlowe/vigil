"""Coverage projection and frontier calculation folded from Ledger events.

Computes detection coverage posture per environment on read:
- Techniques attacked and observed
- Coverage per technique by layer (rule, loglm, both, promoted)
- Open gaps
- The frontier: missed steps per cycle
Replay from the append-only Ledger reproduces the projection and SQL view deterministically.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence, Set

from core.storage.connection import get_db_manager

logger = logging.getLogger(__name__)


@dataclass
class TechniqueCoverage:
    """Coverage status for an individual ATT&CK technique."""

    technique_id: str
    layer: str  # rule, loglm, both, promoted, missed
    cycle_last_seen: int
    matching_rules: List[str] = field(default_factory=list)
    is_covered: bool = True


@dataclass
class CoveragePosture:
    """Consolidated coverage posture for an environment."""

    environment_id: str
    total_techniques_attacked: int
    techniques_covered: int
    techniques_missed: int
    coverage_by_layer: Dict[str, int]
    frontier: Dict[int, int]  # cycle_number -> missed_count
    techniques: Dict[str, TechniqueCoverage]
    open_gaps: List[Dict[str, Any]]


class CoverageService:
    """Folds reconstruction and promotion events into real-time coverage posture."""

    def __init__(self, session_factory: Any = None):
        self._session_factory = session_factory

    def _get_session(self):
        if self._session_factory:
            return self._session_factory()
        db_mgr = get_db_manager()
        return db_mgr.session()

    def project_from_events(
        self,
        events: Sequence[Dict[str, Any]],
        environment_id: str,
    ) -> CoveragePosture:
        """Fold raw agent_events into CoveragePosture deterministically."""
        techniques: Dict[str, TechniqueCoverage] = {}
        frontier_missed_per_cycle: Dict[int, int] = defaultdict(int)
        open_gaps: List[Dict[str, Any]] = []

        # Sort events by ts or sequence if present
        for event in events:
            kind = event.get("kind")
            payload = event.get("payload") or {}
            env = payload.get("environment_id") or "default"
            if env != environment_id:
                continue

            cycle = int(payload.get("cycle_number") or 1)
            tech = payload.get("technique_id")
            if not tech:
                continue

            if kind == "promotion":
                # Promoted rule elevates technique coverage to 'promoted'
                matching = [payload.get("rule_name") or payload.get("candidate_id", "custom_rule")]
                techniques[tech] = TechniqueCoverage(
                    technique_id=tech,
                    layer="promoted",
                    cycle_last_seen=cycle,
                    matching_rules=matching,
                    is_covered=True,
                )
            elif kind == "reconstruction":
                verdict = payload.get("verdict", "missed")
                rules = payload.get("matching_rules") or []

                # If technique was already promoted, it remains covered unless demoted
                existing = techniques.get(tech)
                if existing and existing.layer == "promoted":
                    continue

                is_covered = verdict in ("rule", "loglm", "both")
                techniques[tech] = TechniqueCoverage(
                    technique_id=tech,
                    layer=verdict,
                    cycle_last_seen=cycle,
                    matching_rules=rules,
                    is_covered=is_covered,
                )

                if verdict == "missed":
                    frontier_missed_per_cycle[cycle] += 1
                    open_gaps.append({
                        "step_id": payload.get("step_id"),
                        "technique_id": tech,
                        "cycle_number": cycle,
                        "reason": "Missed by both rules and LogLM",
                    })

        layer_counts = {"rule": 0, "loglm": 0, "both": 0, "promoted": 0, "missed": 0}
        covered_count = 0
        missed_count = 0

        for t in techniques.values():
            if t.layer in layer_counts:
                layer_counts[t.layer] += 1
            if t.is_covered:
                covered_count += 1
            else:
                missed_count += 1

        return CoveragePosture(
            environment_id=environment_id,
            total_techniques_attacked=len(techniques),
            techniques_covered=covered_count,
            techniques_missed=missed_count,
            coverage_by_layer=layer_counts,
            frontier=dict(sorted(frontier_missed_per_cycle.items())),
            techniques=techniques,
            open_gaps=open_gaps,
        )

    def get_frontier(
        self,
        environment_id: str,
        events: Optional[Sequence[Dict[str, Any]]] = None,
    ) -> Dict[int, int]:
        """Expose frontier (missed steps per cycle) for /metrics and scorecard."""
        if events is not None:
            posture = self.project_from_events(events, environment_id)
            return posture.frontier

        # Read from database
        try:
            with self._get_session() as session:
                rows = session.execute(
                    """
                    SELECT cycle_number, count(*) as missed_count
                    FROM coverage
                    WHERE environment_id = :env AND verdict = 'missed'
                    GROUP BY cycle_number
                    ORDER BY cycle_number;
                    """,
                    {"env": environment_id},
                ).fetchall()
                return {int(r[0]): int(r[1]) for r in rows}
        except Exception as exc:
            logger.debug("Database coverage query fallback: %s", exc)
            return {}
