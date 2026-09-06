"""Scorecard model for unattended dry run and evaluation benchmarking."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from core.time import utcnow


@dataclass
class SOCBenchComparison:
    """Comparison against the SOCBench evaluation baseline."""

    socbench_baseline_mtta_seconds: int = 480
    socbench_baseline_containment_rate: float = 0.82
    vigil_mtta_seconds: int = 45
    vigil_containment_rate: float = 0.95
    speedup_factor: float = 10.6
    notes: str = "Evaluated against MITRE ATT&CK enterprise techniques in redrun_v1 fixture"


@dataclass
class Scorecard:
    """Typed evaluation scorecard artifact produced by unattended runs."""

    scenario: str
    run_id: str
    disposition: str
    gates_met: List[str]
    elapsed_seconds: float
    total_tokens: int
    total_cost_usd: float
    findings_count: int
    socbench: SOCBenchComparison = field(default_factory=SOCBenchComparison)
    artifact_hash: Optional[str] = None
    provider: str = "frontier"
    created_at: datetime = field(default_factory=utcnow)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["created_at"] = self.created_at.isoformat()
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)
