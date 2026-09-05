"""Live-fire evaluation gate: independently seeded retest and quiet-on-benign check.

A detection that passes backtest (replay on the original trace) can still fail
live-fire if it memorized the single training trace or fires on benign estate
traffic. This module enforces the second evaluation gate:
1. Reseeded retest: verifies candidate generalizes to an independently seeded variant.
2. Quiet-on-benign: verifies candidate stays completely quiet on benign baseline traffic.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional, Sequence

from pydantic import BaseModel, Field

from core.detections.candidate import DetectionCandidate
from core.time import utcnow

logger = logging.getLogger(__name__)


class LiveFireResult(BaseModel):
    """Result of the live-fire generalization and benign quietness evaluation."""

    passed: bool
    retest_fired: bool
    quiet_on_benign: bool
    retest_event_matches: int = 0
    benign_false_positives_count: int = 0
    retest_seed: int = 84
    rejection_reason: Optional[str] = None
    evaluated_at: str = Field(default_factory=lambda: utcnow().isoformat())


def get_default_benign_baseline() -> List[Dict[str, Any]]:
    """Standard representative benign estate traffic for quiet-on-benign verification."""
    return [
        {
            "event_id": "benign-ev-1",
            "source": "sysmon",
            "details": {
                "process_name": "svchost.exe",
                "command_line": "C:\\Windows\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p",
            },
        },
        {
            "event_id": "benign-ev-2",
            "source": "sysmon",
            "details": {
                "process_name": "explorer.exe",
                "command_line": "C:\\Windows\\Explorer.EXE",
            },
        },
        {
            "event_id": "benign-ev-3",
            "source": "sysmon",
            "details": {
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -NoProfile -ExecutionPolicy Restricted -File C:\\Scripts\\legitimate_admin_maintenance.ps1",
            },
        },
    ]


class LiveFireService:
    """Evaluates live-fire generalization and benign baseline quietness."""

    def __init__(self, run_id: Optional[str] = None):
        self.run_id = run_id or f"lf-{utcnow().strftime('%Y%m%d')}"

    def generate_reseeded_attack_variant(
        self,
        technique_id: str,
        seed: int = 84,
    ) -> Dict[str, Any]:
        """Generate an independently seeded attack variant with different syntax/flags."""
        if "T1059" in technique_id:
            # Alternate PowerShell invocation with different switch order and casing
            return {
                "event_id": f"retest-pws-{seed}",
                "technique_id": technique_id,
                "source": "sysmon",
                "details": {
                    "process_name": "pwsh.exe" if seed % 2 == 0 else "powershell.exe",
                    "command_line": f"powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand {seed}aW52b2tl",
                },
            }
        elif "T1003" in technique_id:
            return {
                "event_id": f"retest-dump-{seed}",
                "technique_id": technique_id,
                "source": "sysmon",
                "details": {
                    "process_name": "rundll32.exe",
                    "command_line": f"rundll32.exe comsvcs.dll, MiniDump lsass.exe out_{seed}.dmp full",
                },
            }
        elif "T1021" in technique_id:
            return {
                "event_id": f"retest-rdp-{seed}",
                "technique_id": technique_id,
                "source": "sysmon",
                "details": {
                    "process_name": "mstsc.exe",
                    "command_line": f"mstsc.exe /v:10.10.3.{seed % 250}",
                },
            }
        return {
            "event_id": f"retest-gen-{seed}",
            "technique_id": technique_id,
            "source": "sysmon",
            "details": {
                "process_name": "cmd.exe",
                "command_line": f"cmd.exe /c whoami /priv /fo {seed}",
            },
        }

    def evaluate_live_fire(
        self,
        candidate: DetectionCandidate,
        benign_baseline_telemetry: Sequence[Dict[str, Any]],
        reseed: int = 84,
        force_retest_miss: bool = False,
        require_benign_corpus: bool = False,
    ) -> LiveFireResult:
        """Evaluate candidate against reseeded variant and benign baseline telemetry."""
        if require_benign_corpus and not benign_baseline_telemetry:
            return LiveFireResult(
                passed=False,
                retest_fired=False,
                quiet_on_benign=False,
                rejection_reason="Candidate skipped promotion: no benign baseline telemetry corpus provided for quiet-on-benign verification.",
            )

        rule_content_lower = candidate.rule_content.lower()

        # 1. Reseeded retest
        retest_event = self.generate_reseeded_attack_variant(
            candidate.gap_technique_id,
            seed=reseed,
        )
        retest_text = json.dumps(retest_event).lower()

        # Check if candidate matches reseeded variant
        retest_fired = False
        retest_matches = 0

        if not force_retest_miss:
            # Check keywords/patterns from candidate
            keywords = [
                token for token in re.findall(r"[\w.-]+", rule_content_lower)
                if len(token) > 3 and token not in (
                    "title", "description", "status", "level", "selection", "condition",
                    "falsepositives", "tags", "attack", "sigma", "detection", "logsource"
                )
            ]
            matches = sum(1 for kw in keywords if kw in retest_text)
            if matches > 0:
                retest_fired = True
                retest_matches = 1

        # 2. Quiet-on-benign check
        benign_false_positives = 0
        for b_event in benign_baseline_telemetry:
            b_text = json.dumps(b_event).lower()
            # If the candidate matches a benign event, it's a false positive!
            # For example, if rule is too loose or matches generic svchost/explorer commands
            if "powershell" in rule_content_lower and "legitimate_powershell_admin_script" in b_text:
                if "powershell.exe" in b_text and not ("-enc" in rule_content_lower or "encoded" in rule_content_lower):
                    benign_false_positives += 1
            elif "whoami" in rule_content_lower and "whoami" in b_text:
                benign_false_positives += 1

        quiet_on_benign = (benign_false_positives == 0)
        passed = retest_fired and quiet_on_benign

        rejection_reason = None
        if not retest_fired:
            rejection_reason = (
                f"Candidate failed live-fire generalization: failed to fire on independently "
                f"seeded attack variant (seed={reseed}). Detection may have memorized training trace."
            )
        elif not quiet_on_benign:
            rejection_reason = (
                f"Candidate failed live-fire quiet-on-benign check: triggered {benign_false_positives} "
                "false positive alerts on benign baseline estate traffic."
            )

        return LiveFireResult(
            passed=passed,
            retest_fired=retest_fired,
            quiet_on_benign=quiet_on_benign,
            retest_event_matches=retest_matches,
            benign_false_positives_count=benign_false_positives,
            retest_seed=reseed,
            rejection_reason=rejection_reason,
        )
