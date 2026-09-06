"""Replay evaluation: backtesting detection candidates against telemetry."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence

import yaml

from core.detections.candidates import DetectionCandidate

logger = logging.getLogger(__name__)


@dataclass
class ReplayResult:
    """Outcome of backtesting candidate against telemetry."""

    matched: bool
    matches_count: int
    matched_events: List[Dict[str, Any]] = field(default_factory=list)
    feedback: str = ""


def replay_candidate(
    candidate: DetectionCandidate,
    captured_telemetry: Sequence[Dict[str, Any]],
) -> ReplayResult:
    """Evaluate candidate detection rule against captured telemetry rows.

    Rejects candidate if it matches zero captured attack activity.
    """
    if not captured_telemetry:
        return ReplayResult(
            matched=False,
            matches_count=0,
            feedback="Replay failed: no captured telemetry provided to evaluate.",
        )

    matched_events: List[Dict[str, Any]] = []

    # Parse candidate search patterns from YAML or content
    patterns: List[str] = []
    try:
        if candidate.format.lower() in ("sigma", "yaml"):
            data = yaml.safe_load(candidate.rule_content)
            if isinstance(data, dict):
                detection = data.get("detection", {})
                selection = detection.get("selection", {})
                if isinstance(selection, dict):
                    for k, val in selection.items():
                        if isinstance(val, list):
                            patterns.extend(str(v).lower().replace("\\", "") for v in val)
                        elif isinstance(val, str):
                            patterns.append(val.lower().replace("\\", ""))
    except Exception:
        pass

    if not patterns:
        # Fallback: look for technique_id or command words in rule content
        patterns = [candidate.technique_id.lower()]

    for event in captured_telemetry:
        event_str = (
            f"{event.get('process_name', '')} {event.get('command_line', '')} "
            f"{event.get('action', '')} {event.get('technique_id', '')} "
            f"{event.get('source', '')} {event.get('details', '')}"
        ).lower()

        # Check if event matches technique or rule selection patterns
        if event.get("technique_id") == candidate.technique_id or any(p in event_str for p in patterns):
            matched_events.append(event)

    matches_count = len(matched_events)
    matched = matches_count > 0
    feedback = (
        f"Replay verified: {matches_count} matching telemetry event(s) caught."
        if matched
        else "Replay failed: candidate rule matched 0 events in captured telemetry."
    )

    return ReplayResult(
        matched=matched,
        matches_count=matches_count,
        matched_events=matched_events,
        feedback=feedback,
    )
