"""Typed artifacts for candidate detections and validation records.

Candidates are distinct from live detection rules: they carry their lint result,
replay result, review verdict, repair history, and grounding context.
Only after passing all gates in the validation harness can a candidate be promoted.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from core.time import utcnow


class CandidateStatus(str, Enum):
    """Lifecycle status of a detection candidate."""

    DRAFT = "draft"
    VALIDATING = "validating"
    VALIDATED = "validated"
    REJECTED = "rejected"
    PROMOTED = "promoted"


class RuleFormat(str, Enum):
    """Target detection rule format."""

    SIGMA = "sigma"
    SPLUNK = "splunk"
    ELASTIC = "elastic"
    KQL = "kql"


class LintResult(BaseModel):
    """Outcome of artifact linting and anti-brittleness checks."""

    passed: bool
    syntax_valid: bool = True
    anti_brittleness_passed: bool = True
    detected_literals: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    rewrite_guidance: Optional[str] = None


class ReplayResult(BaseModel):
    """Outcome of replaying candidate against captured attack telemetry."""

    passed: bool
    matched_events_count: int = 0
    matched_event_ids: List[str] = Field(default_factory=list)
    reason: Optional[str] = None


class ReviewResult(BaseModel):
    """Outcome of fresh-context judge evaluation."""

    passed: bool
    score: float = Field(..., ge=0.0, le=1.0)
    behavioral_alignment: str = "aligned"
    robustness_assessment: str = "high"
    critique: str = ""
    recommendations: List[str] = Field(default_factory=list)


class ValidationRecord(BaseModel):
    """Durable record of a candidate passing through the validation harness."""

    validation_id: str = Field(
        default_factory=lambda: f"val-{utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}"
    )
    lint_result: Optional[LintResult] = None
    replay_result: Optional[ReplayResult] = None
    review_result: Optional[ReviewResult] = None
    is_valid: bool = False
    repair_attempts: int = 0
    feedback_history: List[str] = Field(default_factory=list)
    validated_at: Optional[datetime] = None


class DetectionCandidate(BaseModel):
    """A candidate detection rule under test in the validation harness."""

    candidate_id: str = Field(
        default_factory=lambda: f"cand-{utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8]}"
    )
    gap_technique_id: str
    name: str
    format: str = "sigma"
    rule_content: str
    target_environment: str = "staging"
    source_step_id: Optional[str] = None
    source_finding_ids: List[str] = Field(default_factory=list)
    grounding_features: List[str] = Field(default_factory=list)
    loglm_neighborhood_used: bool = False
    validation: Optional[ValidationRecord] = None
    status: CandidateStatus = CandidateStatus.DRAFT
    created_at: datetime = Field(default_factory=utcnow)
    promoted_at: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
