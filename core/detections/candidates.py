"""Core loop contract types for detection verdicts, candidates, and validation.

Types-only module defining pure contracts and Pydantic schemas for the loop.
No behavior, no concrete detection engine imports.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

from core.time import utcnow


class VerdictOutcome(str, Enum):
    """Classification of detection capability against an attack step."""

    RULE = "rule"
    LOGLM = "loglm"
    BOTH = "both"
    MISSED = "missed"


class CandidateStatus(str, Enum):
    """Lifecycle status of a detection candidate."""

    DRAFT = "draft"
    VALIDATING = "validating"
    VALIDATED = "validated"
    REJECTED = "rejected"
    PROMOTED = "promoted"
    DEMOTED = "demoted"


class DetectionVerdict(BaseModel):
    """Verdict evaluating whether an attack step was detected."""

    step_id: str
    technique_id: str
    verdict: Literal["rule", "loglm", "both", "missed"]
    environment_id: str
    matching_rules: List[str] = Field(default_factory=list)
    evidence_citations: List[Dict[str, Any]] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=utcnow)
    cycle_number: Optional[int] = None
    telemetry_count: int = 0
    raw_evidence: Optional[Dict[str, Any]] = None


class ValidationRecord(BaseModel):
    """Detailed audit record of multi-gate detection candidate validation."""

    candidate_id: str
    environment_id: str
    is_valid: bool
    passed_lint: bool = False
    passed_replay: bool = False
    passed_judge: bool = False
    repair_attempts: int = 0
    repair_history: List[Dict[str, Any]] = Field(default_factory=list)
    lint_feedback: Optional[str] = None
    replay_matches_count: int = 0
    judge_feedback: Optional[str] = None
    validated_at: datetime = Field(default_factory=utcnow)
    error: Optional[str] = None


class DetectionCandidate(BaseModel):
    """A proposed detection rule or LogLM behavioral profile."""

    candidate_id: str
    environment_id: str
    technique_id: str
    gap_id: Optional[str] = None
    format: str = "sigma"
    rule_name: str
    rule_content: str
    rationale: str
    target_log_sources: List[str] = Field(default_factory=list)
    status: CandidateStatus = CandidateStatus.DRAFT
    validation_record: Optional[ValidationRecord] = None
    created_at: datetime = Field(default_factory=utcnow)
    promoted_at: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
