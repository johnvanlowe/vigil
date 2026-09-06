"""FastAPI endpoint for recording finding verdicts."""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from core.findings.verdicts import VerdictAction, record_verdict

router = APIRouter(prefix="/verdicts", tags=["Verdicts"])


class RecordVerdictRequest(BaseModel):
    finding_id: str
    action: VerdictAction
    actor: str
    reason: Optional[str] = None
    source: str = "ui"
    new_severity: Optional[str] = None
    loglm_provenance: Optional[Dict[str, Any]] = None
    attack_mapping: Optional[List[Dict[str, Any]]] = None
    run_id: Optional[str] = None


@router.post("", status_code=status.HTTP_201_CREATED)
async def post_verdict(request: RecordVerdictRequest) -> Dict[str, Any]:
    """Record a canonical verdict on a finding."""
    try:
        verdict = record_verdict(
            finding_id=request.finding_id,
            action=request.action,
            actor=request.actor,
            reason=request.reason,
            source=request.source,
            new_severity=request.new_severity,
            loglm_provenance=request.loglm_provenance,
            attack_mapping=request.attack_mapping,
            run_id=request.run_id,
        )
        return {"status": "ok", "verdict": verdict}
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to record verdict: {exc}"
        ) from exc
