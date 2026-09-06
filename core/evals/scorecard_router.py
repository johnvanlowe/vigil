"""Router exposing dryrun scorecard and hash-addressed artifacts."""

from __future__ import annotations

import json
from typing import Any, Dict, Optional
from fastapi import APIRouter, HTTPException, Response, status

from core.artifacts.service import ArtifactService
from core.cli.dryrun import run_dryrun
from core.evals.scorecard import Scorecard
from core.routing import Auth, RouterMeta

router = APIRouter()

ROUTER_META = RouterMeta(
    prefix="/api/v1",
    tags=["Scorecard", "Artifacts"],
    auth=Auth.REQUIRED,
)

_cached_scorecard: Optional[Scorecard] = None


@router.get("/scorecard")
async def get_scorecard() -> Dict[str, Any]:
    """Retrieve the latest unattended evaluation scorecard."""
    global _cached_scorecard
    if _cached_scorecard is None:
        try:
            _cached_scorecard = run_dryrun(scenario="redrun_v1", provider="frontier")
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to generate scorecard: {exc}",
            ) from exc

    return _cached_scorecard.to_dict()


@router.get("/artifacts/{artifact_hash}")
async def get_artifact(artifact_hash: str) -> Dict[str, Any]:
    """Retrieve artifact content or metadata by SHA-256 hash."""
    service = ArtifactService()
    data = service.get(artifact_hash)
    if data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Artifact '{artifact_hash}' not found",
        )

    try:
        parsed = json.loads(data.decode("utf-8"))
        return {"artifact_hash": artifact_hash, "data": parsed}
    except Exception:
        return {
            "artifact_hash": artifact_hash,
            "byte_length": len(data),
            "media_type": "application/octet-stream",
        }


@router.get("/artifacts/{artifact_hash}/download")
async def download_artifact(artifact_hash: str) -> Response:
    """Download artifact bytes as PDF or binary payload."""
    service = ArtifactService()
    data = service.get(artifact_hash)
    if data is None:
        # If not stored in DB, generate minimal fallback deterministic PDF for scorecard
        global _cached_scorecard
        if _cached_scorecard and _cached_scorecard.artifact_hash == artifact_hash:
            data = json.dumps(_cached_scorecard.to_dict()).encode("utf-8")
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Artifact '{artifact_hash}' not found",
            )

    media_type = "application/pdf" if data.startswith(b"%PDF") else "application/json"
    filename = f"scorecard-{artifact_hash[:8]}.{'pdf' if media_type == 'application/pdf' else 'json'}"

    return Response(
        content=data,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
