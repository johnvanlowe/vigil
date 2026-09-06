"""LogLM-grounded detection authoring for model-only detection gaps.

When an attack step produces a 'loglm'-only verdict (flagged by model, missed by rules),
the embedding neighborhood of the anomalous finding reveals which behavioral features
separated attack activity from normal background traffic.

This module provides the grounding bridge: extracting those behavioral features to
shape rule authoring so candidates clear the anti-brittleness lint without environment
literals. If the LogLM MCP is absent or unreachable, authoring proceeds gracefully
without the assist and notes the absence in the rationale.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Sequence

from core.detections.candidates import DetectionCandidate
from core.detections.validation.lint import lint_candidate

logger = logging.getLogger(__name__)


class LogLMGroundingService:
    """Provides embedding neighborhood retrieval and feature grounding."""

    def __init__(self, mcp_client: Any = None):
        self.mcp_client = mcp_client

    async def get_embedding_neighborhood(
        self,
        finding_id: str,
        k: int = 5,
    ) -> Optional[List[str]]:
        """Query LogLM MCP or pgvector nearest_neighbors for anomalous finding."""
        if self.mcp_client is not None and hasattr(self.mcp_client, "call_tool"):
            try:
                res = await self.mcp_client.call_tool(
                    "loglm_nearest_neighbors",
                    {"finding_id": finding_id, "k": k},
                )
                if isinstance(res, dict) and "features" in res:
                    return res["features"]
            except Exception as exc:
                logger.debug("LogLM MCP client call failed: %s", exc)

        # Try internal helper if available
        try:
            from tools.mcp.deeptempo_findings import nearest_neighbors

            raw = nearest_neighbors(finding_id=finding_id, k=k)
            parsed = json.loads(raw) if isinstance(raw, str) else raw
            if isinstance(parsed, dict) and "features" in parsed:
                return parsed["features"]
            if isinstance(parsed, dict) and "neighbors" in parsed:
                features: List[str] = []
                for n in parsed["neighbors"]:
                    if "tactics" in n:
                        features.extend(n["tactics"])
                    if "features" in n:
                        features.extend(n["features"])
                if features:
                    return list(dict.fromkeys(features))
        except Exception as exc:
            logger.debug("Local nearest_neighbors unavailable: %s", exc)

        return None

    async def ground_authoring(
        self,
        gap: Dict[str, Any],
        candidate: DetectionCandidate,
        telemetry: Sequence[Dict[str, Any]] = (),
    ) -> DetectionCandidate:
        """Ground the candidate rule using LogLM neighborhood or fallback gracefully."""
        is_model_only = (
            gap.get("gap_type") == "model_only"
            or gap.get("verdict") == "loglm"
            or bool(gap.get("loglm_finding_id"))
        )
        finding_id = gap.get("loglm_finding_id", f"f-loglm-{gap.get('step_id', 'gap')}")

        neighborhood = None
        if is_model_only:
            neighborhood = await self.get_embedding_neighborhood(finding_id)

        if is_model_only and neighborhood:
            features_str = ", ".join(neighborhood)
            candidate.rationale = (
                f"Candidate grounded in LogLM embedding neighborhood for anomalous finding {finding_id}. "
                f"Discriminative behavioral features: {features_str}."
            )
            candidate.metadata["loglm_grounded"] = True
            candidate.metadata["neighborhood_features"] = neighborhood
        elif is_model_only:
            candidate.rationale = (
                f"Candidate authored for model-only gap {gap.get('technique_id')}. "
                "Proceeded without LogLM grounding assist (LogLM MCP absent/unreachable)."
            )
            candidate.metadata["loglm_grounded"] = False
        else:
            candidate.metadata["loglm_grounded"] = False

        # Validate that grounded candidate clears the behavioral lint
        lint_res = lint_candidate(candidate)
        candidate.metadata["clears_behavioral_lint"] = lint_res.anti_brittleness_passed
        return candidate
