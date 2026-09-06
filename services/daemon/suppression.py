"""Daemon finding suppression filter integrating active Policy(kind=suppression)."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from core.policies.suppression import is_suppressed
from core.policies.service import PolicyService

logger = logging.getLogger(__name__)


class DaemonSuppressionFilter:
    """Evaluates incoming findings against active suppression policies."""

    def __init__(self, policy_service: Optional[PolicyService] = None):
        self._policy_service = policy_service or PolicyService()

    def should_suppress(self, finding: Dict[str, Any]) -> bool:
        """Determine if a finding should be skipped by the daemon."""
        suppressed, policy_id = is_suppressed(finding, service=self._policy_service)
        if suppressed:
            logger.info("Daemon suppressed finding %s under policy %s", finding.get("finding_id"), policy_id)
            return True
        return False
