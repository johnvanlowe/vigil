"""Metrics endpoint handler for Vigil API service."""

from fastapi import APIRouter, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from core.metrics.registry import get_metrics

router = APIRouter(tags=["Metrics"])


@router.get("/metrics")
def metrics_endpoint() -> Response:
    """Expose Prometheus metrics from the injected registry."""
    reg = get_metrics().registry
    data = generate_latest(reg)
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)
