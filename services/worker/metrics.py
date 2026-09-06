"""Prometheus metrics helper for Vigil Worker service."""

from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from core.metrics.registry import get_metrics


def get_worker_metrics_payload() -> bytes:
    """Export Prometheus format metrics string for the worker process."""
    return generate_latest(get_metrics().registry)
