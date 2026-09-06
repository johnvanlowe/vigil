"""Test verifying that all metrics defined in docs/metrics.md exist in the registry."""

import os
import re
from prometheus_client import generate_latest
from core.metrics.registry import VigilMetrics


def test_metrics_contract_agrees_with_registry():
    """Extract metric names from docs/metrics.md and assert each is declared in the registry."""
    metrics_doc_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../../docs/metrics.md")
    )
    assert os.path.isfile(metrics_doc_path)

    with open(metrics_doc_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Find all occurrences of `vigil_[a-zA-Z0-9_]+`
    doc_metrics = set(re.findall(r"`(vigil_[a-zA-Z0-9_]+)`", content))
    assert len(doc_metrics) >= 15, "Expected at least 15 metrics documented in docs/metrics.md"

    # Instantiate registry and get exposition
    metrics = VigilMetrics()
    exposition = generate_latest(metrics.registry).decode("utf-8")

    for metric_name in doc_metrics:
        # In Prometheus exposition, metric names appear as '# HELP <name>' or '# TYPE <name>'
        pattern = rf"# (?:HELP|TYPE) {metric_name}\b"
        assert re.search(pattern, exposition), (
            f"Metric {metric_name!r} from docs/metrics.md was not found in VigilMetrics registry."
        )
