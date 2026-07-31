"""Fix proxy metrics transformation rule — stub for vendored MetricFlow."""

from __future__ import annotations

from metricflow.semantic_interfaces.transformations.transform_rule import SemanticManifestTransformRule


class FixProxyMetricsRule(SemanticManifestTransformRule):
    """No-op stub — the full implementation requires upstream MetricFlow package."""

    @property
    def description(self) -> str:
        return "Fix proxy metrics (stub)"

    def transform_model(self, semantic_manifest):
        return semantic_manifest
