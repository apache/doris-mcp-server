"""Offline unit tests for the MetricFlow provider adapter."""

import sys
import unittest
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from providers.base import Filter, ModelSource, ProviderError, QueryRequest  # noqa: E402
from providers.metricflow_adapter import (  # noqa: E402
    MetricFlowProviderAdapter,
    MetricFlowRuntimeAdapter,
)

MF_YAML = """
semantic_models:
  - name: orders
    model: ref('orders')
    measures:
      - name: revenue
        expr: amount
        agg: sum
    dimensions:
      - name: country
        type: categorical
      - name: ordered_at
        type: time
metrics:
  - name: total_revenue
    type: simple
    description: "总收入"
"""


class _FakeManifest:
    def list_metrics(self):
        return [{"name": "total_revenue", "description": "总收入", "type": "simple"}]

    def list_dimensions_for_metric(self, metric):
        return [{"name": "country", "type": "categorical"}]


class _FakeCompiler:
    def compile(self, metrics, group_by, where, order_by, limit, having):
        return "SELECT 1", "mf query", None


class TestBuildTime(unittest.TestCase):
    def setUp(self):
        self.provider = MetricFlowProviderAdapter()

    def test_detect_semantic_models(self):
        score = self.provider.detect(ModelSource("sem.yml", MF_YAML))
        self.assertGreaterEqual(score, 0.9)

    def test_detect_metrics_only(self):
        score = self.provider.detect(
            ModelSource("m.yml", "metrics:\n  - name: x\n    type: simple\n")
        )
        self.assertGreaterEqual(score, 0.7)

    def test_parse_extracts_preview(self):
        model = self.provider.parse(ModelSource("sem.yml", MF_YAML))
        self.assertEqual(model.provider, "metricflow")
        self.assertIn("revenue", {m.name for m in model.metrics})
        self.assertIn("total_revenue", {m.name for m in model.metrics})
        self.assertIn("country", {d.name for d in model.dimensions})

    def test_validate_rejects_empty(self):
        problems = self.provider.validate(ModelSource("a.yml", "version: 2\n"))
        self.assertTrue(problems)

    def test_compile_artifact(self):
        art = self.provider.build(ModelSource("sem.yml", MF_YAML))
        self.assertEqual(art.provider, "metricflow")
        self.assertEqual(art.payload["format"], "metricflow")
        self.assertTrue(art.payload["semantic_models"])


class TestRuntime(unittest.TestCase):
    def setUp(self):
        self.provider = MetricFlowProviderAdapter()
        self.art = self.provider.build(ModelSource("sem.yml", MF_YAML))

    def test_unbound_generate_sql_fails_loudly(self):
        rt = MetricFlowRuntimeAdapter()
        self.assertFalse(rt.is_bound)
        with self.assertRaises(ProviderError):
            rt.generate_sql(self.art, QueryRequest(metrics=["total_revenue"]))

    def test_payload_projection_without_binding(self):
        rt = MetricFlowRuntimeAdapter()
        names = {m.name for m in rt.get_metrics(self.art)}
        self.assertEqual(names, {"revenue", "total_revenue"})
        dims = {d.name for d in rt.get_dimensions(self.art)}
        self.assertEqual(dims, {"country", "ordered_at"})

    def test_bind_returns_copy_singleton_untouched(self):
        singleton = MetricFlowRuntimeAdapter()
        bound = singleton.bind(_FakeCompiler(), _FakeManifest())
        self.assertIsNot(bound, singleton)
        self.assertFalse(singleton.is_bound)
        self.assertTrue(bound.is_bound)

    def test_bound_metadata_from_manifest(self):
        bound = MetricFlowRuntimeAdapter().bind(_FakeCompiler(), _FakeManifest())
        metrics = bound.get_metrics(self.art)
        self.assertEqual([m.name for m in metrics], ["total_revenue"])
        dims = bound.get_dimensions(self.art, "total_revenue")
        self.assertEqual([d.name for d in dims], ["country"])

    def test_bound_generate_sql_delegates(self):
        bound = MetricFlowRuntimeAdapter().bind(_FakeCompiler(), _FakeManifest())
        sql = bound.generate_sql(
            self.art,
            QueryRequest(
                metrics=["total_revenue"],
                dimensions=["country"],
                filters=[Filter("country", "eq", "US")],
                limit=10,
            ),
        )
        self.assertEqual(sql, "SELECT 1")

    def test_bound_generate_sql_rejects_non_eq_filter(self):
        bound = MetricFlowRuntimeAdapter().bind(_FakeCompiler(), _FakeManifest())
        with self.assertRaises(ProviderError):
            bound.generate_sql(
                self.art,
                QueryRequest(
                    metrics=["total_revenue"], filters=[Filter("country", "gt", 5)]
                ),
            )

    def test_bound_compile_error_wrapped(self):
        class _BadCompiler:
            def compile(self, *args):
                return None, None, "boom"

        bound = MetricFlowRuntimeAdapter().bind(_BadCompiler(), _FakeManifest())
        with self.assertRaises(ProviderError):
            bound.generate_sql(self.art, QueryRequest(metrics=["x"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
