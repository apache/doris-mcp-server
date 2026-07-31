"""Unit tests for SemanticManifest.list_dimensions_for_metric.

Covers recursive measure resolution across all metric types:
  - simple metric (type_params.measure)
  - derived-of-derived chains (type_params.metrics[] resolved recursively)
  - ratio metrics (numerator/denominator reference metrics)
  - conversion metrics (base_measure / conversion_measure)
  - cumulative metrics wrapping another metric
  - reference cycles (visited-set guard, must not hang)
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from store.manifest import SemanticManifest  # noqa: E402


SEMANTIC_MODELS = [
    {
        "name": "orders",
        "measures": [{"name": "total_amount"}, {"name": "order_count"}],
        "dimensions": [
            {"name": "channel", "type": "categorical", "description": "渠道"},
            {"name": "order_date", "type": "time", "description": "下单日期"},
        ],
    },
    {
        "name": "users",
        "measures": [{"name": "user_count"}],
        "dimensions": [
            {"name": "city", "type": "categorical", "description": "城市"},
        ],
    },
    {
        "name": "visits",
        "measures": [{"name": "visit_count"}, {"name": "signup_count"}],
        "dimensions": [
            {"name": "source", "type": "categorical", "description": "来源"},
        ],
    },
]

METRICS = [
    {
        "name": "total_amount",
        "type": "simple",
        "type_params": {"measure": {"name": "total_amount"}},
    },
    {
        "name": "order_count",
        "type": "simple",
        "type_params": {"measure": {"name": "order_count"}},
    },
    {
        "name": "user_count",
        "type": "simple",
        "type_params": {"measure": {"name": "user_count"}},
    },
    {
        "name": "amount_per_order",
        "type": "ratio",
        "type_params": {
            "numerator": {"name": "total_amount"},
            "denominator": {"name": "order_count"},
        },
    },
    {
        "name": "revenue_per_user",
        "type": "derived",
        "type_params": {"metrics": [{"name": "total_amount"}, {"name": "user_count"}]},
    },
    {
        "name": "revenue_per_user_double",
        "type": "derived",
        "type_params": {
            "expr": "revenue_per_user * 2",
            "metrics": [{"name": "revenue_per_user"}],
        },
    },
    {
        "name": "visit_to_signup",
        "type": "conversion",
        "type_params": {
            "conversion_type_params": {
                "base_measure": {"name": "visit_count"},
                "conversion_measure": {"name": "signup_count"},
                "entity": "user",
            },
        },
    },
    {
        "name": "cumulative_amount",
        "type": "cumulative",
        "type_params": {
            "cumulative_type_params": {
                "metric": {"name": "total_amount"},
                "window": "7 days",
            },
        },
    },
    # Reference cycle: cycle_a -> cycle_b -> cycle_a
    {
        "name": "cycle_a",
        "type": "derived",
        "type_params": {"metrics": [{"name": "cycle_b"}]},
    },
    {
        "name": "cycle_b",
        "type": "derived",
        "type_params": {"metrics": [{"name": "cycle_a"}]},
    },
]


def _make_manifest() -> SemanticManifest:
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8")
    json.dump({"metrics": METRICS, "semantic_models": SEMANTIC_MODELS}, tmp)
    tmp.close()
    manifest = SemanticManifest(Path(tmp.name))
    Path(tmp.name).unlink()
    return manifest


class TestListDimensionsForMetric(unittest.TestCase):

    def setUp(self):
        self.manifest = _make_manifest()

    def _dim_names(self, metric_name: str) -> set[str]:
        return {d["name"] for d in self.manifest.list_dimensions_for_metric(metric_name)}

    def test_unknown_metric_returns_empty(self):
        self.assertEqual(self.manifest.list_dimensions_for_metric("nope"), [])

    def test_simple_metric(self):
        self.assertEqual(
            self._dim_names("total_amount"), {"channel", "order_date"})

    def test_ratio_metric_resolves_numerator_denominator(self):
        self.assertEqual(
            self._dim_names("amount_per_order"), {"channel", "order_date"})

    def test_derived_metric_resolves_sub_metrics(self):
        self.assertEqual(
            self._dim_names("revenue_per_user"), {"channel", "order_date", "city"})

    def test_derived_of_derived_resolves_recursively(self):
        """Second-level derived chain must resolve all the way to measures."""
        self.assertEqual(
            self._dim_names("revenue_per_user_double"),
            {"channel", "order_date", "city"},
        )

    def test_conversion_metric_resolves_base_and_conversion_measures(self):
        self.assertEqual(self._dim_names("visit_to_signup"), {"source"})

    def test_cumulative_metric_wraps_metric(self):
        self.assertEqual(
            self._dim_names("cumulative_amount"), {"channel", "order_date"})

    def test_reference_cycle_does_not_hang(self):
        """A derived-metric cycle must terminate via the visited guard."""
        self.assertEqual(self._dim_names("cycle_a"), set())


if __name__ == "__main__":
    unittest.main(verbosity=2)
