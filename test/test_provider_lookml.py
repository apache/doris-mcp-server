"""Offline unit tests for the LookML semantic provider (lkml-based)."""

import sys
import unittest
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from providers.base import Filter, ModelSource, ProviderError, QueryRequest  # noqa: E402
from providers.lookml.provider import LookmlProvider, LookmlRuntime  # noqa: E402


LOOKML = """
view: orders {
  sql_table_name: dw.orders ;;
  dimension: country {
    type: string
    sql: ${TABLE}.country ;;
    description: "国家"
  }
  dimension_group: created {
    type: time
    timeframes: [date, week, month]
    sql: ${TABLE}.create_time ;;
  }
  measure: revenue {
    type: sum
    sql: ${TABLE}.amount ;;
  }
  measure: order_count {
    type: count
  }
}
"""


def _artifact(text: str = LOOKML):
    return LookmlProvider().build(ModelSource("orders.view.lkml", text))


class TestDetection(unittest.TestCase):
    def test_detects_view_lkml(self):
        score = LookmlProvider().detect(ModelSource("orders.view.lkml", LOOKML))
        self.assertGreaterEqual(score, 0.9)

    def test_rejects_yaml_files(self):
        score = LookmlProvider().detect(ModelSource("orders.yaml", LOOKML))
        self.assertEqual(score, 0.0)


class TestParse(unittest.TestCase):
    def test_dimension_group_expansion(self):
        model = LookmlProvider().parse(ModelSource("orders.view.lkml", LOOKML))
        names = {d.name for d in model.dimensions}
        self.assertEqual(names, {"country", "created_date", "created_week", "created_month"})

    def test_derived_table_rejected(self):
        bad = "view: v {\n  derived_table: { sql: SELECT 1 ;; }\n}\n"
        problems = LookmlProvider().validate(ModelSource("v.view.lkml", bad))
        self.assertTrue(any("sql_table_name" in p for p in problems))

    def test_cross_view_reference_rejected(self):
        bad = LOOKML.replace("sql: ${TABLE}.amount ;;", "sql: ${users.amount} ;;")
        problems = LookmlProvider().validate(ModelSource("orders.view.lkml", bad))
        self.assertTrue(any("cross-view" in p for p in problems))

    def test_same_view_reference_ok(self):
        text = LOOKML.replace("sql: ${TABLE}.amount ;;", "sql: ${amount} ;;")
        problems = LookmlProvider().validate(ModelSource("orders.view.lkml", text))
        self.assertEqual(problems, [])


class TestRuntime(unittest.TestCase):
    def setUp(self):
        self.art = _artifact()
        self.rt = LookmlRuntime()

    def test_artifact_provider_preserved(self):
        self.assertEqual(self.art.provider, "lookml")
        self.assertIn("lookml_views", self.art.payload)

    def test_metrics_via_shared_runtime(self):
        names = {m.name for m in self.rt.get_metrics(self.art)}
        self.assertEqual(names, {"revenue", "order_count"})

    def test_generate_sql(self):
        sql = self.rt.generate_sql(
            self.art,
            QueryRequest(
                metrics=["revenue"],
                dimensions=["country", "created_month"],
                filters=[Filter("created_date", "between", ["2025-01-01", "2025-03-31"])],
                order_by=["-revenue"],
                limit=50,
            ),
        )
        self.assertIn("sum(`orders`.`amount`) AS `revenue`", sql)
        self.assertIn("date_trunc(create_time, 'month') AS `created_month`", sql)
        self.assertIn("`dw`.`orders` AS `orders`", sql)
        self.assertIn("BETWEEN '2025-01-01' AND '2025-03-31'", sql)
        self.assertIn("LIMIT 50", sql)

    def test_wrong_artifact_provider_rejected(self):
        from providers.base import CompiledArtifact

        foreign = CompiledArtifact(provider="metricflow", name="x", payload={})
        with self.assertRaises(ValueError):
            self.rt.get_metrics(foreign)


if __name__ == "__main__":
    unittest.main(verbosity=2)
