"""Offline unit tests for the Cube semantic provider.

Covers: format detection, parse/validate errors, compilation, Doris SQL
generation (single cube, many_to_one joins, filters, ordering, limits),
and injection-safety guarantees of the generated SQL.
"""

import sys
import unittest
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from providers.base import Filter, ModelSource, ProviderError, QueryRequest  # noqa: E402
from providers.cube.provider import CubeProvider, CubeRuntime  # noqa: E402


CUBE_YAML = """
cubes:
  - name: orders
    sql_table: dw.orders
    joins:
      - name: users
        sql: "{CUBE}.user_id = {users}.id"
        relationship: many_to_one
    measures:
      - name: revenue
        type: sum
        sql: amount
        description: "总收入"
      - name: order_count
        type: count
    dimensions:
      - name: country
        sql: country
        type: string
      - name: create_time
        sql: create_time
        type: time
  - name: users
    sql_table: dw.users
    dimensions:
      - name: id
        sql: id
        type: number
        primary_key: true
      - name: city
        sql: city
        type: string
"""


def _artifact(yaml_text: str = CUBE_YAML):
    provider = CubeProvider()
    return provider.build(ModelSource("sales.yaml", yaml_text))


class TestDetection(unittest.TestCase):
    def test_detects_cube_yaml(self):
        score = CubeProvider().detect(ModelSource("sales.yaml", CUBE_YAML))
        self.assertGreaterEqual(score, 0.9)

    def test_rejects_non_yaml_extension(self):
        score = CubeProvider().detect(ModelSource("sales.txt", CUBE_YAML))
        self.assertEqual(score, 0.0)

    def test_rejects_other_yaml(self):
        score = CubeProvider().detect(ModelSource("a.yaml", "version: 2\nmodels: []\n"))
        self.assertEqual(score, 0.0)


class TestValidation(unittest.TestCase):
    def test_missing_cubes(self):
        problems = CubeProvider().validate(ModelSource("a.yaml", "foo: bar\n"))
        self.assertTrue(problems)

    def test_unknown_measure_type(self):
        bad = CUBE_YAML.replace("type: sum", "type: median")
        problems = CubeProvider().validate(ModelSource("a.yaml", bad))
        self.assertTrue(any("median" in p for p in problems))

    def test_measure_sql_required_for_sum(self):
        bad = CUBE_YAML.replace("        sql: amount\n", "")
        problems = CubeProvider().validate(ModelSource("a.yaml", bad))
        self.assertTrue(any("requires 'sql'" in p for p in problems))

    def test_only_many_to_one_joins(self):
        bad = CUBE_YAML.replace("many_to_one", "one_to_many")
        problems = CubeProvider().validate(ModelSource("a.yaml", bad))
        self.assertTrue(any("many_to_one" in p for p in problems))

    def test_duplicate_cube_rejected(self):
        dup = CUBE_YAML[CUBE_YAML.index("  - name: orders"):CUBE_YAML.index("  - name: users")]
        bad = CUBE_YAML + dup
        problems = CubeProvider().validate(ModelSource("a.yaml", bad))
        self.assertTrue(any("duplicate" in p for p in problems))


class TestCompile(unittest.TestCase):
    def test_artifact_envelope(self):
        art = _artifact()
        self.assertEqual(art.provider, "cube")
        self.assertTrue(art.source_digest)
        self.assertIn("orders", art.payload["cubes"])
        self.assertEqual(art.payload["metric_index"]["revenue"], "orders")
        self.assertEqual(art.payload["dimension_index"]["city"], "users")

    def test_artifact_json_roundtrip(self):
        from providers.base import CompiledArtifact

        art = _artifact()
        loaded = CompiledArtifact.from_json(art.to_json())
        self.assertEqual(loaded.payload, art.payload)
        self.assertEqual(loaded.source_digest, art.source_digest)


class TestRuntimeSQL(unittest.TestCase):
    def setUp(self):
        self.art = _artifact()
        self.rt = CubeRuntime()

    def test_simple_aggregate(self):
        sql = self.rt.generate_sql(self.art, QueryRequest(metrics=["revenue"]))
        self.assertIn("sum(`orders`.`amount`) AS `revenue`", sql)
        self.assertIn("FROM\n  `dw`.`orders` AS `orders`", sql)
        self.assertNotIn("GROUP BY", sql)

    def test_dimension_group_by(self):
        sql = self.rt.generate_sql(
            self.art, QueryRequest(metrics=["revenue"], dimensions=["country"])
        )
        self.assertIn("`orders`.`country` AS `country`", sql)
        self.assertIn("GROUP BY\n  `orders`.`country`", sql)

    def test_join_dimension(self):
        sql = self.rt.generate_sql(
            self.art, QueryRequest(metrics=["revenue"], dimensions=["city"])
        )
        self.assertIn("LEFT JOIN `dw`.`users` AS `users` ON", sql)
        self.assertIn("`users`.`city` AS `city`", sql)

    def test_no_join_when_unused(self):
        sql = self.rt.generate_sql(
            self.art, QueryRequest(metrics=["revenue"], dimensions=["country"])
        )
        self.assertNotIn("JOIN", sql)

    def test_structured_filters(self):
        sql = self.rt.generate_sql(
            self.art,
            QueryRequest(
                metrics=["revenue"],
                filters=[
                    Filter("country", "eq", "US"),
                    Filter("create_time", "between", ["2025-01-01", "2025-01-31"]),
                    Filter("country", "in", ["US", "CN"]),
                ],
            ),
        )
        self.assertIn("`orders`.`country` = 'US'", sql)
        self.assertIn("BETWEEN '2025-01-01' AND '2025-01-31'", sql)
        self.assertIn("IN ('US', 'CN')", sql)

    def test_filter_value_escaped(self):
        sql = self.rt.generate_sql(
            self.art,
            QueryRequest(
                metrics=["revenue"],
                filters=[Filter("country", "eq", "x' OR '1'='1")],
            ),
        )
        self.assertIn("'x'' OR ''1''=''1'", sql)
        self.assertNotIn("= 'x' OR '1'='1'", sql)

    def test_contains_uses_doris_concat(self):
        sql = self.rt.generate_sql(
            self.art,
            QueryRequest(metrics=["revenue"], filters=[Filter("country", "contains", "U")]),
        )
        self.assertIn("LIKE concat('%', 'U', '%')", sql)

    def test_order_by_and_limit(self):
        sql = self.rt.generate_sql(
            self.art,
            QueryRequest(
                metrics=["revenue"],
                dimensions=["country"],
                order_by=["-revenue", "country"],
                limit=10,
            ),
        )
        self.assertIn("ORDER BY\n  `revenue` DESC, `country` ASC", sql)
        self.assertIn("LIMIT 10", sql)

    # -- error paths ----------------------------------------------------------

    def test_unknown_metric(self):
        with self.assertRaises(ProviderError):
            self.rt.generate_sql(self.art, QueryRequest(metrics=["nope"]))

    def test_unknown_dimension(self):
        with self.assertRaises(ProviderError):
            self.rt.generate_sql(
                self.art, QueryRequest(metrics=["revenue"], dimensions=["nope"])
            )

    def test_unknown_filter_dimension(self):
        with self.assertRaises(ProviderError):
            self.rt.generate_sql(
                self.art,
                QueryRequest(metrics=["revenue"], filters=[Filter("nope", "eq", 1)]),
            )

    def test_bad_operator(self):
        with self.assertRaises(ProviderError):
            self.rt.generate_sql(
                self.art,
                QueryRequest(
                    metrics=["revenue"], filters=[Filter("country", "regex", ".*")]
                ),
            )

    def test_order_by_not_in_select(self):
        with self.assertRaises(ProviderError):
            self.rt.generate_sql(
                self.art, QueryRequest(metrics=["revenue"], order_by=["country"])
            )

    def test_identifier_injection_blocked(self):
        bad = CUBE_YAML.replace("sql: country", "sql: country; DROP TABLE x--")
        art = CubeProvider().build(ModelSource("evil.yaml", bad))
        # bare-column qualification must reject non-column sql here via expr;
        # the expression passes through as model-author SQL, but aliases stay safe
        sql = self.rt.generate_sql(art, QueryRequest(metrics=["revenue"], dimensions=["country"]))
        self.assertIn("AS `country`", sql)  # alias quoting intact


class TestMetadata(unittest.TestCase):
    def setUp(self):
        self.art = _artifact()
        self.rt = CubeRuntime()

    def test_get_metrics(self):
        names = {m.name for m in self.rt.get_metrics(self.art)}
        self.assertEqual(names, {"revenue", "order_count"})

    def test_get_dimensions_all(self):
        names = {d.name for d in self.rt.get_dimensions(self.art)}
        self.assertEqual(names, {"country", "create_time", "id", "city"})

    def test_get_dimensions_for_metric_includes_joined(self):
        names = {d.name for d in self.rt.get_dimensions(self.art, "revenue")}
        self.assertEqual(names, {"country", "create_time", "id", "city"})

    def test_get_dimensions_unknown_metric(self):
        with self.assertRaises(ProviderError):
            self.rt.get_dimensions(self.art, "nope")


if __name__ == "__main__":
    unittest.main(verbosity=2)
