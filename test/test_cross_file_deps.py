"""Unit tests for cross-file dependency detection before delete.

Covers:
  - Delete independent file → allowed
  - Derived metric references deleted measure → blocked
  - Ratio metric references deleted measure → blocked
  - Conversion metric references deleted entity → blocked
  - Foreign entity reference → blocked
  - create_metric: false → not treated as export
  - Same measure exists in another surviving file → allowed
  - Non-YAML file → skipped
  - Multiple surviving files depend on deleted file → all reported
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from tools.dependency import (  # noqa: E402
    check_delete_dependencies,
    _extract_exports,
    _extract_references,
    _extract_measure_names_from_expr,
    _extract_ref_name,
)


# ══════════════════════════════════════════════════════════════════
# YAML fixtures
# ══════════════════════════════════════════════════════════════════

ORDERS_YAML = """---
semantic_model:
  name: orders
  db_table: dw.orders
  defaults:
    agg_time_dimension: order_date
  entities:
    - name: order
      type: primary
      expr: order_id
  measures:
    - name: total_amount
      expr: amount
      agg: sum
    - name: order_count
      expr: order_id
      agg: count_distinct
"""

USERS_YAML = """---
semantic_model:
  name: users
  db_table: dw.users
  defaults:
    agg_time_dimension: register_date
  entities:
    - name: user
      type: primary
      expr: user_id
  measures:
    - name: user_count
      expr: user_id
      agg: count_distinct
"""

REVENUE_YAML = """---
semantic_model:
  name: revenue_metrics
  db_table: dw.orders
  defaults:
    agg_time_dimension: order_date
  entities:
    - name: order
      type: primary
      expr: order_id
  metrics:
    - name: revenue_per_user
      type: derived
      description: 人均消费
      expr: total_amount / user_count
"""

RATIO_METRIC_YAML = """---
semantic_model:
  name: ratio_metrics
  db_table: dw.orders
  defaults:
    agg_time_dimension: order_date
  entities:
    - name: order
      type: primary
      expr: order_id
  metrics:
    - name: order_completion_rate
      type: ratio
      description: 订单完成率
      numerator: order_count
      denominator: total_amount
"""

CONVERSION_METRIC_YAML = """---
semantic_model:
  name: conversion_metrics
  db_table: dw.orders
  defaults:
    agg_time_dimension: order_date
  entities:
    - name: order
      type: primary
      expr: order_id
    - name: user
      type: foreign
      expr: user_id
  metrics:
    - name: visit_to_order
      type: conversion
      description: 访问到下单转化
      entity: user
"""

CREATE_METRIC_FALSE_YAML = """---
semantic_model:
  name: internal_helpers
  db_table: dw.orders
  defaults:
    agg_time_dimension: order_date
  entities:
    - name: order
      type: primary
      expr: order_id
  measures:
    - name: internal_counter
      expr: order_id
      agg: count
      create_metric: false
"""

SAME_MEASURE_TWO_FILES_YAML = """---
semantic_model:
  name: orders_v2
  db_table: dw.orders
  defaults:
    agg_time_dimension: order_date
  entities:
    - name: order
      type: primary
      expr: order_id
  measures:
    - name: total_amount
      expr: amount
      agg: sum
"""

MODEL_REF_YAML = """---
semantic_model:
  name: order_facts
  model: ref('orders')
  db_table: dw.order_facts
  defaults:
    agg_time_dimension: order_date
  entities:
    - name: order
      type: primary
      expr: order_id
  measures:
    - name: fact_count
      expr: order_id
      agg: count
"""

MODEL_REF_PLAIN_YAML = """---
semantic_model:
  name: order_facts_plain
  model: orders
  db_table: dw.order_facts
  defaults:
    agg_time_dimension: order_date
  entities:
    - name: order
      type: primary
      expr: order_id
  measures:
    - name: fact_count
      expr: order_id
      agg: count
"""


# ══════════════════════════════════════════════════════════════════
class TestDeleteDependencies(unittest.TestCase):

    def test_delete_independent_file_no_error(self):
        """Deleting a file no other file depends on → empty error list."""
        active = {
            "orders.yaml": ORDERS_YAML,
            "users.yaml": USERS_YAML,
        }
        errors = check_delete_dependencies("orders.yaml", ORDERS_YAML, active)
        self.assertEqual(errors, [],
                         f"Expected no errors, got: {errors}")

    def test_derived_metric_references_deleted_measure(self):
        """Deleting orders.yaml when revenue.yaml has a derived metric
        referencing total_amount → blocked."""
        active = {
            "orders.yaml": ORDERS_YAML,
            "users.yaml": USERS_YAML,
            "revenue.yaml": REVENUE_YAML,
        }
        errors = check_delete_dependencies("orders.yaml", ORDERS_YAML, active)
        self.assertEqual(len(errors), 1,
                         f"Expected 1 error, got {len(errors)}: {errors}")
        self.assertIn("revenue.yaml", errors[0])
        self.assertIn("total_amount", errors[0])
        self.assertIn("orders.yaml", errors[0])

    def test_ratio_metric_references_deleted_measure(self):
        """Deleting orders.yaml when ratio_metrics.yaml has a ratio metric
        referencing order_count and total_amount → blocked."""
        active = {
            "orders.yaml": ORDERS_YAML,
            "users.yaml": USERS_YAML,
            "ratio_metrics.yaml": RATIO_METRIC_YAML,
        }
        errors = check_delete_dependencies("orders.yaml", ORDERS_YAML, active)
        # ratio_metrics references both order_count AND total_amount from orders
        self.assertGreaterEqual(len(errors), 1,
                                f"Expected at least 1 error, got {len(errors)}: {errors}")
        error_text = " ".join(errors)
        self.assertIn("ratio_metrics.yaml", error_text)

    def test_delete_orders_does_not_affect_conversion_metric(self):
        """Deleting orders.yaml when conversion_metrics.yaml has a metric
        referencing entity 'user' (provided by users.yaml) → allowed."""
        active = {
            "orders.yaml": ORDERS_YAML,
            "users.yaml": USERS_YAML,
            "conversion_metrics.yaml": CONVERSION_METRIC_YAML,
        }
        errors = check_delete_dependencies("orders.yaml", ORDERS_YAML, active)
        # conversion_metrics references entity 'user' which comes from users.yaml, not orders
        self.assertEqual(errors, [],
                         f"orders.yaml not depended on by conversion_metrics, got: {errors}")

    def test_create_metric_false_not_exported(self):
        """A measure with create_metric: false should not be treated as
        an export — deleting the file is safe."""
        active = {
            "internal.yaml": CREATE_METRIC_FALSE_YAML,
            "orders.yaml": ORDERS_YAML,
        }
        errors = check_delete_dependencies("internal.yaml", CREATE_METRIC_FALSE_YAML, active)
        self.assertEqual(errors, [],
                         f"create_metric:false should not block deletion, got: {errors}")

    def test_same_measure_exists_in_another_file(self):
        """If total_amount is provided by both orders.yaml and orders_v2.yaml,
        deleting orders.yaml is allowed because the measure still exists."""
        active = {
            "orders.yaml": ORDERS_YAML,
            "orders_v2.yaml": SAME_MEASURE_TWO_FILES_YAML,
            "revenue.yaml": REVENUE_YAML,
        }
        errors = check_delete_dependencies("orders.yaml", ORDERS_YAML, active)
        self.assertEqual(errors, [],
                         f"total_amount provided by orders_v2 too, should allow: {errors}")

    def test_delete_users_breaks_revenue(self):
        """Deleting users.yaml when revenue.yaml references user_count → blocked."""
        active = {
            "orders.yaml": ORDERS_YAML,
            "users.yaml": USERS_YAML,
            "revenue.yaml": REVENUE_YAML,
        }
        errors = check_delete_dependencies("users.yaml", USERS_YAML, active)
        self.assertEqual(len(errors), 1,
                         f"Expected 1 error, got {len(errors)}: {errors}")
        self.assertIn("revenue.yaml", errors[0])
        self.assertIn("user_count", errors[0])

    def test_multiple_files_depend_on_deleted_file(self):
        """Two surviving files both reference the deleted file's exports → all reported."""
        active = {
            "orders.yaml": ORDERS_YAML,
            "users.yaml": USERS_YAML,
            "revenue.yaml": REVENUE_YAML,
            "ratio_metrics.yaml": RATIO_METRIC_YAML,
        }
        errors = check_delete_dependencies("orders.yaml", ORDERS_YAML, active)
        # revenue references total_amount, ratio_metrics references order_count & total_amount
        self.assertGreaterEqual(len(errors), 2,
                                f"Expected at least 2 errors, got {len(errors)}: {errors}")
        error_text = " ".join(errors)
        self.assertIn("revenue.yaml", error_text)
        self.assertIn("ratio_metrics.yaml", error_text)

    def test_non_yaml_file_deletion_skipped(self):
        """Deleting a non-YAML file (like project.yaml with just time_config)
        has no exports → always allowed."""
        project_yaml = """---
time_config:
  calendar:
    - table: dw.dim_date
      column: date_id
      grain: day
"""
        active = {
            "project.yaml": project_yaml,
            "orders.yaml": ORDERS_YAML,
        }
        errors = check_delete_dependencies("project.yaml", project_yaml, active)
        self.assertEqual(errors, [],
                         "Non-model YAML should have no exports")

    def test_model_ref_field_blocks_delete(self):
        """Deleting orders.yaml when order_facts.yaml references model
        'orders' via ``model: ref('orders')`` → blocked."""
        active = {
            "orders.yaml": ORDERS_YAML,
            "order_facts.yaml": MODEL_REF_YAML,
        }
        errors = check_delete_dependencies("orders.yaml", ORDERS_YAML, active)
        self.assertEqual(len(errors), 1,
                         f"Expected 1 error, got {len(errors)}: {errors}")
        self.assertIn("order_facts.yaml", errors[0])
        self.assertIn("orders", errors[0])

    def test_model_ref_plain_name_blocks_delete(self):
        """A plain ``model: orders`` (no ref() wrapper) also blocks deletion."""
        active = {
            "orders.yaml": ORDERS_YAML,
            "order_facts_plain.yaml": MODEL_REF_PLAIN_YAML,
        }
        errors = check_delete_dependencies("orders.yaml", ORDERS_YAML, active)
        self.assertEqual(len(errors), 1,
                         f"Expected 1 error, got {len(errors)}: {errors}")

    def test_model_provided_by_surviving_file_allowed(self):
        """If another surviving file also provides model 'orders',
        deleting orders.yaml is allowed."""
        active = {
            "orders.yaml": ORDERS_YAML,
            "orders_backup.yaml": ORDERS_YAML,
            "order_facts.yaml": MODEL_REF_YAML,
        }
        errors = check_delete_dependencies("orders.yaml", ORDERS_YAML, active)
        self.assertEqual(errors, [],
                         f"model provided by orders_backup too, should allow: {errors}")


class TestExportExtraction(unittest.TestCase):
    """Unit tests for _extract_exports and _extract_references helpers."""

    def test_extract_exports_from_orders(self):
        exports = _extract_exports(ORDERS_YAML)
        self.assertIn("total_amount", exports["measures"])
        self.assertIn("order_count", exports["measures"])
        self.assertEqual(exports["models"], ["orders"])
        self.assertIn("order", exports["entities"])

    def test_extract_exports_create_metric_false(self):
        exports = _extract_exports(CREATE_METRIC_FALSE_YAML)
        self.assertNotIn("internal_counter", exports["measures"],
                         "create_metric: false should NOT be in exports")

    def test_extract_references_derived_metric(self):
        refs = _extract_references(REVENUE_YAML)
        self.assertIn("total_amount", refs["measures"])
        self.assertIn("user_count", refs["measures"])

    def test_extract_references_ratio_metric(self):
        refs = _extract_references(RATIO_METRIC_YAML)
        self.assertIn("order_count", refs["measures"])
        self.assertIn("total_amount", refs["measures"])

    def test_extract_references_conversion_metric(self):
        refs = _extract_references(CONVERSION_METRIC_YAML)
        self.assertIn("user", refs["entities"])

    def test_extract_references_model_field(self):
        refs = _extract_references(MODEL_REF_YAML)
        self.assertIn("orders", refs["models"])

    def test_extract_references_model_field_plain_name(self):
        refs = _extract_references(MODEL_REF_PLAIN_YAML)
        self.assertIn("orders", refs["models"])

    def test_extract_exports_with_broken_yaml(self):
        exports = _extract_exports("this is not: valid: yaml: [")
        self.assertEqual(exports, {"measures": [], "models": [], "entities": []})

    def test_extract_references_with_broken_yaml(self):
        refs = _extract_references("garbage in: [")
        self.assertEqual(refs, {"measures": [], "models": [], "entities": []})


class TestExpressionParsing(unittest.TestCase):
    """Unit tests for _extract_measure_names_from_expr."""

    def test_simple_division(self):
        names = _extract_measure_names_from_expr("total_amount / user_count")
        self.assertIn("total_amount", names)
        self.assertIn("user_count", names)

    def test_sql_keywords_filtered(self):
        names = _extract_measure_names_from_expr("SUM(total_amount)")
        self.assertIn("total_amount", names)
        self.assertNotIn("SUM", names)

    def test_complex_expression(self):
        names = _extract_measure_names_from_expr(
            "(revenue - cost) / user_count * 100"
        )
        self.assertIn("revenue", names)
        self.assertIn("cost", names)
        self.assertIn("user_count", names)

    def test_empty_expression(self):
        names = _extract_measure_names_from_expr("")
        self.assertEqual(names, [])


class TestRefNameParsing(unittest.TestCase):
    """Unit tests for _extract_ref_name."""

    def test_ref_call_single_quotes(self):
        self.assertEqual(_extract_ref_name("ref('orders')"), "orders")

    def test_ref_call_double_quotes(self):
        self.assertEqual(_extract_ref_name('ref("orders")'), "orders")

    def test_ref_call_with_whitespace(self):
        self.assertEqual(_extract_ref_name("ref( 'orders' )"), "orders")

    def test_plain_name(self):
        self.assertEqual(_extract_ref_name("orders"), "orders")


if __name__ == "__main__":
    unittest.main(verbosity=2)
