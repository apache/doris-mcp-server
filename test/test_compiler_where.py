"""Offline tests for resolve_where string-literal handling in store.compiler."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from store.compiler import MetricFlowCompiler  # noqa: E402


def _make_compiler() -> MetricFlowCompiler:
    """Compiler instance with a stubbed dimension map (no engine needed)."""
    compiler = MetricFlowCompiler.__new__(MetricFlowCompiler)
    compiler._engine_mode = False
    compiler._engine = None
    compiler._build_dimension_map = lambda metrics: (  # noqa: E731
        {
            "channel": "order_entity__channel",
            "order_date": "metric_time__day",
        },
        {"order_date"},
    )
    return compiler


class ResolveWhereLiteralTests(unittest.TestCase):
    def setUp(self) -> None:
        self.compiler = _make_compiler()

    def resolve(self, where: str) -> str:
        return self.compiler.resolve_where(["some_metric"], where)

    def test_literal_equal_to_column_name_is_not_replaced(self) -> None:
        self.assertEqual(
            self.resolve("channel = 'channel'"),
            "{{ Dimension('order_entity__channel') }} = 'channel'",
        )

    def test_plain_literal_replacement_still_works(self) -> None:
        self.assertEqual(
            self.resolve("channel = 'APP' AND order_date >= '2024-03-01'"),
            "{{ Dimension('order_entity__channel') }} = 'APP' "
            "AND {{ TimeDimension('metric_time', 'day') }} >= '2024-03-01'",
        )

    def test_in_list_with_column_name_literal(self) -> None:
        self.assertEqual(
            self.resolve("channel IN ('channel', 'Web')"),
            "{{ Dimension('order_entity__channel') }} IN ('channel', 'Web')",
        )

    def test_doubled_quote_escape_inside_literal(self) -> None:
        self.assertEqual(
            self.resolve("channel = 'it''s channel'"),
            "{{ Dimension('order_entity__channel') }} = 'it''s channel'",
        )

    def test_backslash_escape_inside_literal(self) -> None:
        self.assertEqual(
            self.resolve(r"channel = 'a\'b channel'"),
            r"{{ Dimension('order_entity__channel') }} = 'a\'b channel'",
        )

    def test_double_quoted_literal_is_not_replaced(self) -> None:
        self.assertEqual(
            self.resolve('channel = "channel"'),
            "{{ Dimension('order_entity__channel') }} = \"channel\"",
        )


if __name__ == "__main__":
    unittest.main()
