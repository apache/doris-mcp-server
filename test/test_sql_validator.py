"""Unit tests for core.sql_validator.validate_readonly (offline, pure function).

Covers:
  - Allowed: SELECT / WITH / UNION / SHOW / DESC / DESCRIBE / EXPLAIN
  - Blocked: INSERT / UPDATE / DELETE / DROP / CREATE / GRANT / TRUNCATE / ALTER
  - Multiple statements (stacked queries) rejected
  - Comment-based bypass attempts rejected
  - Empty / whitespace-only input rejected
  - Known behaviour: EXPLAIN/SHOW prefix check has no word boundary
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from core.sql_validator import validate_readonly  # noqa: E402


class TestValidateReadonlyAllowed(unittest.TestCase):
    """Read-only statements must be accepted."""

    def _assert_allowed(self, sql: str) -> None:
        ok, err = validate_readonly(sql)
        self.assertTrue(ok, f"Expected allowed, got error: {err} (sql={sql!r})")
        self.assertEqual(err, "")

    def test_simple_select(self):
        self._assert_allowed("SELECT 1")

    def test_select_with_where_and_trailing_semicolon(self):
        self._assert_allowed("SELECT * FROM dw.orders WHERE id = 1;")

    def test_with_cte(self):
        self._assert_allowed("WITH x AS (SELECT 1 AS a) SELECT * FROM x")

    def test_union(self):
        self._assert_allowed("select * from t union select * from u")

    def test_show(self):
        self._assert_allowed("SHOW DATABASES")
        self._assert_allowed("SHOW TABLES FROM mysql")

    def test_desc_and_describe(self):
        self._assert_allowed("DESC dw.orders")
        self._assert_allowed("DESCRIBE dw.orders")

    def test_explain(self):
        self._assert_allowed("EXPLAIN SELECT count(*) FROM dw.orders")

    def test_leading_comments_on_select(self):
        """Comments around a legitimate SELECT do not change the verdict."""
        self._assert_allowed("/* comment */ SELECT 1")
        self._assert_allowed("-- comment\nSELECT 1")


class TestValidateReadonlyBlocked(unittest.TestCase):
    """Write / DDL / admin statements must be rejected."""

    def _assert_blocked(self, sql: str) -> None:
        ok, err = validate_readonly(sql)
        self.assertFalse(ok, f"Expected blocked: {sql!r}")
        self.assertNotEqual(err, "")

    def test_insert(self):
        self._assert_blocked("INSERT INTO dw.orders VALUES (1)")

    def test_update(self):
        self._assert_blocked("UPDATE dw.orders SET a = 1")

    def test_delete(self):
        self._assert_blocked("DELETE FROM dw.orders")

    def test_drop(self):
        self._assert_blocked("DROP TABLE dw.orders")

    def test_create(self):
        self._assert_blocked("CREATE TABLE t (id INT)")

    def test_grant(self):
        self._assert_blocked("GRANT SELECT_PRIV ON *.* TO u")

    def test_truncate(self):
        self._assert_blocked("TRUNCATE TABLE t")

    def test_alter(self):
        self._assert_blocked("ALTER TABLE t ADD COLUMN c INT")

    def test_use_and_set(self):
        self._assert_blocked("USE dw")
        self._assert_blocked("SET x = 1")

    def test_multiple_statements(self):
        self._assert_blocked("SELECT 1; SELECT 2")

    def test_stacked_write_after_select(self):
        self._assert_blocked("SELECT 1; DROP TABLE t")

    def test_comment_bypass_attempts(self):
        """Comments must not smuggle a write statement past the validator."""
        self._assert_blocked("/* x */ DROP TABLE t")
        self._assert_blocked("DROP TABLE t -- trailing comment")


class TestValidateReadonlyEmpty(unittest.TestCase):
    def test_empty_inputs_rejected(self):
        for sql in ("", "   ", ";"):
            with self.subTest(sql=sql):
                ok, err = validate_readonly(sql)
                self.assertFalse(ok)
                self.assertEqual(err, "Empty SQL statement")


class TestValidateReadonlyPrefixNoWordBoundary(unittest.TestCase):
    """Known current behaviour: the SHOW/DESC/EXPLAIN prefix fallback uses
    str.startswith() without a word boundary, so any identifier starting
    with one of these prefixes is accepted. This test documents the status
    quo — do NOT 'fix' the test; if src changes to require a word boundary,
    update these assertions accordingly."""

    def test_explain_prefix_without_word_boundary_is_allowed(self):
        # "EXPLAINXXX" is not a valid EXPLAIN statement, but the raw-text
        # prefix check (sql_validator.py:70-73) accepts it anyway.
        ok, _ = validate_readonly("EXPLAINXXX weird")
        self.assertTrue(ok)

    def test_show_prefix_without_word_boundary_is_allowed(self):
        ok, _ = validate_readonly("SHOWxxx nonsense")
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main(verbosity=2)
