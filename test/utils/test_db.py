from unittest.mock import AsyncMock, MagicMock
import pytest

from doris_mcp_server.utils.db import (
    DorisConnection,
    DorisSessionCache,
    get_first_sql_keyword,
)


@pytest.fixture
def session_cache():
    """Provides a DorisSessionCache instance with a mock connection manager."""
    connection_manager = MagicMock()
    cache = DorisSessionCache(connection_manager=connection_manager)
    yield cache, connection_manager


class TestDorisSessionCache:

    def test_initialization(self, session_cache):
        cache, _ = session_cache
        assert cache.cache_system_session is True
        assert cache.cache_user_session is False
        assert not cache.cached

    def test_should_cache(self, session_cache):
        cache, _ = session_cache
        assert cache._should_cache("query") is True
        assert cache._should_cache("system") is True
        assert cache._should_cache("user-test-session-id") is False

        cache.cache_user_session = True
        assert cache._should_cache("user-test-session-id") is True

    def test_save_and_get_session(self, session_cache):
        cache, _ = session_cache
        mock_connection = MagicMock(spec=DorisConnection)
        mock_connection.session_id = "query"

        cache.save(mock_connection)
        retrieved_conn = cache.get("query")
        assert retrieved_conn is mock_connection

        mock_user_connection = MagicMock(spec=DorisConnection)
        mock_user_connection.session_id = "user-test-session-id"
        cache.save(mock_user_connection)
        assert cache.get("user-test-session-id") is None

        cache.cache_user_session = True
        cache.save(mock_user_connection)
        retrieved_user_conn = cache.get("user-test-session-id")
        assert retrieved_user_conn is mock_user_connection

    def test_remove_session(self, session_cache):
        cache, _ = session_cache
        mock_connection = MagicMock(spec=DorisConnection)
        mock_connection.session_id = "system"

        cache.save(mock_connection)
        assert cache.get("system") is not None

        cache.remove("system")
        assert cache.get("system") is None

    def test_clear_cache(self, session_cache):
        cache, connection_manager = session_cache
        mock_conn1 = MagicMock(spec=DorisConnection)
        mock_conn1.session_id = "query"
        mock_conn2 = MagicMock(spec=DorisConnection)
        mock_conn2.session_id = "system"

        cache.save(mock_conn1)
        cache.save(mock_conn2)
        assert len(cache.cached) == 2

        cache.clear()

        assert not cache.cached
        connection_manager.release_connection.assert_any_call("query", mock_conn1)
        connection_manager.release_connection.assert_any_call("system", mock_conn2)
        assert connection_manager.release_connection.call_count == 2


class TestGetFirstSqlKeyword:
    """Unit tests for get_first_sql_keyword.

    Used by query_executor.py:689 to detect SELECT before cursor.execute
    (where cursor.description is not yet available), so the auto-injected
    LIMIT {max_rows} cap also works when the SQL is comment-prefixed.
    """

    def test_plain_select(self):
        assert get_first_sql_keyword("SELECT 1") == "SELECT"

    def test_leading_whitespace(self):
        assert get_first_sql_keyword("   \n\t SELECT 1") == "SELECT"

    def test_lowercase(self):
        assert get_first_sql_keyword("select 1") == "SELECT"

    def test_line_comment_then_select(self):
        sql = "-- a leading note\nSELECT 1"
        assert get_first_sql_keyword(sql) == "SELECT"

    def test_block_comment_then_select(self):
        sql = "/* note */ SELECT 1"
        assert get_first_sql_keyword(sql) == "SELECT"

    def test_multiline_block_comment_then_select(self):
        sql = "/*\n multi\n line\n*/\nSELECT 1"
        assert get_first_sql_keyword(sql) == "SELECT"

    def test_mixed_whitespace_and_comments(self):
        sql = "  -- one\n  /* two */ \n  SELECT 1"
        assert get_first_sql_keyword(sql) == "SELECT"

    def test_comment_then_with_cte(self):
        sql = "-- note\nWITH x AS (SELECT 1) SELECT * FROM x"
        assert get_first_sql_keyword(sql) == "WITH"

    def test_non_select_unaffected(self):
        assert get_first_sql_keyword("INSERT INTO t VALUES (1)") == "INSERT"
        assert get_first_sql_keyword("-- c\nINSERT INTO t VALUES (1)") == "INSERT"

    def test_empty_and_only_comments(self):
        assert get_first_sql_keyword("") == ""
        assert get_first_sql_keyword("   ") == ""
        assert get_first_sql_keyword("-- only a comment") == ""
        assert get_first_sql_keyword("/* only */") == ""


def _make_doris_connection(cursor_description, fetchall_rows, rowcount=0):
    """Build a DorisConnection whose underlying cursor returns the given values.

    The driver-level cursor is fully mocked: only `description`, `fetchall()`
    and `rowcount` matter for the result-set-detection branch we want to test.
    """
    cursor = MagicMock()
    cursor.execute = AsyncMock(return_value=None)
    cursor.fetchall = AsyncMock(return_value=fetchall_rows)
    cursor.description = cursor_description
    cursor.rowcount = rowcount

    cursor_ctx = MagicMock()
    cursor_ctx.__aenter__ = AsyncMock(return_value=cursor)
    cursor_ctx.__aexit__ = AsyncMock(return_value=None)

    raw_connection = MagicMock()
    raw_connection.cursor = MagicMock(return_value=cursor_ctx)

    return DorisConnection(connection=raw_connection, session_id="test")


class TestExecuteResultSetDetection:
    """Behavior contract for DorisConnection.execute().

    These tests pin the user-facing contract: any statement the driver
    reports as producing a result set must have its rows returned, and any
    statement that does not produce a result set must report rowcount.

    Guards against regression of:
    - Issue #62 Bug 5 (CTE / WITH returning empty data)
    - The leading-comment bug (SELECT prefixed by `--` or `/* */` returning
      empty data while row_count was non-zero)
    - Future "missing keyword in the whitelist" bugs of the same class

    The tests deliberately do not assert anything about how the SQL text is
    parsed — they only assert that when `cursor.description` is populated,
    rows are fetched, regardless of the SQL phrasing.
    """

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT 1",
            "   SELECT 1",
            "-- leading line comment\nSELECT 1",
            "/* leading block comment */ SELECT 1",
            "/*\n multi\n line\n*/\nSELECT 1",
            "  -- one\n  /* two */ \n  SELECT 1",
            "(SELECT 1)",
            "WITH t AS (SELECT 1) SELECT * FROM t",
            "-- comment\nWITH t AS (SELECT 1) SELECT * FROM t",
            "SHOW TABLES",
            "DESC some_table",
            "EXPLAIN SELECT 1",
        ],
        ids=[
            "plain_select",
            "leading_whitespace",
            "line_comment_then_select",
            "block_comment_then_select",
            "multiline_block_comment",
            "mixed_whitespace_and_comments",
            "parenthesized_select",
            "with_cte",
            "comment_then_with_cte",
            "show",
            "desc",
            "explain",
        ],
    )
    async def test_returns_rows_when_driver_reports_result_set(self, sql):
        rows = [{"col": 1}]
        conn = _make_doris_connection(
            cursor_description=[("col", None, None, None, None, None, None)],
            fetchall_rows=rows,
        )

        result = await conn.execute(sql)

        assert result.data == rows
        assert result.row_count == len(rows)

    @pytest.mark.parametrize(
        "sql, affected",
        [
            ("INSERT INTO t VALUES (1)", 1),
            ("UPDATE t SET x = 1", 5),
            ("DELETE FROM t WHERE x = 1", 3),
            ("CREATE TABLE t (x INT)", 0),
        ],
    )
    async def test_no_fetch_when_driver_reports_no_result_set(self, sql, affected):
        conn = _make_doris_connection(
            cursor_description=None,
            fetchall_rows=[],
            rowcount=affected,
        )

        result = await conn.execute(sql)

        assert result.data == []
        assert result.row_count == affected
