import pytest

from doris_mcp_server.utils.db import DorisUserPoolMissingError, QueryResult
from doris_mcp_server.utils.schema_extractor import MetadataExtractor
from doris_mcp_server.utils.security import AuthContext, reset_auth_context, set_current_auth_context


METADATA_TOOL_CASES = [
    ("get_db_list", "get_db_list_for_mcp", (None,)),
    ("get_db_table_list", "get_db_table_list_for_mcp", ("db1", None)),
    ("get_table_schema", "get_table_schema_for_mcp", ("tbl1", "db1", None)),
    ("get_table_comment", "get_table_comment_for_mcp", ("tbl1", "db1", None)),
    ("get_table_column_comments", "get_table_column_comments_for_mcp", ("tbl1", "db1", None)),
    ("get_table_indexes", "get_table_indexes_for_mcp", ("tbl1", "db1", None)),
    ("get_catalog_list", "get_catalog_list_for_mcp", ()),
]

VISIBLE_EMPTY_COLLECTION_CASES = [
    ("get_db_list", "get_db_list_for_mcp", (None,), []),
    ("get_db_table_list", "get_db_table_list_for_mcp", ("db1", None), []),
    ("get_catalog_list", "get_catalog_list_for_mcp", (), []),
]

TABLE_SCOPED_NO_ROW_CASES = [
    ("get_table_schema", "get_table_schema_for_mcp", ("tbl1", "db1", None)),
    ("get_table_comment", "get_table_comment_for_mcp", ("tbl1", "db1", None)),
    ("get_table_column_comments", "get_table_column_comments_for_mcp", ("tbl1", "db1", None)),
    ("get_table_indexes", "get_table_indexes_for_mcp", ("tbl1", "db1", None)),
]


class FakeConnectionManager:
    def __init__(self, *, rows=None, error=None, responses=None):
        self.rows = rows if rows is not None else []
        self.error = error
        self.responses = list(responses) if responses is not None else None
        self.calls = []

    async def execute_query(self, session_id, sql, params=None, auth_context=None):
        self.calls.append((session_id, sql, params, auth_context))
        if self.error:
            raise self.error
        if self.responses is not None:
            response = self.responses.pop(0)
            if isinstance(response, Exception):
                raise response
            rows = response
        else:
            rows = self.rows
        return QueryResult(
            data=rows,
            metadata={},
            execution_time=0.01,
            row_count=len(rows),
            sql=sql,
        )


def doris_context():
    return AuthContext(
        auth_method="doris_oauth",
        user_id="alice",
        doris_user="alice",
        oauth_scopes=["tool:call:get_db_list"],
        pool_key="doris_user:alice",
    )


async def _call_tool(method_name, args, connection_manager):
    extractor = MetadataExtractor(db_name="db1", connection_manager=connection_manager)
    method = getattr(extractor, method_name)
    token = set_current_auth_context(doris_context())
    try:
        return await method(*args)
    finally:
        reset_auth_context(token)


@pytest.mark.parametrize(("tool_name", "method_name", "args"), METADATA_TOOL_CASES)
@pytest.mark.parametrize(
    ("error", "error_code", "status_code"),
    [
        (DorisUserPoolMissingError("missing doris pool"), "DORIS_OAUTH_POOL_MISSING", 401),
        (RuntimeError("Access denied; missing privilege"), "DORIS_OAUTH_METADATA_PERMISSION_DENIED", 403),
        (RuntimeError(1142, "SELECT command denied to user"), "DORIS_OAUTH_METADATA_PERMISSION_DENIED", 403),
        (RuntimeError("backend exploded"), "DORIS_OAUTH_METADATA_BACKEND_ERROR", 502),
    ],
)
@pytest.mark.asyncio
async def test_doris_oauth_metadata_errors_are_structured_failures(
    tool_name,
    method_name,
    args,
    error,
    error_code,
    status_code,
):
    response = await _call_tool(method_name, args, FakeConnectionManager(error=error))

    assert response["success"] is False, tool_name
    assert response["error_code"] == error_code
    assert response["status_code"] == status_code
    assert "result" not in response


@pytest.mark.parametrize(("tool_name", "method_name", "args", "empty_result"), VISIBLE_EMPTY_COLLECTION_CASES)
@pytest.mark.asyncio
async def test_doris_oauth_true_empty_collection_metadata_results_are_not_backend_errors(
    tool_name,
    method_name,
    args,
    empty_result,
):
    response = await _call_tool(method_name, args, FakeConnectionManager(rows=[]))

    assert response["success"] is True, tool_name
    assert "error_code" not in response
    assert response["result"] == empty_result


@pytest.mark.parametrize(("tool_name", "method_name", "args"), TABLE_SCOPED_NO_ROW_CASES)
@pytest.mark.asyncio
async def test_doris_oauth_table_scoped_no_rows_are_structured_not_visible(
    tool_name,
    method_name,
    args,
):
    response = await _call_tool(method_name, args, FakeConnectionManager(rows=[]))

    assert response["success"] is False, tool_name
    assert response["error_code"] == "DORIS_OAUTH_METADATA_NOT_VISIBLE"
    assert response["status_code"] == 404
    assert "result" not in response


@pytest.mark.asyncio
async def test_doris_oauth_empty_table_comment_is_success_when_table_row_exists():
    response = await _call_tool(
        "get_table_comment_for_mcp",
        ("tbl1", "db1", None),
        FakeConnectionManager(rows=[{"TABLE_COMMENT": ""}]),
    )

    assert response["success"] is True
    assert "error_code" not in response
    assert response["result"] == ""


@pytest.mark.asyncio
async def test_doris_oauth_empty_column_comments_are_success_when_column_rows_exist():
    response = await _call_tool(
        "get_table_column_comments_for_mcp",
        ("tbl1", "db1", None),
        FakeConnectionManager(
            rows=[
                {"COLUMN_NAME": "c1", "COLUMN_COMMENT": ""},
                {"COLUMN_NAME": "c2", "COLUMN_COMMENT": None},
            ]
        ),
    )

    assert response["success"] is True
    assert "error_code" not in response
    assert response["result"] == {"c1": "", "c2": ""}


@pytest.mark.asyncio
async def test_doris_oauth_empty_indexes_are_success_after_visibility_check():
    connection_manager = FakeConnectionManager(
        responses=[
            [],
            [{"TABLE_VISIBLE": 1}],
        ]
    )
    response = await _call_tool(
        "get_table_indexes_for_mcp",
        ("tbl1", "db1", None),
        connection_manager,
    )

    assert response["success"] is True
    assert "error_code" not in response
    assert response["result"] == []
    assert len(connection_manager.calls) == 2
