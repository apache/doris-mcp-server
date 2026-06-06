import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import mcp.types as mcp_types
import pytest

from doris_mcp_server.auth.operation_policy import HIGH_RISK_TOOLS, OperationAuthorizationError, authorize_operation
from doris_mcp_server.main import DorisServer, Server
from doris_mcp_server.tools.tools_manager import DorisToolsManager
from doris_mcp_server.utils.analysis_tools import SQLAnalyzer
from doris_mcp_server.utils.db import QueryResult
from doris_mcp_server.utils.query_executor import DorisQueryExecutor
from doris_mcp_server.utils.schema_extractor import MetadataExtractor
from doris_mcp_server.utils.security import (
    AuthContext,
    get_current_auth_context,
    reset_auth_context,
    set_current_auth_context,
)


class FakeRoutedConnection:
    def __init__(self, manager, session_id, auth_context):
        self.manager = manager
        self.session_id = session_id
        self.auth_context = auth_context

    async def execute(self, sql, params=None, auth_context=None):
        return await self.manager.execute_query(
            self.session_id,
            sql,
            params,
            auth_context or self.auth_context,
        )


class FakeRoutedConnectionManager:
    def __init__(self, tmp_path):
        self.config = SimpleNamespace(
            temp_files_dir=str(tmp_path),
            performance=SimpleNamespace(
                max_cache_size=100,
                cache_ttl=300,
                max_concurrent_queries=10,
                max_response_content_size=20000,
            ),
            security=SimpleNamespace(enable_security_check=False),
            adbc=SimpleNamespace(
                default_max_rows=100,
                default_timeout=30,
                default_return_format="dict",
            ),
        )
        self.security_manager = None
        self.routed_calls = []
        self.global_calls = 0
        self.token_calls = 0
        self.connection_acquires = 0
        self.connection_releases = 0

    def _get_effective_auth_context(self, auth_context=None):
        return auth_context or get_current_auth_context()

    async def _get_connection_for_auth_context(self, session_id, auth_context=None):
        self.connection_acquires += 1
        return FakeRoutedConnection(self, session_id, auth_context)

    async def release_connection(self, session_id, connection):
        self.connection_releases += 1

    async def execute_query(self, session_id, sql, params=None, auth_context=None):
        if getattr(auth_context, "auth_method", "") != "doris_oauth":
            raise AssertionError("Doris OAuth tool path did not pass AuthContext")
        if getattr(auth_context, "doris_user", "") != "alice":
            raise AssertionError("Doris OAuth tool path did not use the logged-in Doris user")
        self.routed_calls.append(
            {
                "session_id": session_id,
                "sql": sql,
                "params": params,
                "doris_user": auth_context.doris_user,
            }
        )
        if sql.strip().upper().startswith("EXPLAIN"):
            return QueryResult(
                data=[{"Plan": "SCAN"}],
                metadata={"columns": ["Plan"]},
                execution_time=0.01,
                row_count=1,
                sql=sql,
            )
        return QueryResult(
            data=[{"one": 1}],
            metadata={"columns": ["one"]},
            execution_time=0.01,
            row_count=1,
            sql=sql,
        )

    async def _get_global_connection(self, session_id):
        self.global_calls += 1
        raise AssertionError("Doris OAuth tool path fell back to the global pool")

    async def get_connection_for_token(self, token, session_id):
        self.token_calls += 1
        raise AssertionError("Doris OAuth tool path fell back to token routing")


def doris_context(
    scopes,
    *,
    user_id="doris_user",
    db_tools_enabled=False,
    allowlist=None,
    query_tools_enabled=False,
    query_allowlist=None,
    explain_tools_enabled=False,
    explain_allowlist=None,
):
    context = AuthContext(
        user_id=user_id,
        auth_method="doris_oauth",
        oauth_scopes=list(scopes),
        doris_user=user_id,
        pool_key=f"doris_user:{user_id}",
    )
    context.doris_oauth_db_tools_enabled = db_tools_enabled
    context.doris_oauth_db_tool_allowlist = tuple(allowlist or ())
    context.doris_oauth_query_tools_enabled = query_tools_enabled
    context.doris_oauth_query_tool_allowlist = tuple(query_allowlist or ("exec_query",))
    context.doris_oauth_explain_tools_enabled = explain_tools_enabled
    context.doris_oauth_explain_tool_allowlist = tuple(explain_allowlist or ("get_sql_explain",))
    return context


def _real_tool_manager_for_routing(tmp_path):
    connection_manager = FakeRoutedConnectionManager(tmp_path)
    manager = object.__new__(DorisToolsManager)
    manager.connection_manager = connection_manager
    manager.metadata_extractor = MetadataExtractor(connection_manager=connection_manager)
    manager.sql_analyzer = SQLAnalyzer(connection_manager)
    return manager, connection_manager


def _configured_rbac_default_scopes():
    return [
        "tool:list",
        "resource:list",
        "resource:read",
        "tool:call:get_db_list",
        "tool:call:get_db_table_list",
        "tool:call:get_table_schema",
        "tool:call:get_table_comment",
        "tool:call:get_table_column_comments",
        "tool:call:get_table_indexes",
        "tool:call:get_catalog_list",
        "tool:call:exec_query",
        "tool:call:get_sql_explain",
    ]


@pytest.mark.asyncio
async def test_high_risk_tool_is_rejected_before_dispatch():
    manager = object.__new__(DorisToolsManager)
    called = False

    async def fake_sql_profile_tool(arguments):
        nonlocal called
        called = True
        return {"unexpected": arguments}

    manager._get_sql_profile_tool = fake_sql_profile_tool
    token = set_current_auth_context(doris_context(["tool:call:get_sql_profile"]))

    try:
        with pytest.raises(OperationAuthorizationError) as exc:
            await manager.call_tool("get_sql_profile", {"query_id": "q1"})
    finally:
        reset_auth_context(token)

    assert exc.value.error_code == "UNSUPPORTED_FOR_DORIS_OAUTH"
    assert called is False


@pytest.mark.asyncio
async def test_doris_oauth_exec_query_rejected_before_global_pool_dispatch():
    manager = object.__new__(DorisToolsManager)
    called = False

    async def fake_exec_query_tool(arguments):
        nonlocal called
        called = True
        return {"unexpected": arguments}

    manager._exec_query_tool = fake_exec_query_tool
    token = set_current_auth_context(doris_context(["tool:call:exec_query"]))

    try:
        with pytest.raises(OperationAuthorizationError) as exc:
            await manager.call_tool("exec_query", {"sql": "SELECT 1"})
    finally:
        reset_auth_context(token)

    assert exc.value.error_code == "DORIS_OAUTH_QUERY_TOOL_NOT_ENABLED"
    assert called is False


@pytest.mark.asyncio
async def test_doris_oauth_exec_query_dispatches_when_query_gate_enabled():
    manager = object.__new__(DorisToolsManager)
    called_arguments = None

    async def fake_exec_query_tool(arguments):
        nonlocal called_arguments
        called_arguments = arguments
        return {"ok": True}

    manager._exec_query_tool = fake_exec_query_tool
    token = set_current_auth_context(
        doris_context(
            ["tool:call:exec_query"],
            user_id="alice",
            query_tools_enabled=True,
        )
    )

    try:
        result = await manager.call_tool("exec_query", {"sql": "SELECT 1"})
    finally:
        reset_auth_context(token)

    payload = json.loads(result)
    assert payload["ok"] is True
    assert called_arguments == {"sql": "SELECT 1"}


@pytest.mark.asyncio
async def test_doris_oauth_exec_query_real_tool_path_uses_doris_user_route(tmp_path, monkeypatch):
    monkeypatch.setattr(DorisQueryExecutor, "_start_background_tasks", lambda self: None)
    manager, connection_manager = _real_tool_manager_for_routing(tmp_path)
    token = set_current_auth_context(
        doris_context(
            ["tool:call:exec_query"],
            user_id="alice",
            query_tools_enabled=True,
        )
    )

    try:
        result = await manager.call_tool("exec_query", {"sql": "SELECT 1", "max_rows": 5})
    finally:
        reset_auth_context(token)

    payload = json.loads(result)
    assert payload["success"] is True
    assert payload["data"] == [{"one": 1}]
    assert connection_manager.global_calls == 0
    assert connection_manager.token_calls == 0
    assert len(connection_manager.routed_calls) == 1
    assert connection_manager.routed_calls[0]["doris_user"] == "alice"
    assert connection_manager.routed_calls[0]["sql"] == "SELECT 1 LIMIT 5"


@pytest.mark.asyncio
async def test_doris_oauth_exec_query_with_db_catalog_uses_one_routed_connection(tmp_path, monkeypatch):
    monkeypatch.setattr(DorisQueryExecutor, "_start_background_tasks", lambda self: None)
    manager, connection_manager = _real_tool_manager_for_routing(tmp_path)
    token = set_current_auth_context(
        doris_context(
            ["tool:call:exec_query"],
            user_id="alice",
            query_tools_enabled=True,
        )
    )

    try:
        result = await manager.call_tool(
            "exec_query",
            {
                "sql": "SELECT * FROM orders",
                "db_name": "db1",
                "catalog_name": "ctl1",
                "max_rows": 5,
            },
        )
    finally:
        reset_auth_context(token)

    payload = json.loads(result)
    assert payload["success"] is True
    assert connection_manager.connection_acquires == 1
    assert connection_manager.connection_releases == 1
    assert [call["sql"] for call in connection_manager.routed_calls] == [
        "USE CATALOG `ctl1`",
        "USE `db1`",
        "SELECT * FROM orders LIMIT 5",
    ]
    assert {call["doris_user"] for call in connection_manager.routed_calls} == {"alice"}


@pytest.mark.asyncio
async def test_doris_oauth_sql_explain_real_tool_path_uses_doris_user_route(tmp_path):
    manager, connection_manager = _real_tool_manager_for_routing(tmp_path)
    token = set_current_auth_context(
        doris_context(
            ["tool:call:get_sql_explain"],
            user_id="alice",
            explain_tools_enabled=True,
        )
    )

    try:
        result = await manager.call_tool("get_sql_explain", {"sql": "SELECT 1"})
    finally:
        reset_auth_context(token)

    payload = json.loads(result)
    assert payload["success"] is True
    assert "EXPLAIN SELECT 1" in payload["content"]
    assert connection_manager.global_calls == 0
    assert connection_manager.token_calls == 0
    assert len(connection_manager.routed_calls) == 1
    assert connection_manager.routed_calls[0]["doris_user"] == "alice"
    assert connection_manager.routed_calls[0]["sql"] == "EXPLAIN SELECT 1"


@pytest.mark.asyncio
async def test_doris_oauth_sql_explain_with_db_catalog_uses_one_routed_connection(tmp_path):
    manager, connection_manager = _real_tool_manager_for_routing(tmp_path)
    token = set_current_auth_context(
        doris_context(
            ["tool:call:get_sql_explain"],
            user_id="alice",
            explain_tools_enabled=True,
        )
    )

    try:
        result = await manager.call_tool(
            "get_sql_explain",
            {
                "sql": "SELECT * FROM orders",
                "db_name": "db1",
                "catalog_name": "ctl1",
            },
        )
    finally:
        reset_auth_context(token)

    payload = json.loads(result)
    assert payload["success"] is True
    assert connection_manager.connection_acquires == 1
    assert connection_manager.connection_releases == 1
    assert [call["sql"] for call in connection_manager.routed_calls] == [
        "USE CATALOG `ctl1`",
        "USE `db1`",
        "EXPLAIN SELECT * FROM orders",
    ]
    assert {call["doris_user"] for call in connection_manager.routed_calls} == {"alice"}


@pytest.mark.asyncio
async def test_doris_oauth_list_tools_uses_configured_default_scope_visibility(tmp_path):
    manager, _connection_manager = _real_tool_manager_for_routing(tmp_path)
    token = set_current_auth_context(
        doris_context(
            _configured_rbac_default_scopes(),
            db_tools_enabled=True,
            allowlist=[
                "get_db_list",
                "get_db_table_list",
                "get_table_schema",
                "get_table_comment",
                "get_table_column_comments",
                "get_table_indexes",
                "get_catalog_list",
            ],
            query_tools_enabled=True,
            explain_tools_enabled=True,
        )
    )

    try:
        tools = await manager.list_tools()
    finally:
        reset_auth_context(token)

    names = {tool.name for tool in tools}
    assert {
        "exec_query",
        "get_sql_explain",
        "get_db_list",
        "get_db_table_list",
        "get_table_schema",
        "get_table_comment",
        "get_table_column_comments",
        "get_table_indexes",
        "get_catalog_list",
    } <= names
    assert names.isdisjoint(HIGH_RISK_TOOLS)


@pytest.mark.asyncio
async def test_doris_oauth_exec_query_ddl_rejected_before_backend_when_global_security_disabled():
    manager = object.__new__(DorisToolsManager)
    manager.connection_manager = SimpleNamespace(
        config=SimpleNamespace(security=SimpleNamespace(enable_security_check=False))
    )
    called = False

    async def fake_exec_query_tool(arguments):
        nonlocal called
        called = True
        return {"unexpected": arguments}

    manager._exec_query_tool = fake_exec_query_tool
    token = set_current_auth_context(
        doris_context(
            ["tool:call:exec_query"],
            db_tools_enabled=True,
            allowlist=["get_db_list"],
        )
    )

    try:
        with pytest.raises(OperationAuthorizationError) as exc:
            await manager.call_tool("exec_query", {"sql": "DROP TABLE sensitive_table"})
    finally:
        reset_auth_context(token)

    assert exc.value.error_code == "DORIS_OAUTH_QUERY_TOOL_NOT_ENABLED"
    assert called is False


@pytest.mark.asyncio
async def test_doris_oauth_metadata_tool_rejected_before_cache_backend_dispatch_when_gate_false():
    manager = object.__new__(DorisToolsManager)
    called = False

    async def fake_table_schema_tool(arguments):
        nonlocal called
        called = True
        return {"unexpected": arguments}

    manager._get_table_schema_tool = fake_table_schema_tool
    token = set_current_auth_context(doris_context(["tool:call:get_table_schema"]))

    try:
        with pytest.raises(OperationAuthorizationError) as exc:
            await manager.call_tool("get_table_schema", {"table_name": "orders"})
    finally:
        reset_auth_context(token)

    assert exc.value.error_code == "DORIS_OAUTH_DB_TOOLS_NOT_ENABLED"
    assert called is False


@pytest.mark.asyncio
async def test_missing_auth_context_keeps_legacy_dispatch_compatible():
    assert get_current_auth_context() is None
    manager = object.__new__(DorisToolsManager)
    called_arguments = None

    async def fake_sql_profile_tool(arguments):
        nonlocal called_arguments
        called_arguments = arguments
        return {"profile": "ok"}

    manager._get_sql_profile_tool = fake_sql_profile_tool

    result = await manager.call_tool("get_sql_profile", {"query_id": "q1"})

    payload = json.loads(result)
    assert payload["profile"] == "ok"
    assert payload["_execution_info"]["tool_name"] == "get_sql_profile"
    assert called_arguments == {"query_id": "q1"}


def _server_with_mock_managers():
    server = object.__new__(DorisServer)
    server.server = Server("test-doris-mcp-server")
    server.resources_manager = MagicMock()
    server.resources_manager.list_resources = AsyncMock(return_value=[])
    server.resources_manager.read_resource = AsyncMock(return_value="{}")
    server.prompts_manager = MagicMock()
    server.prompts_manager.list_prompts = AsyncMock(return_value=[])
    server.prompts_manager.get_prompt = AsyncMock(return_value="prompt")
    server.tools_manager = MagicMock()
    server.logger = MagicMock()
    DorisServer._setup_handlers(server)
    return server


def _handler_request(operation):
    if operation == "list_resources":
        return mcp_types.ListResourcesRequest(method="resources/list")
    if operation == "read_resource":
        return SimpleNamespace(params=SimpleNamespace(uri="doris://tables"))
    if operation == "list_prompts":
        return mcp_types.ListPromptsRequest(method="prompts/list")
    if operation == "get_prompt":
        return SimpleNamespace(
            params=SimpleNamespace(name="query_analysis", arguments={})
        )
    raise AssertionError(f"Unexpected operation: {operation}")


def _manager_mock_for_operation(server, operation):
    return {
        "list_resources": server.resources_manager.list_resources,
        "read_resource": server.resources_manager.read_resource,
        "list_prompts": server.prompts_manager.list_prompts,
        "get_prompt": server.prompts_manager.get_prompt,
    }[operation]


def _handler_type_for_operation(operation):
    return {
        "list_resources": mcp_types.ListResourcesRequest,
        "read_resource": mcp_types.ReadResourceRequest,
        "list_prompts": mcp_types.ListPromptsRequest,
        "get_prompt": mcp_types.GetPromptRequest,
    }[operation]


@pytest.mark.parametrize(
    ("operation", "scope"),
    [
        ("list_resources", "resource:list"),
        ("read_resource", "resource:read"),
    ],
)
@pytest.mark.asyncio
async def test_doris_oauth_resources_real_handler_calls_manager_with_matching_scope(
    operation,
    scope,
):
    server = _server_with_mock_managers()
    token = set_current_auth_context(doris_context([scope]))

    try:
        await server.server.request_handlers[_handler_type_for_operation(operation)](
            _handler_request(operation)
        )
    finally:
        reset_auth_context(token)

    _manager_mock_for_operation(server, operation).assert_awaited_once()


@pytest.mark.parametrize(
    ("operation", "scope"),
    [
        ("list_resources", "resource:list"),
        ("read_resource", "resource:read"),
    ],
)
@pytest.mark.asyncio
async def test_doris_oauth_resources_real_handler_propagates_manager_errors(
    operation,
    scope,
):
    server = _server_with_mock_managers()
    _manager_mock_for_operation(server, operation).side_effect = RuntimeError(
        f"{operation} backend failed"
    )
    token = set_current_auth_context(doris_context([scope]))

    try:
        with pytest.raises(RuntimeError, match=f"{operation} backend failed"):
            await server.server.request_handlers[_handler_type_for_operation(operation)](
                _handler_request(operation)
            )
    finally:
        reset_auth_context(token)


@pytest.mark.asyncio
async def test_legacy_list_resources_handler_keeps_empty_list_compatibility():
    server = _server_with_mock_managers()
    server.resources_manager.list_resources.side_effect = RuntimeError("legacy backend failed")

    result = await server.server.request_handlers[mcp_types.ListResourcesRequest](
        mcp_types.ListResourcesRequest(method="resources/list")
    )

    assert result.root.resources == []


@pytest.mark.parametrize(
    ("operation", "scope"),
    [
        ("list_prompts", "prompt:list"),
        ("get_prompt", "prompt:get"),
    ],
)
@pytest.mark.asyncio
async def test_doris_oauth_prompts_real_handler_rejected_before_manager(
    operation,
    scope,
):
    server = _server_with_mock_managers()
    metadata_cache = MagicMock()
    connection_manager = MagicMock()
    connection_manager.get_connection = AsyncMock()
    token = set_current_auth_context(doris_context([scope]))

    try:
        with pytest.raises(OperationAuthorizationError) as exc:
            await server.server.request_handlers[_handler_type_for_operation(operation)](
                _handler_request(operation)
            )
    finally:
        reset_auth_context(token)

    assert exc.value.error_code == "UNSUPPORTED_FOR_DORIS_OAUTH"
    _manager_mock_for_operation(server, operation).assert_not_awaited()
    metadata_cache.get.assert_not_called()
    connection_manager.get_connection.assert_not_awaited()
