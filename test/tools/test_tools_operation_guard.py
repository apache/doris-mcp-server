from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import mcp.types as mcp_types
import pytest
from mcp.shared.exceptions import MCPError

from doris_mcp_server import __version__
from doris_mcp_server.auth.operation_policy import (
    HIGH_RISK_TOOLS,
    OperationAuthorizationError,
    authorize_operation,
)
from doris_mcp_server.protocol import create_doris_mcp_server
from doris_mcp_server.tools.domain_dispatcher import (
    ToolExposureMode,
    ToolNotFoundError,
)
from doris_mcp_server.tools.domain_manifest import DomainManifestService
from doris_mcp_server.tools.doris_feature_matrix import (
    EXPECTED_DOMAIN_CHILDREN,
)
from doris_mcp_server.tools.tools_manager import DorisToolsManager
from doris_mcp_server.utils.analysis_tools import SQLAnalyzer
from doris_mcp_server.utils.data_governance_tools import DataGovernanceTools
from doris_mcp_server.utils.db import QueryResult
from doris_mcp_server.utils.schema_extractor import MetadataExtractor
from doris_mcp_server.utils.security import (
    AuthContext,
    get_current_auth_context,
    reset_auth_context,
    set_current_auth_context,
)
from doris_mcp_server.utils.security_analytics_tools import SecurityAnalyticsTools


class FakeRoutedConnection:
    def __init__(self, manager, session_id, auth_context):
        self.manager = manager
        self.session_id = session_id
        self.auth_context = auth_context

    async def execute(
        self,
        sql,
        params=None,
        auth_context=None,
        *,
        max_rows=None,
        max_bytes=None,
    ):
        return await self.manager.execute_query(
            self.session_id,
            sql,
            params,
            auth_context or self.auth_context,
            max_rows=max_rows,
            max_bytes=max_bytes,
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

    async def get_connection(self, session_id):
        return await self._get_connection_for_auth_context(
            session_id,
            self._get_effective_auth_context(),
        )

    async def release_connection(self, session_id, connection):
        self.connection_releases += 1

    async def execute_query(
        self,
        session_id,
        sql,
        params=None,
        auth_context=None,
        *,
        max_rows=None,
        max_bytes=None,
    ):
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
                "max_rows": max_rows,
                "max_bytes": max_bytes,
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


class Doris4RoleMetadataConnection:
    def __init__(self):
        self.calls = []

    async def execute(
        self,
        sql,
        params=None,
        auth_context=None,
        *,
        mask_result=True,
    ):
        self.calls.append(sql.strip())
        assert mask_result is False
        if sql.strip() == "SHOW ALL GRANTS":
            return QueryResult(
                data=[
                    {
                        "UserIdentity": "'root'@'%'",
                        "Roles": "operator, admin",
                    },
                    {
                        "UserIdentity": "'reader'@'10.%'",
                        "Roles": "readonly",
                    },
                    {
                        "UserIdentity": "'loader'@'%'",
                        "Roles": "",
                    },
                ],
                metadata={},
                execution_time=0.01,
                row_count=3,
                sql=sql,
            )
        raise RuntimeError("Unknown column 'Default_role'")


class CurrentUserRoleMetadataConnection:
    def __init__(self):
        self.calls = []

    async def execute(
        self,
        sql,
        params=None,
        auth_context=None,
        *,
        mask_result=True,
    ):
        self.calls.append(sql.strip())
        assert mask_result is False
        if sql.strip() == "SHOW ALL GRANTS":
            raise PermissionError("SHOW ALL GRANTS requires elevated privileges")
        if sql.strip() == "SHOW GRANTS":
            return QueryResult(
                data=[
                    {
                        "UserIdentity": "'reader'@'%'",
                        "Roles": "readonly",
                    }
                ],
                metadata={},
                execution_time=0.01,
                row_count=1,
                sql=sql,
            )
        raise AssertionError(f"Unexpected SQL: {sql}")


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
    manager._tool_exposure_mode = ToolExposureMode.HIERARCHICAL
    manager._domain_manifest_service = DomainManifestService()
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
    token = set_current_auth_context(doris_context(["tool:call:get_sql_profile"]))

    try:
        with pytest.raises(OperationAuthorizationError) as exc:
            authorize_operation(
                get_current_auth_context(),
                "tool:get_sql_profile",
            )
    finally:
        reset_auth_context(token)

    assert exc.value.error_code == "UNSUPPORTED_FOR_DORIS_OAUTH"


@pytest.mark.asyncio
async def test_doris_oauth_exec_query_rejected_before_global_pool_dispatch():
    token = set_current_auth_context(doris_context(["tool:call:exec_query"]))

    try:
        with pytest.raises(OperationAuthorizationError) as exc:
            authorize_operation(
                get_current_auth_context(),
                "tool:exec_query",
            )
    finally:
        reset_auth_context(token)

    assert exc.value.error_code == "DORIS_OAUTH_QUERY_TOOL_NOT_ENABLED"


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
        authorize_operation(
            get_current_auth_context(),
            "tool:exec_query",
        )
        result = await manager._exec_query_tool({"sql": "SELECT 1"})
    finally:
        reset_auth_context(token)

    assert result["ok"] is True
    assert called_arguments == {"sql": "SELECT 1"}


@pytest.mark.asyncio
async def test_doris_oauth_exec_query_real_tool_path_uses_doris_user_route(tmp_path):
    manager, connection_manager = _real_tool_manager_for_routing(tmp_path)
    token = set_current_auth_context(
        doris_context(
            ["tool:call:exec_query"],
            user_id="alice",
            query_tools_enabled=True,
        )
    )

    try:
        authorize_operation(
            get_current_auth_context(),
            "tool:exec_query",
        )
        result = await manager._exec_query_tool(
            {"sql": "SELECT 1", "max_rows": 5}
        )
    finally:
        reset_auth_context(token)

    assert result["success"] is True
    assert result["data"] == [{"one": 1}]
    assert connection_manager.global_calls == 0
    assert connection_manager.token_calls == 0
    assert len(connection_manager.routed_calls) == 1
    assert connection_manager.routed_calls[0]["doris_user"] == "alice"
    assert connection_manager.routed_calls[0]["sql"] == "SELECT 1 LIMIT 5"


@pytest.mark.asyncio
async def test_doris_oauth_exec_query_with_db_catalog_uses_one_routed_connection(
    tmp_path,
):
    manager, connection_manager = _real_tool_manager_for_routing(tmp_path)
    token = set_current_auth_context(
        doris_context(
            ["tool:call:exec_query"],
            user_id="alice",
            query_tools_enabled=True,
        )
    )

    try:
        authorize_operation(
            get_current_auth_context(),
            "tool:exec_query",
        )
        result = await manager._exec_query_tool(
            {
                "sql": "SELECT * FROM orders",
                "db_name": "db1",
                "catalog_name": "ctl1",
                "max_rows": 5,
            },
        )
    finally:
        reset_auth_context(token)

    assert result["success"] is True
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
        authorize_operation(
            get_current_auth_context(),
            "tool:get_sql_explain",
        )
        result = await manager._get_sql_explain_tool({"sql": "SELECT 1"})
    finally:
        reset_auth_context(token)

    assert result["success"] is True
    assert "EXPLAIN SELECT 1" in result["content"]
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
        authorize_operation(
            get_current_auth_context(),
            "tool:get_sql_explain",
        )
        result = await manager._get_sql_explain_tool(
            {
                "sql": "SELECT * FROM orders",
                "db_name": "db1",
                "catalog_name": "ctl1",
            },
        )
    finally:
        reset_auth_context(token)

    assert result["success"] is True
    assert connection_manager.connection_acquires == 1
    assert connection_manager.connection_releases == 1
    assert [call["sql"] for call in connection_manager.routed_calls] == [
        "USE CATALOG `ctl1`",
        "USE `db1`",
        "EXPLAIN SELECT * FROM orders",
    ]
    assert {call["doris_user"] for call in connection_manager.routed_calls} == {"alice"}


@pytest.mark.asyncio
@pytest.mark.parametrize("db_name", [None, "db1"])
async def test_sql_profile_binds_auth_context_without_catalog(tmp_path, db_name):
    manager, connection_manager = _real_tool_manager_for_routing(tmp_path)
    manager.sql_analyzer._get_query_id_by_trace_id = AsyncMock(return_value="query-1")
    manager.sql_analyzer._get_profile_by_query_id = AsyncMock(
        return_value={"profile": "ok"}
    )
    token = set_current_auth_context(
        doris_context(
            ["tool:call:get_sql_profile"],
            user_id="alice",
        )
    )

    try:
        result = await manager.sql_analyzer.get_sql_profile(
            "SELECT 1",
            db_name=db_name,
        )
    finally:
        reset_auth_context(token)

    assert result["success"] is True
    expected_sql = [
        'set session_context="trace_id:',
        "set enable_profile=true",
        "SELECT 1",
    ]
    if db_name:
        expected_sql.insert(0, "USE `db1`")
    assert len(connection_manager.routed_calls) == len(expected_sql)
    for call, sql_prefix in zip(
        connection_manager.routed_calls,
        expected_sql,
        strict=True,
    ):
        assert call["sql"].startswith(sql_prefix)
        assert call["doris_user"] == "alice"
    assert connection_manager.connection_acquires == 1
    assert connection_manager.connection_releases == 1


@pytest.mark.asyncio
async def test_data_freshness_none_threshold_uses_default():
    manager = object.__new__(DorisToolsManager)
    manager.data_governance_tools = SimpleNamespace(
        monitor_data_freshness=AsyncMock(return_value={"ok": True})
    )

    result = await manager._monitor_data_freshness_tool(
        {
            "table_names": ["orders"],
            "freshness_threshold_hours": None,
        }
    )

    assert result == {"ok": True}
    manager.data_governance_tools.monitor_data_freshness.assert_awaited_once_with(
        tables=["orders"],
        time_threshold_hours=24,
        catalog_name=None,
        db_name=None,
    )


@pytest.mark.asyncio
async def test_unknown_data_freshness_is_not_compared_as_a_number():
    governance = DataGovernanceTools(SimpleNamespace())

    issues = await governance._identify_data_flow_issues(
        {
            "orders": {
                "status": "unknown",
                "staleness_hours": None,
            }
        }
    )

    assert issues == []


@pytest.mark.asyncio
async def test_data_freshness_releases_query_connection():
    connection = SimpleNamespace()
    connection_manager = SimpleNamespace(
        get_connection=AsyncMock(return_value=connection),
        release_connection=AsyncMock(),
    )
    governance = DataGovernanceTools(connection_manager)
    governance._analyze_table_freshness = AsyncMock(
        return_value={
            "status": "unknown",
            "staleness_hours": None,
        }
    )

    result = await governance.monitor_data_freshness(tables=["orders"])

    assert result["table_freshness"]["orders"]["status"] == "unknown"
    connection_manager.release_connection.assert_awaited_once_with(
        "query",
        connection,
    )


@pytest.mark.asyncio
async def test_doris4_user_roles_use_show_grants_metadata():
    connection = Doris4RoleMetadataConnection()
    analytics = SecurityAnalyticsTools(SimpleNamespace())

    roles = await analytics._get_user_roles(connection)

    assert roles == {
        "root": ["operator", "admin"],
        "reader": ["readonly"],
        "loader": ["default"],
    }
    assert connection.calls == ["SHOW ALL GRANTS"]


@pytest.mark.asyncio
async def test_data_access_patterns_releases_query_connection():
    connection = SimpleNamespace()
    connection_manager = SimpleNamespace(
        get_connection=AsyncMock(return_value=connection),
        release_connection=AsyncMock(),
    )
    analytics = SecurityAnalyticsTools(connection_manager)
    analytics._get_audit_log_data = AsyncMock(return_value=[{"user_name": "root"}])
    analytics._analyze_user_access_patterns = AsyncMock(return_value=[])
    analytics._analyze_role_access_patterns = AsyncMock(return_value={})
    analytics._detect_security_anomalies = AsyncMock(return_value=[])
    analytics._generate_access_insights = AsyncMock(return_value={})

    result = await analytics.analyze_data_access_patterns()

    assert "error" not in result
    connection_manager.release_connection.assert_awaited_once_with(
        "query",
        connection,
    )


@pytest.mark.asyncio
async def test_user_roles_fall_back_to_current_user_grants():
    connection = CurrentUserRoleMetadataConnection()
    analytics = SecurityAnalyticsTools(SimpleNamespace())

    roles = await analytics._get_user_roles(connection)

    assert roles == {"reader": ["readonly"]}
    assert connection.calls == ["SHOW ALL GRANTS", "SHOW GRANTS"]


@pytest.mark.asyncio
async def test_doris_oauth_list_tools_exposes_only_domain_discovery_scopes(
    tmp_path,
):
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
    assert names == set(EXPECTED_DOMAIN_CHILDREN)
    assert names.isdisjoint(HIGH_RISK_TOOLS)


@pytest.mark.asyncio
async def test_doris_oauth_exec_query_ddl_rejected_before_backend_when_global_security_disabled():
    token = set_current_auth_context(
        doris_context(
            ["tool:call:exec_query"],
            db_tools_enabled=True,
            allowlist=["get_db_list"],
        )
    )

    try:
        with pytest.raises(OperationAuthorizationError) as exc:
            authorize_operation(
                get_current_auth_context(),
                "tool:exec_query",
            )
    finally:
        reset_auth_context(token)

    assert exc.value.error_code == "DORIS_OAUTH_QUERY_TOOL_NOT_ENABLED"


@pytest.mark.asyncio
async def test_doris_oauth_metadata_tool_rejected_before_cache_backend_dispatch_when_gate_false():
    token = set_current_auth_context(doris_context(["tool:call:get_table_schema"]))

    try:
        with pytest.raises(OperationAuthorizationError) as exc:
            authorize_operation(
                get_current_auth_context(),
                "tool:get_table_schema",
            )
    finally:
        reset_auth_context(token)

    assert exc.value.error_code == "DORIS_OAUTH_DB_TOOLS_NOT_ENABLED"


@pytest.mark.asyncio
async def test_missing_auth_context_does_not_restore_removed_tool_names():
    assert get_current_auth_context() is None
    manager = object.__new__(DorisToolsManager)
    manager._tool_exposure_mode = ToolExposureMode.HIERARCHICAL
    manager._domain_manifest_service = DomainManifestService()

    with pytest.raises(ToolNotFoundError) as exc_info:
        await manager.call_tool("get_sql_profile", {"query_id": "q1"})

    assert exc_info.value.name == "get_sql_profile"


def _server_with_mock_managers():
    server = SimpleNamespace()
    server.resources_manager = MagicMock()
    server.resources_manager.list_resources = AsyncMock(return_value=[])
    server.resources_manager.read_resource = AsyncMock(return_value="{}")
    server.prompts_manager = MagicMock()
    server.prompts_manager.list_prompts = AsyncMock(return_value=[])
    server.prompts_manager.get_prompt = AsyncMock(return_value="prompt")
    server.tools_manager = MagicMock()
    server.tools_manager.list_tools = AsyncMock(return_value=[])
    server.tools_manager.call_tool = AsyncMock(return_value="{}")
    server.logger = MagicMock()
    server.server = create_doris_mcp_server(
        resources_manager=server.resources_manager,
        tools_manager=server.tools_manager,
        prompts_manager=server.prompts_manager,
        name="test-doris-mcp-server",
        version=__version__,
        logger=server.logger,
    )
    return server


async def _invoke_protocol_handler(server, operation):
    method, params = {
        "list_resources": ("resources/list", None),
        "read_resource": (
            "resources/read",
            mcp_types.ReadResourceRequestParams(uri="doris://tables"),
        ),
        "list_prompts": ("prompts/list", None),
        "get_prompt": (
            "prompts/get",
            mcp_types.GetPromptRequestParams(
                name="query_analysis",
                arguments={},
            ),
        ),
    }[operation]
    entry = server.server.get_request_handler(method)
    assert entry is not None
    context = SimpleNamespace(protocol_version=mcp_types.LATEST_PROTOCOL_VERSION)
    return await entry.handler(context, params)


def _manager_mock_for_operation(server, operation):
    return {
        "list_resources": server.resources_manager.list_resources,
        "read_resource": server.resources_manager.read_resource,
        "list_prompts": server.prompts_manager.list_prompts,
        "get_prompt": server.prompts_manager.get_prompt,
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
        await _invoke_protocol_handler(server, operation)
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
        if operation == "list_resources":
            with pytest.raises(MCPError) as exc:
                await _invoke_protocol_handler(server, operation)
            assert exc.value.code == -32603
            assert exc.value.message == "Internal server error"
            assert exc.value.data == {
                "operation": "resources/list",
                "listErrorCategory": "internal_error",
            }
        else:
            with pytest.raises(RuntimeError, match=f"{operation} backend failed"):
                await _invoke_protocol_handler(server, operation)
    finally:
        reset_auth_context(token)


@pytest.mark.asyncio
async def test_list_resources_handler_propagates_backend_failure():
    server = _server_with_mock_managers()
    server.resources_manager.list_resources.side_effect = RuntimeError("legacy backend failed")

    with pytest.raises(MCPError) as exc:
        await _invoke_protocol_handler(server, "list_resources")
    assert exc.value.code == -32603
    assert exc.value.message == "Internal server error"
    assert exc.value.data == {
        "operation": "resources/list",
        "listErrorCategory": "internal_error",
    }


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
            await _invoke_protocol_handler(server, operation)
    finally:
        reset_auth_context(token)

    assert exc.value.error_code == "UNSUPPORTED_FOR_DORIS_OAUTH"
    _manager_mock_for_operation(server, operation).assert_not_awaited()
    metadata_cache.get.assert_not_called()
    connection_manager.get_connection.assert_not_awaited()
