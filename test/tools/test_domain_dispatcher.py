# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Contract tests for exact child dispatch and formal flat exposure."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any
from unittest.mock import AsyncMock, Mock, patch

import pytest

from doris_mcp_server.schema_validation import SchemaLimits, ToolSchemaGuard
from doris_mcp_server.tools.domain_catalog import (
    CURRENT_FLAT_TOOL_NAMES,
    DORIS_DOMAIN_CATALOG,
)
from doris_mcp_server.tools.domain_dispatcher import (
    ChildArgumentsAdapterError,
    DomainDispatcher,
    ToolExposureMode,
    ToolNotFoundError,
    _adapt_arguments,
    _as_object,
    _legacy_metadata,
    _unwrap_legacy_result,
    formal_flat_name,
    serialize_dispatch_result,
)
from doris_mcp_server.tools.domain_models import (
    Availability,
    AvailabilityStatus,
    ChildToolDefinition,
    DomainDefinition,
    DomainErrorCode,
)
from doris_mcp_server.tools.tools_manager import DorisToolsManager
from doris_mcp_server.utils.config import DorisConfig
from doris_mcp_server.utils.query_runtime import QueryRuntimeFailure
from doris_mcp_server.utils.security import AuthContext


class SelectiveAvailabilityProvider:
    """Expose only explicitly selected formal capabilities as callable."""

    def __init__(self, callable_features: set[str]) -> None:
        self.callable_features = callable_features

    async def availability_for(
        self,
        domain: DomainDefinition,
        child: ChildToolDefinition,
        auth_context: Any | None,
    ) -> Availability:
        del auth_context
        feature_id = f"{domain.name}.{child.name}"
        if feature_id in self.callable_features:
            return Availability(
                status=AvailabilityStatus.AVAILABLE,
                callable=True,
                reason_code="TEST_HANDLER_READY",
                active_variant=child.support_contract.variants[0].name,
                evidence_sources=("test_handler",),
            )
        return Availability(
            status=AvailabilityStatus.UNKNOWN,
            callable=False,
            reason_code="TEST_HANDLER_PENDING",
        )


def _connection_manager() -> Mock:
    connection_manager = Mock()
    connection_manager.config = DorisConfig()
    return connection_manager


def _manager(
    *callable_features: str,
    mode: str | ToolExposureMode = ToolExposureMode.HIERARCHICAL,
    availability_provider: SelectiveAvailabilityProvider | None = None,
) -> DorisToolsManager:
    return DorisToolsManager(
        _connection_manager(),
        domain_availability_provider=(
            availability_provider
            or SelectiveAvailabilityProvider(set(callable_features))
        ),
        tool_exposure_mode=mode,
    )


def _successful_query() -> dict[str, Any]:
    return {
        "success": True,
        "data": [{"answer": 1}],
        "row_count": 1,
        "metadata": {"columns": ["answer"]},
    }


def test_exposure_mode_and_flat_name_are_exact() -> None:
    assert ToolExposureMode.parse("hierarchical") is ToolExposureMode.HIERARCHICAL
    assert ToolExposureMode.parse(ToolExposureMode.FLAT) is ToolExposureMode.FLAT
    assert formal_flat_name("doris_query", "execute_query") == (
        "doris_query_execute_query"
    )

    with pytest.raises(ValueError, match="hierarchical.*flat"):
        ToolExposureMode.parse("legacy")


def test_dispatcher_registers_exactly_47_formal_flat_names() -> None:
    manager = _manager()
    names = manager.domain_dispatcher.formal_flat_names

    assert len(names) == 47
    assert len(set(names)) == 47
    assert "doris_query_execute_query" in names
    assert not set(CURRENT_FLAT_TOOL_NAMES).intersection(names)
    assert manager.domain_dispatcher.handles_flat("doris_query_execute_query")
    assert not manager.domain_dispatcher.handles_flat("exec_query")


@pytest.mark.asyncio
async def test_default_manager_fails_closed_without_capability_snapshot() -> None:
    manager = DorisToolsManager(_connection_manager())
    manager._exec_query_tool = AsyncMock(return_value=_successful_query())

    manifest = await manager.domain_dispatcher.call_domain(
        "doris_query",
        {},
        None,
    )
    children = {child.name: child for child in manifest.children}

    assert children["execute_query"].availability.callable is False
    assert children["execute_query"].availability.reason_code == "DORIS_VERSION_UNKNOWN"
    assert children["diagnose_query_performance"].availability.callable is False
    assert (
        children["diagnose_query_performance"].availability.reason_code
        == "DORIS_VERSION_UNKNOWN"
    )

    manager._exec_query_tool.assert_not_awaited()


def test_dispatcher_rejects_colliding_formal_flat_names() -> None:
    manager = _manager()

    with (
        patch(
            "doris_mcp_server.tools.domain_dispatcher.formal_flat_name",
            return_value="doris_duplicate",
        ),
        pytest.raises(ValueError, match="duplicate formal flat tool"),
    ):
        DomainDispatcher(
            manager,
            manager.domain_manifest_service,
        )


@pytest.mark.asyncio
async def test_hierarchical_discovery_and_execution_use_one_exact_handler() -> None:
    manager = _manager("doris_query.execute_query")
    manager._exec_query_tool = AsyncMock(return_value=_successful_query())

    tools = await manager.list_tools()
    ToolSchemaGuard().compile_catalog(tools)
    manifest = json.loads(await manager.call_tool("doris_query", {}))
    result = json.loads(
        await manager.call_tool(
            "doris_query",
            {
                "child_tool": "execute_query",
                "arguments": {
                    "sql": "SELECT 1 AS answer",
                    "timeout_ms": 1500,
                },
                "manifest_version": manifest["manifest_version"],
            },
        )
    )

    assert [tool.name for tool in tools] == [
        domain.name for domain in DORIS_DOMAIN_CATALOG.domains
    ]
    assert result["mode"] == "result"
    assert result["domain"] == "doris_query"
    assert result["child_tool"] == "execute_query"
    assert result["data"]["data"] == {
        "columns": [{"name": "answer"}],
        "rows": [{"answer": 1}],
        "row_count": 1,
        "truncated": False,
    }
    manager._exec_query_tool.assert_awaited_once_with(
        {
            "sql": "SELECT 1 AS answer",
            "timeout": 2,
        }
    )


@pytest.mark.asyncio
async def test_flat_mode_lists_47_formal_tools_and_uses_same_handler() -> None:
    manager = _manager(
        "doris_query.execute_query",
        mode=ToolExposureMode.FLAT,
    )
    manager._exec_query_tool = AsyncMock(return_value=_successful_query())

    tools = await manager.list_tools()
    ToolSchemaGuard().compile_catalog(tools)
    result = json.loads(
        await manager.call_tool(
            "doris_query_execute_query",
            {"sql": "SELECT 1 AS answer"},
        )
    )

    assert len(tools) == 47
    assert tools[5].name == "doris_query_execute_query"
    assert tools[5].description.startswith("[AVAILABLE |")
    assert tools[5].input_schema["required"] == ["sql"]
    assert result["domain"] == "doris_query"
    assert result["child_tool"] == "execute_query"
    manager._exec_query_tool.assert_awaited_once_with({"sql": "SELECT 1 AS answer"})


@pytest.mark.asyncio
async def test_error_envelopes_match_both_public_output_schemas() -> None:
    hierarchical = _manager("doris_query.execute_query")
    hierarchical_tool = next(
        tool for tool in await hierarchical.list_tools() if tool.name == "doris_query"
    )
    hierarchical_schema = ToolSchemaGuard().compile_tool(hierarchical_tool)
    hierarchical_error = json.loads(
        await hierarchical.call_tool(
            "doris_query",
            {
                "child_tool": "execute_query",
                "arguments": {"unknown": True},
            },
        )
    )

    flat = _manager(
        "doris_query.execute_query",
        mode=ToolExposureMode.FLAT,
    )
    flat_tool = next(
        tool
        for tool in await flat.list_tools()
        if tool.name == "doris_query_execute_query"
    )
    flat_schema = ToolSchemaGuard().compile_tool(flat_tool)
    flat_error = json.loads(
        await flat.call_tool(
            "doris_query_execute_query",
            {"unknown": True},
        )
    )

    assert hierarchical_error["mode"] == "error"
    assert flat_error["mode"] == "error"
    hierarchical_schema.validate_output(hierarchical_error)
    flat_schema.validate_output(flat_error)


@pytest.mark.asyncio
async def test_flat_list_hides_children_outside_explicit_grants() -> None:
    manager = _manager(mode=ToolExposureMode.FLAT)
    context = AuthContext(
        auth_method="external_oauth",
        oauth_scopes=["child:call:doris_catalog:list_tables"],
    )

    tools = await manager.domain_dispatcher.list_flat_tools(context)

    assert [tool.name for tool in tools] == ["doris_catalog_list_tables"]


@pytest.mark.asyncio
async def test_direct_flat_dispatch_rejects_unknown_name() -> None:
    manager = _manager()

    with pytest.raises(ToolNotFoundError) as exc_info:
        await manager.domain_dispatcher.call_flat(
            "doris_query_execute_quer",
            {"sql": "SELECT 1"},
            None,
        )

    assert exc_info.value.name == "doris_query_execute_quer"


def test_dispatcher_rejects_missing_migrated_handler() -> None:
    manager = _manager()
    manager._exec_query_tool = None

    with pytest.raises(ValueError, match="references missing handler"):
        DomainDispatcher(
            manager,
            manager.domain_manifest_service,
        )


def test_dispatcher_rejects_ambiguous_atomic_bindings() -> None:
    manager = _manager()
    migrations = list(DORIS_DOMAIN_CATALOG.legacy_migrations)
    migrations[2] = migrations[2].model_copy(
        update={
            "domain": "doris_query",
            "child_name": "execute_query",
        }
    )
    invalid_catalog = DORIS_DOMAIN_CATALOG.model_copy(
        update={"legacy_migrations": tuple(migrations)}
    )

    with pytest.raises(ValueError, match="ambiguous atomic handler"):
        DomainDispatcher(
            manager,
            manager.domain_manifest_service,
            catalog=invalid_catalog,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mode",
    [ToolExposureMode.HIERARCHICAL, ToolExposureMode.FLAT],
)
async def test_old_and_unknown_top_level_names_are_not_callable(
    mode: ToolExposureMode,
) -> None:
    manager = _manager("doris_query.execute_query", mode=mode)

    for name in ("exec_query", "get_db_list", "missing_tool"):
        with pytest.raises(ToolNotFoundError) as error:
            await manager.call_tool(name, {})
        assert error.value.name == name
        assert str(error.value) == "Tool not found"


@pytest.mark.asyncio
async def test_similar_child_spelling_never_matches() -> None:
    manager = _manager("doris_query.execute_query")

    payload = json.loads(
        await manager.call_tool(
            "doris_query",
            {
                "child_tool": "execute_quer",
                "arguments": {"sql": "SELECT 1"},
            },
        )
    )

    assert payload["mode"] == "error"
    assert payload["error"]["code"] == DomainErrorCode.CHILD_TOOL_NOT_FOUND


@pytest.mark.asyncio
async def test_manifest_race_still_fails_closed_as_not_found() -> None:
    manager = _manager("doris_query.execute_query")
    domain = DORIS_DOMAIN_CATALOG.resolve_domain("doris_query")
    manifest = await manager.domain_manifest_service.discover(domain, None)
    filtered_manifest = manifest.model_copy(update={"children": ()})

    with patch.object(
        manager.domain_manifest_service,
        "discover",
        AsyncMock(return_value=filtered_manifest),
    ):
        result = await manager.domain_dispatcher.call_domain(
            "doris_query",
            {
                "child_tool": "execute_query",
                "arguments": {"sql": "SELECT 1"},
            },
            None,
        )

    assert result.mode == "error"
    assert result.error.code is DomainErrorCode.CHILD_TOOL_NOT_FOUND


@pytest.mark.asyncio
async def test_domain_and_child_argument_schemas_fail_closed() -> None:
    manager = _manager("doris_query.execute_query")

    invalid_outer = json.loads(
        await manager.call_tool(
            "doris_query",
            {"arguments": {"sql": "SELECT 1"}},
        )
    )
    invalid_child = json.loads(
        await manager.call_tool(
            "doris_query",
            {
                "child_tool": "execute_query",
                "arguments": {"max_rows": 10},
            },
        )
    )

    assert invalid_outer["error"]["code"] == (DomainErrorCode.CHILD_ARGUMENTS_INVALID)
    assert invalid_child["error"]["code"] == (DomainErrorCode.CHILD_ARGUMENTS_INVALID)
    assert invalid_child["error"]["details"]["violations"] == [
        {"instancePath": "", "keyword": "required"}
    ]


@pytest.mark.asyncio
async def test_child_argument_violation_list_is_bounded_and_marked() -> None:
    manager = _manager("doris_query.execute_query")
    dispatcher = DomainDispatcher(
        manager,
        manager.domain_manifest_service,
        schema_guard=ToolSchemaGuard(SchemaLimits(max_validation_errors=1)),
    )

    result = await dispatcher.call_domain(
        "doris_query",
        {
            "child_tool": "execute_query",
            "arguments": {"unknown": True},
        },
        None,
    )

    assert result.mode == "error"
    assert result.error.code is DomainErrorCode.CHILD_ARGUMENTS_INVALID
    assert result.to_wire()["error"]["details"]["truncated"] is True


@pytest.mark.asyncio
async def test_manifest_version_unavailable_and_unbound_fail_closed() -> None:
    callable_manager = _manager("doris_query.execute_query")
    stale = json.loads(
        await callable_manager.call_tool(
            "doris_query",
            {
                "child_tool": "execute_query",
                "arguments": {"sql": "SELECT 1"},
                "manifest_version": "query.stale",
            },
        )
    )
    unavailable_manager = _manager()
    unavailable = json.loads(
        await unavailable_manager.call_tool(
            "doris_query",
            {
                "child_tool": "execute_query",
                "arguments": {"sql": "SELECT 1"},
            },
        )
    )
    unbound_manager = _manager("doris_cluster.list_cluster_nodes")
    unbound = json.loads(
        await unbound_manager.call_tool(
            "doris_cluster",
            {
                "child_tool": "list_cluster_nodes",
                "arguments": {},
            },
        )
    )

    assert stale["error"]["code"] == DomainErrorCode.CHILD_MANIFEST_STALE
    assert stale["error"]["details"]["rediscover"] is True
    assert unavailable["error"]["code"] == (
        DomainErrorCode.CHILD_CAPABILITY_UNAVAILABLE
    )
    assert unavailable["error"]["details"]["reason_code"] == ("TEST_HANDLER_PENDING")
    assert unbound["error"]["details"]["reason_code"] == "HANDLER_NOT_BOUND"


@pytest.mark.asyncio
async def test_runtime_provider_down_is_rechecked_before_execution() -> None:
    provider = SelectiveAvailabilityProvider({"doris_query.execute_query"})
    manager = _manager(availability_provider=provider)
    manager._exec_query_tool = AsyncMock(return_value=_successful_query())
    manifest = await manager.domain_dispatcher.call_domain(
        "doris_query",
        {},
        None,
    )

    provider.callable_features.clear()
    stale = await manager.domain_dispatcher.call_domain(
        "doris_query",
        {
            "child_tool": "execute_query",
            "arguments": {"sql": "SELECT 1"},
            "manifest_version": manifest.manifest_version,
        },
        None,
    )
    unavailable = await manager.domain_dispatcher.call_domain(
        "doris_query",
        {
            "child_tool": "execute_query",
            "arguments": {"sql": "SELECT 1"},
        },
        None,
    )

    assert stale.mode == "error"
    assert stale.error.code is DomainErrorCode.CHILD_MANIFEST_STALE
    assert unavailable.mode == "error"
    assert unavailable.error.code is DomainErrorCode.CHILD_CAPABILITY_UNAVAILABLE
    assert unavailable.error.details["reason_code"] == "TEST_HANDLER_PENDING"
    manager._exec_query_tool.assert_not_awaited()


@pytest.mark.asyncio
async def test_undiscoverable_child_is_indistinguishable_from_missing() -> None:
    manager = _manager("doris_query.execute_query")
    context = AuthContext(
        auth_method="external_oauth",
        oauth_scopes=[
            "child:call:doris_catalog:list_tables",
        ],
    )

    result = await manager.domain_dispatcher.call_domain(
        "doris_query",
        {
            "child_tool": "execute_query",
            "arguments": {"sql": "SELECT 1"},
        },
        context,
    )

    assert result.mode == "error"
    assert result.error.code is DomainErrorCode.CHILD_TOOL_NOT_FOUND


@pytest.mark.asyncio
@pytest.mark.parametrize("auth_method", ["external_oauth", "doris_oauth"])
@pytest.mark.parametrize(
    "oauth_scopes",
    [
        ["tool:list"],
        [
            "tool:list",
            "child:discover:doris_query:execute_query",
        ],
    ],
)
async def test_oauth_execution_requires_exact_child_call_grant(
    auth_method: str,
    oauth_scopes: list[str],
) -> None:
    manager = _manager("doris_query.execute_query")
    manager._exec_query_tool = AsyncMock(return_value=_successful_query())
    context = AuthContext(
        auth_method=auth_method,
        oauth_scopes=oauth_scopes,
        doris_oauth_child_tools_enabled=auth_method == "doris_oauth",
        doris_oauth_child_tool_allowlist=(
            ("doris_query.execute_query",) if auth_method == "doris_oauth" else ()
        ),
    )

    result = await manager.domain_dispatcher.call_domain(
        "doris_query",
        {
            "child_tool": "execute_query",
            "arguments": {"sql": "SELECT 1"},
        },
        context,
    )

    assert result.mode == "error"
    assert result.error.code is DomainErrorCode.CHILD_TOOL_NOT_FOUND
    manager._exec_query_tool.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("auth_method", ["external_oauth", "doris_oauth"])
async def test_exact_child_call_grant_executes_and_static_token_fallback_remains(
    auth_method: str,
) -> None:
    manager = _manager("doris_query.execute_query")
    manager._exec_query_tool = AsyncMock(return_value=_successful_query())
    request = {
        "child_tool": "execute_query",
        "arguments": {"sql": "SELECT 1"},
    }

    oauth_result = await manager.domain_dispatcher.call_domain(
        "doris_query",
        request,
        AuthContext(
            auth_method=auth_method,
            oauth_scopes=[
                "tool:list",
                "child:call:doris_query:execute_query",
            ],
            doris_oauth_child_tools_enabled=auth_method == "doris_oauth",
            doris_oauth_child_tool_allowlist=(
                ("doris_query.execute_query",) if auth_method == "doris_oauth" else ()
            ),
        ),
    )
    token_result = await manager.domain_dispatcher.call_domain(
        "doris_query",
        request,
        AuthContext(
            auth_method="token",
            permissions=["read"],
        ),
    )

    assert oauth_result.mode == "result"
    assert token_result.mode == "result"
    assert manager._exec_query_tool.await_count == 2


@pytest.mark.asyncio
async def test_flat_dispatch_cannot_bypass_discovery_only_grant() -> None:
    manager = _manager(
        "doris_query.execute_query",
        mode=ToolExposureMode.FLAT,
    )
    manager._exec_query_tool = AsyncMock(return_value=_successful_query())
    context = AuthContext(
        auth_method="external_oauth",
        oauth_scopes=[
            "tool:list",
            "child:discover:doris_query:execute_query",
        ],
    )

    result = await manager.domain_dispatcher.call_flat(
        "doris_query_execute_query",
        {"sql": "SELECT 1"},
        context,
    )

    assert result.mode == "error"
    assert result.error.code is DomainErrorCode.CHILD_TOOL_NOT_FOUND
    manager._exec_query_tool.assert_not_awaited()


@pytest.mark.asyncio
async def test_query_adapters_support_formal_query_capabilities() -> None:
    manager = _manager(
        "doris_query.execute_query",
        "doris_query.explain_query",
        "doris_query.get_query_profile",
    )
    manager._exec_query_tool = AsyncMock(
        return_value={
            "status": "success",
            "data": {
                "columns": [{"name": "value"}],
                "rows": [{"value": 1}],
                "row_count": 1,
                "truncated": False,
            },
            "warnings": [],
            "metadata": {},
        }
    )
    diagnostic = {
        "status": "success",
        "data": {},
        "warnings": [],
        "metadata": {},
        "evidence": [],
    }
    manager._get_sql_explain_tool = AsyncMock(return_value=diagnostic)
    manager._get_sql_profile_tool = AsyncMock(return_value=diagnostic)

    cases = (
        (
            "execute_query",
            {
                "sql": "SELECT %(value)s",
                "parameters": {"value": 1},
            },
        ),
        (
            "explain_query",
            {"sql": "SELECT 1", "level": "costs"},
        ),
        (
            "get_query_profile",
            {"query_id": "query-1"},
        ),
    )
    for child_name, arguments in cases:
        result = await manager.domain_dispatcher.call_domain(
            "doris_query",
            {"child_tool": child_name, "arguments": arguments},
            None,
        )
        assert result.mode == "result"

    manager._exec_query_tool.assert_awaited_once_with(
        {
            "sql": "SELECT %(value)s",
            "parameters": {"value": 1},
        }
    )
    manager._get_sql_explain_tool.assert_awaited_once_with(
        {"sql": "SELECT 1", "level": "costs"}
    )
    manager._get_sql_profile_tool.assert_awaited_once_with(
        {"query_id": "query-1"}
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("reason_code", "expected_code"),
    [
        (
            "QUERY_READ_ONLY_VIOLATION",
            DomainErrorCode.CHILD_ARGUMENTS_INVALID,
        ),
        ("QUERY_TIMEOUT", DomainErrorCode.CHILD_EXECUTION_TIMEOUT),
        (
            "QUERY_BACKEND_UNAVAILABLE",
            DomainErrorCode.CHILD_EXECUTION_FAILED,
        ),
    ],
)
async def test_query_runtime_failures_map_to_stable_domain_errors(
    reason_code: str,
    expected_code: DomainErrorCode,
) -> None:
    manager = _manager("doris_query.execute_query")
    manager._exec_query_tool = AsyncMock(
        side_effect=QueryRuntimeFailure(
            "Sanitized query failure.",
            reason_code=reason_code,
            status_code=504 if reason_code == "QUERY_TIMEOUT" else 400,
            retryable=reason_code != "QUERY_READ_ONLY_VIOLATION",
        )
    )

    result = await manager.domain_dispatcher.call_domain(
        "doris_query",
        {
            "child_tool": "execute_query",
            "arguments": {"sql": "SELECT 1"},
        },
        None,
    )

    assert result.mode == "error"
    assert result.error.code is expected_code
    assert result.error.message == "Sanitized query failure."
    assert result.error.details["reason_code"] == reason_code


@pytest.mark.asyncio
async def test_new_query_diagnosis_uses_formal_direct_binding() -> None:
    manager = _manager("doris_query.diagnose_query_performance")
    manager.query_runtime.diagnose_query_performance = AsyncMock(
        return_value={
            "status": "partial",
            "data": {
                "query_id": None,
                "steps": {"cluster_context": {"status": "not_requested"}},
                "findings": [],
                "recommendations": [],
            },
            "warnings": ["No matching audit-log evidence was found."],
            "metadata": {
                "source": "deterministic_query_diagnosis",
                "rule_version": "query-diagnosis-v1",
            },
            "evidence": [],
        }
    )

    result = await manager.domain_dispatcher.call_domain(
        "doris_query",
        {
            "child_tool": "diagnose_query_performance",
            "arguments": {"sql": "SELECT 1"},
        },
        None,
    )

    assert result.mode == "result"
    assert result.to_wire()["data"]["status"] == "partial"
    manager.query_runtime.diagnose_query_performance.assert_awaited_once_with(
        query_id=None,
        sql="SELECT 1",
        database=None,
        include_cluster_context=False,
    )


@pytest.mark.asyncio
async def test_handler_failure_is_safe_and_audited_with_formal_name() -> None:
    manager = _manager("doris_query.execute_query")
    manager._exec_query_tool = AsyncMock(
        return_value={
            "success": False,
            "error": "secret backend detail",
        }
    )
    audit_logger = Mock()

    with patch(
        "doris_mcp_server.tools.domain_dispatcher.get_audit_logger",
        return_value=audit_logger,
    ):
        result = await manager.domain_dispatcher.call_domain(
            "doris_query",
            {
                "child_tool": "execute_query",
                "arguments": {"sql": "SELECT 'secret'"},
            },
            None,
        )

    assert result.mode == "error"
    assert result.error.code is DomainErrorCode.CHILD_EXECUTION_FAILED
    assert "secret" not in result.to_canonical_json()
    assert "doris_query.execute_query" in repr(audit_logger.info.call_args)
    assert "exec_query" not in repr(audit_logger.info.call_args)
    assert "SELECT" not in repr(audit_logger.info.call_args)


@pytest.mark.asyncio
async def test_non_object_handler_result_is_safe_execution_error() -> None:
    manager = _manager("doris_query.execute_query")
    manager._exec_query_tool = AsyncMock(return_value=["not", "an", "object"])

    result = await manager.domain_dispatcher.call_domain(
        "doris_query",
        {
            "child_tool": "execute_query",
            "arguments": {"sql": "SELECT 1"},
        },
        None,
    )

    assert result.mode == "error"
    assert result.error.code is DomainErrorCode.CHILD_EXECUTION_FAILED


@pytest.mark.asyncio
async def test_output_schema_violation_becomes_stable_server_error() -> None:
    manager = _manager("doris_query.execute_query")
    manager._exec_query_tool = AsyncMock(return_value=_successful_query())

    with patch.object(
        manager.domain_dispatcher,
        "_normalize_child_result",
        return_value={"not": "valid"},
    ):
        result = await manager.domain_dispatcher.call_domain(
            "doris_query",
            {
                "child_tool": "execute_query",
                "arguments": {"sql": "SELECT 1"},
            },
            None,
        )

    assert result.mode == "error"
    assert result.error.code is DomainErrorCode.CHILD_RESULT_INVALID


@pytest.mark.asyncio
async def test_table_context_composite_merges_selected_sections() -> None:
    manager = _manager("doris_catalog.get_table_context")
    manager._get_table_schema_tool = AsyncMock(
        return_value={"success": True, "result": {"columns": ["id"]}}
    )
    manager._get_table_comment_tool = AsyncMock(
        return_value={"success": True, "result": {"comment": "orders"}}
    )
    manager._get_table_column_comments_tool = AsyncMock(
        return_value={"success": True, "result": {"id": "key"}}
    )
    manager._get_table_indexes_tool = AsyncMock(
        return_value={"success": False, "error": "not available"}
    )
    manager._get_table_basic_info_tool = AsyncMock(
        return_value={"success": True, "row_count": 1}
    )

    result = await manager.domain_dispatcher.call_domain(
        "doris_catalog",
        {
            "child_tool": "get_table_context",
            "arguments": {
                "catalog": "internal",
                "database": "analytics",
                "table": "orders",
            },
        },
        None,
    )

    assert result.mode == "result"
    child_result = cast_mapping(result.to_wire()["data"])
    assert child_result["status"] == "partial"
    assert child_result["data"]["schema"] == {
        "status": "success",
        "data": {"columns": ["id"]},
        "warnings": [],
        "source": "_get_table_schema_tool",
    }
    assert child_result["data"]["comments"]["data"] == {
        "table": {"comment": "orders"},
        "columns": {"id": "key"},
    }
    assert child_result["data"]["indexes"]["status"] == "unavailable"
    assert child_result["data"]["indexes"]["data"] == {}
    assert (
        child_result["data"]["indexes"]["warnings"]
        == [
            "Optional indexes section is unavailable "
            "(CATALOG_EXECUTION_FAILED)."
        ]
    )
    assert child_result["data"]["basic"]["data"]["row_count"] == 1
    assert len(child_result["evidence"]) == 5
    manager._get_table_schema_tool.assert_awaited_once_with(
        {
            "catalog_name": "internal",
            "db_name": "analytics",
            "table_name": "orders",
            "_formal_catalog": True,
        }
    )


@pytest.mark.asyncio
async def test_table_context_required_schema_failure_is_execution_error() -> None:
    manager = _manager("doris_catalog.get_table_context")
    manager._get_table_schema_tool = AsyncMock(
        return_value={"success": False, "error": "missing"}
    )

    result = await manager.domain_dispatcher.call_domain(
        "doris_catalog",
        {
            "child_tool": "get_table_context",
            "arguments": {
                "database": "analytics",
                "table": "orders",
                "sections": ["schema"],
            },
        },
        None,
    )

    assert result.mode == "error"
    assert result.error.code is DomainErrorCode.CHILD_EXECUTION_FAILED


@pytest.mark.asyncio
async def test_table_context_required_schema_distinguishes_missing_object() -> None:
    manager = _manager("doris_catalog.get_table_context")
    manager._get_table_schema_tool = AsyncMock(
        return_value={
            "success": False,
            "error": "not visible",
            "error_code": "DORIS_METADATA_NOT_VISIBLE",
            "status_code": 404,
        }
    )

    result = await manager.domain_dispatcher.call_domain(
        "doris_catalog",
        {
            "child_tool": "get_table_context",
            "arguments": {
                "database": "analytics",
                "table": "missing",
                "sections": ["schema"],
            },
        },
        None,
    )

    assert result.mode == "error"
    assert result.error.code is DomainErrorCode.CHILD_EXECUTION_FAILED
    assert (
        result.error.details["reason_code"]
        == "CATALOG_OBJECT_NOT_FOUND"
    )
    assert result.error.details["status_code"] == 404


@pytest.mark.asyncio
async def test_table_context_skips_unrequested_optional_sections() -> None:
    manager = _manager("doris_catalog.get_table_context")
    manager._get_table_schema_tool = AsyncMock(
        return_value={"success": True, "result": {"columns": ["id"]}}
    )

    result = await manager.domain_dispatcher.call_domain(
        "doris_catalog",
        {
            "child_tool": "get_table_context",
            "arguments": {
                "database": "analytics",
                "table": "orders",
                "sections": ["schema"],
            },
        },
        None,
    )

    assert result.mode == "result"
    assert result.to_wire()["data"]["data"] == {
        "schema": {
            "status": "success",
            "data": {"columns": ["id"]},
            "warnings": [],
            "source": "_get_table_schema_tool",
        }
    }


@pytest.mark.asyncio
async def test_table_context_includes_schema_for_comments_only_selection() -> None:
    manager = _manager("doris_catalog.get_table_context")
    manager._get_table_schema_tool = AsyncMock(
        return_value={"success": True, "result": {"columns": ["id"]}}
    )
    manager._get_table_comment_tool = AsyncMock(
        return_value={"success": True, "result": {"comment": "orders"}}
    )
    manager._get_table_column_comments_tool = AsyncMock(
        return_value={"success": True, "result": {"id": "key"}}
    )
    manager._get_table_indexes_tool = AsyncMock()
    manager._get_table_basic_info_tool = AsyncMock()

    result = await manager.domain_dispatcher.call_domain(
        "doris_catalog",
        {
            "child_tool": "get_table_context",
            "arguments": {
                "database": "analytics",
                "table": "orders",
                "sections": ["comments"],
            },
        },
        None,
    )

    assert result.mode == "result"
    child_result = cast_mapping(result.to_wire()["data"])
    assert child_result["data"] == {
        "schema": {
            "status": "success",
            "data": {"columns": ["id"]},
            "warnings": [],
            "source": "_get_table_schema_tool",
        },
        "comments": {
            "status": "success",
            "data": {
                "table": {"comment": "orders"},
                "columns": {"id": "key"},
            },
            "warnings": [],
            "source": (
                "_get_table_comment_tool,"
                "_get_table_column_comments_tool"
            ),
        },
    }
    assert child_result["metadata"]["sections"] == ["schema", "comments"]
    assert child_result["metadata"]["requested_sections"] == ["comments"]
    manager._get_table_indexes_tool.assert_not_awaited()
    manager._get_table_basic_info_tool.assert_not_awaited()


@pytest.mark.asyncio
async def test_table_context_internal_guards_reject_invalid_composition() -> None:
    manager = _manager()
    dispatcher = manager.domain_dispatcher
    table_context = DORIS_DOMAIN_CATALOG.resolve_child(
        "doris_catalog",
        "get_table_context",
    )
    wrong_child = DORIS_DOMAIN_CATALOG.resolve_child(
        "doris_catalog",
        "list_catalogs",
    )
    migrations = dispatcher._bindings["doris_catalog.get_table_context"]
    assert isinstance(migrations, tuple)

    with pytest.raises(RuntimeError, match="unsupported composite"):
        await dispatcher._call_table_context(
            wrong_child,
            migrations,
            {},
        )
    with pytest.raises(RuntimeError, match="required schema"):
        await dispatcher._call_table_context(
            table_context,
            (),
            {
                "database": "analytics",
                "table": "orders",
            },
        )


def test_collection_result_normalization_filters_and_paginates() -> None:
    manager = _manager()
    child = DORIS_DOMAIN_CATALOG.resolve_child(
        "doris_catalog",
        "list_catalogs",
    )

    result = manager.domain_dispatcher._normalize_child_result(
        child,
        {
            "success": True,
            "result": [
                {"name": "internal", "scope": "internal"},
                *[
                    {"name": f"external_{index:03d}", "scope": "external"}
                    for index in range(101)
                ],
            ],
        },
        {
            "pattern": "*",
            "include_external": True,
        },
        (),
    )

    assert result["status"] == "success"
    assert len(result["data"]["items"]) == 100
    assert result["data"]["truncated"] is True
    assert isinstance(result["data"]["next_cursor"], str)

    next_page = manager.domain_dispatcher._normalize_child_result(
        child,
        {
            "success": True,
            "result": [
                {"name": "internal", "scope": "internal"},
                *[
                    {"name": f"external_{index:03d}", "scope": "external"}
                    for index in range(101)
                ],
            ],
        },
        {
            "pattern": "*",
            "include_external": True,
            "page": result["data"]["next_cursor"],
        },
        (),
    )
    assert len(next_page["data"]["items"]) == 2
    assert next_page["data"]["next_cursor"] is None
    assert next_page["data"]["truncated"] is False

    internal_only = manager.domain_dispatcher._normalize_child_result(
        child,
        {
            "success": True,
            "result": [
                {"name": "internal", "scope": "internal"},
                {"name": "iceberg", "scope": "external"},
            ],
        },
        {"include_external": False},
        (),
    )
    assert internal_only["data"]["items"] == [
        {"name": "internal", "scope": "internal"}
    ]


def test_table_collection_filters_exact_normalized_object_types() -> None:
    manager = _manager()
    child = DORIS_DOMAIN_CATALOG.resolve_child(
        "doris_catalog",
        "list_tables",
    )

    result = manager.domain_dispatcher._normalize_child_result(
        child,
        {
            "success": True,
            "result": [
                {"name": "orders", "type": "table"},
                {"name": "orders_view", "type": "view"},
                {"name": "orders_mv", "type": "materialized_view"},
            ],
        },
        {
            "database": "analytics",
            "types": ["view", "materialized_view"],
        },
        (),
    )

    assert result["data"]["items"] == [
        {"name": "orders_mv", "type": "materialized_view"},
        {"name": "orders_view", "type": "view"},
    ]


def test_collection_cursor_is_bound_to_the_exact_request() -> None:
    manager = _manager()
    child = DORIS_DOMAIN_CATALOG.resolve_child(
        "doris_catalog",
        "list_tables",
    )
    raw = {
        "success": True,
        "result": [
            {"name": f"table_{index:03d}", "type": "table"}
            for index in range(101)
        ],
    }
    first = manager.domain_dispatcher._normalize_child_result(
        child,
        raw,
        {"database": "analytics"},
        (),
    )

    with pytest.raises(
        ChildArgumentsAdapterError,
        match="invalid",
    ):
        manager.domain_dispatcher._normalize_child_result(
            child,
            raw,
            {
                "database": "other_database",
                "page": first["data"]["next_cursor"],
            },
            (),
        )


def test_collection_cursor_is_bound_to_the_authorization_principal() -> None:
    manager = _manager()
    child = DORIS_DOMAIN_CATALOG.resolve_child(
        "doris_catalog",
        "list_tables",
    )
    raw = {
        "success": True,
        "result": [
            {"name": f"table_{index:03d}", "type": "table"}
            for index in range(101)
        ],
    }
    alice = AuthContext(auth_method="basic", user_id="alice")
    bob = AuthContext(auth_method="basic", user_id="bob")
    first = manager.domain_dispatcher._normalize_child_result(
        child,
        raw,
        {"database": "analytics"},
        (),
        alice,
    )

    with pytest.raises(ChildArgumentsAdapterError, match="invalid"):
        manager.domain_dispatcher._normalize_child_result(
            child,
            raw,
            {
                "database": "analytics",
                "page": first["data"]["next_cursor"],
            },
            (),
            bob,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("raw", "reason_code"),
    [
        (
            {
                "success": False,
                "error": "hidden backend message",
                "error_code": "DORIS_METADATA_PERMISSION_DENIED",
                "status_code": 403,
            },
            "CATALOG_PERMISSION_DENIED",
        ),
        (
            {
                "success": False,
                "error": "table does not exist",
                "error_code": "DORIS_METADATA_NOT_VISIBLE",
                "status_code": 404,
            },
            "CATALOG_OBJECT_NOT_FOUND",
        ),
    ],
)
async def test_catalog_atomic_failures_have_stable_reason_codes(
    raw: dict[str, Any],
    reason_code: str,
) -> None:
    manager = _manager("doris_catalog.list_tables")
    manager._get_db_table_list_tool = AsyncMock(return_value=raw)

    result = await manager.domain_dispatcher.call_domain(
        "doris_catalog",
        {
            "child_tool": "list_tables",
            "arguments": {"database": "analytics"},
        },
        None,
    )

    assert result.mode == "error"
    assert result.error.code is DomainErrorCode.CHILD_EXECUTION_FAILED
    assert result.error.details["reason_code"] == reason_code
    assert "hidden backend message" not in result.error.message


@pytest.mark.asyncio
async def test_table_size_preserves_partition_degradation_as_partial_result() -> None:
    manager = _manager("doris_catalog.get_table_size")
    manager._get_table_data_size_tool = AsyncMock(
        return_value={
            "success": True,
            "result": {
                "row_count": 10,
                "data_size_bytes": 100,
                "partitions": [],
            },
            "warnings": [
                "Partition statistics are unavailable "
                "(CATALOG_SECTION_UNSUPPORTED)."
            ],
            "metadata": {
                "partition_status": "unavailable",
                "partition_reason_code": "CATALOG_SECTION_UNSUPPORTED",
            },
        }
    )

    result = await manager.domain_dispatcher.call_domain(
        "doris_catalog",
        {
            "child_tool": "get_table_size",
            "arguments": {
                "database": "analytics",
                "table": "orders",
                "include_partitions": True,
            },
        },
        None,
    )

    assert result.mode == "result"
    child_result = result.to_wire()["data"]
    assert child_result["status"] == "partial"
    assert child_result["data"]["row_count"] == 10
    assert child_result["metadata"]["partition_status"] == "unavailable"
    manager._get_table_data_size_tool.assert_awaited_once_with(
        {
            "db_name": "analytics",
            "table_name": "orders",
            "include_partitions": True,
            "single_replica": False,
            "_formal_catalog": True,
        }
    )


@pytest.mark.asyncio
async def test_table_context_marks_unsupported_optional_section() -> None:
    manager = _manager("doris_catalog.get_table_context")
    manager._get_table_schema_tool = AsyncMock(
        return_value={"success": True, "result": {"columns": ["id"]}}
    )
    manager._get_table_indexes_tool = AsyncMock(
        return_value={
            "success": False,
            "error": "unsupported",
            "error_code": "CATALOG_SECTION_UNSUPPORTED",
            "status_code": 501,
        }
    )

    result = await manager.domain_dispatcher.call_domain(
        "doris_catalog",
        {
            "child_tool": "get_table_context",
            "arguments": {
                "database": "analytics",
                "table": "orders",
                "sections": ["indexes"],
            },
        },
        None,
    )

    assert result.mode == "result"
    indexes = result.to_wire()["data"]["data"]["indexes"]
    assert indexes["status"] == "unavailable"
    assert indexes["data"] == {}
    assert "CATALOG_SECTION_UNSUPPORTED" in indexes["warnings"][0]
    assert (
        result.to_wire()["data"]["evidence"][1]["reason_code"]
        == "CATALOG_SECTION_UNSUPPORTED"
    )


def test_query_result_normalization_handles_malformed_legacy_shapes() -> None:
    manager = _manager()
    child = DORIS_DOMAIN_CATALOG.resolve_child(
        "doris_query",
        "execute_query",
    )

    empty = manager.domain_dispatcher._normalize_child_result(
        child,
        {
            "success": True,
            "data": "not-a-row-list",
            "columns": "not-a-column-list",
            "metadata": {"columns": "also-invalid"},
        },
        {},
        (),
    )
    derived = manager.domain_dispatcher._normalize_child_result(
        child,
        {
            "success": True,
            "data": [{"answer": 1}, 2],
            "columns": None,
        },
        {},
        (),
    )

    assert empty["data"] == {
        "columns": [],
        "rows": [],
        "row_count": 0,
        "truncated": False,
    }
    assert derived["data"]["columns"] == [{"name": "answer"}]
    assert derived["data"]["rows"] == [
        {"answer": 1},
        {"value": 2},
    ]


def test_detail_result_normalization_adds_formal_evidence() -> None:
    manager = _manager()
    child = DORIS_DOMAIN_CATALOG.resolve_child(
        "doris_query",
        "explain_query",
    )

    result = manager.domain_dispatcher._normalize_child_result(
        child,
        {"success": True, "result": "SCAN"},
        {},
        ("adapter warning",),
    )

    assert result["status"] == "partial"
    assert result["data"] == {"value": "SCAN"}
    assert result["evidence"] == [
        {
            "source": "existing_read_only_handler",
            "handler": "child:doris_query:explain_query",
        }
    ]


@pytest.mark.parametrize(
    ("adapter", "arguments", "expected", "warning_count"),
    [
        (
            "adapt:catalog_object_names",
            {
                "catalog": "internal",
                "database": "db",
                "pattern": "*",
                "types": ["table"],
                "page": "cursor",
            },
            {
                "catalog_name": "internal",
                "db_name": "db",
                "_formal_catalog": True,
            },
            0,
        ),
        (
            "adapt:remove_random_string",
            {"include_external": True},
            {"_formal_catalog": True},
            0,
        ),
        (
            "adapt:explain_arguments",
            {"sql": "SELECT 1", "level": "verbose"},
            {"sql": "SELECT 1", "verbose": True},
            0,
        ),
        (
            "adapt:table_size_arguments",
            {
                "database": "db",
                "table": "t",
                "include_partitions": True,
            },
            {
                "db_name": "db",
                "table_name": "t",
                "include_partitions": True,
                "single_replica": False,
                "_formal_catalog": True,
            },
            0,
        ),
        (
            "adapt:monitoring_arguments",
            {"metric_names": ["qps"]},
            {},
            1,
        ),
        (
            "adapt:memory_arguments",
            {"detail": "trackers", "node_ids": ["be-1"]},
            {"data_type": "realtime", "tracker_type": "all"},
            1,
        ),
        (
            "adapt:audit_filters",
            {
                "window_minutes": 1500,
                "user": "alice",
                "limit": 5,
            },
            {"days": 2, "limit": 5},
            1,
        ),
        (
            "adapt:column_analysis_arguments",
            {
                "database": "db",
                "table": "t",
                "columns": ["id"],
                "sample_ratio": 0.25,
            },
            {
                "db_name": "db",
                "table_name": "t",
                "columns": ["id"],
                "sample_size": 25000,
            },
            0,
        ),
        (
            "adapt:storage_analysis_arguments",
            {
                "database": "db",
                "table": "t",
                "include_indexes": True,
            },
            {
                "db_name": "db",
                "table_name": "t",
                "detailed_response": True,
            },
            0,
        ),
        (
            "adapt:lineage_arguments",
            {
                "object": "db.orders",
                "column": "customer_id",
                "depth": 2,
                "direction": "both",
                "evidence_mode": "auto",
            },
            {
                "target_columns": ["db.orders.customer_id"],
                "analysis_depth": 2,
            },
            0,
        ),
        (
            "adapt:freshness_arguments",
            {
                "database": "db",
                "table": "orders",
                "threshold_seconds": 3601,
                "time_column": "updated_at",
            },
            {
                "db_name": "db",
                "table_names": ["orders"],
                "freshness_threshold_hours": 2,
            },
            1,
        ),
        (
            "adapt:access_analysis_arguments",
            {
                "database": "db",
                "window_days": 3,
                "group_by": "user",
            },
            {"days": 3},
            1,
        ),
        (
            "adapt:dependency_arguments",
            {
                "catalog": "internal",
                "database": "db",
                "object": "orders",
                "depth": 4,
                "direction": "upstream",
            },
            {
                "catalog_name": "internal",
                "db_name": "db",
                "target_table": "orders",
                "analysis_depth": 4,
            },
            0,
        ),
        (
            "adapt:slow_query_arguments",
            {
                "window_minutes": 60,
                "limit": 8,
                "min_duration_ms": 500,
                "database": "db",
            },
            {
                "days": 1,
                "top_n": 8,
                "min_execution_time_ms": 500,
                "db_name": "db",
            },
            0,
        ),
        (
            "adapt:resource_growth_arguments",
            {
                "resource": "memory",
                "window_days": 9,
                "granularity": "day",
            },
            {
                "days": 9,
                "resource_types": ["memory"],
            },
            1,
        ),
        (
            "adapt:adbc_query_arguments",
            {
                "sql": "SELECT 1",
                "timeout_ms": 1001,
                "result_format": "dict",
            },
            {
                "sql": "SELECT 1",
                "timeout": 2,
                "return_format": "dict",
            },
            0,
        ),
    ],
)
def test_argument_adapters_are_deterministic(
    adapter: str,
    arguments: dict[str, Any],
    expected: dict[str, Any],
    warning_count: int,
) -> None:
    original = dict(arguments)

    prepared, warnings = _adapt_arguments(adapter, arguments)

    assert prepared == expected
    assert len(warnings) == warning_count
    assert arguments == original


def test_argument_adapter_identity_and_unknown_adapter() -> None:
    arguments = {"value": 1}

    assert _adapt_arguments(None, arguments) == (arguments, ())
    with pytest.raises(ChildArgumentsAdapterError, match="unknown"):
        _adapt_arguments("adapt:missing", arguments)


def test_legacy_result_helpers_do_not_mutate_values() -> None:
    success = {
        "success": True,
        "result": ["a"],
        "metadata": {"columns": ["name"]},
    }
    direct = {"success": True, "value": 1, "_execution_info": {"x": 1}}

    assert _unwrap_legacy_result(success) == ["a"]
    assert _unwrap_legacy_result(direct) == {"value": 1}
    assert _legacy_metadata(success) == {"columns": ["name"]}
    assert _legacy_metadata({"metadata": "invalid"}) == {}
    assert _as_object({"x": 1}) == {"x": 1}
    assert _as_object([1]) == {"items": [1]}
    assert _as_object("value") == {"value": "value"}


def test_dispatch_result_serialization_supports_models_and_plain_values() -> None:
    error = DomainDispatcher._error(
        "doris_query",
        DomainErrorCode.CHILD_TOOL_NOT_FOUND,
        "Child tool was not found.",
    )

    assert json.loads(serialize_dispatch_result(error))["mode"] == "error"
    assert serialize_dispatch_result({"ok": True}) == '{"ok":true}'


def cast_mapping(value: Any) -> Mapping[str, Any]:
    assert isinstance(value, Mapping)
    return value
