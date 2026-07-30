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
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""Contract tests for the single Doris MCP tool definition registry."""

from __future__ import annotations

import inspect
from unittest.mock import AsyncMock, Mock, patch

import pytest
from mcp.types import Tool

from doris_mcp_server.schema_validation import ToolSchemaGuard
from doris_mcp_server.tools.domain_dispatcher import ToolNotFoundError
from doris_mcp_server.tools.tool_catalog import build_tool_registry
from doris_mcp_server.tools.tool_registry import (
    DORIS_OAUTH_EXPLAIN_TOOL_SET,
    DORIS_OAUTH_METADATA_TOOL_SET,
    DORIS_OAUTH_QUERY_TOOL_SET,
    LEGACY_TOOL_ALIAS_NAMES,
    RESTRICTED_TOOL_NAMES,
    ToolDefinitionRegistry,
    ToolRegistryError,
    policy_definition_for_tool,
)
from doris_mcp_server.tools.tools_manager import DorisToolsManager


@pytest.fixture
def tools_manager() -> DorisToolsManager:
    connection_manager = Mock()
    connection_manager.config.adbc.default_max_rows = 1000
    connection_manager.config.adbc.default_timeout = 30
    connection_manager.config.adbc.default_return_format = "dict"
    return DorisToolsManager(connection_manager)


def _migration_registry(
    tools_manager: DorisToolsManager,
) -> ToolDefinitionRegistry:
    return build_tool_registry(
        tools_manager,
        tools_manager.connection_manager.config,
    )


def test_registry_is_the_complete_schema_policy_handler_and_audit_source(
    tools_manager: DorisToolsManager,
) -> None:
    registry = _migration_registry(tools_manager)
    advertised = registry.advertised_definitions

    assert len(advertised) == 25
    assert len(registry.definitions) == 25 + len(LEGACY_TOOL_ALIAS_NAMES)
    assert len(registry.advertised_names) == len(set(registry.advertised_names))

    ToolSchemaGuard().compile_catalog(registry.listed_tools())
    for definition in registry.definitions:
        assert definition.bind_handler(tools_manager)
        assert definition.audit.event_name == (
            f"mcp.tool.call.{definition.name}"
        )
        assert definition.policy == policy_definition_for_tool(definition.name)
        if definition.tool is not None:
            properties = definition.tool.input_schema.get("properties", {})
            assert set(definition.audit.argument_names) == set(properties)


def test_registry_policy_classes_cover_every_executable_tool(
    tools_manager: DorisToolsManager,
) -> None:
    registry = _migration_registry(tools_manager)
    names_by_policy = {
        policy_class: {
            definition.name
            for definition in registry.definitions
            if definition.policy.policy_class == policy_class
        }
        for policy_class in ("metadata", "query", "explain", "restricted")
    }

    assert names_by_policy["metadata"] == DORIS_OAUTH_METADATA_TOOL_SET
    assert names_by_policy["query"] == DORIS_OAUTH_QUERY_TOOL_SET
    assert names_by_policy["explain"] == DORIS_OAUTH_EXPLAIN_TOOL_SET
    assert names_by_policy["restricted"] == RESTRICTED_TOOL_NAMES


@pytest.mark.asyncio
async def test_migration_registry_is_not_a_runtime_dispatch_source(
    tools_manager: DorisToolsManager,
) -> None:
    sql = "SELECT 'registry-secret-value'"
    tools_manager._exec_query_tool = AsyncMock(return_value={"ok": True})
    audit_logger = Mock()

    with patch(
        "doris_mcp_server.tools.tools_manager.get_audit_logger",
        return_value=audit_logger,
    ):
        with pytest.raises(ToolNotFoundError):
            await tools_manager.call_tool("exec_query", {"sql": sql})

    tools_manager._exec_query_tool.assert_not_awaited()
    audit_logger.info.assert_not_called()
    assert sql not in repr(audit_logger.info.call_args)
    assert _migration_registry(tools_manager).resolve(
        "exec_query"
    ).audit.sensitive_arguments == ("sql",)


@pytest.mark.asyncio
async def test_legacy_alias_uses_registry_override_without_mutating_input(
    tools_manager: DorisToolsManager,
) -> None:
    tools_manager._get_monitoring_metrics_tool = AsyncMock(
        return_value={"ok": True}
    )
    arguments = {"role": "fe"}

    registry = _migration_registry(tools_manager)
    definition = registry.resolve("get_monitoring_metrics_info")
    prepared = definition.prepare_arguments(arguments)

    assert arguments == {"role": "fe"}
    assert prepared == {"role": "fe", "content_type": "definitions"}
    assert definition.canonical_name == (
        "get_monitoring_metrics"
    )
    assert "get_monitoring_metrics_info" not in (
        registry.advertised_names
    )
    with pytest.raises(ToolNotFoundError):
        await tools_manager.call_tool(
            "get_monitoring_metrics_info",
            arguments,
        )
    tools_manager._get_monitoring_metrics_tool.assert_not_awaited()


def test_registry_rejects_duplicate_unknown_and_missing_handler_definitions(
    tools_manager: DorisToolsManager,
) -> None:
    tool = Tool(
        name="exec_query",
        description="Execute a query",
        input_schema={
            "type": "object",
            "properties": {"sql": {"type": "string"}},
            "required": ["sql"],
        },
    )

    with pytest.raises(ToolRegistryError, match="Duplicate tool schema"):
        ToolDefinitionRegistry.from_tools([tool, tool], Mock())

    with pytest.raises(ToolRegistryError, match="has no policy definition"):
        ToolDefinitionRegistry.from_tools(
            [
                Tool(
                    name="unclassified_tool",
                    description="Unclassified",
                    input_schema={"type": "object", "properties": {}},
                )
            ],
            Mock(),
        )

    with pytest.raises(ToolRegistryError, match="missing handler"):
        ToolDefinitionRegistry.from_tools(
            _migration_registry(tools_manager).listed_tools(),
            object(),
        )


def test_internal_migration_registry_rendering_is_deterministic(
    tools_manager: DorisToolsManager,
) -> None:
    registry = _migration_registry(tools_manager)
    first = registry.render_markdown()
    second = registry.render_markdown()

    assert first == second
    assert first.startswith("# Doris MCP Tool Registry")


def test_tools_manager_has_no_parallel_decorator_or_dispatch_registry() -> None:
    source = inspect.getsource(DorisToolsManager)

    assert "register_tools_with_mcp" not in source
    assert "@mcp.tool" not in source
    assert 'elif name == "' not in source
