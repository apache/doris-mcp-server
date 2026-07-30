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

"""Exact 1.0 child dispatch tests for the packaged Python client."""

from unittest.mock import AsyncMock, Mock, call

import pytest
from mcp.types import Tool

from doris_mcp_client.client import (
    DorisClientConfig,
    DorisToolsClient,
    DorisUnifiedClient,
)


def _tool(name: str) -> Tool:
    return Tool(
        name=name,
        description=name,
        input_schema={
            "type": "object",
            "properties": {},
        },
    )


@pytest.mark.asyncio
async def test_tools_client_discovers_then_calls_exact_hierarchical_child() -> None:
    client = DorisToolsClient(Mock())
    client.list_tools = AsyncMock(return_value=[_tool("doris_query")])
    client.call_tool = AsyncMock(
        side_effect=[
            {
                "mode": "manifest",
                "manifest_version": "query.v1",
                "children": [{"name": "execute_query"}],
            },
            {
                "mode": "result",
                "domain": "doris_query",
                "child_tool": "execute_query",
            },
        ]
    )

    result = await client.call_child(
        "doris_query",
        "execute_query",
        {"sql": "SELECT 1"},
    )

    assert result["mode"] == "result"
    assert client.call_tool.await_args_list == [
        call("doris_query", {}),
        call(
            "doris_query",
            {
                "child_tool": "execute_query",
                "arguments": {"sql": "SELECT 1"},
                "manifest_version": "query.v1",
            },
        ),
    ]


@pytest.mark.asyncio
async def test_tools_client_calls_exact_formal_flat_child() -> None:
    client = DorisToolsClient(Mock())
    client.list_tools = AsyncMock(
        return_value=[_tool("doris_query_execute_query")]
    )
    client.call_tool = AsyncMock(return_value={"mode": "result"})

    result = await client.call_child(
        "doris_query",
        "execute_query",
        {"sql": "SELECT 1"},
    )

    assert result == {"mode": "result"}
    client.call_tool.assert_awaited_once_with(
        "doris_query_execute_query",
        {"sql": "SELECT 1"},
    )


@pytest.mark.asyncio
async def test_tools_client_never_guesses_missing_child_or_legacy_name() -> None:
    client = DorisToolsClient(Mock())
    client.list_tools = AsyncMock(return_value=[_tool("doris_query")])
    client.call_tool = AsyncMock(
        return_value={
            "mode": "manifest",
            "manifest_version": "query.v1",
            "children": [{"name": "explain_query"}],
        }
    )

    result = await client.call_child(
        "doris_query",
        "execute_quer",
        {"sql": "SELECT 1"},
    )

    assert result["error_code"] == "CHILD_TOOL_NOT_FOUND"
    assert result["child_tool"] == "execute_quer"
    client.call_tool.assert_awaited_once_with("doris_query", {})


@pytest.mark.asyncio
async def test_unified_client_helpers_use_only_formal_domain_children() -> None:
    client = DorisUnifiedClient(DorisClientConfig())
    client.tools = Mock()
    client.tools.call_child = AsyncMock(return_value={"mode": "result"})

    await client.execute_sql("SELECT 1", max_rows=5)
    await client.get_table_schema(
        "orders",
        "analytics",
        catalog="internal",
    )
    await client.get_database_list(catalog="internal")
    await client.get_memory_stats(
        detail="trackers",
        node_ids=["be-1"],
    )

    assert client.tools.call_child.await_args_list == [
        call(
            "doris_query",
            "execute_query",
            {"sql": "SELECT 1", "max_rows": 5},
        ),
        call(
            "doris_catalog",
            "get_table_context",
            {
                "table": "orders",
                "sections": ["schema"],
                "database": "analytics",
                "catalog": "internal",
            },
        ),
        call(
            "doris_catalog",
            "list_databases",
            {"catalog": "internal"},
        ),
        call(
            "doris_cluster",
            "get_memory_stats",
            {
                "detail": "trackers",
                "node_ids": ["be-1"],
            },
        ),
    ]
