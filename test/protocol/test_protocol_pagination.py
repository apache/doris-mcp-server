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
"""Explicit, permission-bound pagination handles for MCP list operations."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx2
import pytest
from mcp import Client, MCPError, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import (
    INVALID_PARAMS,
    LATEST_PROTOCOL_VERSION,
    PaginatedRequestParams,
    Tool,
)

from doris_mcp_server.http_transport import DorisMCPHTTPTransport
from doris_mcp_server.utils.security import (
    AuthContext,
    reset_auth_context,
    set_current_auth_context,
)
from test.protocol.pagination_fixture import (
    PROMPT_NAMES,
    RESOURCE_URIS,
    TOOL_NAMES,
    create_pagination_server,
)


async def _collect_pages(
    list_method,
    *,
    result_field: str,
    item_key,
) -> tuple[list[str], int]:
    cursor = None
    seen_cursors: set[str] = set()
    identifiers: list[str] = []
    page_count = 0

    while True:
        result = await list_method(cursor=cursor, cache_mode="bypass")
        page_count += 1
        page = getattr(result, result_field)
        assert 0 < len(page) <= 2
        identifiers.extend(item_key(item) for item in page)

        cursor = result.next_cursor
        if cursor is None:
            break
        assert cursor not in seen_cursors
        seen_cursors.add(cursor)

    return identifiers, page_count


async def _assert_all_lists_are_complete(client: Client) -> None:
    resource_uris, resource_pages = await _collect_pages(
        client.list_resources,
        result_field="resources",
        item_key=lambda resource: str(resource.uri),
    )
    tool_names, tool_pages = await _collect_pages(
        client.list_tools,
        result_field="tools",
        item_key=lambda tool: tool.name,
    )
    prompt_names, prompt_pages = await _collect_pages(
        client.list_prompts,
        result_field="prompts",
        item_key=lambda prompt: prompt.name,
    )

    assert resource_uris == RESOURCE_URIS
    assert tool_names == TOOL_NAMES
    assert prompt_names == PROMPT_NAMES
    assert len(resource_uris) == len(set(resource_uris))
    assert len(tool_names) == len(set(tool_names))
    assert len(prompt_names) == len(set(prompt_names))
    assert (resource_pages, tool_pages, prompt_pages) == (3, 3, 3)


@pytest.mark.parametrize("mode", ["modern", "legacy"])
@pytest.mark.asyncio
async def test_all_list_operations_page_without_duplicates_or_loss(mode: str):
    server, _ = create_pagination_server()
    client_context = (
        Client(server) if mode == "modern" else Client(server, mode="legacy")
    )

    async with client_context as client:
        await _assert_all_lists_are_complete(client)


@pytest.mark.asyncio
async def test_streamable_http_carries_opaque_cursor_across_all_list_methods():
    server, _ = create_pagination_server()
    app = DorisMCPHTTPTransport(app=server, security_settings=None)

    async with (
        app.run(),
        httpx2.ASGITransport(app.handle_request) as transport,
        httpx2.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:3000",
        ) as client,
    ):
        for method, result_field, item_key, expected in (
            (
                "resources/list",
                "resources",
                lambda item: item["uri"],
                RESOURCE_URIS,
            ),
            ("tools/list", "tools", lambda item: item["name"], TOOL_NAMES),
            ("prompts/list", "prompts", lambda item: item["name"], PROMPT_NAMES),
        ):
            cursor = None
            identifiers: list[str] = []
            while True:
                params: dict[str, Any] = {
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                        "io.modelcontextprotocol/clientCapabilities": {},
                        "io.modelcontextprotocol/clientInfo": {
                            "name": "pagination-http-test",
                            "version": "1.0.0",
                        },
                    }
                }
                if cursor is not None:
                    params["cursor"] = cursor
                response = await client.post(
                    "/mcp",
                    json={
                        "jsonrpc": "2.0",
                        "id": len(identifiers) + 1,
                        "method": method,
                        "params": params,
                    },
                    headers={
                        "Accept": "application/json, text/event-stream",
                        "Content-Type": "application/json",
                        "Mcp-Protocol-Version": "2026-07-28",
                        "Mcp-Method": method,
                    },
                )
                assert response.status_code == 200
                assert "mcp-session-id" not in response.headers
                result = response.json()["result"]
                identifiers.extend(item_key(item) for item in result[result_field])
                cursor = result.get("nextCursor")
                if cursor is None:
                    break

            assert identifiers == expected


@pytest.mark.asyncio
async def test_true_subprocess_stdio_pages_all_list_methods():
    project_root = Path(__file__).resolve().parents[2]
    server_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "test.protocol.pagination_stdio_server"],
        cwd=project_root,
    )

    async with Client(stdio_client(server_params)) as client:
        await _assert_all_lists_are_complete(client)


@pytest.mark.asyncio
async def test_cursor_rejects_wrong_collection_malformed_and_stale_snapshots():
    server, managers = create_pagination_server()

    async with Client(server) as client:
        first_tools = await client.list_tools(cache_mode="bypass")
        assert first_tools.next_cursor is not None

        with pytest.raises(MCPError) as wrong_collection:
            await client.list_resources(
                cursor=first_tools.next_cursor,
                cache_mode="bypass",
            )
        assert wrong_collection.value.code == INVALID_PARAMS
        assert wrong_collection.value.data == {"cursorError": "wrong_collection"}

        with pytest.raises(MCPError) as malformed:
            await client.list_tools(
                cursor="not-a-valid-pagination-cursor",
                cache_mode="bypass",
            )
        assert malformed.value.code == INVALID_PARAMS
        assert malformed.value.data == {"cursorError": "invalid"}

        tampered_parts = first_tools.next_cursor.split(".")
        tampered_parts[1] = (
            "A" if tampered_parts[1][0] != "A" else "B"
        ) + tampered_parts[1][1:]
        with pytest.raises(MCPError) as tampered:
            await client.list_tools(
                cursor=".".join(tampered_parts),
                cache_mode="bypass",
            )
        assert tampered.value.code == INVALID_PARAMS
        assert tampered.value.data == {"cursorError": "invalid"}

        managers.tools.tools.append(
            Tool(
                name="foxtrot",
                description="new item invalidates the snapshot",
                input_schema={"type": "object", "properties": {}},
            )
        )
        with pytest.raises(MCPError) as stale:
            await client.list_tools(
                cursor=first_tools.next_cursor,
                cache_mode="bypass",
            )
        assert stale.value.code == INVALID_PARAMS
        assert stale.value.data == {"cursorError": "stale"}


@pytest.mark.asyncio
async def test_cursor_is_bound_to_the_authorization_context():
    server, _ = create_pagination_server(page_size=1)
    entry = server.get_request_handler("tools/list")
    assert entry is not None
    context = SimpleNamespace(protocol_version=LATEST_PROTOCOL_VERSION)

    first_context = AuthContext(
        token_id="token-a",
        user_id="user-a",
        permissions=["tool:list"],
        roles=["analyst"],
        auth_method="token",
    )
    token = set_current_auth_context(first_context)
    try:
        first_page = await entry.handler(context, PaginatedRequestParams())
    finally:
        reset_auth_context(token)
    assert first_page.next_cursor is not None

    second_context = AuthContext(
        token_id="token-b",
        user_id="user-b",
        permissions=["tool:list"],
        roles=["analyst"],
        auth_method="token",
    )
    token = set_current_auth_context(second_context)
    try:
        with pytest.raises(MCPError) as changed_context:
            await entry.handler(
                context,
                PaginatedRequestParams(cursor=first_page.next_cursor),
            )
    finally:
        reset_auth_context(token)

    assert changed_context.value.code == INVALID_PARAMS
    assert changed_context.value.data == {
        "cursorError": "authorization_context_changed"
    }


@pytest.mark.asyncio
async def test_cursor_crosses_server_instances_with_shared_secret_not_session():
    secret = "pagination-shared-state-handle-secret-value"
    first_server, _ = create_pagination_server(
        page_size=1,
        state_handle_secret=secret,
    )
    second_server, _ = create_pagination_server(
        page_size=1,
        state_handle_secret=secret,
    )
    first_entry = first_server.get_request_handler("tools/list")
    second_entry = second_server.get_request_handler("tools/list")
    assert first_entry is not None
    assert second_entry is not None
    context = SimpleNamespace(protocol_version=LATEST_PROTOCOL_VERSION)

    first_request = AuthContext(
        token_id="token-a",
        user_id="user-a",
        permissions=["tool:list"],
        roles=["analyst"],
        auth_method="token",
        session_id="transport-session-one",
    )
    token = set_current_auth_context(first_request)
    try:
        first_page = await first_entry.handler(context, PaginatedRequestParams())
    finally:
        reset_auth_context(token)
    assert first_page.next_cursor is not None

    second_request = AuthContext(
        token_id="token-a",
        user_id="user-a",
        permissions=["tool:list"],
        roles=["analyst"],
        auth_method="token",
        session_id="transport-session-two",
    )
    token = set_current_auth_context(second_request)
    try:
        second_page = await second_entry.handler(
            context,
            PaginatedRequestParams(cursor=first_page.next_cursor),
        )
    finally:
        reset_auth_context(token)

    assert [tool.name for tool in first_page.tools] == ["alpha"]
    assert [tool.name for tool in second_page.tools] == ["bravo"]
