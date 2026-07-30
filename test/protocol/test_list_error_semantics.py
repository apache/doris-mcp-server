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
"""Contract tests that distinguish list failures from successful empty lists."""

from __future__ import annotations

import sys
from pathlib import Path

import httpx2
import pytest
from mcp import Client, MCPError, StdioServerParameters
from mcp.client.stdio import stdio_client

from doris_mcp_server.protocol import create_transport_security
from test.protocol.list_error_semantics_server import (
    SENSITIVE_MARKER,
    create_list_error_semantics_server,
)


def _modern_request(request_id: int, method: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {
                    "name": "list-error-semantics-test",
                    "version": "1.0.0",
                },
            }
        },
    }


def _modern_headers(method: str) -> dict[str, str]:
    return {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "Mcp-Protocol-Version": "2026-07-28",
        "Mcp-Method": method,
    }


def _assert_list_error(
    error: MCPError,
    *,
    operation: str,
    category: str,
    message: str,
    error_code: str | None = None,
) -> None:
    assert error.code == -32603
    assert error.message == message
    expected = {
        "operation": operation,
        "listErrorCategory": category,
    }
    if error_code is not None:
        expected["listErrorCode"] = error_code
    assert error.data == expected
    assert SENSITIVE_MARKER not in repr(error)


async def _exercise_stdio_list_contract(client: Client) -> None:
    with pytest.raises(MCPError) as backend:
        await client.list_resources(cache_mode="bypass")
    _assert_list_error(
        backend.value,
        operation="resources/list",
        category="backend_unavailable",
        message="List backend unavailable",
        error_code="DORIS_METADATA_BACKEND_ERROR",
    )

    with pytest.raises(MCPError) as permission:
        await client.list_resources(cache_mode="bypass")
    _assert_list_error(
        permission.value,
        operation="resources/list",
        category="permission_denied",
        message="List operation permission denied",
        error_code="DORIS_METADATA_PERMISSION_DENIED",
    )
    assert (await client.list_resources(cache_mode="bypass")).resources == []

    with pytest.raises(MCPError) as tools_failure:
        await client.list_tools(cache_mode="bypass")
    _assert_list_error(
        tools_failure.value,
        operation="tools/list",
        category="internal_error",
        message="Internal server error",
    )
    assert (await client.list_tools(cache_mode="bypass")).tools == []

    with pytest.raises(MCPError) as prompts_failure:
        await client.list_prompts(cache_mode="bypass")
    _assert_list_error(
        prompts_failure.value,
        operation="prompts/list",
        category="internal_error",
        message="Internal server error",
    )
    assert (await client.list_prompts(cache_mode="bypass")).prompts == []


@pytest.mark.asyncio
async def test_streamable_http_list_failures_are_not_successful_empty_lists():
    app = create_list_error_semantics_server().streamable_http_app(
        json_response=True,
        stateless_http=True,
        host="127.0.0.1",
        transport_security=create_transport_security("127.0.0.1"),
    )

    async with (
        app.router.lifespan_context(app),
        httpx2.ASGITransport(app) as transport,
        httpx2.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:3000",
        ) as client,
    ):
        request_id = 0

        async def send(method: str):
            nonlocal request_id
            request_id += 1
            return await client.post(
                "/mcp",
                json=_modern_request(request_id, method),
                headers=_modern_headers(method),
            )

        backend = await send("resources/list")
        assert backend.status_code == 200
        assert backend.json()["error"] == {
            "code": -32603,
            "message": "List backend unavailable",
            "data": {
                "operation": "resources/list",
                "listErrorCategory": "backend_unavailable",
                "listErrorCode": "DORIS_METADATA_BACKEND_ERROR",
            },
        }
        assert SENSITIVE_MARKER not in backend.text

        permission = await send("resources/list")
        assert permission.status_code == 200
        assert permission.json()["error"] == {
            "code": -32603,
            "message": "List operation permission denied",
            "data": {
                "operation": "resources/list",
                "listErrorCategory": "permission_denied",
                "listErrorCode": "DORIS_METADATA_PERMISSION_DENIED",
            },
        }
        assert SENSITIVE_MARKER not in permission.text

        empty_resources = await send("resources/list")
        assert empty_resources.status_code == 200
        assert empty_resources.json()["result"]["resources"] == []

        internal_tools = await send("tools/list")
        assert internal_tools.status_code == 200
        assert internal_tools.json()["error"] == {
            "code": -32603,
            "message": "Internal server error",
            "data": {
                "operation": "tools/list",
                "listErrorCategory": "internal_error",
            },
        }
        assert SENSITIVE_MARKER not in internal_tools.text

        empty_tools = await send("tools/list")
        assert empty_tools.status_code == 200
        assert empty_tools.json()["result"]["tools"] == []

        internal_prompts = await send("prompts/list")
        assert internal_prompts.status_code == 200
        assert internal_prompts.json()["error"] == {
            "code": -32603,
            "message": "Internal server error",
            "data": {
                "operation": "prompts/list",
                "listErrorCategory": "internal_error",
            },
        }
        assert SENSITIVE_MARKER not in internal_prompts.text

        empty_prompts = await send("prompts/list")
        assert empty_prompts.status_code == 200
        assert empty_prompts.json()["result"]["prompts"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["2026-07-28", "legacy"])
async def test_true_subprocess_stdio_list_failures_recover_to_empty_lists(mode: str):
    server_script = Path(__file__).with_name("list_error_semantics_server.py")
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[str(server_script)],
    )

    async with Client(stdio_client(server_params), mode=mode) as client:
        await _exercise_stdio_list_contract(client)
