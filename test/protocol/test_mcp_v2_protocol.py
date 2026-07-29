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

import json
import logging
import sys
from pathlib import Path

import httpx2
import pytest
from mcp import Client, ClientSession, MCPError, StdioServerParameters
from mcp.client import advertise
from mcp.client.stdio import stdio_client
from mcp.types import (
    ClientCapabilities,
    GetPromptResult,
    Prompt,
    PromptMessage,
    Resource,
    TextContent,
    Tool,
)

from doris_mcp_server.protocol import (
    create_doris_mcp_server,
    create_transport_security,
)

REQUIRED_EXTENSION = "io.apache.doris/read"


class StubResourcesManager:
    async def list_resources(self) -> list[Resource]:
        return [
            Resource(
                uri="doris://table/orders",
                name="orders",
                mime_type="application/json",
            )
        ]

    async def read_resource(self, uri: str) -> str:
        return json.dumps({"uri": uri, "columns": 3})


class StubToolsManager:
    async def list_tools(self) -> list[Tool]:
        return [
            Tool(
                name="echo",
                description="Echo structured input.",
                input_schema={
                    "type": "object",
                    "properties": {"value": {"type": "string"}},
                    "required": ["value"],
                },
            ),
            Tool(
                name="fail",
                description="Return a model-readable tool error.",
                input_schema={"type": "object", "properties": {}},
            ),
        ]

    async def call_tool(self, name: str, arguments: dict) -> str:
        if name == "fail":
            return json.dumps({"error": "expected failure"})
        return json.dumps({"name": name, "arguments": arguments})


class StubPromptsManager:
    async def list_prompts(self) -> list[Prompt]:
        return [Prompt(name="explain", description="Explain a query.")]

    async def get_prompt(self, name: str, arguments: dict) -> GetPromptResult:
        return GetPromptResult(
            description=name,
            messages=[
                PromptMessage(
                    role="user",
                    content=TextContent(
                        type="text",
                        text=f"Explain {arguments.get('sql', '')}",
                    ),
                )
            ],
        )


def create_test_server(
    required_client_capabilities: dict[str, ClientCapabilities] | None = None,
):
    return create_doris_mcp_server(
        resources_manager=StubResourcesManager(),
        tools_manager=StubToolsManager(),
        prompts_manager=StubPromptsManager(),
        name="doris-mcp-server",
        version="0.6.1",
        logger=logging.getLogger(__name__),
        required_client_capabilities=required_client_capabilities,
    )


@pytest.mark.asyncio
async def test_modern_and_legacy_clients_share_the_v2_protocol_core():
    server = create_test_server()

    async with Client(server) as modern:
        assert modern.protocol_version == "2026-07-28"
        assert modern.server_info is not None
        assert modern.server_info.name == "doris-mcp-server"
        assert modern.server_info.version == "0.6.1"
        assert modern.session.discover_result is not None
        assert modern.session.discover_result.result_type == "complete"

        tools_result = await modern.list_tools(cache_mode="bypass")
        assert [tool.name for tool in tools_result.tools] == ["echo", "fail"]
        assert tools_result.result_type == "complete"
        assert tools_result.ttl_ms == 0
        assert tools_result.cache_scope == "private"

        resources_result = await modern.list_resources(cache_mode="bypass")
        assert [resource.name for resource in resources_result.resources] == ["orders"]
        assert resources_result.result_type == "complete"
        assert resources_result.ttl_ms == 0
        assert resources_result.cache_scope == "private"

        prompts_result = await modern.list_prompts(cache_mode="bypass")
        assert [prompt.name for prompt in prompts_result.prompts] == ["explain"]
        assert prompts_result.result_type == "complete"
        assert prompts_result.ttl_ms == 0
        assert prompts_result.cache_scope == "private"

        tool_result = await modern.call_tool("echo", {"value": "hello"})
        assert tool_result.result_type == "complete"
        assert tool_result.is_error is False
        assert tool_result.structured_content == {
            "name": "echo",
            "arguments": {"value": "hello"},
        }

        error_result = await modern.call_tool("fail", {})
        assert error_result.is_error is True
        assert error_result.structured_content == {"error": "expected failure"}

        resource_result = await modern.read_resource(
            "doris://table/orders",
            cache_mode="bypass",
        )
        assert resource_result.result_type == "complete"
        assert resource_result.cache_scope == "private"
        assert resource_result.contents[0].uri == "doris://table/orders"

        prompt_result = await modern.get_prompt("explain", {"sql": "SELECT 1"})
        assert prompt_result.result_type == "complete"
        assert prompt_result.messages[0].content.text == "Explain SELECT 1"

    async with Client(server, mode="legacy") as legacy:
        assert legacy.protocol_version == "2025-11-25"
        assert [tool.name for tool in (await legacy.list_tools()).tools] == [
            "echo",
            "fail",
        ]


def modern_request(request_id: int, method: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {
                    "name": "doris-mcp-test",
                    "version": "1.0.0",
                },
            }
        },
    }


def modern_headers(method: str) -> dict[str, str]:
    return {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "Mcp-Protocol-Version": "2026-07-28",
        "Mcp-Method": method,
    }


@pytest.mark.asyncio
async def test_http_discover_is_stateless_and_unknown_method_does_not_kill_server():
    app = create_test_server().streamable_http_app(
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
        first = await client.post(
            "/mcp",
            json=modern_request(1, "server/discover"),
            headers=modern_headers("server/discover"),
        )
        assert first.status_code == 200
        assert "mcp-session-id" not in first.headers
        assert first.json()["result"]["supportedVersions"] == ["2026-07-28"]

        unknown = await client.post(
            "/mcp",
            json=modern_request(2, "vendor/unknown"),
            headers=modern_headers("vendor/unknown"),
        )
        assert unknown.status_code == 404
        assert unknown.json()["error"]["code"] == -32601

        malformed = await client.post(
            "/mcp",
            content=b"{",
            headers=modern_headers("server/discover"),
        )
        assert malformed.status_code == 400
        assert malformed.json()["error"]["code"] == -32700

        mismatched_header = await client.post(
            "/mcp",
            json=modern_request(3, "server/discover"),
            headers=modern_headers("tools/list"),
        )
        assert mismatched_header.status_code == 400
        assert mismatched_header.json()["error"]["code"] == -32020

        unsupported_request = modern_request(4, "server/discover")
        unsupported_request["params"]["_meta"][
            "io.modelcontextprotocol/protocolVersion"
        ] = "2099-01-01"
        unsupported_headers = modern_headers("server/discover")
        unsupported_headers["Mcp-Protocol-Version"] = "2099-01-01"
        unsupported_version = await client.post(
            "/mcp",
            json=unsupported_request,
            headers=unsupported_headers,
        )
        assert unsupported_version.status_code == 400
        assert unsupported_version.json()["error"]["code"] == -32022

        second = await client.post(
            "/mcp",
            json=modern_request(5, "server/discover"),
            headers=modern_headers("server/discover"),
        )
        assert second.status_code == 200
        assert second.json()["result"]["resultType"] == "complete"


@pytest.mark.asyncio
async def test_http_rejects_untrusted_origin_and_legacy_is_stateless():
    app = create_test_server().streamable_http_app(
        json_response=True,
        stateless_http=True,
        host="127.0.0.1",
        transport_security=create_transport_security("127.0.0.1"),
    )
    legacy_initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "legacy-test", "version": "1.0.0"},
        },
    }
    legacy_headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }

    async with (
        app.router.lifespan_context(app),
        httpx2.ASGITransport(app) as transport,
        httpx2.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:3000",
        ) as client,
    ):
        rejected = await client.post(
            "/mcp",
            json=modern_request(1, "server/discover"),
            headers={
                **modern_headers("server/discover"),
                "Origin": "https://evil.example",
            },
        )
        assert rejected.status_code == 403

        rejected_host = await client.post(
            "/mcp",
            json=modern_request(2, "server/discover"),
            headers={
                **modern_headers("server/discover"),
                "Host": "evil.example",
            },
        )
        assert rejected_host.status_code == 421

        initialized = await client.post(
            "/mcp",
            json=legacy_initialize,
            headers=legacy_headers,
        )
        assert initialized.status_code == 200
        assert "mcp-session-id" not in initialized.headers
        assert initialized.json()["result"]["protocolVersion"] == "2025-11-25"


@pytest.mark.asyncio
async def test_http_validates_request_meta_and_required_client_capabilities():
    server = create_test_server(
        {
            "tools/list": ClientCapabilities(
                extensions={REQUIRED_EXTENSION: {}},
            )
        }
    )
    app = server.streamable_http_app(
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
        missing_meta = modern_request(1, "tools/list")
        del missing_meta["params"]["_meta"][
            "io.modelcontextprotocol/clientCapabilities"
        ]
        invalid = await client.post(
            "/mcp",
            json=missing_meta,
            headers=modern_headers("tools/list"),
        )
        assert invalid.status_code == 400
        assert invalid.json()["error"]["code"] == -32602

        missing_capability = await client.post(
            "/mcp",
            json=modern_request(2, "tools/list"),
            headers=modern_headers("tools/list"),
        )
        assert missing_capability.status_code == 400
        assert missing_capability.json()["error"]["code"] == -32021
        assert missing_capability.json()["error"]["data"] == {
            "requiredCapabilities": {
                "extensions": {
                    REQUIRED_EXTENSION: {},
                }
            }
        }

        capable_request = modern_request(3, "tools/list")
        capable_request["params"]["_meta"][
            "io.modelcontextprotocol/clientCapabilities"
        ] = {
            "extensions": {
                REQUIRED_EXTENSION: {},
            }
        }
        capable = await client.post(
            "/mcp",
            json=capable_request,
            headers=modern_headers("tools/list"),
        )
        assert capable.status_code == 200
        assert [tool["name"] for tool in capable.json()["result"]["tools"]] == [
            "echo",
            "fail",
        ]


@pytest.mark.asyncio
async def test_stdio_validates_capabilities_versions_and_process_survival():
    server_script = Path(__file__).with_name("stdio_capability_server.py")
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[str(server_script)],
    )

    async with stdio_client(server_params) as streams:
        async with ClientSession(*streams) as raw_session:
            with pytest.raises(MCPError) as unsupported:
                await raw_session.send_discover("2099-01-01")
            assert unsupported.value.code == -32022
            assert unsupported.value.data == {
                "supported": ["2026-07-28"],
                "requested": "2099-01-01",
            }

            recovered = await raw_session.send_discover("2026-07-28")
            assert recovered["resultType"] == "complete"

    async with Client(stdio_client(server_params)) as missing:
        with pytest.raises(MCPError) as missing_capability:
            await missing.list_tools(cache_mode="bypass")
        assert missing_capability.value.code == -32021
        assert (await missing.list_resources(cache_mode="bypass")).resources == []

    async with Client(
        stdio_client(server_params),
        extensions=[advertise(REQUIRED_EXTENSION)],
    ) as capable:
        assert [tool.name for tool in (await capable.list_tools()).tools] == [
            "echo"
        ]

    async with Client(stdio_client(server_params), mode="legacy") as legacy:
        assert [tool.name for tool in (await legacy.list_tools()).tools] == ["echo"]
