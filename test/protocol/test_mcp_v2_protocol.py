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
    SamplingCapability,
    TextContent,
    Tool,
)

from doris_mcp_server import __version__
from doris_mcp_server.protocol import (
    create_doris_mcp_server,
    create_transport_security,
)
from test.protocol.stdio_capability_server import OneToolManager as ProfileToolManager

REQUIRED_EXTENSION = "io.apache.doris/read"


async def _unused_sampling_callback(context, params):
    del context, params
    raise AssertionError("The capability fixture must not issue sampling requests")


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
        if uri == "doris://table/missing":
            return json.dumps(
                {
                    "error": "Failed to read resource: Table missing does not exist",
                    "error_code": "RESOURCE_NOT_FOUND",
                    "uri": uri,
                }
            )
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


class PromptFixtureError(Exception):
    def __init__(
        self,
        message: str,
        *,
        error_code: str,
        argument: str | None = None,
    ):
        super().__init__(message)
        self.error_code = error_code
        self.argument = argument


class StubPromptsManager:
    async def list_prompts(self) -> list[Prompt]:
        return [Prompt(name="explain", description="Explain a query.")]

    async def get_prompt(self, name: str, arguments: dict) -> GetPromptResult:
        if name == "missing":
            raise PromptFixtureError(
                "Prompt not found",
                error_code="UNKNOWN_PROMPT",
            )
        if name == "needs_argument" and "required" not in arguments:
            raise PromptFixtureError(
                "Missing required argument",
                error_code="MISSING_REQUIRED_ARGUMENT",
                argument="required",
            )
        if name == "database_failure":
            raise PromptFixtureError(
                "Database context failed",
                error_code="DATABASE_CONTEXT_UNAVAILABLE",
            )
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
    required_tool_capabilities: dict[str, ClientCapabilities] | None = None,
    tools_manager=None,
):
    return create_doris_mcp_server(
        resources_manager=StubResourcesManager(),
        tools_manager=tools_manager or StubToolsManager(),
        prompts_manager=StubPromptsManager(),
        name="doris-mcp-server",
        version=__version__,
        logger=logging.getLogger(__name__),
        required_client_capabilities=required_client_capabilities,
        required_tool_capabilities=required_tool_capabilities,
    )


@pytest.mark.asyncio
async def test_modern_and_legacy_clients_share_the_v2_protocol_core():
    server = create_test_server()

    async with Client(server) as modern:
        assert modern.protocol_version == "2026-07-28"
        assert modern.server_info is not None
        assert modern.server_info.name == "doris-mcp-server"
        assert modern.server_info.version == __version__
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
        assert legacy.server_info is not None
        assert legacy.server_info.name == "doris-mcp-server"
        assert legacy.server_info.version == __version__
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


def modern_resource_request(request_id: int, uri: str) -> dict:
    request = modern_request(request_id, "resources/read")
    request["params"]["uri"] = uri
    return request


def modern_resource_headers(uri: str) -> dict[str, str]:
    return {
        **modern_headers("resources/read"),
        "Mcp-Name": uri,
    }


def modern_prompt_request(
    request_id: int,
    name: str,
    arguments: dict | None = None,
) -> dict:
    request = modern_request(request_id, "prompts/get")
    request["params"].update(
        {
            "name": name,
            "arguments": arguments or {},
        }
    )
    return request


def modern_prompt_headers(name: str) -> dict[str, str]:
    return {
        **modern_headers("prompts/get"),
        "Mcp-Name": name,
    }


def modern_tool_request(
    request_id: int,
    name: str,
    arguments: dict | None = None,
) -> dict:
    request = modern_request(request_id, "tools/call")
    request["params"].update(
        {
            "name": name,
            "arguments": arguments or {},
        }
    )
    return request


def modern_tool_headers(name: str) -> dict[str, str]:
    return {
        **modern_headers("tools/call"),
        "Mcp-Name": name,
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
        discover_server_info = first.json()["result"]["_meta"][
            "io.modelcontextprotocol/serverInfo"
        ]
        assert discover_server_info["name"] == "doris-mcp-server"
        assert discover_server_info["version"] == __version__

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
        legacy_server_info = initialized.json()["result"]["serverInfo"]
        assert legacy_server_info["name"] == "doris-mcp-server"
        assert legacy_server_info["version"] == __version__


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
async def test_http_enforces_tool_specific_client_capabilities_and_recovers():
    server = create_test_server(
        required_tool_capabilities={
            "echo": ClientCapabilities(sampling=SamplingCapability()),
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
        missing = await client.post(
            "/mcp",
            json=modern_tool_request(1, "echo", {"value": "missing"}),
            headers=modern_tool_headers("echo"),
        )
        assert missing.status_code == 400
        assert missing.json()["error"] == {
            "code": -32021,
            "message": "Missing required client capability",
            "data": {"requiredCapabilities": {"sampling": {}}},
        }

        capable_request = modern_tool_request(2, "echo", {"value": "capable"})
        capable_request["params"]["_meta"][
            "io.modelcontextprotocol/clientCapabilities"
        ] = {"sampling": {}}
        capable = await client.post(
            "/mcp",
            json=capable_request,
            headers=modern_tool_headers("echo"),
        )
        assert capable.status_code == 200
        assert capable.json()["result"]["structuredContent"] == {
            "name": "echo",
            "arguments": {"value": "capable"},
        }

        recovered = await client.post(
            "/mcp",
            json=modern_tool_request(3, "fail"),
            headers=modern_tool_headers("fail"),
        )
        assert recovered.status_code == 200
        assert recovered.json()["result"]["isError"] is True


@pytest.mark.asyncio
async def test_http_resource_not_found_is_invalid_params_and_server_recovers():
    app = create_test_server().streamable_http_app(
        json_response=True,
        stateless_http=True,
        host="127.0.0.1",
        transport_security=create_transport_security("127.0.0.1"),
    )
    missing_uri = "doris://table/missing"
    valid_uri = "doris://table/orders"

    async with (
        app.router.lifespan_context(app),
        httpx2.ASGITransport(app) as transport,
        httpx2.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:3000",
        ) as client,
    ):
        missing = await client.post(
            "/mcp",
            json=modern_resource_request(1, missing_uri),
            headers=modern_resource_headers(missing_uri),
        )
        assert missing.status_code == 400
        assert missing.json()["error"] == {
            "code": -32602,
            "message": "Resource not found",
            "data": {
                "uri": missing_uri,
                "resourceErrorCode": "RESOURCE_NOT_FOUND",
            },
        }

        recovered = await client.post(
            "/mcp",
            json=modern_resource_request(2, valid_uri),
            headers=modern_resource_headers(valid_uri),
        )
        assert recovered.status_code == 200
        assert recovered.json()["result"]["contents"][0]["uri"] == valid_uri


@pytest.mark.asyncio
async def test_http_prompt_errors_are_typed_and_server_recovers():
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
        unknown = await client.post(
            "/mcp",
            json=modern_prompt_request(1, "missing"),
            headers=modern_prompt_headers("missing"),
        )
        assert unknown.status_code == 400
        assert unknown.json()["error"] == {
            "code": -32602,
            "message": "Prompt not found",
            "data": {
                "name": "missing",
                "promptErrorCode": "UNKNOWN_PROMPT",
            },
        }

        missing_argument = await client.post(
            "/mcp",
            json=modern_prompt_request(2, "needs_argument"),
            headers=modern_prompt_headers("needs_argument"),
        )
        assert missing_argument.status_code == 400
        assert missing_argument.json()["error"] == {
            "code": -32602,
            "message": "Missing required prompt argument",
            "data": {
                "name": "needs_argument",
                "promptErrorCode": "MISSING_REQUIRED_ARGUMENT",
                "argument": "required",
            },
        }

        database_failure = await client.post(
            "/mcp",
            json=modern_prompt_request(3, "database_failure"),
            headers=modern_prompt_headers("database_failure"),
        )
        assert database_failure.status_code == 200
        assert database_failure.json()["error"] == {
            "code": -32603,
            "message": "Database context unavailable",
            "data": {
                "name": "database_failure",
                "promptErrorCode": "DATABASE_CONTEXT_UNAVAILABLE",
            },
        }

        recovered = await client.post(
            "/mcp",
            json=modern_prompt_request(4, "explain", {"sql": "SELECT 1"}),
            headers=modern_prompt_headers("explain"),
        )
        assert recovered.status_code == 200
        assert recovered.json()["result"]["messages"][0]["content"]["text"] == (
            "Explain SELECT 1"
        )


@pytest.mark.asyncio
async def test_http_sql_profile_without_catalog_uses_production_analyzer_path():
    app = create_test_server(
        tools_manager=ProfileToolManager(),
    ).streamable_http_app(
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
        result = await client.post(
            "/mcp",
            json=modern_tool_request(
                1,
                "get_sql_profile",
                {"sql": "SELECT 1", "db_name": "hhm_dt_sim"},
            ),
            headers=modern_tool_headers("get_sql_profile"),
        )
        assert result.status_code == 200
        assert result.json()["result"]["isError"] is False
        assert result.json()["result"]["structuredContent"]["success"] is True
        assert result.json()["result"]["structuredContent"]["query_id"] == "query-1"

        recovered = await client.post(
            "/mcp",
            json=modern_tool_request(2, "echo", {}),
            headers=modern_tool_headers("echo"),
        )
        assert recovered.status_code == 200
        assert recovered.json()["result"]["isError"] is False


@pytest.mark.asyncio
async def test_http_unknown_freshness_uses_default_threshold():
    app = create_test_server(
        tools_manager=ProfileToolManager(),
    ).streamable_http_app(
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
        result = await client.post(
            "/mcp",
            json=modern_tool_request(
                1,
                "monitor_data_freshness",
                {"table_names": ["org_tenant"]},
            ),
            headers=modern_tool_headers("monitor_data_freshness"),
        )

        assert result.status_code == 200
        payload = result.json()["result"]["structuredContent"]
        assert result.json()["result"]["isError"] is False
        assert "error" not in payload
        assert payload["monitoring_scope"]["time_threshold_hours"] == 24
        assert payload["table_freshness"]["org_tenant"]["status"] == "unknown"


@pytest.mark.asyncio
async def test_http_doris4_role_metadata_uses_public_grants_command():
    app = create_test_server(
        tools_manager=ProfileToolManager(),
    ).streamable_http_app(
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
        result = await client.post(
            "/mcp",
            json=modern_tool_request(1, "analyze_data_access_patterns", {}),
            headers=modern_tool_headers("analyze_data_access_patterns"),
        )

        assert result.status_code == 200
        assert result.json()["result"]["isError"] is False
        roles = result.json()["result"]["structuredContent"]["role_analysis"]
        assert list(roles) == ["operator"]
        assert roles["operator"]["users"] == ["root"]


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
        with pytest.raises(MCPError) as missing_resource:
            await missing.read_resource(
                "doris://table/missing",
                cache_mode="bypass",
            )
        assert missing_resource.value.code == -32602
        assert missing_resource.value.data == {
            "uri": "doris://table/missing",
            "resourceErrorCode": "RESOURCE_NOT_FOUND",
        }
        recovered_resource = await missing.read_resource(
            "doris://table/orders",
            cache_mode="bypass",
        )
        assert recovered_resource.contents[0].uri == "doris://table/orders"

    async with Client(
        stdio_client(server_params),
        extensions=[advertise(REQUIRED_EXTENSION)],
    ) as capable:
        assert [tool.name for tool in (await capable.list_tools()).tools] == [
            "echo",
            "get_sql_profile",
            "monitor_data_freshness",
            "analyze_data_access_patterns",
        ]

    async with Client(stdio_client(server_params), mode="legacy") as legacy:
        assert [tool.name for tool in (await legacy.list_tools()).tools] == [
            "echo",
            "get_sql_profile",
            "monitor_data_freshness",
            "analyze_data_access_patterns",
        ]
        legacy_error = await legacy.read_resource("doris://table/missing")
        assert (
            json.loads(legacy_error.contents[0].text)["error_code"]
            == "RESOURCE_NOT_FOUND"
        )


@pytest.mark.asyncio
async def test_stdio_enforces_tool_specific_client_capabilities_and_recovers():
    server_script = Path(__file__).with_name("conformance_server.py")
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[str(server_script), "--transport", "stdio"],
    )

    async with Client(stdio_client(server_params)) as missing:
        assert [tool.name for tool in (await missing.list_tools()).tools] == [
            "test_missing_capability"
        ]
        with pytest.raises(MCPError) as missing_capability:
            await missing.call_tool("test_missing_capability", {})
        assert missing_capability.value.code == -32021
        assert missing_capability.value.data == {
            "requiredCapabilities": {"sampling": {}}
        }
        assert [tool.name for tool in (await missing.list_tools()).tools] == [
            "test_missing_capability"
        ]

    async with Client(
        stdio_client(server_params),
        sampling_callback=_unused_sampling_callback,
        sampling_capabilities=SamplingCapability(),
    ) as capable:
        result = await capable.call_tool("test_missing_capability", {})
        assert result.is_error is False
        assert result.structured_content == {
            "ok": True,
            "tool": "test_missing_capability",
        }

    async with Client(stdio_client(server_params), mode="legacy") as legacy:
        result = await legacy.call_tool("test_missing_capability", {})
        assert json.loads(result.content[0].text) == {
            "ok": True,
            "tool": "test_missing_capability",
        }


@pytest.mark.asyncio
async def test_stdio_sql_profile_without_catalog_uses_production_analyzer_path():
    server_script = Path(__file__).with_name("stdio_capability_server.py")
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[str(server_script)],
    )

    async with Client(
        stdio_client(server_params),
        extensions=[advertise(REQUIRED_EXTENSION)],
    ) as modern:
        result = await modern.call_tool(
            "get_sql_profile",
            {"sql": "SELECT 1", "db_name": "hhm_dt_sim"},
        )
        assert result.is_error is False
        assert result.structured_content["success"] is True
        assert result.structured_content["query_id"] == "query-1"

        recovered = await modern.call_tool("echo", {})
        assert recovered.is_error is False

    async with Client(stdio_client(server_params), mode="legacy") as legacy:
        result = await legacy.call_tool(
            "get_sql_profile",
            {"sql": "SELECT 1", "db_name": "hhm_dt_sim"},
        )
        assert json.loads(result.content[0].text)["success"] is True


@pytest.mark.asyncio
async def test_stdio_unknown_freshness_uses_default_threshold():
    server_script = Path(__file__).with_name("stdio_capability_server.py")
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[str(server_script)],
    )

    async with Client(
        stdio_client(server_params),
        extensions=[advertise(REQUIRED_EXTENSION)],
    ) as modern:
        result = await modern.call_tool(
            "monitor_data_freshness",
            {"table_names": ["org_tenant"]},
        )
        payload = result.structured_content
        assert result.is_error is False
        assert "error" not in payload
        assert payload["monitoring_scope"]["time_threshold_hours"] == 24

    async with Client(stdio_client(server_params), mode="legacy") as legacy:
        result = await legacy.call_tool(
            "monitor_data_freshness",
            {"table_names": ["org_tenant"]},
        )
        payload = json.loads(result.content[0].text)
        assert "error" not in payload
        assert payload["monitoring_scope"]["time_threshold_hours"] == 24


@pytest.mark.asyncio
async def test_stdio_doris4_role_metadata_uses_public_grants_command():
    server_script = Path(__file__).with_name("stdio_capability_server.py")
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[str(server_script)],
    )

    async with Client(
        stdio_client(server_params),
        extensions=[advertise(REQUIRED_EXTENSION)],
    ) as modern:
        result = await modern.call_tool("analyze_data_access_patterns", {})
        assert result.is_error is False
        roles = result.structured_content["role_analysis"]
        assert list(roles) == ["operator"]

    async with Client(stdio_client(server_params), mode="legacy") as legacy:
        result = await legacy.call_tool("analyze_data_access_patterns", {})
        roles = json.loads(result.content[0].text)["role_analysis"]
        assert list(roles) == ["operator"]


@pytest.mark.asyncio
async def test_stdio_prompt_errors_are_typed_and_process_survives():
    server_script = Path(__file__).with_name("stdio_capability_server.py")
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[str(server_script)],
    )

    async with Client(stdio_client(server_params)) as modern:
        with pytest.raises(MCPError) as unknown:
            await modern.get_prompt("missing", {})
        assert unknown.value.code == -32602
        assert unknown.value.data == {
            "name": "missing",
            "promptErrorCode": "UNKNOWN_PROMPT",
        }

        with pytest.raises(MCPError) as missing_argument:
            await modern.get_prompt("needs_argument", {})
        assert missing_argument.value.code == -32602
        assert missing_argument.value.data == {
            "name": "needs_argument",
            "promptErrorCode": "MISSING_REQUIRED_ARGUMENT",
            "argument": "required",
        }

        with pytest.raises(MCPError) as database_failure:
            await modern.get_prompt("database_failure", {})
        assert database_failure.value.code == -32603
        assert database_failure.value.data == {
            "name": "database_failure",
            "promptErrorCode": "DATABASE_CONTEXT_UNAVAILABLE",
        }

        recovered = await modern.get_prompt("explain", {"sql": "SELECT 1"})
        assert recovered.messages[0].content.text == "Explain SELECT 1"

    async with Client(stdio_client(server_params), mode="legacy") as legacy:
        with pytest.raises(MCPError) as legacy_unknown:
            await legacy.get_prompt("missing", {})
        assert legacy_unknown.value.code == -32602
