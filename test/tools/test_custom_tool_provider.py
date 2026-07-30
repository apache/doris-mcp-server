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
"""Tests for the explicit trusted custom-tool provider boundary."""

from __future__ import annotations

import json
import logging
from importlib import metadata
from unittest.mock import AsyncMock, Mock

import httpx2
import pytest
from mcp.types import Tool

from doris_mcp_server import __version__
from doris_mcp_server.protocol import (
    create_doris_mcp_server,
    create_transport_security,
)
from doris_mcp_server.tools.tool_provider import (
    CustomTool,
    LocalToolRateLimiter,
    ToolProviderError,
    ToolRateLimit,
    load_tool_providers,
)
from doris_mcp_server.tools.tool_registry import ToolRegistryError
from doris_mcp_server.tools.tools_manager import DorisToolsManager
from doris_mcp_server.utils.config import DorisConfig
from doris_mcp_server.utils.security import (
    AuthContext,
    reset_auth_context,
    set_current_auth_context,
)


def _connection_manager() -> Mock:
    manager = Mock()
    manager.config = DorisConfig()
    manager.get_connection = AsyncMock()
    return manager


class RecordingProvider:
    name = "orders_api"

    def __init__(
        self,
        *,
        tool_name: str = "lookup_business_order",
        rate_limit: ToolRateLimit | None = None,
    ) -> None:
        self.handler = AsyncMock(
            return_value={"ok": True, "source": "business-api"}
        )
        self.start = AsyncMock()
        self.close = AsyncMock()
        self._tool_name = tool_name
        self._rate_limit = rate_limit

    def tools(self) -> tuple[CustomTool, ...]:
        return (
            CustomTool(
                tool=Tool(
                    name=self._tool_name,
                    description="Look up one order through a trusted business API",
                    input_schema={
                        "type": "object",
                        "properties": {
                            "order_id": {"type": "string"},
                        },
                        "required": ["order_id"],
                        "additionalProperties": False,
                    },
                    output_schema={
                        "type": "object",
                        "properties": {
                            "ok": {"type": "boolean"},
                            "source": {"type": "string"},
                        },
                        "required": ["ok", "source"],
                        "additionalProperties": False,
                    },
                ),
                handler=self.handler,
                rate_limit=self._rate_limit,
            ),
        )


@pytest.mark.asyncio
async def test_provider_tool_is_listed_dispatched_audited_and_lifecycle_managed():
    provider = RecordingProvider()
    manager = DorisToolsManager(
        _connection_manager(),
        tool_providers=[provider],
    )
    manager.query_executor.start = AsyncMock()
    manager.query_executor.close = AsyncMock()

    await manager.start()
    listed = await manager.list_tools()
    payload = json.loads(
        await manager.call_tool(
            "lookup_business_order",
            {"order_id": "order-42"},
        )
    )
    await manager.close()

    assert "lookup_business_order" in {tool.name for tool in listed}
    provider.handler.assert_awaited_once_with({"order_id": "order-42"})
    assert payload["ok"] is True
    assert payload["source"] == "business-api"
    assert "_execution_info" not in payload
    definition = manager.tool_registry.resolve("lookup_business_order")
    assert definition.provider_name == "orders_api"
    assert definition.policy.channel == "custom_provider"
    provider.start.assert_awaited_once_with()
    provider.close.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_provider_start_failure_rolls_back_started_providers():
    first = RecordingProvider()
    second = RecordingProvider(tool_name="lookup_customer")
    second.name = "customer_api"
    second.start.side_effect = RuntimeError("upstream unavailable")
    manager = DorisToolsManager(
        _connection_manager(),
        tool_providers=[first, second],
    )
    manager.query_executor.start = AsyncMock()
    manager.query_executor.close = AsyncMock()

    with pytest.raises(RuntimeError, match="upstream unavailable"):
        await manager.start()

    first.start.assert_awaited_once_with()
    first.close.assert_awaited_once_with()
    second.start.assert_awaited_once_with()
    second.close.assert_not_awaited()
    manager.query_executor.close.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_custom_tool_rate_limit_is_fail_closed_and_principal_scoped():
    provider = RecordingProvider(
        rate_limit=ToolRateLimit(
            max_calls=1,
            period_seconds=60,
            scope="principal",
        )
    )
    manager = DorisToolsManager(
        _connection_manager(),
        tool_providers=[provider],
    )

    first = json.loads(
        await manager.call_tool(
            "lookup_business_order",
            {"order_id": "first"},
        )
    )
    limited = json.loads(
        await manager.call_tool(
            "lookup_business_order",
            {"order_id": "second"},
        )
    )

    context_token = set_current_auth_context(
        AuthContext(
            auth_method="token",
            token_id="another-principal",
            user_id="another-principal",
        )
    )
    try:
        another_principal = json.loads(
            await manager.call_tool(
                "lookup_business_order",
                {"order_id": "third"},
            )
        )
    finally:
        reset_auth_context(context_token)

    assert first["ok"] is True
    assert limited["error_code"] == "TOOL_RATE_LIMITED"
    assert limited["retry_after_seconds"] >= 1
    assert another_principal["ok"] is True
    assert provider.handler.await_count == 2


def test_custom_tool_cannot_shadow_a_builtin_tool():
    provider = RecordingProvider(tool_name="exec_query")

    with pytest.raises(ToolRegistryError, match="Duplicate tool definition"):
        DorisToolsManager(
            _connection_manager(),
            tool_providers=[provider],
        )


def test_custom_tools_cannot_shadow_each_other():
    first = RecordingProvider()
    second = RecordingProvider()
    second.name = "customer_api"

    with pytest.raises(ToolRegistryError, match="Duplicate tool definition"):
        DorisToolsManager(
            _connection_manager(),
            tool_providers=[first, second],
        )


class FakeEntryPoint:
    def __init__(self, name: str, factory: object) -> None:
        self.name = name
        self._factory = factory

    def load(self) -> object:
        return self._factory


def test_loader_loads_only_explicit_installed_entry_points(monkeypatch):
    provider = RecordingProvider()
    unselected_factory = Mock(side_effect=AssertionError("must not be loaded"))
    monkeypatch.setattr(
        metadata,
        "entry_points",
        lambda **kwargs: [
            FakeEntryPoint("orders_api", lambda: provider),
            FakeEntryPoint("unselected", unselected_factory),
        ],
    )

    loaded = load_tool_providers(["orders_api"])

    assert [item.name for item in loaded] == ["orders_api"]
    assert loaded[0].provider is provider
    assert loaded[0].tools[0].tool.name == "lookup_business_order"
    unselected_factory.assert_not_called()


def test_loader_rejects_unknown_or_mismatched_providers(monkeypatch):
    monkeypatch.setattr(metadata, "entry_points", lambda **kwargs: [])
    with pytest.raises(ToolProviderError, match="is not installed"):
        load_tool_providers(["missing"])

    mismatched = RecordingProvider()
    mismatched.name = "different_name"
    monkeypatch.setattr(
        metadata,
        "entry_points",
        lambda **kwargs: [
            FakeEntryPoint("orders_api", lambda: mismatched),
        ],
    )
    with pytest.raises(ToolProviderError, match="mismatched name"):
        load_tool_providers(["orders_api"])


@pytest.mark.parametrize(
    ("max_calls", "period_seconds", "scope"),
    [
        (0, 1, "principal"),
        (1, 0, "principal"),
        (1, 1, "unknown"),
    ],
)
def test_custom_tool_rate_limit_rejects_invalid_bounds(
    max_calls,
    period_seconds,
    scope,
):
    with pytest.raises(ToolProviderError):
        ToolRateLimit(
            max_calls=max_calls,
            period_seconds=period_seconds,
            scope=scope,
        )


@pytest.mark.asyncio
async def test_rate_limiter_recycles_expired_principal_keys():
    now = 0.0
    limiter = LocalToolRateLimiter(clock=lambda: now, max_keys=1)
    limit = ToolRateLimit(max_calls=1, period_seconds=1)

    assert (
        await limiter.retry_after(
            tool_name="lookup",
            principal="first",
            limit=limit,
        )
        is None
    )
    assert (
        await limiter.retry_after(
            tool_name="lookup",
            principal="second",
            limit=limit,
        )
        == 1
    )

    now = 1.1
    assert (
        await limiter.retry_after(
            tool_name="lookup",
            principal="second",
            limit=limit,
        )
        is None
    )


def _modern_request(
    request_id: int,
    method: str,
    *,
    name: str | None = None,
    arguments: dict | None = None,
) -> dict:
    params: dict = {
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {
                "name": "custom-provider-test",
                "version": "1.0.0",
            },
        }
    }
    if name is not None:
        params.update({"name": name, "arguments": arguments or {}})
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": params,
    }


def _modern_headers(method: str, *, name: str | None = None) -> dict[str, str]:
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "Mcp-Protocol-Version": "2026-07-28",
        "Mcp-Method": method,
    }
    if name is not None:
        headers["Mcp-Name"] = name
    return headers


@pytest.mark.asyncio
async def test_custom_tool_uses_real_streamable_http_list_validation_and_call():
    provider = RecordingProvider()
    manager = DorisToolsManager(
        _connection_manager(),
        tool_providers=[provider],
    )
    resources_manager = Mock()
    resources_manager.list_resources = AsyncMock(return_value=[])
    resources_manager.read_resource = AsyncMock()
    prompts_manager = Mock()
    prompts_manager.list_prompts = AsyncMock(return_value=[])
    prompts_manager.get_prompt = AsyncMock()
    server = create_doris_mcp_server(
        resources_manager=resources_manager,
        tools_manager=manager,
        prompts_manager=prompts_manager,
        name="doris-mcp-custom-provider-test",
        version=__version__,
        logger=logging.getLogger(__name__),
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
        listed = await client.post(
            "/mcp",
            json=_modern_request(1, "tools/list"),
            headers=_modern_headers("tools/list"),
        )
        invalid = await client.post(
            "/mcp",
            json=_modern_request(
                2,
                "tools/call",
                name="lookup_business_order",
            ),
            headers=_modern_headers(
                "tools/call",
                name="lookup_business_order",
            ),
        )
        called = await client.post(
            "/mcp",
            json=_modern_request(
                3,
                "tools/call",
                name="lookup_business_order",
                arguments={"order_id": "order-42"},
            ),
            headers=_modern_headers(
                "tools/call",
                name="lookup_business_order",
            ),
        )

    assert listed.status_code == 200
    listed_tools = {
        tool["name"]: tool for tool in listed.json()["result"]["tools"]
    }
    assert "lookup_business_order" in listed_tools
    assert listed_tools["lookup_business_order"]["inputSchema"]["required"] == [
        "order_id"
    ]
    assert invalid.status_code == 400
    assert invalid.json()["error"]["code"] == -32602
    assert called.status_code == 200
    structured = called.json()["result"]["structuredContent"]
    assert structured["ok"] is True
    assert structured["source"] == "business-api"
    assert "_execution_info" not in structured
