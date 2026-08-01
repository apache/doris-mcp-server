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
"""Protocol boundary tests for modern and legacy Streamable HTTP."""

import anyio
import httpx2
import pytest
from mcp.server import Server

from doris_mcp_server.http_transport import (
    LEGACY_MCP_PATH,
    MODERN_MCP_PATH,
    DorisMCPHTTPTransport,
)


def _modern_request(request_id: int = 1) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "server/discover",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
                "io.modelcontextprotocol/clientInfo": {
                    "name": "http-boundary-test",
                    "version": "1.0.0",
                },
            }
        },
    }


def _modern_headers() -> dict[str, str]:
    return {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "Mcp-Protocol-Version": "2026-07-28",
        "Mcp-Method": "server/discover",
    }


def _legacy_initialize(protocol_version: str = "2025-11-25") -> dict:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": protocol_version,
            "capabilities": {},
            "clientInfo": {
                "name": "legacy-http-boundary-test",
                "version": "1.0.0",
            },
        },
    }


def _legacy_headers() -> dict[str, str]:
    return {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }


def _transport(*, legacy_adapter_enabled: bool = False) -> DorisMCPHTTPTransport:
    return DorisMCPHTTPTransport(
        app=Server("doris-mcp-server", version="test"),
        security_settings=None,
        legacy_adapter_enabled=legacy_adapter_enabled,
    )


@pytest.mark.asyncio
async def test_modern_core_is_exact_post_only_and_never_falls_back_to_legacy():
    app = _transport()

    async with (
        app.run(),
        httpx2.ASGITransport(app.handle_request) as asgi_transport,
        httpx2.AsyncClient(
            transport=asgi_transport,
            base_url="http://127.0.0.1:3000",
        ) as client,
    ):
        modern = await client.post(
            MODERN_MCP_PATH,
            json=_modern_request(),
            headers=_modern_headers(),
        )
        assert modern.status_code == 200
        assert modern.json()["result"]["supportedVersions"] == ["2026-07-28"]
        assert "mcp-session-id" not in modern.headers

        get_response = await client.get(
            MODERN_MCP_PATH,
            headers=_modern_headers(),
        )
        assert get_response.status_code == 405
        assert get_response.headers["allow"] == "POST"
        assert get_response.headers.get("content-type") != "text/event-stream"

        delete_response = await client.delete(
            MODERN_MCP_PATH,
            headers=_modern_headers(),
        )
        assert delete_response.status_code == 405
        assert delete_response.headers["allow"] == "POST"

        legacy_on_core = await client.post(
            MODERN_MCP_PATH,
            json=_legacy_initialize(),
            headers=_legacy_headers(),
        )
        assert legacy_on_core.status_code == 400
        assert legacy_on_core.json()["error"]["code"] == -32602

        disabled_legacy = await client.post(
            LEGACY_MCP_PATH,
            json=_legacy_initialize(),
            headers=_legacy_headers(),
        )
        assert disabled_legacy.status_code == 404

        inexact_path = await client.post(
            f"{MODERN_MCP_PATH}/",
            json=_modern_request(2),
            headers=_modern_headers(),
        )
        assert inexact_path.status_code == 404


@pytest.mark.parametrize("protocol_version", ["2025-06-18", "2025-11-25"])
@pytest.mark.asyncio
async def test_opt_in_legacy_adapter_accepts_only_handshake_era_traffic(
    protocol_version: str,
):
    app = _transport(legacy_adapter_enabled=True)

    async with (
        app.run(),
        httpx2.ASGITransport(app.handle_request) as asgi_transport,
        httpx2.AsyncClient(
            transport=asgi_transport,
            base_url="http://127.0.0.1:3000",
        ) as client,
    ):
        initialized = await client.post(
            LEGACY_MCP_PATH,
            json=_legacy_initialize(protocol_version),
            headers=_legacy_headers(),
        )
        assert initialized.status_code == 200
        assert initialized.json()["result"]["protocolVersion"] == protocol_version
        assert "mcp-session-id" not in initialized.headers

        modern_on_legacy = await client.post(
            LEGACY_MCP_PATH,
            json=_modern_request(),
            headers=_modern_headers(),
        )
        assert modern_on_legacy.status_code == 400
        assert modern_on_legacy.json() == {
            "error": "legacy_adapter_only",
            "message": f"Use {MODERN_MCP_PATH} for modern MCP protocol requests",
        }

        modern_on_core = await client.post(
            MODERN_MCP_PATH,
            json=_modern_request(2),
            headers=_modern_headers(),
        )
        assert modern_on_core.status_code == 200


@pytest.mark.asyncio
async def test_legacy_get_sse_exists_only_inside_the_opt_in_adapter():
    app = _transport(legacy_adapter_enabled=True)
    response_started = anyio.Event()
    messages: list[dict] = []

    async def receive() -> dict:
        await response_started.wait()
        return {"type": "http.disconnect"}

    async def send(message: dict) -> None:
        messages.append(message)
        if message["type"] == "http.response.start":
            response_started.set()

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": LEGACY_MCP_PATH,
        "raw_path": LEGACY_MCP_PATH.encode(),
        "query_string": b"",
        "headers": [
            (b"accept", b"text/event-stream"),
            (b"host", b"127.0.0.1:3000"),
        ],
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 3000),
    }

    async with app.run():
        await app.handle_request(scope, receive, send)

    response_start = next(
        message for message in messages if message["type"] == "http.response.start"
    )
    assert response_start["status"] == 200
    assert dict(response_start["headers"])[b"content-type"].startswith(
        b"text/event-stream"
    )
