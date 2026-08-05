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
"""Exact HTTP boundaries for the modern MCP core and legacy adapter."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Final

from mcp.server import Server

# SDK 2.0 exposes only a dual-era public HTTP manager. Keep its modern-only
# entry point isolated here so a future public API replacement is one edit.
from mcp.server._streamable_http_modern import handle_modern_request
from mcp.server.streamable_http_manager import (
    DEFAULT_MAX_REQUEST_BODY_SIZE,
    RequestBodyLimitMiddleware,
    StreamableHTTPSessionManager,
)
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.inbound import MCP_PROTOCOL_VERSION_HEADER
from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS
from starlette.datastructures import Headers
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Receive, Scope, Send

MODERN_MCP_PATH: Final = "/mcp"
LEGACY_MCP_PATH: Final = "/mcp/legacy"
AUXILIARY_MAX_REQUEST_BODY_SIZE: Final = 64 * 1024


def protect_auxiliary_http_app(
    app: ASGIApp,
    *,
    max_request_body_size: int = AUXILIARY_MAX_REQUEST_BODY_SIZE,
) -> ASGIApp:
    """Bound form and JSON bodies before auxiliary handlers parse them."""
    if max_request_body_size <= 0:
        raise ValueError("max_request_body_size must be positive")
    return RequestBodyLimitMiddleware(app, max_request_body_size)


class DorisMCPHTTPTransport:
    """Expose a POST-only modern core and an opt-in legacy HTTP adapter.

    The SDK's public session manager intentionally dispatches both protocol
    eras. Doris MCP Server keeps that manager as the lifecycle owner and for
    the optional legacy adapter, while routing the modern endpoint directly to
    the SDK's 2026-07-28 handler. This prevents a missing or legacy protocol
    header from silently selecting the old transport on ``/mcp``.
    """

    def __init__(
        self,
        *,
        app: Server[Any],
        security_settings: TransportSecuritySettings | None,
        legacy_adapter_enabled: bool = False,
        json_response: bool = True,
        max_request_body_size: int = DEFAULT_MAX_REQUEST_BODY_SIZE,
    ) -> None:
        self._app = app
        self._security_settings = security_settings
        self._json_response = json_response
        self._running = False
        self.legacy_adapter_enabled = legacy_adapter_enabled
        self._session_manager = StreamableHTTPSessionManager(
            app=app,
            json_response=json_response,
            stateless=True,
            security_settings=security_settings,
            max_request_body_size=max_request_body_size,
        )
        self._modern_app: ASGIApp = RequestBodyLimitMiddleware(
            self._handle_modern_request,
            max_request_body_size,
        )

    @asynccontextmanager
    async def run(self) -> AsyncIterator[None]:
        """Own the shared SDK lifespan for both HTTP protocol eras."""
        async with self._session_manager.run():
            self._running = True
            try:
                yield
            finally:
                self._running = False

    async def handle_request(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        """Route only exact MCP paths to their respective protocol boundary."""
        path = scope.get("path", "")
        if path == MODERN_MCP_PATH:
            await self._modern_app(scope, receive, send)
            return
        if path == LEGACY_MCP_PATH and self.legacy_adapter_enabled:
            await self._handle_legacy_request(scope, receive, send)
            return
        await Response("Not Found", status_code=404)(scope, receive, send)

    async def _handle_modern_request(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        """Enter only the SDK's modern POST handler on the core endpoint."""
        if not self._running:
            raise RuntimeError(
                "HTTP transport is not initialized. Make sure to use run()."
            )
        await handle_modern_request(
            self._app,
            self._security_settings,
            self._json_response,
            self._session_manager._lifespan_state,
            scope,
            receive,
            send,
        )

    async def _handle_legacy_request(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        """Serve only handshake-era traffic on the explicit legacy endpoint."""
        protocol_version = Headers(scope=scope).get(MCP_PROTOCOL_VERSION_HEADER)
        if (
            protocol_version is not None
            and protocol_version not in HANDSHAKE_PROTOCOL_VERSIONS
        ):
            await JSONResponse(
                {
                    "error": "legacy_adapter_only",
                    "message": (
                        f"Use {MODERN_MCP_PATH} for modern MCP protocol requests"
                    ),
                },
                status_code=400,
            )(scope, receive, send)
            return
        await self._session_manager.handle_request(scope, receive, send)
