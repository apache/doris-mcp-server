#!/usr/bin/env python3
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
"""CORS helpers for protected MCP HTTP routes."""

from typing import Any, Awaitable, Callable

from starlette.responses import Response


ASGISend = Callable[[dict[str, Any]], Awaitable[None]]


def _headers(scope: dict[str, Any]) -> dict[bytes, bytes]:
    return dict(scope.get("headers", []))


def mcp_cors_header_pairs(scope: dict[str, Any]) -> list[tuple[bytes, bytes]]:
    """Return CORS headers for MCP responses."""
    headers = _headers(scope)
    origin = headers.get(b"origin") or b"*"
    cors_headers = [
        (b"access-control-allow-origin", origin),
        (b"access-control-allow-credentials", b"true"),
        (b"access-control-expose-headers", b"mcp-session-id, www-authenticate"),
    ]
    if origin != b"*":
        cors_headers.append((b"vary", b"Origin"))
    return cors_headers


async def send_with_mcp_cors(scope: dict[str, Any], send: ASGISend, message: dict[str, Any]) -> None:
    """Forward an ASGI message after adding MCP CORS headers to response starts."""
    if message.get("type") == "http.response.start":
        response_headers = list(message.get("headers", []))
        existing_names = {name.lower() for name, _ in response_headers}
        for name, value in mcp_cors_header_pairs(scope):
            normalized_name = name.lower()
            if normalized_name not in existing_names:
                response_headers.append((name, value))
                existing_names.add(normalized_name)
        message["headers"] = response_headers
    await send(message)


def mcp_cors_preflight_response(scope: dict[str, Any]) -> Response:
    """Build an MCP CORS preflight response without invoking MCP auth/session code."""
    headers = _headers(scope)
    origin = headers.get(b"origin", b"*").decode("latin-1")
    request_headers = headers.get(
        b"access-control-request-headers",
        b"",
    ).decode("latin-1")
    response = Response("", status_code=204)
    response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = (
        request_headers or "authorization, content-type, mcp-session-id"
    )
    response.headers["Access-Control-Max-Age"] = "86400"
    if origin != "*":
        response.headers["Vary"] = "Origin"
    return response
