# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""ASGI and MCP boundaries for the JWT authentication middleware."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from doris_mcp_server.auth.auth_middleware import (
    AuthenticationError,
    AuthMiddleware,
    AuthorizationError,
)
from doris_mcp_server.utils.auth_credentials import BearerCredentials
from doris_mcp_server.utils.security import AuthContext, SecurityLevel


class _JWTManager:
    async def validate_token(self, token: str, token_type: str) -> dict[str, Any]:
        if token == "invalid":
            raise ValueError("invalid token")
        assert token_type == "access"
        return {
            "payload": {
                "jti": "jwt-1",
                "sub": "reader-1",
                "roles": ["reader"],
                "permissions": ["read_data"],
                "security_level": "internal",
                "iat": int(datetime.now(UTC).timestamp()),
            }
        }


async def _receive() -> dict[str, Any]:
    return {"type": "http.disconnect"}


@pytest.mark.asyncio
async def test_header_helpers_and_mcp_authentication() -> None:
    middleware = AuthMiddleware(_JWTManager())

    assert middleware.extract_token_from_header("Bearer jwt-value") == "jwt-value"
    assert middleware.extract_token_from_header("Basic ignored") is None

    context = await middleware.authenticate_mcp_request({"X-Auth-Token": "jwt-value"})
    assert context.user_id == "reader-1"
    assert context.auth_method == "jwt"
    assert context.token == ""

    headers = await middleware.create_auth_response_headers(context)
    assert headers == {
        "X-Auth-User": "reader-1",
        "X-Auth-Roles": "reader",
        "X-Auth-Session": "jwt-1",
        "X-Auth-Security-Level": "internal",
    }

    with pytest.raises(ValueError, match="Missing JWT token"):
        await middleware.authenticate_request(BearerCredentials())
    with pytest.raises(ValueError, match="JWT authentication failed"):
        await middleware.authenticate_mcp_request({"Authorization": "Bearer invalid"})


@pytest.mark.asyncio
async def test_http_middleware_adds_identity_headers() -> None:
    middleware = AuthMiddleware(_JWTManager())

    async def app(
        scope: dict[str, Any],
        receive: Any,
        send: Any,
    ) -> None:
        assert scope["auth_context"].user_id == "reader-1"
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"x-existing", b"kept")],
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})

    wrapped = middleware.create_http_middleware(app, skip_paths=["/public"])
    sent: list[dict[str, Any]] = []

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    await wrapped(
        {
            "type": "http",
            "path": "/mcp",
            "headers": [(b"authorization", b"Bearer jwt-value")],
        },
        _receive,
        send,
    )

    response_headers = dict(sent[0]["headers"])
    assert sent[0]["status"] == 200
    assert response_headers[b"x-existing"] == b"kept"
    assert response_headers[b"X-Auth-User"] == b"reader-1"
    assert response_headers[b"X-Auth-Security-Level"] == b"internal"


@pytest.mark.asyncio
async def test_http_middleware_skips_public_and_non_http_scopes() -> None:
    middleware = AuthMiddleware(_JWTManager())
    observed: list[str] = []

    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        observed.append(scope["type"])

    wrapped = middleware.create_http_middleware(app, skip_paths=["/public"])

    async def send(_message: dict[str, Any]) -> None:
        raise AssertionError("pass-through requests must not emit their own response")

    await wrapped(
        {"type": "http", "path": "/public/child", "headers": []},
        _receive,
        send,
    )
    await wrapped(
        {"type": "websocket", "path": "/mcp", "headers": []},
        _receive,
        send,
    )

    assert observed == ["http", "websocket"]


@pytest.mark.asyncio
async def test_http_middleware_returns_bearer_challenge_on_failure() -> None:
    middleware = AuthMiddleware(_JWTManager())

    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        raise AssertionError("unauthenticated request reached the application")

    wrapped = middleware.create_http_middleware(app, skip_paths=["/public"])
    sent: list[dict[str, Any]] = []

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    await wrapped(
        {
            "type": "http",
            "path": "/mcp",
            "headers": [(b"authorization", b"Bearer invalid")],
        },
        _receive,
        send,
    )

    assert sent[0]["status"] == 401
    assert dict(sent[0]["headers"])[b"www-authenticate"] == b"Bearer"
    assert b"Authentication failed" in sent[1]["body"]


def test_authentication_and_authorization_errors_keep_codes() -> None:
    authentication = AuthenticationError("bad credentials")
    authorization = AuthorizationError("forbidden")

    assert authentication.message == "bad credentials"
    assert authentication.error_code == "AUTH_FAILED"
    assert authorization.message == "forbidden"
    assert authorization.error_code == "ACCESS_DENIED"


def test_auth_response_headers_use_security_level_value() -> None:
    context = AuthContext(
        user_id="reader-1",
        roles=["reader", "analyst"],
        session_id="session-1",
        security_level=SecurityLevel.INTERNAL,
    )

    assert context.security_level.value == "internal"
