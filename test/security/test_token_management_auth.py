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

from urllib.parse import urlencode

import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.routing import Route

from doris_mcp_server.auth.token_handlers import TokenHandlers
from doris_mcp_server.auth.token_security_middleware import TokenSecurityMiddleware
from doris_mcp_server.utils.config import DorisConfig

ADMIN_TOKEN = "J8pR4mX2vN7qL5sT9kW3cF6hY1uD8aB0eG4iC2oP"


def _config() -> DorisConfig:
    config = DorisConfig()
    config.security.enable_http_token_management = True
    config.security.require_admin_auth = True
    config.security.token_management_admin_token = ADMIN_TOKEN
    config.security.token_management_allowed_ips = ["127.0.0.1"]
    return config


def _request(
    path: str = "/token/stats",
    *,
    headers: dict[str, str] | None = None,
    query: dict[str, str] | None = None,
    client_ip: str = "127.0.0.1",
) -> Request:
    encoded_headers = [
        (name.lower().encode(), value.encode())
        for name, value in (headers or {}).items()
    ]
    return Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "http",
            "server": ("127.0.0.1", 3000),
            "client": (client_ip, 50000),
            "path": path,
            "raw_path": path.encode(),
            "query_string": urlencode(query or {}).encode(),
            "headers": encoded_headers,
        }
    )


@pytest.mark.asyncio
async def test_admin_query_token_is_rejected_and_headers_are_accepted():
    middleware = TokenSecurityMiddleware(_config())

    query_only = await middleware.check_token_management_access(
        _request(query={"admin_token": ADMIN_TOKEN})
    )
    assert query_only is not None
    assert query_only.status_code == 401

    bad_header_with_query = await middleware.check_token_management_access(
        _request(
            headers={"Authorization": "Bearer wrong-token"},
            query={"admin_token": ADMIN_TOKEN},
        )
    )
    assert bad_header_with_query is not None
    assert bad_header_with_query.status_code == 401

    assert (
        await middleware.check_token_management_access(
            _request(headers={"Authorization": f"Bearer {ADMIN_TOKEN}"})
        )
        is None
    )
    assert (
        await middleware.check_token_management_access(
            _request(headers={"X-Admin-Token": ADMIN_TOKEN})
        )
        is None
    )


@pytest.mark.asyncio
async def test_proxy_headers_cannot_spoof_token_management_allowlist():
    config = _config()
    config.security.token_management_allowed_ips = ["203.0.113.7"]
    middleware = TokenSecurityMiddleware(config)

    denied = await middleware.check_token_management_access(
        _request(
            headers={
                "Authorization": f"Bearer {ADMIN_TOKEN}",
                "X-Forwarded-For": "203.0.113.7",
                "X-Real-IP": "203.0.113.7",
            },
            client_ip="198.51.100.9",
        )
    )

    assert denied is not None
    assert denied.status_code == 403
    assert b'"client_ip":"198.51.100.9"' in denied.body


class _AuthProvider:
    token_manager = object()


class _SecurityManager:
    auth_provider = _AuthProvider()

    @staticmethod
    def get_token_stats():
        return {
            "total_tokens": 0,
            "active_tokens": 0,
            "expired_tokens": 0,
            "expiry_enabled": True,
            "default_expiry_hours": 24,
        }


@pytest.mark.asyncio
async def test_http_management_route_requires_admin_header():
    handlers = TokenHandlers(_SecurityManager(), _config())
    app = Starlette(
        routes=[Route("/token/stats", handlers.handle_token_stats, methods=["GET"])]
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://127.0.0.1:3000",
    ) as client:
        denied = await client.get(
            "/token/stats",
            params={"admin_token": ADMIN_TOKEN},
        )
        accepted = await client.get(
            "/token/stats",
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        )

    assert denied.status_code == 401
    assert accepted.status_code == 200
    assert accepted.json()["success"] is True


@pytest.mark.asyncio
async def test_management_page_uses_header_only_and_never_builds_token_urls():
    handlers = TokenHandlers(_SecurityManager(), _config())

    response = await handlers.handle_management_page(
        _request(
            path="/token/management",
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        )
    )
    body = response.body.decode()

    assert response.status_code == 200
    assert "admin_token" not in body
    assert "URLSearchParams" not in body
    assert "getAuthURL" not in body
    assert "Authorization" in body
    assert 'type="password" id="adminToken"' in body
