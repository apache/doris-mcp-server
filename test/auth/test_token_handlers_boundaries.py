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

"""HTTP boundary coverage for token-management handlers."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import httpx
import pytest
from starlette.applications import Starlette
from starlette.routing import Route

from doris_mcp_server.auth.token_handlers import TokenHandlers


def _manager(*, enabled: bool = True) -> SimpleNamespace:
    return SimpleNamespace(
        auth_provider=SimpleNamespace(token_manager=object() if enabled else None),
        create_token=AsyncMock(return_value="generated-token"),
        revoke_token=AsyncMock(return_value=True),
        list_tokens=AsyncMock(return_value=[{"token_id": "reader"}]),
        get_token_stats=Mock(return_value={"active_tokens": 1}),
        cleanup_expired_tokens=AsyncMock(return_value=2),
    )


def _app(manager: SimpleNamespace) -> Starlette:
    handlers = TokenHandlers(manager, config=None)
    return Starlette(
        routes=[
            Route(
                "/token/create",
                handlers.handle_create_token,
                methods=["GET", "POST"],
            ),
            Route(
                "/token/revoke",
                handlers.handle_revoke_token,
                methods=["DELETE"],
            ),
            Route(
                "/token/revoke/{token_id}",
                handlers.handle_revoke_token,
                methods=["DELETE"],
            ),
            Route("/token/list", handlers.handle_list_tokens, methods=["GET"]),
            Route("/token/stats", handlers.handle_token_stats, methods=["GET"]),
            Route(
                "/token/cleanup",
                handlers.handle_cleanup_tokens,
                methods=["POST"],
            ),
        ]
    )


def _client(manager: SimpleNamespace) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app(manager)),
        base_url="http://testserver",
    )


@pytest.mark.asyncio
async def test_create_token_from_get_query_includes_database_config():
    manager = _manager()

    async with _client(manager) as client:
        response = await client.get(
            "/token/create",
            params={
                "token_id": "reader",
                "expires_hours": "12",
                "description": "read only",
                "custom_token": "chosen-token",
                "db_host": "doris.internal",
                "db_hosts": "doris.internal,doris-2.internal",
                "db_port": "9031",
                "db_user": "readonly",
                "db_password": "secret",
                "db_database": "analytics",
                "db_fe_http_host": "doris-http.internal",
                "db_fe_http_hosts": (
                    "doris-http.internal,doris-http-2.internal"
                ),
                "db_fe_http_port": "8031",
            },
        )

    assert response.status_code == 200
    assert response.json()["token"] == "generated-token"
    call = manager.create_token.await_args
    assert call.kwargs["token_id"] == "reader"
    assert call.kwargs["expires_hours"] == 12
    assert call.kwargs["custom_token"] == "chosen-token"
    database = call.kwargs["database_config"]
    assert database.host == "doris.internal"
    assert database.hosts == ["doris.internal", "doris-2.internal"]
    assert database.port == 9031
    assert database.user == "readonly"
    assert database.password == "secret"
    assert database.database == "analytics"
    assert database.fe_http_host == "doris-http.internal"
    assert database.fe_http_hosts == [
        "doris-http.internal",
        "doris-http-2.internal",
    ]
    assert database.fe_http_port == 8031


@pytest.mark.asyncio
async def test_create_token_from_post_json_uses_defaults():
    manager = _manager()

    async with _client(manager) as client:
        response = await client.post(
            "/token/create",
            json={
                "token_id": "writer",
                "database_config": {
                    "hosts": ["doris.internal", "doris-2.internal"]
                },
            },
        )

    assert response.status_code == 200
    database = manager.create_token.await_args.kwargs["database_config"]
    assert database.host == "doris.internal"
    assert database.hosts == ["doris.internal", "doris-2.internal"]
    assert database.port == 9030
    assert database.user == "root"
    assert database.database == "information_schema"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("request_kind", "payload", "expected_error"),
    [
        ("json", {}, "token_id is required"),
        ("query", {"token_id": "reader", "expires_hours": "soon"}, "integer"),
        (
            "json",
            {"token_id": "reader", "database_config": {"port": "bad"}},
            "Invalid database configuration",
        ),
    ],
)
async def test_create_token_rejects_invalid_inputs(
    request_kind: str,
    payload: dict[str, object],
    expected_error: str,
):
    manager = _manager()

    async with _client(manager) as client:
        if request_kind == "query":
            response = await client.get("/token/create", params=payload)
        else:
            response = await client.post("/token/create", json=payload)

    assert response.status_code == 400
    assert expected_error in response.json()["error"]
    manager.create_token.assert_not_awaited()


@pytest.mark.asyncio
async def test_create_token_rejects_invalid_json_and_reports_service_failures():
    manager = _manager()

    async with _client(manager) as client:
        invalid_json = await client.post(
            "/token/create",
            content=b"{",
            headers={"content-type": "application/json"},
        )
        bad_query_database = await client.get(
            "/token/create",
            params={"token_id": "reader", "db_host": "doris", "db_port": "bad"},
        )
        manager.create_token.side_effect = RuntimeError("do not expose")
        create_failure = await client.post(
            "/token/create",
            json={"token_id": "reader"},
        )

    assert invalid_json.status_code == 400
    assert invalid_json.json()["error"] == "Invalid JSON body"
    assert bad_query_database.status_code == 500
    assert bad_query_database.json()["error"] == "Internal server error"
    assert create_failure.status_code == 400
    assert create_failure.json()["error"] == "Token creation failed"


@pytest.mark.asyncio
async def test_create_token_reports_disabled_authentication():
    manager = _manager(enabled=False)

    async with _client(manager) as client:
        response = await client.post("/token/create", json={"token_id": "reader"})

    assert response.status_code == 503
    manager.create_token.assert_not_awaited()


@pytest.mark.asyncio
async def test_revoke_token_supports_query_and_path_outcomes():
    manager = _manager()

    async with _client(manager) as client:
        success = await client.delete("/token/revoke", params={"token_id": "reader"})
        manager.revoke_token.return_value = False
        not_found = await client.delete("/token/revoke/missing")
        missing = await client.delete("/token/revoke")

    assert success.status_code == 200
    assert success.json()["success"] is True
    assert not_found.status_code == 404
    assert not_found.json()["success"] is False
    assert missing.status_code == 400
    assert missing.json()["error"] == "token_id is required"
    assert manager.revoke_token.await_args_list[0].args == ("reader",)
    assert manager.revoke_token.await_args_list[1].args == ("missing",)


@pytest.mark.asyncio
async def test_revoke_token_reports_disabled_and_internal_failures():
    disabled = _manager(enabled=False)
    failing = _manager()
    failing.revoke_token.side_effect = RuntimeError("database unavailable")

    async with _client(disabled) as client:
        unavailable = await client.delete(
            "/token/revoke", params={"token_id": "reader"}
        )
    async with _client(failing) as client:
        failed = await client.delete("/token/revoke", params={"token_id": "reader"})

    assert unavailable.status_code == 503
    assert failed.status_code == 500
    assert failed.json()["error"] == "Internal server error"


@pytest.mark.asyncio
async def test_list_stats_and_cleanup_success_paths():
    manager = _manager()

    async with _client(manager) as client:
        listed = await client.get("/token/list")
        stats = await client.get("/token/stats")
        cleaned = await client.post("/token/cleanup")

    assert listed.json() == {
        "success": True,
        "count": 1,
        "tokens": [{"token_id": "reader"}],
    }
    assert stats.json() == {"success": True, "stats": {"active_tokens": 1}}
    assert cleaned.json() == {
        "success": True,
        "cleaned_count": 2,
        "message": "Cleaned up 2 expired tokens",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("path", "method", "mock_name"),
    [
        ("/token/list", "GET", "list_tokens"),
        ("/token/stats", "GET", "get_token_stats"),
        ("/token/cleanup", "POST", "cleanup_expired_tokens"),
    ],
)
async def test_list_stats_and_cleanup_hide_internal_failures(
    path: str,
    method: str,
    mock_name: str,
):
    manager = _manager()
    getattr(manager, mock_name).side_effect = RuntimeError("sensitive failure")

    async with _client(manager) as client:
        response = await client.request(method, path)

    assert response.status_code == 500
    assert response.json()["error"] == "Internal server error"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("path", "method"),
    [
        ("/token/list", "GET"),
        ("/token/stats", "GET"),
        ("/token/cleanup", "POST"),
    ],
)
async def test_read_and_cleanup_handlers_require_token_manager(path: str, method: str):
    manager = _manager(enabled=False)

    async with _client(manager) as client:
        response = await client.request(method, path)

    assert response.status_code == 503
    assert response.json()["error"] == "Token authentication is not enabled"
