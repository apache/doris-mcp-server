import json

import pytest

import doris_mcp_server.auth.mcp_auth_middleware as middleware_module
from doris_mcp_server.auth.mcp_auth_middleware import MCPAuthASGIMiddleware
from doris_mcp_server.auth.operation_policy import OperationAuthorizationError
from doris_mcp_server.utils.config import EffectiveAuthConfig
from doris_mcp_server.utils.security import AuthContext, get_current_auth_context


def _effective(auth_methods=("token",), discovery_mode="none", base_url=""):
    return EffectiveAuthConfig(
        enable_token_auth="token" in auth_methods,
        enable_jwt_auth="jwt" in auth_methods,
        enable_external_oauth_auth="external_oauth" in auth_methods,
        enable_doris_oauth_auth="doris_oauth" in auth_methods,
        auth_methods=tuple(auth_methods),
        oauth_discovery_mode=discovery_mode,
        doris_oauth_base_url=base_url,
        transport="http",
        requested_workers=1,
        effective_workers=1,
        legacy_auth_type="",
    )


async def _receive():
    return {"type": "http.request", "body": b"", "more_body": False}


def _send_collector(messages):
    async def send(message):
        messages.append(message)

    return send


@pytest.mark.asyncio
async def test_mcp_auth_middleware_sets_scope_and_resets_context():
    auth_context = AuthContext(token_id="t1", user_id="u1", auth_method="token")

    class SecurityManager:
        async def authenticate_request(self, auth_info):
            assert auth_info["token"] == "abc"
            return auth_context

    async def downstream(scope, receive, send):
        assert scope["auth_context"] is auth_context
        assert get_current_auth_context() is auth_context
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    messages = []
    middleware = MCPAuthASGIMiddleware(SecurityManager(), downstream, _effective())
    await middleware(
        {
            "type": "http",
            "path": "/mcp",
            "headers": [(b"authorization", b"Bearer abc")],
            "client": ("127.0.0.1", 1),
        },
        _receive,
        _send_collector(messages),
    )

    assert messages[0]["status"] == 200
    assert get_current_auth_context() is None


@pytest.mark.asyncio
async def test_mcp_auth_middleware_accepts_legacy_query_string_token():
    auth_context = AuthContext(token_id="t1", user_id="u1", auth_method="token")

    class SecurityManager:
        async def authenticate_request(self, auth_info):
            assert auth_info["token"] == "legacy-query-token"
            assert auth_info["authorization"] == ""
            return auth_context

    async def downstream(scope, receive, send):
        assert scope["auth_context"] is auth_context
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    messages = []
    middleware = MCPAuthASGIMiddleware(SecurityManager(), downstream, _effective())
    await middleware(
        {
            "type": "http",
            "path": "/mcp",
            "query_string": b"token=legacy-query-token",
            "headers": [],
            "client": ("127.0.0.1", 1),
        },
        _receive,
        _send_collector(messages),
    )

    assert messages[0]["status"] == 200
    assert get_current_auth_context() is None


@pytest.mark.asyncio
async def test_mcp_auth_middleware_returns_doris_oauth_challenge_on_401():
    class SecurityManager:
        async def authenticate_request(self, auth_info):
            raise ValueError("missing")

    async def downstream(scope, receive, send):
        raise AssertionError("downstream must not be called")

    messages = []
    middleware = MCPAuthASGIMiddleware(
        SecurityManager(),
        downstream,
        _effective(
            auth_methods=("doris_oauth",),
            discovery_mode="doris_oauth",
            base_url="https://mcp.example.test",
        ),
    )
    await middleware(
        {"type": "http", "path": "/mcp", "headers": [], "client": ("127.0.0.1", 1)},
        _receive,
        _send_collector(messages),
    )

    assert messages[0]["status"] == 401
    headers = dict(messages[0]["headers"])
    assert b"www-authenticate" in headers
    assert b"oauth-protected-resource" in headers[b"www-authenticate"]
    assert b"https://mcp.example.test/.well-known/oauth-protected-resource" in headers[b"www-authenticate"]
    body = json.loads(messages[1]["body"])
    assert body["error"] == "authentication_required"


@pytest.mark.asyncio
async def test_mcp_auth_middleware_returns_insufficient_scope_challenge_on_operation_denial():
    auth_context = AuthContext(
        token_id="t1",
        user_id="alice",
        auth_method="doris_oauth",
        doris_user="alice",
        oauth_scopes=["tool:list"],
    )

    class SecurityManager:
        async def authenticate_request(self, auth_info):
            return auth_context

    async def downstream(scope, receive, send):
        raise OperationAuthorizationError(
            "Missing required scope",
            status_code=403,
            error_code="PERMISSION_DENIED",
            required_scope="tool:call:exec_query",
            operation="tool:exec_query",
        )

    messages = []
    middleware = MCPAuthASGIMiddleware(
        SecurityManager(),
        downstream,
        _effective(
            auth_methods=("doris_oauth",),
            discovery_mode="doris_oauth",
            base_url="https://mcp.example.test",
        ),
    )
    await middleware(
        {"type": "http", "path": "/mcp", "headers": [(b"authorization", b"Bearer doa_x")], "client": ("127.0.0.1", 1)},
        _receive,
        _send_collector(messages),
    )

    assert messages[0]["status"] == 403
    headers = dict(messages[0]["headers"])
    assert b"insufficient_scope" in headers[b"www-authenticate"]
    assert b"tool:call:exec_query" in headers[b"www-authenticate"]
    body = json.loads(messages[1]["body"])
    assert body["error"] == "PERMISSION_DENIED"


@pytest.mark.asyncio
async def test_mcp_auth_middleware_resets_context_on_verify_failure(monkeypatch):
    auth_context = AuthContext(token_id="t1", user_id="u1", auth_method="token")

    class SecurityManager:
        async def authenticate_request(self, auth_info):
            return auth_context

    async def downstream(scope, receive, send):
        raise AssertionError("downstream must not be called")

    monkeypatch.setattr(
        middleware_module,
        "get_current_auth_context",
        lambda: AuthContext(token_id="different", auth_method="token"),
    )

    messages = []
    middleware = MCPAuthASGIMiddleware(SecurityManager(), downstream, _effective())
    await middleware(
        {"type": "http", "path": "/mcp", "headers": [], "client": ("127.0.0.1", 1)},
        _receive,
        _send_collector(messages),
    )

    assert messages[0]["status"] == 500
    assert get_current_auth_context() is None


@pytest.mark.asyncio
async def test_mcp_auth_middleware_force_clears_context_when_reset_fails(monkeypatch):
    auth_context = AuthContext(token_id="t1", user_id="u1", auth_method="token")

    class SecurityManager:
        async def authenticate_request(self, auth_info):
            return auth_context

    async def downstream(scope, receive, send):
        assert get_current_auth_context() is auth_context
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    def broken_reset(token):
        raise RuntimeError("reset failed")

    monkeypatch.setattr(middleware_module, "reset_auth_context", broken_reset)

    messages = []
    middleware = MCPAuthASGIMiddleware(SecurityManager(), downstream, _effective())
    await middleware(
        {"type": "http", "path": "/mcp", "headers": [], "client": ("127.0.0.1", 1)},
        _receive,
        _send_collector(messages),
    )

    assert messages[0]["status"] == 200
    assert get_current_auth_context() is None
