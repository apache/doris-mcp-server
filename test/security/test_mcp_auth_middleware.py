import json

import pytest

import doris_mcp_server.auth.mcp_auth_middleware as middleware_module
from doris_mcp_server.auth.mcp_auth_middleware import MCPAuthASGIMiddleware
from doris_mcp_server.auth.oauth_token_validation import (
    OAuthAccessTokenValidationError,
)
from doris_mcp_server.auth.operation_policy import OperationAuthorizationError
from doris_mcp_server.utils.auth_credentials import BearerCredentials
from doris_mcp_server.utils.config import EffectiveAuthConfig
from doris_mcp_server.utils.security import AuthContext, get_current_auth_context


def _effective(
    auth_methods=("token",),
    discovery_mode="none",
    base_url="",
    *,
    external_issuer="https://issuer.example.test",
    external_resource="https://mcp.example.test/mcp",
    external_scopes=("tool:list", "resource:read"),
    external_required_scopes=("tool:list",),
):
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
        external_oauth_issuer=external_issuer,
        external_oauth_resource=external_resource,
        external_oauth_scopes=external_scopes,
        external_oauth_required_scopes=external_required_scopes,
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
        async def authenticate_request(self, credentials):
            assert credentials == BearerCredentials(
                scheme="bearer",
                token="abc",
                client_ip="127.0.0.1",
            )
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
async def test_mcp_auth_middleware_rejects_query_string_token():
    class SecurityManager:
        async def authenticate_request(self, credentials):
            assert credentials == BearerCredentials(client_ip="127.0.0.1")
            raise ValueError("missing bearer token")

    async def downstream(scope, receive, send):
        raise AssertionError("query-string credentials must not reach downstream")

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

    assert messages[0]["status"] == 401
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
async def test_external_oauth_missing_token_returns_discovery_challenge():
    class SecurityManager:
        async def authenticate_request(self, credentials):
            assert credentials.is_bearer is False
            raise ValueError("Missing external OAuth access token")

    async def downstream(scope, receive, send):
        raise AssertionError("downstream must not be called")

    messages = []
    middleware = MCPAuthASGIMiddleware(
        SecurityManager(),
        downstream,
        _effective(
            auth_methods=("external_oauth",),
            discovery_mode="external_oauth",
        ),
    )
    await middleware(
        {
            "type": "http",
            "path": "/mcp",
            "headers": [],
            "client": ("127.0.0.1", 1),
        },
        _receive,
        _send_collector(messages),
    )

    assert messages[0]["status"] == 401
    challenge = dict(messages[0]["headers"])[b"www-authenticate"]
    assert challenge.startswith(b"Bearer ")
    assert (
        b'resource_metadata="https://mcp.example.test/'
        b'.well-known/oauth-protected-resource"' in challenge
    )
    assert b'scope="tool:list"' in challenge
    assert b"error=" not in challenge
    body = json.loads(messages[1]["body"])
    assert body == {
        "error": "authentication_required",
        "error_description": "Authentication required",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("oauth_error", "status_code", "required_scopes"),
    [
        ("invalid_token", 401, ()),
        ("insufficient_scope", 403, ("tool:call:exec_query",)),
    ],
)
async def test_external_oauth_validation_error_preserves_bearer_challenge(
    oauth_error,
    status_code,
    required_scopes,
):
    secret = "must-not-leak"

    class SecurityManager:
        async def authenticate_request(self, credentials):
            assert credentials.token == secret
            raise OAuthAccessTokenValidationError(
                oauth_error,
                f"Controlled {oauth_error} description",
                required_scopes=required_scopes,
            )

    async def downstream(scope, receive, send):
        raise AssertionError("downstream must not be called")

    messages = []
    middleware = MCPAuthASGIMiddleware(
        SecurityManager(),
        downstream,
        _effective(
            auth_methods=("external_oauth",),
            discovery_mode="external_oauth",
        ),
    )
    await middleware(
        {
            "type": "http",
            "path": "/mcp",
            "headers": [
                (b"authorization", f"Bearer {secret}".encode())
            ],
            "client": ("127.0.0.1", 1),
        },
        _receive,
        _send_collector(messages),
    )

    assert messages[0]["status"] == status_code
    challenge = dict(messages[0]["headers"])[b"www-authenticate"]
    assert f'error="{oauth_error}"'.encode() in challenge
    assert b"oauth-protected-resource" in challenge
    if required_scopes:
        assert b'scope="tool:call:exec_query"' in challenge
    assert secret.encode() not in challenge
    assert secret.encode() not in messages[1]["body"]
    body = json.loads(messages[1]["body"])
    assert body["error"] == oauth_error


@pytest.mark.asyncio
async def test_external_oauth_generic_failure_does_not_expose_provider_detail():
    secret = "provider-reflected-secret"

    class SecurityManager:
        async def authenticate_request(self, credentials):
            raise RuntimeError(f"introspection backend echoed {secret}")

    async def downstream(scope, receive, send):
        raise AssertionError("downstream must not be called")

    messages = []
    middleware = MCPAuthASGIMiddleware(
        SecurityManager(),
        downstream,
        _effective(
            auth_methods=("external_oauth",),
            discovery_mode="external_oauth",
        ),
    )
    await middleware(
        {
            "type": "http",
            "path": "/mcp",
            "headers": [(b"authorization", f"Bearer {secret}".encode())],
            "client": ("127.0.0.1", 1),
        },
        _receive,
        _send_collector(messages),
    )

    assert messages[0]["status"] == 401
    challenge = dict(messages[0]["headers"])[b"www-authenticate"]
    assert b'error="invalid_token"' in challenge
    assert secret.encode() not in challenge
    assert secret.encode() not in messages[1]["body"]
    assert json.loads(messages[1]["body"]) == {
        "error": "invalid_token",
        "error_description": "Invalid access token",
    }


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
async def test_external_oauth_operation_denial_returns_step_up_challenge():
    auth_context = AuthContext(
        token_id="t1",
        user_id="alice",
        auth_method="external_oauth",
        oauth_scopes=["tool:list"],
    )

    class SecurityManager:
        async def authenticate_request(self, credentials):
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
            auth_methods=("external_oauth",),
            discovery_mode="external_oauth",
        ),
    )
    await middleware(
        {
            "type": "http",
            "path": "/mcp",
            "headers": [(b"authorization", b"Bearer external-token")],
            "client": ("127.0.0.1", 1),
        },
        _receive,
        _send_collector(messages),
    )

    assert messages[0]["status"] == 403
    challenge = dict(messages[0]["headers"])[b"www-authenticate"]
    assert b'error="insufficient_scope"' in challenge
    assert b'scope="tool:call:exec_query"' in challenge
    assert b"oauth-protected-resource" in challenge


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
