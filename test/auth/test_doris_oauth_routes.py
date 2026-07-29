import asyncio
import base64
import hashlib
import re
import time
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from starlette.applications import Starlette

from doris_mcp_server.auth.doris_oauth_handlers import DorisOAuthHandlers
from doris_mcp_server.auth.doris_oauth_provider import DorisOAuthProvider
from doris_mcp_server.auth.doris_oauth_types import (
    ProtectedResourceAuthError,
    TokenEndpointError,
)
from doris_mcp_server.utils.auth_credentials import BearerCredentials
from doris_mcp_server.utils.config import (
    DorisConfig,
    _mark_source,
    normalize_effective_auth_config,
)

FULL_DORIS_OAUTH_SCOPE_SET = tuple(
    sorted(
        {
            "tool:list",
            "resource:list",
            "resource:read",
            "tool:call:get_db_list",
            "tool:call:get_db_table_list",
            "tool:call:get_table_schema",
            "tool:call:get_table_comment",
            "tool:call:get_table_column_comments",
            "tool:call:get_table_indexes",
            "tool:call:get_catalog_list",
            "tool:call:exec_query",
            "tool:call:get_sql_explain",
        }
    )
)


class FakeConnectionManager:
    def __init__(self):
        self.pools = {}
        self.create_calls = []
        self.cleanup_calls = []
        self.has_pool_calls = []
        self.global_acquire_calls = 0

    async def create_or_replace_doris_user_pool(self, username, password):
        self.create_calls.append((username, password))
        if password == "bad":
            raise RuntimeError("invalid credentials")
        self.pools[username] = True

    def has_doris_user_pool(self, username):
        self.has_pool_calls.append(username)
        return self.pools.get(username, False)

    async def cleanup_idle_doris_user_pools(self, active_users):
        self.cleanup_calls.append(set(active_users))


def _pkce(verifier="verifier-123"):
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("="), verifier


def _config(
    *,
    db_tools_enabled=False,
    allowlist=None,
    query_tools_enabled=False,
    explain_tools_enabled=False,
):
    config = DorisConfig()
    config.transport = "http"
    _mark_source(config, "transport", "test")
    config.security.enable_doris_oauth_auth = True
    _mark_source(config, "enable_doris_oauth_auth", "test")
    config.security.doris_oauth_base_url = "http://localhost:3000"
    config.security.doris_oauth_db_tools_enabled = db_tools_enabled
    if allowlist is not None:
        config.security.doris_oauth_db_tool_allowlist = list(allowlist)
    config.security.doris_oauth_query_tools_enabled = query_tools_enabled
    config.security.doris_oauth_explain_tools_enabled = explain_tools_enabled
    config.security.doris_oauth_access_token_expire_seconds = 900
    config.security.doris_oauth_refresh_token_expire_seconds = 86400
    normalize_effective_auth_config(config, requested_workers=1)
    return config


def _provider_app(config=None):
    cm = FakeConnectionManager()
    provider = DorisOAuthProvider(config or _config())
    provider.configure_connection_manager(cm)
    return provider, cm, Starlette(routes=DorisOAuthHandlers(provider).routes())


async def _client(app):
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://localhost:3000", follow_redirects=False)


def _authorization_response_query(response, expected_issuer):
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["iss"] == [expected_issuer]
    return query


def _native_registration(redirect_uri="http://localhost:7777/callback", **metadata):
    return {
        "application_type": "native",
        "redirect_uris": [redirect_uri],
        **metadata,
    }


@pytest.mark.asyncio
async def test_authorization_server_metadata_advertises_response_issuer():
    provider, _cm, app = _provider_app()

    async with await _client(app) as client:
        response = await client.get("/.well-known/oauth-authorization-server")

    assert response.status_code == 200
    metadata = response.json()
    assert metadata["issuer"] == provider.issuer
    assert metadata["authorization_response_iss_parameter_supported"] is True
    assert metadata["client_id_metadata_document_supported"] is True
    assert "registration_endpoint" in metadata


@pytest.mark.parametrize(
    "metadata",
    [
        pytest.param({}, id="missing"),
        pytest.param({"application_type": None}, id="null"),
        pytest.param({"application_type": ""}, id="blank"),
        pytest.param({"application_type": "desktop"}, id="unsupported"),
        pytest.param({"application_type": 1}, id="non-string"),
    ],
)
@pytest.mark.asyncio
async def test_register_requires_supported_application_type(metadata):
    _provider, _cm, app = _provider_app()
    payload = {
        "redirect_uris": ["http://localhost:7777/callback"],
        **metadata,
    }

    async with await _client(app) as client:
        response = await client.post("/oauth/register", json=payload)

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_client_metadata"


@pytest.mark.parametrize(
    ("application_type", "redirect_uri"),
    [
        pytest.param(
            "native",
            "http://localhost:7777/callback",
            id="native-localhost",
        ),
        pytest.param(
            "native",
            "http://127.0.0.2:7777/callback",
            id="native-loopback-ip",
        ),
        pytest.param(
            "native",
            "org.apache.doris.mcp:/oauth/callback",
            id="native-custom-scheme",
        ),
        pytest.param("web", "https://client.example.com/callback", id="web-https"),
    ],
)
@pytest.mark.asyncio
async def test_register_persists_application_type(application_type, redirect_uri):
    provider, _cm, app = _provider_app()
    async with await _client(app) as client:
        response = await client.post(
            "/oauth/register",
            json={
                "application_type": application_type,
                "redirect_uris": [redirect_uri],
            },
        )

    assert response.status_code == 201
    body = response.json()
    assert body["application_type"] == application_type
    assert body["redirect_uris"] == [redirect_uri]
    record = provider.store.get_client(body["client_id"])
    assert record is not None
    assert record.application_type == application_type


@pytest.mark.parametrize(
    ("application_type", "redirect_uri"),
    [
        pytest.param(
            "native",
            "https://client.example.com/callback",
            id="native-https",
        ),
        pytest.param(
            "native",
            "http://client.example.com/callback",
            id="native-remote-http",
        ),
        pytest.param(
            "native",
            "myapp:/oauth/callback",
            id="native-non-domain-custom-scheme",
        ),
        pytest.param(
            "native",
            "javascript:alert(1)",
            id="native-unsafe-scheme",
        ),
        pytest.param(
            "web",
            "http://localhost:7777/callback",
            id="web-loopback-http",
        ),
        pytest.param(
            "web",
            "https://localhost:7777/callback",
            id="web-loopback-https",
        ),
        pytest.param(
            "web",
            "org.apache.doris.mcp:/oauth/callback",
            id="web-custom-scheme",
        ),
    ],
)
@pytest.mark.asyncio
async def test_register_rejects_redirect_uri_for_other_application_type(
    application_type,
    redirect_uri,
):
    _provider, _cm, app = _provider_app()
    async with await _client(app) as client:
        response = await client.post(
            "/oauth/register",
            json={
                "application_type": application_type,
                "redirect_uris": [redirect_uri],
            },
        )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_redirect_uri"


@pytest.mark.parametrize(
    "redirect_uris",
    [
        pytest.param([], id="empty"),
        pytest.param("https://client.example.com/callback", id="not-an-array"),
        pytest.param([123], id="non-string-entry"),
        pytest.param(
            ["https://client.example.com:invalid/callback"],
            id="malformed-port",
        ),
        pytest.param(
            ["https://client.example.com/callback#fragment"],
            id="fragment",
        ),
        pytest.param(
            ["https://user:secret@client.example.com/callback"],
            id="credentials",
        ),
        pytest.param(
            ["https://*.example.com/callback"],
            id="wildcard",
        ),
        pytest.param(
            [
                "https://client.example.com/callback",
                "https://localhost:7777/callback",
            ],
            id="mixed-web-and-loopback",
        ),
    ],
)
@pytest.mark.asyncio
async def test_register_rejects_malformed_redirect_metadata_without_persisting(
    redirect_uris,
):
    provider, _cm, app = _provider_app()
    async with await _client(app) as client:
        response = await client.post(
            "/oauth/register",
            json={
                "application_type": "web",
                "redirect_uris": redirect_uris,
            },
        )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_redirect_uri"
    assert provider.store.clients_by_id == {}


@pytest.mark.asyncio
async def test_register_omitted_and_blank_scope_allow_safe_client_scope_set():
    _provider, _cm, app = _provider_app()
    async with await _client(app) as client:
        response = await client.post(
            "/oauth/register",
            json=_native_registration(),
        )
        assert response.status_code == 201
        assert response.json()["scope"] == "resource:list resource:read tool:list"

        response = await client.post(
            "/oauth/register",
            json=_native_registration(
                "http://localhost:7778/callback",
                scope="",
            ),
        )
        assert response.status_code == 201
        assert response.json()["scope"] == "resource:list resource:read tool:list"


@pytest.mark.asyncio
async def test_register_omitted_scope_client_allowlist_includes_safe_metadata_when_db_gate_true():
    config = _config(db_tools_enabled=True, allowlist=["get_db_list"])
    _provider, _cm, app = _provider_app(config)
    async with await _client(app) as client:
        response = await client.post(
            "/oauth/register",
            json=_native_registration(),
        )

    assert response.status_code == 201
    assert response.json()["scope"] == "resource:list resource:read tool:call:get_db_list tool:list"


@pytest.mark.asyncio
async def test_register_explicit_unknown_or_forbidden_scope_is_invalid_scope():
    _provider, _cm, app = _provider_app()
    async with await _client(app) as client:
        response = await client.post(
            "/oauth/register",
            json={
                "application_type": "native",
                "redirect_uris": ["http://localhost:7777/callback"],
                "scope": "tool:list scope:admin unknown",
            },
        )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_scope"


@pytest.mark.asyncio
async def test_register_metadata_scope_requires_db_gate():
    _provider, _cm, app = _provider_app()
    async with await _client(app) as client:
        response = await client.post(
            "/oauth/register",
            json={
                "application_type": "native",
                "redirect_uris": ["http://localhost:7777/callback"],
                "scope": "tool:list tool:call:get_db_list",
            },
        )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_scope"


@pytest.mark.asyncio
async def test_register_metadata_scope_allowed_when_db_gate_true_and_explicit():
    config = _config(db_tools_enabled=True, allowlist=["get_db_list"])
    _provider, _cm, app = _provider_app(config)
    async with await _client(app) as client:
        response = await client.post(
            "/oauth/register",
            json={
                "application_type": "native",
                "redirect_uris": ["http://localhost:7777/callback"],
                "scope": "tool:list tool:call:get_db_list",
            },
        )

    assert response.status_code == 201
    assert response.json()["scope"] == "tool:call:get_db_list tool:list"


@pytest.mark.asyncio
async def test_register_resource_scopes_allowed_explicitly_without_metadata_gate():
    _provider, _cm, app = _provider_app()
    async with await _client(app) as client:
        metadata = await client.get("/.well-known/oauth-protected-resource")
        response = await client.post(
            "/oauth/register",
            json={
                "application_type": "native",
                "redirect_uris": ["http://localhost:7777/callback"],
                "scope": "tool:list resource:list resource:read",
            },
        )

    assert "resource:list" in metadata.json()["scopes_supported"]
    assert "resource:read" in metadata.json()["scopes_supported"]
    assert response.status_code == 201
    assert response.json()["scope"] == "resource:list resource:read tool:list"


@pytest.mark.asyncio
async def test_authorize_can_request_resource_scopes_after_dcr_omits_scope():
    provider, _cm, app = _provider_app()
    async with await _client(app) as client:
        register = await client.post(
            "/oauth/register",
            json=_native_registration(),
        )
        client_id = register.json()["client_id"]
        challenge, _verifier = _pkce()
        authorize = await client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": "http://localhost:7777/callback",
                "state": "state-resource",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "scope": "tool:list resource:list resource:read",
            },
        )

    assert authorize.status_code == 302
    assert authorize.headers["location"].startswith("/doris-login?")
    txn_id = parse_qs(urlparse(authorize.headers["location"]).query)["txn_id"][0]
    transaction = provider.get_login_transaction(txn_id)
    assert transaction.candidate_granted_scopes == (
        "resource:list",
        "resource:read",
        "tool:list",
    )


@pytest.mark.parametrize("scope", ["tool:call:exec_query", "tool:call:get_sql_explain"])
@pytest.mark.asyncio
async def test_register_query_and_explain_scopes_require_their_own_gates(scope):
    config = _config(db_tools_enabled=True, allowlist=["get_db_list"])
    _provider, _cm, app = _provider_app(config)
    async with await _client(app) as client:
        response = await client.post(
            "/oauth/register",
            json={
                "application_type": "native",
                "redirect_uris": ["http://localhost:7777/callback"],
                "scope": f"tool:list {scope}",
            },
        )

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_scope"


@pytest.mark.asyncio
async def test_register_omitted_scope_client_allowlist_includes_query_and_explain_when_enabled():
    config = _config(
        db_tools_enabled=True,
        allowlist=["get_db_list"],
        query_tools_enabled=True,
        explain_tools_enabled=True,
    )
    _provider, _cm, app = _provider_app(config)
    async with await _client(app) as client:
        response = await client.post(
            "/oauth/register",
            json=_native_registration(),
        )

    assert response.status_code == 201
    assert response.json()["scope"] == (
        "resource:list resource:read tool:call:exec_query "
        "tool:call:get_db_list tool:call:get_sql_explain tool:list"
    )


@pytest.mark.asyncio
async def test_register_short_tool_scope_aliases_are_canonicalized_when_enabled():
    config = _config(
        db_tools_enabled=True,
        allowlist=["get_db_list"],
        query_tools_enabled=True,
        explain_tools_enabled=True,
    )
    _provider, _cm, app = _provider_app(config)
    async with await _client(app) as client:
        response = await client.post(
            "/oauth/register",
            json={
                "application_type": "native",
                "redirect_uris": ["http://localhost:7777/callback"],
                "scope": "tool:list get_db_list exec_query get_sql_explain",
            },
        )

    assert response.status_code == 201
    assert response.json()["scope"] == (
        "tool:call:exec_query tool:call:get_db_list "
        "tool:call:get_sql_explain tool:list"
    )


@pytest.mark.asyncio
async def test_authorize_omitted_scope_grants_configured_server_allowlist():
    provider, _cm, app = _provider_app(
        _config(
            db_tools_enabled=True,
            allowlist=["get_db_list"],
            query_tools_enabled=True,
            explain_tools_enabled=True,
        )
    )
    async with await _client(app) as client:
        register = await client.post(
            "/oauth/register",
            json=_native_registration(),
        )
        client_id = register.json()["client_id"]
        challenge, _verifier = _pkce()
        authorize = await client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": "http://localhost:7777/callback",
                "state": "state-default",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )

    assert authorize.status_code == 302
    txn_id = parse_qs(urlparse(authorize.headers["location"]).query)["txn_id"][0]
    transaction = provider.get_login_transaction(txn_id)
    assert transaction.candidate_granted_scopes == (
        "resource:list",
        "resource:read",
        "tool:call:exec_query",
        "tool:call:get_db_list",
        "tool:call:get_sql_explain",
        "tool:list",
    )


@pytest.mark.asyncio
async def test_authorize_short_tool_scope_aliases_are_canonicalized_when_enabled():
    provider, _cm, app = _provider_app(
        _config(
            db_tools_enabled=True,
            allowlist=["get_db_list"],
            query_tools_enabled=True,
            explain_tools_enabled=True,
        )
    )
    async with await _client(app) as client:
        register = await client.post(
            "/oauth/register",
            json=_native_registration(),
        )
        client_id = register.json()["client_id"]
        challenge, _verifier = _pkce()
        authorize = await client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": "http://localhost:7777/callback",
                "state": "state-alias",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "scope": "tool:list get_db_list exec_query get_sql_explain",
            },
        )

    assert authorize.status_code == 302
    txn_id = parse_qs(urlparse(authorize.headers["location"]).query)["txn_id"][0]
    transaction = provider.get_login_transaction(txn_id)
    assert transaction.requested_scopes == (
        "tool:list",
        "tool:call:get_db_list",
        "tool:call:exec_query",
        "tool:call:get_sql_explain",
    )
    assert transaction.candidate_granted_scopes == (
        "tool:call:exec_query",
        "tool:call:get_db_list",
        "tool:call:get_sql_explain",
        "tool:list",
    )


@pytest.mark.asyncio
async def test_expired_dcr_clients_do_not_count_against_capacity():
    config = _config()
    config.security.doris_oauth_dcr_max_clients = 1
    cm = FakeConnectionManager()
    provider = DorisOAuthProvider(config)
    provider.configure_connection_manager(cm)
    provider.store.add_client(
        client_id="expired-dcr",
        client_secret=None,
        token_endpoint_auth_method="none",
        application_type="native",
        redirect_uris=("http://localhost:7000/callback",),
        client_allowed_scopes=("tool:list",),
        source="dcr",
        expires_at=time.time() - 1,
    )
    app = Starlette(routes=DorisOAuthHandlers(provider).routes())

    async with await _client(app) as client:
        response = await client.post(
            "/oauth/register",
            json=_native_registration(),
        )

    assert response.status_code == 201
    assert "expired-dcr" not in provider.store.clients_by_id


@pytest.mark.asyncio
async def test_authorize_invalid_redirect_is_direct_400_and_invalid_scope_redirects():
    provider, _cm, app = _provider_app()
    client_record = provider.store.add_client(
        client_id="client-1",
        client_secret=None,
        token_endpoint_auth_method="none",
        application_type="native",
        redirect_uris=("http://localhost:7777/callback",),
        client_allowed_scopes=("tool:list",),
        source="dcr",
        expires_at=None,
    )
    challenge, _verifier = _pkce()

    async with await _client(app) as client:
        response = await client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": client_record.client_id,
                "redirect_uri": "http://localhost:8888/callback",
                "state": "state-1",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": provider.resource,
            },
        )
        assert response.status_code == 400
        assert "location" not in response.headers

        response = await client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": client_record.client_id,
                "redirect_uri": "http://localhost:7777/callback",
                "state": "state-2",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "scope": "unknown",
            },
        )

    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith("http://localhost:7777/callback")
    query = _authorization_response_query(response, provider.issuer)
    assert query["error"] == ["invalid_scope"]
    assert query["state"] == ["state-2"]


@pytest.mark.parametrize(
    ("overrides", "expected_error"),
    [
        pytest.param(
            {"response_type": "token"},
            "unsupported_response_type",
            id="unsupported-response-type",
        ),
        pytest.param(
            {"code_challenge_method": "plain"},
            "invalid_request",
            id="invalid-pkce",
        ),
        pytest.param(
            {"resource": "http://localhost:3000/not-the-mcp-resource"},
            "invalid_target",
            id="invalid-resource",
        ),
        pytest.param(
            {"scope": "unknown"},
            "invalid_scope",
            id="invalid-scope",
        ),
    ],
)
@pytest.mark.asyncio
async def test_redirected_authorization_errors_identify_exact_issuer(
    overrides,
    expected_error,
):
    provider, _cm, app = _provider_app()
    client_record = provider.store.add_client(
        client_id="client-issuer-errors",
        client_secret=None,
        token_endpoint_auth_method="none",
        application_type="native",
        redirect_uris=("http://localhost:7777/callback",),
        client_allowed_scopes=("tool:list",),
        source="dcr",
        expires_at=None,
    )
    challenge, _verifier = _pkce()
    params = {
        "response_type": "code",
        "client_id": client_record.client_id,
        "redirect_uri": "http://localhost:7777/callback",
        "state": "state-issuer",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        **overrides,
    }

    async with await _client(app) as client:
        response = await client.get("/oauth/authorize", params=params)

    assert response.status_code == 302
    query = _authorization_response_query(response, provider.issuer)
    assert query["error"] == [expected_error]
    assert query["state"] == ["state-issuer"]


@pytest.mark.asyncio
async def test_full_login_code_exchange_auth_context_and_pool_missing_revocation():
    provider, cm, app = _provider_app()
    async with await _client(app) as client:
        register = await client.post(
            "/oauth/register",
            json=_native_registration(),
        )
        client_id = register.json()["client_id"]
        challenge, verifier = _pkce()
        authorize = await client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": "http://localhost:7777/callback",
                "state": "state-1",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        assert authorize.status_code == 302

        login_get = await client.get(authorize.headers["location"])
        assert login_get.status_code == 200
        assert "<title>doris</title>" in login_get.text
        assert "<h2>doris</h2>" in login_get.text
        assert "Doris Username" in login_get.text
        assert "Doris Password" in login_get.text
        assert "httponly" in login_get.headers["set-cookie"].lower()
        assert "samesite=lax" in login_get.headers["set-cookie"].lower()
        assert "path=/doris-login" in login_get.headers["set-cookie"].lower()
        csrf = re.search(r'name="login_csrf" value="([^"]+)"', login_get.text).group(1)
        txn_id = re.search(r'name="txn_id" value="([^"]+)"', login_get.text).group(1)

        login_post = await client.post(
            "/doris-login",
            data={
                "txn_id": txn_id,
                "login_csrf": csrf,
                "username": "alice",
                "password": "correct",
            },
        )
        assert cm.create_calls == [("alice", "correct")]
        authorization_response = _authorization_response_query(
            login_post,
            provider.issuer,
        )
        assert authorization_response["state"] == ["state-1"]
        code = authorization_response["code"][0]

        token_response = await client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": code,
                "redirect_uri": "http://localhost:7777/callback",
                "code_verifier": verifier,
                "resource": provider.resource,
            },
        )
        assert token_response.status_code == 200
        token_json = token_response.json()
        assert token_json["access_token"].startswith("doa_")
        assert token_json["scope"] == "resource:list resource:read tool:list"

    credentials = BearerCredentials(
        scheme="bearer",
        token=token_json["access_token"],
    )
    auth_context = await provider.authenticate_access_token(credentials)
    assert auth_context.auth_method == "doris_oauth"
    assert auth_context.doris_user == "alice"
    assert auth_context.oauth_client_id == client_id
    assert auth_context.oauth_scopes == ["resource:list", "resource:read", "tool:list"]
    assert auth_context.oauth_issuer == provider.issuer
    assert auth_context.oauth_resource == provider.resource
    assert auth_context.oauth_audiences == [provider.resource]
    assert auth_context.pool_key == "doris_user:alice"
    assert auth_context.token == ""

    cm.pools["alice"] = False
    with pytest.raises(ProtectedResourceAuthError) as exc:
        await provider.authenticate_access_token(credentials)
    assert exc.value.error == "login_required"
    assert exc.value.error_code == "DORIS_OAUTH_POOL_MISSING"
    assert cm.global_acquire_calls == 0

    cm.pools["alice"] = True
    with pytest.raises(ProtectedResourceAuthError):
        await provider.authenticate_access_token(credentials)


@pytest.mark.asyncio
async def test_access_token_for_other_resource_is_rejected_before_pool_access():
    provider, cm, _app = _provider_app()
    pair = provider.store.issue_token_pair(
        client_id="resource-bound-client",
        doris_user="alice",
        scopes=("tool:list",),
        resource=provider.issuer,
        access_ttl_seconds=900,
        refresh_ttl_seconds=86400,
    )
    cm.pools["alice"] = True
    credentials = BearerCredentials(
        scheme="bearer",
        token=pair.access_token,
    )

    with pytest.raises(ProtectedResourceAuthError) as exc_info:
        await provider.authenticate_access_token(credentials)

    assert exc_info.value.status_code == 401
    assert exc_info.value.challenge_error == "invalid_token"
    assert exc_info.value.error_code == "DORIS_OAUTH_RESOURCE_MISMATCH"
    assert cm.has_pool_calls == []
    assert provider.store.get_access_token(pair.access_token).revoked_at is None
    assert provider.store.get_access_token(pair.access_token).last_used_at is None


@pytest.mark.parametrize(
    "token_resource",
    [
        pytest.param(None, id="missing"),
        pytest.param("http://localhost:3000", id="different-resource"),
    ],
)
@pytest.mark.asyncio
async def test_authorization_code_exchange_rejects_unbound_resource(
    token_resource,
):
    provider, _cm, app = _provider_app()
    client_record = provider.store.add_client(
        client_id="resource-exchange-client",
        client_secret=None,
        token_endpoint_auth_method="none",
        application_type="native",
        redirect_uris=("http://localhost:7777/callback",),
        client_allowed_scopes=("tool:list",),
        source="dcr",
        expires_at=None,
    )
    challenge, verifier = _pkce()
    code, _record = provider.store.create_authorization_code(
        client_id=client_record.client_id,
        doris_user="alice",
        redirect_uri="http://localhost:7777/callback",
        scopes=("tool:list",),
        resource=provider.resource,
        code_challenge=challenge,
        code_challenge_method="S256",
        ttl_seconds=300,
    )
    payload = {
        "grant_type": "authorization_code",
        "client_id": client_record.client_id,
        "code": code,
        "redirect_uri": "http://localhost:7777/callback",
        "code_verifier": verifier,
    }
    if token_resource is not None:
        payload["resource"] = token_resource

    async with await _client(app) as client:
        response = await client.post("/oauth/token", data=payload)

    assert response.status_code == 400
    assert response.json()["error"] == "invalid_target"
    assert provider.store.access_by_hash == {}
    assert provider.store.refresh_by_hash == {}
    assert provider.store.pop_authorization_code(code) is None


@pytest.mark.asyncio
async def test_full_login_without_scope_grants_configured_rbac_capability_envelope():
    provider, cm, app = _provider_app(
        _config(
            db_tools_enabled=True,
            query_tools_enabled=True,
            explain_tools_enabled=True,
        )
    )
    async with await _client(app) as client:
        register = await client.post(
            "/oauth/register",
            json=_native_registration(),
        )
        client_id = register.json()["client_id"]
        challenge, verifier = _pkce()
        authorize = await client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": "http://localhost:7777/callback",
                "state": "state-full-default",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": provider.resource,
            },
        )
        assert authorize.status_code == 302

        login_get = await client.get(authorize.headers["location"])
        csrf = re.search(r'name="login_csrf" value="([^"]+)"', login_get.text).group(1)
        txn_id = re.search(r'name="txn_id" value="([^"]+)"', login_get.text).group(1)

        login_post = await client.post(
            "/doris-login",
            data={
                "txn_id": txn_id,
                "login_csrf": csrf,
                "username": "alice",
                "password": "correct",
            },
        )
        code = parse_qs(urlparse(login_post.headers["location"]).query)["code"][0]

        token_response = await client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": code,
                "redirect_uri": "http://localhost:7777/callback",
                "code_verifier": verifier,
                "resource": provider.resource,
            },
        )

    assert cm.create_calls == [("alice", "correct")]
    assert token_response.status_code == 200
    token_json = token_response.json()
    assert tuple(token_json["scope"].split()) == FULL_DORIS_OAUTH_SCOPE_SET
    assert "*" not in token_json["scope"].split()
    assert "scope:admin" not in token_json["scope"].split()
    assert "scope:profile:read" not in token_json["scope"].split()
    assert "scope:monitoring:read" not in token_json["scope"].split()
    assert "scope:adbc:execute" not in token_json["scope"].split()

    auth_context = await provider.authenticate_access_token(
        BearerCredentials(
            scheme="bearer",
            token=token_json["access_token"],
        )
    )
    assert auth_context.auth_method == "doris_oauth"
    assert auth_context.doris_user == "alice"
    assert tuple(auth_context.oauth_scopes) == FULL_DORIS_OAUTH_SCOPE_SET
    assert auth_context.doris_oauth_db_tools_enabled is True
    assert auth_context.doris_oauth_query_tools_enabled is True
    assert auth_context.doris_oauth_explain_tools_enabled is True
    assert auth_context.pool_key == "doris_user:alice"
    assert auth_context.token == ""


@pytest.mark.asyncio
async def test_token_endpoint_invalid_code_invalid_client_refresh_pool_missing_and_revoke_unknown():
    provider, cm, app = _provider_app()
    public_client = provider.store.add_client(
        client_id="public",
        client_secret=None,
        token_endpoint_auth_method="none",
        application_type="native",
        redirect_uris=("http://localhost:7777/callback",),
        client_allowed_scopes=("tool:list",),
        source="dcr",
        expires_at=None,
    )
    provider.store.add_client(
        client_id="secret-client",
        client_secret="dos_secret",
        token_endpoint_auth_method="client_secret_post",
        application_type="native",
        redirect_uris=("http://localhost:7778/callback",),
        client_allowed_scopes=("tool:list",),
        source="dcr",
        expires_at=None,
    )
    pair = provider.store.issue_token_pair(
        client_id=public_client.client_id,
        doris_user="alice",
        scopes=("tool:list",),
        resource=provider.resource,
        access_ttl_seconds=900,
        refresh_ttl_seconds=86400,
    )
    cm.pools["alice"] = False

    async with await _client(app) as client:
        invalid_code = await client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": "public",
                "code": "doc_missing",
                "redirect_uri": "http://localhost:7777/callback",
                "code_verifier": "verifier",
            },
        )
        invalid_client = await client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": "secret-client",
                "client_secret": "wrong",
                "code": "doc_missing",
                "redirect_uri": "http://localhost:7778/callback",
                "code_verifier": "verifier",
            },
        )
        refresh_missing_pool = await client.post(
            "/oauth/token",
            data={
                "grant_type": "refresh_token",
                "client_id": "public",
                "refresh_token": pair.refresh_token,
            },
        )
        revoke_unknown = await client.post("/oauth/revoke", data={"token": "dor_unknown"})
        revoke_unknown_bad_client = await client.post(
            "/oauth/revoke",
            data={"token": "dor_unknown", "client_id": "secret-client", "client_secret": "wrong"},
        )
        api_refresh_unknown = await client.post(
            "/api/auth/refresh",
            json={"refresh_token": "dor_unknown"},
        )

    assert invalid_code.status_code == 400
    assert invalid_code.json()["error"] == "invalid_grant"
    assert invalid_client.status_code == 401
    assert invalid_client.json()["error"] == "invalid_client"
    assert refresh_missing_pool.status_code == 401
    assert refresh_missing_pool.json()["error"] == "login_required"
    assert provider.store.get_refresh_token(pair.refresh_token).revoked_at is not None
    assert revoke_unknown.status_code == 200
    assert revoke_unknown_bad_client.status_code == 401
    assert revoke_unknown_bad_client.json()["error"] == "invalid_client"
    assert api_refresh_unknown.status_code == 400
    assert api_refresh_unknown.json()["error"] == "invalid_grant"


@pytest.mark.asyncio
async def test_refresh_token_replay_under_lock_only_issues_one_new_pair():
    provider, cm, _app = _provider_app()
    provider.store.add_client(
        client_id="public",
        client_secret=None,
        token_endpoint_auth_method="none",
        application_type="native",
        redirect_uris=("http://localhost:7777/callback",),
        client_allowed_scopes=("tool:list",),
        source="dcr",
        expires_at=None,
    )
    pair = provider.store.issue_token_pair(
        client_id="public",
        doris_user="alice",
        scopes=("tool:list",),
        resource=provider.resource,
        access_ttl_seconds=900,
        refresh_ttl_seconds=86400,
    )
    cm.pools["alice"] = True
    payload = {
        "grant_type": "refresh_token",
        "client_id": "public",
        "refresh_token": pair.refresh_token,
    }

    await provider._lock.acquire()
    try:
        first = asyncio.create_task(provider.refresh_token(dict(payload)))
        second = asyncio.create_task(provider.refresh_token(dict(payload)))
        await asyncio.sleep(0)
    finally:
        provider._lock.release()

    results = await asyncio.gather(first, second, return_exceptions=True)
    successes = [result for result in results if isinstance(result, dict)]
    errors = [result for result in results if isinstance(result, TokenEndpointError)]

    assert len(successes) == 1
    assert len(errors) == 1
    assert errors[0].error == "invalid_grant"
    active_refresh_tokens = [
        record for record in provider.store.refresh_by_hash.values() if record.revoked_at is None
    ]
    assert len(active_refresh_tokens) == 1
    assert active_refresh_tokens[0].token_id != pair.refresh_record.token_id


@pytest.mark.asyncio
async def test_api_auth_token_defaults_to_configured_server_allowlist_not_wildcard():
    provider, cm, app = _provider_app()
    async with await _client(app) as client:
        response = await client.post(
            "/api/auth/token",
            json={"username": "cli_user", "password": "correct"},
        )

    assert response.status_code == 200
    assert response.json()["scope"] == "resource:list resource:read tool:list"
    assert "*" not in response.json()["scope"]
    assert cm.create_calls == [("cli_user", "correct")]
    assert provider.store.get_client("cli").application_type == "native"


@pytest.mark.asyncio
async def test_revoke_client_bucket_rate_limit_is_enforced():
    config = _config()
    config.security.doris_oauth_revoke_rate_limit_per_client = 1
    provider = DorisOAuthProvider(config)
    provider.store.add_client(
        client_id="public",
        client_secret=None,
        token_endpoint_auth_method="none",
        application_type="native",
        redirect_uris=("http://localhost:7777/callback",),
        client_allowed_scopes=("tool:list",),
        source="dcr",
        expires_at=None,
    )
    app = Starlette(routes=DorisOAuthHandlers(provider).routes())

    async with await _client(app) as client:
        first = await client.post("/oauth/revoke", data={"token": "dor_unknown", "client_id": "public"})
        second = await client.post("/oauth/revoke", data={"token": "dor_other", "client_id": "public"})

    assert first.status_code == 200
    assert second.status_code == 429


def test_trusted_proxy_headers_are_used_only_from_trusted_cidrs():
    config = _config()
    config.security.doris_oauth_trust_proxy_headers = True
    config.security.doris_oauth_trusted_proxy_cidrs = ["10.0.0.0/8"]
    handler = DorisOAuthHandlers(DorisOAuthProvider(config))

    trusted_scope = {
        "type": "http",
        "method": "GET",
        "path": "/oauth/register",
        "headers": [(b"x-forwarded-for", b"203.0.113.7, 10.1.2.3")],
        "client": ("10.1.2.3", 1234),
    }
    untrusted_scope = dict(trusted_scope)
    untrusted_scope["client"] = ("192.0.2.10", 1234)

    from starlette.requests import Request

    assert handler._client_ip(Request(trusted_scope)) == "203.0.113.7"
    assert handler._client_ip(Request(untrusted_scope)) == "192.0.2.10"


@pytest.mark.asyncio
async def test_doris_oauth_http_startup_fails_when_global_pool_missing(monkeypatch):
    from doris_mcp_server.main import DorisServer

    server = DorisServer(_config())

    async def skip_security_initialize():
        return None

    async def missing_global_pool():
        return False

    monkeypatch.setattr(server.security_manager, "initialize", skip_security_initialize)
    monkeypatch.setattr(server.connection_manager, "initialize_for_http_mode", missing_global_pool)

    with pytest.raises(RuntimeError, match="service/global Doris account"):
        await server.start_http(host="127.0.0.1", port=0, workers=1)


@pytest.mark.asyncio
async def test_multiworker_exported_app_explicitly_handles_doris_oauth_paths():
    from doris_mcp_server import multiworker_app

    transport = httpx.ASGITransport(app=multiworker_app.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://localhost:3000") as client:
        response = await client.get("/.well-known/oauth-protected-resource")

    assert response.status_code != 404
