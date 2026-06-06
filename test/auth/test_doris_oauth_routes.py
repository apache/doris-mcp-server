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
from doris_mcp_server.auth.doris_oauth_types import ProtectedResourceAuthError, TokenEndpointError
from doris_mcp_server.utils.config import DorisConfig, _mark_source, normalize_effective_auth_config


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
        self.global_acquire_calls = 0

    async def create_or_replace_doris_user_pool(self, username, password):
        self.create_calls.append((username, password))
        if password == "bad":
            raise RuntimeError("invalid credentials")
        self.pools[username] = True

    def has_doris_user_pool(self, username):
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


@pytest.mark.asyncio
async def test_register_omitted_and_blank_scope_allow_safe_client_scope_set():
    _provider, _cm, app = _provider_app()
    async with await _client(app) as client:
        response = await client.post(
            "/oauth/register",
            json={"redirect_uris": ["http://localhost:7777/callback"]},
        )
        assert response.status_code == 201
        assert response.json()["scope"] == "resource:list resource:read tool:list"

        response = await client.post(
            "/oauth/register",
            json={"redirect_uris": ["http://localhost:7778/callback"], "scope": ""},
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
            json={"redirect_uris": ["http://localhost:7777/callback"]},
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
            json={"redirect_uris": ["http://localhost:7777/callback"]},
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
            json={"redirect_uris": ["http://localhost:7777/callback"]},
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
            json={"redirect_uris": ["http://localhost:7777/callback"]},
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
            json={"redirect_uris": ["http://localhost:7777/callback"]},
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
        redirect_uris=("http://localhost:7000/callback",),
        client_allowed_scopes=("tool:list",),
        source="dcr",
        expires_at=time.time() - 1,
    )
    app = Starlette(routes=DorisOAuthHandlers(provider).routes())

    async with await _client(app) as client:
        response = await client.post(
            "/oauth/register",
            json={"redirect_uris": ["http://localhost:7777/callback"]},
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
    query = parse_qs(urlparse(location).query)
    assert query["error"] == ["invalid_scope"]
    assert query["state"] == ["state-2"]


@pytest.mark.asyncio
async def test_full_login_code_exchange_auth_context_and_pool_missing_revocation():
    provider, cm, app = _provider_app()
    async with await _client(app) as client:
        register = await client.post(
            "/oauth/register",
            json={"redirect_uris": ["http://localhost:7777/callback"]},
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
        code = parse_qs(urlparse(login_post.headers["location"]).query)["code"][0]

        token_response = await client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": client_id,
                "code": code,
                "redirect_uri": "http://localhost:7777/callback",
                "code_verifier": verifier,
            },
        )
        assert token_response.status_code == 200
        token_json = token_response.json()
        assert token_json["access_token"].startswith("doa_")
        assert token_json["scope"] == "resource:list resource:read tool:list"

    auth_context = await provider.authenticate_access_token({"token": token_json["access_token"]})
    assert auth_context.auth_method == "doris_oauth"
    assert auth_context.doris_user == "alice"
    assert auth_context.oauth_client_id == client_id
    assert auth_context.oauth_scopes == ["resource:list", "resource:read", "tool:list"]
    assert auth_context.pool_key == "doris_user:alice"
    assert auth_context.token == ""

    cm.pools["alice"] = False
    with pytest.raises(ProtectedResourceAuthError) as exc:
        await provider.authenticate_access_token({"token": token_json["access_token"]})
    assert exc.value.error == "login_required"
    assert exc.value.error_code == "DORIS_OAUTH_POOL_MISSING"
    assert cm.global_acquire_calls == 0

    cm.pools["alice"] = True
    with pytest.raises(ProtectedResourceAuthError):
        await provider.authenticate_access_token({"token": token_json["access_token"]})


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
            json={"redirect_uris": ["http://localhost:7777/callback"]},
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

    auth_context = await provider.authenticate_access_token({"token": token_json["access_token"]})
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
        redirect_uris=("http://localhost:7777/callback",),
        client_allowed_scopes=("tool:list",),
        source="dcr",
        expires_at=None,
    )
    provider.store.add_client(
        client_id="secret-client",
        client_secret="dos_secret",
        token_endpoint_auth_method="client_secret_post",
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
    _provider, cm, app = _provider_app()
    async with await _client(app) as client:
        response = await client.post(
            "/api/auth/token",
            json={"username": "cli_user", "password": "correct"},
        )

    assert response.status_code == 200
    assert response.json()["scope"] == "resource:list resource:read tool:list"
    assert "*" not in response.json()["scope"]
    assert cm.create_calls == [("cli_user", "correct")]


@pytest.mark.asyncio
async def test_revoke_client_bucket_rate_limit_is_enforced():
    config = _config()
    config.security.doris_oauth_revoke_rate_limit_per_client = 1
    provider = DorisOAuthProvider(config)
    provider.store.add_client(
        client_id="public",
        client_secret=None,
        token_endpoint_auth_method="none",
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
