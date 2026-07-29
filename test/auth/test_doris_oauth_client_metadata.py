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
"""Client ID Metadata Document conformance and integration tests."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import re
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from starlette.applications import Starlette

import doris_mcp_server.auth.doris_oauth_client_metadata as client_metadata_module
from doris_mcp_server.auth.doris_oauth_client_metadata import (
    ClientMetadataError,
    DorisOAuthClientMetadataResolver,
    metadata_address_allowed,
    validate_client_identifier_url,
)
from doris_mcp_server.auth.doris_oauth_handlers import DorisOAuthHandlers
from doris_mcp_server.auth.doris_oauth_provider import DorisOAuthProvider
from doris_mcp_server.utils.config import (
    DorisConfig,
    _mark_source,
    normalize_effective_auth_config,
)

CLIENT_ID = "https://client.example/oauth/client.json"
REDIRECT_URI = "http://localhost:7777/callback"


class FakeConnectionManager:
    def __init__(self):
        self.pools = {}
        self.create_calls = []

    async def create_or_replace_doris_user_pool(self, username, password):
        self.create_calls.append((username, password))
        if password != "correct":
            raise RuntimeError("invalid credentials")
        self.pools[username] = True

    def has_doris_user_pool(self, username):
        return self.pools.get(username, False)

    async def cleanup_idle_doris_user_pools(self, active_users):
        return None


class FakeResponseContent:
    def __init__(self, body):
        self.body = body

    async def iter_chunked(self, _size):
        yield self.body


class FakeMetadataResponse:
    def __init__(self, *, status=200, headers=None, body=b"{}"):
        self.status = status
        self.headers = headers or {}
        self.content = FakeResponseContent(body)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None


class FakeClientSession:
    response = None
    request = None

    def __init__(self, *, connector, **_kwargs):
        self.connector = connector

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        await self.connector.close()

    def get(self, url, **kwargs):
        type(self).request = (url, kwargs)
        return type(self).response


def _config() -> DorisConfig:
    config = DorisConfig()
    config.transport = "http"
    _mark_source(config, "transport", "test")
    config.security.enable_doris_oauth_auth = True
    _mark_source(config, "enable_doris_oauth_auth", "test")
    config.security.doris_oauth_base_url = "http://localhost:3000"
    normalize_effective_auth_config(config, requested_workers=1)
    return config


def _document(client_id=CLIENT_ID, **overrides):
    return {
        "client_id": client_id,
        "client_name": "Example MCP Client",
        "redirect_uris": [REDIRECT_URI],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        **overrides,
    }


def _resolver(fetch_document):
    provider = DorisOAuthProvider(_config())
    return DorisOAuthClientMetadataResolver(
        issuer=provider.issuer,
        redirect_policy=provider.redirect_policy,
        scope_policy=provider.scope_policy,
        fetch_document=fetch_document,
    )


async def _client(app):
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://localhost:3000",
        follow_redirects=False,
    )


def _pkce(verifier="cimd-verifier"):
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return (
        base64.urlsafe_b64encode(digest).decode("ascii").rstrip("="),
        verifier,
    )


@pytest.mark.parametrize(
    "client_id",
    [
        "http://client.example/oauth/client.json",
        "https://client.example",
        "https://user@client.example/oauth/client.json",
        "https://client.example/oauth/../client.json",
        "https://client.example/oauth/%2e%2e/client.json",
        "https://client.example/oauth/client.json#fragment",
        r"https://client.example\@private.example/oauth/client.json",
    ],
)
def test_client_identifier_url_rejects_nonconforming_values(client_id):
    with pytest.raises(ClientMetadataError):
        validate_client_identifier_url(client_id)


def test_client_identifier_url_preserves_query_and_explicit_port():
    hostname, port = validate_client_identifier_url(
        "https://client.example:8443/oauth/client.json?v=1"
    )

    assert hostname == "client.example"
    assert port == 8443


def test_metadata_address_policy_blocks_special_use_addresses():
    assert metadata_address_allowed("93.184.216.34", "https://as.example")
    assert not metadata_address_allowed("10.0.0.10", "https://as.example")
    assert not metadata_address_allowed("127.0.0.1", "https://as.example")
    assert metadata_address_allowed("127.0.0.1", "http://localhost:3000")
    assert not metadata_address_allowed("10.0.0.10", "http://localhost:3000")


@pytest.mark.asyncio
async def test_fetch_document_does_not_follow_redirects(monkeypatch):
    resolver = _resolver(lambda _client_id: None)

    async def resolve_addresses(_hostname, _port):
        return ("93.184.216.34",)

    monkeypatch.setattr(resolver, "_resolve_addresses", resolve_addresses)
    FakeClientSession.response = FakeMetadataResponse(
        status=302,
        headers={"Location": "https://attacker.example/client.json"},
    )
    FakeClientSession.request = None
    monkeypatch.setattr(
        client_metadata_module.aiohttp,
        "ClientSession",
        FakeClientSession,
    )

    with pytest.raises(ClientMetadataError, match="did not return 200"):
        await resolver._fetch_document(CLIENT_ID)

    request_url, request_options = FakeClientSession.request
    assert request_url == CLIENT_ID
    assert request_options["allow_redirects"] is False


@pytest.mark.asyncio
async def test_fetch_document_enforces_streamed_size_limit(monkeypatch):
    resolver = _resolver(lambda _client_id: None)

    async def resolve_addresses(_hostname, _port):
        return ("93.184.216.34",)

    monkeypatch.setattr(resolver, "_resolve_addresses", resolve_addresses)
    FakeClientSession.response = FakeMetadataResponse(
        headers={"Content-Type": "application/json"},
        body=b"x" * (resolver.max_document_bytes + 1),
    )
    monkeypatch.setattr(
        client_metadata_module.aiohttp,
        "ClientSession",
        FakeClientSession,
    )

    with pytest.raises(ClientMetadataError, match="too large"):
        await resolver._fetch_document(CLIENT_ID)


@pytest.mark.asyncio
async def test_resolver_validates_infers_native_and_respects_cache_headers():
    calls = []

    async def fetch_document(client_id):
        calls.append(client_id)
        return _document(client_id), {"Cache-Control": "public, max-age=60"}

    resolver = _resolver(fetch_document)
    first = await resolver.resolve(CLIENT_ID)
    second = await resolver.resolve(CLIENT_ID)

    assert first is second
    assert first.client_name == "Example MCP Client"
    assert first.application_type == "native"
    assert first.redirect_uris == (REDIRECT_URI,)
    assert calls == [CLIENT_ID]


@pytest.mark.asyncio
async def test_resolver_does_not_cache_no_store_response():
    calls = []

    async def fetch_document(client_id):
        calls.append(client_id)
        return _document(client_id), {"Cache-Control": "no-store"}

    resolver = _resolver(fetch_document)
    await resolver.resolve(CLIENT_ID)
    await resolver.resolve(CLIENT_ID)

    assert calls == [CLIENT_ID, CLIENT_ID]


@pytest.mark.asyncio
async def test_resolver_coalesces_concurrent_fetches_and_releases_lock():
    calls = []

    async def fetch_document(client_id):
        calls.append(client_id)
        await asyncio.sleep(0)
        return _document(client_id), {"Cache-Control": "max-age=60"}

    resolver = _resolver(fetch_document)
    results = await asyncio.gather(
        resolver.resolve(CLIENT_ID),
        resolver.resolve(CLIENT_ID),
        resolver.resolve(CLIENT_ID),
    )

    assert results[0] is results[1] is results[2]
    assert calls == [CLIENT_ID]
    assert resolver._locks == {}


@pytest.mark.asyncio
async def test_resolver_does_not_cache_invalid_document():
    calls = []

    async def fetch_document(client_id):
        calls.append(client_id)
        if len(calls) == 1:
            return _document("https://other.example/oauth/client.json"), {}
        return _document(client_id), {"Cache-Control": "max-age=60"}

    resolver = _resolver(fetch_document)
    with pytest.raises(ClientMetadataError):
        await resolver.resolve(CLIENT_ID)

    metadata = await resolver.resolve(CLIENT_ID)

    assert metadata.client_id == CLIENT_ID
    assert calls == [CLIENT_ID, CLIENT_ID]
    assert resolver._locks == {}


@pytest.mark.parametrize(
    "document",
    [
        _document("https://other.example/oauth/client.json"),
        _document(client_name=""),
        _document(client_name="Example\nClient"),
        _document(redirect_uris=[]),
        _document(client_secret="secret"),
        _document(token_endpoint_auth_method="client_secret_post"),
        _document(jwks={"keys": [{"kty": "RSA", "d": "private"}]}),
        _document(response_types=["token"]),
        _document(
            redirect_uris=[
                REDIRECT_URI,
                "https://client.example/callback",
            ]
        ),
    ],
)
@pytest.mark.asyncio
async def test_resolver_rejects_invalid_or_unsafe_documents(document):
    async def fetch_document(_client_id):
        return document, {}

    with pytest.raises(ClientMetadataError):
        await _resolver(fetch_document).resolve(CLIENT_ID)


@pytest.mark.asyncio
async def test_url_client_runs_full_authorization_code_flow_and_displays_hosts():
    async def fetch_document(client_id):
        return _document(
            client_id,
            client_name="<Example & Client>",
        ), {"Cache-Control": "max-age=300"}

    config = _config()
    provider = DorisOAuthProvider(config)
    provider.client_metadata_resolver = DorisOAuthClientMetadataResolver(
        issuer=provider.issuer,
        redirect_policy=provider.redirect_policy,
        scope_policy=provider.scope_policy,
        fetch_document=fetch_document,
    )
    connection_manager = FakeConnectionManager()
    provider.configure_connection_manager(connection_manager)
    app = Starlette(routes=DorisOAuthHandlers(provider).routes())
    challenge, verifier = _pkce()

    async with await _client(app) as client:
        metadata_response = await client.get("/.well-known/oauth-authorization-server")
        assert metadata_response.json()["client_id_metadata_document_supported"] is True
        assert "registration_endpoint" in metadata_response.json()

        authorize = await client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "state": "cimd-state",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": provider.resource,
            },
        )
        assert authorize.status_code == 302
        assert authorize.headers["location"].startswith("/doris-login?")

        login_get = await client.get(authorize.headers["location"])
        assert login_get.status_code == 200
        assert "&lt;Example &amp; Client&gt;" in login_get.text
        assert "<Example & Client>" not in login_get.text
        assert "Client host: client.example" in login_get.text
        assert "Redirect host: localhost" in login_get.text
        assert "Local redirect:" in login_get.text
        csrf = re.search(
            r'name="login_csrf" value="([^"]+)"',
            login_get.text,
        ).group(1)
        txn_id = re.search(
            r'name="txn_id" value="([^"]+)"',
            login_get.text,
        ).group(1)

        login_post = await client.post(
            "/doris-login",
            data={
                "txn_id": txn_id,
                "login_csrf": csrf,
                "username": "alice",
                "password": "correct",
            },
        )
        authorization_response = parse_qs(
            urlparse(login_post.headers["location"]).query
        )
        assert authorization_response["iss"] == [provider.issuer]
        assert authorization_response["state"] == ["cimd-state"]

        token_response = await client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": CLIENT_ID,
                "code": authorization_response["code"][0],
                "redirect_uri": REDIRECT_URI,
                "code_verifier": verifier,
                "resource": provider.resource,
            },
        )

    assert token_response.status_code == 200
    assert token_response.json()["access_token"].startswith("doa_")
    assert connection_manager.create_calls == [("alice", "correct")]
    record = provider.store.get_client(CLIENT_ID)
    assert record.source == "client_id_metadata"
    assert record.client_name == "<Example & Client>"
    assert record.application_type == "native"


@pytest.mark.asyncio
async def test_preconfigured_client_takes_precedence_over_url_discovery():
    async def fetch_document(_client_id):
        raise AssertionError("preconfigured client must not be fetched")

    provider = DorisOAuthProvider(_config())
    existing = provider.store.add_client(
        client_id=CLIENT_ID,
        client_secret=None,
        token_endpoint_auth_method="none",
        application_type="native",
        redirect_uris=(REDIRECT_URI,),
        client_allowed_scopes=tuple(
            sorted(provider.scope_policy.server_allowed_scopes)
        ),
        source="preconfigured",
        expires_at=None,
    )
    provider.client_metadata_resolver = DorisOAuthClientMetadataResolver(
        issuer=provider.issuer,
        redirect_policy=provider.redirect_policy,
        scope_policy=provider.scope_policy,
        fetch_document=fetch_document,
    )

    resolved = await provider._authorization_client(
        CLIENT_ID,
        client_ip="127.0.0.1",
    )

    assert resolved is existing


@pytest.mark.asyncio
async def test_untrusted_metadata_never_enables_redirect():
    async def fetch_document(client_id):
        return _document(client_id), {}

    provider = DorisOAuthProvider(_config())
    provider.client_metadata_resolver = DorisOAuthClientMetadataResolver(
        issuer=provider.issuer,
        redirect_policy=provider.redirect_policy,
        scope_policy=provider.scope_policy,
        fetch_document=fetch_document,
    )
    app = Starlette(routes=DorisOAuthHandlers(provider).routes())
    challenge, _verifier = _pkce()

    async with await _client(app) as client:
        response = await client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": CLIENT_ID,
                "redirect_uri": "https://attacker.example/callback",
                "state": "state",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": provider.resource,
            },
        )

    assert response.status_code == 400
    assert "location" not in response.headers


@pytest.mark.asyncio
async def test_metadata_fetch_failure_never_enables_redirect():
    async def fetch_document(_client_id):
        raise ClientMetadataError("unavailable")

    provider = DorisOAuthProvider(_config())
    provider.client_metadata_resolver = DorisOAuthClientMetadataResolver(
        issuer=provider.issuer,
        redirect_policy=provider.redirect_policy,
        scope_policy=provider.scope_policy,
        fetch_document=fetch_document,
    )
    app = Starlette(routes=DorisOAuthHandlers(provider).routes())
    challenge, _verifier = _pkce()

    async with await _client(app) as client:
        response = await client.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "state": "state",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "resource": provider.resource,
            },
        )

    assert response.status_code == 400
    assert "location" not in response.headers


@pytest.mark.asyncio
async def test_cimd_remains_advertised_when_dcr_is_disabled():
    config = _config()
    config.security.doris_oauth_dynamic_client_registration_mode = "disabled"
    provider = DorisOAuthProvider(config)
    app = Starlette(routes=DorisOAuthHandlers(provider).routes())

    async with await _client(app) as client:
        metadata_response = await client.get("/.well-known/oauth-authorization-server")
        registration_response = await client.post("/oauth/register", json={})

    metadata = metadata_response.json()
    assert metadata["client_id_metadata_document_supported"] is True
    assert "registration_endpoint" not in metadata
    assert registration_response.status_code == 404
