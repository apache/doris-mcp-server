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

import time
from urllib.parse import parse_qs, urlparse

import pytest

from doris_mcp_server.auth.oauth_client import OAuthClient
from doris_mcp_server.utils.config import (
    DorisConfig,
    _mark_source,
    normalize_effective_auth_config,
)

ISSUER = "https://issuer.example.test"
RESOURCE = "https://mcp.example.test/mcp"


class _FakeResponse:
    def __init__(self, status, payload):
        self.status = status
        self.payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False

    async def json(self):
        return self.payload

    def raise_for_status(self):
        if self.status >= 400:
            raise RuntimeError(f"HTTP {self.status}")


class _FakeSession:
    def __init__(self, *, post_responses=None, get_responses=None):
        self.post_responses = list(post_responses or [])
        self.get_responses = list(get_responses or [])
        self.post_calls = []
        self.get_calls = []

    def post(self, url, **kwargs):
        self.post_calls.append((url, kwargs))
        status, payload = self.post_responses.pop(0)
        return _FakeResponse(status, payload)

    def get(self, url, **kwargs):
        self.get_calls.append((url, kwargs))
        status, payload = self.get_responses.pop(0)
        return _FakeResponse(status, payload)


def _external_oauth_config() -> DorisConfig:
    config = DorisConfig()
    config.security.enable_oauth_auth = True
    _mark_source(config, "enable_oauth_auth", "test")
    config.security.oauth_provider = "custom"
    config.security.oauth_client_id = "oauth-client"
    config.security.oauth_client_secret = "oauth-secret"
    config.security.oauth_redirect_uri = "http://localhost:3000/auth/callback"
    config.security.oauth_authorization_endpoint = f"{ISSUER}/authorize"
    config.security.oauth_token_endpoint = f"{ISSUER}/token"
    config.security.oauth_introspection_endpoint = f"{ISSUER}/introspect"
    config.security.oauth_userinfo_endpoint = f"{ISSUER}/userinfo"
    config.security.oauth_issuer = ISSUER
    config.security.oauth_resource = RESOURCE
    config.security.oauth_audience = RESOURCE
    config.security.oauth_scopes = [
        "tool:list",
        "resource:list",
        "resource:read",
    ]
    config.security.oauth_required_scopes = ["tool:list", "resource:read"]
    normalize_effective_auth_config(config)
    return config


def test_authorization_request_includes_resource_indicator():
    client = OAuthClient(_external_oauth_config())

    authorization_url, _ = client.build_authorization_url()
    query = parse_qs(urlparse(authorization_url).query)

    assert query["resource"] == [RESOURCE]
    assert query["scope"] == ["tool:list resource:list resource:read"]


@pytest.mark.asyncio
async def test_token_exchange_and_refresh_preserve_resource_binding():
    session = _FakeSession(
        post_responses=[
            (200, {"access_token": "access-1", "refresh_token": "refresh-1"}),
            (200, {"access_token": "access-2"}),
        ]
    )
    client = OAuthClient(_external_oauth_config())
    client._session = session
    _, oauth_state = client.build_authorization_url()

    tokens, _ = await client.exchange_code_for_tokens(
        "code-1",
        oauth_state.state,
    )
    refreshed = await client.refresh_tokens(tokens.refresh_token)

    assert tokens.access_token == "access-1"
    assert refreshed.access_token == "access-2"
    assert session.post_calls[0][1]["data"]["resource"] == RESOURCE
    assert session.post_calls[1][1]["data"]["resource"] == RESOURCE


@pytest.mark.asyncio
async def test_introspection_uses_confidential_client_and_returns_context():
    session = _FakeSession(
        post_responses=[
            (
                200,
                {
                    "active": True,
                    "iss": ISSUER,
                    "aud": RESOURCE,
                    "scope": (
                        "tool:list resource:list resource:read unconfigured:admin"
                    ),
                    "sub": "user-1",
                    "client_id": "caller-client",
                    "jti": "token-1",
                    "exp": int(time.time()) + 3600,
                },
            )
        ]
    )
    client = OAuthClient(_external_oauth_config())
    client._session = session

    context = await client.introspect_access_token("access-secret")

    endpoint, kwargs = session.post_calls[0]
    assert endpoint == f"{ISSUER}/introspect"
    assert kwargs["data"] == {
        "token": "access-secret",
        "token_type_hint": "access_token",
    }
    assert kwargs["auth"].login == "oauth-client"
    assert kwargs["auth"].password == "oauth-secret"
    assert context.subject == "user-1"
    assert context.audiences == (RESOURCE,)
    assert context.scopes == (
        "resource:list",
        "resource:read",
        "tool:list",
    )
    assert "unconfigured:admin" not in context.scopes


@pytest.mark.asyncio
async def test_discovery_document_must_match_configured_issuer():
    session = _FakeSession(
        get_responses=[
            (
                200,
                {
                    "issuer": "https://other-issuer.example.test",
                    "authorization_endpoint": f"{ISSUER}/authorize",
                    "token_endpoint": f"{ISSUER}/token",
                },
            )
        ]
    )
    client = OAuthClient(_external_oauth_config())
    client.provider_config.discovery_url = f"{ISSUER}/.well-known/oauth"
    client._session = session

    with pytest.raises(ValueError, match="issuer does not match"):
        await client._discover_oidc_endpoints()
