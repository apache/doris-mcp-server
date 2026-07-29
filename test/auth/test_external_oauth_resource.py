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

from types import SimpleNamespace

import httpx
import pytest
from starlette.requests import Request

import doris_mcp_server.multiworker_app as multiworker_app
from doris_mcp_server.auth.oauth_handlers import OAuthHandlers
from doris_mcp_server.auth.oauth_resource import (
    bearer_challenge_header,
    external_oauth_protected_resource_metadata,
    external_oauth_resource_metadata_url,
)
from doris_mcp_server.auth.oauth_token_validation import (
    OAuthAccessTokenValidationError,
)
from doris_mcp_server.utils.config import (
    DorisConfig,
    _mark_source,
    normalize_effective_auth_config,
)

ISSUER = "https://issuer.example.test/tenant"
RESOURCE = "https://mcp.example.test/mcp"


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
    config.security.oauth_required_scopes = ["tool:list"]
    normalize_effective_auth_config(config)
    return config


def test_external_oauth_metadata_matches_normalized_resource_context():
    effective = _external_oauth_config().effective_auth

    assert effective.external_oauth_issuer == ISSUER
    assert effective.external_oauth_resource == RESOURCE
    assert effective.external_oauth_scopes == (
        "tool:list",
        "resource:list",
        "resource:read",
    )
    assert effective.external_oauth_required_scopes == ("tool:list",)
    assert external_oauth_protected_resource_metadata(effective) == {
        "resource": RESOURCE,
        "authorization_servers": [ISSUER],
        "scopes_supported": [
            "tool:list",
            "resource:list",
            "resource:read",
        ],
        "bearer_methods_supported": ["header"],
    }


def test_external_oauth_metadata_url_uses_served_root_well_known_path():
    assert external_oauth_resource_metadata_url(RESOURCE) == (
        "https://mcp.example.test/.well-known/oauth-protected-resource"
    )


def test_bearer_challenge_escapes_quoted_values_and_header_injection():
    challenge = bearer_challenge_header(
        'https://mcp.example.test/.well-known/"metadata"\r\nInjected: yes',
        error="invalid_token",
        scopes=("tool:list", "tool:list", "resource:read"),
    )

    assert "\r" not in challenge
    assert "\n" not in challenge
    assert '\\"metadata\\"' in challenge
    assert challenge.count("tool:list") == 1
    assert 'scope="tool:list resource:read"' in challenge


@pytest.mark.asyncio
async def test_external_oauth_handler_serves_protected_resource_metadata():
    config = _external_oauth_config()
    handlers = OAuthHandlers(SimpleNamespace(config=config))

    response = await handlers.handle_protected_resource_metadata(
        Request({"type": "http", "method": "GET", "path": "/"})
    )

    assert response.status_code == 200
    assert b'"resource":"https://mcp.example.test/mcp"' in response.body
    assert b'"authorization_servers":["https://issuer.example.test/tenant"]' in (
        response.body
    )


@pytest.mark.asyncio
async def test_multiworker_dispatches_external_oauth_resource_metadata(
    monkeypatch,
):
    config = _external_oauth_config()
    handlers = OAuthHandlers(SimpleNamespace(config=config))
    monkeypatch.setattr(
        multiworker_app,
        "_worker_effective_auth",
        config.effective_auth,
    )
    monkeypatch.setattr(multiworker_app, "_oauth_handlers", handlers)
    monkeypatch.setattr(multiworker_app, "_doris_oauth_handlers", None)

    response = await multiworker_app.oauth_protected_resource_metadata(
        Request({"type": "http", "method": "GET", "path": "/"})
    )

    assert response.status_code == 200
    assert b'"resource":"https://mcp.example.test/mcp"' in response.body


@pytest.mark.asyncio
async def test_multiworker_http_routes_external_oauth_metadata_and_challenge(
    monkeypatch,
):
    config = _external_oauth_config()
    handlers = OAuthHandlers(SimpleNamespace(config=config))

    class RejectingSecurityManager:
        async def authenticate_request(self, credentials):
            raise OAuthAccessTokenValidationError(
                "invalid_token",
                "OAuth access token has expired",
            )

    monkeypatch.setattr(multiworker_app, "_worker_initialized", True)
    monkeypatch.setattr(
        multiworker_app,
        "_worker_effective_auth",
        config.effective_auth,
    )
    monkeypatch.setattr(
        multiworker_app,
        "_worker_security_manager",
        RejectingSecurityManager(),
    )
    monkeypatch.setattr(multiworker_app, "_oauth_handlers", handlers)
    monkeypatch.setattr(multiworker_app, "_doris_oauth_handlers", None)

    transport = httpx.ASGITransport(app=multiworker_app.app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="https://mcp.example.test",
    ) as client:
        metadata = await client.get("/.well-known/oauth-protected-resource")
        rejected = await client.post(
            "/mcp",
            headers={"Authorization": "Bearer expired-token"},
            json={"jsonrpc": "2.0", "id": 1, "method": "server/discover"},
        )

    assert metadata.status_code == 200
    assert metadata.json()["resource"] == RESOURCE
    assert rejected.status_code == 401
    assert rejected.json()["error"] == "invalid_token"
    challenge = rejected.headers["www-authenticate"]
    assert 'error="invalid_token"' in challenge
    assert 'scope="tool:list"' in challenge
    assert "oauth-protected-resource" in challenge
    assert "expired-token" not in rejected.text
    assert "expired-token" not in challenge
