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

import pytest

from doris_mcp_server.auth.oauth_provider import OAuthAuthenticationProvider
from doris_mcp_server.auth.oauth_token_validation import (
    OAuthAccessTokenContext,
    OAuthAccessTokenValidationError,
)
from doris_mcp_server.auth.oauth_types import OAuthState, OAuthTokens, OAuthUserInfo

ISSUER = "https://issuer.example.test"
RESOURCE = "https://mcp.example.test/mcp"


def _token_context(subject="user-1") -> OAuthAccessTokenContext:
    return OAuthAccessTokenContext(
        issuer=ISSUER,
        resource=RESOURCE,
        audiences=(RESOURCE,),
        scopes=("resource:read", "tool:list"),
        subject=subject,
        client_id="caller-client",
        token_id="token-1",
        expires_at=200,
    )


class _FlowOAuthClient:
    def __init__(self, *, token_subject="user-1", user_subject="user-1"):
        self.events = []
        self.token_subject = token_subject
        self.user_subject = user_subject

    async def exchange_code_for_tokens(self, code, state):
        self.events.append(("exchange", code, state))
        return (
            OAuthTokens(
                access_token="callback-access",
                refresh_token="callback-refresh",
            ),
            OAuthState(state=state),
        )

    async def refresh_tokens(self, refresh_token):
        self.events.append(("refresh", refresh_token))
        return OAuthTokens(access_token="refreshed-access")

    async def introspect_access_token(self, access_token):
        self.events.append(("introspect", access_token))
        return _token_context(self.token_subject)

    async def get_user_info(self, tokens):
        self.events.append(("userinfo", tokens.access_token))
        return OAuthUserInfo(
            sub=self.user_subject,
            email="user@example.test",
            roles=["oauth_user"],
        )


def _provider(client) -> OAuthAuthenticationProvider:
    provider = object.__new__(OAuthAuthenticationProvider)
    provider.enabled = True
    provider.oauth_client = client
    return provider


@pytest.mark.asyncio
@pytest.mark.parametrize("flow", ["callback", "bearer", "refresh"])
async def test_every_external_oauth_entry_validates_before_userinfo(flow):
    client = _FlowOAuthClient()
    provider = _provider(client)

    if flow == "callback":
        context = await provider.handle_callback("code-1", "state-1")
        assert client.events == [
            ("exchange", "code-1", "state-1"),
            ("introspect", "callback-access"),
            ("userinfo", "callback-access"),
        ]
    elif flow == "bearer":
        context = await provider.authenticate_with_token("bearer-access")
        assert client.events == [
            ("introspect", "bearer-access"),
            ("userinfo", "bearer-access"),
        ]
    else:
        context, access_token = await provider.refresh_authentication("refresh-1")
        assert access_token == "refreshed-access"
        assert client.events == [
            ("refresh", "refresh-1"),
            ("introspect", "refreshed-access"),
            ("userinfo", "refreshed-access"),
        ]

    assert context.user_id == "user-1"
    assert context.token_id == "token-1"
    assert context.token == ""
    assert context.auth_method == "external_oauth"
    assert context.oauth_client_id == "caller-client"
    assert context.oauth_scopes == ["resource:read", "tool:list"]
    assert context.oauth_issuer == ISSUER
    assert context.oauth_resource == RESOURCE
    assert context.oauth_audiences == [RESOURCE]
    assert context.pool_key == "global"


@pytest.mark.asyncio
async def test_failed_introspection_never_calls_userinfo():
    class RejectingOAuthClient(_FlowOAuthClient):
        async def introspect_access_token(self, access_token):
            self.events.append(("introspect", access_token))
            raise OAuthAccessTokenValidationError(
                "invalid_token",
                "inactive",
            )

    client = RejectingOAuthClient()
    provider = _provider(client)

    with pytest.raises(
        OAuthAccessTokenValidationError,
        match="inactive",
    ) as exc_info:
        await provider.authenticate_with_token("rejected-access")

    assert exc_info.value.error == "invalid_token"
    assert exc_info.value.status_code == 401
    assert client.events == [("introspect", "rejected-access")]


@pytest.mark.asyncio
async def test_userinfo_subject_must_match_introspected_subject():
    client = _FlowOAuthClient(
        token_subject="token-user",
        user_subject="userinfo-user",
    )
    provider = _provider(client)

    with pytest.raises(
        OAuthAccessTokenValidationError,
        match="userinfo subject does not match",
    ) as exc_info:
        await provider.authenticate_with_token("access-1")

    assert exc_info.value.error == "invalid_token"
