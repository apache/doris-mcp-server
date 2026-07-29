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

import logging
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from doris_mcp_server.auth.oauth_token_validation import (
    OAuthAccessTokenValidationError,
)
from doris_mcp_server.utils.auth_credentials import (
    BearerCredentials,
    normalize_bearer_credentials,
)
from doris_mcp_server.utils.security import (
    AuthContext,
    AuthenticationProvider,
    DorisSecurityManager,
)


def test_authorization_header_is_normalized_and_token_is_not_represented():
    credentials = BearerCredentials.from_authorization(
        "bEaReR secret-value",
        client_ip="192.0.2.10",
        session_id="session-1",
    )

    assert credentials.scheme == "bearer"
    assert credentials.token == "secret-value"
    assert credentials.client_ip == "192.0.2.10"
    assert credentials.session_id == "session-1"
    assert credentials.is_bearer is True
    assert "secret-value" not in repr(credentials)


@pytest.mark.parametrize(
    ("authorization", "scheme"),
    [
        ("", ""),
        ("Bearer", "bearer"),
        ("Bearer   ", "bearer"),
        ("Basic abc", "basic"),
    ],
)
def test_invalid_or_non_bearer_headers_do_not_produce_a_token(
    authorization,
    scheme,
):
    credentials = BearerCredentials.from_authorization(authorization)

    assert credentials.scheme == scheme
    assert credentials.token == ""
    assert credentials.is_bearer is False


def test_legacy_mapping_is_normalized_once_to_the_canonical_dto():
    credentials = normalize_bearer_credentials(
        {
            "access_token": "external-token",
            "client_ip": "198.51.100.4",
            "session_id": "session-2",
        }
    )

    assert credentials == BearerCredentials(
        scheme="bearer",
        token="external-token",
        client_ip="198.51.100.4",
        session_id="session-2",
    )
    assert normalize_bearer_credentials(credentials) is credentials


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "provider_method", "token"),
    [
        ("token", "authenticate_token", "static-token"),
        ("jwt", "authenticate_jwt", "jwt-token"),
        ("external_oauth", "authenticate_oauth", "external-token"),
        ("doris_oauth", "authenticate_doris_oauth", "doa_access-token"),
    ],
)
async def test_security_manager_passes_the_same_dto_to_every_provider(
    method,
    provider_method,
    token,
):
    credentials = BearerCredentials(
        scheme="bearer",
        token=token,
        client_ip="203.0.113.8",
        session_id="session-3",
    )
    expected_context = AuthContext(user_id=method, auth_method=method)
    received = []

    class Provider:
        async def authenticate_token(self, value):
            received.append(("authenticate_token", value))
            return expected_context

        async def authenticate_jwt(self, value):
            received.append(("authenticate_jwt", value))
            return expected_context

        async def authenticate_oauth(self, value):
            received.append(("authenticate_oauth", value))
            return expected_context

        async def authenticate_doris_oauth(self, value):
            received.append(("authenticate_doris_oauth", value))
            return expected_context

    manager = object.__new__(DorisSecurityManager)
    manager.auth_provider = Provider()
    manager.logger = logging.getLogger(__name__)
    manager._get_effective_auth_config = lambda: SimpleNamespace(auth_methods=(method,))

    result = await manager.authenticate_request(credentials)

    assert result is expected_context
    assert received == [(provider_method, credentials)]
    assert received[0][1] is credentials


@pytest.mark.asyncio
async def test_security_manager_preserves_external_oauth_challenge_error():
    expected = OAuthAccessTokenValidationError(
        "insufficient_scope",
        "A required scope is missing",
        required_scopes=("tool:call:exec_query",),
    )

    class Provider:
        async def authenticate_oauth(self, credentials):
            raise expected

    manager = object.__new__(DorisSecurityManager)
    manager.auth_provider = Provider()
    manager.logger = logging.getLogger(__name__)
    manager._get_effective_auth_config = lambda: SimpleNamespace(
        auth_methods=("external_oauth",)
    )

    with pytest.raises(OAuthAccessTokenValidationError) as exc_info:
        await manager.authenticate_request(
            BearerCredentials(scheme="bearer", token="external-token")
        )

    assert exc_info.value is expected
    assert exc_info.value.status_code == 403
    assert exc_info.value.required_scopes == ("tool:call:exec_query",)


@pytest.mark.asyncio
async def test_static_token_provider_uses_canonical_credentials():
    token_info = SimpleNamespace(
        token_id="static-id",
        last_used=datetime.now(UTC),
    )

    class TokenManager:
        async def validate_token(self, token):
            assert token == "static-token"
            return SimpleNamespace(is_valid=True, token_info=token_info)

    provider = object.__new__(AuthenticationProvider)
    provider.token_manager = TokenManager()
    provider.security_manager = None
    provider.logger = logging.getLogger(__name__)

    context = await provider._authenticate_token(
        BearerCredentials(
            scheme="token",
            token="static-token",
            client_ip="192.0.2.20",
            session_id="static-session",
        )
    )

    assert context.auth_method == "token"
    assert context.token_id == "static-id"
    assert context.client_ip == "192.0.2.20"
    assert context.session_id == "static-session"


@pytest.mark.asyncio
async def test_external_oauth_provider_receives_normalized_bearer_token():
    received = []

    class OAuthProvider:
        async def authenticate_with_token(self, token):
            received.append(token)
            return AuthContext(user_id="oauth-user")

    provider = object.__new__(AuthenticationProvider)
    provider.oauth_provider = OAuthProvider()

    context = await provider._authenticate_oauth(
        BearerCredentials(scheme="bearer", token="external-token")
    )

    assert received == ["external-token"]
    assert context.auth_method == "external_oauth"
    assert context.token == ""
    assert context.pool_key == "global"


@pytest.mark.asyncio
async def test_legacy_external_oauth_callback_keeps_normalized_auth_context():
    class OAuthProvider:
        async def handle_callback(self, code, state):
            assert (code, state) == ("code-1", "state-1")
            return AuthContext(user_id="oauth-user")

    provider = object.__new__(AuthenticationProvider)
    provider.effective_auth = SimpleNamespace(enable_external_oauth_auth=True)
    provider.oauth_provider = OAuthProvider()

    context = await provider.authenticate(
        {
            "type": "oauth",
            "code": "code-1",
            "state": "state-1",
        }
    )

    assert context.auth_method == "external_oauth"
    assert context.token == ""
    assert context.pool_key == "global"


@pytest.mark.asyncio
async def test_doris_oauth_provider_receives_the_same_credentials_object():
    credentials = BearerCredentials(scheme="bearer", token="doa_access-token")
    received = []

    class DorisOAuthProvider:
        async def authenticate_access_token(self, value):
            received.append(value)
            return AuthContext(user_id="doris-user", auth_method="doris_oauth")

    provider = object.__new__(AuthenticationProvider)
    provider.effective_auth = SimpleNamespace(enable_doris_oauth_auth=True)
    provider.doris_oauth_provider = DorisOAuthProvider()

    context = await provider.authenticate_doris_oauth(credentials)

    assert context.auth_method == "doris_oauth"
    assert received == [credentials]
    assert received[0] is credentials
