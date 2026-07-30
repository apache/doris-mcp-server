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
"""Contract tests for explicit state handles across stateless MCP calls."""

from __future__ import annotations

import pytest

from doris_mcp_server.state_handles import (
    StateHandleCodec,
    StateHandleError,
    authorization_fingerprint,
)
from doris_mcp_server.utils.security import AuthContext

_SHARED_SECRET = "shared-state-handle-secret-value-32-bytes"


def _auth_context(
    *,
    user_id: str = "user-a",
    session_id: str = "request-session-a",
    scopes: list[str] | None = None,
) -> AuthContext:
    return AuthContext(
        token_id="token-a",
        user_id=user_id,
        roles=["analyst"],
        permissions=["tool:list"],
        session_id=session_id,
        token="must-not-enter-handle",
        auth_method="doris_oauth",
        oauth_client_id="client-a",
        oauth_scopes=scopes or ["mcp:tools"],
        oauth_token_id="oauth-token-a",
        oauth_issuer="https://auth.example.test",
        oauth_resource="https://mcp.example.test",
        oauth_audiences=["https://mcp.example.test"],
    )


def _codec(now: list[float]) -> StateHandleCodec:
    return StateHandleCodec(
        _SHARED_SECRET,
        default_ttl_seconds=60,
        clock=lambda: now[0],
        nonce_factory=lambda: "fixed-handle-id",
    )


def test_handle_round_trip_is_explicit_bounded_and_session_independent():
    now = [1_000.0]
    codec = _codec(now)
    first_context = _auth_context(session_id="protocol-session-a")
    handle = codec.issue(
        kind="list-page",
        scope="tools:list",
        resource="mcp://tools",
        state={"after": "bravo", "snapshot": "digest"},
        auth_context=first_context,
    )

    assert handle.startswith("mcp-h1.")
    assert first_context.user_id not in handle
    assert first_context.token not in handle
    assert authorization_fingerprint(first_context) == authorization_fingerprint(
        _auth_context(session_id="different-protocol-session")
    )

    claims = codec.resolve(
        handle,
        expected_kind="list-page",
        expected_scope="tools:list",
        expected_resource="mcp://tools",
        auth_context=_auth_context(session_id="different-protocol-session"),
    )
    assert claims.handle_id == "fixed-handle-id"
    assert claims.expires_at == 1_060
    assert claims.state == {"after": "bravo", "snapshot": "digest"}


def test_handle_is_portable_across_instances_only_with_the_shared_secret():
    now = [1_000.0]
    issued = _codec(now).issue(
        kind="list-page",
        scope="tools:list",
        resource="mcp://tools",
        state={"after": "bravo"},
        auth_context=_auth_context(),
    )

    claims = StateHandleCodec(
        _SHARED_SECRET,
        clock=lambda: now[0],
    ).resolve(
        issued,
        expected_kind="list-page",
        expected_scope="tools:list",
        expected_resource="mcp://tools",
        auth_context=_auth_context(),
    )
    assert claims.state == {"after": "bravo"}

    with pytest.raises(StateHandleError, match="invalid"):
        StateHandleCodec(
            "another-shared-state-handle-secret-value",
            clock=lambda: now[0],
        ).resolve(
            issued,
            expected_kind="list-page",
            expected_scope="tools:list",
            expected_resource="mcp://tools",
            auth_context=_auth_context(),
        )


@pytest.mark.parametrize(
    ("context", "kind", "scope", "resource", "reason"),
    [
        (
            _auth_context(user_id="user-b"),
            "list-page",
            "tools:list",
            "mcp://tools",
            "authorization_context_changed",
        ),
        (_auth_context(), "other-kind", "tools:list", "mcp://tools", "wrong_kind"),
        (_auth_context(), "list-page", "resources:list", "mcp://tools", "wrong_scope"),
        (
            _auth_context(),
            "list-page",
            "tools:list",
            "mcp://resources",
            "wrong_resource",
        ),
    ],
)
def test_handle_rejects_cross_principal_scope_resource_and_kind(
    context: AuthContext,
    kind: str,
    scope: str,
    resource: str,
    reason: str,
):
    now = [1_000.0]
    codec = _codec(now)
    handle = codec.issue(
        kind="list-page",
        scope="tools:list",
        resource="mcp://tools",
        state={"after": "bravo"},
        auth_context=_auth_context(),
    )

    with pytest.raises(StateHandleError, match=reason):
        codec.resolve(
            handle,
            expected_kind=kind,
            expected_scope=scope,
            expected_resource=resource,
            auth_context=context,
        )


def test_handle_rejects_expiry_and_tampering_before_exposing_state():
    now = [1_000.0]
    codec = _codec(now)
    handle = codec.issue(
        kind="list-page",
        scope="tools:list",
        resource="mcp://tools",
        state={"after": "bravo"},
        auth_context=_auth_context(),
        ttl_seconds=10,
    )

    now[0] = 1_010.0
    with pytest.raises(StateHandleError, match="expired"):
        codec.resolve(
            handle,
            expected_kind="list-page",
            expected_scope="tools:list",
            expected_resource="mcp://tools",
            auth_context=_auth_context(),
        )

    parts = handle.split(".")
    parts[1] = ("A" if parts[1][0] != "A" else "B") + parts[1][1:]
    with pytest.raises(StateHandleError, match="invalid"):
        codec.resolve(
            ".".join(parts),
            expected_kind="list-page",
            expected_scope="tools:list",
            expected_resource="mcp://tools",
            auth_context=_auth_context(),
        )


def test_handle_enforces_secret_ttl_claim_and_payload_limits():
    with pytest.raises(ValueError, match="at least 32 bytes"):
        StateHandleCodec("too-short")
    with pytest.raises(ValueError, match="TTL"):
        StateHandleCodec(_SHARED_SECRET, default_ttl_seconds=0)

    codec = StateHandleCodec(_SHARED_SECRET)
    with pytest.raises(ValueError, match="resource"):
        codec.issue(
            kind="list-page",
            scope="tools:list",
            resource="",
            state={},
            auth_context=None,
        )
    with pytest.raises(ValueError, match="payload exceeds"):
        codec.issue(
            kind="list-page",
            scope="tools:list",
            resource="mcp://tools",
            state={"oversized": "x" * 3_000},
            auth_context=None,
        )
    with pytest.raises(ValueError, match="handle_id"):
        StateHandleCodec(
            _SHARED_SECRET,
            nonce_factory=lambda: "",
        ).issue(
            kind="list-page",
            scope="tools:list",
            resource="mcp://tools",
            state={},
            auth_context=None,
        )
