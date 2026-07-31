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
"""Tamper-evident, principal-bound state handles for stateless MCP calls."""

from __future__ import annotations

import base64
import binascii
import json
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest
from hmac import new as new_hmac
from typing import Any

from .utils.security import AuthContext

DEFAULT_STATE_HANDLE_TTL_SECONDS = 300
MAX_STATE_HANDLE_TTL_SECONDS = 3600
MIN_STATE_HANDLE_SECRET_BYTES = 32

_HANDLE_PREFIX = "mcp-h1"
_HANDLE_VERSION = 1
_MAX_HANDLE_LENGTH = 4096
_MAX_PAYLOAD_BYTES = 2048
_MAX_CLAIM_LENGTH = 256
_HANDLE_FIELDS = {
    "version",
    "handleId",
    "kind",
    "scope",
    "resource",
    "principal",
    "expiresAt",
    "state",
}


class StateHandleError(ValueError):
    """A state handle is malformed, expired, or outside the caller boundary."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class StateHandleClaims:
    """Verified, non-identity claims recovered from an explicit state handle."""

    handle_id: str
    kind: str
    scope: str
    resource: str
    expires_at: int
    state: dict[str, Any]


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return sha256(_canonical_json(value)).hexdigest()


def authorization_fingerprint(auth_context: AuthContext | None) -> str:
    """Hash the stable authorization boundary without protocol-session state."""
    if auth_context is None:
        return _digest({"authMethod": "anonymous", "principal": "anonymous"})

    security_level = getattr(auth_context.security_level, "value", "")
    return _digest(
        {
            "authMethod": auth_context.auth_method,
            "tokenId": auth_context.token_id,
            "userId": auth_context.user_id,
            "roles": sorted(auth_context.roles),
            "permissions": sorted(auth_context.permissions),
            "securityLevel": security_level,
            "dorisUser": auth_context.doris_user,
            "oauthClientId": auth_context.oauth_client_id,
            "oauthScopes": sorted(auth_context.oauth_scopes),
            "oauthTokenId": auth_context.oauth_token_id,
            "oauthIssuer": auth_context.oauth_issuer,
            "oauthResource": auth_context.oauth_resource,
            "oauthAudiences": sorted(auth_context.oauth_audiences),
            "poolKey": auth_context.pool_key,
            "dorisOAuthChildTools": {
                "enabled": auth_context.doris_oauth_child_tools_enabled,
                "allowlist": sorted(
                    auth_context.doris_oauth_child_tool_allowlist
                ),
            },
            "dorisOAuthDatabaseTools": {
                "enabled": auth_context.doris_oauth_db_tools_enabled,
                "allowlist": sorted(auth_context.doris_oauth_db_tool_allowlist),
            },
            "dorisOAuthQueryTools": {
                "enabled": auth_context.doris_oauth_query_tools_enabled,
                "allowlist": sorted(auth_context.doris_oauth_query_tool_allowlist),
            },
            "dorisOAuthExplainTools": {
                "enabled": auth_context.doris_oauth_explain_tools_enabled,
                "allowlist": sorted(auth_context.doris_oauth_explain_tool_allowlist),
            },
        }
    )


def _encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_base64url(value: str) -> bytes:
    try:
        padding = "=" * (-len(value) % 4)
        decoded = base64.b64decode(
            (value + padding).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise StateHandleError("invalid") from exc
    if _encode_base64url(decoded) != value:
        raise StateHandleError("invalid")
    return decoded


def _validate_claim(name: str, value: str) -> None:
    if not value or len(value) > _MAX_CLAIM_LENGTH:
        raise ValueError(f"{name} must be 1-{_MAX_CLAIM_LENGTH} characters")


class StateHandleCodec:
    """Issue and verify explicit state handles shared by MCP transports."""

    def __init__(
        self,
        secret: str | bytes,
        *,
        default_ttl_seconds: int = DEFAULT_STATE_HANDLE_TTL_SECONDS,
        clock: Callable[[], float] = time.time,
        nonce_factory: Callable[[], str] = lambda: secrets.token_urlsafe(18),
    ) -> None:
        secret_bytes = secret.encode("utf-8") if isinstance(secret, str) else secret
        if len(secret_bytes) < MIN_STATE_HANDLE_SECRET_BYTES:
            raise ValueError(
                "state handle secret must contain at least "
                f"{MIN_STATE_HANDLE_SECRET_BYTES} bytes"
            )
        if not 1 <= default_ttl_seconds <= MAX_STATE_HANDLE_TTL_SECONDS:
            raise ValueError(
                "state handle TTL must be in the range "
                f"1-{MAX_STATE_HANDLE_TTL_SECONDS} seconds"
            )
        self._secret = secret_bytes
        self._default_ttl_seconds = default_ttl_seconds
        self._clock = clock
        self._nonce_factory = nonce_factory

    def issue(
        self,
        *,
        kind: str,
        scope: str,
        resource: str,
        state: Mapping[str, Any],
        auth_context: AuthContext | None,
        ttl_seconds: int | None = None,
    ) -> str:
        """Return an explicit handle for state needed by a later MCP call."""
        _validate_claim("kind", kind)
        _validate_claim("scope", scope)
        _validate_claim("resource", resource)
        ttl = self._default_ttl_seconds if ttl_seconds is None else ttl_seconds
        if isinstance(ttl, bool) or not 1 <= ttl <= MAX_STATE_HANDLE_TTL_SECONDS:
            raise ValueError(
                "state handle TTL must be in the range "
                f"1-{MAX_STATE_HANDLE_TTL_SECONDS} seconds"
            )

        now = int(self._clock())
        handle_id = self._nonce_factory()
        _validate_claim("handle_id", handle_id)
        payload = {
            "version": _HANDLE_VERSION,
            "handleId": handle_id,
            "kind": kind,
            "scope": scope,
            "resource": resource,
            "principal": authorization_fingerprint(auth_context),
            "expiresAt": now + ttl,
            "state": dict(state),
        }
        payload_bytes = _canonical_json(payload)
        if len(payload_bytes) > _MAX_PAYLOAD_BYTES:
            raise ValueError(f"state handle payload exceeds {_MAX_PAYLOAD_BYTES} bytes")

        encoded_payload = _encode_base64url(payload_bytes)
        signature = new_hmac(
            self._secret,
            encoded_payload.encode("ascii"),
            sha256,
        ).digest()
        handle = ".".join(
            (_HANDLE_PREFIX, encoded_payload, _encode_base64url(signature))
        )
        if len(handle) > _MAX_HANDLE_LENGTH:
            raise ValueError(f"state handle exceeds {_MAX_HANDLE_LENGTH} characters")
        return handle

    def resolve(
        self,
        handle: str,
        *,
        expected_kind: str,
        expected_scope: str,
        expected_resource: str,
        auth_context: AuthContext | None,
    ) -> StateHandleClaims:
        """Verify a handle and return state only inside its original boundary."""
        if not handle or len(handle) > _MAX_HANDLE_LENGTH:
            raise StateHandleError("invalid")
        parts = handle.split(".")
        if len(parts) != 3 or parts[0] != _HANDLE_PREFIX:
            raise StateHandleError("invalid")

        encoded_payload, encoded_signature = parts[1:]
        supplied_signature = _decode_base64url(encoded_signature)
        expected_signature = new_hmac(
            self._secret,
            encoded_payload.encode("ascii"),
            sha256,
        ).digest()
        if not compare_digest(supplied_signature, expected_signature):
            raise StateHandleError("invalid")

        payload_bytes = _decode_base64url(encoded_payload)
        if len(payload_bytes) > _MAX_PAYLOAD_BYTES:
            raise StateHandleError("invalid")
        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise StateHandleError("invalid") from exc

        if not isinstance(payload, dict) or set(payload) != _HANDLE_FIELDS:
            raise StateHandleError("invalid")
        if payload.get("version") != _HANDLE_VERSION:
            raise StateHandleError("invalid")
        if not all(
            isinstance(payload.get(field), str)
            for field in (
                "handleId",
                "kind",
                "scope",
                "resource",
                "principal",
            )
        ):
            raise StateHandleError("invalid")
        expires_at = payload.get("expiresAt")
        if isinstance(expires_at, bool) or not isinstance(expires_at, int):
            raise StateHandleError("invalid")
        state = payload.get("state")
        if not isinstance(state, dict):
            raise StateHandleError("invalid")
        if expires_at <= int(self._clock()):
            raise StateHandleError("expired")
        if payload["kind"] != expected_kind:
            raise StateHandleError("wrong_kind")
        if payload["scope"] != expected_scope:
            raise StateHandleError("wrong_scope")
        if payload["resource"] != expected_resource:
            raise StateHandleError("wrong_resource")
        if not compare_digest(
            payload["principal"],
            authorization_fingerprint(auth_context),
        ):
            raise StateHandleError("authorization_context_changed")

        return StateHandleClaims(
            handle_id=payload["handleId"],
            kind=payload["kind"],
            scope=payload["scope"],
            resource=payload["resource"],
            expires_at=expires_at,
            state=dict(state),
        )
