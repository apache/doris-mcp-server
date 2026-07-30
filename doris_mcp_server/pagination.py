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
"""Stateless, permission-bound pagination for MCP list operations."""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest
from typing import Any, Generic, Literal, TypeVar

from .utils.security import AuthContext

DEFAULT_LIST_PAGE_SIZE = 100
MAX_LIST_PAGE_SIZE = 1000
_CURSOR_VERSION = 1
_MAX_CURSOR_LENGTH = 2048
_CURSOR_FIELDS = {
    "version",
    "collection",
    "after",
    "snapshot",
    "authorization",
}

CursorCollection = Literal["resources", "tools", "prompts"]
T = TypeVar("T")


class PaginationCursorError(ValueError):
    """An invalid cursor supplied by an MCP client."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class PaginationPage(Generic[T]):
    """One deterministic page and the opaque cursor for its successor."""

    items: list[T]
    next_cursor: str | None


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return sha256(_canonical_json(value)).hexdigest()


def _authorization_fingerprint(auth_context: AuthContext | None) -> str:
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


def _encode_cursor(payload: dict[str, Any]) -> str:
    return (
        base64.urlsafe_b64encode(_canonical_json(payload)).decode("ascii").rstrip("=")
    )


def _decode_cursor(cursor: str) -> dict[str, Any]:
    if not cursor or len(cursor) > _MAX_CURSOR_LENGTH:
        raise PaginationCursorError("invalid")
    try:
        padding = "=" * (-len(cursor) % 4)
        raw = base64.b64decode(
            (cursor + padding).encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
        payload = json.loads(raw.decode("utf-8"))
    except (
        UnicodeEncodeError,
        UnicodeDecodeError,
        binascii.Error,
        json.JSONDecodeError,
    ) as exc:
        raise PaginationCursorError("invalid") from exc

    if not isinstance(payload, dict) or set(payload) != _CURSOR_FIELDS:
        raise PaginationCursorError("invalid")
    if payload.get("version") != _CURSOR_VERSION:
        raise PaginationCursorError("invalid")
    if not all(
        isinstance(payload.get(field), str)
        for field in ("collection", "after", "snapshot", "authorization")
    ):
        raise PaginationCursorError("invalid")
    return payload


def paginate(
    items: Sequence[T],
    *,
    collection: CursorCollection,
    cursor: str | None,
    page_size: int,
    identifier: Callable[[T], str],
    auth_context: AuthContext | None,
) -> PaginationPage[T]:
    """Return a deterministic keyset page or reject an unsafe continuation."""
    if not 1 <= page_size <= MAX_LIST_PAGE_SIZE:
        raise ValueError(f"page_size must be in the range 1-{MAX_LIST_PAGE_SIZE}")

    ordered = sorted(items, key=identifier)
    identifiers = [identifier(item) for item in ordered]
    if len(identifiers) != len(set(identifiers)):
        raise RuntimeError(f"{collection} list contains duplicate identifiers")

    snapshot = _digest(identifiers)
    authorization = _authorization_fingerprint(auth_context)
    start = 0

    if cursor is not None:
        payload = _decode_cursor(cursor)
        if payload["collection"] != collection:
            raise PaginationCursorError("wrong_collection")
        if not compare_digest(payload["authorization"], authorization):
            raise PaginationCursorError("authorization_context_changed")
        if not compare_digest(payload["snapshot"], snapshot):
            raise PaginationCursorError("stale")
        try:
            start = identifiers.index(payload["after"]) + 1
        except ValueError as exc:
            raise PaginationCursorError("stale") from exc
        if start >= len(ordered):
            raise PaginationCursorError("invalid")

    page_items = ordered[start : start + page_size]
    end = start + len(page_items)
    next_cursor = None
    if page_items and end < len(ordered):
        next_cursor = _encode_cursor(
            {
                "version": _CURSOR_VERSION,
                "collection": collection,
                "after": identifiers[end - 1],
                "snapshot": snapshot,
                "authorization": authorization,
            }
        )

    return PaginationPage(items=page_items, next_cursor=next_cursor)
