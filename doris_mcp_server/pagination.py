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
"""Explicit, permission-bound continuation handles for MCP list operations."""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest
from typing import Generic, Literal, TypeVar

from .state_handles import StateHandleCodec, StateHandleError
from .utils.security import AuthContext

DEFAULT_LIST_PAGE_SIZE = 100
MAX_LIST_PAGE_SIZE = 1000

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


def _handle_scope(collection: CursorCollection) -> str:
    return f"{collection}:list"


def _handle_resource(collection: CursorCollection) -> str:
    return f"mcp://{collection}"


def _snapshot_digest(identifiers: list[str]) -> str:
    payload = json.dumps(
        identifiers,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(payload).hexdigest()


def paginate(
    items: Sequence[T],
    *,
    collection: CursorCollection,
    cursor: str | None,
    page_size: int,
    identifier: Callable[[T], str],
    auth_context: AuthContext | None,
    handle_codec: StateHandleCodec,
) -> PaginationPage[T]:
    """Return a deterministic page or reject an unsafe explicit handle."""
    if not 1 <= page_size <= MAX_LIST_PAGE_SIZE:
        raise ValueError(f"page_size must be in the range 1-{MAX_LIST_PAGE_SIZE}")

    ordered = sorted(items, key=identifier)
    identifiers = [identifier(item) for item in ordered]
    if len(identifiers) != len(set(identifiers)):
        raise RuntimeError(f"{collection} list contains duplicate identifiers")

    snapshot = _snapshot_digest(identifiers)
    start = 0

    if cursor is not None:
        try:
            claims = handle_codec.resolve(
                cursor,
                expected_kind="list-page",
                expected_scope=_handle_scope(collection),
                expected_resource=_handle_resource(collection),
                auth_context=auth_context,
            )
        except StateHandleError as exc:
            reason = (
                "wrong_collection"
                if exc.reason in {"wrong_resource", "wrong_scope"}
                else exc.reason
            )
            raise PaginationCursorError(reason) from exc
        if set(claims.state) != {"after", "snapshot"}:
            raise PaginationCursorError("invalid")
        after = claims.state.get("after")
        claimed_snapshot = claims.state.get("snapshot")
        if not isinstance(after, str) or not isinstance(claimed_snapshot, str):
            raise PaginationCursorError("invalid")
        if not compare_digest(claimed_snapshot, snapshot):
            raise PaginationCursorError("stale")
        try:
            start = identifiers.index(after) + 1
        except ValueError as exc:
            raise PaginationCursorError("stale") from exc
        if start >= len(ordered):
            raise PaginationCursorError("invalid")

    page_items = ordered[start : start + page_size]
    end = start + len(page_items)
    next_cursor = None
    if page_items and end < len(ordered):
        next_cursor = handle_codec.issue(
            kind="list-page",
            scope=_handle_scope(collection),
            resource=_handle_resource(collection),
            state={
                "after": identifiers[end - 1],
                "snapshot": snapshot,
            },
            auth_context=auth_context,
        )

    return PaginationPage(items=page_items, next_cursor=next_cursor)
