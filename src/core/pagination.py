"""Pagination utilities with TTL-cached tokens."""

from __future__ import annotations

import time
import uuid


# In-memory store: token -> (items, created_at)
_cache: dict[str, tuple[list, float]] = {}
_TTL = 3600  # 1 hour


def _cleanup() -> None:
    """Remove expired tokens."""
    now = time.time()
    expired = [k for k, (_, ts) in _cache.items() if now - ts > _TTL]
    for k in expired:
        del _cache[k]


def paginate(
    items: list,
    page_size: int = 50,
    page_token: str | None = None,
) -> tuple[list, str | None, int]:
    """Paginate a list of items.

    Returns (page_items, next_page_token, total_count).
    """
    _cleanup()
    total = len(items)

    if page_token and page_token in _cache:
        cached_items, _ = _cache[page_token]
        items = cached_items
        total = len(items)
        # Find the offset encoded in the token
        # Token format: uuid:offset
        parts = page_token.split(":")
        offset = int(parts[1]) if len(parts) > 1 else 0
    else:
        offset = 0

    if page_size <= 0:
        page_size = 50

    page = items[offset : offset + page_size]
    next_offset = offset + page_size

    next_token = None
    if next_offset < total:
        token_id = str(uuid.uuid4())[:8]
        next_token = f"{token_id}:{next_offset}"
        _cache[next_token] = (items, time.time())

    # Clean up used token
    if page_token and page_token in _cache:
        del _cache[page_token]

    return page, next_token, total
