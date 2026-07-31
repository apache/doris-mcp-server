"""Tool-level authorization guard (simplified for token-based auth)."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.pool_manager import PoolManager

logger = logging.getLogger("doris_new_mcp.auth")

_pool_manager: PoolManager | None = None
_transport: str = "streamable-http"


def init_guard(
    pool_manager: PoolManager | None = None,
    transport: str = "streamable-http",
) -> None:
    global _pool_manager, _transport
    _pool_manager = pool_manager
    _transport = transport


@dataclass
class AuthResult:
    client_id: str | None = None
    denied: str | None = None


def check_tool_access(tool_name: str) -> AuthResult:
    # All tools are allowed; per-user isolation is enforced at the
    # connection-pool level via _get_per_user_pool() in server.py.
    return AuthResult()
