"""Per-user Doris connection pool manager.

Manages independent connection pools for each authenticated Doris user.
Pools are created lazily via get_or_create_local_pool and validated
against Doris via non-127.0.0.1 machine IP (SELECT 1).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Callable

from config.loader import ClusterConfig
from core.connection import ConnectionPool

logger = logging.getLogger("doris_new_mcp.pool_manager")


def _is_auth_error(exc: Exception) -> bool:
    """Check if an exception is caused by Doris authentication failure."""
    msg = str(exc).lower()
    return "access denied" in msg or "password" in msg or "authentication" in msg


class PoolManager:
    """Manages per-user connection pools for Doris."""

    def __init__(self, cluster: ClusterConfig):
        self._cluster = cluster
        self._pools: dict[str, ConnectionPool] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._meta_lock = asyncio.Lock()

    async def get_or_create_local_pool(
        self, user: str, password: str = "",
        host: str | None = None,
        on_auth_error: Callable[[], None] | None = None,
    ) -> ConnectionPool:
        """Get or create a per-user pool.

        ``host`` overrides the default cluster host — used for non-127.0.0.1
        per-user connections while admin ops stay on 127.0.0.1.

        ``on_auth_error`` is called if a newly-created pool fails its first
        connection — used to invalidate the credential cache.
        """
        lock = await self._get_user_lock(user)
        async with lock:
            existing = self._pools.get(user)
            if existing is not None:
                if existing._password == password and existing._host == (host or self._cluster.fe_host):
                    return existing
                old_pool = existing
                new_pool = ConnectionPool(
                    self._cluster, user, password,
                    min_size=0, max_size=self._cluster.pool_max_size,
                    host=host,
                )
                # Validate new pool before replacing old one
                try:
                    await new_pool.execute("SELECT 1", timeout=5)
                except Exception as e:
                    if _is_auth_error(e) and on_auth_error:
                        on_auth_error()
                    await new_pool.close()
                    raise
                self._pools[user] = new_pool
                await self._drain_pool(old_pool, user)
                logger.info("Replaced pool for user '%s' (credentials/host changed)", user)
                return new_pool
            new_pool = ConnectionPool(
                self._cluster, user, password,
                min_size=0, max_size=self._cluster.pool_max_size,
                host=host,
            )
            # Validate on first creation
            try:
                await new_pool.execute("SELECT 1", timeout=5)
            except Exception as e:
                if _is_auth_error(e) and on_auth_error:
                    on_auth_error()
                await new_pool.close()
                raise
            self._pools[user] = new_pool
            logger.info(
                "Created pool for user '%s' @ %s (min=0, max=%d)",
                user, host or self._cluster.fe_host, self._cluster.pool_max_size,
            )
            return new_pool

    async def evict(self, user: str) -> None:
        lock = self._locks.get(user)
        if lock is None:
            return

        async with lock:
            pool = self._pools.pop(user, None)
            if pool is None:
                return

        try:
            await pool.close()
            logger.info("Evicted pool for user '%s'", user)
        except Exception:
            logger.exception("Error while closing pool for user '%s'", user)

    async def close_all(self) -> None:
        """Close all connection pools. Called on server shutdown."""
        async with self._meta_lock:
            users = list(self._pools.keys())

        for user in users:
            try:
                await self.evict(user)
            except Exception:
                logger.exception("close_all: failed to evict user '%s'", user)

        logger.info("All user pools closed")

    async def _get_user_lock(self, user: str) -> asyncio.Lock:
        lock = self._locks.get(user)
        if lock is not None:
            return lock
        async with self._meta_lock:
            lock = self._locks.get(user)
            if lock is None:
                lock = asyncio.Lock()
                self._locks[user] = lock
        return lock

    async def _drain_pool(self, pool: ConnectionPool, user: str) -> None:
        try:
            await pool.close()
            logger.info("Drained replaced pool for user '%s'", user)
        except Exception:
            logger.exception(
                "Error while draining replaced pool for user '%s'", user,
            )
