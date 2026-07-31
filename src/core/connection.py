"""Async connection pool for a single Doris cluster."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import aiomysql

from config.loader import ClusterConfig

logger = logging.getLogger("doris_new_mcp.connection")


class ConnectionPool:
    """Manages an aiomysql pool for the Doris cluster."""

    def __init__(
        self,
        cluster: ClusterConfig,
        user: str,
        password: str,
        min_size: int | None = None,
        max_size: int | None = None,
        host: str | None = None,
    ):
        self._cluster = cluster
        self._user = user
        self._password = password
        self._min_size = min_size if min_size is not None else cluster.pool_min_size
        self._max_size = max_size if max_size is not None else cluster.pool_max_size
        self._host = host or cluster.fe_host  # override for per-user non-127.0.0.1 pools
        self._pool: aiomysql.Pool | None = None
        self._lock = asyncio.Lock()

    async def _ensure_pool(self) -> aiomysql.Pool:
        if self._pool is not None and not self._pool.closed:
            return self._pool
        async with self._lock:
            if self._pool is not None and not self._pool.closed:
                return self._pool
            self._pool = await aiomysql.create_pool(
                host=self._host,
                port=self._cluster.fe_mysql_port,
                user=self._user,
                password=self._password,
                minsize=self._min_size,
                maxsize=self._max_size,
                connect_timeout=10,
                autocommit=True,
                # Recycle connections idle longer than this so a connection
                # silently dropped by Doris wait_timeout is never reused.
                pool_recycle=self._cluster.pool_idle_timeout,
            )
            return self._pool

    async def execute(
        self,
        sql: str,
        database: str | None = None,
        max_rows: int | None = None,
        timeout: int | None = None,
    ) -> tuple[list[dict[str, Any]], list[str]]:
        """Execute SQL and return (rows_as_dicts, column_names)."""
        pool = await self._ensure_pool()
        _timeout = timeout or self._cluster.query_timeout
        _max_rows = max_rows or self._cluster.max_rows

        async with pool.acquire() as conn:
            try:
                if database:
                    await conn.select_db(database)
                async with conn.cursor(aiomysql.DictCursor) as cur:
                    await asyncio.wait_for(cur.execute(sql), timeout=_timeout)
                    rows = await cur.fetchmany(_max_rows)
                    columns = [d[0] for d in cur.description] if cur.description else []
                    return list(rows), columns
            except (asyncio.TimeoutError, asyncio.CancelledError):
                # Timed out or cancelled mid-query: the connection's protocol
                # state is unknown, so close it — pool.release() discards
                # closed connections instead of returning them to the pool.
                # asyncio.TimeoutError is builtin TimeoutError on 3.11+ and
                # a distinct class on 3.10; both are covered here.
                conn.close()
                raise

    async def close(self) -> None:
        if self._pool and not self._pool.closed:
            self._pool.close()
            await self._pool.wait_closed()
            self._pool = None
