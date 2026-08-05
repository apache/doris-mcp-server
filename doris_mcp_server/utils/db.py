#!/usr/bin/env python3
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
"""
Apache Doris Database Connection Management Module

Provides high-performance database connection pool management, automatic reconnection mechanism and connection health check functionality
Supports asynchronous operations and concurrent connection management, ensuring stability and performance for enterprise applications
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import re
import secrets
import time
import uuid
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, NotRequired, TypedDict

import aiomysql
from aiomysql import Connection, Pool

from ..result_limits import json_array_row_size
from .config import DorisConfig
from .datetime_utils import utc_now
from .logger import get_logger

if TYPE_CHECKING:
    from ..auth.token_manager import TokenManager
    from .security import AuthContext, DorisSecurityManager

_SQL_COMMENT_RE = re.compile(r"/\*.*?\*/|--[^\n]*", re.DOTALL)
_QUOTED_IDENTIFIER_SQL = r"`(?:``|[^`])+`"
_INTERNAL_SESSION_CONTROL_PATTERNS = (
    re.compile(
        rf"\AUSE\s+(?:CATALOG\s+)?{_QUOTED_IDENTIFIER_SQL}\s*;?\Z",
        re.IGNORECASE,
    ),
    re.compile(
        rf"\ASWITCH\s+{_QUOTED_IDENTIFIER_SQL}\s*;?\Z",
        re.IGNORECASE,
    ),
    re.compile(r"\ASET\s+ENABLE_PROFILE\s*=\s*TRUE\s*;?\Z", re.IGNORECASE),
    re.compile(
        r'\ASET\s+SESSION_CONTEXT\s*=\s*"TRACE_ID:[0-9A-F-]{32,36}"\s*;?\Z',
        re.IGNORECASE,
    ),
)


def get_first_sql_keyword(sql: str) -> str:
    """Return the first SQL keyword (uppercase), ignoring leading comments/whitespace.

    Strips `--` line comments and `/* */` block comments before extracting
    the first token. A leading comment must not change how a statement is
    classified (e.g. `-- note\\nSELECT 1` is still a SELECT).
    """
    if not sql:
        return ""
    stripped = _SQL_COMMENT_RE.sub("", sql).strip()
    if not stripped:
        return ""
    return stripped.split(None, 1)[0].upper()


def _validate_internal_session_control(sql: str) -> None:
    """Allow only the fixed session controls required by trusted runtimes."""
    if any(
        pattern.fullmatch(sql.strip()) for pattern in _INTERNAL_SESSION_CONTROL_PATTERNS
    ):
        return
    raise ValueError("SQL is not an approved internal session-control statement")


@dataclass
class ConnectionMetrics:
    """Connection pool performance metrics"""

    total_connections: int = 0
    active_connections: int = 0
    idle_connections: int = 0
    failed_connections: int = 0
    connection_errors: int = 0
    avg_connection_time: float = 0.0
    last_health_check: datetime | None = None


@dataclass
class QueryResult:
    """Query result wrapper"""

    data: list[dict[str, Any]]
    metadata: dict[str, Any]
    execution_time: float
    row_count: int
    sql: str


class DatabasePoolConfig(TypedDict):
    """Connection parameters shared by global and token-owned pools."""

    host: str
    hosts: NotRequired[list[str]]
    port: int
    user: str
    password: str
    database: str
    charset: str


@dataclass
class DorisUserPoolMeta:
    """Metadata for an active Doris-user-owned pool."""

    user: str
    pool_key: str
    owner_id: str
    created_at: datetime
    last_used: datetime
    maxsize: int
    database: str
    charset: str
    credential_fingerprint: str
    generation: int = 0


@dataclass(frozen=True, slots=True)
class DorisRouteIdentity:
    """Secret-free identity for one routed Doris connection pool."""

    route_key: str
    generation: int
    endpoint_fingerprint: str
    fingerprint: str


class DorisUserPoolMissingError(RuntimeError):
    """Raised when a Doris OAuth request has no local Doris user pool."""

    error_code = "DORIS_OAUTH_POOL_MISSING"
    status_code = 401

    def __init__(self, message: str = "Doris OAuth user pool is missing"):
        super().__init__(message)


class DorisUserAuthenticationError(RuntimeError):
    """Raised when Doris username/password authentication fails."""

    error_code = "DORIS_AUTHENTICATION_FAILED"
    status_code = 401

    def __init__(self, message: str = "Doris user authentication failed"):
        super().__init__(message)


class DorisConnection:
    """Doris database connection wrapper class"""

    def __init__(
        self,
        connection: Connection,
        session_id: str,
        security_manager: DorisSecurityManager | None = None,
        *,
        pool_kind: str = "global",
        route_key: str = "global",
        owner_id: str = "global:0",
        generation: int = 0,
        owner_pool: Pool | None = None,
    ) -> None:
        self.connection = connection
        self.session_id = session_id
        self.created_at = utc_now()
        self.last_used = utc_now()
        self.query_count = 0
        self.is_healthy = True
        self.security_manager = security_manager
        self.pool_kind = pool_kind
        self.route_key = route_key
        self.owner_id = owner_id
        self.generation = generation
        self.owner_pool = owner_pool
        self.logger = get_logger(__name__)

    async def execute(
        self,
        sql: str,
        params: Mapping[str, Any] | tuple[Any, ...] | None = None,
        auth_context: AuthContext | None = None,
        *,
        mask_result: bool = True,
        max_rows: int | None = None,
        max_bytes: int | None = None,
        internal_session_control: bool = False,
    ) -> QueryResult:
        """Execute SQL after validation, with optional result masking.

        ``mask_result=False`` is reserved for trusted internal control data
        that must remain machine-readable after authorization. Session state
        changes require ``internal_session_control=True`` and must match the
        fixed allowlist enforced below.
        """
        start_time = time.time()
        cursor: Any | None = None
        bounded_result = max_rows is not None or max_bytes is not None

        try:
            # The production connection boundary is read-only even when a
            # caller omits auth_context. Only tightly constrained, code-owned
            # session controls can take the explicit internal path.
            security_result = None
            if internal_session_control:
                _validate_internal_session_control(sql)
            else:
                # Local import avoids a module import cycle: query_runtime owns
                # the canonical Query-domain read-only parser and imports db.
                from .query_runtime import ReadOnlySQLGuard

                ReadOnlySQLGuard.validate(sql)
                if self.security_manager and auth_context:
                    validation_result = (
                        await self.security_manager.validate_sql_security(
                            sql, auth_context
                        )
                    )
                    if not validation_result.is_valid:
                        raise ValueError(
                            "SQL security validation failed: "
                            f"{validation_result.error_message}"
                        )
                    security_result = {
                        "is_valid": validation_result.is_valid,
                        "risk_level": validation_result.risk_level,
                        "blocked_operations": validation_result.blocked_operations,
                    }

            cursor_type = (
                aiomysql.SSDictCursor if bounded_result else aiomysql.DictCursor
            )
            cursor = await self.connection.cursor(cursor_type)
            await cursor.execute(sql, params)

            # cursor.description is set by the DB driver for any statement that returns rows,
            # avoiding a brittle hardcoded keyword list (e.g. missing WITH/CTE, comments before keywords).
            result_bytes: int | None = None
            truncated = False
            truncation_reason: str | None = None
            if cursor.description:
                if bounded_result:
                    (
                        final_data,
                        result_bytes,
                        truncated,
                        truncation_reason,
                    ) = await self._fetch_bounded_rows(
                        cursor,
                        auth_context=auth_context,
                        mask_result=mask_result,
                        max_rows=max_rows,
                        max_bytes=max_bytes,
                    )
                    data = final_data
                    row_count = len(final_data)
                else:
                    data = await cursor.fetchall()
                    row_count = len(data)
            else:
                data = []
                row_count = cursor.rowcount

            execution_time = time.time() - start_time
            self.last_used = utc_now()
            self.query_count += 1

            # Get column information
            columns = []
            if cursor.description:
                columns = [desc[0] for desc in cursor.description]

            # If security manager exists and has auth context, apply data masking
            final_data = list(data) if data else []
            if (
                not bounded_result
                and self.security_manager
                and auth_context
                and final_data
                and mask_result
            ):
                final_data = await self.security_manager.apply_data_masking(
                    final_data,
                    auth_context,
                )

            metadata: dict[str, Any] = {
                "columns": columns,
                "query": sql,
                "params": params,
            }
            if security_result:
                metadata["security_check"] = security_result
            if bounded_result:
                metadata.update(
                    {
                        "result_bytes": result_bytes or 2,
                        "truncated": truncated,
                        "truncation_reason": truncation_reason,
                    }
                )

            if truncated:
                # An unbuffered cursor still has unread rows.  Closing the
                # physical connection avoids draining an attacker-sized
                # result and prevents it from returning to the pool.  Clear
                # the local cursor first so cleanup never calls SSCursor.close,
                # which would otherwise drain the unread result.
                self.is_healthy = False
                cursor = None
                await self.connection.ensure_closed()
            else:
                cursor_to_close = cursor
                cursor = None
                try:
                    await cursor_to_close.close()
                except Exception:
                    self.is_healthy = False
                    await self.connection.ensure_closed()
                    raise

            return QueryResult(
                data=final_data,
                metadata=metadata,
                execution_time=execution_time,
                row_count=row_count,
                sql=sql,
            )

        except asyncio.CancelledError:
            # MCP cancellation and asyncio timeouts both arrive here as task
            # cancellation.  A running MySQL command cannot safely be returned
            # to the pool, so terminate its physical connection first.
            self.is_healthy = False
            cursor = None
            try:
                await self.connection.ensure_closed()
            finally:
                raise
        except Exception as e:
            self.is_healthy = False
            if bounded_result and cursor is not None:
                # SSCursor.close() drains unread rows.  A bounded fetch that
                # fails must terminate its physical connection instead.
                cursor = None
                try:
                    await self.connection.ensure_closed()
                except Exception as close_error:
                    self.logger.warning(
                        "Failed to close connection after bounded query failure: %s",
                        close_error,
                    )
            logging.error(f"Query execution failed: {e}")
            raise
        finally:
            if cursor is not None:
                try:
                    await cursor.close()
                except Exception as cleanup_error:
                    self.is_healthy = False
                    self.logger.warning(
                        "Failed to close cursor after query failure: %s",
                        cleanup_error,
                    )
                    try:
                        await self.connection.ensure_closed()
                    except Exception as close_error:
                        self.logger.warning(
                            "Failed to close connection after cursor cleanup failure: %s",
                            close_error,
                        )

    async def _fetch_bounded_rows(
        self,
        cursor: Any,
        *,
        auth_context: AuthContext | None,
        mask_result: bool,
        max_rows: int | None,
        max_bytes: int | None,
    ) -> tuple[list[dict[str, Any]], int, bool, str | None]:
        """Fetch a result incrementally under row and serialized-byte budgets."""
        row_budget = max_rows if max_rows is not None else 100_000
        byte_budget = max_bytes if max_bytes is not None else 16 * 1024 * 1024
        final_data: list[dict[str, Any]] = []
        result_bytes = 2  # JSON array brackets.
        truncation_reason: str | None = None

        while truncation_reason is None:
            remaining_rows = row_budget - len(final_data)
            fetch_size = min(128, remaining_rows + 1)
            rows = list(await cursor.fetchmany(fetch_size))
            if not rows:
                break

            processed_rows = [dict(row) for row in rows]
            if (
                self.security_manager
                and auth_context
                and processed_rows
                and mask_result
            ):
                processed_rows = list(
                    await self.security_manager.apply_data_masking(
                        processed_rows,
                        auth_context,
                    )
                )

            for row in processed_rows:
                if len(final_data) >= row_budget:
                    truncation_reason = "row_limit"
                    break
                row_size = json_array_row_size(row, first=not final_data)
                if result_bytes + row_size > byte_budget:
                    truncation_reason = "byte_limit"
                    break
                final_data.append(row)
                result_bytes += row_size

            if len(rows) < fetch_size:
                break

        return (
            final_data,
            result_bytes,
            truncation_reason is not None,
            truncation_reason,
        )

    async def ping(self) -> bool:
        """Check connection health status with enhanced at_eof error detection"""
        try:
            # Check 1: Connection exists and is not closed
            if not self.connection or self.connection.closed:
                self.is_healthy = False
                return False

            # Check 2: Use ONLY safe operations - avoid internal state access
            # Instead of checking _reader state directly, use a simple query test
            try:
                # Use a simple query with timeout instead of ping() to avoid at_eof issues
                async with asyncio.timeout(3):  # 3 second timeout
                    async with self.connection.cursor() as cursor:
                        await cursor.execute("SELECT 1")
                        result = await cursor.fetchone()
                        if result and result[0] == 1:
                            self.is_healthy = True
                            return True
                        else:
                            self.logger.debug(
                                f"Connection {self.session_id} ping query returned unexpected result"
                            )
                            self.is_healthy = False
                            return False

            except TimeoutError:
                self.logger.debug(f"Connection {self.session_id} ping timed out")
                self.is_healthy = False
                return False
            except Exception as query_error:
                # Check for specific at_eof related errors
                error_str = str(query_error).lower()
                if "at_eof" in error_str or "nonetype" in error_str:
                    self.logger.debug(
                        f"Connection {self.session_id} ping failed with at_eof error: {query_error}"
                    )
                else:
                    self.logger.debug(
                        f"Connection {self.session_id} ping failed: {query_error}"
                    )
                self.is_healthy = False
                return False

        except Exception as e:
            # Catch any other unexpected errors
            self.logger.debug(
                f"Connection {self.session_id} ping failed with unexpected error: {e}"
            )
            self.is_healthy = False
            return False

    async def close(self) -> None:
        """Close connection"""
        try:
            if self.connection and not self.connection.closed:
                await self.connection.ensure_closed()
        except Exception as e:
            logging.error(f"Error occurred while closing connection: {e}")


class DorisSessionCache:
    """Doris database session cache

    Save doris session in memory and get session by session id.
    Provide cache_system_session/cache_user_session to specify whether to save system/user type sessions.
    By default, only session_id is "query" or "system" will be saved.
    """

    def __init__(
        self,
        connection_manager: Any | None = None,
        cache_system_session: bool = True,
        cache_user_session: bool = False,
    ) -> None:
        self.logger = get_logger(__name__)
        self.cached: dict[str, DorisConnection] = {}
        self.connection_manager = connection_manager
        self.cache_system_session = cache_system_session
        self.cache_user_session = cache_user_session
        self.logger.info(
            f"Session  Cache initialized, save system session: {self.cache_system_session}, save user session: {self.cache_user_session}"
        )

    def save(self, connection: DorisConnection) -> None:
        if self._should_cache(connection.session_id):
            self.cached[connection.session_id] = connection

    def get(self, session_id: str) -> DorisConnection | None:
        self.logger.debug(f"Use cached connection: {session_id}")
        return self.cached.get(session_id)

    def remove(self, session_id: str) -> None:
        if session_id in self.cached:
            del self.cached[session_id]
            self.logger.debug(f"Removed session {session_id} from cache.")
        else:
            if self._should_cache(session_id):
                self.logger.warning(f"Session {session_id} is not existed.")

    def clear(self) -> None:
        if self.connection_manager:
            for k, v in self.cached.items():
                self.connection_manager.release_connection(k, v)
        self.cached = {}

    def _is_system_session(self, session_id: str) -> bool:
        return session_id in ["query", "system"]

    def _should_cache(self, session_id: str) -> bool:
        return (self.cache_system_session and self._is_system_session(session_id)) or (
            self.cache_user_session and not self._is_system_session(session_id)
        )


class DorisConnectionManager:
    """Doris database connection manager - Enhanced Strategy

    Uses direct connection pool management with proper synchronization
    Implements connection pool health monitoring and proactive cleanup
    Supports token-bound database configurations for multi-tenant access
    """

    def __init__(
        self,
        config: DorisConfig,
        security_manager: DorisSecurityManager | None = None,
        token_manager: TokenManager | None = None,
    ) -> None:
        self.config = config
        self.pool: Pool | None = None
        self.logger = get_logger(__name__)
        self.security_manager = security_manager
        self.token_manager = token_manager  # Token manager for token-bound DB config

        # 🔧 FIX for multi-tenant concurrency: Per-token connection pool isolation
        # Each token gets its own connection pool to prevent configuration conflicts
        self.token_pools: dict[str, Pool] = {}  # token_hash -> pool
        self.token_configs: dict[str, DatabasePoolConfig] = {}
        self._token_pool_locks: dict[str, asyncio.Lock] = {}  # token_hash -> lock
        self._token_pools_lock = asyncio.Lock()  # Lock for managing token_pools dict
        self._token_pool_owner_ids: dict[str, str] = {}  # token_hash -> owner id
        self._token_pool_generations: dict[
            str, int
        ] = {}  # token_hash -> physical pool generation

        # Doris OAuth user-owned pool state. Raw Doris passwords are never stored.
        self.doris_user_pools: dict[
            str, Pool
        ] = {}  # normalized Doris user -> active pool
        self.doris_user_pool_meta: dict[str, DorisUserPoolMeta] = {}
        self._retired_doris_user_pools: dict[str, Pool] = {}  # owner_id -> retired pool
        self._doris_user_pool_locks: dict[str, asyncio.Lock] = {}
        self._doris_user_pools_lock = asyncio.Lock()
        self._doris_user_pool_secret = secrets.token_bytes(32)
        self._global_pool_owner_id = "global:0"
        self._global_pool_generation = 0

        # FIX for Issue #58 Problem 1: Disable session caching to prevent connection sharing
        # Session caching causes multiple threads to share the same MySQL connection,
        # leading to race conditions and deadlocks in multi-threaded environments
        # By disabling caching, each request gets a fresh connection from the pool
        self.session_cache = DorisSessionCache(
            self,
            cache_system_session=False,  # Disabled to prevent multi-thread issues
            cache_user_session=False,  # Disabled to prevent multi-thread issues
        )

        # Store original database config for fallback
        configured_hosts = self._ordered_hosts(
            config.database.host,
            getattr(config.database, "hosts", []),
        )
        self.original_db_config: DatabasePoolConfig = {
            "host": configured_hosts[0],
            "hosts": configured_hosts,
            "port": config.database.port,
            "user": config.database.user,
            "password": config.database.password,
            "database": config.database.database,
            "charset": config.database.charset,
        }

        # Current active database config (may be overridden by token-bound config)
        # NOTE: This is kept for backward compatibility with non-token requests
        self.active_db_config: DatabasePoolConfig = self.original_db_config.copy()

        # Connection pool state management
        self.pool_recovering = False
        self.pool_health_check_task: asyncio.Task[None] | None = None
        self.pool_cleanup_task: asyncio.Task[None] | None = None

        # Metrics tracking
        self.metrics = ConnectionMetrics()

        # 🔧 FIX: Add connection acquisition lock to prevent race conditions
        self._connection_lock = asyncio.Lock()
        self._recovery_lock = asyncio.Lock()

        # 🔧 FIX: Add connection acquisition queue to serialize requests
        self._connection_semaphore = asyncio.Semaphore(
            value=20
        )  # Max concurrent acquisitions

        # Database connection parameters from config.database
        self.pool_recovery_lock = self._recovery_lock  # Compatibility alias
        self._update_db_params_from_config(self.active_db_config)
        self.connect_timeout = config.database.connection_timeout

        # Connection pool parameters - more conservative settings
        self.minsize = config.database.min_connections  # This is always 0
        self.maxsize = config.database.max_connections or 20
        self.pool_recycle = (
            config.database.max_connection_age or 3600
        )  # 1 hour, more conservative

        # 🔧 FIX: Add missing monitoring parameters that were removed during refactoring
        self.health_check_interval = 30  # seconds
        self.pool_warmup_size = 3  # connections to maintain
        self._last_pool_config: dict[str, str | int] | None = None

    def _update_db_params_from_config(
        self,
        db_config: DatabasePoolConfig,
    ) -> None:
        """Update database connection parameters from config dictionary"""
        self.host = db_config["host"]
        self.port = db_config["port"]
        self.user = db_config["user"]
        self.password = db_config["password"]
        self.database = db_config["database"]
        # Convert charset to aiomysql compatible format
        charset_map = {"UTF8": "utf8", "UTF8MB4": "utf8mb4"}
        self.charset = charset_map.get(
            db_config["charset"].upper(), db_config["charset"].lower()
        )

    @staticmethod
    def _ordered_hosts(primary: str, configured: object) -> list[str]:
        hosts = (
            [
                host.strip()
                for host in configured
                if isinstance(host, str) and host.strip()
            ]
            if isinstance(configured, list)
            else []
        )
        return list(dict.fromkeys(([primary] if primary else []) + hosts))

    def _host_candidates(self, db_config: Mapping[str, Any]) -> list[str]:
        return self._ordered_hosts(
            str(db_config.get("host", "")),
            db_config.get("hosts", []),
        )

    def _set_active_global_host(self, host: str) -> None:
        self.host = host
        self.active_db_config["host"] = host

    def _is_config_empty(self, config_value: object) -> bool:
        """Check if a config value is empty (None, empty string, or 'null')"""
        return (
            config_value is None
            or config_value == ""
            or str(config_value).lower() == "null"
        )

    def _has_valid_global_config(self) -> bool:
        """Check if global database configuration is valid and non-empty"""
        return not self._is_config_empty(
            self.original_db_config["host"]
        ) and not self._is_config_empty(self.original_db_config["user"])

    def _get_token_hash(self, token: str) -> str:
        """Get hash of token for use as dictionary key"""
        import hashlib

        return hashlib.sha256(token.encode()).hexdigest()[:16]

    def _get_current_token_db_config(
        self,
        token: str,
    ) -> DatabasePoolConfig | None:
        """Get current database config for token from TokenManager

        This is used to check if config has changed for hot reload support.
        """
        if not self.token_manager:
            return None

        token_db_config = self.token_manager.get_database_config_by_token(token)
        if token_db_config:
            db_config: DatabasePoolConfig = {
                "host": token_db_config.host,
                "port": token_db_config.port,
                "user": token_db_config.user,
                "password": token_db_config.password,
                "database": token_db_config.database,
                "charset": token_db_config.charset,
            }
            token_hosts = getattr(token_db_config, "hosts", [])
            if token_hosts:
                db_config["hosts"] = self._ordered_hosts(
                    token_db_config.host,
                    token_hosts,
                )
            return db_config
        return None

    def _config_changed(
        self,
        old_config: DatabasePoolConfig | None,
        new_config: DatabasePoolConfig | None,
    ) -> bool:
        """Check if database configuration has changed"""
        if old_config is None or new_config is None:
            return old_config != new_config

        # Compare key fields
        for key in ["host", "hosts", "port", "user", "password", "database"]:
            if old_config.get(key) != new_config.get(key):
                return True
        return False

    def _validate_doris_user(self, user: str) -> str:
        """Validate and normalize a Doris username for pool routing."""
        if not isinstance(user, str) or not user:
            raise DorisUserAuthenticationError("Doris user must be a non-empty string")
        if user != user.strip():
            raise DorisUserAuthenticationError(
                "Doris user must not contain leading or trailing whitespace"
            )
        if len(user) > 256:
            raise DorisUserAuthenticationError("Doris user is too long")
        if any(ch in user for ch in ("\x00", "\n", "\r")):
            raise DorisUserAuthenticationError("Doris user contains invalid characters")
        return user

    def _validate_doris_password(self, password: str) -> None:
        """Validate a Doris password without logging or storing it."""
        if not isinstance(password, str) or not password:
            raise DorisUserAuthenticationError(
                "Doris password must be a non-empty string"
            )
        if len(password) > 256:
            raise DorisUserAuthenticationError("Doris password is too long")
        if any(ch in password for ch in ("\x00", "\n", "\r")):
            raise DorisUserAuthenticationError(
                "Doris password contains invalid characters"
            )

    def _validate_doris_auth_retries(self, max_retries: int) -> int:
        if (
            isinstance(max_retries, bool)
            or not isinstance(max_retries, int)
            or max_retries < 1
        ):
            raise DorisUserAuthenticationError("max_retries must be a positive integer")
        return max_retries

    def _doris_user_route_key(self, user: str) -> str:
        return f"doris_user:{user}"

    def _credential_fingerprint(self, password: str) -> str:
        return hmac.new(
            self._doris_user_pool_secret,
            password.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _get_doris_user_pool_maxsize(self) -> int:
        return max(1, min(5, int(self.maxsize or 1)))

    def _build_doris_user_db_config(self, user: str, password: str) -> dict:
        return {
            "host": self.host,
            "hosts": self._host_candidates(self.original_db_config),
            "port": self.original_db_config["port"],
            "user": user,
            "password": password,
            # Per-user pools must not depend on the service/global default DB:
            # low-privilege Doris RBAC users may lack access to it. Queries can
            # still use fully qualified names or select a DB later.
            "database": "information_schema",
            "charset": self.original_db_config["charset"],
            "maxsize": self._get_doris_user_pool_maxsize(),
        }

    async def _get_doris_user_lock(self, user: str) -> asyncio.Lock:
        async with self._doris_user_pools_lock:
            lock = self._doris_user_pool_locks.get(user)
            if lock is None:
                lock = asyncio.Lock()
                self._doris_user_pool_locks[user] = lock
            return lock

    async def _close_pool_safely(
        self, pool: Pool | None, label: str, timeout: float = 2.0
    ) -> None:
        """Close a pool without letting one failure block broader cleanup."""
        if not pool:
            return
        try:
            if getattr(pool, "closed", False) is not True:
                pool.close()
            wait_closed = getattr(pool, "wait_closed", None)
            if wait_closed:
                try:
                    await asyncio.wait_for(wait_closed(), timeout=timeout)
                except TimeoutError:
                    self.logger.warning(f"Timeout waiting for {label} pool to close")
        except Exception as e:
            self.logger.warning(f"Error closing {label} pool: {e}")

    async def _force_close_raw_connection(
        self, raw_connection: Any, reason: str
    ) -> None:
        """Force-close a raw connection when owner-based release is impossible."""
        if not raw_connection:
            return
        try:
            if getattr(raw_connection, "closed", False) is True:
                return
            ensure_closed = getattr(raw_connection, "ensure_closed", None)
            if ensure_closed:
                result = ensure_closed()
                if asyncio.iscoroutine(result):
                    await result
                return
            close = getattr(raw_connection, "close", None)
            if close:
                result = close()
                if asyncio.iscoroutine(result):
                    await result
        except Exception as e:
            self.logger.debug(f"Error force closing connection after {reason}: {e}")

    async def _close_auth_connection(self, conn: Any) -> None:
        if not conn:
            return
        try:
            close = getattr(conn, "close", None)
            if close:
                result = close()
                if asyncio.iscoroutine(result):
                    await result
                return
            ensure_closed = getattr(conn, "ensure_closed", None)
            if ensure_closed:
                result = ensure_closed()
                if asyncio.iscoroutine(result):
                    await result
        except Exception as e:
            self.logger.debug(f"Error closing Doris auth connection: {e}")

    def _mark_global_pool_created(self) -> None:
        self._global_pool_generation += 1
        self._global_pool_owner_id = (
            f"global:gen:{self._global_pool_generation}:{uuid.uuid4().hex}"
        )

    async def authenticate_doris_user(
        self,
        user: str,
        password: str,
        *,
        max_retries: int = 1,
    ) -> None:
        """Validate Doris username/password against FE MySQL without creating a pool."""
        normalized_user = self._validate_doris_user(user)
        self._validate_doris_password(password)
        retries = self._validate_doris_auth_retries(max_retries)

        last_error: Exception | None = None
        candidate_config = self.original_db_config.copy()
        candidate_config["host"] = self.host
        hosts = self._host_candidates(candidate_config)
        for attempt in range(1, retries + 1):
            for host in hosts:
                conn = None
                try:
                    conn = await aiomysql.connect(
                        host=host,
                        port=self.original_db_config["port"],
                        user=normalized_user,
                        password=password,
                        db="information_schema",
                        charset=self.charset,
                        connect_timeout=self.connect_timeout,
                        autocommit=True,
                    )
                    self._set_active_global_host(host)
                    return
                except DorisUserAuthenticationError:
                    raise
                except Exception as exc:
                    last_error = exc
                    self.logger.warning(
                        "Doris user authentication failed for %s@%s:%s "
                        "on attempt %s/%s (%s)",
                        normalized_user,
                        host,
                        self.original_db_config["port"],
                        attempt,
                        retries,
                        type(exc).__name__,
                    )
                finally:
                    await self._close_auth_connection(conn)

        raise DorisUserAuthenticationError(
            f"Doris user authentication failed for {normalized_user}: {type(last_error).__name__}"
        )

    async def create_or_replace_doris_user_pool(
        self,
        user: str,
        password: str,
        *,
        max_retries: int = 1,
    ) -> None:
        """Authenticate a Doris user, then create/reuse/soft-replace its pool."""
        normalized_user = self._validate_doris_user(user)
        self._validate_doris_password(password)
        self._validate_doris_auth_retries(max_retries)

        await self.authenticate_doris_user(
            normalized_user, password, max_retries=max_retries
        )
        fingerprint = self._credential_fingerprint(password)
        lock = await self._get_doris_user_lock(normalized_user)
        old_pool = None
        old_owner_id = ""

        async with lock:
            existing = self.doris_user_pools.get(normalized_user)
            meta = self.doris_user_pool_meta.get(normalized_user)
            if (
                existing
                and getattr(existing, "closed", False) is not True
                and meta
                and meta.credential_fingerprint == fingerprint
            ):
                meta.last_used = utc_now()
                self.logger.debug("Reusing Doris user pool for %s", normalized_user)
                return

            db_config = self._build_doris_user_db_config(normalized_user, password)
            new_pool = await self._create_pool_with_config(db_config)

            old_pool = existing
            old_meta = meta
            generation = (old_meta.generation + 1) if old_meta else 1
            owner_id = (
                f"doris_user:{normalized_user}:gen:{generation}:{uuid.uuid4().hex}"
            )
            now = utc_now()
            new_meta = DorisUserPoolMeta(
                user=normalized_user,
                pool_key=self._doris_user_route_key(normalized_user),
                owner_id=owner_id,
                created_at=now,
                last_used=now,
                maxsize=db_config["maxsize"],
                database=db_config["database"],
                charset=db_config["charset"],
                credential_fingerprint=fingerprint,
                generation=generation,
            )

            self.doris_user_pools[normalized_user] = new_pool
            self.doris_user_pool_meta[normalized_user] = new_meta
            if old_pool:
                old_owner_id = (
                    old_meta.owner_id
                    if old_meta
                    else f"doris_user:{normalized_user}:retired:{uuid.uuid4().hex}"
                )
                self._retired_doris_user_pools[old_owner_id] = old_pool

        if old_pool:
            await self._close_pool_safely(
                old_pool, f"retired Doris user {old_owner_id}"
            )

    def has_doris_user_pool(self, user: str) -> bool:
        try:
            normalized_user = self._validate_doris_user(user)
        except DorisUserAuthenticationError:
            return False
        pool = self.doris_user_pools.get(normalized_user)
        return bool(pool and getattr(pool, "closed", False) is not True)

    async def get_connection_for_doris_user(
        self, user: str, session_id: str
    ) -> DorisConnection:
        """Acquire a connection from an existing Doris-user pool, fail-closed if absent."""
        try:
            normalized_user = self._validate_doris_user(user)
        except DorisUserAuthenticationError as e:
            raise DorisUserPoolMissingError(str(e)) from e

        lock = await self._get_doris_user_lock(normalized_user)
        async with lock:
            pool = self.doris_user_pools.get(normalized_user)
            meta = self.doris_user_pool_meta.get(normalized_user)
            if not pool or getattr(pool, "closed", False) is True or not meta:
                raise DorisUserPoolMissingError(
                    f"Doris user pool missing for {normalized_user}"
                )

            raw_conn = await asyncio.wait_for(
                pool.acquire(), timeout=self.connect_timeout
            )
            meta.last_used = utc_now()
            return DorisConnection(
                raw_conn,
                session_id,
                self.security_manager,
                pool_kind="doris_user",
                route_key=meta.pool_key,
                owner_id=meta.owner_id,
                generation=meta.generation,
                owner_pool=pool,
            )

    async def release_connection_for_doris_user(
        self, user: str, connection: DorisConnection
    ) -> None:
        """Release a Doris-user connection to its captured owner pool."""
        try:
            normalized_user = self._validate_doris_user(user)
            expected_route_key = self._doris_user_route_key(normalized_user)
        except DorisUserAuthenticationError:
            expected_route_key = ""

        if connection and (
            getattr(connection, "pool_kind", "") != "doris_user"
            or getattr(connection, "route_key", "") != expected_route_key
        ):
            self.logger.warning(
                "Doris user connection route mismatch on release: expected=%s actual=%s kind=%s",
                expected_route_key,
                getattr(connection, "route_key", ""),
                getattr(connection, "pool_kind", ""),
            )
        await self.release_routed_connection(connection)

    async def evict_doris_user_pool(self, user: str) -> None:
        """Remove and close a Doris-user pool if it exists."""
        try:
            normalized_user = self._validate_doris_user(user)
        except DorisUserAuthenticationError:
            return

        lock = await self._get_doris_user_lock(normalized_user)
        pool = None
        owner_id = ""
        async with lock:
            pool = self.doris_user_pools.pop(normalized_user, None)
            meta = self.doris_user_pool_meta.pop(normalized_user, None)
            owner_id = (
                meta.owner_id if meta else self._doris_user_route_key(normalized_user)
            )
            if pool and meta:
                self._retired_doris_user_pools[meta.owner_id] = pool

        await self._close_pool_safely(pool, f"evicted Doris user {owner_id}")

    async def cleanup_idle_doris_user_pools(
        self,
        active_users: set[str] | None = None,
        max_idle_time: int | None = None,
    ) -> None:
        """Close Doris-user pools that are not in active_users and are optionally idle."""
        active_users = active_users or set()
        normalized_active_users = {u for u in active_users if isinstance(u, str)}
        now = utc_now()
        users_to_remove: list[str] = []

        async with self._doris_user_pools_lock:
            for user, pool in list(self.doris_user_pools.items()):
                meta = self.doris_user_pool_meta.get(user)
                if user in normalized_active_users:
                    continue
                if max_idle_time is not None and meta:
                    idle_seconds = (now - meta.last_used).total_seconds()
                    if idle_seconds < max_idle_time:
                        continue
                if pool:
                    users_to_remove.append(user)

        for user in users_to_remove:
            await self.evict_doris_user_pool(user)

    async def close_all_doris_user_pools(self) -> None:
        """Close all active and retired Doris-user pools for shutdown."""
        async with self._doris_user_pools_lock:
            pools_by_owner: list[tuple[str, Pool]] = []
            for user, pool in list(self.doris_user_pools.items()):
                meta = self.doris_user_pool_meta.get(user)
                pools_by_owner.append(
                    (meta.owner_id if meta else self._doris_user_route_key(user), pool)
                )
            pools_by_owner.extend(list(self._retired_doris_user_pools.items()))
            self.doris_user_pools.clear()
            self.doris_user_pool_meta.clear()
            self._retired_doris_user_pools.clear()
            self._doris_user_pool_locks.clear()

        seen_pool_ids: set[int] = set()
        for owner_id, pool in pools_by_owner:
            if not pool or id(pool) in seen_pool_ids:
                continue
            seen_pool_ids.add(id(pool))
            await self._close_pool_safely(pool, f"Doris user {owner_id}")

    async def get_pool_for_token(
        self,
        token: str,
    ) -> tuple[Pool, DatabasePoolConfig]:
        """Get or create a dedicated connection pool for a specific token

        This method implements per-token connection pool isolation to prevent
        concurrent requests from different tokens interfering with each other.

        🔧 FIX: Supports hot reload - if tokens.json config changes,
        the old pool is closed and a new one is created automatically.

        Args:
            token: Authentication token

        Returns:
            (pool, db_config): The dedicated pool and its configuration

        Raises:
            RuntimeError: If no valid database configuration is available
        """
        token_hash = self._get_token_hash(token)

        # Fast path: pool already exists
        if token_hash in self.token_pools:
            pool = self.token_pools[token_hash]
            cached_config = self.token_configs.get(token_hash)

            # 🔧 FIX: Check if config has changed (hot reload support)
            current_config = self._get_current_token_db_config(token)
            if (
                current_config
                and cached_config
                and self._config_changed(cached_config, current_config)
            ):
                self.logger.info(
                    f"Token config changed (hash: {token_hash[:8]}...), recreating pool..."
                )
                # Config changed, need to recreate pool
                async with self._token_pools_lock:
                    # Close old pool
                    old_pool = self.token_pools.pop(token_hash, None)
                    if old_pool and not old_pool.closed:
                        try:
                            old_pool.close()
                            await asyncio.wait_for(old_pool.wait_closed(), timeout=2.0)
                        except Exception as e:
                            self.logger.warning(
                                f"Error closing old pool during hot reload: {e}"
                            )
                    self.token_configs.pop(token_hash, None)
                    self._token_pool_owner_ids.pop(token_hash, None)
                # Continue to slow path to create new pool
            elif pool and not pool.closed and cached_config is not None:
                return pool, cached_config

        # Slow path: need to create pool (with lock to prevent race conditions)
        async with self._token_pools_lock:
            # Double-check after acquiring lock
            if token_hash in self.token_pools:
                pool = self.token_pools[token_hash]
                cached_config = self.token_configs.get(token_hash)
                if pool and not pool.closed and cached_config is not None:
                    return pool, cached_config
                if pool and not pool.closed:
                    pool.close()
                    await pool.wait_closed()
                self.token_pools.pop(token_hash, None)
                self.token_configs.pop(token_hash, None)

            # Get database config for this token
            db_config: DatabasePoolConfig | None = None
            config_source = "unknown"

            if self.token_manager:
                token_db_config = self.token_manager.get_database_config_by_token(token)
                if token_db_config:
                    db_config = {
                        "host": token_db_config.host,
                        "port": token_db_config.port,
                        "user": token_db_config.user,
                        "password": token_db_config.password,
                        "database": token_db_config.database,
                        "charset": token_db_config.charset,
                    }
                    token_hosts = getattr(token_db_config, "hosts", [])
                    if token_hosts:
                        db_config["hosts"] = self._ordered_hosts(
                            token_db_config.host,
                            token_hosts,
                        )
                    config_source = "token-bound"

            # Fallback to global config if token has no specific config
            if (
                not db_config
                or self._is_config_empty(db_config.get("host"))
                or self._is_config_empty(db_config.get("user"))
            ):
                if self._has_valid_global_config():
                    db_config = self.original_db_config.copy()
                    config_source = "global-env"
                else:
                    raise RuntimeError(
                        "No valid database configuration available for token. "
                        "Please configure database in tokens.json or .env file."
                    )

            # Create dedicated pool for this token
            self.logger.info(
                f"Creating dedicated connection pool for token (hash: {token_hash[:8]}...) "
                f"using {config_source} config: {db_config['user']}@{db_config['host']}:{db_config['port']}"
            )

            pool = await self._create_pool_with_config(db_config)

            # Store pool and config
            self.token_pools[token_hash] = pool
            self.token_configs[token_hash] = db_config
            token_generation = self._token_pool_generations.get(token_hash, 0) + 1
            self._token_pool_generations[token_hash] = token_generation
            self._token_pool_owner_ids[token_hash] = (
                f"static_token:{token_hash}:gen:{token_generation}:{uuid.uuid4().hex}"
            )

            # Create lock for this token if not exists
            if token_hash not in self._token_pool_locks:
                self._token_pool_locks[token_hash] = asyncio.Lock()

            return pool, db_config

    async def _create_pool_with_config(
        self,
        db_config: Mapping[str, Any],
    ) -> Pool:
        """Create a pool, failing over when multiple FE hosts are configured."""
        pool, _ = await self._create_pool_with_candidates(db_config)
        return pool

    async def _probe_pool(self, pool: Pool) -> bool:
        raw_connection = None
        try:
            raw_connection = await asyncio.wait_for(
                pool.acquire(),
                timeout=self.connect_timeout,
            )
            async with raw_connection.cursor() as cursor:
                await cursor.execute("SELECT 1")
                result = await cursor.fetchone()
                return bool(result and result[0] == 1)
        except Exception as exc:
            self.logger.debug(
                "Doris FE candidate health probe failed: %s",
                type(exc).__name__,
            )
            return False
        finally:
            if raw_connection is not None:
                try:
                    pool.release(raw_connection)
                except Exception:
                    await self._force_close_raw_connection(
                        raw_connection,
                        "candidate health probe release failure",
                    )

    async def _create_pool_with_candidates(
        self,
        db_config: Mapping[str, Any],
        *,
        minsize: int = 0,
        maxsize: int | None = None,
        timeout: float | None = None,
        require_health: bool | None = None,
    ) -> tuple[Pool, str]:
        """Create a pool against the first reachable FE in an ordered list."""
        # Convert charset to aiomysql compatible format
        charset_map = {"UTF8": "utf8", "UTF8MB4": "utf8mb4"}
        charset = charset_map.get(
            db_config["charset"].upper(), db_config["charset"].lower()
        )
        candidates = self._host_candidates(db_config)
        should_probe = len(candidates) > 1 if require_health is None else require_health
        pool_timeout = timeout or (self.connect_timeout + 5)
        last_error: Exception | None = None

        for host in candidates:
            pool: Pool | None = None
            self.logger.debug(
                "Creating pool for %s@%s:%s/%s",
                db_config["user"],
                host,
                db_config["port"],
                db_config["database"],
            )
            try:
                pool = await asyncio.wait_for(
                    aiomysql.create_pool(
                        host=host,
                        port=db_config["port"],
                        user=db_config["user"],
                        password=db_config["password"],
                        db=db_config["database"],
                        charset=charset,
                        minsize=minsize,
                        maxsize=maxsize or db_config.get("maxsize", self.maxsize),
                        connect_timeout=self.connect_timeout,
                        autocommit=True,
                        pool_recycle=self.pool_recycle,
                    ),
                    timeout=pool_timeout,
                )
                if should_probe and not await self._probe_pool(pool):
                    raise RuntimeError("Doris FE candidate failed its health probe")
                self.logger.info(
                    "Successfully created pool for %s@%s:%s",
                    db_config["user"],
                    host,
                    db_config["port"],
                )
                return pool, host
            except Exception as exc:
                last_error = exc
                await self._close_pool_safely(pool, f"failed FE candidate {host}")
                self.logger.warning(
                    "Doris FE candidate %s:%s failed during pool creation (%s)",
                    host,
                    db_config["port"],
                    type(exc).__name__,
                )

        raise RuntimeError(
            "Unable to create a Doris connection pool from the configured FE hosts"
        ) from last_error

    async def get_connection_for_token(
        self,
        token: str,
        session_id: str,
    ) -> DorisConnection:
        """Get a connection from the token's dedicated pool

        Args:
            token: Authentication token
            session_id: Session identifier for logging

        Returns:
            DorisConnection wrapper
        """
        token_hash = self._get_token_hash(token)
        last_error: Exception | None = None
        for attempt in range(2):
            pool, db_config = await self.get_pool_for_token(token)
            try:
                connection = await asyncio.wait_for(
                    pool.acquire(), timeout=self.connect_timeout
                )
                if getattr(connection, "closed", False):
                    pool.release(connection)
                    raise RuntimeError("Token pool returned a closed connection")

                self.logger.debug(
                    f"Session {session_id}: Acquired connection from token pool "
                    f"(user: {db_config['user']}@{db_config['host']})"
                )

                return DorisConnection(
                    connection,
                    session_id,
                    self.security_manager,
                    pool_kind="static_token",
                    route_key=f"static_token:{token_hash}",
                    owner_id=self._token_pool_owner_ids.get(
                        token_hash, f"static_token:{token_hash}:0"
                    ),
                    generation=self._token_pool_generations.get(token_hash, 0),
                    owner_pool=pool,
                )
            except Exception as exc:
                last_error = exc
                has_failover = len(self._host_candidates(db_config)) > 1
                if attempt == 0 and has_failover:
                    self.logger.warning(
                        "Session %s: token pool acquisition failed; "
                        "recreating it from configured FE candidates (%s)",
                        session_id,
                        type(exc).__name__,
                    )
                    await self._evict_token_pool_for_recovery(token_hash, pool)
                    continue
                self.logger.error(
                    "Session %s: Failed to acquire connection from token pool (%s)",
                    session_id,
                    type(exc).__name__,
                )
                raise

        raise RuntimeError("Token pool recovery failed") from last_error

    async def _evict_token_pool_for_recovery(
        self,
        token_hash: str,
        expected_pool: Pool,
    ) -> None:
        """Remove a failed token pool without evicting a concurrent replacement."""
        pool_to_close: Pool | None = None
        async with self._token_pools_lock:
            if self.token_pools.get(token_hash) is expected_pool:
                pool_to_close = self.token_pools.pop(token_hash)
                self.token_configs.pop(token_hash, None)
                self._token_pool_owner_ids.pop(token_hash, None)
        if pool_to_close is not None:
            await self._close_pool_safely(
                pool_to_close,
                f"failed static token pool {token_hash[:8]}",
            )

    async def release_connection_for_token(
        self,
        token: str,
        connection: DorisConnection,
    ) -> None:
        """Release a connection back to the token's dedicated pool

        Args:
            token: Authentication token
            connection: DorisConnection wrapper to release
        """
        token_hash = self._get_token_hash(token)
        expected_route_key = f"static_token:{token_hash}"

        if connection and (
            getattr(connection, "pool_kind", "") != "static_token"
            or getattr(connection, "route_key", "") != expected_route_key
        ):
            self.logger.warning(
                "Static token connection route mismatch on release: expected=%s actual=%s kind=%s",
                expected_route_key,
                getattr(connection, "route_key", ""),
                getattr(connection, "pool_kind", ""),
            )
        await self.release_routed_connection(connection)

    async def cleanup_token_pools(self, max_idle_time: int = 3600) -> None:
        """Clean up idle token connection pools

        Args:
            max_idle_time: Maximum idle time in seconds before closing a pool
        """
        async with self._token_pools_lock:
            pools_to_remove = []

            for token_hash, pool in self.token_pools.items():
                if pool and not pool.closed:
                    # Check if pool is idle (no active connections)
                    if pool.size == 0 and pool.freesize == 0:
                        pools_to_remove.append(token_hash)
                elif pool and pool.closed:
                    pools_to_remove.append(token_hash)

            for token_hash in pools_to_remove:
                try:
                    pool = self.token_pools.pop(token_hash, None)
                    if pool and not pool.closed:
                        pool.close()
                        await pool.wait_closed()
                    self.token_configs.pop(token_hash, None)
                    self._token_pool_locks.pop(token_hash, None)
                    self._token_pool_owner_ids.pop(token_hash, None)
                    self._token_pool_generations.pop(token_hash, None)
                    self.logger.info(
                        f"Cleaned up idle token pool (hash: {token_hash[:8]}...)"
                    )
                except Exception as e:
                    self.logger.warning(f"Error cleaning up token pool: {e}")

    async def close_all_token_pools(self) -> None:
        """Close all token connection pools (for shutdown)"""
        # Use timeout to prevent blocking on lock acquisition during shutdown
        try:
            async with asyncio.timeout(5):  # 5 second timeout for lock
                async with self._token_pools_lock:
                    for token_hash, pool in list(self.token_pools.items()):
                        try:
                            if pool and not pool.closed:
                                pool.close()
                                # Use timeout for wait_closed to prevent hanging
                                try:
                                    await asyncio.wait_for(
                                        pool.wait_closed(), timeout=2.0
                                    )
                                except TimeoutError:
                                    self.logger.warning(
                                        f"Timeout waiting for token pool to close (hash: {token_hash[:8]}...)"
                                    )
                                self.logger.info(
                                    f"Closed token pool (hash: {token_hash[:8]}...)"
                                )
                        except Exception as e:
                            self.logger.warning(f"Error closing token pool: {e}")

                    self.token_pools.clear()
                    self.token_configs.clear()
                    self._token_pool_locks.clear()
                    self._token_pool_owner_ids.clear()
                    self._token_pool_generations.clear()
        except TimeoutError:
            self.logger.warning(
                "Timeout acquiring lock for token pool cleanup, forcing clear"
            )
            # Force clear without lock
            self.token_pools.clear()
            self.token_configs.clear()
            self._token_pool_locks.clear()
            self._token_pool_owner_ids.clear()
            self._token_pool_generations.clear()

    async def configure_for_token(self, token: str) -> tuple[bool, str]:
        """Validate the database route selected for a static token.

        Priority: Token-bound DB config > .env config > error

        Args:
            token: Authentication token to get database config for

        Returns:
            (success: bool, config_source: str): Result and which config was used

        Raises:
            RuntimeError: If no valid database configuration is available
        """
        current_token_config = self._get_current_token_db_config(token)
        uses_token_config = bool(
            current_token_config
            and not self._is_config_empty(current_token_config.get("host"))
            and not self._is_config_empty(current_token_config.get("user"))
        )
        config_source = "token-bound" if uses_token_config else "global-env"

        connection: DorisConnection | None = None
        try:
            # Validate the same dedicated route that query execution will use.
            # Never mutate active_db_config or rebuild the shared global pool
            # while authenticating a tenant token.
            connection = await self.get_connection_for_token(
                token,
                f"token_validation_{self._get_token_hash(token)[:8]}",
            )
            result = await asyncio.wait_for(
                connection.execute(
                    "SELECT 1 AS connection_check",
                    mask_result=False,
                    max_rows=1,
                    max_bytes=256,
                ),
                timeout=self.connect_timeout,
            )
            if result.data != [{"connection_check": 1}]:
                raise RuntimeError("Token database validation query returned no result")
            return True, config_source
        except Exception as e:
            self.logger.error(
                "Failed to validate database route for token (%s): %s",
                type(e).__name__,
                str(e) or "<no message>",
            )
            raise
        finally:
            if connection is not None:
                await self.release_connection_for_token(token, connection)

    async def _ensure_pool_with_current_config(self) -> None:
        """Ensure connection pool exists with current configuration"""
        try:
            # If pool exists with different config, need to recreate it
            # If no pool exists, create one with current config
            if self.pool and not self.pool.closed:
                # Since we can't reliably check pool config attributes,
                # we'll recreate the pool if we detect a potential config change
                # by checking if current config differs from what we stored
                pool_needs_recreation = False

                # Compare current config with what we might have used before
                if self._last_pool_config is not None:
                    current_config = {
                        "host": self.host,
                        "port": self.port,
                        "user": self.user,
                        "database": self.database,
                    }
                    if current_config != self._last_pool_config:
                        pool_needs_recreation = True

                if pool_needs_recreation:
                    self.logger.info(
                        "Database configuration changed, recreating connection pool"
                    )
                    await self._recreate_pool()
            elif not self.pool:
                self.logger.info("Creating connection pool with current configuration")
                await self._create_pool_with_current_config()

            # Test the connection immediately
            if not await self._test_pool_health():
                raise RuntimeError(
                    f"Database connection test failed for {self.host}:{self.port}"
                )

        except Exception as e:
            self.logger.error(f"Failed to ensure connection pool: {e}")
            raise

    async def _create_pool_with_current_config(self) -> None:
        """Create connection pool with current database configuration"""
        try:
            await self._create_global_pool()

            # Store the current config for comparison later
            self._last_pool_config = {
                "host": self.host,
                "port": self.port,
                "user": self.user,
                "database": self.database,
            }

            # Test initial connection
            if not await self._test_pool_health():
                raise RuntimeError("Connection pool health check failed")

            # Start background monitoring tasks if not already running
            if not self.pool_health_check_task or self.pool_health_check_task.done():
                self.pool_health_check_task = asyncio.create_task(
                    self._pool_health_monitor()
                )
            if not self.pool_cleanup_task or self.pool_cleanup_task.done():
                self.pool_cleanup_task = asyncio.create_task(
                    self._pool_cleanup_monitor()
                )

            # Perform initial pool warmup
            await self._warmup_pool()

            self.logger.info(
                f"Connection pool created successfully with {self.host}:{self.port}"
            )

        except Exception as e:
            self.logger.error(f"Failed to create connection pool: {e}")
            raise

    async def _create_global_pool(self, *, timeout: float | None = None) -> None:
        """Create the global pool against the first healthy configured FE."""
        candidate_config = self.original_db_config.copy()
        candidate_config["host"] = self.host
        pool, selected_host = await self._create_pool_with_candidates(
            candidate_config,
            minsize=self.minsize,
            maxsize=self.maxsize,
            timeout=timeout,
            require_health=True,
        )
        self.pool = pool
        self._set_active_global_host(selected_host)
        self._mark_global_pool_created()

    async def _recreate_pool(self) -> None:
        """Recreate connection pool with current database configuration"""
        try:
            # Close existing pool
            if self.pool and not self.pool.closed:
                self.pool.close()
                await self.pool.wait_closed()
                self.pool = None

            # Create new pool with current config
            await self._create_pool_with_current_config()

        except Exception as e:
            self.logger.error(f"Failed to recreate connection pool: {e}")
            raise

    def validate_database_configuration(self) -> tuple[bool, str]:
        """Validate database configuration completeness

        Returns:
            (is_valid, error_message): Configuration validation result
        """
        # Check if Token authentication is enabled
        token_auth_enabled = getattr(self.config.security, "enable_token_auth", False)

        # Check if tokens.json exists and has valid tokens with database configs
        tokens_file_available = False
        token_bound_configs_available = False

        if self.token_manager:
            try:
                # Check if tokens.json file exists
                import os

                tokens_file_path = getattr(
                    self.token_manager, "token_file_path", "tokens.json"
                )
                tokens_file_available = os.path.exists(tokens_file_path)

                # Check if any tokens have database configurations
                if tokens_file_available or self.token_manager._tokens:
                    for _token_hash, token_info in self.token_manager._tokens.items():
                        if token_info.database_config:
                            token_bound_configs_available = True
                            break
            except Exception as exc:
                self.logger.warning(
                    f"Unable to inspect token-bound database configurations: {exc}"
                )

        # Validate .env database configuration
        env_config_valid = self._has_valid_global_config()

        # Decision logic
        if token_auth_enabled:
            if tokens_file_available:
                # tokens.json exists - either .env OR token-bound config must be valid
                if env_config_valid or token_bound_configs_available:
                    return True, "Configuration valid"
                else:
                    return False, (
                        "Token authentication is enabled and tokens.json exists, but no valid database "
                        "configuration found. Please provide either:\n"
                        "1. Valid database configuration in .env file (DB_HOST, DB_USER, etc.)\n"
                        "2. Database configuration in tokens.json for at least one token"
                    )
            else:
                # tokens.json does not exist - must have valid .env config
                if env_config_valid:
                    return True, "Configuration valid"
                else:
                    return False, (
                        "Token authentication is enabled but tokens.json file not found. "
                        "Either:\n"
                        "1. Create tokens.json file with token configurations\n"
                        "2. Provide valid database configuration in .env file (DB_HOST, DB_USER, etc.)"
                    )
        else:
            # Token auth is disabled, must have valid .env config
            if env_config_valid:
                return True, "Configuration valid"
            else:
                return False, (
                    "Token authentication is disabled. Valid database configuration is required "
                    "in .env file (DB_HOST, DB_USER, etc.)"
                )

    async def initialize(self) -> None:
        """Initialize connection pool with health monitoring"""
        try:
            # First validate configuration
            is_valid, error_message = self.validate_database_configuration()
            if not is_valid:
                self.logger.error(
                    f"Database configuration validation failed: {error_message}"
                )
                raise RuntimeError(
                    f"Database configuration validation failed:\n{error_message}"
                )

            self.logger.info("Database configuration validated successfully")
            self.logger.info(f"Initializing connection pool to {self.host}:{self.port}")

            # Only create connection pool if we have valid global config
            # Token-bound configs will be handled dynamically during requests
            if not self._has_valid_global_config():
                self.logger.info(
                    "No valid global database config, pool will be created dynamically for token-bound configs"
                )
                return

            # Create connection pool against the first healthy configured FE.
            await self._create_global_pool()

            # Test initial connection
            if not await self._test_pool_health():
                raise RuntimeError("Connection pool health check failed")

            # Start background monitoring tasks
            self.pool_health_check_task = asyncio.create_task(
                self._pool_health_monitor()
            )
            self.pool_cleanup_task = asyncio.create_task(self._pool_cleanup_monitor())

            # Perform initial pool warmup
            await self._warmup_pool()

            self.logger.info(
                f"Connection pool initialized successfully, min connections: {self.minsize}, max connections: {self.maxsize}"
            )

        except Exception as e:
            self.logger.error(f"Failed to initialize connection pool: {e}")
            raise

    async def initialize_for_stdio_mode(self, timeout: float = 30.0) -> None:
        """
        Initialize connection pool for stdio mode with strict validation

        stdio mode requires a working database connection because:
        - No HTTP authentication mechanism to support token-bound configs
        - All database operations depend on the global connection pool

        Args:
            timeout: Maximum time to wait for connection establishment

        Raises:
            RuntimeError: If configuration is invalid or connection fails
        """
        try:
            # Validate that we have valid global configuration
            if not self._has_valid_global_config():
                error_msg = (
                    "stdio mode requires valid global database configuration. "
                    "Please set DORIS_HOST and DORIS_USER in environment variables or .env file. "
                    f"Current config: host='{self.host}', user='{self.user}'"
                )
                self.logger.error(error_msg)
                raise RuntimeError(error_msg)

            self.logger.info(
                f"stdio mode database config validated: {self.host}:{self.port}"
            )

            # Validate configuration format
            is_valid, error_message = self.validate_database_configuration()
            if not is_valid:
                error_msg = f"Database configuration validation failed: {error_message}"
                self.logger.error(error_msg)
                raise RuntimeError(error_msg)

            # Test connectivity with timeout
            self.logger.info("Testing database connectivity for stdio mode...")
            if not await self._test_connectivity_with_timeout(timeout):
                error_msg = (
                    f"Failed to connect to Doris database within {timeout} seconds. "
                    f"Please check if Doris is running at {self.host}:{self.port} "
                    f"and verify network connectivity."
                )
                self.logger.error(error_msg)
                raise RuntimeError(error_msg)

            # Initialize the connection pool
            await self._create_connection_pool()

            # Verify that we have a working connection pool
            if not self.pool:
                error_msg = "Database connection pool was not created successfully."
                self.logger.error(error_msg)
                raise RuntimeError(error_msg)

            # Start background monitoring tasks
            self.pool_health_check_task = asyncio.create_task(
                self._pool_health_monitor()
            )
            self.pool_cleanup_task = asyncio.create_task(self._pool_cleanup_monitor())

            # Perform initial pool warmup
            await self._warmup_pool()

            self.logger.info(
                "Database connection established successfully for stdio mode"
            )

        except Exception as e:
            self.logger.error(f"stdio mode database initialization failed: {e}")
            raise

    async def initialize_for_http_mode(self) -> bool:
        """
        Initialize connection pool for HTTP mode with graceful degradation

        HTTP mode can work without global database configuration because:
        - Supports token-bound database configurations
        - Can handle authentication and use per-request database configs
        - Has fallback mechanisms for database operations

        Returns:
            bool: True if global database pool was created, False if gracefully degraded
        """
        try:
            # First validate configuration format if we have one
            if self._has_valid_global_config():
                is_valid, error_message = self.validate_database_configuration()
                if not is_valid:
                    self.logger.warning(
                        f"Global database configuration invalid: {error_message}"
                    )
                    self.logger.info(
                        "HTTP mode will rely on token-bound database configurations"
                    )
                    return False

                # Try to establish global connection pool
                self.logger.info(
                    f"Attempting to create global connection pool: {self.host}:{self.port}"
                )

                try:
                    # Test connectivity with shorter timeout for HTTP mode
                    if await self._test_connectivity_with_timeout(10.0):
                        await self._create_connection_pool()

                        if self.pool:
                            # Start background monitoring tasks
                            self.pool_health_check_task = asyncio.create_task(
                                self._pool_health_monitor()
                            )
                            self.pool_cleanup_task = asyncio.create_task(
                                self._pool_cleanup_monitor()
                            )

                            # Perform initial pool warmup
                            await self._warmup_pool()

                            self.logger.info(
                                "Global database connection pool created successfully for HTTP mode"
                            )
                            return True
                        return False
                    else:
                        self.logger.warning(
                            "Global database connection test failed, will use token-bound configs"
                        )
                        return False

                except Exception as pool_error:
                    self.logger.warning(
                        f"Failed to create global connection pool: {pool_error}"
                    )
                    self.logger.info(
                        "HTTP mode will rely on token-bound database configurations"
                    )
                    return False
            else:
                self.logger.info(
                    "No valid global database config found, HTTP mode will use token-bound configurations"
                )
                return False

        except Exception as e:
            self.logger.warning(
                f"HTTP mode database initialization encountered error: {e}"
            )
            self.logger.info(
                "HTTP mode will rely on token-bound database configurations"
            )
            return False

    async def _test_connectivity_with_timeout(self, timeout: float) -> bool:
        """
        Test database connectivity with timeout

        Args:
            timeout: Maximum time to wait for connection test

        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            await asyncio.wait_for(self._test_basic_connectivity(), timeout=timeout)
            return True
        except TimeoutError:
            self.logger.error(
                f"Database connectivity test timed out after {timeout} seconds"
            )
            return False
        except Exception as e:
            self.logger.error(f"Database connectivity test failed: {e}")
            return False

    async def check_readiness(self, *, timeout_seconds: float = 2.0) -> bool:
        """Run a bounded, side-effect-free Doris readiness probe."""
        if not self._has_valid_global_config():
            return False
        try:
            timeout = float(timeout_seconds)
        except (TypeError, ValueError):
            timeout = 2.0
        timeout = min(max(timeout, 0.05), 5.0)
        try:
            await asyncio.wait_for(
                self._test_basic_connectivity(),
                timeout=timeout,
            )
            return True
        except TimeoutError:
            self.logger.debug(
                "Doris readiness probe timed out after %s seconds",
                timeout,
            )
            return False
        except Exception as exc:
            self.logger.debug("Doris readiness probe failed: %s", exc)
            return False

    async def _test_basic_connectivity(self) -> None:
        """
        Test basic database connectivity without connection pool

        Raises:
            Exception: If connection fails
        """
        import aiomysql

        last_error: Exception | None = None
        for host in self._host_candidates(self.original_db_config):
            conn = None
            try:
                conn = await aiomysql.connect(
                    host=host,
                    port=self.port,
                    user=self.user,
                    password=self.password,
                    db=self.database,
                    charset=self.charset,
                    connect_timeout=self.connect_timeout,
                    autocommit=True,
                )

                async with conn.cursor() as cursor:
                    await cursor.execute("SELECT 1")
                    result = await cursor.fetchone()
                    if not result or result[0] != 1:
                        raise RuntimeError("Database connectivity test query failed")
                self._set_active_global_host(host)
                return
            except Exception as exc:
                last_error = exc
                self.logger.warning(
                    "Doris FE candidate %s:%s failed connectivity check (%s)",
                    host,
                    self.port,
                    type(exc).__name__,
                )
            finally:
                if conn:
                    conn.close()

        raise RuntimeError(
            "Database connectivity test failed for all configured Doris FE hosts"
        ) from last_error

    async def _create_connection_pool(self) -> None:
        """
        Create the connection pool

        Raises:
            Exception: If pool creation fails
        """
        await self._create_global_pool()

    async def _test_pool_health(self) -> bool:
        """Test connection pool health"""
        pool = self.pool
        if pool is None:
            return False
        try:
            async with pool.acquire() as conn:
                async with conn.cursor() as cursor:
                    await cursor.execute("SELECT 1")
                    result = await cursor.fetchone()
                    return bool(result and result[0] == 1)
        except Exception as e:
            self.logger.error(f"Pool health test failed: {e}")
            return False

    async def _warmup_pool(self) -> None:
        """Warm up connection pool by creating initial connections"""
        pool = self.pool
        if pool is None:
            return
        warmup_size = min(self.pool_warmup_size, self.maxsize)
        self.logger.info(
            f"🔥 Warming up connection pool with {warmup_size} connections"
        )

        warmup_connections = []
        try:
            # Acquire connections to force pool to create them
            for i in range(warmup_size):
                try:
                    conn = await pool.acquire()
                    warmup_connections.append(conn)
                    self.logger.debug(f"Warmed up connection {i + 1}/{warmup_size}")
                except Exception as e:
                    self.logger.warning(f"Failed to warm up connection {i + 1}: {e}")
                    break

            # Release all warmup connections back to pool
            for conn in warmup_connections:
                try:
                    pool.release(conn)
                except Exception as e:
                    self.logger.warning(f"Failed to release warmup connection: {e}")

            self.logger.info(
                f"✅ Pool warmup completed, {len(warmup_connections)} connections created"
            )

        except Exception as e:
            self.logger.error(f"Pool warmup failed: {e}")
            # Clean up any remaining connections
            for conn in warmup_connections:
                try:
                    await conn.ensure_closed()
                except Exception as cleanup_error:
                    self.logger.warning(
                        f"Failed to close warmup connection: {cleanup_error}"
                    )

    async def _pool_health_monitor(self) -> None:
        """Background task to monitor pool health"""
        self.logger.info("🩺 Starting pool health monitor")

        while True:
            try:
                await asyncio.sleep(self.health_check_interval)
                await self._check_pool_health()
            except asyncio.CancelledError:
                self.logger.info("Pool health monitor stopped")
                break
            except Exception as e:
                self.logger.error(f"Pool health monitor error: {e}")

    async def _pool_cleanup_monitor(self) -> None:
        """Background task to clean up stale connections"""
        self.logger.info("🧹 Starting pool cleanup monitor")

        while True:
            try:
                await asyncio.sleep(
                    self.health_check_interval * 2
                )  # Less frequent cleanup
                await self._cleanup_stale_connections()
            except asyncio.CancelledError:
                self.logger.info("Pool cleanup monitor stopped")
                break
            except Exception as e:
                self.logger.error(f"Pool cleanup monitor error: {e}")

    async def _check_pool_health(self) -> None:
        """Check and maintain pool health"""
        try:
            # Skip health check if already recovering
            if self.pool_recovering:
                self.logger.debug("Pool recovery in progress, skipping health check")
                return

            # Test pool with a simple query
            health_ok = await self._test_pool_health()

            if health_ok:
                self.logger.debug("✅ Pool health check passed")
                self.metrics.last_health_check = utc_now()
            else:
                self.logger.warning("❌ Pool health check failed, attempting recovery")
                await self._recover_pool()

        except Exception as e:
            self.logger.error(f"Pool health check error: {e}")
            await self._recover_pool()

    async def _cleanup_stale_connections(self) -> None:
        """Proactively clean up potentially stale connections"""
        pool = self.pool
        if pool is None:
            return
        try:
            self.logger.debug("🧹 Checking for stale connections")

            # Get pool statistics
            pool_free = pool.freesize

            # If pool has idle connections, test some of them
            if pool_free > 0:
                test_count = min(pool_free, 2)  # Test up to 2 idle connections

                for i in range(test_count):
                    conn = None
                    try:
                        # Acquire connection, test it, and release
                        conn = await asyncio.wait_for(pool.acquire(), timeout=5)

                        # Quick test
                        async with conn.cursor() as cursor:
                            await asyncio.wait_for(
                                cursor.execute("SELECT 1"), timeout=3
                            )
                            await cursor.fetchone()

                        # Connection is healthy, release it
                        pool.release(conn)

                    except TimeoutError:
                        self.logger.debug(f"Stale connection test {i + 1} timed out")
                        if conn is not None:
                            try:
                                await conn.ensure_closed()
                            except Exception as cleanup_error:
                                self.logger.debug(
                                    "Failed to close timed-out connection "
                                    f"{i + 1}: {cleanup_error}"
                                )
                    except Exception as e:
                        self.logger.debug(f"Stale connection test {i + 1} failed: {e}")
                        if conn is not None:
                            try:
                                await conn.ensure_closed()
                            except Exception as cleanup_error:
                                self.logger.debug(
                                    "Failed to close unhealthy connection "
                                    f"{i + 1}: {cleanup_error}"
                                )

                self.logger.debug(
                    f"Stale connection cleanup completed, tested {test_count} connections"
                )

        except Exception as e:
            self.logger.error(f"Stale connection cleanup error: {e}")

    async def _recover_pool(self) -> None:
        """Recover connection pool when health check fails"""
        # Use lock to prevent concurrent recovery attempts
        async with self.pool_recovery_lock:
            # Check if another recovery is already in progress
            if self.pool_recovering:
                self.logger.debug("Pool recovery already in progress, waiting...")
                return

            try:
                self.pool_recovering = True
                max_retries = 3

                for attempt in range(max_retries):
                    try:
                        self.logger.info(
                            f"🔄 Attempting pool recovery (attempt {attempt + 1}/{max_retries})"
                        )

                        # Try to close existing pool with timeout
                        if self.pool:
                            try:
                                if not self.pool.closed:
                                    self.pool.close()
                                    await asyncio.wait_for(
                                        self.pool.wait_closed(), timeout=3.0
                                    )
                                self.logger.debug("Old pool closed successfully")
                            except TimeoutError:
                                self.logger.warning(
                                    "Pool close timeout, forcing cleanup"
                                )
                            except Exception as e:
                                self.logger.warning(f"Error closing old pool: {e}")
                            finally:
                                self.pool = None

                        # Wait before creating new pool (reduced delay)
                        if attempt > 0:
                            await asyncio.sleep(2)  # Reduced from 5 to 2 seconds

                        # Recreate pool with timeout
                        self.logger.debug("Creating new connection pool...")
                        await self._create_global_pool(timeout=10.0)

                        # Test recovered pool with timeout
                        if await asyncio.wait_for(
                            self._test_pool_health(), timeout=5.0
                        ):
                            self.logger.info(
                                f"✅ Pool recovery successful on attempt {attempt + 1}"
                            )
                            # Re-warm the pool with timeout
                            try:
                                await asyncio.wait_for(self._warmup_pool(), timeout=5.0)
                            except TimeoutError:
                                self.logger.warning(
                                    "Pool warmup timeout, but recovery successful"
                                )
                            return
                        else:
                            self.logger.warning(
                                f"❌ Pool recovery health check failed on attempt {attempt + 1}"
                            )

                    except TimeoutError:
                        self.logger.error(
                            f"Pool recovery attempt {attempt + 1} timed out"
                        )
                        if self.pool:
                            try:
                                self.pool.close()
                            except Exception as cleanup_error:
                                self.logger.warning(
                                    "Failed to close timed-out recovery pool: "
                                    f"{cleanup_error}"
                                )
                            self.pool = None
                    except Exception as e:
                        self.logger.error(
                            f"Pool recovery error on attempt {attempt + 1}: {e}"
                        )

                        # Clean up failed pool
                        if self.pool:
                            try:
                                self.pool.close()
                                await asyncio.wait_for(
                                    self.pool.wait_closed(), timeout=2.0
                                )
                            except Exception as cleanup_error:
                                self.logger.warning(
                                    "Failed to close unsuccessful recovery pool: "
                                    f"{cleanup_error}"
                                )
                            finally:
                                self.pool = None

                # All recovery attempts failed
                self.logger.error("❌ Pool recovery failed after all attempts")
                self.pool = None

            finally:
                self.pool_recovering = False

    async def _recover_pool_with_lock(self) -> None:
        """🔧 FIX: Recovery method that uses the new recovery lock to prevent races"""
        async with self._recovery_lock:
            if not self.pool_recovering:  # Only recover if not already in progress
                await self._recover_pool()

    def _get_effective_auth_context(
        self,
        auth_context: AuthContext | None = None,
    ) -> AuthContext | None:
        if auth_context is not None:
            return auth_context
        try:
            from .security import mcp_auth_context_var

            return mcp_auth_context_var.get()
        except Exception as e:
            self.logger.debug(f"Could not get auth_context: {e}")
            return None

    def get_database_config_for_auth_context(
        self,
        auth_context: AuthContext | None = None,
    ) -> Any:
        """Return the endpoint config for the current authenticated route."""
        effective_context = self._get_effective_auth_context(auth_context)
        token = getattr(effective_context, "token", "") if effective_context else ""
        if token and self.token_manager:
            token_config = self.token_manager.get_database_config_by_token(token)
            if token_config is not None:
                return token_config
        return self.config.database

    def get_route_identity(
        self,
        auth_context: AuthContext | None = None,
    ) -> DorisRouteIdentity:
        """Return the current routed pool identity without exposing credentials."""
        effective_context = self._get_effective_auth_context(auth_context)
        route_key = "global"
        generation = self._global_pool_generation

        if (
            effective_context is not None
            and effective_context.auth_method == "doris_oauth"
        ):
            doris_user = self._validate_doris_user(effective_context.doris_user)
            route_key = self._doris_user_route_key(doris_user)
            meta = self.doris_user_pool_meta.get(doris_user)
            generation = meta.generation if meta is not None else 0
        elif effective_context is not None and effective_context.token:
            token_hash = self._get_token_hash(effective_context.token)
            route_key = f"static_token:{token_hash}"
            generation = self._token_pool_generations.get(token_hash, 0)

        database_config = self.get_database_config_for_auth_context(effective_context)

        def config_value(name: str, default: Any = "") -> Any:
            if isinstance(database_config, Mapping):
                return database_config.get(name, default)
            return getattr(database_config, name, default)

        hosts = self._ordered_hosts(
            str(config_value("host", "")),
            config_value("hosts", ()),
        )
        endpoint_material = "\x1f".join(
            (
                *hosts,
                str(config_value("port", "")),
                str(config_value("user", "")),
                str(config_value("database", "")),
            )
        )
        endpoint_fingerprint = hashlib.sha256(
            endpoint_material.encode("utf-8")
        ).hexdigest()
        route_material = f"{route_key}\x1f{generation}\x1f{endpoint_fingerprint}"
        return DorisRouteIdentity(
            route_key=route_key,
            generation=generation,
            endpoint_fingerprint=endpoint_fingerprint,
            fingerprint=hashlib.sha256(route_material.encode("utf-8")).hexdigest(),
        )

    async def _get_connection_for_auth_context(
        self,
        session_id: str,
        auth_context: AuthContext | None = None,
    ) -> DorisConnection:
        """Resolve the request route with Doris OAuth fail-closed priority."""
        if auth_context is not None and auth_context.auth_method == "doris_oauth":
            doris_user = auth_context.doris_user
            if not doris_user:
                raise DorisUserPoolMissingError(
                    "Doris OAuth auth context is missing doris_user"
                )
            try:
                normalized_user = self._validate_doris_user(doris_user)
            except DorisUserAuthenticationError as e:
                raise DorisUserPoolMissingError(str(e)) from e
            expected_route_key = self._doris_user_route_key(normalized_user)
            context_pool_key = auth_context.pool_key
            if context_pool_key and context_pool_key != expected_route_key:
                raise DorisUserPoolMissingError(
                    "Doris OAuth pool key does not match doris_user"
                )
            self.logger.debug(
                "get_connection: Using Doris user pool for session %s", session_id
            )
            return await self.get_connection_for_doris_user(normalized_user, session_id)

        if auth_context is not None and auth_context.token:
            # SECURITY: Do not catch token pool errors here; token-bound requests must not fall back.
            self.logger.debug(
                f"get_connection: Using token-specific pool for session {session_id}"
            )
            return await self.get_connection_for_token(auth_context.token, session_id)

        return await self._get_global_connection(session_id)

    async def get_connection(self, session_id: str) -> DorisConnection:
        """Acquire a connection using Doris OAuth -> static token -> global priority."""
        return await self._get_connection_for_auth_context(
            session_id,
            self._get_effective_auth_context(),
        )

    async def _get_global_connection(self, session_id: str) -> DorisConnection:
        """Acquire a connection from the global pool."""
        cached_conn = self.session_cache.get(session_id)
        if cached_conn:
            return cached_conn

        # 🔧 FIX: Use only semaphore to limit concurrent acquisitions (remove double locking)
        async with self._connection_semaphore:
            try:
                # Wait for any ongoing recovery to complete
                if self.pool_recovering:
                    self.logger.debug(
                        "Pool recovery in progress, waiting for completion..."
                    )
                    # Wait for recovery to complete (max 10 seconds)
                    start_wait = time.time()
                    while self.pool_recovering and (time.time() - start_wait) < 10:
                        await asyncio.sleep(0.1)  # More frequent checks

                    if self.pool_recovering:
                        self.logger.error(
                            "Pool recovery is taking too long, proceeding anyway"
                        )
                        # Continue but log the issue

                # Check if pool is available
                if not self.pool:
                    self.logger.warning(
                        "Connection pool is not available, attempting recovery..."
                    )

                    # Fallback to recovery
                    if not self.pool:
                        await self._recover_pool_with_lock()

                    if not self.pool:
                        raise RuntimeError(
                            "Connection pool is not available and recovery failed"
                        )

                # Check if pool is closed
                if self.pool.closed:
                    self.logger.warning(
                        "Connection pool is closed, attempting recovery..."
                    )
                    await self._recover_pool_with_lock()

                    if not self.pool or self.pool.closed:
                        raise RuntimeError(
                            "Connection pool is closed and recovery failed"
                        )

                # 🔧 FIX: Increased timeout to prevent hanging
                try:
                    raw_conn = await asyncio.wait_for(self.pool.acquire(), timeout=10.0)
                except TimeoutError:
                    self.logger.error(
                        f"Connection acquisition timed out for session {session_id}"
                    )
                    # Try one recovery attempt
                    await self._recover_pool_with_lock()
                    if self.pool and not self.pool.closed:
                        try:
                            raw_conn = await asyncio.wait_for(
                                self.pool.acquire(), timeout=5.0
                            )
                        except TimeoutError:
                            raise RuntimeError(
                                "Connection acquisition timed out after recovery"
                            )
                    else:
                        raise RuntimeError("Connection acquisition timed out")

                # Wrap in DorisConnection
                doris_conn = DorisConnection(
                    raw_conn,
                    session_id,
                    self.security_manager,
                    pool_kind="global",
                    route_key="global",
                    owner_id=self._global_pool_owner_id,
                    generation=self._global_pool_generation,
                    owner_pool=self.pool,
                )

                # Basic validation - check if connection is open
                if raw_conn.closed:
                    # Return connection and raise error
                    try:
                        self.pool.release(raw_conn)
                    except Exception as release_error:
                        self.logger.warning(
                            "Failed to release already-closed connection: "
                            f"{release_error}"
                        )
                    raise RuntimeError("Acquired connection is already closed")

                self.logger.debug(
                    f"✅ Acquired fresh connection for session {session_id}"
                )

                self.session_cache.save(doris_conn)
                return doris_conn

            except Exception as e:
                self.logger.error(
                    f"Failed to get connection for session {session_id}: {e}"
                )
                raise

    async def release_routed_connection(
        self, connection: DorisConnection | None
    ) -> None:
        """Release a DorisConnection to the exact pool captured at acquire time."""
        if not connection or not getattr(connection, "connection", None):
            return

        raw_connection = connection.connection
        owner_pool = getattr(connection, "owner_pool", None)
        if getattr(connection, "is_healthy", True) is False:
            await self._force_close_raw_connection(
                raw_connection,
                "unhealthy routed connection",
            )
            if owner_pool is not None:
                try:
                    owner_pool.release(raw_connection)
                    self.logger.debug(
                        "Discarded unhealthy %s connection for route=%s owner=%s",
                        getattr(connection, "pool_kind", ""),
                        getattr(connection, "route_key", ""),
                        getattr(connection, "owner_id", ""),
                    )
                except Exception as release_error:
                    self.logger.warning(
                        "Failed to discard unhealthy connection for route=%s "
                        "owner=%s: %s",
                        getattr(connection, "route_key", ""),
                        getattr(connection, "owner_id", ""),
                        release_error,
                    )
            return
        if owner_pool is None:
            self.logger.warning(
                "Connection %s has no captured owner pool; force closing raw connection",
                getattr(connection, "session_id", ""),
            )
            await self._force_close_raw_connection(raw_connection, "missing owner pool")
            return

        try:
            owner_pool.release(raw_connection)
            self.logger.debug(
                "Released %s connection for route=%s owner=%s",
                getattr(connection, "pool_kind", ""),
                getattr(connection, "route_key", ""),
                getattr(connection, "owner_id", ""),
            )
        except Exception as release_error:
            self.logger.warning(
                "Connection release failed for route=%s owner=%s: %s; force closing",
                getattr(connection, "route_key", ""),
                getattr(connection, "owner_id", ""),
                release_error,
            )
            await self._force_close_raw_connection(
                raw_connection, "owner pool release failure"
            )

    async def release_connection(
        self,
        session_id: str,
        connection: DorisConnection,
    ) -> None:
        """🔧 FIX: Release connection back to pool with proper error handling"""
        cached_conn = self.session_cache.get(session_id)
        if cached_conn:
            self.session_cache.remove(session_id)
            if cached_conn is not connection:
                self.logger.warning("Invalid connection")
                connection = cached_conn

        if not connection or not connection.connection:
            self.logger.debug(f"No connection to release for session {session_id}")
            return

        if getattr(connection, "owner_pool", None) is not None:
            await self.release_routed_connection(connection)
            return

        if getattr(connection, "pool_kind", "global") != "global":
            await self.release_routed_connection(connection)
            return

        try:
            # Check pool availability before attempting release
            if not self.pool or self.pool.closed:
                self.logger.warning(
                    f"Pool unavailable during release for session {session_id}, force closing connection"
                )
                try:
                    await connection.connection.ensure_closed()
                except Exception as cleanup_error:
                    self.logger.warning(
                        "Failed to force-close connection while pool was unavailable: "
                        f"{cleanup_error}"
                    )
                return

            # Check connection state before release
            if connection.connection.closed:
                self.logger.debug(f"Connection already closed for session {session_id}")
                return

            # 🔧 FIX: Simplified release operation without thread wrapper
            try:
                self.pool.release(connection.connection)
                self.logger.debug(f"✅ Released connection for session {session_id}")
            except Exception as release_error:
                self.logger.warning(
                    f"Connection release failed for session {session_id}: {release_error}, force closing"
                )
                await connection.connection.ensure_closed()

        except Exception as e:
            self.logger.error(
                f"Error releasing connection for session {session_id}: {e}"
            )
            # Force close if release fails
            try:
                await connection.connection.ensure_closed()
            except Exception as close_error:
                self.logger.debug(f"Error force closing connection: {close_error}")

    async def close(self) -> None:
        """Close connection manager"""
        try:
            # Cancel background tasks
            if self.pool_health_check_task:
                self.pool_health_check_task.cancel()
                try:
                    await self.pool_health_check_task
                except asyncio.CancelledError:
                    pass

            if self.pool_cleanup_task:
                self.pool_cleanup_task.cancel()
                try:
                    await self.pool_cleanup_task
                except asyncio.CancelledError:
                    pass

            # Close Doris OAuth user pools before legacy token/global pools.
            await self.close_all_doris_user_pools()

            # 🔧 FIX: Close all per-token connection pools
            await self.close_all_token_pools()

            # Close global connection pool with timeout
            if self.pool:
                self.pool.close()
                try:
                    await asyncio.wait_for(self.pool.wait_closed(), timeout=5.0)
                except TimeoutError:
                    self.logger.warning("Timeout waiting for global pool to close")

            self.logger.info("Connection manager closed successfully")

        except Exception as e:
            self.logger.error(f"Error closing connection manager: {e}")

    async def test_connection(self) -> bool:
        """Test database connection using robust connection test"""
        return await self._test_pool_health()

    async def get_metrics(self) -> ConnectionMetrics:
        """Get connection pool metrics - Simplified Strategy"""
        try:
            if self.pool:
                self.metrics.idle_connections = self.pool.freesize
                self.metrics.active_connections = self.pool.size - self.pool.freesize
            else:
                self.metrics.idle_connections = 0
                self.metrics.active_connections = 0

            return self.metrics
        except Exception as e:
            self.logger.error(f"Error getting metrics: {e}")
            return self.metrics

    async def execute_query(
        self,
        session_id: str,
        sql: str,
        params: Mapping[str, Any] | tuple[Any, ...] | None = None,
        auth_context: AuthContext | None = None,
        *,
        max_rows: int | None = None,
        max_bytes: int | None = None,
    ) -> QueryResult:
        """Execute query using the same routed acquire/release contract as get_connection()."""
        connection = None
        effective_auth_context = self._get_effective_auth_context(auth_context)

        try:
            connection = await self._get_connection_for_auth_context(
                session_id, effective_auth_context
            )

            # Execute query
            result = await connection.execute(
                sql,
                params,
                effective_auth_context,
                max_rows=max_rows,
                max_bytes=max_bytes,
            )

            return result

        except Exception as e:
            self.logger.error(f"Query execution failed for session {session_id}: {e}")
            raise
        finally:
            if connection:
                await self.release_connection(session_id, connection)

    @asynccontextmanager
    async def get_connection_context(
        self,
        session_id: str,
    ) -> AsyncIterator[DorisConnection]:
        """Get connection context manager - Simplified Strategy"""
        async with self.get_connection_context_for_auth_context(
            session_id,
            self._get_effective_auth_context(),
        ) as connection:
            yield connection

    @asynccontextmanager
    async def get_connection_context_for_auth_context(
        self,
        session_id: str,
        auth_context: AuthContext | None,
    ) -> AsyncIterator[DorisConnection]:
        """Acquire and release a connection for an explicit request route."""
        connection = None
        try:
            connection = await self._get_connection_for_auth_context(
                session_id,
                auth_context,
            )
            yield connection
        finally:
            if connection:
                await self.release_connection(session_id, connection)

    async def diagnose_connection_health(self) -> dict[str, Any]:
        """Diagnose connection pool health - Simplified Strategy"""
        diagnosis: dict[str, Any] = {
            "timestamp": utc_now().isoformat(),
            "pool_status": "unknown",
            "pool_info": {},
            "recommendations": [],
        }

        try:
            # Check pool status
            if not self.pool:
                diagnosis["pool_status"] = "not_initialized"
                diagnosis["recommendations"].append("Initialize connection pool")
                return diagnosis

            if self.pool.closed:
                diagnosis["pool_status"] = "closed"
                diagnosis["recommendations"].append("Recreate connection pool")
                return diagnosis

            diagnosis["pool_status"] = "healthy"
            diagnosis["pool_info"] = {
                "size": self.pool.size,
                "free_size": self.pool.freesize,
                "min_size": self.pool.minsize,
                "max_size": self.pool.maxsize,
            }

            # Generate recommendations based on pool status
            if self.pool.freesize == 0 and self.pool.size >= self.pool.maxsize:
                diagnosis["recommendations"].append(
                    "Connection pool exhausted - consider increasing max_connections"
                )

            # Test pool health
            if await self._test_pool_health():
                diagnosis["pool_health"] = "healthy"
            else:
                diagnosis["pool_health"] = "unhealthy"
                diagnosis["recommendations"].append(
                    "Pool health check failed - may need recovery"
                )

            return diagnosis

        except Exception as e:
            diagnosis["error"] = str(e)
            diagnosis["recommendations"].append("Manual intervention required")
            return diagnosis


class ConnectionPoolMonitor:
    """Connection pool monitor

    Provides detailed monitoring and reporting capabilities for connection pool status
    """

    def __init__(self, connection_manager: DorisConnectionManager) -> None:
        self.connection_manager = connection_manager
        self.logger = get_logger(__name__)

    async def get_pool_status(self) -> dict[str, Any]:
        """Get connection pool status"""
        metrics = await self.connection_manager.get_metrics()

        status = {
            "pool_size": self.connection_manager.pool.size
            if self.connection_manager.pool
            else 0,
            "free_connections": self.connection_manager.pool.freesize
            if self.connection_manager.pool
            else 0,
            "active_connections": metrics.active_connections,
            "idle_connections": metrics.idle_connections,
            "total_connections": metrics.total_connections,
            "failed_connections": metrics.failed_connections,
            "connection_errors": metrics.connection_errors,
            "avg_connection_time": metrics.avg_connection_time,
            "last_health_check": metrics.last_health_check.isoformat()
            if metrics.last_health_check
            else None,
        }

        return status

    async def get_session_details(self) -> list[dict[str, Any]]:
        """Get session connection details - Simplified Strategy (No session caching)"""
        # In simplified strategy, we don't maintain session connections
        # Return empty list as connections are managed by the pool directly
        return []

    async def generate_health_report(self) -> dict[str, Any]:
        """Generate connection health report - Simplified Strategy"""
        pool_status = await self.get_pool_status()

        # Calculate pool utilization
        pool_utilization = (
            1.0 - (pool_status["free_connections"] / pool_status["pool_size"])
            if pool_status["pool_size"] > 0
            else 0.0
        )

        report: dict[str, Any] = {
            "timestamp": utc_now().isoformat(),
            "pool_status": pool_status,
            "pool_utilization": pool_utilization,
            "recommendations": [],
        }

        # Add recommendations based on pool status
        if pool_status["connection_errors"] > 10:
            report["recommendations"].append(
                "High connection error rate detected, review connection configuration"
            )

        if pool_utilization > 0.9:
            report["recommendations"].append(
                "Connection pool utilization is high, consider increasing pool size"
            )

        if pool_status["free_connections"] == 0:
            report["recommendations"].append(
                "No free connections available, consider increasing pool size"
            )

        return report
