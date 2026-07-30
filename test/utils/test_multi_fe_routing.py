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
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Regression tests for multi-instance routing and multi-FE failover."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from doris_mcp_server.auth.token_manager import DatabaseConfig as TokenDatabaseConfig
from doris_mcp_server.utils import db as db_module
from doris_mcp_server.utils.adbc_query_tools import DorisADBCQueryTools
from doris_mcp_server.utils.config import DorisConfig
from doris_mcp_server.utils.db import DorisConnectionManager
from doris_mcp_server.utils.doris_http_client import (
    DorisHTTPClient,
    DorisHTTPRequestError,
    DorisHTTPResponse,
    configured_fe_http_hosts,
)
from doris_mcp_server.utils.security import (
    AuthContext,
    reset_auth_context,
    set_current_auth_context,
)


class _ProbeCursor:
    def __init__(self, healthy: bool):
        self.healthy = healthy

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False

    async def execute(self, sql: str) -> None:
        assert sql == "SELECT 1"

    async def fetchone(self):
        return (1,) if self.healthy else None


class _ProbeConnection:
    def __init__(self, healthy: bool):
        self.healthy = healthy
        self.closed = False

    def cursor(self):
        return _ProbeCursor(self.healthy)


class _ProbePool:
    def __init__(self, healthy: bool):
        self.healthy = healthy
        self.closed = False
        self.released = []
        self.close_calls = 0

    async def acquire(self):
        return _ProbeConnection(self.healthy)

    def release(self, connection):
        self.released.append(connection)

    def close(self):
        self.closed = True
        self.close_calls += 1

    async def wait_closed(self):
        return None


class _BrokenAcquirePool(_ProbePool):
    async def acquire(self):
        raise OSError("active FE is unavailable")


def _config(*hosts: str) -> DorisConfig:
    config = DorisConfig()
    config.database.host = hosts[0]
    config.database.hosts = list(hosts)
    config.database.user = "root"
    config.database.password = "secret"
    config.database.connection_timeout = 1
    config.database.max_connections = 2
    return config


def test_environment_loads_ordered_sql_and_http_fe_hosts(monkeypatch):
    monkeypatch.setenv("DORIS_HOST", "sql-primary")
    monkeypatch.setenv("DORIS_HOSTS", "sql-secondary,sql-primary,sql-third")
    monkeypatch.setenv("DORIS_FE_HTTP_HOST", "http-primary")
    monkeypatch.setenv(
        "DORIS_FE_HTTP_HOSTS",
        "http-secondary,http-primary,http-third",
    )

    config = DorisConfig.from_env()

    assert config.database.host == "sql-primary"
    assert config.database.hosts == [
        "sql-primary",
        "sql-secondary",
        "sql-third",
    ]
    assert config.database.fe_http_host == "http-primary"
    assert config.database.fe_http_hosts == [
        "http-primary",
        "http-secondary",
        "http-third",
    ]
    serialized = config.to_dict()["database"]
    assert serialized["hosts"] == config.database.hosts
    assert serialized["fe_http_hosts"] == config.database.fe_http_hosts


def test_config_file_host_lists_set_backward_compatible_primary():
    config = DorisConfig._from_dict(
        {
            "database": {
                "hosts": ["fe-a", "fe-b"],
                "fe_http_hosts": ["fe-http-a", "fe-http-b"],
            }
        }
    )

    assert config.database.host == "fe-a"
    assert config.database.fe_http_host == "fe-http-a"


@pytest.mark.asyncio
async def test_global_pool_fails_over_to_second_fe(monkeypatch):
    manager = DorisConnectionManager(_config("fe-down", "fe-up"))
    failed_pool = _ProbePool(healthy=False)
    healthy_pool = _ProbePool(healthy=True)
    create_pool = AsyncMock(side_effect=[failed_pool, healthy_pool])
    monkeypatch.setattr(db_module.aiomysql, "create_pool", create_pool)

    await manager._create_global_pool()

    assert [call.kwargs["host"] for call in create_pool.await_args_list] == [
        "fe-down",
        "fe-up",
    ]
    assert failed_pool.closed is True
    assert manager.pool is healthy_pool
    assert manager.host == "fe-up"
    assert manager.active_db_config["host"] == "fe-up"


@pytest.mark.asyncio
async def test_doris_user_authentication_uses_same_fe_candidates(monkeypatch):
    manager = DorisConnectionManager(_config("fe-down", "fe-up"))
    good_connection = SimpleNamespace(close=lambda: None)
    connect = AsyncMock(
        side_effect=[OSError("unreachable"), good_connection],
    )
    monkeypatch.setattr(db_module.aiomysql, "connect", connect)

    await manager.authenticate_doris_user("alice", "correct-password")

    assert [call.kwargs["host"] for call in connect.await_args_list] == [
        "fe-down",
        "fe-up",
    ]
    assert manager.host == "fe-up"


def test_token_selects_an_independent_cluster_and_http_allowlist():
    manager = DorisConnectionManager(_config("global-fe"))
    tenant_config = TokenDatabaseConfig(
        host="tenant-a-fe-1",
        hosts=["tenant-a-fe-1", "tenant-a-fe-2"],
        user="tenant_a",
        password="tenant-secret",
        fe_http_hosts=["tenant-a-http-1", "tenant-a-http-2"],
    )
    manager.token_manager = SimpleNamespace(
        get_database_config_by_token=lambda token: (
            tenant_config if token == "tenant-a-token" else None
        )
    )
    auth_context = AuthContext(
        user_id="tenant-a",
        auth_method="token",
        token="tenant-a-token",
    )

    selected = manager.get_database_config_for_auth_context(auth_context)

    assert selected is tenant_config
    assert configured_fe_http_hosts(selected) == (
        "tenant-a-http-1",
        "tenant-a-http-2",
    )
    client = DorisHTTPClient.from_database_config(selected)
    assert client.allowed_endpoints["fe"] == {
        ("tenant-a-http-1", 8030),
        ("tenant-a-http-2", 8030),
    }


@pytest.mark.asyncio
async def test_token_bound_pool_fails_over_inside_its_own_cluster(monkeypatch):
    manager = DorisConnectionManager(_config("global-fe"))
    tenant_config = TokenDatabaseConfig(
        host="tenant-fe-down",
        hosts=["tenant-fe-down", "tenant-fe-up"],
        user="tenant_user",
        password="tenant-secret",
        database="tenant_db",
    )
    manager.token_manager = SimpleNamespace(
        get_database_config_by_token=lambda token: (
            tenant_config if token == "tenant-token" else None
        )
    )
    failed_pool = _ProbePool(healthy=False)
    healthy_pool = _ProbePool(healthy=True)
    create_pool = AsyncMock(side_effect=[failed_pool, healthy_pool])
    monkeypatch.setattr(db_module.aiomysql, "create_pool", create_pool)

    pool, selected_config = await manager.get_pool_for_token("tenant-token")

    assert pool is healthy_pool
    assert selected_config["hosts"] == ["tenant-fe-down", "tenant-fe-up"]
    assert [call.kwargs["host"] for call in create_pool.await_args_list] == [
        "tenant-fe-down",
        "tenant-fe-up",
    ]
    assert failed_pool.closed is True


@pytest.mark.asyncio
async def test_token_bound_pool_recreates_after_active_fe_failure(monkeypatch):
    manager = DorisConnectionManager(_config("global-fe"))
    tenant_config = TokenDatabaseConfig(
        host="tenant-fe-1",
        hosts=["tenant-fe-1", "tenant-fe-2"],
        user="tenant_user",
        password="tenant-secret",
        database="tenant_db",
    )
    manager.token_manager = SimpleNamespace(
        get_database_config_by_token=lambda token: (
            tenant_config if token == "tenant-token" else None
        )
    )
    token_hash = manager._get_token_hash("tenant-token")
    broken_pool = _BrokenAcquirePool(healthy=False)
    recovered_pool = _ProbePool(healthy=True)
    manager.token_pools[token_hash] = broken_pool
    manager.token_configs[token_hash] = {
        "host": "tenant-fe-1",
        "hosts": ["tenant-fe-1", "tenant-fe-2"],
        "port": 9030,
        "user": "tenant_user",
        "password": "tenant-secret",
        "database": "tenant_db",
        "charset": "UTF8",
    }
    manager._token_pool_owner_ids[token_hash] = "static_token:old"
    manager._token_pool_generations[token_hash] = 3
    create_pool = AsyncMock(return_value=recovered_pool)
    monkeypatch.setattr(manager, "_create_pool_with_config", create_pool)

    connection = await manager.get_connection_for_token(
        "tenant-token",
        "recovering-session",
    )

    assert broken_pool.closed is True
    assert connection.owner_pool is recovered_pool
    assert manager.token_pools[token_hash] is recovered_pool
    assert connection.generation == 4
    create_pool.assert_awaited_once()


@pytest.mark.asyncio
async def test_adbc_fails_closed_for_token_bound_cluster():
    manager = DorisConnectionManager(_config("global-fe"))
    tenant_config = TokenDatabaseConfig(
        host="tenant-fe",
        user="tenant_user",
        password="tenant-secret",
    )
    manager.token_manager = SimpleNamespace(
        get_database_config_by_token=lambda token: (
            tenant_config if token == "tenant-token" else None
        )
    )
    context_token = set_current_auth_context(
        AuthContext(
            user_id="tenant",
            auth_method="token",
            token="tenant-token",
        )
    )
    try:
        result = await DorisADBCQueryTools(manager).exec_adbc_query("SELECT 1")
    finally:
        reset_auth_context(context_token)

    assert result["success"] is False
    assert result["error_type"] == "token_bound_adbc_unsupported"


@pytest.mark.asyncio
async def test_http_request_fails_over_only_within_allowlisted_hosts():
    client = DorisHTTPClient(
        user="root",
        password="secret",
        allowed_endpoints={
            "fe": {("fe-a", 8030), ("fe-b", 8030)},
            "be": set(),
        },
    )
    expected = DorisHTTPResponse(
        status=200,
        headers={},
        body=b"ok",
        url="http://fe-b:8030/metrics",
    )
    client.get = AsyncMock(  # type: ignore[method-assign]
        side_effect=[DorisHTTPRequestError("down"), expected]
    )

    response = await client.get_first_available(
        role="fe",
        hosts=["fe-a", "fe-b"],
        port=8030,
        path="/metrics",
    )

    assert response is expected
    assert [call.kwargs["host"] for call in client.get.await_args_list] == [
        "fe-a",
        "fe-b",
    ]
