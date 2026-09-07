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

"""An optional ``init_command`` rides every pool the manager creates."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from doris_mcp_server.auth.token_manager import DatabaseConfig as TokenDatabaseConfig
from doris_mcp_server.utils import db as db_module
from doris_mcp_server.utils.config import DorisConfig
from doris_mcp_server.utils.db import DorisConnectionManager

INIT = "SET SESSION time_zone = '+00:00'"


class _ProbeCursor:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False

    async def execute(self, sql: str) -> None:
        assert sql == "SELECT 1"

    async def fetchone(self):
        return (1,)


class _ProbeConnection:
    closed = False

    def cursor(self):
        return _ProbeCursor()


class _ProbePool:
    def __init__(self):
        self.closed = False

    async def acquire(self):
        return _ProbeConnection()

    def release(self, connection):
        return None

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


def _config(init_command: str | None = None) -> DorisConfig:
    config = DorisConfig()
    config.database.host = "fe-1"
    config.database.hosts = ["fe-1"]
    config.database.user = "root"
    config.database.password = "secret"
    config.database.connection_timeout = 1
    config.database.max_connections = 2
    config.database.init_command = init_command
    return config


def test_global_config_carries_init_command_into_the_pool_config():
    manager = DorisConnectionManager(_config(INIT))
    assert manager.original_db_config["init_command"] == INIT


def test_global_config_default_omits_the_key():
    # Unset = byte-identical pool config (no key), so equality-based callers
    # and serialized configs are unaffected by this feature.
    manager = DorisConnectionManager(_config())
    assert "init_command" not in manager.original_db_config


@pytest.mark.asyncio
async def test_pool_factory_passes_init_command_to_aiomysql(monkeypatch):
    manager = DorisConnectionManager(_config(INIT))
    create_pool = AsyncMock(return_value=_ProbePool())
    monkeypatch.setattr(db_module.aiomysql, "create_pool", create_pool)

    await manager._create_global_pool()

    assert create_pool.await_args.kwargs["init_command"] == INIT


@pytest.mark.asyncio
async def test_pool_factory_passes_none_when_unset(monkeypatch):
    manager = DorisConnectionManager(_config())
    create_pool = AsyncMock(return_value=_ProbePool())
    monkeypatch.setattr(db_module.aiomysql, "create_pool", create_pool)

    await manager._create_global_pool()

    assert create_pool.await_args.kwargs["init_command"] is None


@pytest.mark.asyncio
async def test_explicit_pool_config_wins(monkeypatch):
    manager = DorisConnectionManager(_config())
    create_pool = AsyncMock(return_value=_ProbePool())
    monkeypatch.setattr(db_module.aiomysql, "create_pool", create_pool)

    db_config = dict(manager.original_db_config)
    db_config["init_command"] = "SET SESSION sql_mode = ''"
    await manager._create_pool_with_candidates(db_config, require_health=False)

    assert create_pool.await_args.kwargs["init_command"] == "SET SESSION sql_mode = ''"


def test_token_database_config_accepts_init_command():
    token_config = TokenDatabaseConfig(host="fe-1", init_command=INIT)
    assert token_config.init_command == INIT
    assert TokenDatabaseConfig(host="fe-1").init_command is None


@pytest.mark.asyncio
async def test_token_bound_pool_carries_the_token_init_command(monkeypatch):
    manager = DorisConnectionManager(_config())
    token_config = TokenDatabaseConfig(
        host="fe-1", user="svc", password="x", database="db", init_command=INIT
    )
    manager.token_manager = SimpleNamespace(
        get_database_config_by_token=lambda token: token_config
    )
    create_pool = AsyncMock(return_value=_ProbePool())
    monkeypatch.setattr(db_module.aiomysql, "create_pool", create_pool)

    pool, _ = await manager.get_pool_for_token("token-1")

    assert create_pool.await_args.kwargs["init_command"] == INIT
    assert create_pool.await_args.kwargs["user"] == "svc"
    assert pool is not None
