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
"""Opt-in production-process integration tests against a real Doris instance.

Set ``DORIS_REAL_INTEGRATION=1`` and provide ``DORIS_REAL_HOST``,
``DORIS_REAL_USER``, and ``DORIS_REAL_DATABASE``. ``DORIS_REAL_PORT`` defaults
to 9030 and ``DORIS_REAL_PASSWORD`` may be empty.
"""

from __future__ import annotations

import asyncio
import os
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pymysql
import pytest
from mcp import Client, StdioServerParameters
from mcp.client.stdio import stdio_client

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.getenv("DORIS_REAL_INTEGRATION") != "1",
        reason="set DORIS_REAL_INTEGRATION=1 to run real Doris tests",
    ),
]

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class RealDorisSettings:
    host: str
    port: int
    user: str
    password: str
    database: str


@dataclass
class DorisSandbox:
    settings: RealDorisSettings
    admin_connection: pymysql.Connection
    table: str
    readonly_user: str
    readonly_password: str
    marker: str

    @property
    def qualified_table(self) -> str:
        return f"`{self.settings.database}`.`{self.table}`"

    def kill_connection(self, connection_id: int) -> None:
        with self.admin_connection.cursor() as cursor:
            cursor.execute(f"KILL CONNECTION {int(connection_id)}")


def _real_doris_settings() -> RealDorisSettings:
    required = {
        name: os.getenv(name, "").strip()
        for name in (
            "DORIS_REAL_HOST",
            "DORIS_REAL_USER",
            "DORIS_REAL_DATABASE",
        )
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        pytest.fail(
            "missing real Doris settings: " + ", ".join(sorted(missing)),
            pytrace=False,
        )
    if not SAFE_IDENTIFIER.fullmatch(required["DORIS_REAL_DATABASE"]):
        pytest.fail("DORIS_REAL_DATABASE must be a safe SQL identifier", pytrace=False)
    return RealDorisSettings(
        host=required["DORIS_REAL_HOST"],
        port=int(os.getenv("DORIS_REAL_PORT", "9030")),
        user=required["DORIS_REAL_USER"],
        password=os.getenv("DORIS_REAL_PASSWORD", ""),
        database=required["DORIS_REAL_DATABASE"],
    )


@pytest.fixture
def doris_sandbox() -> DorisSandbox:
    settings = _real_doris_settings()
    suffix = secrets.token_hex(6)
    table = f"mcp_real_it_{suffix}"
    readonly_user = f"mcp_it_ro_{suffix}"
    readonly_password = secrets.token_hex(16)
    marker = secrets.token_hex(12)
    user_identity = f"'{readonly_user}'@'%'"
    qualified_table = f"`{settings.database}`.`{table}`"
    admin_connection = pymysql.connect(
        host=settings.host,
        port=settings.port,
        user=settings.user,
        password=settings.password,
        database=settings.database,
        autocommit=True,
    )

    try:
        with admin_connection.cursor() as cursor:
            cursor.execute(
                f"""
                CREATE TABLE {qualified_table} (
                    id BIGINT,
                    marker VARCHAR(64)
                )
                DUPLICATE KEY(id)
                DISTRIBUTED BY HASH(id) BUCKETS 1
                PROPERTIES ("replication_num" = "1")
                """
            )
            cursor.execute(
                f"CREATE USER {user_identity} IDENTIFIED BY '{readonly_password}'"
            )
            cursor.execute(f"GRANT SELECT_PRIV ON {qualified_table} TO {user_identity}")

        yield DorisSandbox(
            settings=settings,
            admin_connection=admin_connection,
            table=table,
            readonly_user=readonly_user,
            readonly_password=readonly_password,
            marker=marker,
        )
    finally:
        with suppress(Exception), admin_connection.cursor() as cursor:
            cursor.execute(f"DROP USER IF EXISTS {user_identity}")
        with suppress(Exception), admin_connection.cursor() as cursor:
            cursor.execute(f"DROP TABLE IF EXISTS {qualified_table}")
        admin_connection.close()


def _server_environment(
    settings: RealDorisSettings,
    *,
    user: str,
    password: str,
) -> dict[str, str]:
    return {
        **os.environ,
        "DORIS_HOST": settings.host,
        "DORIS_PORT": str(settings.port),
        "DORIS_USER": user,
        "DORIS_PASSWORD": password,
        "DORIS_DATABASE": settings.database,
        "DORIS_MAX_CONNECTIONS": "1",
        "DORIS_CONNECTION_TIMEOUT": "3",
        "ENABLE_SECURITY_CHECK": "false",
        "ENABLE_TOKEN_AUTH": "false",
        "ENABLE_JWT_AUTH": "false",
        "ENABLE_OAUTH_AUTH": "false",
        "OAUTH_ENABLED": "false",
        "ENABLE_DORIS_OAUTH_AUTH": "false",
        "LOG_LEVEL": "ERROR",
        "PYTHONUNBUFFERED": "1",
    }


def _free_tcp_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _read_process_log(log_file: Any) -> str:
    log_file.flush()
    log_file.seek(0)
    return log_file.read().decode("utf-8", errors="replace")[-4000:]


async def _stop_process(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    process.terminate()
    try:
        await asyncio.wait_for(process.wait(), timeout=10)
    except TimeoutError:
        process.kill()
        await process.wait()


async def _wait_for_http_server(
    process: asyncio.subprocess.Process,
    port: int,
    log_file: Any,
) -> None:
    deadline = time.monotonic() + 30
    async with httpx.AsyncClient(timeout=0.5) as client:
        while time.monotonic() < deadline:
            if process.returncode is not None:
                pytest.fail(
                    "HTTP MCP process exited during startup:\n"
                    + _read_process_log(log_file),
                    pytrace=False,
                )
            try:
                response = await client.get(f"http://127.0.0.1:{port}/health")
                if response.status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0.1)
    pytest.fail(
        "HTTP MCP process did not become healthy:\n" + _read_process_log(log_file),
        pytrace=False,
    )


@asynccontextmanager
async def _http_client(environment: dict[str, str]) -> AsyncIterator[Client]:
    port = _free_tcp_port()
    with tempfile.TemporaryFile() as log_file:
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "doris_mcp_server",
            "--transport",
            "http",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            cwd=PROJECT_ROOT,
            env=environment,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        try:
            await _wait_for_http_server(process, port, log_file)
            async with Client(
                f"http://127.0.0.1:{port}/mcp",
                read_timeout_seconds=15,
            ) as client:
                yield client
        finally:
            await _stop_process(process)


@asynccontextmanager
async def _stdio_client(environment: dict[str, str]) -> AsyncIterator[Client]:
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "doris_mcp_server", "--transport", "stdio"],
        cwd=PROJECT_ROOT,
        env=environment,
    )
    with tempfile.TemporaryFile(mode="w+") as log_file:
        stack = AsyncExitStack()
        try:
            client = await stack.enter_async_context(
                Client(
                    stdio_client(parameters, errlog=log_file),
                    read_timeout_seconds=15,
                )
            )
        except Exception:
            log_file.seek(0)
            pytest.fail(
                "STDIO MCP process failed during startup:\n" + log_file.read()[-4000:],
                pytrace=False,
            )
        try:
            yield client
        finally:
            await stack.aclose()


def _transport_client(
    transport: str,
    environment: dict[str, str],
) -> Any:
    if transport == "http":
        return _http_client(environment)
    return _stdio_client(environment)


async def _exec_query(
    client: Client,
    sql: str,
    *,
    timeout: int = 5,
) -> tuple[Any, dict[str, Any]]:
    result = await client.call_tool(
        "exec_query",
        {
            "sql": sql,
            "max_rows": 20,
            "timeout": timeout,
        },
    )
    assert isinstance(result.structured_content, dict)
    return result, result.structured_content


@pytest.mark.parametrize("transport", ["http", "stdio"])
async def test_real_doris_read_write_permission_timeout_and_recovery(
    transport: str,
    doris_sandbox: DorisSandbox,
) -> None:
    admin_environment = _server_environment(
        doris_sandbox.settings,
        user=doris_sandbox.settings.user,
        password=doris_sandbox.settings.password,
    )
    async with _transport_client(transport, admin_environment) as client:
        read_result, read_payload = await _exec_query(client, "SELECT 42 AS answer")
        assert read_result.is_error is False
        assert read_payload["success"] is True
        assert read_payload["data"][0]["answer"] == 42

        write_result, write_payload = await _exec_query(
            client,
            f"""
            INSERT INTO {doris_sandbox.qualified_table}
            VALUES (1, '{doris_sandbox.marker}')
            """,
        )
        assert write_result.is_error is False
        assert write_payload["success"] is True

        verify_result, verify_payload = await _exec_query(
            client,
            f"""
            SELECT marker
            FROM {doris_sandbox.qualified_table}
            WHERE id = 1
            """,
        )
        assert verify_result.is_error is False
        assert verify_payload["data"] == [{"marker": doris_sandbox.marker}]

        timeout_result, timeout_payload = await _exec_query(
            client,
            "SELECT SLEEP(2) AS slept",
            timeout=1,
        )
        assert timeout_result.is_error is True
        assert timeout_payload["success"] is False
        assert timeout_payload["error_type"] == "timeout"

        _, connection_payload = await _exec_query(
            client,
            "SELECT CONNECTION_ID() AS connection_id",
        )
        connection_id = int(connection_payload["data"][0]["connection_id"])
        doris_sandbox.kill_connection(connection_id)

        recovered_result, recovered_payload = await _exec_query(
            client,
            "SELECT 1 AS recovered",
        )
        assert recovered_result.is_error is False
        assert recovered_payload["success"] is True
        assert recovered_payload["data"][0]["recovered"] == 1

    readonly_environment = _server_environment(
        doris_sandbox.settings,
        user=doris_sandbox.readonly_user,
        password=doris_sandbox.readonly_password,
    )
    async with _transport_client(transport, readonly_environment) as client:
        allowed_result, allowed_payload = await _exec_query(
            client,
            f"SELECT marker FROM {doris_sandbox.qualified_table} WHERE id = 1",
        )
        assert allowed_result.is_error is False
        assert allowed_payload["data"] == [{"marker": doris_sandbox.marker}]

        denied_result, denied_payload = await _exec_query(
            client,
            f"""
            INSERT INTO {doris_sandbox.qualified_table}
            VALUES (2, 'must-not-write')
            """,
        )
        assert denied_result.is_error is True
        assert denied_payload["success"] is False
        assert denied_payload["error_type"] == "permission_denied"


@pytest.mark.parametrize("transport", ["http", "stdio"])
async def test_real_doris_tool_regression_paths(
    transport: str,
    doris_sandbox: DorisSandbox,
) -> None:
    environment = _server_environment(
        doris_sandbox.settings,
        user=doris_sandbox.settings.user,
        password=doris_sandbox.settings.password,
    )
    missing_table = f"{doris_sandbox.table}_missing"

    async with _transport_client(transport, environment) as client:
        profile_result = await client.call_tool(
            "get_sql_profile",
            {
                "sql": f"SELECT COUNT(*) AS row_count FROM {doris_sandbox.qualified_table}",
                "db_name": doris_sandbox.settings.database,
            },
        )
        assert isinstance(profile_result.structured_content, dict)
        profile_payload = profile_result.structured_content
        assert isinstance(profile_payload["success"], bool)
        assert profile_payload["trace_id"]
        assert isinstance(profile_payload["execution_time"], int | float)
        assert "auth_context" not in str(profile_payload.get("error", ""))
        assert "referenced before assignment" not in str(
            profile_payload.get("error", "")
        )

        freshness_result = await client.call_tool(
            "monitor_data_freshness",
            {
                "table_names": [missing_table],
                "db_name": doris_sandbox.settings.database,
            },
        )
        assert freshness_result.is_error is False
        assert isinstance(freshness_result.structured_content, dict)
        freshness_payload = freshness_result.structured_content
        assert freshness_payload["monitoring_scope"]["time_threshold_hours"] == 24
        assert freshness_payload["table_freshness"][missing_table] == {
            "last_update": None,
            "staleness_hours": None,
            "freshness_score": 0.0,
            "status": "unknown",
            "method_used": "none",
            "error": "Unable to determine last update time",
        }
        assert freshness_payload["data_flow_issues"] == []

        access_result = await client.call_tool(
            "analyze_data_access_patterns",
            {
                "days": 1,
                "include_system_users": True,
                "min_query_threshold": 1,
            },
        )
        assert access_result.is_error is False
        assert isinstance(access_result.structured_content, dict)
        access_payload = access_result.structured_content
        assert "error" not in access_payload
        role_analysis = access_payload["role_analysis"]
        assert role_analysis
        assert any(
            doris_sandbox.settings.user in role["users"]
            for role in role_analysis.values()
        )

        recovered_result, recovered_payload = await _exec_query(
            client,
            "SELECT 1 AS recovered",
        )
        assert recovered_result.is_error is False
        assert recovered_payload["success"] is True
        assert recovered_payload["data"][0]["recovered"] == 1
