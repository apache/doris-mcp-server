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
to 9030 and ``DORIS_REAL_PASSWORD`` may be empty. Set
``DORIS_REAL_HTTP_INTEGRATION=1`` with ``DORIS_REAL_FE_HTTP_HOST``,
``DORIS_REAL_FE_HTTP_PORT``, ``DORIS_REAL_BE_HOSTS``, and
``DORIS_REAL_BE_WEBSERVER_PORT`` to exercise independent SQL/FE/BE endpoints
through both transports.
"""

from __future__ import annotations

import asyncio
import json
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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import httpx2
import pymysql
import pytest
from mcp import Client, MCPError, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client
from mcp.types import (
    SubscriptionFilter,
    SubscriptionsListenRequest,
    SubscriptionsListenRequestParams,
    SubscriptionsListenResult,
)

from doris_mcp_server import __version__
from doris_mcp_server.utils.secret_policy import build_token_digest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.getenv("DORIS_REAL_INTEGRATION") != "1",
        reason="set DORIS_REAL_INTEGRATION=1 to run real Doris tests",
    ),
]

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
CLUSTER_CHILD_NAMES = (
    "get_cluster_overview",
    "list_cluster_nodes",
    "list_active_tasks",
    "get_monitoring_metrics",
    "get_memory_stats",
    "get_cache_status",
    "get_compaction_status",
    "get_workload_group_status",
    "get_compute_group_status",
    "analyze_resource_growth",
    "get_runtime_capabilities",
)
PIPELINE_CHILD_NAMES = (
    "get_ingestion_status",
    "diagnose_ingestion",
    "get_materialized_view_status",
    "monitor_data_freshness",
    "analyze_data_dependencies",
)
SEARCH_CHILD_NAMES = (
    "search_data",
    "preview_text_analysis",
    "inspect_search_indexes",
    "diagnose_search_query",
)
GOVERNANCE_CHILD_NAMES = (
    "analyze_columns",
    "analyze_table_storage",
    "get_lineage_capability_status",
    "trace_column_lineage",
    "analyze_data_access_patterns",
    "get_recent_audit_logs",
    "list_udfs",
    "get_auth_mapping_status",
)
LAKEHOUSE_CHILD_NAMES = (
    "inspect_external_catalog",
    "inspect_lakehouse_table",
    "inspect_variant_column",
)


@dataclass(frozen=True)
class RealDorisSettings:
    host: str
    port: int
    user: str
    password: str = field(repr=False)
    database: str


@dataclass
class DorisSandbox:
    settings: RealDorisSettings
    admin_connection: pymysql.Connection
    table: str
    restricted_table: str
    readonly_user: str
    readonly_password: str = field(repr=False)
    marker: str

    @property
    def qualified_table(self) -> str:
        return f"`{self.settings.database}`.`{self.table}`"

    @property
    def qualified_restricted_table(self) -> str:
        return f"`{self.settings.database}`.`{self.restricted_table}`"

    def kill_connection(self, connection_id: int) -> None:
        with self.admin_connection.cursor() as cursor:
            cursor.execute(f"KILL CONNECTION {int(connection_id)}")


@dataclass
class DorisSearchSandbox:
    settings: RealDorisSettings
    admin_connection: pymysql.Connection
    table: str

    @property
    def qualified_table(self) -> str:
        return f"`{self.settings.database}`.`{self.table}`"


@dataclass
class DorisVariantSandbox:
    settings: RealDorisSettings
    admin_connection: pymysql.Connection
    table: str
    marker: str

    @property
    def qualified_table(self) -> str:
        return f"`{self.settings.database}`.`{self.table}`"


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
    restricted_table = f"mcp_real_private_{suffix}"
    readonly_user = f"mcp_it_ro_{suffix}"
    readonly_password = secrets.token_hex(16)
    marker = secrets.token_hex(12)
    user_identity = f"'{readonly_user}'@'%'"
    qualified_table = f"`{settings.database}`.`{table}`"
    qualified_restricted_table = f"`{settings.database}`.`{restricted_table}`"
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
                    marker VARCHAR(64) COMMENT 'Integration marker'
                )
                DUPLICATE KEY(id)
                DISTRIBUTED BY HASH(id) BUCKETS 1
                PROPERTIES ("replication_num" = "1")
                """
            )
            cursor.execute(
                f"""
                CREATE TABLE {qualified_restricted_table} (
                    id BIGINT,
                    marker VARCHAR(64)
                )
                DUPLICATE KEY(id)
                DISTRIBUTED BY HASH(id) BUCKETS 1
                PROPERTIES ("replication_num" = "1")
                """
            )
            cursor.execute(
                f"INSERT INTO {qualified_restricted_table} VALUES (1, %s)",
                (marker,),
            )
            cursor.execute(
                f"CREATE USER {user_identity} IDENTIFIED BY '{readonly_password}'"
            )
            cursor.execute(f"GRANT SELECT_PRIV ON {qualified_table} TO {user_identity}")

        yield DorisSandbox(
            settings=settings,
            admin_connection=admin_connection,
            table=table,
            restricted_table=restricted_table,
            readonly_user=readonly_user,
            readonly_password=readonly_password,
            marker=marker,
        )
    finally:
        with suppress(Exception), admin_connection.cursor() as cursor:
            cursor.execute(f"DROP USER IF EXISTS {user_identity}")
        with suppress(Exception), admin_connection.cursor() as cursor:
            cursor.execute(f"DROP TABLE IF EXISTS {qualified_table}")
        with suppress(Exception), admin_connection.cursor() as cursor:
            cursor.execute(f"DROP TABLE IF EXISTS {qualified_restricted_table}")
        admin_connection.close()


@pytest.fixture
def doris_search_sandbox() -> DorisSearchSandbox:
    settings = _real_doris_settings()
    table = f"mcp_search_it_{secrets.token_hex(6)}"
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
                    id BIGINT NOT NULL,
                    title STRING NOT NULL,
                    category VARCHAR(64) NOT NULL,
                    embedding ARRAY<FLOAT> NOT NULL,
                    INDEX idx_title (title) USING INVERTED
                        PROPERTIES (
                            "parser" = "english",
                            "support_phrase" = "true"
                        ),
                    INDEX idx_embedding (embedding) USING ANN
                        PROPERTIES (
                            "index_type" = "hnsw",
                            "metric_type" = "l2_distance",
                            "dim" = "3"
                        )
                )
                DUPLICATE KEY(id)
                DISTRIBUTED BY HASH(id) BUCKETS 1
                PROPERTIES ("replication_num" = "1")
                """
            )
            cursor.execute(
                f"""
                INSERT INTO {qualified_table} VALUES
                    (1, 'Apache Doris search', 'database', [0.1, 0.2, 0.3]),
                    (2, 'Hybrid retrieval', 'search', [0.2, 0.1, 0.4]),
                    (3, 'Warehouse analytics', 'analytics', [0.8, 0.7, 0.6])
                """
            )

        yield DorisSearchSandbox(
            settings=settings,
            admin_connection=admin_connection,
            table=table,
        )
    finally:
        with suppress(Exception), admin_connection.cursor() as cursor:
            cursor.execute(f"DROP TABLE IF EXISTS {qualified_table}")
        admin_connection.close()


@pytest.fixture
def doris_variant_sandbox() -> DorisVariantSandbox:
    settings = _real_doris_settings()
    table = f"mcp_variant_it_{secrets.token_hex(6)}"
    marker = secrets.token_hex(12)
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
                    payload VARIANT
                )
                DUPLICATE KEY(id)
                DISTRIBUTED BY HASH(id) BUCKETS 1
                PROPERTIES ("replication_num" = "1")
                """
            )
            cursor.executemany(
                f"INSERT INTO {qualified_table} VALUES (%s, %s)",
                [
                    (
                        1,
                        json.dumps(
                            {
                                "profile": {"age": 42},
                                "private_marker": marker,
                            }
                        ),
                    ),
                    (
                        2,
                        json.dumps(
                            {
                                "profile": {"age": 43},
                                "private_marker": marker,
                            }
                        ),
                    ),
                ],
            )

        yield DorisVariantSandbox(
            settings=settings,
            admin_connection=admin_connection,
            table=table,
            marker=marker,
        )
    finally:
        with suppress(Exception), admin_connection.cursor() as cursor:
            cursor.execute(f"DROP TABLE IF EXISTS {qualified_table}")
        admin_connection.close()


def _server_environment(
    settings: RealDorisSettings,
    *,
    user: str,
    password: str,
) -> dict[str, str]:
    environment = {
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
        "MCP_TOOL_EXPOSURE_MODE": "hierarchical",
    }
    fe_http_host = os.getenv("DORIS_REAL_FE_HTTP_HOST", "").strip()
    if fe_http_host:
        environment["DORIS_FE_HTTP_HOST"] = fe_http_host
    fe_http_port = os.getenv("DORIS_REAL_FE_HTTP_PORT", "").strip()
    if fe_http_port:
        environment["DORIS_FE_HTTP_PORT"] = fe_http_port
    be_hosts = os.getenv("DORIS_REAL_BE_HOSTS", "").strip()
    if be_hosts:
        environment["DORIS_BE_HOSTS"] = be_hosts
    be_http_port = os.getenv("DORIS_REAL_BE_WEBSERVER_PORT", "").strip()
    if be_http_port:
        environment["DORIS_BE_WEBSERVER_PORT"] = be_http_port
    return environment


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
                response = await client.get(f"http://127.0.0.1:{port}/live")
                if response.status_code == 200:
                    assert response.json()["version"] == __version__
                    assert response.json()["status"] == "alive"
                    return
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0.1)
    pytest.fail(
        "HTTP MCP process did not become live:\n" + _read_process_log(log_file),
        pytrace=False,
    )


@asynccontextmanager
async def _http_process(environment: dict[str, str]) -> AsyncIterator[str]:
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
            try:
                yield f"http://127.0.0.1:{port}"
            except Exception as exc:
                exc.add_note(
                    "HTTP MCP process log:\n" + _read_process_log(log_file)
                )
                raise
        finally:
            await _stop_process(process)


@asynccontextmanager
async def _http_client(
    environment: dict[str, str],
    *,
    read_timeout_seconds: int = 15,
) -> AsyncIterator[Client]:
    async with _http_process(environment) as base_url:
        async with Client(
            f"{base_url}/mcp",
            read_timeout_seconds=read_timeout_seconds,
        ) as client:
            yield client


@asynccontextmanager
async def _authenticated_http_client(
    environment: dict[str, str],
    *,
    bearer_token: str,
    read_timeout_seconds: int = 15,
) -> AsyncIterator[Client]:
    async with _http_process(environment) as base_url:
        async with httpx2.AsyncClient(
            headers={"Authorization": f"Bearer {bearer_token}"},
        ) as http_client:
            transport = streamable_http_client(
                f"{base_url}/mcp",
                http_client=http_client,
            )
            async with Client(
                transport,
                read_timeout_seconds=read_timeout_seconds,
            ) as client:
                yield client


@asynccontextmanager
async def _stdio_client(
    environment: dict[str, str],
    *,
    read_timeout_seconds: int = 15,
) -> AsyncIterator[Client]:
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
                    read_timeout_seconds=read_timeout_seconds,
                )
            )
        except Exception:
            log_file.seek(0)
            pytest.fail(
                "STDIO MCP process failed during startup:\n" + log_file.read()[-4000:],
                pytrace=False,
            )
        try:
            try:
                yield client
            except Exception as exc:
                log_file.flush()
                log_file.seek(0)
                exc.add_note(
                    "STDIO MCP process log:\n" + log_file.read()[-4000:]
                )
                raise
        finally:
            await stack.aclose()


def _transport_client(
    transport: str,
    environment: dict[str, str],
    *,
    read_timeout_seconds: int = 15,
) -> Any:
    if transport == "http":
        return _http_client(
            environment,
            read_timeout_seconds=read_timeout_seconds,
        )
    return _stdio_client(
        environment,
        read_timeout_seconds=read_timeout_seconds,
    )


async def _exec_query(
    client: Client,
    sql: str,
    *,
    timeout: int = 5,
    max_rows: int | None = None,
) -> tuple[Any, dict[str, Any]]:
    manifest = await _discover_domain(client, "doris_query")
    arguments: dict[str, Any] = {
        "sql": sql,
        "timeout_ms": timeout * 1000,
    }
    if max_rows is not None:
        arguments["max_rows"] = max_rows
    result, envelope = await _call_domain_child_result(
        client,
        domain="doris_query",
        child_tool="execute_query",
        arguments=arguments,
        manifest_version=manifest["manifest_version"],
    )
    if result.is_error:
        return result, envelope
    return result, envelope["data"]


async def _discover_domain(client: Client, domain: str) -> dict[str, Any]:
    result = await client.call_tool(domain, {})
    assert result.is_error is False, json.dumps(
        result.model_dump(by_alias=True, mode="json"),
        ensure_ascii=False,
    )
    assert isinstance(result.structured_content, dict)
    manifest = result.structured_content
    assert manifest["mode"] == "manifest"
    assert manifest["domain"] == domain
    return manifest


async def _call_domain_child_result(
    client: Client,
    *,
    domain: str,
    child_tool: str,
    arguments: dict[str, Any],
    manifest_version: str,
) -> tuple[Any, dict[str, Any]]:
    result = await client.call_tool(
        domain,
        {
            "child_tool": child_tool,
            "arguments": arguments,
            "manifest_version": manifest_version,
        },
    )
    assert isinstance(result.structured_content, dict)
    payload = result.structured_content
    assert payload["domain"] == domain
    assert payload.get("child_tool") == child_tool
    assert payload["mode"] == ("error" if result.is_error else "result")
    return result, payload


async def _call_domain_child(
    client: Client,
    *,
    domain: str,
    child_tool: str,
    arguments: dict[str, Any],
    manifest_version: str,
) -> dict[str, Any]:
    result, payload = await _call_domain_child_result(
        client,
        domain=domain,
        child_tool=child_tool,
        arguments=arguments,
        manifest_version=manifest_version,
    )
    assert result.is_error is False, json.dumps(
        result.model_dump(by_alias=True, mode="json"),
        ensure_ascii=False,
    )
    assert payload["mode"] == "result"
    assert isinstance(payload["data"], dict)
    return payload["data"]


@pytest.mark.parametrize("transport", ["http", "stdio"])
async def test_real_doris_result_boundaries_and_cancellation(
    transport: str,
    doris_sandbox: DorisSandbox,
) -> None:
    environment = _server_environment(
        doris_sandbox.settings,
        user=doris_sandbox.settings.user,
        password=doris_sandbox.settings.password,
    )
    environment.update(
        {
            "MAX_RESULT_ROWS": "5",
            "DEFAULT_RESULT_ROWS": "2",
            "MAX_RESULT_BYTES": "256",
            "QUERY_TIMEOUT": "5",
        }
    )
    with doris_sandbox.admin_connection.cursor() as cursor:
        cursor.executemany(
            f"INSERT INTO {doris_sandbox.qualified_table} VALUES (%s, %s)",
            [
                (index, f"{doris_sandbox.marker}-{index}-" + ("x" * 32))
                for index in range(1, 7)
            ],
        )

    async with _transport_client(
        transport,
        environment,
        read_timeout_seconds=10,
    ) as client:
        tools = {
            tool.name: tool
            for tool in (await client.list_tools(cache_mode="bypass")).tools
        }
        assert "exec_query" not in tools
        assert "doris_query" in tools
        manifest = await _discover_domain(client, "doris_query")
        children = {child["name"]: child for child in manifest["children"]}
        query_schema = children["execute_query"]["input_schema"]["properties"]
        assert set(query_schema) == {
            "sql",
            "catalog",
            "database",
            "parameters",
            "max_rows",
            "timeout_ms",
        }
        assert query_schema["max_rows"]["maximum"] == 100_000
        assert query_schema["timeout_ms"]["maximum"] == 300_000

        default_result, default_payload = await _exec_query(
            client,
            f"SELECT id FROM {doris_sandbox.qualified_table} ORDER BY id",
            timeout=5,
        )
        assert default_result.is_error is False
        assert len(default_payload["data"]["rows"]) == 2
        assert default_payload["metadata"]["limits"]["max_rows"] == 2

        excessive_rows, excessive_payload = await _call_domain_child_result(
            client,
            domain="doris_query",
            child_tool="execute_query",
            arguments={
                "sql": f"SELECT * FROM {doris_sandbox.qualified_table}",
                "max_rows": 6,
                "timeout_ms": 5000,
            },
            manifest_version=manifest["manifest_version"],
        )
        assert excessive_rows.is_error is True
        assert excessive_payload["error"]["code"] == "CHILD_ARGUMENTS_INVALID"
        assert excessive_payload["error"]["details"]["reason_code"] == (
            "QUERY_ARGUMENT_INVALID"
        )

        row_result, row_payload = await _exec_query(
            client,
            f"SELECT id FROM {doris_sandbox.qualified_table} ORDER BY id",
            max_rows=2,
            timeout=5,
        )
        assert row_result.is_error is False
        assert len(row_payload["data"]["rows"]) == 2
        assert row_payload["metadata"]["result_bytes"] <= 256
        assert row_payload["metadata"]["limits"] == {
            "max_rows": 2,
            "max_bytes": 256,
            "timeout_seconds": 5,
        }

        byte_result, byte_payload = await _exec_query(
            client,
            (f"SELECT id, marker FROM {doris_sandbox.qualified_table} ORDER BY id"),
            max_rows=5,
            timeout=5,
        )
        assert byte_result.is_error is False
        assert byte_payload["metadata"]["result_bytes"] <= 256
        assert byte_payload["data"]["truncated"] is True
        assert byte_payload["metadata"]["truncation_reason"] == "byte_limit"
        assert 0 < len(byte_payload["data"]["rows"]) < 5

        if transport == "stdio":
            cancelled_query = asyncio.create_task(
                client.call_tool(
                    "doris_query",
                    {
                        "child_tool": "execute_query",
                        "arguments": {
                            "sql": (
                                "SELECT COUNT(*) AS row_count "
                                'FROM numbers("number" = "1000000000")'
                            ),
                            "max_rows": 1,
                            "timeout_ms": 5000,
                        },
                        "manifest_version": manifest["manifest_version"],
                    },
                )
            )
            await asyncio.sleep(0.2)
            cancelled_query.cancel()
            with pytest.raises(asyncio.CancelledError):
                await cancelled_query
        else:
            timed_out, timed_out_payload = await _exec_query(
                client,
                'SELECT COUNT(*) AS row_count FROM numbers("number" = "1000000000")',
                max_rows=1,
                timeout=1,
            )
            assert timed_out.is_error is True
            assert timed_out_payload["error"]["code"] == ("CHILD_EXECUTION_TIMEOUT")
            assert timed_out_payload["error"]["details"]["reason_code"] == (
                "QUERY_TIMEOUT"
            )

        recovery_started = time.monotonic()
        recovered_result, recovered_payload = await _exec_query(
            client,
            "SELECT 1 AS recovered",
            max_rows=1,
            timeout=5,
        )
        assert time.monotonic() - recovery_started < 3
        assert recovered_result.is_error is False
        assert recovered_payload["data"]["rows"] == [{"recovered": 1}]


async def test_real_doris_token_pool_recovers_after_repeated_query_timeouts(
    doris_sandbox: DorisSandbox,
    tmp_path: Path,
) -> None:
    bearer_token = secrets.token_urlsafe(48)
    token_file = tmp_path / "tokens.json"
    token_file.write_text(
        json.dumps(
            {
                "version": "2.0",
                "tokens": [
                    {
                        "token_id": "real-timeout-regression",
                        "token_digest": build_token_digest(
                            bearer_token,
                            "sha256",
                        ),
                        "created_at": "2026-07-30T00:00:00Z",
                        "expires_at": None,
                        "last_used": None,
                        "description": "real token pool timeout regression",
                        "is_active": True,
                        "database_config": {
                            "host": doris_sandbox.settings.host,
                            "port": doris_sandbox.settings.port,
                            "user": doris_sandbox.readonly_user,
                            "password": doris_sandbox.readonly_password,
                            "database": doris_sandbox.settings.database,
                            "charset": "UTF8",
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    token_file.chmod(0o600)
    environment = _server_environment(
        doris_sandbox.settings,
        user=doris_sandbox.settings.user,
        password=doris_sandbox.settings.password,
    )
    environment.update(
        {
            "ENABLE_TOKEN_AUTH": "true",
            "TOKEN_FILE_PATH": str(token_file),
            "TOKEN_DB_VALIDATION_TTL_SECONDS": "60",
            "DORIS_MAX_CONNECTIONS": "1",
            "QUERY_TIMEOUT": "5",
        }
    )

    async with _authenticated_http_client(
        environment,
        bearer_token=bearer_token,
        read_timeout_seconds=10,
    ) as client:
        for attempt in range(3):
            timed_out, timed_out_payload = await _exec_query(
                client,
                'SELECT COUNT(*) AS row_count FROM numbers("number" = "1000000000")',
                max_rows=1,
                timeout=1,
            )
            assert timed_out.is_error is True
            assert timed_out_payload["error"]["code"] == ("CHILD_EXECUTION_TIMEOUT")
            assert timed_out_payload["error"]["details"]["reason_code"] == (
                "QUERY_TIMEOUT"
            )

            recovery_started = time.monotonic()
            recovered, recovered_payload = await _exec_query(
                client,
                "SELECT CURRENT_USER() AS current_user",
                max_rows=1,
                timeout=5,
            )
            assert time.monotonic() - recovery_started < 3
            assert recovered.is_error is False, f"recovery {attempt + 1} failed"
            assert (
                doris_sandbox.readonly_user
                in recovered_payload["data"]["rows"][0]["current_user"]
            )


async def _collect_list_pages(
    list_method: Any,
    *,
    result_field: str,
    identifier: Any,
    max_page_size: int,
) -> tuple[list[str], int]:
    cursor = None
    seen_cursors: set[str] = set()
    identifiers: list[str] = []
    page_count = 0

    while True:
        result = await list_method(cursor=cursor, cache_mode="bypass")
        page = getattr(result, result_field)
        assert 0 < len(page) <= max_page_size
        identifiers.extend(identifier(item) for item in page)
        page_count += 1

        cursor = result.next_cursor
        if cursor is None:
            break
        assert cursor not in seen_cursors
        seen_cursors.add(cursor)

    assert identifiers == sorted(identifiers)
    assert len(identifiers) == len(set(identifiers))
    return identifiers, page_count


async def test_real_doris_liveness_and_readiness(
    doris_sandbox: DorisSandbox,
) -> None:
    environment = _server_environment(
        doris_sandbox.settings,
        user=doris_sandbox.settings.user,
        password=doris_sandbox.settings.password,
    )
    async with _http_process(environment) as base_url:
        async with httpx.AsyncClient(timeout=5) as client:
            health = await client.get(f"{base_url}/health")
            live = await client.get(f"{base_url}/live")
            ready = await client.get(f"{base_url}/ready")

    assert health.status_code == 200
    assert health.json()["status"] == "healthy"
    assert live.status_code == 200
    assert live.json()["status"] == "alive"
    assert ready.status_code == 200
    assert ready.json()["status"] == "ready"
    assert ready.json()["checks"] == {
        "service": "ready",
        "doris": "ready",
    }


@pytest.mark.parametrize("transport", ["http", "stdio"])
async def test_real_doris_protocol_lists_paginate_without_loss(
    transport: str,
    doris_sandbox: DorisSandbox,
) -> None:
    environment = _server_environment(
        doris_sandbox.settings,
        user=doris_sandbox.settings.user,
        password=doris_sandbox.settings.password,
    )
    page_size = 2
    environment["MCP_LIST_PAGE_SIZE"] = str(page_size)
    results: dict[str, tuple[list[str], int]] = {}

    async with _transport_client(
        transport,
        environment,
        read_timeout_seconds=60,
    ) as client:
        capabilities = client.server_capabilities
        assert capabilities is not None
        assert capabilities.tools is not None
        assert capabilities.tools.list_changed is False
        assert capabilities.prompts is not None
        assert capabilities.prompts.list_changed is False
        assert capabilities.resources is not None
        assert capabilities.resources.list_changed is False
        assert capabilities.resources.subscribe is False

        with pytest.raises(MCPError) as unsupported:
            await client.session.send_request(
                SubscriptionsListenRequest(
                    params=SubscriptionsListenRequestParams(
                        notifications=SubscriptionFilter(
                            tools_list_changed=True,
                            prompts_list_changed=True,
                            resources_list_changed=True,
                            resource_subscriptions=[
                                f"doris://table/{doris_sandbox.table}"
                            ],
                        )
                    )
                ),
                SubscriptionsListenResult,
                request_read_timeout_seconds=5,
            )
        assert unsupported.value.code == -32601
        assert unsupported.value.message == "Method not found"

        query_manifest = await _discover_domain(client, "doris_query")
        invalid_arguments, invalid_payload = await _call_domain_child_result(
            client,
            domain="doris_query",
            child_tool="execute_query",
            arguments={"sql": ["SELECT 1"]},
            manifest_version=query_manifest["manifest_version"],
        )
        assert invalid_arguments.is_error is True
        assert invalid_payload["error"]["code"] == "CHILD_ARGUMENTS_INVALID"
        assert invalid_payload["error"]["details"]["violations"]

        for list_method, result_field, identifier in (
            (
                client.list_resources,
                "resources",
                lambda resource: str(resource.uri),
            ),
            (client.list_tools, "tools", lambda tool: tool.name),
            (client.list_prompts, "prompts", lambda prompt: prompt.name),
        ):
            identifiers, page_count = await _collect_list_pages(
                list_method,
                result_field=result_field,
                identifier=identifier,
                max_page_size=page_size,
            )
            results[result_field] = (identifiers, page_count)

    resource_identifiers, resource_page_count = results["resources"]
    assert len(resource_identifiers) > page_size
    assert resource_page_count > 1
    assert results["tools"][0]
    assert results["prompts"][0]


@pytest.mark.parametrize("transport", ["http", "stdio"])
async def test_real_doris_read_only_permission_timeout_and_recovery(
    transport: str,
    doris_sandbox: DorisSandbox,
) -> None:
    with doris_sandbox.admin_connection.cursor() as cursor:
        cursor.execute(
            f"INSERT INTO {doris_sandbox.qualified_table} VALUES (1, %s)",
            (doris_sandbox.marker,),
        )

    admin_environment = _server_environment(
        doris_sandbox.settings,
        user=doris_sandbox.settings.user,
        password=doris_sandbox.settings.password,
    )
    async with _transport_client(transport, admin_environment) as client:
        assert client.server_info is not None
        assert client.server_info.name == "doris-mcp-server"
        assert client.server_info.version == __version__

        read_result, read_payload = await _exec_query(client, "SELECT 42 AS answer")
        assert read_result.is_error is False
        assert read_payload["status"] == "success"
        assert read_payload["data"]["rows"][0]["answer"] == 42

        write_result, write_payload = await _exec_query(
            client,
            f"""
            INSERT INTO {doris_sandbox.qualified_table}
            VALUES (1, '{doris_sandbox.marker}')
            """,
        )
        assert write_result.is_error is True
        assert write_payload["error"]["code"] == "CHILD_ARGUMENTS_INVALID"
        assert write_payload["error"]["details"]["reason_code"] == (
            "QUERY_READ_ONLY_VIOLATION"
        )

        verify_result, verify_payload = await _exec_query(
            client,
            f"""
            SELECT marker
            FROM {doris_sandbox.qualified_table}
            WHERE id = 1
            """,
        )
        assert verify_result.is_error is False
        assert verify_payload["data"]["rows"] == [{"marker": doris_sandbox.marker}]

        response_secret = f"sec016-{secrets.token_hex(12)}"
        sensitive_error_result, sensitive_error_payload = await _exec_query(
            client,
            (
                f"SELECT '{response_secret}' AS marker "
                f"FROM `{doris_sandbox.table}_missing`"
            ),
        )
        assert sensitive_error_result.is_error is True
        assert sensitive_error_payload["error"]["code"] == ("CHILD_EXECUTION_FAILED")
        serialized_error = json.dumps(
            sensitive_error_result.model_dump(by_alias=True, mode="json"),
            ensure_ascii=False,
        )
        assert response_secret not in serialized_error

        timeout_result, timeout_payload = await _exec_query(
            client,
            'SELECT COUNT(*) AS row_count FROM numbers("number" = "1000000000")',
            timeout=1,
        )
        assert timeout_result.is_error is True
        assert timeout_payload["error"]["code"] == "CHILD_EXECUTION_TIMEOUT"
        assert timeout_payload["error"]["details"]["reason_code"] == ("QUERY_TIMEOUT")

        _, connection_payload = await _exec_query(
            client,
            "SELECT CONNECTION_ID() AS connection_id",
        )
        connection_id = int(connection_payload["data"]["rows"][0]["connection_id"])
        doris_sandbox.kill_connection(connection_id)

        recovered_result, recovered_payload = await _exec_query(
            client,
            "SELECT 1 AS recovered",
        )
        assert recovered_result.is_error is False
        assert recovered_payload["status"] == "success"
        assert recovered_payload["data"]["rows"][0]["recovered"] == 1

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
        assert allowed_payload["data"]["rows"] == [{"marker": doris_sandbox.marker}]

        denied_result, denied_payload = await _exec_query(
            client,
            f"SELECT marker FROM {doris_sandbox.qualified_restricted_table}",
        )
        assert denied_result.is_error is True
        assert denied_payload["error"]["code"] == "CHILD_EXECUTION_FAILED"
        assert denied_payload["error"]["details"]["reason_code"] == (
            "QUERY_PERMISSION_DENIED"
        )


@pytest.mark.parametrize("transport", ["http", "stdio"])
async def test_real_doris_hierarchical_tool_regression_paths(
    transport: str,
    doris_sandbox: DorisSandbox,
) -> None:
    environment = _server_environment(
        doris_sandbox.settings,
        user=doris_sandbox.settings.user,
        password=doris_sandbox.settings.password,
    )
    with doris_sandbox.admin_connection.cursor() as cursor:
        cursor.execute(
            f"INSERT INTO {doris_sandbox.qualified_table} VALUES (1, %s)",
            (doris_sandbox.marker,),
        )

    async with _transport_client(transport, environment) as client:
        listed_tools = {
            tool.name for tool in (await client.list_tools(cache_mode="bypass")).tools
        }
        assert {
            "get_table_basic_info",
            "get_table_schema",
            "analyze_columns",
            "get_sql_profile",
            "monitor_data_freshness",
            "analyze_data_access_patterns",
            "exec_query",
        }.isdisjoint(listed_tools)

        catalog_manifest = await _discover_domain(client, "doris_catalog")
        table_context = await _call_domain_child(
            client,
            domain="doris_catalog",
            child_tool="get_table_context",
            arguments={
                "database": doris_sandbox.settings.database,
                "table": doris_sandbox.table,
                "sections": ["schema", "basic"],
            },
            manifest_version=catalog_manifest["manifest_version"],
        )
        basic = table_context["data"]["basic"]
        schema = table_context["data"]["schema"]
        assert basic["status"] == "success"
        assert basic["data"]["table"] == doris_sandbox.table
        assert basic["data"]["row_count"] >= 0
        assert schema["status"] == "success"
        assert schema["data"]["column_count"] == 2
        schema_columns = schema["data"]["columns"]
        assert (
            next(
                column for column in schema_columns if column["column_name"] == "marker"
            )["comment"]
            == "Integration marker"
        )

        governance_manifest = await _discover_domain(client, "doris_governance")
        column_analysis = await _call_domain_child(
            client,
            domain="doris_governance",
            child_tool="analyze_columns",
            arguments={
                "database": doris_sandbox.settings.database,
                "table": doris_sandbox.table,
                "columns": ["id", "marker"],
                "sample_ratio": 0.1,
            },
            manifest_version=governance_manifest["manifest_version"],
        )
        assert [item["name"] for item in column_analysis["data"]["columns"]] == [
            "id",
            "marker",
        ]
        assert column_analysis["metadata"]["invented_statistics"] is False

        injected_result, injected_payload = await _call_domain_child_result(
            client,
            domain="doris_governance",
            child_tool="analyze_columns",
            arguments={
                "database": doris_sandbox.settings.database,
                "table": (f"{doris_sandbox.table}; DROP TABLE {doris_sandbox.table}"),
                "columns": ["id"],
            },
            manifest_version=governance_manifest["manifest_version"],
        )
        assert injected_result.is_error is True
        assert injected_payload["error"]["code"] == "CHILD_ARGUMENTS_INVALID"
        assert injected_payload["error"]["details"]["reason_code"] == (
            "GOVERNANCE_ARGUMENT_INVALID"
        )

        intact_result, intact_payload = await _exec_query(
            client,
            f"SELECT COUNT(*) AS row_count FROM {doris_sandbox.qualified_table}",
        )
        assert intact_result.is_error is False
        assert intact_payload["data"]["rows"] == [{"row_count": 1}]

        query_manifest = await _discover_domain(client, "doris_query")
        query_children = {child["name"]: child for child in query_manifest["children"]}
        profile_availability = query_children["get_query_profile"]["availability"]
        profile_result, profile_envelope = await _call_domain_child_result(
            client,
            domain="doris_query",
            child_tool="get_query_profile",
            arguments={
                "sql": f"SELECT COUNT(*) AS row_count FROM {doris_sandbox.qualified_table}",
            },
            manifest_version=query_manifest["manifest_version"],
        )
        if profile_result.is_error:
            profile_error = profile_envelope["error"]
            if profile_availability["callable"]:
                assert profile_error["code"] == "CHILD_EXECUTION_FAILED"
                assert profile_error["details"]["reason_code"].startswith(
                    "QUERY_PROFILE_"
                )
            else:
                assert profile_error["code"] == "CHILD_CAPABILITY_UNAVAILABLE"
                assert (
                    profile_error["details"]["reason_code"]
                    == (profile_availability["reason_code"])
                )
            profile_text = json.dumps(profile_error, ensure_ascii=False)
            assert "auth_context" not in profile_text
            assert "referenced before assignment" not in profile_text
        else:
            assert profile_availability["callable"] is True
            profile_payload = profile_envelope["data"]
            assert profile_payload["status"] in {"success", "partial"}
            assert profile_payload["data"]["query_summary"] is not None

        pipeline_manifest = await _discover_domain(client, "doris_pipeline")
        freshness = await _call_domain_child(
            client,
            domain="doris_pipeline",
            child_tool="monitor_data_freshness",
            arguments={
                "database": doris_sandbox.settings.database,
                "table": doris_sandbox.table,
                "threshold_seconds": 86_400,
            },
            manifest_version=pipeline_manifest["manifest_version"],
        )
        assert freshness["data"]["status"] in {"fresh", "stale"}
        assert freshness["metadata"]["invented_evidence"] is False

        access = await _call_domain_child(
            client,
            domain="doris_governance",
            child_tool="analyze_data_access_patterns",
            arguments={
                "database": doris_sandbox.settings.database,
                "table": doris_sandbox.table,
                "window_days": 1,
                "group_by": "operation",
            },
            manifest_version=governance_manifest["manifest_version"],
        )
        assert access["metadata"]["raw_sql_exposed"] is False

        recovered_result, recovered_payload = await _exec_query(
            client,
            "SELECT 1 AS recovered",
        )
        assert recovered_result.is_error is False
        assert recovered_payload["status"] == "success"
        assert recovered_payload["data"]["rows"][0]["recovered"] == 1


@pytest.mark.parametrize("transport", ["http", "stdio"])
async def test_real_doris_flat_tool_list_stays_bounded_and_callable(
    transport: str,
) -> None:
    settings = _real_doris_settings()
    environment = _server_environment(
        settings,
        user=settings.user,
        password=settings.password,
    )
    environment["MCP_TOOL_EXPOSURE_MODE"] = "flat"

    async with _transport_client(
        transport,
        environment,
        read_timeout_seconds=60,
    ) as client:
        tools = {
            tool.name: tool
            for tool in (await client.list_tools(cache_mode="bypass")).tools
        }
        assert len(tools) == 55
        assert "doris_query_execute_query" in tools

        result = await client.call_tool(
            "doris_query_execute_query",
            {
                "sql": "SELECT @@version_comment",
                "max_rows": 1,
            },
        )
        assert result.is_error is False
        assert isinstance(result.structured_content, dict)
        assert "4.0.5-rc01" in json.dumps(
            result.structured_content,
            ensure_ascii=False,
        )


@pytest.mark.parametrize("transport", ["http", "stdio"])
async def test_real_doris_ossie_exact_revision_model_is_read_only_and_live(
    transport: str,
    doris_sandbox: DorisSandbox,
    tmp_path: Path,
) -> None:
    """Resolve an exact ``+revision`` Ossie model over real Doris metadata."""
    model_ref = "sales/commerce@2026.08.05+4f91c2a"
    (tmp_path / "sales-commerce.yaml").write_text(
        """
version: "0.2.0.dev0"
semantic_model:
  - name: sales_commerce
    description: Governed sales acceptance model
    datasets:
      - name: orders
        source: commerce.orders
        primary_key: [order_id]
        fields:
          - name: order_id
            expression:
              dialects:
                - dialect: ANSI_SQL
                  expression: id
            datatype: Integer
          - name: order_marker
            expression:
              dialects:
                - dialect: ANSI_SQL
                  expression: marker
            datatype: String
    metrics:
      - name: order_count
        expression:
          dialects:
            - dialect: ANSI_SQL
              expression: COUNT(orders.order_id)
        datatype: Integer
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / "bindings.yaml").write_text(
        f"""
api_version: doris-mcp.apache.org/ossie-binding/v1alpha1
model_sources:
  {model_ref}:
    model_file: sales-commerce.yaml
    model_name: sales_commerce
    namespace: commerce
    tags: [certified]
    route_profile: global
    datasets:
      orders:
        catalog: internal
        database: {doris_sandbox.settings.database}
        object: {doris_sandbox.table}
        kind: table
""".strip(),
        encoding="utf-8",
    )
    environment = _server_environment(
        doris_sandbox.settings,
        user=doris_sandbox.readonly_user,
        password=doris_sandbox.readonly_password,
    )
    environment.update(
        {
            "OSSIE_ENABLED": "true",
            "OSSIE_MODEL_DIRECTORY": str(tmp_path),
            "OSSIE_BINDING_MANIFEST": str(tmp_path / "bindings.yaml"),
            "METRICFLOW_ENABLED": "false",
        }
    )

    with doris_sandbox.admin_connection.cursor() as cursor:
        cursor.execute(
            f"SELECT COUNT(*) AS row_count FROM {doris_sandbox.qualified_table}"
        )
        rows_before = int(cursor.fetchone()[0])

    async with _transport_client(
        transport,
        environment,
        read_timeout_seconds=60,
    ) as client:
        manifest = await _discover_domain(client, "doris_semantic")
        children = {child["name"]: child for child in manifest["children"]}
        ossie_children = {
            "list_semantic_models",
            "get_semantic_model_summary",
            "get_semantic_context",
            "get_semantic_mapping_status",
        }
        metricflow_children = {name for name in children if "metricflow" in name}
        assert len(children) == 12
        assert len(metricflow_children) == 8
        assert all(
            children[name]["availability"]["callable"] for name in ossie_children
        )
        assert all(
            not children[name]["availability"]["callable"]
            for name in metricflow_children
        )
        manifest_version = manifest["manifest_version"]

        listed = await _call_domain_child(
            client,
            domain="doris_semantic",
            child_tool="list_semantic_models",
            arguments={},
            manifest_version=manifest_version,
        )
        assert [item["model_ref"] for item in listed["data"]["items"]] == [model_ref]

        summary = await _call_domain_child(
            client,
            domain="doris_semantic",
            child_tool="get_semantic_model_summary",
            arguments={"model_ref": model_ref, "include_bindings": True},
            manifest_version=manifest_version,
        )
        assert summary["data"]["model_ref"] == model_ref
        assert summary["data"]["datasets"][0]["binding"] == {
            "catalog": "internal",
            "database": doris_sandbox.settings.database,
            "object": doris_sandbox.table,
            "kind": "table",
        }

        context = await _call_domain_child(
            client,
            domain="doris_semantic",
            child_tool="get_semantic_context",
            arguments={
                "model_ref": model_ref,
                "request": {
                    "question": "How many governed orders are available?",
                    "metrics": ["order_count"],
                    "dimensions": ["orders.order_marker"],
                },
            },
            manifest_version=manifest_version,
        )
        assert context["data"]["context"]["metrics"][0]["name"] == "order_count"
        assert context["data"]["execution_boundary"].endswith(
            "Doris Query domain for SQL execution."
        )

        mapping = await _call_domain_child(
            client,
            domain="doris_semantic",
            child_tool="get_semantic_mapping_status",
            arguments={"model_ref": model_ref, "datasource": "orders"},
            manifest_version=manifest_version,
        )
        assert mapping["data"]["mapping_status"] == "resolved"
        assert mapping["data"]["datasets"][0]["visible_fields"] == [
            {
                "name": "order_id",
                "physical_columns": ["id"],
                "physical_types": ["BIGINT"],
            },
            {
                "name": "order_marker",
                "physical_columns": ["marker"],
                "physical_types": ["VARCHAR"],
            },
        ]

    with doris_sandbox.admin_connection.cursor() as cursor:
        cursor.execute(
            f"SELECT COUNT(*) AS row_count FROM {doris_sandbox.qualified_table}"
        )
        rows_after = int(cursor.fetchone()[0])
    assert rows_after == rows_before


@pytest.mark.parametrize("transport", ["http", "stdio"])
async def test_real_doris_metricflow_provider_contract_is_guarded_and_live(
    transport: str,
    tmp_path: Path,
) -> None:
    """Exercise every MetricFlow child and execute compiled SQL on real Doris."""
    model_ref = "sales/commerce@2026.08.05+4f91c2a"
    settings = _real_doris_settings()
    provider_script = tmp_path / "metricflow_provider.py"
    provider_script.write_text(
        """
import json
import sys

request = json.loads(sys.stdin.read())
operation = request["operation"]
arguments = request["arguments"]
responses = {
    "list_models": {
        "items": [{"model_ref": "sales/commerce@2026.08.05+4f91c2a", "revision": "v1"}],
    },
    "get_status": {
        "model_ref": arguments.get("model_ref"),
        "valid": True,
        "dialect": "doris",
    },
    "list_metrics": {
        "items": [{"name": "acceptance_count", "dimensions": ["segment"]}],
    },
    "get_group_bys": {
        "dimensions": ["segment"],
        "entities": [],
    },
    "list_saved_queries": {
        "items": [{"name": "acceptance_saved_query"}],
    },
    "compile_dimension_values": {
        "sql": "SELECT 'enterprise' AS segment",
    },
    "compile_query": {
        "sql": "SELECT @@version_comment AS doris_version",
    },
}
data = responses.get(operation)
if data is None:
    response = {
        "protocol_version": request["protocol_version"],
        "request_id": request["request_id"],
        "ok": False,
        "error": {"reason_code": "METRICFLOW_OPERATION_UNSUPPORTED"},
    }
else:
    response = {
        "protocol_version": request["protocol_version"],
        "request_id": request["request_id"],
        "ok": True,
        "data": data,
    }
sys.stdout.write(json.dumps(response))
""".strip(),
        encoding="utf-8",
    )
    environment = _server_environment(
        settings,
        user=settings.user,
        password=settings.password,
    )
    environment.update(
        {
            "MCP_TOOL_EXPOSURE_MODE": "hierarchical",
            "METRICFLOW_ENABLED": "true",
            "METRICFLOW_PROVIDER_COMMAND_JSON": json.dumps(
                [sys.executable, str(provider_script)]
            ),
            "METRICFLOW_PROJECT_DIRECTORY": str(tmp_path),
        }
    )

    async with _transport_client(
        transport,
        environment,
        read_timeout_seconds=60,
    ) as client:
        manifest = await _discover_domain(client, "doris_semantic")
        children = {child["name"]: child for child in manifest["children"]}
        metricflow_children = {
            name: child
            for name, child in children.items()
            if "metricflow" in name
        }
        assert len(metricflow_children) == 8
        assert all(
            child["availability"]["callable"]
            for child in metricflow_children.values()
        )
        manifest_version = manifest["manifest_version"]

        models = await _call_domain_child(
            client,
            domain="doris_semantic",
            child_tool="list_metricflow_models",
            arguments={},
            manifest_version=manifest_version,
        )
        assert models["data"]["items"][0]["model_ref"] == model_ref

        status = await _call_domain_child(
            client,
            domain="doris_semantic",
            child_tool="get_metricflow_status",
            arguments={"model_ref": model_ref},
            manifest_version=manifest_version,
        )
        assert status["data"]["dialect"] == "doris"

        metrics = await _call_domain_child(
            client,
            domain="doris_semantic",
            child_tool="list_metricflow_metrics",
            arguments={
                "model_ref": model_ref,
                "include_dimensions": True,
                "limit": 20,
            },
            manifest_version=manifest_version,
        )
        assert metrics["data"]["items"][0]["name"] == "acceptance_count"

        group_bys = await _call_domain_child(
            client,
            domain="doris_semantic",
            child_tool="get_metricflow_group_bys",
            arguments={
                "model_ref": model_ref,
                "metrics": ["acceptance_count"],
            },
            manifest_version=manifest_version,
        )
        assert group_bys["data"]["dimensions"] == ["segment"]

        saved_queries = await _call_domain_child(
            client,
            domain="doris_semantic",
            child_tool="list_metricflow_saved_queries",
            arguments={"model_ref": model_ref, "limit": 20},
            manifest_version=manifest_version,
        )
        assert saved_queries["data"]["items"][0]["name"] == (
            "acceptance_saved_query"
        )

        dimension_values = await _call_domain_child(
            client,
            domain="doris_semantic",
            child_tool="get_metricflow_dimension_values",
            arguments={
                "model_ref": model_ref,
                "metrics": ["acceptance_count"],
                "dimension": "segment",
                "limit": 20,
            },
            manifest_version=manifest_version,
        )
        assert dimension_values["data"]["rows"][0]["segment"] == "enterprise"
        assert dimension_values["metadata"]["semantic_provider"] == "metricflow"

        compiled = await _call_domain_child(
            client,
            domain="doris_semantic",
            child_tool="compile_metricflow_query",
            arguments={
                "model_ref": model_ref,
                "request": {"metrics": ["acceptance_count"]},
            },
            manifest_version=manifest_version,
        )
        assert compiled["data"]["sql"].startswith("SELECT")

        executed = await _call_domain_child(
            client,
            domain="doris_semantic",
            child_tool="execute_metricflow_query",
            arguments={
                "model_ref": model_ref,
                "request": {"saved_query": "acceptance_saved_query"},
                "max_rows": 1,
            },
            manifest_version=manifest_version,
        )
        assert "4.0.5-rc01" in executed["data"]["rows"][0]["doris_version"]
        assert executed["metadata"]["semantic_provider"] == "metricflow"
        assert executed["metadata"]["compile_execution_boundary"] == (
            "mcp_query_runtime"
        )


@pytest.mark.skipif(
    os.getenv("DORIS_REAL_HTTP_INTEGRATION") != "1",
    reason="set DORIS_REAL_HTTP_INTEGRATION=1 with independent FE/BE HTTP endpoints",
)
@pytest.mark.parametrize("transport", ["http", "stdio"])
async def test_real_doris_hierarchical_cluster_domain_is_read_only_and_live(
    transport: str,
) -> None:
    settings = _real_doris_settings()
    environment = _server_environment(
        settings,
        user=settings.user,
        password=settings.password,
    )
    environment["MCP_TOOL_EXPOSURE_MODE"] = "hierarchical"
    assert environment.get("DORIS_FE_HTTP_HOST")
    assert environment.get("DORIS_BE_HOSTS")

    async with _transport_client(
        transport,
        environment,
        read_timeout_seconds=60,
    ) as client:
        tools = {
            tool.name: tool
            for tool in (await client.list_tools(cache_mode="bypass")).tools
        }
        assert "doris_catalog" in tools
        assert "doris_cluster" in tools

        catalog_result = await client.call_tool("doris_catalog", {})
        assert catalog_result.is_error is False
        assert isinstance(catalog_result.structured_content, dict)
        assert catalog_result.structured_content["mode"] == "manifest"
        assert catalog_result.structured_content["domain"] == "doris_catalog"

        cluster_result = await client.call_tool("doris_cluster", {})
        assert cluster_result.is_error is False, json.dumps(
            cluster_result.model_dump(by_alias=True, mode="json"),
            ensure_ascii=False,
        )
        assert isinstance(cluster_result.structured_content, dict)
        cluster_manifest = cluster_result.structured_content
        assert cluster_manifest["mode"] == "manifest"
        assert cluster_manifest["domain"] == "doris_cluster"
        children = {
            child["name"]: child
            for child in cluster_manifest["children"]
        }
        assert tuple(children) == CLUSTER_CHILD_NAMES
        manifest_version = cluster_manifest["manifest_version"]

        runtime = await _call_domain_child(
            client,
            domain="doris_cluster",
            child_tool="get_runtime_capabilities",
            arguments={"detail": "full"},
            manifest_version=manifest_version,
        )
        master_fe_version = runtime["data"]["versions"]["master_fe"]
        assert master_fe_version
        patch_certification = runtime["data"]["patch_certification"]
        assert patch_certification["uniform_observed_version"]
        assert patch_certification["status"] in {
            "certified",
            "target_uncertified",
            "outside_target",
        }
        assert patch_certification["target_versions"]
        assert isinstance(patch_certification["certified_versions"], list)

        nodes = await _call_domain_child(
            client,
            domain="doris_cluster",
            child_tool="list_cluster_nodes",
            arguments={"node_types": ["fe", "be"], "include_metrics": False},
            manifest_version=manifest_version,
        )
        assert nodes["data"]["items"]
        assert {"fe", "be"}.issubset(
            {item["node_type"] for item in nodes["data"]["items"]}
        )

        memory = await _call_domain_child(
            client,
            domain="doris_cluster",
            child_tool="get_memory_stats",
            arguments={"detail": "summary"},
            manifest_version=manifest_version,
        )
        assert memory["metadata"]["invented_values"] is False

        compaction_availability = children["get_compaction_status"]["availability"]
        if master_fe_version.startswith("4.0.5"):
            assert compaction_availability["callable"] is True
            assert (
                compaction_availability["active_variant"]
                == "legacy_compaction_summary"
            )
            compaction = await _call_domain_child(
                client,
                domain="doris_cluster",
                child_tool="get_compaction_status",
                arguments={"limit": 20},
                manifest_version=manifest_version,
            )
            assert compaction["data"]["mode"] == "legacy_summary"
            assert compaction["data"]["native_tracker"] is False


@pytest.mark.parametrize("transport", ["http", "stdio"])
async def test_real_doris_hierarchical_pipeline_domain_is_read_only_and_live(
    transport: str,
    doris_sandbox: DorisSandbox,
) -> None:
    environment = _server_environment(
        doris_sandbox.settings,
        user=doris_sandbox.settings.user,
        password=doris_sandbox.settings.password,
    )
    environment["MCP_TOOL_EXPOSURE_MODE"] = "hierarchical"
    with doris_sandbox.admin_connection.cursor() as cursor:
        cursor.execute(
            f"INSERT INTO {doris_sandbox.qualified_table} VALUES (1, %s)",
            (doris_sandbox.marker,),
        )

    async with _transport_client(
        transport,
        environment,
        read_timeout_seconds=60,
    ) as client:
        pipeline_result = await client.call_tool("doris_pipeline", {})
        assert pipeline_result.is_error is False
        assert isinstance(pipeline_result.structured_content, dict)
        manifest = pipeline_result.structured_content
        assert manifest["mode"] == "manifest"
        assert manifest["domain"] == "doris_pipeline"
        children = {child["name"]: child for child in manifest["children"]}
        assert tuple(children) == PIPELINE_CHILD_NAMES
        assert all(child["availability"]["callable"] for child in children.values())
        manifest_version = manifest["manifest_version"]

        ingestion = await _call_domain_child(
            client,
            domain="doris_pipeline",
            child_tool="get_ingestion_status",
            arguments={
                "database": doris_sandbox.settings.database,
                "table": doris_sandbox.table,
                "limit": 20,
            },
            manifest_version=manifest_version,
        )
        assert ingestion["metadata"]["database"] == (
            doris_sandbox.settings.database
        )
        assert ingestion["data"]["truncated"] is False

        diagnosis = await _call_domain_child(
            client,
            domain="doris_pipeline",
            child_tool="diagnose_ingestion",
            arguments={
                "database": doris_sandbox.settings.database,
                "table": doris_sandbox.table,
                "window_minutes": 60,
                "include_dependencies": False,
            },
            manifest_version=manifest_version,
        )
        assert diagnosis["data"]["summary"]["matched_jobs"] >= 0
        assert diagnosis["metadata"]["invented_evidence"] is False

        freshness = await _call_domain_child(
            client,
            domain="doris_pipeline",
            child_tool="monitor_data_freshness",
            arguments={
                "database": doris_sandbox.settings.database,
                "table": doris_sandbox.table,
                "threshold_seconds": 3600,
            },
            manifest_version=manifest_version,
        )
        assert freshness["data"]["status"] in {"fresh", "stale"}
        assert freshness["data"]["method"] == "partition_visible_version"
        assert freshness["metadata"]["invented_evidence"] is False

        materialized_views = await _call_domain_child(
            client,
            domain="doris_pipeline",
            child_tool="get_materialized_view_status",
            arguments={
                "database": doris_sandbox.settings.database,
                "include_refresh_history": True,
            },
            manifest_version=manifest_version,
        )
        assert isinstance(materialized_views["data"]["items"], list)

        dependencies = await _call_domain_child(
            client,
            domain="doris_pipeline",
            child_tool="analyze_data_dependencies",
            arguments={
                "database": doris_sandbox.settings.database,
                "object": doris_sandbox.table,
                "direction": "both",
                "depth": 2,
            },
            manifest_version=manifest_version,
        )
        assert dependencies["metadata"]["invented_evidence"] is False
        assert "unknown_source" not in str(dependencies)

        with doris_sandbox.admin_connection.cursor() as cursor:
            cursor.execute(
                f"SELECT COUNT(*) AS row_count "
                f"FROM {doris_sandbox.qualified_table}"
            )
            row = cursor.fetchone()
        assert row == (1,)


@pytest.mark.parametrize("transport", ["http", "stdio"])
async def test_real_doris_hierarchical_search_domain_is_read_only_and_live(
    transport: str,
    doris_search_sandbox: DorisSearchSandbox,
) -> None:
    environment = _server_environment(
        doris_search_sandbox.settings,
        user=doris_search_sandbox.settings.user,
        password=doris_search_sandbox.settings.password,
    )
    environment["MCP_TOOL_EXPOSURE_MODE"] = "hierarchical"
    with doris_search_sandbox.admin_connection.cursor() as cursor:
        cursor.execute(
            f"SELECT COUNT(*) FROM {doris_search_sandbox.qualified_table}"
        )
        row_count_before = int(cursor.fetchone()[0])

    async with _transport_client(
        transport,
        environment,
        read_timeout_seconds=60,
    ) as client:
        search_result = await client.call_tool("doris_search", {})
        assert search_result.is_error is False
        assert isinstance(search_result.structured_content, dict)
        manifest = search_result.structured_content
        assert manifest["mode"] == "manifest"
        assert manifest["domain"] == "doris_search"
        children = {child["name"]: child for child in manifest["children"]}
        assert tuple(children) == SEARCH_CHILD_NAMES
        assert all(child["availability"]["callable"] for child in children.values())
        manifest_version = manifest["manifest_version"]

        indexes = await _call_domain_child(
            client,
            domain="doris_search",
            child_tool="inspect_search_indexes",
            arguments={
                "database": doris_search_sandbox.settings.database,
                "table": doris_search_sandbox.table,
            },
            manifest_version=manifest_version,
        )
        assert {
            item["index_type"] for item in indexes["data"]["items"]
        } == {"INVERTED", "ANN"}
        assert indexes["data"]["capabilities"]["hybrid"] is True

        analysis = await _call_domain_child(
            client,
            domain="doris_search",
            child_tool="preview_text_analysis",
            arguments={
                "text": "Apache Doris search",
                "analyzer": "english",
            },
            manifest_version=manifest_version,
        )
        terms = [item["term"] for item in analysis["data"]["tokens"]]
        assert {"apache", "doris", "search"} <= set(terms)
        assert "[REDACTED]" not in terms

        text = await _call_domain_child(
            client,
            domain="doris_search",
            child_tool="search_data",
            arguments={
                "database": doris_search_sandbox.settings.database,
                "table": doris_search_sandbox.table,
                "query": "Doris",
                "mode": "text",
                "fields": ["title"],
                "top_k": 5,
                "return_fields": ["id", "title", "category"],
            },
            manifest_version=manifest_version,
        )
        assert text["data"]["rows"][0]["id"] == 1
        assert text["metadata"]["invented_scores"] is False

        vector = await _call_domain_child(
            client,
            domain="doris_search",
            child_tool="search_data",
            arguments={
                "database": doris_search_sandbox.settings.database,
                "table": doris_search_sandbox.table,
                "mode": "vector",
                "vector": [0.1, 0.2, 0.3],
                "vector_field": "embedding",
                "top_k": 2,
                "return_fields": ["id", "title", "category"],
            },
            manifest_version=manifest_version,
        )
        assert vector["data"]["rows"][0]["id"] == 1
        assert vector["metadata"]["vector_metric"] == "l2_distance"

        hybrid_request = {
            "database": doris_search_sandbox.settings.database,
            "table": doris_search_sandbox.table,
            "query": "Doris",
            "mode": "hybrid",
            "fields": ["title"],
            "vector": [0.1, 0.2, 0.3],
            "vector_field": "embedding",
            "top_k": 2,
            "filters": {"category": "database"},
            "return_fields": ["id", "title", "category"],
        }
        hybrid = await _call_domain_child(
            client,
            domain="doris_search",
            child_tool="search_data",
            arguments=hybrid_request,
            manifest_version=manifest_version,
        )
        assert hybrid["data"]["rows"][0]["id"] == 1

        diagnosis = await _call_domain_child(
            client,
            domain="doris_search",
            child_tool="diagnose_search_query",
            arguments={
                "search_request": hybrid_request,
                "include_profile": False,
            },
            manifest_version=manifest_version,
        )
        assert (
            diagnosis["data"]["explain"]["facets"][
                "ann_pushdown_observed"
            ]
            is True
        )
        assert diagnosis["metadata"]["invented_index_hits"] is False

        injected_identifier = await client.call_tool(
            "doris_search",
            {
                "child_tool": "search_data",
                "arguments": {
                    "database": doris_search_sandbox.settings.database,
                    "table": doris_search_sandbox.table,
                    "query": "Doris",
                    "mode": "text",
                    "fields": ["title"],
                    "return_fields": [
                        f"title; DROP TABLE {doris_search_sandbox.table}"
                    ],
                },
                "manifest_version": manifest_version,
            },
        )
        assert injected_identifier.is_error is True

    with doris_search_sandbox.admin_connection.cursor() as cursor:
        cursor.execute(
            f"SELECT COUNT(*) FROM {doris_search_sandbox.qualified_table}"
        )
        row_count_after = int(cursor.fetchone()[0])
    assert row_count_after == row_count_before


@pytest.mark.parametrize("transport", ["http", "stdio"])
async def test_real_doris_hierarchical_governance_domain_is_read_only_and_live(
    transport: str,
    doris_sandbox: DorisSandbox,
) -> None:
    environment = _server_environment(
        doris_sandbox.settings,
        user=doris_sandbox.settings.user,
        password=doris_sandbox.settings.password,
    )
    environment["MCP_TOOL_EXPOSURE_MODE"] = "hierarchical"
    with doris_sandbox.admin_connection.cursor() as cursor:
        cursor.execute(
            f"INSERT INTO {doris_sandbox.qualified_table} VALUES (1, %s)",
            (doris_sandbox.marker,),
        )
        cursor.execute(f"SELECT COUNT(*) FROM {doris_sandbox.qualified_table}")
        row_count_before = int(cursor.fetchone()[0])

    async with _transport_client(
        transport,
        environment,
        read_timeout_seconds=60,
    ) as client:
        governance_result = await client.call_tool("doris_governance", {})
        assert governance_result.is_error is False
        assert isinstance(governance_result.structured_content, dict)
        manifest = governance_result.structured_content
        assert manifest["mode"] == "manifest"
        assert manifest["domain"] == "doris_governance"
        children = {child["name"]: child for child in manifest["children"]}
        assert tuple(children) == GOVERNANCE_CHILD_NAMES
        assert all(child["availability"]["callable"] for child in children.values())
        manifest_version = manifest["manifest_version"]

        columns = await _call_domain_child(
            client,
            domain="doris_governance",
            child_tool="analyze_columns",
            arguments={
                "database": doris_sandbox.settings.database,
                "table": doris_sandbox.table,
                "columns": ["id", "marker"],
                "sample_ratio": 0.1,
            },
            manifest_version=manifest_version,
        )
        assert [item["name"] for item in columns["data"]["columns"]] == [
            "id",
            "marker",
        ]
        assert columns["metadata"]["invented_statistics"] is False

        storage = await _call_domain_child(
            client,
            domain="doris_governance",
            child_tool="analyze_table_storage",
            arguments={
                "database": doris_sandbox.settings.database,
                "table": doris_sandbox.table,
                "include_partitions": True,
                "include_indexes": True,
            },
            manifest_version=manifest_version,
        )
        assert storage["data"]["table"] == doris_sandbox.table
        assert storage["metadata"]["raw_create_table_exposed"] is False

        lineage_status = await _call_domain_child(
            client,
            domain="doris_governance",
            child_tool="get_lineage_capability_status",
            arguments={},
            manifest_version=manifest_version,
        )
        assert lineage_status["data"]["active_path"] in {
            "audit_sql_inference",
            "doris_native_event_store",
        }
        assert lineage_status["metadata"]["invented_lineage_capability"] is False

        lineage = await _call_domain_child(
            client,
            domain="doris_governance",
            child_tool="trace_column_lineage",
            arguments={
                "object": (
                    f"{doris_sandbox.settings.database}.{doris_sandbox.table}"
                ),
                "direction": "both",
                "depth": 2,
                "evidence_mode": "audit",
            },
            manifest_version=manifest_version,
        )
        assert lineage["metadata"]["invented_edges"] is False
        assert "unknown_source" not in str(lineage)

        access = await _call_domain_child(
            client,
            domain="doris_governance",
            child_tool="analyze_data_access_patterns",
            arguments={
                "database": doris_sandbox.settings.database,
                "table": doris_sandbox.table,
                "window_days": 1,
                "group_by": "operation",
            },
            manifest_version=manifest_version,
        )
        assert access["metadata"]["raw_sql_exposed"] is False

        audit = await _call_domain_child(
            client,
            domain="doris_governance",
            child_tool="get_recent_audit_logs",
            arguments={
                "window_minutes": 60,
                "database": doris_sandbox.settings.database,
                "limit": 20,
            },
            manifest_version=manifest_version,
        )
        assert audit["metadata"]["raw_sql_exposed"] is False
        assert audit["metadata"]["client_address_exposed"] is False

        udfs = await _call_domain_child(
            client,
            domain="doris_governance",
            child_tool="list_udfs",
            arguments={"database": doris_sandbox.settings.database},
            manifest_version=manifest_version,
        )
        assert isinstance(udfs["data"]["items"], list)
        assert udfs["metadata"]["code_executed"] is False

        auth = await _call_domain_child(
            client,
            domain="doris_governance",
            child_tool="get_auth_mapping_status",
            arguments={"provider": "ldap", "include_roles": False},
            manifest_version=manifest_version,
        )
        assert auth["data"]["secrets_exposed"] is False
        assert auth["data"]["mapping_rules_exposed"] is False

    with doris_sandbox.admin_connection.cursor() as cursor:
        cursor.execute(f"SELECT COUNT(*) FROM {doris_sandbox.qualified_table}")
        row_count_after = int(cursor.fetchone()[0])
    assert row_count_after == row_count_before


@pytest.mark.parametrize("transport", ["http", "stdio"])
async def test_real_doris_hierarchical_lakehouse_domain_is_read_only_and_live(
    transport: str,
    doris_variant_sandbox: DorisVariantSandbox,
) -> None:
    environment = _server_environment(
        doris_variant_sandbox.settings,
        user=doris_variant_sandbox.settings.user,
        password=doris_variant_sandbox.settings.password,
    )
    environment["MCP_TOOL_EXPOSURE_MODE"] = "hierarchical"
    with doris_variant_sandbox.admin_connection.cursor() as cursor:
        cursor.execute(
            f"SELECT COUNT(*) FROM {doris_variant_sandbox.qualified_table}"
        )
        row_count_before = int(cursor.fetchone()[0])

    async with _transport_client(
        transport,
        environment,
        read_timeout_seconds=60,
    ) as client:
        lakehouse_result = await client.call_tool("doris_lakehouse", {})
        assert lakehouse_result.is_error is False
        assert isinstance(lakehouse_result.structured_content, dict)
        manifest = lakehouse_result.structured_content
        assert manifest["mode"] == "manifest"
        assert manifest["domain"] == "doris_lakehouse"
        children = {child["name"]: child for child in manifest["children"]}
        assert tuple(children) == LAKEHOUSE_CHILD_NAMES
        assert all(
            child["availability"]["callable"]
            for child in children.values()
        )
        manifest_version = manifest["manifest_version"]

        variant = await _call_domain_child(
            client,
            domain="doris_lakehouse",
            child_tool="inspect_variant_column",
            arguments={
                "database": doris_variant_sandbox.settings.database,
                "table": doris_variant_sandbox.table,
                "column": "payload",
                "path": "$.profile.age",
                "sample_rows": 10,
            },
            manifest_version=manifest_version,
        )
        assert variant["data"]["shape_sample"]["rows_observed"] == 2
        assert variant["data"]["shape_sample"]["paths"] == [
            {
                "path": "$.profile.age",
                "types": [{"type": "BIGINT", "rows": 2}],
                "rows_observed": 2,
                "presence_ratio": 1.0,
            }
        ]
        assert (
            variant["data"]["advanced_capabilities"][
                "storage_v3_supported"
            ]
            is False
        )
        assert variant["metadata"]["sampled_values_returned"] is False
        assert doris_variant_sandbox.marker not in json.dumps(
            variant,
            ensure_ascii=False,
        )

        internal_catalog = await client.call_tool(
            "doris_lakehouse",
            {
                "child_tool": "inspect_external_catalog",
                "arguments": {"catalog": "internal"},
                "manifest_version": manifest_version,
            },
        )
        assert internal_catalog.is_error is True
        assert doris_variant_sandbox.marker not in json.dumps(
            internal_catalog.model_dump(by_alias=True, mode="json"),
            ensure_ascii=False,
        )

    with doris_variant_sandbox.admin_connection.cursor() as cursor:
        cursor.execute(
            f"SELECT COUNT(*) FROM {doris_variant_sandbox.qualified_table}"
        )
        row_count_after = int(cursor.fetchone()[0])
    assert row_count_after == row_count_before


@pytest.mark.skipif(
    os.getenv("DORIS_REAL_HTTP_INTEGRATION") != "1",
    reason="set DORIS_REAL_HTTP_INTEGRATION=1 with independent FE/BE HTTP endpoints",
)
@pytest.mark.parametrize("transport", ["http", "stdio"])
async def test_real_doris_configured_monitoring_http_endpoints_and_recovery(
    transport: str,
    doris_sandbox: DorisSandbox,
) -> None:
    environment = _server_environment(
        doris_sandbox.settings,
        user=doris_sandbox.settings.user,
        password=doris_sandbox.settings.password,
    )
    assert environment.get("DORIS_FE_HTTP_HOST")
    assert environment.get("DORIS_FE_HTTP_PORT")
    assert environment.get("DORIS_BE_HOSTS")
    assert environment.get("DORIS_BE_WEBSERVER_PORT")

    async with _transport_client(transport, environment) as client:
        cluster_manifest = await _discover_domain(client, "doris_cluster")
        metrics = await _call_domain_child(
            client,
            domain="doris_cluster",
            child_tool="get_monitoring_metrics",
            arguments={},
            manifest_version=cluster_manifest["manifest_version"],
        )
        nodes = metrics["data"]["nodes"]
        fe_nodes = [node for node in nodes if node["role"] == "fe"]
        be_nodes = [node for node in nodes if node["role"] == "be"]
        assert len(fe_nodes) == 1
        assert fe_nodes[0]["host"] == environment["DORIS_FE_HTTP_HOST"]
        assert fe_nodes[0]["host"] != doris_sandbox.settings.host
        assert be_nodes
        assert all(node["host"] for node in be_nodes)

        recovered_result, recovered_payload = await _exec_query(
            client,
            "SELECT 1 AS recovered",
        )
        assert recovered_result.is_error is False
        assert recovered_payload["status"] == "success"
        assert recovered_payload["data"]["rows"][0]["recovered"] == 1
