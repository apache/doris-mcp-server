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
"""SSRF, timeout, and response-boundary tests for Doris FE/BE HTTP."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, suppress
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from doris_mcp_server.utils import doris_http_client as doris_http_client_module
from doris_mcp_server.utils.analysis_tools import SQLAnalyzer
from doris_mcp_server.utils.config import DorisConfig
from doris_mcp_server.utils.doris_http_client import (
    MAX_RESPONSE_BYTES,
    MAX_TIMEOUT_SECONDS,
    DorisHTTPClient,
    DorisHTTPPolicyError,
    DorisHTTPRequestError,
    DorisHTTPResponseTooLarge,
)
from doris_mcp_server.utils.monitoring_tools import DorisMonitoringTools


def _database_config(
    *,
    host: str,
    fe_http_port: int,
    be_hosts: list[str] | None = None,
    be_webserver_port: int = 8040,
    max_response_bytes: int = 4096,
    connect_timeout: float = 1.0,
    read_timeout: float = 1.0,
    total_timeout: float = 1.0,
) -> SimpleNamespace:
    return SimpleNamespace(
        host=host,
        fe_http_port=fe_http_port,
        be_hosts=be_hosts or [],
        be_webserver_port=be_webserver_port,
        user="root",
        password="",
        http_connect_timeout_seconds=connect_timeout,
        http_read_timeout_seconds=read_timeout,
        http_total_timeout_seconds=total_timeout,
        http_max_response_bytes=max_response_bytes,
    )


def _manager(database_config: SimpleNamespace) -> SimpleNamespace:
    return SimpleNamespace(
        config=SimpleNamespace(database=database_config),
        get_connection=AsyncMock(
            side_effect=AssertionError("HTTP monitoring must not discover SQL nodes")
        ),
    )


@asynccontextmanager
async def _http_server(
    *,
    status: int = 200,
    body: bytes = b"",
    headers: dict[str, str] | None = None,
    delay_seconds: float = 0,
):
    response_headers = {
        "Content-Length": str(len(body)),
        "Connection": "close",
        **(headers or {}),
    }

    async def handler(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            await reader.readuntil(b"\r\n\r\n")
            if delay_seconds:
                await asyncio.sleep(delay_seconds)
            reason = "OK" if status == 200 else "Found"
            head = (
                f"HTTP/1.1 {status} {reason}\r\n"
                + "".join(
                    f"{key}: {value}\r\n" for key, value in response_headers.items()
                )
                + "\r\n"
            ).encode()
            writer.write(head + body)
            await writer.drain()
        except (BrokenPipeError, ConnectionResetError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    try:
        port = int(server.sockets[0].getsockname()[1])
        yield port
    finally:
        server.close()
        await server.wait_closed()


def _http_client(
    host: str,
    port: int,
    *,
    max_response_bytes: int = 4096,
    connect_timeout: float = 1,
    read_timeout: float = 1,
    total_timeout: float = 1,
) -> DorisHTTPClient:
    return DorisHTTPClient(
        user="root",
        password="",
        allowed_endpoints={"fe": {(host, port)}, "be": set()},
        connect_timeout_seconds=connect_timeout,
        read_timeout_seconds=read_timeout,
        total_timeout_seconds=total_timeout,
        max_response_bytes=max_response_bytes,
    )


@pytest.mark.parametrize(
    "host",
    [
        "169.254.169.254",
        "169.254.170.2",
        "100.100.100.200",
        "fd00:ec2::254",
        "::ffff:100.100.100.200",
        "metadata.google.internal",
    ],
)
async def test_configured_metadata_and_link_local_endpoints_are_rejected(
    host: str,
) -> None:
    client = _http_client(host, 80)
    with pytest.raises(DorisHTTPPolicyError, match="prohibited"):
        await client.get(role="fe", host=host, port=80, path="/metrics")


async def test_unconfigured_endpoint_is_rejected_before_network_access() -> None:
    client = _http_client("127.0.0.1", 8030)
    with pytest.raises(DorisHTTPPolicyError, match="explicitly configured"):
        await client.get(
            role="fe",
            host="127.0.0.2",
            port=8030,
            path="/metrics",
        )


async def test_hostname_resolving_to_link_local_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_loop = SimpleNamespace(
        getaddrinfo=AsyncMock(
            return_value=[
                (
                    2,
                    1,
                    6,
                    "",
                    ("169.254.169.254", 8030),
                )
            ]
        )
    )
    monkeypatch.setattr(
        doris_http_client_module.asyncio,
        "get_running_loop",
        lambda: fake_loop,
    )
    client = _http_client("doris.internal", 8030)
    with pytest.raises(DorisHTTPPolicyError, match="prohibited"):
        await client._resolve_addresses("doris.internal", 8030)
    fake_loop.getaddrinfo.assert_awaited_once()


async def test_redirects_are_not_followed() -> None:
    async with _http_server(
        status=302,
        headers={"Location": "http://169.254.169.254/latest/meta-data"},
    ) as port:
        response = await _http_client("127.0.0.1", port).get(
            role="fe",
            host="127.0.0.1",
            port=port,
            path="/metrics",
        )
    assert response.status == 302
    assert response.body == b""


async def test_response_content_length_is_bounded_before_body_read() -> None:
    async with _http_server(body=b"x" * 128) as port:
        with pytest.raises(DorisHTTPResponseTooLarge):
            await _http_client(
                "127.0.0.1",
                port,
                max_response_bytes=32,
            ).get(
                role="fe",
                host="127.0.0.1",
                port=port,
                path="/metrics",
            )


async def test_read_and_total_timeouts_are_enforced() -> None:
    async with _http_server(body=b"ok", delay_seconds=0.2) as port:
        with pytest.raises(DorisHTTPRequestError, match="timed out"):
            await _http_client(
                "127.0.0.1",
                port,
                connect_timeout=0.05,
                read_timeout=0.05,
                total_timeout=0.05,
            ).get(
                role="fe",
                host="127.0.0.1",
                port=port,
                path="/metrics",
            )


async def test_monitoring_does_not_discover_be_http_nodes_from_sql() -> None:
    manager = _manager(
        _database_config(
            host="127.0.0.1",
            fe_http_port=8030,
            be_hosts=[],
        )
    )
    tools = DorisMonitoringTools(manager)
    assert await tools.get_be_nodes() == []
    manager.get_connection.assert_not_awaited()

    results = await tools._get_be_metrics("all", "p0", "prometheus", False)
    assert results == [
        {
            "success": False,
            "error": ("BE HTTP metrics require explicit DORIS_BE_HOSTS configuration"),
            "error_type": "unconfigured_endpoint",
        }
    ]
    manager.get_connection.assert_not_awaited()


async def test_monitoring_rejects_configured_metadata_without_network() -> None:
    manager = _manager(
        _database_config(
            host="169.254.169.254",
            fe_http_port=80,
        )
    )
    result = await DorisMonitoringTools(manager)._get_fe_metrics(
        "all",
        "p0",
        "prometheus",
        False,
    )
    assert result["success"] is False
    assert result["error_type"] == "prohibited_endpoint"


async def test_monitoring_fetches_configured_loopback_metrics() -> None:
    metrics = b"doris_fe_query_total 7\n"
    async with _http_server(
        body=metrics,
        headers={"Content-Type": "text/plain"},
    ) as port:
        manager = _manager(
            _database_config(
                host="127.0.0.1",
                fe_http_port=port,
            )
        )
        result = await DorisMonitoringTools(manager).get_monitoring_metrics(
            role="fe",
            priority="all",
            include_raw_metrics=True,
        )
    assert result["success"] is True
    assert result["data"]["fe"]["success"] is True
    assert result["data"]["fe"]["metrics"]["doris_fe_query_total"] == 7


async def test_analysis_fe_http_path_uses_same_policy() -> None:
    manager = _manager(
        _database_config(
            host="metadata.google.internal",
            fe_http_port=80,
        )
    )
    analyzer = SQLAnalyzer(manager)
    assert await analyzer._get_query_id_by_trace_id("trace-id") is None
    result = await analyzer.get_table_data_size(db_name="db", table_name="table")
    assert result["success"] is False
    assert "prohibited" in result["error"].lower()


def test_http_safety_configuration_loads_and_has_runtime_hard_caps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DORIS_HTTP_CONNECT_TIMEOUT_SECONDS", "2")
    monkeypatch.setenv("DORIS_HTTP_READ_TIMEOUT_SECONDS", "4")
    monkeypatch.setenv("DORIS_HTTP_TOTAL_TIMEOUT_SECONDS", "8")
    monkeypatch.setenv("DORIS_HTTP_MAX_RESPONSE_BYTES", "8192")
    config = DorisConfig.from_env()
    assert config.database.http_connect_timeout_seconds == 2
    assert config.database.http_read_timeout_seconds == 4
    assert config.database.http_total_timeout_seconds == 8
    assert config.database.http_max_response_bytes == 8192
    assert not [error for error in config.validate() if error.startswith("Doris HTTP")]

    database_config = _database_config(
        host="127.0.0.1",
        fe_http_port=8030,
        connect_timeout=999,
        read_timeout=999,
        total_timeout=999,
        max_response_bytes=MAX_RESPONSE_BYTES * 2,
    )
    client = DorisHTTPClient.from_database_config(database_config)
    assert client.connect_timeout_seconds == MAX_TIMEOUT_SECONDS
    assert client.read_timeout_seconds == MAX_TIMEOUT_SECONDS
    assert client.total_timeout_seconds == MAX_TIMEOUT_SECONDS
    assert client.max_response_bytes == MAX_RESPONSE_BYTES
