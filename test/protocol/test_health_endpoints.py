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
"""Liveness and readiness regression tests."""

from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from mcp import Client

from doris_mcp_server import __version__
from doris_mcp_server.health import liveness_payload, readiness_payload
from doris_mcp_server.utils.config import DorisConfig
from doris_mcp_server.utils.db import DorisConnectionManager

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _free_tcp_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def _stop_process(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    process.terminate()
    try:
        await asyncio.wait_for(process.wait(), timeout=10)
    except TimeoutError:
        process.kill()
        await process.wait()


async def _wait_for_live(
    process: asyncio.subprocess.Process,
    port: int,
    log_file,
) -> None:
    deadline = time.monotonic() + 15
    async with httpx.AsyncClient(timeout=0.5) as client:
        while time.monotonic() < deadline:
            if process.returncode is not None:
                log_file.seek(0)
                pytest.fail(
                    "HTTP process exited before liveness became available:\n"
                    + log_file.read().decode("utf-8", errors="replace"),
                    pytrace=False,
                )
            try:
                response = await client.get(f"http://127.0.0.1:{port}/live")
                if response.status_code == 200:
                    assert response.json()["status"] == "alive"
                    return
            except httpx.HTTPError:
                pass
            await asyncio.sleep(0.1)
    log_file.seek(0)
    pytest.fail(
        "HTTP process did not expose liveness:\n"
        + log_file.read().decode("utf-8", errors="replace"),
        pytrace=False,
    )


def test_liveness_payload_is_database_independent() -> None:
    assert liveness_payload(
        service="doris-mcp-server",
        version=__version__,
    ) == {
        "status": "alive",
        "service": "doris-mcp-server",
        "version": __version__,
        "checks": {"process": "alive"},
    }


@pytest.mark.asyncio
async def test_readiness_recovers_without_changing_liveness() -> None:
    manager = SimpleNamespace(
        check_readiness=AsyncMock(side_effect=[False, True]),
    )

    unavailable, unavailable_status = await readiness_payload(
        manager,
        service="doris-mcp-server",
        version=__version__,
    )
    recovered, recovered_status = await readiness_payload(
        manager,
        service="doris-mcp-server",
        version=__version__,
    )

    assert unavailable_status == 503
    assert unavailable["status"] == "not_ready"
    assert unavailable["checks"]["doris"] == "not_ready"
    assert recovered_status == 200
    assert recovered["status"] == "ready"
    assert recovered["checks"]["doris"] == "ready"
    assert (
        liveness_payload(
            service="doris-mcp-server",
            version=__version__,
        )["status"]
        == "alive"
    )


@pytest.mark.asyncio
async def test_readiness_has_a_hard_timeout() -> None:
    async def never_finishes(*, timeout_seconds: float) -> bool:
        del timeout_seconds
        await asyncio.sleep(60)
        return True

    manager = SimpleNamespace(check_readiness=never_finishes)
    started = time.monotonic()
    payload, status_code = await readiness_payload(
        manager,
        service="doris-mcp-server",
        version=__version__,
        timeout_seconds=0.01,
    )

    assert time.monotonic() - started < 0.5
    assert status_code == 503
    assert payload["status"] == "not_ready"


@pytest.mark.asyncio
async def test_connection_readiness_uses_a_direct_probe() -> None:
    config = DorisConfig()
    manager = DorisConnectionManager(config)
    manager._test_basic_connectivity = AsyncMock(return_value=None)

    assert await manager.check_readiness(timeout_seconds=60) is True
    manager._test_basic_connectivity.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_connection_readiness_direct_probe_times_out() -> None:
    config = DorisConfig()
    manager = DorisConnectionManager(config)

    async def slow_connectivity() -> None:
        await asyncio.sleep(60)

    manager._test_basic_connectivity = slow_connectivity
    started = time.monotonic()
    assert await manager.check_readiness(timeout_seconds=0.01) is False
    assert time.monotonic() - started < 0.5


@pytest.mark.asyncio
@pytest.mark.parametrize("workers", [1, 2])
async def test_http_process_stays_live_when_doris_is_unavailable(
    workers: int,
) -> None:
    server_port = _free_tcp_port()
    unavailable_doris_port = _free_tcp_port()
    environment = os.environ.copy()
    environment.update(
        {
            "DORIS_HOST": "127.0.0.1",
            "DORIS_PORT": str(unavailable_doris_port),
            "DORIS_USER": "root",
            "DORIS_PASSWORD": "",
            "DORIS_DATABASE": "information_schema",
            "DORIS_CONNECTION_TIMEOUT": "1",
            "ENABLE_TOKEN_AUTH": "false",
            "ENABLE_JWT_AUTH": "false",
            "ENABLE_OAUTH_AUTH": "false",
            "ENABLE_DORIS_OAUTH_AUTH": "false",
            "LOG_LEVEL": "ERROR",
            "PYTHONUNBUFFERED": "1",
        }
    )

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
            str(server_port),
            "--workers",
            str(workers),
            cwd=PROJECT_ROOT,
            env=environment,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        try:
            await _wait_for_live(process, server_port, log_file)
            async with httpx.AsyncClient(timeout=3) as client:
                health = await client.get(f"http://127.0.0.1:{server_port}/health")
                live = await client.get(f"http://127.0.0.1:{server_port}/live")
                started = time.monotonic()
                ready = await client.get(f"http://127.0.0.1:{server_port}/ready")
                readiness_elapsed = time.monotonic() - started

            assert health.status_code == 200
            assert health.json()["status"] == "healthy"
            assert live.status_code == 200
            assert live.json()["status"] == "alive"
            assert ready.status_code == 503
            assert ready.json()["status"] == "not_ready"
            assert readiness_elapsed < 3

            async with Client(
                f"http://127.0.0.1:{server_port}/mcp",
                read_timeout_seconds=10,
            ) as client:
                tools = await client.list_tools(cache_mode="bypass")
                assert tools.tools

            assert process.returncode is None
        finally:
            await _stop_process(process)
