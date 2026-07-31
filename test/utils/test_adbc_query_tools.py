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
"""Bounded streaming and cancellation tests for Arrow Flight SQL queries."""

from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from doris_mcp_server.result_limits import ResultLimits
from doris_mcp_server.utils.adbc_query_tools import DorisADBCQueryTools
from doris_mcp_server.utils.security import (
    AuthContext,
    reset_auth_context,
    set_current_auth_context,
)


def _manager() -> SimpleNamespace:
    return SimpleNamespace(
        config=SimpleNamespace(
            security=SimpleNamespace(max_result_rows=50),
            performance=SimpleNamespace(
                max_result_bytes=4096,
                query_timeout=20,
            ),
            adbc=SimpleNamespace(
                default_max_rows=20,
                default_timeout=10,
                default_return_format="dict",
                connection_timeout=30,
            ),
            database=SimpleNamespace(
                be_hosts=["be-1"],
                user="root",
                password="",
            ),
        ),
        host="fe-1",
        security_manager=None,
    )


class _StreamingCursor:
    description = (("id", "BIGINT"), ("payload", "VARCHAR"))

    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self._rows = rows
        self._offset = 0
        self.executed_sql: str | None = None
        self.fetch_sizes: list[int] = []
        self.closed = False

    def execute(self, sql: str) -> None:
        self.executed_sql = sql

    def fetchmany(self, size: int) -> list[tuple[Any, ...]]:
        self.fetch_sizes.append(size)
        batch = self._rows[self._offset : self._offset + size]
        self._offset += len(batch)
        return batch

    def close(self) -> None:
        self.closed = True

    def adbc_cancel(self) -> None:
        raise AssertionError("completed queries must not be cancelled")


class _BlockingCursor:
    description: tuple[()] = ()

    def __init__(self) -> None:
        self.started = threading.Event()
        self.cancelled = threading.Event()
        self.closed = False
        self.cancel_calls = 0

    def execute(self, sql: str) -> None:
        del sql
        self.started.set()
        self.cancelled.wait(timeout=5)

    def fetchmany(self, size: int) -> list[tuple[Any, ...]]:
        del size
        return []

    def adbc_cancel(self) -> None:
        self.cancel_calls += 1
        self.cancelled.set()

    def close(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_adbc_streams_to_row_limit_without_fetchall() -> None:
    cursor = _StreamingCursor([(1, "one"), (2, "two"), (3, "three")])
    tools = DorisADBCQueryTools(_manager())
    tools.adbc_client = SimpleNamespace(cursor=lambda: cursor)

    result = await tools._execute_query_with_adbc(
        "SELECT id, payload FROM bounded",
        ResultLimits(max_rows=2, max_bytes=4096, timeout_seconds=5),
        "dict",
    )

    assert result["success"] is True
    assert result["result"]["data"] == [
        {"id": 1, "payload": "one"},
        {"id": 2, "payload": "two"},
    ]
    assert result["truncated"] is True
    assert result["truncation_reason"] == "max_rows"
    assert result["result_bytes"] <= 4096
    assert cursor.closed is True
    assert cursor.fetch_sizes == [3]


@pytest.mark.asyncio
async def test_adbc_streams_to_byte_limit() -> None:
    cursor = _StreamingCursor([(1, "x" * 180), (2, "y" * 180)])
    tools = DorisADBCQueryTools(_manager())
    tools.adbc_client = SimpleNamespace(cursor=lambda: cursor)

    result = await tools._execute_query_with_adbc(
        "SELECT id, payload FROM bounded",
        ResultLimits(max_rows=10, max_bytes=256, timeout_seconds=5),
        "pandas",
    )

    assert result["success"] is True
    assert result["result"]["num_rows"] == 1
    assert result["truncated"] is True
    assert result["truncation_reason"] == "max_bytes"
    assert result["result_bytes"] <= 256
    assert cursor.closed is True


@pytest.mark.asyncio
async def test_adbc_cancellation_calls_driver_and_reaps_worker() -> None:
    cursor = _BlockingCursor()
    tools = DorisADBCQueryTools(_manager())
    tools.adbc_client = SimpleNamespace(cursor=lambda: cursor)

    task = asyncio.create_task(
        tools._execute_query_with_adbc(
            "SELECT SLEEP(5)",
            ResultLimits(max_rows=1, max_bytes=256, timeout_seconds=10),
            "dict",
        )
    )
    assert await asyncio.to_thread(cursor.started.wait, 1)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert cursor.cancel_calls == 1
    assert cursor.closed is True


@pytest.mark.asyncio
async def test_adbc_rejects_limit_escalation_before_network_checks() -> None:
    tools = DorisADBCQueryTools(_manager())

    result = await tools.exec_adbc_query(
        "SELECT 1",
        max_rows=51,
        max_bytes=1024,
        timeout=5,
    )

    assert result["success"] is False
    assert result["error_type"] == "invalid_result_limits"
    assert result["error"] == ("max_rows exceeds the configured maximum of 50")


@pytest.mark.asyncio
async def test_adbc_fails_closed_for_doris_oauth_before_probing() -> None:
    tools = DorisADBCQueryTools(_manager())
    tools._check_arrow_flight_ports = MagicMock(  # type: ignore[method-assign]
        side_effect=AssertionError("ADBC endpoint probe must not run")
    )
    context_token = set_current_auth_context(
        AuthContext(
            auth_method="doris_oauth",
            doris_user="analyst",
        )
    )
    try:
        result = await tools.exec_adbc_query("SELECT 1")
    finally:
        reset_auth_context(context_token)

    assert result["success"] is False
    assert result["error_type"] == "token_bound_adbc_unsupported"
    tools._check_arrow_flight_ports.assert_not_called()


@pytest.mark.asyncio
async def test_adbc_capability_probe_uses_bounded_socket_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tools = DorisADBCQueryTools(_manager())
    connectivity = MagicMock(return_value=True)
    tools._check_port_connectivity = connectivity  # type: ignore[method-assign]
    monkeypatch.setenv("FE_ARROW_FLIGHT_SQL_PORT", "8070")
    monkeypatch.setenv("BE_ARROW_FLIGHT_SQL_PORT", "8060")

    result = await tools._check_arrow_flight_ports(
        connectivity_timeout=0.25,
    )

    assert result["success"] is True
    assert connectivity.call_args_list == [
        (("fe-1", 8070, 0.25),),
        (("be-1", 8060, 0.25),),
    ]
