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

import pytest

from doris_mcp_server.result_limits import ResultLimits
from doris_mcp_server.utils.adbc_query_tools import DorisADBCQueryTools


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
            ),
        ),
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
    cursor = _StreamingCursor(
        [(1, "one"), (2, "two"), (3, "three")]
    )
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
    cursor = _StreamingCursor(
        [(1, "x" * 180), (2, "y" * 180)]
    )
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
    assert result["error"] == (
        "max_rows exceeds the configured maximum of 50"
    )
