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
"""Tests for non-escalating query result and timeout budgets."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from doris_mcp_server.result_limits import (
    ABSOLUTE_MAX_QUERY_TIMEOUT_SECONDS,
    ABSOLUTE_MAX_RESULT_BYTES,
    ABSOLUTE_MAX_RESULT_ROWS,
    ResultLimitError,
    configured_result_limits,
    resolve_result_limits,
)
from doris_mcp_server.tools.tool_catalog import build_tool_registry
from doris_mcp_server.tools.tools_manager import DorisToolsManager
from doris_mcp_server.utils.config import DorisConfig
from doris_mcp_server.utils.query_executor import DorisQueryExecutor


def _config(
    *,
    rows: int = 50,
    default_rows: int = 10,
    result_bytes: int = 4096,
    timeout: int = 20,
) -> SimpleNamespace:
    return SimpleNamespace(
        security=SimpleNamespace(
            max_result_rows=rows,
            enable_security_check=False,
        ),
        performance=SimpleNamespace(
            default_result_rows=default_rows,
            max_result_bytes=result_bytes,
            query_timeout=timeout,
            max_cache_size=10,
            cache_ttl=10,
            max_concurrent_queries=2,
        ),
        adbc=SimpleNamespace(
            default_max_rows=rows,
            default_timeout=timeout,
            default_return_format="dict",
        ),
    )


def test_configured_limits_cannot_exceed_absolute_hard_caps() -> None:
    limits = configured_result_limits(
        _config(
            rows=ABSOLUTE_MAX_RESULT_ROWS + 1,
            result_bytes=ABSOLUTE_MAX_RESULT_BYTES + 1,
            timeout=ABSOLUTE_MAX_QUERY_TIMEOUT_SECONDS + 1,
        )
    )

    assert limits.max_rows == ABSOLUTE_MAX_RESULT_ROWS
    assert limits.max_bytes == ABSOLUTE_MAX_RESULT_BYTES
    assert limits.timeout_seconds == ABSOLUTE_MAX_QUERY_TIMEOUT_SECONDS


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("max_rows", True, "max_rows must be an integer"),
        ("max_rows", 51, "max_rows exceeds the configured maximum of 50"),
        ("max_bytes", 255, "max_bytes must be at least 256"),
        ("max_bytes", 4097, "max_bytes exceeds the configured maximum of 4096"),
        ("timeout_seconds", 21, "timeout exceeds the configured maximum of 20"),
    ],
)
def test_request_cannot_raise_deployment_ceiling(
    field: str,
    value: object,
    message: str,
) -> None:
    kwargs = {
        "max_rows": 10,
        "max_bytes": 1024,
        "timeout_seconds": 10,
    }
    kwargs[field] = value

    with pytest.raises(ResultLimitError, match=message):
        resolve_result_limits(_config(), **kwargs)


def test_doris_config_validation_rejects_values_above_hard_caps() -> None:
    config = DorisConfig()
    config.security.max_result_rows = ABSOLUTE_MAX_RESULT_ROWS + 1
    config.performance.max_result_bytes = ABSOLUTE_MAX_RESULT_BYTES + 1
    config.performance.query_timeout = ABSOLUTE_MAX_QUERY_TIMEOUT_SECONDS + 1

    errors = config.validate()

    assert f"Maximum result rows must not exceed {ABSOLUTE_MAX_RESULT_ROWS}" in errors
    assert (
        "Maximum result bytes must be in the range "
        f"256-{ABSOLUTE_MAX_RESULT_BYTES}"
    ) in errors
    assert (
        "Query timeout must not exceed "
        f"{ABSOLUTE_MAX_QUERY_TIMEOUT_SECONDS} seconds"
    ) in errors


def test_exec_query_schema_advertises_effective_ceilings() -> None:
    connection_manager = Mock()
    connection_manager.config = _config()
    manager = DorisToolsManager(connection_manager)
    tool = build_tool_registry(
        manager,
        connection_manager.config,
    ).resolve("exec_query").tool
    assert tool is not None
    properties = tool.input_schema["properties"]

    assert properties["max_rows"]["maximum"] == 50
    assert properties["max_rows"]["default"] == 10
    assert properties["max_bytes"]["maximum"] == 4096
    assert properties["timeout"]["maximum"] == 20


def test_config_validation_rejects_default_rows_above_ceiling() -> None:
    config = DorisConfig()
    config.security.max_result_rows = 50
    config.performance.default_result_rows = 51

    assert (
        "Default result rows must not exceed the configured maximum result rows (50)"
        in config.validate()
    )


def test_environment_configures_default_rows_independently_from_ceiling(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("MAX_RESULT_ROWS", "500")
    monkeypatch.setenv("DEFAULT_RESULT_ROWS", "321")
    monkeypatch.setenv("ADBC_DEFAULT_MAX_ROWS", "500")

    config = DorisConfig.from_env(str(tmp_path / "missing.env"))

    assert config.security.max_result_rows == 500
    assert config.performance.default_result_rows == 321
    assert config.validate() == []


@pytest.mark.asyncio
async def test_exec_query_uses_configured_default_rows_when_argument_is_omitted() -> None:
    connection_manager = Mock()
    connection_manager.config = _config(default_rows=17)
    manager = DorisToolsManager(connection_manager)
    manager.query_runtime.execute_query = AsyncMock(
        return_value={
            "status": "success",
            "data": {
                "columns": [],
                "rows": [],
                "row_count": 0,
                "truncated": False,
            },
            "warnings": [],
            "metadata": {},
        }
    )

    result = await manager._exec_query_tool({"sql": "SELECT 1"})

    assert result["status"] == "success"
    assert manager.query_runtime._resolve_limits(
        max_rows=None,
        timeout_ms=None,
    ).max_rows == 17
    manager.query_runtime.execute_query.assert_awaited_once_with(
        sql="SELECT 1",
        catalog=None,
        database=None,
        parameters=None,
        max_rows=None,
        timeout_ms=None,
    )


def test_exec_adbc_query_schema_advertises_effective_ceilings() -> None:
    connection_manager = Mock()
    connection_manager.config = _config()
    manager = DorisToolsManager(connection_manager)
    tool = build_tool_registry(
        manager,
        connection_manager.config,
    ).resolve("exec_adbc_query").tool
    assert tool is not None
    properties = tool.input_schema["properties"]

    assert properties["max_rows"]["maximum"] == 50
    assert properties["max_bytes"]["maximum"] == 4096
    assert properties["timeout"]["maximum"] == 20


@pytest.mark.asyncio
async def test_executor_returns_typed_error_before_database_dispatch() -> None:
    connection_manager = Mock()
    connection_manager.config = _config()
    connection_manager.execute_query = Mock()
    executor = DorisQueryExecutor(connection_manager)

    result = await executor.execute_sql_for_mcp(
        "SELECT 1",
        limit=51,
        max_bytes=1024,
        timeout=10,
    )

    assert result == {
        "success": False,
        "error": "max_rows exceeds the configured maximum of 50",
        "error_type": "invalid_result_limits",
        "data": None,
    }
    connection_manager.execute_query.assert_not_called()
