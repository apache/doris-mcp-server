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

"""MetricFlow consumer, compile, and guarded Doris execution tests."""

from __future__ import annotations

import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, Mock

import pytest

from doris_mcp_server.semantic.metricflow import (
    METRICFLOW_PROVIDER_PROTOCOL,
    MetricFlowProviderFailure,
    MetricFlowSemanticRuntime,
    MetricFlowSidecarProvider,
)
from doris_mcp_server.semantic.runtime import SemanticRuntimeFailure
from doris_mcp_server.utils.config import DorisConfig
from doris_mcp_server.utils.query_runtime import QueryRuntimeFailure


class _Provider:
    def __init__(self, responses: Mapping[str, Mapping[str, Any]]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def request(
        self,
        operation: str,
        arguments: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        self.calls.append((operation, dict(arguments)))
        return self.responses[operation]


def _query_runtime() -> Any:
    return type(
        "QueryRuntime",
        (),
        {
            "execute_query": AsyncMock(
                return_value={
                    "status": "success",
                    "data": {"columns": [], "rows": [], "truncated": False},
                    "warnings": [],
                    "metadata": {"source": "doris_query"},
                    "evidence": [],
                }
            )
        },
    )()


@pytest.mark.asyncio
async def test_metricflow_metadata_operations_require_exact_model_refs() -> None:
    provider = _Provider(
        {
            "list_models": {"items": [{"model_ref": "sales/main"}]},
            "get_status": {"valid": True, "dialect": "doris"},
            "list_metrics": {"items": [{"name": "revenue"}]},
            "get_group_bys": {"dimensions": ["metric_time"]},
            "list_saved_queries": {"items": [{"name": "weekly_sales"}]},
        }
    )
    runtime = MetricFlowSemanticRuntime(
        _query_runtime(),
        enabled=True,
        provider=provider,
    )

    models = await runtime.list_models()
    status = await runtime.get_status(model_ref="sales/main")
    metrics = await runtime.list_metrics(
        model_ref="sales/main",
        search="rev",
        include_dimensions=True,
        limit=20,
    )
    group_bys = await runtime.get_group_bys(
        model_ref="sales/main",
        metrics=["revenue"],
    )
    saved = await runtime.list_saved_queries(
        model_ref="sales/main",
        search=None,
        limit=20,
    )

    assert models["data"]["items"] == [{"model_ref": "sales/main"}]
    assert status["data"]["dialect"] == "doris"
    assert metrics["data"]["items"] == [{"name": "revenue"}]
    assert group_bys["data"]["dimensions"] == ["metric_time"]
    assert saved["data"]["items"] == [{"name": "weekly_sales"}]
    assert provider.calls[1] == (
        "get_status",
        {"model_ref": "sales/main"},
    )


@pytest.mark.asyncio
async def test_metricflow_compiles_without_executing_doris_sql() -> None:
    provider = _Provider(
        {
            "compile_query": {
                "sql": "SELECT SUM(amount) AS revenue FROM sales",
                "columns": ["revenue"],
            }
        }
    )
    query_runtime = _query_runtime()
    runtime = MetricFlowSemanticRuntime(
        query_runtime,
        enabled=True,
        provider=provider,
    )

    result = await runtime.compile_query(
        model_ref="sales/main",
        request={"metrics": ["revenue"]},
    )

    assert result["data"]["sql"].startswith("SELECT")
    assert provider.calls == [
        (
            "compile_query",
            {
                "model_ref": "sales/main",
                "request": {"metrics": ["revenue"]},
                "dialect": "doris",
            },
        )
    ]
    query_runtime.execute_query.assert_not_awaited()


@pytest.mark.asyncio
async def test_metricflow_execution_returns_to_guarded_mcp_query_runtime() -> None:
    provider = _Provider(
        {"compile_query": {"sql": "SELECT SUM(amount) AS revenue FROM sales"}}
    )
    query_runtime = _query_runtime()
    runtime = MetricFlowSemanticRuntime(
        query_runtime,
        enabled=True,
        provider=provider,
    )

    result = await runtime.execute_query(
        model_ref="sales/main",
        request={
            "metrics": ["revenue"],
            "order_by": ["-revenue"],
        },
        max_rows=100,
        timeout_ms=5000,
    )

    query_runtime.execute_query.assert_awaited_once_with(
        sql="SELECT SUM(amount) AS revenue FROM sales",
        max_rows=100,
        timeout_ms=5000,
    )
    assert result["metadata"]["semantic_provider"] == "metricflow"
    assert result["metadata"]["semantic_model_ref"] == "sales/main"
    assert result["metadata"]["compile_execution_boundary"] == ("mcp_query_runtime")


@pytest.mark.asyncio
async def test_metricflow_rejects_implicit_models_and_unsafe_compiled_sql() -> None:
    provider = _Provider({"compile_query": {"sql": "DROP TABLE sales"}})
    query_runtime = _query_runtime()
    runtime = MetricFlowSemanticRuntime(
        query_runtime,
        enabled=True,
        provider=provider,
    )

    with pytest.raises(SemanticRuntimeFailure) as model_error:
        await runtime.get_status(model_ref="")
    with pytest.raises(QueryRuntimeFailure) as sql_error:
        await runtime.execute_query(
            model_ref="sales/main",
            request={"metrics": ["revenue"]},
            max_rows=100,
            timeout_ms=5000,
        )

    assert model_error.value.reason_code == "METRICFLOW_MODEL_REF_INVALID"
    assert sql_error.value.reason_code == "QUERY_READ_ONLY_VIOLATION"
    query_runtime.execute_query.assert_not_awaited()


@pytest.mark.asyncio
async def test_metricflow_disabled_and_provider_failures_are_sanitized() -> None:
    disabled = MetricFlowSemanticRuntime(
        _query_runtime(),
        enabled=False,
        provider=None,
    )

    with pytest.raises(SemanticRuntimeFailure) as disabled_error:
        await disabled.list_models()

    assert disabled_error.value.reason_code == "METRICFLOW_DISABLED"
    assert disabled_error.value.status_code == 503


@pytest.mark.asyncio
async def test_metricflow_sidecar_protocol_round_trip(tmp_path: Path) -> None:
    script = tmp_path / "provider.py"
    script.write_text(
        """
import json
import sys

request = json.loads(sys.stdin.read())
response = {
    "protocol_version": request["protocol_version"],
    "request_id": request["request_id"],
    "ok": True,
    "data": {"items": [{"model_ref": "sales/main"}]},
}
sys.stdout.write(json.dumps(response))
""".strip(),
        encoding="utf-8",
    )
    provider = MetricFlowSidecarProvider(
        [sys.executable, str(script)],
        timeout_seconds=5,
    )

    result = await provider.request("list_models", {})

    assert result == {"items": [{"model_ref": "sales/main"}]}


@pytest.mark.asyncio
async def test_metricflow_sidecar_rejects_protocol_mismatch(tmp_path: Path) -> None:
    script = tmp_path / "provider.py"
    script.write_text(
        """
import json
import sys

request = json.loads(sys.stdin.read())
sys.stdout.write(json.dumps({
    "protocol_version": "wrong",
    "request_id": request["request_id"],
    "ok": True,
    "data": {},
}))
""".strip(),
        encoding="utf-8",
    )
    provider = MetricFlowSidecarProvider(
        [sys.executable, str(script)],
        timeout_seconds=5,
    )

    with pytest.raises(MetricFlowProviderFailure) as error:
        await provider.request("get_status", {"model_ref": "sales/main"})

    assert error.value.reason_code == "METRICFLOW_PROVIDER_PROTOCOL_MISMATCH"
    assert METRICFLOW_PROVIDER_PROTOCOL not in str(error.value)


def test_metricflow_and_adbc_are_opt_in_advanced_providers() -> None:
    config = DorisConfig()

    assert config.adbc.enabled is False
    assert config.semantic.metricflow_enabled is False
    assert config.semantic.metricflow_provider_command == []

    config.semantic.metricflow_enabled = True
    assert "Enabled MetricFlow support requires a provider command" in (
        config.validate()
    )


def test_unstructured_mock_config_does_not_enable_metricflow() -> None:
    runtime = MetricFlowSemanticRuntime.from_config(
        _query_runtime(),
        Mock(),
    )

    assert runtime._enabled is False
    assert runtime._provider is None
