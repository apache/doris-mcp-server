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

"""Production evidence contracts for the formal Cluster runtime."""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any

import pytest

from doris_mcp_server.utils.cluster_runtime import (
    ClusterRuntimeFailure,
    DorisClusterRuntime,
)


class _ConnectionManager:
    def __init__(
        self,
        rows: dict[str, list[dict[str, Any]]] | None = None,
        failures: dict[str, Exception] | None = None,
    ) -> None:
        self.rows = rows or {}
        self.failures = failures or {}
        self.calls: list[str] = []
        self.params: list[Mapping[str, Any] | tuple[Any, ...] | None] = []

    @asynccontextmanager
    async def get_connection_context_for_auth_context(
        self,
        _session_id: str,
        _auth_context: Any,
    ):
        manager = self

        class _Connection:
            async def execute(
                self,
                sql: str,
                params: Mapping[str, Any] | tuple[Any, ...] | None = None,
                **_kwargs: Any,
            ) -> SimpleNamespace:
                manager.calls.append(sql)
                manager.params.append(params)
                if sql in manager.failures:
                    raise manager.failures[sql]
                return SimpleNamespace(data=manager.rows.get(sql, []))

        yield _Connection()


class _MonitoringTools:
    def __init__(self, response: dict[str, Any]) -> None:
        self.response = response
        self.calls: list[dict[str, Any]] = []

    async def get_monitoring_metrics(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        return self.response


def _metrics_response() -> dict[str, Any]:
    return {
        "success": True,
        "timestamp": "2026-07-31T00:00:00Z",
        "data": {
            "fe": {
                "success": True,
                "node_info": {"host": "fe-1"},
                "metrics": {"doris_fe_query_total": 7},
                "raw_metrics": {
                    "doris_fe_query_total": 7,
                    "doris_fe_tablet_max_compaction_score": 3,
                },
            },
            "be": [
                {
                    "success": True,
                    "node_info": {
                        "backend_id": "1",
                        "host": "be-1",
                    },
                    "metrics": {
                        "memory_allocated_bytes": 1024,
                    },
                    "raw_metrics": {
                        "doris_be_memory_allocated_bytes": 1024,
                        "doris_be_memory_jemalloc_active_bytes": 2048,
                        "doris_be_file_cache_hits_ratio": 0.75,
                        "doris_be_tablet_base_max_compaction_score": 4,
                    },
                }
            ],
        },
    }


def _runtime(
    *,
    rows: dict[str, list[dict[str, Any]]] | None = None,
    failures: dict[str, Exception] | None = None,
    metrics: dict[str, Any] | None = None,
) -> tuple[DorisClusterRuntime, _ConnectionManager, _MonitoringTools]:
    manager = _ConnectionManager(rows, failures)
    monitoring = _MonitoringTools(metrics or _metrics_response())
    return (
        DorisClusterRuntime(manager, monitoring),  # type: ignore[arg-type]
        manager,
        monitoring,  # type: ignore[return-value]
    )


@pytest.mark.asyncio
async def test_list_cluster_nodes_normalizes_real_fe_and_be_rows() -> None:
    runtime, manager, _ = _runtime(
        rows={
            "SHOW FRONTENDS": [
                {
                    "Name": "fe-1",
                    "Host": "10.0.0.1",
                    "IsMaster": "true",
                    "Version": "doris-4.0.5-rc01",
                }
            ],
            "SHOW BACKENDS": [
                {
                    "BackendId": 10001,
                    "Host": "10.0.0.2",
                    "Alive": "true",
                    "Version": "doris-4.0.5-rc01",
                }
            ],
            "SHOW BROKER": [],
        }
    )

    result = await runtime.list_cluster_nodes(
        node_types=["fe", "be"],
        include_metrics=False,
    )

    assert result["status"] == "success"
    assert result["data"]["items"] == [
        {
            "node_type": "be",
            "node_id": "10001",
            "host": "10.0.0.2",
            "backend_id": 10001,
            "alive": "true",
            "version": "doris-4.0.5-rc01",
        },
        {
            "node_type": "fe",
            "node_id": "fe-1",
            "host": "10.0.0.1",
            "name": "fe-1",
            "is_master": "true",
            "version": "doris-4.0.5-rc01",
        },
    ]
    assert manager.calls == ["SHOW FRONTENDS", "SHOW BACKENDS"]


@pytest.mark.asyncio
async def test_active_tasks_falls_back_to_read_only_active_queries_view() -> None:
    proc_statement = 'SHOW PROC "/current_queries"'
    view_statement = "SELECT * FROM information_schema.active_queries"
    runtime, manager, _ = _runtime(
        rows={
            view_statement: [
                {
                    "QUERY_ID": "query-1",
                    "STATE": "RUNNING",
                    "COMMAND": "Query",
                }
            ]
        },
        failures={proc_statement: RuntimeError(1105, "access denied")},
    )

    result = await runtime.list_active_tasks(
        task_types=["query"],
        states=None,
        limit=10,
    )

    assert result["status"] == "success"
    assert result["data"]["items"] == [
        {
            "query_id": "query-1",
            "state": "RUNNING",
            "command": "Query",
            "task_type": "query",
        }
    ]
    assert manager.calls == [proc_statement, view_statement]


@pytest.mark.asyncio
async def test_memory_stats_only_returns_observed_metrics() -> None:
    runtime, _, _ = _runtime()

    result = await runtime.get_memory_stats(
        node_ids=["1"],
        detail="top_consumers",
    )

    assert result["metadata"]["invented_values"] is False
    metrics = result["data"]["nodes"][0]["metrics"]
    assert metrics == {
        "doris_be_memory_jemalloc_active_bytes": 2048,
        "doris_be_memory_allocated_bytes": 1024,
    }
    assert "8 GB" not in str(result)
    assert "4.5 GB" not in str(result)


@pytest.mark.asyncio
async def test_cache_status_prefers_supported_system_table() -> None:
    statement = "SELECT * FROM information_schema.file_cache_statistics"
    runtime, manager, monitoring = _runtime(
        rows={
            statement: [
                {
                    "BE_ID": 1,
                    "BE_IP": "be-1",
                    "CACHE_PATH": "/cache",
                    "METRIC_NAME": "hits_ratio",
                    "METRIC_VALUE": 0.9,
                },
                {
                    "BE_ID": 1,
                    "BE_IP": "be-1",
                    "CACHE_PATH": "/cache",
                    "METRIC_NAME": "normal_queue_curr_size",
                    "METRIC_VALUE": 10,
                },
            ]
        }
    )

    result = await runtime.get_cache_status(
        scope=None,
        node_ids=None,
        include_queues=False,
    )

    assert result["data"]["mode"] == "system_table"
    assert [item["metric_name"] for item in result["data"]["items"]] == [
        "hits_ratio"
    ]
    assert manager.calls == [statement]
    assert monitoring.calls == []


@pytest.mark.asyncio
async def test_compaction_falls_back_to_real_metrics_without_task_detail() -> None:
    native = "SELECT * FROM information_schema.doris_be_compaction_tasks"
    runtime, _, _ = _runtime(
        failures={native: RuntimeError(1146, "table does not exist")}
    )

    result = await runtime.get_compaction_status(
        database="analytics",
        table="orders",
        state="running",
        limit=10,
    )

    assert result["status"] == "partial"
    assert result["data"]["mode"] == "legacy_summary"
    assert result["data"]["native_tracker"] is False
    assert "task-level detail" in result["warnings"][0]
    be_node = next(
        node for node in result["data"]["nodes"] if node["role"] == "be"
    )
    assert be_node["metrics"] == {
        "doris_be_tablet_base_max_compaction_score": 4
    }


@pytest.mark.asyncio
async def test_resource_growth_uses_recorded_rows_and_reports_partial_sources() -> None:
    query_sql = (
        "SELECT DATE(`time`) AS bucket, COUNT(*) AS value "
        "FROM internal.__internal_schema.audit_log "
        "WHERE `time` >= DATE_SUB(NOW(), INTERVAL %s DAY) "
        "GROUP BY bucket ORDER BY bucket"
    )
    runtime, manager, _ = _runtime(
        rows={
            query_sql: [
                {"bucket": "2026-07-30", "value": 10},
                {"bucket": "2026-07-31", "value": 15},
            ]
        }
    )

    result = await runtime.analyze_resource_growth(
        resource="query_volume",
        window_days=7,
        granularity="day",
    )

    assert manager.calls == [query_sql]
    assert manager.params == [(7,)]
    assert result["metadata"]["invented_history"] is False
    assert result["data"]["summaries"]["query_volume"] == {
        "point_count": 2,
        "first_value": 10.0,
        "last_value": 15.0,
        "growth_percent": 50.0,
    }
    assert result["evidence"][0]["source"] == (
        "internal.__internal_schema.audit_log"
    )


@pytest.mark.asyncio
async def test_resource_growth_rejects_unknown_resource_before_sql() -> None:
    runtime, manager, _ = _runtime()

    with pytest.raises(ClusterRuntimeFailure) as error:
        await runtime.analyze_resource_growth(
            resource="forecast",
            window_days=7,
            granularity="day",
        )

    assert error.value.reason_code == "CLUSTER_ARGUMENT_INVALID"
    assert manager.calls == []
