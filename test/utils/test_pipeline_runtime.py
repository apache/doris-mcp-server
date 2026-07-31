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

"""Production evidence contracts for the formal Pipeline runtime."""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from datetime import datetime
from types import SimpleNamespace
from typing import Any

import pytest

from doris_mcp_server.utils.pipeline_runtime import (
    DorisPipelineRuntime,
    PipelineRuntimeFailure,
)


class _ConnectionManager:
    def __init__(
        self,
        *,
        rows: dict[str, list[dict[str, Any]]] | None = None,
        failures: dict[str, Exception] | None = None,
    ) -> None:
        self.rows = rows or {}
        self.failures = failures or {}
        self.calls: list[str] = []
        self.params: list[Mapping[str, Any] | tuple[Any, ...] | None] = []
        self.context_count = 0

    @asynccontextmanager
    async def get_connection_context_for_auth_context(
        self,
        _session_id: str,
        _auth_context: Any,
    ) -> AsyncIterator[Any]:
        self.context_count += 1
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


def _runtime(
    *,
    rows: dict[str, list[dict[str, Any]]] | None = None,
    failures: dict[str, Exception] | None = None,
) -> tuple[DorisPipelineRuntime, _ConnectionManager]:
    manager = _ConnectionManager(rows=rows, failures=failures)
    return DorisPipelineRuntime(manager), manager  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_ingestion_status_normalizes_real_rows_and_omits_sensitive_fields() -> None:
    batch_sql = "SHOW LOAD FROM `analytics` LIMIT 20"
    routine_sql = "SHOW ALL ROUTINE LOAD"
    runtime, manager = _runtime(
        rows={
            batch_sql: [
                {
                    "JobId": 101,
                    "Label": "orders_20260731",
                    "State": "FINISHED",
                    "Progress": "100%",
                    "JobDetails": '{"table_name":"orders"}',
                    "URL": "http://fe:8030/api/load?token=secret",
                    "CreateTime": "2026-07-31 01:00:00",
                    "LoadFinishTime": "2026-07-31 01:01:00",
                }
            ],
            routine_sql: [
                {
                    "Id": 202,
                    "Name": "orders_kafka",
                    "DbName": "analytics",
                    "TableName": "orders",
                    "State": "RUNNING",
                    "DataSourceType": "KAFKA",
                    "CurrentTaskNum": 3,
                    "Lag": '{"0": 4}',
                    "Progress": '{"0": "17"}',
                    "ErrorLogUrls": "http://be:8040/error?password=secret",
                },
                {
                    "Id": 203,
                    "Name": "other_db",
                    "DbName": "other",
                    "TableName": "orders",
                    "State": "RUNNING",
                },
            ],
        }
    )

    result = await runtime.get_ingestion_status(
        job_types=["batch_load", "routine_load"],
        database="analytics",
        table="orders",
        states=None,
        limit=10,
    )

    assert result["status"] == "success"
    assert [item["job_type"] for item in result["data"]["items"]] == [
        "batch_load",
        "routine_load",
    ]
    assert result["data"]["items"][1]["lag"] == {"0": 4}
    serialized = str(result)
    assert "ErrorLogUrls" not in serialized
    assert "http://fe:8030" not in serialized
    assert "password=secret" not in serialized
    assert manager.calls == [
        batch_sql,
        "USE `analytics`",
        routine_sql,
    ]
    assert manager.context_count == 2


@pytest.mark.asyncio
async def test_ingestion_status_fails_closed_without_any_evidence_source() -> None:
    sql = "SHOW LOAD FROM `analytics` LIMIT 20"
    runtime, _ = _runtime(
        failures={sql: RuntimeError(1146, "source does not exist")}
    )

    with pytest.raises(
        PipelineRuntimeFailure,
        match="ingestion evidence is unavailable",
    ) as failure:
        await runtime.get_ingestion_status(
            job_types=["batch_load"],
            database="analytics",
            table=None,
            states=None,
            limit=10,
        )

    assert failure.value.reason_code == "PIPELINE_INGESTION_EVIDENCE_UNAVAILABLE"


@pytest.mark.asyncio
async def test_freshness_prefers_recorded_partition_visibility_time() -> None:
    sql = "SHOW PARTITIONS FROM `analytics`.`orders` LIMIT 1000"
    now = datetime.now()
    runtime, _ = _runtime(
        rows={
            sql: [
                {
                    "PartitionName": "p20260731",
                    "VisibleVersion": 12,
                    "VisibleVersionTime": now,
                }
            ]
        }
    )

    result = await runtime.monitor_data_freshness(
        database="analytics",
        table="orders",
        threshold_seconds=60,
        time_column=None,
    )

    assert result["data"]["status"] == "fresh"
    assert result["data"]["method"] == "partition_visible_version"
    assert result["data"]["partitions_observed"] == 1
    assert result["metadata"]["invented_evidence"] is False


@pytest.mark.asyncio
async def test_freshness_rejects_identifier_injection_before_execution() -> None:
    runtime, manager = _runtime()

    with pytest.raises(PipelineRuntimeFailure) as failure:
        await runtime.monitor_data_freshness(
            database="analytics",
            table="orders; DROP TABLE users",
            threshold_seconds=60,
            time_column=None,
        )

    assert failure.value.reason_code == "PIPELINE_ARGUMENT_INVALID"
    assert manager.calls == []


@pytest.mark.asyncio
async def test_materialized_view_status_uses_recorded_jobs_and_refresh_tasks() -> None:
    info_sql = (
        "SELECT Id, Name, JobName, State, SchemaChangeDetail, RefreshState, "
        'RefreshInfo, SyncWithBaseTables FROM mv_infos("database"="analytics") '
        "LIMIT 500"
    )
    job_sql = (
        "SELECT Id, Name, MvId, MvName, MvDatabaseName, ExecuteType, "
        'RecurringStrategy, Status, CreateTime FROM jobs("type"="mv") '
        "WHERE MvDatabaseName = %s LIMIT 500"
    )
    task_sql = (
        "SELECT TaskId, JobId, JobName, MvId, MvName, MvDatabaseName, Status, "
        "ErrorMsg, CreateTime, StartTime, FinishTime, DurationMs, RefreshMode, "
        "NeedRefreshPartitions, CompletedPartitions, Progress, LastQueryId "
        'FROM tasks("type"="mv") WHERE MvDatabaseName = %s '
        "ORDER BY CreateTime DESC LIMIT 500"
    )
    sync_sql = "SHOW ALTER TABLE MATERIALIZED VIEW FROM `analytics`"
    runtime, manager = _runtime(
        rows={
            info_sql: [
                {
                    "Id": 1,
                    "Name": "mv_orders",
                    "JobName": "inner_mtmv_1",
                    "State": "NORMAL",
                    "RefreshState": "SUCCESS",
                    "SyncWithBaseTables": "true",
                }
            ],
            job_sql: [
                {
                    "Id": 11,
                    "Name": "inner_mtmv_1",
                    "MvName": "mv_orders",
                    "MvDatabaseName": "analytics",
                    "Status": "RUNNING",
                }
            ],
            task_sql: [
                {
                    "TaskId": 21,
                    "MvName": "mv_orders",
                    "Status": "SUCCESS",
                    "DurationMs": 45,
                    "LastQueryId": "query-1",
                }
            ],
            sync_sql: [],
        }
    )

    result = await runtime.get_materialized_view_status(
        database="analytics",
        view="mv_orders",
        states=None,
        include_refresh_history=True,
    )

    item = result["data"]["items"][0]
    assert item["view"] == "mv_orders"
    assert item["sync_with_base_tables"] is True
    assert item["latest_refresh"]["task_id"] == 21
    assert item["refresh_history"][0]["duration_ms"] == 45
    assert manager.params[1] == ("analytics",)
    assert manager.params[2] == ("analytics",)
    assert "query_sql" not in str(result).casefold()


@pytest.mark.asyncio
async def test_dependency_graph_uses_only_recorded_edges_without_synthetic_nodes() -> None:
    mv_sql = (
        'SELECT Name, QuerySql FROM mv_infos("database"="analytics") LIMIT 500'
    )
    view_sql = (
        "SELECT TABLE_NAME, VIEW_DEFINITION FROM information_schema.views "
        "WHERE TABLE_SCHEMA = %s LIMIT 500"
    )
    audit_sql = (
        "SELECT stmt, `time` AS observed_at "
        "FROM internal.__internal_schema.audit_log "
        "WHERE `time` >= DATE_SUB(NOW(), INTERVAL 30 DAY) "
        "AND (UPPER(stmt) LIKE '%INSERT%' OR "
        "UPPER(stmt) LIKE '%CREATE%VIEW%') "
        "ORDER BY `time` DESC LIMIT 500"
    )
    runtime, _ = _runtime(
        rows={
            mv_sql: [
                {
                    "Name": "daily_orders",
                    "QuerySql": "SELECT * FROM raw_orders",
                }
            ],
            view_sql: [
                {
                    "TABLE_NAME": "order_view",
                    "VIEW_DEFINITION": "SELECT * FROM analytics.daily_orders",
                }
            ],
            audit_sql: [
                {
                    "stmt": (
                        "INSERT INTO final_orders "
                        "SELECT * FROM analytics.order_view"
                    ),
                    "observed_at": "2026-07-31 02:00:00",
                }
            ],
        }
    )

    result = await runtime.analyze_data_dependencies(
        catalog="internal",
        database="analytics",
        object_name="final_orders",
        direction="upstream",
        depth=5,
    )

    assert result["data"]["nodes"] == [
        "internal.analytics.daily_orders",
        "internal.analytics.final_orders",
        "internal.analytics.order_view",
        "internal.analytics.raw_orders",
    ]
    assert len(result["data"]["edges"]) == 3
    assert "unknown_source" not in str(result)
    assert result["metadata"]["invented_evidence"] is False
