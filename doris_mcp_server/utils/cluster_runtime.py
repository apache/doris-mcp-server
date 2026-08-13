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

"""Strict, evidence-bearing runtime for the read-only Cluster domain."""

from __future__ import annotations

import re
import uuid
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any

from .db import DorisConnectionManager
from .monitoring_tools import DorisMonitoringTools
from .redaction import redact_sensitive_data
from .security import get_current_auth_context

_MAX_ROWS = 1_000
_MAX_METRIC_NAMES = 100
_MAX_METRICS_PER_NODE = 256
_MEMORY_MARKERS = ("memory", "mem_tracker", "memtable", "jemalloc")
_CACHE_MARKERS = ("cache", "file_cache")
_COMPACTION_MARKERS = ("compaction",)
_SNAKE_BOUNDARY = re.compile(r"(?<!^)(?=[A-Z])")
_SAFE_KEY = re.compile(r"[^a-z0-9]+")
_GROWTH_SQL = {
    ("query_volume", "hour"): (
        "SELECT DATE_FORMAT(`time`, '%%Y-%%m-%%dT%%H:00:00') AS bucket, "
        "COUNT(*) AS value "
        "FROM internal.__internal_schema.audit_log "
        "WHERE `time` >= DATE_SUB(NOW(), INTERVAL %s DAY) "
        "GROUP BY bucket ORDER BY bucket"
    ),
    ("query_volume", "day"): (
        "SELECT DATE(`time`) AS bucket, COUNT(*) AS value "
        "FROM internal.__internal_schema.audit_log "
        "WHERE `time` >= DATE_SUB(NOW(), INTERVAL %s DAY) "
        "GROUP BY bucket ORDER BY bucket"
    ),
    ("query_volume", "week"): (
        "SELECT DATE_FORMAT("
        "DATE_SUB(DATE(`time`), INTERVAL WEEKDAY(`time`) DAY), "
        "'%%Y-%%m-%%d') AS bucket, COUNT(*) AS value "
        "FROM internal.__internal_schema.audit_log "
        "WHERE `time` >= DATE_SUB(NOW(), INTERVAL %s DAY) "
        "GROUP BY bucket ORDER BY bucket"
    ),
    ("user_activity", "hour"): (
        "SELECT DATE_FORMAT(`time`, '%%Y-%%m-%%dT%%H:00:00') AS bucket, "
        "COUNT(DISTINCT `user`) AS value "
        "FROM internal.__internal_schema.audit_log "
        "WHERE `time` >= DATE_SUB(NOW(), INTERVAL %s DAY) "
        "GROUP BY bucket ORDER BY bucket"
    ),
    ("user_activity", "day"): (
        "SELECT DATE(`time`) AS bucket, COUNT(DISTINCT `user`) AS value "
        "FROM internal.__internal_schema.audit_log "
        "WHERE `time` >= DATE_SUB(NOW(), INTERVAL %s DAY) "
        "GROUP BY bucket ORDER BY bucket"
    ),
    ("user_activity", "week"): (
        "SELECT DATE_FORMAT("
        "DATE_SUB(DATE(`time`), INTERVAL WEEKDAY(`time`) DAY), "
        "'%%Y-%%m-%%d') AS bucket, COUNT(DISTINCT `user`) AS value "
        "FROM internal.__internal_schema.audit_log "
        "WHERE `time` >= DATE_SUB(NOW(), INTERVAL %s DAY) "
        "GROUP BY bucket ORDER BY bucket"
    ),
    ("storage", "hour"): (
        "SELECT DATE_FORMAT(CREATE_TIME, '%%Y-%%m-%%dT%%H:00:00') AS bucket, "
        "SUM(COALESCE(DATA_LENGTH, 0) + COALESCE(INDEX_LENGTH, 0)) AS value "
        "FROM information_schema.partitions "
        "WHERE CREATE_TIME >= DATE_SUB(NOW(), INTERVAL %s DAY) "
        "GROUP BY bucket ORDER BY bucket"
    ),
    ("storage", "day"): (
        "SELECT DATE(CREATE_TIME) AS bucket, "
        "SUM(COALESCE(DATA_LENGTH, 0) + COALESCE(INDEX_LENGTH, 0)) AS value "
        "FROM information_schema.partitions "
        "WHERE CREATE_TIME >= DATE_SUB(NOW(), INTERVAL %s DAY) "
        "GROUP BY bucket ORDER BY bucket"
    ),
    ("storage", "week"): (
        "SELECT DATE_FORMAT("
        "DATE_SUB(DATE(CREATE_TIME), INTERVAL WEEKDAY(CREATE_TIME) DAY), "
        "'%%Y-%%m-%%d') AS bucket, "
        "SUM(COALESCE(DATA_LENGTH, 0) + COALESCE(INDEX_LENGTH, 0)) AS value "
        "FROM information_schema.partitions "
        "WHERE CREATE_TIME >= DATE_SUB(NOW(), INTERVAL %s DAY) "
        "GROUP BY bucket ORDER BY bucket"
    ),
}


class ClusterRuntimeFailure(RuntimeError):
    """Sanitized Cluster-domain failure with a stable reason code."""

    def __init__(
        self,
        message: str,
        *,
        reason_code: str,
        status_code: int,
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.status_code = status_code
        self.retryable = retryable


class DorisClusterRuntime:
    """Read bounded cluster metadata and monitoring evidence without invention."""

    def __init__(
        self,
        connection_manager: DorisConnectionManager,
        monitoring_tools: DorisMonitoringTools,
    ) -> None:
        self._connection_manager = connection_manager
        self._monitoring_tools = monitoring_tools
        self._session_prefix = f"formal_cluster_{uuid.uuid4().hex[:8]}"

    async def get_cluster_overview(
        self,
        *,
        include: Sequence[str] | None,
    ) -> dict[str, Any]:
        sections = tuple(
            dict.fromkeys(
                include
                or (
                    "nodes",
                    "tasks",
                    "metrics",
                    "memory",
                    "cache",
                    "compaction",
                )
            )
        )
        data: dict[str, Any] = {}
        evidence: list[dict[str, Any]] = []
        warnings: list[str] = []
        operations = {
            "nodes": lambda: self.list_cluster_nodes(
                node_types=None,
                include_metrics=False,
            ),
            "tasks": lambda: self.list_active_tasks(
                task_types=None,
                states=None,
                limit=100,
            ),
            "metrics": lambda: self.get_monitoring_metrics(
                metric_names=None,
                node_ids=None,
                window=None,
            ),
            "memory": lambda: self.get_memory_stats(
                node_ids=None,
                detail="summary",
            ),
            "cache": lambda: self.get_cache_status(
                scope=None,
                node_ids=None,
                include_queues=False,
            ),
            "compaction": lambda: self.get_compaction_status(
                database=None,
                table=None,
                state=None,
                limit=100,
            ),
        }
        for section in sections:
            operation = operations[section]
            try:
                result = await operation()
            except ClusterRuntimeFailure as exc:
                data[section] = {
                    "status": "unavailable",
                    "reason_code": exc.reason_code,
                }
                warnings.append(
                    f"{section} evidence is unavailable ({exc.reason_code})."
                )
                evidence.append(
                    {
                        "section": section,
                        "success": False,
                        "reason_code": exc.reason_code,
                    }
                )
                continue
            data[section] = {
                "status": result["status"],
                "data": result["data"],
            }
            warnings.extend(result["warnings"])
            evidence.append(
                {
                    "section": section,
                    "success": True,
                    "source": result["metadata"].get("source"),
                }
            )
        if not any(item["success"] for item in evidence):
            raise ClusterRuntimeFailure(
                "Doris cluster evidence is unavailable.",
                reason_code="CLUSTER_EVIDENCE_UNAVAILABLE",
                status_code=503,
                retryable=True,
            )
        return _result(
            data,
            source="cluster_composite",
            warnings=warnings,
            evidence=evidence,
            metadata={"sections": list(sections)},
        )

    async def list_cluster_nodes(
        self,
        *,
        node_types: Sequence[str] | None,
        include_metrics: bool,
    ) -> dict[str, Any]:
        requested = set(node_types or ("fe", "be", "broker"))
        statements = {
            "fe": "SHOW FRONTENDS",
            "be": "SHOW BACKENDS",
            "broker": "SHOW BROKER",
        }
        items: list[dict[str, Any]] = []
        warnings: list[str] = []
        successful_sources: list[str] = []
        for node_type in ("fe", "be", "broker"):
            if node_type not in requested:
                continue
            try:
                rows = await self._execute(statements[node_type], max_rows=512)
            except ClusterRuntimeFailure as exc:
                if node_type in {"fe", "be"}:
                    warnings.append(
                        f"{node_type.upper()} metadata is unavailable "
                        f"({exc.reason_code})."
                    )
                continue
            successful_sources.append(statements[node_type])
            items.extend(_node_item(node_type, row) for row in rows)
        if not successful_sources:
            raise ClusterRuntimeFailure(
                "Doris node metadata is unavailable.",
                reason_code="CLUSTER_NODE_METADATA_UNAVAILABLE",
                status_code=503,
                retryable=True,
            )

        metric_nodes: dict[str, dict[str, Any]] = {}
        if include_metrics:
            try:
                monitoring_result = await self.get_monitoring_metrics(
                    metric_names=None,
                    node_ids=None,
                    window=None,
                )
            except ClusterRuntimeFailure as exc:
                warnings.append(f"Node metrics are unavailable ({exc.reason_code}).")
            else:
                for node in monitoring_result["data"].get("nodes", []):
                    for identity in (
                        node.get("node_id"),
                        node.get("host"),
                    ):
                        if identity:
                            metric_nodes[str(identity)] = node.get("metrics", {})
        for item in items:
            node_metrics: dict[str, Any] | None = None
            for identity in (item.get("node_id"), item.get("host")):
                if identity is not None and str(identity) in metric_nodes:
                    node_metrics = metric_nodes[str(identity)]
                    break
            if node_metrics is not None:
                item["metrics"] = node_metrics
        items.sort(
            key=lambda item: (
                str(item.get("node_type", "")),
                str(item.get("node_id", "")),
                str(item.get("host", "")),
            )
        )
        return _collection(
            items,
            source=",".join(successful_sources),
            warnings=warnings,
        )

    async def list_active_tasks(
        self,
        *,
        task_types: Sequence[str] | None,
        states: Sequence[str] | None,
        limit: int | None,
    ) -> dict[str, Any]:
        requested_types = {value.casefold() for value in (task_types or ("query",))}
        max_rows = _bounded_limit(limit, default=100)
        items: list[dict[str, Any]] = []
        warnings: list[str] = []
        sources: list[str] = []

        if "query" in requested_types:
            query_rows: list[Mapping[str, Any]] | None = None
            for statement in (
                'SHOW PROC "/current_queries"',
                "SELECT * FROM information_schema.active_queries",
                "SHOW FULL PROCESSLIST",
            ):
                try:
                    query_rows = await self._execute(
                        statement,
                        max_rows=max_rows + 1,
                    )
                except ClusterRuntimeFailure:
                    continue
                sources.append(statement)
                break
            if query_rows is None:
                warnings.append("Active query tasks are unavailable.")
            else:
                for row in query_rows:
                    item = _normalized_row(row)
                    command = str(item.get("command", "")).casefold()
                    if command == "sleep":
                        continue
                    item["task_type"] = "query"
                    items.append(item)

        if "compaction" in requested_types:
            try:
                rows = await self._execute(
                    "SELECT * FROM information_schema.doris_be_compaction_tasks",
                    max_rows=max_rows + 1,
                )
            except ClusterRuntimeFailure:
                warnings.append(
                    "Compaction task detail is unavailable; use "
                    "get_compaction_status for a summary fallback."
                )
            else:
                sources.append("information_schema.doris_be_compaction_tasks")
                for row in rows:
                    item = _normalized_row(row)
                    item["task_type"] = "compaction"
                    items.append(item)

        unsupported = requested_types - {"query", "compaction"}
        if unsupported:
            warnings.append(
                "No cluster-wide read-only source is available for requested "
                f"task types: {', '.join(sorted(unsupported))}."
            )

        state_filter = {value.casefold() for value in (states or ())}
        if state_filter:
            items = [
                item for item in items if _task_state(item).casefold() in state_filter
            ]
        items.sort(
            key=lambda item: (
                str(item.get("task_type", "")),
                str(
                    item.get("query_id") or item.get("task_id") or item.get("id") or ""
                ),
            )
        )
        truncated = len(items) > max_rows
        items = items[:max_rows]
        if not sources and not items:
            raise ClusterRuntimeFailure(
                "Doris active task metadata is unavailable.",
                reason_code="CLUSTER_TASK_METADATA_UNAVAILABLE",
                status_code=503,
                retryable=True,
            )
        return _collection(
            items,
            source=",".join(sources) or "cluster_task_views",
            warnings=warnings,
            truncated=truncated,
        )

    async def get_monitoring_metrics(
        self,
        *,
        metric_names: Sequence[str] | None,
        node_ids: Sequence[str] | None,
        window: str | None,
    ) -> dict[str, Any]:
        requested_names = tuple(dict.fromkeys(metric_names or ()))
        if len(requested_names) > _MAX_METRIC_NAMES:
            raise _argument_failure("At most 100 metric names may be requested.")
        raw = await self._monitoring_tools.get_monitoring_metrics(
            role="all",
            monitor_type="all",
            priority="all" if requested_names else "p0",
            info_only=False,
            include_raw_metrics=bool(requested_names),
            format_type="prometheus",
        )
        if raw.get("success") is False:
            raise ClusterRuntimeFailure(
                "Doris monitoring metrics are unavailable.",
                reason_code="CLUSTER_METRICS_UNAVAILABLE",
                status_code=503,
                retryable=True,
            )
        nodes, warnings = _monitoring_nodes(
            raw,
            metric_names=requested_names,
            node_ids=node_ids,
        )
        if not nodes:
            raise ClusterRuntimeFailure(
                "No readable Doris monitoring endpoint returned metrics.",
                reason_code="CLUSTER_METRICS_UNAVAILABLE",
                status_code=503,
                retryable=True,
            )
        if window:
            warnings.append(
                "The Doris metrics endpoint returns a point-in-time snapshot; "
                "the requested window was not synthesized."
            )
        return _result(
            {"nodes": nodes},
            source="doris_http_metrics",
            warnings=warnings,
            metadata={
                "snapshot_at": raw.get("timestamp"),
                "requested_metric_names": list(requested_names),
            },
        )

    async def get_memory_stats(
        self,
        *,
        node_ids: Sequence[str] | None,
        detail: str | None,
    ) -> dict[str, Any]:
        nodes, warnings = await self._metric_family(
            markers=_MEMORY_MARKERS,
            node_ids=node_ids,
        )
        if not nodes:
            raise ClusterRuntimeFailure(
                "No real Doris memory metrics were observed.",
                reason_code="MEMORY_METRICS_UNAVAILABLE",
                status_code=503,
                retryable=True,
            )
        effective_detail = detail or "summary"
        if effective_detail == "top_consumers":
            for node in nodes:
                metrics = node["metrics"]
                node["metrics"] = dict(
                    sorted(
                        metrics.items(),
                        key=lambda item: _metric_total(item[1]),
                        reverse=True,
                    )[:20]
                )
        return _result(
            {"detail": effective_detail, "nodes": nodes},
            source="doris_be_metrics",
            warnings=warnings,
            metadata={"invented_values": False},
        )

    async def get_cache_status(
        self,
        *,
        scope: str | None,
        node_ids: Sequence[str] | None,
        include_queues: bool,
    ) -> dict[str, Any]:
        warnings: list[str] = []
        try:
            rows = await self._execute(
                "SELECT * FROM information_schema.file_cache_statistics",
                max_rows=_MAX_ROWS,
            )
        except ClusterRuntimeFailure as exc:
            warnings.append(
                "File-cache system table is unavailable; using BE metrics "
                f"({exc.reason_code})."
            )
        else:
            items = [_normalized_row(row) for row in rows]
            if node_ids:
                allowed = {str(value) for value in node_ids}
                items = [
                    item
                    for item in items
                    if str(item.get("be_id", "")) in allowed
                    or str(item.get("be_ip", "")) in allowed
                ]
            if scope:
                scope_folded = scope.casefold()
                items = [
                    item
                    for item in items
                    if scope_folded
                    in " ".join(str(value) for value in item.values()).casefold()
                ]
            if not include_queues:
                items = [
                    item
                    for item in items
                    if "queue" not in str(item.get("metric_name", "")).casefold()
                ]
            return _result(
                {"mode": "system_table", "items": items},
                source="information_schema.file_cache_statistics",
                warnings=warnings,
                metadata={"row_count": len(items)},
            )

        nodes, metric_warnings = await self._metric_family(
            markers=_CACHE_MARKERS,
            node_ids=node_ids,
        )
        warnings.extend(metric_warnings)
        if not include_queues:
            for node in nodes:
                node["metrics"] = {
                    name: value
                    for name, value in node["metrics"].items()
                    if "queue" not in name.casefold()
                }
        if scope:
            scope_folded = scope.casefold()
            for node in nodes:
                node["metrics"] = {
                    name: value
                    for name, value in node["metrics"].items()
                    if scope_folded in name.casefold()
                }
        if not any(node["metrics"] for node in nodes):
            raise ClusterRuntimeFailure(
                "No real Doris cache metrics were observed.",
                reason_code="CACHE_METRICS_UNAVAILABLE",
                status_code=503,
                retryable=True,
            )
        return _result(
            {"mode": "metrics", "nodes": nodes},
            source="doris_be_metrics",
            warnings=warnings,
        )

    async def get_compaction_status(
        self,
        *,
        database: str | None,
        table: str | None,
        state: str | None,
        limit: int | None,
    ) -> dict[str, Any]:
        max_rows = _bounded_limit(limit, default=100)
        try:
            rows = await self._execute(
                "SELECT * FROM information_schema.doris_be_compaction_tasks",
                max_rows=max_rows + 1,
            )
        except ClusterRuntimeFailure as exc:
            native_failure = exc
        else:
            items = [_normalized_row(row) for row in rows]
            items = _filter_rows(
                items,
                database=database,
                table=table,
                state=state,
            )
            truncated = len(items) > max_rows
            return _result(
                {
                    "mode": "native_task_tracker",
                    "items": items[:max_rows],
                    "truncated": truncated,
                },
                source="information_schema.doris_be_compaction_tasks",
                metadata={"native_tracker": True},
            )

        nodes, warnings = await self._metric_family(
            markers=_COMPACTION_MARKERS,
            node_ids=None,
        )
        if not any(node["metrics"] for node in nodes):
            raise ClusterRuntimeFailure(
                "Doris compaction evidence is unavailable.",
                reason_code=native_failure.reason_code,
                status_code=native_failure.status_code,
                retryable=native_failure.retryable,
            )
        warnings.insert(
            0,
            "Native CompactionTaskTracker is unavailable; returning aggregate "
            "metrics without database, table, state, or task-level detail.",
        )
        return _result(
            {
                "mode": "legacy_summary",
                "nodes": nodes,
                "native_tracker": False,
            },
            source="doris_metrics_compaction_summary",
            warnings=warnings,
            metadata={"native_tracker": False},
        )

    async def get_workload_group_status(
        self,
        *,
        name: str | None,
        include_usage: bool,
    ) -> dict[str, Any]:
        rows = await self._execute("SHOW WORKLOAD GROUPS", max_rows=_MAX_ROWS)
        items = [_normalized_row(row) for row in rows]
        if name:
            items = [
                item
                for item in items
                if str(item.get("name", "")).casefold() == name.casefold()
            ]
        if not include_usage:
            usage_markers = (
                "current_",
                "running_",
                "waiting_",
                "queue_",
                "usage",
            )
            items = [
                {
                    key: value
                    for key, value in item.items()
                    if not key.startswith(usage_markers)
                }
                for item in items
            ]
        return _result(
            {"items": items},
            source="SHOW WORKLOAD GROUPS",
            metadata={"row_count": len(items)},
        )

    async def get_compute_group_status(
        self,
        *,
        name: str | None,
        include_nodes: bool,
        include_usage: bool,
    ) -> dict[str, Any]:
        rows = await self._execute("SHOW COMPUTE GROUPS", max_rows=_MAX_ROWS)
        items = [_normalized_row(row) for row in rows]
        if name:
            items = [
                item
                for item in items
                if str(
                    item.get("name") or item.get("compute_group_name") or ""
                ).casefold()
                == name.casefold()
            ]
        if not include_nodes:
            for item in items:
                for key in tuple(item):
                    if "node" in key or "backend" in key:
                        item.pop(key, None)
        if not include_usage:
            for item in items:
                for key in tuple(item):
                    if any(
                        marker in key
                        for marker in ("usage", "cpu", "memory", "running", "queue")
                    ):
                        item.pop(key, None)
        return _result(
            {"items": items},
            source="SHOW COMPUTE GROUPS",
            metadata={"row_count": len(items)},
        )

    async def analyze_resource_growth(
        self,
        *,
        resource: str | None,
        window_days: int | None,
        granularity: str | None,
    ) -> dict[str, Any]:
        days = _bounded_limit(window_days, default=30, maximum=3650)
        bucket = granularity or "day"
        requested = (
            (resource,) if resource else ("storage", "query_volume", "user_activity")
        )
        series: dict[str, list[dict[str, Any]]] = {}
        evidence: list[dict[str, Any]] = []
        warnings: list[str] = []
        for resource_name in requested:
            sql, params = _growth_sql(resource_name, days, bucket)
            try:
                rows = await self._execute(
                    sql,
                    params=params,
                    max_rows=_MAX_ROWS,
                )
            except ClusterRuntimeFailure as exc:
                warnings.append(
                    f"{resource_name} history is unavailable ({exc.reason_code})."
                )
                evidence.append(
                    {
                        "resource": resource_name,
                        "success": False,
                        "reason_code": exc.reason_code,
                    }
                )
                continue
            points = [
                {
                    "bucket": _row_lookup(row, "bucket"),
                    "value": _number(_row_lookup(row, "value")),
                }
                for row in rows
                if _row_lookup(row, "bucket") is not None
            ]
            if len(points) < 2:
                warnings.append(
                    f"{resource_name} history has fewer than two recorded "
                    "time buckets."
                )
                evidence.append(
                    {
                        "resource": resource_name,
                        "success": False,
                        "reason_code": "RESOURCE_HISTORY_INSUFFICIENT",
                        "points": len(points),
                    }
                )
                continue
            series[resource_name] = points
            evidence.append(
                {
                    "resource": resource_name,
                    "success": True,
                    "source": _growth_source(resource_name),
                    "points": len(points),
                }
            )
            if resource_name == "storage":
                warnings.append(
                    "Storage growth uses partition creation evidence inside the "
                    "window, not synthesized historical cluster snapshots."
                )
        if not series:
            raise ClusterRuntimeFailure(
                "Recorded Doris resource history is unavailable.",
                reason_code="RESOURCE_HISTORY_UNAVAILABLE",
                status_code=503,
                retryable=True,
            )
        summaries = {name: _growth_summary(points) for name, points in series.items()}
        return _result(
            {
                "window_days": days,
                "granularity": bucket,
                "series": series,
                "summaries": summaries,
            },
            source="recorded_doris_metadata",
            warnings=warnings,
            evidence=evidence,
            metadata={"invented_history": False},
        )

    async def _metric_family(
        self,
        *,
        markers: Sequence[str],
        node_ids: Sequence[str] | None,
    ) -> tuple[list[dict[str, Any]], list[str]]:
        raw = await self._monitoring_tools.get_monitoring_metrics(
            role="be",
            monitor_type="all",
            priority="all",
            info_only=False,
            include_raw_metrics=True,
            format_type="prometheus",
        )
        if raw.get("success") is False:
            return [], ["BE monitoring metrics are unavailable."]
        nodes, warnings = _monitoring_nodes(
            raw,
            metric_names=None,
            node_ids=node_ids,
            markers=markers,
        )
        return nodes, warnings

    async def _execute(
        self,
        sql: str,
        *,
        params: Mapping[str, Any] | tuple[Any, ...] | None = None,
        max_rows: int,
    ) -> list[Mapping[str, Any]]:
        auth_context = get_current_auth_context()
        session_id = f"{self._session_prefix}:{uuid.uuid4().hex[:8]}"
        try:
            async with (
                self._connection_manager.get_connection_context_for_auth_context(
                    session_id,
                    auth_context,
                ) as connection
            ):
                result = await connection.execute(
                    sql,
                    params=params,
                    auth_context=auth_context,
                    mask_result=False,
                    max_rows=max_rows,
                    max_bytes=2 * 1024 * 1024,
                )
        except Exception as exc:
            raise _classify_failure(exc) from exc
        rows: list[Mapping[str, Any]] = [
            row for row in (result.data or ()) if isinstance(row, Mapping)
        ]
        return rows[:max_rows]


def _result(
    data: Mapping[str, Any],
    *,
    source: str,
    warnings: Sequence[str] = (),
    metadata: Mapping[str, Any] | None = None,
    evidence: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    unique_warnings = list(dict.fromkeys(str(item) for item in warnings))
    response: dict[str, Any] = {
        "status": "partial" if unique_warnings else "success",
        "data": redact_sensitive_data(dict(data)),
        "warnings": unique_warnings,
        "metadata": {
            "source": source,
            **dict(metadata or {}),
        },
    }
    if evidence is not None:
        response["evidence"] = [redact_sensitive_data(dict(item)) for item in evidence]
    return response


def _collection(
    items: Sequence[Mapping[str, Any]],
    *,
    source: str,
    warnings: Sequence[str] = (),
    truncated: bool = False,
) -> dict[str, Any]:
    return _result(
        {
            "items": [dict(item) for item in items],
            "next_cursor": None,
            "truncated": truncated,
        },
        source=source,
        warnings=warnings,
        metadata={"returned_items": len(items)},
    )


def _node_item(node_type: str, row: Mapping[str, Any]) -> dict[str, Any]:
    normalized = _normalized_row(row)
    node_id = next(
        (
            normalized.get(key)
            for key in (
                "backend_id",
                "frontend_id",
                "broker_id",
                "name",
                "host",
            )
            if normalized.get(key) not in (None, "")
        ),
        None,
    )
    host = next(
        (
            normalized.get(key)
            for key in ("host", "ip", "host_name", "hostname")
            if normalized.get(key) not in (None, "")
        ),
        None,
    )
    return {
        "node_type": node_type,
        "node_id": None if node_id is None else str(node_id),
        "host": None if host is None else str(host),
        **normalized,
    }


def _normalized_row(row: Mapping[str, Any]) -> dict[str, Any]:
    return {_normalize_key(str(key)): _safe_value(value) for key, value in row.items()}


def _normalize_key(value: str) -> str:
    snake = (
        value.casefold()
        if value.upper() == value
        else _SNAKE_BOUNDARY.sub("_", value).casefold()
    )
    return _SAFE_KEY.sub("_", snake).strip("_")


def _safe_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _monitoring_nodes(
    raw: Mapping[str, Any],
    *,
    metric_names: Sequence[str] | None,
    node_ids: Sequence[str] | None,
    markers: Sequence[str] | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    data = raw.get("data")
    if not isinstance(data, Mapping):
        return [], ["Monitoring response did not contain metric data."]
    allowed_nodes = {str(value) for value in (node_ids or ())}
    requested_names = set(metric_names or ())
    nodes: list[dict[str, Any]] = []
    warnings: list[str] = []
    be_data = data.get("be")
    be_candidates = be_data if isinstance(be_data, list) else []
    role_values: tuple[tuple[str, list[Any]], ...] = (
        ("fe", [data.get("fe")]),
        ("be", be_candidates),
    )
    for role, candidates in role_values:
        for candidate in candidates:
            if not isinstance(candidate, Mapping):
                continue
            if candidate.get("success") is False:
                warnings.append(f"{role.upper()} metrics endpoint was unavailable.")
                continue
            node_info = candidate.get("node_info")
            node_info = node_info if isinstance(node_info, Mapping) else {}
            node_id = (
                node_info.get("backend_id")
                or node_info.get("name")
                or node_info.get("host")
                or role
            )
            host = node_info.get("host")
            if (
                allowed_nodes
                and not {
                    str(node_id),
                    str(host),
                }
                & allowed_nodes
            ):
                continue
            metrics = candidate.get("raw_metrics")
            if not isinstance(metrics, Mapping):
                metrics = candidate.get("metrics")
            if not isinstance(metrics, Mapping):
                metrics = {}
            selected: dict[str, Any] = {}
            for name, value in metrics.items():
                metric_name = str(name)
                if requested_names and metric_name not in requested_names:
                    continue
                if markers and not any(
                    marker in metric_name.casefold() for marker in markers
                ):
                    continue
                selected[metric_name] = _safe_value(value)
                if len(selected) >= _MAX_METRICS_PER_NODE:
                    warnings.append(
                        f"{role.upper()} metric output was truncated to "
                        f"{_MAX_METRICS_PER_NODE} names per node."
                    )
                    break
            nodes.append(
                {
                    "role": role,
                    "node_id": str(node_id),
                    "host": None if host is None else str(host),
                    "metrics": selected,
                }
            )
    return nodes, list(dict.fromkeys(warnings))


def _metric_total(value: Any) -> float:
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, list):
        return sum(
            _metric_total(item.get("value"))
            for item in value
            if isinstance(item, Mapping)
        )
    return 0.0


def _task_state(item: Mapping[str, Any]) -> str:
    return str(
        item.get("query_status")
        or item.get("state")
        or item.get("status")
        or item.get("command")
        or ""
    )


def _filter_rows(
    rows: Sequence[dict[str, Any]],
    *,
    database: str | None,
    table: str | None,
    state: str | None,
) -> list[dict[str, Any]]:
    filters = tuple(value.casefold() for value in (database, table, state) if value)
    if not filters:
        return list(rows)
    return [
        row
        for row in rows
        if all(
            expected in " ".join(str(value) for value in row.values()).casefold()
            for expected in filters
        )
    ]


def _growth_sql(
    resource: str,
    days: int,
    granularity: str,
) -> tuple[str, tuple[int]]:
    try:
        return _GROWTH_SQL[(resource, granularity)], (days,)
    except KeyError:
        if resource not in {"storage", "query_volume", "user_activity"}:
            raise _argument_failure(
                "resource must be storage, query_volume, or user_activity."
            ) from None
        raise _argument_failure("granularity must be hour, day, or week.") from None


def _growth_source(resource: str) -> str:
    if resource == "storage":
        return "information_schema.partitions"
    return "internal.__internal_schema.audit_log"


def _growth_summary(points: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    values = [
        float(value)
        for point in points
        if isinstance((value := point.get("value")), int | float)
    ]
    if not values:
        return {"point_count": 0, "growth_percent": None}
    growth = None
    if len(values) > 1 and values[0] != 0:
        growth = round((values[-1] - values[0]) / values[0] * 100, 4)
    return {
        "point_count": len(values),
        "first_value": values[0],
        "last_value": values[-1],
        "growth_percent": growth,
    }


def _row_lookup(row: Mapping[str, Any], name: str) -> Any:
    expected = name.casefold()
    return next(
        (value for key, value in row.items() if str(key).casefold() == expected),
        None,
    )


def _number(value: Any) -> int | float | None:
    if value is None:
        return None
    if isinstance(value, int | float):
        return value
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return int(parsed) if parsed.is_integer() else parsed


def _bounded_limit(
    value: int | None,
    *,
    default: int,
    maximum: int = _MAX_ROWS,
) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise _argument_failure("limit must be a positive integer.")
    return min(value, maximum)


def _argument_failure(message: str) -> ClusterRuntimeFailure:
    return ClusterRuntimeFailure(
        message,
        reason_code="CLUSTER_ARGUMENT_INVALID",
        status_code=400,
    )


def _classify_failure(exc: Exception) -> ClusterRuntimeFailure:
    if isinstance(exc, ClusterRuntimeFailure):
        return exc
    numeric_code = next(
        (value for value in getattr(exc, "args", ()) if isinstance(value, int)),
        None,
    )
    message = str(exc).casefold()
    if numeric_code in {1044, 1045, 1142, 1227} or any(
        marker in message
        for marker in ("access denied", "permission denied", "privilege")
    ):
        return ClusterRuntimeFailure(
            "Doris denied access to cluster metadata.",
            reason_code="CLUSTER_PERMISSION_DENIED",
            status_code=403,
        )
    if numeric_code in {1064, 1109, 1146} or any(
        marker in message
        for marker in (
            "doesn't exist",
            "does not exist",
            "not supported",
            "unsupported",
            "unknown table",
        )
    ):
        return ClusterRuntimeFailure(
            "The requested Doris cluster evidence source is unsupported.",
            reason_code="CLUSTER_SOURCE_UNSUPPORTED",
            status_code=501,
        )
    if isinstance(exc, TimeoutError | ConnectionError | OSError):
        return ClusterRuntimeFailure(
            "Doris cluster evidence is temporarily unavailable.",
            reason_code="CLUSTER_BACKEND_UNAVAILABLE",
            status_code=503,
            retryable=True,
        )
    return ClusterRuntimeFailure(
        "Doris cluster metadata execution failed.",
        reason_code="CLUSTER_EXECUTION_FAILED",
        status_code=502,
    )


__all__ = ["ClusterRuntimeFailure", "DorisClusterRuntime"]
