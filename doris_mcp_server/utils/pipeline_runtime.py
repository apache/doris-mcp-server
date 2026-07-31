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

"""Strict, evidence-bearing runtime for the read-only Pipeline domain."""

from __future__ import annotations

import json
import re
import uuid
from collections import deque
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

import sqlparse
from sqlparse import tokens as sql_tokens

from .db import DorisConnectionManager
from .redaction import redact_sensitive_data
from .security import get_current_auth_context
from .sql_security_utils import (
    SQLSecurityError,
    build_table_reference,
    quote_identifier,
    validate_identifier,
)

_MAX_BYTES = 2 * 1024 * 1024
_MAX_LIMIT = 200
_MAX_SOURCE_ROWS = 500
_MAX_PARTITIONS = 1_000
_MAX_DEPENDENCY_DEPTH = 5
_MAX_DEPENDENCY_EDGES = 500
_DEFAULT_FRESHNESS_THRESHOLD_SECONDS = 86_400
_DEFAULT_DIAGNOSIS_WINDOW_MINUTES = 60
_DEFAULT_DEPENDENCY_WINDOW_DAYS = 30
_JOB_TYPES = frozenset(
    {
        "batch_load",
        "stream_load",
        "routine_load",
        "insert_job",
        "continuous_load",
    }
)
_REFERENCE_IDENTIFIER = (
    r"(?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*)"
    r"(?:\s*\.\s*(?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*)){0,2}"
)
_SOURCE_REFERENCE = re.compile(
    rf"\b(?:FROM|JOIN)\s+({_REFERENCE_IDENTIFIER})",
    re.IGNORECASE,
)
_WRITE_TARGET = re.compile(
    rf"\b(?:INSERT\s+INTO|CREATE\s+(?:MATERIALIZED\s+)?VIEW|"
    rf"CREATE\s+TABLE)\s+({_REFERENCE_IDENTIFIER})",
    re.IGNORECASE,
)
_CTE_NAME = re.compile(
    r"(?:\bWITH|,)\s*(`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*)\s+AS\s*\(",
    re.IGNORECASE,
)
_ERROR_STATES = frozenset(
    {
        "cancelled",
        "canceled",
        "failed",
        "fail",
        "paused",
        "stopped",
        "error",
    }
)
_RUNNING_STATES = frozenset(
    {
        "pending",
        "etl",
        "loading",
        "running",
        "need_schedule",
        "waiting_txn",
    }
)
_SUCCESS_STATES = frozenset({"finished", "success", "visible", "succeeded"})


class PipelineRuntimeFailure(RuntimeError):
    """Sanitized Pipeline-domain failure with a stable reason code."""

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


class DorisPipelineRuntime:
    """Read bounded ingestion, freshness, MV, and dependency evidence."""

    def __init__(self, connection_manager: DorisConnectionManager) -> None:
        self._connection_manager = connection_manager
        self._session_prefix = f"formal_pipeline_{uuid.uuid4().hex[:8]}"

    async def get_ingestion_status(
        self,
        *,
        job_types: Sequence[str] | None,
        database: str | None,
        table: str | None,
        states: Sequence[str] | None,
        limit: int | None,
    ) -> dict[str, Any]:
        selected_types = _job_types(job_types)
        selected_states = _normalized_filter(states)
        result_limit = _bounded_int(limit, default=100, minimum=1, maximum=_MAX_LIMIT)
        database_name = await self._resolve_database(database)
        table_name = _optional_identifier(table, "table name")
        fetch_limit = min(max(result_limit * 2, result_limit), _MAX_SOURCE_ROWS)

        items: list[dict[str, Any]] = []
        warnings: list[str] = []
        evidence: list[dict[str, Any]] = []
        possibly_truncated = False

        async def read_source(
            source: str,
            statement: str,
            normalizer: Any,
            *,
            database_context: str | None = None,
        ) -> None:
            nonlocal possibly_truncated
            try:
                rows = await self._execute(
                    statement,
                    max_rows=fetch_limit,
                    database_context=database_context,
                )
            except PipelineRuntimeFailure as exc:
                warnings.append(f"{source} evidence is unavailable ({exc.reason_code}).")
                evidence.append(
                    {
                        "source": source,
                        "success": False,
                        "reason_code": exc.reason_code,
                    }
                )
                return
            normalized_items = [
                item
                for row in rows
                if (item := normalizer(row)) is not None
            ]
            items.extend(normalized_items)
            possibly_truncated = possibly_truncated or len(rows) >= fetch_limit
            evidence.append(
                {
                    "source": source,
                    "success": True,
                    "rows_observed": len(rows),
                }
            )

        quoted_database = quote_identifier(database_name, "database name")
        if "batch_load" in selected_types:
            await read_source(
                "SHOW LOAD",
                f"SHOW LOAD FROM {quoted_database} LIMIT {fetch_limit}",
                lambda row: _batch_load_item(row, database_name),
            )
        if "stream_load" in selected_types:
            await read_source(
                "SHOW STREAM LOAD",
                f"SHOW STREAM LOAD FROM {quoted_database} LIMIT {fetch_limit}",
                _stream_load_item,
            )
        if "routine_load" in selected_types:
            await read_source(
                "SHOW ALL ROUTINE LOAD",
                "SHOW ALL ROUTINE LOAD",
                _routine_load_item,
                database_context=database_name,
            )
        if {"insert_job", "continuous_load"} & selected_types:
            try:
                rows = await self._execute(
                    'SELECT * FROM jobs("type"="insert") '
                    "ORDER BY CreateTime DESC LIMIT %s",
                    params=(fetch_limit,),
                    max_rows=fetch_limit,
                )
            except PipelineRuntimeFailure as exc:
                warnings.append(
                    "Insert/continuous job evidence is unavailable "
                    f"({exc.reason_code})."
                )
                evidence.append(
                    {
                        "source": 'jobs("type"="insert")',
                        "success": False,
                        "reason_code": exc.reason_code,
                    }
                )
            else:
                for row in rows:
                    item = _insert_job_item(row, database_name)
                    if item["job_type"] in selected_types:
                        items.append(item)
                possibly_truncated = possibly_truncated or len(rows) >= fetch_limit
                evidence.append(
                    {
                        "source": 'jobs("type"="insert")',
                        "success": True,
                        "rows_observed": len(rows),
                    }
                )

        if not any(item.get("success") for item in evidence):
            raise PipelineRuntimeFailure(
                "Doris ingestion evidence is unavailable.",
                reason_code="PIPELINE_INGESTION_EVIDENCE_UNAVAILABLE",
                status_code=503,
                retryable=True,
            )

        filtered: list[dict[str, Any]] = []
        omitted_unscoped = 0
        for item in items:
            if selected_states and _state(item) not in selected_states:
                continue
            if table_name is not None:
                observed_table = item.get("table")
                if not isinstance(observed_table, str):
                    omitted_unscoped += 1
                    continue
                if observed_table.casefold() != table_name.casefold():
                    continue
            observed_database = item.get("database")
            if isinstance(observed_database, str) and (
                observed_database.casefold() != database_name.casefold()
            ):
                continue
            filtered.append(item)
        if omitted_unscoped:
            warnings.append(
                "Ingestion rows without an explicit target table were omitted "
                "from the table-scoped result."
            )

        filtered.sort(key=_job_sort_key, reverse=True)
        truncated = possibly_truncated or len(filtered) > result_limit
        return _collection(
            filtered[:result_limit],
            sources=[item["source"] for item in evidence if item.get("success")],
            warnings=warnings,
            truncated=truncated,
            metadata={
                "database": database_name,
                "requested_job_types": sorted(selected_types),
                "evidence": evidence,
            },
        )

    async def diagnose_ingestion(
        self,
        *,
        job_id: str | None,
        database: str | None,
        table: str | None,
        window_minutes: int | None,
        include_dependencies: bool,
    ) -> dict[str, Any]:
        normalized_job_id = _optional_text(job_id, "job identifier")
        table_name = _optional_identifier(table, "table name")
        if normalized_job_id is None and (database is None or table_name is None):
            raise PipelineRuntimeFailure(
                "Provide job_id or both database and table.",
                reason_code="PIPELINE_ARGUMENT_INVALID",
                status_code=400,
            )
        lookback = _bounded_int(
            window_minutes,
            default=_DEFAULT_DIAGNOSIS_WINDOW_MINUTES,
            minimum=1,
            maximum=43_200,
        )
        database_name = await self._resolve_database(database)
        status_result = await self.get_ingestion_status(
            job_types=None,
            database=database_name,
            table=table_name,
            states=None,
            limit=_MAX_LIMIT,
        )
        jobs = list(status_result["data"]["items"])
        if normalized_job_id is not None:
            jobs = [
                item
                for item in jobs
                if str(item.get("job_id", "")).casefold()
                == normalized_job_id.casefold()
                or str(item.get("label", "")).casefold()
                == normalized_job_id.casefold()
                or str(item.get("name", "")).casefold()
                == normalized_job_id.casefold()
            ]

        warnings = list(status_result["warnings"])
        evidence: list[dict[str, Any]] = [
            {
                "source": "ingestion_status",
                "matched_jobs": len(jobs),
            }
        ]
        freshness: dict[str, Any] | None = None
        dependencies: dict[str, Any] | None = None
        if table_name is not None:
            try:
                freshness_result = await self.monitor_data_freshness(
                    database=database_name,
                    table=table_name,
                    threshold_seconds=None,
                    time_column=None,
                )
            except PipelineRuntimeFailure as exc:
                warnings.append(
                    f"Freshness evidence is unavailable ({exc.reason_code})."
                )
                evidence.append(
                    {
                        "source": "freshness",
                        "success": False,
                        "reason_code": exc.reason_code,
                    }
                )
            else:
                freshness = freshness_result["data"]
                warnings.extend(freshness_result["warnings"])
                evidence.extend(freshness_result["evidence"])
            if include_dependencies:
                try:
                    dependency_result = await self.analyze_data_dependencies(
                        catalog=None,
                        database=database_name,
                        object_name=table_name,
                        direction="upstream",
                        depth=2,
                    )
                except PipelineRuntimeFailure as exc:
                    warnings.append(
                        f"Dependency evidence is unavailable ({exc.reason_code})."
                    )
                    evidence.append(
                        {
                            "source": "dependencies",
                            "success": False,
                            "reason_code": exc.reason_code,
                        }
                    )
                else:
                    dependencies = dependency_result["data"]
                    warnings.extend(dependency_result["warnings"])
                    evidence.extend(dependency_result["evidence"])

        audit_events, audit_warning = await self._recent_ingestion_audit(
            job_id=normalized_job_id,
            database=database_name,
            table=table_name,
            window_minutes=lookback,
        )
        if audit_warning:
            warnings.append(audit_warning)
        evidence.append(
            {
                "source": "internal.__internal_schema.audit_log",
                "rows_observed": len(audit_events),
                "success": audit_warning is None,
            }
        )

        findings = _ingestion_findings(jobs, freshness)
        if not jobs:
            warnings.append("No ingestion job matched the requested scope.")
        data: dict[str, Any] = {
            "scope": {
                "job_id": normalized_job_id,
                "database": database_name,
                "table": table_name,
                "window_minutes": lookback,
            },
            "summary": {
                "matched_jobs": len(jobs),
                "failed_jobs": sum(_state(item) in _ERROR_STATES for item in jobs),
                "running_jobs": sum(_state(item) in _RUNNING_STATES for item in jobs),
                "completed_jobs": sum(
                    _state(item) in _SUCCESS_STATES for item in jobs
                ),
                "finding_count": len(findings),
            },
            "jobs": jobs,
            "freshness": freshness,
            "dependencies": dependencies,
            "recent_audit_events": audit_events,
            "findings": findings,
        }
        return _result(
            data,
            source="deterministic_ingestion_diagnosis",
            warnings=warnings,
            evidence=evidence,
            metadata={"invented_evidence": False},
        )

    async def get_materialized_view_status(
        self,
        *,
        database: str | None,
        view: str | None,
        states: Sequence[str] | None,
        include_refresh_history: bool,
    ) -> dict[str, Any]:
        database_name = await self._resolve_database(database)
        view_name = _optional_identifier(view, "materialized view name")
        selected_states = _normalized_filter(states)
        database_property = _doris_property_string(database_name)
        source_warnings: list[str] = []
        successful_sources: list[str] = []
        source_evidence: list[dict[str, Any]] = []

        async def optional_rows(
            source: str,
            statement: str,
            *,
            max_rows: int = _MAX_SOURCE_ROWS,
            params: tuple[Any, ...] | None = None,
        ) -> list[dict[str, Any]]:
            try:
                rows = await self._execute(
                    statement,
                    params=params,
                    max_rows=max_rows,
                )
            except PipelineRuntimeFailure as exc:
                source_warnings.append(
                    f"{source} evidence is unavailable ({exc.reason_code})."
                )
                source_evidence.append(
                    {
                        "source": source,
                        "success": False,
                        "reason_code": exc.reason_code,
                    }
                )
                return []
            successful_sources.append(source)
            source_evidence.append(
                {"source": source, "success": True, "rows_observed": len(rows)}
            )
            return rows

        infos = await optional_rows(
            'mv_infos("database"=...)',
            # SQL sink audit: database_name is accepted only after
            # validate_identifier and encoded as a Doris TVF property before
            # DorisConnection.execute.
            (
                "SELECT Id, Name, JobName, State, SchemaChangeDetail, "  # nosec B608
                "RefreshState, RefreshInfo, SyncWithBaseTables "
                f'FROM mv_infos("database"={database_property}) LIMIT '
                "500"
            ),
        )
        jobs = await optional_rows(
            'jobs("type"="mv")',
            (
                "SELECT Id, Name, MvId, MvName, MvDatabaseName, ExecuteType, "
                "RecurringStrategy, Status, CreateTime "
                'FROM jobs("type"="mv") '
                "WHERE MvDatabaseName = %s LIMIT 500"
            ),
            params=(database_name,),
        )
        tasks: list[dict[str, Any]] = []
        if include_refresh_history:
            tasks = await optional_rows(
                'tasks("type"="mv")',
                (
                    "SELECT TaskId, JobId, JobName, MvId, MvName, "
                    "MvDatabaseName, Status, ErrorMsg, CreateTime, StartTime, "
                    "FinishTime, DurationMs, RefreshMode, "
                    "NeedRefreshPartitions, CompletedPartitions, Progress, "
                    "LastQueryId "
                    'FROM tasks("type"="mv") '
                    "WHERE MvDatabaseName = %s ORDER BY CreateTime DESC LIMIT "
                    "500"
                ),
                params=(database_name,),
            )

        quoted_database = quote_identifier(database_name, "database name")
        sync_rows = await optional_rows(
            "SHOW ALTER TABLE MATERIALIZED VIEW",
            f"SHOW ALTER TABLE MATERIALIZED VIEW FROM {quoted_database}",
        )
        if not successful_sources:
            raise PipelineRuntimeFailure(
                "Doris materialized-view evidence is unavailable.",
                reason_code="PIPELINE_MV_EVIDENCE_UNAVAILABLE",
                status_code=503,
                retryable=True,
            )

        jobs_by_view = {
            str(_value(row, "mv_name", "MvName", "name", "Name")).casefold(): row
            for row in jobs
            if _value(row, "mv_name", "MvName", "name", "Name") not in (None, "")
        }
        tasks_by_view: dict[str, list[Mapping[str, Any]]] = {}
        for row in tasks:
            name = _value(row, "mv_name", "MvName")
            if name not in (None, ""):
                tasks_by_view.setdefault(str(name).casefold(), []).append(row)

        items: list[dict[str, Any]] = []
        seen_views: set[str] = set()
        for row in infos:
            normalized = _normalized_row(row)
            name = str(normalized.get("name", ""))
            if not name:
                continue
            seen_views.add(name.casefold())
            job = jobs_by_view.get(name.casefold())
            history = tasks_by_view.get(name.casefold(), [])
            item = _async_mv_item(
                normalized,
                _normalized_row(job) if job is not None else None,
                [_normalized_row(task) for task in history],
                database_name=database_name,
                include_history=include_refresh_history,
            )
            items.append(item)
        for row in jobs:
            normalized = _normalized_row(row)
            name = str(normalized.get("mv_name") or normalized.get("name") or "")
            if not name or name.casefold() in seen_views:
                continue
            items.append(
                _async_mv_item(
                    None,
                    normalized,
                    [
                        _normalized_row(task)
                        for task in tasks_by_view.get(name.casefold(), [])
                    ],
                    database_name=database_name,
                    include_history=include_refresh_history,
                )
            )
        items.extend(_sync_mv_item(row, database_name) for row in sync_rows)

        filtered = [
            item
            for item in items
            if (
                view_name is None
                or str(item.get("view", "")).casefold() == view_name.casefold()
            )
            and (
                not selected_states
                or str(item.get("state", "")).casefold() in selected_states
                or str(item.get("refresh_state", "")).casefold()
                in selected_states
            )
        ]
        filtered.sort(
            key=lambda item: (
                str(item.get("database", "")),
                str(item.get("view", "")),
                str(item.get("kind", "")),
            )
        )
        truncated = len(filtered) > _MAX_LIMIT or any(
            item.get("rows_observed", 0) >= _MAX_SOURCE_ROWS
            for item in source_evidence
        )
        return _collection(
            filtered[:_MAX_LIMIT],
            sources=successful_sources,
            warnings=source_warnings,
            truncated=truncated,
            metadata={
                "database": database_name,
                "include_refresh_history": include_refresh_history,
                "evidence": source_evidence,
            },
        )

    async def monitor_data_freshness(
        self,
        *,
        database: str,
        table: str,
        threshold_seconds: int | None,
        time_column: str | None,
    ) -> dict[str, Any]:
        database_name = _required_identifier(database, "database name")
        table_name = _required_identifier(table, "table name")
        threshold = _bounded_int(
            threshold_seconds,
            default=_DEFAULT_FRESHNESS_THRESHOLD_SECONDS,
            minimum=1,
            maximum=31_536_000,
        )
        column_name = _optional_identifier(time_column, "time column")
        table_reference = build_table_reference(table_name, database_name)
        warnings: list[str] = []
        evidence: list[dict[str, Any]] = []
        observed_at: Any | None = None
        lag_seconds: int | None = None
        method = "unknown"
        partitions_observed = 0

        if column_name is not None:
            quoted_column = quote_identifier(column_name, "time column")
            try:
                # SQL sink audit: column_name and the table components pass
                # quote_identifier/build_table_reference before
                # DorisConnection.execute.
                rows = await self._execute(
                    (
                        f"SELECT MAX({quoted_column}) AS observed_at, "  # nosec B608
                        f"TIMESTAMPDIFF(SECOND, MAX({quoted_column}), NOW()) "
                        f"AS lag_seconds FROM {table_reference}"
                    ),
                    max_rows=1,
                )
            except PipelineRuntimeFailure as exc:
                warnings.append(
                    f"Event-time evidence is unavailable ({exc.reason_code})."
                )
                evidence.append(
                    {
                        "source": f"MAX({column_name})",
                        "success": False,
                        "reason_code": exc.reason_code,
                    }
                )
            else:
                if rows:
                    normalized = _normalized_row(rows[0])
                    observed_at = normalized.get("observed_at")
                    lag_seconds = _as_int(normalized.get("lag_seconds"))
                if observed_at is not None:
                    method = "event_time_column"
                evidence.append(
                    {
                        "source": f"MAX({column_name})",
                        "success": observed_at is not None,
                        "evidence_quality": "recorded_event_time",
                    }
                )

        if observed_at is None:
            try:
                partitions = await self._execute(
                    f"SHOW PARTITIONS FROM {table_reference} LIMIT {_MAX_PARTITIONS}",
                    max_rows=_MAX_PARTITIONS,
                )
            except PipelineRuntimeFailure as exc:
                warnings.append(
                    f"Visible-version evidence is unavailable ({exc.reason_code})."
                )
                evidence.append(
                    {
                        "source": "SHOW PARTITIONS",
                        "success": False,
                        "reason_code": exc.reason_code,
                    }
                )
            else:
                timestamps = [
                    value
                    for row in partitions
                    if (
                        value := _value(
                            row,
                            "VisibleVersionTime",
                            "visible_version_time",
                        )
                    )
                    not in (None, "", "N/A")
                ]
                partitions_observed = len(partitions)
                if timestamps:
                    observed_at = max(timestamps, key=lambda value: str(value))
                    lag_seconds = _seconds_since(observed_at)
                    method = "partition_visible_version"
                if len(partitions) >= _MAX_PARTITIONS:
                    warnings.append(
                        "Partition evidence reached the server-side row limit."
                    )
                evidence.append(
                    {
                        "source": "SHOW PARTITIONS.VisibleVersionTime",
                        "success": observed_at is not None,
                        "rows_observed": len(partitions),
                        "evidence_quality": "recorded_visible_version",
                    }
                )

        if observed_at is None:
            pattern = f"%{_escape_like(table_name)}%"
            try:
                rows = await self._execute(
                    (
                        "SELECT MAX(`time`) AS observed_at "
                        "FROM internal.__internal_schema.audit_log "
                        "WHERE stmt LIKE %s AND "
                        "(UPPER(stmt) LIKE '%INSERT%' OR "
                        "UPPER(stmt) LIKE '%LOAD%')"
                    ),
                    params=(pattern,),
                    max_rows=1,
                )
            except PipelineRuntimeFailure as exc:
                warnings.append(
                    f"Audit freshness fallback is unavailable ({exc.reason_code})."
                )
                evidence.append(
                    {
                        "source": "audit_log",
                        "success": False,
                        "reason_code": exc.reason_code,
                    }
                )
            else:
                if rows:
                    observed_at = _value(rows[0], "observed_at")
                if observed_at is not None:
                    lag_seconds = _seconds_since(observed_at)
                    method = "audit_statement_time"
                    warnings.append(
                        "Freshness is inferred from an audit statement timestamp, "
                        "not a committed data version."
                    )
                evidence.append(
                    {
                        "source": "internal.__internal_schema.audit_log",
                        "success": observed_at is not None,
                        "evidence_quality": "inferred",
                    }
                )

        if observed_at is None or lag_seconds is None:
            status = "unknown"
            warnings.append("No recorded freshness evidence was found.")
        elif lag_seconds <= threshold:
            status = "fresh"
        else:
            status = "stale"

        return _result(
            {
                "database": database_name,
                "table": table_name,
                "time_column": column_name,
                "threshold_seconds": threshold,
                "status": status,
                "observed_at": _json_value(observed_at),
                "lag_seconds": lag_seconds,
                "method": method,
                "partitions_observed": partitions_observed,
            },
            source=method,
            warnings=warnings,
            evidence=evidence,
            metadata={"invented_evidence": False},
        )

    async def analyze_data_dependencies(
        self,
        *,
        catalog: str | None,
        database: str | None,
        object_name: str,
        direction: str | None,
        depth: int | None,
    ) -> dict[str, Any]:
        catalog_name = _optional_identifier(catalog, "catalog name") or "internal"
        database_name = await self._resolve_database(database)
        target_object = _required_identifier(object_name, "object name")
        traversal_direction = direction or "both"
        if traversal_direction not in {"upstream", "downstream", "both"}:
            raise PipelineRuntimeFailure(
                "Dependency direction must be upstream, downstream, or both.",
                reason_code="PIPELINE_ARGUMENT_INVALID",
                status_code=400,
            )
        max_depth = _bounded_int(
            depth,
            default=3,
            minimum=1,
            maximum=_MAX_DEPENDENCY_DEPTH,
        )
        target = _canonical_object(
            target_object,
            default_catalog=catalog_name,
            default_database=database_name,
        )
        warnings: list[str] = []
        evidence: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []

        if catalog_name == "internal":
            database_property = _doris_property_string(database_name)
            try:
                # SQL sink audit: database_name is accepted only after
                # validate_identifier and encoded as a Doris TVF property
                # before DorisConnection.execute.
                mv_rows = await self._execute(
                    (
                        "SELECT Name, QuerySql "  # nosec B608
                        f'FROM mv_infos("database"={database_property}) '
                        "LIMIT 500"
                    ),
                    max_rows=_MAX_DEPENDENCY_EDGES,
                )
            except PipelineRuntimeFailure as exc:
                warnings.append(
                    f"Materialized-view dependency evidence is unavailable "
                    f"({exc.reason_code})."
                )
                evidence.append(
                    {
                        "source": "mv_infos",
                        "success": False,
                        "reason_code": exc.reason_code,
                    }
                )
            else:
                edges.extend(
                    _declared_edges(
                        mv_rows,
                        target_key="Name",
                        sql_key="QuerySql",
                        default_catalog=catalog_name,
                        default_database=database_name,
                        evidence_source="mv_infos.QuerySql",
                        kind="materialized_view",
                    )
                )
                evidence.append(
                    {
                        "source": "mv_infos.QuerySql",
                        "success": True,
                        "rows_observed": len(mv_rows),
                    }
                )

            try:
                view_rows = await self._execute(
                    (
                        "SELECT TABLE_NAME, VIEW_DEFINITION "
                        "FROM information_schema.views "
                        "WHERE TABLE_SCHEMA = %s "
                        "LIMIT 500"
                    ),
                    params=(database_name,),
                    max_rows=_MAX_DEPENDENCY_EDGES,
                )
            except PipelineRuntimeFailure as exc:
                warnings.append(
                    f"View dependency evidence is unavailable ({exc.reason_code})."
                )
                evidence.append(
                    {
                        "source": "information_schema.views",
                        "success": False,
                        "reason_code": exc.reason_code,
                    }
                )
            else:
                edges.extend(
                    _declared_edges(
                        view_rows,
                        target_key="TABLE_NAME",
                        sql_key="VIEW_DEFINITION",
                        default_catalog=catalog_name,
                        default_database=database_name,
                        evidence_source="information_schema.views",
                        kind="view",
                    )
                )
                evidence.append(
                    {
                        "source": "information_schema.views",
                        "success": True,
                        "rows_observed": len(view_rows),
                    }
                )

        try:
            audit_rows = await self._execute(
                (
                    "SELECT stmt, `time` AS observed_at "
                    "FROM internal.__internal_schema.audit_log "
                    "WHERE `time` >= DATE_SUB(NOW(), INTERVAL 30 DAY) "
                    "AND (UPPER(stmt) LIKE '%INSERT%' OR "
                    "UPPER(stmt) LIKE '%CREATE%VIEW%') "
                    "ORDER BY `time` DESC "
                    "LIMIT 500"
                ),
                max_rows=_MAX_SOURCE_ROWS,
            )
        except PipelineRuntimeFailure as exc:
            warnings.append(
                f"Audit dependency evidence is unavailable ({exc.reason_code})."
            )
            evidence.append(
                {
                    "source": "audit_log",
                    "success": False,
                    "reason_code": exc.reason_code,
                }
            )
        else:
            edges.extend(
                _audit_edges(
                    audit_rows,
                    default_catalog=catalog_name,
                    default_database=database_name,
                )
            )
            evidence.append(
                {
                    "source": "internal.__internal_schema.audit_log",
                    "success": True,
                    "rows_observed": len(audit_rows),
                    "evidence_quality": "inferred",
                }
            )

        if not any(item.get("success") for item in evidence):
            raise PipelineRuntimeFailure(
                "Doris dependency evidence is unavailable.",
                reason_code="PIPELINE_DEPENDENCY_EVIDENCE_UNAVAILABLE",
                status_code=503,
                retryable=True,
            )
        merged_edges = _merge_edges(edges)[:_MAX_DEPENDENCY_EDGES]
        graph = _traverse_dependencies(
            target,
            merged_edges,
            direction=traversal_direction,
            max_depth=max_depth,
        )
        if not graph["edges"]:
            warnings.append("No recorded dependency evidence matched the object.")
        return _result(
            {
                "target": target,
                "direction": traversal_direction,
                "max_depth": max_depth,
                **graph,
            },
            source="recorded_dependency_graph",
            warnings=warnings,
            evidence=evidence,
            metadata={
                "invented_evidence": False,
                "total_recorded_edges": len(merged_edges),
            },
        )

    async def _recent_ingestion_audit(
        self,
        *,
        job_id: str | None,
        database: str,
        table: str | None,
        window_minutes: int,
    ) -> tuple[list[dict[str, Any]], str | None]:
        marker = table or job_id
        if marker is None:
            return [], None
        pattern = f"%{_escape_like(marker)}%"
        try:
            rows = await self._execute(
                (
                    "SELECT `time` AS observed_at, query_id, stmt "
                    "FROM internal.__internal_schema.audit_log "
                    "WHERE `time` >= DATE_SUB(NOW(), INTERVAL %s MINUTE) "
                    "AND stmt LIKE %s ORDER BY `time` DESC LIMIT 50"
                ),
                params=(window_minutes, pattern),
                max_rows=50,
            )
        except PipelineRuntimeFailure as exc:
            return [], f"Recent audit evidence is unavailable ({exc.reason_code})."
        events: list[dict[str, Any]] = []
        for row in rows:
            statement = str(_value(row, "stmt") or "")
            events.append(
                {
                    "observed_at": _json_value(_value(row, "observed_at")),
                    "query_id": _value(row, "query_id"),
                    "operation": _statement_operation(statement),
                    "referenced_objects": _extract_sources(
                        statement,
                        default_catalog="internal",
                        default_database=database,
                    )[:20],
                }
            )
        return events, None

    async def _resolve_database(self, database: str | None) -> str:
        if database is not None:
            return _required_identifier(database, "database name")
        try:
            rows = await self._execute(
                "SELECT DATABASE() AS database_name",
                max_rows=1,
            )
        except PipelineRuntimeFailure as exc:
            raise PipelineRuntimeFailure(
                "A database is required for this Pipeline operation.",
                reason_code="PIPELINE_DATABASE_REQUIRED",
                status_code=400,
            ) from exc
        value = _value(rows[0], "database_name") if rows else None
        if not isinstance(value, str) or not value:
            raise PipelineRuntimeFailure(
                "A database is required for this Pipeline operation.",
                reason_code="PIPELINE_DATABASE_REQUIRED",
                status_code=400,
            )
        return _required_identifier(value, "database name")

    async def _execute(
        self,
        sql: str,
        *,
        params: Mapping[str, Any] | tuple[Any, ...] | None = None,
        max_rows: int,
        database_context: str | None = None,
    ) -> list[dict[str, Any]]:
        auth_context = get_current_auth_context()
        session_id = f"{self._session_prefix}:{uuid.uuid4().hex[:8]}"
        try:
            async with (
                self._connection_manager.get_connection_context_for_auth_context(
                    session_id,
                    auth_context,
                ) as connection
            ):
                if database_context is not None:
                    safe_database = quote_identifier(
                        database_context,
                        "database name",
                    )
                    await connection.execute(
                        f"USE {safe_database}",
                        auth_context=auth_context,
                        mask_result=False,
                        max_rows=1,
                        max_bytes=1024,
                    )
                result = await connection.execute(
                    sql,
                    params=params,
                    auth_context=auth_context,
                    mask_result=False,
                    max_rows=max_rows,
                    max_bytes=_MAX_BYTES,
                )
        except Exception as exc:
            raise _classify_failure(exc) from exc
        return [
            dict(row)
            for row in (result.data or ())
            if isinstance(row, Mapping)
        ][:max_rows]


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
        response["evidence"] = [
            redact_sensitive_data(dict(item)) for item in evidence
        ]
    return response


def _collection(
    items: Sequence[Mapping[str, Any]],
    *,
    sources: Sequence[str],
    warnings: Sequence[str] = (),
    truncated: bool,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return _result(
        {
            "items": [dict(item) for item in items],
            "next_cursor": None,
            "truncated": truncated,
        },
        source=",".join(dict.fromkeys(sources)) or "pipeline_metadata",
        warnings=warnings,
        metadata={
            "returned_items": len(items),
            **dict(metadata or {}),
        },
    )


def _job_types(values: Sequence[str] | None) -> frozenset[str]:
    if not values:
        return _JOB_TYPES
    normalized = frozenset(str(value).casefold() for value in values)
    unsupported = normalized - _JOB_TYPES
    if unsupported:
        raise PipelineRuntimeFailure(
            "Unsupported ingestion job type.",
            reason_code="PIPELINE_ARGUMENT_INVALID",
            status_code=400,
        )
    return normalized


def _normalized_filter(values: Sequence[str] | None) -> frozenset[str]:
    return frozenset(str(value).strip().casefold() for value in values or ())


def _bounded_int(
    value: int | None,
    *,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    candidate = default if value is None else value
    if isinstance(candidate, bool) or not isinstance(candidate, int):
        raise PipelineRuntimeFailure(
            "Pipeline numeric arguments must be integers.",
            reason_code="PIPELINE_ARGUMENT_INVALID",
            status_code=400,
        )
    if candidate < minimum or candidate > maximum:
        raise PipelineRuntimeFailure(
            "Pipeline numeric argument is outside the supported range.",
            reason_code="PIPELINE_ARGUMENT_INVALID",
            status_code=400,
        )
    return candidate


def _required_identifier(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PipelineRuntimeFailure(
            f"{label.capitalize()} is required.",
            reason_code="PIPELINE_ARGUMENT_INVALID",
            status_code=400,
        )
    try:
        return validate_identifier(value.strip(), label)
    except SQLSecurityError as exc:
        raise PipelineRuntimeFailure(
            f"Invalid {label}.",
            reason_code="PIPELINE_ARGUMENT_INVALID",
            status_code=400,
        ) from exc


def _optional_identifier(value: str | None, label: str) -> str | None:
    return None if value is None else _required_identifier(value, label)


def _optional_text(value: str | None, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise PipelineRuntimeFailure(
            f"Invalid {label}.",
            reason_code="PIPELINE_ARGUMENT_INVALID",
            status_code=400,
        )
    return value.strip()


def _normalized_row(row: Mapping[str, Any] | None) -> dict[str, Any]:
    if row is None:
        return {}
    return {_snake_case(str(key)): value for key, value in row.items()}


def _snake_case(value: str) -> str:
    value = re.sub(r"(?<!^)(?=[A-Z])", "_", value)
    return re.sub(r"[^a-z0-9]+", "_", value.casefold()).strip("_")


def _value(row: Mapping[str, Any], *names: str) -> Any | None:
    normalized = _normalized_row(row)
    for name in names:
        key = _snake_case(name)
        if key in normalized:
            return normalized[key]
    return None


def _batch_load_item(
    row: Mapping[str, Any],
    database_name: str,
) -> dict[str, Any] | None:
    item = _normalized_row(row)
    job_id = item.get("job_id")
    if job_id in (None, ""):
        return None
    target = _find_named_value(
        (item.get("job_details"), item.get("task_info")),
        {"table", "table_name", "tablename", "tbl"},
    )
    return {
        "job_type": "batch_load",
        "job_id": str(job_id),
        "label": item.get("label"),
        "database": database_name,
        "table": target,
        "state": _normalized_state(item.get("state")),
        "progress": item.get("progress"),
        "load_type": item.get("type"),
        "create_time": _json_value(item.get("create_time")),
        "start_time": _json_value(
            item.get("load_start_time") or item.get("etl_start_time")
        ),
        "finish_time": _json_value(
            item.get("load_finish_time") or item.get("etl_finish_time")
        ),
        "transaction_id": item.get("transaction_id"),
        "error": item.get("first_error_msg") or item.get("error_msg"),
        "comment": item.get("comment"),
    }


def _stream_load_item(row: Mapping[str, Any]) -> dict[str, Any] | None:
    item = _normalized_row(row)
    label = item.get("label")
    if label in (None, ""):
        return None
    return {
        "job_type": "stream_load",
        "job_id": str(label),
        "label": label,
        "database": item.get("db"),
        "table": item.get("table"),
        "state": _normalized_state(item.get("status")),
        "total_rows": _as_int(item.get("total_rows")),
        "loaded_rows": _as_int(item.get("loaded_rows")),
        "filtered_rows": _as_int(item.get("filtered_rows")),
        "unselected_rows": _as_int(item.get("unselected_rows")),
        "load_bytes": _as_int(item.get("load_bytes")),
        "start_time": _json_value(item.get("start_time")),
        "finish_time": _json_value(item.get("finish_time")),
        "error": item.get("first_error_msg") or item.get("message"),
        "comment": item.get("comment"),
    }


def _routine_load_item(row: Mapping[str, Any]) -> dict[str, Any] | None:
    item = _normalized_row(row)
    job_id = item.get("id")
    if job_id in (None, ""):
        return None
    return {
        "job_type": "routine_load",
        "job_id": str(job_id),
        "name": item.get("name"),
        "database": item.get("db_name"),
        "table": item.get("table_name"),
        "state": _normalized_state(item.get("state")),
        "data_source_type": item.get("data_source_type"),
        "current_task_count": _as_int(item.get("current_task_num")),
        "lag": _safe_json(item.get("lag")),
        "progress": _safe_json(item.get("progress")),
        "statistics": _safe_json(item.get("statistic")),
        "create_time": _json_value(item.get("create_time")),
        "pause_time": _json_value(item.get("pause_time")),
        "finish_time": _json_value(item.get("end_time")),
        "error": item.get("reason_of_state_changed") or item.get("other_msg"),
        "compute_group": item.get("compute_group"),
        "comment": item.get("comment"),
    }


def _insert_job_item(
    row: Mapping[str, Any],
    database_name: str,
) -> dict[str, Any]:
    item = _normalized_row(row)
    statement = str(item.get("execute_sql") or "")
    target = _extract_write_target(
        statement,
        default_catalog="internal",
        default_database=database_name,
    )
    current_offset = item.get("current_offset")
    end_offset = item.get("end_offset")
    runtime_message = str(item.get("job_runtime_msg") or "")
    continuous = any(
        value not in (None, "", "null", "NULL")
        for value in (current_offset, end_offset)
    ) or "stream" in runtime_message.casefold()
    target_parts = target.split(".") if target else []
    return {
        "job_type": "continuous_load" if continuous else "insert_job",
        "job_id": str(item.get("id") or item.get("name") or ""),
        "name": item.get("name"),
        "database": target_parts[-2] if len(target_parts) >= 2 else None,
        "table": target_parts[-1] if target_parts else None,
        "state": _normalized_state(item.get("status")),
        "execute_type": item.get("execute_type"),
        "recurring_strategy": item.get("recurring_strategy"),
        "create_time": _json_value(item.get("create_time")),
        "succeeded_task_count": _as_int(item.get("succeed_task_count")),
        "failed_task_count": _as_int(item.get("failed_task_count")),
        "canceled_task_count": _as_int(item.get("canceled_task_count")),
        "current_offset": _safe_json(current_offset),
        "end_offset": _safe_json(end_offset),
        "load_statistics": _safe_json(item.get("load_statistic")),
        "error": item.get("error_msg"),
        "comment": item.get("comment"),
    }


def _async_mv_item(
    info: Mapping[str, Any] | None,
    job: Mapping[str, Any] | None,
    tasks: Sequence[Mapping[str, Any]],
    *,
    database_name: str,
    include_history: bool,
) -> dict[str, Any]:
    view = (
        (info or {}).get("name")
        or (job or {}).get("mv_name")
        or (job or {}).get("name")
    )
    history = [_mv_task_item(task) for task in tasks[:20]]
    item: dict[str, Any] = {
        "kind": "asynchronous",
        "database": database_name,
        "view": view,
        "state": _normalized_state(
            (info or {}).get("state") or (job or {}).get("status")
        ),
        "refresh_state": _normalized_state((info or {}).get("refresh_state")),
        "sync_with_base_tables": _as_bool(
            (info or {}).get("sync_with_base_tables")
        ),
        "refresh_info": (info or {}).get("refresh_info"),
        "schema_change_detail": (info or {}).get("schema_change_detail"),
        "job": {
            "job_id": (job or {}).get("id"),
            "job_name": (info or {}).get("job_name")
            or (job or {}).get("name"),
            "status": _normalized_state((job or {}).get("status")),
            "execute_type": (job or {}).get("execute_type"),
            "recurring_strategy": (job or {}).get("recurring_strategy"),
            "create_time": _json_value((job or {}).get("create_time")),
        },
        "latest_refresh": history[0] if history else None,
    }
    if include_history:
        item["refresh_history"] = history
    return item


def _mv_task_item(task: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "task_id": task.get("task_id"),
        "status": _normalized_state(task.get("status")),
        "error": task.get("error_msg"),
        "create_time": _json_value(task.get("create_time")),
        "start_time": _json_value(task.get("start_time")),
        "finish_time": _json_value(task.get("finish_time")),
        "duration_ms": _as_int(task.get("duration_ms")),
        "refresh_mode": task.get("refresh_mode"),
        "progress": task.get("progress"),
        "needed_partitions": _safe_json(task.get("need_refresh_partitions")),
        "completed_partitions": _safe_json(task.get("completed_partitions")),
        "last_query_id": task.get("last_query_id"),
    }


def _sync_mv_item(
    row: Mapping[str, Any],
    database_name: str,
) -> dict[str, Any]:
    item = _normalized_row(row)
    return {
        "kind": "synchronous_build",
        "database": database_name,
        "view": item.get("rollup_index_name") or item.get("index_name"),
        "base_table": item.get("table_name"),
        "job_id": item.get("job_id"),
        "state": _normalized_state(item.get("state")),
        "progress": item.get("progress"),
        "create_time": _json_value(item.get("create_time")),
        "finish_time": _json_value(item.get("finish_time")),
        "error": item.get("msg"),
    }


def _ingestion_findings(
    jobs: Sequence[Mapping[str, Any]],
    freshness: Mapping[str, Any] | None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for item in jobs:
        state = _state(item)
        if state in _ERROR_STATES:
            findings.append(
                {
                    "severity": "high",
                    "code": "INGESTION_JOB_NOT_HEALTHY",
                    "job_id": item.get("job_id"),
                    "state": state,
                    "message": "The recorded ingestion job is not healthy.",
                }
            )
        lag = _numeric_total(item.get("lag"))
        if lag is not None and lag > 0:
            findings.append(
                {
                    "severity": "medium",
                    "code": "ROUTINE_LOAD_LAG_RECORDED",
                    "job_id": item.get("job_id"),
                    "lag_total": lag,
                    "message": "Routine Load reports a positive source lag.",
                }
            )
        failed_tasks = _as_int(item.get("failed_task_count"))
        if failed_tasks is not None and failed_tasks > 0:
            findings.append(
                {
                    "severity": "medium",
                    "code": "INGESTION_TASK_FAILURES_RECORDED",
                    "job_id": item.get("job_id"),
                    "failed_task_count": failed_tasks,
                    "message": "The ingestion job records failed tasks.",
                }
            )
    if freshness and freshness.get("status") == "stale":
        findings.append(
            {
                "severity": "medium",
                "code": "TARGET_TABLE_STALE",
                "lag_seconds": freshness.get("lag_seconds"),
                "message": "The target table exceeds the freshness threshold.",
            }
        )
    return findings


def _declared_edges(
    rows: Sequence[Mapping[str, Any]],
    *,
    target_key: str,
    sql_key: str,
    default_catalog: str,
    default_database: str,
    evidence_source: str,
    kind: str,
) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    for row in rows:
        target_value = _value(row, target_key)
        statement = _value(row, sql_key)
        if not isinstance(target_value, str) or not isinstance(statement, str):
            continue
        target = _canonical_object(
            target_value,
            default_catalog=default_catalog,
            default_database=default_database,
        )
        for source in _extract_sources(
            statement,
            default_catalog=default_catalog,
            default_database=default_database,
        ):
            if source != target:
                edges.append(
                    {
                        "source": source,
                        "target": target,
                        "kind": kind,
                        "confidence": 1.0,
                        "evidence_source": evidence_source,
                        "observed_at": None,
                    }
                )
    return edges


def _audit_edges(
    rows: Sequence[Mapping[str, Any]],
    *,
    default_catalog: str,
    default_database: str,
) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    for row in rows:
        statement = _value(row, "stmt")
        if not isinstance(statement, str):
            continue
        target = _extract_write_target(
            statement,
            default_catalog=default_catalog,
            default_database=default_database,
        )
        if target is None:
            continue
        for source in _extract_sources(
            statement,
            default_catalog=default_catalog,
            default_database=default_database,
        ):
            if source != target:
                edges.append(
                    {
                        "source": source,
                        "target": target,
                        "kind": "audit_sql_inference",
                        "confidence": 0.7,
                        "evidence_source": "internal.__internal_schema.audit_log",
                        "observed_at": _json_value(_value(row, "observed_at")),
                    }
                )
    return edges


def _merge_edges(edges: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for edge in edges:
        source = str(edge.get("source", ""))
        target = str(edge.get("target", ""))
        if not source or not target:
            continue
        key = (source, target)
        current = merged.get(key)
        if current is None:
            merged[key] = {
                "source": source,
                "target": target,
                "kind": edge.get("kind"),
                "confidence": edge.get("confidence"),
                "evidence_sources": [edge.get("evidence_source")],
                "observed_at": edge.get("observed_at"),
            }
            continue
        current["confidence"] = max(
            float(current.get("confidence") or 0),
            float(edge.get("confidence") or 0),
        )
        current["evidence_sources"] = list(
            dict.fromkeys(
                [
                    *current["evidence_sources"],
                    edge.get("evidence_source"),
                ]
            )
        )
        if edge.get("observed_at") is not None:
            current["observed_at"] = max(
                str(current.get("observed_at") or ""),
                str(edge["observed_at"]),
            )
    return sorted(merged.values(), key=lambda item: (item["source"], item["target"]))


def _traverse_dependencies(
    target: str,
    edges: Sequence[Mapping[str, Any]],
    *,
    direction: str,
    max_depth: int,
) -> dict[str, Any]:
    adjacency_up: dict[str, list[Mapping[str, Any]]] = {}
    adjacency_down: dict[str, list[Mapping[str, Any]]] = {}
    for edge in edges:
        source = str(edge["source"])
        destination = str(edge["target"])
        adjacency_up.setdefault(destination, []).append(edge)
        adjacency_down.setdefault(source, []).append(edge)

    selected_edges: dict[tuple[str, str], Mapping[str, Any]] = {}
    paths: list[dict[str, Any]] = []
    directions = (
        ("upstream", adjacency_up)
        if direction == "upstream"
        else (
            ("downstream", adjacency_down)
            if direction == "downstream"
            else None
        )
    )
    direction_pairs = (
        (directions,)
        if directions is not None
        else (("upstream", adjacency_up), ("downstream", adjacency_down))
    )
    for traversal_name, adjacency in direction_pairs:
        queue: deque[tuple[str, list[str], int]] = deque([(target, [target], 0)])
        visited: set[tuple[str, int]] = {(target, 0)}
        while queue:
            current, path, current_depth = queue.popleft()
            if current_depth >= max_depth:
                continue
            for edge in adjacency.get(current, ()):
                source = str(edge["source"])
                destination = str(edge["target"])
                next_node = (
                    source if traversal_name == "upstream" else destination
                )
                selected_edges[(source, destination)] = edge
                next_path = [*path, next_node]
                paths.append(
                    {
                        "direction": traversal_name,
                        "depth": current_depth + 1,
                        "nodes": next_path,
                    }
                )
                marker = (next_node, current_depth + 1)
                if marker not in visited:
                    visited.add(marker)
                    queue.append((next_node, next_path, current_depth + 1))

    edge_items = sorted(
        (dict(edge) for edge in selected_edges.values()),
        key=lambda item: (item["source"], item["target"]),
    )
    nodes = sorted(
        {
            target,
            *(
                str(value)
                for edge in edge_items
                for value in (edge["source"], edge["target"])
            ),
        }
    )
    paths.sort(key=lambda item: (item["direction"], item["depth"], item["nodes"]))
    return {"nodes": nodes, "edges": edge_items, "paths": paths}


def _extract_sources(
    sql: str,
    *,
    default_catalog: str,
    default_database: str,
) -> list[str]:
    cleaned = _sql_structure(sql)
    cte_names = {
        _strip_identifier(match.group(1)).casefold()
        for match in _CTE_NAME.finditer(cleaned)
    }
    sources = []
    for match in _SOURCE_REFERENCE.finditer(cleaned):
        raw = match.group(1)
        if _strip_identifier(raw).casefold() in cte_names:
            continue
        try:
            source = _canonical_object(
                raw,
                default_catalog=default_catalog,
                default_database=default_database,
            )
        except PipelineRuntimeFailure:
            continue
        sources.append(source)
    return list(dict.fromkeys(sources))


def _extract_write_target(
    sql: str,
    *,
    default_catalog: str,
    default_database: str,
) -> str | None:
    cleaned = _sql_structure(sql)
    match = _WRITE_TARGET.search(cleaned)
    if match is None:
        return None
    try:
        return _canonical_object(
            match.group(1),
            default_catalog=default_catalog,
            default_database=default_database,
        )
    except PipelineRuntimeFailure:
        return None


def _sql_structure(sql: str) -> str:
    statements = sqlparse.parse(sql)
    if not statements:
        return ""
    parts: list[str] = []
    for token in statements[0].flatten():
        token_type = token.ttype
        if token_type in sql_tokens.Comment or token_type in sql_tokens.Literal.String:
            parts.append(" ")
        else:
            parts.append(token.value)
    return "".join(parts)


def _canonical_object(
    value: str,
    *,
    default_catalog: str,
    default_database: str,
) -> str:
    parts = [
        _strip_identifier(part)
        for part in re.split(r"\s*\.\s*", value.strip())
        if part.strip()
    ]
    if len(parts) == 1:
        parts = [default_catalog, default_database, parts[0]]
    elif len(parts) == 2:
        parts = [default_catalog, *parts]
    elif len(parts) != 3:
        raise PipelineRuntimeFailure(
            "Invalid object reference.",
            reason_code="PIPELINE_ARGUMENT_INVALID",
            status_code=400,
        )
    validated = [
        _required_identifier(part, "object identifier")
        for part in parts
    ]
    return ".".join(validated)


def _strip_identifier(value: str) -> str:
    return value.strip().strip("`").strip('"')


def _statement_operation(statement: str) -> str:
    cleaned = _sql_structure(statement).lstrip()
    match = re.match(r"([A-Za-z]+)", cleaned)
    return match.group(1).upper() if match else "UNKNOWN"


def _find_named_value(
    values: Sequence[Any],
    keys: set[str],
) -> str | None:
    for value in values:
        parsed = _safe_json(value)
        if isinstance(parsed, Mapping):
            for key, candidate in parsed.items():
                if _snake_case(str(key)) in keys and isinstance(candidate, str):
                    try:
                        return validate_identifier(candidate, "table name")
                    except SQLSecurityError:
                        continue
    return None


def _safe_json(value: Any) -> Any:
    if not isinstance(value, str):
        return _json_value(value)
    stripped = value.strip()
    if not stripped:
        return None
    try:
        parsed = json.loads(stripped)
    except (TypeError, ValueError):
        return stripped[:512]
    return _json_value(parsed)


def _json_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes):
        return [_json_value(item) for item in value]
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _normalized_state(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return str(value).strip().casefold()


def _state(item: Mapping[str, Any]) -> str:
    return str(item.get("state") or "").casefold()


def _job_sort_key(item: Mapping[str, Any]) -> str:
    for key in ("finish_time", "start_time", "create_time"):
        value = item.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def _as_int(value: Any) -> int | None:
    if value in (None, "") or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        if value.casefold() in {"1", "true", "yes"}:
            return True
        if value.casefold() in {"0", "false", "no"}:
            return False
    return None


def _numeric_total(value: Any) -> float | None:
    if isinstance(value, int | float) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, Mapping):
        numbers = [
            float(item)
            for item in value.values()
            if isinstance(item, int | float) and not isinstance(item, bool)
        ]
        return sum(numbers) if numbers else None
    return None


def _seconds_since(value: Any) -> int | None:
    if isinstance(value, datetime):
        observed = value
    elif isinstance(value, str):
        try:
            observed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    now = datetime.now(UTC) if observed.tzinfo is not None else datetime.now()
    return max(0, int((now - observed).total_seconds()))


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _doris_property_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _classify_failure(exc: Exception) -> PipelineRuntimeFailure:
    if isinstance(exc, PipelineRuntimeFailure):
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
        return PipelineRuntimeFailure(
            "Doris denied access to Pipeline metadata.",
            reason_code="PIPELINE_PERMISSION_DENIED",
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
            "no viable alternative",
        )
    ):
        return PipelineRuntimeFailure(
            "The requested Doris Pipeline evidence source is unsupported.",
            reason_code="PIPELINE_SOURCE_UNSUPPORTED",
            status_code=501,
        )
    if isinstance(exc, TimeoutError | ConnectionError | OSError):
        return PipelineRuntimeFailure(
            "Doris Pipeline evidence is temporarily unavailable.",
            reason_code="PIPELINE_BACKEND_UNAVAILABLE",
            status_code=503,
            retryable=True,
        )
    return PipelineRuntimeFailure(
        "Doris Pipeline metadata execution failed.",
        reason_code="PIPELINE_EXECUTION_FAILED",
        status_code=502,
    )


__all__ = ["DorisPipelineRuntime", "PipelineRuntimeFailure"]
