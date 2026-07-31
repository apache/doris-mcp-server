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

"""Strict, evidence-bearing runtime for the read-only Governance domain."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
import uuid
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol
from urllib.parse import urlsplit

import sqlparse

from ..tools.doris_version import DorisVersion, parse_doris_version_comment
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
_MAX_COLUMNS = 32
_MAX_AUDIT_ROWS = 1_000
_MAX_AUDIT_RESULTS = 200
_MAX_UDFS = 500
_MAX_PARTITIONS = 1_000
_MAX_INDEXES = 512
_MAX_LINEAGE_DEPTH = 5
_NATIVE_LINEAGE_MINIMUM = parse_doris_version_comment("Doris version doris-4.0.6")
_AUDIT_TABLE = "internal.__internal_schema.audit_log"
_SIMPLE_IDENTIFIER = r"(?:`[^`]+`|[A-Za-z_][A-Za-z0-9_$]*)"
_QUALIFIED_IDENTIFIER = (
    rf"{_SIMPLE_IDENTIFIER}"
    rf"(?:\s*\.\s*{_SIMPLE_IDENTIFIER}){{0,2}}"
)
_WRITE_TARGET = re.compile(
    rf"\b(?:INSERT\s+INTO|INSERT\s+OVERWRITE\s+TABLE|CREATE\s+TABLE)"
    rf"\s+({_QUALIFIED_IDENTIFIER})",
    re.IGNORECASE,
)
_SOURCE_REFERENCE = re.compile(
    rf"\b(?:FROM|JOIN)\s+({_QUALIFIED_IDENTIFIER})",
    re.IGNORECASE,
)
_SIMPLE_INSERT_SELECT = re.compile(
    rf"""
    \bINSERT\s+(?:INTO|OVERWRITE\s+TABLE)\s+
    (?P<target>{_QUALIFIED_IDENTIFIER})
    \s*\((?P<target_columns>[^()]+)\)\s*
    SELECT\s+(?P<select_list>.+?)\s+
    FROM\s+(?P<source>{_QUALIFIED_IDENTIFIER})
    (?P<tail>.*)
    """,
    re.IGNORECASE | re.DOTALL | re.VERBOSE,
)
_SAFE_CREATE_PROPERTY_KEYS = frozenset(
    {
        "compression",
        "enable_light_schema_change",
        "enable_unique_key_merge_on_write",
        "replication_allocation",
        "replication_num",
        "storage_format",
        "variant_enable_typed_paths_to_sparse",
        "variant_flatten_nested",
        "variant_max_sparse_column_statistics_size",
        "variant_sparse_hash_shard_count",
    }
)
_COMPLEX_TYPE_MARKERS = (
    "ARRAY",
    "MAP",
    "STRUCT",
    "JSON",
    "VARIANT",
    "HLL",
    "BITMAP",
    "QUANTILE_STATE",
    "AGG_STATE",
)
_AUDIT_FIELD_ORDER = (
    "query_id",
    "stmt_id",
    "time",
    "user",
    "catalog",
    "db",
    "state",
    "error_code",
    "query_time",
    "scan_bytes",
    "scan_rows",
    "return_rows",
    "stmt_type",
    "is_query",
    "queried_tables_and_views",
    "chosen_m_views",
    "stmt",
)
_LINEAGE_STORE_REQUIRED_COLUMNS = frozenset(
    {
        "event_id",
        "event_time",
        "source_object",
        "target_object",
    }
)
_LINEAGE_STORE_OPTIONAL_COLUMNS = (
    "query_id",
    "source_column",
    "target_column",
    "dependency_type",
    "statement_type",
)


class GovernanceRuntimeFailure(RuntimeError):
    """Sanitized Governance-domain failure with a stable reason code."""

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


@dataclass(frozen=True, slots=True)
class LineageProviderStatus:
    """Queryable lineage-provider health without implementation secrets."""

    provider_id: str
    status: str
    queryable: bool
    observed_columns: tuple[str, ...] = ()
    row_count: int | None = None
    latest_event_time: Any | None = None
    recent_event_observed: bool = False
    limitations: tuple[str, ...] = ()


class QueryableLineageProvider(Protocol):
    """Provider boundary for Doris native or external lineage stores."""

    async def status(self) -> LineageProviderStatus:
        """Return current queryability and freshness evidence."""

    async def trace(
        self,
        *,
        object_name: str,
        column: str | None,
        direction: str,
        depth: int,
        max_edges: int,
    ) -> dict[str, Any]:
        """Return bounded lineage edges preserving native evidence IDs."""


class DorisLineageStoreProvider:
    """Read the canonical MCP lineage-event table populated by a plugin sink."""

    def __init__(
        self,
        connection_manager: DorisConnectionManager,
        *,
        table: str,
        recent_event_minutes: int,
    ) -> None:
        self._connection_manager = connection_manager
        self._table_parts = _qualified_parts(
            table,
            field="lineage store table",
            minimum_parts=2,
        )
        self._table = _table_reference(self._table_parts)
        self._recent_event_minutes = recent_event_minutes
        self._session_prefix = f"lineage_store_{uuid.uuid4().hex[:8]}"

    async def status(self) -> LineageProviderStatus:
        try:
            # SQL sink audit: the constructor strictly validates and quotes the
            # configured table before _execute sends this read-only statement.
            rows = await self._execute(
                f"DESC {self._table}",  # nosec B608
                max_rows=128,
            )
        except GovernanceRuntimeFailure as exc:
            return LineageProviderStatus(
                provider_id="doris_native_event_store",
                status="unavailable",
                queryable=False,
                limitations=(
                    f"The configured lineage store is unreadable ({exc.reason_code}).",
                ),
            )

        columns = tuple(
            dict.fromkeys(
                str(_value(row, "field", "column_name", "name")).casefold()
                for row in rows
                if _value(row, "field", "column_name", "name") is not None
            )
        )
        missing = sorted(_LINEAGE_STORE_REQUIRED_COLUMNS - set(columns))
        if missing:
            return LineageProviderStatus(
                provider_id="doris_native_event_store",
                status="misconfigured",
                queryable=False,
                observed_columns=columns,
                limitations=(
                    "The lineage store is missing required canonical columns: "
                    + ", ".join(missing),
                ),
            )

        summary_sql = (
            "SELECT COUNT(*) AS row_count, "
            "MAX(`event_time`) AS latest_event_time, "
            "SUM(CASE WHEN `event_time` >= "
            "DATE_SUB(NOW(), INTERVAL %s MINUTE) THEN 1 ELSE 0 END) "
            # SQL sink audit: the table is validated and quoted at construction;
            # _execute binds the only value parameter before reaching the sink.
            f"AS recent_event_count FROM {self._table}"  # nosec B608
        )
        try:
            summary = await self._execute(
                summary_sql,
                params=(self._recent_event_minutes,),
                max_rows=1,
            )
        except GovernanceRuntimeFailure as exc:
            return LineageProviderStatus(
                provider_id="doris_native_event_store",
                status="degraded",
                queryable=True,
                observed_columns=columns,
                limitations=(
                    f"Lineage freshness evidence is unavailable ({exc.reason_code}).",
                ),
            )
        row = summary[0] if summary else {}
        row_count = _optional_int(_value(row, "row_count"))
        recent_count = _optional_int(_value(row, "recent_event_count")) or 0
        latest = _json_value(_value(row, "latest_event_time"))
        limitations: tuple[str, ...] = ()
        status = "available"
        if not row_count or recent_count <= 0:
            status = "degraded"
            limitations = (
                "The store is queryable but no recent lineage event was observed.",
            )
        return LineageProviderStatus(
            provider_id="doris_native_event_store",
            status=status,
            queryable=True,
            observed_columns=columns,
            row_count=row_count,
            latest_event_time=latest,
            recent_event_observed=recent_count > 0,
            limitations=limitations,
        )

    async def trace(
        self,
        *,
        object_name: str,
        column: str | None,
        direction: str,
        depth: int,
        max_edges: int,
    ) -> dict[str, Any]:
        provider_status = await self.status()
        if not provider_status.queryable:
            raise GovernanceRuntimeFailure(
                "The configured lineage event store is unavailable.",
                reason_code="GOVERNANCE_LINEAGE_STORE_UNAVAILABLE",
                status_code=503,
                retryable=True,
            )
        selected = (
            "event_id",
            "event_time",
            "source_object",
            "target_object",
            *tuple(
                name
                for name in _LINEAGE_STORE_OPTIONAL_COLUMNS
                if name in provider_status.observed_columns
            ),
        )
        select_list = ", ".join(quote_identifier(name) for name in selected)
        frontier = {object_name}
        visited = {object_name}
        edges: list[dict[str, Any]] = []
        edge_keys: set[tuple[Any, ...]] = set()
        source_rows = 0

        for level in range(1, depth + 1):
            if not frontier or len(edges) >= max_edges:
                break
            placeholders = ", ".join("%s" for _ in frontier)
            predicates: list[str] = []
            params: list[Any] = []
            ordered_frontier = sorted(frontier)
            if direction in {"upstream", "both"}:
                predicates.append(f"`target_object` IN ({placeholders})")
                params.extend(ordered_frontier)
            if direction in {"downstream", "both"}:
                predicates.append(f"`source_object` IN ({placeholders})")
                params.extend(ordered_frontier)
            if column is not None:
                column_predicates: list[str] = []
                if "source_column" in selected:
                    column_predicates.append("`source_column` = %s")
                    params.append(column)
                if "target_column" in selected:
                    column_predicates.append("`target_column` = %s")
                    params.append(column)
                if not column_predicates:
                    return {
                        "edges": [],
                        "truncated": False,
                        "rows_observed": 0,
                        "provider_status": provider_status,
                        "limitations": [
                            "The lineage store has no column-level fields."
                        ],
                    }
                predicates = [
                    f"({' OR '.join(predicates)}) "
                    f"AND ({' OR '.join(column_predicates)})"
                ]

            remaining = max_edges - len(edges)
            # SQL sink audit: table and selected fields are canonical quoted
            # identifiers, predicates use placeholders, and _execute receives
            # a bounded server-generated integer limit.
            sql = (
                f"SELECT {select_list} FROM {self._table} "  # nosec B608
                f"WHERE {' OR '.join(predicates)} "
                "ORDER BY `event_time` DESC LIMIT "
                f"{remaining}"
            )
            rows = await self._execute(
                sql,
                params=tuple(params),
                max_rows=remaining,
            )
            source_rows += len(rows)
            next_frontier: set[str] = set()
            for row in rows:
                edge = _native_lineage_edge(row, level=level)
                if edge is None:
                    continue
                key = (
                    edge["source_object"],
                    edge.get("source_column"),
                    edge["target_object"],
                    edge.get("target_column"),
                    edge["source_event_id"],
                )
                if key in edge_keys:
                    continue
                edge_keys.add(key)
                edges.append(edge)
                if direction in {"upstream", "both"} and (
                    edge["target_object"] in frontier
                ):
                    next_frontier.add(edge["source_object"])
                if direction in {"downstream", "both"} and (
                    edge["source_object"] in frontier
                ):
                    next_frontier.add(edge["target_object"])
                if len(edges) >= max_edges:
                    break
            frontier = next_frontier - visited
            visited.update(frontier)

        return {
            "edges": edges,
            "truncated": len(edges) >= max_edges,
            "rows_observed": source_rows,
            "provider_status": provider_status,
            "limitations": list(provider_status.limitations),
        }

    async def _execute(
        self,
        sql: str,
        *,
        params: Mapping[str, Any] | tuple[Any, ...] | None = None,
        max_rows: int,
    ) -> list[dict[str, Any]]:
        auth_context = get_current_auth_context()
        session_id = f"{self._session_prefix}:{uuid.uuid4().hex[:8]}"
        try:
            async with self._connection_manager.get_connection_context_for_auth_context(
                session_id,
                auth_context,
            ) as connection:
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
        return [dict(row) for row in (result.data or ()) if isinstance(row, Mapping)][
            :max_rows
        ]


class DorisGovernanceRuntime:
    """Read bounded governance evidence without creating metadata or edges."""

    def __init__(
        self,
        connection_manager: DorisConnectionManager,
        *,
        lineage_provider: QueryableLineageProvider | None = None,
    ) -> None:
        self._connection_manager = connection_manager
        self._session_prefix = f"formal_governance_{uuid.uuid4().hex[:8]}"
        config = getattr(connection_manager, "config", None)
        governance = getattr(config, "governance", None)
        sample_ratio = getattr(governance, "max_sample_ratio", None)
        self._max_sample_ratio = (
            float(sample_ratio)
            if isinstance(sample_ratio, int | float)
            and not isinstance(sample_ratio, bool)
            else 0.25
        )
        audit_window_days = getattr(governance, "max_audit_window_days", None)
        self._max_audit_window_days = (
            audit_window_days
            if isinstance(audit_window_days, int)
            and not isinstance(audit_window_days, bool)
            else 30
        )
        max_lineage_edges = getattr(governance, "max_lineage_edges", None)
        self._max_lineage_edges = (
            max_lineage_edges
            if isinstance(max_lineage_edges, int)
            and not isinstance(max_lineage_edges, bool)
            else 500
        )
        configured_store = getattr(governance, "lineage_store_table", None)
        lineage_store_table = (
            configured_store.strip() if isinstance(configured_store, str) else ""
        )
        configured_recent_minutes = getattr(
            governance,
            "lineage_recent_event_minutes",
            None,
        )
        recent_event_minutes = (
            configured_recent_minutes
            if isinstance(configured_recent_minutes, int)
            and not isinstance(configured_recent_minutes, bool)
            else 1440
        )
        self._lineage_provider = lineage_provider
        if self._lineage_provider is None and lineage_store_table:
            self._lineage_provider = DorisLineageStoreProvider(
                connection_manager,
                table=lineage_store_table,
                recent_event_minutes=recent_event_minutes,
            )

    async def analyze_columns(
        self,
        *,
        database: str,
        table: str,
        columns: Sequence[str] | None,
        sample_ratio: float | None,
    ) -> dict[str, Any]:
        database_name = _identifier(database, "database name")
        table_name = _identifier(table, "table name")
        table_ref = build_table_reference(
            table_name,
            database_name,
            "internal",
        )
        column_rows = await self._execute(
            (
                "SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE, COLUMN_DEFAULT, "
                "COLUMN_COMMENT, ORDINAL_POSITION "
                "FROM information_schema.columns "
                "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s "
                "ORDER BY ORDINAL_POSITION LIMIT 512"
            ),
            params=(database_name, table_name),
            max_rows=512,
        )
        available = {
            str(_value(row, "column_name")): row
            for row in column_rows
            if _value(row, "column_name") is not None
        }
        if not available:
            raise GovernanceRuntimeFailure(
                "The requested Doris table is unavailable.",
                reason_code="GOVERNANCE_TABLE_NOT_FOUND",
                status_code=404,
            )

        warnings: list[str] = []
        if columns:
            selected = tuple(
                dict.fromkeys(_identifier(item, "column name") for item in columns)
            )
            missing = [name for name in selected if name not in available]
            if missing:
                raise GovernanceRuntimeFailure(
                    "One or more requested columns are unavailable.",
                    reason_code="GOVERNANCE_COLUMN_NOT_FOUND",
                    status_code=404,
                )
        else:
            selected = tuple(available)
        if len(selected) > _MAX_COLUMNS:
            selected = selected[:_MAX_COLUMNS]
            warnings.append(
                f"Column analysis was limited to the first {_MAX_COLUMNS} columns."
            )

        stats_rows: list[dict[str, Any]] = []
        stats_failure: GovernanceRuntimeFailure | None = None
        try:
            # SQL sink audit: table_ref contains only strictly validated and
            # quoted identifiers before _execute sends this read-only command.
            stats_rows = await self._execute(
                f"SHOW COLUMN STATS {table_ref}",  # nosec B608
                max_rows=512,
            )
        except GovernanceRuntimeFailure as exc:
            stats_failure = exc
            warnings.append(
                f"Recorded Doris column statistics are unavailable ({exc.reason_code})."
            )
        stats = {
            str(_value(row, "column_name")): row
            for row in stats_rows
            if _value(row, "column_name") is not None
        }

        applied_ratio = _sample_ratio(
            sample_ratio,
            maximum=self._max_sample_ratio,
        )
        if sample_ratio is not None and applied_ratio < float(sample_ratio):
            warnings.append(
                "Requested sample ratio exceeded the configured Governance "
                f"ceiling and was reduced to {applied_ratio:g}."
            )
        sample: Mapping[str, Any] = {}
        sample_columns = tuple(
            name
            for name in selected
            if not _is_complex_type(str(_value(available[name], "data_type") or ""))
        )
        sample_failure: GovernanceRuntimeFailure | None = None
        if applied_ratio > 0 and sample_columns:
            percentage = max(1, min(100, round(applied_ratio * 100)))
            projections = ["COUNT(*) AS `sample_rows`"]
            for index, name in enumerate(sample_columns):
                column_ref = quote_identifier(name, "column name")
                projections.extend(
                    (
                        f"COUNT({column_ref}) AS `c{index}_non_null`",
                        f"NDV({column_ref}) AS `c{index}_ndv`",
                    )
                )
            # SQL sink audit: table and column identifiers are validated and
            # quoted; the sample percentage is a bounded server-generated int
            # before _execute receives the read-only statement.
            sample_sql = (
                f"SELECT {', '.join(projections)} FROM {table_ref} "  # nosec B608
                f"TABLESAMPLE {percentage} PERCENT REPEATABLE 1"
            )
            try:
                sample_rows = await self._execute(
                    sample_sql,
                    max_rows=1,
                )
                sample = sample_rows[0] if sample_rows else {}
            except GovernanceRuntimeFailure as exc:
                sample_failure = exc
                warnings.append(
                    f"Bounded live sampling is unavailable ({exc.reason_code})."
                )
        elif applied_ratio > 0:
            warnings.append(
                "Live sampling was skipped because all selected columns use "
                "complex or aggregate-state types."
            )

        sample_row_count = _optional_int(_value(sample, "sample_rows"))
        items: list[dict[str, Any]] = []
        for name in selected:
            metadata = available[name]
            statistic = stats.get(name, {})
            count = _optional_float(_value(statistic, "count"))
            null_count = _optional_float(_value(statistic, "num_null", "null_count"))
            sample_index = (
                sample_columns.index(name) if name in sample_columns else None
            )
            sampled_non_null = (
                _optional_int(_value(sample, f"c{sample_index}_non_null"))
                if sample_index is not None
                else None
            )
            sampled_ndv = (
                _optional_int(_value(sample, f"c{sample_index}_ndv"))
                if sample_index is not None
                else None
            )
            risks: list[str] = []
            data_type = str(_value(metadata, "data_type") or "")
            nullable = str(_value(metadata, "is_nullable") or "").upper() == "YES"
            if nullable:
                risks.append("nullable")
            if _is_complex_type(data_type):
                risks.append("complex_type_statistics_limited")
            if not statistic:
                risks.append("recorded_statistics_missing")
            item = {
                "name": name,
                "data_type": data_type,
                "nullable": nullable,
                "ordinal_position": _optional_int(_value(metadata, "ordinal_position")),
                "statistics": {
                    "row_count": count,
                    "distinct_count": _optional_float(_value(statistic, "ndv")),
                    "null_count": null_count,
                    "null_ratio": (
                        round(null_count / count, 6)
                        if count and null_count is not None
                        else None
                    ),
                    "data_size_bytes": _optional_float(_value(statistic, "data_size")),
                    "collection_method": _value(statistic, "method"),
                    "updated_at": _json_value(
                        _value(statistic, "updated_time", "update_time")
                    ),
                    "min_observed": _value(statistic, "min") is not None,
                    "max_observed": _value(statistic, "max") is not None,
                },
                "sample": {
                    "sample_rows": sample_row_count,
                    "non_null_count": sampled_non_null,
                    "distinct_count": sampled_ndv,
                    "null_ratio": (
                        round(
                            (sample_row_count - sampled_non_null) / sample_row_count,
                            6,
                        )
                        if sample_row_count and sampled_non_null is not None
                        else None
                    ),
                },
                "risks": risks,
            }
            items.append(item)

        evidence = [
            {
                "source": "information_schema.columns",
                "success": True,
                "rows_observed": len(column_rows),
            },
            {
                "source": "SHOW COLUMN STATS",
                "success": stats_failure is None,
                "rows_observed": len(stats_rows),
                "reason_code": (
                    None if stats_failure is None else stats_failure.reason_code
                ),
            },
        ]
        if applied_ratio > 0:
            evidence.append(
                {
                    "source": "TABLESAMPLE",
                    "success": sample_failure is None and bool(sample_columns),
                    "sample_ratio": applied_ratio,
                    "sample_rows": sample_row_count,
                    "reason_code": (
                        None if sample_failure is None else sample_failure.reason_code
                    ),
                }
            )
        return _result(
            {
                "database": database_name,
                "table": table_name,
                "columns": items,
                "sample_ratio_requested": sample_ratio,
                "sample_ratio_applied": applied_ratio,
                "truncated": len(available) > len(selected),
            },
            source="doris_column_metadata_and_statistics",
            warnings=warnings,
            evidence=evidence,
            metadata={"invented_statistics": False},
        )

    async def analyze_table_storage(
        self,
        *,
        database: str,
        table: str,
        include_partitions: bool,
        include_indexes: bool,
    ) -> dict[str, Any]:
        database_name = _identifier(database, "database name")
        table_name = _identifier(table, "table name")
        table_ref = build_table_reference(
            table_name,
            database_name,
            "internal",
        )
        table_rows = await self._execute(
            (
                "SELECT TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE, "
                "ENGINE, TABLE_ROWS, AVG_ROW_LENGTH, DATA_LENGTH, INDEX_LENGTH, "
                "DATA_FREE, CREATE_TIME, UPDATE_TIME "
                "FROM information_schema.tables "
                "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s LIMIT 2"
            ),
            params=(database_name, table_name),
            max_rows=2,
        )
        if not table_rows:
            raise GovernanceRuntimeFailure(
                "The requested Doris table is unavailable.",
                reason_code="GOVERNANCE_TABLE_NOT_FOUND",
                status_code=404,
            )
        table_row = table_rows[0]
        warnings: list[str] = []
        evidence: list[dict[str, Any]] = [
            {
                "source": "information_schema.tables",
                "success": True,
                "rows_observed": len(table_rows),
            }
        ]

        # SQL sink audit: table_ref contains only strictly validated and quoted
        # identifiers before _optional_execute sends this read-only command.
        table_stats, stats_failure = await self._optional_execute(
            f"SHOW TABLE STATS {table_ref}",  # nosec B608
            max_rows=2,
        )
        _append_optional_evidence(
            evidence,
            warnings,
            source="SHOW TABLE STATS",
            rows=table_stats,
            failure=stats_failure,
        )
        # SQL sink audit: table_ref contains only strictly validated and quoted
        # identifiers before _optional_execute sends this read-only command.
        create_rows, create_failure = await self._optional_execute(
            f"SHOW CREATE TABLE {table_ref}",  # nosec B608
            max_rows=1,
        )
        _append_optional_evidence(
            evidence,
            warnings,
            source="SHOW CREATE TABLE",
            rows=create_rows,
            failure=create_failure,
        )
        create_sql = (
            str(_value(create_rows[0], "create table", "create_table") or "")
            if create_rows
            else ""
        )

        partition_items: list[dict[str, Any]] = []
        partitions_truncated = False
        if include_partitions:
            # SQL sink audit: table_ref is validated and quoted, and the limit
            # is a module constant before _optional_execute reaches the sink.
            partition_rows, partition_failure = await self._optional_execute(
                f"SHOW PARTITIONS FROM {table_ref} LIMIT {_MAX_PARTITIONS}",  # nosec B608
                max_rows=_MAX_PARTITIONS,
            )
            _append_optional_evidence(
                evidence,
                warnings,
                source="SHOW PARTITIONS",
                rows=partition_rows,
                failure=partition_failure,
            )
            partition_items = [_storage_partition(row) for row in partition_rows]
            partitions_truncated = len(partition_rows) >= _MAX_PARTITIONS

        index_items: list[dict[str, Any]] = []
        indexes_truncated = False
        if include_indexes:
            # SQL sink audit: table_ref contains only strictly validated and
            # quoted identifiers before _optional_execute reaches the sink.
            index_rows, index_failure = await self._optional_execute(
                f"SHOW INDEX FROM {table_ref}",  # nosec B608
                max_rows=_MAX_INDEXES,
            )
            _append_optional_evidence(
                evidence,
                warnings,
                source="SHOW INDEX",
                rows=index_rows,
                failure=index_failure,
            )
            index_items = [_storage_index(row) for row in index_rows]
            indexes_truncated = len(index_rows) >= _MAX_INDEXES

        stats_row = table_stats[0] if table_stats else {}
        properties = _safe_create_properties(create_sql)
        data = {
            "database": database_name,
            "table": table_name,
            "table_type": _value(table_row, "table_type"),
            "engine": _value(table_row, "engine"),
            "estimated_rows": _optional_int(_value(table_row, "table_rows")),
            "average_row_length": _optional_int(_value(table_row, "avg_row_length")),
            "data_length_bytes": _optional_int(_value(table_row, "data_length")),
            "index_length_bytes": _optional_int(_value(table_row, "index_length")),
            "data_free_bytes": _optional_int(_value(table_row, "data_free")),
            "created_at": _json_value(_value(table_row, "create_time")),
            "updated_at": _json_value(_value(table_row, "update_time")),
            "statistics": {
                "row_count": _optional_int(_value(stats_row, "row_count")),
                "updated_rows": _optional_int(_value(stats_row, "updated_rows")),
                "query_times": _optional_int(_value(stats_row, "query_times")),
                "last_analyze_time": _json_value(
                    _value(stats_row, "last_analyze_time")
                ),
                "auto_analyze_enabled": _value(
                    stats_row,
                    "enable_auto_analyze",
                ),
            },
            "properties": properties,
            "features": {
                "storage_format": properties.get("storage_format"),
                "compression": properties.get("compression"),
                "merge_on_write": properties.get("enable_unique_key_merge_on_write"),
                "variant": {
                    key: value
                    for key, value in properties.items()
                    if key.startswith("variant_")
                },
            },
            "partitions": partition_items if include_partitions else None,
            "indexes": index_items if include_indexes else None,
            "truncated": partitions_truncated or indexes_truncated,
        }
        return _result(
            data,
            source="doris_storage_metadata",
            warnings=warnings,
            evidence=evidence,
            metadata={
                "raw_create_table_exposed": False,
                "include_partitions": include_partitions,
                "include_indexes": include_indexes,
            },
        )

    async def get_lineage_capability_status(self) -> dict[str, Any]:
        versions, version_evidence, version_warnings = await self._lineage_versions()
        parsed_versions = tuple(version for version in versions if version.is_parsed)
        all_frontends_eligible = (
            bool(versions)
            and len(parsed_versions) == len(versions)
            and all(
                version.is_at_least(_NATIVE_LINEAGE_MINIMUM)
                for version in parsed_versions
            )
        )
        any_frontend_eligible = any(
            version.is_at_least(_NATIVE_LINEAGE_MINIMUM) for version in parsed_versions
        )

        (
            plugin_config,
            plugin_evidence,
            plugin_warnings,
        ) = await self._lineage_plugin_config()
        audit_status, audit_evidence = await self._audit_status()
        provider_status = await self._lineage_provider_status()

        active_plugins = _csv_values(plugin_config.get("activate_lineage_plugin"))
        recent_native_event = provider_status.recent_event_observed
        native_ready = (
            all_frontends_eligible
            and provider_status.queryable
            and bool(active_plugins)
            and recent_native_event
        )
        native_degraded = (
            all_frontends_eligible
            and provider_status.queryable
            and bool(active_plugins)
        )
        if native_ready:
            active_path = "doris_native_event_store"
            capability_status = "available"
        elif native_degraded:
            active_path = "doris_native_event_store"
            capability_status = "degraded"
        elif audit_status["readable"]:
            active_path = "audit_sql_inference"
            capability_status = "degraded" if any_frontend_eligible else "available"
        else:
            active_path = "unavailable"
            capability_status = "unavailable"

        limitations = [
            "Native lineage delivery is asynchronous and best effort.",
            "Doris does not persist lineage events or expose a lineage query API.",
            "Native events cover successful INSERT SELECT, INSERT OVERWRITE "
            "SELECT, and CTAS statements only.",
            "SELECT, UPDATE, DELETE, load jobs, VALUES-only inserts, and writes "
            "to __internal_schema are not covered by native events.",
        ]
        limitations.extend(version_warnings)
        limitations.extend(plugin_warnings)
        limitations.extend(provider_status.limitations)
        if active_path == "audit_sql_inference":
            limitations.append(
                "The active path infers bounded lineage from audit SQL and is "
                "not native column-lineage evidence."
            )

        evidence = [
            *version_evidence,
            *plugin_evidence,
            audit_evidence,
            {
                "source": provider_status.provider_id,
                "success": provider_status.queryable,
                "status": provider_status.status,
                "row_count": provider_status.row_count,
                "latest_event_time": _json_value(provider_status.latest_event_time),
                "recent_event_observed": recent_native_event,
            },
        ]
        return _result(
            {
                "status": capability_status,
                "active_path": active_path,
                "native_spi": {
                    "minimum_version": "4.0.6",
                    "all_frontends_eligible": all_frontends_eligible,
                    "mixed_or_unparsed_frontends": (
                        len(parsed_versions) != len(versions)
                        or len({version.core for version in parsed_versions}) > 1
                    ),
                    "detected_versions": [
                        version.normalized or "unknown" for version in versions
                    ],
                },
                "plugin": {
                    "configured_names": active_plugins,
                    "configuration_observed": bool(plugin_config),
                    "loaded_verified": recent_native_event,
                    "queue_size": _optional_int(
                        plugin_config.get("lineage_event_queue_size")
                    ),
                    "configuration_scope": "connected_frontend",
                },
                "queryable_store": {
                    "provider_id": provider_status.provider_id,
                    "status": provider_status.status,
                    "queryable": provider_status.queryable,
                    "row_count": provider_status.row_count,
                    "latest_event_time": _json_value(provider_status.latest_event_time),
                    "recent_event_observed": recent_native_event,
                },
                "audit_fallback": audit_status,
                "coverage": {
                    "native_supported_statements": [
                        "INSERT INTO ... SELECT",
                        "INSERT OVERWRITE TABLE ... SELECT",
                        "CREATE TABLE AS SELECT",
                    ],
                    "native_excluded_statements": [
                        "SELECT",
                        "UPDATE",
                        "DELETE",
                        "load jobs",
                        "VALUES-only INSERT",
                        "writes to __internal_schema",
                    ],
                    "delivery_guarantee": "asynchronous_best_effort",
                },
                "limitations": list(dict.fromkeys(limitations)),
            },
            source="doris_lineage_capability_evidence",
            warnings=limitations if capability_status != "available" else (),
            evidence=evidence,
            metadata={"invented_lineage_capability": False},
        )

    async def trace_column_lineage(
        self,
        *,
        object_name: str,
        column: str | None,
        direction: str | None,
        depth: int | None,
        evidence_mode: str | None,
    ) -> dict[str, Any]:
        object_parts = _qualified_parts(
            object_name,
            field="lineage object",
            minimum_parts=2,
        )
        canonical_object = _canonical_object(object_parts)
        column_name = _identifier(column, "column name") if column is not None else None
        selected_direction = direction or "both"
        if selected_direction not in {"upstream", "downstream", "both"}:
            raise _argument_failure("Unsupported lineage direction.")
        selected_depth = _bounded_int(
            depth,
            default=3,
            minimum=1,
            maximum=_MAX_LINEAGE_DEPTH,
            field="lineage depth",
        )
        selected_mode = evidence_mode or "auto"
        if selected_mode not in {"auto", "native", "audit"}:
            raise _argument_failure("Unsupported lineage evidence mode.")

        status_result = await self.get_lineage_capability_status()
        capability = status_result["data"]
        active_path = str(capability["active_path"])
        if selected_mode == "native":
            if active_path != "doris_native_event_store":
                raise GovernanceRuntimeFailure(
                    "Native lineage evidence is unavailable.",
                    reason_code="GOVERNANCE_NATIVE_LINEAGE_UNAVAILABLE",
                    status_code=409,
                )
            path = "doris_native_event_store"
        elif selected_mode == "audit":
            if not capability["audit_fallback"]["readable"]:
                raise GovernanceRuntimeFailure(
                    "Audit lineage evidence is unavailable.",
                    reason_code="GOVERNANCE_AUDIT_LINEAGE_UNAVAILABLE",
                    status_code=503,
                    retryable=True,
                )
            path = "audit_sql_inference"
        else:
            path = active_path

        if path == "doris_native_event_store":
            provider = self._lineage_provider
            if provider is None:
                raise GovernanceRuntimeFailure(
                    "Native lineage provider is not configured.",
                    reason_code="GOVERNANCE_LINEAGE_PROVIDER_NOT_CONFIGURED",
                    status_code=503,
                )
            traced = await provider.trace(
                object_name=canonical_object,
                column=column_name,
                direction=selected_direction,
                depth=selected_depth,
                max_edges=self._max_lineage_edges,
            )
            edges = traced["edges"]
            warnings = list(traced.get("limitations", ()))
            evidence = [
                {
                    "source": "doris_native_event_store",
                    "success": True,
                    "rows_observed": traced.get("rows_observed", 0),
                    "edges_returned": len(edges),
                }
            ]
            truncated = bool(traced.get("truncated"))
        elif path == "audit_sql_inference":
            traced = await self._trace_audit_lineage(
                object_name=canonical_object,
                column=column_name,
                direction=selected_direction,
                depth=selected_depth,
            )
            edges = traced["edges"]
            warnings = list(traced["limitations"])
            evidence = [
                {
                    "source": "internal.__internal_schema.audit_log",
                    "success": True,
                    "rows_observed": traced["rows_observed"],
                    "edges_returned": len(edges),
                    "evidence_quality": "inferred",
                }
            ]
            truncated = bool(traced["truncated"])
        else:
            raise GovernanceRuntimeFailure(
                "No queryable lineage evidence source is available.",
                reason_code="GOVERNANCE_LINEAGE_EVIDENCE_UNAVAILABLE",
                status_code=503,
                retryable=True,
            )

        if not edges:
            warnings.append(
                "No qualifying lineage edge was observed; no placeholder edge "
                "was generated."
            )
        return _result(
            {
                "object": canonical_object,
                "column": column_name,
                "direction": selected_direction,
                "depth": selected_depth,
                "evidence_mode": selected_mode,
                "active_path": path,
                "edges": edges,
                "edge_count": len(edges),
                "truncated": truncated,
                "determinate": bool(edges),
                "coverage": capability["coverage"],
            },
            source=path,
            warnings=warnings,
            evidence=evidence,
            metadata={
                "invented_edges": False,
                "numeric_confidence_emitted": False,
            },
        )

    async def analyze_data_access_patterns(
        self,
        *,
        database: str | None,
        table: str | None,
        window_days: int | None,
        group_by: str | None,
    ) -> dict[str, Any]:
        database_name = (
            _identifier(database, "database name") if database is not None else None
        )
        table_name = _identifier(table, "table name") if table is not None else None
        days = _bounded_int(
            window_days,
            default=7,
            minimum=1,
            maximum=self._max_audit_window_days,
            field="audit window",
        )
        grouping = group_by or "object"
        if grouping not in {"user", "object", "hour", "operation"}:
            raise _argument_failure("Unsupported access grouping.")
        rows, audit_metadata = await self._read_audit_rows(
            window_minutes=days * 1440,
            database=database_name,
            user=None,
            row_limit=_MAX_AUDIT_ROWS,
        )

        aggregates: dict[str, dict[str, Any]] = defaultdict(
            lambda: {
                "event_count": 0,
                "error_count": 0,
                "query_time_ms": 0,
                "scan_bytes": 0,
                "scan_rows": 0,
                "return_rows": 0,
            }
        )
        matched_rows = 0
        for row in rows:
            referenced = _audit_referenced_objects(row)
            if table_name is not None and not any(
                _object_matches_table(item, database_name, table_name)
                for item in referenced
            ):
                continue
            operation = _audit_operation(row)
            groups: Sequence[str]
            if grouping == "user":
                groups = (_principal_label(_value(row, "user")),)
            elif grouping == "hour":
                groups = (_hour_bucket(_value(row, "time")),)
            elif grouping == "operation":
                groups = (operation,)
            else:
                groups = tuple(referenced) or (_database_object_label(row),)
            matched_rows += 1
            for key in dict.fromkeys(groups):
                aggregate = aggregates[key]
                aggregate["event_count"] += 1
                if not _audit_success(row):
                    aggregate["error_count"] += 1
                aggregate["query_time_ms"] += (
                    _optional_int(_value(row, "query_time")) or 0
                )
                aggregate["scan_bytes"] += _optional_int(_value(row, "scan_bytes")) or 0
                aggregate["scan_rows"] += _optional_int(_value(row, "scan_rows")) or 0
                aggregate["return_rows"] += (
                    _optional_int(_value(row, "return_rows")) or 0
                )

        items = []
        for key, aggregate in sorted(
            aggregates.items(),
            key=lambda item: (-item[1]["event_count"], item[0]),
        ):
            event_count = aggregate["event_count"]
            items.append(
                {
                    "group": key,
                    **aggregate,
                    "error_rate": round(
                        aggregate["error_count"] / event_count,
                        6,
                    ),
                    "average_query_time_ms": round(
                        aggregate["query_time_ms"] / event_count,
                        3,
                    ),
                }
            )
        truncated = len(rows) >= _MAX_AUDIT_ROWS
        warnings = []
        if truncated:
            warnings.append("Access analysis reached the bounded audit-row limit.")
        return _result(
            {
                "group_by": grouping,
                "window_days": days,
                "database": database_name,
                "table": table_name,
                "items": items,
                "matched_event_count": matched_rows,
                "source_event_count": len(rows),
                "truncated": truncated,
            },
            source="doris_audit_access_history",
            warnings=warnings,
            evidence=[
                {
                    "source": _AUDIT_TABLE,
                    "success": True,
                    "rows_observed": len(rows),
                    "fields": audit_metadata["fields"],
                }
            ],
            metadata={
                "principal_representation": "stable_pseudonym",
                "raw_sql_exposed": False,
            },
        )

    async def get_recent_audit_logs(
        self,
        *,
        window_minutes: int | None,
        user: str | None,
        operation: str | None,
        database: str | None,
        table: str | None,
        limit: int | None,
    ) -> dict[str, Any]:
        maximum_minutes = self._max_audit_window_days * 1440
        minutes = _bounded_int(
            window_minutes,
            default=1440,
            minimum=1,
            maximum=maximum_minutes,
            field="audit window",
        )
        result_limit = _bounded_int(
            limit,
            default=100,
            minimum=1,
            maximum=_MAX_AUDIT_RESULTS,
            field="audit result limit",
        )
        database_name = (
            _identifier(database, "database name") if database is not None else None
        )
        table_name = _identifier(table, "table name") if table is not None else None
        principal = (
            _bounded_text(user, "audit user", maximum=128) if user is not None else None
        )
        requested_operation = (
            _bounded_text(operation, "audit operation", maximum=64).upper()
            if operation is not None
            else None
        )
        fetch_limit = min(
            _MAX_AUDIT_ROWS,
            max(result_limit * 4, result_limit),
        )
        rows, metadata = await self._read_audit_rows(
            window_minutes=minutes,
            database=database_name,
            user=principal,
            row_limit=fetch_limit,
        )
        items: list[dict[str, Any]] = []
        for row in rows:
            observed_operation = _audit_operation(row)
            if (
                requested_operation is not None
                and observed_operation != requested_operation
            ):
                continue
            referenced = _audit_referenced_objects(row)
            if table_name is not None and not any(
                _object_matches_table(item, database_name, table_name)
                for item in referenced
            ):
                continue
            items.append(
                {
                    "event_id": _value(row, "query_id", "stmt_id"),
                    "observed_at": _json_value(_value(row, "time")),
                    "principal": _principal_label(_value(row, "user")),
                    "operation": observed_operation,
                    "catalog": _value(row, "catalog"),
                    "database": _value(row, "db"),
                    "state": _value(row, "state"),
                    "error_code": _optional_int(_value(row, "error_code")),
                    "query_time_ms": _optional_int(_value(row, "query_time")),
                    "scan_bytes": _optional_int(_value(row, "scan_bytes")),
                    "scan_rows": _optional_int(_value(row, "scan_rows")),
                    "return_rows": _optional_int(_value(row, "return_rows")),
                    "referenced_objects": referenced[:32],
                }
            )
            if len(items) >= result_limit:
                break
        truncated = len(items) >= result_limit and len(rows) > len(items)
        return _collection(
            items,
            source="doris_audit_log",
            truncated=truncated,
            metadata={
                "window_minutes": minutes,
                "source_rows_observed": len(rows),
                "fields": metadata["fields"],
                "principal_representation": "stable_pseudonym",
                "raw_sql_exposed": False,
                "client_address_exposed": False,
                "error_message_exposed": False,
            },
        )

    async def list_udfs(
        self,
        *,
        database: str | None,
        language: str | None,
        name_pattern: str | None,
    ) -> dict[str, Any]:
        database_name = (
            _identifier(database, "database name")
            if database is not None
            else await self._current_database()
        )
        language_filter = (
            _bounded_text(language, "UDF language", maximum=32).casefold()
            if language is not None
            else None
        )
        pattern = (
            _bounded_text(name_pattern, "UDF name pattern", maximum=128)
            if name_pattern is not None
            else None
        )
        if database_name is not None:
            quoted_database = quote_identifier(
                database_name,
                "database name",
            )
            # SQL sink audit: quoted_database is a strictly validated identifier
            # before _execute sends this read-only SHOW command.
            statement = f"SHOW FULL FUNCTIONS IN {quoted_database}"  # nosec B608
            scope = database_name
        else:
            statement = "SHOW GLOBAL FULL FUNCTIONS"
            scope = "global"
        rows = await self._execute(statement, max_rows=_MAX_UDFS)
        items: list[dict[str, Any]] = []
        for row in rows:
            udf = _udf_item(row, scope=scope)
            if udf is None:
                continue
            if language_filter is not None and (
                str(udf["language"]).casefold() != language_filter
            ):
                continue
            if pattern is not None and not _matches_name_pattern(
                str(udf["name"]),
                pattern,
            ):
                continue
            items.append(udf)
        return _collection(
            items,
            source="SHOW FULL FUNCTIONS",
            truncated=len(rows) >= _MAX_UDFS,
            metadata={
                "scope": scope,
                "code_loaded": False,
                "code_executed": False,
                "raw_object_location_exposed": False,
            },
        )

    async def get_auth_mapping_status(
        self,
        *,
        principal: str | None,
        provider: str | None,
        include_roles: bool,
    ) -> dict[str, Any]:
        selected_provider = provider
        if selected_provider is not None and selected_provider not in {
            "ldap",
            "oidc",
        }:
            raise _argument_failure("Unsupported authentication provider.")
        principal_filter = (
            _bounded_text(
                principal,
                "principal",
                maximum=128,
            )
            if principal is not None
            else None
        )
        provider_names = (
            (selected_provider,) if selected_provider is not None else ("ldap", "oidc")
        )
        providers: list[dict[str, Any]] = []
        warnings: list[str] = []
        evidence: list[dict[str, Any]] = []

        if "ldap" in provider_names:
            ldap_config, ldap_evidence, ldap_warnings = await self._ldap_status()
            providers.append(ldap_config)
            evidence.extend(ldap_evidence)
            warnings.extend(ldap_warnings)

        if "oidc" in provider_names:
            role_rows, role_failure = await self._optional_execute(
                "SELECT * FROM information_schema.role_mappings LIMIT 500",
                max_rows=500,
            )
            evidence.append(
                {
                    "source": "information_schema.role_mappings",
                    "success": role_failure is None,
                    "rows_observed": len(role_rows),
                    "reason_code": (
                        None if role_failure is None else role_failure.reason_code
                    ),
                }
            )
            if role_failure is not None:
                warnings.append(
                    "OIDC role-mapping metadata is unavailable "
                    f"({role_failure.reason_code})."
                )
            mappings = []
            for row in role_rows:
                mapping = _safe_role_mapping(row)
                raw_principal = _role_mapping_principal(row)
                if (
                    principal_filter is not None
                    and raw_principal is not None
                    and raw_principal != principal_filter
                ):
                    continue
                if principal_filter is not None and raw_principal is None:
                    continue
                mappings.append(mapping)
            providers.append(
                {
                    "provider": "oidc",
                    "status": (
                        "configured"
                        if role_rows
                        else ("not_configured" if role_failure is None else "unknown")
                    ),
                    "mapping_count": len(mappings),
                    "mappings": mappings,
                    "minimum_role_mapping_version": "4.1.2",
                }
            )

        roles: list[dict[str, Any]] | None = None
        if include_roles:
            role_rows, role_failure = await self._optional_execute(
                "SHOW ROLES",
                max_rows=500,
            )
            evidence.append(
                {
                    "source": "SHOW ROLES",
                    "success": role_failure is None,
                    "rows_observed": len(role_rows),
                    "reason_code": (
                        None if role_failure is None else role_failure.reason_code
                    ),
                }
            )
            if role_failure is not None:
                warnings.append(
                    f"Authorized role metadata is unavailable ({role_failure.reason_code})."
                )
            roles = [
                {
                    "name": _value(row, "name", "role"),
                    "assigned_principal_count": _listed_value_count(
                        _value(row, "users")
                    ),
                }
                for row in role_rows
                if _value(row, "name", "role") is not None
            ]

        return _result(
            {
                "providers": providers,
                "principal_filter": (
                    _principal_label(principal_filter)
                    if principal_filter is not None
                    else None
                ),
                "roles": roles,
                "secrets_exposed": False,
                "mapping_rules_exposed": False,
            },
            source="doris_authentication_mapping_metadata",
            warnings=warnings,
            evidence=evidence,
            metadata={
                "principal_representation": "stable_pseudonym",
                "raw_configuration_exposed": False,
            },
        )

    async def _trace_audit_lineage(
        self,
        *,
        object_name: str,
        column: str | None,
        direction: str,
        depth: int,
    ) -> dict[str, Any]:
        rows, _ = await self._read_audit_rows(
            window_minutes=self._max_audit_window_days * 1440,
            database=None,
            user=None,
            row_limit=_MAX_AUDIT_ROWS,
        )
        inferred: list[dict[str, Any]] = []
        for row in rows:
            inferred.extend(_audit_lineage_edges(row, column=column))
        edges, truncated = _traverse_edges(
            inferred,
            object_name=object_name,
            direction=direction,
            depth=depth,
            max_edges=self._max_lineage_edges,
        )
        limitations = [
            "Audit SQL inference is bounded and may omit statements outside "
            "the configured history window.",
            "Audit-derived edges are inferred and are never labeled as native.",
        ]
        if column is not None:
            limitations.append(
                "Column edges are emitted only for simple direct INSERT SELECT "
                "mappings with explicit target columns."
            )
        return {
            "edges": edges,
            "truncated": truncated or len(rows) >= _MAX_AUDIT_ROWS,
            "rows_observed": len(rows),
            "limitations": limitations,
        }

    async def _lineage_provider_status(self) -> LineageProviderStatus:
        if self._lineage_provider is None:
            return LineageProviderStatus(
                provider_id="doris_native_event_store",
                status="not_configured",
                queryable=False,
                limitations=(
                    "No queryable lineage event-store provider is configured.",
                ),
            )
        return await self._lineage_provider.status()

    async def _lineage_versions(
        self,
    ) -> tuple[
        list[DorisVersion],
        list[dict[str, Any]],
        list[str],
    ]:
        versions: list[DorisVersion] = []
        evidence: list[dict[str, Any]] = []
        warnings: list[str] = []
        version_rows, version_failure = await self._optional_execute(
            "SELECT @@version_comment;",
            max_rows=1,
        )
        if version_failure is None and version_rows:
            raw = _value(version_rows[0], "@@version_comment", "version_comment")
            if isinstance(raw, str):
                versions.append(parse_doris_version_comment(raw))
        evidence.append(
            {
                "source": "SELECT @@version_comment",
                "success": version_failure is None and bool(versions),
                "rows_observed": len(version_rows),
                "reason_code": (
                    None if version_failure is None else version_failure.reason_code
                ),
            }
        )

        frontend_rows, frontend_failure = await self._optional_execute(
            "SHOW FRONTENDS",
            max_rows=128,
        )
        frontend_versions = []
        for row in frontend_rows:
            raw = _value(
                row,
                "version",
                "version_comment",
                "fe_version",
            )
            if isinstance(raw, str):
                frontend_versions.append(parse_doris_version_comment(raw))
        if frontend_versions:
            versions = frontend_versions
        evidence.append(
            {
                "source": "SHOW FRONTENDS",
                "success": frontend_failure is None,
                "rows_observed": len(frontend_rows),
                "versions_observed": len(frontend_versions),
                "reason_code": (
                    None if frontend_failure is None else frontend_failure.reason_code
                ),
            }
        )
        if frontend_failure is not None:
            warnings.append(
                "Cluster-wide FE version coverage is unavailable "
                f"({frontend_failure.reason_code})."
            )
        if not versions:
            warnings.append("No parseable Doris FE version was observed.")
        return versions, evidence, warnings

    async def _lineage_plugin_config(
        self,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
        values: dict[str, Any] = {}
        evidence: list[dict[str, Any]] = []
        warnings: list[str] = []
        for key in (
            "activate_lineage_plugin",
            "lineage_event_queue_size",
        ):
            # SQL sink audit: key comes exclusively from the fixed tuple above
            # before _optional_execute sends this read-only SHOW command.
            rows, failure = await self._optional_execute(
                f"SHOW FRONTEND CONFIG LIKE '{key}'",  # nosec B608
                max_rows=4,
            )
            if rows:
                values[key] = _value(rows[0], "value")
            evidence.append(
                {
                    "source": f"SHOW FRONTEND CONFIG:{key}",
                    "success": failure is None,
                    "rows_observed": len(rows),
                    "reason_code": (None if failure is None else failure.reason_code),
                }
            )
            if failure is not None:
                warnings.append(
                    f"Frontend lineage configuration {key} is unavailable "
                    f"({failure.reason_code})."
                )
        return values, evidence, warnings

    async def _audit_status(
        self,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        # SQL sink audit: _AUDIT_TABLE is a module-owned constant and the
        # statement has no user values before _optional_execute reaches the sink.
        rows, failure = await self._optional_execute(
            (
                "SELECT `time`, `query_id` "
                f"FROM {_AUDIT_TABLE} ORDER BY `time` DESC LIMIT 1"  # nosec B608
            ),
            max_rows=1,
        )
        return (
            {
                "readable": failure is None,
                "status": ("available" if failure is None else "unavailable"),
                "recent_event_observed": bool(rows),
                "evidence_quality": "inferred",
            },
            {
                "source": _AUDIT_TABLE,
                "success": failure is None,
                "rows_observed": len(rows),
                "reason_code": (None if failure is None else failure.reason_code),
            },
        )

    async def _read_audit_rows(
        self,
        *,
        window_minutes: int,
        database: str | None,
        user: str | None,
        row_limit: int,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        schema_rows = await self._execute(
            f"DESC {_AUDIT_TABLE}",
            max_rows=256,
        )
        available = {
            str(_value(row, "field", "column_name", "name")).casefold()
            for row in schema_rows
            if _value(row, "field", "column_name", "name") is not None
        }
        selected = tuple(field for field in _AUDIT_FIELD_ORDER if field in available)
        if "time" not in selected:
            raise GovernanceRuntimeFailure(
                "Doris audit metadata does not expose an event time.",
                reason_code="GOVERNANCE_AUDIT_SCHEMA_UNSUPPORTED",
                status_code=503,
            )
        select_list = ", ".join(quote_identifier(field) for field in selected)
        predicates = ["`time` >= DATE_SUB(NOW(), INTERVAL %s MINUTE)"]
        params: list[Any] = [window_minutes]
        if database is not None and "db" in selected:
            predicates.append("`db` = %s")
            params.append(database)
        if user is not None and "user" in selected:
            predicates.append("`user` = %s")
            params.append(user)
        bounded_limit = min(max(1, row_limit), _MAX_AUDIT_ROWS)
        # SQL sink audit: selected fields and predicates come from fixed
        # allowlists, values remain bound, and _execute receives a bounded limit.
        sql = (
            f"SELECT {select_list} FROM {_AUDIT_TABLE} "  # nosec B608
            f"WHERE {' AND '.join(predicates)} "
            f"ORDER BY `time` DESC LIMIT {bounded_limit}"
        )
        rows = await self._execute(
            sql,
            params=tuple(params),
            max_rows=bounded_limit,
        )
        return rows, {"fields": list(selected)}

    async def _ldap_status(
        self,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
        observed: dict[str, Any] = {}
        evidence: list[dict[str, Any]] = []
        warnings: list[str] = []
        for key in (
            "authentication_type",
            "ldap_authentication_enabled",
            "ldap_use_ssl",
            "ldap_default_roles",
        ):
            # SQL sink audit: key comes exclusively from the fixed tuple above
            # before _optional_execute sends this read-only SHOW command.
            rows, failure = await self._optional_execute(
                f"SHOW FRONTEND CONFIG LIKE '{key}'",  # nosec B608
                max_rows=4,
            )
            if rows:
                observed[key] = _value(rows[0], "value")
            evidence.append(
                {
                    "source": f"SHOW FRONTEND CONFIG:{key}",
                    "success": failure is None,
                    "rows_observed": len(rows),
                    "reason_code": (None if failure is None else failure.reason_code),
                }
            )
            if failure is not None:
                warnings.append(
                    f"LDAP configuration {key} is unavailable ({failure.reason_code})."
                )
        authentication_type = str(observed.get("authentication_type", "")).casefold()
        enabled_value = str(observed.get("ldap_authentication_enabled", "")).casefold()
        configured = authentication_type == "ldap" or enabled_value in {
            "true",
            "1",
            "yes",
            "on",
        }
        return (
            {
                "provider": "ldap",
                "status": "configured" if configured else "not_configured",
                "tls_enabled": str(observed.get("ldap_use_ssl", "")).casefold()
                in {"true", "1", "yes", "on"},
                "default_roles": _csv_values(observed.get("ldap_default_roles")),
                "group_mapping_mode": "ldap_group_name_to_doris_role_name",
                "configuration_scope": "connected_frontend",
            },
            evidence,
            warnings,
        )

    async def _current_database(self) -> str | None:
        rows = await self._execute(
            "SELECT DATABASE() AS database_name",
            max_rows=1,
        )
        value = _value(rows[0], "database_name") if rows else None
        if value is None:
            return None
        return _identifier(str(value), "database name")

    async def _optional_execute(
        self,
        sql: str,
        *,
        params: Mapping[str, Any] | tuple[Any, ...] | None = None,
        max_rows: int,
    ) -> tuple[list[dict[str, Any]], GovernanceRuntimeFailure | None]:
        try:
            return await self._execute(
                sql,
                params=params,
                max_rows=max_rows,
            ), None
        except GovernanceRuntimeFailure as exc:
            return [], exc

    async def _execute(
        self,
        sql: str,
        *,
        params: Mapping[str, Any] | tuple[Any, ...] | None = None,
        max_rows: int,
    ) -> list[dict[str, Any]]:
        auth_context = get_current_auth_context()
        session_id = f"{self._session_prefix}:{uuid.uuid4().hex[:8]}"
        try:
            async with self._connection_manager.get_connection_context_for_auth_context(
                session_id,
                auth_context,
            ) as connection:
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
        return [dict(row) for row in (result.data or ()) if isinstance(row, Mapping)][
            :max_rows
        ]


def _result(
    data: Mapping[str, Any],
    *,
    source: str,
    warnings: Sequence[str] = (),
    evidence: Sequence[Mapping[str, Any]],
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    unique_warnings = list(dict.fromkeys(str(item) for item in warnings))
    return {
        "status": "partial" if unique_warnings else "success",
        "data": redact_sensitive_data(dict(data)),
        "warnings": unique_warnings,
        "metadata": {
            "source": source,
            **dict(metadata or {}),
        },
        "evidence": [redact_sensitive_data(dict(item)) for item in evidence],
    }


def _collection(
    items: Sequence[Mapping[str, Any]],
    *,
    source: str,
    warnings: Sequence[str] = (),
    truncated: bool,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    unique_warnings = list(dict.fromkeys(str(item) for item in warnings))
    return {
        "status": "partial" if unique_warnings else "success",
        "data": {
            "items": [redact_sensitive_data(dict(item)) for item in items],
            "next_cursor": None,
            "truncated": truncated,
        },
        "warnings": unique_warnings,
        "metadata": {
            "source": source,
            **dict(metadata or {}),
        },
    }


def _identifier(value: Any, field: str) -> str:
    try:
        return validate_identifier(value, field)
    except (SQLSecurityError, TypeError) as exc:
        raise _argument_failure(f"Invalid {field}.") from exc


def _qualified_parts(
    value: Any,
    *,
    field: str,
    minimum_parts: int,
) -> tuple[str, ...]:
    if not isinstance(value, str):
        raise _argument_failure(f"Invalid {field}.")
    raw_parts = [part.strip().strip("`") for part in value.split(".")]
    if not minimum_parts <= len(raw_parts) <= 3:
        raise _argument_failure(
            f"{field.capitalize()} must contain two or three identifiers."
        )
    return tuple(_identifier(part, field) for part in raw_parts)


def _table_reference(parts: Sequence[str]) -> str:
    if len(parts) == 2:
        return build_table_reference(parts[1], parts[0])
    return build_table_reference(parts[2], parts[1], parts[0])


def _canonical_object(parts: Sequence[str]) -> str:
    if len(parts) == 2:
        return f"internal.{parts[0]}.{parts[1]}"
    return ".".join(parts)


def _bounded_text(value: Any, field: str, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise _argument_failure(f"{field.capitalize()} must be a string.")
    normalized = value.strip()
    if not normalized or len(normalized) > maximum:
        raise _argument_failure(
            f"{field.capitalize()} must contain 1-{maximum} characters."
        )
    if any(character in normalized for character in ("\x00", "\r", "\n")):
        raise _argument_failure(f"{field.capitalize()} contains control characters.")
    return normalized


def _bounded_int(
    value: Any,
    *,
    default: int,
    minimum: int,
    maximum: int,
    field: str,
) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise _argument_failure(f"{field.capitalize()} must be an integer.")
    if not minimum <= value <= maximum:
        raise _argument_failure(
            f"{field.capitalize()} must be between {minimum} and {maximum}."
        )
    return int(value)


def _sample_ratio(value: Any, *, maximum: float) -> float:
    if value is None:
        return 0.0
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise _argument_failure("Sample ratio must be numeric.")
    normalized = float(value)
    if not 0 <= normalized <= 1:
        raise _argument_failure("Sample ratio must be between 0 and 1.")
    return min(normalized, maximum)


def _argument_failure(message: str) -> GovernanceRuntimeFailure:
    return GovernanceRuntimeFailure(
        message,
        reason_code="GOVERNANCE_ARGUMENT_INVALID",
        status_code=400,
    )


def _classify_failure(error: Exception) -> GovernanceRuntimeFailure:
    if isinstance(error, GovernanceRuntimeFailure):
        return error
    if isinstance(error, SQLSecurityError):
        return _argument_failure("Governance arguments are invalid.")
    error_code = next(
        (item for item in getattr(error, "args", ()) if isinstance(item, int)),
        None,
    )
    if error_code in {1044, 1045, 1142, 1227}:
        return GovernanceRuntimeFailure(
            "Doris denied access to the requested governance evidence.",
            reason_code="GOVERNANCE_PERMISSION_DENIED",
            status_code=403,
        )
    if error_code in {1049, 1054, 1064, 1109, 1146, 1305}:
        return GovernanceRuntimeFailure(
            "The requested Doris governance evidence is unsupported.",
            reason_code="GOVERNANCE_EVIDENCE_UNSUPPORTED",
            status_code=503,
        )
    if isinstance(error, ConnectionError | TimeoutError):
        return GovernanceRuntimeFailure(
            "Doris governance evidence is temporarily unavailable.",
            reason_code="GOVERNANCE_CONNECTION_FAILED",
            status_code=503,
            retryable=True,
        )
    return GovernanceRuntimeFailure(
        "Doris governance evidence execution failed.",
        reason_code="GOVERNANCE_EXECUTION_FAILED",
        status_code=502,
    )


def _value(row: Mapping[str, Any], *names: str) -> Any:
    normalized = {
        str(key).strip().casefold().replace(" ", "_"): value
        for key, value in row.items()
    }
    for name in names:
        key = name.strip().casefold().replace(" ", "_")
        if key in normalized:
            return normalized[key]
    return None


def _json_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError, OverflowError):
        return None


def _optional_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _is_complex_type(data_type: str) -> bool:
    upper = data_type.upper()
    return any(marker in upper for marker in _COMPLEX_TYPE_MARKERS)


def _safe_create_properties(create_sql: str) -> dict[str, str]:
    properties: dict[str, str] = {}
    for key, value in re.findall(
        r'["\']([A-Za-z_][A-Za-z0-9_]*)["\']\s*=\s*["\']([^"\']*)["\']',
        create_sql,
    ):
        normalized = key.casefold()
        if normalized in _SAFE_CREATE_PROPERTY_KEYS:
            properties[normalized] = value
    return properties


def _storage_partition(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "name": _value(row, "partitionname", "partition_name"),
        "id": _value(row, "partitionid", "partition_id"),
        "state": _value(row, "state"),
        "visible_version": _value(row, "visibleversion", "visible_version"),
        "visible_version_time": _json_value(
            _value(row, "visibleversiontime", "visible_version_time")
        ),
        "distribution_key": _value(
            row,
            "distributionkey",
            "distribution_key",
        ),
        "buckets": _optional_int(_value(row, "buckets")),
        "replication_allocation": _value(
            row,
            "replicationallocation",
            "replication_allocation",
        ),
        "data_size": _value(row, "datasize", "data_size"),
        "row_count": _optional_int(_value(row, "rowcount", "row_count")),
    }


def _storage_index(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "name": _value(row, "key_name", "index_name", "name"),
        "column": _value(row, "column_name", "columns"),
        "type": _value(row, "index_type", "type"),
        "visible": _value(row, "visible"),
    }


def _append_optional_evidence(
    evidence: list[dict[str, Any]],
    warnings: list[str],
    *,
    source: str,
    rows: Sequence[Mapping[str, Any]],
    failure: GovernanceRuntimeFailure | None,
) -> None:
    evidence.append(
        {
            "source": source,
            "success": failure is None,
            "rows_observed": len(rows),
            "reason_code": None if failure is None else failure.reason_code,
        }
    )
    if failure is not None:
        warnings.append(
            f"Optional {source} evidence is unavailable ({failure.reason_code})."
        )


def _csv_values(value: Any) -> list[str]:
    if value is None:
        return []
    return [item.strip() for item in str(value).split(",") if item.strip()][:64]


def _native_lineage_edge(
    row: Mapping[str, Any],
    *,
    level: int,
) -> dict[str, Any] | None:
    source = _value(row, "source_object")
    target = _value(row, "target_object")
    event_id = _value(row, "event_id")
    if not all(isinstance(item, str) and item for item in (source, target)):
        return None
    return {
        "source_object": source,
        "source_column": _value(row, "source_column"),
        "target_object": target,
        "target_column": _value(row, "target_column"),
        "dependency_type": (_value(row, "dependency_type") or "unspecified"),
        "statement_type": _value(row, "statement_type"),
        "depth": level,
        "evidence_type": "native_event",
        "source_event_id": event_id,
        "query_id": _value(row, "query_id"),
        "observed_at": _json_value(_value(row, "event_time")),
        "coverage": {
            "level": (
                "column"
                if _value(row, "source_column", "target_column") is not None
                else "table"
            ),
            "delivery": "asynchronous_best_effort",
        },
        "limitations": [
            "Native events cover only supported successful DML statements."
        ],
    }


def _audit_lineage_edges(
    row: Mapping[str, Any],
    *,
    column: str | None,
) -> list[dict[str, Any]]:
    if not _audit_success(row):
        return []
    statement = _value(row, "stmt")
    if not isinstance(statement, str) or not statement.strip():
        return []
    normalized_sql = sqlparse.format(
        statement,
        strip_comments=True,
        keyword_case="upper",
    ).strip()
    target_match = _WRITE_TARGET.search(normalized_sql)
    if target_match is None:
        return []
    default_catalog = str(_value(row, "catalog") or "internal")
    default_database = _value(row, "db")
    target = _normalize_sql_object(
        target_match.group(1),
        default_catalog=default_catalog,
        default_database=(
            str(default_database) if default_database is not None else None
        ),
    )
    if target is None:
        return []
    event_id = _value(row, "query_id", "stmt_id")
    observed_at = _json_value(_value(row, "time"))
    statement_type = _audit_operation(row)

    if column is not None:
        direct = _simple_direct_column_edges(
            normalized_sql,
            target=target,
            column=column,
            default_catalog=default_catalog,
            default_database=(
                str(default_database) if default_database is not None else None
            ),
            event_id=event_id,
            observed_at=observed_at,
            statement_type=statement_type,
        )
        return direct

    sources = _audit_referenced_objects(row)
    if not sources:
        sources = tuple(
            item
            for match in _SOURCE_REFERENCE.finditer(normalized_sql)
            if (
                item := _normalize_sql_object(
                    match.group(1),
                    default_catalog=default_catalog,
                    default_database=(
                        str(default_database) if default_database is not None else None
                    ),
                )
            )
        )
    edges = []
    for source in dict.fromkeys(sources):
        if source == target:
            continue
        edges.append(
            {
                "source_object": source,
                "source_column": None,
                "target_object": target,
                "target_column": None,
                "dependency_type": "table_dependency",
                "statement_type": statement_type,
                "depth": 1,
                "evidence_type": "audit_sql_inference",
                "source_event_id": event_id,
                "query_id": _value(row, "query_id"),
                "observed_at": observed_at,
                "coverage": {
                    "level": "table",
                    "derivation": (
                        "recorded_queried_tables"
                        if _value(row, "queried_tables_and_views") is not None
                        else "bounded_sql_parse"
                    ),
                },
                "limitations": ["This edge is inferred from bounded audit evidence."],
            }
        )
    return edges


def _simple_direct_column_edges(
    statement: str,
    *,
    target: str,
    column: str,
    default_catalog: str,
    default_database: str | None,
    event_id: Any,
    observed_at: Any,
    statement_type: str,
) -> list[dict[str, Any]]:
    match = _SIMPLE_INSERT_SELECT.search(statement)
    if match is None:
        return []
    tail = match.group("tail")
    if re.search(r"\b(?:JOIN|UNION|GROUP\s+BY|WINDOW)\b", tail, re.IGNORECASE):
        return []
    parsed_target = _normalize_sql_object(
        match.group("target"),
        default_catalog=default_catalog,
        default_database=default_database,
    )
    if parsed_target != target:
        return []
    source = _normalize_sql_object(
        match.group("source"),
        default_catalog=default_catalog,
        default_database=default_database,
    )
    if source is None:
        return []
    target_columns = [
        _strip_identifier(item) for item in match.group("target_columns").split(",")
    ]
    select_expressions = [
        item.strip() for item in match.group("select_list").split(",")
    ]
    if len(target_columns) != len(select_expressions):
        return []
    edges = []
    for target_column, expression in zip(
        target_columns,
        select_expressions,
        strict=True,
    ):
        if target_column != column:
            continue
        direct_match = re.fullmatch(
            rf"\s*(?:{_SIMPLE_IDENTIFIER}\s*\.\s*)?"
            rf"(?P<column>{_SIMPLE_IDENTIFIER})"
            rf"(?:\s+AS\s+{_SIMPLE_IDENTIFIER})?\s*",
            expression,
            re.IGNORECASE,
        )
        if direct_match is None:
            continue
        source_column = _strip_identifier(direct_match.group("column"))
        edges.append(
            {
                "source_object": source,
                "source_column": source_column,
                "target_object": target,
                "target_column": target_column,
                "dependency_type": "direct",
                "statement_type": statement_type,
                "depth": 1,
                "evidence_type": "audit_sql_inference",
                "source_event_id": event_id,
                "query_id": event_id,
                "observed_at": observed_at,
                "coverage": {
                    "level": "column_direct",
                    "derivation": "simple_explicit_insert_projection",
                },
                "limitations": [
                    "This direct mapping is inferred from a simple audited "
                    "INSERT SELECT projection."
                ],
            }
        )
    return edges


def _traverse_edges(
    edges: Sequence[Mapping[str, Any]],
    *,
    object_name: str,
    direction: str,
    depth: int,
    max_edges: int,
) -> tuple[list[dict[str, Any]], bool]:
    frontier = {object_name}
    visited = {object_name}
    selected: list[dict[str, Any]] = []
    selected_keys: set[tuple[Any, ...]] = set()
    for level in range(1, depth + 1):
        next_frontier: set[str] = set()
        for raw in edges:
            source = raw.get("source_object")
            target = raw.get("target_object")
            include = False
            if direction in {"upstream", "both"} and target in frontier:
                include = True
                if isinstance(source, str):
                    next_frontier.add(source)
            if direction in {"downstream", "both"} and source in frontier:
                include = True
                if isinstance(target, str):
                    next_frontier.add(target)
            if not include:
                continue
            key = (
                source,
                raw.get("source_column"),
                target,
                raw.get("target_column"),
                raw.get("source_event_id"),
            )
            if key in selected_keys:
                continue
            selected_keys.add(key)
            item = dict(raw)
            item["depth"] = level
            selected.append(item)
            if len(selected) >= max_edges:
                return selected, True
        frontier = next_frontier - visited
        visited.update(frontier)
        if not frontier:
            break
    return selected, False


def _audit_success(row: Mapping[str, Any]) -> bool:
    state = str(_value(row, "state") or "").strip().casefold()
    error_code = _optional_int(_value(row, "error_code"))
    return state in {"", "ok", "success", "finished"} and (
        error_code is None or error_code == 0
    )


def _audit_operation(row: Mapping[str, Any]) -> str:
    statement_type = _value(row, "stmt_type")
    if isinstance(statement_type, str) and statement_type.strip():
        return statement_type.strip().upper()
    statement = _value(row, "stmt")
    if not isinstance(statement, str):
        return "UNKNOWN"
    formatted = str(sqlparse.format(statement, strip_comments=True)).strip()
    if not formatted:
        return "UNKNOWN"
    upper = formatted.upper()
    if upper.startswith("INSERT OVERWRITE"):
        return "INSERT_OVERWRITE"
    if upper.startswith("CREATE TABLE") and re.search(
        r"\bAS\s+SELECT\b",
        upper,
    ):
        return "CTAS"
    return formatted.split(None, 1)[0].upper()


def _audit_referenced_objects(row: Mapping[str, Any]) -> tuple[str, ...]:
    raw = _value(row, "queried_tables_and_views")
    values: Sequence[Any] = ()
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = [item.strip() for item in raw.split(",") if item.strip()]
        if isinstance(parsed, list):
            values = parsed
    elif isinstance(raw, Sequence) and not isinstance(raw, bytes):
        values = raw
    normalized = []
    default_catalog = str(_value(row, "catalog") or "internal")
    database = _value(row, "db")
    for item in values:
        if not isinstance(item, str):
            continue
        object_name = _normalize_sql_object(
            item,
            default_catalog=default_catalog,
            default_database=(str(database) if database is not None else None),
        )
        if object_name is not None:
            normalized.append(object_name)
    if normalized:
        return tuple(dict.fromkeys(normalized))

    statement = _value(row, "stmt")
    if not isinstance(statement, str):
        return ()
    clean = sqlparse.format(statement, strip_comments=True)
    for match in _SOURCE_REFERENCE.finditer(clean):
        object_name = _normalize_sql_object(
            match.group(1),
            default_catalog=default_catalog,
            default_database=(str(database) if database is not None else None),
        )
        if object_name is not None:
            normalized.append(object_name)
    return tuple(dict.fromkeys(normalized))


def _normalize_sql_object(
    value: str,
    *,
    default_catalog: str,
    default_database: str | None,
) -> str | None:
    cleaned = re.sub(r"\s+", "", value)
    parts = [_strip_identifier(part) for part in cleaned.split(".")]
    try:
        validated = tuple(validate_identifier(part, "lineage object") for part in parts)
    except SQLSecurityError:
        return None
    if len(validated) == 3:
        return ".".join(validated)
    if len(validated) == 2:
        return f"{default_catalog}.{validated[0]}.{validated[1]}"
    if len(validated) == 1 and default_database:
        return f"{default_catalog}.{default_database}.{validated[0]}"
    return None


def _strip_identifier(value: str) -> str:
    return value.strip().strip("`")


def _principal_label(value: Any) -> str:
    normalized = str(value or "unknown")
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:12]
    return f"principal:{digest}"


def _hour_bucket(value: Any) -> str:
    if isinstance(value, datetime):
        return value.replace(minute=0, second=0, microsecond=0).isoformat()
    text = str(value or "")
    return text[:13] + ":00:00" if len(text) >= 13 else "unknown"


def _database_object_label(row: Mapping[str, Any]) -> str:
    catalog = str(_value(row, "catalog") or "internal")
    database = str(_value(row, "db") or "unknown")
    return f"{catalog}.{database}.*"


def _object_matches_table(
    object_name: str,
    database: str | None,
    table: str,
) -> bool:
    parts = object_name.split(".")
    if not parts or parts[-1].casefold() != table.casefold():
        return False
    return (
        database is None
        or len(parts) < 2
        or parts[-2].casefold() == database.casefold()
    )


def _safe_url_type(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    parsed = urlsplit(value)
    suffix = parsed.path.rsplit(".", 1)[-1].casefold()
    return suffix if suffix in {"jar", "so", "py", "zip"} else None


def _parse_properties(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return {str(key).casefold(): item for key, item in value.items()}
    if not isinstance(value, str) or not value.strip():
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, Mapping):
        return {str(key).casefold(): item for key, item in parsed.items()}
    return {
        key.casefold(): item
        for key, item in re.findall(
            r'["\']?([A-Za-z_][A-Za-z0-9_]*)["\']?\s*'
            r'[:=]\s*["\']?([^,"\'}]+)',
            value,
        )
    }


def _udf_item(
    row: Mapping[str, Any],
    *,
    scope: str,
) -> dict[str, Any] | None:
    signature = _value(row, "signature", "function_name", "name")
    if not isinstance(signature, str) or not signature.strip():
        return None
    properties = _parse_properties(_value(row, "properties"))
    declared_type = str(
        properties.get("type") or _value(row, "function_type") or ""
    ).upper()
    object_type = _safe_url_type(
        properties.get("object_file") or properties.get("file")
    )
    if "PYTHON" in declared_type or object_type == "py":
        language = "python"
    elif "JAVA" in declared_type or object_type == "jar":
        language = "java"
    elif object_type == "so":
        language = "native"
    elif str(_value(row, "function_type") or "").casefold() == "alias":
        language = "sql_alias"
    else:
        language = "unknown"
    name = signature.split("(", 1)[0].strip()
    return {
        "name": name,
        "signature": signature,
        "scope": scope,
        "language": language,
        "function_type": _value(row, "function_type"),
        "return_type": _value(row, "return_type"),
        "intermediate_type": _value(row, "intermediate_type"),
        "runtime_version": properties.get("runtime_version"),
        "volatility": properties.get("volatility"),
        "always_nullable": properties.get("always_nullable"),
        "status": "registered",
    }


def _matches_name_pattern(name: str, pattern: str) -> bool:
    shell_pattern = pattern.replace("%", "*").replace("_", "?")
    return fnmatch.fnmatchcase(name.casefold(), shell_pattern.casefold())


def _safe_role_mapping(row: Mapping[str, Any]) -> dict[str, Any]:
    principal = _role_mapping_principal(row)
    roles = _csv_values(
        _value(
            row,
            "roles",
            "role_names",
            "target_roles",
            "role",
        )
    )
    return {
        "name": _value(
            row,
            "name",
            "mapping_name",
            "rule_name",
            "id",
        ),
        "principal": (_principal_label(principal) if principal is not None else None),
        "roles": roles,
        "enabled": _value(row, "enabled", "is_enabled", "active"),
        "status": _value(row, "status", "state") or "configured",
        "rule_redacted": True,
    }


def _role_mapping_principal(row: Mapping[str, Any]) -> str | None:
    value = _value(
        row,
        "principal",
        "subject",
        "user",
        "username",
        "claim_value",
    )
    return str(value) if value is not None else None


def _listed_value_count(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, Sequence) and not isinstance(value, str | bytes):
        return len(value)
    text = str(value).strip()
    if not text:
        return 0
    return len([item for item in text.split(",") if item.strip()])
