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

"""Bounded, read-only runtime for external lakehouse and Variant evidence."""

from __future__ import annotations

import json
import re
import uuid
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from datetime import date, datetime
from typing import Any

from ..tools.doris_version import (
    DORIS_VERSION_COMMENT_QUERY,
    DorisVersion,
    parse_doris_version_comment,
)
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
_DEFAULT_CATALOG_OBJECTS = 50
_DEFAULT_CATALOG_DATABASES = 20
_DEFAULT_SNAPSHOTS = 50
_DEFAULT_PARTITIONS = 100
_DEFAULT_VARIANT_SAMPLE_ROWS = 20
_DEFAULT_VARIANT_PATHS = 200
_ABSOLUTE_CATALOG_OBJECTS = 500
_ABSOLUTE_CATALOG_DATABASES = 100
_ABSOLUTE_SNAPSHOTS = 500
_ABSOLUTE_PARTITIONS = 1_000
_ABSOLUTE_VARIANT_SAMPLE_ROWS = 500
_ABSOLUTE_VARIANT_PATHS = 2_000
_MAX_COLUMNS = 1_000
_MAX_PROPERTY_KEYS = 128
_MAX_TYPED_PATHS = 256
_DORIS_4_1 = parse_doris_version_comment("Doris version doris-4.1.0")
_LAKEHOUSE_FORMATS = frozenset({"iceberg", "hudi", "paimon", "delta"})
_SNAPSHOT_SYSTEM_TABLE_FORMATS = frozenset({"iceberg", "paimon"})
_SYSTEM_TABLE_SUFFIXES = frozenset({"snapshots", "partitions"})
_SENSITIVE_PROPERTY_PARTS = (
    "password",
    "secret",
    "token",
    "credential",
    "keytab",
    "access_key",
    "secret_key",
    "private_key",
    "jdbc_url",
    "endpoint",
    "uri",
)
_SAFE_VARIANT_PROPERTIES = frozenset(
    {
        "storage_format",
        "variant_doc_hash_shard_count",
        "variant_doc_materialization_min_rows",
        "variant_enable_doc_mode",
        "variant_enable_typed_paths_to_sparse",
        "variant_flatten_nested",
        "variant_max_sparse_column_statistics_size",
        "variant_max_subcolumns_count",
        "variant_sparse_hash_shard_count",
    }
)
_CATALOG_CAPABILITIES: Mapping[str, tuple[str, ...]] = {
    "iceberg": (
        "metadata_discovery",
        "partition_pruning",
        "predicate_pushdown",
        "snapshots",
        "system_tables",
        "time_travel",
    ),
    "paimon": (
        "incremental_read",
        "metadata_discovery",
        "partition_pruning",
        "predicate_pushdown",
        "snapshots",
        "system_tables",
        "time_travel",
    ),
    "hudi": (
        "incremental_read",
        "metadata_discovery",
        "partition_pruning",
        "predicate_pushdown",
        "time_travel",
    ),
    "hms": (
        "metadata_discovery",
        "partition_pruning",
        "predicate_pushdown",
    ),
    "hive": (
        "metadata_discovery",
        "partition_pruning",
        "predicate_pushdown",
    ),
    "delta": (
        "metadata_discovery",
        "partition_pruning",
        "predicate_pushdown",
        "time_travel",
    ),
    "jdbc": ("metadata_discovery", "predicate_pushdown"),
    "es": ("metadata_discovery", "predicate_pushdown"),
}
_SIMPLE_PATH_SEGMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,254}")
_VARIANT_PROPERTY = re.compile(
    r"""(?P<key>storage_format|variant_[a-z0-9_]+)
        ["']?\s*=\s*["'](?P<value>[^"']{0,256})["']""",
    re.IGNORECASE | re.VERBOSE,
)
_TYPED_PATH = re.compile(
    r"""["'](?P<path>[^"']{1,255})["']\s*:\s*
        (?P<type>[A-Za-z][A-Za-z0-9_]*(?:\s*\([^)]*\))?)""",
    re.VERBOSE,
)


class LakehouseRuntimeFailure(RuntimeError):
    """Sanitized failure carrying a stable Lakehouse reason code."""

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


class DorisLakehouseRuntime:
    """Inspect external lakehouse metadata without exposing source secrets."""

    def __init__(self, connection_manager: DorisConnectionManager) -> None:
        self._connection_manager = connection_manager
        config = getattr(
            getattr(connection_manager, "config", None),
            "lakehouse",
            None,
        )
        self._max_catalog_objects = _configured_limit(
            getattr(config, "max_catalog_objects", None),
            default=_DEFAULT_CATALOG_OBJECTS,
            absolute=_ABSOLUTE_CATALOG_OBJECTS,
        )
        self._max_catalog_databases = _configured_limit(
            getattr(config, "max_catalog_databases", None),
            default=_DEFAULT_CATALOG_DATABASES,
            absolute=_ABSOLUTE_CATALOG_DATABASES,
        )
        self._max_snapshots = _configured_limit(
            getattr(config, "max_snapshots", None),
            default=_DEFAULT_SNAPSHOTS,
            absolute=_ABSOLUTE_SNAPSHOTS,
        )
        self._max_partitions = _configured_limit(
            getattr(config, "max_partitions", None),
            default=_DEFAULT_PARTITIONS,
            absolute=_ABSOLUTE_PARTITIONS,
        )
        self._max_variant_sample_rows = _configured_limit(
            getattr(config, "max_variant_sample_rows", None),
            default=_DEFAULT_VARIANT_SAMPLE_ROWS,
            absolute=_ABSOLUTE_VARIANT_SAMPLE_ROWS,
        )
        self._max_variant_paths = _configured_limit(
            getattr(config, "max_variant_paths", None),
            default=_DEFAULT_VARIANT_PATHS,
            absolute=_ABSOLUTE_VARIANT_PATHS,
        )
        self._session_prefix = f"lakehouse_{uuid.uuid4().hex[:8]}"

    async def inspect_external_catalog(
        self,
        *,
        catalog: str,
        include_objects: bool = False,
        object_limit: int | None = None,
    ) -> dict[str, Any]:
        """Return sanitized catalog metadata and an optional bounded sample."""
        catalog_name = _identifier(catalog, "catalog name")
        limit = _bounded_int(
            object_limit,
            default=min(_DEFAULT_CATALOG_OBJECTS, self._max_catalog_objects),
            maximum=self._max_catalog_objects,
            field="object limit",
        )
        (
            catalog_item,
            properties,
            evidence,
            catalog_warning,
        ) = await self._external_catalog(catalog_name)
        catalog_type = _canonical_catalog_type(catalog_item.get("type"))
        warnings = [catalog_warning] if catalog_warning else []
        object_sample: dict[str, Any] = {
            "databases": [],
            "relations": [],
            "truncated": False,
        }
        if include_objects:
            object_sample, object_evidence, object_warnings = (
                await self._catalog_object_sample(
                    catalog_name,
                    relation_limit=limit,
                )
            )
            evidence.extend(object_evidence)
            warnings.extend(object_warnings)

        property_summary = _catalog_property_summary(properties)
        data = {
            "catalog": catalog_name,
            "scope": "external",
            "reported_type": catalog_type,
            "visibility": "visible_to_caller",
            "is_current": _as_bool(catalog_item.get("is_current")),
            "created_at": _json_value(catalog_item.get("create_time")),
            "last_updated_at": _json_value(
                catalog_item.get("last_update_time")
            ),
            "declared_capabilities": list(
                _CATALOG_CAPABILITIES.get(
                    catalog_type,
                    ("metadata_discovery",),
                )
            ),
            "capability_evidence_quality": "inferred_from_reported_type",
            "configuration": property_summary,
            "object_sample": object_sample,
        }
        return _result(
            data,
            source="SHOW CATALOGS + SHOW CATALOG",
            warnings=warnings,
            evidence=evidence,
            metadata={
                "property_values_returned": False,
                "object_limit": limit,
            },
        )

    async def inspect_lakehouse_table(
        self,
        *,
        catalog: str,
        database: str,
        table: str,
        include_snapshots: bool = False,
        include_partitions: bool = False,
    ) -> dict[str, Any]:
        """Inspect one external table with format-specific recorded evidence."""
        catalog_name = _identifier(catalog, "catalog name")
        database_name = _identifier(database, "database name")
        table_name = _identifier(table, "table name")
        (
            catalog_item,
            properties,
            evidence,
            catalog_warning,
        ) = await self._external_catalog(catalog_name)
        del properties
        warnings = [catalog_warning] if catalog_warning else []
        relation = build_table_reference(
            table_name,
            database_name,
            catalog_name,
        )
        # SQL sink audit: relation contains only strictly validated and quoted
        # identifiers before _execute sends this read-only metadata command.
        columns = await self._execute(
            f"SHOW FULL COLUMNS FROM {relation}",  # nosec B608
            max_rows=_MAX_COLUMNS,
        )
        if not columns:
            raise LakehouseRuntimeFailure(
                "The requested external table is unavailable.",
                reason_code="LAKEHOUSE_TABLE_NOT_FOUND",
                status_code=404,
            )
        evidence.append(
            _evidence("SHOW FULL COLUMNS", success=True, rows=len(columns))
        )

        # SQL sink audit: relation contains only strictly validated and quoted
        # identifiers before _optional_execute reaches the read-only SQL sink.
        create_rows, create_failure = await self._optional_execute(
            f"SHOW CREATE TABLE {relation}",  # nosec B608
            max_rows=1,
        )
        create_sql = _create_statement(create_rows)
        evidence.append(
            _evidence(
                "SHOW CREATE TABLE",
                success=create_failure is None,
                rows=len(create_rows),
                failure=create_failure,
            )
        )
        if create_failure is not None:
            warnings.append(
                "External table DDL metadata is unavailable; format evidence "
                "is limited to the catalog provider."
            )

        catalog_type = _canonical_catalog_type(catalog_item.get("type"))
        table_format = _infer_table_format(catalog_type, create_sql)
        if table_format not in _LAKEHOUSE_FORMATS:
            raise LakehouseRuntimeFailure(
                "The requested table is not exposed as a supported lakehouse format.",
                reason_code="LAKEHOUSE_TABLE_FORMAT_UNSUPPORTED",
                status_code=409,
            )

        stats, stats_failure = await self._table_statistics(relation)
        evidence.append(
            _evidence(
                "SHOW TABLE STATS",
                success=stats_failure is None,
                rows=1 if stats else 0,
                failure=stats_failure,
            )
        )
        if stats_failure is not None:
            warnings.append("External table statistics are unavailable.")

        snapshots: list[dict[str, Any]] = []
        snapshots_truncated = False
        if include_snapshots:
            (
                snapshots,
                snapshots_truncated,
                snapshot_evidence,
                snapshot_warning,
            ) = await self._snapshot_metadata(
                catalog_name,
                database_name,
                table_name,
                table_format,
            )
            evidence.append(snapshot_evidence)
            if snapshot_warning:
                warnings.append(snapshot_warning)

        partitions: list[dict[str, Any]] = []
        partitions_truncated = False
        if include_partitions:
            (
                partitions,
                partitions_truncated,
                partition_evidence,
                partition_warning,
            ) = await self._partition_metadata(
                catalog_name,
                database_name,
                table_name,
                table_format,
            )
            evidence.append(partition_evidence)
            if partition_warning:
                warnings.append(partition_warning)

        plan_facets, plan_evidence, plan_warning = await self._plan_facets(
            relation
        )
        evidence.append(plan_evidence)
        if plan_warning:
            warnings.append(plan_warning)
        version = await self._version()
        lifecycle = _lifecycle_capabilities(
            version,
            table_format,
            columns,
            snapshots,
        )
        if not plan_facets["predicate_pushdown_observed"]:
            warnings.append(
                "The metadata-only probe has no caller predicate and therefore "
                "does not prove filter pushdown for a business query."
            )

        data = {
            "catalog": catalog_name,
            "database": database_name,
            "table": table_name,
            "format": table_format,
            "format_evidence_quality": (
                "reported"
                if catalog_type in _LAKEHOUSE_FORMATS
                else "inferred_from_sanitized_ddl"
            ),
            "columns": [_column_item(row) for row in columns],
            "column_count": len(columns),
            "partition_columns": _partition_columns(create_sql),
            "statistics": stats,
            "snapshots": {
                "items": snapshots,
                "truncated": snapshots_truncated,
                "supported_for_format": (
                    table_format in _SNAPSHOT_SYSTEM_TABLE_FORMATS
                ),
            },
            "partitions": {
                "items": partitions,
                "truncated": partitions_truncated,
            },
            "pushdown": plan_facets,
            "lifecycle": lifecycle,
        }
        return _result(
            data,
            source="external catalog metadata",
            warnings=warnings,
            evidence=evidence,
            metadata={
                "raw_ddl_returned": False,
                "raw_plan_returned": False,
                "storage_locations_returned": False,
            },
        )

    async def inspect_variant_column(
        self,
        *,
        catalog: str | None,
        database: str,
        table: str,
        column: str,
        path: str | None = None,
        sample_rows: int | None = None,
    ) -> dict[str, Any]:
        """Inspect Variant configuration and sampled type shape without values."""
        catalog_name = (
            _identifier(catalog, "catalog name")
            if catalog is not None
            else "internal"
        )
        database_name = _identifier(database, "database name")
        table_name = _identifier(table, "table name")
        column_name = _identifier(column, "column name")
        sample_limit = _bounded_int(
            sample_rows,
            default=min(
                _DEFAULT_VARIANT_SAMPLE_ROWS,
                self._max_variant_sample_rows,
            ),
            maximum=self._max_variant_sample_rows,
            field="sample rows",
        )
        path_segments = _variant_path(path)
        relation = build_table_reference(
            table_name,
            database_name,
            None if catalog_name == "internal" else catalog_name,
        )
        # SQL sink audit: relation contains only strictly validated and quoted
        # identifiers before _execute sends this read-only metadata command.
        columns = await self._execute(
            f"SHOW FULL COLUMNS FROM {relation}",  # nosec B608
            max_rows=_MAX_COLUMNS,
        )
        target = next(
            (
                row
                for row in columns
                if str(_value(row, "field", "column_name") or "") == column_name
            ),
            None,
        )
        if target is None:
            raise LakehouseRuntimeFailure(
                "The requested Variant column is unavailable.",
                reason_code="LAKEHOUSE_VARIANT_COLUMN_NOT_FOUND",
                status_code=404,
            )
        declared_type = str(_value(target, "type", "data_type") or "")
        if not declared_type.upper().startswith("VARIANT"):
            raise LakehouseRuntimeFailure(
                "The requested column is not a Doris Variant column.",
                reason_code="LAKEHOUSE_COLUMN_NOT_VARIANT",
                status_code=409,
            )

        # SQL sink audit: relation contains only strictly validated and quoted
        # identifiers before _optional_execute reaches the read-only SQL sink.
        create_rows, create_failure = await self._optional_execute(
            f"SHOW CREATE TABLE {relation}",  # nosec B608
            max_rows=1,
        )
        create_sql = _create_statement(create_rows)
        properties = _variant_properties(f"{declared_type}\n{create_sql}")
        configuration, configuration_warnings = _variant_configuration(
            properties
        )

        column_ref = quote_identifier(column_name, "column name")
        expression = column_ref
        params: list[Any] = []
        for segment in path_segments:
            expression += "[%s]"
            params.append(segment)
        # SQL sink audit: relation and column are validated/quoted, every path
        # segment remains driver-bound, and _execute receives a bounded limit.
        sample_sql = (
            f"SELECT VARIANT_TYPE({expression}) AS `variant_type` "  # nosec B608
            f"FROM {relation} WHERE {column_ref} IS NOT NULL "
            f"LIMIT {sample_limit}"
        )
        sample_result, sample_failure = await self._optional_execute(
            sample_sql,
            params=tuple(params),
            max_rows=sample_limit,
        )
        warnings = list(configuration_warnings)
        if create_failure is not None:
            warnings.append(
                "Table DDL is unavailable; Variant mode properties may be incomplete."
            )
        if sample_failure is not None:
            warnings.append(
                "Bounded VARIANT_TYPE sampling is unavailable; no row values "
                "or inferred path shapes were returned."
            )
        observed_paths, paths_truncated = _variant_type_observations(
            sample_result,
            requested_path=path,
            maximum=self._max_variant_paths,
        )
        version = await self._version()
        advanced = _variant_advanced_capabilities(version, configuration)
        typed_paths = _typed_paths(declared_type)
        if len(typed_paths) >= _MAX_TYPED_PATHS:
            warnings.append(
                f"Typed Variant path metadata was limited to {_MAX_TYPED_PATHS} paths."
            )
        if paths_truncated:
            warnings.append(
                f"Observed Variant paths were limited to {self._max_variant_paths}."
            )

        evidence = [
            _evidence("SHOW FULL COLUMNS", success=True, rows=len(columns)),
            _evidence(
                "SHOW CREATE TABLE",
                success=create_failure is None,
                rows=len(create_rows),
                failure=create_failure,
            ),
            _evidence(
                "VARIANT_TYPE bounded sample",
                success=sample_failure is None,
                rows=len(sample_result),
                failure=sample_failure,
            ),
        ]
        data = {
            "catalog": catalog_name,
            "database": database_name,
            "table": table_name,
            "column": column_name,
            "declared_type": declared_type,
            "nullable": str(_value(target, "null") or "").upper() == "YES",
            "requested_path": path,
            "typed_paths": typed_paths,
            "configuration": configuration,
            "advanced_capabilities": advanced,
            "shape_sample": {
                "rows_observed": len(sample_result),
                "paths": observed_paths,
                "truncated": paths_truncated,
            },
        }
        return _result(
            data,
            source="SHOW FULL COLUMNS + VARIANT_TYPE",
            warnings=warnings,
            evidence=evidence,
            metadata={
                "sample_limit": sample_limit,
                "sampled_values_returned": False,
                "raw_ddl_returned": False,
            },
        )

    async def _external_catalog(
        self,
        catalog_name: str,
    ) -> tuple[
        dict[str, Any],
        dict[str, Any],
        list[dict[str, Any]],
        str | None,
    ]:
        rows = await self._execute("SHOW CATALOGS", max_rows=1_000)
        catalog_item = next(
            (
                _catalog_item(row)
                for row in rows
                if str(_value(row, "catalogname", "catalog_name") or "")
                == catalog_name
            ),
            None,
        )
        if catalog_item is None:
            raise LakehouseRuntimeFailure(
                "The requested external catalog is unavailable.",
                reason_code="LAKEHOUSE_CATALOG_NOT_FOUND",
                status_code=404,
            )
        if catalog_name == "internal":
            raise LakehouseRuntimeFailure(
                "The internal Doris catalog is not an external catalog.",
                reason_code="LAKEHOUSE_CATALOG_NOT_EXTERNAL",
                status_code=409,
            )
        catalog_ref = quote_identifier(catalog_name, "catalog name")
        # SQL sink audit: catalog_ref is a strictly validated and quoted
        # identifier before _optional_execute sends this read-only command.
        property_rows, property_failure = await self._optional_execute(
            f"SHOW CATALOG {catalog_ref}",  # nosec B608
            max_rows=1_000,
        )
        properties = {
            str(key).strip().casefold(): value
            for row in property_rows
            if (key := _value(row, "key", "property", "name")) is not None
            for value in (_value(row, "value", "property_value"),)
        }
        return (
            catalog_item,
            properties,
            [
                _evidence("SHOW CATALOGS", success=True, rows=len(rows)),
                _evidence(
                    "SHOW CATALOG",
                    success=property_failure is None,
                    rows=len(property_rows),
                    failure=property_failure,
                ),
            ],
            (
                None
                if property_failure is None
                else "External catalog configuration metadata is unavailable."
            ),
        )

    async def _catalog_object_sample(
        self,
        catalog_name: str,
        *,
        relation_limit: int,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
        catalog_ref = quote_identifier(catalog_name, "catalog name")
        # SQL sink audit: catalog_ref is a strictly validated and quoted
        # identifier before _optional_execute sends this read-only command.
        database_rows, database_failure = await self._optional_execute(
            f"SHOW DATABASES FROM {catalog_ref}",  # nosec B608
            max_rows=self._max_catalog_databases + 1,
        )
        if database_failure is not None:
            return (
                {
                    "databases": [],
                    "relations": [],
                    "truncated": False,
                },
                [
                    _evidence(
                        "SHOW DATABASES",
                        success=False,
                        rows=0,
                        failure=database_failure,
                    )
                ],
                ["Catalog database metadata is unavailable."],
            )
        database_names: list[str] = []
        unaddressable_databases = 0
        for row in database_rows:
            value = _first_value(row)
            if value is None:
                continue
            try:
                database_names.append(
                    _identifier(str(value), "database name")
                )
            except LakehouseRuntimeFailure:
                unaddressable_databases += 1
        databases_truncated = len(database_names) > self._max_catalog_databases
        database_names = database_names[: self._max_catalog_databases]
        relations: list[dict[str, Any]] = []
        warnings: list[str] = []
        if unaddressable_databases:
            warnings.append(
                f"{unaddressable_databases} catalog database names were not "
                "addressable under the strict identifier policy."
            )
        evidence = [
            _evidence(
                "SHOW DATABASES",
                success=True,
                rows=len(database_rows),
            )
        ]
        for database_name in database_names:
            if len(relations) >= relation_limit:
                break
            scope = (
                f"{quote_identifier(catalog_name, 'catalog name')}."
                f"{quote_identifier(database_name, 'database name')}"
            )
            # SQL sink audit: scope contains only strictly validated and quoted
            # identifiers before _optional_execute reaches the read-only sink.
            rows, failure = await self._optional_execute(
                f"SHOW FULL TABLES FROM {scope}",  # nosec B608
                max_rows=(relation_limit - len(relations)) + 1,
            )
            evidence.append(
                _evidence(
                    "SHOW FULL TABLES",
                    success=failure is None,
                    rows=len(rows),
                    failure=failure,
                )
            )
            if failure is not None:
                warnings.append(
                    f"Relation metadata is unavailable for database {database_name}."
                )
                continue
            for row in rows:
                if len(relations) >= relation_limit:
                    break
                name = _table_name(row)
                if name is None:
                    continue
                relations.append(
                    {
                        "database": database_name,
                        "name": name,
                        "type": _table_type(row),
                    }
                )
        truncated = (
            databases_truncated
            or bool(unaddressable_databases)
            or len(relations) >= relation_limit
        )
        return (
            {
                "databases": [{"name": name} for name in database_names],
                "relations": relations,
                "truncated": truncated,
            },
            evidence,
            warnings,
        )

    async def _snapshot_metadata(
        self,
        catalog: str,
        database: str,
        table: str,
        table_format: str,
    ) -> tuple[
        list[dict[str, Any]],
        bool,
        dict[str, Any],
        str | None,
    ]:
        if table_format not in _SNAPSHOT_SYSTEM_TABLE_FORMATS:
            return (
                [],
                False,
                _evidence(
                    "format system table",
                    success=False,
                    rows=0,
                    reason_code="SNAPSHOT_SYSTEM_TABLE_NOT_SUPPORTED",
                ),
                f"Snapshot system-table inspection is not defined for {table_format}.",
            )
        reference = _system_table_reference(
            catalog,
            database,
            table,
            "snapshots",
        )
        # SQL sink audit: reference is assembled from validated/quoted user
        # identifiers plus a fixed suffix before _optional_execute reaches Doris.
        rows, failure = await self._optional_execute(
            f"SELECT * FROM {reference} LIMIT {self._max_snapshots + 1}",  # nosec B608
            max_rows=self._max_snapshots + 1,
        )
        if failure is not None:
            return (
                [],
                False,
                _evidence(
                    f"{table_format} snapshots system table",
                    success=False,
                    rows=0,
                    failure=failure,
                ),
                "Snapshot metadata is unavailable for the requested table.",
            )
        truncated = len(rows) > self._max_snapshots
        return (
            [_snapshot_item(row) for row in rows[: self._max_snapshots]],
            truncated,
            _evidence(
                f"{table_format} snapshots system table",
                success=True,
                rows=len(rows),
            ),
            None,
        )

    async def _partition_metadata(
        self,
        catalog: str,
        database: str,
        table: str,
        table_format: str,
    ) -> tuple[
        list[dict[str, Any]],
        bool,
        dict[str, Any],
        str | None,
    ]:
        relation = build_table_reference(table, database, catalog)
        # SQL sink audit: relation contains only validated and quoted identifiers,
        # and the integer limit is bounded before _optional_execute reaches Doris.
        rows, failure = await self._optional_execute(
            f"SHOW PARTITIONS FROM {relation} LIMIT {self._max_partitions + 1}",  # nosec B608
            max_rows=self._max_partitions + 1,
        )
        source = "SHOW PARTITIONS"
        if failure is not None and table_format in _SNAPSHOT_SYSTEM_TABLE_FORMATS:
            reference = _system_table_reference(
                catalog,
                database,
                table,
                "partitions",
            )
            # SQL sink audit: reference is assembled from validated/quoted user
            # identifiers plus a fixed suffix and a bounded integer limit.
            rows, failure = await self._optional_execute(
                f"SELECT * FROM {reference} LIMIT {self._max_partitions + 1}",  # nosec B608
                max_rows=self._max_partitions + 1,
            )
            source = f"{table_format} partitions system table"
        if failure is not None:
            return (
                [],
                False,
                _evidence(
                    source,
                    success=False,
                    rows=0,
                    failure=failure,
                ),
                "Partition metadata is unavailable for the requested table.",
            )
        truncated = len(rows) > self._max_partitions
        return (
            [_partition_item(row) for row in rows[: self._max_partitions]],
            truncated,
            _evidence(source, success=True, rows=len(rows)),
            None,
        )

    async def _table_statistics(
        self,
        relation: str,
    ) -> tuple[dict[str, Any], LakehouseRuntimeFailure | None]:
        # SQL sink audit: relation contains only strictly validated and quoted
        # identifiers before _optional_execute reaches the read-only SQL sink.
        rows, failure = await self._optional_execute(
            f"SHOW TABLE STATS {relation}",  # nosec B608
            max_rows=2,
        )
        if not rows:
            return {}, failure
        row = rows[0]
        return (
            {
                "row_count": _number(
                    _value(row, "row_count", "rowcount", "rows")
                ),
                "data_size_bytes": _number(
                    _value(
                        row,
                        "data_size",
                        "data_length",
                        "datasize",
                    )
                ),
                "updated_at": _json_value(
                    _value(row, "update_time", "updated_at")
                ),
            },
            failure,
        )

    async def _plan_facets(
        self,
        relation: str,
    ) -> tuple[dict[str, Any], dict[str, Any], str | None]:
        # SQL sink audit: relation contains only strictly validated and quoted
        # identifiers before _optional_execute reaches this read-only EXPLAIN.
        rows, failure = await self._optional_execute(
            f"EXPLAIN SELECT * FROM {relation} LIMIT 1",  # nosec B608
            max_rows=512,
        )
        if failure is not None:
            return (
                {
                    "external_scan_observed": False,
                    "partition_pruning_observed": False,
                    "predicate_pushdown_observed": False,
                    "scan_nodes": [],
                },
                _evidence(
                    "EXPLAIN",
                    success=False,
                    rows=0,
                    failure=failure,
                ),
                "External scan plan evidence is unavailable.",
            )
        plan = "\n".join(
            str(value)
            for row in rows
            for value in row.values()
            if value is not None
        )
        upper = plan.upper()
        scan_nodes = sorted(
            {
                marker
                for marker in (
                    "HIVE_SCAN_NODE",
                    "ICEBERG_SCAN_NODE",
                    "HUDI_SCAN_NODE",
                    "PAIMON_SCAN_NODE",
                    "JDBC_SCAN_NODE",
                    "ES_SCAN_NODE",
                    "FILE_SCAN_NODE",
                    "VOlapScanNode",
                )
                if marker.upper() in upper
            }
        )
        return (
            {
                "external_scan_observed": bool(scan_nodes)
                or "EXTERNAL" in upper,
                "partition_pruning_observed": any(
                    marker in upper
                    for marker in (
                        "PARTITION PREDICATES",
                        "PARTITIONS=",
                        "PARTITION PRUNING",
                    )
                ),
                "predicate_pushdown_observed": any(
                    marker in upper
                    for marker in (
                        "PUSHDOWN",
                        "PREDICATES:",
                        "PUSH DOWN",
                    )
                ),
                "scan_nodes": scan_nodes,
            },
            _evidence("EXPLAIN", success=True, rows=len(rows)),
            None,
        )

    async def _version(self) -> DorisVersion:
        rows, failure = await self._optional_execute(
            DORIS_VERSION_COMMENT_QUERY,
            max_rows=1,
        )
        if failure is not None or not rows:
            return parse_doris_version_comment("")
        value = _value(
            rows[0],
            "version_comment",
            "@@version_comment",
        )
        return parse_doris_version_comment(
            str(value) if value is not None else ""
        )

    async def _optional_execute(
        self,
        sql: str,
        *,
        params: Mapping[str, Any] | tuple[Any, ...] | None = None,
        max_rows: int,
    ) -> tuple[list[dict[str, Any]], LakehouseRuntimeFailure | None]:
        try:
            return (
                await self._execute(
                    sql,
                    params=params,
                    max_rows=max_rows,
                ),
                None,
            )
        except LakehouseRuntimeFailure as exc:
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
    warnings: Sequence[str],
    evidence: Sequence[Mapping[str, Any]],
    metadata: Mapping[str, Any],
) -> dict[str, Any]:
    unique_warnings = list(dict.fromkeys(str(item) for item in warnings))
    return {
        "status": "partial" if unique_warnings else "success",
        "data": redact_sensitive_data(dict(data)),
        "warnings": unique_warnings,
        "metadata": {
            "source": source,
            **dict(metadata),
        },
        "evidence": [
            redact_sensitive_data(dict(item))
            for item in evidence
        ],
    }


def _evidence(
    source: str,
    *,
    success: bool,
    rows: int,
    failure: LakehouseRuntimeFailure | None = None,
    reason_code: str | None = None,
) -> dict[str, Any]:
    return {
        "source": source,
        "success": success,
        "rows_observed": rows,
        "reason_code": (
            reason_code
            if reason_code is not None
            else (None if failure is None else failure.reason_code)
        ),
    }


def _identifier(value: Any, field: str) -> str:
    try:
        return validate_identifier(value, field)
    except (SQLSecurityError, TypeError) as exc:
        raise _argument_failure(f"Invalid {field}.") from exc


def _bounded_int(
    value: Any,
    *,
    default: int,
    maximum: int,
    field: str,
) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise _argument_failure(f"{field.capitalize()} must be an integer.")
    if not 1 <= value <= maximum:
        raise _argument_failure(
            f"{field.capitalize()} must be between 1 and {maximum}."
        )
    return int(value)


def _configured_limit(value: Any, *, default: int, absolute: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return value if 1 <= value <= absolute else default


def _variant_path(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, str):
        raise _argument_failure("Variant path must be a string.")
    normalized = value.strip()
    if not normalized or len(normalized) > 1_024:
        raise _argument_failure(
            "Variant path must contain 1-1024 characters."
        )
    if normalized == "$":
        return ()
    if normalized.startswith("$."):
        normalized = normalized[2:]
    elif normalized.startswith("$"):
        raise _argument_failure(
            "Variant path must use simple $.segment notation."
        )
    parts = normalized.split(".")
    if not 1 <= len(parts) <= 16 or any(
        _SIMPLE_PATH_SEGMENT.fullmatch(part) is None for part in parts
    ):
        raise _argument_failure(
            "Variant path must contain 1-16 simple dot-separated segments."
        )
    return tuple(parts)


def _system_table_reference(
    catalog: str,
    database: str,
    table: str,
    suffix: str,
) -> str:
    catalog_name = _identifier(catalog, "catalog name")
    database_name = _identifier(database, "database name")
    table_name = _identifier(table, "table name")
    if suffix not in _SYSTEM_TABLE_SUFFIXES:
        raise _argument_failure("Unsupported lakehouse system-table suffix.")
    system_table = f"`{table_name}${suffix}`"
    return (
        f"{quote_identifier(catalog_name, 'catalog name')}."
        f"{quote_identifier(database_name, 'database name')}."
        f"{system_table}"
    )


def _catalog_item(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "name": _value(row, "catalogname", "catalog_name"),
        "type": _value(row, "type", "catalog_type"),
        "is_current": _value(row, "iscurrent", "is_current"),
        "create_time": _value(row, "createtime", "create_time"),
        "last_update_time": _value(
            row,
            "lastupdatetime",
            "last_update_time",
        ),
        "comment": _value(row, "comment"),
    }


def _catalog_property_summary(
    properties: Mapping[str, Any],
) -> dict[str, Any]:
    safe_keys = sorted(
        key
        for key in properties
        if not _sensitive_property(key)
    )[:_MAX_PROPERTY_KEYS]
    redacted_count = sum(
        1 for key in properties if _sensitive_property(key)
    )
    cache_keys = (
        "use_meta_cache",
        "metadata_cache_enabled",
        "enable_meta_cache",
    )
    refresh_keys = (
        "metadata_refresh_interval_sec",
        "refresh_interval_sec",
    )
    return {
        "property_count": len(properties),
        "property_keys": safe_keys,
        "property_keys_truncated": len(safe_keys)
        < (len(properties) - redacted_count),
        "sensitive_property_count": redacted_count,
        "property_values_returned": False,
        "metadata_cache_configured": any(
            key in properties for key in cache_keys
        ),
        "refresh_interval_configured": any(
            key in properties for key in refresh_keys
        ),
        "warehouse_configured": any(
            key in properties
            for key in (
                "warehouse",
                "warehouse_location",
                "iceberg.catalog.warehouse",
            )
        ),
    }


def _sensitive_property(key: str) -> bool:
    normalized = key.casefold().replace(".", "_").replace("-", "_")
    return any(part in normalized for part in _SENSITIVE_PROPERTY_PARTS)


def _canonical_catalog_type(value: Any) -> str:
    normalized = (
        str(value or "unknown")
        .strip()
        .casefold()
        .replace("-", "_")
        .replace(" ", "_")
    )
    aliases = {
        "iceberg_catalog": "iceberg",
        "paimon_catalog": "paimon",
        "hudi_catalog": "hudi",
        "hive": "hms",
        "deltalake": "delta",
        "delta_lake": "delta",
        "elasticsearch": "es",
    }
    return aliases.get(normalized, normalized)


def _infer_table_format(catalog_type: str, create_sql: str) -> str:
    if catalog_type in _LAKEHOUSE_FORMATS:
        return catalog_type
    upper = create_sql.upper()
    for marker, name in (
        ("ICEBERG", "iceberg"),
        ("PAIMON", "paimon"),
        ("HUDI", "hudi"),
        ("DELTA", "delta"),
    ):
        if marker in upper:
            return name
    return "unknown"


def _column_item(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "name": _json_value(_value(row, "field", "column_name")),
        "type": _json_value(_value(row, "type", "data_type")),
        "nullable": str(_value(row, "null") or "").upper() == "YES",
        "key": _json_value(_value(row, "key")),
        "comment": _bounded_output(_value(row, "comment"), 512),
    }


def _create_statement(rows: Sequence[Mapping[str, Any]]) -> str:
    if not rows:
        return ""
    row = rows[0]
    value = _value(row, "create table", "create_table", "create view")
    if value is None:
        values = list(row.values())
        value = values[-1] if values else ""
    return str(value or "")


def _partition_columns(create_sql: str) -> list[str]:
    match = re.search(
        r"\bPARTITIONED?\s+BY\s*\((?P<columns>[^)]*)\)",
        create_sql,
        re.IGNORECASE | re.DOTALL,
    )
    if match is None:
        return []
    columns: list[str] = []
    for item in match.group("columns").split(","):
        raw = item.strip().strip("`").split()[0] if item.strip() else ""
        try:
            name = validate_identifier(raw, "partition column")
        except SQLSecurityError:
            continue
        columns.append(name)
    return columns[:128]


def _snapshot_item(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "snapshot_id": _json_value(
            _value(row, "snapshot_id", "snapshotid", "id")
        ),
        "parent_id": _json_value(
            _value(row, "parent_id", "parent_snapshot_id")
        ),
        "schema_id": _json_value(_value(row, "schema_id")),
        "committed_at": _json_value(
            _value(
                row,
                "commit_time",
                "committed_at",
                "timestamp",
                "timestamp_ms",
            )
        ),
        "operation": _bounded_output(
            _value(row, "operation", "commit_kind", "kind"),
            64,
        ),
        "record_count": _number(
            _value(row, "record_count", "total_record_count")
        ),
        "summary_available": _value(row, "summary") is not None,
    }


def _partition_item(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "name": _bounded_output(
            _value(row, "partitionname", "partition_name", "partition"),
            512,
        ),
        "partition_id": _json_value(
            _value(row, "partitionid", "partition_id", "spec_id")
        ),
        "record_count": _number(
            _value(row, "record_count", "row_count", "table_rows", "rows")
        ),
        "file_count": _number(
            _value(row, "file_count", "data_file_count")
        ),
        "updated_at": _json_value(
            _value(
                row,
                "lastconsistencychecktime",
                "last_update_time",
                "update_time",
            )
        ),
    }


def _lifecycle_capabilities(
    version: DorisVersion,
    table_format: str,
    columns: Sequence[Mapping[str, Any]],
    snapshots: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    supports_4_1 = version.is_parsed and version.is_at_least(_DORIS_4_1)
    column_names = {
        str(_value(row, "field", "column_name") or "").casefold()
        for row in columns
    }
    row_lineage_columns = sorted(
        name
        for name in (
            "_row_id",
            "_last_updated_sequence_number",
        )
        if name in column_names
    )
    eligible = supports_4_1 and table_format == "iceberg"
    return {
        "detected_server_version": version.normalized,
        "iceberg_v3_lifecycle_eligible": eligible,
        "deletion_vector": {
            "server_support": eligible,
            "target_evidence_observed": any(
                "deletion" in str(item).casefold() for item in snapshots
            ),
        },
        "row_lineage": {
            "server_support": eligible,
            "target_evidence_observed": bool(row_lineage_columns),
            "observable_hidden_columns": row_lineage_columns,
        },
    }


def _variant_properties(source: str) -> dict[str, str]:
    properties: dict[str, str] = {}
    for match in _VARIANT_PROPERTY.finditer(source):
        key = match.group("key").casefold()
        if key in _SAFE_VARIANT_PROPERTIES:
            properties[key] = match.group("value").strip()
    return properties


def _variant_configuration(
    properties: Mapping[str, str],
) -> tuple[dict[str, Any], tuple[str, ...]]:
    doc_mode = _as_bool(properties.get("variant_enable_doc_mode"))
    typed_sparse = _as_bool(
        properties.get("variant_enable_typed_paths_to_sparse")
    )
    sparse_shards = _number(
        properties.get("variant_sparse_hash_shard_count")
    )
    doc_shards = _number(properties.get("variant_doc_hash_shard_count"))
    sparse_mode = bool(typed_sparse) or (
        isinstance(sparse_shards, int | float) and sparse_shards > 1
    )
    warnings: list[str] = []
    if doc_mode and sparse_mode:
        warnings.append(
            "DOC mode and sparse Variant storage both appear configured; "
            "Doris documents these modes as mutually exclusive."
        )
    mode = "doc" if doc_mode else "sparse" if sparse_mode else "default"
    storage_format = properties.get("storage_format")
    return (
        {
            "mode": mode,
            "storage_format": (
                storage_format.upper() if storage_format else None
            ),
            "storage_v3": bool(
                storage_format and storage_format.casefold() == "v3"
            ),
            "max_subcolumns_count": _number(
                properties.get("variant_max_subcolumns_count")
            ),
            "typed_paths_to_sparse": typed_sparse,
            "sparse_hash_shard_count": sparse_shards,
            "doc_hash_shard_count": doc_shards,
            "doc_materialization_min_rows": _number(
                properties.get("variant_doc_materialization_min_rows")
            ),
            "flatten_nested": _as_bool(
                properties.get("variant_flatten_nested")
            ),
        },
        tuple(warnings),
    )


def _variant_advanced_capabilities(
    version: DorisVersion,
    configuration: Mapping[str, Any],
) -> dict[str, Any]:
    supported = version.is_parsed and version.is_at_least(_DORIS_4_1)
    return {
        "detected_server_version": version.normalized,
        "storage_v3_supported": supported,
        "sparse_sharding_supported": supported,
        "sparse_cache_supported": supported,
        "doc_mode_supported": supported,
        "configured_mode": configuration.get("mode"),
    }


def _typed_paths(declared_type: str) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for match in _TYPED_PATH.finditer(declared_type):
        items.append(
            {
                "path": match.group("path"),
                "type": match.group("type").upper(),
            }
        )
        if len(items) >= _MAX_TYPED_PATHS:
            break
    return items


def _variant_type_observations(
    rows: Sequence[Mapping[str, Any]],
    *,
    requested_path: str | None,
    maximum: int,
) -> tuple[list[dict[str, Any]], bool]:
    counts: dict[str, Counter[str]] = defaultdict(Counter)
    observed_rows: Counter[str] = Counter()
    for row in rows:
        raw = _value(row, "variant_type")
        if raw is None:
            continue
        parsed = _parse_variant_type(raw)
        if isinstance(parsed, Mapping):
            for path, value_type in parsed.items():
                raw_path = str(path)
                if requested_path and not raw_path:
                    path_name = requested_path
                else:
                    path_name = raw_path or "$"
                counts[path_name][_variant_type_label(value_type)] += 1
                observed_rows[path_name] += 1
        else:
            path_name = requested_path or "$"
            counts[path_name][_variant_type_label(parsed)] += 1
            observed_rows[path_name] += 1
    ordered = sorted(
        counts,
        key=lambda path: (-observed_rows[path], path),
    )
    truncated = len(ordered) > maximum
    items = []
    denominator = len(rows)
    for path_name in ordered[:maximum]:
        present = observed_rows[path_name]
        items.append(
            {
                "path": path_name,
                "types": [
                    {"type": value_type, "rows": count}
                    for value_type, count in counts[path_name].most_common()
                ],
                "rows_observed": present,
                "presence_ratio": (
                    round(present / denominator, 6) if denominator else None
                ),
            }
        )
    return items, truncated


def _variant_type_label(value: Any) -> str:
    return str(value).strip().upper()[:128] or "UNKNOWN"


def _parse_variant_type(value: Any) -> Mapping[str, Any] | str:
    if isinstance(value, Mapping):
        return value
    text = str(value)
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        return text[:128]
    if isinstance(parsed, Mapping):
        return parsed
    if isinstance(parsed, str):
        return parsed[:128]
    return type(parsed).__name__


def _table_name(row: Mapping[str, Any]) -> str | None:
    value = next(
        (
            value
            for key, value in row.items()
            if str(key).casefold().startswith("tables_in_")
        ),
        _first_value(row),
    )
    if value is None:
        return None
    try:
        return validate_identifier(str(value), "table name")
    except SQLSecurityError:
        return None


def _table_type(row: Mapping[str, Any]) -> str:
    raw = str(_value(row, "table_type", "type") or "table").casefold()
    return "view" if "view" in raw else "table"


def _first_value(row: Mapping[str, Any]) -> Any:
    return next(iter(row.values()), None)


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
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if value is None or isinstance(value, str | int | float | bool):
        return value
    return str(value)


def _number(value: Any) -> int | float | None:
    if value in (None, "") or isinstance(value, bool):
        return None
    try:
        number = float(str(value).replace(",", "").strip())
    except (TypeError, ValueError):
        return None
    return int(number) if number.is_integer() else number


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().casefold() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _bounded_output(value: Any, maximum: int) -> str | None:
    if value is None:
        return None
    normalized = str(value).replace("\x00", "").replace("\r", " ").replace(
        "\n",
        " ",
    )
    return normalized[:maximum]


def _argument_failure(message: str) -> LakehouseRuntimeFailure:
    return LakehouseRuntimeFailure(
        message,
        reason_code="LAKEHOUSE_ARGUMENT_INVALID",
        status_code=400,
    )


def _classify_failure(error: Exception) -> LakehouseRuntimeFailure:
    if isinstance(error, LakehouseRuntimeFailure):
        return error
    if isinstance(error, SQLSecurityError):
        return _argument_failure("Lakehouse arguments are invalid.")
    error_code = next(
        (item for item in getattr(error, "args", ()) if isinstance(item, int)),
        None,
    )
    if error_code in {1044, 1045, 1142, 1227}:
        return LakehouseRuntimeFailure(
            "Doris denied access to the requested lakehouse metadata.",
            reason_code="LAKEHOUSE_PERMISSION_DENIED",
            status_code=403,
        )
    if error_code in {
        1049,
        1054,
        1064,
        1109,
        1146,
        1176,
        1305,
    }:
        return LakehouseRuntimeFailure(
            "The requested Doris lakehouse metadata is unavailable.",
            reason_code="LAKEHOUSE_METADATA_UNAVAILABLE",
            status_code=404,
        )
    if isinstance(error, ConnectionError | TimeoutError):
        return LakehouseRuntimeFailure(
            "Doris lakehouse metadata is temporarily unavailable.",
            reason_code="LAKEHOUSE_CONNECTION_FAILED",
            status_code=503,
            retryable=True,
        )
    return LakehouseRuntimeFailure(
        "Doris lakehouse metadata execution failed.",
        reason_code="LAKEHOUSE_EXECUTION_FAILED",
        status_code=502,
    )


__all__ = [
    "DorisLakehouseRuntime",
    "LakehouseRuntimeFailure",
]
