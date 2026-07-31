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

"""Strict, read-only Doris catalog metadata access for formal domain tools."""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from typing import Any

from .db import DorisConnectionManager
from .security import get_current_auth_context
from .sql_security_utils import (
    SQLSecurityError,
    quote_identifier,
    validate_identifier,
)


class CatalogMetadataFailure(RuntimeError):
    """A sanitized catalog failure that remains machine distinguishable."""

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


class DorisCatalogMetadataReader:
    """Read formal Catalog-domain metadata without swallowing Doris failures."""

    def __init__(self, connection_manager: DorisConnectionManager) -> None:
        self._connection_manager = connection_manager
        self._session_id = f"formal_catalog_{uuid.uuid4().hex[:8]}"

    async def list_catalogs(self) -> dict[str, Any]:
        """Return visible catalogs with their reported provider type."""
        rows = await self._execute("SHOW CATALOGS")
        items: list[dict[str, Any]] = []
        for row in rows:
            name = _row_value(row, "CatalogName")
            if name is None:
                values = list(row.values())
                name = values[1] if len(values) > 1 else values[0] if values else None
            if name is None:
                continue
            catalog_name = str(name)
            reported_type = _row_value(row, "Type")
            scope = "internal" if catalog_name == "internal" else "external"
            items.append(
                {
                    "name": catalog_name,
                    "type": (
                        str(reported_type).lower()
                        if reported_type not in (None, "")
                        else scope
                    ),
                    "scope": scope,
                    "is_current": _as_bool(_row_value(row, "IsCurrent")),
                }
            )
        return _success(items, "SHOW CATALOGS")

    async def list_databases(
        self,
        *,
        catalog_name: str | None,
    ) -> dict[str, Any]:
        """Return visible databases in one catalog."""
        effective_catalog = catalog_name or "internal"
        if catalog_name and catalog_name != "internal":
            safe_catalog = _quote(catalog_name, "catalog name")
            sql = f"SHOW DATABASES FROM {safe_catalog}"
        else:
            sql = "SHOW DATABASES"
        rows = await self._execute(sql)
        items = [
            {
                "name": str(name),
                "catalog": effective_catalog,
            }
            for row in rows
            if (name := _first_value(row)) is not None
        ]
        return _success(items, "SHOW DATABASES")

    async def list_tables(
        self,
        *,
        database_name: str,
        catalog_name: str | None,
    ) -> dict[str, Any]:
        """Return visible tables and views with stable normalized object types."""
        relation = _qualified_name(catalog_name, database_name)
        rows = await self._execute(f"SHOW FULL TABLES FROM {relation}")
        items: list[dict[str, Any]] = []
        for row in rows:
            name = next(
                (
                    value
                    for key, value in row.items()
                    if str(key).lower().startswith("tables_in_")
                ),
                _first_value(row),
            )
            if name is None:
                continue
            raw_type = _row_value(row, "Table_type", "TABLE_TYPE")
            items.append(
                {
                    "name": str(name),
                    "type": _normalize_table_type(raw_type),
                    "raw_type": "" if raw_type is None else str(raw_type),
                    "catalog": catalog_name or "internal",
                    "database": database_name,
                    "storage_format": _optional_string(
                        _row_value(row, "Storage_format")
                    ),
                    "inverted_index_storage_format": _optional_string(
                        _row_value(row, "Inverted_index_storage_format")
                    ),
                }
            )
        return _success(items, "SHOW FULL TABLES")

    async def get_table_schema(
        self,
        *,
        table_name: str,
        database_name: str,
        catalog_name: str | None,
    ) -> dict[str, Any]:
        """Return a strict schema section and prove that the table is visible."""
        relation = _qualified_name(catalog_name, database_name, table_name)
        rows = await self._execute(f"SHOW FULL COLUMNS FROM {relation}")
        if not rows:
            raise _object_not_found()
        columns = [
            {
                "column_name": _optional_string(_row_value(row, "Field")),
                "data_type": _optional_string(_row_value(row, "Type")),
                "is_nullable": str(_row_value(row, "Null") or "NO").upper()
                == "YES",
                "default_value": _row_value(row, "Default"),
                "comment": _optional_string(_row_value(row, "Comment")),
                "key": _optional_string(_row_value(row, "Key")),
                "extra": _optional_string(_row_value(row, "Extra")),
            }
            for row in rows
        ]
        return _success(
            {
                "catalog": catalog_name or "internal",
                "database": database_name,
                "table": table_name,
                "columns": columns,
                "column_count": len(columns),
            },
            "SHOW FULL COLUMNS",
        )

    async def get_table_comment(
        self,
        *,
        table_name: str,
        database_name: str,
        catalog_name: str | None,
    ) -> dict[str, Any]:
        """Return the table comment from the catalog-local information schema."""
        relation = _information_schema_relation(catalog_name, "tables")
        # SQL sink audit: relation is assembled only from quote_identifier
        # outputs; filter values stay bound before _execute reaches Doris.
        rows = await self._execute(
            (
                "SELECT TABLE_COMMENT "
                f"FROM {relation} "  # nosec B608
                "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s"
            ),
            (database_name, table_name),
        )
        if not rows:
            raise _object_not_found()
        return _success(
            {
                "comment": _optional_string(
                    _row_value(rows[0], "TABLE_COMMENT")
                )
            },
            "information_schema.tables",
        )

    async def get_column_comments(
        self,
        *,
        table_name: str,
        database_name: str,
        catalog_name: str | None,
    ) -> dict[str, Any]:
        """Return ordered column comments from the catalog-local metadata."""
        relation = _information_schema_relation(catalog_name, "columns")
        # SQL sink audit: relation is assembled only from quote_identifier
        # outputs; filter values stay bound before _execute reaches Doris.
        rows = await self._execute(
            (
                "SELECT COLUMN_NAME, COLUMN_COMMENT "
                f"FROM {relation} "  # nosec B608
                "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s "
                "ORDER BY ORDINAL_POSITION"
            ),
            (database_name, table_name),
        )
        return _success(
            {
                str(name): _optional_string(
                    _row_value(row, "COLUMN_COMMENT")
                )
                for row in rows
                if (name := _row_value(row, "COLUMN_NAME")) is not None
            },
            "information_schema.columns",
        )

    async def get_table_indexes(
        self,
        *,
        table_name: str,
        database_name: str,
        catalog_name: str | None,
    ) -> dict[str, Any]:
        """Return table indexes, preserving multi-column index order."""
        relation = _qualified_name(catalog_name, database_name, table_name)
        rows = await self._execute(f"SHOW INDEX FROM {relation}")
        indexes: dict[str, dict[str, Any]] = {}
        for row in rows:
            raw_name = _row_value(row, "Key_name", "KEY_NAME")
            if raw_name is None:
                continue
            name = str(raw_name)
            index = indexes.setdefault(
                name,
                {
                    "name": name,
                    "columns": [],
                    "unique": _as_int(_row_value(row, "Non_unique"), 1) == 0,
                    "type": _optional_string(
                        _row_value(row, "Index_type", "INDEX_TYPE")
                    ),
                },
            )
            column_name = _row_value(row, "Column_name", "COLUMN_NAME")
            if column_name is not None:
                index["columns"].append(str(column_name))
        return _success(
            {"items": list(indexes.values()), "index_count": len(indexes)},
            "SHOW INDEX",
        )

    async def get_table_basic(
        self,
        *,
        table_name: str,
        database_name: str,
        catalog_name: str | None,
    ) -> dict[str, Any]:
        """Return stable basic metadata without scanning table data."""
        row = await self._get_table_metadata_row(
            table_name=table_name,
            database_name=database_name,
            catalog_name=catalog_name,
        )
        return _success(
            _normalize_basic_row(
                row,
                catalog_name=catalog_name,
                database_name=database_name,
                table_name=table_name,
            ),
            "information_schema.tables",
        )

    async def get_table_size(
        self,
        *,
        table_name: str,
        database_name: str,
        catalog_name: str | None,
        include_partitions: bool,
    ) -> dict[str, Any]:
        """Return table statistics and optional partition statistics."""
        row = await self._get_table_metadata_row(
            table_name=table_name,
            database_name=database_name,
            catalog_name=catalog_name,
        )
        data_size = _optional_int(_row_value(row, "DATA_LENGTH"))
        index_size = _optional_int(_row_value(row, "INDEX_LENGTH"))
        result: dict[str, Any] = {
            "catalog": catalog_name or "internal",
            "database": database_name,
            "table": table_name,
            "row_count": _optional_int(_row_value(row, "TABLE_ROWS")),
            "data_size_bytes": data_size,
            "index_size_bytes": index_size,
            "total_size_bytes": (
                data_size + index_size
                if data_size is not None and index_size is not None
                else data_size
            ),
            "partitions": [],
        }
        warnings: list[str] = []
        metadata: dict[str, Any] = {
            "source": "information_schema.tables",
            "partition_status": "not_requested",
        }
        if include_partitions:
            try:
                partition_rows = await self._get_partition_rows(
                    table_name=table_name,
                    database_name=database_name,
                    catalog_name=catalog_name,
                )
            except CatalogMetadataFailure as exc:
                warnings.append(
                    "Partition statistics are unavailable for the requested "
                    f"table ({exc.reason_code})."
                )
                metadata["partition_status"] = "unavailable"
                metadata["partition_reason_code"] = exc.reason_code
            else:
                result["partitions"] = [
                    {
                        "name": _optional_string(
                            _row_value(partition, "PARTITION_NAME")
                        ),
                        "ordinal_position": _optional_int(
                            _row_value(
                                partition,
                                "PARTITION_ORDINAL_POSITION",
                            )
                        ),
                        "row_count": _optional_int(
                            _row_value(partition, "TABLE_ROWS")
                        ),
                        "data_size_bytes": _optional_int(
                            _row_value(partition, "DATA_LENGTH")
                        ),
                        "index_size_bytes": _optional_int(
                            _row_value(partition, "INDEX_LENGTH")
                        ),
                    }
                    for partition in partition_rows
                ]
                metadata["partition_status"] = "available"
                metadata["source"] = (
                    "information_schema.tables,"
                    "information_schema.partitions"
                )
        return _success(
            result,
            metadata["source"],
            warnings=warnings,
            metadata=metadata,
        )

    async def _get_table_metadata_row(
        self,
        *,
        table_name: str,
        database_name: str,
        catalog_name: str | None,
    ) -> Mapping[str, Any]:
        relation = _information_schema_relation(catalog_name, "tables")
        # SQL sink audit: relation is assembled only from quote_identifier
        # outputs; filter values stay bound before _execute reaches Doris.
        rows = await self._execute(
            (
                "SELECT TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE, "
                "ENGINE, TABLE_ROWS, AVG_ROW_LENGTH, DATA_LENGTH, INDEX_LENGTH, "
                "CREATE_TIME, UPDATE_TIME, TABLE_COMMENT "
                f"FROM {relation} "  # nosec B608
                "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s"
            ),
            (database_name, table_name),
        )
        if not rows:
            raise _object_not_found()
        return rows[0]

    async def _get_partition_rows(
        self,
        *,
        table_name: str,
        database_name: str,
        catalog_name: str | None,
    ) -> list[Mapping[str, Any]]:
        relation = _information_schema_relation(catalog_name, "partitions")
        # SQL sink audit: relation is assembled only from quote_identifier
        # outputs; filter values stay bound before _execute reaches Doris.
        return await self._execute(
            (
                "SELECT PARTITION_NAME, PARTITION_ORDINAL_POSITION, TABLE_ROWS, "
                f"DATA_LENGTH, INDEX_LENGTH FROM {relation} "  # nosec B608
                "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s "
                "ORDER BY PARTITION_ORDINAL_POSITION"
            ),
            (database_name, table_name),
        )

    async def _execute(
        self,
        sql: str,
        params: tuple[Any, ...] | None = None,
    ) -> list[Mapping[str, Any]]:
        try:
            result = await self._connection_manager.execute_query(
                self._session_id,
                sql,
                params,
                get_current_auth_context(),
            )
        except Exception as exc:
            raise _classify_failure(exc) from exc
        return [
            row
            for row in (result.data or [])
            if isinstance(row, Mapping)
        ]


def _success(
    result: Any,
    source: str,
    *,
    warnings: list[str] | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    response_metadata = dict(metadata or {})
    response_metadata.setdefault("source", source)
    return {
        "success": True,
        "result": result,
        "warnings": list(warnings or ()),
        "metadata": response_metadata,
    }


def _classify_failure(exc: Exception) -> CatalogMetadataFailure:
    if isinstance(exc, CatalogMetadataFailure):
        return exc
    if isinstance(exc, SQLSecurityError):
        return CatalogMetadataFailure(
            "Catalog arguments contain an invalid Doris identifier.",
            reason_code="CATALOG_ARGUMENT_INVALID",
            status_code=400,
        )

    numeric_code = next(
        (
            value
            for value in getattr(exc, "args", ())
            if isinstance(value, int)
        ),
        None,
    )
    message = str(exc).lower()
    if numeric_code in {1044, 1045, 1142, 1227} or any(
        marker in message
        for marker in (
            "access denied",
            "permission denied",
            "not authorized",
            "privilege",
        )
    ):
        return CatalogMetadataFailure(
            "Doris denied access to the requested catalog metadata.",
            reason_code="CATALOG_PERMISSION_DENIED",
            status_code=403,
        )
    if numeric_code in {1049, 1146} or any(
        marker in message
        for marker in (
            "doesn't exist",
            "does not exist",
            "unknown database",
            "unknown table",
            "not found",
        )
    ):
        return _object_not_found()
    if numeric_code in {1064, 1109} or any(
        marker in message
        for marker in (
            "not supported",
            "unsupported",
            "unknown system table",
        )
    ):
        return CatalogMetadataFailure(
            "The requested Doris metadata section is unsupported.",
            reason_code="CATALOG_SECTION_UNSUPPORTED",
            status_code=501,
        )
    if isinstance(exc, TimeoutError | ConnectionError | OSError):
        return CatalogMetadataFailure(
            "Doris catalog metadata is temporarily unavailable.",
            reason_code="CATALOG_BACKEND_UNAVAILABLE",
            status_code=503,
            retryable=True,
        )
    return CatalogMetadataFailure(
        "Doris catalog metadata execution failed.",
        reason_code="CATALOG_EXECUTION_FAILED",
        status_code=502,
    )


def _object_not_found() -> CatalogMetadataFailure:
    return CatalogMetadataFailure(
        "The requested Doris metadata object was not found.",
        reason_code="CATALOG_OBJECT_NOT_FOUND",
        status_code=404,
    )


def _quote(value: str, label: str) -> str:
    try:
        validate_identifier(value, label)
        return quote_identifier(value, label)
    except SQLSecurityError as exc:
        raise _classify_failure(exc) from exc


def _qualified_name(
    catalog_name: str | None,
    database_name: str,
    table_name: str | None = None,
) -> str:
    parts = []
    if catalog_name and catalog_name != "internal":
        parts.append(_quote(catalog_name, "catalog name"))
    parts.append(_quote(database_name, "database name"))
    if table_name is not None:
        parts.append(_quote(table_name, "table name"))
    return ".".join(parts)


def _information_schema_relation(
    catalog_name: str | None,
    table_name: str,
) -> str:
    parts = []
    if catalog_name and catalog_name != "internal":
        parts.append(_quote(catalog_name, "catalog name"))
    parts.extend(
        (
            quote_identifier("information_schema", "database name"),
            _quote(table_name, "metadata table name"),
        )
    )
    return ".".join(parts)


def _row_value(row: Mapping[str, Any], *names: str) -> Any | None:
    lowered = {str(key).lower(): value for key, value in row.items()}
    for name in names:
        if name.lower() in lowered:
            return lowered[name.lower()]
    return None


def _first_value(row: Mapping[str, Any]) -> Any | None:
    return next(iter(row.values()), None)


def _optional_string(value: Any) -> str:
    return "" if value is None else str(value)


def _optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_int(value: Any, default: int) -> int:
    parsed = _optional_int(value)
    return default if parsed is None else parsed


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes"}


def _normalize_table_type(value: Any) -> str:
    normalized = str(value or "").strip().upper().replace("-", " ")
    if "MATERIALIZED" in normalized:
        return "materialized_view"
    if "VIEW" in normalized:
        return "view"
    return "table"


def _normalize_basic_row(
    row: Mapping[str, Any],
    *,
    catalog_name: str | None,
    database_name: str,
    table_name: str,
) -> dict[str, Any]:
    return {
        "catalog": catalog_name or "internal",
        "database": database_name,
        "table": table_name,
        "type": _normalize_table_type(_row_value(row, "TABLE_TYPE")),
        "raw_type": _optional_string(_row_value(row, "TABLE_TYPE")),
        "engine": _optional_string(_row_value(row, "ENGINE")),
        "row_count": _optional_int(_row_value(row, "TABLE_ROWS")),
        "average_row_length": _optional_int(
            _row_value(row, "AVG_ROW_LENGTH")
        ),
        "data_size_bytes": _optional_int(_row_value(row, "DATA_LENGTH")),
        "index_size_bytes": _optional_int(_row_value(row, "INDEX_LENGTH")),
        "created_at": _optional_string(_row_value(row, "CREATE_TIME")),
        "updated_at": _optional_string(_row_value(row, "UPDATE_TIME")),
        "comment": _optional_string(_row_value(row, "TABLE_COMMENT")),
    }


__all__ = [
    "CatalogMetadataFailure",
    "DorisCatalogMetadataReader",
]
