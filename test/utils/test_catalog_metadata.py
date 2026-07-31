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

"""Production contract tests for strict formal Catalog metadata reads."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from doris_mcp_server.utils.catalog_metadata import (
    CatalogMetadataFailure,
    DorisCatalogMetadataReader,
)


class _ConnectionManager:
    def __init__(self, *responses: Any) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, tuple[Any, ...] | None]] = []

    async def execute_query(
        self,
        _session_id: str,
        sql: str,
        params: tuple[Any, ...] | None,
        _auth_context: Any,
    ) -> SimpleNamespace:
        self.calls.append((sql, params))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return SimpleNamespace(data=response)


def _reader(*responses: Any) -> tuple[DorisCatalogMetadataReader, _ConnectionManager]:
    manager = _ConnectionManager(*responses)
    return (
        DorisCatalogMetadataReader(manager),  # type: ignore[arg-type]
        manager,
    )


@pytest.mark.asyncio
async def test_discovery_reads_rich_catalog_database_and_table_metadata() -> None:
    reader, manager = _reader(
        [
            {
                "CatalogId": 0,
                "CatalogName": "internal",
                "Type": "internal",
                "IsCurrent": "Yes",
            },
            {
                "CatalogId": 1,
                "CatalogName": "lake",
                "Type": "iceberg",
                "IsCurrent": "No",
            },
        ],
        [{"Database": "analytics"}],
        [
            {
                "Tables_in_analytics": "orders",
                "Table_type": "BASE TABLE",
                "Storage_format": "V2",
                "Inverted_index_storage_format": "V1",
            },
            {
                "Tables_in_analytics": "orders_view",
                "Table_type": "VIEW",
                "Storage_format": "NONE",
                "Inverted_index_storage_format": "NONE",
            },
            {
                "Tables_in_analytics": "orders_mv",
                "Table_type": "MATERIALIZED VIEW",
            },
        ],
    )

    catalogs = await reader.list_catalogs()
    databases = await reader.list_databases(catalog_name="lake")
    tables = await reader.list_tables(
        database_name="analytics",
        catalog_name="lake",
    )

    assert catalogs["result"] == [
        {
            "name": "internal",
            "type": "internal",
            "scope": "internal",
            "is_current": True,
        },
        {
            "name": "lake",
            "type": "iceberg",
            "scope": "external",
            "is_current": False,
        },
    ]
    assert databases["result"] == [
        {"name": "analytics", "catalog": "lake"}
    ]
    assert [item["type"] for item in tables["result"]] == [
        "table",
        "view",
        "materialized_view",
    ]
    assert manager.calls == [
        ("SHOW CATALOGS", None),
        ("SHOW DATABASES FROM `lake`", None),
        ("SHOW FULL TABLES FROM `lake`.`analytics`", None),
    ]


@pytest.mark.asyncio
async def test_table_context_sections_use_strict_read_only_metadata_paths() -> None:
    reader, manager = _reader(
        [
            {
                "Field": "id",
                "Type": "bigint",
                "Null": "NO",
                "Key": "PRI",
                "Default": None,
                "Comment": "identifier",
                "Extra": "",
            }
        ],
        [{"TABLE_COMMENT": "orders"}],
        [
            {"COLUMN_NAME": "id", "COLUMN_COMMENT": "identifier"},
            {"COLUMN_NAME": "amount", "COLUMN_COMMENT": ""},
        ],
        [
            {
                "Key_name": "idx_amount",
                "Column_name": "amount",
                "Non_unique": 1,
                "Index_type": "INVERTED",
            },
            {
                "Key_name": "idx_compound",
                "Column_name": "id",
                "Non_unique": 0,
                "Index_type": "BTREE",
            },
            {
                "Key_name": "idx_compound",
                "Column_name": "amount",
                "Non_unique": 0,
                "Index_type": "BTREE",
            },
        ],
        [
            {
                "TABLE_TYPE": "BASE TABLE",
                "ENGINE": "OLAP",
                "TABLE_ROWS": 7,
                "AVG_ROW_LENGTH": 20,
                "DATA_LENGTH": 140,
                "INDEX_LENGTH": 10,
                "CREATE_TIME": "2026-07-01 00:00:00",
                "UPDATE_TIME": "2026-07-30 00:00:00",
                "TABLE_COMMENT": "orders",
            }
        ],
    )

    schema = await reader.get_table_schema(
        table_name="orders",
        database_name="analytics",
        catalog_name="internal",
    )
    table_comment = await reader.get_table_comment(
        table_name="orders",
        database_name="analytics",
        catalog_name="internal",
    )
    column_comments = await reader.get_column_comments(
        table_name="orders",
        database_name="analytics",
        catalog_name="internal",
    )
    indexes = await reader.get_table_indexes(
        table_name="orders",
        database_name="analytics",
        catalog_name="internal",
    )
    basic = await reader.get_table_basic(
        table_name="orders",
        database_name="analytics",
        catalog_name="internal",
    )

    assert schema["result"]["column_count"] == 1
    assert schema["result"]["columns"][0]["comment"] == "identifier"
    assert table_comment["result"] == {"comment": "orders"}
    assert column_comments["result"] == {
        "id": "identifier",
        "amount": "",
    }
    assert indexes["result"]["items"][1]["columns"] == ["id", "amount"]
    assert basic["result"]["row_count"] == 7
    assert basic["result"]["data_size_bytes"] == 140
    assert manager.calls[0] == (
        "SHOW FULL COLUMNS FROM `analytics`.`orders`",
        None,
    )
    assert all(
        statement.lstrip().upper().startswith(("SHOW", "SELECT"))
        for statement, _params in manager.calls
    )


@pytest.mark.asyncio
async def test_table_size_returns_optional_partition_statistics() -> None:
    reader, manager = _reader(
        [
            {
                "TABLE_ROWS": "9",
                "DATA_LENGTH": "200",
                "INDEX_LENGTH": "20",
            }
        ],
        [
            {
                "PARTITION_NAME": "p1",
                "PARTITION_ORDINAL_POSITION": 1,
                "TABLE_ROWS": 4,
                "DATA_LENGTH": 80,
                "INDEX_LENGTH": 8,
            }
        ],
    )

    result = await reader.get_table_size(
        table_name="orders",
        database_name="analytics",
        catalog_name=None,
        include_partitions=True,
    )

    assert result["result"]["total_size_bytes"] == 220
    assert result["result"]["partitions"] == [
        {
            "name": "p1",
            "ordinal_position": 1,
            "row_count": 4,
            "data_size_bytes": 80,
            "index_size_bytes": 8,
        }
    ]
    assert result["warnings"] == []
    assert result["metadata"]["partition_status"] == "available"
    assert "`information_schema`.`partitions`" in manager.calls[1][0]


@pytest.mark.asyncio
async def test_table_size_preserves_base_result_when_partitions_are_unsupported() -> None:
    reader, _manager = _reader(
        [{"TABLE_ROWS": 9, "DATA_LENGTH": 200, "INDEX_LENGTH": 20}],
        RuntimeError(1109, "Unknown system table"),
    )

    result = await reader.get_table_size(
        table_name="orders",
        database_name="analytics",
        catalog_name="lake",
        include_partitions=True,
    )

    assert result["result"]["row_count"] == 9
    assert result["result"]["partitions"] == []
    assert result["metadata"]["partition_status"] == "unavailable"
    assert (
        result["metadata"]["partition_reason_code"]
        == "CATALOG_SECTION_UNSUPPORTED"
    )
    assert result["warnings"] == [
        "Partition statistics are unavailable for the requested table "
        "(CATALOG_SECTION_UNSUPPORTED)."
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "reason_code", "status_code", "retryable"),
    [
        (
            RuntimeError(1142, "SELECT command denied"),
            "CATALOG_PERMISSION_DENIED",
            403,
            False,
        ),
        (
            RuntimeError(1146, "Table does not exist"),
            "CATALOG_OBJECT_NOT_FOUND",
            404,
            False,
        ),
        (
            RuntimeError(1064, "Syntax is not supported"),
            "CATALOG_SECTION_UNSUPPORTED",
            501,
            False,
        ),
        (
            TimeoutError("timed out"),
            "CATALOG_BACKEND_UNAVAILABLE",
            503,
            True,
        ),
    ],
)
async def test_catalog_failures_are_sanitized_and_distinguishable(
    failure: Exception,
    reason_code: str,
    status_code: int,
    retryable: bool,
) -> None:
    reader, _manager = _reader(failure)

    with pytest.raises(CatalogMetadataFailure) as exc_info:
        await reader.list_catalogs()

    assert exc_info.value.reason_code == reason_code
    assert exc_info.value.status_code == status_code
    assert exc_info.value.retryable is retryable
    assert "SELECT command denied" not in str(exc_info.value)


@pytest.mark.asyncio
async def test_empty_schema_and_invalid_identifier_fail_before_ambiguous_results() -> None:
    empty_reader, _manager = _reader([])
    invalid_reader, invalid_manager = _reader([])

    with pytest.raises(CatalogMetadataFailure) as missing:
        await empty_reader.get_table_schema(
            table_name="missing",
            database_name="analytics",
            catalog_name=None,
        )
    with pytest.raises(CatalogMetadataFailure) as invalid:
        await invalid_reader.list_tables(
            database_name="analytics; DROP TABLE orders",
            catalog_name=None,
        )

    assert missing.value.reason_code == "CATALOG_OBJECT_NOT_FOUND"
    assert invalid.value.reason_code == "CATALOG_ARGUMENT_INVALID"
    assert invalid_manager.calls == []
