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

"""Production evidence contracts for the formal Lakehouse runtime."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any

import pytest

from doris_mcp_server.utils.lakehouse_runtime import (
    DorisLakehouseRuntime,
    LakehouseRuntimeFailure,
)

_Params = Mapping[str, Any] | tuple[Any, ...] | None
_Responder = Callable[[str, _Params], list[dict[str, Any]]]


class _ConnectionManager:
    def __init__(
        self,
        responder: _Responder,
        *,
        lakehouse: Any | None = None,
    ) -> None:
        self._responder = responder
        self.calls: list[str] = []
        self.params: list[_Params] = []
        self.max_rows: list[int] = []
        self.context_count = 0
        self.config = SimpleNamespace(
            lakehouse=lakehouse
            or SimpleNamespace(
                max_catalog_objects=50,
                max_catalog_databases=20,
                max_snapshots=50,
                max_partitions=100,
                max_variant_sample_rows=20,
                max_variant_paths=200,
            )
        )

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
                params: _Params = None,
                **kwargs: Any,
            ) -> SimpleNamespace:
                manager.calls.append(sql)
                manager.params.append(params)
                manager.max_rows.append(int(kwargs["max_rows"]))
                return SimpleNamespace(data=manager._responder(sql, params))

        yield _Connection()


def _runtime(
    responder: _Responder,
    *,
    lakehouse: Any | None = None,
) -> tuple[DorisLakehouseRuntime, _ConnectionManager]:
    manager = _ConnectionManager(responder, lakehouse=lakehouse)
    runtime = DorisLakehouseRuntime(manager)  # type: ignore[arg-type]
    return runtime, manager


def _catalog_rows() -> list[dict[str, Any]]:
    return [
        {
            "CatalogName": "ice_prod",
            "Type": "iceberg",
            "IsCurrent": "No",
            "CreateTime": "2026-07-01 00:00:00",
            "LastUpdateTime": "2026-07-30 10:00:00",
            "Comment": "Warehouse endpoint https://comment.private.invalid",
        },
        {
            "CatalogName": "internal",
            "Type": "internal",
            "IsCurrent": "Yes",
        },
    ]


@pytest.mark.asyncio
async def test_external_catalog_returns_only_sanitized_bounded_metadata() -> None:
    def responder(sql: str, _params: _Params) -> list[dict[str, Any]]:
        if sql == "SHOW CATALOGS":
            return _catalog_rows()
        if sql == "SHOW CATALOG `ice_prod`":
            return [
                {"Key": "type", "Value": "iceberg"},
                {"Key": "password", "Value": "do-not-return"},
                {
                    "Key": "s3.endpoint",
                    "Value": "https://private.example.invalid",
                },
                {"Key": "use_meta_cache", "Value": "true"},
                {"Key": "metadata_refresh_interval_sec", "Value": "60"},
                {"Key": "warehouse", "Value": "s3://private/warehouse"},
            ]
        if sql == "SHOW DATABASES FROM `ice_prod`":
            return [{"Database": "analytics"}, {"Database": "archive"}]
        if sql == "SHOW FULL TABLES FROM `ice_prod`.`analytics`":
            return [
                {
                    "Tables_in_analytics": "events",
                    "Table_type": "BASE TABLE",
                },
                {
                    "Tables_in_analytics": "events_view",
                    "Table_type": "VIEW",
                },
            ]
        raise AssertionError(f"Unexpected SQL: {sql}")

    runtime, manager = _runtime(responder)
    result = await runtime.inspect_external_catalog(
        catalog="ice_prod",
        include_objects=True,
        object_limit=1,
    )

    assert result["status"] == "success"
    assert result["data"]["reported_type"] == "iceberg"
    assert result["data"]["configuration"] == {
        "property_count": 6,
        "property_keys": [
            "metadata_refresh_interval_sec",
            "type",
            "use_meta_cache",
            "warehouse",
        ],
        "property_keys_truncated": False,
        "sensitive_property_count": 2,
        "property_values_returned": False,
        "metadata_cache_configured": True,
        "refresh_interval_configured": True,
        "warehouse_configured": True,
    }
    assert result["data"]["object_sample"]["relations"] == [
        {"database": "analytics", "name": "events", "type": "table"}
    ]
    assert result["data"]["object_sample"]["truncated"] is True
    serialized = str(result)
    assert "do-not-return" not in serialized
    assert "private.example.invalid" not in serialized
    assert "comment.private.invalid" not in serialized
    assert "s3://private/warehouse" not in serialized
    assert manager.max_rows[-1] == 2


@pytest.mark.asyncio
async def test_external_catalog_rejects_internal_and_injected_names() -> None:
    runtime, manager = _runtime(
        lambda sql, _params: _catalog_rows() if sql == "SHOW CATALOGS" else []
    )

    with pytest.raises(LakehouseRuntimeFailure) as internal_failure:
        await runtime.inspect_external_catalog(catalog="internal")
    assert internal_failure.value.reason_code == "LAKEHOUSE_CATALOG_NOT_EXTERNAL"

    call_count = len(manager.calls)
    with pytest.raises(LakehouseRuntimeFailure) as injection_failure:
        await runtime.inspect_external_catalog(catalog="ice; DROP DATABASE prod")
    assert injection_failure.value.reason_code == "LAKEHOUSE_ARGUMENT_INVALID"
    assert len(manager.calls) == call_count


@pytest.mark.asyncio
async def test_external_catalog_degrades_when_properties_are_not_visible() -> None:
    def responder(sql: str, _params: _Params) -> list[dict[str, Any]]:
        if sql == "SHOW CATALOGS":
            return _catalog_rows()
        if sql == "SHOW CATALOG `ice_prod`":
            raise RuntimeError(1142, "catalog properties denied")
        raise AssertionError(f"Unexpected SQL: {sql}")

    runtime, _ = _runtime(responder)
    result = await runtime.inspect_external_catalog(catalog="ice_prod")

    assert result["status"] == "partial"
    assert result["data"]["configuration"]["property_count"] == 0
    assert result["evidence"][1]["reason_code"] == "LAKEHOUSE_PERMISSION_DENIED"
    assert "catalog properties denied" not in str(result)


@pytest.mark.asyncio
async def test_iceberg_table_returns_recorded_facets_without_raw_artifacts() -> None:
    def responder(sql: str, _params: _Params) -> list[dict[str, Any]]:
        if sql == "SHOW CATALOGS":
            return _catalog_rows()
        if sql == "SHOW CATALOG `ice_prod`":
            return [{"Key": "type", "Value": "iceberg"}]
        if sql == "SHOW FULL COLUMNS FROM `ice_prod`.`analytics`.`events`":
            return [
                {
                    "Field": "event_id",
                    "Type": "BIGINT",
                    "Null": "NO",
                    "Key": "",
                    "Comment": "Stable identifier",
                },
                {
                    "Field": "_row_id",
                    "Type": "BIGINT",
                    "Null": "YES",
                    "Key": "",
                    "Comment": "",
                },
            ]
        if sql == "SHOW CREATE TABLE `ice_prod`.`analytics`.`events`":
            return [
                {
                    "Create Table": (
                        "CREATE TABLE events (event_id BIGINT) "
                        "PARTITIONED BY (`event_date`) "
                        "PROPERTIES ('warehouse'='s3://private/location')"
                    )
                }
            ]
        if sql == "SHOW TABLE STATS `ice_prod`.`analytics`.`events`":
            return [
                {
                    "row_count": "1000",
                    "data_size": "4096",
                    "update_time": "2026-07-30 12:00:00",
                }
            ]
        if sql.startswith(
            "SELECT * FROM `ice_prod`.`analytics`.`events$snapshots`"
        ):
            return [
                {
                    "snapshot_id": 42,
                    "parent_id": 41,
                    "schema_id": 7,
                    "committed_at": "2026-07-30 12:00:00",
                    "operation": "append",
                    "record_count": 1000,
                    "summary": '{"private-location":"s3://secret"}',
                }
            ]
        if sql.startswith(
            "SHOW PARTITIONS FROM `ice_prod`.`analytics`.`events`"
        ):
            return [
                {
                    "PartitionName": "event_date=2026-07-30",
                    "PartitionId": 9,
                    "Rows": 1000,
                    "UpdateTime": "2026-07-30 12:00:00",
                }
            ]
        if sql.startswith(
            "EXPLAIN SELECT * FROM `ice_prod`.`analytics`.`events`"
        ):
            return [
                {
                    "Explain String": (
                        "ICEBERG_SCAN_NODE\nPARTITIONS=1/12\nPREDICATES: event_id"
                    )
                }
            ]
        if sql == "SELECT @@version_comment;":
            return [
                {
                    "@@version_comment": (
                        "Doris version doris-4.1.0-43f06a5e26 "
                        "(Cloud Mode)"
                    )
                }
            ]
        raise AssertionError(f"Unexpected SQL: {sql}")

    runtime, _ = _runtime(responder)
    result = await runtime.inspect_lakehouse_table(
        catalog="ice_prod",
        database="analytics",
        table="events",
        include_snapshots=True,
        include_partitions=True,
    )

    assert result["status"] == "success"
    assert result["data"]["format"] == "iceberg"
    assert result["data"]["partition_columns"] == ["event_date"]
    assert result["data"]["statistics"]["row_count"] == 1000
    assert result["data"]["snapshots"]["items"][0] == {
        "snapshot_id": 42,
        "parent_id": 41,
        "schema_id": 7,
        "committed_at": "2026-07-30 12:00:00",
        "operation": "append",
        "record_count": 1000,
        "summary_available": True,
    }
    assert result["data"]["partitions"]["items"][0]["record_count"] == 1000
    assert result["data"]["pushdown"] == {
        "external_scan_observed": True,
        "partition_pruning_observed": True,
        "predicate_pushdown_observed": True,
        "scan_nodes": ["ICEBERG_SCAN_NODE"],
    }
    assert result["data"]["lifecycle"]["iceberg_v3_lifecycle_eligible"] is True
    assert result["data"]["lifecycle"]["row_lineage"][
        "observable_hidden_columns"
    ] == ["_row_id"]
    serialized = str(result)
    assert "CREATE TABLE events (" not in serialized
    assert "s3://private/location" not in serialized
    assert "ICEBERG_SCAN_NODE\nPARTITIONS" not in serialized
    assert "s3://secret" not in serialized


@pytest.mark.asyncio
async def test_lakehouse_table_rejects_non_lakehouse_catalog() -> None:
    def responder(sql: str, _params: _Params) -> list[dict[str, Any]]:
        if sql == "SHOW CATALOGS":
            return [{"CatalogName": "hms_prod", "Type": "hms"}]
        if sql == "SHOW CATALOG `hms_prod`":
            return [{"Key": "type", "Value": "hms"}]
        if sql == "SHOW FULL COLUMNS FROM `hms_prod`.`analytics`.`events`":
            return [{"Field": "id", "Type": "BIGINT", "Null": "NO"}]
        if sql == "SHOW CREATE TABLE `hms_prod`.`analytics`.`events`":
            return [{"Create Table": "CREATE TABLE events (id BIGINT)"}]
        raise AssertionError(f"Unexpected SQL: {sql}")

    runtime, _ = _runtime(responder)

    with pytest.raises(LakehouseRuntimeFailure) as failure:
        await runtime.inspect_lakehouse_table(
            catalog="hms_prod",
            database="analytics",
            table="events",
        )
    assert (
        failure.value.reason_code
        == "LAKEHOUSE_TABLE_FORMAT_UNSUPPORTED"
    )


@pytest.mark.asyncio
async def test_variant_inspection_binds_path_and_returns_only_type_shape() -> None:
    def responder(sql: str, params: _Params) -> list[dict[str, Any]]:
        if sql == "SHOW FULL COLUMNS FROM `analytics`.`profiles`":
            return [
                {
                    "Field": "payload",
                    "Type": "VARIANT<'$.profile.age': INT>",
                    "Null": "YES",
                }
            ]
        if sql == "SHOW CREATE TABLE `analytics`.`profiles`":
            return [
                {
                    "Create Table": (
                        "CREATE TABLE profiles (payload VARIANT) "
                        "PROPERTIES ("
                        "'storage_format'='V3',"
                        "'variant_enable_doc_mode'='true',"
                        "'variant_sparse_hash_shard_count'='4',"
                        "'password'='do-not-return')"
                    )
                }
            ]
        if sql.startswith(
            "SELECT VARIANT_TYPE(`payload`[%s][%s]) AS `variant_type`"
        ):
            assert params == ("profile", "age")
            assert sql.endswith("LIMIT 2")
            return [
                {"variant_type": '{"":"int"}'},
                {"variant_type": '{"":"bigint"}'},
            ]
        if sql == "SELECT @@version_comment;":
            return [{"@@version_comment": "Apache Doris 4.1.0"}]
        raise AssertionError(f"Unexpected SQL: {sql}")

    runtime, manager = _runtime(responder)
    result = await runtime.inspect_variant_column(
        catalog=None,
        database="analytics",
        table="profiles",
        column="payload",
        path="$.profile.age",
        sample_rows=2,
    )

    assert result["status"] == "partial"
    assert result["data"]["typed_paths"] == [
        {"path": "$.profile.age", "type": "INT"}
    ]
    assert result["data"]["configuration"]["mode"] == "doc"
    assert result["data"]["configuration"]["storage_v3"] is True
    assert result["data"]["advanced_capabilities"]["doc_mode_supported"] is True
    assert result["data"]["shape_sample"]["paths"] == [
        {
            "path": "$.profile.age",
            "types": [
                {"type": "INT", "rows": 1},
                {"type": "BIGINT", "rows": 1},
            ],
            "rows_observed": 2,
            "presence_ratio": 1.0,
        }
    ]
    assert manager.params[-2] == ("profile", "age")
    serialized = str(result)
    assert "do-not-return" not in serialized
    assert "CREATE TABLE profiles (" not in serialized
    assert result["metadata"]["sampled_values_returned"] is False


@pytest.mark.asyncio
async def test_variant_sampling_failure_degrades_without_exposing_values() -> None:
    def responder(sql: str, _params: _Params) -> list[dict[str, Any]]:
        if sql == "SHOW FULL COLUMNS FROM `analytics`.`profiles`":
            return [{"Field": "payload", "Type": "VARIANT", "Null": "YES"}]
        if sql == "SHOW CREATE TABLE `analytics`.`profiles`":
            return [{"Create Table": "CREATE TABLE profiles (payload VARIANT)"}]
        if sql.startswith("SELECT VARIANT_TYPE"):
            raise RuntimeError(1142, "SELECT denied for secret principal")
        if sql == "SELECT @@version_comment;":
            return [{"@@version_comment": "Apache Doris 4.0.6"}]
        raise AssertionError(f"Unexpected SQL: {sql}")

    runtime, _ = _runtime(responder)
    result = await runtime.inspect_variant_column(
        catalog=None,
        database="analytics",
        table="profiles",
        column="payload",
    )

    assert result["status"] == "partial"
    assert result["data"]["shape_sample"]["rows_observed"] == 0
    assert result["data"]["shape_sample"]["paths"] == []
    assert result["evidence"][-1]["reason_code"] == "LAKEHOUSE_PERMISSION_DENIED"
    assert "secret principal" not in str(result)


@pytest.mark.asyncio
async def test_variant_rejects_non_variant_path_injection_and_oversized_sample() -> None:
    def responder(sql: str, _params: _Params) -> list[dict[str, Any]]:
        if sql == "SHOW FULL COLUMNS FROM `analytics`.`profiles`":
            return [{"Field": "payload", "Type": "VARCHAR", "Null": "YES"}]
        raise AssertionError(f"Unexpected SQL: {sql}")

    lakehouse = SimpleNamespace(
        max_catalog_objects=50,
        max_catalog_databases=20,
        max_snapshots=50,
        max_partitions=100,
        max_variant_sample_rows=5,
        max_variant_paths=200,
    )
    runtime, manager = _runtime(responder, lakehouse=lakehouse)

    with pytest.raises(LakehouseRuntimeFailure) as type_failure:
        await runtime.inspect_variant_column(
            catalog=None,
            database="analytics",
            table="profiles",
            column="payload",
        )
    assert type_failure.value.reason_code == "LAKEHOUSE_COLUMN_NOT_VARIANT"

    call_count = len(manager.calls)
    with pytest.raises(LakehouseRuntimeFailure) as path_failure:
        await runtime.inspect_variant_column(
            catalog=None,
            database="analytics",
            table="profiles",
            column="payload",
            path="$['profile']; DROP TABLE users",
        )
    assert path_failure.value.reason_code == "LAKEHOUSE_ARGUMENT_INVALID"
    assert len(manager.calls) == call_count

    with pytest.raises(LakehouseRuntimeFailure) as limit_failure:
        await runtime.inspect_variant_column(
            catalog=None,
            database="analytics",
            table="profiles",
            column="payload",
            sample_rows=6,
        )
    assert limit_failure.value.reason_code == "LAKEHOUSE_ARGUMENT_INVALID"
    assert len(manager.calls) == call_count
