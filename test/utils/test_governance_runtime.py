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

"""Production evidence contracts for the formal Governance runtime."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any

import pytest

from doris_mcp_server.utils.governance_runtime import (
    DorisGovernanceRuntime,
    DorisLineageStoreProvider,
    GovernanceRuntimeFailure,
    LineageProviderStatus,
)

_Params = Mapping[str, Any] | tuple[Any, ...] | None
_Responder = Callable[[str, _Params], list[dict[str, Any]]]


class _ConnectionManager:
    def __init__(
        self,
        responder: _Responder,
        *,
        governance: Any | None = None,
    ) -> None:
        self._responder = responder
        self.calls: list[str] = []
        self.params: list[_Params] = []
        self.context_count = 0
        self.config = SimpleNamespace(
            governance=governance
            or SimpleNamespace(
                max_sample_ratio=0.25,
                max_audit_window_days=30,
                max_lineage_edges=500,
                lineage_store_table="",
                lineage_recent_event_minutes=1440,
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
                **_kwargs: Any,
            ) -> SimpleNamespace:
                manager.calls.append(sql)
                manager.params.append(params)
                return SimpleNamespace(data=manager._responder(sql, params))

        yield _Connection()


def _runtime(
    responder: _Responder,
    *,
    governance: Any | None = None,
    lineage_provider: Any | None = None,
) -> tuple[DorisGovernanceRuntime, _ConnectionManager]:
    manager = _ConnectionManager(responder, governance=governance)
    runtime = DorisGovernanceRuntime(
        manager,  # type: ignore[arg-type]
        lineage_provider=lineage_provider,
    )
    return runtime, manager


def _lineage_responder(
    sql: str,
    _params: _Params,
    *,
    version: str,
    plugin: str = "",
    audit_available: bool = True,
) -> list[dict[str, Any]]:
    if sql == "SELECT @@version_comment;":
        return [{"version_comment": version}]
    if sql == "SHOW FRONTENDS":
        return [{"Version": version}]
    if sql == "SHOW FRONTEND CONFIG LIKE 'activate_lineage_plugin'":
        return [{"Value": plugin}] if plugin else []
    if sql == "SHOW FRONTEND CONFIG LIKE 'lineage_event_queue_size'":
        return [{"Value": "1000"}] if plugin else []
    if sql.startswith("SELECT `time`, `query_id` FROM"):
        if not audit_available:
            raise RuntimeError(1146, "audit metadata unavailable")
        return [{"time": "2026-07-31 10:00:00", "query_id": "audit-1"}]
    return []


@pytest.mark.asyncio
async def test_column_analysis_uses_recorded_stats_and_clamps_live_sampling() -> None:
    def responder(sql: str, _params: _Params) -> list[dict[str, Any]]:
        if "FROM information_schema.columns" in sql:
            return [
                {
                    "COLUMN_NAME": "id",
                    "DATA_TYPE": "BIGINT",
                    "IS_NULLABLE": "NO",
                    "ORDINAL_POSITION": 1,
                },
                {
                    "COLUMN_NAME": "email",
                    "DATA_TYPE": "VARCHAR",
                    "IS_NULLABLE": "YES",
                    "ORDINAL_POSITION": 2,
                },
            ]
        if sql.startswith("SHOW COLUMN STATS"):
            return [
                {
                    "column_name": "id",
                    "count": 100,
                    "ndv": 100,
                    "num_null": 0,
                    "data_size": 800,
                },
                {
                    "column_name": "email",
                    "count": 100,
                    "ndv": 80,
                    "num_null": 10,
                    "data_size": 1200,
                },
            ]
        if "TABLESAMPLE 25 PERCENT REPEATABLE 1" in sql:
            return [
                {
                    "sample_rows": 25,
                    "c0_non_null": 25,
                    "c0_ndv": 25,
                    "c1_non_null": 20,
                    "c1_ndv": 18,
                }
            ]
        raise AssertionError(f"Unexpected SQL: {sql}")

    runtime, manager = _runtime(responder)
    result = await runtime.analyze_columns(
        database="analytics",
        table="customers",
        columns=None,
        sample_ratio=0.9,
    )

    assert result["status"] == "partial"
    assert result["data"]["sample_ratio_requested"] == 0.9
    assert result["data"]["sample_ratio_applied"] == 0.25
    assert result["data"]["columns"][1]["statistics"]["null_ratio"] == 0.1
    assert result["data"]["columns"][1]["sample"]["null_ratio"] == 0.2
    assert any("configured Governance ceiling" in item for item in result["warnings"])
    assert manager.params[0] == ("analytics", "customers")
    assert any("TABLESAMPLE 25 PERCENT" in sql for sql in manager.calls)


@pytest.mark.asyncio
async def test_column_analysis_rejects_identifier_injection_before_sql() -> None:
    runtime, manager = _runtime(lambda _sql, _params: [])

    with pytest.raises(GovernanceRuntimeFailure) as failure:
        await runtime.analyze_columns(
            database="analytics",
            table="orders; DROP TABLE users",
            columns=None,
            sample_ratio=None,
        )

    assert failure.value.reason_code == "GOVERNANCE_ARGUMENT_INVALID"
    assert manager.calls == []


@pytest.mark.asyncio
async def test_storage_analysis_keeps_optional_failures_and_raw_ddl_private() -> None:
    def responder(sql: str, _params: _Params) -> list[dict[str, Any]]:
        if "FROM information_schema.tables" in sql:
            return [
                {
                    "TABLE_TYPE": "BASE TABLE",
                    "ENGINE": "OLAP",
                    "TABLE_ROWS": 120,
                    "DATA_LENGTH": 4096,
                }
            ]
        if sql.startswith("SHOW TABLE STATS"):
            raise RuntimeError(1105, "table stats disabled")
        if sql.startswith("SHOW CREATE TABLE"):
            return [
                {
                    "Create Table": (
                        "CREATE TABLE orders (id BIGINT) PROPERTIES ("
                        '"compression"="zstd",'
                        '"password"="do-not-return",'
                        '"enable_unique_key_merge_on_write"="true")'
                    )
                }
            ]
        if sql.startswith("SHOW PARTITIONS"):
            return [
                {
                    "PartitionName": "p202607",
                    "State": "NORMAL",
                    "VisibleVersion": 7,
                    "ReplicationNum": 3,
                }
            ]
        if sql.startswith("SHOW INDEX"):
            return [
                {
                    "Key_name": "idx_message",
                    "Column_name": "message",
                    "Index_type": "INVERTED",
                }
            ]
        raise AssertionError(f"Unexpected SQL: {sql}")

    runtime, _ = _runtime(responder)
    result = await runtime.analyze_table_storage(
        database="analytics",
        table="orders",
        include_partitions=True,
        include_indexes=True,
    )

    assert result["status"] == "partial"
    assert result["data"]["properties"]["compression"] == "zstd"
    assert result["data"]["features"]["merge_on_write"] == "true"
    assert result["data"]["partitions"][0]["name"] == "p202607"
    assert result["data"]["indexes"][0]["type"] == "INVERTED"
    serialized = str(result)
    assert "do-not-return" not in serialized
    assert "CREATE TABLE orders" not in serialized


@pytest.mark.asyncio
async def test_lineage_before_406_uses_audit_as_primary_path() -> None:
    runtime, _ = _runtime(
        lambda sql, params: _lineage_responder(
            sql,
            params,
            version="Doris version doris-4.0.5-rc01",
        )
    )

    result = await runtime.get_lineage_capability_status()

    assert result["data"]["status"] == "available"
    assert result["data"]["active_path"] == "audit_sql_inference"
    assert result["data"]["native_spi"]["all_frontends_eligible"] is False


@pytest.mark.asyncio
async def test_lineage_406_without_plugin_uses_explicit_degraded_audit_fallback() -> (
    None
):
    runtime, _ = _runtime(
        lambda sql, params: _lineage_responder(
            sql,
            params,
            version="Doris version doris-4.0.6-43f06a5e26 (Cloud Mode)",
        )
    )

    result = await runtime.get_lineage_capability_status()

    assert result["status"] == "partial"
    assert result["data"]["status"] == "degraded"
    assert result["data"]["active_path"] == "audit_sql_inference"
    assert result["data"]["native_spi"]["all_frontends_eligible"] is True


@pytest.mark.asyncio
async def test_explicit_native_lineage_fails_when_native_path_is_unavailable() -> None:
    runtime, _ = _runtime(
        lambda sql, params: _lineage_responder(
            sql,
            params,
            version="Doris version doris-4.0.6-43f06a5e26",
        )
    )

    with pytest.raises(GovernanceRuntimeFailure) as failure:
        await runtime.trace_column_lineage(
            object_name="analytics.orders",
            column=None,
            direction="upstream",
            depth=1,
            evidence_mode="native",
        )

    assert failure.value.reason_code == "GOVERNANCE_NATIVE_LINEAGE_UNAVAILABLE"


class _NativeProvider:
    def __init__(self) -> None:
        self.trace_calls: list[dict[str, Any]] = []

    async def status(self) -> LineageProviderStatus:
        return LineageProviderStatus(
            provider_id="doris_native_event_store",
            status="available",
            queryable=True,
            row_count=12,
            latest_event_time="2026-07-31 10:00:00",
            recent_event_observed=True,
        )

    async def trace(self, **kwargs: Any) -> dict[str, Any]:
        self.trace_calls.append(kwargs)
        return {
            "edges": [
                {
                    "source_object": "internal.analytics.raw_orders",
                    "source_column": "id",
                    "target_object": "internal.analytics.orders",
                    "target_column": "id",
                    "evidence_type": "native_event",
                    "source_event_id": "native-1",
                    "limitations": [],
                }
            ],
            "rows_observed": 1,
            "truncated": False,
            "limitations": [],
        }


@pytest.mark.asyncio
async def test_native_lineage_provider_is_selected_deterministically() -> None:
    provider = _NativeProvider()
    runtime, _ = _runtime(
        lambda sql, params: _lineage_responder(
            sql,
            params,
            version="Doris version doris-4.1.2-43f06a5e26 (Cloud Mode)",
            plugin="mcp_lineage_sink",
        ),
        lineage_provider=provider,
    )

    result = await runtime.trace_column_lineage(
        object_name="analytics.orders",
        column="id",
        direction="upstream",
        depth=2,
        evidence_mode="auto",
    )

    assert result["data"]["active_path"] == "doris_native_event_store"
    assert result["data"]["edges"][0]["source_event_id"] == "native-1"
    assert provider.trace_calls == [
        {
            "object_name": "internal.analytics.orders",
            "column": "id",
            "direction": "upstream",
            "depth": 2,
            "max_edges": 500,
        }
    ]
    assert result["metadata"]["numeric_confidence_emitted"] is False
    assert "confidence" not in result["data"]["edges"][0]


def _audit_schema() -> list[dict[str, Any]]:
    return [
        {"Field": field}
        for field in (
            "query_id",
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
            "queried_tables_and_views",
            "stmt",
        )
    ]


@pytest.mark.asyncio
async def test_audit_lineage_emits_only_simple_direct_column_evidence() -> None:
    statement = (
        "INSERT INTO analytics.orders (id, amount) "
        "SELECT id, amount FROM analytics.raw_orders"
    )

    def responder(sql: str, params: _Params) -> list[dict[str, Any]]:
        base = _lineage_responder(
            sql,
            params,
            version="Doris version doris-4.0.5",
        )
        if base:
            return base
        if sql == "DESC internal.__internal_schema.audit_log":
            return _audit_schema()
        if "WHERE `time` >= DATE_SUB" in sql:
            return [
                {
                    "query_id": "audit-insert-1",
                    "time": "2026-07-31 09:00:00",
                    "user": "alice",
                    "catalog": "internal",
                    "db": "analytics",
                    "state": "OK",
                    "error_code": 0,
                    "stmt_type": "INSERT",
                    "stmt": statement,
                },
                {
                    "query_id": "audit-select-1",
                    "time": "2026-07-31 08:00:00",
                    "state": "OK",
                    "stmt_type": "SELECT",
                    "stmt": "SELECT id FROM analytics.raw_orders",
                },
            ]
        return []

    runtime, _ = _runtime(responder)
    result = await runtime.trace_column_lineage(
        object_name="analytics.orders",
        column="amount",
        direction="upstream",
        depth=3,
        evidence_mode="audit",
    )

    assert result["data"]["edge_count"] == 1
    edge = result["data"]["edges"][0]
    assert edge["source_object"] == "internal.analytics.raw_orders"
    assert edge["source_column"] == "amount"
    assert edge["target_object"] == "internal.analytics.orders"
    assert edge["target_column"] == "amount"
    assert edge["evidence_type"] == "audit_sql_inference"
    assert result["metadata"]["numeric_confidence_emitted"] is False
    assert "confidence" not in edge


@pytest.mark.asyncio
async def test_audit_lineage_returns_no_placeholder_when_evidence_has_no_edge() -> None:
    def responder(sql: str, params: _Params) -> list[dict[str, Any]]:
        base = _lineage_responder(
            sql,
            params,
            version="Doris version doris-4.0.5",
        )
        if base:
            return base
        if sql == "DESC internal.__internal_schema.audit_log":
            return _audit_schema()
        if "WHERE `time` >= DATE_SUB" in sql:
            return [
                {
                    "query_id": "audit-select-1",
                    "time": "2026-07-31 08:00:00",
                    "state": "OK",
                    "stmt_type": "SELECT",
                    "stmt": "SELECT id FROM analytics.raw_orders",
                }
            ]
        return []

    runtime, _ = _runtime(responder)
    result = await runtime.trace_column_lineage(
        object_name="analytics.orders",
        column=None,
        direction="both",
        depth=3,
        evidence_mode="auto",
    )

    assert result["data"]["edges"] == []
    assert result["data"]["determinate"] is False
    assert "unknown_source" not in str(result)
    assert any("no placeholder edge" in item for item in result["warnings"])


@pytest.mark.asyncio
async def test_recent_audit_logs_are_bounded_and_redacted() -> None:
    def responder(sql: str, _params: _Params) -> list[dict[str, Any]]:
        if sql == "DESC internal.__internal_schema.audit_log":
            return _audit_schema()
        if "WHERE `time` >= DATE_SUB" in sql:
            return [
                {
                    "query_id": "query-1",
                    "time": "2026-07-31 08:00:00",
                    "user": "alice@example.com",
                    "catalog": "internal",
                    "db": "analytics",
                    "state": "FAILED",
                    "error_code": 1105,
                    "stmt_type": "SELECT",
                    "stmt": "SELECT * FROM secret_table WHERE password='secret'",
                    "queried_tables_and_views": '["analytics.orders"]',
                    "client_ip": "10.0.0.8",
                    "error_message": "password=secret",
                }
            ]
        raise AssertionError(f"Unexpected SQL: {sql}")

    runtime, manager = _runtime(responder)
    result = await runtime.get_recent_audit_logs(
        window_minutes=60,
        user=None,
        operation=None,
        database=None,
        table=None,
        limit=10,
    )

    item = result["data"]["items"][0]
    assert item["principal"].startswith("principal:")
    assert item["referenced_objects"] == ("internal.analytics.orders",)
    serialized = str(result)
    assert "alice@example.com" not in serialized
    assert "password='secret'" not in serialized
    assert "10.0.0.8" not in serialized
    assert manager.params[-1] == (60,)


@pytest.mark.asyncio
async def test_access_patterns_pseudonymize_principals() -> None:
    def responder(sql: str, _params: _Params) -> list[dict[str, Any]]:
        if sql == "DESC internal.__internal_schema.audit_log":
            return _audit_schema()
        if "WHERE `time` >= DATE_SUB" in sql:
            return [
                {
                    "query_id": "query-1",
                    "time": "2026-07-31 08:00:00",
                    "user": "alice",
                    "state": "OK",
                    "error_code": 0,
                    "query_time": 12,
                    "scan_bytes": 100,
                    "scan_rows": 10,
                    "return_rows": 2,
                    "stmt_type": "SELECT",
                    "queried_tables_and_views": '["analytics.orders"]',
                }
            ]
        raise AssertionError(f"Unexpected SQL: {sql}")

    runtime, _ = _runtime(responder)
    result = await runtime.analyze_data_access_patterns(
        database=None,
        table=None,
        window_days=1,
        group_by="user",
    )

    assert result["data"]["items"][0]["group"].startswith("principal:")
    assert "alice" not in str(result)


@pytest.mark.asyncio
async def test_udf_listing_does_not_expose_object_location() -> None:
    def responder(sql: str, _params: _Params) -> list[dict[str, Any]]:
        if sql == "SHOW FULL FUNCTIONS IN `analytics`":
            return [
                {
                    "Signature": "normalize_email(VARCHAR)",
                    "Function Type": "SCALAR",
                    "Return Type": "VARCHAR",
                    "Properties": (
                        '{"type":"JAVA_UDF","object_file":'
                        '"s3://private-bucket/udf.jar?token=secret",'
                        '"runtime_version":"17"}'
                    ),
                }
            ]
        raise AssertionError(f"Unexpected SQL: {sql}")

    runtime, _ = _runtime(responder)
    result = await runtime.list_udfs(
        database="analytics",
        language="java",
        name_pattern="normalize%",
    )

    assert result["data"]["items"][0]["language"] == "java"
    assert result["data"]["items"][0]["runtime_version"] == "17"
    serialized = str(result)
    assert "private-bucket" not in serialized
    assert "token=secret" not in serialized


@pytest.mark.asyncio
async def test_auth_mapping_status_redacts_rules_secrets_and_principals() -> None:
    def responder(sql: str, _params: _Params) -> list[dict[str, Any]]:
        if sql == "SELECT * FROM information_schema.role_mappings LIMIT 500":
            return [
                {
                    "mapping_name": "engineering",
                    "claim_value": "alice@example.com",
                    "roles": "analyst,reader",
                    "enabled": True,
                    "rule": "groups contains secret-admin",
                    "client_secret": "do-not-return",
                }
            ]
        if sql == "SHOW ROLES":
            return [{"Role": "analyst", "Users": "alice,bob"}]
        raise AssertionError(f"Unexpected SQL: {sql}")

    runtime, _ = _runtime(responder)
    result = await runtime.get_auth_mapping_status(
        principal=None,
        provider="oidc",
        include_roles=True,
    )

    mapping = result["data"]["providers"][0]["mappings"][0]
    assert mapping["principal"].startswith("principal:")
    assert mapping["roles"] == ["analyst", "reader"]
    assert mapping["rule_redacted"] is True
    serialized = str(result)
    assert "alice@example.com" not in serialized
    assert "secret-admin" not in serialized
    assert "do-not-return" not in serialized


@pytest.mark.asyncio
async def test_ldap_mapping_status_exposes_only_safe_configuration_facets() -> None:
    values = {
        "authentication_type": "ldap",
        "ldap_authentication_enabled": "true",
        "ldap_use_ssl": "true",
        "ldap_default_roles": "reader,analyst",
    }

    def responder(sql: str, _params: _Params) -> list[dict[str, Any]]:
        for name, value in values.items():
            if sql == f"SHOW FRONTEND CONFIG LIKE '{name}'":
                return [
                    {
                        "Value": value,
                        "Password": "ldap-bind-secret",
                        "Host": "ldap.private.example",
                    }
                ]
        raise AssertionError(f"Unexpected SQL: {sql}")

    runtime, _ = _runtime(responder)
    result = await runtime.get_auth_mapping_status(
        principal=None,
        provider="ldap",
        include_roles=False,
    )

    provider = result["data"]["providers"][0]
    assert provider["status"] == "configured"
    assert provider["tls_enabled"] is True
    assert provider["default_roles"] == ["reader", "analyst"]
    serialized = str(result)
    assert "ldap-bind-secret" not in serialized
    assert "ldap.private.example" not in serialized


@pytest.mark.asyncio
async def test_lineage_store_validates_schema_and_preserves_parameter_order() -> None:
    observed_params: list[_Params] = []

    def responder(sql: str, params: _Params) -> list[dict[str, Any]]:
        observed_params.append(params)
        if sql == "DESC `governance`.`lineage_events`":
            return [
                {"Field": name}
                for name in (
                    "event_id",
                    "event_time",
                    "source_object",
                    "target_object",
                    "source_column",
                    "target_column",
                    "query_id",
                )
            ]
        if sql.startswith("SELECT COUNT(*) AS row_count"):
            return [
                {
                    "row_count": 1,
                    "latest_event_time": "2026-07-31 08:00:00",
                    "recent_event_count": 1,
                }
            ]
        if sql.startswith("SELECT `event_id`"):
            return [
                {
                    "event_id": "event-1",
                    "event_time": "2026-07-31 08:00:00",
                    "source_object": "internal.analytics.raw_orders",
                    "target_object": "internal.analytics.orders",
                    "source_column": "id",
                    "target_column": "id",
                    "query_id": "query-1",
                }
            ]
        raise AssertionError(f"Unexpected SQL: {sql}")

    manager = _ConnectionManager(responder)
    provider = DorisLineageStoreProvider(
        manager,  # type: ignore[arg-type]
        table="governance.lineage_events",
        recent_event_minutes=120,
    )
    result = await provider.trace(
        object_name="internal.analytics.orders",
        column="id",
        direction="both",
        depth=1,
        max_edges=10,
    )

    assert result["edges"][0]["evidence_type"] == "native_event"
    assert observed_params[1] == (120,)
    assert observed_params[2] == (
        "internal.analytics.orders",
        "internal.analytics.orders",
        "id",
        "id",
    )


@pytest.mark.asyncio
async def test_lineage_store_rejects_noncanonical_schema() -> None:
    manager = _ConnectionManager(
        lambda sql, _params: (
            [
                {"Field": "event_id"},
                {"Field": "event_time"},
                {"Field": "target_object"},
            ]
            if sql == "DESC `governance`.`lineage_events`"
            else []
        )
    )
    provider = DorisLineageStoreProvider(
        manager,  # type: ignore[arg-type]
        table="governance.lineage_events",
        recent_event_minutes=120,
    )

    status = await provider.status()

    assert status.status == "misconfigured"
    assert status.queryable is False
    assert "source_object" in status.limitations[0]
