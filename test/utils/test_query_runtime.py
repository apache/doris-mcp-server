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

"""Security and evidence contracts for the formal Query-domain runtime."""

from __future__ import annotations

import math
from contextlib import asynccontextmanager
from decimal import Decimal
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from doris_mcp_server.utils.config import DorisConfig
from doris_mcp_server.utils.db import QueryResult
from doris_mcp_server.utils.doris_http_client import DorisHTTPResponse
from doris_mcp_server.utils.query_runtime import (
    DorisQueryRuntime,
    QueryRuntimeFailure,
    ReadOnlySQLGuard,
)
from doris_mcp_server.utils.security import (
    AuthContext,
    reset_auth_context,
    set_current_auth_context,
)


def _query_result(
    *,
    sql: str = "SELECT 1",
    rows: list[dict[str, Any]] | None = None,
    columns: list[str] | None = None,
    truncated: bool = False,
) -> QueryResult:
    data = rows if rows is not None else [{"answer": 1}]
    return QueryResult(
        data=data,
        metadata={
            "columns": columns or ["answer"],
            "truncated": truncated,
            "result_bytes": 16,
            "truncation_reason": "row_limit" if truncated else None,
        },
        execution_time=0.01,
        row_count=len(data),
        sql=sql,
    )


class _Connection:
    def __init__(
        self,
        results: list[QueryResult] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.results = list(results or [_query_result()])
        self.error = error
        self.calls: list[tuple[str, Any, dict[str, Any]]] = []

    async def execute(
        self,
        sql: str,
        params: Any = None,
        **kwargs: Any,
    ) -> QueryResult:
        self.calls.append((sql, params, kwargs))
        if self.error is not None:
            raise self.error
        if sql.startswith(("USE ", "SET ", "SWITCH ")):
            return _query_result(sql=sql, rows=[], columns=[])
        if self.results:
            return self.results.pop(0)
        return _query_result(sql=sql, rows=[], columns=[])


class _ConnectionManager:
    def __init__(self, connection: _Connection) -> None:
        self.config = DorisConfig()
        self.connection = connection
        self.session_ids: list[str] = []

    @asynccontextmanager
    async def get_connection_context_for_auth_context(
        self,
        session_id: str,
        _auth_context: Any,
    ):
        self.session_ids.append(session_id)
        yield self.connection


def _runtime(
    *,
    connection: _Connection | None = None,
    adbc: Any | None = None,
) -> tuple[DorisQueryRuntime, _ConnectionManager, Any]:
    manager = _ConnectionManager(connection or _Connection())
    adbc_tools = adbc or SimpleNamespace(
        exec_adbc_query=AsyncMock(),
        get_adbc_connection_info=AsyncMock(),
    )
    return DorisQueryRuntime(manager, adbc_tools), manager, adbc_tools


@pytest.mark.parametrize(
    ("sql", "operation"),
    [
        ("SELECT 1", "SELECT"),
        ("WITH value AS (SELECT 1) SELECT * FROM value", "SELECT"),
        ("SHOW DATABASES", "SHOW"),
        ("DESC internal.__internal_schema.audit_log", "DESC"),
        ("DESCRIBE t", "DESCRIBE"),
        ("EXPLAIN SELECT 1", "EXPLAIN"),
        ("EXPLAIN SELECT REPLACE(name, 'a', 'b') FROM t", "EXPLAIN"),
        ("SELECT REPLACE(name, 'a', 'b') FROM t", "SELECT"),
        ("SELECT admin, load FROM metrics", "SELECT"),
        ("SELECT 'DROP TABLE t' AS harmless", "SELECT"),
        ("/* DELETE FROM t */ SELECT 1", "SELECT"),
        ("SELECT 1; /* trailing comment */", "SELECT"),
    ],
)
def test_read_only_guard_accepts_supported_statements(
    sql: str,
    operation: str,
) -> None:
    assert ReadOnlySQLGuard.validate(sql).operation == operation


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 1; SELECT 2",
        "INSERT INTO t VALUES (1)",
        "WITH old AS (SELECT 1) DELETE FROM t",
        "EXPLAIN DELETE FROM t",
        "SELECT * FROM t INTO OUTFILE '/tmp/result'",
        "SELECT SLEEP(1)",
        "SELECT @value := 1",
        "SELECT * FROM t FOR UPDATE",
        "SELECT * FROM t LOCK IN SHARE MODE",
        "/*!50000 DROP TABLE t */ SELECT 1",
        "SET enable_profile=true",
        "USE analytics",
    ],
)
def test_read_only_guard_rejects_mutating_or_side_effecting_sql(
    sql: str,
) -> None:
    with pytest.raises(
        QueryRuntimeFailure,
        match="read-only|allowed|assignment|Locking|comments|export|side-effecting",
    ) as error:
        ReadOnlySQLGuard.validate(sql)

    assert error.value.reason_code == "QUERY_READ_ONLY_VIOLATION"


def test_query_target_rejects_nested_explain() -> None:
    with pytest.raises(QueryRuntimeFailure) as error:
        ReadOnlySQLGuard.validate("EXPLAIN SELECT 1", query_target=True)

    assert error.value.reason_code == "QUERY_READ_ONLY_VIOLATION"


def test_named_parameters_are_exact_and_ignore_literals_and_comments() -> None:
    sql = (
        "SELECT %(customer_id)s AS customer_id, "
        "'%(literal)s' AS literal /* %(comment)s */"
    )

    assert ReadOnlySQLGuard.validate_parameters(
        sql,
        {"customer_id": 7},
    ) == {"customer_id": 7}

    with pytest.raises(QueryRuntimeFailure, match="match exactly"):
        ReadOnlySQLGuard.validate_parameters(
            "SELECT %(customer_id)s",
            {"customer_id": 7, "extra": True},
        )
    with pytest.raises(QueryRuntimeFailure, match="missing"):
        ReadOnlySQLGuard.validate_parameters(
            "SELECT %(customer_id)s",
            None,
        )
    with pytest.raises(QueryRuntimeFailure, match="JSON scalars"):
        ReadOnlySQLGuard.validate_parameters(
            "SELECT %(customer_id)s",
            {"customer_id": {"nested": "not allowed"}},
        )
    with pytest.raises(QueryRuntimeFailure, match="finite"):
        ReadOnlySQLGuard.validate_parameters(
            "SELECT %(customer_id)s",
            {"customer_id": math.inf},
        )
    with pytest.raises(QueryRuntimeFailure, match="Positional"):
        ReadOnlySQLGuard.validate_parameters("SELECT %s", None)


def test_driver_sql_escapes_non_placeholder_percent_signs() -> None:
    sql = (
        "SELECT %(customer_id)s AS customer_id, "
        "'100%' AS ratio, '%(literal)s' AS literal "
        "/* %(comment)s and 50% */"
    )
    parameters = {"customer_id": 7}

    prepared = ReadOnlySQLGuard.prepare_driver_sql(sql, parameters)

    assert prepared % parameters == (
        "SELECT 7 AS customer_id, '100%' AS ratio, "
        "'%(literal)s' AS literal /* %(comment)s and 50% */"
    )


@pytest.mark.asyncio
async def test_execute_query_binds_context_parameters_and_result_limits() -> None:
    runtime, manager, _ = _runtime()

    result = await runtime.execute_query(
        sql="SELECT %(answer)s AS answer, '100%' AS ratio",
        catalog="internal",
        database="analytics",
        parameters={"answer": 42},
        max_rows=25,
        timeout_ms=1500,
    )

    assert result["status"] == "success"
    assert result["data"] == {
        "columns": [{"name": "answer"}],
        "rows": [{"answer": 1}],
        "row_count": 1,
        "truncated": False,
    }
    assert [call[0] for call in manager.connection.calls] == [
        "SWITCH `internal`",
        "USE `analytics`",
        "SELECT %(answer)s AS answer, '100%%' AS ratio",
    ]
    assert manager.connection.calls[-1][1] == {"answer": 42}
    assert manager.connection.calls[-1][2]["max_rows"] == 25
    assert result["metadata"]["limits"]["timeout_seconds"] == 2
    assert manager.connection.is_healthy is False


@pytest.mark.asyncio
async def test_execute_query_preserves_decimal_precision_as_json_string() -> None:
    connection = _Connection(
        results=[
            _query_result(
                rows=[{"amount": Decimal("12345678901234567890.123456789012345678")}],
                columns=["amount"],
            )
        ]
    )
    runtime, _, _ = _runtime(connection=connection)

    result = await runtime.execute_query(sql="SELECT amount FROM payments")

    assert result["data"]["rows"] == [
        {"amount": "12345678901234567890.123456789012345678"}
    ]


@pytest.mark.asyncio
async def test_execute_query_sanitizes_backend_errors() -> None:
    runtime, _, _ = _runtime(
        connection=_Connection(
            error=RuntimeError(
                "access denied for user root password=secret at 10.0.0.8"
            )
        )
    )

    with pytest.raises(QueryRuntimeFailure) as error:
        await runtime.execute_query(sql="SELECT * FROM restricted")

    assert str(error.value) == "Doris denied the query on the active route."
    assert error.value.reason_code == "QUERY_PERMISSION_DENIED"
    assert "secret" not in str(error.value)
    assert "10.0.0.8" not in str(error.value)


@pytest.mark.asyncio
async def test_explain_costs_uses_supported_verbose_syntax() -> None:
    connection = _Connection(
        results=[
            _query_result(
                sql="EXPLAIN VERBOSE SELECT 1",
                rows=[{"Explain String": "PLAN FRAGMENT 0\ncardinality=1"}],
                columns=["Explain String"],
            )
        ]
    )
    runtime, manager, _ = _runtime(connection=connection)
    manager.config.security.max_result_rows = 200

    result = await runtime.explain_query(sql="SELECT 1", level="costs")

    assert connection.calls[0][0] == "EXPLAIN VERBOSE SELECT 1"
    assert connection.calls[0][2]["max_rows"] == 200
    assert result["status"] == "partial"
    assert result["data"]["requested_level"] == "costs"
    assert result["data"]["effective_level"] == "verbose"
    assert "no EXPLAIN COSTS keyword" in result["warnings"][0]


@pytest.mark.asyncio
async def test_explain_reports_bounded_plan_truncation() -> None:
    connection = _Connection(
        results=[
            _query_result(
                sql="EXPLAIN SELECT 1",
                rows=[{"Explain String": "PLAN FRAGMENT 0"}],
                columns=["Explain String"],
                truncated=True,
            )
        ]
    )
    runtime, _, _ = _runtime(connection=connection)

    result = await runtime.explain_query(sql="SELECT 1")

    assert result["status"] == "partial"
    assert result["metadata"]["plan_truncated"] is True
    assert result["metadata"]["truncation_reason"] == "row_limit"
    assert "truncated" in result["warnings"][0]


@pytest.mark.asyncio
async def test_profile_requires_exactly_one_input_and_bounds_text() -> None:
    runtime, _, _ = _runtime()
    runtime._fetch_profile = AsyncMock(  # type: ignore[method-assign]
        return_value={
            "query_id": "query_123",
            "profile_text": "PLAN\n  SCAN\nPeak Memory: 10",
        }
    )

    with pytest.raises(QueryRuntimeFailure, match="exactly one"):
        await runtime.get_query_profile()
    with pytest.raises(QueryRuntimeFailure, match="exactly one"):
        await runtime.get_query_profile(
            query_id="query_123",
            sql="SELECT 1",
        )
    with pytest.raises(QueryRuntimeFailure, match="recent_window_minutes"):
        await runtime.get_query_profile(
            query_id="query_123",
            recent_window_minutes=0,
        )

    result = await runtime.get_query_profile(
        query_id="query_123",
        include_operator_tree=True,
    )

    assert result["status"] == "success"
    assert result["data"]["query_id"] == "query_123"
    assert result["data"]["operator_tree"]
    runtime._fetch_profile.assert_awaited_once_with("query_123")


@pytest.mark.asyncio
async def test_profiled_query_discards_connection_with_session_state() -> None:
    runtime, manager, _ = _runtime()
    limits = runtime._resolve_limits(max_rows=1, timeout_ms=1000)

    await runtime._execute_profiled_statement(
        "SELECT 1",
        trace_id="trace_1",
        database=None,
        limits=limits,
    )

    assert [call[0] for call in manager.connection.calls] == [
        'SET session_context="trace_id:trace_1"',
        "SET enable_profile=true",
        "SELECT 1",
    ]
    assert manager.connection.is_healthy is False


@pytest.mark.asyncio
async def test_profile_http_payload_codes_are_handled_without_leaking_data() -> None:
    runtime, _, _ = _runtime()
    runtime._profile_http_get = AsyncMock(  # type: ignore[method-assign]
        side_effect=[
            DorisHTTPResponse(
                status=400,
                headers={"content-type": "application/json"},
                body=(
                    b'{"msg":"Bad Request","code":403,'
                    b'"data":"internal permission detail"}'
                ),
                url="http://configured-fe/profile",
            ),
            DorisHTTPResponse(
                status=200,
                headers={"content-type": "application/json"},
                body=(b'{"msg":"success","code":0,"data":{"profile":"PLAN\\nSCAN"}}'),
                url="http://configured-fe/profile",
            ),
            DorisHTTPResponse(
                status=400,
                headers={"content-type": "application/json"},
                body=(
                    b'{"msg":"Bad Request","code":403,"data":"secret backend detail"}'
                ),
                url="http://configured-fe/profile",
            ),
        ]
    )

    assert await runtime._fetch_query_id("trace_1") is None
    assert await runtime._fetch_profile("query_1") == {
        "query_id": "query_1",
        "profile_text": "PLAN\nSCAN",
    }
    with pytest.raises(QueryRuntimeFailure) as error:
        await runtime._fetch_profile("query_2")
    assert error.value.reason_code == "QUERY_PROFILE_PERMISSION_DENIED"
    assert "secret" not in str(error.value)


@pytest.mark.asyncio
async def test_profile_content_is_not_used_as_a_not_found_sentinel() -> None:
    runtime, _, _ = _runtime()
    runtime._profile_http_get = AsyncMock(  # type: ignore[method-assign]
        side_effect=[
            DorisHTTPResponse(
                status=200,
                headers={"content-type": "application/json"},
                body=(
                    b'{"msg":"success","code":0,"data":{"profile":'
                    b'"SQL: SELECT * FROM messages WHERE state = \\"not found\\"\\nSCAN"}}'
                ),
                url="http://configured-fe/profile",
            ),
            DorisHTTPResponse(
                status=200,
                headers={"content-type": "application/json"},
                body=b'{"msg":"Not Found","code":404,"data":""}',
                url="http://configured-fe/profile",
            ),
        ]
    )

    profile = await runtime._fetch_profile("query_1")
    assert '"not found"' in profile["profile_text"]

    with pytest.raises(QueryRuntimeFailure) as error:
        await runtime._fetch_profile("query_2")
    assert error.value.reason_code == "QUERY_PROFILE_NOT_FOUND"


@pytest.mark.asyncio
async def test_profile_http_fails_closed_for_doris_oauth_route() -> None:
    runtime, _, _ = _runtime()
    context_token = set_current_auth_context(
        AuthContext(
            auth_method="doris_oauth",
            doris_user="analyst",
        )
    )
    try:
        with pytest.raises(QueryRuntimeFailure) as error:
            await runtime._profile_http_get(
                "/rest/v2/manager/query/profile/text/query_1"
            )
    finally:
        reset_auth_context(context_token)

    assert error.value.reason_code == "QUERY_PROFILE_CREDENTIAL_ROUTE_UNAVAILABLE"
    assert error.value.status_code == 503


@pytest.mark.asyncio
async def test_query_sql_http_evidence_is_validated_and_sanitized() -> None:
    runtime, _, _ = _runtime()
    runtime._profile_http_get = AsyncMock(  # type: ignore[method-assign]
        side_effect=[
            DorisHTTPResponse(
                status=200,
                headers={"content-type": "application/json"},
                body=(b'{"msg":"success","code":0,"data":{"sql":"SELECT 1"}}'),
                url="http://configured-fe/sql",
            ),
            DorisHTTPResponse(
                status=400,
                headers={"content-type": "application/json"},
                body=(
                    b'{"msg":"Bad Request","code":403,"data":"secret backend detail"}'
                ),
                url="http://configured-fe/sql",
            ),
        ]
    )

    assert await runtime._fetch_query_sql("query_1") == "SELECT 1"
    with pytest.raises(QueryRuntimeFailure) as error:
        await runtime._fetch_query_sql("query_2")
    assert error.value.reason_code == "QUERY_PROFILE_PERMISSION_DENIED"
    assert "secret" not in str(error.value)


@pytest.mark.asyncio
async def test_list_slow_queries_uses_bound_filters_and_truncates_sql() -> None:
    long_sql = "SELECT '" + ("x" * 9000) + "'"
    connection = _Connection(
        results=[
            _query_result(
                rows=[
                    {
                        "query_id": "q1",
                        "time": "2026-07-31 00:00:00",
                        "user": "analyst",
                        "catalog": "internal",
                        "db": "analytics",
                        "state": "EOF",
                        "query_time": 2500,
                        "cpu_time_ms": 125,
                        "scan_bytes": 2048,
                        "scan_rows": 100,
                        "return_rows": 1,
                        "peak_memory_bytes": 4096,
                        "sql_hash": "hash",
                        "sql_digest": "digest",
                        "stmt": long_sql,
                    }
                ],
                columns=["query_id"],
            )
        ]
    )
    runtime, _, _ = _runtime(connection=connection)

    result = await runtime.list_slow_queries(
        window_minutes=15,
        limit=10,
        min_duration_ms=2000,
        database="analytics",
        user="analyst",
    )

    sql, params, _ = connection.calls[0]
    assert "(%s IS NULL OR `db` = %s)" in sql
    assert "(%s IS NULL OR `user` = %s)" in sql
    assert "`state` <> 'ERR'" not in sql
    assert params[1:] == (
        2000,
        "analytics",
        "analytics",
        "analyst",
        "analyst",
        11,
    )
    item = result["data"]["items"][0]
    assert len(item["sql"]) == 8192
    assert item["sql_truncated"] is True


@pytest.mark.asyncio
async def test_list_slow_queries_rejects_unsafe_filter_before_doris() -> None:
    runtime, manager, _ = _runtime()

    with pytest.raises(QueryRuntimeFailure) as error:
        await runtime.list_slow_queries(database="analytics`; DROP TABLE t")

    assert error.value.reason_code == "QUERY_ARGUMENT_INVALID"
    assert manager.connection.calls == []


@pytest.mark.asyncio
async def test_list_slow_queries_masks_audit_rows_for_requester() -> None:
    audit_row = {
        "query_id": "q1",
        "time": "2026-07-31 00:00:00",
        "user": "analyst",
        "catalog": "internal",
        "db": "analytics",
        "state": "EOF",
        "query_time": 2500,
        "stmt": "SELECT secret_phone FROM customers",
    }
    runtime, manager, _ = _runtime(
        connection=_Connection(
            results=[_query_result(rows=[audit_row], columns=["query_id"])]
        )
    )
    manager.security_manager = SimpleNamespace(
        apply_data_masking=AsyncMock(
            return_value=[{**audit_row, "stmt": "SELECT [MASKED]"}]
        )
    )
    context_token = set_current_auth_context(
        AuthContext(auth_method="token", user_id="reader")
    )
    try:
        result = await runtime.list_slow_queries(limit=1)
    finally:
        reset_auth_context(context_token)

    assert result["data"]["items"][0]["sql"] == "SELECT [MASKED]"
    manager.security_manager.apply_data_masking.assert_awaited_once()


@pytest.mark.asyncio
async def test_slow_query_bounds_distinguish_zero_from_missing_values() -> None:
    runtime, manager, _ = _runtime(
        connection=_Connection(results=[_query_result(rows=[])])
    )

    result = await runtime.list_slow_queries(min_duration_ms=0)

    _, params, _ = manager.connection.calls[0]
    assert params[1] == 0
    assert result["status"] == "success"

    with pytest.raises(QueryRuntimeFailure):
        await runtime.list_slow_queries(window_minutes=0)
    with pytest.raises(QueryRuntimeFailure):
        await runtime.list_slow_queries(limit=0)


@pytest.mark.asyncio
async def test_adbc_guard_runs_before_provider_and_normalizes_rows() -> None:
    adbc = SimpleNamespace(
        exec_adbc_query=AsyncMock(
            return_value={
                "success": True,
                "result": {
                    "format": "dict",
                    "column_names": ["id"],
                    "column_types": ["BIGINT"],
                    "num_rows": 1,
                    "data": [{"id": 1}],
                },
                "truncated": False,
                "execution_time": 0.01,
            }
        ),
        get_adbc_connection_info=AsyncMock(),
    )
    runtime, _, _ = _runtime(adbc=adbc)

    with pytest.raises(QueryRuntimeFailure) as error:
        await runtime.execute_adbc_query(sql="DROP TABLE customer")
    assert error.value.reason_code == "QUERY_READ_ONLY_VIOLATION"
    adbc.exec_adbc_query.assert_not_awaited()

    result = await runtime.execute_adbc_query(
        sql="SELECT id FROM customer",
        max_rows=10,
        timeout_ms=2000,
        result_format="dict",
    )

    assert result["data"]["columns"] == [{"name": "id", "type": "BIGINT"}]
    assert result["data"]["rows"] == [{"id": 1}]
    adbc.exec_adbc_query.assert_awaited_once_with(
        "SELECT id FROM customer",
        max_rows=10,
        timeout=2,
        return_format="dict",
    )


@pytest.mark.asyncio
async def test_adbc_rejects_invalid_runtime_options_before_provider() -> None:
    adbc = SimpleNamespace(
        exec_adbc_query=AsyncMock(),
        get_adbc_connection_info=AsyncMock(),
    )
    runtime, _, _ = _runtime(adbc=adbc)

    with pytest.raises(QueryRuntimeFailure, match="format"):
        await runtime.execute_adbc_query(
            sql="SELECT 1",
            result_format="csv",
        )
    with pytest.raises(QueryRuntimeFailure, match="timeout_ms"):
        await runtime.execute_adbc_query(
            sql="SELECT 1",
            timeout_ms=0,
        )

    adbc.exec_adbc_query.assert_not_awaited()


@pytest.mark.asyncio
async def test_adbc_connection_info_never_returns_endpoint_or_identity() -> None:
    adbc = SimpleNamespace(
        exec_adbc_query=AsyncMock(),
        get_adbc_connection_info=AsyncMock(
            return_value={
                "status": "ready",
                "configuration": {
                    "fe_host": "10.0.0.8",
                    "fe_arrow_flight_port": "8070",
                    "be_arrow_flight_port": "8060",
                    "user": "root",
                },
                "port_status": {
                    "success": True,
                    "be_available_count": 1,
                    "be_check_results": [{"host": "10.0.0.9", "port": 8060}],
                },
                "module_status": {
                    "success": True,
                    "adbc_manager_version": "1.8.0",
                    "flight_sql_version": "1.8.0",
                },
            }
        ),
    )
    runtime, _, _ = _runtime(adbc=adbc)

    result = await runtime.get_adbc_connection_info()
    serialized = repr(result)

    assert result["data"]["status"] == "ready"
    assert "10.0.0.8" not in serialized
    assert "10.0.0.9" not in serialized
    assert "root" not in serialized


@pytest.mark.asyncio
async def test_diagnosis_is_deterministic_and_marks_missing_optional_evidence() -> None:
    runtime, _, _ = _runtime()
    runtime.explain_query = AsyncMock(  # type: ignore[method-assign]
        return_value={
            "status": "success",
            "data": {"plan_text": "CROSS JOIN", "facets": {}},
            "warnings": [],
            "metadata": {"source": "doris_explain"},
            "evidence": [{"source": "doris_sql", "kind": "explain"}],
        }
    )
    runtime.get_query_profile = AsyncMock(  # type: ignore[method-assign]
        side_effect=QueryRuntimeFailure(
            "Profile unavailable.",
            reason_code="QUERY_PROFILE_NOT_FOUND",
            status_code=404,
        )
    )
    runtime._find_audit_record = AsyncMock(  # type: ignore[method-assign]
        return_value=None
    )

    result = await runtime.diagnose_query_performance(
        sql="SELECT * FROM a CROSS JOIN b",
        include_cluster_context=True,
    )

    assert result["status"] == "partial"
    assert result["metadata"]["rule_version"] == "query-diagnosis-v1"
    assert result["data"]["findings"] == [
        {
            "code": "CROSS_JOIN_OBSERVED",
            "severity": "high",
            "evidence": "The Doris explain plan contains CROSS JOIN.",
        }
    ]
    assert result["data"]["recommendations"][0]["finding_code"] == (
        "CROSS_JOIN_OBSERVED"
    )
    assert result["data"]["cluster_context"]["reason_code"] == (
        "CLUSTER_DOMAIN_NOT_YET_IMPLEMENTED"
    )
    assert (
        result["data"]["steps"]["cluster_context"]
        is not result["data"]["cluster_context"]
    )


@pytest.mark.asyncio
async def test_diagnosis_uses_profile_sql_when_audit_record_is_missing() -> None:
    runtime, _, _ = _runtime()
    runtime._find_audit_record = AsyncMock(  # type: ignore[method-assign]
        return_value=None
    )
    runtime._fetch_query_sql = AsyncMock(  # type: ignore[method-assign]
        return_value="SELECT 1"
    )
    runtime.explain_query = AsyncMock(  # type: ignore[method-assign]
        return_value={
            "status": "success",
            "data": {"plan_text": "SCAN", "facets": {}},
            "warnings": [],
            "metadata": {"source": "doris_explain"},
            "evidence": [{"source": "doris_sql", "kind": "explain"}],
        }
    )
    runtime.get_query_profile = AsyncMock(  # type: ignore[method-assign]
        return_value={
            "status": "success",
            "data": {"query_id": "query_1", "profile": "SCAN"},
            "warnings": [],
            "metadata": {"source": "doris_profile_api"},
            "evidence": [{"source": "doris_fe_http", "kind": "query_profile"}],
        }
    )

    result = await runtime.diagnose_query_performance(query_id="query_1")

    assert result["status"] == "partial"
    runtime._fetch_query_sql.assert_awaited_once_with("query_1")
    runtime.explain_query.assert_awaited_once_with(
        sql="SELECT 1",
        catalog=None,
        database=None,
        level="verbose",
    )


@pytest.mark.asyncio
async def test_diagnosis_reuses_audit_context_masks_output_and_propagates_partial() -> (
    None
):
    audit_row = {
        "query_id": "query_1",
        "time": "2026-07-31 00:00:00",
        "user": "analyst",
        "catalog": "internal",
        "db": "analytics",
        "state": "EOF",
        "query_time": 2500,
        "stmt": "SELECT * FROM orders",
    }
    runtime, manager, _ = _runtime()
    runtime._find_audit_record = AsyncMock(  # type: ignore[method-assign]
        return_value=audit_row
    )
    runtime.explain_query = AsyncMock(  # type: ignore[method-assign]
        return_value={
            "status": "partial",
            "data": {"plan_text": "SCAN", "facets": {}},
            "warnings": ["The EXPLAIN output was truncated."],
            "metadata": {"source": "doris_explain"},
            "evidence": [{"source": "doris_sql", "kind": "explain"}],
        }
    )
    runtime.get_query_profile = AsyncMock(  # type: ignore[method-assign]
        return_value={
            "status": "partial",
            "data": {"query_id": "query_1", "profile": "SCAN"},
            "warnings": ["Profile text was truncated."],
            "metadata": {"source": "doris_profile_api"},
            "evidence": [{"source": "doris_fe_http", "kind": "query_profile"}],
        }
    )
    manager.security_manager = SimpleNamespace(
        apply_data_masking=AsyncMock(
            return_value=[{**audit_row, "stmt": "SELECT [MASKED]"}]
        )
    )
    context_token = set_current_auth_context(
        AuthContext(auth_method="token", user_id="reader")
    )
    try:
        result = await runtime.diagnose_query_performance(query_id="query_1")
    finally:
        reset_auth_context(context_token)

    runtime.explain_query.assert_awaited_once_with(
        sql="SELECT * FROM orders",
        catalog="internal",
        database="analytics",
        level="verbose",
    )
    assert result["status"] == "partial"
    assert result["warnings"] == [
        "The EXPLAIN output was truncated.",
        "Profile text was truncated.",
    ]
    assert result["data"]["steps"]["explain"]["status"] == "partial"
    assert result["data"]["steps"]["profile"]["status"] == "partial"
    assert result["data"]["audit_record"]["sql"] == "SELECT [MASKED]"
    manager.security_manager.apply_data_masking.assert_awaited_once()
