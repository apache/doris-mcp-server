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

"""Production contracts for the formal read-only Search runtime."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from doris_mcp_server.utils.db import QueryResult
from doris_mcp_server.utils.search_runtime import (
    DorisSearchRuntime,
    SearchRuntimeFailure,
)

_COLUMN_SQL = (
    "SELECT COLUMN_NAME, DATA_TYPE "
    "FROM information_schema.columns "
    "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s "
    "ORDER BY ORDINAL_POSITION LIMIT 2048"
)
_INDEX_SQL = "SHOW INDEX FROM `analytics`.`documents`"


def _columns() -> list[dict[str, Any]]:
    return [
        {"COLUMN_NAME": "id", "DATA_TYPE": "BIGINT"},
        {"COLUMN_NAME": "title", "DATA_TYPE": "TEXT"},
        {"COLUMN_NAME": "category", "DATA_TYPE": "VARCHAR"},
        {"COLUMN_NAME": "embedding", "DATA_TYPE": "ARRAY<FLOAT>"},
    ]


def _indexes(
    *,
    inverted: bool = True,
    ann: bool = True,
    metric: str = "l2_distance",
    dimension: int = 3,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if inverted:
        rows.append(
            {
                "Key_name": "idx_title",
                "Column_name": "title",
                "Index_type": "INVERTED",
                "Properties": (
                    '"parser" = "english", '
                    '"support_phrase" = "true", '
                    '"comment_text" = "café"'
                ),
                "Comment": "title search",
            }
        )
    if ann:
        rows.append(
            {
                "Key_name": "idx_embedding",
                "Column_name": "embedding",
                "Index_type": "ANN",
                "Properties": (
                    '"index_type" = "hnsw", '
                    f'"metric_type" = "{metric}", '
                    f'"dim" = "{dimension}"'
                ),
                "Comment": "vector search",
            }
        )
    return rows


class _ConnectionManager:
    def __init__(
        self,
        *,
        columns: list[dict[str, Any]] | None = None,
        indexes: list[dict[str, Any]] | None = None,
        search_rows: list[dict[str, Any]] | None = None,
        tokenize_payload: Any = None,
        analyzers: list[dict[str, Any]] | None = None,
        build_tasks: list[dict[str, Any]] | None = None,
        plan_rows: list[dict[str, Any]] | None = None,
        failures: dict[str, Exception] | None = None,
    ) -> None:
        self.columns = _columns() if columns is None else columns
        self.indexes = _indexes() if indexes is None else indexes
        self.search_rows = (
            [{"id": 1, "title": "Apache Doris", "category": "database"}]
            if search_rows is None
            else search_rows
        )
        self.tokenize_payload = (
            json.dumps(
                [
                    {"token": "apache", "position": 0, "type": "word"},
                    {"token": "doris", "position": 1, "type": "word"},
                ]
            )
            if tokenize_payload is None
            else tokenize_payload
        )
        self.analyzers = analyzers or []
        self.build_tasks = build_tasks or []
        self.plan_rows = plan_rows or [
            {
                "Explain String": (
                    "0:VTOP-N\nANN SORT INFO: "
                    "l2_distance_approximate(embedding, [0.1,0.2,0.3])\n"
                    "ANN SORT LIMIT: 5\n"
                    "1:VOlapScanNode\nPREDICATES: title MATCH_ANY 'doris'"
                )
            }
        ]
        self.failures = failures or {}
        self.calls: list[dict[str, Any]] = []
        self.context_count = 0

    @asynccontextmanager
    async def get_connection_context_for_auth_context(
        self,
        session_id: str,
        _auth_context: Any,
    ) -> AsyncIterator[Any]:
        self.context_count += 1
        manager = self

        class _Connection:
            async def execute(
                self,
                sql: str,
                params: Mapping[str, Any] | tuple[Any, ...] | None = None,
                **kwargs: Any,
            ) -> QueryResult:
                manager.calls.append(
                    {
                        "session_id": session_id,
                        "sql": sql,
                        "params": params,
                        "kwargs": kwargs,
                    }
                )
                for prefix, failure in manager.failures.items():
                    if sql.startswith(prefix):
                        raise failure
                if sql == _COLUMN_SQL:
                    rows = manager.columns
                elif sql == _INDEX_SQL:
                    rows = manager.indexes
                elif sql == "SHOW INVERTED INDEX ANALYZER":
                    rows = manager.analyzers
                elif sql.startswith("SHOW BUILD INDEX"):
                    rows = manager.build_tasks
                elif sql.startswith("SELECT TOKENIZE"):
                    rows = [{"tokens": manager.tokenize_payload}]
                elif sql.startswith("EXPLAIN "):
                    rows = manager.plan_rows
                elif sql.startswith("USE "):
                    rows = []
                else:
                    rows = manager.search_rows
                columns = list(rows[0]) if rows else []
                return QueryResult(
                    data=rows,
                    metadata={"columns": columns, "truncated": False},
                    execution_time=0.01,
                    row_count=len(rows),
                    sql=sql,
                )

        yield _Connection()


def _runtime(
    manager: _ConnectionManager | None = None,
) -> tuple[DorisSearchRuntime, _ConnectionManager, Any]:
    connection_manager = manager or _ConnectionManager()
    query_runtime = SimpleNamespace(
        get_query_profile=AsyncMock(
            return_value={
                "status": "success",
                "data": {"query_id": "query-1"},
                "warnings": [],
                "evidence": [{"source": "runtime_profile"}],
            }
        )
    )
    return (
        DorisSearchRuntime(  # type: ignore[arg-type]
            connection_manager,
            query_runtime,
        ),
        connection_manager,
        query_runtime,
    )


async def _search(
    runtime: DorisSearchRuntime,
    **overrides: Any,
) -> dict[str, Any]:
    request = {
        "database": "analytics",
        "table": "documents",
        "query": "Doris",
        "mode": "text",
        "fields": ["title"],
        "vector": None,
        "vector_field": None,
        "text_operator": "any",
        "top_k": 5,
        "filters": {"category": "database"},
        "return_fields": ["id", "title", "category"],
    }
    request.update(overrides)
    return await runtime.search_data(**request)


@pytest.mark.asyncio
async def test_text_search_binds_values_and_uses_target_index_metadata() -> None:
    runtime, manager, _ = _runtime()

    result = await _search(
        runtime,
        query="Doris' OR 1=1 --",
        filters={
            "category": {
                "operator": "in",
                "values": ["database", "analytics"],
            }
        },
    )

    assert result["status"] == "success"
    assert result["data"]["rows"][0]["title"] == "Apache Doris"
    assert result["metadata"]["invented_scores"] is False
    query_call = manager.calls[-1]
    assert "`title` MATCH_ANY %s" in query_call["sql"]
    assert "`category` IN (%s, %s)" in query_call["sql"]
    assert "Doris' OR 1=1 --" not in query_call["sql"]
    assert query_call["params"] == (
        "Doris' OR 1=1 --",
        "database",
        "analytics",
    )
    assert query_call["kwargs"]["mask_result"] is True
    assert manager.context_count == 3
    assert len({call["session_id"] for call in manager.calls}) == 3


@pytest.mark.asyncio
async def test_search_rejects_identifier_injection_before_execution() -> None:
    runtime, manager, _ = _runtime()

    with pytest.raises(SearchRuntimeFailure) as failure:
        await _search(runtime, table="documents; DROP TABLE accounts")

    assert failure.value.reason_code == "SEARCH_ARGUMENT_INVALID"
    assert manager.calls == []


@pytest.mark.asyncio
async def test_text_search_requires_visible_inverted_index() -> None:
    runtime, manager, _ = _runtime(
        _ConnectionManager(indexes=_indexes(inverted=False))
    )

    with pytest.raises(SearchRuntimeFailure) as failure:
        await _search(runtime)

    assert failure.value.reason_code == "SEARCH_TEXT_INDEX_REQUIRED"
    assert len(manager.calls) == 2


@pytest.mark.asyncio
async def test_vector_search_binds_json_vector_and_uses_l2_order() -> None:
    runtime, manager, _ = _runtime()

    result = await _search(
        runtime,
        query=None,
        mode="vector",
        fields=None,
        vector=[0.1, 0.2, 0.3],
        vector_field="embedding",
        filters=None,
    )

    assert result["status"] == "success"
    assert result["metadata"]["vector_metric"] == "l2_distance"
    query_call = manager.calls[-1]
    assert "CAST(%s AS ARRAY<FLOAT>)" in query_call["sql"]
    assert "ORDER BY `__mcp_vector_distance` ASC" in query_call["sql"]
    assert "[0.1,0.2,0.3]" not in query_call["sql"]
    assert query_call["params"] == ("[0.1,0.2,0.3]",)


@pytest.mark.asyncio
async def test_inner_product_vector_search_orders_descending() -> None:
    runtime, manager, _ = _runtime(
        _ConnectionManager(indexes=_indexes(metric="inner_product"))
    )

    await _search(
        runtime,
        query=None,
        mode="vector",
        fields=None,
        vector=[0.1, 0.2, 0.3],
        vector_field=None,
        filters=None,
    )

    assert "inner_product_approximate" in manager.calls[-1]["sql"]
    assert "ORDER BY `__mcp_vector_distance` DESC" in manager.calls[-1]["sql"]


@pytest.mark.asyncio
async def test_hybrid_search_binds_select_parameter_before_predicates() -> None:
    runtime, manager, _ = _runtime()

    await _search(
        runtime,
        mode="hybrid",
        vector=[0.1, 0.2, 0.3],
        vector_field="embedding",
    )

    assert manager.calls[-1]["params"] == (
        "[0.1,0.2,0.3]",
        "Doris",
        "database",
    )


@pytest.mark.asyncio
async def test_vector_dimension_mismatch_fails_before_search_execution() -> None:
    runtime, manager, _ = _runtime()

    with pytest.raises(SearchRuntimeFailure) as failure:
        await _search(
            runtime,
            query=None,
            mode="vector",
            fields=None,
            vector=[0.1, 0.2],
            vector_field="embedding",
            filters=None,
        )

    assert failure.value.reason_code == "SEARCH_ARGUMENT_INVALID"
    assert len(manager.calls) == 2


@pytest.mark.asyncio
async def test_filter_operator_is_allowlisted() -> None:
    runtime, manager, _ = _runtime()

    with pytest.raises(SearchRuntimeFailure) as failure:
        await _search(
            runtime,
            filters={
                "category": {
                    "operator": "eq) OR 1=1 --",
                    "value": "database",
                }
            },
        )

    assert failure.value.reason_code == "SEARCH_ARGUMENT_INVALID"
    assert len(manager.calls) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        ('["apache", "doris"]', ["apache", "doris"]),
        (
            '[{"token":"apache","position":3},{"token":"doris","type":"word"}]',
            ["apache", "doris"],
        ),
    ],
)
async def test_tokenize_normalizes_legacy_and_structured_payloads(
    payload: str,
    expected: list[str],
) -> None:
    runtime, manager, _ = _runtime(
        _ConnectionManager(tokenize_payload=payload)
    )

    result = await runtime.preview_text_analysis(
        text="Apache Doris",
        analyzer="english",
        tokenizer=None,
        token_filters=None,
    )

    assert [item["term"] for item in result["data"]["tokens"]] == expected
    call = manager.calls[-1]
    assert call["sql"] == "SELECT TOKENIZE(%s, %s) AS tokens"
    assert call["params"] == (
        "Apache Doris",
        '"parser"="english"',
    )


@pytest.mark.asyncio
async def test_custom_analyzer_components_must_match_recorded_definition() -> None:
    runtime, manager, _ = _runtime(
        _ConnectionManager(
            analyzers=[
                {
                    "Name": "customer_text",
                    "Tokenizer": "standard",
                    "TokenFilters": '["lowercase", "asciifolding"]',
                }
            ]
        )
    )

    with pytest.raises(SearchRuntimeFailure) as failure:
        await runtime.preview_text_analysis(
            text="Apache Doris",
            analyzer="customer_text",
            tokenizer="standard",
            token_filters=["lowercase"],
        )

    assert failure.value.reason_code == "SEARCH_ARGUMENT_INVALID"
    assert manager.calls[-1]["sql"] == "SHOW INVERTED INDEX ANALYZER"


@pytest.mark.asyncio
async def test_index_inspection_normalizes_properties_and_build_tasks() -> None:
    runtime, _, _ = _runtime(
        _ConnectionManager(
            build_tasks=[
                {
                    "JobId": 11,
                    "TableName": "documents",
                    "State": "FINISHED",
                    "Progress": "100%",
                }
            ]
        )
    )

    result = await runtime.inspect_search_indexes(
        database="analytics",
        table="documents",
        index=None,
    )

    assert result["status"] == "success"
    assert result["data"]["capabilities"] == {
        "text": True,
        "vector": True,
        "hybrid": True,
        "metrics": ["l2_distance"],
    }
    items = {item["name"]: item for item in result["data"]["items"]}
    assert items["idx_embedding"]["dimension"] == 3
    assert items["idx_title"]["parser"] == "english"
    assert items["idx_title"]["properties"]["comment_text"] == "café"
    assert result["data"]["build_tasks"][0]["state"] == "FINISHED"


@pytest.mark.asyncio
async def test_diagnosis_reports_ann_plan_without_inventing_text_hits() -> None:
    runtime, _, query_runtime = _runtime()

    result = await runtime.diagnose_search_query(
        sql=None,
        search_request={
            "database": "analytics",
            "table": "documents",
            "query": "Doris",
            "mode": "hybrid",
            "fields": ["title"],
            "vector": [0.1, 0.2, 0.3],
            "vector_field": "embedding",
            "top_k": 5,
            "return_fields": ["id", "title"],
        },
        include_profile=True,
    )

    facets = result["data"]["explain"]["facets"]
    assert facets["ann_pushdown_observed"] is True
    assert facets["text_match_predicate_observed"] is True
    assert facets["profile_required_for_inverted_hit_confirmation"] is True
    assert result["metadata"]["invented_index_hits"] is False
    assert result["metadata"]["profile_observed"] is False
    assert result["status"] == "partial"
    query_runtime.get_query_profile.assert_not_awaited()


@pytest.mark.asyncio
async def test_raw_diagnosis_rejects_write_and_profiles_read_only_sql() -> None:
    runtime, manager, query_runtime = _runtime()

    with pytest.raises(SearchRuntimeFailure) as failure:
        await runtime.diagnose_search_query(
            sql="DELETE FROM analytics.documents",
            search_request=None,
            include_profile=False,
        )
    assert failure.value.reason_code == "SEARCH_ARGUMENT_INVALID"
    assert manager.calls == []

    result = await runtime.diagnose_search_query(
        sql=(
            "SELECT id FROM analytics.documents "
            "WHERE title MATCH_ANY 'Doris' LIMIT 5"
        ),
        search_request=None,
        include_profile=True,
    )

    assert result["metadata"]["profile_observed"] is True
    query_runtime.get_query_profile.assert_awaited_once()
