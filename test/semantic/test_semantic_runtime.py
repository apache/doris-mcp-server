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

"""Permission, selection, and execution-boundary tests for semantic runtime."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from doris_mcp_server.semantic.runtime import (
    DorisSemanticRuntime,
    SemanticRuntimeFailure,
)
from doris_mcp_server.utils.security import (
    AuthContext,
    reset_auth_context,
    set_current_auth_context,
)

_Responder = Callable[[str, tuple[Any, ...]], list[dict[str, Any]]]


def _model_yaml() -> str:
    return """
version: "0.2.0.dev0"
semantic_model:
  - name: retail
    description: Governed retail model
    ai_context:
      instructions: Treat annotations as business metadata.
      synonyms: [commerce]
    datasets:
      - name: orders
        source: sales.orders
        primary_key: [order_id]
        description: Order facts
        fields:
          - name: order_id
            expression:
              dialects:
                - dialect: ANSI_SQL
                  expression: order_id
            datatype: Integer
          - name: customer_id
            expression:
              dialects:
                - dialect: ANSI_SQL
                  expression: customer_id
            datatype: Integer
          - name: amount
            expression:
              dialects:
                - dialect: ANSI_SQL
                  expression: amount
            datatype: Decimal
            ai_context:
              synonyms: [revenue, sales]
      - name: customers
        source: sales.customers
        primary_key: [customer_id]
        fields:
          - name: customer_id
            expression:
              dialects:
                - dialect: ANSI_SQL
                  expression: customer_id
            datatype: Integer
          - name: segment
            expression:
              dialects:
                - dialect: ANSI_SQL
                  expression: segment
            datatype: String
            ai_context:
              synonyms: [customer group]
    relationships:
      - name: orders_to_customers
        from: orders
        to: customers
        from_columns: [customer_id]
        to_columns: [customer_id]
    metrics:
      - name: total_sales
        expression:
          dialects:
            - dialect: ANSI_SQL
              expression: SUM(orders.amount)
        description: Governed revenue
        datatype: Decimal
        ai_context:
          synonyms: [revenue]
      - name: customer_count
        expression:
          dialects:
            - dialect: ANSI_SQL
              expression: COUNT(DISTINCT customers.customer_id)
        datatype: Integer
""".strip()


def _binding_yaml(*, model_ref: str = "retail/main") -> str:
    return f"""
api_version: doris-mcp.apache.org/ossie-binding/v1alpha1
model_sources:
  {model_ref}:
    model_file: retail.yaml
    model_name: retail
    namespace: commerce
    tags: [certified]
    route_profile: global
    datasets:
      orders:
        catalog: internal
        database: sales
        object: orders
        kind: table
      customers:
        catalog: internal
        database: sales
        object: customers
        kind: table
""".strip()


class _ConnectionManager:
    def __init__(
        self,
        tmp_path: Path,
        responder: _Responder,
        *,
        route_key: str = "global",
        oauth_tools_enabled: bool = False,
        oauth_resources_enabled: bool = False,
    ) -> None:
        self._responder = responder
        self._route_key = route_key
        self.calls: list[tuple[str, tuple[Any, ...]]] = []
        self.config = SimpleNamespace(
            semantic=SimpleNamespace(
                enabled=True,
                model_directory=str(tmp_path),
                binding_manifest=str(tmp_path / "bindings.yaml"),
                max_file_bytes=2 * 1024 * 1024,
                max_total_bytes=8 * 1024 * 1024,
                max_models=64,
                max_depth=32,
                max_aliases=32,
                max_string_bytes=16 * 1024,
                max_expression_bytes=4096,
                context_max_bytes=16 * 1024,
                context_hard_max_bytes=64 * 1024,
                oauth_tools_enabled=oauth_tools_enabled,
                oauth_resources_enabled=oauth_resources_enabled,
            )
        )

    def get_route_identity(self, _auth_context: Any) -> SimpleNamespace:
        return SimpleNamespace(route_key=self._route_key)

    @asynccontextmanager
    async def get_connection_context_for_auth_context(
        self,
        _session_id: str,
        _auth_context: Any,
    ) -> AsyncIterator[Any]:
        manager = self

        class _Connection:
            async def execute(
                self,
                sql: str,
                params: tuple[Any, ...] | None = None,
                **_kwargs: Any,
            ) -> SimpleNamespace:
                bound = params or ()
                manager.calls.append((sql, bound))
                return SimpleNamespace(data=manager._responder(sql, bound))

        yield _Connection()


def _metadata_responder(
    sql: str,
    params: tuple[Any, ...],
) -> list[dict[str, Any]]:
    assert sql.startswith("SELECT ")
    object_name = str(params[2])
    if "information_schema.tables" in sql:
        return [{"TABLE_TYPE": "BASE TABLE"}]
    if object_name == "orders":
        return [
            {"COLUMN_NAME": "order_id", "DATA_TYPE": "BIGINT"},
            {"COLUMN_NAME": "customer_id", "DATA_TYPE": "BIGINT"},
            {"COLUMN_NAME": "amount", "DATA_TYPE": "DECIMAL(18,2)"},
        ]
    if object_name == "customers":
        return [
            {"COLUMN_NAME": "customer_id", "DATA_TYPE": "BIGINT"},
            {"COLUMN_NAME": "segment", "DATA_TYPE": "VARCHAR(64)"},
        ]
    raise AssertionError(object_name)


def _runtime(
    tmp_path: Path,
    responder: _Responder = _metadata_responder,
    **manager_kwargs: Any,
) -> tuple[DorisSemanticRuntime, _ConnectionManager]:
    (tmp_path / "retail.yaml").write_text(_model_yaml(), encoding="utf-8")
    (tmp_path / "bindings.yaml").write_text(_binding_yaml(), encoding="utf-8")
    manager = _ConnectionManager(
        tmp_path,
        responder,
        **manager_kwargs,
    )
    return DorisSemanticRuntime(manager), manager  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_lists_summarizes_and_maps_exact_visible_model(
    tmp_path: Path,
) -> None:
    runtime, manager = _runtime(tmp_path)

    listed = await runtime.list_semantic_models(
        namespace="commerce",
        tag="certified",
        pattern="ret*",
    )
    assert listed["status"] == "success"
    assert listed["data"]["items"][0]["model_ref"] == "retail/main"
    assert listed["data"]["items"][0]["visible_datasets"] == 2

    summary = await runtime.get_semantic_model_summary(
        model_ref="retail/main",
        include_bindings=True,
    )
    assert summary["status"] == "success"
    assert [item["name"] for item in summary["data"]["datasets"]] == [
        "orders",
        "customers",
    ]
    assert summary["data"]["datasets"][0]["binding"] == {
        "catalog": "internal",
        "database": "sales",
        "object": "orders",
        "kind": "table",
    }
    mapping = await runtime.get_semantic_mapping_status(
        model_ref="retail/main",
        datasource="orders",
    )
    assert mapping["data"]["datasets"][0]["visible_fields"][2] == {
        "name": "amount",
        "physical_columns": ["amount"],
        "physical_types": ["DECIMAL(18,2)"],
    }
    assert all("SUM(" not in sql for sql, _ in manager.calls)


@pytest.mark.asyncio
async def test_context_is_deterministic_and_never_executes_model_expression(
    tmp_path: Path,
) -> None:
    runtime, manager = _runtime(tmp_path)

    result = await runtime.get_semantic_context(
        model_ref="retail/main",
        request={
            "question": "revenue by customer group",
            "metrics": ["total_sales"],
            "dimensions": ["customers.segment"],
        },
    )

    context = result["data"]["context"]
    assert [item["name"] for item in context["metrics"]] == ["total_sales"]
    assert [item["name"] for item in context["relationships"]] == [
        "orders_to_customers"
    ]
    assert [item["name"] for item in context["datasets"]] == [
        "customers",
        "orders",
    ]
    assert context["metrics"][0]["expressions"][0]["expression"] == (
        "SUM(orders.amount)"
    )
    assert result["data"]["execution_boundary"].endswith(
        "Doris Query domain for SQL execution."
    )
    assert all("SUM(" not in sql for sql, _ in manager.calls)


@pytest.mark.asyncio
async def test_hidden_dataset_closes_relationship_and_metric_visibility(
    tmp_path: Path,
) -> None:
    def restricted(
        sql: str,
        params: tuple[Any, ...],
    ) -> list[dict[str, Any]]:
        if str(params[2]) == "customers":
            return []
        return _metadata_responder(sql, params)

    runtime, _ = _runtime(tmp_path, restricted)
    summary = await runtime.get_semantic_model_summary(
        model_ref="retail/main",
    )

    serialized = str(summary)
    assert [item["name"] for item in summary["data"]["datasets"]] == [
        "orders"
    ]
    assert summary["data"]["relationships"] == []
    assert [item["name"] for item in summary["data"]["metrics"]] == [
        "total_sales"
    ]
    assert "customers.customer_id" not in serialized
    assert "orders_to_customers" not in serialized
    assert summary["status"] == "partial"


@pytest.mark.asyncio
async def test_exact_model_route_and_selector_fail_closed(tmp_path: Path) -> None:
    runtime, _ = _runtime(tmp_path, route_key="another-route")
    with pytest.raises(SemanticRuntimeFailure) as route_failure:
        await runtime.get_semantic_model_summary(model_ref="retail/main")
    assert route_failure.value.reason_code == "SEMANTIC_MODEL_NOT_FOUND"

    runtime, _ = _runtime(tmp_path)
    for model_ref in ("", "retail", "retail/main;DROP"):
        with pytest.raises(SemanticRuntimeFailure) as model_failure:
            await runtime.get_semantic_model_summary(model_ref=model_ref)
        assert model_failure.value.reason_code == "SEMANTIC_MODEL_NOT_FOUND"

    with pytest.raises(SemanticRuntimeFailure) as selector_failure:
        await runtime.get_semantic_context(
            model_ref="retail/main",
            request={"metrics": ["missing_metric"]},
        )
    assert (
        selector_failure.value.reason_code
        == "SEMANTIC_DEPENDENCY_UNRESOLVED"
    )

    with pytest.raises(SemanticRuntimeFailure) as datasource_failure:
        await runtime.get_semantic_mapping_status(
            model_ref="retail/main",
            datasource="missing_dataset",
        )
    assert (
        datasource_failure.value.reason_code
        == "SEMANTIC_DEPENDENCY_UNRESOLVED"
    )

    with pytest.raises(SemanticRuntimeFailure) as budget_failure:
        await runtime.get_semantic_context(
            model_ref="retail/main",
            request={"metrics": ["total_sales"], "max_bytes": 65537},
        )
    assert budget_failure.value.reason_code == "SEMANTIC_ARGUMENT_INVALID"

    with pytest.raises(SemanticRuntimeFailure) as dimension_failure:
        await runtime.get_semantic_context(
            model_ref="retail/main",
            request={"dimensions": ["customers.segment.extra"]},
        )
    assert dimension_failure.value.reason_code == "SEMANTIC_ARGUMENT_INVALID"


@pytest.mark.asyncio
async def test_exact_model_ref_with_revision_metadata_is_resolved(
    tmp_path: Path,
) -> None:
    model_ref = "sales/commerce@2026.08.05+4f91c2a"
    (tmp_path / "retail.yaml").write_text(_model_yaml(), encoding="utf-8")
    (tmp_path / "bindings.yaml").write_text(
        _binding_yaml(model_ref=model_ref),
        encoding="utf-8",
    )
    manager = _ConnectionManager(tmp_path, _metadata_responder)
    runtime = DorisSemanticRuntime(manager)

    summary = await runtime.get_semantic_model_summary(model_ref=model_ref)

    assert summary["data"]["model_ref"] == model_ref


@pytest.mark.asyncio
async def test_backend_errors_are_sanitized(tmp_path: Path) -> None:
    def denied(
        _sql: str,
        _params: tuple[Any, ...],
    ) -> list[dict[str, Any]]:
        raise RuntimeError(1142, "private principal may not read secret_table")

    runtime, _ = _runtime(tmp_path, denied)

    with pytest.raises(SemanticRuntimeFailure) as failure:
        await runtime.get_semantic_model_summary(model_ref="retail/main")

    assert failure.value.reason_code == "SEMANTIC_MODEL_NOT_FOUND"
    assert "private principal" not in str(failure.value)
    assert "secret_table" not in str(failure.value)


@pytest.mark.asyncio
async def test_type_conflicts_remove_dependent_metric_and_report_warning(
    tmp_path: Path,
) -> None:
    def incompatible_amount(
        sql: str,
        params: tuple[Any, ...],
    ) -> list[dict[str, Any]]:
        rows = _metadata_responder(sql, params)
        if (
            "information_schema.columns" in sql
            and str(params[2]) == "orders"
        ):
            return [
                {
                    **row,
                    "DATA_TYPE": (
                        "VARCHAR(64)"
                        if row["COLUMN_NAME"] == "amount"
                        else row["DATA_TYPE"]
                    ),
                }
                for row in rows
            ]
        return rows

    runtime, _ = _runtime(tmp_path, incompatible_amount)

    summary = await runtime.get_semantic_model_summary(
        model_ref="retail/main",
    )
    mapping = await runtime.get_semantic_mapping_status(
        model_ref="retail/main",
        datasource="orders",
    )

    assert "total_sales" not in str(summary["data"]["metrics"])
    assert summary["status"] == "partial"
    assert "SEMANTIC_TYPE_CONFLICT" in summary["warnings"]
    assert mapping["data"]["datasets"][0]["status"] == "type_conflict"
    assert mapping["data"]["datasets"][0]["warnings"] == [
        "SEMANTIC_TYPE_CONFLICT"
    ]


@pytest.mark.asyncio
async def test_disabled_and_oauth_channels_fail_closed(tmp_path: Path) -> None:
    disabled = DorisSemanticRuntime(
        SimpleNamespace(
            config=SimpleNamespace(
                semantic=SimpleNamespace(enabled=False),
            )
        )  # type: ignore[arg-type]
    )
    with pytest.raises(SemanticRuntimeFailure) as disabled_failure:
        await disabled.list_semantic_models()
    assert disabled_failure.value.reason_code == "OSSIE_DISABLED"
    assert await disabled.list_resource_descriptors() == []

    oauth_runtime, _ = _runtime(
        tmp_path,
        oauth_tools_enabled=True,
        oauth_resources_enabled=True,
    )
    missing_scope = set_current_auth_context(
        AuthContext(
            auth_method="external_oauth",
            oauth_scopes=[],
        )
    )
    try:
        with pytest.raises(SemanticRuntimeFailure) as scope_failure:
            await oauth_runtime.get_semantic_model_summary(
                model_ref="retail/main"
            )
        assert scope_failure.value.reason_code == "SEMANTIC_MODEL_NOT_FOUND"
        assert await oauth_runtime.list_resource_descriptors() == []
    finally:
        reset_auth_context(missing_scope)

    allowed = set_current_auth_context(
        AuthContext(
            auth_method="external_oauth",
            oauth_scopes=["semantic:read"],
        )
    )
    try:
        assert (
            await oauth_runtime.get_semantic_model_summary(
                model_ref="retail/main"
            )
        )["status"] == "success"
        assert len(await oauth_runtime.list_resource_descriptors()) == 1
    finally:
        reset_auth_context(allowed)


def test_unstructured_mock_config_does_not_enable_semantic_runtime() -> None:
    runtime = DorisSemanticRuntime(Mock())

    assert runtime.enabled is False
    assert runtime.model_count == 0


@pytest.mark.asyncio
async def test_revisioned_resource_and_oauth_policy(tmp_path: Path) -> None:
    runtime, _ = _runtime(tmp_path)
    descriptors = await runtime.list_resource_descriptors()
    assert len(descriptors) == 1
    uri = descriptors[0]["uri"]
    payload = await runtime.read_resource(uri)
    assert '"model_ref":"retail/main"' in payload
    assert "/tmp/" not in payload

    with pytest.raises(SemanticRuntimeFailure) as stale_failure:
        await runtime.read_resource(uri[:-1] + "0")
    assert stale_failure.value.reason_code == "SEMANTIC_MODEL_NOT_FOUND"

    oauth_runtime, _ = _runtime(
        tmp_path,
        oauth_tools_enabled=False,
        oauth_resources_enabled=False,
    )
    token = set_current_auth_context(
        AuthContext(
            auth_method="doris_oauth",
            oauth_scopes=["semantic:read"],
        )
    )
    try:
        with pytest.raises(SemanticRuntimeFailure) as tool_failure:
            await oauth_runtime.list_semantic_models()
        assert tool_failure.value.reason_code == "SEMANTIC_MODEL_NOT_FOUND"
        assert await oauth_runtime.list_resource_descriptors() == []
    finally:
        reset_auth_context(token)
