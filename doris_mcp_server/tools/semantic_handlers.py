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

"""Formal Semantic-domain handlers backed by Ossie and MetricFlow runtimes."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol, cast

from ..semantic.metricflow import MetricFlowSemanticRuntime
from ..semantic.runtime import DorisSemanticRuntime
from ..utils.db import DorisConnectionManager
from ..utils.query_runtime import DorisQueryRuntime


class _SemanticHandlerOwner(Protocol):
    semantic_runtime: DorisSemanticRuntime
    metricflow_runtime: MetricFlowSemanticRuntime


class SemanticToolHandlersMixin:
    """Route all semantic children through exact-reference operations."""

    def _initialize_semantic_handlers(
        self: _SemanticHandlerOwner,
        connection_manager: DorisConnectionManager,
        query_runtime: DorisQueryRuntime,
    ) -> None:
        self.semantic_runtime = DorisSemanticRuntime(connection_manager)
        config = getattr(connection_manager, "config", None)
        self.metricflow_runtime = MetricFlowSemanticRuntime.from_config(
            query_runtime,
            getattr(config, "semantic", None),
        )

    async def _formal_doris_semantic_list_semantic_models_tool(
        self: _SemanticHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.semantic_runtime.list_semantic_models(
            namespace=cast(str | None, arguments.get("namespace")),
            tag=cast(str | None, arguments.get("tag")),
            pattern=cast(str | None, arguments.get("pattern")),
        )

    async def _formal_doris_semantic_get_semantic_model_summary_tool(
        self: _SemanticHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.semantic_runtime.get_semantic_model_summary(
            model_ref=cast(str, arguments.get("model_ref")),
            include_bindings=bool(arguments.get("include_bindings", False)),
        )

    async def _formal_doris_semantic_get_semantic_context_tool(
        self: _SemanticHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.semantic_runtime.get_semantic_context(
            model_ref=cast(str, arguments.get("model_ref")),
            request=cast(Mapping[str, Any], arguments.get("request")),
        )

    async def _formal_doris_semantic_get_semantic_mapping_status_tool(
        self: _SemanticHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.semantic_runtime.get_semantic_mapping_status(
            model_ref=cast(str, arguments.get("model_ref")),
            datasource=cast(str | None, arguments.get("datasource")),
        )

    async def _formal_doris_semantic_list_metricflow_models_tool(
        self: _SemanticHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        del arguments
        return await self.metricflow_runtime.list_models()

    async def _formal_doris_semantic_get_metricflow_status_tool(
        self: _SemanticHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.metricflow_runtime.get_status(
            model_ref=cast(str, arguments.get("model_ref")),
        )

    async def _formal_doris_semantic_list_metricflow_metrics_tool(
        self: _SemanticHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.metricflow_runtime.list_metrics(
            model_ref=cast(str, arguments.get("model_ref")),
            search=cast(str | None, arguments.get("search")),
            include_dimensions=bool(arguments.get("include_dimensions", True)),
            limit=cast(int | None, arguments.get("limit")),
        )

    async def _formal_doris_semantic_get_metricflow_group_bys_tool(
        self: _SemanticHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.metricflow_runtime.get_group_bys(
            model_ref=cast(str, arguments.get("model_ref")),
            metrics=cast(list[str], arguments.get("metrics")),
        )

    async def _formal_doris_semantic_list_metricflow_saved_queries_tool(
        self: _SemanticHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.metricflow_runtime.list_saved_queries(
            model_ref=cast(str, arguments.get("model_ref")),
            search=cast(str | None, arguments.get("search")),
            limit=cast(int | None, arguments.get("limit")),
        )

    async def _formal_doris_semantic_get_metricflow_dimension_values_tool(
        self: _SemanticHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.metricflow_runtime.get_dimension_values(
            model_ref=cast(str, arguments.get("model_ref")),
            metrics=cast(list[str], arguments.get("metrics")),
            dimension=cast(str, arguments.get("dimension")),
            start_time=cast(str | None, arguments.get("start_time")),
            end_time=cast(str | None, arguments.get("end_time")),
            limit=cast(int | None, arguments.get("limit")),
            timeout_ms=cast(int | None, arguments.get("timeout_ms")),
        )

    async def _formal_doris_semantic_compile_metricflow_query_tool(
        self: _SemanticHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.metricflow_runtime.compile_query(
            model_ref=cast(str, arguments.get("model_ref")),
            request=cast(Mapping[str, Any], arguments.get("request")),
        )

    async def _formal_doris_semantic_execute_metricflow_query_tool(
        self: _SemanticHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.metricflow_runtime.execute_query(
            model_ref=cast(str, arguments.get("model_ref")),
            request=cast(Mapping[str, Any], arguments.get("request")),
            max_rows=cast(int | None, arguments.get("max_rows")),
            timeout_ms=cast(int | None, arguments.get("timeout_ms")),
        )


__all__ = ["SemanticToolHandlersMixin"]
