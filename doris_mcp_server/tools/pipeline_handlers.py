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

"""Formal Pipeline-domain handlers backed by one strict runtime."""

from __future__ import annotations

from typing import Any, Protocol, cast

from ..utils.db import DorisConnectionManager
from ..utils.pipeline_runtime import DorisPipelineRuntime


class _PipelineHandlerOwner(Protocol):
    """State supplied by ``DorisToolsManager`` to the mixin."""

    pipeline_runtime: DorisPipelineRuntime


class PipelineToolHandlersMixin:
    """Route every Pipeline child through the evidence-bearing runtime."""

    def _initialize_pipeline_handlers(
        self: _PipelineHandlerOwner,
        connection_manager: DorisConnectionManager,
    ) -> None:
        self.pipeline_runtime = DorisPipelineRuntime(connection_manager)

    async def _formal_doris_pipeline_get_ingestion_status_tool(
        self: _PipelineHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.pipeline_runtime.get_ingestion_status(
            job_types=cast(list[str] | None, arguments.get("job_types")),
            database=cast(str | None, arguments.get("database")),
            table=cast(str | None, arguments.get("table")),
            states=cast(list[str] | None, arguments.get("states")),
            limit=cast(int | None, arguments.get("limit")),
        )

    async def _formal_doris_pipeline_diagnose_ingestion_tool(
        self: _PipelineHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.pipeline_runtime.diagnose_ingestion(
            job_id=cast(str | None, arguments.get("job_id")),
            database=cast(str | None, arguments.get("database")),
            table=cast(str | None, arguments.get("table")),
            window_minutes=cast(int | None, arguments.get("window_minutes")),
            include_dependencies=bool(
                arguments.get("include_dependencies", True)
            ),
        )

    async def _formal_doris_pipeline_get_materialized_view_status_tool(
        self: _PipelineHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.pipeline_runtime.get_materialized_view_status(
            database=cast(str | None, arguments.get("database")),
            view=cast(str | None, arguments.get("view")),
            states=cast(list[str] | None, arguments.get("states")),
            include_refresh_history=bool(
                arguments.get("include_refresh_history", False)
            ),
        )

    async def _formal_doris_pipeline_monitor_data_freshness_tool(
        self: _PipelineHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.pipeline_runtime.monitor_data_freshness(
            database=cast(str, arguments.get("database")),
            table=cast(str, arguments.get("table")),
            threshold_seconds=cast(
                int | None,
                arguments.get("threshold_seconds"),
            ),
            time_column=cast(str | None, arguments.get("time_column")),
        )

    async def _formal_doris_pipeline_analyze_data_dependencies_tool(
        self: _PipelineHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.pipeline_runtime.analyze_data_dependencies(
            catalog=cast(str | None, arguments.get("catalog")),
            database=cast(str | None, arguments.get("database")),
            object_name=cast(str, arguments.get("object")),
            direction=cast(str | None, arguments.get("direction")),
            depth=cast(int | None, arguments.get("depth")),
        )


__all__ = ["PipelineToolHandlersMixin"]
