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

"""Formal Governance-domain handlers backed by one strict runtime."""

from __future__ import annotations

from typing import Any, Protocol, cast

from ..utils.db import DorisConnectionManager
from ..utils.governance_runtime import (
    DorisGovernanceRuntime,
    QueryableLineageProvider,
)


class _GovernanceHandlerOwner(Protocol):
    """State supplied by ``DorisToolsManager`` to the mixin."""

    governance_runtime: DorisGovernanceRuntime


class GovernanceToolHandlersMixin:
    """Route every Governance child through the evidence-bearing runtime."""

    def _initialize_governance_handlers(
        self: _GovernanceHandlerOwner,
        connection_manager: DorisConnectionManager,
        *,
        lineage_provider: QueryableLineageProvider | None = None,
    ) -> None:
        self.governance_runtime = DorisGovernanceRuntime(
            connection_manager,
            lineage_provider=lineage_provider,
        )

    async def _formal_doris_governance_analyze_columns_tool(
        self: _GovernanceHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.governance_runtime.analyze_columns(
            database=cast(str, arguments.get("database")),
            table=cast(str, arguments.get("table")),
            columns=cast(list[str] | None, arguments.get("columns")),
            sample_ratio=cast(float | None, arguments.get("sample_ratio")),
        )

    async def _formal_doris_governance_analyze_table_storage_tool(
        self: _GovernanceHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.governance_runtime.analyze_table_storage(
            database=cast(str, arguments.get("database")),
            table=cast(str, arguments.get("table")),
            include_partitions=bool(arguments.get("include_partitions", False)),
            include_indexes=bool(arguments.get("include_indexes", False)),
        )

    async def _formal_doris_governance_get_lineage_capability_status_tool(
        self: _GovernanceHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        del arguments
        return await self.governance_runtime.get_lineage_capability_status()

    async def _formal_doris_governance_trace_column_lineage_tool(
        self: _GovernanceHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.governance_runtime.trace_column_lineage(
            object_name=cast(str, arguments.get("object")),
            column=cast(str | None, arguments.get("column")),
            direction=cast(str | None, arguments.get("direction")),
            depth=cast(int | None, arguments.get("depth")),
            evidence_mode=cast(
                str | None,
                arguments.get("evidence_mode"),
            ),
        )

    async def _formal_doris_governance_analyze_data_access_patterns_tool(
        self: _GovernanceHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.governance_runtime.analyze_data_access_patterns(
            database=cast(str | None, arguments.get("database")),
            table=cast(str | None, arguments.get("table")),
            window_days=cast(int | None, arguments.get("window_days")),
            group_by=cast(str | None, arguments.get("group_by")),
        )

    async def _formal_doris_governance_get_recent_audit_logs_tool(
        self: _GovernanceHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.governance_runtime.get_recent_audit_logs(
            window_minutes=cast(
                int | None,
                arguments.get("window_minutes"),
            ),
            user=cast(str | None, arguments.get("user")),
            operation=cast(str | None, arguments.get("operation")),
            database=cast(str | None, arguments.get("database")),
            table=cast(str | None, arguments.get("table")),
            limit=cast(int | None, arguments.get("limit")),
        )

    async def _formal_doris_governance_list_udfs_tool(
        self: _GovernanceHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.governance_runtime.list_udfs(
            database=cast(str | None, arguments.get("database")),
            language=cast(str | None, arguments.get("language")),
            name_pattern=cast(str | None, arguments.get("name_pattern")),
        )

    async def _formal_doris_governance_get_auth_mapping_status_tool(
        self: _GovernanceHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.governance_runtime.get_auth_mapping_status(
            principal=cast(str | None, arguments.get("principal")),
            provider=cast(str | None, arguments.get("provider")),
            include_roles=bool(arguments.get("include_roles", False)),
        )


__all__ = ["GovernanceToolHandlersMixin"]
