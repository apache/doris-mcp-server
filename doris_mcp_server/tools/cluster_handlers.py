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

"""Formal Cluster-domain handlers backed by one strict runtime."""

from __future__ import annotations

from typing import Any, Protocol, cast

from ..utils.cluster_runtime import DorisClusterRuntime
from ..utils.db import DorisConnectionManager
from ..utils.monitoring_tools import DorisMonitoringTools
from ..utils.security import get_current_auth_context
from .capability_registry import CapabilityRegistry


class _ClusterHandlerOwner(Protocol):
    """State supplied by ``DorisToolsManager`` to the mixin."""

    cluster_runtime: DorisClusterRuntime
    _capability_registry: CapabilityRegistry | None


class ClusterToolHandlersMixin:
    """Route every Cluster child through the strict evidence runtime."""

    def _initialize_cluster_handlers(
        self: _ClusterHandlerOwner,
        connection_manager: DorisConnectionManager,
        monitoring_tools: DorisMonitoringTools,
    ) -> None:
        self.cluster_runtime = DorisClusterRuntime(
            connection_manager,
            monitoring_tools,
        )

    async def _formal_doris_cluster_get_cluster_overview_tool(
        self: _ClusterHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.cluster_runtime.get_cluster_overview(
            include=cast(list[str] | None, arguments.get("include")),
        )

    async def _formal_doris_cluster_list_cluster_nodes_tool(
        self: _ClusterHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.cluster_runtime.list_cluster_nodes(
            node_types=cast(list[str] | None, arguments.get("node_types")),
            include_metrics=bool(arguments.get("include_metrics", False)),
        )

    async def _formal_doris_cluster_list_active_tasks_tool(
        self: _ClusterHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.cluster_runtime.list_active_tasks(
            task_types=cast(list[str] | None, arguments.get("task_types")),
            states=cast(list[str] | None, arguments.get("states")),
            limit=cast(int | None, arguments.get("limit")),
        )

    async def _formal_doris_cluster_get_cache_status_tool(
        self: _ClusterHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.cluster_runtime.get_cache_status(
            scope=cast(str | None, arguments.get("scope")),
            node_ids=cast(list[str] | None, arguments.get("node_ids")),
            include_queues=bool(arguments.get("include_queues", False)),
        )

    async def _formal_doris_cluster_get_compaction_status_tool(
        self: _ClusterHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.cluster_runtime.get_compaction_status(
            database=cast(str | None, arguments.get("database")),
            table=cast(str | None, arguments.get("table")),
            state=cast(str | None, arguments.get("state")),
            limit=cast(int | None, arguments.get("limit")),
        )

    async def _formal_doris_cluster_get_workload_group_status_tool(
        self: _ClusterHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.cluster_runtime.get_workload_group_status(
            name=cast(str | None, arguments.get("name")),
            include_usage=bool(arguments.get("include_usage", False)),
        )

    async def _formal_doris_cluster_get_compute_group_status_tool(
        self: _ClusterHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.cluster_runtime.get_compute_group_status(
            name=cast(str | None, arguments.get("name")),
            include_nodes=bool(arguments.get("include_nodes", False)),
            include_usage=bool(arguments.get("include_usage", False)),
        )

    async def _formal_doris_cluster_get_runtime_capabilities_tool(
        self: _ClusterHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        registry = self._capability_registry
        if registry is None:
            return {
                "status": "partial",
                "data": {
                    "detail": arguments.get("detail", "summary"),
                    "capability_registry": "external",
                },
                "warnings": [
                    "Runtime capability evidence is supplied by an external "
                    "availability provider."
                ],
                "metadata": {"source": "availability_provider"},
                "evidence": [],
            }
        snapshot = await registry.ensure_fresh(
            "doris_cluster",
            get_current_auth_context(),
        )
        detail = str(arguments.get("detail", "summary"))
        versions = {
            "master_fe": snapshot.version_vector.master_fe.normalized,
            "follower_fes": [
                version.normalized for version in snapshot.version_vector.follower_fes
            ],
            "backends": [
                version.normalized for version in snapshot.version_vector.backends
            ],
        }
        statuses: dict[str, int] = {}
        for probe in snapshot.probes.values():
            statuses[probe.status.value] = statuses.get(probe.status.value, 0) + 1
        data: dict[str, Any] = {
            "detail": detail,
            "versions": versions,
            "deployment_mode": snapshot.deployment_mode,
            "mixed_versions": snapshot.mixed_versions,
            "stale": snapshot.stale,
            "probe_status_counts": statuses,
            "probed_domains": sorted(snapshot.probed_domains),
        }
        if detail == "full":
            data["probes"] = {
                probe_id: {
                    "status": probe.status.value,
                    "reason_code": probe.reason_code,
                    "evidence_sources": list(probe.evidence_sources),
                }
                for probe_id, probe in sorted(snapshot.probes.items())
            }
        warnings = (
            ["Capability evidence is stale and may be retried."]
            if snapshot.stale
            else []
        )
        return {
            "status": "partial" if warnings else "success",
            "data": data,
            "warnings": warnings,
            "metadata": {
                "source": "route_private_capability_snapshot",
                "created_at": snapshot.created_at.isoformat(),
                "expires_at": snapshot.expires_at.isoformat(),
            },
            "evidence": [
                {
                    "source": "SELECT @@version_comment",
                    "probe": "version_probe_completed",
                },
                {
                    "source": "SHOW FRONTENDS, SHOW BACKENDS",
                    "probe": "cluster_components_discoverable",
                },
            ],
        }


__all__ = ["ClusterToolHandlersMixin"]
