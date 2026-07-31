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

"""Branch coverage for the manager's thin routing helpers."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from doris_mcp_server.tools.tools_manager import DorisToolsManager


def _manager() -> DorisToolsManager:
    manager = object.__new__(DorisToolsManager)
    manager.monitoring_tools = SimpleNamespace(
        get_monitoring_metrics=AsyncMock(
            side_effect=[
                {"success": True, "kind": "definitions"},
                {"success": True, "timestamp": "2026-07-30T00:00:00Z"},
            ]
        )
    )
    manager.cluster_runtime = SimpleNamespace(
        get_monitoring_metrics=AsyncMock(
            return_value={
                "status": "success",
                "data": {"nodes": []},
                "warnings": [],
                "metadata": {"source": "test"},
            }
        ),
        get_memory_stats=AsyncMock(
            return_value={
                "status": "success",
                "data": {"nodes": []},
                "warnings": [],
                "metadata": {"source": "test"},
            }
        ),
    )
    manager.data_governance_tools = SimpleNamespace(
        trace_column_lineage=AsyncMock(
            side_effect=lambda **kwargs: {
                "success": True,
                "analysis_timestamp": "2026-07-30T00:00:00Z",
                **kwargs,
            }
        )
    )
    return manager


@pytest.mark.asyncio
async def test_monitoring_metrics_routes_formal_filters_to_cluster_runtime():
    manager = _manager()

    result = await manager._get_monitoring_metrics_tool(
        {
            "metric_names": ["doris_be_cpu"],
            "node_ids": ["be-1"],
            "window": "instant",
        }
    )

    assert result["status"] == "success"
    manager.cluster_runtime.get_monitoring_metrics.assert_awaited_once_with(
        metric_names=["doris_be_cpu"],
        node_ids=["be-1"],
        window="instant",
    )


@pytest.mark.asyncio
async def test_memory_stats_routes_formal_detail_to_cluster_runtime():
    manager = _manager()

    result = await manager._get_memory_stats_tool(
        {
            "detail": "top_consumers",
            "node_ids": ["be-1"],
        }
    )

    assert result["status"] == "success"
    manager.cluster_runtime.get_memory_stats.assert_awaited_once_with(
        node_ids=["be-1"],
        detail="top_consumers",
    )


@pytest.mark.asyncio
async def test_column_lineage_requires_targets_and_validates_single_specification():
    manager = _manager()

    missing = await manager._trace_column_lineage_tool({})
    invalid = await manager._trace_column_lineage_tool(
        {"target_columns": "too.many.name.parts"}
    )
    two_part = await manager._trace_column_lineage_tool(
        {
            "target_columns": "orders.customer_id",
            "analysis_depth": 2,
            "catalog_name": "internal",
        }
    )
    three_part = await manager._trace_column_lineage_tool(
        {"target_columns": "analytics.orders.customer_id"}
    )

    assert missing == {"error": "target_columns parameter is required"}
    assert "Invalid column specification" in invalid["error"]
    assert two_part["table_name"] == "orders"
    assert two_part["column_name"] == "customer_id"
    assert two_part["db_name"] is None
    assert two_part["depth"] == 2
    assert three_part["db_name"] == "analytics"


@pytest.mark.asyncio
async def test_column_lineage_collects_multi_target_results_and_errors():
    manager = _manager()

    async def trace(**kwargs):
        if kwargs["column_name"] == "broken":
            raise RuntimeError("lineage unavailable")
        return {
            "success": True,
            "analysis_timestamp": "2026-07-30T00:00:00Z",
            **kwargs,
        }

    manager.data_governance_tools.trace_column_lineage.side_effect = trace
    result = await manager._trace_column_lineage_tool(
        {
            "target_columns": [
                "orders.customer_id",
                "analytics.orders.total",
                "invalid",
                "orders.broken",
            ],
            "analysis_depth": 4,
        }
    )

    assert result["multi_column_lineage"] is True
    assert result["column_count"] == 4
    assert result["analysis_timestamp"] == "2026-07-30T00:00:00Z"
    assert result["results"]["orders.customer_id"]["db_name"] is None
    assert result["results"]["analytics.orders.total"]["db_name"] == "analytics"
    assert "Invalid column specification" in result["results"]["invalid"]["error"]
    assert "lineage unavailable" in result["results"]["orders.broken"]["error"]
