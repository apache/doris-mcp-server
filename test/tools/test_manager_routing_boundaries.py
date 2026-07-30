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
from unittest.mock import AsyncMock, call

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
    manager.memory_tracker = SimpleNamespace(
        get_realtime_memory_stats=AsyncMock(
            return_value={
                "success": True,
                "timestamp": "2026-07-30T00:00:00Z",
            }
        ),
        get_historical_memory_stats=AsyncMock(
            return_value={"success": True, "points": []}
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
async def test_monitoring_metrics_routes_definitions_data_and_both():
    definitions_manager = _manager()
    definitions_manager.monitoring_tools.get_monitoring_metrics.side_effect = None
    definitions_manager.monitoring_tools.get_monitoring_metrics.return_value = {
        "success": True
    }
    definitions = await definitions_manager._get_monitoring_metrics_tool(
        {
            "content_type": "definitions",
            "role": "fe",
            "monitor_type": "system",
            "priority": "all",
        }
    )

    data_manager = _manager()
    data_manager.monitoring_tools.get_monitoring_metrics.side_effect = None
    data_manager.monitoring_tools.get_monitoring_metrics.return_value = {
        "success": True
    }
    data = await data_manager._get_monitoring_metrics_tool(
        {
            "content_type": "data",
            "role": "be",
            "monitor_type": "query",
            "priority": "core",
            "include_raw_metrics": True,
        }
    )

    both_manager = _manager()
    both = await both_manager._get_monitoring_metrics_tool({"content_type": "both"})

    assert definitions == {"success": True}
    definitions_manager.monitoring_tools.get_monitoring_metrics.assert_awaited_once_with(
        "fe", "system", "all", info_only=True, format_type="prometheus"
    )
    assert data == {"success": True}
    data_manager.monitoring_tools.get_monitoring_metrics.assert_awaited_once_with(
        "be",
        "query",
        "core",
        info_only=False,
        format_type="prometheus",
        include_raw_metrics=True,
    )
    assert both["content_type"] == "both"
    assert both["timestamp"] == "2026-07-30T00:00:00Z"
    assert both["_execution_info"] == {
        "combined_response": True,
        "definitions_available": True,
        "data_available": True,
    }


@pytest.mark.asyncio
async def test_monitoring_metrics_rejects_unknown_content_type():
    manager = _manager()

    result = await manager._get_monitoring_metrics_tool({"content_type": "unknown"})

    assert "Invalid content_type" in result["error"]
    manager.monitoring_tools.get_monitoring_metrics.assert_not_awaited()


@pytest.mark.asyncio
async def test_memory_stats_routes_realtime_historical_and_both():
    manager = _manager()

    realtime = await manager._get_memory_stats_tool(
        {
            "data_type": "realtime",
            "tracker_type": "process",
            "include_details": False,
        }
    )
    historical = await manager._get_memory_stats_tool(
        {
            "data_type": "historical",
            "tracker_names": ["query"],
            "time_range": "24h",
        }
    )
    both = await manager._get_memory_stats_tool({"data_type": "both"})

    assert realtime["success"] is True
    assert historical == {"success": True, "points": []}
    assert both["data_type"] == "both"
    assert both["timestamp"] == "2026-07-30T00:00:00Z"
    assert both["_execution_info"] == {
        "combined_response": True,
        "realtime_available": True,
        "historical_available": True,
    }
    assert manager.memory_tracker.get_realtime_memory_stats.await_args_list == [
        call("process", False),
        call("overview", True),
    ]
    assert manager.memory_tracker.get_historical_memory_stats.await_args_list == [
        call(["query"], "24h"),
        call(None, "1h"),
    ]


@pytest.mark.asyncio
async def test_memory_stats_rejects_unknown_data_type():
    manager = _manager()

    result = await manager._get_memory_stats_tool({"data_type": "unknown"})

    assert "Invalid data_type" in result["error"]
    manager.memory_tracker.get_realtime_memory_stats.assert_not_awaited()
    manager.memory_tracker.get_historical_memory_stats.assert_not_awaited()


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
