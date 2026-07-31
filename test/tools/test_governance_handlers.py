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

"""Exact argument-routing contracts for the formal Governance handlers."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from doris_mcp_server.tools.governance_handlers import (
    GovernanceToolHandlersMixin,
)


class _Harness(GovernanceToolHandlersMixin):
    def __init__(self) -> None:
        self.governance_runtime = SimpleNamespace(
            analyze_columns=AsyncMock(return_value={"status": "success"}),
            analyze_table_storage=AsyncMock(return_value={"status": "success"}),
            get_lineage_capability_status=AsyncMock(
                return_value={"status": "success"}
            ),
            trace_column_lineage=AsyncMock(return_value={"status": "success"}),
            analyze_data_access_patterns=AsyncMock(
                return_value={"status": "success"}
            ),
            get_recent_audit_logs=AsyncMock(return_value={"status": "success"}),
            list_udfs=AsyncMock(return_value={"status": "success"}),
            get_auth_mapping_status=AsyncMock(
                return_value={"status": "success"}
            ),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("handler_name", "runtime_name", "arguments", "expected"),
    [
        (
            "_formal_doris_governance_analyze_columns_tool",
            "analyze_columns",
            {
                "database": "analytics",
                "table": "orders",
                "columns": ["id"],
                "sample_ratio": 0.1,
            },
            {
                "database": "analytics",
                "table": "orders",
                "columns": ["id"],
                "sample_ratio": 0.1,
            },
        ),
        (
            "_formal_doris_governance_analyze_table_storage_tool",
            "analyze_table_storage",
            {
                "database": "analytics",
                "table": "orders",
                "include_partitions": True,
                "include_indexes": True,
            },
            {
                "database": "analytics",
                "table": "orders",
                "include_partitions": True,
                "include_indexes": True,
            },
        ),
        (
            "_formal_doris_governance_get_lineage_capability_status_tool",
            "get_lineage_capability_status",
            {},
            {},
        ),
        (
            "_formal_doris_governance_trace_column_lineage_tool",
            "trace_column_lineage",
            {
                "object": "analytics.orders",
                "column": "id",
                "direction": "upstream",
                "depth": 2,
                "evidence_mode": "native",
            },
            {
                "object_name": "analytics.orders",
                "column": "id",
                "direction": "upstream",
                "depth": 2,
                "evidence_mode": "native",
            },
        ),
        (
            "_formal_doris_governance_analyze_data_access_patterns_tool",
            "analyze_data_access_patterns",
            {
                "database": "analytics",
                "table": "orders",
                "window_days": 7,
                "group_by": "operation",
            },
            {
                "database": "analytics",
                "table": "orders",
                "window_days": 7,
                "group_by": "operation",
            },
        ),
        (
            "_formal_doris_governance_get_recent_audit_logs_tool",
            "get_recent_audit_logs",
            {
                "window_minutes": 60,
                "user": "alice",
                "operation": "SELECT",
                "database": "analytics",
                "table": "orders",
                "limit": 20,
            },
            {
                "window_minutes": 60,
                "user": "alice",
                "operation": "SELECT",
                "database": "analytics",
                "table": "orders",
                "limit": 20,
            },
        ),
        (
            "_formal_doris_governance_list_udfs_tool",
            "list_udfs",
            {
                "database": "analytics",
                "language": "java",
                "name_pattern": "normalize%",
            },
            {
                "database": "analytics",
                "language": "java",
                "name_pattern": "normalize%",
            },
        ),
        (
            "_formal_doris_governance_get_auth_mapping_status_tool",
            "get_auth_mapping_status",
            {
                "principal": "alice",
                "provider": "oidc",
                "include_roles": True,
            },
            {
                "principal": "alice",
                "provider": "oidc",
                "include_roles": True,
            },
        ),
    ],
)
async def test_governance_handlers_forward_exact_arguments(
    handler_name: str,
    runtime_name: str,
    arguments: dict[str, Any],
    expected: dict[str, Any],
) -> None:
    harness = _Harness()

    result = await getattr(harness, handler_name)(arguments)

    assert result == {"status": "success"}
    runtime_method = getattr(harness.governance_runtime, runtime_name)
    if expected:
        runtime_method.assert_awaited_once_with(**expected)
    else:
        runtime_method.assert_awaited_once_with()
