# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Integration tests for the default detector-to-dispatch capability path."""

from __future__ import annotations

from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from doris_mcp_server.tools.domain_models import AvailabilityStatus
from doris_mcp_server.tools.tools_manager import DorisToolsManager
from doris_mcp_server.utils.config import DorisConfig
from doris_mcp_server.utils.db import DorisRouteIdentity


class _CapabilityConnection:
    def __init__(self) -> None:
        self.statements: list[str] = []

    async def execute(
        self,
        sql: str,
        *_args: Any,
        **_kwargs: Any,
    ) -> SimpleNamespace:
        self.statements.append(sql)
        rows = {
            "SELECT @@version_comment;": [
                {
                    "@@version_comment": (
                        "Doris version doris-4.0.5-59de8c4c524 "
                        "(Cloud Mode)"
                    )
                }
            ],
            "SELECT 1 AS capability_probe": [
                {"capability_probe": 1}
            ],
            "SHOW FRONTENDS": [
                {
                    "Name": "fe-1",
                    "IsMaster": "true",
                    "Version": "doris-4.0.5-59de8c4c524",
                }
            ],
            "SHOW BACKENDS": [
                {
                    "BackendId": "1",
                    "Version": "doris-4.0.5-59de8c4c524",
                }
            ],
            "EXPLAIN SELECT 1": [{"Explain String": "PLAN"}],
        }
        return SimpleNamespace(data=rows.get(sql, []))


class _CapabilityConnectionManager:
    def __init__(self) -> None:
        self.config = DorisConfig()
        self.connection = _CapabilityConnection()
        self.route = DorisRouteIdentity(
            route_key="global",
            generation=1,
            endpoint_fingerprint="endpoint-a",
            fingerprint="route-a",
        )

    def get_route_identity(
        self,
        _auth_context: Any = None,
    ) -> DorisRouteIdentity:
        return self.route

    @asynccontextmanager
    async def get_connection_context_for_auth_context(
        self,
        _session_id: str,
        _auth_context: Any,
    ):
        yield self.connection


@pytest.mark.asyncio
async def test_default_manager_detects_caches_and_dispatches() -> None:
    connection_manager = _CapabilityConnectionManager()
    manager = DorisToolsManager(connection_manager)  # type: ignore[arg-type]
    manager._exec_query_tool = AsyncMock(
        return_value={
            "success": True,
            "data": [{"answer": 42}],
            "row_count": 1,
            "metadata": {"columns": ["answer"]},
        }
    )

    first = await manager.domain_dispatcher.call_domain(
        "doris_query",
        {},
        None,
    )
    second = await manager.domain_dispatcher.call_domain(
        "doris_query",
        {},
        None,
    )
    execute_child = next(
        child
        for child in first.children
        if child.name == "execute_query"
    )
    result = await manager.domain_dispatcher.call_domain(
        "doris_query",
        {
            "child_tool": "execute_query",
            "arguments": {"sql": "SELECT 42 AS answer"},
            "manifest_version": first.manifest_version,
        },
        None,
    )

    assert execute_child.availability.status is AvailabilityStatus.AVAILABLE
    assert execute_child.availability.callable is True
    assert execute_child.availability.detected_versions == {
        "master_fe": ("4.0.5",),
        "be": ("4.0.5",),
    }
    assert first.manifest_version == second.manifest_version
    assert result.mode == "result"
    assert connection_manager.connection.statements.count(
        "SELECT @@version_comment;"
    ) == 1
    assert connection_manager.connection.statements.count(
        "EXPLAIN SELECT 1"
    ) == 1
    manager._exec_query_tool.assert_awaited_once()

