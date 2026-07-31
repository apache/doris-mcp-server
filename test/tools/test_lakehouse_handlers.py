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

"""Exact argument-routing contracts for the formal Lakehouse handlers."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from doris_mcp_server.tools.lakehouse_handlers import (
    LakehouseToolHandlersMixin,
)


class _Harness(LakehouseToolHandlersMixin):
    def __init__(self) -> None:
        self.lakehouse_runtime = SimpleNamespace(
            inspect_external_catalog=AsyncMock(
                return_value={"status": "success"}
            ),
            inspect_lakehouse_table=AsyncMock(
                return_value={"status": "success"}
            ),
            inspect_variant_column=AsyncMock(
                return_value={"status": "success"}
            ),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("handler_name", "runtime_name", "arguments", "expected"),
    [
        (
            "_formal_doris_lakehouse_inspect_external_catalog_tool",
            "inspect_external_catalog",
            {
                "catalog": "ice_prod",
                "include_objects": True,
                "object_limit": 12,
            },
            {
                "catalog": "ice_prod",
                "include_objects": True,
                "object_limit": 12,
            },
        ),
        (
            "_formal_doris_lakehouse_inspect_lakehouse_table_tool",
            "inspect_lakehouse_table",
            {
                "catalog": "ice_prod",
                "database": "analytics",
                "table": "events",
                "include_snapshots": True,
                "include_partitions": True,
            },
            {
                "catalog": "ice_prod",
                "database": "analytics",
                "table": "events",
                "include_snapshots": True,
                "include_partitions": True,
            },
        ),
        (
            "_formal_doris_lakehouse_inspect_variant_column_tool",
            "inspect_variant_column",
            {
                "catalog": "internal",
                "database": "analytics",
                "table": "profiles",
                "column": "payload",
                "path": "$.profile.age",
                "sample_rows": 10,
            },
            {
                "catalog": "internal",
                "database": "analytics",
                "table": "profiles",
                "column": "payload",
                "path": "$.profile.age",
                "sample_rows": 10,
            },
        ),
    ],
)
async def test_lakehouse_handlers_forward_exact_arguments(
    handler_name: str,
    runtime_name: str,
    arguments: dict[str, Any],
    expected: dict[str, Any],
) -> None:
    harness = _Harness()

    result = await getattr(harness, handler_name)(arguments)

    assert result == {"status": "success"}
    getattr(harness.lakehouse_runtime, runtime_name).assert_awaited_once_with(
        **expected
    )


@pytest.mark.asyncio
async def test_lakehouse_handlers_apply_documented_defaults() -> None:
    harness = _Harness()

    await harness._formal_doris_lakehouse_inspect_external_catalog_tool(
        {"catalog": "ice_prod"}
    )
    await harness._formal_doris_lakehouse_inspect_lakehouse_table_tool(
        {
            "catalog": "ice_prod",
            "database": "analytics",
            "table": "events",
        }
    )
    await harness._formal_doris_lakehouse_inspect_variant_column_tool(
        {
            "database": "analytics",
            "table": "profiles",
            "column": "payload",
        }
    )

    harness.lakehouse_runtime.inspect_external_catalog.assert_awaited_once_with(
        catalog="ice_prod",
        include_objects=False,
        object_limit=None,
    )
    harness.lakehouse_runtime.inspect_lakehouse_table.assert_awaited_once_with(
        catalog="ice_prod",
        database="analytics",
        table="events",
        include_snapshots=False,
        include_partitions=False,
    )
    harness.lakehouse_runtime.inspect_variant_column.assert_awaited_once_with(
        catalog=None,
        database="analytics",
        table="profiles",
        column="payload",
        path=None,
        sample_rows=None,
    )
