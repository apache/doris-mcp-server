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

"""Formal Lakehouse-domain handlers backed by one strict runtime."""

from __future__ import annotations

from typing import Any, Protocol, cast

from ..utils.db import DorisConnectionManager
from ..utils.lakehouse_runtime import DorisLakehouseRuntime


class _LakehouseHandlerOwner(Protocol):
    """State supplied by ``DorisToolsManager`` to the mixin."""

    lakehouse_runtime: DorisLakehouseRuntime


class LakehouseToolHandlersMixin:
    """Route every Lakehouse child through the read-only runtime."""

    def _initialize_lakehouse_handlers(
        self: _LakehouseHandlerOwner,
        connection_manager: DorisConnectionManager,
    ) -> None:
        self.lakehouse_runtime = DorisLakehouseRuntime(connection_manager)

    async def _formal_doris_lakehouse_inspect_external_catalog_tool(
        self: _LakehouseHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.lakehouse_runtime.inspect_external_catalog(
            catalog=cast(str, arguments.get("catalog")),
            include_objects=bool(arguments.get("include_objects", False)),
            object_limit=cast(int | None, arguments.get("object_limit")),
        )

    async def _formal_doris_lakehouse_inspect_lakehouse_table_tool(
        self: _LakehouseHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.lakehouse_runtime.inspect_lakehouse_table(
            catalog=cast(str, arguments.get("catalog")),
            database=cast(str, arguments.get("database")),
            table=cast(str, arguments.get("table")),
            include_snapshots=bool(
                arguments.get("include_snapshots", False)
            ),
            include_partitions=bool(
                arguments.get("include_partitions", False)
            ),
        )

    async def _formal_doris_lakehouse_inspect_variant_column_tool(
        self: _LakehouseHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.lakehouse_runtime.inspect_variant_column(
            catalog=cast(str | None, arguments.get("catalog")),
            database=cast(str, arguments.get("database")),
            table=cast(str, arguments.get("table")),
            column=cast(str, arguments.get("column")),
            path=cast(str | None, arguments.get("path")),
            sample_rows=cast(int | None, arguments.get("sample_rows")),
        )


__all__ = ["LakehouseToolHandlersMixin"]
