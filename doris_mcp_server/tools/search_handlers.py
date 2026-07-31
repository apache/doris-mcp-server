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

"""Formal Search-domain handlers backed by one strict runtime."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol, cast

from ..utils.db import DorisConnectionManager
from ..utils.query_runtime import DorisQueryRuntime
from ..utils.search_runtime import DorisSearchRuntime


class _SearchHandlerOwner(Protocol):
    """State supplied by ``DorisToolsManager`` to the mixin."""

    search_runtime: DorisSearchRuntime


class SearchToolHandlersMixin:
    """Route every Search child through the Doris-native runtime."""

    def _initialize_search_handlers(
        self: _SearchHandlerOwner,
        connection_manager: DorisConnectionManager,
        query_runtime: DorisQueryRuntime,
    ) -> None:
        self.search_runtime = DorisSearchRuntime(
            connection_manager,
            query_runtime,
        )

    async def _formal_doris_search_search_data_tool(
        self: _SearchHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.search_runtime.search_data(
            database=cast(str, arguments.get("database")),
            table=cast(str, arguments.get("table")),
            query=cast(str | None, arguments.get("query")),
            mode=cast(str, arguments.get("mode")),
            fields=cast(list[str] | None, arguments.get("fields")),
            vector=cast(list[Any] | None, arguments.get("vector")),
            vector_field=cast(str | None, arguments.get("vector_field")),
            text_operator=cast(str | None, arguments.get("text_operator")),
            top_k=cast(int | None, arguments.get("top_k")),
            filters=cast(
                Mapping[str, Any] | None,
                arguments.get("filters"),
            ),
            return_fields=cast(
                list[str] | None,
                arguments.get("return_fields"),
            ),
        )

    async def _formal_doris_search_preview_text_analysis_tool(
        self: _SearchHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.search_runtime.preview_text_analysis(
            text=cast(str, arguments.get("text")),
            analyzer=cast(str | None, arguments.get("analyzer")),
            tokenizer=cast(str | None, arguments.get("tokenizer")),
            token_filters=cast(
                list[str] | None,
                arguments.get("token_filters"),
            ),
        )

    async def _formal_doris_search_inspect_search_indexes_tool(
        self: _SearchHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.search_runtime.inspect_search_indexes(
            database=cast(str, arguments.get("database")),
            table=cast(str, arguments.get("table")),
            index=cast(str | None, arguments.get("index")),
        )

    async def _formal_doris_search_diagnose_search_query_tool(
        self: _SearchHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.search_runtime.diagnose_search_query(
            sql=cast(str | None, arguments.get("sql")),
            search_request=cast(
                Mapping[str, Any] | None,
                arguments.get("search_request"),
            ),
            include_profile=bool(arguments.get("include_profile", False)),
        )


__all__ = ["SearchToolHandlersMixin"]
