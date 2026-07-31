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

"""Formal Query-domain handlers backed by one strict runtime."""

from __future__ import annotations

from typing import Any, Protocol, cast

from ..utils.adbc_query_tools import DorisADBCQueryTools
from ..utils.db import DorisConnectionManager
from ..utils.query_runtime import DorisQueryRuntime


class _QueryHandlerOwner(Protocol):
    """State supplied by ``DorisToolsManager`` to the mixin."""

    query_runtime: DorisQueryRuntime

    @staticmethod
    def _required_string(arguments: dict[str, Any], name: str) -> str: ...


class QueryToolHandlersMixin:
    """Route every Query child through the strict formal runtime."""

    def _initialize_query_handlers(
        self: _QueryHandlerOwner,
        connection_manager: DorisConnectionManager,
        adbc_query_tools: DorisADBCQueryTools,
    ) -> None:
        self.query_runtime = DorisQueryRuntime(
            connection_manager,
            adbc_query_tools,
        )

    async def _exec_query_tool(
        self: _QueryHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        sql = self._required_string(arguments, "sql")
        timeout_ms = arguments.get("timeout_ms")
        if timeout_ms is None and arguments.get("timeout") is not None:
            timeout_ms = int(arguments["timeout"]) * 1000
        return await self.query_runtime.execute_query(
            sql=sql,
            catalog=cast(
                str | None,
                arguments.get("catalog", arguments.get("catalog_name")),
            ),
            database=cast(
                str | None,
                arguments.get("database", arguments.get("db_name")),
            ),
            parameters=arguments.get("parameters"),
            max_rows=cast(int | None, arguments.get("max_rows")),
            timeout_ms=cast(int | None, timeout_ms),
        )

    async def _get_sql_explain_tool(
        self: _QueryHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        sql = self._required_string(arguments, "sql")
        level = arguments.get("level")
        if level is None:
            level = "verbose" if arguments.get("verbose") else "normal"
        return await self.query_runtime.explain_query(
            sql=sql,
            catalog=cast(
                str | None,
                arguments.get("catalog", arguments.get("catalog_name")),
            ),
            database=cast(
                str | None,
                arguments.get("database", arguments.get("db_name")),
            ),
            level=cast(str, level),
        )

    async def _get_sql_profile_tool(
        self: _QueryHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.query_runtime.get_query_profile(
            query_id=cast(str | None, arguments.get("query_id")),
            sql=cast(str | None, arguments.get("sql")),
            recent_window_minutes=cast(
                int | None,
                arguments.get("recent_window_minutes"),
            ),
            include_operator_tree=bool(
                arguments.get("include_operator_tree", False)
            ),
            database=cast(
                str | None,
                arguments.get("database", arguments.get("db_name")),
            ),
        )

    async def _analyze_slow_queries_topn_tool(
        self: _QueryHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        window_minutes = arguments.get("window_minutes")
        if window_minutes is None and arguments.get("days") is not None:
            window_minutes = int(arguments["days"]) * 1440
        return await self.query_runtime.list_slow_queries(
            window_minutes=cast(int | None, window_minutes),
            limit=cast(
                int | None,
                arguments.get("limit", arguments.get("top_n")),
            ),
            min_duration_ms=cast(
                int | None,
                arguments.get(
                    "min_duration_ms",
                    arguments.get("min_execution_time_ms"),
                ),
            ),
            database=cast(
                str | None,
                arguments.get("database", arguments.get("db_name")),
            ),
            user=cast(str | None, arguments.get("user")),
        )

    async def _exec_adbc_query_tool(
        self: _QueryHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        sql = self._required_string(arguments, "sql")
        timeout_ms = arguments.get("timeout_ms")
        if timeout_ms is None and arguments.get("timeout") is not None:
            timeout_ms = int(arguments["timeout"]) * 1000
        return await self.query_runtime.execute_adbc_query(
            explicit_adbc=arguments.get("explicit_adbc") is True,
            sql=sql,
            max_rows=cast(int | None, arguments.get("max_rows")),
            timeout_ms=cast(int | None, timeout_ms),
            result_format=cast(
                str | None,
                arguments.get(
                    "result_format",
                    arguments.get("return_format"),
                ),
            ),
        )

    async def _get_adbc_connection_info_tool(
        self: _QueryHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.query_runtime.get_adbc_connection_info(
            explicit_adbc=arguments.get("explicit_adbc") is True,
        )

    async def _formal_doris_query_diagnose_query_performance_tool(
        self: _QueryHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.query_runtime.diagnose_query_performance(
            query_id=cast(str | None, arguments.get("query_id")),
            sql=cast(str | None, arguments.get("sql")),
            database=cast(str | None, arguments.get("database")),
            include_cluster_context=bool(
                arguments.get("include_cluster_context", False)
            ),
        )


__all__ = ["QueryToolHandlersMixin"]
