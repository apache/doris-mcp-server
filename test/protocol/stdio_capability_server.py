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
"""STDIO fixture for required-client-capability protocol tests."""

import asyncio
import json
import logging
import tempfile
from types import SimpleNamespace

from mcp.server.stdio import stdio_server
from mcp.types import (
    ClientCapabilities,
    GetPromptResult,
    Prompt,
    PromptMessage,
    Resource,
    TextContent,
    Tool,
)

from doris_mcp_server.protocol import create_doris_mcp_server
from doris_mcp_server.utils.analysis_tools import SQLAnalyzer
from doris_mcp_server.utils.db import QueryResult

REQUIRED_EXTENSION = "io.apache.doris/read"


class EmptyResourcesManager:
    async def list_resources(self) -> list[Resource]:
        return []

    async def read_resource(self, uri: str) -> str:
        if uri == "doris://table/orders":
            return json.dumps({"uri": uri, "columns": 3})
        return json.dumps(
            {
                "error": f"Failed to read resource: Table {uri} does not exist",
                "error_code": "RESOURCE_NOT_FOUND",
                "uri": uri,
            }
        )


class ProfileConnection:
    async def execute(self, sql: str, params=None, auth_context=None) -> QueryResult:
        return QueryResult(
            data=[{"one": 1}],
            metadata={"columns": ["one"]},
            execution_time=0.01,
            row_count=1,
            sql=sql,
        )


class ProfileConnectionManager:
    def __init__(self) -> None:
        self._temp_dir = tempfile.TemporaryDirectory(prefix="doris-mcp-profile-")
        self.config = SimpleNamespace(
            temp_files_dir=self._temp_dir.name,
            performance=SimpleNamespace(max_response_content_size=20_000),
        )
        self.connection = ProfileConnection()

    async def get_connection(self, session_id: str) -> ProfileConnection:
        return self.connection


class ProfileAnalyzer(SQLAnalyzer):
    async def _get_query_id_by_trace_id(self, trace_id: str) -> str:
        return "query-1"

    async def _get_profile_by_query_id(self, query_id: str) -> dict:
        return {"profile": "ok", "query_id": query_id}


class OneToolManager:
    def __init__(self) -> None:
        self.profile_analyzer = ProfileAnalyzer(ProfileConnectionManager())

    async def list_tools(self) -> list[Tool]:
        return [
            Tool(
                name="echo",
                description="Echo structured input.",
                input_schema={"type": "object", "properties": {}},
            ),
            Tool(
                name="get_sql_profile",
                description="Exercise the production SQL profile path.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "sql": {"type": "string"},
                        "db_name": {"type": "string"},
                    },
                    "required": ["sql"],
                },
            ),
        ]

    async def call_tool(self, name: str, arguments: dict) -> str:
        if name == "get_sql_profile":
            return json.dumps(
                await self.profile_analyzer.get_sql_profile(
                    arguments["sql"],
                    db_name=arguments.get("db_name"),
                )
            )
        return "{}"


class PromptFixtureError(Exception):
    def __init__(
        self,
        message: str,
        *,
        error_code: str,
        argument: str | None = None,
    ):
        super().__init__(message)
        self.error_code = error_code
        self.argument = argument


class EmptyPromptsManager:
    async def list_prompts(self) -> list[Prompt]:
        return []

    async def get_prompt(
        self,
        name: str,
        arguments: dict,
    ) -> GetPromptResult:
        if name == "missing":
            raise PromptFixtureError(
                "Prompt not found",
                error_code="UNKNOWN_PROMPT",
            )
        if name == "needs_argument" and "required" not in arguments:
            raise PromptFixtureError(
                "Missing required argument",
                error_code="MISSING_REQUIRED_ARGUMENT",
                argument="required",
            )
        if name == "database_failure":
            raise PromptFixtureError(
                "Database context failed",
                error_code="DATABASE_CONTEXT_UNAVAILABLE",
            )
        return GetPromptResult(
            description=name,
            messages=[
                PromptMessage(
                    role="user",
                    content=TextContent(
                        type="text",
                        text=f"Explain {arguments.get('sql', '')}",
                    ),
                )
            ],
        )


async def main() -> None:
    server = create_doris_mcp_server(
        resources_manager=EmptyResourcesManager(),
        tools_manager=OneToolManager(),
        prompts_manager=EmptyPromptsManager(),
        name="doris-mcp-stdio-capability-test",
        version="0.6.1",
        logger=logging.getLogger(__name__),
        required_client_capabilities={
            "tools/list": ClientCapabilities(
                extensions={REQUIRED_EXTENSION: {}},
            )
        },
    )

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
