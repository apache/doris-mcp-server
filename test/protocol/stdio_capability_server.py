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

from doris_mcp_server import __version__
from doris_mcp_server.protocol import create_doris_mcp_server
from doris_mcp_server.tools.tools_manager import DorisToolsManager
from doris_mcp_server.utils.analysis_tools import SQLAnalyzer
from doris_mcp_server.utils.data_governance_tools import DataGovernanceTools
from doris_mcp_server.utils.db import QueryResult
from doris_mcp_server.utils.security_analytics_tools import SecurityAnalyticsTools

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


class FreshnessGovernanceTools(DataGovernanceTools):
    async def _analyze_table_freshness(
        self,
        connection,
        table_name: str,
        threshold_hours: int,
    ) -> dict:
        return {
            "last_update": None,
            "staleness_hours": None,
            "freshness_score": 0.0,
            "status": "unknown",
            "method_used": "none",
        }


class RoleMetadataConnection:
    async def execute(
        self,
        sql: str,
        params=None,
        auth_context=None,
        *,
        mask_result: bool = True,
    ) -> QueryResult:
        assert mask_result is False
        if sql.strip() == "SHOW ALL GRANTS":
            return QueryResult(
                data=[
                    {
                        "UserIdentity": "'root'@'%'",
                        "Roles": "operator",
                    }
                ],
                metadata={},
                execution_time=0.01,
                row_count=1,
                sql=sql,
            )
        raise RuntimeError("Unknown column 'Default_role'")


class RoleConnectionManager:
    def __init__(self) -> None:
        self.connection = RoleMetadataConnection()

    async def get_connection(self, session_id: str) -> RoleMetadataConnection:
        return self.connection


class RoleSecurityAnalyticsTools(SecurityAnalyticsTools):
    async def _get_audit_log_data(
        self,
        connection,
        start_date,
        end_date,
        include_system_users,
    ) -> list[dict]:
        return [{"user_name": "root"}]

    async def _analyze_user_access_patterns(
        self,
        audit_data: list[dict],
        min_query_threshold: int,
    ) -> list[dict]:
        return [
            {
                "user_name": "root",
                "access_stats": {"total_queries": 1},
                "query_type_distribution": {"SELECT": 1},
            }
        ]

    async def _detect_security_anomalies(
        self,
        audit_data: list[dict],
        user_access_analysis: list[dict],
    ) -> list[dict]:
        return []

    async def _generate_access_insights(
        self,
        user_access_analysis: list[dict],
        role_analysis: dict,
    ) -> dict:
        return {}


class OneToolManager:
    def __init__(self) -> None:
        connection_manager = ProfileConnectionManager()
        self.profile_analyzer = ProfileAnalyzer(connection_manager)
        self.freshness_router = object.__new__(DorisToolsManager)
        self.freshness_router.data_governance_tools = FreshnessGovernanceTools(
            connection_manager
        )
        self.role_analyzer = RoleSecurityAnalyticsTools(RoleConnectionManager())

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
            Tool(
                name="monitor_data_freshness",
                description="Exercise unknown freshness values with the default threshold.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "table_names": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                        "freshness_threshold_hours": {"type": "integer"},
                    },
                },
            ),
            Tool(
                name="analyze_data_access_patterns",
                description="Exercise Doris 4 role metadata compatibility.",
                input_schema={"type": "object", "properties": {}},
            ),
        ]

    async def call_tool(self, name: str, arguments: dict) -> str:
        if name == "echo" and arguments.get("fail"):
            return json.dumps(
                {
                    "error": (
                        f"query failed: password={arguments['password']}; "
                        f"token={arguments['token']}; {arguments['sql']}"
                    ),
                    "arguments": arguments,
                    "token": arguments["token"],
                }
            )
        if name == "get_sql_profile":
            return json.dumps(
                await self.profile_analyzer.get_sql_profile(
                    arguments["sql"],
                    db_name=arguments.get("db_name"),
                )
            )
        if name == "monitor_data_freshness":
            return json.dumps(
                await self.freshness_router._monitor_data_freshness_tool(arguments)
            )
        if name == "analyze_data_access_patterns":
            return json.dumps(
                await self.role_analyzer.analyze_data_access_patterns()
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
        version=__version__,
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
