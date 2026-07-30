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
"""Production-registry fixture for HTTP and true subprocess Stdio tests."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from mcp.server.stdio import stdio_server
from mcp.types import GetPromptResult, Prompt, Resource

from doris_mcp_server import __version__
from doris_mcp_server.protocol import create_doris_mcp_server
from doris_mcp_server.tools.domain_models import (
    Availability,
    AvailabilityStatus,
    ChildToolDefinition,
    DomainDefinition,
)
from doris_mcp_server.tools.tools_manager import DorisToolsManager
from doris_mcp_server.utils.config import DorisConfig
from doris_mcp_server.utils.db import DorisConnectionManager


class EmptyResourcesManager:
    async def list_resources(self) -> list[Resource]:
        return []

    async def read_resource(self, uri: str) -> str:
        return json.dumps({"uri": uri})


class EmptyPromptsManager:
    async def list_prompts(self) -> list[Prompt]:
        return []

    async def get_prompt(
        self,
        name: str,
        arguments: dict[str, Any],
    ) -> GetPromptResult:
        del name, arguments
        raise ValueError("Unknown prompt")


class RegistryToolsManager(DorisToolsManager):
    """Use the production registry while replacing database execution."""

    async def _exec_query_tool(
        self,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "success": True,
            "data": [
                {
                    "registry_dispatch": True,
                    "sql_length": len(self._required_string(arguments, "sql")),
                }
            ],
            "row_count": 1,
            "metadata": {
                "columns": ["registry_dispatch", "sql_length"],
            },
        }


class RegistryAvailabilityProvider:
    """Enable only the deterministic query handler used by this fixture."""

    async def availability_for(
        self,
        domain: DomainDefinition,
        child: ChildToolDefinition,
        auth_context: Any | None,
    ) -> Availability:
        del auth_context
        if domain.name == "doris_query" and child.name == "execute_query":
            return Availability(
                status=AvailabilityStatus.AVAILABLE,
                callable=True,
                reason_code="FIXTURE_HANDLER_READY",
                active_variant=child.support_contract.variants[0].name,
                evidence_sources=("fixture_handler",),
            )
        return Availability(
            status=AvailabilityStatus.UNKNOWN,
            callable=False,
            reason_code="FIXTURE_HANDLER_PENDING",
        )


def create_registry_test_server():
    config = DorisConfig.from_env()
    connection_manager = DorisConnectionManager(config)
    return create_doris_mcp_server(
        resources_manager=EmptyResourcesManager(),
        tools_manager=RegistryToolsManager(
            connection_manager,
            domain_availability_provider=RegistryAvailabilityProvider(),
        ),
        prompts_manager=EmptyPromptsManager(),
        name="doris-mcp-tool-registry-test",
        version=__version__,
        logger=logging.getLogger(__name__),
    )


async def main() -> None:
    server = create_registry_test_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
