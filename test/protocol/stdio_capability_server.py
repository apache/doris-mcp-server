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
import logging

from mcp.server.stdio import stdio_server
from mcp.types import ClientCapabilities, GetPromptResult, Prompt, Resource, Tool

from doris_mcp_server.protocol import create_doris_mcp_server

REQUIRED_EXTENSION = "io.apache.doris/read"


class EmptyResourcesManager:
    async def list_resources(self) -> list[Resource]:
        return []

    async def read_resource(self, uri: str) -> str:
        raise ValueError(f"Unknown resource: {uri}")


class OneToolManager:
    async def list_tools(self) -> list[Tool]:
        return [
            Tool(
                name="echo",
                description="Echo structured input.",
                input_schema={"type": "object", "properties": {}},
            )
        ]

    async def call_tool(self, name: str, arguments: dict) -> str:
        return "{}"


class EmptyPromptsManager:
    async def list_prompts(self) -> list[Prompt]:
        return []

    async def get_prompt(
        self,
        name: str,
        arguments: dict,
    ) -> GetPromptResult:
        raise ValueError(f"Unknown prompt: {name}")


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
