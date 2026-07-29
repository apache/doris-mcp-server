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
"""Transport fixture for the official MCP 2026-07-28 conformance suite."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging

import uvicorn
from mcp.server.stdio import stdio_server
from mcp.types import (
    ClientCapabilities,
    GetPromptResult,
    Prompt,
    Resource,
    SamplingCapability,
    Tool,
)

from doris_mcp_server import __version__
from doris_mcp_server.protocol import (
    create_doris_mcp_server,
    create_transport_security,
)


class EmptyResourcesManager:
    async def list_resources(self) -> list[Resource]:
        return []

    async def read_resource(self, uri: str) -> str:
        return json.dumps({"uri": uri})


class CapabilityToolsManager:
    async def list_tools(self) -> list[Tool]:
        return [
            Tool(
                name="test_missing_capability",
                description="Exercise the required-client-capability boundary.",
                input_schema={"type": "object", "properties": {}},
            )
        ]

    async def call_tool(self, name: str, arguments: dict) -> str:
        del arguments
        return json.dumps({"ok": True, "tool": name})


class EmptyPromptsManager:
    async def list_prompts(self) -> list[Prompt]:
        return []

    async def get_prompt(self, name: str, arguments: dict) -> GetPromptResult:
        raise ValueError(f"Unknown prompt: {name}")


def create_conformance_server():
    return create_doris_mcp_server(
        resources_manager=EmptyResourcesManager(),
        tools_manager=CapabilityToolsManager(),
        prompts_manager=EmptyPromptsManager(),
        name="doris-mcp-conformance-test",
        version=__version__,
        logger=logging.getLogger(__name__),
        required_tool_capabilities={
            "test_missing_capability": ClientCapabilities(sampling=SamplingCapability())
        },
    )


async def run_stdio() -> None:
    server = create_conformance_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--transport", choices=("http", "stdio"), required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=39123, type=int)
    args = parser.parse_args()

    if args.transport == "stdio":
        asyncio.run(run_stdio())
        return

    server = create_conformance_server()
    app = server.streamable_http_app(
        json_response=True,
        stateless_http=True,
        host=args.host,
        transport_security=create_transport_security(args.host),
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
