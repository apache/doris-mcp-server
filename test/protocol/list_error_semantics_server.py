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
"""Transport fixture for list failure and recovery semantics."""

from __future__ import annotations

import asyncio
import json
import logging

from mcp.server.stdio import stdio_server
from mcp.types import GetPromptResult, Prompt, Resource, Tool

from doris_mcp_server import __version__
from doris_mcp_server.protocol import create_doris_mcp_server
from doris_mcp_server.tools.resources_manager import ResourceMetadataError

SENSITIVE_MARKER = "backend-sensitive-list-error-detail"


class SequentialResourcesManager:
    def __init__(self) -> None:
        self.calls = 0

    async def list_resources(self) -> list[Resource]:
        self.calls += 1
        if self.calls == 1:
            raise ResourceMetadataError(
                SENSITIVE_MARKER,
                error_code="DORIS_METADATA_BACKEND_ERROR",
                status_code=502,
                list_error_category="backend_unavailable",
            )
        if self.calls == 2:
            raise ResourceMetadataError(
                SENSITIVE_MARKER,
                error_code="DORIS_METADATA_PERMISSION_DENIED",
                status_code=403,
                list_error_category="permission_denied",
            )
        return []

    async def read_resource(self, uri: str) -> str:
        return json.dumps({"uri": uri})


class SequentialToolsManager:
    def __init__(self) -> None:
        self.calls = 0

    async def list_tools(self) -> list[Tool]:
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError(SENSITIVE_MARKER)
        return []

    async def call_tool(self, name: str, arguments: dict) -> str:
        return json.dumps({"name": name, "arguments": arguments})


class SequentialPromptsManager:
    def __init__(self) -> None:
        self.calls = 0

    async def list_prompts(self) -> list[Prompt]:
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError(SENSITIVE_MARKER)
        return []

    async def get_prompt(
        self,
        name: str,
        arguments: dict,
    ) -> GetPromptResult:
        raise AssertionError((name, arguments))


def create_list_error_semantics_server():
    return create_doris_mcp_server(
        resources_manager=SequentialResourcesManager(),
        tools_manager=SequentialToolsManager(),
        prompts_manager=SequentialPromptsManager(),
        name="doris-mcp-list-error-semantics-test",
        version=__version__,
        logger=logging.getLogger(__name__),
    )


async def main() -> None:
    server = create_list_error_semantics_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
