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
"""Static managers used to verify MCP list pagination across transports."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from mcp.types import (
    GetPromptResult,
    Prompt,
    PromptMessage,
    Resource,
    TextContent,
    Tool,
)

from doris_mcp_server import __version__
from doris_mcp_server.protocol import create_doris_mcp_server

RESOURCE_URIS = [
    "doris://table/alpha",
    "doris://table/bravo",
    "doris://table/charlie",
    "doris://table/delta",
    "doris://table/echo",
]
TOOL_NAMES = ["alpha", "bravo", "charlie", "delta", "echo"]
PROMPT_NAMES = ["alpha", "bravo", "charlie", "delta", "echo"]


@dataclass
class PaginationManagers:
    resources: PaginationResourcesManager
    tools: PaginationToolsManager
    prompts: PaginationPromptsManager


class PaginationResourcesManager:
    def __init__(self) -> None:
        self.resources = [
            Resource(
                uri=uri,
                name=uri.rsplit("/", 1)[-1],
                mime_type="application/json",
            )
            for uri in reversed(RESOURCE_URIS)
        ]

    async def list_resources(self) -> list[Resource]:
        return list(self.resources)

    async def read_resource(self, uri: str) -> str:
        return json.dumps({"uri": uri})


class PaginationToolsManager:
    def __init__(self) -> None:
        self.tools = [
            Tool(
                name=name,
                description=f"{name} test tool",
                input_schema={"type": "object", "properties": {}},
            )
            for name in reversed(TOOL_NAMES)
        ]

    async def list_tools(self) -> list[Tool]:
        return list(self.tools)

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> str:
        return json.dumps({"name": name, "arguments": arguments})


class PaginationPromptsManager:
    def __init__(self) -> None:
        self.prompts = [
            Prompt(name=name, description=f"{name} test prompt")
            for name in reversed(PROMPT_NAMES)
        ]

    async def list_prompts(self) -> list[Prompt]:
        return list(self.prompts)

    async def get_prompt(
        self,
        name: str,
        arguments: dict[str, Any],
    ) -> GetPromptResult:
        return GetPromptResult(
            description=name,
            messages=[
                PromptMessage(
                    role="user",
                    content=TextContent(
                        type="text",
                        text=json.dumps(arguments, sort_keys=True),
                    ),
                )
            ],
        )


def create_pagination_server(
    *,
    page_size: int = 2,
    state_handle_secret: str | None = None,
    state_handle_ttl_seconds: int = 300,
):
    resources = PaginationResourcesManager()
    tools = PaginationToolsManager()
    prompts = PaginationPromptsManager()
    server = create_doris_mcp_server(
        resources_manager=resources,
        tools_manager=tools,
        prompts_manager=prompts,
        name="doris-mcp-pagination-test",
        version=__version__,
        logger=logging.getLogger(__name__),
        list_page_size=page_size,
        state_handle_secret=state_handle_secret,
        state_handle_ttl_seconds=state_handle_ttl_seconds,
    )
    return server, PaginationManagers(
        resources=resources,
        tools=tools,
        prompts=prompts,
    )
