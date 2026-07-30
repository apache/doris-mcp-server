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
"""Standalone stdio fixture for bounded JSON Schema validation."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from mcp.server.stdio import stdio_server
from mcp.types import GetPromptResult, Prompt, Resource, Tool

from doris_mcp_server import __version__
from doris_mcp_server.protocol import create_doris_mcp_server
from doris_mcp_server.schema_validation import JSON_SCHEMA_2020_12

SCHEMA_GUARD_INPUT = {
    "$schema": JSON_SCHEMA_2020_12,
    "type": "object",
    "$defs": {
        "selector": {
            "oneOf": [
                {
                    "type": "object",
                    "properties": {"id": {"type": "integer"}},
                    "required": ["id"],
                    "additionalProperties": False,
                },
                {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "minLength": 1,
                        }
                    },
                    "required": ["name"],
                    "additionalProperties": False,
                },
            ]
        }
    },
    "properties": {
        "selector": {"$ref": "#/$defs/selector"},
    },
    "required": ["selector"],
    "additionalProperties": False,
}
BOOLEAN_OUTPUT = {
    "$schema": JSON_SCHEMA_2020_12,
    "type": "object",
    "properties": {"accepted": {"type": "boolean"}},
    "required": ["accepted"],
    "additionalProperties": False,
}


class EmptyResourcesManager:
    async def list_resources(self) -> list[Resource]:
        return []

    async def read_resource(self, uri: str) -> str:
        return json.dumps({"uri": uri})


class SchemaToolsManager:
    async def list_tools(self) -> list[Tool]:
        return [
            Tool(
                name="schema_guard",
                description="Exercise full JSON Schema 2020-12 input validation.",
                input_schema=SCHEMA_GUARD_INPUT,
                output_schema=BOOLEAN_OUTPUT,
            ),
            Tool(
                name="bad_output",
                description="Exercise server output-schema enforcement.",
                input_schema={
                    "type": "object",
                    "additionalProperties": False,
                },
                output_schema=BOOLEAN_OUTPUT,
            ),
            Tool(
                name="array_output",
                description="Exercise non-object 2026-07-28 structured content.",
                input_schema={
                    "type": "object",
                    "additionalProperties": False,
                },
                output_schema={
                    "$schema": JSON_SCHEMA_2020_12,
                    "type": "array",
                    "items": {"type": "integer"},
                },
            ),
            Tool(
                name="echo",
                description="Verify process recovery after schema errors.",
                input_schema={
                    "type": "object",
                    "properties": {"value": {"type": "string"}},
                    "required": ["value"],
                    "additionalProperties": False,
                },
            ),
        ]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> str:
        if name == "schema_guard":
            return json.dumps({"accepted": True})
        if name == "bad_output":
            return json.dumps({"accepted": "not-a-boolean"})
        if name == "array_output":
            return json.dumps([1, 2, 3])
        return json.dumps({"value": arguments["value"]})


class EmptyPromptsManager:
    async def list_prompts(self) -> list[Prompt]:
        return []

    async def get_prompt(
        self,
        name: str,
        arguments: dict[str, Any],
    ) -> GetPromptResult:
        del name, arguments
        raise AssertionError("schema fixture has no prompts")


def create_schema_validation_server():
    return create_doris_mcp_server(
        resources_manager=EmptyResourcesManager(),
        tools_manager=SchemaToolsManager(),
        prompts_manager=EmptyPromptsManager(),
        name="doris-mcp-schema-validation-test",
        version=__version__,
        logger=logging.getLogger(__name__),
    )


async def main() -> None:
    server = create_schema_validation_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
