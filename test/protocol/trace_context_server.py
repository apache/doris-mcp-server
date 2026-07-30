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
"""True-subprocess stdio fixture for MCP OpenTelemetry propagation."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import mcp.shared._otel as mcp_otel
from mcp.server.stdio import stdio_server
from mcp.types import GetPromptResult, Prompt, Resource, Tool
from opentelemetry.baggage import get_all
from opentelemetry.trace import (
    NonRecordingSpan,
    SpanContext,
    TraceFlags,
    get_current_span,
    use_span,
)

from doris_mcp_server import __version__
from doris_mcp_server.protocol import create_doris_mcp_server


class _ResourcesManager:
    async def list_resources(self) -> list[Resource]:
        return []

    async def read_resource(self, uri: str) -> str:
        return json.dumps({"uri": uri})


class _ToolsManager:
    async def list_tools(self) -> list[Tool]:
        return [
            Tool(
                name="echo",
                description="Return a fixed response without request metadata.",
                input_schema={"type": "object", "properties": {}},
            )
        ]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> str:
        del name, arguments
        return json.dumps({"ok": True})


class _PromptsManager:
    async def list_prompts(self) -> list[Prompt]:
        return []

    async def get_prompt(
        self,
        name: str,
        arguments: dict[str, Any],
    ) -> GetPromptResult:
        del name, arguments
        raise AssertionError("prompt fixture is not called")


class _ObservationTracer:
    """Small API-only tracer that records propagation without an SDK exporter."""

    def __init__(self, output_path: Path) -> None:
        self._output_path = output_path

    @contextmanager
    def start_as_current_span(
        self,
        name: str,
        *,
        context: Any = None,
        attributes: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Generator[NonRecordingSpan]:
        del attributes, kwargs
        parent = get_current_span(context).get_span_context()
        trace_id = parent.trace_id if parent.is_valid else secrets.randbits(128) or 1
        child_context = SpanContext(
            trace_id=trace_id,
            span_id=secrets.randbits(64) or 1,
            is_remote=False,
            trace_flags=parent.trace_flags if parent.is_valid else TraceFlags(0),
            trace_state=parent.trace_state if parent.is_valid else None,
        )
        baggage = get_all(context=context)
        record = {
            "name": name,
            "parentTraceId": (
                f"{parent.trace_id:032x}" if parent.is_valid else None
            ),
            "parentSpanId": (
                f"{parent.span_id:016x}" if parent.is_valid else None
            ),
            "baggageCount": len(baggage),
            "redactedBaggageCount": sum(
                value == "[REDACTED]" for value in baggage.values()
            ),
        }
        with self._output_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, sort_keys=True) + "\n")
        span = NonRecordingSpan(child_context)
        with use_span(span, end_on_exit=False):
            yield span


async def main() -> None:
    observation_path = Path(os.environ["DORIS_MCP_TRACE_OBSERVATIONS"])
    log_path = Path(os.environ["DORIS_MCP_TRACE_LOG"])
    logging.basicConfig(
        filename=log_path,
        level=logging.WARNING,
        force=True,
    )
    mcp_otel._tracer = _ObservationTracer(observation_path)
    logger = logging.getLogger("doris_mcp_server.trace_context_fixture")
    server = create_doris_mcp_server(
        resources_manager=_ResourcesManager(),
        tools_manager=_ToolsManager(),
        prompts_manager=_PromptsManager(),
        name="doris-mcp-trace-context-test",
        version=__version__,
        logger=logger,
    )
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
