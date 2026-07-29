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
"""MCP 2026-07-28 protocol boundary for Doris managers."""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from typing import Any, Protocol

from mcp.server import Server, ServerRequestContext
from mcp.server.caching import CacheHint
from mcp.server.context import CallNext
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.exceptions import MCPError
from mcp.types import (
    INVALID_PARAMS,
    LATEST_PROTOCOL_VERSION,
    MISSING_REQUIRED_CLIENT_CAPABILITY,
    CallToolRequestParams,
    CallToolResult,
    ClientCapabilities,
    GetPromptRequestParams,
    GetPromptResult,
    ListPromptsResult,
    ListResourcesResult,
    ListToolsResult,
    MissingRequiredClientCapabilityErrorData,
    PaginatedRequestParams,
    Prompt,
    ReadResourceRequestParams,
    ReadResourceResult,
    Resource,
    TextContent,
    TextResourceContents,
    Tool,
)

from .auth.operation_policy import authorize_operation
from .utils.security import get_current_auth_context


class ResourcesManager(Protocol):
    async def list_resources(self) -> list[Resource]: ...

    async def read_resource(self, uri: str) -> str: ...


class ToolsManager(Protocol):
    async def list_tools(self) -> list[Tool]: ...

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> str: ...


class PromptsManager(Protocol):
    async def list_prompts(self) -> list[Prompt]: ...

    async def get_prompt(
        self, name: str, arguments: dict[str, Any]
    ) -> GetPromptResult: ...


def create_transport_security(host: str) -> TransportSecuritySettings:
    """Create a fail-closed Host and Origin policy for a bind host."""
    if host in {"127.0.0.1", "localhost", "::1"}:
        allowed_hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
        allowed_origins = [
            "http://127.0.0.1:*",
            "http://localhost:*",
            "http://[::1]:*",
        ]
    else:
        # A bind address is not a public deployment hostname. Explicit
        # deployment allowlists will replace this conservative fallback.
        allowed_hosts = [host, f"{host}:*"]
        allowed_origins = []
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
    )


def _decode_structured_tool_result(payload: str) -> tuple[Any | None, bool]:
    """Extract safe structured content and the legacy manager's error marker."""
    try:
        decoded = json.loads(payload)
    except (TypeError, json.JSONDecodeError):
        return None, False

    if not isinstance(decoded, dict):
        return None, False
    return decoded, "error" in decoded


_RESOURCE_INVALID_PARAMS_MESSAGES = {
    "INVALID_RESOURCE_URI": "Invalid resource URI",
    "RESOURCE_NOT_FOUND": "Resource not found",
}


def _decode_resource_request_error(payload: str) -> tuple[str, str] | None:
    """Decode only manager errors that are safe to classify as client input."""
    try:
        decoded = json.loads(payload)
    except (TypeError, json.JSONDecodeError):
        return None

    if not isinstance(decoded, dict):
        return None
    error_code = decoded.get("error_code")
    if not isinstance(error_code, str):
        return None
    message = _RESOURCE_INVALID_PARAMS_MESSAGES.get(error_code)
    if message is None:
        return None
    return error_code, message


def create_doris_mcp_server(
    *,
    resources_manager: ResourcesManager,
    tools_manager: ToolsManager,
    prompts_manager: PromptsManager,
    name: str,
    version: str,
    logger: logging.Logger,
    required_client_capabilities: Mapping[str, ClientCapabilities] | None = None,
) -> Server:
    """Create the one low-level SDK v2 server used by every transport."""

    async def list_resources(
        ctx: ServerRequestContext,
        params: PaginatedRequestParams | None,
    ) -> ListResourcesResult:
        del ctx, params
        authorize_operation(get_current_auth_context(), "list_resources")
        resources = await resources_manager.list_resources()
        logger.info("Returning %d resources", len(resources))
        return ListResourcesResult(resources=resources)

    async def read_resource(
        ctx: ServerRequestContext,
        params: ReadResourceRequestParams,
    ) -> ReadResourceResult:
        authorize_operation(get_current_auth_context(), "read_resource")
        content = await resources_manager.read_resource(params.uri)
        if ctx.protocol_version == LATEST_PROTOCOL_VERSION:
            request_error = _decode_resource_request_error(content)
            if request_error is not None:
                error_code, message = request_error
                raise MCPError(
                    code=INVALID_PARAMS,
                    message=message,
                    data={
                        "uri": str(params.uri),
                        "resourceErrorCode": error_code,
                    },
                )
        return ReadResourceResult(
            contents=[
                TextResourceContents(
                    uri=params.uri,
                    mime_type="application/json",
                    text=content,
                )
            ]
        )

    async def list_tools(
        ctx: ServerRequestContext,
        params: PaginatedRequestParams | None,
    ) -> ListToolsResult:
        del ctx, params
        authorize_operation(get_current_auth_context(), "list_tools")
        tools = await tools_manager.list_tools()
        logger.info("Returning %d tools", len(tools))
        return ListToolsResult(tools=tools)

    async def call_tool(
        ctx: ServerRequestContext,
        params: CallToolRequestParams,
    ) -> CallToolResult:
        del ctx
        arguments = params.arguments or {}
        payload = await tools_manager.call_tool(params.name, arguments)
        structured_content, is_error = _decode_structured_tool_result(payload)
        return CallToolResult(
            content=[TextContent(type="text", text=payload)],
            structured_content=structured_content,
            is_error=is_error,
        )

    async def list_prompts(
        ctx: ServerRequestContext,
        params: PaginatedRequestParams | None,
    ) -> ListPromptsResult:
        del ctx, params
        authorize_operation(get_current_auth_context(), "list_prompts")
        prompts = await prompts_manager.list_prompts()
        logger.info("Returning %d prompts", len(prompts))
        return ListPromptsResult(prompts=prompts)

    async def get_prompt(
        ctx: ServerRequestContext,
        params: GetPromptRequestParams,
    ) -> GetPromptResult:
        del ctx
        authorize_operation(get_current_auth_context(), "get_prompt")
        return await prompts_manager.get_prompt(
            params.name,
            dict(params.arguments or {}),
        )

    private_no_cache = CacheHint(ttl_ms=0, scope="private")
    server = Server(
        name,
        version=version,
        description="Model Context Protocol server for Apache Doris",
        cache_hints={
            "server/discover": CacheHint(ttl_ms=300_000, scope="public"),
            "tools/list": private_no_cache,
            "resources/list": private_no_cache,
            "resources/read": private_no_cache,
            "prompts/list": private_no_cache,
        },
        on_list_resources=list_resources,
        on_read_resource=read_resource,
        on_list_tools=list_tools,
        on_call_tool=call_tool,
        on_list_prompts=list_prompts,
        on_get_prompt=get_prompt,
    )

    if required_client_capabilities:
        requirements = dict(required_client_capabilities)

        async def enforce_required_client_capabilities(
            ctx: ServerRequestContext,
            call_next: CallNext,
        ):
            required = requirements.get(ctx.method)
            if (
                required is not None
                and ctx.protocol_version == LATEST_PROTOCOL_VERSION
                and not ctx.session.check_client_capability(required)
            ):
                data = MissingRequiredClientCapabilityErrorData(
                    required_capabilities=required,
                ).model_dump(by_alias=True, mode="json", exclude_none=True)
                raise MCPError(
                    code=MISSING_REQUIRED_CLIENT_CAPABILITY,
                    message="Missing required client capability",
                    data=data,
                )
            return await call_next(ctx)

        server.middleware.append(enforce_required_client_capabilities)

    return server
