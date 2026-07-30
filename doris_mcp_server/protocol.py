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
import secrets
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any, Protocol, TypeVar

from mcp.server import Server, ServerRequestContext
from mcp.server.caching import CacheHint
from mcp.server.context import CallNext
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.exceptions import MCPError
from mcp.types import (
    INTERNAL_ERROR,
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

from .auth.operation_policy import OperationAuthorizationError, authorize_operation
from .pagination import (
    DEFAULT_LIST_PAGE_SIZE,
    MAX_LIST_PAGE_SIZE,
    CursorCollection,
    PaginationCursorError,
    PaginationPage,
    paginate,
)
from .schema_validation import (
    DEFAULT_SCHEMA_LIMITS,
    SchemaLimits,
    ToolArgumentsValidationError,
    ToolOutputValidationError,
    ToolSchemaGuard,
)
from .state_handles import (
    DEFAULT_STATE_HANDLE_TTL_SECONDS,
    StateHandleCodec,
)
from .utils.redaction import (
    redact_error_payload,
    redact_sensitive_text,
    redact_uri,
)
from .utils.security import get_current_auth_context

_ListItemT = TypeVar("_ListItemT")


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


def _explicit_transport_allowlist(
    values: Iterable[str] | None,
    *,
    setting: str,
) -> list[str]:
    """Normalize an explicit transport allowlist without accepting allow-all."""
    normalized = list(dict.fromkeys(str(value).strip() for value in values or ()))
    normalized = [value for value in normalized if value]
    if "*" in normalized:
        raise ValueError(
            f"{setting} must list deployment hosts explicitly; '*' is not allowed"
        )
    return normalized


def create_transport_security(
    host: str,
    *,
    allowed_hosts: Iterable[str] | None = None,
    allowed_origins: Iterable[str] | None = None,
) -> TransportSecuritySettings:
    """Create a fail-closed Host and Origin policy for a bind host."""
    configured_hosts = _explicit_transport_allowlist(
        allowed_hosts,
        setting="MCP_ALLOWED_HOSTS",
    )
    configured_origins = _explicit_transport_allowlist(
        allowed_origins,
        setting="MCP_ALLOWED_ORIGINS",
    )
    if host in {"127.0.0.1", "localhost", "::1"}:
        default_hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
        default_origins = [
            "http://127.0.0.1:*",
            "http://localhost:*",
            "http://[::1]:*",
        ]
    else:
        # A bind address is not a public deployment hostname. Explicit
        # deployment allowlists replace this conservative fallback.
        default_hosts = [host, f"{host}:*"]
        default_origins = []
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=configured_hosts or default_hosts,
        allowed_origins=configured_origins or default_origins,
    )


def _decode_structured_tool_result(payload: str) -> tuple[Any | None, bool]:
    """Extract safe structured content and the legacy manager's error marker."""
    try:
        decoded = json.loads(payload)
    except (TypeError, json.JSONDecodeError):
        return None, False

    return decoded, isinstance(decoded, dict) and "error" in decoded


def _sanitize_manager_error_payload(
    payload: str,
) -> tuple[str, Any | None, bool]:
    decoded, is_error = _decode_structured_tool_result(payload)
    if not is_error:
        return payload, decoded, False
    decoded = redact_error_payload(decoded)
    return (
        json.dumps(decoded, ensure_ascii=False, indent=2),
        decoded,
        True,
    )


_RESOURCE_INVALID_PARAMS_MESSAGES = {
    "INVALID_RESOURCE_URI": "Invalid resource URI",
    "RESOURCE_NOT_FOUND": "Resource not found",
}

_PROMPT_INVALID_PARAMS_MESSAGES = {
    "UNKNOWN_PROMPT": "Prompt not found",
    "MISSING_REQUIRED_ARGUMENT": "Missing required prompt argument",
}
_PROMPT_DATABASE_CONTEXT_ERROR = "DATABASE_CONTEXT_UNAVAILABLE"
_LIST_ERROR_CATEGORIES = {
    "backend_unavailable",
    "internal_error",
    "permission_denied",
}
_LIST_ERROR_MESSAGES = {
    "backend_unavailable": "List backend unavailable",
    "internal_error": "Internal server error",
    "permission_denied": "List operation permission denied",
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


def _list_operation_error(operation: str, exc: Exception) -> MCPError:
    """Build a value-safe MCP failure for a list operation."""
    category = getattr(exc, "list_error_category", "internal_error")
    if not isinstance(category, str) or category not in _LIST_ERROR_CATEGORIES:
        category = "internal_error"

    data = {
        "operation": operation,
        "listErrorCategory": category,
    }
    error_code = getattr(exc, "error_code", None)
    if (
        isinstance(error_code, str)
        and len(error_code) <= 96
        and error_code.replace("_", "").isalnum()
    ):
        data["listErrorCode"] = error_code

    return MCPError(
        code=INTERNAL_ERROR,
        message=_LIST_ERROR_MESSAGES[category],
        data=data,
    )


def _paginate_list_or_raise(
    items: Sequence[_ListItemT],
    *,
    collection: CursorCollection,
    cursor: str | None,
    page_size: int,
    identifier: Callable[[_ListItemT], str],
    handle_codec: StateHandleCodec,
) -> PaginationPage[_ListItemT]:
    try:
        return paginate(
            items,
            collection=collection,
            cursor=cursor,
            page_size=page_size,
            identifier=identifier,
            auth_context=get_current_auth_context(),
            handle_codec=handle_codec,
        )
    except PaginationCursorError as exc:
        raise MCPError(
            code=INVALID_PARAMS,
            message="Invalid pagination cursor",
            data={"cursorError": exc.reason},
        ) from exc


def _tools_for_protocol(
    tools: Sequence[Tool],
    protocol_version: str,
) -> list[Tool]:
    """Hide non-object output schemas from protocol eras that cannot encode them."""
    if protocol_version == LATEST_PROTOCOL_VERSION:
        return list(tools)
    return [
        (
            tool.model_copy(update={"output_schema": None})
            if tool.output_schema is not None
            and tool.output_schema.get("type") != "object"
            else tool
        )
        for tool in tools
    ]


def create_doris_mcp_server(
    *,
    resources_manager: ResourcesManager,
    tools_manager: ToolsManager,
    prompts_manager: PromptsManager,
    name: str,
    version: str,
    logger: logging.Logger,
    list_page_size: int = DEFAULT_LIST_PAGE_SIZE,
    state_handle_secret: str | bytes | None = None,
    state_handle_ttl_seconds: int = DEFAULT_STATE_HANDLE_TTL_SECONDS,
    schema_limits: SchemaLimits = DEFAULT_SCHEMA_LIMITS,
    required_client_capabilities: Mapping[str, ClientCapabilities] | None = None,
    required_tool_capabilities: Mapping[str, ClientCapabilities] | None = None,
) -> Server:
    """Create the one low-level SDK v2 server used by every transport."""
    if not 1 <= list_page_size <= MAX_LIST_PAGE_SIZE:
        raise ValueError(f"list_page_size must be in the range 1-{MAX_LIST_PAGE_SIZE}")
    handle_codec = StateHandleCodec(
        (
            state_handle_secret
            if state_handle_secret is not None
            else secrets.token_urlsafe(32)
        ),
        default_ttl_seconds=state_handle_ttl_seconds,
    )
    schema_guard = ToolSchemaGuard(schema_limits)

    async def list_resources(
        ctx: ServerRequestContext,
        params: PaginatedRequestParams | None,
    ) -> ListResourcesResult:
        del ctx
        authorize_operation(get_current_auth_context(), "list_resources")
        try:
            resources = await resources_manager.list_resources()
            page = _paginate_list_or_raise(
                resources,
                collection="resources",
                cursor=params.cursor if params else None,
                page_size=list_page_size,
                identifier=lambda resource: str(resource.uri),
                handle_codec=handle_codec,
            )
        except (MCPError, OperationAuthorizationError):
            raise
        except Exception as exc:
            logger.exception("resources/list failed")
            raise _list_operation_error("resources/list", exc) from exc
        logger.info(
            "Returning %d of %d resources",
            len(page.items),
            len(resources),
        )
        return ListResourcesResult(
            resources=page.items,
            next_cursor=page.next_cursor,
        )

    async def read_resource(
        ctx: ServerRequestContext,
        params: ReadResourceRequestParams,
    ) -> ReadResourceResult:
        authorize_operation(get_current_auth_context(), "read_resource")
        content = await resources_manager.read_resource(params.uri)
        content, _, _ = _sanitize_manager_error_payload(content)
        if ctx.protocol_version == LATEST_PROTOCOL_VERSION:
            request_error = _decode_resource_request_error(content)
            if request_error is not None:
                error_code, message = request_error
                raise MCPError(
                    code=INVALID_PARAMS,
                    message=message,
                    data={
                        "uri": redact_uri(str(params.uri)),
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
        authorize_operation(get_current_auth_context(), "list_tools")
        try:
            tools = await tools_manager.list_tools()
            schema_guard.compile_catalog(tools)
            tools = _tools_for_protocol(tools, ctx.protocol_version)
            page = _paginate_list_or_raise(
                tools,
                collection="tools",
                cursor=params.cursor if params else None,
                page_size=list_page_size,
                identifier=lambda tool: tool.name,
                handle_codec=handle_codec,
            )
        except (MCPError, OperationAuthorizationError):
            raise
        except Exception as exc:
            logger.exception("tools/list failed")
            raise _list_operation_error("tools/list", exc) from exc
        logger.info("Returning %d of %d tools", len(page.items), len(tools))
        return ListToolsResult(
            tools=page.items,
            next_cursor=page.next_cursor,
        )

    async def call_tool(
        ctx: ServerRequestContext,
        params: CallToolRequestParams,
    ) -> CallToolResult:
        arguments = params.arguments or {}
        tools = await tools_manager.list_tools()
        compiled_schema = schema_guard.compile_catalog(tools).get(params.name)
        if compiled_schema is not None:
            try:
                compiled_schema.validate_arguments(arguments)
            except ToolArgumentsValidationError as exc:
                data: dict[str, Any] = {
                    "name": redact_sensitive_text(params.name),
                    "violations": [
                        violation.as_dict()
                        for violation in exc.violations
                    ],
                }
                if exc.truncated:
                    data["truncated"] = True
                raise MCPError(
                    code=INVALID_PARAMS,
                    message="Tool arguments do not match input schema",
                    data=data,
                ) from exc
        try:
            payload = await tools_manager.call_tool(params.name, arguments)
        except OperationAuthorizationError:
            raise
        except Exception:
            logger.exception("Tool execution failed")
            payload = json.dumps(
                {
                    "error": "Tool execution failed",
                    "error_code": "TOOL_EXECUTION_FAILED",
                }
            )
        payload, structured_content, is_error = _sanitize_manager_error_payload(
            payload
        )
        if compiled_schema is not None and not is_error:
            try:
                compiled_schema.validate_output(structured_content)
            except ToolOutputValidationError:
                logger.exception(
                    "Tool %s returned structured content that violates outputSchema",
                    params.name,
                )
                raise
        if (
            ctx.protocol_version != LATEST_PROTOCOL_VERSION
            and not isinstance(structured_content, dict)
        ):
            structured_content = None
        return CallToolResult(
            content=[TextContent(type="text", text=payload)],
            structured_content=structured_content,
            is_error=is_error,
        )

    async def list_prompts(
        ctx: ServerRequestContext,
        params: PaginatedRequestParams | None,
    ) -> ListPromptsResult:
        del ctx
        authorize_operation(get_current_auth_context(), "list_prompts")
        try:
            prompts = await prompts_manager.list_prompts()
            page = _paginate_list_or_raise(
                prompts,
                collection="prompts",
                cursor=params.cursor if params else None,
                page_size=list_page_size,
                identifier=lambda prompt: prompt.name,
                handle_codec=handle_codec,
            )
        except (MCPError, OperationAuthorizationError):
            raise
        except Exception as exc:
            logger.exception("prompts/list failed")
            raise _list_operation_error("prompts/list", exc) from exc
        logger.info(
            "Returning %d of %d prompts",
            len(page.items),
            len(prompts),
        )
        return ListPromptsResult(
            prompts=page.items,
            next_cursor=page.next_cursor,
        )

    async def get_prompt(
        ctx: ServerRequestContext,
        params: GetPromptRequestParams,
    ) -> GetPromptResult:
        del ctx
        authorize_operation(get_current_auth_context(), "get_prompt")
        try:
            return await prompts_manager.get_prompt(
                params.name,
                dict(params.arguments or {}),
            )
        except Exception as exc:
            prompt_error_code = getattr(exc, "error_code", None)
            message = (
                _PROMPT_INVALID_PARAMS_MESSAGES.get(prompt_error_code)
                if isinstance(prompt_error_code, str)
                else None
            )
            if message is not None:
                data = {
                    "name": redact_sensitive_text(params.name),
                    "promptErrorCode": prompt_error_code,
                }
                argument = getattr(exc, "argument", None)
                if isinstance(argument, str):
                    data["argument"] = argument
                raise MCPError(
                    code=INVALID_PARAMS,
                    message=message,
                    data=data,
                ) from exc
            if prompt_error_code == _PROMPT_DATABASE_CONTEXT_ERROR:
                logger.exception(
                    "Database context failed while rendering prompt %s",
                    params.name,
                )
                raise MCPError(
                    code=INTERNAL_ERROR,
                    message="Database context unavailable",
                    data={
                        "name": params.name,
                        "promptErrorCode": prompt_error_code,
                    },
                ) from exc
            raise

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

    async def hide_unhandled_errors(
        ctx: ServerRequestContext,
        call_next: CallNext,
    ) -> Any:
        try:
            return await call_next(ctx)
        except (MCPError, OperationAuthorizationError):
            raise
        except Exception as exc:
            logger.exception("Unhandled MCP request failure for %s", ctx.method)
            raise MCPError(
                code=INTERNAL_ERROR,
                message="Internal server error",
            ) from exc

    server.middleware.append(hide_unhandled_errors)

    if required_client_capabilities or required_tool_capabilities:
        requirements = dict(required_client_capabilities or {})
        tool_requirements = dict(required_tool_capabilities or {})

        async def enforce_required_client_capabilities(
            ctx: ServerRequestContext,
            call_next: CallNext,
        ) -> Any:
            required = requirements.get(ctx.method)
            if ctx.method == "tools/call" and ctx.params is not None:
                tool_name = ctx.params.get("name")
                if isinstance(tool_name, str):
                    required = tool_requirements.get(tool_name, required)
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
