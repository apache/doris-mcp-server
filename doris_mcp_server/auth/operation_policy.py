#!/usr/bin/env python3
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
"""MCP operation policy for scope-aware OAuth authentication."""

from dataclasses import dataclass
from typing import Any

from ..tools.tool_registry import (
    DORIS_OAUTH_EXPLAIN_TOOL_SET,
    DORIS_OAUTH_METADATA_TOOL_NAMES,
    DORIS_OAUTH_METADATA_TOOL_SET,
    DORIS_OAUTH_QUERY_TOOL_SET,
    RESTRICTED_TOOL_NAMES,
    policy_definition_for_tool,
)


@dataclass(frozen=True)
class OperationPolicy:
    name: str
    required_scope: str | None
    doris_oauth_policy: str  # allow, deny
    channel: str = "none"
    risk: str = "low"
    error_code: str | None = None


class OperationAuthorizationError(Exception):
    """Raised when an MCP operation is not authorized."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int = 403,
        error_code: str = "PERMISSION_DENIED",
        required_scope: str | None = None,
        operation: str = "",
    ):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        self.required_scope = required_scope
        self.operation = operation

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "error": self.error_code,
            "message": self.message,
            "operation": self.operation,
            "status_code": self.status_code,
        }
        if self.required_scope:
            payload["required_scope"] = self.required_scope
        return payload


P4_DORIS_OAUTH_METADATA_TOOLS = DORIS_OAUTH_METADATA_TOOL_SET
P4_DORIS_OAUTH_QUERY_TOOLS = DORIS_OAUTH_QUERY_TOOL_SET
P4_DORIS_OAUTH_EXPLAIN_TOOLS = DORIS_OAUTH_EXPLAIN_TOOL_SET
P4_DORIS_OAUTH_DEFAULT_METADATA_TOOL_ALLOWLIST = DORIS_OAUTH_METADATA_TOOL_NAMES

# Phase 4 keeps DB-backed Doris OAuth tools fail-closed unless configuration and
# exact tool scope both allow a reviewed metadata tool.
DORIS_OAUTH_DB_TOOLS_ENABLED = False
DORIS_OAUTH_DB_TOOL_ALLOWLIST = P4_DORIS_OAUTH_DEFAULT_METADATA_TOOL_ALLOWLIST

DORIS_OAUTH_QUERY_TOOLS_ENABLED = False
DORIS_OAUTH_QUERY_TOOL_ALLOWLIST = ("exec_query",)
DORIS_OAUTH_EXPLAIN_TOOLS_ENABLED = False
DORIS_OAUTH_EXPLAIN_TOOL_ALLOWLIST = ("get_sql_explain",)

HIGH_RISK_TOOLS = RESTRICTED_TOOL_NAMES


def normalize_doris_oauth_metadata_tool_allowlist(tools: Any = None) -> tuple[str, ...]:
    if tools is None:
        return P4_DORIS_OAUTH_DEFAULT_METADATA_TOOL_ALLOWLIST
    if isinstance(tools, str):
        candidates = [part.strip() for part in tools.split(",") if part.strip()]
    else:
        candidates = [str(tool).strip() for tool in tools if str(tool).strip()]

    normalized = []
    seen = set()
    invalid = []
    for tool_name in candidates:
        if tool_name not in P4_DORIS_OAUTH_METADATA_TOOLS:
            invalid.append(tool_name)
            continue
        if tool_name not in seen:
            normalized.append(tool_name)
            seen.add(tool_name)
    if invalid:
        invalid_list = ", ".join(sorted(set(invalid)))
        raise ValueError(
            "DORIS_OAUTH_DB_TOOL_ALLOWLIST can only contain Phase 4 metadata tools; "
            f"invalid entries: {invalid_list}"
        )
    return tuple(normalized)


def _setting(auth_context: Any, name: str, default: Any) -> Any:
    return getattr(auth_context, name, default)


def _metadata_tools_enabled(auth_context: Any) -> bool:
    return bool(
        _setting(
            auth_context,
            "doris_oauth_db_tools_enabled",
            DORIS_OAUTH_DB_TOOLS_ENABLED,
        )
    )


def _metadata_tool_allowlist(auth_context: Any) -> tuple[str, ...]:
    raw_allowlist = _setting(
        auth_context,
        "doris_oauth_db_tool_allowlist",
        DORIS_OAUTH_DB_TOOL_ALLOWLIST,
    )
    return normalize_doris_oauth_metadata_tool_allowlist(raw_allowlist)


def _query_tools_enabled(auth_context: Any) -> bool:
    return bool(
        _setting(
            auth_context,
            "doris_oauth_query_tools_enabled",
            DORIS_OAUTH_QUERY_TOOLS_ENABLED,
        )
    )


def _query_tool_allowlist(auth_context: Any) -> tuple[str, ...]:
    raw_allowlist = _setting(
        auth_context,
        "doris_oauth_query_tool_allowlist",
        DORIS_OAUTH_QUERY_TOOL_ALLOWLIST,
    )
    if isinstance(raw_allowlist, str):
        return tuple(part.strip() for part in raw_allowlist.split(",") if part.strip())
    return tuple(str(tool).strip() for tool in raw_allowlist if str(tool).strip())


def _explain_tools_enabled(auth_context: Any) -> bool:
    return bool(
        _setting(
            auth_context,
            "doris_oauth_explain_tools_enabled",
            DORIS_OAUTH_EXPLAIN_TOOLS_ENABLED,
        )
    )


def _explain_tool_allowlist(auth_context: Any) -> tuple[str, ...]:
    raw_allowlist = _setting(
        auth_context,
        "doris_oauth_explain_tool_allowlist",
        DORIS_OAUTH_EXPLAIN_TOOL_ALLOWLIST,
    )
    if isinstance(raw_allowlist, str):
        return tuple(part.strip() for part in raw_allowlist.split(",") if part.strip())
    return tuple(str(tool).strip() for tool in raw_allowlist if str(tool).strip())


def _denied_tool_policy(
    tool_name: str,
    *,
    channel: str,
    risk: str,
    error_code: str,
) -> OperationPolicy:
    return OperationPolicy(
        name=f"tool:{tool_name}",
        required_scope=f"tool:call:{tool_name}",
        doris_oauth_policy="deny",
        channel=channel,
        risk=risk,
        error_code=error_code,
    )


def _allowed_metadata_tool_policy(tool_name: str) -> OperationPolicy:
    return OperationPolicy(
        name=f"tool:{tool_name}",
        required_scope=f"tool:call:{tool_name}",
        doris_oauth_policy="allow",
        channel="mysql_metadata",
        risk="metadata",
    )


def _tool_policy(tool_name: str, auth_context: Any = None) -> OperationPolicy:
    registry_policy = policy_definition_for_tool(tool_name)
    if registry_policy is None:
        return _denied_tool_policy(
            tool_name,
            channel="unknown",
            risk="unknown",
            error_code="UNKNOWN_OPERATION",
        )

    if registry_policy.policy_class == "metadata":
        if not _metadata_tools_enabled(auth_context):
            return _denied_tool_policy(
                tool_name,
                channel="doris_oauth_metadata_disabled",
                risk="metadata",
                error_code="DORIS_OAUTH_DB_TOOLS_NOT_ENABLED",
            )
        try:
            allowlist = set(_metadata_tool_allowlist(auth_context))
        except ValueError:
            return _denied_tool_policy(
                tool_name,
                channel="doris_oauth_metadata_misconfigured",
                risk="metadata",
                error_code="DORIS_OAUTH_DB_TOOL_ALLOWLIST_INVALID",
            )
        if tool_name not in allowlist:
            return _denied_tool_policy(
                tool_name,
                channel="doris_oauth_metadata_not_allowed",
                risk="metadata",
                error_code="DORIS_OAUTH_TOOL_NOT_ALLOWED",
            )
        return _allowed_metadata_tool_policy(tool_name)

    if registry_policy.policy_class == "query":
        if not _query_tools_enabled(auth_context):
            return _denied_tool_policy(
                tool_name,
                channel="doris_oauth_query_disabled",
                risk="query",
                error_code="DORIS_OAUTH_QUERY_TOOL_NOT_ENABLED",
            )
        if tool_name not in set(_query_tool_allowlist(auth_context)):
            return _denied_tool_policy(
                tool_name,
                channel="doris_oauth_query_not_allowed",
                risk="query",
                error_code="DORIS_OAUTH_TOOL_NOT_ALLOWED",
            )
        return OperationPolicy(
            name=f"tool:{tool_name}",
            required_scope=f"tool:call:{tool_name}",
            doris_oauth_policy="allow",
            channel="mysql_query",
            risk="query",
        )

    if registry_policy.policy_class == "explain":
        if not _explain_tools_enabled(auth_context):
            return _denied_tool_policy(
                tool_name,
                channel="doris_oauth_explain_disabled",
                risk="explain",
                error_code="DORIS_OAUTH_EXPLAIN_TOOL_NOT_ENABLED",
            )
        if tool_name not in set(_explain_tool_allowlist(auth_context)):
            return _denied_tool_policy(
                tool_name,
                channel="doris_oauth_explain_not_allowed",
                risk="explain",
                error_code="DORIS_OAUTH_TOOL_NOT_ALLOWED",
            )
        return OperationPolicy(
            name=f"tool:{tool_name}",
            required_scope=f"tool:call:{tool_name}",
            doris_oauth_policy="allow",
            channel="mysql_explain",
            risk="explain",
        )

    if registry_policy.policy_class == "restricted":
        return _denied_tool_policy(
            tool_name,
            channel=registry_policy.channel,
            risk=registry_policy.risk,
            error_code=registry_policy.error_code
            or "UNSUPPORTED_FOR_DORIS_OAUTH",
        )

    raise AssertionError(f"Unhandled registry policy: {registry_policy.policy_class}")


OPERATION_POLICIES: dict[str, OperationPolicy] = {
    "list_tools": OperationPolicy("list_tools", "tool:list", "allow"),
    "list_resources": OperationPolicy("list_resources", "resource:list", "allow", "mysql", "metadata"),
    "read_resource": OperationPolicy("read_resource", "resource:read", "allow", "mysql", "metadata"),
    "list_prompts": OperationPolicy("list_prompts", "prompt:list", "deny", "local", "medium"),
    "get_prompt": OperationPolicy("get_prompt", "prompt:get", "deny", "mysql", "medium"),
    "http:/": OperationPolicy("http:/", None, "allow"),
    "http:/health": OperationPolicy("http:/health", None, "allow"),
    "http:/live": OperationPolicy("http:/live", None, "allow"),
    "http:/ready": OperationPolicy("http:/ready", None, "allow"),
    "http:/auth/login": OperationPolicy("http:/auth/login", None, "deny", "external_oauth", "medium"),
    "http:/auth/callback": OperationPolicy("http:/auth/callback", None, "deny", "external_oauth", "medium"),
    "http:/auth/provider": OperationPolicy("http:/auth/provider", None, "deny", "external_oauth", "medium"),
    "http:/auth/demo": OperationPolicy("http:/auth/demo", None, "deny", "external_oauth", "medium"),
    "http:/token/create": OperationPolicy("http:/token/create", None, "deny", "token_admin", "high"),
    "http:/token/revoke": OperationPolicy("http:/token/revoke", None, "deny", "token_admin", "high"),
    "http:/token/list": OperationPolicy("http:/token/list", None, "deny", "token_admin", "high"),
    "http:/token/stats": OperationPolicy("http:/token/stats", None, "deny", "token_admin", "high"),
    "http:/token/cleanup": OperationPolicy("http:/token/cleanup", None, "deny", "token_admin", "high"),
    "http:/token/management": OperationPolicy("http:/token/management", None, "deny", "token_admin", "high"),
}

EXTERNAL_OAUTH_OPERATION_SCOPES: dict[str, str] = {
    "list_tools": "tool:list",
    "list_resources": "resource:list",
    "read_resource": "resource:read",
    "list_prompts": "prompt:list",
    "get_prompt": "prompt:get",
}


def resolve_operation_policy(operation: str, auth_context: Any = None) -> OperationPolicy:
    if operation.startswith("tool:"):
        return _tool_policy(operation.split(":", 1)[1], auth_context)
    return OPERATION_POLICIES.get(
        operation,
        OperationPolicy(operation, None, "deny", "unknown", "unknown", "UNKNOWN_OPERATION"),
    )


def _has_scope(auth_context: Any, required_scope: str | None) -> bool:
    if not required_scope:
        return True
    scopes = set(auth_context.oauth_scopes or [])
    return required_scope in scopes


def _external_oauth_required_scope(operation: str) -> str:
    if operation.startswith("tool:"):
        tool_name = operation.split(":", 1)[1]
        if policy_definition_for_tool(tool_name) is None:
            raise OperationAuthorizationError(
                f"Unknown MCP operation: {operation}",
                status_code=403,
                error_code="UNKNOWN_OPERATION",
                required_scope=f"tool:call:{tool_name}",
                operation=operation,
            )
        return f"tool:call:{tool_name}"

    required_scope = EXTERNAL_OAUTH_OPERATION_SCOPES.get(operation)
    if required_scope is None:
        raise OperationAuthorizationError(
            f"Unknown MCP operation: {operation}",
            status_code=403,
            error_code="UNKNOWN_OPERATION",
            operation=operation,
        )
    return required_scope


def authorize_operation(auth_context: Any | None, operation: str) -> None:
    """Authorize scope-aware OAuth operations.

    Static token, JWT, anonymous, and local stdio paths retain their existing
    authorization behavior outside this OAuth scope policy.
    """
    if auth_context is None:
        return

    if auth_context.auth_method == "external_oauth":
        required_scope = _external_oauth_required_scope(operation)
        if not _has_scope(auth_context, required_scope):
            raise OperationAuthorizationError(
                f"Missing required scope: {required_scope}",
                status_code=403,
                error_code="PERMISSION_DENIED",
                required_scope=required_scope,
                operation=operation,
            )
        return

    if auth_context.auth_method != "doris_oauth":
        return

    policy = resolve_operation_policy(operation, auth_context)
    if policy.doris_oauth_policy != "allow":
        raise OperationAuthorizationError(
            f"Operation is not supported for Doris OAuth: {operation}",
            status_code=403,
            error_code=policy.error_code or "UNSUPPORTED_FOR_DORIS_OAUTH",
            required_scope=policy.required_scope,
            operation=operation,
        )

    if not _has_scope(auth_context, policy.required_scope):
        raise OperationAuthorizationError(
            f"Missing required scope: {policy.required_scope}",
            status_code=403,
            error_code="PERMISSION_DENIED",
            required_scope=policy.required_scope,
            operation=operation,
        )


def filter_tools_for_auth_context(auth_context: Any | None, tools: list[Any]) -> list[Any]:
    """Filter visible tools for Doris OAuth users."""
    if auth_context is None or auth_context.auth_method != "doris_oauth":
        return tools

    filtered = []
    for tool in tools:
        tool_name = getattr(tool, "name", "")
        try:
            authorize_operation(auth_context, f"tool:{tool_name}")
        except OperationAuthorizationError:
            continue
        filtered.append(tool)
    return filtered
