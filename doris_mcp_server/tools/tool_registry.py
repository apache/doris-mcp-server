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
"""Single source of truth for Doris MCP tool definitions."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal, Protocol, cast

from mcp.types import Tool

ToolPolicyClass = Literal["metadata", "query", "explain", "restricted"]
ToolHandler = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]

DORIS_OAUTH_METADATA_TOOL_NAMES = (
    "get_db_list",
    "get_db_table_list",
    "get_table_schema",
    "get_table_comment",
    "get_table_column_comments",
    "get_table_indexes",
    "get_catalog_list",
)
DORIS_OAUTH_METADATA_TOOL_SET = frozenset(DORIS_OAUTH_METADATA_TOOL_NAMES)
DORIS_OAUTH_QUERY_TOOL_SET = frozenset({"exec_query"})
DORIS_OAUTH_EXPLAIN_TOOL_SET = frozenset({"get_sql_explain"})

_LEGACY_ALIASES: tuple[tuple[str, str, tuple[tuple[str, Any], ...]], ...] = (
    (
        "get_monitoring_metrics_info",
        "get_monitoring_metrics",
        (("content_type", "definitions"),),
    ),
    (
        "get_monitoring_metrics_data",
        "get_monitoring_metrics",
        (("content_type", "data"),),
    ),
    (
        "get_realtime_memory_stats",
        "get_memory_stats",
        (("data_type", "realtime"),),
    ),
    (
        "get_historical_memory_stats",
        "get_memory_stats",
        (("data_type", "historical"),),
    ),
)
LEGACY_TOOL_ALIAS_NAMES = frozenset(alias for alias, _, _ in _LEGACY_ALIASES)
RESTRICTED_TOOL_NAMES = frozenset(
    {
        "get_recent_audit_logs",
        "get_sql_profile",
        "get_table_data_size",
        "get_monitoring_metrics",
        "get_memory_stats",
        "get_table_basic_info",
        "analyze_columns",
        "analyze_table_storage",
        "trace_column_lineage",
        "monitor_data_freshness",
        "analyze_data_access_patterns",
        "analyze_data_flow_dependencies",
        "analyze_slow_queries_topn",
        "analyze_resource_growth_curves",
        "exec_adbc_query",
        "get_adbc_connection_info",
    }
) | LEGACY_TOOL_ALIAS_NAMES


class ToolRegistryError(ValueError):
    """Raised when the tool registry is invalid or a tool is unknown."""


class ToolHandlerOwner(Protocol):
    """Structural type for objects that own registry handlers."""


@dataclass(frozen=True)
class ToolPolicyDefinition:
    """Authorization metadata consumed by the operation policy."""

    policy_class: ToolPolicyClass
    channel: str
    risk: str
    error_code: str | None = None


@dataclass(frozen=True)
class ToolAuditDefinition:
    """Safe audit metadata derived from the advertised tool schema."""

    event_name: str
    category: str
    risk: str
    argument_names: tuple[str, ...]
    sensitive_arguments: tuple[str, ...]


@dataclass(frozen=True)
class ToolDefinition:
    """Schema, policy, handler, audit, and documentation for one tool."""

    name: str
    canonical_name: str
    tool: Tool | None
    handler_name: str
    policy: ToolPolicyDefinition
    audit: ToolAuditDefinition
    advertised: bool = True
    argument_overrides: tuple[tuple[str, Any], ...] = ()

    def bind_handler(self, owner: ToolHandlerOwner) -> ToolHandler:
        handler = getattr(owner, self.handler_name, None)
        if not callable(handler):
            raise ToolRegistryError(
                f"Tool {self.name!r} references missing handler {self.handler_name!r}"
            )
        return cast(ToolHandler, handler)

    def prepare_arguments(self, arguments: dict[str, Any]) -> dict[str, Any]:
        prepared = dict(arguments)
        prepared.update(self.argument_overrides)
        return prepared


def _policy_for_name(name: str) -> ToolPolicyDefinition:
    if name in DORIS_OAUTH_METADATA_TOOL_SET:
        return ToolPolicyDefinition("metadata", "mysql_metadata", "metadata")
    if name in DORIS_OAUTH_QUERY_TOOL_SET:
        return ToolPolicyDefinition("query", "mysql_query", "query")
    if name in DORIS_OAUTH_EXPLAIN_TOOL_SET:
        return ToolPolicyDefinition("explain", "mysql_explain", "explain")
    if name in RESTRICTED_TOOL_NAMES:
        return ToolPolicyDefinition(
            "restricted",
            "unsupported",
            "high",
            "UNSUPPORTED_FOR_DORIS_OAUTH",
        )
    raise ToolRegistryError(f"Tool {name!r} has no policy definition")


def _audit_category(name: str, policy: ToolPolicyDefinition) -> str:
    if name == "get_recent_audit_logs":
        return "audit"
    if name.startswith(("get_monitoring_", "get_memory_", "get_realtime_")):
        return "monitoring"
    if name.startswith("get_historical_") or name == "get_table_data_size":
        return "monitoring"
    if "adbc" in name:
        return "adbc"
    if name.startswith(("analyze_", "trace_", "monitor_")):
        return "analytics"
    if name in {"get_sql_profile", "get_sql_explain", "exec_query"}:
        return "query"
    return policy.policy_class


def _audit_for_tool(
    name: str,
    tool: Tool | None,
    policy: ToolPolicyDefinition,
) -> ToolAuditDefinition:
    properties: dict[str, Any] = {}
    if tool is not None:
        raw_properties = tool.input_schema.get("properties", {})
        if isinstance(raw_properties, dict):
            properties = raw_properties
    argument_names = tuple(sorted(str(key) for key in properties))
    sensitive_arguments = tuple(
        argument for argument in argument_names if argument in {"sql"}
    )
    return ToolAuditDefinition(
        event_name=f"mcp.tool.call.{name}",
        category=_audit_category(name, policy),
        risk=policy.risk,
        argument_names=argument_names,
        sensitive_arguments=sensitive_arguments,
    )


class ToolDefinitionRegistry:
    """Immutable registry used by listing, dispatch, policy, audit, and docs."""

    def __init__(
        self,
        definitions: Iterable[ToolDefinition],
        owner: ToolHandlerOwner,
    ) -> None:
        definitions_by_name: dict[str, ToolDefinition] = {}
        ordered_names: list[str] = []
        for definition in definitions:
            if definition.name in definitions_by_name:
                raise ToolRegistryError(
                    f"Duplicate tool definition: {definition.name}"
                )
            definition.bind_handler(owner)
            if definition.advertised and definition.tool is None:
                raise ToolRegistryError(
                    f"Advertised tool {definition.name!r} has no MCP schema"
                )
            definitions_by_name[definition.name] = definition
            ordered_names.append(definition.name)

        self._definitions = MappingProxyType(definitions_by_name)
        self._ordered_names = tuple(ordered_names)

    @classmethod
    def from_tools(
        cls,
        tools: Iterable[Tool],
        owner: ToolHandlerOwner,
    ) -> ToolDefinitionRegistry:
        tools_by_name: dict[str, Tool] = {}
        definitions: list[ToolDefinition] = []
        for tool in tools:
            if tool.name in tools_by_name:
                raise ToolRegistryError(f"Duplicate tool schema: {tool.name}")
            tools_by_name[tool.name] = tool
            policy = _policy_for_name(tool.name)
            definitions.append(
                ToolDefinition(
                    name=tool.name,
                    canonical_name=tool.name,
                    tool=tool,
                    handler_name=f"_{tool.name}_tool",
                    policy=policy,
                    audit=_audit_for_tool(tool.name, tool, policy),
                )
            )

        for alias, canonical_name, overrides in _LEGACY_ALIASES:
            if canonical_name not in tools_by_name:
                raise ToolRegistryError(
                    f"Legacy alias {alias!r} references unknown tool "
                    f"{canonical_name!r}"
                )
            policy = _policy_for_name(alias)
            definitions.append(
                ToolDefinition(
                    name=alias,
                    canonical_name=canonical_name,
                    tool=tools_by_name[canonical_name],
                    handler_name=f"_{canonical_name}_tool",
                    policy=policy,
                    audit=_audit_for_tool(
                        alias,
                        tools_by_name[canonical_name],
                        policy,
                    ),
                    advertised=False,
                    argument_overrides=overrides,
                )
            )

        return cls(definitions, owner)

    @property
    def definitions(self) -> tuple[ToolDefinition, ...]:
        return tuple(
            self._definitions[name] for name in self._ordered_names
        )

    @property
    def advertised_definitions(self) -> tuple[ToolDefinition, ...]:
        return tuple(
            definition
            for definition in self.definitions
            if definition.advertised
        )

    @property
    def advertised_names(self) -> tuple[str, ...]:
        return tuple(
            definition.name for definition in self.advertised_definitions
        )

    def resolve(self, name: str) -> ToolDefinition:
        try:
            return self._definitions[name]
        except KeyError as exc:
            raise ToolRegistryError(f"Unknown tool: {name}") from exc

    def listed_tools(self) -> list[Tool]:
        return [
            cast(Tool, definition.tool)
            for definition in self.advertised_definitions
        ]

    def render_markdown(self) -> str:
        """Render the checked-in public catalog from registry definitions."""
        lines = [
            "# Doris MCP Tool Registry",
            "",
            "<!-- Generated from ToolDefinitionRegistry; do not edit by hand. -->",
            "",
            "| Tool | Policy | Risk | Handler | Audit event | Parameters |",
            "|---|---|---|---|---|---|",
        ]
        for definition in self.advertised_definitions:
            tool = cast(Tool, definition.tool)
            required = set(tool.input_schema.get("required", []))
            parameters = ", ".join(
                f"`{name}`{'*' if name in required else ''}"
                for name in definition.audit.argument_names
            )
            lines.append(
                "| "
                f"`{definition.name}` | "
                f"`{definition.policy.policy_class}` | "
                f"`{definition.policy.risk}` | "
                f"`{definition.handler_name}` | "
                f"`{definition.audit.event_name}` | "
                f"{parameters or 'None'} |"
            )
        lines.extend(
            [
                "",
                "Required parameters are marked with `*`. Tool descriptions and "
                "JSON Schemas are exposed directly by MCP `tools/list` from the "
                "same registry entries.",
                "",
            ]
        )
        return "\n".join(lines)


def policy_definition_for_tool(name: str) -> ToolPolicyDefinition | None:
    """Return policy metadata for a registered canonical tool or legacy alias."""
    if (
        name in DORIS_OAUTH_METADATA_TOOL_SET
        or name in DORIS_OAUTH_QUERY_TOOL_SET
        or name in DORIS_OAUTH_EXPLAIN_TOOL_SET
        or name in RESTRICTED_TOOL_NAMES
    ):
        return _policy_for_name(name)
    return None
