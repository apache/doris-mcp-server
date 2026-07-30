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
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Exact child dispatch and formal flat exposure for Doris MCP 1.0."""

from __future__ import annotations

import fnmatch
import json
import math
import secrets
import time
from collections import defaultdict
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol, cast

from mcp.types import Tool, ToolAnnotations
from pydantic import ValidationError

from ..schema_validation import (
    CompiledToolSchema,
    ToolArgumentsValidationError,
    ToolOutputValidationError,
    ToolSchemaGuard,
)
from ..utils.logger import get_audit_logger, get_logger
from . import domain_catalog as domain_catalog_module
from .domain_catalog import (
    DorisDomainCatalog,
    LegacyMigrationMode,
    LegacyToolMigration,
)
from .domain_manifest import (
    DOMAIN_ERROR_OUTPUT_SCHEMA,
    DomainManifestService,
    authorized_child_discovery,
    authorized_child_execution,
)
from .domain_models import (
    Availability,
    AvailabilityStatus,
    ChildToolDefinition,
    DomainDefinition,
    DomainErrorCode,
    DomainToolRequest,
    ErrorEnvelope,
    ExecutionEnvelope,
    ExecutionMetadata,
    StandardError,
)

logger = get_logger(__name__)


class ToolExposureMode(StrEnum):
    """Supported public tool-list shapes."""

    HIERARCHICAL = "hierarchical"
    FLAT = "flat"

    @classmethod
    def parse(cls, value: str | ToolExposureMode) -> ToolExposureMode:
        """Parse one exact configured mode without aliases or coercion."""
        if isinstance(value, cls):
            return value
        try:
            return cls(value)
        except ValueError as exc:
            raise ValueError(
                "tool exposure mode must be 'hierarchical' or 'flat'"
            ) from exc


class ToolNotFoundError(LookupError):
    """Raised when a public top-level MCP tool name is not registered."""

    def __init__(self, name: str) -> None:
        super().__init__("Tool not found")
        self.name = name


class ChildArgumentsAdapterError(ValueError):
    """Raised when formal arguments cannot use the active handler adapter."""


class ChildHandlerOwner(Protocol):
    """Structural owner of the existing read-only Doris handler methods."""


@dataclass(frozen=True)
class _AtomicBinding:
    migration: LegacyToolMigration


_Binding = _AtomicBinding | tuple[LegacyToolMigration, ...]


def _build_bindings(
    owner: ChildHandlerOwner,
    catalog: DorisDomainCatalog,
) -> dict[str, _Binding]:
    migrations_by_feature: dict[str, list[LegacyToolMigration]] = defaultdict(
        list
    )
    for migration in catalog.legacy_migrations:
        migrations_by_feature[migration.feature_id].append(migration)

    bindings: dict[str, _Binding] = {}
    for feature_id, migrations in migrations_by_feature.items():
        for migration in migrations:
            handler = getattr(
                owner,
                migration.legacy_handler_name,
                None,
            )
            if not callable(handler):
                raise ValueError(
                    f"{feature_id} references missing handler "
                    f"{migration.legacy_handler_name!r}"
                )
        if all(
            migration.mode is LegacyMigrationMode.COMPOSITE_SECTION
            for migration in migrations
        ):
            bindings[feature_id] = tuple(migrations)
            continue
        if len(migrations) != 1:
            raise ValueError(
                f"{feature_id} has ambiguous atomic handler bindings"
            )
        bindings[feature_id] = _AtomicBinding(migrations[0])
    return bindings


class BoundHandlerAvailabilityProvider:
    """Expose bound production handlers while capability probes are pending."""

    def __init__(
        self,
        owner: ChildHandlerOwner,
        *,
        catalog: DorisDomainCatalog | None = None,
    ) -> None:
        self._catalog = catalog or domain_catalog_module.DORIS_DOMAIN_CATALOG
        self._bindings = _build_bindings(owner, self._catalog)

    async def availability_for(
        self,
        domain: DomainDefinition,
        child: ChildToolDefinition,
        auth_context: Any | None,
    ) -> Availability:
        del auth_context
        feature_id = f"{domain.name}.{child.name}"
        if feature_id not in self._bindings:
            return Availability(
                status=AvailabilityStatus.UNKNOWN,
                callable=False,
                reason_code="HANDLER_NOT_BOUND",
                evidence_sources=("catalog_contract", "handler_registry"),
            )
        return Availability(
            status=AvailabilityStatus.DEGRADED,
            callable=True,
            reason_code="BOUND_HANDLER_FALLBACK",
            active_variant=child.support_contract.variants[0].name,
            evidence_sources=("catalog_contract", "handler_registry"),
            limitations=(
                "Live Doris capability verification is pending.",
            ),
        )


def formal_flat_name(domain_name: str, child_name: str) -> str:
    """Return the collision-free formal flat name for one child."""
    return f"{domain_name}_{child_name}"


def _execution_output_schema(
    child_output_schema: Mapping[str, Any],
) -> dict[str, Any]:
    """Build the fixed execution envelope around one child result schema."""
    result_schema = {
        "type": "object",
        "properties": {
            "mode": {"type": "string", "const": "result"},
            "domain": {"type": "string"},
            "child_tool": {"type": "string"},
            "manifest_version": {"type": "string"},
            "data": dict(child_output_schema),
            "metadata": {
                "type": "object",
                "properties": {
                    "request_id": {"type": "string"},
                    "duration_ms": {"type": "number", "minimum": 0},
                    "source": {"type": "string"},
                    "truncated": {"type": "boolean"},
                },
                "required": [
                    "request_id",
                    "duration_ms",
                    "source",
                    "truncated",
                ],
                "additionalProperties": False,
            },
            "warnings": {
                "type": "array",
                "items": {"type": "string"},
            },
        },
        "required": [
            "mode",
            "domain",
            "child_tool",
            "manifest_version",
            "data",
            "metadata",
            "warnings",
        ],
        "additionalProperties": False,
    }
    return {
        "type": "object",
        "oneOf": [
            result_schema,
            deepcopy(DOMAIN_ERROR_OUTPUT_SCHEMA),
        ],
    }


class DomainDispatcher:
    """Dispatch exact domain children and formal flat names to one handler path."""

    def __init__(
        self,
        owner: ChildHandlerOwner,
        manifest_service: DomainManifestService,
        *,
        catalog: DorisDomainCatalog | None = None,
        schema_guard: ToolSchemaGuard | None = None,
    ) -> None:
        catalog = catalog or domain_catalog_module.DORIS_DOMAIN_CATALOG
        catalog.validate_integrity()
        self._owner = owner
        self._manifest_service = manifest_service
        self._catalog = catalog
        self._schema_guard = schema_guard or ToolSchemaGuard()
        self._flat_children: dict[str, tuple[str, ChildToolDefinition]] = {}
        self._schemas: dict[str, CompiledToolSchema] = {}
        self._bindings = _build_bindings(owner, catalog)

        for domain in self._catalog.domains:
            for child in domain.children:
                feature_id = f"{domain.name}.{child.name}"
                flat_name = formal_flat_name(domain.name, child.name)
                if flat_name in self._flat_children:
                    raise ValueError(f"duplicate formal flat tool: {flat_name}")
                self._flat_children[flat_name] = (domain.name, child)
                self._schemas[feature_id] = self._schema_guard.compile_tool(
                    Tool(
                        name=flat_name,
                        description=child.canonical_description,
                        input_schema=cast(
                            dict[str, Any],
                            child.to_wire()["input_schema"],
                        ),
                        output_schema=cast(
                            dict[str, Any],
                            child.to_wire()["output_schema"],
                        ),
                    )
                )

    @property
    def formal_flat_names(self) -> tuple[str, ...]:
        """Return all 47 formal flat names in catalog order."""
        return tuple(self._flat_children)

    def handles_flat(self, name: str) -> bool:
        """Return whether a name is an exact formal flat child name."""
        return name in self._flat_children

    async def list_flat_tools(self, auth_context: Any | None) -> list[Tool]:
        """Render authorized formal children as top-level flat MCP tools."""
        tools: list[Tool] = []
        for domain in self._catalog.domains:
            manifest = await self._manifest_service.discover(
                domain,
                auth_context,
            )
            children_by_name = {
                child.name: child for child in manifest.children
            }
            for child in domain.children:
                manifest_child = children_by_name.get(child.name)
                if manifest_child is None:
                    continue
                annotations = child.annotations
                tools.append(
                    Tool(
                        name=formal_flat_name(domain.name, child.name),
                        title=f"{domain.title}: {child.title}",
                        description=manifest_child.description,
                        input_schema=cast(
                            dict[str, Any],
                            child.to_wire()["input_schema"],
                        ),
                        output_schema=_execution_output_schema(
                            cast(
                                dict[str, Any],
                                child.to_wire()["output_schema"],
                            )
                        ),
                        annotations=ToolAnnotations(
                            title=child.title,
                            read_only_hint=annotations.read_only,
                            destructive_hint=annotations.destructive,
                            idempotent_hint=annotations.idempotent,
                            open_world_hint=annotations.open_world,
                        ),
                    )
                )
        return tools

    async def call_domain(
        self,
        domain_name: str,
        arguments: Mapping[str, Any],
        auth_context: Any | None,
    ) -> ExecutionEnvelope | ErrorEnvelope | Any:
        """Discover a domain or execute one exact child request."""
        domain = self._catalog.resolve_domain(domain_name)
        try:
            request = DomainToolRequest.model_validate(dict(arguments))
        except ValidationError:
            return self._error(
                domain.name,
                DomainErrorCode.CHILD_ARGUMENTS_INVALID,
                "Domain tool arguments are invalid.",
                details={"rediscover": True},
            )

        if request.is_discovery:
            return await self._manifest_service.discover(domain, auth_context)

        child_name = cast(str, request.child_tool)
        return await self._execute(
            domain.name,
            child_name,
            request.execution_arguments,
            auth_context,
            requested_manifest_version=request.manifest_version,
        )

    async def call_flat(
        self,
        name: str,
        arguments: Mapping[str, Any],
        auth_context: Any | None,
    ) -> ExecutionEnvelope | ErrorEnvelope:
        """Execute one exact formal flat name through the child dispatcher."""
        try:
            domain_name, child = self._flat_children[name]
        except KeyError as exc:
            raise ToolNotFoundError(name) from exc
        return await self._execute(
            domain_name,
            child.name,
            dict(arguments),
            auth_context,
            requested_manifest_version=None,
        )

    async def _execute(
        self,
        domain_name: str,
        child_name: str,
        arguments: dict[str, Any],
        auth_context: Any | None,
        *,
        requested_manifest_version: str | None,
    ) -> ExecutionEnvelope | ErrorEnvelope:
        try:
            domain = self._catalog.resolve_domain(domain_name)
            child = self._catalog.resolve_child(domain_name, child_name)
        except ValueError:
            return self._error(
                domain_name,
                DomainErrorCode.CHILD_TOOL_NOT_FOUND,
                "Child tool was not found.",
                child_tool=child_name,
                details={"rediscover": True},
            )

        if not authorized_child_discovery(auth_context, domain, child):
            return self._error(
                domain.name,
                DomainErrorCode.CHILD_TOOL_NOT_FOUND,
                "Child tool was not found.",
                child_tool=child.name,
                details={"rediscover": True},
            )
        if not authorized_child_execution(auth_context, domain, child):
            return self._error(
                domain.name,
                DomainErrorCode.CHILD_TOOL_NOT_FOUND,
                "Child tool was not found.",
                child_tool=child.name,
                details={"rediscover": True},
            )

        manifest = await self._manifest_service.discover(domain, auth_context)
        manifest_child = next(
            (
                candidate
                for candidate in manifest.children
                if candidate.name == child.name
            ),
            None,
        )
        if manifest_child is None:
            return self._error(
                domain.name,
                DomainErrorCode.CHILD_TOOL_NOT_FOUND,
                "Child tool was not found.",
                child_tool=child.name,
                details={"rediscover": True},
            )
        if (
            requested_manifest_version is not None
            and requested_manifest_version != manifest.manifest_version
        ):
            return self._error(
                domain.name,
                DomainErrorCode.CHILD_MANIFEST_STALE,
                "The domain manifest has changed. Discover this domain again.",
                child_tool=child.name,
                manifest_version=manifest.manifest_version,
                details={"rediscover": True},
            )
        if not manifest_child.availability.callable:
            return self._error(
                domain.name,
                DomainErrorCode.CHILD_CAPABILITY_UNAVAILABLE,
                "Child capability is not callable in the current runtime.",
                child_tool=child.name,
                manifest_version=manifest.manifest_version,
                details={
                    "rediscover": True,
                    "reason_code": manifest_child.availability.reason_code,
                },
            )

        feature_id = f"{domain.name}.{child.name}"
        binding = self._bindings.get(feature_id)
        if binding is None:
            return self._error(
                domain.name,
                DomainErrorCode.CHILD_CAPABILITY_UNAVAILABLE,
                "Child capability has no bound runtime handler.",
                child_tool=child.name,
                manifest_version=manifest.manifest_version,
                details={
                    "rediscover": False,
                    "reason_code": "HANDLER_NOT_BOUND",
                },
            )

        compiled = self._schemas[feature_id]
        try:
            compiled.validate_arguments(arguments)
        except ToolArgumentsValidationError as exc:
            details: dict[str, Any] = {
                "violations": [
                    violation.as_dict() for violation in exc.violations
                ],
                "rediscover": False,
            }
            if exc.truncated:
                details["truncated"] = True
            return self._error(
                domain.name,
                DomainErrorCode.CHILD_ARGUMENTS_INVALID,
                "Child arguments do not match the declared schema.",
                child_tool=child.name,
                manifest_version=manifest.manifest_version,
                details=details,
            )

        started = time.perf_counter()
        try:
            if isinstance(binding, _AtomicBinding):
                raw, adapter_warnings = await self._call_atomic(
                    binding.migration,
                    arguments,
                )
                data = self._normalize_child_result(
                    child,
                    raw,
                    arguments,
                    adapter_warnings,
                )
            else:
                data = await self._call_table_context(
                    child,
                    binding,
                    arguments,
                )
            compiled.validate_output(data)
        except (ToolArgumentsValidationError, ChildArgumentsAdapterError) as exc:
            violations = (
                [
                    violation.as_dict() for violation in exc.violations
                ]
                if isinstance(exc, ToolArgumentsValidationError)
                else [{"instancePath": "/", "keyword": "activeHandler"}]
            )
            return self._error(
                domain.name,
                DomainErrorCode.CHILD_ARGUMENTS_INVALID,
                "Child arguments cannot be represented by the active handler.",
                child_tool=child.name,
                manifest_version=manifest.manifest_version,
                details={
                    "rediscover": False,
                    "violations": violations,
                },
            )
        except ToolOutputValidationError:
            logger.exception("Formal child output validation failed for %s", feature_id)
            self._audit(
                feature_id,
                arguments,
                "result_invalid",
                started,
            )
            return self._error(
                domain.name,
                DomainErrorCode.CHILD_RESULT_INVALID,
                "Child result did not match the declared schema.",
                child_tool=child.name,
                manifest_version=manifest.manifest_version,
                details={"rediscover": False},
            )
        except Exception as exc:
            logger.error(
                "Formal child execution failed for %s (%s)",
                feature_id,
                type(exc).__name__,
            )
            self._audit(feature_id, arguments, "error", started)
            return self._error(
                domain.name,
                DomainErrorCode.CHILD_EXECUTION_FAILED,
                "Child execution failed.",
                child_tool=child.name,
                manifest_version=manifest.manifest_version,
                details={"rediscover": False},
                retryable=False,
            )

        duration_ms = (time.perf_counter() - started) * 1000
        self._audit(feature_id, arguments, "success", started)
        truncated = bool(
            isinstance(data, dict)
            and isinstance(data.get("data"), dict)
            and data["data"].get("truncated")
        )
        warnings = tuple(
            str(item)
            for item in (
                data.get("warnings", [])
                if isinstance(data, dict)
                else []
            )
        )
        return ExecutionEnvelope(
            mode="result",
            domain=domain.name,
            child_tool=child.name,
            manifest_version=manifest.manifest_version,
            data=data,
            metadata=ExecutionMetadata(
                request_id=f"req_{secrets.token_hex(8)}",
                duration_ms=round(duration_ms, 3),
                source="doris",
                truncated=truncated,
            ),
            warnings=warnings,
        )

    async def _call_atomic(
        self,
        migration: LegacyToolMigration,
        arguments: dict[str, Any],
    ) -> tuple[dict[str, Any], tuple[str, ...]]:
        prepared, warnings = _adapt_arguments(
            migration.adapter_name,
            arguments,
        )
        handler = getattr(self._owner, migration.legacy_handler_name)
        raw = await handler(prepared)
        if not isinstance(raw, dict):
            raise TypeError("child handler must return an object")
        if raw.get("success") is False or (
            "error" in raw and raw.get("success") is not True
        ):
            raise RuntimeError("child handler reported failure")
        return raw, warnings

    async def _call_table_context(
        self,
        child: ChildToolDefinition,
        migrations: tuple[LegacyToolMigration, ...],
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        if child.name != "get_table_context":
            raise RuntimeError("unsupported composite migration")
        requested_sections = set(
            cast(
                list[str],
                arguments.get(
                    "sections",
                    ["schema", "comments", "indexes", "basic"],
                ),
            )
        )
        effective_sections = requested_sections | {"schema"}
        legacy_arguments = {
            "catalog_name": arguments.get("catalog"),
            "db_name": arguments.get("database"),
            "table_name": arguments.get("table"),
        }
        legacy_arguments = {
            key: value
            for key, value in legacy_arguments.items()
            if value is not None
        }

        data: dict[str, Any] = {}
        evidence: list[dict[str, Any]] = []
        warnings: list[str] = []
        comments: dict[str, Any] = {}
        for migration in migrations:
            section = cast(str, migration.target_section)
            if section not in effective_sections:
                continue
            handler = getattr(self._owner, migration.legacy_handler_name)
            raw = await handler(dict(legacy_arguments))
            success = isinstance(raw, dict) and not (
                raw.get("success") is False
                or ("error" in raw and raw.get("success") is not True)
            )
            evidence.append(
                {
                    "section": section,
                    "handler": migration.legacy_handler_name,
                    "success": success,
                }
            )
            if not success:
                if section == "schema":
                    raise RuntimeError("required schema section failed")
                warnings.append(f"Optional {section} section is unavailable.")
                continue
            value = _unwrap_legacy_result(raw)
            if section == "comments":
                comment_key = (
                    "columns"
                    if migration.legacy_tool_name
                    == "get_table_column_comments"
                    else "table"
                )
                comments[comment_key] = _as_object(value)
            else:
                data[section] = _as_object(value)
        if comments:
            data["comments"] = comments
        if "schema" not in data:
            raise RuntimeError("required schema section was not executed")
        return {
            "status": "partial" if warnings else "success",
            "data": data,
            "warnings": warnings,
            "metadata": {"sections": sorted(effective_sections)},
            "evidence": evidence,
        }

    def _normalize_child_result(
        self,
        child: ChildToolDefinition,
        raw: dict[str, Any],
        arguments: dict[str, Any],
        adapter_warnings: tuple[str, ...],
    ) -> dict[str, Any]:
        output = cast(
            dict[str, Any],
            child.to_wire()["output_schema"],
        )
        data_schema = cast(
            dict[str, Any],
            cast(dict[str, Any], output["properties"])["data"],
        )
        data_properties = cast(
            dict[str, Any],
            data_schema.get("properties", {}),
        )
        warnings = list(adapter_warnings)
        metadata = _legacy_metadata(raw)

        if {"items", "next_cursor", "truncated"} <= set(data_properties):
            values = _unwrap_legacy_result(raw)
            raw_items = values if isinstance(values, list) else []
            items = [
                item if isinstance(item, dict) else {"name": item}
                for item in raw_items
            ]
            pattern = arguments.get("pattern")
            if isinstance(pattern, str):
                items = [
                    item
                    for item in items
                    if fnmatch.fnmatchcase(str(item.get("name", "")), pattern)
                ]
            if arguments.get("page") is not None:
                warnings.append(
                    "Pagination is not supported by the active handler."
                )
            if arguments.get("types") is not None:
                warnings.append(
                    "Object type filtering is not supported by the active handler."
                )
            child_data: dict[str, Any] = {
                "items": items,
                "next_cursor": None,
                "truncated": False,
            }
        elif {"columns", "rows", "row_count", "truncated"} <= set(
            data_properties
        ):
            rows = raw.get("data")
            if not isinstance(rows, list):
                rows = []
            columns = raw.get("columns")
            if not isinstance(columns, list):
                metadata_columns = metadata.get("columns", [])
                columns = (
                    metadata_columns
                    if isinstance(metadata_columns, list)
                    else []
                )
            if not columns and rows and isinstance(rows[0], dict):
                columns = list(rows[0])
            child_data = {
                "columns": [
                    column
                    if isinstance(column, dict)
                    else {"name": str(column)}
                    for column in columns
                ],
                "rows": [
                    row if isinstance(row, dict) else {"value": row}
                    for row in rows
                ],
                "row_count": int(raw.get("row_count", len(rows))),
                "truncated": bool(
                    raw.get("truncated")
                    or metadata.get("truncated")
                    or raw.get("bytes_truncated")
                ),
            }
        else:
            child_data = _as_object(_unwrap_legacy_result(raw))

        result: dict[str, Any] = {
            "status": "partial" if warnings else "success",
            "data": child_data,
            "warnings": warnings,
            "metadata": metadata,
        }
        if "evidence" in cast(dict[str, Any], output["properties"]):
            result["evidence"] = [
                {
                    "source": "existing_read_only_handler",
                    "handler": child.handler_name,
                }
            ]
        return result

    @staticmethod
    def _audit(
        feature_id: str,
        arguments: Mapping[str, Any],
        status: str,
        started: float,
    ) -> None:
        get_audit_logger().info(
            "event=mcp.tool.call.%s tool=%s category=child risk=metadata "
            "status=%s duration_ms=%d argument_names=%s",
            feature_id,
            feature_id,
            status,
            round((time.perf_counter() - started) * 1000),
            ",".join(sorted(arguments)),
        )

    @staticmethod
    def _error(
        domain_name: str,
        code: DomainErrorCode,
        message: str,
        *,
        child_tool: str | None = None,
        manifest_version: str | None = None,
        retryable: bool = False,
        details: dict[str, Any] | None = None,
    ) -> ErrorEnvelope:
        return ErrorEnvelope(
            mode="error",
            domain=domain_name,
            child_tool=child_tool,
            manifest_version=manifest_version,
            error=StandardError(
                code=code,
                message=message,
                retryable=retryable,
                details=details or {},
            ),
        )


def _adapt_arguments(
    adapter_name: str | None,
    arguments: Mapping[str, Any],
) -> tuple[dict[str, Any], tuple[str, ...]]:
    args = dict(arguments)
    warnings: list[str] = []
    if adapter_name is None:
        return args, ()

    common_names = {
        "catalog": "catalog_name",
        "database": "db_name",
        "table": "table_name",
    }
    prepared = {
        common_names.get(key, key): value
        for key, value in args.items()
        if value is not None
    }

    if adapter_name == "adapt:query_arguments":
        if prepared.pop("parameters", None):
            raise ChildArgumentsAdapterError(
                "bound query parameters are not yet supported"
            )
        timeout_ms = prepared.pop("timeout_ms", None)
        if timeout_ms is not None:
            prepared["timeout"] = max(1, math.ceil(timeout_ms / 1000))
    elif adapter_name == "adapt:catalog_object_names":
        for unsupported in ("pattern", "types", "page"):
            prepared.pop(unsupported, None)
    elif adapter_name == "adapt:remove_random_string":
        prepared = {}
    elif adapter_name == "adapt:explain_arguments":
        level = prepared.pop("level", None)
        if level == "costs":
            raise ChildArgumentsAdapterError(
                "cost explain is not supported by the active handler"
            )
        if level is not None:
            prepared["verbose"] = level == "verbose"
    elif adapter_name == "adapt:profile_arguments":
        query_id = prepared.pop("query_id", None)
        prepared.pop("recent_window_minutes", None)
        prepared.pop("include_operator_tree", None)
        if query_id is not None and "sql" not in prepared:
            raise ChildArgumentsAdapterError(
                "query-id profile lookup is not yet supported"
            )
    elif adapter_name == "adapt:table_size_arguments":
        prepared["single_replica"] = False
        if prepared.pop("include_partitions", False):
            warnings.append(
                "Partition detail is not supported by the active handler."
            )
    elif adapter_name == "adapt:monitoring_arguments":
        if prepared:
            warnings.append(
                "Metric and node filters are not supported by the active handler."
            )
        prepared = {}
    elif adapter_name == "adapt:memory_arguments":
        detail = prepared.pop("detail", None)
        if prepared.pop("node_ids", None) is not None:
            warnings.append(
                "Memory node filtering is not supported by the active handler."
            )
        prepared["data_type"] = "realtime"
        prepared["tracker_type"] = {
            None: "overview",
            "summary": "overview",
            "trackers": "all",
            "top_consumers": "all",
        }.get(detail, "overview")
    elif adapter_name == "adapt:audit_filters":
        window_minutes = prepared.pop("window_minutes", None)
        if window_minutes is not None:
            prepared["days"] = max(1, math.ceil(window_minutes / 1440))
        for unsupported in ("user", "operation", "db_name", "table_name"):
            if prepared.pop(unsupported, None) is not None:
                warnings.append(
                    "One or more audit filters are not supported by the active "
                    "handler."
                )
    elif adapter_name == "adapt:column_analysis_arguments":
        prepared["columns"] = prepared.get("columns") or ["*"]
        sample_ratio = prepared.pop("sample_ratio", None)
        if sample_ratio is not None:
            prepared["sample_size"] = max(1, int(sample_ratio * 100_000))
    elif adapter_name == "adapt:storage_analysis_arguments":
        prepared["detailed_response"] = bool(
            prepared.pop("include_partitions", False)
            or prepared.pop("include_indexes", False)
        )
    elif adapter_name == "adapt:lineage_arguments":
        object_name = cast(str, prepared.pop("object"))
        column = prepared.pop("column", None)
        prepared["target_columns"] = [
            f"{object_name}.{column}" if column else object_name
        ]
        prepared["analysis_depth"] = prepared.pop("depth", 3)
        prepared.pop("direction", None)
        prepared.pop("evidence_mode", None)
    elif adapter_name == "adapt:freshness_arguments":
        table_name = cast(str, prepared.pop("table_name"))
        prepared["table_names"] = [table_name]
        threshold = prepared.pop("threshold_seconds", None)
        if threshold is not None:
            prepared["freshness_threshold_hours"] = max(
                1,
                math.ceil(threshold / 3600),
            )
        if prepared.pop("time_column", None) is not None:
            warnings.append(
                "Event-time column selection is not supported by the active "
                "handler."
            )
    elif adapter_name == "adapt:access_analysis_arguments":
        prepared["days"] = prepared.pop("window_days", 7)
        for unsupported in ("db_name", "table_name", "group_by"):
            if prepared.pop(unsupported, None) is not None:
                warnings.append(
                    "One or more access-analysis filters are not supported by "
                    "the active handler."
                )
    elif adapter_name == "adapt:dependency_arguments":
        prepared["target_table"] = prepared.pop("object")
        prepared["analysis_depth"] = prepared.pop("depth", 3)
        prepared.pop("direction", None)
    elif adapter_name == "adapt:slow_query_arguments":
        window = prepared.pop("window_minutes", None)
        if window is not None:
            prepared["days"] = max(1, math.ceil(window / 1440))
        prepared["top_n"] = prepared.pop("limit", 20)
        prepared["min_execution_time_ms"] = prepared.pop(
            "min_duration_ms",
            1000,
        )
        for unsupported in ("db_name", "user"):
            if prepared.pop(unsupported, None) is not None:
                warnings.append(
                    "One or more slow-query filters are not supported by the "
                    "active handler."
                )
    elif adapter_name == "adapt:resource_growth_arguments":
        resource = prepared.pop("resource", None)
        prepared["days"] = prepared.pop("window_days", 30)
        prepared["resource_types"] = [resource] if resource else []
        if prepared.pop("granularity", None) is not None:
            warnings.append(
                "Growth granularity is not supported by the active handler."
            )
    elif adapter_name == "adapt:adbc_query_arguments":
        timeout_ms = prepared.pop("timeout_ms", None)
        if timeout_ms is not None:
            prepared["timeout"] = max(1, math.ceil(timeout_ms / 1000))
        result_format = prepared.pop("result_format", None)
        if result_format is not None:
            prepared["return_format"] = result_format
    else:
        raise ChildArgumentsAdapterError(
            f"unknown formal argument adapter: {adapter_name}"
        )
    return prepared, tuple(dict.fromkeys(warnings))


def _unwrap_legacy_result(raw: Mapping[str, Any]) -> Any:
    if raw.get("success") is True and "result" in raw:
        return raw["result"]
    return {
        key: value
        for key, value in raw.items()
        if key not in {"success", "_execution_info"}
    }


def _legacy_metadata(raw: Mapping[str, Any]) -> dict[str, Any]:
    metadata = raw.get("metadata")
    if isinstance(metadata, dict):
        return dict(metadata)
    return {}


def _as_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, list):
        return {"items": value}
    return {"value": value}


def serialize_dispatch_result(result: Any) -> str:
    """Serialize a validated dispatcher model or JSON-compatible value."""
    if hasattr(result, "to_canonical_json"):
        return cast(str, result.to_canonical_json())
    return json.dumps(result, ensure_ascii=False, separators=(",", ":"))


__all__ = [
    "BoundHandlerAvailabilityProvider",
    "DomainDispatcher",
    "ChildArgumentsAdapterError",
    "ToolExposureMode",
    "ToolNotFoundError",
    "formal_flat_name",
    "serialize_dispatch_result",
]
