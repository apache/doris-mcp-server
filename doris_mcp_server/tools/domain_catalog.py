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

"""Authoritative hierarchical domain catalog for the Doris MCP 1.0 surface."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, Self

from pydantic import Field, model_validator

from .domain_models import (
    ChildToolDefinition,
    CompositePlan,
    CompositeStep,
    ContractModel,
    DomainDefinition,
    Identifier,
    NonEmptyText,
    ToolContractAnnotations,
)
from .doris_feature_matrix import (
    DORIS_FEATURE_MATRIX,
    EXPECTED_DOMAIN_CHILDREN,
)
from .tool_registry import (
    ToolDefinitionRegistry,
    ToolHandlerOwner,
    ToolRegistryError,
)

CURRENT_FLAT_TOOL_NAMES = (
    "exec_query",
    "get_table_schema",
    "get_db_table_list",
    "get_db_list",
    "get_table_comment",
    "get_table_column_comments",
    "get_table_indexes",
    "get_recent_audit_logs",
    "get_catalog_list",
    "get_sql_explain",
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
)

_READ_ONLY_ANNOTATIONS = ToolContractAnnotations(
    read_only=True,
    idempotent=True,
    destructive=False,
    open_world=False,
    requires_confirmation=False,
)


class DomainCatalogError(ValueError):
    """Raised when the hierarchical catalog or migration map is invalid."""


class LegacyMigrationMode(StrEnum):
    """How one pre-1.0 flat tool contributes to a formal child capability."""

    ATOMIC = "atomic"
    ADAPTED = "adapted"
    COMPOSITE_SECTION = "composite_section"


class LegacyToolMigration(ContractModel):
    """Auditable migration from one current flat tool to one formal child."""

    legacy_tool_name: Identifier
    legacy_handler_name: NonEmptyText
    domain: Identifier
    child_name: Identifier
    mode: LegacyMigrationMode
    adapter_name: NonEmptyText | None = None
    target_section: Identifier | None = None

    @property
    def feature_id(self) -> str:
        return f"{self.domain}.{self.child_name}"

    @model_validator(mode="after")
    def _validate_mode(self) -> Self:
        if self.mode is LegacyMigrationMode.COMPOSITE_SECTION:
            if self.target_section is None:
                raise ValueError(
                    "composite-section migrations require target_section"
                )
        elif self.target_section is not None:
            raise ValueError(
                "target_section is only valid for composite-section migrations"
            )
        if self.mode is LegacyMigrationMode.ADAPTED and self.adapter_name is None:
            raise ValueError("adapted migrations require adapter_name")
        if self.mode is not LegacyMigrationMode.ADAPTED and self.adapter_name is not None:
            raise ValueError("adapter_name is only valid for adapted migrations")
        return self


class DomainCatalogDomainSummary(ContractModel):
    """Stable summary for one top-level domain."""

    name: Identifier
    child_count: Annotated[int, Field(ge=1)]
    child_names: tuple[Identifier, ...]


class DomainCatalogSummary(ContractModel):
    """Machine-readable summary used by startup and acceptance checks."""

    domain_count: Annotated[int, Field(ge=1)]
    child_count: Annotated[int, Field(ge=1)]
    migrated_flat_tool_count: Annotated[int, Field(ge=0)]
    domains: tuple[DomainCatalogDomainSummary, ...]


class DorisDomainCatalog(ContractModel):
    """Single validated catalog for domains, children, and legacy migration."""

    domains: Annotated[tuple[DomainDefinition, ...], Field(min_length=1)]
    legacy_migrations: tuple[LegacyToolMigration, ...]

    @model_validator(mode="after")
    def _validate_model(self) -> Self:
        self.validate_integrity()
        return self

    def validate_integrity(self) -> None:
        """Reject catalog drift before any MCP tool can be exposed."""
        for domain in self.domains:
            if len(domain.children) > 12:
                raise DomainCatalogError(
                    f"domain {domain.name!r} exceeds the 12-child limit"
                )

        expected = {
            domain: tuple(children)
            for domain, children in EXPECTED_DOMAIN_CHILDREN.items()
        }
        actual = {
            domain.name: tuple(child.name for child in domain.children)
            for domain in self.domains
        }
        if actual != expected:
            raise DomainCatalogError(
                "domain catalog must contain the exact ordered "
                "8-domain/47-child contract"
            )

        domain_names = tuple(domain.name for domain in self.domains)
        _require_unique(domain_names, "domain names")
        child_feature_ids = tuple(
            f"{domain.name}.{child.name}"
            for domain in self.domains
            for child in domain.children
        )
        _require_unique(child_feature_ids, "formal child feature IDs")
        handler_names = tuple(
            child.handler_name
            for domain in self.domains
            for child in domain.children
        )
        _require_unique(handler_names, "formal child handler bindings")

        expected_contracts = {
            feature.feature_id: feature.support_contract
            for feature in DORIS_FEATURE_MATRIX.features
        }
        for domain in self.domains:
            if not domain.annotations.read_only:
                raise DomainCatalogError(
                    f"read-only domain {domain.name!r} is not marked read-only"
                )
            for child in domain.children:
                feature_id = f"{domain.name}.{child.name}"
                if child.support_contract != expected_contracts[feature_id]:
                    raise DomainCatalogError(
                        f"{feature_id} does not use the feature-matrix contract"
                    )
                if (
                    not child.annotations.read_only
                    or child.annotations.destructive
                    or child.annotations.requires_confirmation
                ):
                    raise DomainCatalogError(
                        f"{feature_id} violates the read-only risk contract"
                    )
                expected_handler = f"child:{domain.name}:{child.name}"
                if child.handler_name != expected_handler:
                    raise DomainCatalogError(
                        f"{feature_id} has non-canonical handler binding"
                    )
                expected_policy = f"child:call:{domain.name}:{child.name}"
                if child.authorization_policy != expected_policy:
                    raise DomainCatalogError(
                        f"{feature_id} has non-canonical authorization policy"
                    )

        migration_names = tuple(
            migration.legacy_tool_name for migration in self.legacy_migrations
        )
        if migration_names != CURRENT_FLAT_TOOL_NAMES:
            raise DomainCatalogError(
                "legacy migration map must cover the exact ordered 25-tool baseline"
            )
        _require_unique(migration_names, "legacy migration tool names")

        known_features = set(child_feature_ids)
        for migration in self.legacy_migrations:
            if migration.feature_id not in known_features:
                raise DomainCatalogError(
                    f"legacy tool {migration.legacy_tool_name!r} targets unknown "
                    f"child {migration.feature_id!r}"
                )
            target = self.resolve_child(
                migration.domain,
                migration.child_name,
            )
            if (
                migration.mode is LegacyMigrationMode.COMPOSITE_SECTION
                and target.composite_plan is None
            ):
                raise DomainCatalogError(
                    f"legacy tool {migration.legacy_tool_name!r} targets a "
                    "non-composite child"
                )

        table_context_migrations = tuple(
            migration
            for migration in self.legacy_migrations
            if migration.feature_id == "doris_catalog.get_table_context"
        )
        expected_sections = (
            "schema",
            "comments",
            "comments",
            "indexes",
            "basic",
        )
        if tuple(
            migration.target_section for migration in table_context_migrations
        ) != expected_sections:
            raise DomainCatalogError(
                "get_table_context must merge the exact five legacy handlers "
                "into schema, comments, indexes, and basic sections"
            )

    def validate_legacy_registry(
        self,
        registry: ToolDefinitionRegistry,
        owner: ToolHandlerOwner,
    ) -> None:
        """Prove that every migrated flat capability still has a real handler."""
        core_definitions = tuple(
            definition
            for definition in registry.advertised_definitions
            if definition.provider_name is None
        )
        actual_names = tuple(definition.name for definition in core_definitions)
        if actual_names != CURRENT_FLAT_TOOL_NAMES:
            raise DomainCatalogError(
                "runtime flat registry does not match the 25-tool migration baseline"
            )

        for migration in self.legacy_migrations:
            definition = registry.resolve(migration.legacy_tool_name)
            if definition.handler_name != migration.legacy_handler_name:
                raise DomainCatalogError(
                    f"legacy tool {migration.legacy_tool_name!r} changed handler "
                    f"from {migration.legacy_handler_name!r} to "
                    f"{definition.handler_name!r}"
                )
            try:
                definition.bind_handler(owner)
            except ToolRegistryError as exc:
                raise DomainCatalogError(
                    f"legacy tool {migration.legacy_tool_name!r} has a dangling "
                    f"handler {migration.legacy_handler_name!r}"
                ) from exc

    def resolve_domain(self, name: str) -> DomainDefinition:
        """Resolve one exact top-level domain name."""
        for domain in self.domains:
            if domain.name == name:
                return domain
        raise DomainCatalogError(f"unknown domain: {name}")

    def resolve_child(self, domain_name: str, child_name: str) -> ChildToolDefinition:
        """Resolve one exact domain and child pair without fuzzy matching."""
        domain = self.resolve_domain(domain_name)
        for child in domain.children:
            if child.name == child_name:
                return child
        raise DomainCatalogError(
            f"unknown child {child_name!r} in domain {domain_name!r}"
        )

    def summary(self) -> DomainCatalogSummary:
        """Return a deterministic catalog summary."""
        domains = tuple(
            DomainCatalogDomainSummary(
                name=domain.name,
                child_count=len(domain.children),
                child_names=tuple(child.name for child in domain.children),
            )
            for domain in self.domains
        )
        return DomainCatalogSummary(
            domain_count=len(domains),
            child_count=sum(domain.child_count for domain in domains),
            migrated_flat_tool_count=len(self.legacy_migrations),
            domains=domains,
        )

    def render_markdown(self) -> str:
        """Generate deterministic internal documentation from this catalog."""
        lines = [
            "# Doris MCP Hierarchical Domain Catalog",
            "",
            "<!-- Generated from DorisDomainCatalog; do not edit by hand. -->",
            "",
            "| Domain | Child count | Enablement | Discovery |",
            "|---|---:|---|---|",
        ]
        for domain in self.domains:
            lines.append(
                f"| `{domain.name}` | {len(domain.children)} | "
                f"`{domain.enablement_policy}` | `{domain.discovery_policy}` |"
            )
        lines.extend(
            [
                "",
                "## Formal child tools",
                "",
                "| Feature ID | Handler binding | Authorization | Variants |",
                "|---|---|---|---|",
            ]
        )
        for domain in self.domains:
            for child in domain.children:
                variants = ", ".join(
                    f"`{variant.name}`"
                    for variant in child.support_contract.variants
                )
                lines.append(
                    f"| `{domain.name}.{child.name}` | `{child.handler_name}` | "
                    f"`{child.authorization_policy}` | {variants} |"
                )
        lines.extend(
            [
                "",
                "## Pre-1.0 migration coverage",
                "",
                "| Flat tool | Handler | Formal feature | Mode | Section |",
                "|---|---|---|---|---|",
            ]
        )
        for migration in self.legacy_migrations:
            lines.append(
                f"| `{migration.legacy_tool_name}` | "
                f"`{migration.legacy_handler_name}` | "
                f"`{migration.feature_id}` | `{migration.mode.value}` | "
                f"{f'`{migration.target_section}`' if migration.target_section else '-'} "
                "|"
            )
        lines.extend(
            [
                "",
                "This document describes internal 1.0 routing contracts. The "
                "pre-1.0 flat names are migration inputs, not registered 1.0 "
                "tool aliases.",
                "",
            ]
        )
        return "\n".join(lines)


def _require_unique(values: tuple[str, ...], label: str) -> None:
    if len(values) != len(set(values)):
        raise DomainCatalogError(f"{label} must be unique")


def _string(
    description: str,
    *,
    enum: tuple[str, ...] | None = None,
    pattern: str | None = None,
) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "string", "description": description}
    if enum is not None:
        schema["enum"] = list(enum)
    if pattern is not None:
        schema["pattern"] = pattern
    return schema


def _integer(
    description: str,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "integer",
        "description": description,
        "minimum": minimum,
    }
    if maximum is not None:
        schema["maximum"] = maximum
    return schema


def _number(
    description: str,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "number", "description": description}
    if minimum is not None:
        schema["minimum"] = minimum
    if maximum is not None:
        schema["maximum"] = maximum
    return schema


def _boolean(description: str) -> dict[str, Any]:
    return {"type": "boolean", "description": description}


def _string_array(
    description: str,
    *,
    enum: tuple[str, ...] | None = None,
    min_items: int = 1,
) -> dict[str, Any]:
    item_schema: dict[str, Any] = {"type": "string"}
    if enum is not None:
        item_schema["enum"] = list(enum)
    return {
        "type": "array",
        "description": description,
        "items": item_schema,
        "minItems": min_items,
        "uniqueItems": True,
    }


def _object(description: str) -> dict[str, Any]:
    return {
        "type": "object",
        "description": description,
        "additionalProperties": True,
    }


def _array(description: str) -> dict[str, Any]:
    return {
        "type": "array",
        "description": description,
        "items": {},
    }


def _input_schema(
    properties: dict[str, Any],
    *,
    required: tuple[str, ...] = (),
    any_of: tuple[dict[str, Any], ...] = (),
) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
    if required:
        schema["required"] = list(required)
    if any_of:
        schema["anyOf"] = list(any_of)
    return schema


def _result_schema(
    data_schema: dict[str, Any],
    *,
    evidence: bool = False,
) -> dict[str, Any]:
    properties: dict[str, Any] = {
        "status": {
            "type": "string",
            "enum": ["success", "partial"],
        },
        "data": data_schema,
        "warnings": {
            "type": "array",
            "items": {"type": "string"},
        },
        "metadata": {
            "type": "object",
            "additionalProperties": True,
        },
    }
    required = ["status", "data", "warnings", "metadata"]
    if evidence:
        properties["evidence"] = {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": True,
            },
        }
        required.append("evidence")
    return {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


_DETAIL_OUTPUT = _result_schema(
    {"type": "object", "additionalProperties": True}
)
_DIAGNOSTIC_OUTPUT = _result_schema(
    {"type": "object", "additionalProperties": True},
    evidence=True,
)
_COLLECTION_OUTPUT = _result_schema(
    {
        "type": "object",
        "properties": {
            "items": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": True,
                },
            },
            "next_cursor": {"type": ["string", "null"]},
            "truncated": {"type": "boolean"},
        },
        "required": ["items", "next_cursor", "truncated"],
        "additionalProperties": False,
    }
)
_QUERY_OUTPUT = _result_schema(
    {
        "type": "object",
        "properties": {
            "columns": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": True,
                },
            },
            "rows": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": True,
                },
            },
            "row_count": {"type": "integer", "minimum": 0},
            "truncated": {"type": "boolean"},
        },
        "required": ["columns", "rows", "row_count", "truncated"],
        "additionalProperties": False,
    }
)
_TABLE_CONTEXT_OUTPUT = _result_schema(
    {
        "type": "object",
        "properties": {
            "schema": {"type": "object", "additionalProperties": True},
            "comments": {"type": "object", "additionalProperties": True},
            "indexes": {"type": "object", "additionalProperties": True},
            "basic": {"type": "object", "additionalProperties": True},
        },
        "required": ["schema"],
        "additionalProperties": False,
    },
    evidence=True,
)


def _child(
    domain: str,
    name: str,
    title: str,
    description: str,
    input_schema: dict[str, Any],
    output_schema: dict[str, Any] = _DETAIL_OUTPUT,
    *,
    composite_plan: CompositePlan | None = None,
) -> ChildToolDefinition:
    feature = DORIS_FEATURE_MATRIX.get_feature(domain, name)
    return ChildToolDefinition(
        name=name,
        title=title,
        canonical_description=description,
        input_schema=input_schema,
        output_schema=output_schema,
        handler_name=f"child:{domain}:{name}",
        support_contract=feature.support_contract,
        authorization_policy=f"child:call:{domain}:{name}",
        annotations=_READ_ONLY_ANNOTATIONS,
        composite_plan=composite_plan,
    )


def _domain(
    name: str,
    title: str,
    description: str,
    children: tuple[ChildToolDefinition, ...],
) -> DomainDefinition:
    return DomainDefinition(
        name=name,
        title=title,
        description=description,
        annotations=_READ_ONLY_ANNOTATIONS,
        children=children,
        enablement_policy="readonly_domain_enabled",
        discovery_policy="authorized_child_discovery",
    )


_TABLE_CONTEXT_PLAN = CompositePlan(
    steps=(
        CompositeStep(
            name="schema",
            handler_name="_get_table_schema_tool",
        ),
        CompositeStep(
            name="table_comments",
            handler_name="_get_table_comment_tool",
            depends_on=("schema",),
        ),
        CompositeStep(
            name="column_comments",
            handler_name="_get_table_column_comments_tool",
            depends_on=("schema",),
        ),
        CompositeStep(
            name="indexes",
            handler_name="_get_table_indexes_tool",
            depends_on=("schema",),
        ),
        CompositeStep(
            name="basic",
            handler_name="_get_table_basic_info_tool",
            depends_on=("schema",),
        ),
    ),
    required_steps=("schema",),
    optional_steps=("table_comments", "column_comments", "indexes", "basic"),
    partial_success_policy="required_schema_optional_sections",
    merge_handler_name="merge:doris_catalog:table_context",
)

_QUERY_DIAGNOSIS_PLAN = CompositePlan(
    steps=(
        CompositeStep(name="explain", handler_name="child:doris_query:explain_query"),
        CompositeStep(
            name="profile",
            handler_name="child:doris_query:get_query_profile",
        ),
        CompositeStep(
            name="slow_queries",
            handler_name="child:doris_query:list_slow_queries",
        ),
        CompositeStep(
            name="cluster_context",
            handler_name="child:doris_cluster:get_cluster_overview",
        ),
    ),
    required_steps=("explain",),
    optional_steps=("profile", "slow_queries", "cluster_context"),
    partial_success_policy="evidence_preserving_partial",
    merge_handler_name="merge:doris_query:performance_diagnosis",
)

_CLUSTER_OVERVIEW_PLAN = CompositePlan(
    steps=(
        CompositeStep(
            name="nodes",
            handler_name="child:doris_cluster:list_cluster_nodes",
        ),
        CompositeStep(
            name="tasks",
            handler_name="child:doris_cluster:list_active_tasks",
        ),
        CompositeStep(
            name="metrics",
            handler_name="child:doris_cluster:get_monitoring_metrics",
        ),
        CompositeStep(
            name="memory",
            handler_name="child:doris_cluster:get_memory_stats",
        ),
        CompositeStep(
            name="cache",
            handler_name="child:doris_cluster:get_cache_status",
        ),
        CompositeStep(
            name="compaction",
            handler_name="child:doris_cluster:get_compaction_status",
        ),
    ),
    required_steps=("nodes",),
    optional_steps=("tasks", "metrics", "memory", "cache", "compaction"),
    partial_success_policy="health_summary_partial",
    merge_handler_name="merge:doris_cluster:overview",
)

_INGESTION_DIAGNOSIS_PLAN = CompositePlan(
    steps=(
        CompositeStep(
            name="ingestion",
            handler_name="child:doris_pipeline:get_ingestion_status",
        ),
        CompositeStep(
            name="freshness",
            handler_name="child:doris_pipeline:monitor_data_freshness",
        ),
        CompositeStep(
            name="dependencies",
            handler_name="child:doris_pipeline:analyze_data_dependencies",
        ),
        CompositeStep(
            name="audit",
            handler_name="child:doris_governance:get_recent_audit_logs",
        ),
    ),
    required_steps=("ingestion",),
    optional_steps=("freshness", "dependencies", "audit"),
    partial_success_policy="evidence_preserving_partial",
    merge_handler_name="merge:doris_pipeline:ingestion_diagnosis",
)

_SEARCH_DIAGNOSIS_PLAN = CompositePlan(
    steps=(
        CompositeStep(
            name="indexes",
            handler_name="child:doris_search:inspect_search_indexes",
        ),
        CompositeStep(
            name="explain",
            handler_name="child:doris_query:explain_query",
        ),
        CompositeStep(
            name="profile",
            handler_name="child:doris_query:get_query_profile",
            depends_on=("explain",),
        ),
    ),
    required_steps=("indexes",),
    optional_steps=("explain", "profile"),
    partial_success_policy="evidence_preserving_partial",
    merge_handler_name="merge:doris_search:query_diagnosis",
)


DOMAIN_DEFINITIONS = (
    _domain(
        "doris_catalog",
        "Doris Catalog",
        "Explore Doris catalogs, databases, tables, schemas, comments, indexes, "
        "key models, storage metadata, and object sizes.",
        (
            _child(
                "doris_catalog",
                "list_catalogs",
                "List catalogs",
                "List visible internal and external Doris catalogs.",
                _input_schema(
                    {
                        "include_external": _boolean(
                            "Include external catalogs."
                        ),
                        "pattern": _string("Optional catalog-name pattern."),
                    }
                ),
                _COLLECTION_OUTPUT,
            ),
            _child(
                "doris_catalog",
                "list_databases",
                "List databases",
                "List visible databases in one exact catalog.",
                _input_schema(
                    {
                        "catalog": _string("Catalog name."),
                        "pattern": _string("Optional database-name pattern."),
                    }
                ),
                _COLLECTION_OUTPUT,
            ),
            _child(
                "doris_catalog",
                "list_tables",
                "List tables",
                "List visible tables, views, and materialized views.",
                _input_schema(
                    {
                        "catalog": _string("Catalog name."),
                        "database": _string("Database name."),
                        "pattern": _string("Optional object-name pattern."),
                        "types": _string_array(
                            "Object types to include.",
                            enum=("table", "view", "materialized_view"),
                        ),
                        "page": _string("Opaque pagination cursor."),
                    },
                    required=("database",),
                ),
                _COLLECTION_OUTPUT,
            ),
            _child(
                "doris_catalog",
                "get_table_context",
                "Get table context",
                "Read schema, comments, indexes, and basic table information "
                "through a deterministic four-section composition.",
                _input_schema(
                    {
                        "catalog": _string("Catalog name."),
                        "database": _string("Database name."),
                        "table": _string("Table name."),
                        "sections": _string_array(
                            "Optional sections to return. Schema is always "
                            "included as the composition prerequisite.",
                            enum=("schema", "comments", "indexes", "basic"),
                        ),
                    },
                    required=("database", "table"),
                ),
                _TABLE_CONTEXT_OUTPUT,
                composite_plan=_TABLE_CONTEXT_PLAN,
            ),
            _child(
                "doris_catalog",
                "get_table_size",
                "Get table size",
                "Read table and optional partition size and row statistics.",
                _input_schema(
                    {
                        "catalog": _string("Catalog name."),
                        "database": _string("Database name."),
                        "table": _string("Table name."),
                        "include_partitions": _boolean(
                            "Include per-partition statistics."
                        ),
                    },
                    required=("database", "table"),
                ),
            ),
        ),
    ),
    _domain(
        "doris_query",
        "Doris Query",
        "Execute read-only Doris SQL, inspect plans and profiles, review slow "
        "queries, and use the optional ADBC provider.",
        (
            _child(
                "doris_query",
                "execute_query",
                "Execute query",
                "Execute one read-only Doris SQL statement with bounded results.",
                _input_schema(
                    {
                        "sql": _string("Read-only SQL statement."),
                        "catalog": _string("Catalog context."),
                        "database": _string("Database context."),
                        "parameters": _object("Bound query parameters."),
                        "max_rows": _integer(
                            "Maximum returned rows.",
                            minimum=1,
                        ),
                        "timeout_ms": _integer(
                            "Execution timeout in milliseconds.",
                            minimum=1,
                        ),
                    },
                    required=("sql",),
                ),
                _QUERY_OUTPUT,
            ),
            _child(
                "doris_query",
                "explain_query",
                "Explain query",
                "Inspect a read-only query plan and evidence for pruning, "
                "pushdown, and index selection.",
                _input_schema(
                    {
                        "sql": _string("Read-only SQL statement."),
                        "catalog": _string("Catalog context."),
                        "database": _string("Database context."),
                        "level": _string(
                            "Explain detail level.",
                            enum=("normal", "verbose", "costs"),
                        ),
                    },
                    required=("sql",),
                ),
                _DIAGNOSTIC_OUTPUT,
            ),
            _child(
                "doris_query",
                "get_query_profile",
                "Get query profile",
                "Read a Doris query profile by query ID or a bounded SQL run.",
                _input_schema(
                    {
                        "query_id": _string("Existing Doris query ID."),
                        "sql": _string("Read-only SQL to profile."),
                        "recent_window_minutes": _integer(
                            "Recent lookup window in minutes.",
                            minimum=1,
                        ),
                        "include_operator_tree": _boolean(
                            "Include the operator tree."
                        ),
                    },
                    any_of=(
                        {"required": ["query_id"]},
                        {"required": ["sql"]},
                    ),
                ),
                _DIAGNOSTIC_OUTPUT,
            ),
            _child(
                "doris_query",
                "diagnose_query_performance",
                "Diagnose query performance",
                "Combine explain, profile, slow-query, and cluster evidence "
                "through deterministic diagnostic rules.",
                _input_schema(
                    {
                        "query_id": _string("Existing Doris query ID."),
                        "sql": _string("Read-only SQL to diagnose."),
                        "database": _string("Database context."),
                        "include_cluster_context": _boolean(
                            "Include relevant cluster evidence."
                        ),
                    },
                    any_of=(
                        {"required": ["query_id"]},
                        {"required": ["sql"]},
                    ),
                ),
                _DIAGNOSTIC_OUTPUT,
                composite_plan=_QUERY_DIAGNOSIS_PLAN,
            ),
            _child(
                "doris_query",
                "list_slow_queries",
                "List slow queries",
                "List recorded slow queries with bounded filters.",
                _input_schema(
                    {
                        "window_minutes": _integer(
                            "Lookback window in minutes.",
                            minimum=1,
                        ),
                        "limit": _integer("Maximum results.", minimum=1),
                        "min_duration_ms": _integer(
                            "Minimum duration in milliseconds."
                        ),
                        "database": _string("Database filter."),
                        "user": _string("User filter."),
                    }
                ),
                _COLLECTION_OUTPUT,
            ),
            _child(
                "doris_query",
                "get_adbc_connection_info",
                "Get ADBC connection info",
                "Report sanitized ADBC provider configuration and reachability.",
                _input_schema({}),
            ),
            _child(
                "doris_query",
                "execute_adbc_query",
                "Execute ADBC query",
                "Execute one read-only SQL statement through Arrow Flight SQL.",
                _input_schema(
                    {
                        "sql": _string("Read-only SQL statement."),
                        "max_rows": _integer(
                            "Maximum returned rows.",
                            minimum=1,
                        ),
                        "timeout_ms": _integer(
                            "Execution timeout in milliseconds.",
                            minimum=1,
                        ),
                        "result_format": _string(
                            "Result representation.",
                            enum=("arrow", "pandas", "dict"),
                        ),
                    },
                    required=("sql",),
                ),
                _QUERY_OUTPUT,
            ),
        ),
    ),
    _domain(
        "doris_cluster",
        "Doris Cluster",
        "Inspect Doris health, nodes, tasks, monitoring, memory, cache, "
        "compaction, workload, compute groups, and runtime capabilities.",
        (
            _child(
                "doris_cluster",
                "get_cluster_overview",
                "Get cluster overview",
                "Produce a bounded deterministic cluster health summary.",
                _input_schema(
                    {
                        "include": _string_array(
                            "Optional overview sections.",
                            enum=(
                                "nodes",
                                "tasks",
                                "metrics",
                                "memory",
                                "cache",
                                "compaction",
                            ),
                        )
                    }
                ),
                _DIAGNOSTIC_OUTPUT,
                composite_plan=_CLUSTER_OVERVIEW_PLAN,
            ),
            _child(
                "doris_cluster",
                "list_cluster_nodes",
                "List cluster nodes",
                "List FE, BE, and broker nodes with visible health metadata.",
                _input_schema(
                    {
                        "node_types": _string_array(
                            "Node types to include.",
                            enum=("fe", "be", "broker"),
                        ),
                        "include_metrics": _boolean(
                            "Include bounded node metrics."
                        ),
                    }
                ),
                _COLLECTION_OUTPUT,
            ),
            _child(
                "doris_cluster",
                "list_active_tasks",
                "List active tasks",
                "List visible query, load, schema-change, and compaction tasks.",
                _input_schema(
                    {
                        "task_types": _string_array(
                            "Task types to include."
                        ),
                        "states": _string_array("Task states to include."),
                        "limit": _integer("Maximum results.", minimum=1),
                    }
                ),
                _COLLECTION_OUTPUT,
            ),
            _child(
                "doris_cluster",
                "get_monitoring_metrics",
                "Get monitoring metrics",
                "Read bounded FE and BE monitoring metric snapshots.",
                _input_schema(
                    {
                        "metric_names": _string_array("Metric names."),
                        "node_ids": _string_array("Node identifiers."),
                        "window": _string("Bounded metric window."),
                    }
                ),
            ),
            _child(
                "doris_cluster",
                "get_memory_stats",
                "Get memory statistics",
                "Read process and tracker memory statistics from visible nodes.",
                _input_schema(
                    {
                        "node_ids": _string_array("Node identifiers."),
                        "detail": _string(
                            "Detail level.",
                            enum=("summary", "trackers", "top_consumers"),
                        ),
                    }
                ),
            ),
            _child(
                "doris_cluster",
                "get_cache_status",
                "Get cache status",
                "Inspect file-cache capacity, hit state, and optional queues.",
                _input_schema(
                    {
                        "scope": _string("Cache scope."),
                        "node_ids": _string_array("Node identifiers."),
                        "include_queues": _boolean(
                            "Include queue statistics."
                        ),
                    }
                ),
            ),
            _child(
                "doris_cluster",
                "get_compaction_status",
                "Get compaction status",
                "Inspect compaction summaries or task-tracker evidence.",
                _input_schema(
                    {
                        "database": _string("Database filter."),
                        "table": _string("Table filter."),
                        "state": _string("Compaction state filter."),
                        "limit": _integer("Maximum results.", minimum=1),
                    }
                ),
            ),
            _child(
                "doris_cluster",
                "get_workload_group_status",
                "Get workload group status",
                "Read workload-group quotas, usage, queues, and limits.",
                _input_schema(
                    {
                        "name": _string("Workload-group name."),
                        "include_usage": _boolean(
                            "Include current resource usage."
                        ),
                    }
                ),
            ),
            _child(
                "doris_cluster",
                "get_compute_group_status",
                "Get compute group status",
                "Read compute-group membership and bounded usage metadata.",
                _input_schema(
                    {
                        "name": _string("Compute-group name."),
                        "include_nodes": _boolean("Include member nodes."),
                        "include_usage": _boolean("Include resource usage."),
                    }
                ),
            ),
            _child(
                "doris_cluster",
                "analyze_resource_growth",
                "Analyze resource growth",
                "Analyze recorded resource-growth evidence without inventing "
                "missing history.",
                _input_schema(
                    {
                        "resource": _string("Resource type."),
                        "window_days": _integer(
                            "Lookback window in days.",
                            minimum=1,
                        ),
                        "granularity": _string(
                            "Aggregation granularity.",
                            enum=("hour", "day", "week"),
                        ),
                    }
                ),
                _DIAGNOSTIC_OUTPUT,
            ),
            _child(
                "doris_cluster",
                "get_runtime_capabilities",
                "Get runtime capabilities",
                "Return sanitized version, deployment, feature, endpoint, and "
                "provider capability evidence.",
                _input_schema(
                    {
                        "detail": _string(
                            "Detail level.",
                            enum=("summary", "full"),
                        )
                    }
                ),
                _DIAGNOSTIC_OUTPUT,
            ),
        ),
    ),
    _domain(
        "doris_pipeline",
        "Doris Pipeline",
        "Inspect ingestion, load health, materialized views, data freshness, "
        "and upstream or downstream dependencies.",
        (
            _child(
                "doris_pipeline",
                "get_ingestion_status",
                "Get ingestion status",
                "Read streaming and batch load job status.",
                _input_schema(
                    {
                        "job_types": _string_array("Load job types."),
                        "database": _string("Database filter."),
                        "table": _string("Table filter."),
                        "states": _string_array("Job states."),
                        "limit": _integer("Maximum results.", minimum=1),
                    }
                ),
                _COLLECTION_OUTPUT,
            ),
            _child(
                "doris_pipeline",
                "diagnose_ingestion",
                "Diagnose ingestion",
                "Combine load, freshness, dependency, and audit evidence using "
                "deterministic rules.",
                _input_schema(
                    {
                        "job_id": _string("Load job identifier."),
                        "database": _string("Database name."),
                        "table": _string("Table name."),
                        "window_minutes": _integer(
                            "Lookback window in minutes.",
                            minimum=1,
                        ),
                        "include_dependencies": _boolean(
                            "Include dependency evidence."
                        ),
                    },
                    any_of=(
                        {"required": ["job_id"]},
                        {"required": ["database", "table"]},
                    ),
                ),
                _DIAGNOSTIC_OUTPUT,
                composite_plan=_INGESTION_DIAGNOSIS_PLAN,
            ),
            _child(
                "doris_pipeline",
                "get_materialized_view_status",
                "Get materialized view status",
                "Read materialized-view refresh, state, and failure metadata.",
                _input_schema(
                    {
                        "database": _string("Database filter."),
                        "view": _string("Materialized-view filter."),
                        "states": _string_array("View states."),
                        "include_refresh_history": _boolean(
                            "Include bounded refresh history."
                        ),
                    }
                ),
                _COLLECTION_OUTPUT,
            ),
            _child(
                "doris_pipeline",
                "monitor_data_freshness",
                "Monitor data freshness",
                "Measure table freshness against a bounded threshold.",
                _input_schema(
                    {
                        "database": _string("Database name."),
                        "table": _string("Table name."),
                        "threshold_seconds": _integer(
                            "Freshness threshold in seconds.",
                            minimum=1,
                        ),
                        "time_column": _string("Optional event-time column."),
                    },
                    required=("database", "table"),
                ),
                _DIAGNOSTIC_OUTPUT,
            ),
            _child(
                "doris_pipeline",
                "analyze_data_dependencies",
                "Analyze data dependencies",
                "Trace bounded upstream or downstream object dependencies.",
                _input_schema(
                    {
                        "catalog": _string("Catalog name."),
                        "database": _string("Database name."),
                        "object": _string("Object name."),
                        "direction": _string(
                            "Traversal direction.",
                            enum=("upstream", "downstream", "both"),
                        ),
                        "depth": _integer(
                            "Maximum traversal depth.",
                            minimum=1,
                        ),
                    },
                    required=("object",),
                ),
                _DIAGNOSTIC_OUTPUT,
            ),
        ),
    ),
    _domain(
        "doris_search",
        "Doris Search",
        "Search Doris data with text, vector, or hybrid retrieval and inspect "
        "or diagnose search analyzers and indexes.",
        (
            _child(
                "doris_search",
                "search_data",
                "Search data",
                "Run bounded structured text, vector, or hybrid retrieval.",
                _input_schema(
                    {
                        "database": _string("Database name."),
                        "table": _string("Table name."),
                        "query": _string("Text query."),
                        "mode": _string(
                            "Search mode.",
                            enum=("text", "vector", "hybrid"),
                        ),
                        "fields": _string_array("Searchable fields."),
                        "vector": _array("Query vector."),
                        "top_k": _integer(
                            "Maximum matches.",
                            minimum=1,
                            maximum=1000,
                        ),
                        "filters": _object("Structured filters."),
                        "return_fields": _string_array("Visible return fields."),
                    },
                    required=("database", "table", "mode"),
                ),
                _QUERY_OUTPUT,
            ),
            _child(
                "doris_search",
                "preview_text_analysis",
                "Preview text analysis",
                "Preview deterministic tokenizer and analyzer output.",
                _input_schema(
                    {
                        "text": _string("Input text."),
                        "analyzer": _string("Analyzer name."),
                        "tokenizer": _string("Tokenizer name."),
                        "token_filters": _string_array("Token filters."),
                    },
                    required=("text",),
                ),
            ),
            _child(
                "doris_search",
                "inspect_search_indexes",
                "Inspect search indexes",
                "Inspect inverted and ANN index metadata and availability.",
                _input_schema(
                    {
                        "database": _string("Database name."),
                        "table": _string("Table name."),
                        "index": _string("Optional index name."),
                    },
                    required=("database", "table"),
                ),
            ),
            _child(
                "doris_search",
                "diagnose_search_query",
                "Diagnose search query",
                "Combine index, explain, and optional profile evidence.",
                _input_schema(
                    {
                        "sql": _string("Read-only search SQL."),
                        "search_request": _object(
                            "Structured search request."
                        ),
                        "include_profile": _boolean(
                            "Include query-profile evidence."
                        ),
                    },
                    any_of=(
                        {"required": ["sql"]},
                        {"required": ["search_request"]},
                    ),
                ),
                _DIAGNOSTIC_OUTPUT,
                composite_plan=_SEARCH_DIAGNOSIS_PLAN,
            ),
        ),
    ),
    _domain(
        "doris_governance",
        "Doris Governance",
        "Analyze columns and storage, inspect lineage and access evidence, "
        "read audit metadata, and review UDF or authentication mappings.",
        (
            _child(
                "doris_governance",
                "analyze_columns",
                "Analyze columns",
                "Analyze bounded column completeness, cardinality, and type risks.",
                _input_schema(
                    {
                        "database": _string("Database name."),
                        "table": _string("Table name."),
                        "columns": _string_array("Columns to analyze."),
                        "sample_ratio": _number(
                            "Bounded sample ratio.",
                            minimum=0.0,
                            maximum=1.0,
                        ),
                    },
                    required=("database", "table"),
                ),
                _DIAGNOSTIC_OUTPUT,
            ),
            _child(
                "doris_governance",
                "analyze_table_storage",
                "Analyze table storage",
                "Analyze table partitions, replicas, compression, indexes, and "
                "visible storage features.",
                _input_schema(
                    {
                        "database": _string("Database name."),
                        "table": _string("Table name."),
                        "include_partitions": _boolean(
                            "Include partition details."
                        ),
                        "include_indexes": _boolean("Include index details."),
                    },
                    required=("database", "table"),
                ),
                _DIAGNOSTIC_OUTPUT,
            ),
            _child(
                "doris_governance",
                "get_lineage_capability_status",
                "Get lineage capability status",
                "Report native SPI, plugin, queryable store, provider, audit "
                "fallback, coverage, and health evidence.",
                _input_schema({}),
                _DIAGNOSTIC_OUTPUT,
            ),
            _child(
                "doris_governance",
                "trace_column_lineage",
                "Trace column lineage",
                "Trace bounded lineage while preserving each edge's evidence type "
                "and limitations.",
                _input_schema(
                    {
                        "object": _string("Qualified target object."),
                        "column": _string("Optional target column."),
                        "direction": _string(
                            "Traversal direction.",
                            enum=("upstream", "downstream", "both"),
                        ),
                        "depth": _integer(
                            "Maximum traversal depth.",
                            minimum=1,
                        ),
                        "evidence_mode": _string(
                            "Evidence selection.",
                            enum=("auto", "native", "audit"),
                        ),
                    },
                    required=("object",),
                ),
                _DIAGNOSTIC_OUTPUT,
            ),
            _child(
                "doris_governance",
                "analyze_data_access_patterns",
                "Analyze data access patterns",
                "Analyze bounded, authorized audit history for access patterns.",
                _input_schema(
                    {
                        "database": _string("Database filter."),
                        "table": _string("Table filter."),
                        "window_days": _integer(
                            "Lookback window in days.",
                            minimum=1,
                        ),
                        "group_by": _string(
                            "Grouping dimension.",
                            enum=("user", "object", "hour", "operation"),
                        ),
                    }
                ),
                _DIAGNOSTIC_OUTPUT,
            ),
            _child(
                "doris_governance",
                "get_recent_audit_logs",
                "Get recent audit logs",
                "Read bounded and redacted audit events.",
                _input_schema(
                    {
                        "window_minutes": _integer(
                            "Lookback window in minutes.",
                            minimum=1,
                        ),
                        "user": _string("User filter."),
                        "operation": _string("Operation filter."),
                        "database": _string("Database filter."),
                        "table": _string("Table filter."),
                        "limit": _integer("Maximum results.", minimum=1),
                    }
                ),
                _COLLECTION_OUTPUT,
            ),
            _child(
                "doris_governance",
                "list_udfs",
                "List UDFs",
                "List visible UDF metadata without loading or executing code.",
                _input_schema(
                    {
                        "database": _string("Database filter."),
                        "language": _string("Language filter."),
                        "name_pattern": _string("UDF-name pattern."),
                    }
                ),
                _COLLECTION_OUTPUT,
            ),
            _child(
                "doris_governance",
                "get_auth_mapping_status",
                "Get authentication mapping status",
                "Read sanitized LDAP, OIDC, and role-mapping health metadata.",
                _input_schema(
                    {
                        "principal": _string("Principal filter."),
                        "provider": _string(
                            "Authentication provider.",
                            enum=("ldap", "oidc"),
                        ),
                        "include_roles": _boolean(
                            "Include authorized role mappings."
                        ),
                    }
                ),
                _DIAGNOSTIC_OUTPUT,
            ),
        ),
    ),
    _domain(
        "doris_lakehouse",
        "Doris Lakehouse",
        "Inspect external catalogs, lakehouse tables, snapshots, partitions, "
        "pushdown behavior, and Variant semi-structured columns.",
        (
            _child(
                "doris_lakehouse",
                "inspect_external_catalog",
                "Inspect external catalog",
                "Inspect sanitized external-catalog type, state, and capabilities.",
                _input_schema(
                    {
                        "catalog": _string("External catalog name."),
                        "include_objects": _boolean(
                            "Include a bounded object sample."
                        ),
                        "object_limit": _integer(
                            "Maximum sampled objects.",
                            minimum=1,
                        ),
                    },
                    required=("catalog",),
                ),
                _DIAGNOSTIC_OUTPUT,
            ),
            _child(
                "doris_lakehouse",
                "inspect_lakehouse_table",
                "Inspect lakehouse table",
                "Inspect format, snapshots, partitions, statistics, and pushdown "
                "evidence for one external table.",
                _input_schema(
                    {
                        "catalog": _string("External catalog name."),
                        "database": _string("Database name."),
                        "table": _string("Table name."),
                        "include_snapshots": _boolean(
                            "Include bounded snapshot metadata."
                        ),
                        "include_partitions": _boolean(
                            "Include bounded partition metadata."
                        ),
                    },
                    required=("catalog", "database", "table"),
                ),
                _DIAGNOSTIC_OUTPUT,
            ),
            _child(
                "doris_lakehouse",
                "inspect_variant_column",
                "Inspect Variant column",
                "Inspect Variant paths, types, sparsity, and bounded sample shape.",
                _input_schema(
                    {
                        "catalog": _string("Catalog name."),
                        "database": _string("Database name."),
                        "table": _string("Table name."),
                        "column": _string("Variant column name."),
                        "path": _string("Optional Variant path."),
                        "sample_rows": _integer(
                            "Maximum sampled rows.",
                            minimum=1,
                        ),
                    },
                    required=("database", "table", "column"),
                ),
                _DIAGNOSTIC_OUTPUT,
            ),
        ),
    ),
    _domain(
        "doris_semantic",
        "Doris Semantic",
        "Discover validated Ossie models bound to Doris and read permission-"
        "filtered semantic summaries, context, and mapping status.",
        (
            _child(
                "doris_semantic",
                "list_semantic_models",
                "List semantic models",
                "List authorized validated Ossie model references.",
                _input_schema(
                    {
                        "namespace": _string("Model namespace."),
                        "tag": _string("Model tag."),
                        "pattern": _string("Model-name pattern."),
                    }
                ),
                _COLLECTION_OUTPUT,
            ),
            _child(
                "doris_semantic",
                "get_semantic_model_summary",
                "Get semantic model summary",
                "Read an exact Ossie model summary without guessing a model.",
                _input_schema(
                    {
                        "model_ref": _string(
                            "Exact semantic model reference.",
                            pattern=r"^[A-Za-z0-9_.:/@-]+$",
                        ),
                        "include_bindings": _boolean(
                            "Include authorized Doris bindings."
                        ),
                    },
                    required=("model_ref",),
                ),
                _DIAGNOSTIC_OUTPUT,
            ),
            _child(
                "doris_semantic",
                "get_semantic_context",
                "Get semantic context",
                "Build permission-filtered semantic context for an exact model.",
                _input_schema(
                    {
                        "model_ref": _string(
                            "Exact semantic model reference.",
                            pattern=r"^[A-Za-z0-9_.:/@-]+$",
                        ),
                        "request": _object(
                            "Structured measures, dimensions, filters, and time grain."
                        ),
                    },
                    required=("model_ref", "request"),
                ),
                _DIAGNOSTIC_OUTPUT,
            ),
            _child(
                "doris_semantic",
                "get_semantic_mapping_status",
                "Get semantic mapping status",
                "Validate Doris bindings for an exact semantic model reference.",
                _input_schema(
                    {
                        "model_ref": _string(
                            "Exact semantic model reference.",
                            pattern=r"^[A-Za-z0-9_.:/@-]+$",
                        ),
                        "datasource": _string("Optional datasource filter."),
                    },
                    required=("model_ref",),
                ),
                _DIAGNOSTIC_OUTPUT,
            ),
        ),
    ),
)


def _migration(
    legacy_tool_name: str,
    legacy_handler_name: str,
    domain: str,
    child_name: str,
    *,
    mode: LegacyMigrationMode = LegacyMigrationMode.ATOMIC,
    adapter_name: str | None = None,
    target_section: str | None = None,
) -> LegacyToolMigration:
    return LegacyToolMigration(
        legacy_tool_name=legacy_tool_name,
        legacy_handler_name=legacy_handler_name,
        domain=domain,
        child_name=child_name,
        mode=mode,
        adapter_name=adapter_name,
        target_section=target_section,
    )


LEGACY_TOOL_MIGRATIONS = (
    _migration(
        "exec_query",
        "_exec_query_tool",
        "doris_query",
        "execute_query",
        mode=LegacyMigrationMode.ADAPTED,
        adapter_name="adapt:query_arguments",
    ),
    _migration(
        "get_table_schema",
        "_get_table_schema_tool",
        "doris_catalog",
        "get_table_context",
        mode=LegacyMigrationMode.COMPOSITE_SECTION,
        target_section="schema",
    ),
    _migration(
        "get_db_table_list",
        "_get_db_table_list_tool",
        "doris_catalog",
        "list_tables",
        mode=LegacyMigrationMode.ADAPTED,
        adapter_name="adapt:catalog_object_names",
    ),
    _migration(
        "get_db_list",
        "_get_db_list_tool",
        "doris_catalog",
        "list_databases",
        mode=LegacyMigrationMode.ADAPTED,
        adapter_name="adapt:catalog_object_names",
    ),
    _migration(
        "get_table_comment",
        "_get_table_comment_tool",
        "doris_catalog",
        "get_table_context",
        mode=LegacyMigrationMode.COMPOSITE_SECTION,
        target_section="comments",
    ),
    _migration(
        "get_table_column_comments",
        "_get_table_column_comments_tool",
        "doris_catalog",
        "get_table_context",
        mode=LegacyMigrationMode.COMPOSITE_SECTION,
        target_section="comments",
    ),
    _migration(
        "get_table_indexes",
        "_get_table_indexes_tool",
        "doris_catalog",
        "get_table_context",
        mode=LegacyMigrationMode.COMPOSITE_SECTION,
        target_section="indexes",
    ),
    _migration(
        "get_recent_audit_logs",
        "_get_recent_audit_logs_tool",
        "doris_governance",
        "get_recent_audit_logs",
        mode=LegacyMigrationMode.ADAPTED,
        adapter_name="adapt:audit_filters",
    ),
    _migration(
        "get_catalog_list",
        "_get_catalog_list_tool",
        "doris_catalog",
        "list_catalogs",
        mode=LegacyMigrationMode.ADAPTED,
        adapter_name="adapt:remove_random_string",
    ),
    _migration(
        "get_sql_explain",
        "_get_sql_explain_tool",
        "doris_query",
        "explain_query",
        mode=LegacyMigrationMode.ADAPTED,
        adapter_name="adapt:explain_arguments",
    ),
    _migration(
        "get_sql_profile",
        "_get_sql_profile_tool",
        "doris_query",
        "get_query_profile",
        mode=LegacyMigrationMode.ADAPTED,
        adapter_name="adapt:profile_arguments",
    ),
    _migration(
        "get_table_data_size",
        "_get_table_data_size_tool",
        "doris_catalog",
        "get_table_size",
        mode=LegacyMigrationMode.ADAPTED,
        adapter_name="adapt:table_size_arguments",
    ),
    _migration(
        "get_monitoring_metrics",
        "_get_monitoring_metrics_tool",
        "doris_cluster",
        "get_monitoring_metrics",
        mode=LegacyMigrationMode.ADAPTED,
        adapter_name="adapt:monitoring_arguments",
    ),
    _migration(
        "get_memory_stats",
        "_get_memory_stats_tool",
        "doris_cluster",
        "get_memory_stats",
        mode=LegacyMigrationMode.ADAPTED,
        adapter_name="adapt:memory_arguments",
    ),
    _migration(
        "get_table_basic_info",
        "_get_table_basic_info_tool",
        "doris_catalog",
        "get_table_context",
        mode=LegacyMigrationMode.COMPOSITE_SECTION,
        target_section="basic",
    ),
    _migration(
        "analyze_columns",
        "_analyze_columns_tool",
        "doris_governance",
        "analyze_columns",
        mode=LegacyMigrationMode.ADAPTED,
        adapter_name="adapt:column_analysis_arguments",
    ),
    _migration(
        "analyze_table_storage",
        "_analyze_table_storage_tool",
        "doris_governance",
        "analyze_table_storage",
        mode=LegacyMigrationMode.ADAPTED,
        adapter_name="adapt:storage_analysis_arguments",
    ),
    _migration(
        "trace_column_lineage",
        "_trace_column_lineage_tool",
        "doris_governance",
        "trace_column_lineage",
        mode=LegacyMigrationMode.ADAPTED,
        adapter_name="adapt:lineage_arguments",
    ),
    _migration(
        "monitor_data_freshness",
        "_monitor_data_freshness_tool",
        "doris_pipeline",
        "monitor_data_freshness",
        mode=LegacyMigrationMode.ADAPTED,
        adapter_name="adapt:freshness_arguments",
    ),
    _migration(
        "analyze_data_access_patterns",
        "_analyze_data_access_patterns_tool",
        "doris_governance",
        "analyze_data_access_patterns",
        mode=LegacyMigrationMode.ADAPTED,
        adapter_name="adapt:access_analysis_arguments",
    ),
    _migration(
        "analyze_data_flow_dependencies",
        "_analyze_data_flow_dependencies_tool",
        "doris_pipeline",
        "analyze_data_dependencies",
        mode=LegacyMigrationMode.ADAPTED,
        adapter_name="adapt:dependency_arguments",
    ),
    _migration(
        "analyze_slow_queries_topn",
        "_analyze_slow_queries_topn_tool",
        "doris_query",
        "list_slow_queries",
        mode=LegacyMigrationMode.ADAPTED,
        adapter_name="adapt:slow_query_arguments",
    ),
    _migration(
        "analyze_resource_growth_curves",
        "_analyze_resource_growth_curves_tool",
        "doris_cluster",
        "analyze_resource_growth",
        mode=LegacyMigrationMode.ADAPTED,
        adapter_name="adapt:resource_growth_arguments",
    ),
    _migration(
        "exec_adbc_query",
        "_exec_adbc_query_tool",
        "doris_query",
        "execute_adbc_query",
        mode=LegacyMigrationMode.ADAPTED,
        adapter_name="adapt:adbc_query_arguments",
    ),
    _migration(
        "get_adbc_connection_info",
        "_get_adbc_connection_info_tool",
        "doris_query",
        "get_adbc_connection_info",
    ),
)

DORIS_DOMAIN_CATALOG = DorisDomainCatalog(
    domains=DOMAIN_DEFINITIONS,
    legacy_migrations=LEGACY_TOOL_MIGRATIONS,
)


__all__ = [
    "CURRENT_FLAT_TOOL_NAMES",
    "DOMAIN_DEFINITIONS",
    "DORIS_DOMAIN_CATALOG",
    "LEGACY_TOOL_MIGRATIONS",
    "DomainCatalogDomainSummary",
    "DomainCatalogError",
    "DomainCatalogSummary",
    "DorisDomainCatalog",
    "LegacyMigrationMode",
    "LegacyToolMigration",
]
