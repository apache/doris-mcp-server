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

"""Contract tests for the authoritative hierarchical domain catalog."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import Mock

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from doris_mcp_server.tools import domain_catalog as domain_catalog_module
from doris_mcp_server.tools import tool_catalog
from doris_mcp_server.tools.domain_catalog import (
    CURRENT_FLAT_TOOL_NAMES,
    DOMAIN_DEFINITIONS,
    DORIS_DOMAIN_CATALOG,
    LEGACY_TOOL_MIGRATIONS,
    DomainCatalogError,
    DorisDomainCatalog,
    LegacyMigrationMode,
    LegacyToolMigration,
)
from doris_mcp_server.tools.domain_models import (
    ChildToolDefinition,
    DomainDefinition,
)
from doris_mcp_server.tools.doris_feature_matrix import (
    DORIS_FEATURE_MATRIX,
    EXPECTED_DOMAIN_CHILDREN,
)
from doris_mcp_server.tools.tools_manager import DorisToolsManager


def _config() -> SimpleNamespace:
    return SimpleNamespace(
        security=SimpleNamespace(max_result_rows=1000),
        performance=SimpleNamespace(
            max_result_bytes=4 * 1024 * 1024,
            query_timeout=30,
        ),
        adbc=SimpleNamespace(
            default_max_rows=1000,
            default_timeout=30,
            default_return_format="dict",
        ),
    )


def _manager() -> DorisToolsManager:
    connection_manager = Mock()
    connection_manager.config = _config()
    return DorisToolsManager(connection_manager)


def _migration_registry(manager: DorisToolsManager):
    return tool_catalog.build_tool_registry(
        manager,
        manager.connection_manager.config,
    )


def _copy_catalog(
    *,
    domains: tuple[DomainDefinition, ...] | None = None,
    migrations: tuple[LegacyToolMigration, ...] | None = None,
) -> DorisDomainCatalog:
    return DORIS_DOMAIN_CATALOG.model_copy(
        update={
            "domains": domains or DORIS_DOMAIN_CATALOG.domains,
            "legacy_migrations": migrations or DORIS_DOMAIN_CATALOG.legacy_migrations,
        }
    )


def _wire_input(child: ChildToolDefinition) -> dict[str, Any]:
    return cast(dict[str, Any], child.to_wire()["input_schema"])


def _wire_output(child: ChildToolDefinition) -> dict[str, Any]:
    return cast(dict[str, Any], child.to_wire()["output_schema"])


def test_catalog_has_exact_ordered_eight_domain_fifty_five_child_shape() -> None:
    summary = DORIS_DOMAIN_CATALOG.summary()

    assert summary.domain_count == 8
    assert summary.child_count == 55
    assert summary.migrated_flat_tool_count == 25
    assert tuple(domain.name for domain in summary.domains) == tuple(
        EXPECTED_DOMAIN_CHILDREN
    )
    assert {domain.name: domain.child_names for domain in summary.domains} == dict(
        EXPECTED_DOMAIN_CHILDREN
    )
    assert tuple(len(domain.children) for domain in DORIS_DOMAIN_CATALOG.domains) == (
        5,
        7,
        11,
        5,
        4,
        8,
        3,
        12,
    )


def test_adbc_is_inside_query_and_cluster_has_exactly_eleven_children() -> None:
    query = DORIS_DOMAIN_CATALOG.resolve_domain("doris_query")
    cluster = DORIS_DOMAIN_CATALOG.resolve_domain("doris_cluster")

    assert "get_adbc_connection_info" in {child.name for child in query.children}
    assert "execute_adbc_query" in {child.name for child in query.children}
    assert len(cluster.children) == 11


def test_cluster_active_task_contract_matches_runtime_sources() -> None:
    child = DORIS_DOMAIN_CATALOG.resolve_child(
        "doris_cluster",
        "list_active_tasks",
    )
    task_types = _wire_input(child)["properties"]["task_types"]

    assert task_types["items"]["enum"] == ["query", "compaction"]
    assert "load" not in child.canonical_description.casefold()
    assert "schema-change" not in child.canonical_description.casefold()


def test_every_child_uses_the_exact_feature_matrix_contract() -> None:
    feature_contracts = {
        feature.feature_id: feature.support_contract
        for feature in DORIS_FEATURE_MATRIX.features
    }

    for domain in DORIS_DOMAIN_CATALOG.domains:
        for child in domain.children:
            feature_id = f"{domain.name}.{child.name}"
            assert child.support_contract is feature_contracts[feature_id]
            assert child.handler_name == f"child:{feature_id.replace('.', ':')}"
            assert child.authorization_policy == (
                f"child:call:{feature_id.replace('.', ':')}"
            )


def test_every_domain_and_child_is_strictly_read_only() -> None:
    for domain in DORIS_DOMAIN_CATALOG.domains:
        assert domain.annotations.read_only is True
        assert domain.annotations.idempotent is True
        assert domain.annotations.destructive is False
        assert domain.annotations.requires_confirmation is False
        assert len(domain.children) <= 12
        for child in domain.children:
            assert child.annotations == domain.annotations


def test_every_child_schema_is_valid_closed_and_non_placeholder() -> None:
    for domain in DORIS_DOMAIN_CATALOG.domains:
        for child in domain.children:
            input_schema = _wire_input(child)
            output_schema = _wire_output(child)
            Draft202012Validator.check_schema(input_schema)
            Draft202012Validator.check_schema(output_schema)
            assert input_schema["type"] == "object"
            assert input_schema["additionalProperties"] is False
            assert output_schema["type"] == "object"
            assert output_schema["additionalProperties"] is False
            assert len(child.title) > 3
            assert len(child.canonical_description) > 20


@pytest.mark.parametrize(
    "child_name",
    ["get_query_profile", "diagnose_query_performance"],
)
def test_query_evidence_inputs_require_exactly_one_reference(
    child_name: str,
) -> None:
    child = DORIS_DOMAIN_CATALOG.resolve_child(
        "doris_query",
        child_name,
    )
    validator = Draft202012Validator(_wire_input(child))

    assert list(validator.iter_errors({"query_id": "query_1"})) == []
    assert list(validator.iter_errors({"sql": "SELECT 1"})) == []
    assert list(validator.iter_errors({"query_id": "query_1", "sql": "SELECT 1"}))
    assert list(validator.iter_errors({}))


def test_query_schemas_publish_bounded_execution_limits() -> None:
    query = DORIS_DOMAIN_CATALOG.resolve_domain("doris_query")
    schemas = {child.name: _wire_input(child) for child in query.children}

    assert schemas["execute_query"]["properties"]["sql"]["maxLength"] == 1024 * 1024
    assert schemas["execute_query"]["properties"]["max_rows"]["maximum"] == 100_000
    assert schemas["execute_query"]["properties"]["timeout_ms"]["maximum"] == 300_000
    assert schemas["list_slow_queries"]["properties"]["limit"]["maximum"] == 1000


@pytest.mark.parametrize(
    ("domain_name", "child_name", "required"),
    [
        ("doris_catalog", "list_tables", {"database"}),
        ("doris_catalog", "get_table_context", {"database", "table"}),
        ("doris_query", "execute_query", {"sql"}),
        (
            "doris_query",
            "execute_adbc_query",
            {"explicit_adbc", "sql"},
        ),
        ("doris_pipeline", "monitor_data_freshness", {"database", "table"}),
        (
            "doris_lakehouse",
            "inspect_lakehouse_table",
            {"catalog", "database", "table"},
        ),
        (
            "doris_semantic",
            "get_semantic_model_summary",
            {"model_ref"},
        ),
        ("doris_semantic", "get_semantic_context", {"model_ref", "request"}),
        (
            "doris_semantic",
            "get_semantic_mapping_status",
            {"model_ref"},
        ),
    ],
)
def test_important_child_required_parameters_are_explicit(
    domain_name: str,
    child_name: str,
    required: set[str],
) -> None:
    child = DORIS_DOMAIN_CATALOG.resolve_child(domain_name, child_name)

    assert set(_wire_input(child)["required"]) == required


def test_semantic_content_children_require_explicit_model_ref() -> None:
    semantic = DORIS_DOMAIN_CATALOG.resolve_domain("doris_semantic")
    schemas = {child.name: _wire_input(child) for child in semantic.children}

    assert "required" not in schemas["list_semantic_models"]
    for name in (
        "get_semantic_model_summary",
        "get_semantic_context",
        "get_semantic_mapping_status",
        "get_metricflow_status",
        "list_metricflow_metrics",
        "get_metricflow_group_bys",
        "list_metricflow_saved_queries",
        "get_metricflow_dimension_values",
        "compile_metricflow_query",
        "execute_metricflow_query",
    ):
        assert "model_ref" in schemas[name]["required"]
        assert "model_ref" in schemas[name]["properties"]


def test_semantic_model_ref_schemas_accept_revision_metadata() -> None:
    semantic = DORIS_DOMAIN_CATALOG.resolve_domain("doris_semantic")
    model_ref = "sales/commerce@2026.08.05+4f91c2a"

    for child in semantic.children:
        schema = _wire_input(child)
        if "model_ref" not in schema.get("properties", {}):
            continue
        validator = Draft202012Validator(schema)
        arguments: dict[str, object] = {"model_ref": model_ref}
        if child.name == "get_semantic_context":
            arguments["request"] = {"metrics": ["total_sales"]}
        elif child.name == "get_metricflow_group_bys":
            arguments["metrics"] = ["revenue"]
        elif child.name == "get_metricflow_dimension_values":
            arguments.update({"metrics": ["revenue"], "dimension": "metric_time"})
        elif child.name in {
            "compile_metricflow_query",
            "execute_metricflow_query",
        }:
            arguments["request"] = {"metrics": ["revenue"]}

        assert list(validator.iter_errors(arguments)) == []


@pytest.mark.parametrize(
    "model_ref",
    (
        "+sales/commerce@2026.08.05",
        "sales/commerce@2026.08.05+",
        "sales/commerce@2026.08.05++4f91c2a",
    ),
)
def test_semantic_model_ref_schemas_reject_malformed_revision_metadata(
    model_ref: str,
) -> None:
    child = DORIS_DOMAIN_CATALOG.resolve_child(
        "doris_semantic",
        "get_semantic_model_summary",
    )

    errors = list(
        Draft202012Validator(_wire_input(child)).iter_errors({"model_ref": model_ref})
    )

    assert len(errors) == 1


def test_semantic_context_schema_requires_nonempty_unambiguous_selectors() -> None:
    child = DORIS_DOMAIN_CATALOG.resolve_child(
        "doris_semantic",
        "get_semantic_context",
    )
    validator = Draft202012Validator(_wire_input(child))

    valid = {
        "model_ref": "retail/main",
        "request": {
            "metrics": ["total_sales"],
            "dimensions": ["customers.segment"],
            "max_bytes": 8192,
        },
    }
    assert list(validator.iter_errors(valid)) == []
    for invalid_request in (
        {},
        {"metrics": []},
        {"question": ""},
        {"dimensions": ["customers.segment.extra"]},
        {"metrics": ["total_sales"], "unexpected": True},
    ):
        assert list(
            validator.iter_errors(
                {
                    "model_ref": "retail/main",
                    "request": invalid_request,
                }
            )
        )


def test_table_context_has_four_sections_and_five_deterministic_steps() -> None:
    child = DORIS_DOMAIN_CATALOG.resolve_child(
        "doris_catalog",
        "get_table_context",
    )
    plan = child.composite_plan

    assert plan is not None
    section_enum = _wire_input(child)["properties"]["sections"]["items"]["enum"]
    output = child.to_wire()["output_schema"]
    data_schema = output["properties"]["data"]
    assert tuple(section_enum) == ("schema", "comments", "indexes", "basic")
    for section in ("schema", "comments", "indexes", "basic"):
        section_schema = data_schema["properties"][section]
        assert section_schema["required"] == [
            "status",
            "data",
            "warnings",
            "source",
        ]
        assert section_schema["additionalProperties"] is False
    assert tuple(step.name for step in plan.steps) == (
        "schema",
        "table_comments",
        "column_comments",
        "indexes",
        "basic",
    )
    assert plan.required_steps == ("schema",)
    assert set(plan.optional_steps) == {
        "table_comments",
        "column_comments",
        "indexes",
        "basic",
    }


def test_query_parameter_schema_discloses_exact_placeholder_syntax() -> None:
    child = DORIS_DOMAIN_CATALOG.resolve_child(
        "doris_query",
        "execute_query",
    )
    parameters = _wire_input(child)["properties"]["parameters"]

    assert "%(name)s" in parameters["description"]
    assert "match every placeholder exactly" in parameters["description"]


@pytest.mark.parametrize(
    ("domain_name", "child_name", "required_steps"),
    [
        (
            "doris_query",
            "diagnose_query_performance",
            ("explain",),
        ),
        (
            "doris_cluster",
            "get_cluster_overview",
            ("nodes",),
        ),
        (
            "doris_pipeline",
            "diagnose_ingestion",
            ("ingestion",),
        ),
        (
            "doris_search",
            "diagnose_search_query",
            ("indexes",),
        ),
    ],
)
def test_composite_diagnostics_have_deterministic_required_steps(
    domain_name: str,
    child_name: str,
    required_steps: tuple[str, ...],
) -> None:
    child = DORIS_DOMAIN_CATALOG.resolve_child(domain_name, child_name)

    assert child.composite_plan is not None
    assert child.composite_plan.required_steps == required_steps
    assert child.composite_plan.partial_success_policy


def test_legacy_migrations_cover_exact_flat_baseline_and_real_handlers() -> None:
    manager = _manager()
    registry = _migration_registry(manager)

    assert (
        tuple(
            migration.legacy_tool_name
            for migration in DORIS_DOMAIN_CATALOG.legacy_migrations
        )
        == CURRENT_FLAT_TOOL_NAMES
    )
    assert (
        tuple(
            definition.name
            for definition in registry.advertised_definitions
            if definition.provider_name is None
        )
        == CURRENT_FLAT_TOOL_NAMES
    )
    DORIS_DOMAIN_CATALOG.validate_legacy_registry(
        registry,
        manager,
    )


def test_table_context_migrations_cover_exact_sections() -> None:
    migrations = tuple(
        migration
        for migration in LEGACY_TOOL_MIGRATIONS
        if migration.feature_id == "doris_catalog.get_table_context"
    )

    assert tuple(migration.legacy_tool_name for migration in migrations) == (
        "get_table_schema",
        "get_table_comment",
        "get_table_column_comments",
        "get_table_indexes",
        "get_table_basic_info",
    )
    assert tuple(migration.target_section for migration in migrations) == (
        "schema",
        "comments",
        "comments",
        "indexes",
        "basic",
    )
    assert all(
        migration.mode is LegacyMigrationMode.COMPOSITE_SECTION
        for migration in migrations
    )


def test_renamed_or_reshaped_migrations_declare_adapters() -> None:
    adapted = tuple(
        migration
        for migration in LEGACY_TOOL_MIGRATIONS
        if migration.mode is LegacyMigrationMode.ADAPTED
    )

    assert adapted
    assert all(migration.adapter_name for migration in adapted)
    assert all(migration.target_section is None for migration in adapted)


def test_catalog_markdown_is_deterministic_and_complete() -> None:
    first = DORIS_DOMAIN_CATALOG.render_markdown()
    second = DORIS_DOMAIN_CATALOG.render_markdown()

    assert first == second
    assert first.startswith(
        "<!--\n  ~ Licensed to the Apache Software Foundation (ASF) under one"
    )
    assert "\n# Doris MCP Hierarchical Domain Catalog\n" in first
    assert first.count("| `doris_") >= 55 + 8
    assert "`doris_query.execute_adbc_query`" in first
    assert "`get_table_schema`" in first
    assert "`doris_catalog.get_table_context`" in first
    assert "pre-1.0 flat names are migration inputs" in first


def test_summary_wire_schema_and_serialization_are_stable() -> None:
    summary = DORIS_DOMAIN_CATALOG.summary()

    Draft202012Validator.check_schema(summary.wire_schema())
    assert summary.to_wire() == DORIS_DOMAIN_CATALOG.summary().to_wire()
    assert summary.to_canonical_json() == (
        DORIS_DOMAIN_CATALOG.summary().to_canonical_json()
    )


def test_resolvers_reject_unknown_names_without_fuzzy_matching() -> None:
    with pytest.raises(DomainCatalogError, match="unknown domain"):
        DORIS_DOMAIN_CATALOG.resolve_domain("catalog")
    with pytest.raises(DomainCatalogError, match="unknown child"):
        DORIS_DOMAIN_CATALOG.resolve_child("doris_catalog", "list_table")


def test_duplicate_domain_is_rejected_even_when_validation_was_bypassed() -> None:
    invalid = _copy_catalog(
        domains=(
            *DORIS_DOMAIN_CATALOG.domains,
            DORIS_DOMAIN_CATALOG.domains[0],
        )
    )

    with pytest.raises(DomainCatalogError, match="domain names must be unique"):
        invalid.validate_integrity()


def test_duplicate_child_is_rejected_even_when_validation_was_bypassed() -> None:
    domain = DORIS_DOMAIN_CATALOG.domains[0]
    invalid_domain = domain.model_copy(
        update={"children": (*domain.children, domain.children[0])}
    )
    invalid = _copy_catalog(domains=(invalid_domain, *DORIS_DOMAIN_CATALOG.domains[1:]))

    with pytest.raises(DomainCatalogError, match="exact ordered"):
        invalid.validate_integrity()


def test_domain_above_twelve_child_budget_is_rejected() -> None:
    cluster_index = 2
    cluster = DORIS_DOMAIN_CATALOG.domains[cluster_index]
    invalid_cluster = cluster.model_copy(
        update={
            "children": (
                *cluster.children,
                cluster.children[0],
                cluster.children[1],
            )
        }
    )
    domains = list(DORIS_DOMAIN_CATALOG.domains)
    domains[cluster_index] = invalid_cluster
    invalid = _copy_catalog(domains=tuple(domains))

    with pytest.raises(DomainCatalogError, match="12-child limit"):
        invalid.validate_integrity()


def test_noncanonical_handler_binding_is_rejected() -> None:
    domain = DORIS_DOMAIN_CATALOG.domains[0]
    child = domain.children[0].model_copy(
        update={"handler_name": "child:wrong:binding"}
    )
    invalid_domain = domain.model_copy(
        update={"children": (child, *domain.children[1:])}
    )
    invalid = _copy_catalog(domains=(invalid_domain, *DORIS_DOMAIN_CATALOG.domains[1:]))

    with pytest.raises(DomainCatalogError, match="non-canonical handler"):
        invalid.validate_integrity()


def test_noncanonical_authorization_policy_is_rejected() -> None:
    domain = DORIS_DOMAIN_CATALOG.domains[0]
    child = domain.children[0].model_copy(
        update={"authorization_policy": "child:call:wrong"}
    )
    invalid_domain = domain.model_copy(
        update={"children": (child, *domain.children[1:])}
    )
    invalid = _copy_catalog(domains=(invalid_domain, *DORIS_DOMAIN_CATALOG.domains[1:]))

    with pytest.raises(DomainCatalogError, match="authorization policy"):
        invalid.validate_integrity()


def test_wrong_feature_matrix_contract_is_rejected() -> None:
    domain = DORIS_DOMAIN_CATALOG.domains[0]
    child = domain.children[0].model_copy(
        update={
            "support_contract": DORIS_DOMAIN_CATALOG.domains[0]
            .children[1]
            .support_contract
        }
    )
    invalid_domain = domain.model_copy(
        update={"children": (child, *domain.children[1:])}
    )
    invalid = _copy_catalog(domains=(invalid_domain, *DORIS_DOMAIN_CATALOG.domains[1:]))

    with pytest.raises(DomainCatalogError, match="feature-matrix contract"):
        invalid.validate_integrity()


def test_non_read_only_domain_and_child_are_rejected() -> None:
    domain = DORIS_DOMAIN_CATALOG.domains[0]
    writable_annotations = domain.annotations.model_copy(update={"read_only": False})
    invalid_domain = domain.model_copy(update={"annotations": writable_annotations})
    invalid = _copy_catalog(domains=(invalid_domain, *DORIS_DOMAIN_CATALOG.domains[1:]))

    with pytest.raises(DomainCatalogError, match="not marked read-only"):
        invalid.validate_integrity()

    child = domain.children[0].model_copy(update={"annotations": writable_annotations})
    invalid_domain = domain.model_copy(
        update={"children": (child, *domain.children[1:])}
    )
    invalid = _copy_catalog(domains=(invalid_domain, *DORIS_DOMAIN_CATALOG.domains[1:]))
    with pytest.raises(DomainCatalogError, match="risk contract"):
        invalid.validate_integrity()


def test_migration_baseline_drift_is_rejected() -> None:
    invalid = _copy_catalog(migrations=DORIS_DOMAIN_CATALOG.legacy_migrations[:-1])

    with pytest.raises(DomainCatalogError, match="exact ordered 25-tool"):
        invalid.validate_integrity()


def test_unknown_migration_target_is_rejected() -> None:
    first = LEGACY_TOOL_MIGRATIONS[0].model_copy(update={"child_name": "missing_child"})
    invalid = _copy_catalog(migrations=(first, *LEGACY_TOOL_MIGRATIONS[1:]))

    with pytest.raises(DomainCatalogError, match="targets unknown child"):
        invalid.validate_integrity()


def test_composite_migration_requires_composite_target() -> None:
    first = LEGACY_TOOL_MIGRATIONS[0].model_copy(
        update={
            "mode": LegacyMigrationMode.COMPOSITE_SECTION,
            "target_section": "schema",
        }
    )
    invalid = _copy_catalog(migrations=(first, *LEGACY_TOOL_MIGRATIONS[1:]))

    with pytest.raises(DomainCatalogError, match="non-composite child"):
        invalid.validate_integrity()


def test_table_context_section_mapping_drift_is_rejected() -> None:
    migrations = list(LEGACY_TOOL_MIGRATIONS)
    migrations[1] = migrations[1].model_copy(update={"target_section": "basic"})
    invalid = _copy_catalog(migrations=tuple(migrations))

    with pytest.raises(DomainCatalogError, match="exact five legacy handlers"):
        invalid.validate_integrity()


def test_migration_model_rejects_invalid_mode_fields() -> None:
    common = {
        "legacy_tool_name": "old_tool",
        "legacy_handler_name": "_old_tool",
        "domain": "doris_catalog",
        "child_name": "list_tables",
    }
    with pytest.raises(ValidationError, match="target_section"):
        LegacyToolMigration(
            **common,
            mode=LegacyMigrationMode.COMPOSITE_SECTION,
        )
    with pytest.raises(ValidationError, match="only valid"):
        LegacyToolMigration(
            **common,
            mode=LegacyMigrationMode.ATOMIC,
            target_section="schema",
        )
    with pytest.raises(ValidationError, match="adapter_name"):
        LegacyToolMigration(
            **common,
            mode=LegacyMigrationMode.ADAPTED,
        )
    with pytest.raises(ValidationError, match="adapter_name"):
        LegacyToolMigration(
            **common,
            mode=LegacyMigrationMode.ATOMIC,
            adapter_name="unexpected_adapter",
        )


def test_runtime_registry_handler_name_drift_is_rejected() -> None:
    manager = _manager()
    registry = _migration_registry(manager)
    first = LEGACY_TOOL_MIGRATIONS[0].model_copy(
        update={"legacy_handler_name": "_changed_handler"}
    )
    invalid = _copy_catalog(migrations=(first, *LEGACY_TOOL_MIGRATIONS[1:]))

    with pytest.raises(DomainCatalogError, match="changed handler"):
        invalid.validate_legacy_registry(registry, manager)


def test_runtime_dangling_handler_is_rejected() -> None:
    manager = _manager()
    registry = _migration_registry(manager)
    manager.__dict__["_exec_query_tool"] = None

    with pytest.raises(DomainCatalogError, match="dangling handler"):
        DORIS_DOMAIN_CATALOG.validate_legacy_registry(
            registry,
            manager,
        )


def test_runtime_flat_registry_drift_is_rejected() -> None:
    manager = _manager()
    registry = _migration_registry(manager)
    registry._ordered_names = registry._ordered_names[1:]

    with pytest.raises(DomainCatalogError, match="25-tool migration baseline"):
        DORIS_DOMAIN_CATALOG.validate_legacy_registry(registry, manager)


def test_server_startup_rejects_injected_duplicate_catalog(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    domain = DORIS_DOMAIN_CATALOG.domains[0]
    invalid_domain = domain.model_copy(
        update={"children": (*domain.children, domain.children[0])}
    )
    invalid = _copy_catalog(domains=(invalid_domain, *DORIS_DOMAIN_CATALOG.domains[1:]))
    monkeypatch.setattr(domain_catalog_module, "DORIS_DOMAIN_CATALOG", invalid)

    with pytest.raises(DomainCatalogError, match="exact ordered"):
        _manager()


def test_catalog_model_constructor_rejects_invalid_shape() -> None:
    with pytest.raises(ValidationError, match="exact ordered"):
        DorisDomainCatalog(
            domains=DOMAIN_DEFINITIONS[:-1],
            legacy_migrations=LEGACY_TOOL_MIGRATIONS,
        )
