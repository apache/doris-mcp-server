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

from __future__ import annotations

from collections import Counter
from typing import Any, cast

import pytest
from pydantic import ValidationError

import doris_mcp_server.tools.doris_feature_matrix as matrix_module
from doris_mcp_server.tools.domain_models import CapabilityVariant
from doris_mcp_server.tools.doris_feature_matrix import (
    CERTIFICATION_TARGET_VERSIONS,
    CERTIFIED_DORIS_VERSIONS,
    DORIS_FEATURE_MATRIX,
    DORIS_PATCH_CERTIFICATION_MATRIX,
    EXPECTED_DOMAIN_CHILDREN,
    PROJECT_MINIMUM_DORIS_VERSION,
    CapabilityVersionScope,
    DorisClusterVersionVector,
    DorisFeatureMatrix,
    DorisPatchCertificationMatrix,
    DorisVersionRange,
    FeatureSource,
    FeatureSourceKind,
    PatchCertificationCase,
    PatchCertificationEvidence,
    VersionCertificationStatus,
    matching_version_ranges,
)
from doris_mcp_server.tools.doris_version import parse_doris_version_comment


def _vector(
    version: str,
    *,
    followers: tuple[str, ...] = (),
    backends: tuple[str, ...] | None = None,
) -> DorisClusterVersionVector:
    raw = f"Doris version doris-{version}"
    return DorisClusterVersionVector.from_comments(
        master_fe=raw,
        follower_fes=tuple(f"Doris version doris-{item}" for item in followers),
        backends=tuple(
            f"Doris version doris-{item}"
            for item in (backends if backends is not None else (version,))
        ),
    )


def _matrix_payload() -> dict[str, Any]:
    return cast(dict[str, Any], DORIS_FEATURE_MATRIX.model_dump(mode="python"))


def _certification_cases() -> tuple[PatchCertificationCase, ...]:
    return tuple(
        PatchCertificationCase(
            transport=transport,
            exposure_mode=mode,
            listed_tool_count=8 if mode == "hierarchical" else 55,
            domain_manifest_count=8 if mode == "hierarchical" else 0,
            read_only_query_passed=True,
            write_operations_executed=0,
        )
        for transport in ("stdio", "streamable_http")
        for mode in ("hierarchical", "flat")
    )


def _certification_evidence(
    version: str = "4.1.2",
) -> PatchCertificationEvidence:
    return PatchCertificationEvidence(
        certification_id="doris_4_1_2_linux_amd64",
        version=version,
        master_fe_version_comment=(
            f"Doris version doris-{version}-rc01-43f06a5e26 (Cloud Mode)"
        ),
        backend_version_comments=(
            f"Doris version doris-{version}-rc02-43f06a5e26",
        ),
        platform="linux_amd64",
        deployment_mode="cloud",
        cases=_certification_cases(),
        domain_names=tuple(EXPECTED_DOMAIN_CHILDREN),
        child_contract_count=55,
        evidence_sha256="a" * 64,
        verified_on="2026-08-01",
    )


def test_matrix_contains_exact_8_domain_55_child_contract() -> None:
    assert len(DORIS_FEATURE_MATRIX.features) == 55
    assert tuple(EXPECTED_DOMAIN_CHILDREN) == (
        "doris_catalog",
        "doris_query",
        "doris_cluster",
        "doris_pipeline",
        "doris_search",
        "doris_governance",
        "doris_lakehouse",
        "doris_semantic",
    )
    assert Counter(feature.domain for feature in DORIS_FEATURE_MATRIX.features) == {
        "doris_catalog": 5,
        "doris_query": 7,
        "doris_cluster": 11,
        "doris_pipeline": 5,
        "doris_search": 4,
        "doris_governance": 8,
        "doris_lakehouse": 3,
        "doris_semantic": 12,
    }
    for domain, expected_children in EXPECTED_DOMAIN_CHILDREN.items():
        actual_children = tuple(
            feature.child_name
            for feature in DORIS_FEATURE_MATRIX.features
            if feature.domain == domain
        )
        assert actual_children == expected_children


def test_adbc_is_inside_query_and_variant_is_inside_lakehouse() -> None:
    query_children = EXPECTED_DOMAIN_CHILDREN["doris_query"]
    lakehouse_children = EXPECTED_DOMAIN_CHILDREN["doris_lakehouse"]

    assert "get_adbc_connection_info" in query_children
    assert "execute_adbc_query" in query_children
    assert "inspect_variant_column" in lakehouse_children
    assert "doris_adbc" not in EXPECTED_DOMAIN_CHILDREN
    execute_adbc = DORIS_FEATURE_MATRIX.get_feature(
        "doris_query",
        "execute_adbc_query",
    )
    assert execute_adbc.support_contract.variants[0].required_probes == (
        "adbc_driver_ready",
        "flight_sql_reachable",
        "adbc_release_maturity",
        "read_only_sql_guard_ready",
    )


def test_doris_2_x_uses_per_feature_gates_instead_of_a_global_rejection() -> None:
    baseline = DORIS_FEATURE_MATRIX.evaluate(
        domain="doris_catalog",
        child_name="list_tables",
        versions=_vector("2.0.0"),
    )
    adbc_20 = DORIS_FEATURE_MATRIX.evaluate(
        domain="doris_query",
        child_name="execute_adbc_query",
        versions=_vector("2.0.15"),
    )
    adbc_21 = DORIS_FEATURE_MATRIX.evaluate(
        domain="doris_query",
        child_name="execute_adbc_query",
        versions=_vector("2.1.0"),
    )
    variant_20 = DORIS_FEATURE_MATRIX.evaluate(
        domain="doris_lakehouse",
        child_name="inspect_variant_column",
        versions=_vector("2.0.15"),
    )
    variant_21 = DORIS_FEATURE_MATRIX.evaluate(
        domain="doris_lakehouse",
        child_name="inspect_variant_column",
        versions=_vector("2.1.0"),
    )

    assert baseline.compatible is True
    assert adbc_20.compatible is False
    assert adbc_20.reason_code == "VERSION_RANGE_NOT_MATCHED"
    assert adbc_21.compatible is True
    assert variant_20.compatible is False
    assert variant_21.compatible is True


def test_metricflow_consumer_operations_cover_the_official_command_surface() -> None:
    semantic_children = EXPECTED_DOMAIN_CHILDREN["doris_semantic"]

    assert semantic_children[4:] == (
        "list_metricflow_models",
        "get_metricflow_status",
        "list_metricflow_metrics",
        "get_metricflow_group_bys",
        "list_metricflow_saved_queries",
        "get_metricflow_dimension_values",
        "compile_metricflow_query",
        "execute_metricflow_query",
    )
    for child_name in semantic_children[4:]:
        feature = DORIS_FEATURE_MATRIX.get_feature(
            "doris_semantic",
            child_name,
        )
        variant = feature.support_contract.variants[0]
        assert variant.required_providers == ("metricflow_provider",)
        assert {
            "METRICFLOW_COMMANDS",
            "METRICFLOW_ENGINE",
        } <= set(variant.source_references)


def test_search_prefers_vector_hybrid_and_keeps_text_fallback() -> None:
    search = DORIS_FEATURE_MATRIX.get_feature(
        "doris_search",
        "search_data",
    )

    assert tuple(
        variant.name for variant in search.support_contract.variants
    ) == (
        "vector_hybrid_search",
        "inverted_text_search",
    )
    vector, text = search.support_contract.variants
    assert vector.supported_ranges == (">=4.0.0",)
    assert vector.required_probes == (
        "ann_index_and_metric_compatible",
        "inverted_index_and_search_syntax_ready",
    )
    assert vector.callable_when_degraded is True
    assert text.required_probes == (
        "inverted_index_and_search_syntax_ready",
    )
    assert text.callable_when_degraded is True


def test_lakehouse_prefers_4_1_capabilities_and_keeps_baseline_fallbacks() -> None:
    table_feature = DORIS_FEATURE_MATRIX.get_feature(
        "doris_lakehouse",
        "inspect_lakehouse_table",
    )
    variant_feature = DORIS_FEATURE_MATRIX.get_feature(
        "doris_lakehouse",
        "inspect_variant_column",
    )

    assert tuple(
        variant.name for variant in table_feature.support_contract.variants
    ) == (
        "lakehouse_lifecycle_4_1",
        "lakehouse_table_metadata",
    )
    table_advanced, table_baseline = table_feature.support_contract.variants
    assert table_advanced.supported_ranges == (">=4.1.0",)
    assert table_advanced.required_features == (
        "iceberg_deletion_vector",
        "iceberg_row_lineage",
    )
    assert table_advanced.callable_when_degraded is True
    assert table_baseline.supported_ranges == (">=2.0.0",)

    assert tuple(
        variant.name for variant in variant_feature.support_contract.variants
    ) == (
        "variant_advanced_4_1",
        "variant_type",
    )
    variant_advanced, variant_baseline = (
        variant_feature.support_contract.variants
    )
    assert variant_advanced.supported_ranges == (">=4.1.0",)
    assert variant_advanced.required_features == (
        "variant_sparse_sharding",
        "variant_sparse_cache",
        "variant_doc_mode",
        "storage_v3",
    )
    assert variant_advanced.callable_when_degraded is True
    assert variant_baseline.supported_ranges == (">=2.1.0",)


def test_every_contract_is_fail_closed_and_has_resolvable_sources() -> None:
    known_sources = {source.source_id for source in DORIS_FEATURE_MATRIX.sources}

    for feature in DORIS_FEATURE_MATRIX.features:
        contract = feature.support_contract
        assert contract.rule_id == feature.feature_id
        assert contract.unknown_is_callable is False
        assert contract.unavailable_behavior.value == "show_disabled"
        assert contract.tested_versions == ()
        for variant in contract.variants:
            assert variant.source_references
            assert set(variant.source_references) <= known_sources
            assert variant.required_probes


def test_sources_are_https_authorities_with_branch_ranges() -> None:
    for source in DORIS_FEATURE_MATRIX.sources:
        assert source.url.startswith("https://")
        assert source.applicable_ranges
        assert source.verified_on.isoformat() == "2026-08-01"
        for expression in source.applicable_ranges:
            assert DorisVersionRange(expression).expression == expression

    release_406 = DORIS_FEATURE_MATRIX.get_source("DORIS_RELEASE_4_0_6")
    assert release_406.pull_requests == ("#61004", "#61696")
    assert release_406.applicable_ranges == (">=4.0.6,<4.1.0",)

    release_412 = DORIS_FEATURE_MATRIX.get_source("DORIS_RELEASE_4_1_2")
    assert {"#61819", "#62077", "#63206"} == set(release_412.pull_requests)


def test_only_evidence_backed_targets_are_claimed_as_certified() -> None:
    assert PROJECT_MINIMUM_DORIS_VERSION == "2.0.0"
    assert DORIS_FEATURE_MATRIX.certification_targets == (CERTIFICATION_TARGET_VERSIONS)
    assert DORIS_FEATURE_MATRIX.certified_versions == ("4.0.5",)
    assert CERTIFIED_DORIS_VERSIONS == ("4.0.5",)
    assert DORIS_PATCH_CERTIFICATION_MATRIX.target_versions == (
        CERTIFICATION_TARGET_VERSIONS
    )
    assert tuple(
        record.version for record in DORIS_PATCH_CERTIFICATION_MATRIX.evidence
    ) == ("4.0.5",)
    assert (
        DORIS_PATCH_CERTIFICATION_MATRIX.evidence[0].evidence_sha256
        == "a8d63aa4b5070489e362cfbf57e793c9698f5d583c9cae19861eb73bca5c7a76"
    )
    assert {
        "DORIS_RELEASE_3_0_3",
        "DORIS_RELEASE_3_1_4",
        "DORIS_RELEASE_4_0_5",
        "DORIS_RELEASE_4_1_3",
    } <= {source.source_id for source in DORIS_FEATURE_MATRIX.sources}


def test_certification_uses_three_part_core_for_rc_and_ga_builds() -> None:
    rc_versions = _vector("4.0.5-rc01")
    ga_versions = _vector("4.0.5")
    rc_feature = DORIS_FEATURE_MATRIX.evaluate(
        domain="doris_catalog",
        child_name="list_tables",
        versions=rc_versions,
    )
    ga_feature = DORIS_FEATURE_MATRIX.evaluate(
        domain="doris_catalog",
        child_name="list_tables",
        versions=ga_versions,
    )
    rc_report = DORIS_PATCH_CERTIFICATION_MATRIX.evaluate(rc_versions)
    ga_report = DORIS_PATCH_CERTIFICATION_MATRIX.evaluate(ga_versions)

    assert rc_feature.certification_status is (
        VersionCertificationStatus.CERTIFIED
    )
    assert ga_feature.certification_status is (
        VersionCertificationStatus.CERTIFIED
    )
    assert rc_report.uniform_observed_version == "4.0.5"
    assert ga_report.uniform_observed_version == "4.0.5"
    assert rc_report.observed_fe_versions == ("4.0.5",)
    assert rc_report.observed_be_versions == ("4.0.5",)
    assert rc_report.status is VersionCertificationStatus.CERTIFIED
    assert ga_report.status is VersionCertificationStatus.CERTIFIED
    assert rc_report.evidence_ids == ("doris_4_0_5_linux_amd64",)
    assert ga_report.evidence_ids == rc_report.evidence_ids


def test_complete_real_host_evidence_certifies_its_three_part_patch() -> None:
    evidence = _certification_evidence()
    matrix = DorisPatchCertificationMatrix(
        minimum_supported_version="2.0.0",
        target_versions=CERTIFICATION_TARGET_VERSIONS,
        evidence=(evidence,),
    )
    report = matrix.evaluate(_vector("4.1.2-rc03"))

    assert matrix.certified_versions == ("4.1.2",)
    assert report.uniform_observed_version == "4.1.2"
    assert report.status is VersionCertificationStatus.CERTIFIED
    assert report.targeted is True
    assert report.certified is True
    assert report.evidence_ids == ("doris_4_1_2_linux_amd64",)


def test_patch_certification_fails_closed_for_unknown_or_mixed_components() -> None:
    unknown = DORIS_PATCH_CERTIFICATION_MATRIX.evaluate(
        DorisClusterVersionVector.from_comments(
            master_fe="Doris version doris-4.1.2",
            backends=(),
        )
    )
    mixed = DORIS_PATCH_CERTIFICATION_MATRIX.evaluate(
        _vector("4.1.2", backends=("4.1.1",))
    )

    assert unknown.status is VersionCertificationStatus.UNKNOWN
    assert unknown.reason_code == "PATCH_CERTIFICATION_COMPONENT_VERSION_UNKNOWN"
    assert mixed.status is VersionCertificationStatus.UNKNOWN
    assert mixed.reason_code == "PATCH_CERTIFICATION_MIXED_COMPONENT_VERSIONS"
    assert mixed.uniform_observed_version is None


def test_patch_evidence_rejects_incomplete_host_or_component_proof() -> None:
    evidence = _certification_evidence()
    payload = evidence.model_dump(mode="python")
    payload["cases"] = payload["cases"][:-1]
    with pytest.raises(
        ValidationError,
        match="at least 4 items|each transport and exposure",
    ):
        PatchCertificationEvidence.model_validate(payload)

    payload = evidence.model_dump(mode="python")
    payload["backend_version_comments"] = (
        "Doris version doris-4.1.1-43f06a5e26",
    )
    with pytest.raises(ValidationError, match="Doris core version 4.1.2"):
        PatchCertificationEvidence.model_validate(payload)


@pytest.mark.parametrize(
    ("expression", "matching", "not_matching"),
    [
        (">=3.0.0", "3.0.0-rc01", "2.1.9"),
        (">=4.0.6,<4.1.0", "4.0.7", "4.1.0"),
        ("==4.1.0", "4.1.0", "4.1.1"),
        (">4.1.0", "4.1.1", "4.1.0"),
        ("<=4.0.6", "4.0.6", "4.0.7"),
        ("<4.0.6", "4.0.5-rc02", "4.0.6-rc02"),
    ],
)
def test_version_range_operators(
    expression: str,
    matching: str,
    not_matching: str,
) -> None:
    version_range = DorisVersionRange(expression)

    assert version_range.contains(
        parse_doris_version_comment(f"Doris version doris-{matching}")
    )
    assert not version_range.contains(
        parse_doris_version_comment(f"Doris version doris-{not_matching}")
    )


def test_version_range_normalizes_spacing() -> None:
    version_range = DorisVersionRange(" >=4.0.6 , <4.1.0 ")

    assert version_range.expression == ">=4.0.6,<4.1.0"


@pytest.mark.parametrize(
    "expression",
    [
        "",
        "4.0.6",
        "=>4.0.6",
        ">=4.0",
        ">=4.0.6-rc01",
        ">=4.0.6,",
        ">=4.0.6,<4.0.6",
        ">=4.1.0,<4.0.0",
        "==4.0.6,==4.0.7",
        "==4.0.6,>4.0.6",
    ],
)
def test_invalid_or_contradictory_ranges_are_rejected(
    expression: str,
) -> None:
    with pytest.raises(ValueError):
        DorisVersionRange(expression)


def test_equal_bounds_can_be_inclusive_and_choose_stricter_duplicates() -> None:
    inclusive = DorisVersionRange(">=4.0.6,<=4.0.6")
    stricter_lower = DorisVersionRange(">=4.0.6,>4.0.6,<4.1.0")
    stricter_upper = DorisVersionRange("<=4.1.0,<4.1.0,>=4.0.0")

    stable_406 = parse_doris_version_comment("Doris version doris-4.0.6")
    stable_407 = parse_doris_version_comment("Doris version doris-4.0.7")
    stable_410 = parse_doris_version_comment("Doris version doris-4.1.0")

    assert inclusive.contains(stable_406)
    assert not stricter_lower.contains(stable_406)
    assert stricter_lower.contains(stable_407)
    assert not stricter_upper.contains(stable_410)


def test_unknown_version_never_matches_a_range() -> None:
    unknown = parse_doris_version_comment("Doris version unknown")

    assert DorisVersionRange(">=3.0.0").contains(unknown) is False


def test_version_range_uses_core_and_ignores_release_metadata() -> None:
    stable_range = DorisVersionRange(">=4.0.6")
    release_candidate = parse_doris_version_comment(
        "Doris version doris-4.0.6-rc03-43f06a5e26"
    )
    stable_with_commit = parse_doris_version_comment(
        "Doris version doris-4.0.6-abcdef1234"
    )

    assert stable_range.contains(release_candidate) is True
    assert stable_range.contains(stable_with_commit) is True
    assert DorisVersionRange("==4.0.6").contains(stable_with_commit) is True


def test_variant_exclusions_override_supported_ranges() -> None:
    variant = CapabilityVariant(
        name="branch_feature",
        supported_ranges=(">=4.0.0",),
        excluded_ranges=(">=4.1.0,<4.1.1",),
        required_probes=("branch_feature_probe",),
    )

    assert matching_version_ranges(
        variant,
        parse_doris_version_comment("Doris version doris-4.0.7"),
    ) == (">=4.0.0",)
    assert (
        matching_version_ranges(
            variant,
            parse_doris_version_comment("Doris version doris-4.1.0"),
        )
        == ()
    )
    assert (
        matching_version_ranges(
            variant,
            parse_doris_version_comment("Doris version unknown"),
        )
        == ()
    )


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("4.0.5", False),
        ("4.0.6", True),
        ("4.0.7", True),
        ("4.1.0-rc01", False),
        ("4.1.0", False),
        ("4.1.1", True),
        ("4.1.3", True),
    ],
)
def test_compaction_tracker_uses_non_monotonic_maintenance_ranges(
    version: str,
    expected: bool,
) -> None:
    result = DORIS_FEATURE_MATRIX.evaluate(
        domain="doris_cluster",
        child_name="get_compaction_status",
        versions=_vector(version),
        variant_name="compaction_task_tracker",
    )

    assert result.compatible is expected
    assert result.reason_code == (
        "VERSION_RANGE_MATCHED" if expected else "VERSION_RANGE_NOT_MATCHED"
    )
    if expected:
        assert result.matched_ranges in {
            (">=4.0.6,<4.1.0",),
            (">=4.1.1",),
        }
    else:
        assert result.matched_ranges == ()
    assert {
        "DORIS_RELEASE_4_0_6",
        "DORIS_RELEASE_4_1_1",
    } <= set(result.source_ids)


def test_compaction_child_keeps_a_degraded_legacy_variant() -> None:
    result = DORIS_FEATURE_MATRIX.evaluate(
        domain="doris_cluster",
        child_name="get_compaction_status",
        versions=_vector("4.0.5"),
    )

    assert result.compatible is True
    assert result.matched_variants == ("legacy_compaction_summary",)
    assert result.certification_status is VersionCertificationStatus.CERTIFIED
    assert result.certification_target is False
    assert result.certified is True


def test_resource_growth_declares_full_and_partial_evidence_variants() -> None:
    feature = DORIS_FEATURE_MATRIX.get_feature(
        "doris_cluster",
        "analyze_resource_growth",
    )

    assert tuple(
        variant.name for variant in feature.support_contract.variants
    ) == (
        "all_recorded_resource_history",
        "audit_resource_history",
        "partition_creation_history",
    )
    assert feature.support_contract.variants[1].callable_when_degraded is True
    assert feature.support_contract.variants[2].callable_when_degraded is True


def test_lineage_native_and_audit_paths_are_both_explicit() -> None:
    feature = DORIS_FEATURE_MATRIX.get_feature(
        "doris_governance",
        "trace_column_lineage",
    )
    variants = {variant.name: variant for variant in feature.support_contract.variants}

    assert variants["audit_sql_inference_primary"].supported_ranges == (
        ">=2.0.0,<4.0.6",
    )
    assert variants["native_lineage_events"].supported_ranges == (">=4.0.6",)
    assert variants["audit_sql_inference_fallback"].supported_ranges == (">=4.0.6",)
    assert variants["audit_sql_inference_fallback"].callable_when_degraded is True


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("4.1.0", False),
        ("4.1.1", False),
        ("4.1.2", False),
        ("4.1.3-rc01", True),
        ("4.1.3", True),
    ],
)
def test_python_udf_family_starts_at_4_1_3(
    version: str,
    expected: bool,
) -> None:
    result = DORIS_FEATURE_MATRIX.evaluate(
        domain="doris_governance",
        child_name="list_udfs",
        versions=_vector(version),
        variant_name="python_udf_family",
    )

    assert result.compatible is expected
    assert result.source_ids == ("DORIS_RELEASE_4_1_3",)


def test_native_lineage_requires_every_fe_to_reach_4_0_6() -> None:
    mixed = DORIS_FEATURE_MATRIX.evaluate(
        domain="doris_governance",
        child_name="trace_column_lineage",
        versions=_vector("4.0.7", followers=("4.0.5",)),
        variant_name="native_lineage_events",
    )
    uniform = DORIS_FEATURE_MATRIX.evaluate(
        domain="doris_governance",
        child_name="trace_column_lineage",
        versions=_vector("4.0.7", followers=("4.0.6",)),
        variant_name="native_lineage_events",
    )

    assert mixed.version_scope is CapabilityVersionScope.ALL_FE
    assert mixed.effective_version == "4.0.5"
    assert mixed.compatible is False
    assert uniform.effective_version == "4.0.6"
    assert uniform.compatible is True


def test_mixed_fe_be_patch_uses_conservative_all_component_version() -> None:
    result = DORIS_FEATURE_MATRIX.evaluate(
        domain="doris_cluster",
        child_name="list_active_tasks",
        versions=_vector(
            "4.1.2",
            followers=("4.1.1",),
            backends=("4.0.7", "4.1.2"),
        ),
        variant_name="unified_task_progress",
    )

    assert result.version_scope is CapabilityVersionScope.ALL_COMPONENTS
    assert result.raw_version == "Doris version doris-4.0.7"
    assert result.effective_version == "4.0.7"
    assert result.compatible is False


def test_master_fe_scope_does_not_inherit_an_unrelated_old_be_version() -> None:
    result = DORIS_FEATURE_MATRIX.evaluate(
        domain="doris_catalog",
        child_name="list_tables",
        versions=_vector("4.1.2", backends=("3.0.3",)),
    )

    assert result.version_scope is CapabilityVersionScope.MASTER_FE
    assert result.effective_version == "4.1.2"
    assert result.compatible is True


def test_table_size_uses_master_fe_metadata_with_unknown_backend_version() -> None:
    result = DORIS_FEATURE_MATRIX.evaluate(
        domain="doris_catalog",
        child_name="get_table_size",
        versions=DorisClusterVersionVector.from_comments(
            master_fe="Doris version doris-4.0.5",
            backends=(
                "Doris version doris-4.0.5",
                "",
            ),
        ),
    )

    assert result.version_scope is CapabilityVersionScope.MASTER_FE
    assert result.effective_version == "4.0.5"
    assert result.compatible is True


def test_query_diagnosis_uses_provider_with_master_fe_baseline() -> None:
    result = DORIS_FEATURE_MATRIX.evaluate(
        domain="doris_query",
        child_name="diagnose_query_performance",
        versions=_vector("4.0.5"),
    )

    assert result.version_scope is (
        CapabilityVersionScope.PROVIDER_WITH_MASTER_FE_BASELINE
    )
    assert result.effective_version == "4.0.5"
    assert result.compatible is True


@pytest.mark.parametrize(
    "child_name",
    [
        "execute_query",
        "explain_query",
        "get_query_profile",
    ],
)
def test_fe_query_entrypoints_ignore_unknown_backend_version(
    child_name: str,
) -> None:
    result = DORIS_FEATURE_MATRIX.evaluate(
        domain="doris_query",
        child_name=child_name,
        versions=DorisClusterVersionVector.from_comments(
            master_fe="Doris version doris-4.0.5",
            backends=(
                "Doris version doris-4.0.5",
                "",
            ),
        ),
    )

    assert result.version_scope is CapabilityVersionScope.MASTER_FE
    assert result.effective_version == "4.0.5"
    assert result.compatible is True


def test_missing_required_component_version_fails_closed() -> None:
    versions = DorisClusterVersionVector.from_comments(
        master_fe="Doris version doris-4.1.2",
        backends=(),
    )
    result = DORIS_FEATURE_MATRIX.evaluate(
        domain="doris_cluster",
        child_name="get_cache_status",
        versions=versions,
    )

    assert result.compatible is False
    assert result.effective_version is None
    assert result.reason_code == "DORIS_VERSION_UNKNOWN"
    assert result.certification_status is VersionCertificationStatus.UNKNOWN


def test_all_component_scope_requires_at_least_one_backend_observation() -> None:
    result = DORIS_FEATURE_MATRIX.evaluate(
        domain="doris_cluster",
        child_name="list_active_tasks",
        versions=DorisClusterVersionVector.from_comments(
            master_fe="Doris version doris-4.1.2",
            backends=(),
        ),
        variant_name="unified_task_progress",
    )

    assert result.compatible is False
    assert result.reason_code == "DORIS_VERSION_UNKNOWN"
    assert result.raw_version == "Doris version doris-4.1.2"
    assert result.observed_fe_version_comments == ("Doris version doris-4.1.2",)
    assert result.observed_be_version_comments == ()


def test_an_unparseable_component_version_fails_closed() -> None:
    result = DORIS_FEATURE_MATRIX.evaluate(
        domain="doris_governance",
        child_name="get_lineage_capability_status",
        versions=DorisClusterVersionVector.from_comments(
            master_fe="Doris version doris-4.0.7",
            follower_fes=("Doris version unknown",),
        ),
        variant_name="native_lineage_status",
    )

    assert result.compatible is False
    assert result.reason_code == "DORIS_VERSION_UNKNOWN"
    assert result.raw_version == "Doris version doris-4.0.7"
    assert result.observed_fe_version_comments == (
        "Doris version doris-4.0.7",
        "Doris version unknown",
    )


def test_version_below_2_0_0_is_rejected_before_child_evaluation() -> None:
    result = DORIS_FEATURE_MATRIX.evaluate(
        domain="doris_catalog",
        child_name="list_tables",
        versions=_vector("1.2.8"),
    )

    assert result.compatible is False
    assert result.reason_code == "DORIS_VERSION_BELOW_MINIMUM"
    assert result.minimum_supported_version == "2.0.0"


def test_target_patch_is_distinct_from_certified_patch() -> None:
    result = DORIS_FEATURE_MATRIX.evaluate(
        domain="doris_catalog",
        child_name="list_tables",
        versions=_vector("4.1.2"),
    )

    assert result.compatible is True
    assert result.certification_status is (
        VersionCertificationStatus.TARGET_UNCERTIFIED
    )
    assert result.certification_target is True
    assert result.certified is False


def test_version_outside_initial_certification_targets_is_not_certified() -> None:
    result = DORIS_FEATURE_MATRIX.evaluate(
        domain="doris_catalog",
        child_name="list_tables",
        versions=_vector("4.1.4"),
    )

    assert result.compatible is True
    assert result.certification_status is VersionCertificationStatus.OUTSIDE_TARGET
    assert result.certification_target is False
    assert result.certified is False


def test_semantic_children_require_explicit_model_reference_probes() -> None:
    for child_name in (
        "get_semantic_model_summary",
        "get_semantic_context",
        "get_semantic_mapping_status",
    ):
        feature = DORIS_FEATURE_MATRIX.get_feature(
            "doris_semantic",
            child_name,
        )
        assert "explicit_model_ref_valid" in (
            feature.support_contract.variants[0].required_probes
        )


def test_unknown_feature_source_and_feature_lookups_raise_key_error() -> None:
    with pytest.raises(KeyError, match="DORIS_NOT_REAL"):
        DORIS_FEATURE_MATRIX.get_source("DORIS_NOT_REAL")
    with pytest.raises(KeyError, match="doris_catalog.not_real"):
        DORIS_FEATURE_MATRIX.get_feature("doris_catalog", "not_real")
    with pytest.raises(KeyError, match="not_real"):
        DORIS_FEATURE_MATRIX.evaluate(
            domain="doris_catalog",
            child_name="list_tables",
            versions=_vector("4.1.2"),
            variant_name="not_real",
        )


def test_matrix_rejects_an_unknown_source_reference() -> None:
    payload = _matrix_payload()
    payload["features"][0]["support_contract"]["variants"][0]["source_references"] = (
        "DORIS_NOT_REAL",
    )

    with pytest.raises(ValidationError, match="unknown source IDs"):
        DorisFeatureMatrix.model_validate(payload)


def test_matrix_rejects_a_variant_without_source_ids() -> None:
    payload = _matrix_payload()
    payload["features"][0]["support_contract"]["variants"][0]["source_references"] = ()

    with pytest.raises(ValidationError, match="requires source IDs"):
        DorisFeatureMatrix.model_validate(payload)


def test_matrix_rejects_missing_or_reordered_children() -> None:
    payload = _matrix_payload()
    payload["features"] = payload["features"][:-1]

    with pytest.raises(ValidationError, match="8-domain/55-child"):
        DorisFeatureMatrix.model_validate(payload)


def test_matrix_rejects_invalid_contract_range() -> None:
    payload = _matrix_payload()
    payload["features"][0]["support_contract"]["variants"][0]["supported_ranges"] = (
        ">=4.0",
    )

    with pytest.raises(ValueError, match="version literal"):
        DorisFeatureMatrix.model_validate(payload)


def test_matrix_rejects_certification_outside_target_set() -> None:
    payload = _matrix_payload()
    payload["certified_versions"] = ("4.2.0",)

    with pytest.raises(ValidationError, match="must be certification targets"):
        DorisFeatureMatrix.model_validate(payload)


def test_matrix_rejects_a_prerelease_minimum() -> None:
    payload = _matrix_payload()
    payload["minimum_supported_version"] = "3.0.0-rc01"

    with pytest.raises(ValidationError, match="version literal"):
        DorisFeatureMatrix.model_validate(payload)


def test_a_real_certified_version_is_distinct_from_target_only() -> None:
    payload = _matrix_payload()
    payload["certified_versions"] = ("4.1.2",)
    matrix = DorisFeatureMatrix.model_validate(payload)

    result = matrix.evaluate(
        domain="doris_catalog",
        child_name="list_tables",
        versions=_vector("4.1.2"),
    )

    assert result.certification_status is VersionCertificationStatus.CERTIFIED
    assert result.certification_target is False
    assert result.certified is True


def test_matrix_rejects_duplicate_sources_and_features() -> None:
    source_payload = _matrix_payload()
    source_payload["sources"] = (
        *source_payload["sources"],
        source_payload["sources"][0],
    )
    with pytest.raises(ValidationError, match="feature source IDs"):
        DorisFeatureMatrix.model_validate(source_payload)

    feature_payload = _matrix_payload()
    feature_payload["features"] = (
        feature_payload["features"][0],
        feature_payload["features"][0],
        *feature_payload["features"][2:],
    )
    with pytest.raises(ValidationError, match="feature IDs"):
        DorisFeatureMatrix.model_validate(feature_payload)


def test_matrix_rejects_certification_and_rule_id_duplicates() -> None:
    target_payload = _matrix_payload()
    target_payload["certification_targets"] = ("4.1.2", "4.1.2")
    with pytest.raises(ValidationError, match="certification targets"):
        DorisFeatureMatrix.model_validate(target_payload)

    rule_payload = _matrix_payload()
    rule_payload["features"][1]["support_contract"]["rule_id"] = rule_payload[
        "features"
    ][0]["support_contract"]["rule_id"]
    with pytest.raises(ValidationError):
        DorisFeatureMatrix.model_validate(rule_payload)


def test_source_rejects_non_https_and_invalid_range() -> None:
    with pytest.raises(ValidationError, match="must use HTTPS"):
        FeatureSource(
            source_id="TEST_SOURCE",
            kind=FeatureSourceKind.DOCUMENTATION,
            title="Test source",
            url="http://example.test/docs",
            applicable_ranges=(">=3.0.0",),
            verified_on="2026-07-31",
        )

    with pytest.raises(ValueError, match="version literal"):
        FeatureSource(
            source_id="TEST_SOURCE",
            kind=FeatureSourceKind.DOCUMENTATION,
            title="Test source",
            url="https://example.test/docs",
            applicable_ranges=(">=3.0",),
            verified_on="2026-07-31",
        )


def test_defensive_literal_checks_reject_unparsed_versions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    unknown = parse_doris_version_comment("Doris version unknown")

    with pytest.raises(ValueError, match="Cannot format"):
        matrix_module._version_literal(unknown)

    monkeypatch.setattr(
        matrix_module,
        "parse_doris_version_comment",
        lambda _comment: unknown,
    )
    with pytest.raises(ValueError, match="Invalid Doris version literal"):
        matrix_module._parse_version_literal("4.1.2")


def test_matrix_wire_serialization_is_stable_and_immutable() -> None:
    first = DORIS_FEATURE_MATRIX.to_canonical_json()
    second = DORIS_FEATURE_MATRIX.to_canonical_json()

    assert first == second
    assert '"minimum_supported_version":"2.0.0"' in first
    with pytest.raises(ValidationError):
        DORIS_FEATURE_MATRIX.minimum_supported_version = "4.0.0"
