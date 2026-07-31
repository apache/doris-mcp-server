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

"""Machine-readable Doris child capability matrix and version range engine."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import date
from enum import StrEnum
from types import MappingProxyType
from typing import Annotated, Self

from pydantic import Field, StringConstraints, model_validator

from .domain_models import (
    CapabilityVariant,
    ChildSupportContract,
    ContractModel,
    Identifier,
    NonEmptyText,
    ReasonCode,
    UnavailableBehavior,
)
from .doris_version import DorisVersion, parse_doris_version_comment

PROJECT_MINIMUM_DORIS_VERSION = "3.0.0"
PROJECT_SUPPORTED_RANGE = f">={PROJECT_MINIMUM_DORIS_VERSION}"
SOURCE_VERIFIED_ON = date(2026, 7, 31)

CERTIFICATION_TARGET_VERSIONS = (
    "3.0.3",
    "3.1.4",
    "4.0.5",
    "4.0.6",
    "4.0.7",
    "4.1.0",
    "4.1.1",
    "4.1.2",
    "4.1.3",
)

# Certification is evidence-driven. V1-02 defines targets but certifies no patch.
CERTIFIED_DORIS_VERSIONS: tuple[str, ...] = ()

SourceIdentifier = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Z][A-Z0-9_]*$",
        strip_whitespace=True,
    ),
]
PullRequestReference = Annotated[
    str,
    StringConstraints(pattern=r"^#[1-9][0-9]*$", strip_whitespace=True),
]

_VERSION_LITERAL_PATTERN = re.compile(
    r"\d+\.\d+\.\d+(?:-(?:alpha|beta|rc)\d*)?",
    re.IGNORECASE,
)
_RANGE_CLAUSE_PATTERN = re.compile(
    r"(?P<operator>>=|<=|==|>|<)\s*(?P<version>.+)",
)


class VersionRangeOperator(StrEnum):
    """Supported comparison operators in a Doris version range clause."""

    GREATER_THAN_OR_EQUAL = ">="
    LESS_THAN_OR_EQUAL = "<="
    EQUAL = "=="
    GREATER_THAN = ">"
    LESS_THAN = "<"


@dataclass(frozen=True, slots=True)
class DorisVersionConstraint:
    """One parsed comparison inside a comma-separated version range."""

    operator: VersionRangeOperator
    version: DorisVersion

    def matches(self, candidate: DorisVersion) -> bool:
        comparison = candidate.compare(self.version)
        if self.operator is VersionRangeOperator.GREATER_THAN_OR_EQUAL:
            return comparison >= 0
        if self.operator is VersionRangeOperator.LESS_THAN_OR_EQUAL:
            return comparison <= 0
        if self.operator is VersionRangeOperator.EQUAL:
            return comparison == 0
        if self.operator is VersionRangeOperator.GREATER_THAN:
            return comparison > 0
        return comparison < 0


@dataclass(frozen=True, slots=True)
class DorisVersionRange:
    """An AND range such as ``>=4.0.6,<4.1.0``."""

    expression: str
    constraints: tuple[DorisVersionConstraint, ...] = field(
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        clauses = tuple(part.strip() for part in self.expression.split(","))
        if not clauses or any(not clause for clause in clauses):
            raise ValueError(f"Invalid Doris version range: {self.expression!r}")

        parsed = tuple(_parse_range_clause(clause) for clause in clauses)
        _validate_satisfiable_range(parsed, self.expression)
        normalized = ",".join(
            f"{constraint.operator.value}{_version_literal(constraint.version)}"
            for constraint in parsed
        )
        object.__setattr__(self, "expression", normalized)
        object.__setattr__(self, "constraints", parsed)

    def contains(self, candidate: DorisVersion) -> bool:
        if not candidate.is_parsed:
            return False
        return all(constraint.matches(candidate) for constraint in self.constraints)


class CapabilityVersionScope(StrEnum):
    """Doris component set that must satisfy a child version contract."""

    MASTER_FE = "master_fe"
    ALL_FE = "all_fe"
    ALL_BE = "all_be"
    ALL_COMPONENTS = "all_components"
    PROVIDER_WITH_MASTER_FE_BASELINE = "provider_with_master_fe_baseline"


@dataclass(frozen=True, slots=True)
class DorisClusterVersionVector:
    """Observed versions used for conservative mixed-patch evaluation."""

    master_fe: DorisVersion
    follower_fes: tuple[DorisVersion, ...] = ()
    backends: tuple[DorisVersion, ...] = ()

    @classmethod
    def from_comments(
        cls,
        *,
        master_fe: str,
        follower_fes: tuple[str, ...] = (),
        backends: tuple[str, ...] = (),
    ) -> Self:
        return cls(
            master_fe=parse_doris_version_comment(master_fe),
            follower_fes=tuple(
                parse_doris_version_comment(comment) for comment in follower_fes
            ),
            backends=tuple(
                parse_doris_version_comment(comment) for comment in backends
            ),
        )

    def effective_version(
        self,
        scope: CapabilityVersionScope,
    ) -> DorisVersion | None:
        versions: tuple[DorisVersion, ...]
        if scope in {
            CapabilityVersionScope.MASTER_FE,
            CapabilityVersionScope.PROVIDER_WITH_MASTER_FE_BASELINE,
        }:
            versions = (self.master_fe,)
        elif scope is CapabilityVersionScope.ALL_FE:
            versions = (self.master_fe, *self.follower_fes)
        elif scope is CapabilityVersionScope.ALL_BE:
            versions = self.backends
        else:
            if not self.backends:
                return None
            versions = (self.master_fe, *self.follower_fes, *self.backends)
        return _minimum_parsed_version(versions)


class FeatureSourceKind(StrEnum):
    """Authority type recorded for a feature source."""

    RELEASE_NOTE = "release_note"
    DOCUMENTATION = "documentation"
    PROVIDER_SPECIFICATION = "provider_specification"


class FeatureSource(ContractModel):
    """Stable authority record referenced by capability variants."""

    source_id: SourceIdentifier
    kind: FeatureSourceKind
    title: NonEmptyText
    url: NonEmptyText
    applicable_ranges: Annotated[
        tuple[NonEmptyText, ...],
        Field(min_length=1),
    ]
    pull_requests: tuple[PullRequestReference, ...] = ()
    verified_on: date

    @model_validator(mode="after")
    def _validate_source(self) -> Self:
        if not self.url.startswith("https://"):
            raise ValueError("feature source URL must use HTTPS")
        _require_unique(self.applicable_ranges, "source applicable ranges")
        _require_unique(self.pull_requests, "source pull requests")
        for expression in self.applicable_ranges:
            DorisVersionRange(expression)
        return self


class ChildFeatureDefinition(ContractModel):
    """Version-facing matrix row for one exact hierarchical child tool."""

    domain: Identifier
    child_name: Identifier
    version_scope: CapabilityVersionScope
    support_contract: ChildSupportContract

    @property
    def feature_id(self) -> str:
        return f"{self.domain}.{self.child_name}"

    @model_validator(mode="after")
    def _validate_rule_id(self) -> Self:
        if self.support_contract.rule_id != self.feature_id:
            raise ValueError("support contract rule_id must equal the feature ID")
        return self


class VersionCertificationStatus(StrEnum):
    """Certification relationship for one exact observed Doris patch."""

    CERTIFIED = "certified"
    TARGET_UNCERTIFIED = "target_uncertified"
    OUTSIDE_TARGET = "outside_target"
    UNKNOWN = "unknown"


class FeatureVersionEvaluation(ContractModel):
    """Deterministic version-only result, before runtime probes and policy."""

    feature_id: NonEmptyText
    requested_variant: Identifier | None = None
    version_scope: CapabilityVersionScope
    raw_version: str
    observed_fe_version_comments: tuple[str, ...]
    observed_be_version_comments: tuple[str, ...]
    effective_version: str | None
    compatible: bool
    reason_code: ReasonCode
    matched_variants: tuple[Identifier, ...]
    matched_ranges: tuple[NonEmptyText, ...]
    source_ids: tuple[SourceIdentifier, ...]
    certification_status: VersionCertificationStatus
    certification_target: bool
    certified: bool
    minimum_supported_version: NonEmptyText


EXPECTED_DOMAIN_CHILDREN: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "doris_catalog": (
            "list_catalogs",
            "list_databases",
            "list_tables",
            "get_table_context",
            "get_table_size",
        ),
        "doris_query": (
            "execute_query",
            "explain_query",
            "get_query_profile",
            "diagnose_query_performance",
            "list_slow_queries",
            "get_adbc_connection_info",
            "execute_adbc_query",
        ),
        "doris_cluster": (
            "get_cluster_overview",
            "list_cluster_nodes",
            "list_active_tasks",
            "get_monitoring_metrics",
            "get_memory_stats",
            "get_cache_status",
            "get_compaction_status",
            "get_workload_group_status",
            "get_compute_group_status",
            "analyze_resource_growth",
            "get_runtime_capabilities",
        ),
        "doris_pipeline": (
            "get_ingestion_status",
            "diagnose_ingestion",
            "get_materialized_view_status",
            "monitor_data_freshness",
            "analyze_data_dependencies",
        ),
        "doris_search": (
            "search_data",
            "preview_text_analysis",
            "inspect_search_indexes",
            "diagnose_search_query",
        ),
        "doris_governance": (
            "analyze_columns",
            "analyze_table_storage",
            "get_lineage_capability_status",
            "trace_column_lineage",
            "analyze_data_access_patterns",
            "get_recent_audit_logs",
            "list_udfs",
            "get_auth_mapping_status",
        ),
        "doris_lakehouse": (
            "inspect_external_catalog",
            "inspect_lakehouse_table",
            "inspect_variant_column",
        ),
        "doris_semantic": (
            "list_semantic_models",
            "get_semantic_model_summary",
            "get_semantic_context",
            "get_semantic_mapping_status",
        ),
    }
)


class DorisFeatureMatrix(ContractModel):
    """Complete version policy for the 1.0.0 hierarchical read-only surface."""

    minimum_supported_version: NonEmptyText
    certification_targets: Annotated[
        tuple[NonEmptyText, ...],
        Field(min_length=1),
    ]
    certified_versions: tuple[NonEmptyText, ...]
    sources: Annotated[tuple[FeatureSource, ...], Field(min_length=1)]
    features: Annotated[tuple[ChildFeatureDefinition, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def _validate_matrix(self) -> Self:
        minimum = _parse_version_literal(self.minimum_supported_version)
        if minimum.prerelease is not None:
            raise ValueError("minimum supported version must be stable")

        target_versions = tuple(
            _version_literal(_parse_version_literal(value))
            for value in self.certification_targets
        )
        certified_versions = tuple(
            _version_literal(_parse_version_literal(value))
            for value in self.certified_versions
        )
        _require_unique(target_versions, "certification targets")
        _require_unique(certified_versions, "certified versions")
        if not set(certified_versions).issubset(target_versions):
            raise ValueError("certified versions must be certification targets")

        source_ids = tuple(source.source_id for source in self.sources)
        _require_unique(source_ids, "feature source IDs")
        known_sources = set(source_ids)

        feature_ids = tuple(feature.feature_id for feature in self.features)
        rule_ids = tuple(feature.support_contract.rule_id for feature in self.features)
        _require_unique(feature_ids, "feature IDs")
        _require_unique(rule_ids, "support contract rule IDs")

        actual_domains: dict[str, list[str]] = {}
        for feature in self.features:
            actual_domains.setdefault(feature.domain, []).append(feature.child_name)
            for variant in feature.support_contract.variants:
                if not variant.source_references:
                    raise ValueError(
                        f"{feature.feature_id}.{variant.name} requires source IDs"
                    )
                unknown_sources = set(variant.source_references) - known_sources
                if unknown_sources:
                    raise ValueError(
                        f"{feature.feature_id}.{variant.name} has unknown source IDs: "
                        f"{sorted(unknown_sources)!r}"
                    )
                for expression in (
                    *variant.supported_ranges,
                    *variant.excluded_ranges,
                ):
                    DorisVersionRange(expression)

        expected = {
            domain: tuple(children)
            for domain, children in EXPECTED_DOMAIN_CHILDREN.items()
        }
        actual = {
            domain: tuple(children) for domain, children in actual_domains.items()
        }
        if actual != expected:
            raise ValueError(
                "feature matrix must contain the exact ordered 8-domain/47-child "
                "contract"
            )
        return self

    def get_feature(self, domain: str, child_name: str) -> ChildFeatureDefinition:
        feature_id = f"{domain}.{child_name}"
        for feature in self.features:
            if feature.feature_id == feature_id:
                return feature
        raise KeyError(feature_id)

    def get_source(self, source_id: str) -> FeatureSource:
        for source in self.sources:
            if source.source_id == source_id:
                return source
        raise KeyError(source_id)

    def evaluate(
        self,
        *,
        domain: str,
        child_name: str,
        versions: DorisClusterVersionVector,
        variant_name: str | None = None,
    ) -> FeatureVersionEvaluation:
        feature = self.get_feature(domain, child_name)
        variants = feature.support_contract.variants
        if variant_name is not None:
            variants = tuple(
                variant for variant in variants if variant.name == variant_name
            )
            if not variants:
                raise KeyError(f"{feature.feature_id}.{variant_name}")

        effective = versions.effective_version(feature.version_scope)
        source_ids = _ordered_unique(
            source for variant in variants for source in variant.source_references
        )
        if effective is None:
            return _evaluation(
                feature=feature,
                variant_name=variant_name,
                versions=versions,
                effective=None,
                compatible=False,
                reason_code="DORIS_VERSION_UNKNOWN",
                source_ids=source_ids,
                matrix=self,
            )

        minimum = _parse_version_literal(self.minimum_supported_version)
        if effective.compare(minimum) < 0:
            return _evaluation(
                feature=feature,
                variant_name=variant_name,
                versions=versions,
                effective=effective,
                compatible=False,
                reason_code="DORIS_VERSION_BELOW_MINIMUM",
                source_ids=source_ids,
                matrix=self,
            )

        matched_variants: list[str] = []
        matched_ranges: list[str] = []
        matched_sources: list[str] = []
        for variant in variants:
            ranges = matching_version_ranges(variant, effective)
            if not ranges:
                continue
            matched_variants.append(variant.name)
            matched_ranges.extend(ranges)
            matched_sources.extend(variant.source_references)

        compatible = bool(matched_variants)
        return _evaluation(
            feature=feature,
            variant_name=variant_name,
            versions=versions,
            effective=effective,
            compatible=compatible,
            reason_code=(
                "VERSION_RANGE_MATCHED" if compatible else "VERSION_RANGE_NOT_MATCHED"
            ),
            matched_variants=tuple(matched_variants),
            matched_ranges=_ordered_unique(matched_ranges),
            source_ids=(_ordered_unique(matched_sources) if compatible else source_ids),
            matrix=self,
        )


def _parse_range_clause(clause: str) -> DorisVersionConstraint:
    match = _RANGE_CLAUSE_PATTERN.fullmatch(clause)
    if match is None:
        raise ValueError(f"Invalid Doris version range clause: {clause!r}")
    version = _parse_version_literal(match.group("version").strip())
    return DorisVersionConstraint(
        operator=VersionRangeOperator(match.group("operator")),
        version=version,
    )


def _parse_version_literal(value: str) -> DorisVersion:
    if _VERSION_LITERAL_PATTERN.fullmatch(value) is None:
        raise ValueError(f"Invalid Doris version literal: {value!r}")
    parsed = parse_doris_version_comment(f"Doris version doris-{value}")
    if not parsed.is_parsed:
        raise ValueError(f"Invalid Doris version literal: {value!r}")
    return parsed


def _version_literal(version: DorisVersion) -> str:
    core = version.core
    if core is None:
        raise ValueError("Cannot format an unparsed Doris version")
    return f"{core}-{version.prerelease}" if version.prerelease else core


def _minimum_parsed_version(
    versions: tuple[DorisVersion, ...],
) -> DorisVersion | None:
    if not versions or any(not version.is_parsed for version in versions):
        return None
    minimum = versions[0]
    for version in versions[1:]:
        if version.compare(minimum) < 0:
            minimum = version
    return minimum


def matching_version_ranges(
    variant: CapabilityVariant,
    version: DorisVersion,
) -> tuple[str, ...]:
    """Return supported range expressions after applying exclusions."""
    if not version.is_parsed:
        return ()
    excluded = any(
        DorisVersionRange(expression).contains(version)
        for expression in variant.excluded_ranges
    )
    if excluded:
        return ()
    return tuple(
        expression
        for expression in variant.supported_ranges
        if DorisVersionRange(expression).contains(version)
    )


def _validate_satisfiable_range(
    constraints: tuple[DorisVersionConstraint, ...],
    expression: str,
) -> None:
    equal_versions = tuple(
        constraint.version
        for constraint in constraints
        if constraint.operator is VersionRangeOperator.EQUAL
    )
    if equal_versions:
        reference = equal_versions[0]
        if any(version.compare(reference) != 0 for version in equal_versions[1:]):
            raise ValueError(f"Contradictory Doris version range: {expression!r}")
        if not all(constraint.matches(reference) for constraint in constraints):
            raise ValueError(f"Contradictory Doris version range: {expression!r}")
        return

    lower: DorisVersionConstraint | None = None
    upper: DorisVersionConstraint | None = None
    for constraint in constraints:
        if constraint.operator in {
            VersionRangeOperator.GREATER_THAN,
            VersionRangeOperator.GREATER_THAN_OR_EQUAL,
        }:
            if lower is None or constraint.version.compare(lower.version) > 0:
                lower = constraint
            elif (
                constraint.version.compare(lower.version) == 0
                and constraint.operator is VersionRangeOperator.GREATER_THAN
            ):
                lower = constraint
        elif constraint.operator in {
            VersionRangeOperator.LESS_THAN,
            VersionRangeOperator.LESS_THAN_OR_EQUAL,
        }:
            if upper is None or constraint.version.compare(upper.version) < 0:
                upper = constraint
            elif (
                constraint.version.compare(upper.version) == 0
                and constraint.operator is VersionRangeOperator.LESS_THAN
            ):
                upper = constraint

    if lower is None or upper is None:
        return
    comparison = lower.version.compare(upper.version)
    strict_boundary = (
        lower.operator is VersionRangeOperator.GREATER_THAN
        or upper.operator is VersionRangeOperator.LESS_THAN
    )
    if comparison > 0 or (comparison == 0 and strict_boundary):
        raise ValueError(f"Contradictory Doris version range: {expression!r}")


def _ordered_unique(values: Iterable[object]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(str(value) for value in values))


def _certification_status(
    version: DorisVersion | None,
    matrix: DorisFeatureMatrix,
) -> VersionCertificationStatus:
    if version is None:
        return VersionCertificationStatus.UNKNOWN
    literal = _version_literal(version)
    if literal in matrix.certified_versions:
        return VersionCertificationStatus.CERTIFIED
    if literal in matrix.certification_targets:
        return VersionCertificationStatus.TARGET_UNCERTIFIED
    return VersionCertificationStatus.OUTSIDE_TARGET


def _evaluation(
    *,
    feature: ChildFeatureDefinition,
    variant_name: str | None,
    versions: DorisClusterVersionVector,
    effective: DorisVersion | None,
    compatible: bool,
    reason_code: str,
    source_ids: tuple[str, ...],
    matrix: DorisFeatureMatrix,
    matched_variants: tuple[str, ...] = (),
    matched_ranges: tuple[str, ...] = (),
) -> FeatureVersionEvaluation:
    certification_status = _certification_status(effective, matrix)
    return FeatureVersionEvaluation(
        feature_id=feature.feature_id,
        requested_variant=variant_name,
        version_scope=feature.version_scope,
        raw_version=(
            effective.raw if effective is not None else versions.master_fe.raw
        ),
        observed_fe_version_comments=(
            versions.master_fe.raw,
            *(version.raw for version in versions.follower_fes),
        ),
        observed_be_version_comments=tuple(
            version.raw for version in versions.backends
        ),
        effective_version=effective.normalized if effective is not None else None,
        compatible=compatible,
        reason_code=reason_code,
        matched_variants=matched_variants,
        matched_ranges=matched_ranges,
        source_ids=source_ids,
        certification_status=certification_status,
        certification_target=(
            certification_status is VersionCertificationStatus.TARGET_UNCERTIFIED
        ),
        certified=certification_status is VersionCertificationStatus.CERTIFIED,
        minimum_supported_version=matrix.minimum_supported_version,
    )


def _require_unique(values: tuple[str, ...], label: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must not contain duplicates")


def _source(
    source_id: str,
    kind: FeatureSourceKind,
    title: str,
    url: str,
    *applicable_ranges: str,
    pull_requests: tuple[str, ...] = (),
) -> FeatureSource:
    return FeatureSource(
        source_id=source_id,
        kind=kind,
        title=title,
        url=url,
        applicable_ranges=applicable_ranges or (PROJECT_SUPPORTED_RANGE,),
        pull_requests=pull_requests,
        verified_on=SOURCE_VERIFIED_ON,
    )


FEATURE_SOURCES = (
    _source(
        "DORIS_DOCS_3X",
        FeatureSourceKind.DOCUMENTATION,
        "Apache Doris 3.x Documentation",
        "https://doris.apache.org/docs/3.x/",
        ">=3.0.0,<4.0.0",
    ),
    _source(
        "DORIS_DOCS_4X",
        FeatureSourceKind.DOCUMENTATION,
        "Apache Doris 4.x Documentation",
        "https://doris.apache.org/docs/4.x/",
        ">=4.0.0",
    ),
    _source(
        "DORIS_RELEASE_3_0_3",
        FeatureSourceKind.RELEASE_NOTE,
        "Apache Doris 3.0.3 Release Notes",
        "https://doris.apache.org/docs/3.x/releasenotes/v3.0/release-3.0.3/",
        "==3.0.3",
    ),
    _source(
        "DORIS_RELEASE_3_1_4",
        FeatureSourceKind.RELEASE_NOTE,
        "Apache Doris 3.1.4 Release Notes",
        "https://doris.apache.org/docs/4.x/releasenotes/v3.1/release-3.1.4/",
        "==3.1.4",
    ),
    _source(
        "DORIS_RELEASE_4_0_0",
        FeatureSourceKind.RELEASE_NOTE,
        "Apache Doris 4.0.0 Release Notes",
        "https://doris.apache.org/releases/v4.0/release-4.0.0/",
        ">=4.0.0",
    ),
    _source(
        "DORIS_RELEASE_4_0_5",
        FeatureSourceKind.RELEASE_NOTE,
        "Apache Doris 4.0.5 Release Notes",
        "https://doris.apache.org/releases/v4.0/release-4.0.5/",
        "==4.0.5",
    ),
    _source(
        "DORIS_RELEASE_4_0_6",
        FeatureSourceKind.RELEASE_NOTE,
        "Apache Doris 4.0.6 Release Notes",
        "https://doris.apache.org/releases/v4.0/release-4.0.6/",
        ">=4.0.6,<4.1.0",
        pull_requests=("#61004", "#61696"),
    ),
    _source(
        "DORIS_RELEASE_4_0_7",
        FeatureSourceKind.RELEASE_NOTE,
        "Apache Doris 4.0.7 Release Notes",
        "https://doris.apache.org/releases/v4.0/release-4.0.7/",
        ">=4.0.7,<4.1.0",
        pull_requests=(
            "#62141",
            "#63206",
            "#63576",
            "#63654",
            "#64381",
            "#64569",
            "#64742",
        ),
    ),
    _source(
        "DORIS_RELEASE_4_1_0",
        FeatureSourceKind.RELEASE_NOTE,
        "Apache Doris 4.1.0 Release Notes",
        "https://doris.apache.org/releases/v4.1/release-4.1.0/",
        ">=4.1.0",
    ),
    _source(
        "DORIS_RELEASE_4_1_1",
        FeatureSourceKind.RELEASE_NOTE,
        "Apache Doris 4.1.1 Release Notes",
        "https://doris.apache.org/docs/4.x/releasenotes/v4.1/release-4.1.1/",
        ">=4.1.1",
        pull_requests=("#60567", "#61696"),
    ),
    _source(
        "DORIS_RELEASE_4_1_2",
        FeatureSourceKind.RELEASE_NOTE,
        "Apache Doris 4.1.2 Release Notes",
        "https://doris.apache.org/releases/v4.1/release-4.1.2/",
        ">=4.1.2",
        pull_requests=("#61819", "#62077", "#63206"),
    ),
    _source(
        "DORIS_RELEASE_4_1_3",
        FeatureSourceKind.RELEASE_NOTE,
        "Apache Doris 4.1.3 Release Notes",
        "https://doris.apache.org/releases/v4.1/release-4.1.3/",
        ">=4.1.3",
        pull_requests=("#63387",),
    ),
    _source(
        "DORIS_LINEAGE_GUIDE",
        FeatureSourceKind.DOCUMENTATION,
        "Apache Doris Data Lineage Technical Guide",
        "https://doris.apache.org/docs/4.x/data-governance/data-lineage/",
        ">=4.0.6",
        pull_requests=("#61004",),
    ),
    _source(
        "DORIS_LINEAGE_PLUGIN_GUIDE",
        FeatureSourceKind.DOCUMENTATION,
        "Apache Doris Lineage Plugin Development Guide",
        (
            "https://doris.apache.org/community/developer-guide/"
            "data-lineage-plugin-development/"
        ),
        ">=4.0.6",
        pull_requests=("#61004",),
    ),
    _source(
        "ARROW_ADBC_FLIGHT_SQL",
        FeatureSourceKind.PROVIDER_SPECIFICATION,
        "Apache Arrow ADBC Flight SQL Driver",
        "https://arrow.apache.org/adbc/current/driver/flight_sql.html",
        PROJECT_SUPPORTED_RANGE,
    ),
    _source(
        "APACHE_OSSIE_CORE_SPEC",
        FeatureSourceKind.PROVIDER_SPECIFICATION,
        "Apache Ossie Core Specification",
        (
            "https://github.com/apache/ossie/blob/"
            "9ffc3be3886e82fddc9bbf28722440864644d371/core-spec/spec.md"
        ),
        PROJECT_SUPPORTED_RANGE,
    ),
)


def _variant(
    name: str,
    *,
    ranges: tuple[str, ...] = (PROJECT_SUPPORTED_RANGE,),
    excluded_ranges: tuple[str, ...] = (),
    deployment_modes: tuple[str, ...] = (),
    features: tuple[str, ...] = (),
    system_objects: tuple[str, ...] = (),
    endpoints: tuple[str, ...] = (),
    providers: tuple[str, ...] = (),
    probes: tuple[str, ...],
    evidence_quality: str = "native",
    callable_when_degraded: bool = False,
    sources: tuple[str, ...] = ("DORIS_DOCS_3X", "DORIS_DOCS_4X"),
) -> CapabilityVariant:
    return CapabilityVariant(
        name=name,
        supported_ranges=ranges,
        excluded_ranges=excluded_ranges,
        deployment_modes=deployment_modes,
        required_features=features,
        required_system_objects=system_objects,
        required_endpoints=endpoints,
        required_providers=providers,
        required_probes=probes,
        evidence_quality=evidence_quality,
        callable_when_degraded=callable_when_degraded,
        source_references=sources,
    )


def _feature(
    domain: str,
    child_name: str,
    scope: CapabilityVersionScope,
    *variants: CapabilityVariant,
) -> ChildFeatureDefinition:
    return ChildFeatureDefinition(
        domain=domain,
        child_name=child_name,
        version_scope=scope,
        support_contract=ChildSupportContract(
            rule_id=f"{domain}.{child_name}",
            variants=variants,
            unavailable_behavior=UnavailableBehavior.SHOW_DISABLED,
            unknown_is_callable=False,
            tested_versions=(),
        ),
    )


M = CapabilityVersionScope.MASTER_FE
F = CapabilityVersionScope.ALL_FE
B = CapabilityVersionScope.ALL_BE
A = CapabilityVersionScope.ALL_COMPONENTS
P = CapabilityVersionScope.PROVIDER_WITH_MASTER_FE_BASELINE

FEATURE_DEFINITIONS = (
    _feature(
        "doris_catalog",
        "list_catalogs",
        M,
        _variant("catalog_metadata", probes=("catalog_metadata_readable",)),
    ),
    _feature(
        "doris_catalog",
        "list_databases",
        M,
        _variant("database_metadata", probes=("database_metadata_readable",)),
    ),
    _feature(
        "doris_catalog",
        "list_tables",
        M,
        _variant("table_metadata", probes=("table_metadata_readable",)),
    ),
    _feature(
        "doris_catalog",
        "get_table_context",
        M,
        _variant(
            "base_sections",
            system_objects=("information_schema.columns",),
            probes=("table_context_sections_readable",),
        ),
        _variant(
            "vector_search_metadata",
            ranges=(">=4.0.0",),
            features=("ann_index", "bm25_search"),
            probes=("search_index_metadata_readable",),
            sources=("DORIS_RELEASE_4_0_0",),
        ),
        _variant(
            "variant_v3_metadata",
            ranges=(">=4.1.0",),
            features=("variant", "storage_v3"),
            probes=("variant_table_metadata_readable",),
            sources=("DORIS_RELEASE_4_1_0",),
        ),
    ),
    _feature(
        "doris_catalog",
        "get_table_size",
        M,
        _variant(
            "partition_statistics",
            probes=("table_partition_statistics_readable",),
            callable_when_degraded=True,
        ),
    ),
    _feature(
        "doris_query",
        "execute_query",
        M,
        _variant(
            "mysql_read_only",
            probes=("read_only_sql_guard_ready", "query_execution_readable"),
        ),
    ),
    _feature(
        "doris_query",
        "explain_query",
        M,
        _variant("base_explain", probes=("explain_output_readable",)),
        _variant(
            "search_plan_facets",
            ranges=(">=4.0.0",),
            features=("ann_index", "hybrid_search"),
            probes=("search_plan_facets_readable",),
            sources=("DORIS_RELEASE_4_0_0",),
        ),
    ),
    _feature(
        "doris_query",
        "get_query_profile",
        M,
        _variant(
            "query_profile",
            endpoints=("fe_profile_api",),
            probes=("query_profile_api_readable",),
        ),
    ),
    _feature(
        "doris_query",
        "diagnose_query_performance",
        P,
        _variant(
            "deterministic_query_diagnosis",
            providers=("query_evidence_provider",),
            probes=("explain_readable", "profile_or_audit_readable"),
            evidence_quality="composite",
            callable_when_degraded=True,
        ),
    ),
    _feature(
        "doris_query",
        "list_slow_queries",
        M,
        _variant(
            "audit_slow_queries",
            providers=("audit_log_provider",),
            probes=("audit_log_readable",),
            evidence_quality="recorded",
        ),
    ),
    _feature(
        "doris_query",
        "get_adbc_connection_info",
        P,
        _variant(
            "adbc_flight_sql",
            endpoints=("flight_sql",),
            providers=("adbc_provider",),
            probes=("adbc_driver_ready", "flight_sql_reachable"),
            sources=("ARROW_ADBC_FLIGHT_SQL",),
        ),
    ),
    _feature(
        "doris_query",
        "execute_adbc_query",
        P,
        _variant(
            "adbc_read_only",
            endpoints=("flight_sql",),
            providers=("adbc_provider",),
            probes=(
                "adbc_driver_ready",
                "flight_sql_reachable",
                "read_only_sql_guard_ready",
            ),
            sources=("ARROW_ADBC_FLIGHT_SQL",),
        ),
    ),
    _feature(
        "doris_cluster",
        "get_cluster_overview",
        A,
        _variant(
            "cluster_summary",
            probes=("cluster_components_discoverable",),
            evidence_quality="composite",
            callable_when_degraded=True,
        ),
    ),
    _feature(
        "doris_cluster",
        "list_cluster_nodes",
        A,
        _variant("cluster_nodes", probes=("fe_be_node_metadata_readable",)),
    ),
    _feature(
        "doris_cluster",
        "list_active_tasks",
        A,
        _variant(
            "unified_task_progress",
            ranges=(">=4.1.1",),
            probes=("unified_task_progress_readable",),
            sources=("DORIS_RELEASE_4_1_1",),
        ),
        _variant(
            "legacy_task_views",
            probes=("legacy_task_views_readable",),
            callable_when_degraded=True,
        ),
    ),
    _feature(
        "doris_cluster",
        "get_monitoring_metrics",
        A,
        _variant(
            "observability_4_0_7",
            ranges=(">=4.0.7,<4.1.0",),
            features=(
                "connection_limit_metrics",
                "routine_load_metrics",
                "file_cache_queue_metrics",
            ),
            probes=("enhanced_metrics_present",),
            sources=("DORIS_RELEASE_4_0_7",),
        ),
        _variant(
            "base_metrics",
            endpoints=("fe_metrics", "be_metrics"),
            probes=("metrics_endpoints_readable",),
        ),
    ),
    _feature(
        "doris_cluster",
        "get_memory_stats",
        A,
        _variant(
            "memory_trackers",
            endpoints=("be_metrics",),
            probes=("memory_tracker_metrics_readable",),
            callable_when_degraded=True,
        ),
    ),
    _feature(
        "doris_cluster",
        "get_cache_status",
        B,
        _variant(
            "advanced_cache_types",
            ranges=(">=4.1.0",),
            features=("condition_cache", "parquet_page_cache"),
            probes=("advanced_cache_metrics_present",),
            sources=("DORIS_RELEASE_4_1_0",),
        ),
        _variant(
            "file_cache_queue_metrics",
            ranges=(">=4.0.7,<4.1.0",),
            probes=("file_cache_queue_metrics_present",),
            sources=("DORIS_RELEASE_4_0_7",),
        ),
        _variant(
            "file_cache",
            system_objects=("information_schema.file_cache_statistics",),
            probes=("file_cache_metrics_readable",),
        ),
    ),
    _feature(
        "doris_cluster",
        "get_compaction_status",
        B,
        _variant(
            "compaction_task_tracker",
            ranges=(">=4.0.6,<4.1.0", ">=4.1.1"),
            excluded_ranges=(">=4.1.0-alpha0,<4.1.1",),
            system_objects=("information_schema.doris_be_compaction_tasks",),
            probes=("compaction_system_table_or_http_api",),
            sources=("DORIS_RELEASE_4_0_6", "DORIS_RELEASE_4_1_1"),
        ),
        _variant(
            "legacy_compaction_summary",
            probes=("legacy_compaction_status_readable",),
            evidence_quality="summary",
            callable_when_degraded=True,
        ),
    ),
    _feature(
        "doris_cluster",
        "get_workload_group_status",
        A,
        _variant(
            "workload_group_metrics",
            probes=("workload_group_metadata_and_metrics_readable",),
        ),
    ),
    _feature(
        "doris_cluster",
        "get_compute_group_status",
        A,
        _variant(
            "compute_group",
            deployment_modes=("cloud", "shared_data"),
            probes=("compute_group_metadata_readable",),
        ),
    ),
    _feature(
        "doris_cluster",
        "analyze_resource_growth",
        A,
        _variant(
            "historical_resource_metrics",
            providers=("metrics_history_provider",),
            probes=("metrics_history_readable",),
            evidence_quality="recorded",
        ),
    ),
    _feature(
        "doris_cluster",
        "get_runtime_capabilities",
        M,
        _variant(
            "capability_snapshot",
            probes=("version_probe_completed",),
            evidence_quality="detected",
        ),
    ),
    _feature(
        "doris_pipeline",
        "get_ingestion_status",
        A,
        _variant(
            "load_jobs",
            probes=("stream_broker_routine_load_readable",),
        ),
        _variant(
            "continuous_load",
            ranges=(">=4.1.0",),
            probes=("continuous_load_metadata_readable",),
            sources=("DORIS_RELEASE_4_1_0",),
        ),
    ),
    _feature(
        "doris_pipeline",
        "diagnose_ingestion",
        A,
        _variant(
            "deterministic_ingestion_diagnosis",
            providers=("ingestion_evidence_provider",),
            probes=("ingestion_status_readable", "freshness_evidence_readable"),
            evidence_quality="composite",
            callable_when_degraded=True,
        ),
    ),
    _feature(
        "doris_pipeline",
        "get_materialized_view_status",
        A,
        _variant(
            "materialized_view_metadata",
            probes=("materialized_view_tasks_readable",),
        ),
        _variant(
            "mtmv_compute_group",
            ranges=(">=4.0.7,<4.1.0", ">=4.1.2"),
            deployment_modes=("cloud", "shared_data"),
            probes=("mtmv_compute_group_present",),
            sources=("DORIS_RELEASE_4_0_7", "DORIS_RELEASE_4_1_2"),
        ),
    ),
    _feature(
        "doris_pipeline",
        "monitor_data_freshness",
        A,
        _variant(
            "freshness_evidence",
            probes=("load_offset_or_time_evidence_readable",),
            callable_when_degraded=True,
        ),
    ),
    _feature(
        "doris_pipeline",
        "analyze_data_dependencies",
        M,
        _variant(
            "audit_sql_dependencies",
            providers=("audit_log_provider",),
            probes=("audit_log_readable",),
            evidence_quality="inferred",
            callable_when_degraded=True,
        ),
    ),
    _feature(
        "doris_search",
        "search_data",
        A,
        _variant(
            "inverted_text_search",
            probes=("inverted_index_and_search_syntax_ready",),
        ),
        _variant(
            "vector_hybrid_search",
            ranges=(">=4.0.0",),
            features=("ann_index", "hybrid_search"),
            probes=("ann_index_and_metric_compatible",),
            sources=("DORIS_RELEASE_4_0_0",),
        ),
    ),
    _feature(
        "doris_search",
        "preview_text_analysis",
        A,
        _variant(
            "tokenizer_preview",
            probes=("tokenize_function_or_analyzer_ready",),
        ),
    ),
    _feature(
        "doris_search",
        "inspect_search_indexes",
        M,
        _variant(
            "inverted_index_metadata",
            probes=("inverted_index_metadata_readable",),
        ),
        _variant(
            "ann_index_metadata",
            ranges=(">=4.0.0",),
            features=("ann_index",),
            probes=("ann_index_metadata_readable",),
            sources=("DORIS_RELEASE_4_0_0",),
        ),
    ),
    _feature(
        "doris_search",
        "diagnose_search_query",
        A,
        _variant(
            "search_query_diagnosis",
            providers=("search_evidence_provider",),
            probes=("search_index_and_explain_readable",),
            evidence_quality="composite",
            callable_when_degraded=True,
        ),
    ),
    _feature(
        "doris_governance",
        "analyze_columns",
        A,
        _variant(
            "column_statistics",
            probes=("column_statistics_and_safe_sampling_ready",),
        ),
    ),
    _feature(
        "doris_governance",
        "analyze_table_storage",
        A,
        _variant(
            "base_storage",
            probes=("table_storage_metadata_readable",),
        ),
        _variant(
            "storage_v3_variant",
            ranges=(">=4.1.0",),
            features=("storage_v3", "variant_sparse", "variant_doc"),
            probes=("storage_v3_variant_properties_readable",),
            sources=("DORIS_RELEASE_4_1_0",),
        ),
    ),
    _feature(
        "doris_governance",
        "get_lineage_capability_status",
        F,
        _variant(
            "audit_lineage_status",
            providers=("audit_log_provider",),
            probes=("audit_lineage_provider_status_readable",),
            evidence_quality="inferred",
            callable_when_degraded=True,
        ),
        _variant(
            "native_lineage_status",
            ranges=(">=4.0.6",),
            providers=("lineage_event_store",),
            probes=(
                "all_fe_lineage_plugin_compatible",
                "lineage_store_readable",
            ),
            sources=(
                "DORIS_RELEASE_4_0_6",
                "DORIS_LINEAGE_GUIDE",
                "DORIS_LINEAGE_PLUGIN_GUIDE",
            ),
        ),
    ),
    _feature(
        "doris_governance",
        "trace_column_lineage",
        F,
        _variant(
            "audit_sql_inference_primary",
            ranges=(">=3.0.0,<4.0.6",),
            providers=("audit_log_provider",),
            probes=("audit_log_readable",),
            evidence_quality="inferred",
            callable_when_degraded=True,
        ),
        _variant(
            "native_lineage_events",
            ranges=(">=4.0.6",),
            providers=("lineage_event_store",),
            probes=(
                "all_fe_lineage_plugin_compatible",
                "lineage_store_readable",
            ),
            sources=(
                "DORIS_RELEASE_4_0_6",
                "DORIS_LINEAGE_GUIDE",
                "DORIS_LINEAGE_PLUGIN_GUIDE",
            ),
        ),
        _variant(
            "audit_sql_inference_fallback",
            ranges=(">=4.0.6",),
            providers=("audit_log_provider",),
            probes=("audit_log_readable",),
            evidence_quality="inferred",
            callable_when_degraded=True,
            sources=("DORIS_LINEAGE_GUIDE", "DORIS_DOCS_4X"),
        ),
    ),
    _feature(
        "doris_governance",
        "analyze_data_access_patterns",
        M,
        _variant(
            "audit_access_history",
            providers=("audit_log_provider",),
            probes=("audit_history_readable",),
            evidence_quality="recorded",
        ),
    ),
    _feature(
        "doris_governance",
        "get_recent_audit_logs",
        M,
        _variant(
            "audit_log",
            providers=("audit_log_provider",),
            probes=("audit_log_readable",),
        ),
        _variant(
            "audit_log_4_0_7",
            ranges=(">=4.0.7,<4.1.0",),
            features=("set_var_audit", "enhanced_secret_masking"),
            probes=("enhanced_audit_fields_present",),
            sources=("DORIS_RELEASE_4_0_7",),
        ),
    ),
    _feature(
        "doris_governance",
        "list_udfs",
        M,
        _variant("base_udf_metadata", probes=("udf_metadata_readable",)),
        _variant(
            "python_udf_family",
            ranges=(">=4.1.3",),
            features=("python_udf", "python_udaf", "python_udtf"),
            probes=("python_udf_metadata_readable",),
            sources=("DORIS_RELEASE_4_1_3",),
        ),
    ),
    _feature(
        "doris_governance",
        "get_auth_mapping_status",
        F,
        _variant(
            "ldap_mapping",
            providers=("ldap_auth_provider",),
            probes=("ldap_mapping_status_readable",),
        ),
        _variant(
            "oidc_role_mapping",
            ranges=(">=4.1.2",),
            providers=("oidc_auth_provider",),
            system_objects=("information_schema.role_mappings",),
            probes=("oidc_and_role_mapping_status_readable",),
            sources=("DORIS_RELEASE_4_1_2",),
        ),
    ),
    _feature(
        "doris_lakehouse",
        "inspect_external_catalog",
        M,
        _variant(
            "external_catalog_metadata",
            providers=("external_catalog_provider",),
            probes=("external_catalog_metadata_readable",),
        ),
    ),
    _feature(
        "doris_lakehouse",
        "inspect_lakehouse_table",
        A,
        _variant(
            "lakehouse_table_metadata",
            providers=("external_catalog_provider",),
            probes=("lakehouse_table_metadata_readable",),
        ),
        _variant(
            "lakehouse_lifecycle_4_1",
            ranges=(">=4.1.0",),
            features=("iceberg_deletion_vector", "iceberg_row_lineage"),
            probes=("lakehouse_snapshot_features_readable",),
            sources=("DORIS_RELEASE_4_1_0",),
        ),
    ),
    _feature(
        "doris_lakehouse",
        "inspect_variant_column",
        A,
        _variant(
            "variant_type",
            probes=("variant_column_type_readable",),
        ),
        _variant(
            "variant_advanced_4_1",
            ranges=(">=4.1.0",),
            features=(
                "variant_sparse_sharding",
                "variant_sparse_cache",
                "variant_doc_mode",
                "storage_v3",
            ),
            probes=("variant_advanced_properties_readable",),
            sources=("DORIS_RELEASE_4_1_0",),
        ),
    ),
    _feature(
        "doris_semantic",
        "list_semantic_models",
        P,
        _variant(
            "ossie_model_registry",
            providers=("ossie_provider",),
            probes=("ossie_spec_and_registry_ready",),
            sources=("APACHE_OSSIE_CORE_SPEC",),
        ),
    ),
    _feature(
        "doris_semantic",
        "get_semantic_model_summary",
        P,
        _variant(
            "ossie_model_summary",
            providers=("ossie_provider",),
            probes=("explicit_model_ref_valid", "ossie_model_valid"),
            sources=("APACHE_OSSIE_CORE_SPEC",),
        ),
    ),
    _feature(
        "doris_semantic",
        "get_semantic_context",
        P,
        _variant(
            "ossie_semantic_context",
            providers=("ossie_provider",),
            probes=("explicit_model_ref_valid", "semantic_policy_ready"),
            sources=("APACHE_OSSIE_CORE_SPEC",),
        ),
    ),
    _feature(
        "doris_semantic",
        "get_semantic_mapping_status",
        P,
        _variant(
            "ossie_doris_mapping",
            providers=("ossie_provider",),
            probes=(
                "explicit_model_ref_valid",
                "doris_binding_metadata_readable",
            ),
            sources=("APACHE_OSSIE_CORE_SPEC", "DORIS_DOCS_4X"),
        ),
    ),
)

DORIS_FEATURE_MATRIX = DorisFeatureMatrix(
    minimum_supported_version=PROJECT_MINIMUM_DORIS_VERSION,
    certification_targets=CERTIFICATION_TARGET_VERSIONS,
    certified_versions=CERTIFIED_DORIS_VERSIONS,
    sources=FEATURE_SOURCES,
    features=FEATURE_DEFINITIONS,
)


__all__ = [
    "CERTIFICATION_TARGET_VERSIONS",
    "CERTIFIED_DORIS_VERSIONS",
    "DORIS_FEATURE_MATRIX",
    "EXPECTED_DOMAIN_CHILDREN",
    "FEATURE_DEFINITIONS",
    "FEATURE_SOURCES",
    "PROJECT_MINIMUM_DORIS_VERSION",
    "PROJECT_SUPPORTED_RANGE",
    "CapabilityVersionScope",
    "ChildFeatureDefinition",
    "DorisClusterVersionVector",
    "DorisFeatureMatrix",
    "DorisVersionConstraint",
    "DorisVersionRange",
    "FeatureSource",
    "FeatureSourceKind",
    "FeatureVersionEvaluation",
    "VersionCertificationStatus",
    "VersionRangeOperator",
    "matching_version_ranges",
]
