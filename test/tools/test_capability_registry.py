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

"""Tests for snapshot caching and deterministic availability evaluation."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from doris_mcp_server.tools.capability_detector import (
    CapabilityDetectionError,
    CapabilityProbeEvidence,
    CapabilityProbeStatus,
    CapabilityRouteChangedError,
    DorisCapabilitySnapshot,
)
from doris_mcp_server.tools.capability_registry import (
    CapabilityEvaluator,
    CapabilityProviderEvidence,
    CapabilityProviderRegistry,
    CapabilityRegistry,
)
from doris_mcp_server.tools.domain_catalog import DORIS_DOMAIN_CATALOG
from doris_mcp_server.tools.domain_manifest import DomainManifestService
from doris_mcp_server.tools.domain_models import AvailabilityStatus
from doris_mcp_server.tools.doris_feature_matrix import (
    DORIS_FEATURE_MATRIX,
    DorisClusterVersionVector,
)
from doris_mcp_server.utils.db import DorisRouteIdentity
from doris_mcp_server.utils.security import AuthContext


class _BoundHandlers:
    def __init__(self, *feature_ids: str) -> None:
        self.bound_feature_ids = frozenset(feature_ids)

    def is_bound(self, domain_name: str, child_name: str) -> bool:
        return f"{domain_name}.{child_name}" in self.bound_feature_ids


def _snapshot(
    *,
    route: DorisRouteIdentity | None = None,
    generation: int = 1,
    provider_generation: str = "provider.empty",
    probes: dict[str, CapabilityProbeEvidence] | None = None,
    mixed_versions: bool = False,
    now: datetime | None = None,
) -> DorisCapabilitySnapshot:
    created = now or datetime(2026, 7, 31, tzinfo=UTC)
    versions = DorisClusterVersionVector.from_comments(
        master_fe="Doris version doris-4.0.5",
        follower_fes=("Doris version doris-4.0.5",),
        backends=(
            "Doris version doris-4.0.5",
            (
                "Doris version doris-4.0.6"
                if mixed_versions
                else "Doris version doris-4.0.5"
            ),
        ),
    )
    return DorisCapabilitySnapshot(
        route=route
        or DorisRouteIdentity(
            route_key="global",
            generation=1,
            endpoint_fingerprint="endpoint-a",
            fingerprint="route-a",
        ),
        capability_generation=generation,
        provider_generation=provider_generation,
        cluster_fingerprint="cluster-a",
        version_vector=versions,
        deployment_mode="unknown",
        mixed_versions=mixed_versions,
        probes=probes or {},
        probed_domains=frozenset({"doris_query"}),
        created_at=created,
        expires_at=created + timedelta(seconds=10),
        stale_until=created + timedelta(seconds=30),
    )


def _query_probes() -> dict[str, CapabilityProbeEvidence]:
    return {
        probe_id: CapabilityProbeEvidence(
            probe_id=probe_id,
            status=CapabilityProbeStatus.SUPPORTED,
            reason_code="TEST_PROBE_SUPPORTED",
            evidence_sources=("test_probe",),
        )
        for probe_id in (
            "read_only_sql_guard_ready",
            "query_execution_readable",
        )
    }


def _query_contract():
    domain = DORIS_DOMAIN_CATALOG.resolve_domain("doris_query")
    child = DORIS_DOMAIN_CATALOG.resolve_child(
        "doris_query",
        "execute_query",
    )
    return domain, child


def test_evaluator_requires_version_probes_handler_and_call_permission() -> None:
    bound = _BoundHandlers("doris_query.execute_query")
    evaluator = CapabilityEvaluator(
        matrix=DORIS_FEATURE_MATRIX,
        bound_handlers=bound,  # type: ignore[arg-type]
    )
    providers = CapabilityProviderRegistry({}).snapshot()
    domain, child = _query_contract()

    available = evaluator.evaluate(
        snapshot=_snapshot(probes=_query_probes()),
        providers=providers,
        domain=domain,
        child=child,
        auth_context=None,
    )
    missing_probe = evaluator.evaluate(
        snapshot=_snapshot(probes={}),
        providers=providers,
        domain=domain,
        child=child,
        auth_context=None,
    )
    mixed_backends = evaluator.evaluate(
        snapshot=_snapshot(
            probes=_query_probes(),
            mixed_versions=True,
        ),
        providers=providers,
        domain=domain,
        child=child,
        auth_context=None,
    )
    denied = evaluator.evaluate(
        snapshot=_snapshot(probes=_query_probes()),
        providers=providers,
        domain=domain,
        child=child,
        auth_context=AuthContext(
            auth_method="external_oauth",
            oauth_scopes=["tool:list"],
        ),
    )
    allowed = evaluator.evaluate(
        snapshot=_snapshot(probes=_query_probes()),
        providers=providers,
        domain=domain,
        child=child,
        auth_context=AuthContext(
            auth_method="external_oauth",
            oauth_scopes=["child:call:doris_query:execute_query"],
        ),
    )

    assert available.status is AvailabilityStatus.AVAILABLE
    assert available.callable is True
    assert available.active_variant == "mysql_read_only"
    assert available.reason_code == "CAPABILITY_VERIFIED_UNCERTIFIED"
    assert available.limitations == ()
    assert missing_probe.status is AvailabilityStatus.UNKNOWN
    assert missing_probe.reason_code == "CAPABILITY_PROBE_PENDING"
    assert mixed_backends.status is AvailabilityStatus.AVAILABLE
    assert mixed_backends.callable is True
    assert denied.status is AvailabilityStatus.UNAVAILABLE
    assert denied.reason_code == "CHILD_CALL_PERMISSION_DENIED"
    assert allowed.callable is True


@pytest.mark.parametrize(
    ("domain_name", "child_name", "expected_components"),
    (
        ("doris_governance", "list_udfs", {"master_fe"}),
        (
            "doris_governance",
            "get_lineage_capability_status",
            {"master_fe", "follower_fe"},
        ),
        ("doris_cluster", "get_cache_status", {"be"}),
        (
            "doris_cluster",
            "get_cluster_overview",
            {"master_fe", "follower_fe", "be"},
        ),
        ("doris_query", "get_adbc_connection_info", {"master_fe"}),
    ),
)
def test_evaluator_exposes_only_versions_relevant_to_feature_scope(
    domain_name: str,
    child_name: str,
    expected_components: set[str],
) -> None:
    evaluator = CapabilityEvaluator(
        matrix=DORIS_FEATURE_MATRIX,
        bound_handlers=_BoundHandlers(
            f"{domain_name}.{child_name}"
        ),  # type: ignore[arg-type]
    )
    domain = DORIS_DOMAIN_CATALOG.resolve_domain(domain_name)
    child = DORIS_DOMAIN_CATALOG.resolve_child(
        domain_name,
        child_name,
    )

    availability = evaluator.evaluate(
        snapshot=_snapshot(),
        providers=CapabilityProviderRegistry({}).snapshot(),
        domain=domain,
        child=child,
        auth_context=None,
    )

    assert set(availability.detected_versions) == expected_components


def test_compaction_prefers_native_tracker_and_uses_legacy_on_405() -> None:
    evaluator = CapabilityEvaluator(
        matrix=DORIS_FEATURE_MATRIX,
        bound_handlers=_BoundHandlers(
            "doris_cluster.get_compaction_status"
        ),  # type: ignore[arg-type]
    )
    domain = DORIS_DOMAIN_CATALOG.resolve_domain("doris_cluster")
    child = DORIS_DOMAIN_CATALOG.resolve_child(
        "doris_cluster",
        "get_compaction_status",
    )
    probes = {
        "information_schema.doris_be_compaction_tasks": (
            CapabilityProbeEvidence(
                probe_id="information_schema.doris_be_compaction_tasks",
                status=CapabilityProbeStatus.SUPPORTED,
                reason_code="TEST_NATIVE_TRACKER",
            )
        ),
        "compaction_system_table_or_http_api": CapabilityProbeEvidence(
            probe_id="compaction_system_table_or_http_api",
            status=CapabilityProbeStatus.SUPPORTED,
            reason_code="TEST_NATIVE_TRACKER",
        ),
        "legacy_compaction_status_readable": CapabilityProbeEvidence(
            probe_id="legacy_compaction_status_readable",
            status=CapabilityProbeStatus.DEGRADED,
            reason_code="TEST_LEGACY_SUMMARY",
        ),
    }
    providers = CapabilityProviderRegistry({}).snapshot()
    snapshot_405 = _snapshot(probes=probes)
    snapshot_406 = replace(
        snapshot_405,
        version_vector=DorisClusterVersionVector.from_comments(
            master_fe="Doris version doris-4.0.6",
            follower_fes=("Doris version doris-4.0.6",),
            backends=("Doris version doris-4.0.6",),
        ),
    )

    native = evaluator.evaluate(
        snapshot=snapshot_406,
        providers=providers,
        domain=domain,
        child=child,
        auth_context=None,
    )
    legacy = evaluator.evaluate(
        snapshot=snapshot_405,
        providers=providers,
        domain=domain,
        child=child,
        auth_context=None,
    )

    assert native.callable is True
    assert native.status is AvailabilityStatus.AVAILABLE
    assert native.active_variant == "compaction_task_tracker"
    assert legacy.callable is True
    assert legacy.status is AvailabilityStatus.DEGRADED
    assert legacy.active_variant == "legacy_compaction_summary"
    assert legacy.reason_code == (
        "CAPABILITY_VERIFIED_DEGRADED_UNCERTIFIED"
    )


def test_lakehouse_prefers_4_1_variants_and_falls_back_on_4_0() -> None:
    bound = _BoundHandlers(
        "doris_lakehouse.inspect_lakehouse_table",
        "doris_lakehouse.inspect_variant_column",
    )
    evaluator = CapabilityEvaluator(
        matrix=DORIS_FEATURE_MATRIX,
        bound_handlers=bound,  # type: ignore[arg-type]
    )
    domain = DORIS_DOMAIN_CATALOG.resolve_domain("doris_lakehouse")
    table_child = DORIS_DOMAIN_CATALOG.resolve_child(
        "doris_lakehouse",
        "inspect_lakehouse_table",
    )
    variant_child = DORIS_DOMAIN_CATALOG.resolve_child(
        "doris_lakehouse",
        "inspect_variant_column",
    )
    probes = {
        "lakehouse_table_metadata_readable": CapabilityProbeEvidence(
            probe_id="lakehouse_table_metadata_readable",
            status=CapabilityProbeStatus.SUPPORTED,
            reason_code="TEST_BASELINE_METADATA",
        ),
        "variant_column_type_readable": CapabilityProbeEvidence(
            probe_id="variant_column_type_readable",
            status=CapabilityProbeStatus.SUPPORTED,
            reason_code="TEST_BASELINE_VARIANT",
        ),
        **{
            probe_id: CapabilityProbeEvidence(
                probe_id=probe_id,
                status=CapabilityProbeStatus.DEGRADED,
                reason_code="TEST_CALL_TIME_TARGET_VALIDATION",
            )
            for probe_id in (
                "lakehouse_snapshot_features_readable",
                "iceberg_deletion_vector",
                "iceberg_row_lineage",
                "variant_advanced_properties_readable",
                "variant_sparse_sharding",
                "variant_sparse_cache",
                "variant_doc_mode",
                "storage_v3",
            )
        },
    }
    providers = CapabilityProviderRegistry(
        {
            "external_catalog_provider": CapabilityProviderEvidence(
                provider_id="external_catalog_provider",
                status=CapabilityProbeStatus.SUPPORTED,
                reason_code="PROVIDER_CONFIGURED",
            )
        }
    ).snapshot()
    snapshot_405 = _snapshot(probes=probes)
    snapshot_410 = replace(
        snapshot_405,
        version_vector=DorisClusterVersionVector.from_comments(
            master_fe="Doris version doris-4.1.0",
            follower_fes=("Doris version doris-4.1.0",),
            backends=("Doris version doris-4.1.0",),
        ),
    )

    table_405 = evaluator.evaluate(
        snapshot=snapshot_405,
        providers=providers,
        domain=domain,
        child=table_child,
        auth_context=None,
    )
    table_410 = evaluator.evaluate(
        snapshot=snapshot_410,
        providers=providers,
        domain=domain,
        child=table_child,
        auth_context=None,
    )
    variant_405 = evaluator.evaluate(
        snapshot=snapshot_405,
        providers=providers,
        domain=domain,
        child=variant_child,
        auth_context=None,
    )
    variant_410 = evaluator.evaluate(
        snapshot=snapshot_410,
        providers=providers,
        domain=domain,
        child=variant_child,
        auth_context=None,
    )

    assert table_405.active_variant == "lakehouse_table_metadata"
    assert table_405.status is AvailabilityStatus.AVAILABLE
    assert table_410.active_variant == "lakehouse_lifecycle_4_1"
    assert table_410.status is AvailabilityStatus.DEGRADED
    assert table_410.callable is True
    assert variant_405.active_variant == "variant_type"
    assert variant_405.status is AvailabilityStatus.AVAILABLE
    assert variant_410.active_variant == "variant_advanced_4_1"
    assert variant_410.status is AvailabilityStatus.DEGRADED
    assert variant_410.callable is True


def test_evaluator_normalizes_system_object_probe_evidence_for_manifest() -> None:
    evaluator = CapabilityEvaluator(
        matrix=DORIS_FEATURE_MATRIX,
        bound_handlers=_BoundHandlers("doris_catalog.get_table_context"),  # type: ignore[arg-type]
    )
    domain = DORIS_DOMAIN_CATALOG.resolve_domain("doris_catalog")
    child = DORIS_DOMAIN_CATALOG.resolve_child(
        "doris_catalog",
        "get_table_context",
    )
    probes = {
        probe_id: CapabilityProbeEvidence(
            probe_id=probe_id,
            status=CapabilityProbeStatus.SUPPORTED,
            reason_code="TEST_PROBE_SUPPORTED",
            evidence_sources=("test_probe",),
        )
        for probe_id in (
            "information_schema.columns",
            "table_context_sections_readable",
        )
    }

    availability = evaluator.evaluate(
        snapshot=_snapshot(probes=probes),
        providers=CapabilityProviderRegistry({}).snapshot(),
        domain=domain,
        child=child,
        auth_context=None,
    )

    assert availability.callable is True
    assert "information_schema_columns" in availability.evidence_sources
    assert "information_schema.columns" not in availability.evidence_sources


def test_evaluator_distinguishes_provider_misconfiguration() -> None:
    bound = _BoundHandlers("doris_query.diagnose_query_performance")
    evaluator = CapabilityEvaluator(
        matrix=DORIS_FEATURE_MATRIX,
        bound_handlers=bound,  # type: ignore[arg-type]
    )
    domain = DORIS_DOMAIN_CATALOG.resolve_domain("doris_query")
    child = DORIS_DOMAIN_CATALOG.resolve_child(
        "doris_query",
        "diagnose_query_performance",
    )

    availability = evaluator.evaluate(
        snapshot=_snapshot(),
        providers=CapabilityProviderRegistry({}).snapshot(),
        domain=domain,
        child=child,
        auth_context=None,
    )

    assert availability.status is AvailabilityStatus.MISCONFIGURED
    assert availability.callable is False
    assert availability.reason_code == "PROVIDER_NOT_CONFIGURED"


@pytest.mark.parametrize(
    ("enabled", "bound", "expected_status"),
    [
        (False, True, CapabilityProbeStatus.MISCONFIGURED),
        (True, False, CapabilityProbeStatus.MISCONFIGURED),
        (True, True, CapabilityProbeStatus.SUPPORTED),
    ],
)
def test_adbc_provider_requires_configuration_and_bound_consumer(
    enabled: bool,
    bound: bool,
    expected_status: CapabilityProbeStatus,
) -> None:
    handlers = (
        _BoundHandlers(
            "doris_query.get_adbc_connection_info",
            "doris_query.execute_adbc_query",
        )
        if bound
        else _BoundHandlers()
    )
    registry = CapabilityProviderRegistry.from_runtime(
        matrix=DORIS_FEATURE_MATRIX,
        bound_handlers=handlers,  # type: ignore[arg-type]
        config=SimpleNamespace(adbc=SimpleNamespace(enabled=enabled)),
    )

    provider = registry.snapshot().providers["adbc_provider"]

    assert provider.status is expected_status
    assert provider.reason_code == (
        "PROVIDER_CONFIGURED"
        if expected_status is CapabilityProbeStatus.SUPPORTED
        else "PROVIDER_NOT_CONFIGURED"
    )


@pytest.mark.parametrize(
    ("store_table", "bound", "expected_status"),
    [
        ("", True, CapabilityProbeStatus.MISCONFIGURED),
        ("governance.lineage_events", False, CapabilityProbeStatus.MISCONFIGURED),
        ("governance.lineage_events", True, CapabilityProbeStatus.SUPPORTED),
    ],
)
def test_lineage_store_provider_requires_configuration_and_bound_consumer(
    store_table: str,
    bound: bool,
    expected_status: CapabilityProbeStatus,
) -> None:
    handlers = (
        _BoundHandlers("doris_governance.trace_column_lineage")
        if bound
        else _BoundHandlers()
    )
    registry = CapabilityProviderRegistry.from_runtime(
        matrix=DORIS_FEATURE_MATRIX,
        bound_handlers=handlers,  # type: ignore[arg-type]
        config=SimpleNamespace(
            adbc=SimpleNamespace(enabled=False),
            governance=SimpleNamespace(lineage_store_table=store_table),
        ),
    )

    provider = registry.snapshot().providers["lineage_event_store"]

    assert provider.status is expected_status
    assert provider.reason_code == (
        "PROVIDER_CONFIGURED"
        if expected_status is CapabilityProbeStatus.SUPPORTED
        else "PROVIDER_NOT_CONFIGURED"
    )


def test_builtin_query_evidence_providers_are_ready_when_bound() -> None:
    handlers = _BoundHandlers(
        "doris_query.diagnose_query_performance",
        "doris_query.list_slow_queries",
    )
    registry = CapabilityProviderRegistry.from_runtime(
        matrix=DORIS_FEATURE_MATRIX,
        bound_handlers=handlers,  # type: ignore[arg-type]
        config=SimpleNamespace(adbc=SimpleNamespace(enabled=False)),
    )

    providers = registry.snapshot().providers

    assert (
        providers["query_evidence_provider"].status is CapabilityProbeStatus.SUPPORTED
    )
    assert providers["audit_log_provider"].status is CapabilityProbeStatus.SUPPORTED
    assert providers["query_evidence_provider"].reason_code == ("PROVIDER_CONFIGURED")


def test_external_catalog_provider_is_ready_only_when_lakehouse_is_bound() -> None:
    bound_registry = CapabilityProviderRegistry.from_runtime(
        matrix=DORIS_FEATURE_MATRIX,
        bound_handlers=_BoundHandlers(  # type: ignore[arg-type]
            "doris_lakehouse.inspect_external_catalog",
            "doris_lakehouse.inspect_lakehouse_table",
        ),
        config=SimpleNamespace(adbc=SimpleNamespace(enabled=False)),
    )
    unbound_registry = CapabilityProviderRegistry.from_runtime(
        matrix=DORIS_FEATURE_MATRIX,
        bound_handlers=_BoundHandlers(),  # type: ignore[arg-type]
        config=SimpleNamespace(adbc=SimpleNamespace(enabled=False)),
    )

    bound = bound_registry.snapshot().providers["external_catalog_provider"]
    unbound = unbound_registry.snapshot().providers[
        "external_catalog_provider"
    ]

    assert bound.status is CapabilityProbeStatus.SUPPORTED
    assert bound.reason_code == "PROVIDER_CONFIGURED"
    assert unbound.status is CapabilityProbeStatus.MISCONFIGURED
    assert unbound.reason_code == "PROVIDER_NOT_CONFIGURED"


@pytest.mark.parametrize(
    ("enabled", "paths_configured", "bound", "expected_status"),
    [
        (False, True, True, CapabilityProbeStatus.MISCONFIGURED),
        (True, False, True, CapabilityProbeStatus.MISCONFIGURED),
        (True, True, False, CapabilityProbeStatus.MISCONFIGURED),
        (True, True, True, CapabilityProbeStatus.SUPPORTED),
    ],
)
def test_ossie_provider_requires_opt_in_paths_and_bound_consumer(
    enabled: bool,
    paths_configured: bool,
    bound: bool,
    expected_status: CapabilityProbeStatus,
) -> None:
    handlers = (
        _BoundHandlers(
            "doris_semantic.list_semantic_models",
            "doris_semantic.get_semantic_context",
        )
        if bound
        else _BoundHandlers()
    )
    registry = CapabilityProviderRegistry.from_runtime(
        matrix=DORIS_FEATURE_MATRIX,
        bound_handlers=handlers,  # type: ignore[arg-type]
        config=SimpleNamespace(
            adbc=SimpleNamespace(enabled=False),
            semantic=SimpleNamespace(
                enabled=enabled,
                model_directory="/srv/ossie" if paths_configured else "",
                binding_manifest=(
                    "/srv/ossie/bindings.yaml" if paths_configured else ""
                ),
            ),
        ),
    )

    provider = registry.snapshot().providers["ossie_provider"]

    assert provider.status is expected_status
    assert provider.reason_code == (
        "PROVIDER_CONFIGURED"
        if expected_status is CapabilityProbeStatus.SUPPORTED
        else "PROVIDER_NOT_CONFIGURED"
    )


def test_ossie_provider_rejects_unstructured_mock_configuration() -> None:
    registry = CapabilityProviderRegistry.from_runtime(
        matrix=DORIS_FEATURE_MATRIX,
        bound_handlers=_BoundHandlers(
            "doris_semantic.list_semantic_models",
        ),  # type: ignore[arg-type]
        config=Mock(),
    )

    provider = registry.snapshot().providers["ossie_provider"]

    assert provider.status is CapabilityProbeStatus.MISCONFIGURED
    assert provider.reason_code == "PROVIDER_NOT_CONFIGURED"


def test_semantic_availability_keeps_call_time_validation_callable() -> None:
    bound = _BoundHandlers(
        "doris_semantic.list_semantic_models",
        "doris_semantic.get_semantic_context",
    )
    evaluator = CapabilityEvaluator(
        matrix=DORIS_FEATURE_MATRIX,
        bound_handlers=bound,  # type: ignore[arg-type]
    )
    provider = CapabilityProviderRegistry(
        {
            "ossie_provider": CapabilityProviderEvidence(
                provider_id="ossie_provider",
                status=CapabilityProbeStatus.SUPPORTED,
                reason_code="PROVIDER_CONFIGURED",
            )
        }
    ).snapshot()
    probes = {
        "ossie_spec_and_registry_ready": CapabilityProbeEvidence(
            probe_id="ossie_spec_and_registry_ready",
            status=CapabilityProbeStatus.SUPPORTED,
            reason_code="PINNED_OSSIE_ADAPTER_READY",
        ),
        "explicit_model_ref_valid": CapabilityProbeEvidence(
            probe_id="explicit_model_ref_valid",
            status=CapabilityProbeStatus.DEGRADED,
            reason_code="SEMANTIC_TARGET_REQUIRES_CALL_TIME_VALIDATION",
        ),
        "semantic_policy_ready": CapabilityProbeEvidence(
            probe_id="semantic_policy_ready",
            status=CapabilityProbeStatus.DEGRADED,
            reason_code="SEMANTIC_TARGET_REQUIRES_CALL_TIME_VALIDATION",
        ),
    }
    snapshot = _snapshot(probes=probes)
    domain = DORIS_DOMAIN_CATALOG.resolve_domain("doris_semantic")

    listed = evaluator.evaluate(
        snapshot=snapshot,
        providers=provider,
        domain=domain,
        child=DORIS_DOMAIN_CATALOG.resolve_child(
            "doris_semantic",
            "list_semantic_models",
        ),
        auth_context=None,
    )
    context = evaluator.evaluate(
        snapshot=snapshot,
        providers=provider,
        domain=domain,
        child=DORIS_DOMAIN_CATALOG.resolve_child(
            "doris_semantic",
            "get_semantic_context",
        ),
        auth_context=None,
    )

    assert listed.status is AvailabilityStatus.AVAILABLE
    assert listed.callable is True
    assert context.status is AvailabilityStatus.DEGRADED
    assert context.callable is True
    assert context.reason_code == "CAPABILITY_VERIFIED_DEGRADED_UNCERTIFIED"
    assert "Probe explicit_model_ref_valid is degraded." in context.limitations
    assert "Probe semantic_policy_ready is degraded." in context.limitations


class _MutableClock:
    def __init__(self) -> None:
        self.now = datetime(2026, 7, 31, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


class _FakeDetector:
    def __init__(
        self,
        clock: _MutableClock,
        *,
        probes: dict[str, CapabilityProbeEvidence] | None = None,
    ) -> None:
        self.clock = clock
        self.probes = probes or _query_probes()
        self.route = DorisRouteIdentity(
            route_key="global",
            generation=1,
            endpoint_fingerprint="endpoint-a",
            fingerprint="route-a",
        )
        self.base_calls = 0
        self.domain_calls = 0
        self.fail_base = False
        self.fail_base_with_route_change = False
        self.domain_hook: Callable[[], None] | None = None

    def route_identity(self, _auth_context: Any) -> DorisRouteIdentity:
        return self.route

    async def detect_base(
        self,
        _auth_context: Any,
        *,
        capability_generation: int,
        provider_generation: str,
    ) -> DorisCapabilitySnapshot:
        self.base_calls += 1
        await asyncio.sleep(0.01)
        if self.fail_base_with_route_change:
            self.route = DorisRouteIdentity(
                route_key="global",
                generation=2,
                endpoint_fingerprint="endpoint-b",
                fingerprint="route-b",
            )
            raise CapabilityRouteChangedError("test route change")
        if self.fail_base:
            raise CapabilityDetectionError("test failure")
        return _snapshot(
            route=self.route,
            generation=capability_generation,
            provider_generation=provider_generation,
            probes=self.probes,
            now=self.clock(),
        )

    async def detect_domain(
        self,
        base: DorisCapabilitySnapshot,
        domain_name: str,
        _auth_context: Any,
    ) -> DorisCapabilitySnapshot:
        self.domain_calls += 1
        await asyncio.sleep(0.01)
        if self.domain_hook is not None:
            hook, self.domain_hook = self.domain_hook, None
            hook()
        return replace(
            base,
            probed_domains=base.probed_domains | {domain_name},
        )


def _registry(
    detector: _FakeDetector,
    clock: _MutableClock,
) -> CapabilityRegistry:
    bound = _BoundHandlers("doris_query.execute_query")
    return CapabilityRegistry(
        detector=detector,  # type: ignore[arg-type]
        provider_registry=CapabilityProviderRegistry({}),
        evaluator=CapabilityEvaluator(
            matrix=DORIS_FEATURE_MATRIX,
            bound_handlers=bound,  # type: ignore[arg-type]
        ),
        clock=clock,
    )


@pytest.mark.asyncio
async def test_registry_singleflight_route_switch_and_generation() -> None:
    clock = _MutableClock()
    detector = _FakeDetector(clock)
    registry = _registry(detector, clock)

    snapshots = await asyncio.gather(
        *(registry.ensure_fresh("doris_query", None) for _ in range(12))
    )
    first_generation = snapshots[0].generation_fingerprint

    assert detector.base_calls == 1
    assert detector.domain_calls == 1
    assert len({item.generation_fingerprint for item in snapshots}) == 1

    await registry.ensure_fresh("doris_catalog", None)
    assert detector.base_calls == 1
    assert detector.domain_calls == 2

    detector.route = DorisRouteIdentity(
        route_key="global",
        generation=2,
        endpoint_fingerprint="endpoint-b",
        fingerprint="route-b",
    )
    switched = await registry.ensure_fresh("doris_query", None)
    assert detector.base_calls == 2
    assert switched.route.fingerprint == "route-b"

    await registry.bump_generation()
    regenerated = await registry.ensure_fresh("doris_query", None)
    assert detector.base_calls == 3
    assert regenerated.capability_generation == 2
    assert regenerated.generation_fingerprint != first_generation


@pytest.mark.asyncio
async def test_registry_uses_stale_snapshot_within_grace() -> None:
    clock = _MutableClock()
    detector = _FakeDetector(clock)
    registry = _registry(detector, clock)
    first = await registry.ensure_fresh("doris_query", None)
    clock.now += timedelta(seconds=11)
    detector.fail_base = True

    stale = await registry.ensure_fresh("doris_query", None)

    assert first.stale is False
    assert stale.stale is True
    assert detector.base_calls == 2

    repeated = await registry.ensure_fresh("doris_query", None)

    assert repeated.stale is True
    assert detector.base_calls == 2


@pytest.mark.asyncio
async def test_route_change_does_not_reuse_previous_route_stale_snapshot() -> None:
    clock = _MutableClock()
    detector = _FakeDetector(clock)
    registry = _registry(detector, clock)
    previous = await registry.ensure_fresh("doris_query", None)
    clock.now += timedelta(seconds=11)
    detector.fail_base_with_route_change = True

    current = await registry.ensure_fresh("doris_query", None)

    assert previous.route.fingerprint == "route-a"
    assert current.route.fingerprint == "route-b"
    assert current.stale is False
    assert current.version_vector.master_fe.is_parsed is False


@pytest.mark.asyncio
async def test_singleflight_waiter_cancellation_does_not_cancel_probe() -> None:
    clock = _MutableClock()
    detector = _FakeDetector(clock)
    registry = _registry(detector, clock)
    cancelled_waiter = asyncio.create_task(registry.ensure_fresh("doris_query", None))
    surviving_waiter = asyncio.create_task(registry.ensure_fresh("doris_query", None))
    while detector.base_calls == 0:
        await asyncio.sleep(0)

    cancelled_waiter.cancel()

    with pytest.raises(asyncio.CancelledError):
        await cancelled_waiter
    snapshot = await surviving_waiter

    assert snapshot.route.fingerprint == "route-a"
    assert detector.base_calls == 1
    assert detector.domain_calls == 1


@pytest.mark.asyncio
async def test_generation_bump_does_not_accept_inflight_old_snapshot() -> None:
    clock = _MutableClock()
    detector = _FakeDetector(clock)
    registry = _registry(detector, clock)
    old_request = asyncio.create_task(registry.ensure_fresh("doris_query", None))
    while detector.base_calls == 0:
        await asyncio.sleep(0)

    await registry.bump_generation()
    old_snapshot = await old_request
    current_snapshot = await registry.ensure_fresh(
        "doris_query",
        None,
    )

    assert old_snapshot.capability_generation == 1
    assert current_snapshot.capability_generation == 2
    assert detector.base_calls == 2


@pytest.mark.asyncio
async def test_manifest_version_tracks_private_capability_generation() -> None:
    clock = _MutableClock()
    detector = _FakeDetector(clock)
    registry = _registry(detector, clock)
    service = DomainManifestService(
        availability_provider=registry,
        clock=clock,
    )
    domain = DORIS_DOMAIN_CATALOG.resolve_domain("doris_query")

    first = await service.discover(domain, None)
    await registry.bump_generation()
    second = await service.discover(domain, None)

    assert first.manifest_version != second.manifest_version


@pytest.mark.asyncio
async def test_provider_down_advances_generation_and_fails_closed() -> None:
    clock = _MutableClock()
    detector = _FakeDetector(
        clock,
        probes={
            probe_id: CapabilityProbeEvidence(
                probe_id=probe_id,
                status=CapabilityProbeStatus.SUPPORTED,
                reason_code="TEST_PROBE_SUPPORTED",
                evidence_sources=("test_probe",),
            )
            for probe_id in (
                "adbc_driver_ready",
                "flight_sql",
                "flight_sql_reachable",
                "read_only_sql_guard_ready",
            )
        },
    )
    providers = CapabilityProviderRegistry(
        {
            "adbc_provider": CapabilityProviderEvidence(
                provider_id="adbc_provider",
                status=CapabilityProbeStatus.SUPPORTED,
                reason_code="PROVIDER_HEALTHY",
            )
        }
    )
    registry = CapabilityRegistry(
        detector=detector,  # type: ignore[arg-type]
        provider_registry=providers,
        evaluator=CapabilityEvaluator(
            matrix=DORIS_FEATURE_MATRIX,
            bound_handlers=_BoundHandlers("doris_query.execute_adbc_query"),  # type: ignore[arg-type]
        ),
        clock=clock,
    )
    service = DomainManifestService(
        availability_provider=registry,
        clock=clock,
    )
    domain = DORIS_DOMAIN_CATALOG.resolve_domain("doris_query")

    available = await service.discover(domain, None)
    available_child = next(
        child for child in available.children if child.name == "execute_adbc_query"
    )
    providers.set_provider(
        "adbc_provider",
        status=CapabilityProbeStatus.UNKNOWN,
        reason_code="PROVIDER_HEALTHCHECK_FAILED",
    )
    unavailable = await service.discover(domain, None)
    unavailable_child = next(
        child for child in unavailable.children if child.name == "execute_adbc_query"
    )

    assert available_child.availability.callable is True
    assert unavailable_child.availability.callable is False
    assert unavailable_child.availability.status is AvailabilityStatus.UNKNOWN
    assert unavailable_child.availability.reason_code == "PROVIDER_HEALTHCHECK_FAILED"
    assert available.manifest_version != unavailable.manifest_version
    assert detector.base_calls == 2


@pytest.mark.asyncio
async def test_manifest_uses_one_provider_generation_during_refresh() -> None:
    clock = _MutableClock()
    detector = _FakeDetector(
        clock,
        probes={
            probe_id: CapabilityProbeEvidence(
                probe_id=probe_id,
                status=CapabilityProbeStatus.SUPPORTED,
                reason_code="TEST_PROBE_SUPPORTED",
                evidence_sources=("test_probe",),
            )
            for probe_id in (
                "adbc_driver_ready",
                "flight_sql",
                "flight_sql_reachable",
                "read_only_sql_guard_ready",
            )
        },
    )
    providers = CapabilityProviderRegistry(
        {
            "adbc_provider": CapabilityProviderEvidence(
                provider_id="adbc_provider",
                status=CapabilityProbeStatus.SUPPORTED,
                reason_code="PROVIDER_HEALTHY",
            )
        }
    )
    registry = CapabilityRegistry(
        detector=detector,  # type: ignore[arg-type]
        provider_registry=providers,
        evaluator=CapabilityEvaluator(
            matrix=DORIS_FEATURE_MATRIX,
            bound_handlers=_BoundHandlers("doris_query.execute_adbc_query"),  # type: ignore[arg-type]
        ),
        clock=clock,
    )
    service = DomainManifestService(
        availability_provider=registry,
        clock=clock,
    )
    domain = DORIS_DOMAIN_CATALOG.resolve_domain("doris_query")
    detector.domain_hook = lambda: providers.set_provider(
        "adbc_provider",
        status=CapabilityProbeStatus.UNKNOWN,
        reason_code="PROVIDER_HEALTHCHECK_FAILED",
    )

    coherent_old = await service.discover(domain, None)
    current = await service.discover(domain, None)
    old_child = next(
        child for child in coherent_old.children if child.name == "execute_adbc_query"
    )
    current_child = next(
        child for child in current.children if child.name == "execute_adbc_query"
    )

    assert old_child.availability.callable is True
    assert current_child.availability.callable is False
    assert current_child.availability.reason_code == ("PROVIDER_HEALTHCHECK_FAILED")
    assert coherent_old.manifest_version != current.manifest_version
