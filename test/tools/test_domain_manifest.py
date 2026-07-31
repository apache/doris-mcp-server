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

"""Contract tests for bounded progressive domain discovery."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from doris_mcp_server.schema_validation import ToolSchemaGuard
from doris_mcp_server.tools.domain_catalog import (
    DORIS_DOMAIN_CATALOG,
    DorisDomainCatalog,
)
from doris_mcp_server.tools.domain_manifest import (
    DOMAIN_DISCOVERY_DESCRIPTION_SUFFIX,
    MAX_CHILD_DESCRIPTION_CHARACTERS,
    MAX_CHILD_SCHEMA_BYTES,
    MAX_SCHEMA_ENUM_VALUES,
    DomainManifestBudgetError,
    DomainManifestManagerMixin,
    DomainManifestService,
)
from doris_mcp_server.tools.domain_models import (
    MAX_DOMAIN_MANIFEST_BYTES,
    Availability,
    AvailabilityStatus,
    ChildToolDefinition,
    DomainDefinition,
    DomainErrorCode,
)
from doris_mcp_server.tools.doris_feature_matrix import (
    EXPECTED_DOMAIN_CHILDREN,
)
from doris_mcp_server.utils.security import AuthContext

FIXED_TIME = datetime(2026, 7, 31, 8, 30, tzinfo=UTC)
REPO_ROOT = Path(__file__).resolve().parents[2]


class StaticAvailabilityProvider:
    def __init__(
        self,
        availability: Availability,
    ) -> None:
        self.availability = availability
        self.calls: list[str] = []

    async def availability_for(
        self,
        domain: DomainDefinition,
        child: ChildToolDefinition,
        auth_context: Any | None,
    ) -> Availability:
        del auth_context
        self.calls.append(f"{domain.name}.{child.name}")
        return self.availability


def _availability(
    *,
    status: AvailabilityStatus = AvailabilityStatus.AVAILABLE,
    callable_: bool = True,
    reason_code: str = "RUNTIME_PROBE_CONFIRMED",
    active_variant: str | None = "information_schema",
    detected_versions: dict[str, tuple[str, ...]] | None = None,
    evidence_sources: tuple[str, ...] = ("version", "sql_probe"),
) -> Availability:
    return Availability(
        status=status,
        callable=callable_,
        reason_code=reason_code,
        detected_versions=(
            detected_versions
            if detected_versions is not None
            else {"fe": ("4.0.7",)}
        ),
        active_variant=active_variant,
        evidence_sources=evidence_sources,
    )


def _service(
    provider: StaticAvailabilityProvider | None = None,
    *,
    clock_time: datetime = FIXED_TIME,
) -> DomainManifestService:
    return DomainManifestService(
        availability_provider=provider,
        clock=lambda: clock_time,
    )


def _replace_domain(
    domain_name: str,
    replacement: DomainDefinition,
) -> DorisDomainCatalog:
    domains = tuple(
        replacement if domain.name == domain_name else domain
        for domain in DORIS_DOMAIN_CATALOG.domains
    )
    return DORIS_DOMAIN_CATALOG.model_copy(update={"domains": domains})


def _replace_child(
    domain: DomainDefinition,
    child_index: int,
    replacement: ChildToolDefinition,
) -> DomainDefinition:
    children = list(domain.children)
    children[child_index] = replacement
    return domain.model_copy(update={"children": tuple(children)})


def test_top_level_catalog_is_exactly_eight_stable_read_only_domains() -> None:
    service = _service()
    tools = service.list_tools()

    assert [tool.name for tool in tools] == list(EXPECTED_DOMAIN_CHILDREN)
    assert service.domain_names == frozenset(EXPECTED_DOMAIN_CHILDREN)
    assert service.handles("doris_catalog") is True
    assert service.handles("exec_query") is False
    assert len(tools) == 8
    assert len({tool.name for tool in tools}) == 8
    assert len({str(tool.input_schema) for tool in tools}) == 1
    assert len({str(tool.output_schema) for tool in tools}) == 1
    ToolSchemaGuard().compile_catalog(tools)

    for tool in tools:
        assert tool.description is not None
        assert tool.description.endswith(DOMAIN_DISCOVERY_DESCRIPTION_SUFFIX)
        assert tool.annotations is not None
        assert tool.annotations.read_only_hint is True
        assert tool.annotations.destructive_hint is False
        assert tool.annotations.idempotent_hint is True
        assert tool.annotations.open_world_hint is False
        for child_name in EXPECTED_DOMAIN_CHILDREN[tool.name]:
            assert child_name not in tool.description


def test_manager_mixin_lazily_builds_discovery_service() -> None:
    manager = DomainManifestManagerMixin()

    assert manager.domain_manifest_service.handles("doris_catalog")
    assert manager.domain_manifest_service is manager.domain_manifest_service


def test_checked_in_public_registry_is_generated_from_domain_catalog() -> None:
    checked_in = (REPO_ROOT / "docs" / "tool-registry.md").read_text(
        encoding="utf-8"
    )

    assert checked_in == _service().render_markdown()


@pytest.mark.asyncio
async def test_manager_mixin_lists_and_calls_domain_discovery() -> None:
    manager = DomainManifestManagerMixin()

    listed = await manager.list_tools()
    payload = json.loads(
        await manager._call_domain_tool("doris_catalog", {})
    )

    assert [tool.name for tool in listed] == list(EXPECTED_DOMAIN_CHILDREN)
    assert payload["mode"] == "manifest"
    assert payload["domain"] == "doris_catalog"


@pytest.mark.asyncio
async def test_empty_calls_return_complete_bounded_manifests() -> None:
    service = _service()

    for domain_name, expected_children in EXPECTED_DOMAIN_CHILDREN.items():
        first = await service.call(domain_name, {}, None)
        second = await service.call(domain_name, {}, None)

        assert first.mode == "manifest"
        assert first.domain == domain_name
        assert first.generated_at == FIXED_TIME
        assert first.manifest_version == second.manifest_version
        assert [child.name for child in first.children] == list(
            expected_children
        )
        assert (
            len(first.to_canonical_json().encode("utf-8"))
            <= MAX_DOMAIN_MANIFEST_BYTES
        )
        for child in first.children:
            assert child.availability.status is AvailabilityStatus.UNKNOWN
            assert child.availability.callable is False
            assert child.availability.evidence_sources == (
                "catalog_contract",
            )
            assert child.description.startswith(
                "[UNKNOWN | capability snapshot pending] "
            )
        first_child = first.to_wire()["children"][0]
        assert "excluded_ranges" not in first_child["version_support"]
        assert "tested_versions" not in first_child["version_support"]
        assert "detected_versions" not in first_child["availability"]
        assert "limitations" not in first_child["availability"]


@pytest.mark.asyncio
async def test_non_child_permissions_do_not_hide_read_only_catalog() -> None:
    context = AuthContext(
        auth_method="token",
        permissions=["catalog:read"],
    )

    manifest = await _service().call("doris_catalog", {}, context)

    assert len(manifest.children) == 5


@pytest.mark.asyncio
async def test_manifest_version_excludes_timestamp_but_tracks_content() -> None:
    available = StaticAvailabilityProvider(_availability())
    first = await _service(available).call("doris_catalog", {}, None)
    later = await _service(
        StaticAvailabilityProvider(_availability()),
        clock_time=FIXED_TIME + timedelta(minutes=5),
    ).call("doris_catalog", {}, None)
    unavailable = await _service(
        StaticAvailabilityProvider(
            _availability(
                status=AvailabilityStatus.UNAVAILABLE,
                callable_=False,
                reason_code="DORIS_VERSION_UNSUPPORTED",
                active_variant=None,
            )
        )
    ).call("doris_catalog", {}, None)

    assert first.manifest_version == later.manifest_version
    assert first.generated_at != later.generated_at
    assert first.manifest_version != unavailable.manifest_version


@pytest.mark.asyncio
async def test_dynamic_description_and_structured_availability_agree() -> None:
    provider = StaticAvailabilityProvider(
        _availability(
            status=AvailabilityStatus.DEGRADED,
            callable_=True,
            reason_code="FALLBACK_ACTIVE",
            active_variant="audit_sql_inference",
            detected_versions={},
            evidence_sources=("audit_log",),
        )
    )

    manifest = await _service(provider).call(
        "doris_governance",
        {},
        None,
    )

    assert manifest.children
    for child in manifest.children:
        assert child.description.startswith(
            "[DEGRADED | audit_sql_inference] "
        )
        assert child.availability.status is AvailabilityStatus.DEGRADED
        assert child.availability.callable is True
        assert child.availability.active_variant == "audit_sql_inference"


@pytest.mark.asyncio
async def test_detected_version_has_priority_in_dynamic_description() -> None:
    provider = StaticAvailabilityProvider(
        _availability(
            detected_versions={"be": ("4.0.6",), "fe": ("4.0.7",)},
        )
    )

    manifest = await _service(provider).call("doris_cluster", {}, None)

    assert manifest.children[0].description.startswith(
        "[AVAILABLE | Doris 4.0.7 | information_schema] "
    )


@pytest.mark.asyncio
async def test_realistic_runtime_evidence_stays_within_manifest_budget() -> None:
    provider = StaticAvailabilityProvider(
        _availability(
            detected_versions={
                "master_fe": ("4.1.3",),
                "fe": ("4.1.3",),
                "be": ("4.1.3",),
            },
            evidence_sources=(
                "version_probe",
                "sql_probe",
                "provider_config",
            ),
        )
    )

    manifest = await _service(provider).call("doris_cluster", {}, None)

    assert (
        len(manifest.to_canonical_json().encode("utf-8"))
        <= MAX_DOMAIN_MANIFEST_BYTES
    )


@pytest.mark.asyncio
async def test_explicit_child_grants_hide_every_unauthorized_child() -> None:
    provider = StaticAvailabilityProvider(_availability())
    context = AuthContext(
        auth_method="external_oauth",
        oauth_scopes=[
            "tool:call:doris_catalog",
            "child:call:doris_catalog:list_tables",
        ],
    )

    catalog = await _service(provider).call(
        "doris_catalog",
        {},
        context,
    )
    cluster = await _service(provider).call(
        "doris_cluster",
        {},
        context,
    )

    assert [child.name for child in catalog.children] == ["list_tables"]
    assert cluster.children == ()
    assert provider.calls == ["doris_catalog.list_tables"]
    assert "list_catalogs" not in catalog.to_canonical_json()


@pytest.mark.asyncio
async def test_oauth_without_exact_child_scope_discovers_no_children() -> None:
    context = AuthContext(
        auth_method="external_oauth",
        oauth_scopes=["tool:list"],
    )

    manifest = await _service().call("doris_catalog", {}, context)

    assert manifest.children == ()


@pytest.mark.asyncio
async def test_doris_oauth_requires_gate_allowlist_and_exact_scope() -> None:
    provider = StaticAvailabilityProvider(_availability())
    scope = "child:call:doris_catalog:list_tables"
    disabled = AuthContext(
        auth_method="doris_oauth",
        oauth_scopes=["tool:list", scope],
    )
    enabled = AuthContext(
        auth_method="doris_oauth",
        oauth_scopes=["tool:list", scope],
        doris_oauth_child_tools_enabled=True,
        doris_oauth_child_tool_allowlist=(
            "doris_catalog.list_tables",
        ),
    )

    disabled_manifest = await _service(provider).call(
        "doris_catalog",
        {},
        disabled,
    )
    enabled_manifest = await _service(provider).call(
        "doris_catalog",
        {},
        enabled,
    )

    assert disabled_manifest.children == ()
    assert [child.name for child in enabled_manifest.children] == [
        "list_tables"
    ]


@pytest.mark.asyncio
async def test_explicit_discovery_permission_is_accepted() -> None:
    context = AuthContext(
        permissions=["child:discover:doris_semantic:get_semantic_context"],
    )

    manifest = await _service().call("doris_semantic", {}, context)

    assert [child.name for child in manifest.children] == [
        "get_semantic_context"
    ]


@pytest.mark.asyncio
async def test_authorized_unavailable_children_remain_discoverable() -> None:
    provider = StaticAvailabilityProvider(
        _availability(
            status=AvailabilityStatus.MISCONFIGURED,
            callable_=False,
            reason_code="PROVIDER_NOT_CONFIGURED",
            active_variant=None,
            detected_versions={},
            evidence_sources=("provider_config",),
        )
    )

    manifest = await _service(provider).call(
        "doris_semantic",
        {},
        None,
    )

    assert len(manifest.children) == 4
    assert all(not child.availability.callable for child in manifest.children)
    assert all(
        child.description.startswith(
            "[MISCONFIGURED | provider not configured] "
        )
        for child in manifest.children
    )


@pytest.mark.asyncio
async def test_public_version_support_omits_internal_execution_contracts() -> None:
    manifest = await _service().call("doris_cluster", {}, None)
    serialized = manifest.to_canonical_json()

    for child in manifest.children:
        support = child.version_support.to_wire()
        assert support["rule_id"]
        assert support["supported_ranges"]
        assert "variants" not in support
        assert "required_probes" not in support
        assert "source_references" not in support
    assert '"required_providers"' not in serialized
    assert '"handler_name"' not in serialized
    assert '"authorization_policy"' not in serialized


@pytest.mark.asyncio
async def test_invalid_or_execution_requests_fail_with_stable_envelopes() -> None:
    service = _service()

    empty_arguments = await service.call(
        "doris_catalog",
        {"arguments": {}},
        None,
    )
    invalid = await service.call(
        "doris_catalog",
        {"arguments": {"database": "analytics"}},
        None,
    )
    execution = await service.call(
        "doris_catalog",
        {
            "child_tool": "list_tables",
            "arguments": {"database": "analytics"},
            "manifest_version": "catalog.previous",
        },
        None,
    )

    assert empty_arguments.mode == "error"
    assert (
        empty_arguments.error.code
        is DomainErrorCode.CHILD_ARGUMENTS_INVALID
    )
    assert invalid.mode == "error"
    assert invalid.error.code is DomainErrorCode.CHILD_ARGUMENTS_INVALID
    assert execution.mode == "error"
    assert (
        execution.error.code
        is DomainErrorCode.CHILD_CAPABILITY_UNAVAILABLE
    )
    assert execution.child_tool == "list_tables"
    assert execution.manifest_version == "catalog.previous"


def test_startup_rejects_manifest_over_domain_budget() -> None:
    domain = DORIS_DOMAIN_CATALOG.resolve_domain("doris_cluster")
    constrained = domain.model_copy(update={"max_manifest_bytes": 100})

    with pytest.raises(DomainManifestBudgetError, match="limit is 100 bytes"):
        DomainManifestService(
            catalog=_replace_domain(domain.name, constrained)
        )


@pytest.mark.parametrize(
    ("replacement", "message"),
    [
        (
            {"canonical_description": "x" * MAX_CHILD_DESCRIPTION_CHARACTERS},
            "description exceeds",
        ),
        (
            {
                "input_schema": {
                    "type": "object",
                    "description": "x" * MAX_CHILD_SCHEMA_BYTES,
                }
            },
            "input schema is",
        ),
        (
            {
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "value": {
                            "type": "string",
                            "enum": [
                                str(index)
                                for index in range(
                                    MAX_SCHEMA_ENUM_VALUES + 1
                                )
                            ],
                        }
                    },
                }
            },
            "schema enum exceeds",
        ),
    ],
)
def test_startup_rejects_child_level_budget_violations(
    replacement: dict[str, Any],
    message: str,
) -> None:
    domain = DORIS_DOMAIN_CATALOG.resolve_domain("doris_catalog")
    child = domain.children[0].model_copy(update=replacement)
    modified = _replace_child(domain, 0, child)

    with pytest.raises(DomainManifestBudgetError, match=message):
        DomainManifestService(
            catalog=_replace_domain(domain.name, modified)
        )


@pytest.mark.asyncio
async def test_runtime_availability_cannot_overflow_manifest_budget() -> None:
    provider = StaticAvailabilityProvider(
        _availability(
            evidence_sources=tuple(
                f"evidence_{index}" for index in range(500)
            )
        )
    )

    with pytest.raises(DomainManifestBudgetError, match="manifest is"):
        await _service(provider).call("doris_cluster", {}, None)


@pytest.mark.asyncio
async def test_naive_runtime_clock_fails_closed() -> None:
    service = _service(clock_time=datetime(2026, 7, 31, 8, 30))

    with pytest.raises(ValueError, match="must include a timezone"):
        await service.call("doris_catalog", {}, None)
