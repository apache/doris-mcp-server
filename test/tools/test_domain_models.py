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

from datetime import UTC, datetime
from typing import cast

import pytest
from pydantic import JsonValue, ValidationError

from doris_mcp_server.tools.domain_models import (
    MAX_DOMAIN_MANIFEST_BYTES,
    Availability,
    AvailabilityStatus,
    CapabilityVariant,
    ChildManifestEntry,
    ChildSupportContract,
    ChildToolDefinition,
    CompositePlan,
    CompositeStep,
    DiscoveryEnvelope,
    DomainDefinition,
    DomainErrorCode,
    DomainToolRequest,
    ErrorEnvelope,
    ExecutionEnvelope,
    ExecutionMetadata,
    JsonObject,
    ManifestVersionSupport,
    StandardError,
    ToolContractAnnotations,
    UnavailableBehavior,
)

OBJECT_SCHEMA: JsonObject = {
    "type": "object",
    "properties": {"database": {"type": "string"}},
    "additionalProperties": False,
}
OUTPUT_SCHEMA: JsonObject = {
    "type": "object",
    "properties": {"items": {"type": "array"}},
    "required": ["items"],
    "additionalProperties": False,
}
READ_ONLY = ToolContractAnnotations(
    read_only=True,
    idempotent=True,
    destructive=False,
    open_world=False,
    requires_confirmation=False,
)


def _variant(
    *,
    name: str = "information_schema",
    probes: tuple[str, ...] = ("information_schema_readable",),
    sources: tuple[str, ...] = (),
) -> CapabilityVariant:
    return CapabilityVariant(
        name=name,
        supported_ranges=("project-supported Doris releases",),
        required_probes=probes,
        source_references=sources,
    )


def _support_contract(
    *variants: CapabilityVariant,
) -> ChildSupportContract:
    return ChildSupportContract(
        rule_id="catalog.list_tables.v1",
        variants=variants or (_variant(),),
        unavailable_behavior=UnavailableBehavior.SHOW_DISABLED,
        tested_versions=("4.0.5-rc01",),
    )


def _child(
    *,
    name: str = "list_tables",
    handler_name: str = "_list_tables_child",
    input_schema: JsonObject | None = None,
    output_schema: JsonObject | None = None,
    support_contract: ChildSupportContract | None = None,
    composite_plan: CompositePlan | None = None,
) -> ChildToolDefinition:
    return ChildToolDefinition(
        name=name,
        title="List Doris Tables",
        canonical_description="List visible tables in one Doris database.",
        input_schema=input_schema or OBJECT_SCHEMA,
        output_schema=output_schema or OUTPUT_SCHEMA,
        handler_name=handler_name,
        support_contract=support_contract or _support_contract(),
        authorization_policy="catalog_metadata",
        annotations=READ_ONLY,
        composite_plan=composite_plan,
    )


def _availability(
    *,
    status: AvailabilityStatus = AvailabilityStatus.AVAILABLE,
    callable_: bool = True,
    active_variant: str | None = "information_schema",
) -> Availability:
    return Availability(
        status=status,
        callable=callable_,
        reason_code="RUNTIME_PROBE_CONFIRMED",
        detected_versions={"fe": ("4.0.5-rc01",)},
        active_variant=active_variant,
        evidence_sources=("version", "sql_probe"),
    )


def _manifest_child() -> ChildManifestEntry:
    child = _child()
    return ChildManifestEntry(
        name=child.name,
        title=child.title,
        description="[AVAILABLE] List visible tables in one Doris database.",
        input_schema=child.input_schema,
        output_schema=child.output_schema,
        version_support=ManifestVersionSupport.from_contract(
            child.support_contract
        ),
        availability=_availability(),
        annotations=child.annotations,
    )


def test_domain_definition_is_frozen_and_bounded() -> None:
    domain = DomainDefinition(
        name="doris_catalog",
        title="Doris Catalog",
        description="Discover and inspect Doris metadata.",
        annotations=READ_ONLY,
        children=(_child(),),
        enablement_policy="read_only_default",
        discovery_policy="catalog_discovery",
    )

    assert domain.max_manifest_bytes == MAX_DOMAIN_MANIFEST_BYTES
    with pytest.raises(ValidationError):
        domain.name = "doris_query"


def test_domain_rejects_duplicate_child_names() -> None:
    with pytest.raises(ValidationError, match="child tool names"):
        DomainDefinition(
            name="doris_catalog",
            title="Doris Catalog",
            description="Discover and inspect Doris metadata.",
            annotations=READ_ONLY,
            children=(_child(), _child()),
            enablement_policy="read_only_default",
            discovery_policy="catalog_discovery",
        )


def test_domain_rejects_manifest_budget_above_16_kib() -> None:
    with pytest.raises(ValidationError, match="less than or equal"):
        DomainDefinition(
            name="doris_catalog",
            title="Doris Catalog",
            description="Discover and inspect Doris metadata.",
            annotations=READ_ONLY,
            children=(_child(),),
            enablement_policy="read_only_default",
            discovery_policy="catalog_discovery",
            max_manifest_bytes=MAX_DOMAIN_MANIFEST_BYTES + 1,
        )


def test_annotations_reject_conflicting_risk_flags() -> None:
    with pytest.raises(ValidationError, match="both read-only and destructive"):
        ToolContractAnnotations(
            read_only=True,
            idempotent=False,
            destructive=True,
            open_world=False,
            requires_confirmation=True,
        )

    with pytest.raises(ValidationError, match="must require confirmation"):
        ToolContractAnnotations(
            read_only=False,
            idempotent=False,
            destructive=True,
            open_world=False,
            requires_confirmation=False,
        )


def test_capability_variant_requires_evidence_contract() -> None:
    with pytest.raises(ValidationError, match="source reference or runtime probe"):
        _variant(probes=(), sources=())

    assert _variant(probes=(), sources=("DORIS_CATALOG_GUIDE",)).name == (
        "information_schema"
    )


def test_capability_variant_rejects_duplicate_requirements() -> None:
    with pytest.raises(ValidationError, match="required_probes"):
        CapabilityVariant(
            name="information_schema",
            supported_ranges=(">=3.0.0",),
            required_probes=("metadata_readable", "metadata_readable"),
        )


def test_support_contract_rejects_duplicate_variant_ids() -> None:
    with pytest.raises(ValidationError, match="capability variant names"):
        _support_contract(_variant(), _variant())


def test_manifest_version_support_is_a_compact_ordered_projection() -> None:
    support = ManifestVersionSupport.from_contract(
        _support_contract(
            _variant(name="native"),
            CapabilityVariant(
                name="fallback",
                supported_ranges=(">=3.0.0",),
                excluded_ranges=("==4.0.6-rc1",),
                required_probes=("audit_readable",),
            ),
        )
    )

    assert support.to_wire() == {
        "rule_id": "catalog.list_tables.v1",
        "supported_ranges": [
            "project-supported Doris releases",
            ">=3.0.0",
        ],
        "excluded_ranges": ["==4.0.6-rc1"],
        "tested_versions": ["4.0.5-rc01"],
    }


def test_child_rejects_empty_handler_name() -> None:
    with pytest.raises(ValidationError, match="handler_name"):
        _child(handler_name="")


def test_child_rejects_dynamic_status_in_canonical_description() -> None:
    payload = _child().model_dump()
    payload["canonical_description"] = "[AVAILABLE] List tables."
    with pytest.raises(ValidationError, match="dynamic status prefix"):
        ChildToolDefinition.model_validate(payload)


@pytest.mark.parametrize("schema_field", ["input_schema", "output_schema"])
def test_child_rejects_non_object_root_schema(schema_field: str) -> None:
    invalid_schema: JsonObject = {"type": "array"}
    with pytest.raises(ValidationError, match="root type must be object"):
        if schema_field == "input_schema":
            _child(input_schema=invalid_schema)
        else:
            _child(output_schema=invalid_schema)


def test_child_rejects_invalid_json_schema() -> None:
    with pytest.raises(ValidationError, match="not a valid JSON Schema"):
        _child(input_schema={"type": "object", "required": "database"})


def test_child_schemas_are_deeply_immutable() -> None:
    child = _child()
    with pytest.raises(TypeError):
        child.input_schema["title"] = "changed"

    properties = cast(dict[str, JsonValue], child.input_schema["properties"])
    with pytest.raises(TypeError):
        properties["database"] = {"type": "integer"}

    assert child.to_wire()["input_schema"] == OBJECT_SCHEMA


def test_composite_plan_validates_deterministic_dag() -> None:
    plan = CompositePlan(
        steps=(
            CompositeStep(name="schema", handler_name="_get_schema"),
            CompositeStep(
                name="comments",
                handler_name="_get_comments",
                depends_on=("schema",),
            ),
        ),
        required_steps=("schema",),
        optional_steps=("comments",),
        partial_success_policy="return_required_with_warnings",
        merge_handler_name="_merge_table_context",
    )

    assert plan.steps[1].depends_on == ("schema",)


def test_composite_plan_rejects_unknown_dependency() -> None:
    with pytest.raises(ValidationError, match="unknown dependencies"):
        CompositePlan(
            steps=(
                CompositeStep(
                    name="comments",
                    handler_name="_get_comments",
                    depends_on=("schema",),
                ),
            ),
            required_steps=("comments",),
            optional_steps=(),
            partial_success_policy="fail_required",
            merge_handler_name="_merge",
        )


def test_composite_plan_rejects_cycles() -> None:
    with pytest.raises(ValidationError, match="must be acyclic"):
        CompositePlan(
            steps=(
                CompositeStep(
                    name="schema",
                    handler_name="_get_schema",
                    depends_on=("comments",),
                ),
                CompositeStep(
                    name="comments",
                    handler_name="_get_comments",
                    depends_on=("schema",),
                ),
            ),
            required_steps=("schema", "comments"),
            optional_steps=(),
            partial_success_policy="fail_required",
            merge_handler_name="_merge",
        )


def test_composite_plan_rejects_overlapping_step_classes() -> None:
    with pytest.raises(ValidationError, match="must be disjoint"):
        CompositePlan(
            steps=(CompositeStep(name="schema", handler_name="_get_schema"),),
            required_steps=("schema",),
            optional_steps=("schema",),
            partial_success_policy="fail_required",
            merge_handler_name="_merge",
        )


def test_composite_plan_requires_complete_step_classification() -> None:
    with pytest.raises(ValidationError, match="classify every step"):
        CompositePlan(
            steps=(CompositeStep(name="schema", handler_name="_get_schema"),),
            required_steps=(),
            optional_steps=(),
            partial_success_policy="fail_required",
            merge_handler_name="_merge",
        )


@pytest.mark.parametrize(
    "status",
    [
        AvailabilityStatus.UNAVAILABLE,
        AvailabilityStatus.MISCONFIGURED,
        AvailabilityStatus.UNKNOWN,
    ],
)
def test_non_callable_availability_states_fail_closed(
    status: AvailabilityStatus,
) -> None:
    with pytest.raises(ValidationError, match="cannot be callable"):
        _availability(status=status, callable_=True)


def test_callable_availability_requires_active_variant() -> None:
    with pytest.raises(ValidationError, match="requires an active_variant"):
        _availability(callable_=True, active_variant=None)


def test_degraded_availability_may_be_callable_or_disabled() -> None:
    callable_result = _availability(status=AvailabilityStatus.DEGRADED)
    disabled_result = _availability(
        status=AvailabilityStatus.DEGRADED,
        callable_=False,
        active_variant=None,
    )

    assert callable_result.callable is True
    assert disabled_result.callable is False


def test_domain_request_distinguishes_discovery_and_execution() -> None:
    discovery = DomainToolRequest()
    execution = DomainToolRequest(child_tool="list_tables")

    assert discovery.is_discovery is True
    assert execution.is_discovery is False
    assert execution.execution_arguments == {}


def test_domain_request_rejects_arguments_without_child() -> None:
    for arguments in ({}, {"database": "analytics"}):
        with pytest.raises(
            ValidationError,
            match="arguments require child_tool",
        ):
            DomainToolRequest(arguments=arguments)


def test_request_arguments_and_result_data_are_deeply_immutable() -> None:
    request = DomainToolRequest(
        child_tool="list_tables",
        arguments={"filters": [{"kind": "table"}]},
    )
    arguments = cast(dict[str, JsonValue], request.arguments)
    with pytest.raises(TypeError):
        arguments["database"] = "changed"
    filters = cast(list[JsonValue], arguments["filters"])
    with pytest.raises(TypeError):
        filters[0] = {"kind": "view"}
    assert request.to_wire()["arguments"] == {
        "filters": [{"kind": "table"}]
    }

    result = ExecutionEnvelope(
        mode="result",
        domain="doris_catalog",
        child_tool="list_tables",
        manifest_version="catalog.7a93f2",
        data={"items": [{"name": "orders"}]},
        metadata=ExecutionMetadata(
            request_id="req_fixed",
            duration_ms=18,
            source="doris",
            truncated=False,
        ),
    )
    data = cast(dict[str, JsonValue], result.data)
    with pytest.raises(TypeError):
        data["items"] = []


def test_discovery_envelope_is_canonical_and_repeatable() -> None:
    envelope = DiscoveryEnvelope(
        mode="manifest",
        domain="doris_catalog",
        manifest_version="catalog.7a93f2",
        generated_at=datetime(2026, 7, 31, tzinfo=UTC),
        children=(_manifest_child(),),
    )

    first = envelope.to_canonical_json()
    second = DiscoveryEnvelope.model_validate(envelope.to_wire()).to_canonical_json()
    assert first == second
    assert first.startswith('{"children":')
    assert '"mode":"manifest"' in first


def test_discovery_envelope_rejects_naive_timestamp() -> None:
    with pytest.raises(ValidationError, match="must include a timezone"):
        DiscoveryEnvelope(
            mode="manifest",
            domain="doris_catalog",
            manifest_version="catalog.7a93f2",
            generated_at=datetime(2026, 7, 31),
            children=(),
        )


def test_discovery_envelope_rejects_duplicate_child_ids() -> None:
    with pytest.raises(ValidationError, match="manifest child names"):
        DiscoveryEnvelope(
            mode="manifest",
            domain="doris_catalog",
            manifest_version="catalog.7a93f2",
            generated_at=datetime(2026, 7, 31, tzinfo=UTC),
            children=(_manifest_child(), _manifest_child()),
        )


def test_execution_envelope_has_stable_wire_shape() -> None:
    result = ExecutionEnvelope(
        mode="result",
        domain="doris_catalog",
        child_tool="list_tables",
        manifest_version="catalog.7a93f2",
        data={"items": [{"name": "orders"}]},
        metadata=ExecutionMetadata(
            request_id="req_fixed",
            duration_ms=18,
            source="doris",
            truncated=False,
        ),
    )

    assert result.to_wire() == {
        "mode": "result",
        "domain": "doris_catalog",
        "child_tool": "list_tables",
        "manifest_version": "catalog.7a93f2",
        "data": {"items": [{"name": "orders"}]},
        "metadata": {
            "request_id": "req_fixed",
            "duration_ms": 18.0,
            "source": "doris",
            "truncated": False,
        },
        "warnings": [],
    }


def test_standard_error_envelope_uses_fixed_error_codes() -> None:
    result = ErrorEnvelope(
        mode="error",
        domain="doris_catalog",
        child_tool="list_tables",
        manifest_version="catalog.7a93f2",
        error=StandardError(
            code=DomainErrorCode.CHILD_MANIFEST_STALE,
            message="The domain manifest changed.",
            retryable=True,
            details={"rediscover": True},
        ),
    )

    error = cast(dict[str, JsonValue], result.to_wire()["error"])
    assert error["code"] == "CHILD_MANIFEST_STALE"
    with pytest.raises(ValidationError):
        StandardError.model_validate(
            {
                "code": "NOT_A_STANDARD_ERROR",
                "message": "Invalid error code.",
                "retryable": False,
            }
        )


def test_wire_schema_is_deterministic_and_forbids_extra_fields() -> None:
    first = DiscoveryEnvelope.wire_schema()
    second = DiscoveryEnvelope.wire_schema()

    assert first == second
    assert first["additionalProperties"] is False
    assert "generated_at" in first["properties"]


def test_models_reject_unknown_fields() -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        Availability.model_validate(
            {
                "status": AvailabilityStatus.UNKNOWN,
                "callable": False,
                "reason_code": "PROBE_FAILED",
                "guessed_version": "4.0.5",
            }
        )
