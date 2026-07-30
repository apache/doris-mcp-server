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

"""Immutable wire contracts for hierarchical Doris MCP domain tools."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Annotated, Any, Literal, Self, cast

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    field_serializer,
    field_validator,
    model_validator,
)

MAX_DOMAIN_MANIFEST_BYTES = 16 * 1024

Identifier = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_]*$",
        strip_whitespace=True,
    ),
]
BindingName = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=192,
        pattern=r"^[A-Za-z_][A-Za-z0-9_.:-]*$",
        strip_whitespace=True,
    ),
]
NonEmptyText = Annotated[
    str,
    StringConstraints(min_length=1, max_length=4096, strip_whitespace=True),
]
RuleIdentifier = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=192,
        pattern=r"^[a-z][a-z0-9_.-]*$",
        strip_whitespace=True,
    ),
]
ReasonCode = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Z][A-Z0-9_]*$",
        strip_whitespace=True,
    ),
]
JsonObject = dict[str, JsonValue]


class AvailabilityStatus(StrEnum):
    """Authoritative availability states exposed in domain manifests."""

    AVAILABLE = "available"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    MISCONFIGURED = "misconfigured"
    UNKNOWN = "unknown"


class UnavailableBehavior(StrEnum):
    """Manifest behavior when no capability variant can execute."""

    SHOW_DISABLED = "show_disabled"
    HIDE = "hide"


class DomainErrorCode(StrEnum):
    """Stable errors returned by hierarchical domain tools."""

    DOMAIN_DISCOVERY_DENIED = "DOMAIN_DISCOVERY_DENIED"
    CHILD_TOOL_NOT_FOUND = "CHILD_TOOL_NOT_FOUND"
    CHILD_MANIFEST_STALE = "CHILD_MANIFEST_STALE"
    CHILD_ARGUMENTS_INVALID = "CHILD_ARGUMENTS_INVALID"
    CHILD_RESULT_INVALID = "CHILD_RESULT_INVALID"
    CHILD_CAPABILITY_UNAVAILABLE = "CHILD_CAPABILITY_UNAVAILABLE"
    CHILD_CONFIRMATION_REQUIRED = "CHILD_CONFIRMATION_REQUIRED"
    CHILD_EXECUTION_TIMEOUT = "CHILD_EXECUTION_TIMEOUT"
    CHILD_EXECUTION_FAILED = "CHILD_EXECUTION_FAILED"


class ContractModel(BaseModel):
    """Base class with strict shape and canonical wire serialization."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        validate_default=True,
    )

    def to_wire(self) -> JsonObject:
        """Return a JSON-compatible representation with protocol aliases."""
        return cast(
            JsonObject,
            self.model_dump(
                by_alias=True,
                mode="json",
                exclude_none=True,
            ),
        )

    def to_canonical_json(self) -> str:
        """Serialize deterministically for manifests, tests, and hashing."""
        return json.dumps(
            self.to_wire(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

    @classmethod
    def wire_schema(cls) -> dict[str, Any]:
        """Return the deterministic serialization schema for this contract."""
        return cls.model_json_schema(by_alias=True, mode="serialization")


class ToolContractAnnotations(ContractModel):
    """Risk and side-effect metadata shared by domains and children."""

    read_only: bool
    idempotent: bool
    destructive: bool
    open_world: bool
    requires_confirmation: bool

    @model_validator(mode="after")
    def _validate_risk_contract(self) -> Self:
        if self.read_only and self.destructive:
            raise ValueError("a tool cannot be both read-only and destructive")
        if self.destructive and not self.requires_confirmation:
            raise ValueError("destructive tools must require confirmation")
        return self


class CapabilityVariant(ContractModel):
    """One deterministic implementation variant for a child capability."""

    name: Identifier
    supported_ranges: Annotated[tuple[NonEmptyText, ...], Field(min_length=1)]
    excluded_ranges: tuple[NonEmptyText, ...] = ()
    deployment_modes: tuple[Identifier, ...] = ()
    required_features: tuple[Identifier, ...] = ()
    required_system_objects: tuple[NonEmptyText, ...] = ()
    required_endpoints: tuple[Identifier, ...] = ()
    required_providers: tuple[Identifier, ...] = ()
    required_probes: tuple[Identifier, ...] = ()
    evidence_quality: Identifier = "native"
    callable_when_degraded: bool = False
    source_references: tuple[NonEmptyText, ...] = ()

    @model_validator(mode="after")
    def _validate_variant(self) -> Self:
        _require_unique(self.supported_ranges, "supported_ranges")
        _require_unique(self.excluded_ranges, "excluded_ranges")
        _require_unique(self.deployment_modes, "deployment_modes")
        _require_unique(self.required_features, "required_features")
        _require_unique(self.required_system_objects, "required_system_objects")
        _require_unique(self.required_endpoints, "required_endpoints")
        _require_unique(self.required_providers, "required_providers")
        _require_unique(self.required_probes, "required_probes")
        _require_unique(self.source_references, "source_references")
        if not self.source_references and not self.required_probes:
            raise ValueError(
                "a capability variant requires a source reference or runtime probe"
            )
        return self


class ChildSupportContract(ContractModel):
    """Version and runtime support contract for one child tool."""

    rule_id: RuleIdentifier
    variants: Annotated[tuple[CapabilityVariant, ...], Field(min_length=1)]
    unavailable_behavior: UnavailableBehavior
    unknown_is_callable: bool = False
    tested_versions: tuple[NonEmptyText, ...] = ()

    @model_validator(mode="after")
    def _validate_contract(self) -> Self:
        _require_unique(
            tuple(variant.name for variant in self.variants),
            "capability variant names",
        )
        _require_unique(self.tested_versions, "tested_versions")
        return self


class CompositeStep(ContractModel):
    """One private deterministic step in a composite child DAG."""

    name: Identifier
    handler_name: BindingName
    depends_on: tuple[Identifier, ...] = ()

    @model_validator(mode="after")
    def _validate_dependencies(self) -> Self:
        _require_unique(self.depends_on, "step dependencies")
        return self


class CompositePlan(ContractModel):
    """A deterministic DAG for a composite child tool."""

    steps: Annotated[tuple[CompositeStep, ...], Field(min_length=1)]
    required_steps: tuple[Identifier, ...]
    optional_steps: tuple[Identifier, ...]
    partial_success_policy: Identifier
    merge_handler_name: BindingName

    @model_validator(mode="after")
    def _validate_plan(self) -> Self:
        step_names = tuple(step.name for step in self.steps)
        _require_unique(step_names, "composite step names")
        _require_unique(self.required_steps, "required_steps")
        _require_unique(self.optional_steps, "optional_steps")

        known_steps = set(step_names)
        required = set(self.required_steps)
        optional = set(self.optional_steps)
        if required & optional:
            raise ValueError("required_steps and optional_steps must be disjoint")
        if required | optional != known_steps:
            raise ValueError(
                "required_steps and optional_steps must classify every step"
            )

        graph: dict[str, tuple[str, ...]] = {}
        for step in self.steps:
            unknown = set(step.depends_on) - known_steps
            if unknown:
                raise ValueError(
                    f"step {step.name!r} has unknown dependencies: "
                    f"{sorted(unknown)!r}"
                )
            graph[step.name] = step.depends_on
        _require_acyclic(graph)
        return self


class ChildToolDefinition(ContractModel):
    """Internal, serializable definition for one exact child tool."""

    name: Identifier
    title: NonEmptyText
    canonical_description: NonEmptyText
    input_schema: JsonObject
    output_schema: JsonObject
    handler_name: BindingName
    support_contract: ChildSupportContract
    authorization_policy: BindingName
    annotations: ToolContractAnnotations
    composite_plan: CompositePlan | None = None

    @field_validator("input_schema", "output_schema", mode="before")
    @classmethod
    def _normalize_schema_input(cls, value: Any) -> JsonValue:
        return _thaw_json(value)

    @field_validator("input_schema", "output_schema", mode="after")
    @classmethod
    def _freeze_schemas(cls, value: JsonObject) -> JsonObject:
        return _freeze_json_object(value)

    @field_serializer("input_schema", "output_schema")
    def _serialize_schemas(self, value: JsonObject) -> JsonObject:
        return cast(JsonObject, _thaw_json(value))

    @model_validator(mode="after")
    def _validate_definition(self) -> Self:
        if self.canonical_description.startswith("["):
            raise ValueError(
                "canonical_description must not contain a dynamic status prefix"
            )
        _check_object_schema(self.input_schema, "input_schema")
        _check_object_schema(self.output_schema, "output_schema")
        return self


class DomainDefinition(ContractModel):
    """Stable definition for one top-level MCP domain tool."""

    name: Identifier
    title: NonEmptyText
    description: NonEmptyText
    annotations: ToolContractAnnotations
    children: Annotated[tuple[ChildToolDefinition, ...], Field(min_length=1)]
    enablement_policy: BindingName
    discovery_policy: BindingName
    max_manifest_bytes: Annotated[
        int,
        Field(ge=1, le=MAX_DOMAIN_MANIFEST_BYTES),
    ] = MAX_DOMAIN_MANIFEST_BYTES

    @model_validator(mode="after")
    def _validate_domain(self) -> Self:
        _require_unique(
            tuple(child.name for child in self.children),
            "child tool names",
        )
        return self


class Availability(ContractModel):
    """Authoritative current availability for one discoverable child."""

    status: AvailabilityStatus
    callable: bool
    reason_code: ReasonCode
    detected_versions: dict[Identifier, tuple[NonEmptyText, ...]] = Field(
        default_factory=dict
    )
    active_variant: Identifier | None = None
    evidence_sources: tuple[Identifier, ...] = ()
    limitations: tuple[NonEmptyText, ...] = ()

    @field_validator("detected_versions", mode="after")
    @classmethod
    def _freeze_detected_versions(
        cls,
        value: dict[str, tuple[str, ...]],
    ) -> dict[str, tuple[str, ...]]:
        return cast(
            dict[str, tuple[str, ...]],
            MappingProxyType(dict(value)),
        )

    @field_serializer("detected_versions")
    def _serialize_detected_versions(
        self,
        value: dict[str, tuple[str, ...]],
    ) -> dict[str, tuple[str, ...]]:
        return dict(value)

    @model_validator(mode="after")
    def _validate_availability(self) -> Self:
        for component, versions in self.detected_versions.items():
            _require_unique(versions, f"detected_versions[{component}]")
        _require_unique(self.evidence_sources, "evidence_sources")
        _require_unique(self.limitations, "limitations")

        non_callable_states = {
            AvailabilityStatus.UNAVAILABLE,
            AvailabilityStatus.MISCONFIGURED,
            AvailabilityStatus.UNKNOWN,
        }
        if self.status in non_callable_states and self.callable:
            raise ValueError(f"{self.status.value} availability cannot be callable")
        if self.callable and self.active_variant is None:
            raise ValueError("callable availability requires an active_variant")
        return self


class DomainToolRequest(ContractModel):
    """Common request shape for discovery and exact child execution."""

    child_tool: Identifier | None = None
    arguments: JsonObject | None = None
    manifest_version: NonEmptyText | None = None

    @field_validator("arguments", mode="before")
    @classmethod
    def _normalize_arguments_input(cls, value: Any) -> JsonValue:
        return _thaw_json(value)

    @field_validator("arguments", mode="after")
    @classmethod
    def _freeze_arguments(cls, value: JsonObject | None) -> JsonObject | None:
        return _freeze_json_object(value) if value is not None else None

    @field_serializer("arguments")
    def _serialize_arguments(self, value: JsonObject | None) -> JsonObject | None:
        return cast(JsonObject | None, _thaw_json(value))

    @model_validator(mode="after")
    def _validate_request_mode(self) -> Self:
        if self.child_tool is None and self.arguments:
            raise ValueError("arguments require child_tool")
        return self

    @property
    def is_discovery(self) -> bool:
        return self.child_tool is None

    @property
    def execution_arguments(self) -> JsonObject:
        return dict(self.arguments or {})


class ChildManifestEntry(ContractModel):
    """One authorized child entry returned by domain discovery."""

    name: Identifier
    title: NonEmptyText
    description: NonEmptyText
    input_schema: JsonObject
    output_schema: JsonObject
    version_support: ChildSupportContract
    availability: Availability
    annotations: ToolContractAnnotations

    @field_validator("input_schema", "output_schema", mode="before")
    @classmethod
    def _normalize_schema_input(cls, value: Any) -> JsonValue:
        return _thaw_json(value)

    @field_validator("input_schema", "output_schema", mode="after")
    @classmethod
    def _freeze_schemas(cls, value: JsonObject) -> JsonObject:
        return _freeze_json_object(value)

    @field_serializer("input_schema", "output_schema")
    def _serialize_schemas(self, value: JsonObject) -> JsonObject:
        return cast(JsonObject, _thaw_json(value))

    @model_validator(mode="after")
    def _validate_manifest_entry(self) -> Self:
        _check_object_schema(self.input_schema, "input_schema")
        _check_object_schema(self.output_schema, "output_schema")
        return self


class DiscoveryEnvelope(ContractModel):
    """Stable structured result for an empty domain discovery call."""

    mode: Literal["manifest"]
    domain: Identifier
    manifest_version: NonEmptyText
    generated_at: datetime
    children: tuple[ChildManifestEntry, ...]

    @model_validator(mode="after")
    def _validate_manifest(self) -> Self:
        if self.generated_at.utcoffset() is None:
            raise ValueError("generated_at must include a timezone")
        _require_unique(
            tuple(child.name for child in self.children),
            "manifest child names",
        )
        return self


class ExecutionMetadata(ContractModel):
    """Bounded metadata for an exact child execution result."""

    request_id: NonEmptyText
    duration_ms: Annotated[float, Field(ge=0)]
    source: Identifier
    truncated: bool


class ExecutionEnvelope(ContractModel):
    """Stable structured result for one exact child execution."""

    mode: Literal["result"]
    domain: Identifier
    child_tool: Identifier
    manifest_version: NonEmptyText
    data: JsonValue
    metadata: ExecutionMetadata
    warnings: tuple[NonEmptyText, ...] = ()

    @field_validator("data", mode="before")
    @classmethod
    def _normalize_data_input(cls, value: Any) -> JsonValue:
        return _thaw_json(value)

    @field_validator("data", mode="after")
    @classmethod
    def _freeze_data(cls, value: JsonValue) -> JsonValue:
        return _freeze_json(value)

    @field_serializer("data")
    def _serialize_data(self, value: JsonValue) -> JsonValue:
        return _thaw_json(value)

    @model_validator(mode="after")
    def _validate_warnings(self) -> Self:
        _require_unique(self.warnings, "warnings")
        return self


class StandardError(ContractModel):
    """Safe, machine-readable hierarchical tool failure."""

    code: DomainErrorCode
    message: NonEmptyText
    retryable: bool
    details: JsonObject = Field(default_factory=dict)

    @field_validator("details", mode="before")
    @classmethod
    def _normalize_details_input(cls, value: Any) -> JsonValue:
        return _thaw_json(value)

    @field_validator("details", mode="after")
    @classmethod
    def _freeze_details(cls, value: JsonObject) -> JsonObject:
        return _freeze_json_object(value)

    @field_serializer("details")
    def _serialize_details(self, value: JsonObject) -> JsonObject:
        return cast(JsonObject, _thaw_json(value))


class ErrorEnvelope(ContractModel):
    """Stable structured failure for discovery or execution."""

    mode: Literal["error"]
    domain: Identifier
    child_tool: Identifier | None = None
    manifest_version: NonEmptyText | None = None
    error: StandardError


def _require_unique(values: tuple[str, ...], field_name: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{field_name} must not contain duplicates")


def _check_object_schema(schema: JsonObject, field_name: str) -> None:
    if schema.get("type") != "object":
        raise ValueError(f"{field_name} root type must be object")
    try:
        thawed = cast(dict[str, Any], _thaw_json(schema))
        Draft202012Validator.check_schema(thawed)
    except SchemaError as exc:
        raise ValueError(f"{field_name} is not a valid JSON Schema") from exc


def _freeze_json_object(value: JsonObject) -> JsonObject:
    return cast(JsonObject, _freeze_json(value))


def _freeze_json(value: JsonValue) -> JsonValue:
    if isinstance(value, dict):
        return cast(
            JsonValue,
            MappingProxyType(
                {key: _freeze_json(item) for key, item in value.items()}
            ),
        )
    if isinstance(value, list):
        return cast(JsonValue, tuple(_freeze_json(item) for item in value))
    return value


def _thaw_json(value: Any) -> JsonValue:
    if isinstance(value, Mapping):
        return {str(key): _thaw_json(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_thaw_json(item) for item in value]
    return cast(JsonValue, value)


def _require_acyclic(graph: dict[str, tuple[str, ...]]) -> None:
    states: dict[str, int] = {}

    def visit(node: str) -> None:
        state = states.get(node, 0)
        if state == 1:
            raise ValueError("composite plan must be acyclic")
        if state == 2:
            return
        states[node] = 1
        for dependency in graph[node]:
            visit(dependency)
        states[node] = 2

    for node in graph:
        visit(node)


__all__ = [
    "MAX_DOMAIN_MANIFEST_BYTES",
    "Availability",
    "AvailabilityStatus",
    "CapabilityVariant",
    "ChildManifestEntry",
    "ChildSupportContract",
    "ChildToolDefinition",
    "CompositePlan",
    "CompositeStep",
    "DiscoveryEnvelope",
    "DomainDefinition",
    "DomainErrorCode",
    "DomainToolRequest",
    "ErrorEnvelope",
    "ExecutionEnvelope",
    "ExecutionMetadata",
    "JsonObject",
    "StandardError",
    "ToolContractAnnotations",
    "UnavailableBehavior",
]
