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

"""Bounded progressive discovery for the eight read-only Doris domains."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from mcp.types import Tool, ToolAnnotations
from pydantic import ValidationError

from ..auth.operation_policy import (
    authorize_operation,
    filter_tools_for_auth_context,
)
from ..utils.logger import get_audit_logger
from ..utils.security import get_current_auth_context
from .domain_catalog import DORIS_DOMAIN_CATALOG, DorisDomainCatalog
from .domain_models import (
    Availability,
    AvailabilityStatus,
    ChildManifestEntry,
    ChildToolDefinition,
    DiscoveryEnvelope,
    DomainDefinition,
    DomainErrorCode,
    DomainToolRequest,
    ErrorEnvelope,
    ManifestVersionSupport,
    StandardError,
)

MAX_CHILD_DESCRIPTION_CHARACTERS = 800
MAX_CHILD_SCHEMA_BYTES = 4 * 1024
MAX_SCHEMA_ENUM_VALUES = 32
MAX_TOP_LEVEL_TOOL_LIST_BYTES = 24 * 1024
MANIFEST_FORMAT_VERSION = "1"

DOMAIN_DISCOVERY_DESCRIPTION_SUFFIX = (
    " Choose one matching domain; do not speculatively open others. Call with "
    "an empty object to discover its exact child tools and schemas, then call "
    "it again with the returned child_tool and arguments."
)

DOMAIN_TOOL_INPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "child_tool": {
            "type": "string",
            "minLength": 1,
            "description": (
                "Exact child tool name returned by this domain manifest."
            ),
        },
        "arguments": {
            "type": "object",
            "description": (
                "Arguments validated against the selected child tool schema."
            ),
        },
        "manifest_version": {
            "type": "string",
            "minLength": 1,
            "description": (
                "Optional manifest version returned by domain discovery."
            ),
        },
    },
    "additionalProperties": False,
}

# The complete child contract is validated by DiscoveryEnvelope before it reaches
# the protocol layer. This compact outer schema avoids repeating the manifest
# implementation schema eight times in tools/list.
_DOMAIN_MANIFEST_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "mode": {"type": "string", "const": "manifest"},
        "domain": {"type": "string"},
        "manifest_version": {"type": "string"},
        "generated_at": {"type": "string", "format": "date-time"},
        "children": {
            "type": "array",
            "items": {"type": "object"},
        },
    },
    "required": [
        "mode",
        "domain",
        "manifest_version",
        "generated_at",
        "children",
    ],
    "additionalProperties": False,
}

_DOMAIN_EXECUTION_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "mode": {"type": "string", "const": "result"},
        "domain": {"type": "string"},
        "child_tool": {"type": "string"},
        "manifest_version": {"type": "string"},
        "data": {"type": "object"},
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

DOMAIN_ERROR_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "mode": {"type": "string", "const": "error"},
        "domain": {"type": "string", "minLength": 1},
        "child_tool": {"type": "string", "minLength": 1},
        "manifest_version": {"type": "string", "minLength": 1},
        "error": {
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "enum": [code.value for code in DomainErrorCode],
                },
                "message": {"type": "string", "minLength": 1},
                "retryable": {"type": "boolean"},
                "details": {
                    "type": "object",
                    "additionalProperties": True,
                },
            },
            "required": ["code", "message", "retryable", "details"],
            "additionalProperties": False,
        },
    },
    "required": ["mode", "domain", "error"],
    "additionalProperties": False,
}

DOMAIN_TOOL_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "oneOf": [
        _DOMAIN_MANIFEST_OUTPUT_SCHEMA,
        _DOMAIN_EXECUTION_OUTPUT_SCHEMA,
        DOMAIN_ERROR_OUTPUT_SCHEMA,
    ],
}


class DomainManifestError(ValueError):
    """Raised when a domain manifest cannot be rendered safely."""


class DomainManifestBudgetError(DomainManifestError):
    """Raised when public tool exposure exceeds a hard context budget."""


class DomainAvailabilityProvider(Protocol):
    """Resolve the current capability state for one authorized child."""

    async def availability_for(
        self,
        domain: DomainDefinition,
        child: ChildToolDefinition,
        auth_context: Any | None,
    ) -> Availability:
        """Return authoritative availability for a single child."""


@dataclass(frozen=True, slots=True)
class DomainAvailabilityResolution:
    """One coherent capability generation for a domain manifest."""

    availabilities: Mapping[str, Availability]
    generation_fingerprint: str = ""


class PendingCapabilityProvider:
    """Fail-closed provider used until runtime capability snapshots are enabled."""

    async def availability_for(
        self,
        domain: DomainDefinition,
        child: ChildToolDefinition,
        auth_context: Any | None,
    ) -> Availability:
        del domain, child, auth_context
        return pending_capability_availability()


ChildDiscoveryPolicy = Callable[
    [Any | None, DomainDefinition, ChildToolDefinition],
    bool,
]


def pending_capability_availability() -> Availability:
    """Return the explicit pre-probe state without guessing backend support."""
    return Availability(
        status=AvailabilityStatus.UNKNOWN,
        callable=False,
        reason_code="CAPABILITY_SNAPSHOT_PENDING",
        evidence_sources=("catalog_contract",),
    )


def authorized_child_discovery(
    auth_context: Any | None,
    domain: DomainDefinition,
    child: ChildToolDefinition,
) -> bool:
    """Require exact OAuth discovery grants and preserve local compatibility."""
    if auth_context is None:
        return True

    auth_method = str(getattr(auth_context, "auth_method", ""))
    is_oauth = auth_method in {"external_oauth", "doris_oauth"}
    collection_names = (
        ("oauth_scopes",)
        if is_oauth
        else ("permissions", "oauth_scopes")
    )
    controls = {
        str(value)
        for collection_name in collection_names
        for value in (getattr(auth_context, collection_name, None) or ())
    }
    if is_oauth and domain.name == "doris_semantic":
        if (
            not bool(
                getattr(
                    auth_context,
                    "semantic_tools_enabled",
                    False,
                )
            )
            or "semantic:read" not in controls
        ):
            return False
    child_controls = {
        value
        for value in controls
        if value.startswith(("child:call:", "child:discover:"))
    }
    if not is_oauth and not child_controls:
        return True

    if auth_method == "doris_oauth":
        feature_id = f"{domain.name}.{child.name}"
        if not bool(
            getattr(
                auth_context,
                "doris_oauth_child_tools_enabled",
                False,
            )
        ):
            return False
        allowlist = {
            str(value)
            for value in (
                getattr(
                    auth_context,
                    "doris_oauth_child_tool_allowlist",
                    (),
                )
                or ()
            )
        }
        if feature_id not in allowlist:
            return False

    discover_policy = child.authorization_policy.replace(
        "child:call:",
        "child:discover:",
        1,
    )
    return (
        child.authorization_policy in child_controls
        or discover_policy in child_controls
    )


def authorized_child_execution(
    auth_context: Any | None,
    domain: DomainDefinition,
    child: ChildToolDefinition,
) -> bool:
    """Require an exact child call grant on OAuth execution paths."""
    if auth_context is None:
        return True

    auth_method = str(getattr(auth_context, "auth_method", ""))
    is_oauth = auth_method in {"external_oauth", "doris_oauth"}
    collection_names = (
        ("oauth_scopes",)
        if is_oauth
        else ("permissions", "oauth_scopes")
    )
    controls = {
        str(value)
        for collection_name in collection_names
        for value in (getattr(auth_context, collection_name, None) or ())
    }
    if is_oauth and domain.name == "doris_semantic":
        if (
            not bool(
                getattr(
                    auth_context,
                    "semantic_tools_enabled",
                    False,
                )
            )
            or "semantic:read" not in controls
        ):
            return False

    if auth_method == "doris_oauth":
        feature_id = f"{domain.name}.{child.name}"
        if not bool(
            getattr(
                auth_context,
                "doris_oauth_child_tools_enabled",
                False,
            )
        ):
            return False
        allowlist = {
            str(value)
            for value in (
                getattr(
                    auth_context,
                    "doris_oauth_child_tool_allowlist",
                    (),
                )
                or ()
            )
        }
        if feature_id not in allowlist:
            return False

    if child.authorization_policy in controls:
        return True

    if is_oauth:
        return False

    child_controls = {
        value
        for value in controls
        if value.startswith(("child:call:", "child:discover:"))
    }
    return not child_controls


class DomainManifestService:
    """Render top-level domain tools and deterministic authorized manifests."""

    def __init__(
        self,
        *,
        catalog: DorisDomainCatalog = DORIS_DOMAIN_CATALOG,
        availability_provider: DomainAvailabilityProvider | None = None,
        discovery_policy: ChildDiscoveryPolicy = authorized_child_discovery,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        catalog.validate_integrity()
        self._catalog = catalog
        self._availability_provider = (
            availability_provider or PendingCapabilityProvider()
        )
        self._discovery_policy = discovery_policy
        self._clock = clock or (lambda: datetime.now(UTC))
        self._domain_names = frozenset(
            domain.name for domain in self._catalog.domains
        )
        self._tools = tuple(
            _build_top_level_tool(domain)
            for domain in self._catalog.domains
        )
        self._top_level_tool_list_bytes = _top_level_tool_list_size_bytes(
            self._tools
        )
        if self._top_level_tool_list_bytes > MAX_TOP_LEVEL_TOOL_LIST_BYTES:
            raise DomainManifestBudgetError(
                "top-level tools/list is "
                f"{self._top_level_tool_list_bytes} bytes; "
                f"limit is {MAX_TOP_LEVEL_TOOL_LIST_BYTES} bytes"
            )
        self.validate_default_manifest_budgets()

    @property
    def domain_names(self) -> frozenset[str]:
        return self._domain_names

    @property
    def top_level_tool_list_bytes(self) -> int:
        """Return the deterministic serialized size of the stable tool list."""
        return self._top_level_tool_list_bytes

    def handles(self, name: str) -> bool:
        """Return whether a name is one of the exact top-level domains."""
        return name in self._domain_names

    def list_tools(self) -> list[Tool]:
        """Return all stable read-only top-level domain tools."""
        return list(self._tools)

    def render_markdown(self) -> str:
        """Render the complete deterministic 1.0 tool catalog."""
        return self._catalog.render_markdown()

    async def call(
        self,
        domain_name: str,
        arguments: Mapping[str, Any],
        auth_context: Any | None,
    ) -> DiscoveryEnvelope | ErrorEnvelope:
        """Handle discovery now and reject child execution until the dispatcher."""
        domain = self._catalog.resolve_domain(domain_name)
        try:
            request = DomainToolRequest.model_validate(dict(arguments))
        except ValidationError:
            return ErrorEnvelope(
                mode="error",
                domain=domain.name,
                error=StandardError(
                    code=DomainErrorCode.CHILD_ARGUMENTS_INVALID,
                    message="Domain tool arguments are invalid.",
                    retryable=False,
                    details={"rediscover": True},
                ),
            )

        if not request.is_discovery:
            return ErrorEnvelope(
                mode="error",
                domain=domain.name,
                child_tool=request.child_tool,
                manifest_version=request.manifest_version,
                error=StandardError(
                    code=DomainErrorCode.CHILD_CAPABILITY_UNAVAILABLE,
                    message=(
                        "Exact child execution is not enabled by this runtime "
                        "stage."
                    ),
                    retryable=False,
                    details={"rediscover": False},
                ),
            )

        return await self.discover(domain, auth_context)

    async def discover(
        self,
        domain: DomainDefinition,
        auth_context: Any | None,
    ) -> DiscoveryEnvelope:
        """Build the current authorized manifest in stable catalog order."""
        authorized_children = tuple(
            child
            for child in domain.children
            if self._discovery_policy(auth_context, domain, child)
        )
        batch_resolver = getattr(
            self._availability_provider,
            "resolve_domain",
            None,
        )
        if callable(batch_resolver):
            resolution = await batch_resolver(
                domain,
                authorized_children,
                auth_context,
            )
            if not isinstance(
                resolution,
                DomainAvailabilityResolution,
            ):
                raise TypeError(
                    "domain availability resolver returned an invalid result"
                )
            batch_entries = [
                _render_child(
                    child,
                    resolution.availabilities[child.name],
                )
                for child in authorized_children
            ]
            return _build_manifest(
                domain,
                tuple(batch_entries),
                generated_at=self._clock(),
                generation_fingerprint=(
                    resolution.generation_fingerprint
                ),
            )

        entries: list[ChildManifestEntry] = []
        for child in authorized_children:
            availability = await self._availability_provider.availability_for(
                domain,
                child,
                auth_context,
            )
            entries.append(_render_child(child, availability))

        generation_fingerprint = ""
        resolve_generation = getattr(
            self._availability_provider,
            "manifest_generation",
            None,
        )
        if callable(resolve_generation):
            resolved = await resolve_generation(domain, auth_context)
            if isinstance(resolved, str):
                generation_fingerprint = resolved

        return _build_manifest(
            domain,
            tuple(entries),
            generated_at=self._clock(),
            generation_fingerprint=generation_fingerprint,
        )

    def validate_default_manifest_budgets(self) -> None:
        """Fail startup if the maximum public catalog cannot fit its budgets."""
        generated_at = datetime(2000, 1, 1, tzinfo=UTC)
        for domain in self._catalog.domains:
            entries = tuple(
                _render_child(child, pending_capability_availability())
                for child in domain.children
            )
            _build_manifest(
                domain,
                entries,
                generated_at=generated_at,
            )


class DomainManifestManagerMixin:
    """Integrate domain discovery without growing the legacy handler manager."""

    _domain_manifest_service: DomainManifestService

    @property
    def domain_manifest_service(self) -> DomainManifestService:
        """Return the discovery service, including minimal legacy fixtures."""
        service = getattr(self, "_domain_manifest_service", None)
        if service is None:
            service = DomainManifestService()
            self._domain_manifest_service = service
        return service

    async def list_tools(self) -> list[Tool]:
        """List the eight stable read-only domains visible to this principal."""
        return filter_tools_for_auth_context(
            get_current_auth_context(),
            self.domain_manifest_service.list_tools(),
        )

    async def _call_domain_tool(
        self,
        name: str,
        arguments: dict[str, Any],
    ) -> str:
        """Return a bounded domain manifest without exposing internal handlers."""
        auth_context = get_current_auth_context()
        authorize_operation(auth_context, f"tool:{name}")
        result = await self.domain_manifest_service.call(
            name,
            arguments,
            auth_context,
        )
        get_audit_logger().info(
            "event=mcp.tool.call.%s tool=%s category=domain risk=metadata "
            "status=%s argument_names=%s",
            name,
            name,
            "error" if result.mode == "error" else "success",
            ",".join(sorted(arguments)),
        )
        return result.to_canonical_json()


def _build_top_level_tool(domain: DomainDefinition) -> Tool:
    annotations = domain.annotations
    return Tool(
        name=domain.name,
        title=domain.title,
        description=domain.description + DOMAIN_DISCOVERY_DESCRIPTION_SUFFIX,
        input_schema=DOMAIN_TOOL_INPUT_SCHEMA,
        output_schema=DOMAIN_TOOL_OUTPUT_SCHEMA,
        annotations=ToolAnnotations(
            title=domain.title,
            read_only_hint=annotations.read_only,
            destructive_hint=annotations.destructive,
            idempotent_hint=annotations.idempotent,
            open_world_hint=annotations.open_world,
        ),
    )


def _top_level_tool_list_size_bytes(tools: Sequence[Tool]) -> int:
    payload = {
        "tools": [
            tool.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            )
            for tool in tools
        ]
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return len(canonical.encode("utf-8"))


def _render_child(
    child: ChildToolDefinition,
    availability: Availability,
) -> ChildManifestEntry:
    description = _dynamic_description(
        child.canonical_description,
        availability,
    )
    _validate_child_budget(child, description)
    return ChildManifestEntry(
        name=child.name,
        title=child.title,
        description=description,
        input_schema=_compact_manifest_input_schema(child.input_schema),
        output_schema={"type": "object"},
        version_support=ManifestVersionSupport.from_contract(
            child.support_contract
        ),
        availability=availability,
        annotations=child.annotations,
    )


def _compact_manifest_input_schema(value: Any) -> Any:
    """Expose the call signature while keeping full validation server-side."""
    if isinstance(value, Mapping):
        return {
            str(key): _compact_manifest_input_schema(item)
            for key, item in value.items()
            if key
            not in {
                "description",
                "examples",
                "maxItems",
                "maxLength",
                "minItems",
                "pattern",
                "title",
                "uniqueItems",
            }
        }
    if isinstance(value, Sequence) and not isinstance(value, str | bytes):
        return [_compact_manifest_input_schema(item) for item in value]
    return value


def _dynamic_description(
    canonical_description: str,
    availability: Availability,
) -> str:
    context = _availability_context(availability)
    return (
        f"[{availability.status.value.upper()} | {context}] "
        f"{canonical_description}"
    )


def _availability_context(availability: Availability) -> str:
    context: list[str] = []
    if availability.detected_versions:
        component = next(
            (
                candidate
                for candidate in ("master_fe", "fe", "be")
                if candidate in availability.detected_versions
            ),
            sorted(availability.detected_versions)[0],
        )
        versions = availability.detected_versions[component]
        if versions:
            context.append(f"Doris {versions[0]}")
    if availability.active_variant is not None:
        context.append(availability.active_variant)
    if not context:
        context.append(
            availability.reason_code.lower().replace("_", " ")
        )
    return " | ".join(context)


def _build_manifest(
    domain: DomainDefinition,
    entries: tuple[ChildManifestEntry, ...],
    *,
    generated_at: datetime,
    generation_fingerprint: str = "",
) -> DiscoveryEnvelope:
    version = _manifest_version(
        domain,
        entries,
        generation_fingerprint=generation_fingerprint,
    )
    envelope = DiscoveryEnvelope(
        mode="manifest",
        domain=domain.name,
        manifest_version=version,
        generated_at=generated_at,
        children=entries,
    )
    size = len(envelope.to_canonical_json().encode("utf-8"))
    if size > domain.max_manifest_bytes:
        raise DomainManifestBudgetError(
            f"domain {domain.name!r} manifest is {size} bytes; "
            f"limit is {domain.max_manifest_bytes} bytes"
        )
    return envelope


def _manifest_version(
    domain: DomainDefinition,
    entries: Sequence[ChildManifestEntry],
    *,
    generation_fingerprint: str = "",
) -> str:
    payload = {
        "format_version": MANIFEST_FORMAT_VERSION,
        "domain_contract": domain.to_wire(),
        "children": [entry.to_wire() for entry in entries],
        "capability_generation": generation_fingerprint,
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]
    prefix = domain.name.removeprefix("doris_")
    return f"{prefix}.{digest}"


def _validate_child_budget(
    child: ChildToolDefinition,
    description: str,
) -> None:
    feature_id = child.handler_name.removeprefix("child:")
    child_wire = child.to_wire()
    if len(description) > MAX_CHILD_DESCRIPTION_CHARACTERS:
        raise DomainManifestBudgetError(
            f"{feature_id} description exceeds "
            f"{MAX_CHILD_DESCRIPTION_CHARACTERS} characters"
        )
    for label, schema in (
        ("input", child_wire["input_schema"]),
        ("output", child_wire["output_schema"]),
    ):
        size = len(
            json.dumps(
                schema,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        )
        if size > MAX_CHILD_SCHEMA_BYTES:
            raise DomainManifestBudgetError(
                f"{feature_id} {label} schema is {size} bytes; "
                f"limit is {MAX_CHILD_SCHEMA_BYTES} bytes"
            )
        _validate_enum_budget(feature_id, label, schema)


def _validate_enum_budget(
    feature_id: str,
    label: str,
    value: Any,
) -> None:
    if isinstance(value, Mapping):
        enum = value.get("enum")
        if isinstance(enum, Sequence) and not isinstance(enum, str | bytes):
            if len(enum) > MAX_SCHEMA_ENUM_VALUES:
                raise DomainManifestBudgetError(
                    f"{feature_id} {label} schema enum exceeds "
                    f"{MAX_SCHEMA_ENUM_VALUES} values"
                )
        for child in value.values():
            _validate_enum_budget(feature_id, label, child)
    elif isinstance(value, Sequence) and not isinstance(value, str | bytes):
        for child in value:
            _validate_enum_budget(feature_id, label, child)


__all__ = [
    "DOMAIN_DISCOVERY_DESCRIPTION_SUFFIX",
    "DOMAIN_ERROR_OUTPUT_SCHEMA",
    "DOMAIN_TOOL_OUTPUT_SCHEMA",
    "DOMAIN_TOOL_INPUT_SCHEMA",
    "MAX_CHILD_DESCRIPTION_CHARACTERS",
    "MAX_CHILD_SCHEMA_BYTES",
    "MAX_SCHEMA_ENUM_VALUES",
    "MAX_TOP_LEVEL_TOOL_LIST_BYTES",
    "ChildDiscoveryPolicy",
    "DomainAvailabilityProvider",
    "DomainAvailabilityResolution",
    "DomainManifestBudgetError",
    "DomainManifestError",
    "DomainManifestManagerMixin",
    "DomainManifestService",
    "PendingCapabilityProvider",
    "authorized_child_discovery",
    "authorized_child_execution",
    "pending_capability_availability",
]
