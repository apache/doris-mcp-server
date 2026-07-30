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
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""Bounded JSON Schema 2020-12 validation for MCP tool definitions and calls."""

from __future__ import annotations

import hashlib
import json
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError
from mcp.types import Tool

JSON_SCHEMA_2020_12 = "https://json-schema.org/draft/2020-12/schema"
_SUPPORTED_DIALECTS = frozenset(
    {
        JSON_SCHEMA_2020_12,
        f"{JSON_SCHEMA_2020_12}#",
    }
)
_REFERENCE_KEYWORDS = frozenset({"$ref", "$dynamicRef"})
_COMBINATOR_KEYWORDS = frozenset({"allOf", "anyOf", "oneOf"})


@dataclass(frozen=True)
class SchemaLimits:
    """Hard limits applied before a JSON Schema validator is constructed."""

    max_schema_bytes: int = 65_536
    max_schema_nodes: int = 2_048
    max_schema_depth: int = 32
    max_combinator_branches: int = 64
    max_references: int = 64
    max_enum_values: int = 256
    max_pattern_length: int = 512
    max_instance_bytes: int = 1_048_576
    max_instance_nodes: int = 10_000
    max_instance_depth: int = 32
    max_instance_string_length: int = 262_144
    max_validation_errors: int = 16
    max_cached_schemas: int = 256


DEFAULT_SCHEMA_LIMITS = SchemaLimits()


class ToolSchemaDefinitionError(ValueError):
    """A server-owned tool definition is invalid or exceeds policy."""


@dataclass(frozen=True)
class SchemaViolation:
    """A value failed one schema keyword without echoing the value."""

    instance_path: str
    keyword: str

    def as_dict(self) -> dict[str, str]:
        return {
            "instancePath": self.instance_path,
            "keyword": self.keyword,
        }


class ToolArgumentsValidationError(ValueError):
    """Tool arguments do not satisfy the advertised input schema."""

    def __init__(
        self,
        violations: Sequence[SchemaViolation],
        *,
        truncated: bool = False,
    ) -> None:
        super().__init__("Tool arguments do not match input schema")
        self.violations = tuple(violations)
        self.truncated = truncated


class ToolOutputValidationError(ValueError):
    """A successful tool result does not satisfy its output schema."""


@dataclass(frozen=True)
class _SchemaMetrics:
    graph: Mapping[int, frozenset[int]]
    references: tuple[tuple[Mapping[str, Any], str, str], ...]


@dataclass(frozen=True)
class CompiledToolSchema:
    """Compiled validators for one input/output schema pair."""

    input_validator: Draft202012Validator
    output_validator: Draft202012Validator | None
    limits: SchemaLimits

    def validate_arguments(self, arguments: Mapping[str, Any]) -> None:
        _validate_instance_limits(arguments, self.limits)
        violations, truncated = _collect_violations(
            self.input_validator,
            arguments,
            self.limits.max_validation_errors,
        )
        if violations:
            raise ToolArgumentsValidationError(
                violations,
                truncated=truncated,
            )

    def validate_output(self, output: Any) -> None:
        if self.output_validator is None:
            return
        if output is None:
            raise ToolOutputValidationError(
                "Tool declared outputSchema but returned no structured content"
            )
        try:
            _validate_instance_limits(output, self.limits)
        except ToolArgumentsValidationError as exc:
            raise ToolOutputValidationError(
                "Tool structured content exceeds output limits"
            ) from exc
        violations, _ = _collect_violations(
            self.output_validator,
            output,
            self.limits.max_validation_errors,
        )
        if violations:
            raise ToolOutputValidationError(
                "Tool structured content does not match output schema"
            )


class ToolSchemaGuard:
    """Compile, cache, and apply schemas for the visible tool catalog."""

    def __init__(self, limits: SchemaLimits = DEFAULT_SCHEMA_LIMITS) -> None:
        self.limits = limits
        self._cache: OrderedDict[str, CompiledToolSchema] = OrderedDict()

    def compile_catalog(self, tools: Sequence[Tool]) -> dict[str, CompiledToolSchema]:
        compiled: dict[str, CompiledToolSchema] = {}
        for tool in tools:
            if tool.name in compiled:
                raise ToolSchemaDefinitionError(
                    f"Tool catalog contains duplicate name {tool.name!r}"
                )
            compiled[tool.name] = self.compile_tool(tool)
        return compiled

    def compile_tool(self, tool: Tool) -> CompiledToolSchema:
        cache_key = _schema_cache_key(tool.input_schema, tool.output_schema)
        cached = self._cache.get(cache_key)
        if cached is not None:
            self._cache.move_to_end(cache_key)
            return cached

        try:
            input_validator = _compile_schema(
                tool.input_schema,
                limits=self.limits,
                require_object_root=True,
            )
            output_validator = (
                _compile_schema(
                    tool.output_schema,
                    limits=self.limits,
                    require_object_root=False,
                )
                if tool.output_schema is not None
                else None
            )
        except ToolSchemaDefinitionError as exc:
            raise ToolSchemaDefinitionError(
                f"Invalid schema for tool {tool.name!r}: {exc}"
            ) from exc

        compiled = CompiledToolSchema(
            input_validator=input_validator,
            output_validator=output_validator,
            limits=self.limits,
        )
        self._cache[cache_key] = compiled
        self._cache.move_to_end(cache_key)
        while len(self._cache) > self.limits.max_cached_schemas:
            self._cache.popitem(last=False)
        return compiled


def _schema_cache_key(
    input_schema: Mapping[str, Any],
    output_schema: Mapping[str, Any] | None,
) -> str:
    try:
        payload = json.dumps(
            [input_schema, output_schema],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ToolSchemaDefinitionError(
            "schema must be an acyclic JSON value"
        ) from exc
    return hashlib.sha256(payload).hexdigest()


def _compile_schema(
    schema: Mapping[str, Any],
    *,
    limits: SchemaLimits,
    require_object_root: bool,
) -> Draft202012Validator:
    if require_object_root and schema.get("type") != "object":
        raise ToolSchemaDefinitionError(
            'inputSchema must declare type: "object" at the root'
        )

    dialect = schema.get("$schema")
    if dialect is not None and dialect not in _SUPPORTED_DIALECTS:
        raise ToolSchemaDefinitionError(
            "only the JSON Schema 2020-12 dialect is supported"
        )

    metrics = _measure_schema(schema, limits)
    graph = _validate_local_references(schema, metrics)
    _reject_reference_cycles(graph)

    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        path = _json_pointer(exc.absolute_path)
        location = path or "/"
        raise ToolSchemaDefinitionError(
            f"schema is not valid JSON Schema 2020-12 at {location}"
        ) from exc

    return Draft202012Validator(
        schema,
        format_checker=FormatChecker(),
    )


def _measure_schema(
    schema: Mapping[str, Any],
    limits: SchemaLimits,
) -> _SchemaMetrics:
    stack: list[tuple[Any, int, int | None]] = [(schema, 0, None)]
    seen_containers: set[int] = set()
    graph: dict[int, set[int]] = {}
    references: list[tuple[Mapping[str, Any], str, str]] = []
    node_count = 0
    combinator_branches = 0
    reference_count = 0

    while stack:
        value, depth, parent_id = stack.pop()
        node_count += 1
        if node_count > limits.max_schema_nodes:
            raise ToolSchemaDefinitionError(
                f"schema exceeds {limits.max_schema_nodes} nodes"
            )
        if depth > limits.max_schema_depth:
            raise ToolSchemaDefinitionError(
                f"schema exceeds depth {limits.max_schema_depth}"
            )

        if isinstance(value, str):
            continue
        if isinstance(value, Mapping):
            container_id = id(value)
            if container_id in seen_containers:
                raise ToolSchemaDefinitionError(
                    "schema must not reuse or cycle Python containers"
                )
            seen_containers.add(container_id)
            graph.setdefault(container_id, set())
            if parent_id is not None:
                graph.setdefault(parent_id, set()).add(container_id)

            for keyword in _REFERENCE_KEYWORDS:
                if keyword not in value:
                    continue
                reference = value[keyword]
                if not isinstance(reference, str):
                    raise ToolSchemaDefinitionError(
                        f"{keyword} must be a string"
                    )
                if reference and not reference.startswith("#"):
                    raise ToolSchemaDefinitionError(
                        f"{keyword} must be a same-document reference"
                    )
                reference_count += 1
                if reference_count > limits.max_references:
                    raise ToolSchemaDefinitionError(
                        f"schema exceeds {limits.max_references} references"
                    )
                references.append((value, keyword, reference))

            for keyword in _COMBINATOR_KEYWORDS:
                branches = value.get(keyword)
                if isinstance(branches, list):
                    combinator_branches += len(branches)
                    if combinator_branches > limits.max_combinator_branches:
                        raise ToolSchemaDefinitionError(
                            "schema exceeds "
                            f"{limits.max_combinator_branches} combinator branches"
                        )

            enum_values = value.get("enum")
            if isinstance(enum_values, list) and len(enum_values) > limits.max_enum_values:
                raise ToolSchemaDefinitionError(
                    f"schema enum exceeds {limits.max_enum_values} values"
                )
            pattern = value.get("pattern")
            if isinstance(pattern, str) and len(pattern) > limits.max_pattern_length:
                raise ToolSchemaDefinitionError(
                    f"schema pattern exceeds {limits.max_pattern_length} characters"
                )
            pattern_properties = value.get("patternProperties")
            if isinstance(pattern_properties, Mapping):
                for pattern in pattern_properties:
                    if (
                        isinstance(pattern, str)
                        and len(pattern) > limits.max_pattern_length
                    ):
                        raise ToolSchemaDefinitionError(
                            "schema patternProperties key exceeds "
                            f"{limits.max_pattern_length} characters"
                        )

            for child in reversed(tuple(value.values())):
                stack.append((child, depth + 1, container_id))
            continue

        if isinstance(value, list):
            container_id = id(value)
            if container_id in seen_containers:
                raise ToolSchemaDefinitionError(
                    "schema must not reuse or cycle Python containers"
                )
            seen_containers.add(container_id)
            graph.setdefault(container_id, set())
            if parent_id is not None:
                graph.setdefault(parent_id, set()).add(container_id)
            for child in reversed(value):
                stack.append((child, depth + 1, container_id))

    try:
        encoded = json.dumps(
            schema,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ToolSchemaDefinitionError(
            "schema must be an acyclic JSON value"
        ) from exc
    if len(encoded) > limits.max_schema_bytes:
        raise ToolSchemaDefinitionError(
            f"schema exceeds {limits.max_schema_bytes} bytes"
        )

    return _SchemaMetrics(
        graph={key: frozenset(value) for key, value in graph.items()},
        references=tuple(references),
    )


def _validate_local_references(
    root: Mapping[str, Any],
    metrics: _SchemaMetrics,
) -> Mapping[int, frozenset[int]]:
    anchors: dict[str, Any] = {}
    stack: list[Any] = [root]
    while stack:
        value = stack.pop()
        if isinstance(value, Mapping):
            for keyword in ("$anchor", "$dynamicAnchor"):
                anchor = value.get(keyword)
                if not isinstance(anchor, str):
                    continue
                if anchor in anchors and anchors[anchor] is not value:
                    raise ToolSchemaDefinitionError(
                        f"schema contains duplicate anchor {anchor!r}"
                    )
                anchors[anchor] = value
            stack.extend(value.values())
        elif isinstance(value, list):
            stack.extend(value)

    mutable_graph = {
        key: set(targets)
        for key, targets in metrics.graph.items()
    }
    for source, keyword, reference in metrics.references:
        target = _resolve_local_reference(root, anchors, reference)
        if not isinstance(target, Mapping | bool):
            raise ToolSchemaDefinitionError(
                f"{keyword} target must be a schema"
            )
        if isinstance(target, Mapping):
            mutable_graph.setdefault(id(source), set()).add(id(target))

    return {
        key: frozenset(value)
        for key, value in mutable_graph.items()
    }


def _resolve_local_reference(
    root: Mapping[str, Any],
    anchors: Mapping[str, Any],
    reference: str,
) -> Any:
    if reference in {"", "#"}:
        return root
    fragment = unquote(reference[1:])
    if not fragment.startswith("/"):
        try:
            return anchors[fragment]
        except KeyError as exc:
            raise ToolSchemaDefinitionError(
                f"schema reference points to unknown anchor {fragment!r}"
            ) from exc

    current: Any = root
    for raw_token in fragment[1:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        try:
            if isinstance(current, Mapping):
                current = current[token]
            elif isinstance(current, list):
                current = current[int(token)]
            else:
                raise KeyError(token)
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise ToolSchemaDefinitionError(
                f"schema reference points to missing JSON Pointer {reference!r}"
            ) from exc
    return current


def _reject_reference_cycles(graph: Mapping[int, frozenset[int]]) -> None:
    visiting: set[int] = set()
    visited: set[int] = set()

    def visit(node: int) -> None:
        if node in visiting:
            raise ToolSchemaDefinitionError(
                "recursive local references exceed the bounded validation policy"
            )
        if node in visited:
            return
        visiting.add(node)
        for target in graph.get(node, ()):
            visit(target)
        visiting.remove(node)
        visited.add(node)

    for node in graph:
        visit(node)


def _validate_instance_limits(instance: Any, limits: SchemaLimits) -> None:
    stack: list[tuple[Any, int]] = [(instance, 0)]
    seen_containers: set[int] = set()
    node_count = 0
    while stack:
        value, depth = stack.pop()
        node_count += 1
        if node_count > limits.max_instance_nodes:
            raise ToolArgumentsValidationError(
                [SchemaViolation("", "maxInstanceNodes")]
            )
        if depth > limits.max_instance_depth:
            raise ToolArgumentsValidationError(
                [SchemaViolation("", "maxInstanceDepth")]
            )
        if isinstance(value, str) and len(value) > limits.max_instance_string_length:
            raise ToolArgumentsValidationError(
                [SchemaViolation("", "maxStringLength")]
            )
        if isinstance(value, Mapping):
            container_id = id(value)
            if container_id in seen_containers:
                raise ToolArgumentsValidationError(
                    [SchemaViolation("", "jsonValue")]
                )
            seen_containers.add(container_id)
            for key, child in value.items():
                if not isinstance(key, str):
                    raise ToolArgumentsValidationError(
                        [SchemaViolation("", "jsonObjectKey")]
                    )
                stack.append((child, depth + 1))
        elif isinstance(value, list):
            container_id = id(value)
            if container_id in seen_containers:
                raise ToolArgumentsValidationError(
                    [SchemaViolation("", "jsonValue")]
                )
            seen_containers.add(container_id)
            for child in value:
                stack.append((child, depth + 1))

    try:
        encoded = json.dumps(
            instance,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ToolArgumentsValidationError(
            [SchemaViolation("", "jsonValue")]
        ) from exc
    if len(encoded) > limits.max_instance_bytes:
        raise ToolArgumentsValidationError(
            [SchemaViolation("", "maxInstanceBytes")]
        )


def _collect_violations(
    validator: Draft202012Validator,
    instance: Any,
    limit: int,
) -> tuple[list[SchemaViolation], bool]:
    violations: list[SchemaViolation] = []
    truncated = False
    for error in validator.iter_errors(instance):
        if len(violations) >= limit:
            truncated = True
            break
        keyword = (
            error.validator
            if isinstance(error.validator, str)
            else "schema"
        )
        violations.append(
            SchemaViolation(
                instance_path=_json_pointer(error.absolute_path),
                keyword=keyword,
            )
        )
    return violations, truncated


def _json_pointer(path: Sequence[Any]) -> str:
    if not path:
        return ""
    return "".join(
        f"/{str(token).replace('~', '~0').replace('/', '~1')}"
        for token in path
    )
