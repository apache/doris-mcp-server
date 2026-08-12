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

"""Safe local-file loader and strict validator for the supported Ossie subset."""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from types import MappingProxyType
from typing import Any

import yaml  # type: ignore[import-untyped]
from jsonschema import Draft202012Validator
from yaml.events import AliasEvent  # type: ignore[import-untyped]
from yaml.nodes import MappingNode  # type: ignore[import-untyped]

from .models import (
    OSSIE_BINDING_API_VERSION,
    OSSIE_SCHEMA_SHA256,
    OSSIE_SPEC_VERSION,
    SEMANTIC_MODEL_REF_PATTERN,
    DatasetBinding,
    SemanticAIContext,
    SemanticDataset,
    SemanticExpression,
    SemanticField,
    SemanticMetric,
    SemanticModel,
    SemanticRelationship,
)

_MODEL_REF_RE = re.compile(SEMANTIC_MODEL_REF_PATTERN)
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")
_SELECTOR_COMPONENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,127}$")
_SOURCE_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*"
    r"(?:\.[A-Za-z_][A-Za-z0-9_]*){0,2}$"
)
_QUALIFIED_REFERENCE_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)"
    r"\.([A-Za-z_][A-Za-z0-9_]*)\b"
)
_SIMPLE_COLUMN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_FORBIDDEN_EXPRESSION_RE = re.compile(
    r"(?:^|[^A-Za-z0-9_])"
    r"(?:select|from|join|union|with|insert|update|delete|merge|"
    r"create|alter|drop|truncate|grant|revoke|call|load|outfile)"
    r"(?:$|[^A-Za-z0-9_])",
    re.IGNORECASE,
)
_TEMPORAL_TYPES = frozenset({"Date", "Time", "DateTime", "DateTimeTz"})
_ALLOWED_BINDING_KEYS = frozenset(
    {
        "model_file",
        "model_name",
        "namespace",
        "tags",
        "route_profile",
        "datasets",
    }
)
_ALLOWED_DATASET_BINDING_KEYS = frozenset({"catalog", "database", "object", "kind"})


class SemanticConfigurationError(ValueError):
    """Raised when local Ossie configuration cannot be accepted safely."""

    def __init__(
        self,
        reason_code: str,
        message: str,
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class _StrictSafeLoader(yaml.SafeLoader):
    """SafeLoader with duplicate-key and alias-count rejection."""

    def __init__(self, stream: str, *, max_aliases: int) -> None:
        super().__init__(stream)
        self._max_aliases = max_aliases
        self._alias_count = 0

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(AliasEvent):
            self._alias_count += 1
            if self._alias_count > self._max_aliases:
                raise SemanticConfigurationError(
                    "OSSIE_ALIAS_LIMIT_EXCEEDED",
                    "Ossie YAML alias limit exceeded.",
                )
        return super().compose_node(parent, index)

    def construct_mapping(
        self,
        node: MappingNode,
        deep: bool = False,
    ) -> dict[Any, Any]:
        if not isinstance(node, MappingNode):
            raise SemanticConfigurationError(
                "OSSIE_MODEL_INVALID",
                "Ossie YAML mapping is invalid.",
            )
        mapping: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError as exc:
                raise SemanticConfigurationError(
                    "OSSIE_MODEL_INVALID",
                    "Ossie YAML mapping keys must be scalar.",
                ) from exc
            if duplicate:
                raise SemanticConfigurationError(
                    "OSSIE_DUPLICATE_KEY",
                    "Ossie YAML contains a duplicate key.",
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


@dataclass(frozen=True, slots=True)
class SemanticLoaderLimits:
    max_file_bytes: int = 2 * 1024 * 1024
    max_total_bytes: int = 8 * 1024 * 1024
    max_models: int = 64
    max_depth: int = 32
    max_aliases: int = 32
    max_string_bytes: int = 16 * 1024
    max_expression_bytes: int = 4096


class SemanticRegistry:
    """Immutable exact-reference registry; no fuzzy model selection."""

    def __init__(self, models: Sequence[SemanticModel] = ()) -> None:
        by_ref = {model.model_ref: model for model in models}
        if len(by_ref) != len(models):
            raise SemanticConfigurationError(
                "SEMANTIC_MODEL_AMBIGUOUS",
                "Semantic model references must be unique.",
            )
        self._models = tuple(sorted(models, key=lambda model: model.model_ref))
        self._by_ref = MappingProxyType(by_ref)

    @property
    def models(self) -> tuple[SemanticModel, ...]:
        return self._models

    def get(self, model_ref: str) -> SemanticModel | None:
        return self._by_ref.get(model_ref)


class OssieRegistryLoader:
    """Load a fixed Ossie schema and a private Doris binding manifest."""

    def __init__(
        self,
        *,
        model_directory: str,
        binding_manifest: str,
        limits: SemanticLoaderLimits | None = None,
    ) -> None:
        self._model_directory = Path(model_directory)
        self._binding_manifest = Path(binding_manifest)
        self._limits = limits or SemanticLoaderLimits()
        self._schema = self._load_fixed_schema()
        self._validator = Draft202012Validator(self._schema)

    def load(self) -> SemanticRegistry:
        root = self._validate_model_directory()
        manifest_bytes = self._read_exact_file(
            self._binding_manifest,
            max_bytes=self._limits.max_file_bytes,
            reason_prefix="OSSIE_BINDING",
        )
        manifest = self._parse_document(
            self._binding_manifest,
            manifest_bytes,
        )
        sources = self._validate_binding_manifest(manifest)
        if len(sources) > self._limits.max_models:
            raise SemanticConfigurationError(
                "OSSIE_MODEL_LIMIT_EXCEEDED",
                "Configured Ossie model count exceeds the deployment limit.",
            )

        models: list[SemanticModel] = []
        total_bytes = len(manifest_bytes)
        document_cache: dict[Path, tuple[bytes, Mapping[str, Any]]] = {}
        for model_ref, source_config in sorted(sources.items()):
            model_file = self._resolve_model_file(
                root,
                _required_string(source_config, "model_file"),
            )
            cached = document_cache.get(model_file)
            if cached is None:
                source_bytes = self._read_exact_file(
                    model_file,
                    max_bytes=self._limits.max_file_bytes,
                    reason_prefix="OSSIE_MODEL",
                )
                total_bytes += len(source_bytes)
                if total_bytes > self._limits.max_total_bytes:
                    raise SemanticConfigurationError(
                        "OSSIE_TOTAL_SIZE_LIMIT_EXCEEDED",
                        "Configured Ossie files exceed the total size limit.",
                    )
                document = self._parse_document(model_file, source_bytes)
                self._validate_schema(document)
                cached = (source_bytes, document)
                document_cache[model_file] = cached
            source_bytes, document = cached
            models.append(
                self._build_bound_model(
                    model_ref,
                    source_config,
                    source_bytes,
                    document,
                )
            )
        return SemanticRegistry(models)

    @staticmethod
    def _load_fixed_schema() -> Mapping[str, Any]:
        schema_text = (
            resources.files("doris_mcp_server.semantic")
            .joinpath("osi-schema-0.2.0.dev0.json")
            .read_text(encoding="utf-8")
        )
        schema_digest = hashlib.sha256(schema_text.encode("utf-8")).hexdigest()
        if schema_digest != OSSIE_SCHEMA_SHA256:
            raise SemanticConfigurationError(
                "OSSIE_SCHEMA_DIGEST_MISMATCH",
                "Packaged Ossie schema digest does not match the pinned contract.",
            )
        schema: Mapping[str, Any] = json.loads(schema_text)
        Draft202012Validator.check_schema(schema)
        return schema

    def _validate_model_directory(self) -> Path:
        if not self._model_directory.is_absolute():
            raise SemanticConfigurationError(
                "OSSIE_MODEL_DIRECTORY_INVALID",
                "Ossie model directory must be absolute.",
            )
        if (
            not self._model_directory.exists()
            or not self._model_directory.is_dir()
            or self._model_directory.is_symlink()
        ):
            raise SemanticConfigurationError(
                "OSSIE_MODEL_DIRECTORY_INVALID",
                "Ossie model directory must be a real local directory.",
            )
        return self._model_directory.resolve(strict=True)

    def _resolve_model_file(self, root: Path, configured_path: str) -> Path:
        candidate = Path(configured_path)
        if not candidate.is_absolute():
            candidate = root / candidate
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise SemanticConfigurationError(
                "OSSIE_MODEL_FILE_NOT_FOUND",
                "Configured Ossie model file does not exist.",
            ) from exc
        if not resolved.is_relative_to(root):
            raise SemanticConfigurationError(
                "OSSIE_MODEL_PATH_OUTSIDE_ROOT",
                "Configured Ossie model file is outside the model directory.",
            )
        cursor = candidate
        while cursor != root and cursor.is_relative_to(root):
            if cursor.is_symlink():
                raise SemanticConfigurationError(
                    "OSSIE_MODEL_SYMLINK_REJECTED",
                    "Ossie model files cannot use symbolic links.",
                )
            cursor = cursor.parent
        return resolved

    @staticmethod
    def _read_exact_file(
        path: Path,
        *,
        max_bytes: int,
        reason_prefix: str,
    ) -> bytes:
        if not path.exists() or not path.is_file() or path.is_symlink():
            raise SemanticConfigurationError(
                f"{reason_prefix}_FILE_INVALID",
                "Configured semantic file must be a local regular file.",
            )
        size = path.stat().st_size
        if size <= 0 or size > max_bytes:
            raise SemanticConfigurationError(
                f"{reason_prefix}_FILE_SIZE_INVALID",
                "Configured semantic file size is outside the allowed range.",
            )
        return path.read_bytes()

    def _parse_document(
        self,
        path: Path,
        raw: bytes,
    ) -> Mapping[str, Any]:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SemanticConfigurationError(
                "OSSIE_FILE_ENCODING_INVALID",
                "Ossie files must use UTF-8.",
            ) from exc
        suffix = path.suffix.casefold()
        try:
            if suffix == ".json":
                value = json.loads(
                    text,
                    object_pairs_hook=_json_object_no_duplicates,
                    parse_constant=_reject_json_constant,
                )
            elif suffix in {".yaml", ".yml"}:
                loader = _StrictSafeLoader(
                    text,
                    max_aliases=self._limits.max_aliases,
                )
                try:
                    value = loader.get_data()
                    if loader.check_data():
                        raise SemanticConfigurationError(
                            "OSSIE_MULTIDOCUMENT_YAML_REJECTED",
                            "Ossie YAML must contain exactly one document.",
                        )
                finally:
                    loader.dispose()
            else:
                raise SemanticConfigurationError(
                    "OSSIE_FILE_TYPE_UNSUPPORTED",
                    "Ossie files must use JSON or YAML.",
                )
        except SemanticConfigurationError:
            raise
        except (json.JSONDecodeError, yaml.YAMLError) as exc:
            raise SemanticConfigurationError(
                "OSSIE_MODEL_INVALID",
                "Ossie file could not be parsed.",
            ) from exc
        self._validate_structure(value)
        if not isinstance(value, Mapping):
            raise SemanticConfigurationError(
                "OSSIE_MODEL_INVALID",
                "Ossie document root must be an object.",
            )
        return value

    def _validate_structure(self, value: Any, *, depth: int = 0) -> None:
        if depth > self._limits.max_depth:
            raise SemanticConfigurationError(
                "OSSIE_NESTING_LIMIT_EXCEEDED",
                "Ossie document nesting exceeds the deployment limit.",
            )
        if isinstance(value, str):
            if len(value.encode("utf-8")) > self._limits.max_string_bytes:
                raise SemanticConfigurationError(
                    "OSSIE_STRING_LIMIT_EXCEEDED",
                    "Ossie string exceeds the deployment limit.",
                )
            if any(
                ord(character) < 32 and character not in "\t\n\r" for character in value
            ):
                raise SemanticConfigurationError(
                    "OSSIE_CONTROL_CHARACTER_REJECTED",
                    "Ossie strings cannot contain control characters.",
                )
            return
        if isinstance(value, float) and not math.isfinite(value):
            raise SemanticConfigurationError(
                "OSSIE_NONFINITE_NUMBER_REJECTED",
                "Ossie files cannot contain non-finite numbers.",
            )
        if isinstance(value, Mapping):
            for key, item in value.items():
                if not isinstance(key, str):
                    raise SemanticConfigurationError(
                        "OSSIE_MODEL_INVALID",
                        "Ossie object keys must be strings.",
                    )
                self._validate_structure(key, depth=depth + 1)
                self._validate_structure(item, depth=depth + 1)
        elif isinstance(value, Sequence) and not isinstance(
            value,
            str | bytes | bytearray,
        ):
            for item in value:
                self._validate_structure(item, depth=depth + 1)

    def _validate_schema(self, document: Mapping[str, Any]) -> None:
        if document.get("version") != OSSIE_SPEC_VERSION:
            raise SemanticConfigurationError(
                "OSSIE_VERSION_UNSUPPORTED",
                "Ossie specification version is unsupported.",
            )
        errors = sorted(
            self._validator.iter_errors(document),
            key=lambda error: tuple(str(part) for part in error.absolute_path),
        )
        if errors:
            first = errors[0]
            location = "/".join(str(part) for part in first.absolute_path)
            location = location or "document"
            raise SemanticConfigurationError(
                "OSSIE_MODEL_INVALID",
                f"Ossie schema validation failed at {location}.",
            )

    @staticmethod
    def _validate_binding_manifest(
        manifest: Mapping[str, Any],
    ) -> Mapping[str, Mapping[str, Any]]:
        if set(manifest) != {"api_version", "model_sources"}:
            raise SemanticConfigurationError(
                "OSSIE_BINDING_INVALID",
                "Ossie binding manifest has unsupported fields.",
            )
        if manifest.get("api_version") != OSSIE_BINDING_API_VERSION:
            raise SemanticConfigurationError(
                "OSSIE_BINDING_VERSION_UNSUPPORTED",
                "Ossie binding manifest version is unsupported.",
            )
        sources = manifest.get("model_sources")
        if not isinstance(sources, Mapping) or not sources:
            raise SemanticConfigurationError(
                "OSSIE_BINDING_INVALID",
                "Ossie binding manifest must define model_sources.",
            )
        normalized: dict[str, Mapping[str, Any]] = {}
        for model_ref, config in sources.items():
            if not isinstance(model_ref, str) or not _MODEL_REF_RE.fullmatch(model_ref):
                raise SemanticConfigurationError(
                    "OSSIE_BINDING_INVALID",
                    "Ossie model reference is invalid.",
                )
            if not isinstance(config, Mapping):
                raise SemanticConfigurationError(
                    "OSSIE_BINDING_INVALID",
                    "Ossie model binding must be an object.",
                )
            unknown = set(config) - _ALLOWED_BINDING_KEYS
            if unknown:
                raise SemanticConfigurationError(
                    "OSSIE_BINDING_INVALID",
                    "Ossie model binding has unsupported fields.",
                )
            normalized[model_ref] = config
        return MappingProxyType(normalized)

    def _build_bound_model(
        self,
        model_ref: str,
        source_config: Mapping[str, Any],
        source_bytes: bytes,
        document: Mapping[str, Any],
    ) -> SemanticModel:
        raw_models = document.get("semantic_model")
        if not isinstance(raw_models, list) or not raw_models:
            raise SemanticConfigurationError(
                "OSSIE_MODEL_INVALID",
                "Ossie semantic_model must contain at least one model.",
            )
        requested_name = source_config.get("model_name")
        if requested_name is None:
            if len(raw_models) != 1:
                raise SemanticConfigurationError(
                    "SEMANTIC_MODEL_AMBIGUOUS",
                    "model_name is required when a file contains multiple models.",
                )
            selected = raw_models[0]
        else:
            if not isinstance(requested_name, str):
                raise SemanticConfigurationError(
                    "OSSIE_BINDING_INVALID",
                    "model_name must be a string.",
                )
            matches = [
                candidate
                for candidate in raw_models
                if isinstance(candidate, Mapping)
                and candidate.get("name") == requested_name
            ]
            if len(matches) != 1:
                raise SemanticConfigurationError(
                    "SEMANTIC_MODEL_NOT_FOUND",
                    "Configured Ossie model_name was not found exactly once.",
                )
            selected = matches[0]
        if not isinstance(selected, Mapping):
            raise SemanticConfigurationError(
                "OSSIE_MODEL_INVALID",
                "Ossie semantic model entry must be an object.",
            )

        parsed = self._parse_semantic_model(selected)
        bindings = self._parse_bindings(
            parsed.datasets,
            source_config.get("datasets"),
        )
        route_profile = _required_string(source_config, "route_profile")
        if len(route_profile) > 192:
            raise SemanticConfigurationError(
                "OSSIE_BINDING_INVALID",
                "route_profile exceeds the deployment limit.",
            )
        namespace = source_config.get("namespace", "default")
        if not isinstance(namespace, str) or not _NAME_RE.fullmatch(namespace):
            raise SemanticConfigurationError(
                "OSSIE_BINDING_INVALID",
                "Ossie namespace is invalid.",
            )
        raw_tags = source_config.get("tags", [])
        if (
            not isinstance(raw_tags, list)
            or len(raw_tags) > 32
            or any(
                not isinstance(tag, str) or not _NAME_RE.fullmatch(tag)
                for tag in raw_tags
            )
        ):
            raise SemanticConfigurationError(
                "OSSIE_BINDING_INVALID",
                "Ossie tags are invalid.",
            )

        source_digest = hashlib.sha256(source_bytes).hexdigest()
        binding_payload = {
            "model_ref": model_ref,
            "model_name": parsed.name,
            "namespace": namespace,
            "tags": sorted(raw_tags),
            "route_profile": route_profile,
            "datasets": [
                {
                    "dataset": binding.dataset,
                    "catalog": binding.catalog,
                    "database": binding.database,
                    "object": binding.object_name,
                    "kind": binding.kind,
                }
                for binding in bindings
            ],
        }
        binding_json = json.dumps(
            binding_payload,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        binding_digest = hashlib.sha256(binding_json.encode("utf-8")).hexdigest()
        revision = hashlib.sha256(
            f"{source_digest}:{binding_digest}".encode()
        ).hexdigest()[:16]
        return SemanticModel(
            model_ref=model_ref,
            name=parsed.name,
            namespace=namespace,
            tags=tuple(sorted(raw_tags)),
            description=parsed.description,
            ai_context=parsed.ai_context,
            datasets=parsed.datasets,
            relationships=parsed.relationships,
            metrics=parsed.metrics,
            bindings=bindings,
            route_profile=route_profile,
            source_digest=source_digest,
            revision=revision,
            binding_id=f"binding.{binding_digest[:16]}",
            warnings=parsed.warnings,
        )

    def _parse_semantic_model(
        self,
        raw: Mapping[str, Any],
    ) -> SemanticModel:
        name = _validated_name(raw.get("name"), "semantic model")
        raw_datasets = raw.get("datasets")
        if not isinstance(raw_datasets, list) or not raw_datasets:
            raise SemanticConfigurationError(
                "OSSIE_MODEL_INVALID",
                "Semantic model must contain datasets.",
            )
        datasets = tuple(self._parse_dataset(item) for item in raw_datasets)
        _require_unique(
            (dataset.name for dataset in datasets),
            "dataset names",
        )
        datasets_by_name = {dataset.name: dataset for dataset in datasets}

        raw_relationships = raw.get("relationships", [])
        raw_metrics = raw.get("metrics", [])
        if not isinstance(raw_relationships, list) or not isinstance(
            raw_metrics,
            list,
        ):
            raise SemanticConfigurationError(
                "OSSIE_MODEL_INVALID",
                "Semantic relationships and metrics must be arrays.",
            )
        relationships = tuple(
            self._parse_relationship(item, datasets_by_name)
            for item in raw_relationships
        )
        metrics = tuple(
            self._parse_metric(item, datasets_by_name) for item in raw_metrics
        )
        _require_unique(
            (relationship.name for relationship in relationships),
            "relationship names",
        )
        _require_unique((metric.name for metric in metrics), "metric names")

        warnings: list[str] = []
        for relationship in relationships:
            target = datasets_by_name[relationship.to_dataset]
            unique_targets = {
                target.primary_key,
                *target.unique_keys,
            }
            if relationship.to_columns not in unique_targets:
                warnings.append("SEMANTIC_RELATIONSHIP_TARGET_NOT_DECLARED_UNIQUE")
        if _has_parallel_relationships(relationships):
            warnings.append("SEMANTIC_AMBIGUOUS_JOIN_PATH")
        if _has_relationship_cycle(datasets, relationships):
            warnings.append("SEMANTIC_RELATIONSHIP_CYCLE")

        return SemanticModel(
            model_ref="",
            name=name,
            namespace="",
            tags=(),
            description=_optional_string(raw.get("description")),
            ai_context=_parse_ai_context(raw.get("ai_context")),
            datasets=datasets,
            relationships=relationships,
            metrics=metrics,
            bindings=(),
            route_profile="",
            source_digest="",
            revision="",
            binding_id="",
            warnings=tuple(dict.fromkeys(warnings)),
        )

    def _parse_dataset(self, raw: Any) -> SemanticDataset:
        if not isinstance(raw, Mapping):
            raise SemanticConfigurationError(
                "OSSIE_MODEL_INVALID",
                "Dataset entry must be an object.",
            )
        name = _validated_selector_component(raw.get("name"), "dataset")
        source = _required_string(raw, "source")
        if not _SOURCE_RE.fullmatch(source):
            raise SemanticConfigurationError(
                "OSSIE_QUERY_SOURCE_UNSUPPORTED",
                "Ossie query sources are not supported.",
            )
        raw_fields = raw.get("fields", [])
        if not isinstance(raw_fields, list):
            raise SemanticConfigurationError(
                "OSSIE_MODEL_INVALID",
                "Dataset fields must be an array.",
            )
        fields = tuple(self._parse_field(item, name) for item in raw_fields)
        _require_unique((field.name for field in fields), "field names")
        fields_by_name = {field.name for field in fields}
        primary_key = _string_tuple(raw.get("primary_key", []), "primary_key")
        unique_keys_raw = raw.get("unique_keys", [])
        if not isinstance(unique_keys_raw, list):
            raise SemanticConfigurationError(
                "OSSIE_MODEL_INVALID",
                "unique_keys must be an array.",
            )
        unique_keys = tuple(
            _string_tuple(value, "unique key") for value in unique_keys_raw
        )
        for key_column in (
            *primary_key,
            *(item for key in unique_keys for item in key),
        ):
            if key_column not in fields_by_name:
                raise SemanticConfigurationError(
                    "SEMANTIC_DEPENDENCY_UNRESOLVED",
                    "Dataset key references an unknown field.",
                )
        return SemanticDataset(
            name=name,
            source=source,
            fields=fields,
            primary_key=primary_key,
            unique_keys=unique_keys,
            description=_optional_string(raw.get("description")),
            ai_context=_parse_ai_context(raw.get("ai_context")),
        )

    def _parse_field(
        self,
        raw: Any,
        dataset_name: str,
    ) -> SemanticField:
        if not isinstance(raw, Mapping):
            raise SemanticConfigurationError(
                "OSSIE_MODEL_INVALID",
                "Field entry must be an object.",
            )
        datatype = _optional_string(raw.get("datatype"))
        dimension = raw.get("dimension")
        explicit_is_time: bool | None = None
        if dimension is not None:
            if not isinstance(dimension, Mapping):
                raise SemanticConfigurationError(
                    "OSSIE_MODEL_INVALID",
                    "Field dimension must be an object.",
                )
            raw_is_time = dimension.get("is_time")
            if raw_is_time is not None and not isinstance(raw_is_time, bool):
                raise SemanticConfigurationError(
                    "OSSIE_MODEL_INVALID",
                    "dimension.is_time must be boolean.",
                )
            explicit_is_time = raw_is_time
        return SemanticField(
            name=_validated_selector_component(raw.get("name"), "field"),
            expressions=self._parse_expressions(
                raw.get("expression"),
                datasets=None,
                current_dataset=dataset_name,
                require_dependency=False,
            ),
            label=_optional_string(raw.get("label")),
            description=_optional_string(raw.get("description")),
            datatype=datatype,
            is_time=(
                explicit_is_time
                if explicit_is_time is not None
                else datatype in _TEMPORAL_TYPES
            ),
            ai_context=_parse_ai_context(raw.get("ai_context")),
        )

    def _parse_relationship(
        self,
        raw: Any,
        datasets: Mapping[str, SemanticDataset],
    ) -> SemanticRelationship:
        if not isinstance(raw, Mapping):
            raise SemanticConfigurationError(
                "OSSIE_MODEL_INVALID",
                "Relationship entry must be an object.",
            )
        from_dataset = _required_string(raw, "from")
        to_dataset = _required_string(raw, "to")
        if from_dataset not in datasets or to_dataset not in datasets:
            raise SemanticConfigurationError(
                "SEMANTIC_DEPENDENCY_UNRESOLVED",
                "Relationship references an unknown dataset.",
            )
        from_columns = _string_tuple(raw.get("from_columns"), "from_columns")
        to_columns = _string_tuple(raw.get("to_columns"), "to_columns")
        if not from_columns or len(from_columns) != len(to_columns):
            raise SemanticConfigurationError(
                "OSSIE_MODEL_INVALID",
                "Relationship columns must be non-empty and have equal length.",
            )
        if any(
            column not in datasets[from_dataset].fields_by_name
            for column in from_columns
        ) or any(
            column not in datasets[to_dataset].fields_by_name for column in to_columns
        ):
            raise SemanticConfigurationError(
                "SEMANTIC_DEPENDENCY_UNRESOLVED",
                "Relationship references an unknown field.",
            )
        return SemanticRelationship(
            name=_validated_name(raw.get("name"), "relationship"),
            from_dataset=from_dataset,
            to_dataset=to_dataset,
            from_columns=from_columns,
            to_columns=to_columns,
            ai_context=_parse_ai_context(raw.get("ai_context")),
        )

    def _parse_metric(
        self,
        raw: Any,
        datasets: Mapping[str, SemanticDataset],
    ) -> SemanticMetric:
        if not isinstance(raw, Mapping):
            raise SemanticConfigurationError(
                "OSSIE_MODEL_INVALID",
                "Metric entry must be an object.",
            )
        return SemanticMetric(
            name=_validated_name(raw.get("name"), "metric"),
            expressions=self._parse_expressions(
                raw.get("expression"),
                datasets=datasets,
                current_dataset=None,
                require_dependency=True,
            ),
            description=_optional_string(raw.get("description")),
            datatype=_optional_string(raw.get("datatype")),
            ai_context=_parse_ai_context(raw.get("ai_context")),
        )

    def _parse_expressions(
        self,
        raw: Any,
        *,
        datasets: Mapping[str, SemanticDataset] | None,
        current_dataset: str | None,
        require_dependency: bool,
    ) -> tuple[SemanticExpression, ...]:
        if not isinstance(raw, Mapping):
            raise SemanticConfigurationError(
                "OSSIE_MODEL_INVALID",
                "Expression must be an object.",
            )
        dialects = raw.get("dialects")
        if not isinstance(dialects, list) or not dialects:
            raise SemanticConfigurationError(
                "OSSIE_MODEL_INVALID",
                "Expression must contain dialects.",
            )
        parsed: list[SemanticExpression] = []
        seen_dialects: set[str] = set()
        for dialect_entry in dialects:
            if not isinstance(dialect_entry, Mapping):
                raise SemanticConfigurationError(
                    "OSSIE_MODEL_INVALID",
                    "Dialect expression must be an object.",
                )
            dialect = _required_string(dialect_entry, "dialect")
            expression = _required_string(dialect_entry, "expression")
            if dialect in seen_dialects:
                raise SemanticConfigurationError(
                    "OSSIE_DUPLICATE_DIALECT",
                    "Expression declares the same dialect more than once.",
                )
            seen_dialects.add(dialect)
            if len(expression.encode("utf-8")) > self._limits.max_expression_bytes:
                raise SemanticConfigurationError(
                    "OSSIE_EXPRESSION_LIMIT_EXCEEDED",
                    "Ossie expression exceeds the deployment limit.",
                )
            if (
                _FORBIDDEN_EXPRESSION_RE.search(expression)
                or ";" in expression
                or "--" in expression
                or "/*" in expression
                or "*/" in expression
            ):
                raise SemanticConfigurationError(
                    "OSSIE_EXPRESSION_UNSAFE",
                    "Ossie expressions must be scalar expressions only.",
                )
            dependencies = tuple(
                dict.fromkeys(_QUALIFIED_REFERENCE_RE.findall(expression))
            )
            if datasets is not None:
                for dataset_name, field_name in dependencies:
                    dataset = datasets.get(dataset_name)
                    if dataset is None or field_name not in dataset.fields_by_name:
                        raise SemanticConfigurationError(
                            "SEMANTIC_DEPENDENCY_UNRESOLVED",
                            "Metric expression references an unknown field.",
                        )
            elif current_dataset is not None:
                if any(
                    dataset_name != current_dataset for dataset_name, _ in dependencies
                ):
                    raise SemanticConfigurationError(
                        "SEMANTIC_DEPENDENCY_UNRESOLVED",
                        "Field expression references another dataset.",
                    )
            if require_dependency and not dependencies:
                raise SemanticConfigurationError(
                    "SEMANTIC_DEPENDENCY_UNRESOLVED",
                    "Metric expression must use an explicit dataset.field reference.",
                )
            physical_columns = (
                (expression,) if _SIMPLE_COLUMN_RE.fullmatch(expression) else ()
            )
            parsed.append(
                SemanticExpression(
                    dialect=dialect,
                    expression=expression,
                    dependencies=dependencies,
                    physical_columns=physical_columns,
                )
            )
        return tuple(parsed)

    @staticmethod
    def _parse_bindings(
        datasets: Sequence[SemanticDataset],
        raw: Any,
    ) -> tuple[DatasetBinding, ...]:
        if not isinstance(raw, Mapping):
            raise SemanticConfigurationError(
                "OSSIE_BINDING_INVALID",
                "Every semantic model must define dataset bindings.",
            )
        expected = {dataset.name for dataset in datasets}
        actual = {str(name) for name in raw}
        if actual != expected:
            raise SemanticConfigurationError(
                "OSSIE_BINDING_INVALID",
                "Dataset bindings must cover exactly the semantic datasets.",
            )
        bindings: list[DatasetBinding] = []
        for dataset_name in sorted(expected):
            entry = raw.get(dataset_name)
            if not isinstance(entry, Mapping):
                raise SemanticConfigurationError(
                    "OSSIE_BINDING_INVALID",
                    "Dataset binding must be an object.",
                )
            if set(entry) != _ALLOWED_DATASET_BINDING_KEYS:
                raise SemanticConfigurationError(
                    "OSSIE_BINDING_INVALID",
                    "Dataset binding fields are incomplete or unsupported.",
                )
            kind = _required_string(entry, "kind").casefold()
            if kind not in {"table", "view"}:
                raise SemanticConfigurationError(
                    "OSSIE_BINDING_INVALID",
                    "Dataset binding kind must be table or view.",
                )
            bindings.append(
                DatasetBinding(
                    dataset=dataset_name,
                    catalog=_validated_name(entry.get("catalog"), "catalog"),
                    database=_validated_name(
                        entry.get("database"),
                        "database",
                    ),
                    object_name=_validated_name(entry.get("object"), "object"),
                    kind=kind,
                )
            )
        return tuple(bindings)


def _json_object_no_duplicates(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SemanticConfigurationError(
                "OSSIE_DUPLICATE_KEY",
                "Ossie JSON contains a duplicate key.",
            )
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise SemanticConfigurationError(
        "OSSIE_NONFINITE_NUMBER_REJECTED",
        f"Ossie JSON constant {value!r} is not supported.",
    )


def _required_string(value: Mapping[str, Any], name: str) -> str:
    item = value.get(name)
    if not isinstance(item, str) or not item.strip():
        raise SemanticConfigurationError(
            "OSSIE_MODEL_INVALID",
            f"{name} must be a non-empty string.",
        )
    return item.strip()


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise SemanticConfigurationError(
            "OSSIE_MODEL_INVALID",
            "Optional semantic text must be a string.",
        )
    stripped = value.strip()
    return stripped or None


def _validated_name(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _NAME_RE.fullmatch(value):
        raise SemanticConfigurationError(
            "OSSIE_MODEL_INVALID",
            f"{label} name is invalid.",
        )
    return value


def _validated_selector_component(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not _SELECTOR_COMPONENT_RE.fullmatch(value)
    ):
        raise SemanticConfigurationError(
            "OSSIE_MODEL_INVALID",
            f"Ossie {label} name is invalid.",
        )
    return value


def _string_tuple(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not _NAME_RE.fullmatch(item) for item in value
    ):
        raise SemanticConfigurationError(
            "OSSIE_MODEL_INVALID",
            f"{label} must contain valid names.",
        )
    return tuple(value)


def _parse_ai_context(value: Any) -> SemanticAIContext | None:
    if value is None:
        return None
    if isinstance(value, str):
        return SemanticAIContext(instructions=value.strip() or None)
    if not isinstance(value, Mapping):
        raise SemanticConfigurationError(
            "OSSIE_MODEL_INVALID",
            "ai_context must be a string or object.",
        )
    instructions = _optional_string(value.get("instructions"))
    synonyms = _annotation_strings(value.get("synonyms", []), "synonyms")
    examples = _annotation_strings(value.get("examples", []), "examples")
    return SemanticAIContext(
        instructions=instructions,
        synonyms=synonyms,
        examples=examples,
    )


def _annotation_strings(value: Any, label: str) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or len(value) > 64
        or any(not isinstance(item, str) or not item.strip() for item in value)
    ):
        raise SemanticConfigurationError(
            "OSSIE_MODEL_INVALID",
            f"ai_context {label} must be a bounded string array.",
        )
    return tuple(dict.fromkeys(item.strip() for item in value))


def _require_unique(values: Any, label: str) -> None:
    items = tuple(values)
    if len(items) != len(set(items)):
        raise SemanticConfigurationError(
            "OSSIE_MODEL_INVALID",
            f"{label} must be unique.",
        )


def _has_parallel_relationships(
    relationships: Sequence[SemanticRelationship],
) -> bool:
    pairs = [
        tuple(sorted((relationship.from_dataset, relationship.to_dataset)))
        for relationship in relationships
    ]
    return len(pairs) != len(set(pairs))


def _has_relationship_cycle(
    datasets: Sequence[SemanticDataset],
    relationships: Sequence[SemanticRelationship],
) -> bool:
    adjacency: dict[str, set[str]] = {dataset.name: set() for dataset in datasets}
    for relationship in relationships:
        adjacency[relationship.from_dataset].add(relationship.to_dataset)
        adjacency[relationship.to_dataset].add(relationship.from_dataset)

    visited: set[str] = set()

    def visit(node: str, parent: str | None) -> bool:
        visited.add(node)
        for neighbor in adjacency[node]:
            if neighbor == parent:
                continue
            if neighbor in visited or visit(neighbor, node):
                return True
        return False

    return any(node not in visited and visit(node, None) for node in sorted(adjacency))


__all__ = [
    "OssieRegistryLoader",
    "SemanticConfigurationError",
    "SemanticLoaderLimits",
    "SemanticRegistry",
]
