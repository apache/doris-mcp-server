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

"""Permission-aware Ossie semantic grounding over the active Doris route."""

from __future__ import annotations

import fnmatch
import json
import re
import uuid
from collections import deque
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote, unquote, urlsplit

from ..utils.db import DorisConnectionManager
from ..utils.security import get_current_auth_context
from .loader import (
    OssieRegistryLoader,
    SemanticConfigurationError,
    SemanticLoaderLimits,
    SemanticRegistry,
)
from .models import (
    OSSIE_ADAPTER_VERSION,
    OSSIE_SCHEMA_SHA256,
    OSSIE_SPEC_COMMIT,
    OSSIE_SPEC_VERSION,
    DatasetBinding,
    ResolvedDataset,
    ResolvedField,
    ResolvedSemanticModel,
    SemanticAIContext,
    SemanticDataset,
    SemanticExpression,
    SemanticMetric,
    SemanticModel,
    SemanticRelationship,
)

_MAX_QUERY_ROWS = 2048
_MAX_QUERY_BYTES = 2 * 1024 * 1024
_MODEL_REF_RE = re.compile(r"^[A-Za-z0-9_.:/@-]{1,192}$")
_SELECTOR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")
_DIMENSION_SELECTOR_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_-]{0,127}"
    r"\.[A-Za-z_][A-Za-z0-9_-]{0,127}$"
)
_TOKEN_RE = re.compile(r"[A-Za-z0-9_\u4e00-\u9fff]+")
_DORIS_TYPE_FAMILIES: Mapping[str, frozenset[str]] = {
    "String": frozenset({"CHAR", "VARCHAR", "STRING", "TEXT", "JSON", "VARIANT"}),
    "Integer": frozenset(
        {"TINYINT", "SMALLINT", "INT", "INTEGER", "BIGINT", "LARGEINT"}
    ),
    "Decimal": frozenset({"DECIMAL", "DECIMALV2", "DECIMALV3"}),
    "Float": frozenset({"FLOAT", "DOUBLE", "REAL"}),
    "Boolean": frozenset({"BOOLEAN", "BOOL", "TINYINT"}),
    "Date": frozenset({"DATE", "DATEV2"}),
    "Time": frozenset({"TIME"}),
    "DateTime": frozenset({"DATETIME", "DATETIMEV2"}),
    "DateTimeTz": frozenset({"DATETIME", "DATETIMEV2"}),
    "Opaque": frozenset(),
}


class SemanticRuntimeFailure(RuntimeError):
    """Stable, sanitized semantic-domain failure."""

    def __init__(
        self,
        reason_code: str,
        message: str,
        *,
        retryable: bool = False,
        status_code: int = 400,
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.retryable = retryable
        self.status_code = status_code


def _bool_config(section: Any, name: str, default: bool) -> bool:
    value = getattr(section, name, default)
    return value if isinstance(value, bool) else default


def _int_config(section: Any, name: str, default: int) -> int:
    value = getattr(section, name, default)
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return default


def _str_config(section: Any, name: str, default: str = "") -> str:
    value = getattr(section, name, default)
    return value if isinstance(value, str) else default


class DorisSemanticRuntime:
    """Read-only semantic adapter; it never compiles or executes model SQL."""

    def __init__(self, connection_manager: DorisConnectionManager) -> None:
        self._connection_manager = connection_manager
        config = getattr(connection_manager, "config", None)
        semantic = getattr(config, "semantic", None)
        self._enabled = _bool_config(semantic, "enabled", False)
        self._oauth_tools_enabled = _bool_config(
            semantic,
            "oauth_tools_enabled",
            False,
        )
        self._oauth_resources_enabled = _bool_config(
            semantic,
            "oauth_resources_enabled",
            False,
        )
        self._default_context_bytes = _int_config(
            semantic,
            "context_max_bytes",
            16 * 1024,
        )
        self._max_context_bytes = _int_config(
            semantic,
            "context_hard_max_bytes",
            64 * 1024,
        )
        self._max_models_per_list = _int_config(semantic, "max_models", 64)
        self._session_prefix = "semantic-domain"
        self._registry = SemanticRegistry()
        if self._enabled:
            model_directory = _str_config(semantic, "model_directory")
            binding_manifest = _str_config(semantic, "binding_manifest")
            if not model_directory or not binding_manifest:
                raise SemanticConfigurationError(
                    "OSSIE_CONFIGURATION_INCOMPLETE",
                    "Ossie model directory and binding manifest are required.",
                )
            self._registry = OssieRegistryLoader(
                model_directory=str(model_directory),
                binding_manifest=str(binding_manifest),
                limits=SemanticLoaderLimits(
                    max_file_bytes=_int_config(
                        semantic,
                        "max_file_bytes",
                        2 * 1024 * 1024,
                    ),
                    max_total_bytes=_int_config(
                        semantic,
                        "max_total_bytes",
                        8 * 1024 * 1024,
                    ),
                    max_models=self._max_models_per_list,
                    max_depth=_int_config(semantic, "max_depth", 32),
                    max_aliases=_int_config(semantic, "max_aliases", 32),
                    max_string_bytes=_int_config(
                        semantic,
                        "max_string_bytes",
                        16 * 1024,
                    ),
                    max_expression_bytes=_int_config(
                        semantic,
                        "max_expression_bytes",
                        4096,
                    ),
                ),
            ).load()

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def model_count(self) -> int:
        return len(self._registry.models)

    async def list_semantic_models(
        self,
        *,
        namespace: str | None = None,
        tag: str | None = None,
        pattern: str | None = None,
    ) -> dict[str, Any]:
        self._authorize_channel("tool")
        namespace = _optional_filter(namespace, "namespace")
        tag = _optional_filter(tag, "tag")
        pattern = _optional_filter(pattern, "pattern")
        items: list[dict[str, Any]] = []
        warnings: list[str] = []
        for model in self._registry.models:
            if namespace and model.namespace != namespace:
                continue
            if tag and tag not in model.tags:
                continue
            if pattern and not fnmatch.fnmatchcase(model.name, pattern):
                continue
            resolved = await self._resolve_visible_model(model)
            if resolved is None:
                continue
            items.append(
                {
                    "model_ref": model.model_ref,
                    "name": model.name,
                    "namespace": model.namespace,
                    "tags": list(model.tags),
                    "description": model.description,
                    "revision": model.revision,
                    "visible_datasets": len(resolved.datasets),
                    "mapping_status": ("partial" if resolved.warnings else "resolved"),
                    "experimental": True,
                }
            )
            warnings.extend(resolved.warnings)
        truncated = len(items) > self._max_models_per_list
        items = items[: self._max_models_per_list]
        return {
            "status": "partial" if warnings or truncated else "success",
            "data": {
                "items": items,
                "next_cursor": None,
                "truncated": truncated,
            },
            "warnings": _public_warnings(warnings),
            "metadata": self._metadata(),
        }

    async def get_semantic_model_summary(
        self,
        *,
        model_ref: str,
        include_bindings: bool = False,
    ) -> dict[str, Any]:
        self._authorize_channel("tool")
        resolved = await self._require_visible_model(model_ref)
        data = self._render_summary(
            resolved,
            include_bindings=include_bindings,
        )
        return self._diagnostic_result(resolved, data)

    async def get_semantic_mapping_status(
        self,
        *,
        model_ref: str,
        datasource: str | None = None,
    ) -> dict[str, Any]:
        self._authorize_channel("tool")
        datasource = _optional_filter(datasource, "datasource")
        resolved = await self._require_visible_model(model_ref)
        if datasource and datasource not in resolved.datasets_by_name:
            raise SemanticRuntimeFailure(
                "SEMANTIC_DEPENDENCY_UNRESOLVED",
                "Requested semantic concept is unavailable.",
                status_code=404,
            )
        datasets: list[dict[str, Any]] = []
        for item in resolved.datasets:
            if datasource and item.dataset.name != datasource:
                continue
            payload: dict[str, Any] = {
                "dataset": item.dataset.name,
                "binding_id": resolved.model.binding_id,
                "object_kind": item.object_kind,
                "status": ("type_conflict" if item.type_conflicts else "resolved"),
                "visible_fields": [
                    {
                        "name": field.field.name,
                        "physical_columns": list(field.physical_columns),
                        "physical_types": list(field.physical_types),
                    }
                    for field in item.fields
                ],
            }
            if item.type_conflicts:
                payload["warnings"] = ["SEMANTIC_TYPE_CONFLICT"]
            datasets.append(payload)
        data = {
            "model_ref": resolved.model.model_ref,
            "revision": resolved.model.revision,
            "mapping_status": ("partial" if resolved.warnings else "resolved"),
            "datasets": datasets,
        }
        return self._diagnostic_result(resolved, data)

    async def get_semantic_context(
        self,
        *,
        model_ref: str,
        request: Mapping[str, Any],
    ) -> dict[str, Any]:
        self._authorize_channel("tool")
        resolved = await self._require_visible_model(model_ref)
        normalized = self._normalize_context_request(request)
        context, selection_warnings, truncated = self._select_context(
            resolved,
            normalized,
        )
        warnings = [
            *resolved.warnings,
            *selection_warnings,
        ]
        data = {
            "model_ref": resolved.model.model_ref,
            "revision": resolved.model.revision,
            "context": context,
            "context_bytes": len(_canonical_bytes(context)),
            "truncated": truncated,
            "execution_boundary": (
                "Semantic expressions are grounding metadata only. "
                "Use the Doris Query domain for SQL execution."
            ),
        }
        return self._diagnostic_result(
            resolved,
            data,
            warnings=warnings,
            truncated=truncated,
        )

    async def list_resource_descriptors(self) -> list[dict[str, str]]:
        """Return visible model resources without exposing full model content."""
        if not self._enabled:
            return []
        try:
            self._authorize_channel("resource")
        except SemanticRuntimeFailure:
            return []
        descriptors: list[dict[str, str]] = []
        for model in self._registry.models[: self._max_models_per_list]:
            resolved = await self._resolve_visible_model(model)
            if resolved is None:
                continue
            descriptors.append(
                {
                    "uri": self.resource_uri(model.model_ref, model.revision),
                    "name": f"Semantic Model: {model.name}",
                    "description": (
                        f"Validated Ossie summary for {model.name} "
                        f"(revision {model.revision})"
                    ),
                }
            )
        return descriptors

    async def read_resource(self, uri: str) -> str:
        """Read one exact revisioned semantic summary resource."""
        self._authorize_channel("resource")
        model_ref, revision = self.parse_resource_uri(uri)
        resolved = await self._require_visible_model(model_ref)
        if resolved.model.revision != revision:
            raise SemanticRuntimeFailure(
                "SEMANTIC_MODEL_NOT_FOUND",
                "Semantic model was not found.",
                status_code=404,
            )
        payload = self._render_summary(resolved, include_bindings=False)
        payload["provenance"] = self._provenance(resolved.model)
        return json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )

    @staticmethod
    def resource_uri(model_ref: str, revision: str) -> str:
        return (
            "doris://semantic/models/"
            f"{quote(model_ref, safe='')}/{quote(revision, safe='')}"
        )

    @staticmethod
    def parse_resource_uri(uri: str) -> tuple[str, str]:
        parsed = urlsplit(uri)
        parts = tuple(part for part in parsed.path.split("/") if part)
        if (
            parsed.scheme != "doris"
            or parsed.netloc != "semantic"
            or len(parts) != 3
            or parts[0] != "models"
            or parsed.query
            or parsed.fragment
        ):
            raise SemanticRuntimeFailure(
                "SEMANTIC_MODEL_NOT_FOUND",
                "Semantic model was not found.",
                status_code=404,
            )
        model_ref = unquote(parts[1])
        revision = unquote(parts[2])
        if not _MODEL_REF_RE.fullmatch(model_ref) or not re.fullmatch(
            r"[a-f0-9]{16}", revision
        ):
            raise SemanticRuntimeFailure(
                "SEMANTIC_MODEL_NOT_FOUND",
                "Semantic model was not found.",
                status_code=404,
            )
        return model_ref, revision

    def _authorize_channel(self, channel: str) -> None:
        if not self._enabled:
            raise SemanticRuntimeFailure(
                "OSSIE_DISABLED",
                "Ossie semantic support is disabled.",
                status_code=503,
            )
        auth_context = get_current_auth_context()
        if auth_context is None:
            return
        auth_method = getattr(auth_context, "auth_method", "")
        if auth_method not in {"external_oauth", "doris_oauth"}:
            return
        enabled = (
            self._oauth_tools_enabled
            if channel == "tool"
            else self._oauth_resources_enabled
        )
        scopes = set(getattr(auth_context, "oauth_scopes", ()) or ())
        if not enabled or "semantic:read" not in scopes:
            raise SemanticRuntimeFailure(
                "SEMANTIC_MODEL_NOT_FOUND",
                "Semantic model was not found.",
                status_code=404,
            )

    async def _require_visible_model(
        self,
        model_ref: str,
    ) -> ResolvedSemanticModel:
        if not isinstance(model_ref, str) or not _MODEL_REF_RE.fullmatch(model_ref):
            raise SemanticRuntimeFailure(
                "SEMANTIC_MODEL_NOT_FOUND",
                "Semantic model was not found.",
                status_code=404,
            )
        model = self._registry.get(model_ref)
        if model is None:
            raise SemanticRuntimeFailure(
                "SEMANTIC_MODEL_NOT_FOUND",
                "Semantic model was not found.",
                status_code=404,
            )
        resolved = await self._resolve_visible_model(model)
        if resolved is None:
            raise SemanticRuntimeFailure(
                "SEMANTIC_MODEL_NOT_FOUND",
                "Semantic model was not found.",
                status_code=404,
            )
        return resolved

    async def _resolve_visible_model(
        self,
        model: SemanticModel,
    ) -> ResolvedSemanticModel | None:
        auth_context = get_current_auth_context()
        route = self._connection_manager.get_route_identity(auth_context)
        if model.route_profile != route.route_key:
            return None

        visible_datasets: list[ResolvedDataset] = []
        unresolved = False
        for dataset in model.datasets:
            binding = model.bindings_by_dataset[dataset.name]
            resolved = await self._resolve_dataset(dataset, binding)
            if resolved is None:
                unresolved = True
                continue
            visible_datasets.append(resolved)
        if not visible_datasets:
            return None

        visible_by_name = {item.dataset.name: item for item in visible_datasets}
        relationships = tuple(
            relationship
            for relationship in model.relationships
            if _relationship_visible(relationship, visible_by_name)
        )
        metrics = tuple(
            metric
            for metric in model.metrics
            if _metric_visible(metric, visible_by_name)
        )
        warnings = list(model.warnings)
        if unresolved:
            warnings.append("SEMANTIC_MAPPING_STALE")
        if any(dataset.type_conflicts for dataset in visible_datasets):
            warnings.append("SEMANTIC_TYPE_CONFLICT")
        if len(relationships) != len(model.relationships):
            warnings.append("SEMANTIC_RELATIONSHIP_FILTERED")
        if len(metrics) != len(model.metrics):
            warnings.append("SEMANTIC_METRIC_FILTERED")
        return ResolvedSemanticModel(
            model=model,
            datasets=tuple(visible_datasets),
            relationships=relationships,
            metrics=metrics,
            warnings=tuple(dict.fromkeys(warnings)),
        )

    async def _resolve_dataset(
        self,
        dataset: SemanticDataset,
        binding: DatasetBinding,
    ) -> ResolvedDataset | None:
        table_sql = (
            "SELECT TABLE_TYPE FROM information_schema.tables "
            "WHERE TABLE_CATALOG = %s AND TABLE_SCHEMA = %s "
            "AND TABLE_NAME = %s LIMIT 2"
        )
        column_sql = (
            "SELECT COLUMN_NAME, DATA_TYPE FROM information_schema.columns "
            "WHERE TABLE_CATALOG = %s AND TABLE_SCHEMA = %s "
            "AND TABLE_NAME = %s ORDER BY ORDINAL_POSITION"
        )
        params = (binding.catalog, binding.database, binding.object_name)
        try:
            table_rows = await self._execute(
                table_sql,
                params=params,
                max_rows=2,
            )
            if len(table_rows) != 1:
                return None
            object_kind = _normalize_object_kind(
                _row_value(table_rows[0], "TABLE_TYPE")
            )
            if object_kind != binding.kind:
                return None
            column_rows = await self._execute(
                column_sql,
                params=params,
                max_rows=_MAX_QUERY_ROWS,
            )
        except SemanticRuntimeFailure as exc:
            if exc.reason_code in {
                "SEMANTIC_MAPPING_UNRESOLVED",
                "SEMANTIC_PERMISSION_UNCONFIRMED",
            }:
                return None
            raise
        columns = {
            str(_row_value(row, "COLUMN_NAME")): str(
                _row_value(row, "DATA_TYPE")
            ).upper()
            for row in column_rows
            if _row_value(row, "COLUMN_NAME") is not None
        }
        if not columns:
            return None
        resolved_fields: list[ResolvedField] = []
        type_conflicts: list[str] = []
        for field in dataset.fields:
            expression = _preferred_expression(field.expressions)
            if expression is None or not expression.physical_columns:
                continue
            if any(column not in columns for column in expression.physical_columns):
                continue
            physical_types = tuple(
                columns[column] for column in expression.physical_columns
            )
            if field.datatype and any(
                not _compatible_type(field.datatype, physical_type)
                for physical_type in physical_types
            ):
                type_conflicts.append(field.name)
                continue
            resolved_fields.append(
                ResolvedField(
                    field=field,
                    physical_columns=expression.physical_columns,
                    physical_types=physical_types,
                )
            )
        if dataset.fields and not resolved_fields:
            return None
        return ResolvedDataset(
            dataset=dataset,
            binding=binding,
            object_kind=object_kind,
            fields=tuple(resolved_fields),
            type_conflicts=tuple(type_conflicts),
        )

    async def _execute(
        self,
        sql: str,
        *,
        params: tuple[Any, ...],
        max_rows: int,
    ) -> list[dict[str, Any]]:
        auth_context = get_current_auth_context()
        session_id = f"{self._session_prefix}:{uuid.uuid4().hex[:12]}"
        try:
            async with self._connection_manager.get_connection_context_for_auth_context(
                session_id,
                auth_context,
            ) as connection:
                result = await connection.execute(
                    sql,
                    params=params,
                    auth_context=auth_context,
                    mask_result=False,
                    max_rows=max_rows,
                    max_bytes=_MAX_QUERY_BYTES,
                )
        except Exception as exc:
            raise _runtime_failure(exc) from exc
        return [dict(row) for row in (result.data or ()) if isinstance(row, Mapping)]

    def _render_summary(
        self,
        resolved: ResolvedSemanticModel,
        *,
        include_bindings: bool,
    ) -> dict[str, Any]:
        model = resolved.model
        datasets = [
            _render_dataset(
                dataset,
                include_all_fields=True,
                include_binding=include_bindings,
            )
            for dataset in resolved.datasets
        ]
        return {
            "model_ref": model.model_ref,
            "name": model.name,
            "namespace": model.namespace,
            "tags": list(model.tags),
            "description": model.description,
            "revision": model.revision,
            "spec_version": OSSIE_SPEC_VERSION,
            "experimental": True,
            "binding_id": model.binding_id,
            "mapping_status": ("partial" if resolved.warnings else "resolved"),
            "datasets": datasets,
            "relationships": [
                _render_relationship(relationship)
                for relationship in resolved.relationships
            ],
            "metrics": [_render_metric(metric) for metric in resolved.metrics],
            "ai_context": (
                model.ai_context.to_public() if model.ai_context is not None else None
            ),
        }

    def _normalize_context_request(
        self,
        request: Mapping[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(request, Mapping):
            raise SemanticRuntimeFailure(
                "SEMANTIC_ARGUMENT_INVALID",
                "Semantic context request must be an object.",
            )
        allowed = {
            "question",
            "metrics",
            "dimensions",
            "datasets",
            "max_bytes",
        }
        if set(request) - allowed:
            raise SemanticRuntimeFailure(
                "SEMANTIC_ARGUMENT_INVALID",
                "Semantic context request contains unsupported fields.",
            )
        question = request.get("question")
        if question is not None and (
            not isinstance(question, str)
            or not question.strip()
            or len(question) > 4096
        ):
            raise SemanticRuntimeFailure(
                "SEMANTIC_ARGUMENT_INVALID",
                "Semantic question is invalid.",
            )
        normalized: dict[str, Any] = {
            "question": question.strip() if isinstance(question, str) else "",
        }
        for name in ("metrics", "dimensions", "datasets"):
            raw = request.get(name, [])
            selector_pattern = (
                _DIMENSION_SELECTOR_RE
                if name == "dimensions"
                else _SELECTOR_RE
            )
            if (
                not isinstance(raw, list)
                or len(raw) > 64
                or any(
                    not isinstance(item, str)
                    or not selector_pattern.fullmatch(item)
                    for item in raw
                )
            ):
                raise SemanticRuntimeFailure(
                    "SEMANTIC_ARGUMENT_INVALID",
                    f"Semantic selector {name} is invalid.",
                )
            normalized[name] = tuple(dict.fromkeys(raw))
        if not any(
            (
                normalized["question"],
                normalized["metrics"],
                normalized["dimensions"],
                normalized["datasets"],
            )
        ):
            raise SemanticRuntimeFailure(
                "SEMANTIC_ARGUMENT_INVALID",
                "Semantic context request must select at least one concept.",
            )
        max_bytes = request.get("max_bytes", self._default_context_bytes)
        if (
            not isinstance(max_bytes, int)
            or isinstance(max_bytes, bool)
            or max_bytes < 1024
            or max_bytes > self._max_context_bytes
        ):
            raise SemanticRuntimeFailure(
                "SEMANTIC_ARGUMENT_INVALID",
                "Semantic context byte budget is outside the allowed range.",
            )
        normalized["max_bytes"] = min(
            max_bytes,
            self._default_context_bytes,
        )
        return normalized

    def _select_context(
        self,
        resolved: ResolvedSemanticModel,
        request: Mapping[str, Any],
    ) -> tuple[dict[str, Any], list[str], bool]:
        explicit_metrics = set(request["metrics"])
        explicit_datasets = set(request["datasets"])
        explicit_dimensions = set(request["dimensions"])
        visible_metrics = {metric.name: metric for metric in resolved.metrics}
        visible_datasets = resolved.datasets_by_name
        visible_dimensions = {
            f"{dataset.dataset.name}.{field.field.name}": (dataset, field)
            for dataset in resolved.datasets
            for field in dataset.fields
        }
        if (
            explicit_metrics - set(visible_metrics)
            or explicit_datasets - set(visible_datasets)
            or explicit_dimensions - set(visible_dimensions)
        ):
            raise SemanticRuntimeFailure(
                "SEMANTIC_DEPENDENCY_UNRESOLVED",
                "Requested semantic concept is unavailable.",
                status_code=404,
            )

        question = str(request["question"])
        metric_scores = {
            name: _semantic_score(
                question, metric.name, metric.description, metric.ai_context
            )
            for name, metric in visible_metrics.items()
        }
        dataset_scores = {
            name: _semantic_score(
                question,
                dataset.dataset.name,
                dataset.dataset.description,
                dataset.dataset.ai_context,
            )
            for name, dataset in visible_datasets.items()
        }
        dimension_scores = {
            name: _semantic_score(
                question,
                field.field.name,
                field.field.description,
                field.field.ai_context,
                label=field.field.label,
            )
            for name, (_, field) in visible_dimensions.items()
        }
        selected_metrics = set(explicit_metrics)
        selected_datasets = set(explicit_datasets)
        selected_dimensions = set(explicit_dimensions)
        if question:
            selected_metrics.update(_positive_top(metric_scores, limit=8))
            selected_datasets.update(_positive_top(dataset_scores, limit=8))
            selected_dimensions.update(_positive_top(dimension_scores, limit=16))

        auto_candidates: list[tuple[int, str, str]] = []
        auto_candidates.extend(
            (score, "metric", name)
            for name, score in metric_scores.items()
            if score > 0 and name not in explicit_metrics
        )
        auto_candidates.extend(
            (score, "dataset", name)
            for name, score in dataset_scores.items()
            if score > 0 and name not in explicit_datasets
        )
        auto_candidates.extend(
            (score, "dimension", name)
            for name, score in dimension_scores.items()
            if score > 0 and name not in explicit_dimensions
        )
        auto_candidates.sort(key=lambda item: (item[0], item[1], item[2]))

        warnings: list[str] = []
        if not (selected_metrics or selected_datasets or selected_dimensions):
            warnings.append("SEMANTIC_DEPENDENCY_UNRESOLVED")
        truncated = False
        include_examples = True
        include_descriptions = True
        budget = int(request["max_bytes"])

        while True:
            context, build_warnings = _build_context(
                resolved,
                selected_metrics,
                selected_datasets,
                selected_dimensions,
                include_examples=include_examples,
                include_descriptions=include_descriptions,
            )
            warnings.extend(build_warnings)
            if len(_canonical_bytes(context)) <= budget:
                return (
                    context,
                    list(dict.fromkeys(warnings)),
                    truncated,
                )
            truncated = True
            if include_examples:
                include_examples = False
                continue
            if include_descriptions:
                include_descriptions = False
                continue
            if auto_candidates:
                _, kind, name = auto_candidates.pop(0)
                if kind == "metric":
                    selected_metrics.discard(name)
                elif kind == "dataset":
                    selected_datasets.discard(name)
                else:
                    selected_dimensions.discard(name)
                continue
            raise SemanticRuntimeFailure(
                "SEMANTIC_CONTEXT_TOO_LARGE",
                "Required semantic dependency closure exceeds the byte budget.",
                status_code=413,
            )

    def _diagnostic_result(
        self,
        resolved: ResolvedSemanticModel,
        data: dict[str, Any],
        *,
        warnings: Sequence[str] | None = None,
        truncated: bool = False,
    ) -> dict[str, Any]:
        final_warnings = _public_warnings(
            warnings if warnings is not None else resolved.warnings
        )
        return {
            "status": ("partial" if final_warnings or truncated else "success"),
            "data": data,
            "warnings": final_warnings,
            "metadata": {
                **self._metadata(),
                "model_revision": resolved.model.revision,
                "source_digest": resolved.model.source_digest,
                "binding_id": resolved.model.binding_id,
                "truncated": truncated,
            },
            "evidence": [
                {
                    "source": "pinned_ossie_schema",
                    "status": "verified",
                    "spec_version": OSSIE_SPEC_VERSION,
                    "spec_commit": OSSIE_SPEC_COMMIT,
                },
                {
                    "source": "active_doris_route",
                    "status": "permission_filtered",
                },
            ],
        }

    @staticmethod
    def _metadata() -> dict[str, Any]:
        return {
            "adapter_version": OSSIE_ADAPTER_VERSION,
            "ossie_spec_version": OSSIE_SPEC_VERSION,
            "ossie_spec_commit": OSSIE_SPEC_COMMIT,
            "ossie_schema_digest": OSSIE_SCHEMA_SHA256,
            "resolved_at": datetime.now(UTC).isoformat(),
        }

    @staticmethod
    def _provenance(model: SemanticModel) -> dict[str, Any]:
        return {
            "adapter_version": OSSIE_ADAPTER_VERSION,
            "spec_version": OSSIE_SPEC_VERSION,
            "spec_commit": OSSIE_SPEC_COMMIT,
            "schema_digest": OSSIE_SCHEMA_SHA256,
            "model_ref": model.model_ref,
            "model_revision": model.revision,
            "source_digest": model.source_digest,
            "binding_id": model.binding_id,
        }


def _optional_filter(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > 192:
        raise SemanticRuntimeFailure(
            "SEMANTIC_ARGUMENT_INVALID",
            f"Semantic {label} filter is invalid.",
        )
    return value.strip()


def _runtime_failure(exc: Exception) -> SemanticRuntimeFailure:
    args = getattr(exc, "args", ())
    mysql_code: int | None = None
    if args:
        try:
            mysql_code = int(args[0])
        except (TypeError, ValueError):
            mysql_code = None
    message = str(exc).casefold()
    if mysql_code in {1044, 1045, 1142, 1143, 1227} or any(
        marker in message
        for marker in (
            "permission denied",
            "access denied",
            "not authorized",
            "privilege",
        )
    ):
        return SemanticRuntimeFailure(
            "SEMANTIC_PERMISSION_UNCONFIRMED",
            "Semantic mapping visibility could not be confirmed.",
            status_code=403,
        )
    if mysql_code in {1049, 1051, 1109, 1146} or any(
        marker in message
        for marker in (
            "does not exist",
            "unknown table",
            "unknown database",
        )
    ):
        return SemanticRuntimeFailure(
            "SEMANTIC_MAPPING_UNRESOLVED",
            "Semantic mapping could not be resolved.",
            status_code=404,
        )
    return SemanticRuntimeFailure(
        "SEMANTIC_BACKEND_UNAVAILABLE",
        "Semantic mapping validation failed.",
        retryable=True,
        status_code=502,
    )


def _row_value(row: Mapping[str, Any], name: str) -> Any:
    for key, value in row.items():
        if str(key).casefold() == name.casefold():
            return value
    return None


def _normalize_object_kind(value: Any) -> str:
    normalized = str(value or "").casefold().replace("_", " ")
    if "view" in normalized:
        return "view"
    return "table"


def _preferred_expression(
    expressions: Sequence[SemanticExpression],
) -> SemanticExpression | None:
    return next(
        (expression for expression in expressions if expression.dialect == "ANSI_SQL"),
        None,
    )


def _compatible_type(logical: str, physical: str) -> bool:
    if logical == "Opaque":
        return True
    base = physical.upper().split("(", 1)[0]
    return base in _DORIS_TYPE_FAMILIES.get(logical, frozenset())


def _relationship_visible(
    relationship: SemanticRelationship,
    datasets: Mapping[str, ResolvedDataset],
) -> bool:
    source = datasets.get(relationship.from_dataset)
    target = datasets.get(relationship.to_dataset)
    if source is None or target is None:
        return False
    return all(
        column in source.fields_by_name for column in relationship.from_columns
    ) and all(column in target.fields_by_name for column in relationship.to_columns)


def _metric_visible(
    metric: SemanticMetric,
    datasets: Mapping[str, ResolvedDataset],
) -> bool:
    expression = _preferred_expression(metric.expressions)
    if expression is None:
        return False
    return bool(expression.dependencies) and all(
        dataset_name in datasets and field_name in datasets[dataset_name].fields_by_name
        for dataset_name, field_name in expression.dependencies
    )


def _render_ai_context(
    context: SemanticAIContext | None,
    *,
    include_examples: bool,
) -> dict[str, Any] | None:
    return (
        context.to_public(include_examples=include_examples)
        if context is not None
        else None
    )


def _render_dataset(
    resolved: ResolvedDataset,
    *,
    include_all_fields: bool,
    include_binding: bool,
    field_names: set[str] | None = None,
    include_examples: bool = True,
    include_descriptions: bool = True,
) -> dict[str, Any]:
    fields = [
        {
            "name": field.field.name,
            "label": field.field.label,
            "description": (field.field.description if include_descriptions else None),
            "datatype": field.field.datatype,
            "is_time": field.field.is_time,
            "expressions": [
                expression.to_public() for expression in field.field.expressions
            ],
            "ai_context": _render_ai_context(
                field.field.ai_context,
                include_examples=include_examples,
            ),
        }
        for field in resolved.fields
        if include_all_fields or field_names is None or field.field.name in field_names
    ]
    payload: dict[str, Any] = {
        "name": resolved.dataset.name,
        "description": (resolved.dataset.description if include_descriptions else None),
        "primary_key": list(resolved.dataset.primary_key),
        "unique_keys": [list(key) for key in resolved.dataset.unique_keys],
        "fields": fields,
        "ai_context": _render_ai_context(
            resolved.dataset.ai_context,
            include_examples=include_examples,
        ),
    }
    if include_binding:
        payload["binding"] = {
            "catalog": resolved.binding.catalog,
            "database": resolved.binding.database,
            "object": resolved.binding.object_name,
            "kind": resolved.binding.kind,
        }
    return payload


def _render_metric(
    metric: SemanticMetric,
    *,
    include_examples: bool = True,
    include_descriptions: bool = True,
) -> dict[str, Any]:
    return {
        "name": metric.name,
        "description": metric.description if include_descriptions else None,
        "datatype": metric.datatype,
        "expressions": [expression.to_public() for expression in metric.expressions],
        "dependencies": [
            f"{dataset}.{field}"
            for expression in metric.expressions
            if expression.dialect == "ANSI_SQL"
            for dataset, field in expression.dependencies
        ],
        "ai_context": _render_ai_context(
            metric.ai_context,
            include_examples=include_examples,
        ),
    }


def _render_relationship(
    relationship: SemanticRelationship,
    *,
    include_examples: bool = True,
) -> dict[str, Any]:
    return {
        "name": relationship.name,
        "from": relationship.from_dataset,
        "to": relationship.to_dataset,
        "from_columns": list(relationship.from_columns),
        "to_columns": list(relationship.to_columns),
        "ai_context": _render_ai_context(
            relationship.ai_context,
            include_examples=include_examples,
        ),
    }


def _semantic_score(
    question: str,
    name: str,
    description: str | None,
    ai_context: SemanticAIContext | None,
    *,
    label: str | None = None,
) -> int:
    if not question:
        return 0
    normalized_question = question.casefold()
    score = 0
    candidates = [(name, 100), (label, 90)]
    if ai_context is not None:
        candidates.extend((synonym, 80) for synonym in ai_context.synonyms)
    candidates.append((description, 30))
    question_tokens = set(_TOKEN_RE.findall(normalized_question))
    for candidate, weight in candidates:
        if not candidate:
            continue
        normalized = candidate.casefold()
        if normalized in normalized_question:
            score = max(score, weight + len(normalized))
            continue
        candidate_tokens = set(_TOKEN_RE.findall(normalized))
        overlap = len(question_tokens & candidate_tokens)
        if overlap:
            score = max(score, weight + overlap)
    return score


def _positive_top(scores: Mapping[str, int], *, limit: int) -> tuple[str, ...]:
    ranked = sorted(
        ((score, name) for name, score in scores.items() if score > 0),
        key=lambda item: (-item[0], item[1]),
    )
    return tuple(name for _, name in ranked[:limit])


def _build_context(
    resolved: ResolvedSemanticModel,
    selected_metrics: set[str],
    selected_datasets: set[str],
    selected_dimensions: set[str],
    *,
    include_examples: bool,
    include_descriptions: bool,
) -> tuple[dict[str, Any], list[str]]:
    metrics_by_name = {metric.name: metric for metric in resolved.metrics}
    datasets_by_name = resolved.datasets_by_name
    metric_dependencies: dict[str, set[str]] = {}
    selected_field_names: dict[str, set[str]] = {}
    required_datasets = set(selected_datasets)
    for dimension in selected_dimensions:
        dataset_name, field_name = dimension.split(".", 1)
        required_datasets.add(dataset_name)
        selected_field_names.setdefault(dataset_name, set()).add(field_name)
    for metric_name in selected_metrics:
        metric = metrics_by_name[metric_name]
        dependencies: set[str] = set()
        expression = _preferred_expression(metric.expressions)
        if expression is not None:
            for dataset_name, field_name in expression.dependencies:
                required_datasets.add(dataset_name)
                selected_field_names.setdefault(dataset_name, set()).add(field_name)
                dependencies.add(f"{dataset_name}.{field_name}")
        metric_dependencies[metric_name] = dependencies

    relationships, relationship_warnings = _join_closure(
        resolved.relationships,
        required_datasets,
    )
    for relationship in relationships:
        required_datasets.update((relationship.from_dataset, relationship.to_dataset))
        selected_field_names.setdefault(
            relationship.from_dataset,
            set(),
        ).update(relationship.from_columns)
        selected_field_names.setdefault(
            relationship.to_dataset,
            set(),
        ).update(relationship.to_columns)

    datasets = []
    for dataset_name in sorted(required_datasets):
        dataset = datasets_by_name.get(dataset_name)
        if dataset is None:
            continue
        selected = selected_field_names.setdefault(dataset_name, set())
        selected.update(dataset.dataset.primary_key)
        datasets.append(
            _render_dataset(
                dataset,
                include_all_fields=False,
                include_binding=False,
                field_names=selected,
                include_examples=include_examples,
                include_descriptions=include_descriptions,
            )
        )
    metrics = [
        {
            **_render_metric(
                metrics_by_name[name],
                include_examples=include_examples,
                include_descriptions=include_descriptions,
            ),
            "dependencies": sorted(metric_dependencies[name]),
        }
        for name in sorted(selected_metrics)
    ]
    context = {
        "selection_mode": "deterministic",
        "datasets": datasets,
        "metrics": metrics,
        "relationships": [
            _render_relationship(
                relationship,
                include_examples=include_examples,
            )
            for relationship in relationships
        ],
        "ai_context": _render_ai_context(
            resolved.model.ai_context,
            include_examples=include_examples,
        ),
    }
    return context, relationship_warnings


def _join_closure(
    relationships: Sequence[SemanticRelationship],
    datasets: set[str],
) -> tuple[tuple[SemanticRelationship, ...], list[str]]:
    if len(datasets) < 2:
        return (), []
    adjacency: dict[str, list[tuple[str, SemanticRelationship]]] = {}
    for relationship in relationships:
        adjacency.setdefault(relationship.from_dataset, []).append(
            (relationship.to_dataset, relationship)
        )
        adjacency.setdefault(relationship.to_dataset, []).append(
            (relationship.from_dataset, relationship)
        )
    for edges in adjacency.values():
        edges.sort(key=lambda item: (item[0], item[1].name))

    root = sorted(datasets)[0]
    selected: dict[str, SemanticRelationship] = {}
    warnings: list[str] = []
    for target in sorted(datasets - {root}):
        queue: deque[tuple[str, tuple[SemanticRelationship, ...]]] = deque([(root, ())])
        seen_distance = {root: 0}
        shortest: list[tuple[SemanticRelationship, ...]] = []
        shortest_length: int | None = None
        while queue:
            node, path = queue.popleft()
            if shortest_length is not None and len(path) >= shortest_length:
                continue
            for neighbor, relationship in adjacency.get(node, ()):
                next_path = (*path, relationship)
                if neighbor == target:
                    shortest_length = len(next_path)
                    shortest.append(next_path)
                    continue
                distance = len(next_path)
                if distance <= seen_distance.get(neighbor, distance):
                    seen_distance[neighbor] = distance
                    queue.append((neighbor, next_path))
        if not shortest:
            warnings.append("SEMANTIC_DEPENDENCY_UNRESOLVED")
            continue
        canonical_paths = sorted(
            shortest,
            key=lambda path: tuple(item.name for item in path),
        )
        if len(canonical_paths) > 1:
            warnings.append("SEMANTIC_AMBIGUOUS_JOIN_PATH")
        for relationship in canonical_paths[0]:
            selected[relationship.name] = relationship
    return (
        tuple(selected[name] for name in sorted(selected)),
        list(dict.fromkeys(warnings)),
    )


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _public_warnings(warnings: Sequence[str]) -> list[str]:
    allowed = {
        "SEMANTIC_AMBIGUOUS_JOIN_PATH",
        "SEMANTIC_CONTEXT_TRUNCATED",
        "SEMANTIC_DEPENDENCY_UNRESOLVED",
        "SEMANTIC_MAPPING_STALE",
        "SEMANTIC_METRIC_FILTERED",
        "SEMANTIC_RELATIONSHIP_CYCLE",
        "SEMANTIC_RELATIONSHIP_FILTERED",
        "SEMANTIC_RELATIONSHIP_TARGET_NOT_DECLARED_UNIQUE",
        "SEMANTIC_TYPE_CONFLICT",
    }
    return [warning for warning in dict.fromkeys(warnings) if warning in allowed]


__all__ = [
    "DorisSemanticRuntime",
    "SemanticConfigurationError",
    "SemanticRuntimeFailure",
]
