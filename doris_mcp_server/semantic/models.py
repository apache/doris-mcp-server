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

"""Immutable internal representation for the supported Apache Ossie subset."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

OSSIE_SPEC_VERSION = "0.2.0.dev0"
OSSIE_SPEC_COMMIT = "9ffc3be3886e82fddc9bbf28722440864644d371"
OSSIE_SCHEMA_SHA256 = "8ce9f82aa92080265f9ae119e31cda5bef062f489674d3c467245c2d4c5ff264"
OSSIE_ADAPTER_VERSION = "doris-mcp-ossie/v1alpha1"
OSSIE_BINDING_API_VERSION = "doris-mcp.apache.org/ossie-binding/v1alpha1"
SEMANTIC_MODEL_REF_PATTERN = r"^(?=.{1,192}$)[A-Za-z0-9_.:/@-]+(?:\+[A-Za-z0-9_.-]+)*$"


@dataclass(frozen=True, slots=True)
class SemanticAIContext:
    """Administrator-authored annotations that are never executed."""

    instructions: str | None = None
    synonyms: tuple[str, ...] = ()
    examples: tuple[str, ...] = ()

    def to_public(self, *, include_examples: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "trust": "administrator_annotation",
            "synonyms": list(self.synonyms),
        }
        if self.instructions:
            payload["instructions"] = self.instructions
        if include_examples and self.examples:
            payload["examples"] = list(self.examples)
        return payload


@dataclass(frozen=True, slots=True)
class SemanticExpression:
    dialect: str
    expression: str
    dependencies: tuple[tuple[str, str], ...] = ()
    physical_columns: tuple[str, ...] = ()

    def to_public(self) -> dict[str, Any]:
        return {
            "dialect": self.dialect,
            "expression": self.expression,
        }


@dataclass(frozen=True, slots=True)
class SemanticField:
    name: str
    expressions: tuple[SemanticExpression, ...]
    label: str | None = None
    description: str | None = None
    datatype: str | None = None
    is_time: bool = False
    ai_context: SemanticAIContext | None = None


@dataclass(frozen=True, slots=True)
class SemanticDataset:
    name: str
    source: str
    fields: tuple[SemanticField, ...]
    primary_key: tuple[str, ...] = ()
    unique_keys: tuple[tuple[str, ...], ...] = ()
    description: str | None = None
    ai_context: SemanticAIContext | None = None

    @property
    def fields_by_name(self) -> Mapping[str, SemanticField]:
        return MappingProxyType({field.name: field for field in self.fields})


@dataclass(frozen=True, slots=True)
class SemanticRelationship:
    name: str
    from_dataset: str
    to_dataset: str
    from_columns: tuple[str, ...]
    to_columns: tuple[str, ...]
    ai_context: SemanticAIContext | None = None


@dataclass(frozen=True, slots=True)
class SemanticMetric:
    name: str
    expressions: tuple[SemanticExpression, ...]
    description: str | None = None
    datatype: str | None = None
    ai_context: SemanticAIContext | None = None


@dataclass(frozen=True, slots=True)
class DatasetBinding:
    dataset: str
    catalog: str
    database: str
    object_name: str
    kind: str

    @property
    def logical_key(self) -> tuple[str, str, str, str]:
        return (self.catalog, self.database, self.object_name, self.kind)


@dataclass(frozen=True, slots=True)
class SemanticModel:
    model_ref: str
    name: str
    namespace: str
    tags: tuple[str, ...]
    description: str | None
    ai_context: SemanticAIContext | None
    datasets: tuple[SemanticDataset, ...]
    relationships: tuple[SemanticRelationship, ...]
    metrics: tuple[SemanticMetric, ...]
    bindings: tuple[DatasetBinding, ...]
    route_profile: str
    source_digest: str
    revision: str
    binding_id: str
    warnings: tuple[str, ...] = ()

    @property
    def datasets_by_name(self) -> Mapping[str, SemanticDataset]:
        return MappingProxyType({dataset.name: dataset for dataset in self.datasets})

    @property
    def bindings_by_dataset(self) -> Mapping[str, DatasetBinding]:
        return MappingProxyType({binding.dataset: binding for binding in self.bindings})


@dataclass(frozen=True, slots=True)
class ResolvedField:
    field: SemanticField
    physical_columns: tuple[str, ...]
    physical_types: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ResolvedDataset:
    dataset: SemanticDataset
    binding: DatasetBinding
    object_kind: str
    fields: tuple[ResolvedField, ...]
    type_conflicts: tuple[str, ...] = ()

    @property
    def fields_by_name(self) -> Mapping[str, ResolvedField]:
        return MappingProxyType({field.field.name: field for field in self.fields})


@dataclass(frozen=True, slots=True)
class ResolvedSemanticModel:
    model: SemanticModel
    datasets: tuple[ResolvedDataset, ...]
    relationships: tuple[SemanticRelationship, ...]
    metrics: tuple[SemanticMetric, ...]
    warnings: tuple[str, ...] = ()

    @property
    def datasets_by_name(self) -> Mapping[str, ResolvedDataset]:
        return MappingProxyType(
            {dataset.dataset.name: dataset for dataset in self.datasets}
        )


__all__ = [
    "DatasetBinding",
    "OSSIE_ADAPTER_VERSION",
    "OSSIE_BINDING_API_VERSION",
    "OSSIE_SCHEMA_SHA256",
    "OSSIE_SPEC_COMMIT",
    "OSSIE_SPEC_VERSION",
    "ResolvedDataset",
    "ResolvedField",
    "ResolvedSemanticModel",
    "SEMANTIC_MODEL_REF_PATTERN",
    "SemanticAIContext",
    "SemanticDataset",
    "SemanticExpression",
    "SemanticField",
    "SemanticMetric",
    "SemanticModel",
    "SemanticRelationship",
]
