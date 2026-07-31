"""LookML provider plugin (Google Looker LookML, parsed via lkml)."""

from __future__ import annotations

import lkml

from providers.base import (
    CompiledArtifact,
    DimensionDef,
    MetricDef,
    ModelSource,
    QueryRequest,
    SemanticModel,
    SemanticProvider,
    SemanticRuntime,
)
from providers.cube import runtime as _cube_runtime
from providers.lookml.compiler import compile_lookml_model
from providers.lookml.parser import parse_lookml_file


class LookmlProvider(SemanticProvider):
    """LookML (.view.lkml) semantic model provider — views with dimensions/measures."""

    name = "lookml"

    def detect(self, source: ModelSource) -> float:
        if source.filename.endswith((".view.lkml", ".lkml")):
            try:
                doc = lkml.load(source.content)
            except Exception:
                return 0.0
            if doc.get("views"):
                return 0.95
            return 0.3
        return 0.0

    def validate(self, source: ModelSource) -> list[str]:
        try:
            parse_lookml_file(source)
        except Exception as e:
            return [str(e)]
        return []

    def parse(self, source: ModelSource) -> SemanticModel:
        return parse_lookml_file(source)

    def compile(self, model: SemanticModel) -> CompiledArtifact:
        return compile_lookml_model(model)


def _as_cube_artifact(artifact: CompiledArtifact) -> CompiledArtifact:
    """Re-wrap a LookML artifact so the shared Cube runtime accepts it."""
    if artifact.provider != "lookml":
        raise ValueError(f"LookmlRuntime cannot run '{artifact.provider}' artifacts")
    return CompiledArtifact(
        provider="cube",  # runtime dispatch key only; payload is cube-shaped
        name=artifact.name,
        payload={
            "format": "cube",
            "cubes": artifact.payload["cubes"],
            "metric_index": artifact.payload["metric_index"],
            "dimension_index": artifact.payload["dimension_index"],
        },
        source_digest=artifact.source_digest,
    )


class LookmlRuntime(SemanticRuntime):
    """LookML runtime: reuses the Cube SQL generator over translated artifacts."""

    name = "lookml"

    def get_metrics(self, artifact: CompiledArtifact) -> list[MetricDef]:
        return _cube_runtime.list_metrics(_as_cube_artifact(artifact))

    def get_dimensions(
        self, artifact: CompiledArtifact, metric: str | None = None
    ) -> list[DimensionDef]:
        return _cube_runtime.list_dimensions(_as_cube_artifact(artifact), metric)

    def generate_sql(self, artifact: CompiledArtifact, request: QueryRequest) -> str:
        return _cube_runtime.generate_sql(_as_cube_artifact(artifact), request)
