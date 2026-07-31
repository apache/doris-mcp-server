"""Cube semantic provider plugin (cube-js/cube schema format)."""

from __future__ import annotations

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
from providers.cube import runtime as _runtime
from providers.cube.compiler import compile_cube_model
from providers.cube.parser import load_yaml, parse_cube_file


class CubeProvider(SemanticProvider):
    """Cube (cube-js) semantic model provider: YAML cubes with measures/dimensions/joins."""

    name = "cube"

    def detect(self, source: ModelSource) -> float:
        if not source.filename.endswith((".yml", ".yaml")):
            return 0.0
        try:
            data = load_yaml(source)
        except Exception:
            return 0.0
        if isinstance(data.get("cubes"), list):
            return 0.95
        # a bare single-cube mapping with measures/dimensions
        if "measures" in data or "dimensions" in data:
            return 0.4
        return 0.0

    def validate(self, source: ModelSource) -> list[str]:
        try:
            parse_cube_file(source)
        except Exception as e:
            return [str(e)]
        return []

    def parse(self, source: ModelSource) -> SemanticModel:
        return parse_cube_file(source)

    def compile(self, model: SemanticModel) -> CompiledArtifact:
        return compile_cube_model(model)


class CubeRuntime(SemanticRuntime):
    """Cube runtime: metadata discovery + Doris SQL generation from artifacts."""

    name = "cube"

    def get_metrics(self, artifact: CompiledArtifact) -> list[MetricDef]:
        return _runtime.list_metrics(artifact)

    def get_dimensions(
        self, artifact: CompiledArtifact, metric: str | None = None
    ) -> list[DimensionDef]:
        return _runtime.list_dimensions(artifact, metric)

    def generate_sql(self, artifact: CompiledArtifact, request: QueryRequest) -> str:
        return _runtime.generate_sql(artifact, request)
