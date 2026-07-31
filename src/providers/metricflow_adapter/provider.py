"""MetricFlow provider adapter.

Bridges the existing vendored MetricFlow engine (src/store/compiler.py +
src/store/manifest.py) into the provider SPI so agent-facing tooling can
treat every semantic format uniformly.

Build time: dbt semantic-model YAML is parsed/validated lightly here; the
heavy lifting (manifest build, ref resolution) stays in the MetricFlow
engine. The artifact payload carries the parsed semantic models.

Runtime: generate_sql requires the full MetricFlow engine, which needs the
dbt project on disk. Server integration binds a live workspace via
``bind(compiler, manifest)``; unbound artifacts raise a clear error instead
of silently producing wrong SQL.
"""

from __future__ import annotations

from typing import Any

from providers.base import (
    CompiledArtifact,
    DimensionDef,
    MetricDef,
    ModelSource,
    ProviderError,
    QueryRequest,
    SemanticModel,
    SemanticProvider,
    SemanticRuntime,
)
from providers.cube.parser import load_yaml


class MetricFlowProviderAdapter(SemanticProvider):
    """dbt/MetricFlow semantic model provider (semantic_models YAML)."""

    name = "metricflow"

    def detect(self, source: ModelSource) -> float:
        if not source.filename.endswith((".yml", ".yaml")):
            return 0.0
        try:
            data = load_yaml(source)
        except Exception:
            return 0.0
        if isinstance(data.get("semantic_models"), list):
            return 0.95
        if isinstance(data.get("metrics"), list):
            return 0.7  # dbt metrics-only file
        return 0.0

    def validate(self, source: ModelSource) -> list[str]:
        try:
            self.parse(source)
        except Exception as e:
            return [str(e)]
        return []

    def parse(self, source: ModelSource) -> SemanticModel:
        data = load_yaml(source)
        semantic_models = data.get("semantic_models") or []
        metrics_yaml = data.get("metrics") or []
        if not semantic_models and not metrics_yaml:
            raise ProviderError(
                f"'{source.filename}': no 'semantic_models' or 'metrics' found"
            )

        metrics: list[MetricDef] = []
        dimensions: list[DimensionDef] = []
        for sm in semantic_models:
            if not isinstance(sm, dict) or not sm.get("name"):
                raise ProviderError(f"'{source.filename}': every semantic_model needs a 'name'")
            sm_name = str(sm["name"])
            for meas in sm.get("measures") or []:
                metrics.append(
                    MetricDef(
                        name=str(meas["name"]),
                        description=str(meas.get("description") or ""),
                        expression=str(meas.get("expr") or meas["name"]),
                        model=sm_name,
                    )
                )
            for dim in sm.get("dimensions") or []:
                dimensions.append(
                    DimensionDef(
                        name=str(dim["name"]),
                        description=str(dim.get("description") or ""),
                        expression=str(dim.get("expr") or dim["name"]),
                        type=str(dim.get("type", "categorical")).lower(),
                        model=sm_name,
                    )
                )
        for m in metrics_yaml:
            if isinstance(m, dict) and m.get("name"):
                metrics.append(
                    MetricDef(
                        name=str(m["name"]),
                        description=str(m.get("description") or ""),
                        expression=str(m.get("type", "")),
                        model="(dbt metrics)",
                    )
                )

        name = str(semantic_models[0]["name"]) if len(semantic_models) == 1 else source.filename
        return SemanticModel(
            provider="metricflow",
            name=name,
            metrics=metrics,
            dimensions=dimensions,
            raw={"semantic_models": semantic_models, "metrics": metrics_yaml,
                 "filename": source.filename},
        )

    def compile(self, model: SemanticModel) -> CompiledArtifact:
        if model.provider != "metricflow":
            raise ProviderError(f"MetricFlow adapter cannot compile '{model.provider}'")
        return CompiledArtifact(
            provider="metricflow",
            name=model.name,
            payload={
                "format": "metricflow",
                "semantic_models": model.raw["semantic_models"],
                "metrics": model.raw["metrics"],
            },
        )


class MetricFlowRuntimeAdapter(SemanticRuntime):
    """MetricFlow runtime: delegates SQL generation to a bound workspace engine."""

    name = "metricflow"

    def __init__(self) -> None:
        # The registered instance stays unbound (stateless). Server
        # integration obtains a bound copy via bind(); mutating the shared
        # registry instance would race across concurrent workspaces.
        self._compiler: Any = None
        self._manifest: Any = None

    def bind(self, compiler: Any, manifest: Any) -> "MetricFlowRuntimeAdapter":
        """Return a NEW adapter bound to a live workspace engine + manifest."""
        bound = MetricFlowRuntimeAdapter()
        bound._compiler = compiler
        bound._manifest = manifest
        return bound

    @property
    def is_bound(self) -> bool:
        return self._compiler is not None

    # -- metadata ------------------------------------------------------------

    def get_metrics(self, artifact: CompiledArtifact) -> list[MetricDef]:
        if self._manifest is not None:
            try:
                return [
                    MetricDef(
                        name=m.get("name", ""),
                        description=m.get("description", "") or "",
                        expression=m.get("type", "") or "",
                        model=m.get("model", "") or "",
                    )
                    for m in self._manifest.list_metrics()
                ]
            except Exception as e:
                raise ProviderError(f"MetricFlow manifest error: {e}") from e
        # Fallback: project the artifact payload.
        out: list[MetricDef] = []
        for sm in artifact.payload.get("semantic_models") or []:
            for meas in sm.get("measures") or []:
                out.append(MetricDef(name=str(meas["name"]), model=str(sm.get("name", ""))))
        for m in artifact.payload.get("metrics") or []:
            out.append(MetricDef(name=str(m["name"]), description=str(m.get("description") or "")))
        return out

    def get_dimensions(
        self, artifact: CompiledArtifact, metric: str | None = None
    ) -> list[DimensionDef]:
        if self._manifest is not None and metric:
            try:
                dims = self._manifest.list_dimensions_for_metric(metric)
                return [
                    DimensionDef(
                        name=d.get("name", ""),
                        description=d.get("description", "") or "",
                        type=d.get("type", "categorical") or "categorical",
                    )
                    for d in dims
                ]
            except Exception as e:
                raise ProviderError(f"MetricFlow manifest error: {e}") from e
        out: list[DimensionDef] = []
        for sm in artifact.payload.get("semantic_models") or []:
            for dim in sm.get("dimensions") or []:
                out.append(
                    DimensionDef(
                        name=str(dim["name"]),
                        type=str(dim.get("type", "categorical")).lower(),
                        model=str(sm.get("name", "")),
                    )
                )
        return out

    # -- SQL ------------------------------------------------------------------

    def generate_sql(self, artifact: CompiledArtifact, request: QueryRequest) -> str:
        if self._compiler is None:
            raise ProviderError(
                "MetricFlow runtime is not bound to a workspace engine. "
                "Use the workspace-backed query_metric tool for MetricFlow models."
            )
        where_parts = []
        for flt in request.filters:
            # MetricFlow resolves {{ Dimension(...) }} syntax itself; here we
            # only support simple equality passes through the compiler's
            # where handling.
            if flt.operator != "eq":
                raise ProviderError(
                    "MetricFlow adapter supports only eq filters in generate_sql; "
                    "use query_metric's where for full filter syntax"
                )
            where_parts.append(f"{flt.dimension} = '{flt.value}'")
        sql, _cmd, error = self._compiler.compile(
            list(request.metrics),
            list(request.dimensions) or None,
            " AND ".join(where_parts) if where_parts else None,
            list(request.order_by) or None,
            request.limit,
            None,
        )
        if error:
            raise ProviderError(f"MetricFlow compile error: {error}")
        return sql
