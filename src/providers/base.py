"""Semantic Provider SPI — the plugin contract for semantic model formats.

A *Semantic Provider* is a backend plugin that owns the full lifecycle of one
semantic model format (Cube, MetricFlow, LookML, ...):

Build time:
    validate() -> parse() -> compile()  => CompiledArtifact

Runtime:
    get_metrics() / get_dimensions() / generate_sql()

The compiled artifact is the provider-specific runtime product (analogous to a
Java ``.class`` file, LLVM bitcode, or dbt ``manifest.json``). Its schema is
deliberately NOT standardized across providers — each provider defines its own
payload and is the only component that interprets it.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

# Current artifact envelope version. Bump when the envelope (not the
# provider payload) changes incompatibly.
ARTIFACT_VERSION = 1


class ProviderError(Exception):
    """Raised for any provider-side validation/parse/compile/runtime failure."""


# ---------------------------------------------------------------------------
# Build-time input/output types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ModelSource:
    """One uploaded semantic model file."""

    filename: str
    content: str


@dataclass(frozen=True)
class MetricDef:
    """A provider-neutral description of one metric (for metadata discovery)."""

    name: str
    description: str = ""
    expression: str = ""          # human-readable agg expression, e.g. "sum(amount)"
    model: str = ""               # originating cube / view / semantic model


@dataclass(frozen=True)
class DimensionDef:
    """A provider-neutral description of one dimension."""

    name: str
    description: str = ""
    expression: str = ""          # column or SQL expression
    type: str = "categorical"     # categorical | time | number
    model: str = ""


@dataclass
class SemanticModel:
    """Provider-neutral parsed representation (the "AST").

    ``raw`` keeps the provider-specific parse tree; the metric/dimension lists
    are a normalized projection used for validation and metadata preview.
    """

    provider: str
    name: str
    metrics: list[MetricDef] = field(default_factory=list)
    dimensions: list[DimensionDef] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class CompiledArtifact:
    """Provider-specific compiled runtime product, plus a portable envelope.

    The envelope is standardized (provider name, version, source digest);
    ``payload`` is opaque to everything except the owning provider.
    """

    provider: str
    name: str
    payload: dict[str, Any]
    source_digest: str = ""
    artifact_version: int = ARTIFACT_VERSION

    def to_json(self) -> str:
        return json.dumps(
            {
                "artifact_version": self.artifact_version,
                "provider": self.provider,
                "name": self.name,
                "source_digest": self.source_digest,
                "payload": self.payload,
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )

    @classmethod
    def from_json(cls, text: str) -> "CompiledArtifact":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise ProviderError(f"Invalid artifact JSON: {e}") from e
        if not isinstance(data, dict) or "provider" not in data or "payload" not in data:
            raise ProviderError("Artifact JSON missing required keys (provider/payload)")
        version = data.get("artifact_version", 0)
        if version != ARTIFACT_VERSION:
            raise ProviderError(
                f"Unsupported artifact_version {version} (expected {ARTIFACT_VERSION})"
            )
        return cls(
            provider=data["provider"],
            name=data.get("name", ""),
            payload=data["payload"],
            source_digest=data.get("source_digest", ""),
            artifact_version=version,
        )


# ---------------------------------------------------------------------------
# Runtime query types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Filter:
    """One structured filter on a dimension.

    Structured filters (instead of raw SQL fragments) let providers validate
    the target dimension and safely escape literal values.
    """

    dimension: str
    operator: str          # eq|ne|gt|gte|lt|lte|in|not_in|contains|between
    value: Any             # scalar, list for in/not_in, [low, high] for between


@dataclass
class QueryRequest:
    """Provider-neutral semantic query request issued by an agent."""

    metrics: list[str]
    dimensions: list[str] = field(default_factory=list)
    filters: list[Filter] = field(default_factory=list)
    order_by: list[str] = field(default_factory=list)   # names; prefix '-' for DESC
    limit: int | None = None


# ---------------------------------------------------------------------------
# SPI interfaces
# ---------------------------------------------------------------------------


class SemanticProvider(ABC):
    """Build-time half of a provider plugin: source -> compiled artifact."""

    #: Unique provider name, e.g. "cube", "metricflow", "lookml".
    name: str = ""

    @abstractmethod
    def detect(self, source: ModelSource) -> float:
        """Confidence (0.0-1.0) that this provider owns ``source``.

        Used by the registry for format auto-detection on upload. Return 0.0
        when the file is definitely not this format.
        """

    @abstractmethod
    def validate(self, source: ModelSource) -> list[str]:
        """Return a list of problems with the source ([] means valid)."""

    @abstractmethod
    def parse(self, source: ModelSource) -> SemanticModel:
        """Parse the source into a provider-neutral SemanticModel."""

    @abstractmethod
    def compile(self, model: SemanticModel) -> CompiledArtifact:
        """Compile the parsed model into a provider-specific runtime artifact."""

    # -- convenience pipeline ------------------------------------------------

    def build(self, source: ModelSource) -> CompiledArtifact:
        """Full build pipeline: validate -> parse -> compile."""
        problems = self.validate(source)
        if problems:
            raise ProviderError(
                f"{self.name} validation failed: " + "; ".join(problems)
            )
        return self.compile(self.parse(source))


class SemanticRuntime(ABC):
    """Runtime half of a provider plugin: artifact + request -> Doris SQL."""

    #: Must match the owning SemanticProvider.name.
    name: str = ""

    @abstractmethod
    def get_metrics(self, artifact: CompiledArtifact) -> list[MetricDef]:
        """List metrics exposed by a compiled artifact."""

    @abstractmethod
    def get_dimensions(
        self, artifact: CompiledArtifact, metric: str | None = None
    ) -> list[DimensionDef]:
        """List dimensions, optionally restricted to those valid for a metric."""

    @abstractmethod
    def generate_sql(self, artifact: CompiledArtifact, request: QueryRequest) -> str:
        """Generate a Doris SELECT statement for the given semantic query."""
