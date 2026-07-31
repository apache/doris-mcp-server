"""Semantic manifest loader — reads dbt semantic_manifest.json and YAML files."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("doris_new_mcp.semantic")


class SemanticManifest:
    """Lightweight manifest parsed from target/semantic_manifest.json.

    Provides metadata access (metrics, dimensions, entities) without
    requiring the full MetricFlow engine.
    """

    def __init__(self, manifest_path: str | Path):
        self._path = Path(manifest_path)
        self._data: dict = {}
        self._metrics: list[dict] = []
        self._semantic_models: list[dict] = []
        self.load()

    def load(self) -> None:
        """Load and parse the semantic manifest JSON."""
        if not self._path.exists():
            raise FileNotFoundError(f"Semantic manifest not found: {self._path}")

        with open(self._path, "r") as f:
            self._data = json.load(f)

        self._metrics = list(self._data.get("metrics", {}).values()) if isinstance(
            self._data.get("metrics"), dict
        ) else self._data.get("metrics", [])

        self._semantic_models = list(self._data.get("semantic_models", {}).values()) if isinstance(
            self._data.get("semantic_models"), dict
        ) else self._data.get("semantic_models", [])

    def replace_with(self, other: "SemanticManifest") -> None:
        """Atomically replace content from another SemanticManifest instance."""
        self._data = other._data
        self._metrics = other._metrics
        self._semantic_models = other._semantic_models

    def list_metrics(self) -> list[dict[str, Any]]:
        """Return all metrics with name, description."""
        result = []
        for m in self._metrics:
            result.append({
                "name": m.get("name", ""),
                "description": m.get("description", ""),
            })
        return result

    def get_metric(self, metric_name: str) -> dict | None:
        """Get full metric definition by name."""
        for m in self._metrics:
            if m.get("name") == metric_name:
                return m
        return None

    def _collect_measure_refs(self, metric_name: str, visited: set[str]) -> set[str]:
        """Recursively resolve a metric to the names of its underlying measures.

        Handles all metric types:
        - simple / cumulative: ``type_params.measure`` (or ``type_params.input_measures``)
        - derived: ``type_params.metrics[]`` → recurses into sub-metrics
        - ratio: ``type_params.numerator`` / ``denominator`` → recurses into
          the referenced metrics (a bare name that matches no metric is kept
          as a measure candidate)
        - conversion: ``conversion_type_params`` (or flat ``type_params``)
          ``base_measure`` / ``conversion_measure``, with ``base_metric`` /
          ``conversion_metric`` resolved recursively
        - cumulative: ``cumulative_type_params.metric`` → recurses

        *visited* guards against reference cycles (e.g. derived-of-derived
        loops); metric names already in it are skipped.
        """
        refs: set[str] = set()
        if not metric_name or metric_name in visited:
            return refs
        visited.add(metric_name)

        metric = self.get_metric(metric_name)
        if not metric:
            return refs
        type_params = metric.get("type_params", {})
        if not isinstance(type_params, dict):
            return refs

        def _name_of(ref: Any) -> str:
            if isinstance(ref, dict):
                return ref.get("name", "")
            return ref if isinstance(ref, str) else ""

        # simple / cumulative metrics
        name = _name_of(type_params.get("measure"))
        if name:
            refs.add(name)
        # parsed manifests may also carry resolved input measures
        for input_measure in type_params.get("input_measures") or []:
            name = _name_of(input_measure)
            if name:
                refs.add(name)

        # derived metrics reference other metrics — resolve recursively
        for sub in type_params.get("metrics") or []:
            refs |= self._collect_measure_refs(_name_of(sub), visited)

        # ratio metrics reference numerator/denominator metrics
        for key in ("numerator", "denominator"):
            name = _name_of(type_params.get(key))
            if name:
                refs.add(name)  # harmless if it's a metric name (no measure match)
                refs |= self._collect_measure_refs(name, visited)

        # conversion metrics: measures and/or metrics, nested or flat
        for container in (type_params.get("conversion_type_params") or {}, type_params):
            if not isinstance(container, dict):
                continue
            for key in ("base_measure", "conversion_measure"):
                name = _name_of(container.get(key))
                if name:
                    refs.add(name)
            for key in ("base_metric", "conversion_metric"):
                refs |= self._collect_measure_refs(_name_of(container.get(key)), visited)

        # cumulative metrics may wrap another metric
        cum_params = type_params.get("cumulative_type_params") or {}
        if isinstance(cum_params, dict):
            refs |= self._collect_measure_refs(_name_of(cum_params.get("metric")), visited)

        return refs

    def list_dimensions_for_metric(self, metric_name: str) -> list[dict[str, Any]]:
        """Return dimensions available for a metric.

        Finds the semantic models referenced by the metric's measures,
        then collects their dimensions.
        """
        metric = self.get_metric(metric_name)
        if not metric:
            return []

        # Collect measure references from metric type_params, resolving
        # derived/ratio/conversion/cumulative chains recursively.
        measure_refs = self._collect_measure_refs(metric_name, set())

        # Find semantic models containing these measures
        dimensions = []
        seen = set()
        for sm in self._semantic_models:
            sm_measures = {m.get("name") for m in sm.get("measures", [])}
            if measure_refs & sm_measures:
                for dim in sm.get("dimensions", []):
                    dim_name = dim.get("name", "")
                    if dim_name not in seen:
                        seen.add(dim_name)
                        dimensions.append({
                            "name": dim_name,
                            "type": dim.get("type", ""),
                            "description": dim.get("description", ""),
                        })
        return dimensions
