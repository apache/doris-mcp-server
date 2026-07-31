"""Cube compiler: SemanticModel -> CompiledArtifact.

The artifact pre-resolves everything the runtime needs so queries never
re-parse YAML:

- normalized per-cube measure/dimension/join definitions
- global metric -> cube and dimension -> cube indexes
- join reachability (which cubes can supply dimensions to which base cube)
"""

from __future__ import annotations

import hashlib
from typing import Any

import yaml

from providers.base import CompiledArtifact, ProviderError, SemanticModel


def _digest(model: SemanticModel) -> str:
    blob = yaml.safe_dump(model.raw.get("cubes"), sort_keys=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def compile_cube_model(model: SemanticModel) -> CompiledArtifact:
    if model.provider != "cube":
        raise ProviderError(f"CubeCompiler cannot compile provider '{model.provider}'")

    cubes_payload: dict[str, Any] = {}
    metric_index: dict[str, str] = {}
    dimension_index: dict[str, str] = {}

    for cube in model.raw["cubes"]:
        cube_name = str(cube["name"])

        measures: dict[str, Any] = {}
        for m in cube.get("measures") or []:
            mtype = str(m["type"]).lower()
            measures[str(m["name"])] = {
                "type": mtype,
                "sql": str(m["sql"]) if m.get("sql") is not None else None,
                "description": str(m.get("description") or m.get("title") or ""),
            }
            metric_index.setdefault(str(m["name"]), cube_name)

        dimensions: dict[str, Any] = {}
        for d in cube.get("dimensions") or []:
            dimensions[str(d["name"])] = {
                "type": str(d.get("type", "string")).lower(),
                "sql": str(d.get("sql") or d["name"]),
                "description": str(d.get("description") or d.get("title") or ""),
                "primary_key": bool(d.get("primary_key", False)),
            }
            dimension_index.setdefault(str(d["name"]), cube_name)

        joins: dict[str, Any] = {}
        for j in cube.get("joins") or []:
            joins[str(j["name"])] = {
                "sql": str(j["sql"]),
                "relationship": str(j.get("relationship", "many_to_one")).lower(),
            }

        cubes_payload[cube_name] = {
            "name": cube_name,
            "sql_table": str(cube["sql_table"]) if cube.get("sql_table") else None,
            "sql": str(cube["sql"]) if cube.get("sql") else None,
            "measures": measures,
            "dimensions": dimensions,
            "joins": joins,
        }

    payload = {
        "format": "cube",
        "cubes": cubes_payload,
        "metric_index": metric_index,
        "dimension_index": dimension_index,
    }
    return CompiledArtifact(
        provider="cube",
        name=model.name,
        payload=payload,
        source_digest=_digest(model),
    )
