"""LookML compiler: SemanticModel -> CompiledArtifact.

Strategy: translate LookML views into the Cube artifact shape so the Cube
runtime's battle-tested SQL generator is reused wholesale (borrow, don't
rebuild). The payload keeps the original view definitions under
``lookml_views`` for provenance.
"""

from __future__ import annotations

import hashlib
from typing import Any

from providers.base import CompiledArtifact, ProviderError, SemanticModel
from providers.lookml.parser import MEASURE_TYPE_MAP, TIMEFRAME_MAP, _normalize_sql


def compile_lookml_model(model: SemanticModel) -> CompiledArtifact:
    if model.provider != "lookml":
        raise ProviderError(f"LookML compiler cannot compile provider '{model.provider}'")

    cubes_payload: dict[str, Any] = {}
    metric_index: dict[str, str] = {}
    dimension_index: dict[str, str] = {}

    for view in model.raw["views"]:
        view_name = str(view["name"])

        measures: dict[str, Any] = {}
        for m in view.get("measures") or []:
            mtype = MEASURE_TYPE_MAP[str(m["type"]).lower()]
            sql = m.get("sql")
            measures[str(m["name"])] = {
                "type": mtype,
                "sql": _normalize_sql(str(sql), view_name) if sql is not None else None,
                "description": str(m.get("description") or m.get("label") or ""),
            }
            metric_index.setdefault(str(m["name"]), view_name)

        dimensions: dict[str, Any] = {}
        for d in view.get("dimensions") or []:
            dimensions[str(d["name"])] = {
                "type": _cube_dim_type(str(d.get("type", "string"))),
                "sql": _normalize_sql(str(d.get("sql") or d["name"]), view_name),
                "description": str(d.get("description") or d.get("label") or ""),
                "primary_key": bool(d.get("primary_key", False)),
            }
            dimension_index.setdefault(str(d["name"]), view_name)

        for dg in view.get("dimension_groups") or []:
            base_sql = _normalize_sql(str(dg.get("sql") or dg["name"]), view_name)
            for tf in dg.get("timeframes") or ["date"]:
                tf = str(tf)
                if tf not in TIMEFRAME_MAP:
                    continue
                name = f"{dg['name']}_{tf}"
                dimensions[name] = {
                    "type": "time",
                    "sql": TIMEFRAME_MAP[tf].format(expr=base_sql),
                    "description": str(dg.get("description") or ""),
                    "primary_key": False,
                }
                dimension_index.setdefault(name, view_name)

        cubes_payload[view_name] = {
            "name": view_name,
            "sql_table": str(view["sql_table_name"]),
            "sql": None,
            "measures": measures,
            "dimensions": dimensions,
            "joins": {},
        }

    digest = hashlib.sha256(
        repr(sorted(cubes_payload.items())).encode("utf-8")
    ).hexdigest()[:16]

    return CompiledArtifact(
        provider="lookml",
        name=model.name,
        payload={
            "format": "lookml",
            # Cube-compatible projection consumed by the shared runtime.
            "cubes": cubes_payload,
            "metric_index": metric_index,
            "dimension_index": dimension_index,
            # Original LookML views, kept for provenance/debugging.
            "lookml_views": model.raw["views"],
        },
        source_digest=digest,
    )


def _cube_dim_type(lookml_type: str) -> str:
    if lookml_type in ("time", "date", "date_time"):
        return "time"
    if lookml_type == "number":
        return "number"
    if lookml_type == "yesno":
        return "boolean"
    return "string"
