"""LookML parser (powered by the lkml library, MIT — joshtemple/lkml).

Supported subset (v1): ``.view.lkml`` files with ``sql_table_name`` views,
dimensions, dimension_groups (time) and measures. Explores/joins and
derived tables are rejected with clear errors — use the Cube provider for
multi-entity models.

LookML references are normalized at parse time:
    ${TABLE}.amount   -> amount
    ${amount}         -> amount        (same-view reference)
    ${other.field}    -> ProviderError (cross-view reference, unsupported)
"""

from __future__ import annotations

import re
from typing import Any

import lkml

from providers.base import DimensionDef, MetricDef, ModelSource, ProviderError, SemanticModel

#: LookML measure type -> provider-neutral aggregation.
MEASURE_TYPE_MAP = {
    "count": "count",
    "count_distinct": "count_distinct",
    "sum": "sum",
    "average": "avg",
    "min": "min",
    "max": "max",
    "number": "number",
}

#: dimension_group timeframe -> Doris expression template ({expr} filled in).
TIMEFRAME_MAP = {
    "date": "{expr}",
    "week": "date_trunc({expr}, 'week')",
    "month": "date_trunc({expr}, 'month')",
    "quarter": "date_trunc({expr}, 'quarter')",
    "year": "date_trunc({expr}, 'year')",
}

_REF_RE = re.compile(r"\$\{([^}]+)\}")


def _normalize_sql(sql: str, view_name: str) -> str:
    """Resolve ${TABLE}.x and ${x} references to bare column names."""
    # Handle ${TABLE}.col first so the generic ${...} pass never sees a
    # bare ${TABLE} token.
    sql = sql.replace("${TABLE}.", "")

    def _sub(match: re.Match[str]) -> str:
        ref = match.group(1).strip()
        if ref == "TABLE":
            raise ProviderError(f"view '{view_name}': bare ${{TABLE}} reference is invalid")
        if "." in ref:
            raise ProviderError(
                f"view '{view_name}': cross-view reference '${{{ref}}}' is not supported"
            )
        return ref
    return _REF_RE.sub(_sub, sql)


def parse_lookml_file(source: ModelSource) -> SemanticModel:
    try:
        doc: dict[str, Any] = lkml.load(source.content)
    except Exception as e:
        raise ProviderError(f"LookML parse error in '{source.filename}': {e}") from e

    views = doc.get("views") or []
    if not views:
        raise ProviderError(f"'{source.filename}': no views found (explores are not supported yet)")

    metrics: list[MetricDef] = []
    dimensions: list[DimensionDef] = []
    seen: set[str] = set()

    for view in views:
        view_name = view.get("name")
        if not view_name:
            raise ProviderError(f"'{source.filename}': every view needs a name")
        view_name = str(view_name)
        if view_name in seen:
            raise ProviderError(f"'{source.filename}': duplicate view '{view_name}'")
        seen.add(view_name)
        if not view.get("sql_table_name"):
            raise ProviderError(
                f"view '{view_name}': only 'sql_table_name' views are supported "
                "(no derived_table in v1)"
            )

        for d in view.get("dimensions") or []:
            dimensions.append(
                DimensionDef(
                    name=str(d["name"]),
                    description=str(d.get("description") or d.get("label") or ""),
                    expression=_normalize_sql(str(d.get("sql") or d["name"]), view_name),
                    type=_dimension_type(str(d.get("type", "string"))),
                    model=view_name,
                )
            )

        for dg in view.get("dimension_groups") or []:
            base_sql = _normalize_sql(str(dg.get("sql") or dg["name"]), view_name)
            for tf in dg.get("timeframes") or ["date"]:
                tf = str(tf)
                if tf not in TIMEFRAME_MAP:
                    continue  # skip raw/time/etc. granularities in v1
                dimensions.append(
                    DimensionDef(
                        name=f"{dg['name']}_{tf}",
                        description=str(dg.get("description") or ""),
                        expression=TIMEFRAME_MAP[tf].format(expr=base_sql),
                        type="time",
                        model=view_name,
                    )
                )

        for m in view.get("measures") or []:
            mtype = str(m.get("type", "")).lower()
            if mtype not in MEASURE_TYPE_MAP:
                raise ProviderError(
                    f"view '{view_name}' measure '{m.get('name')}': "
                    f"unsupported type '{mtype}' (allowed: {sorted(MEASURE_TYPE_MAP)})"
                )
            sql = m.get("sql")
            metrics.append(
                MetricDef(
                    name=str(m["name"]),
                    description=str(m.get("description") or m.get("label") or ""),
                    expression=(
                        "count(*)" if MEASURE_TYPE_MAP[mtype] == "count"
                        else f"{MEASURE_TYPE_MAP[mtype]}({_normalize_sql(str(sql), view_name) if sql else m['name']})"
                    ),
                    model=view_name,
                )
            )

    name = str(views[0]["name"]) if len(views) == 1 else source.filename
    return SemanticModel(
        provider="lookml",
        name=name,
        metrics=metrics,
        dimensions=dimensions,
        raw={"views": views, "filename": source.filename},
    )


def _dimension_type(lookml_type: str) -> str:
    if lookml_type in ("time", "date", "date_time"):
        return "time"
    if lookml_type == "number":
        return "number"
    return "categorical"
