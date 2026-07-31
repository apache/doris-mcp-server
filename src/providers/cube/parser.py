"""Cube data model parser.

Parses Cube-schema YAML (the format used by cube-js/cube) into the
provider-neutral SemanticModel. Supported subset:

    cubes:
      - name: orders
        sql_table: dw.orders          # or: sql: SELECT ...
        title / description: ...
        joins:
          - name: users
            sql: "{CUBE}.user_id = {users}.id"
            relationship: many_to_one
        dimensions:
          - name: country
            sql: country              # defaults to the dimension name
            type: string              # string|number|time|boolean
            primary_key: true
        measures:
          - name: revenue
            type: sum                 # count|count_distinct|sum|avg|min|max|number
            sql: amount               # defaults to the measure name (except count)
            description: ...
"""

from __future__ import annotations

from typing import Any

import yaml

from providers.base import DimensionDef, MetricDef, ModelSource, ProviderError, SemanticModel

#: Measure aggregation types understood by the Cube provider.
MEASURE_TYPES = {"count", "count_distinct", "sum", "avg", "min", "max", "number"}

#: Dimension types understood by the Cube provider.
DIMENSION_TYPES = {"string", "number", "time", "boolean"}


def load_yaml(source: ModelSource) -> dict[str, Any]:
    """Parse YAML, raising ProviderError with context on failure."""
    try:
        data = yaml.safe_load(source.content)
    except yaml.YAMLError as e:
        raise ProviderError(f"YAML parse error in '{source.filename}': {e}") from e
    if not isinstance(data, dict):
        raise ProviderError(f"'{source.filename}': top-level YAML must be a mapping")
    return data


def parse_cube_file(source: ModelSource) -> SemanticModel:
    """Parse a Cube YAML file into a SemanticModel (raw keeps the cube list)."""
    data = load_yaml(source)
    cubes = data.get("cubes")
    if not isinstance(cubes, list) or not cubes:
        raise ProviderError(f"'{source.filename}': no 'cubes' list found")

    metrics: list[MetricDef] = []
    dimensions: list[DimensionDef] = []
    seen: set[str] = set()

    for cube in cubes:
        if not isinstance(cube, dict) or not cube.get("name"):
            raise ProviderError(f"'{source.filename}': every cube needs a 'name'")
        cube_name = str(cube["name"])
        if cube_name in seen:
            raise ProviderError(f"'{source.filename}': duplicate cube '{cube_name}'")
        seen.add(cube_name)
        if not cube.get("sql_table") and not cube.get("sql"):
            raise ProviderError(f"cube '{cube_name}': needs 'sql_table' or 'sql'")

        for m in cube.get("measures") or []:
            mtype = str(m.get("type", "")).lower()
            if mtype not in MEASURE_TYPES:
                raise ProviderError(
                    f"cube '{cube_name}' measure '{m.get('name')}': "
                    f"unsupported type '{mtype}' (allowed: {sorted(MEASURE_TYPES)})"
                )
            sql = m.get("sql")
            if mtype != "count" and not sql:
                raise ProviderError(
                    f"cube '{cube_name}' measure '{m.get('name')}': "
                    f"type '{mtype}' requires 'sql'"
                )
            metrics.append(
                MetricDef(
                    name=str(m["name"]),
                    description=str(m.get("description") or m.get("title") or ""),
                    expression=_measure_expression(mtype, sql),
                    model=cube_name,
                )
            )

        for d in cube.get("dimensions") or []:
            dtype = str(d.get("type", "string")).lower()
            if dtype not in DIMENSION_TYPES:
                raise ProviderError(
                    f"cube '{cube_name}' dimension '{d.get('name')}': "
                    f"unsupported type '{dtype}' (allowed: {sorted(DIMENSION_TYPES)})"
                )
            dimensions.append(
                DimensionDef(
                    name=str(d["name"]),
                    description=str(d.get("description") or d.get("title") or ""),
                    expression=str(d.get("sql") or d["name"]),
                    type="time" if dtype == "time" else ("number" if dtype == "number" else "categorical"),
                    model=cube_name,
                )
            )

        for j in cube.get("joins") or []:
            rel = str(j.get("relationship", "")).lower()
            if rel != "many_to_one":
                raise ProviderError(
                    f"cube '{cube_name}' join '{j.get('name')}': only "
                    f"'many_to_one' relationships are supported (got '{rel}')"
                )
            if not j.get("name") or not j.get("sql"):
                raise ProviderError(f"cube '{cube_name}': every join needs 'name' and 'sql'")

    name = cubes[0]["name"] if len(cubes) == 1 else source.filename
    return SemanticModel(
        provider="cube",
        name=str(name),
        metrics=metrics,
        dimensions=dimensions,
        raw={"cubes": cubes, "filename": source.filename},
    )


def _measure_expression(mtype: str, sql: Any) -> str:
    if mtype == "count":
        return "count(*)"
    return f"{mtype}({sql})"
