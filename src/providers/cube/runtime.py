"""Cube runtime: CompiledArtifact + QueryRequest -> Doris SQL.

Single-cube star queries: all metrics come from one base cube; dimensions may
additionally come from cubes joined to the base cube via many_to_one joins.
Filter values are escaped literals and every referenced name is validated
against the artifact, so the generated statement is injection-safe by
construction (model SQL expressions themselves are trusted model-author code).
"""

from __future__ import annotations

import re
from typing import Any

from providers.base import CompiledArtifact, DimensionDef, Filter, MetricDef, ProviderError, QueryRequest

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_TABLE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$")
_COLUMN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

#: Filter operators accepted in QueryRequest (mapped to SQL below).
FILTER_OPERATORS = {"eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in", "contains", "between"}


def quote_ident(name: str) -> str:
    if not _IDENT_RE.match(name):
        raise ProviderError(f"Invalid identifier: {name!r}")
    return f"`{name}`"


def quote_table(name: str) -> str:
    if not _TABLE_RE.match(name):
        raise ProviderError(f"Invalid table reference: {name!r}")
    return ".".join(quote_ident(part) for part in name.split("."))


def escape_literal(value: Any) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float)):
        return repr(value)
    return "'" + str(value).replace("\\", "\\\\").replace("'", "''") + "'"


def _qualify(sql: str, alias: str, cube_name: str) -> str:
    """Substitute {CUBE} placeholders and qualify bare column names."""
    sql = sql.replace("{CUBE}", quote_ident(alias)).replace(
        "{" + cube_name + "}", quote_ident(alias)
    )
    if _COLUMN_RE.match(sql):
        return f"{quote_ident(alias)}.{quote_ident(sql)}"
    return sql


class _CubeQueryBuilder:
    def __init__(self, artifact: CompiledArtifact):
        if artifact.provider != "cube":
            raise ProviderError(f"CubeRuntime cannot run provider '{artifact.provider}' artifacts")
        payload = artifact.payload
        self.cubes: dict[str, Any] = payload.get("cubes") or {}
        self.metric_index: dict[str, str] = payload.get("metric_index") or {}
        self.dimension_index: dict[str, str] = payload.get("dimension_index") or {}

    # -- resolution ----------------------------------------------------------

    def resolve_metric(self, name: str) -> tuple[str, dict[str, Any]]:
        cube_name = self.metric_index.get(name)
        if not cube_name:
            raise ProviderError(
                f"Unknown metric '{name}'. Available: {sorted(self.metric_index)}"
            )
        return cube_name, self.cubes[cube_name]["measures"][name]

    def selectable_dimensions(self, base_cube: str) -> dict[str, tuple[str, dict[str, Any]]]:
        """dimension name -> (alias, definition) selectable from the base cube."""
        out: dict[str, tuple[str, dict[str, Any]]] = {}
        base = self.cubes[base_cube]
        for name, d in base["dimensions"].items():
            out[name] = (base_cube, d)
        for join_name, join in base["joins"].items():
            target = self.cubes.get(join_name)
            if not target:
                continue
            for name, d in target["dimensions"].items():
                out.setdefault(name, (join_name, d))
        return out

    # -- SQL fragments --------------------------------------------------------

    def render_measure(self, definition: dict[str, Any], alias: str, cube_name: str) -> str:
        mtype = definition["type"]
        sql = definition.get("sql")
        if mtype == "count":
            return "count(*)"
        if mtype == "number":
            if not sql:
                raise ProviderError("measure type 'number' requires sql")
            return sql.replace("{CUBE}", quote_ident(alias))
        expr = _qualify(str(sql), alias, cube_name)
        if mtype == "count_distinct":
            return f"count(DISTINCT {expr})"
        return f"{mtype}({expr})"

    def from_clause(self, base_cube: str, needed_joins: set[str]) -> str:
        base = self.cubes[base_cube]
        alias = quote_ident(base_cube)
        if base.get("sql_table"):
            from_sql = f"{quote_table(base['sql_table'])} AS {alias}"
        else:  # sql: subquery
            from_sql = f"(\n{base['sql']}\n) AS {alias}"
        parts = [from_sql]
        for join_name in sorted(needed_joins):
            join = base["joins"].get(join_name)
            if not join:
                raise ProviderError(
                    f"Dimension requires join '{join_name}' which cube "
                    f"'{base_cube}' does not declare"
                )
            target = self.cubes.get(join_name)
            if not target:
                raise ProviderError(f"Join target cube '{join_name}' not in artifact")
            join_alias = quote_ident(join_name)
            if target.get("sql_table"):
                rhs = f"{quote_table(target['sql_table'])} AS {join_alias}"
            else:
                rhs = f"(\n{target['sql']}\n) AS {join_alias}"
            on_sql = join["sql"].replace("{CUBE}", quote_ident(base_cube))
            on_sql = on_sql.replace("{" + join_name + "}", join_alias)
            parts.append(f"LEFT JOIN {rhs} ON {on_sql}")
        return "\n".join(parts)

    def render_filter(self, flt: Filter, selectable: dict[str, tuple[str, dict[str, Any]]]) -> str:
        if flt.operator not in FILTER_OPERATORS:
            raise ProviderError(
                f"Unsupported filter operator '{flt.operator}' (allowed: {sorted(FILTER_OPERATORS)})"
            )
        entry = selectable.get(flt.dimension)
        if not entry:
            raise ProviderError(
                f"Cannot filter on unknown dimension '{flt.dimension}'. "
                f"Available: {sorted(selectable)}"
            )
        alias, definition = entry
        expr = _qualify(definition["sql"], alias, alias)
        op = flt.operator
        if op in ("in", "not_in"):
            values = flt.value if isinstance(flt.value, (list, tuple)) else [flt.value]
            if not values:
                raise ProviderError(f"Filter '{flt.dimension}': empty {op} list")
            kw = "IN" if op == "in" else "NOT IN"
            return f"{expr} {kw} ({', '.join(escape_literal(v) for v in values)})"
        if op == "between":
            values = flt.value
            if not isinstance(values, (list, tuple)) or len(values) != 2:
                raise ProviderError(f"Filter '{flt.dimension}': 'between' needs [low, high]")
            return f"{expr} BETWEEN {escape_literal(values[0])} AND {escape_literal(values[1])}"
        if op == "contains":
            return f"{expr} LIKE concat('%', {escape_literal(str(flt.value))}, '%')"
        simple = {"eq": "=", "ne": "!=", "gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[op]
        return f"{expr} {simple} {escape_literal(flt.value)}"


def generate_sql(artifact: CompiledArtifact, request: QueryRequest) -> str:
    builder = _CubeQueryBuilder(artifact)
    if not request.metrics:
        raise ProviderError("QueryRequest needs at least one metric")

    # Base cube = cube owning the first metric; v1 requires single-cube metrics.
    metric_cubes = {builder.resolve_metric(m)[0] for m in request.metrics}
    if len(metric_cubes) > 1:
        raise ProviderError(
            f"Cross-cube metrics not supported yet: {sorted(metric_cubes)}. "
            "Query metrics from one cube at a time."
        )
    base_cube = metric_cubes.pop()
    selectable = builder.selectable_dimensions(base_cube)

    needed_joins: set[str] = set()
    select_parts: list[str] = []
    group_exprs: list[str] = []

    for dim_name in request.dimensions:
        entry = selectable.get(dim_name)
        if not entry:
            raise ProviderError(
                f"Unknown dimension '{dim_name}' for cube '{base_cube}'. "
                f"Available: {sorted(selectable)}"
            )
        alias, definition = entry
        if alias != base_cube:
            needed_joins.add(alias)
        expr = _qualify(definition["sql"], alias, alias)
        select_parts.append(f"{expr} AS {quote_ident(dim_name)}")
        group_exprs.append(expr)

    for metric_name in request.metrics:
        _, definition = builder.resolve_metric(metric_name)
        agg = builder.render_measure(definition, base_cube, base_cube)
        select_parts.append(f"{agg} AS {quote_ident(metric_name)}")

    where_parts = []
    for flt in request.filters:
        entry = selectable.get(flt.dimension)
        if entry and entry[0] != base_cube:
            needed_joins.add(entry[0])
        where_parts.append(builder.render_filter(flt, selectable))

    sql_lines = ["SELECT", "  " + ",\n  ".join(select_parts)]
    sql_lines.append("FROM")
    sql_lines.append("  " + builder.from_clause(base_cube, needed_joins).replace("\n", "\n  "))
    if where_parts:
        sql_lines.append("WHERE")
        sql_lines.append("  " + "\n  AND ".join(where_parts))
    if group_exprs:
        sql_lines.append("GROUP BY")
        sql_lines.append("  " + ",\n  ".join(group_exprs))
    if request.order_by:
        valid = set(request.dimensions) | set(request.metrics)
        order_parts = []
        for item in request.order_by:
            desc = item.startswith("-")
            name = item[1:] if desc else item
            if name not in valid:
                raise ProviderError(
                    f"Cannot order by '{name}' — not in query select list {sorted(valid)}"
                )
            order_parts.append(f"{quote_ident(name)} {'DESC' if desc else 'ASC'}")
        sql_lines.append("ORDER BY")
        sql_lines.append("  " + ", ".join(order_parts))
    if request.limit is not None:
        if not isinstance(request.limit, int) or request.limit <= 0:
            raise ProviderError(f"limit must be a positive integer, got {request.limit!r}")
        sql_lines.append(f"LIMIT {request.limit}")
    return "\n".join(sql_lines)


def list_metrics(artifact: CompiledArtifact) -> list[MetricDef]:
    payload = artifact.payload
    out: list[MetricDef] = []
    for cube_name, cube in (payload.get("cubes") or {}).items():
        for name, m in (cube.get("measures") or {}).items():
            mtype = m["type"]
            expr = "count(*)" if mtype == "count" else f"{mtype}({m.get('sql')})"
            out.append(
                MetricDef(name=name, description=m.get("description", ""), expression=expr, model=cube_name)
            )
    return out


def list_dimensions(artifact: CompiledArtifact, metric: str | None = None) -> list[DimensionDef]:
    builder = _CubeQueryBuilder(artifact)
    if metric is not None:
        base_cube, _ = builder.resolve_metric(metric)
        selectable = builder.selectable_dimensions(base_cube)
        return [
            DimensionDef(
                name=name,
                description=d.get("description", ""),
                expression=d["sql"],
                type="time" if d["type"] == "time" else ("number" if d["type"] == "number" else "categorical"),
                model=alias,
            )
            for name, (alias, d) in sorted(selectable.items())
        ]
    out: list[DimensionDef] = []
    for cube_name, cube in (artifact.payload.get("cubes") or {}).items():
        for name, d in (cube.get("dimensions") or {}).items():
            out.append(
                DimensionDef(
                    name=name,
                    description=d.get("description", ""),
                    expression=d["sql"],
                    type="time" if d["type"] == "time" else ("number" if d["type"] == "number" else "categorical"),
                    model=cube_name,
                )
            )
    return out
