"""MetricFlow SQL compiler — uses engine.explain() for compile-only mode."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger("doris_new_mcp.semantic")

_SENTINEL_NO_JSON = object()

# Matches single- or double-quoted SQL string literals, including doubled
# quotes ('' / "") and backslash escapes (\'). Used to mask literals before
# bare-name substitution in resolve_where.
_STRING_LITERAL_RE = re.compile(r"'(?:[^'\\]|\\.|'')*'|\"(?:[^\"\\]|\\.|\"\")*\"")
_MASKED_LITERAL_RE = re.compile("\x00(\\d+)\x00")

# Try to import MetricFlow engine
_ENGINE_AVAILABLE = False
try:
    from metricflow.engine.metricflow_engine import (
        MetricFlowEngine,
        MetricFlowExplainResult,
        MetricFlowQueryRequest,
    )
    from metricflow.protocols.sql_client import SqlClient, SqlEngine
    from metricflow.sql.render.doris import DorisSqlPlanRenderer
    from metricflow.sql.render.sql_plan_renderer import SqlPlanRenderer
    from metricflow.semantics.model.semantic_manifest_lookup import SemanticManifestLookup
    from metricflow.semantics.model.dbt_manifest_parser import parse_manifest_from_dbt_generated_manifest
    _ENGINE_AVAILABLE = True
except ImportError:
    _ENGINE_AVAILABLE = False


class _DorisSqlClientStub:
    """Minimal SqlClient stub for compile-only mode.

    MetricFlowEngine requires a sql_client to render SQL in the correct dialect.
    This stub provides sql_engine_type and sql_plan_renderer for Doris,
    but raises on any actual query execution.
    """

    @property
    def sql_engine_type(self) -> Any:
        return SqlEngine.DORIS

    @property
    def sql_plan_renderer(self) -> Any:
        return DorisSqlPlanRenderer()

    def query(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError("Compile-only mode: query execution not supported via MetricFlow sql_client")

    def execute(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError("Compile-only mode: execution not supported via MetricFlow sql_client")

    def dry_run(self, *args: Any, **kwargs: Any) -> Any:
        pass  # No-op for dry run

    def close(self) -> None:
        pass

    def render_bind_parameter_key(self, bind_parameter_key: str) -> str:
        return f"%({bind_parameter_key})s"


class MetricFlowCompiler:
    """Compiles metric queries to SQL using MetricFlowEngine.explain()."""

    def __init__(self, dbt_project_dir: str | Path):
        self._project_dir = Path(dbt_project_dir)
        self._manifest_path = self._project_dir / "target" / "semantic_manifest.json"
        self._engine: Any = None
        self._engine_mode = False

        if _ENGINE_AVAILABLE:
            self._try_init_engine()

    def _try_init_engine(self) -> None:
        """Try to initialize the MetricFlow engine from cached manifest."""
        if not self._manifest_path.exists():
            logger.warning(f"Manifest not found at {self._manifest_path}, engine mode disabled")
            return

        try:
            with open(self._manifest_path, "r") as f:
                manifest_json = f.read()
            manifest = parse_manifest_from_dbt_generated_manifest(manifest_json)
            lookup = SemanticManifestLookup(manifest)
            sql_client = _DorisSqlClientStub()

            self._engine = MetricFlowEngine(
                semantic_manifest_lookup=lookup,
                sql_client=sql_client,
            )
            self._engine_mode = True
            logger.info("MetricFlow engine initialized in compile-only mode (Doris dialect)")
        except Exception as e:
            logger.warning(f"Failed to init MetricFlow engine: {e}")
            self._engine_mode = False

    def replace_with(self, other: "MetricFlowCompiler") -> None:
        """Atomically replace engine state from another compiler instance."""
        self._engine = other._engine
        self._engine_mode = other._engine_mode

    def reload(self) -> bool:
        """Reload manifest (after dbt parse + validate). Returns True on success."""
        self._engine = None
        self._engine_mode = False
        if _ENGINE_AVAILABLE:
            self._try_init_engine()
        return self._engine_mode

    def _build_dimension_map(self, metric_names: list[str]) -> tuple[dict[str, str], set[str]]:
        """Build bare_name → qualified_name mapping and set of time dimension bare names.

        Returns (name_map, time_dims).
        """
        name_map: dict[str, str] = {}
        time_dims: set[str] = set()

        if not self._engine_mode or not self._engine:
            return name_map, time_dims

        try:
            dims = self._engine.simple_dimensions_for_metrics(metric_names)
        except Exception as e:
            logger.warning(f"Failed to get dimensions: {e}")
            return name_map, time_dims

        for d in dims:
            bare = d.name.lower()
            qualified = d.dunder_name
            if bare not in name_map:
                name_map[bare] = qualified
            # Track time dimensions
            if hasattr(d, 'type') and str(d.type).lower().endswith('time'):
                time_dims.add(bare)

        # Time grain shortcuts
        for grain in ("day", "week", "month", "quarter", "year"):
            name_map[grain] = f"metric_time__{grain}"

        return name_map, time_dims

    def resolve_group_by(self, metric_names: list[str], group_by: list[str]) -> list[str]:
        """Resolve bare dimension names to MetricFlow qualified names.

        e.g. 'channel' → 'order_entity__channel', 'month' → 'metric_time__month'
        """
        name_map, _ = self._build_dimension_map(metric_names)
        if not name_map:
            return group_by

        resolved = []
        for g in group_by:
            if "__" in g:
                resolved.append(g)
            elif g.lower() in name_map:
                resolved.append(name_map[g.lower()])
            else:
                resolved.append(g)
        return resolved

    @staticmethod
    def _normalize_where(where: str) -> str:
        """Normalize non-standard where formats from LLM into plain SQL string.

        Handles all known LLM output patterns:
        - JSON object: '{"channel": "APP"}' → "channel = 'APP'"
        - JSON object multi: '{"a": "1", "b": "2"}' → "a = '1' AND b = '2'"
        - JSON object array val: '{"channel": ["A","B"]}' → "channel IN ('A', 'B')"
        - JSON array single: '["origin = \\'ATL\\'"]' → "origin = 'ATL'"
        - JSON array multi: '["cond1", "cond2"]' → "cond1 AND cond2"
        - Outer quotes: '"channel = \\'APP\\'"' → "channel = 'APP'"
        - Plain SQL: "channel = 'APP'" → unchanged
        - Jinja template: "{{ Dimension(...) }}" → unchanged
        """
        import json

        stripped = where.strip()
        if not stripped:
            return where

        # Already Jinja → passthrough
        if "{{" in stripped:
            return stripped

        # Try JSON parse for array or object
        try:
            data = json.loads(stripped)

            # JSON array: ["cond1", "cond2"] → "cond1 AND cond2"
            if isinstance(data, list):
                parts = []
                for item in data:
                    if isinstance(item, str):
                        parts.append(item.strip())
                    elif isinstance(item, dict):
                        # Nested object in array: [{"channel": "APP"}]
                        for k, v in item.items():
                            if isinstance(v, list):
                                quoted = ", ".join(f"'{x}'" for x in v)
                                parts.append(f"{k} IN ({quoted})")
                            elif isinstance(v, str):
                                parts.append(f"{k} = '{v}'")
                            elif isinstance(v, (int, float)):
                                parts.append(f"{k} = {v}")
                return " AND ".join(parts) if parts else where

            # JSON object: {"channel": "APP"} → "channel = 'APP'"
            if isinstance(data, dict):
                conditions = []
                for key, value in data.items():
                    if isinstance(value, list):
                        quoted = ", ".join(f"'{v}'" for v in value)
                        conditions.append(f"{key} IN ({quoted})")
                    elif isinstance(value, str):
                        conditions.append(f"{key} = '{value}'")
                    elif isinstance(value, (int, float)):
                        conditions.append(f"{key} = {value}")
                    else:
                        conditions.append(f"{key} = '{value}'")
                return " AND ".join(conditions) if conditions else where

            # JSON string (double-encoded): "\"channel = 'APP'\""
            if isinstance(data, str):
                return data.strip()

        except (json.JSONDecodeError, TypeError):
            pass

        # Strip outer quotes: '"channel = \'APP\'"' → "channel = 'APP'"
        if (stripped.startswith('"') and stripped.endswith('"')) or \
           (stripped.startswith("'") and stripped.endswith("'")):
            inner = stripped[1:-1].strip()
            if inner:
                return inner

        return stripped

    def resolve_where(self, metric_names: list[str], where: str) -> str:
        """Convert a raw SQL WHERE expression to MetricFlow Jinja template syntax.

        Uses sqlglot to parse the expression AST, finds all column references,
        and replaces them with {{ Dimension('...') }} or {{ TimeDimension('metric_time', 'grain') }}.

        Examples:
            "channel = 'APP'"
              → "{{ Dimension('order_entity__channel') }} = 'APP'"
            "order_date >= '2024-03-01'"
              → "{{ TimeDimension('metric_time', 'day') }} >= '2024-03-01'"
            "channel IN ('APP', 'Web') AND order_date >= '2024-03-01'"
              → "{{ Dimension('order_entity__channel') }} IN ('APP', 'Web') AND {{ TimeDimension('metric_time', 'day') }} >= '2024-03-01'"
        """
        # If already contains Jinja templates, return as-is
        if "{{" in where:
            return where

        # Convert JSON object to SQL: {"channel": "APP"} → "channel = 'APP'"
        # Handles: {"k": "v"}, {"k1": "v1", "k2": "v2"} (AND), {"k": ["v1","v2"]} (IN)
        where = self._normalize_where(where)

        name_map, time_dims = self._build_dimension_map(metric_names)
        if not name_map:
            return where

        try:
            import sqlglot
            from sqlglot import exp

            parsed = sqlglot.parse_one(f"SELECT * FROM t WHERE {where}", dialect="doris")
            where_clause = parsed.find(exp.Where)
            if not where_clause:
                return where

            # Find all column references and build replacement map
            # Key: bare column name (lowercase), Value: Jinja template
            col_templates: dict[str, str] = {}
            for col in where_clause.find_all(exp.Column):
                col_name = col.name.lower()

                if col_name in name_map:
                    qualified = name_map[col_name]
                    if col_name in time_dims or col_name == "metric_time":
                        # Time dimension → {{ TimeDimension('dim_name', 'grain') }}
                        # dunder_name format: metric_time__day (name__grain) or order_entity__order_date (entity__name)
                        # If last segment is a known grain, strip it to get the dimension name
                        _GRAINS = {"day", "week", "month", "quarter", "year"}
                        parts = qualified.rsplit("__", 1)
                        if len(parts) == 2 and parts[1] in _GRAINS:
                            dim_name = parts[0]  # e.g. metric_time
                            grain = parts[1]     # e.g. day
                        else:
                            dim_name = qualified  # e.g. order_entity__order_date
                            grain = "day"
                        col_templates[col_name] = "{{ TimeDimension('" + dim_name + "', '" + grain + "') }}"
                    else:
                        col_templates[col_name] = "{{ Dimension('" + qualified + "') }}"

            # Apply replacements — match both bare name and backtick-quoted name
            # Sort by length descending to avoid partial replacement
            import re
            # Mask string literals first so a literal equal to a column name
            # (e.g. channel = 'channel') is not rewritten. Handles ''/"" doubled
            # quotes and backslash escapes.
            literals: list[str] = []

            def _stash(match: "re.Match[str]") -> str:
                literals.append(match.group(0))
                return f"\x00{len(literals) - 1}\x00"

            result = _STRING_LITERAL_RE.sub(_stash, where)
            for bare_name, template in sorted(col_templates.items(), key=lambda x: -len(x[0])):
                # Match: word boundary + name + word boundary, or `name`
                pattern = re.compile(r'(?<!\w)(?:`?' + re.escape(bare_name) + r'`?)(?!\w)', re.IGNORECASE)
                result = pattern.sub(template, result)

            # Restore masked literals
            result = _MASKED_LITERAL_RE.sub(lambda m: literals[int(m.group(1))], result)
            return result
        except Exception as e:
            logger.warning(f"Failed to parse WHERE expression: {e}, passing through as-is")
            return where

    @property
    def is_engine_mode(self) -> bool:
        return self._engine_mode

    def compile(
        self,
        metrics: list[str],
        group_by: list[str] | None = None,
        where: str | None = None,
        order_by: list[str] | None = None,
        limit: int | None = None,
        having: str | None = None,
    ) -> tuple[str | None, str, str]:
        """Compile a metric query to SQL.

        When `having` is provided, MetricFlow compiles without order_by/limit,
        and the result is wrapped in an outer query:
          SELECT * FROM ({inner}) __mf WHERE {having} [ORDER BY ...] [LIMIT ...]

        Returns (sql, mf_command, error).
        """
        if having:
            having = self._normalize_having(having)
            # Compile inner SQL without order_by/limit — they apply to the outer query
            mf_command = self._build_mf_command(metrics, group_by, where, None, None)
            if self._engine_mode and self._engine is not None:
                inner_sql, mf_command, error = self._compile_via_engine(
                    metrics, group_by, where, None, None, mf_command
                )
            else:
                return None, "", "MetricFlow engine not available — check workspace health"

            if error or not inner_sql:
                return inner_sql, mf_command, error

            return self._wrap_having(inner_sql, having, order_by, limit), mf_command, ""
        else:
            mf_command = self._build_mf_command(metrics, group_by, where, order_by, limit)
            if self._engine_mode and self._engine is not None:
                return self._compile_via_engine(metrics, group_by, where, order_by, limit, mf_command)
            else:
                return None, "", "MetricFlow engine not available — check workspace health"

    @staticmethod
    def _normalize_having(having: str) -> str:
        """Normalize HAVING parameter from LLM-generated input into plain SQL.

        HAVING references outer-query metric aliases, not dimensions, so the
        rule set is a strict subset of _normalize_where: no dict→SQL shorthand,
        no Jinja passthrough. Malformed input raises ValueError with an
        LLM-actionable message rather than silently guessing.

        Steps:
        1. trim; empty → raise
        2. try json.loads:
           - str       → replace and continue
           - list[str] → " AND ".join and skip to step 4
           - anything else → raise
           - JSONDecodeError → skip to step 3
        3. strict strip of outer matching quotes (same quote at both ends AND
           that quote does not appear anywhere in the middle)
        4. reject Jinja templates ({{ ... }})
        5. re-trim and recheck emptiness
        """
        import json

        if having is None:
            raise ValueError("HAVING parameter cannot be empty.")

        s = having.strip()
        if not s:
            raise ValueError("HAVING parameter cannot be empty.")

        # Step 2: try JSON unwrap
        joined_from_list = False
        try:
            data = json.loads(s)
        except (json.JSONDecodeError, ValueError):
            data = _SENTINEL_NO_JSON
        if data is not _SENTINEL_NO_JSON:
            if isinstance(data, str):
                s = data.strip()
            elif isinstance(data, list):
                if not all(isinstance(x, str) for x in data):
                    raise ValueError(
                        f"HAVING parameter must be a SQL string or a JSON array of "
                        f"SQL strings, got list with non-string elements."
                    )
                s = " AND ".join(x.strip() for x in data if x.strip())
                joined_from_list = True
                if not s:
                    raise ValueError("HAVING parameter cannot be empty.")
            elif isinstance(data, dict):
                raise ValueError(
                    "HAVING parameter must be plain SQL comparison like "
                    "'total_flights > 10000', got dict-style input. HAVING does "
                    "not support {key: value} shorthand."
                )
            else:
                raise ValueError(
                    f"HAVING parameter must be a SQL string or a JSON array of "
                    f"SQL strings, got {type(data).__name__}."
                )

        # Step 3: strict outer-quote strip (skip for list-join path — each
        # element is already a clean SQL fragment)
        if not joined_from_list and len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'"):
            q = s[0]
            inner = s[1:-1]
            if q not in inner:
                s = inner.strip()

        # Step 4: reject Jinja
        if "{{" in s:
            raise ValueError(
                "HAVING parameter does not support Jinja templates ({{ ... }}). "
                "HAVING references outer-query metric aliases, use plain SQL "
                "like 'flight_count > 50000'."
            )

        # Step 5: re-check emptiness after unwrapping
        s = s.strip()
        if not s:
            raise ValueError("HAVING parameter cannot be empty.")

        return s

    @staticmethod
    def _wrap_having(
        inner_sql: str,
        having: str,
        order_by: list[str] | None,
        limit: int | None,
    ) -> str:
        """Wrap MetricFlow SQL in outer query with HAVING-as-WHERE."""
        logger.debug("having after normalize: %r", having)
        inner = inner_sql.rstrip().rstrip(";")
        parts = [f"SELECT * FROM ({inner}) __mf"]
        parts.append(f"WHERE {having}")
        if order_by:
            clauses = []
            for o in order_by:
                if o.startswith("-"):
                    clauses.append(f"{o[1:]} DESC")
                else:
                    clauses.append(o)
            parts.append(f"ORDER BY {', '.join(clauses)}")
        if limit is not None:
            parts.append(f"LIMIT {int(limit)}")
        return "\n".join(parts)

    def _build_mf_command(
        self,
        metrics: list[str],
        group_by: list[str] | None,
        where: str | None,
        order_by: list[str] | None,
        limit: int | None,
    ) -> str:
        """Build the equivalent mf CLI command string."""
        parts = ["mf query"]
        parts.append(f"--metrics {','.join(metrics)}")
        if group_by:
            parts.append(f"--group-by {','.join(group_by)}")
        if where:
            parts.append(f"--where \"{where}\"")
        if order_by:
            parts.append(f"--order {','.join(order_by)}")
        if limit:
            parts.append(f"--limit {limit}")
        parts.append("--explain")
        return " ".join(parts)

    @staticmethod
    def _extract_time_constraints(where: str | None) -> tuple[str | None, Any, Any]:
        """Extract metric_time range conditions from where, return as time_constraint_start/end.

        Parses patterns like:
          "metric_time >= '2026-02-01'"  → start=datetime(2026,2,1), remaining_where=None
          "metric_time >= '2026-02-01' AND metric_time <= '2026-02-28'"  → start, end, remaining=None
          "metric_time >= '2026-02-01' AND channel = 'APP'"  → start, remaining="channel = 'APP'"
          "{{ TimeDimension('metric_time', 'day') }} >= '2026-02-01'"  → same

        Returns (remaining_where, time_start, time_end).
        """
        if not where or not where.strip():
            return None, None, None

        from datetime import datetime
        import re

        time_start = None
        time_end = None

        # Match patterns: metric_time >= 'date' or "date", {{ TimeDimension(...) }} >= 'date'
        # Supports both single and double quotes around dates
        _TIME_PATTERN = re.compile(
            r"""(?:{{[^}]*TimeDimension\([^)]*\)[^}]*}}|metric_time(?:__\w+)?)\s*"""
            r"""(>=?|<=?|BETWEEN)\s*['"](\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}:\d{2})?)['"]"""
            r"""(?:\s+AND\s+['"](\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}:\d{2})?)['"])?""",
            re.IGNORECASE
        )

        def _parse_dt(s: str) -> datetime:
            for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
                try:
                    return datetime.strptime(s, fmt)
                except ValueError:
                    continue
            return datetime.strptime(s[:10], "%Y-%m-%d")

        # Collect all matches first, then remove them from the string
        matches = list(_TIME_PATTERN.finditer(where))
        if not matches:
            return where, None, None

        for match in matches:
            op = match.group(1).upper()
            date1 = match.group(2)
            date2 = match.group(3)

            if op == "BETWEEN" and date2:
                time_start = _parse_dt(date1)
                time_end = _parse_dt(date2)
            elif op in (">=", ">"):
                time_start = _parse_dt(date1)
            elif op in ("<=", "<"):
                time_end = _parse_dt(date1)

        if time_start is None and time_end is None:
            return where, None, None

        # Remove matched spans from string (reverse order to preserve positions)
        remaining = where
        for match in reversed(matches):
            remaining = remaining[:match.start()] + remaining[match.end():]

        # Robust cleanup of remaining string
        for _ in range(3):
            remaining = re.sub(r'^\s*AND\s+', '', remaining, flags=re.IGNORECASE)
            remaining = re.sub(r'\s+AND\s*$', '', remaining, flags=re.IGNORECASE)
            remaining = re.sub(r'\s+AND\s+AND\s+', ' AND ', remaining, flags=re.IGNORECASE)
        # Strip whitespace, quotes, parentheses that are now empty wrappers
        remaining = remaining.strip()
        remaining = re.sub(r'^["\'\s()]+$', '', remaining)  # Only quotes/parens/spaces → empty
        remaining = remaining.strip()
        if not remaining:
            remaining = None

        return remaining, time_start, time_end

    def _compile_via_engine(
        self,
        metrics: list[str],
        group_by: list[str] | None,
        where: str | None,
        order_by: list[str] | None,
        limit: int | None,
        mf_command: str,
    ) -> tuple[str | None, str, str]:
        """Compile using MetricFlow engine.explain() — fast path (~100ms)."""
        try:
            # Extract metric_time conditions → time_constraint_start/end
            remaining_where, time_start, time_end = self._extract_time_constraints(where)

            kwargs: dict[str, Any] = {
                "metric_names": metrics,
            }
            if group_by:
                kwargs["group_by_names"] = group_by
            if remaining_where:
                kwargs["where_constraints"] = [remaining_where]
            if order_by:
                kwargs["order_by_names"] = order_by
            if limit is not None:
                kwargs["limit"] = limit
            if time_start is not None:
                kwargs["time_constraint_start"] = time_start
            if time_end is not None:
                kwargs["time_constraint_end"] = time_end

            request = MetricFlowQueryRequest.create(**kwargs)
            explain_result: MetricFlowExplainResult = self._engine.explain(mf_request=request)
            sql = explain_result.sql_statement.sql
            return sql, mf_command, ""
        except Exception as e:
            return None, mf_command, str(e)
