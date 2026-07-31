"""Semantic layer tools: list_metrics, list_dimensions_for_metric, query_metric."""

from __future__ import annotations

import time
from typing import Any

from core.connection import ConnectionPool
from core.pagination import paginate
from core.response import ErrorCode, error_response, success_response
from core.sql_validator import validate_readonly
from store.compiler import MetricFlowCompiler
from store.manifest import SemanticManifest


async def list_metrics(
    manifest: SemanticManifest,
    page_size: int = 50,
    page_token: str | None = None,
) -> str:
    """List all available metrics."""
    try:
        metrics = manifest.list_metrics()
        page, next_token, total = paginate(metrics, page_size, page_token)
        meta: dict[str, Any] = {"total_count": total}
        if next_token:
            meta["next_page_token"] = next_token
        return success_response(page, meta)
    except Exception as e:
        return error_response(ErrorCode.INTERNAL_ERROR, str(e))


async def list_dimensions_for_metric(
    manifest: SemanticManifest,
    metric_name: str,
) -> str:
    """List dimensions available for a specific metric."""
    try:
        metric = manifest.get_metric(metric_name)
        if not metric:
            return error_response(ErrorCode.METRIC_NOT_FOUND, f"Metric '{metric_name}' not found")
        dims = manifest.list_dimensions_for_metric(metric_name)
        return success_response(dims, {"metric": metric_name, "count": len(dims)})
    except Exception as e:
        return error_response(ErrorCode.INTERNAL_ERROR, str(e))


async def query_metric(
    compiler: MetricFlowCompiler,
    pool: ConnectionPool,
    metrics: list[str],
    group_by: list[str] | None = None,
    where: str | None = None,
    order_by: list[str] | None = None,
    limit: int | None = None,
    database: str | None = None,
    max_rows: int | None = None,
    having: str | None = None,
) -> str:
    """Compile a metric query via MetricFlow, then execute the SQL."""
    try:
        # Step 1: Compile
        sql, mf_command, error = compiler.compile(metrics, group_by, where, order_by, limit, having)
        if error:
            # Enhance dimension incompatibility errors with guidance
            if "does not match any" in error and "group-by" in error:
                return error_response(
                    ErrorCode.VALIDATION_ERROR,
                    f"Dimension incompatible with metric(s) {metrics}. "
                    f"This dimension may work with other metrics. "
                    f"Call list_dimensions_for_metric('{metrics[0]}') to see valid dimensions. "
                    f"Original error: {error[:200]}"
                )
            return error_response(ErrorCode.INTERNAL_ERROR, f"MetricFlow compile error: {error}")
        if not sql:
            return error_response(ErrorCode.INTERNAL_ERROR, "MetricFlow returned empty SQL")

        # Step 2: Validate read-only — where/having are user-controlled and can
        # inject arbitrary SQL into the generated statement, so enforce the same
        # read-only policy as execute_query before executing.
        is_valid, err_msg = validate_readonly(sql)
        if not is_valid:
            return error_response(ErrorCode.INVALID_SQL, err_msg)

        # Step 3: Execute via our connection pool
        start = time.monotonic()
        rows, columns = await pool.execute(sql, database=database, max_rows=max_rows)
        duration_ms = (time.monotonic() - start) * 1000

        # Step 4: Post-process — replace null with 0 for metric columns
        # MetricFlow FULL OUTER JOIN can produce null for count/sum metrics
        metric_cols = set(m.replace("-", "_") for m in metrics)
        for row in rows:
            for key, value in row.items():
                if value is None and key in metric_cols:
                    row[key] = 0

        return success_response(
            {"columns": columns, "rows": rows},
            {"duration_ms": round(duration_ms, 2), "row_count": len(rows)},
        )
    except TimeoutError:
        return error_response(ErrorCode.QUERY_TIMEOUT, "MetricFlow query timed out")
    except ValueError as e:
        return error_response(ErrorCode.INVALID_PARAMS, str(e))
    except Exception as e:
        return error_response(ErrorCode.CONNECTION_ERROR, str(e))


