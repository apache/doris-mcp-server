"""Query tools: execute_query."""

from __future__ import annotations

import time

from core.connection import ConnectionPool
from core.response import ErrorCode, error_response, success_response
from core.sql_validator import validate_readonly


async def execute_query(
    pool: ConnectionPool,
    sql: str,
    database: str | None = None,
    max_rows: int | None = None,
) -> str:
    """Execute a read-only SQL query."""
    # Validate read-only
    is_valid, err_msg = validate_readonly(sql)
    if not is_valid:
        return error_response(ErrorCode.INVALID_SQL, err_msg)

    try:
        start = time.monotonic()
        rows, columns = await pool.execute(sql, database=database, max_rows=max_rows)
        duration_ms = (time.monotonic() - start) * 1000

        return success_response(
            {"columns": columns, "rows": rows},
            {
                "duration_ms": round(duration_ms, 2),
                "row_count": len(rows),
                "database": database,
            },
        )
    except TimeoutError:
        return error_response(ErrorCode.QUERY_TIMEOUT, "Query timed out")
    except Exception as e:
        return error_response(ErrorCode.CONNECTION_ERROR, str(e))
