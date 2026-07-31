"""Discovery tools: list_databases, list_tables, describe_table."""

from __future__ import annotations

from typing import Any

from core.connection import ConnectionPool
from core.pagination import paginate
from core.response import ErrorCode, error_response, success_response


async def list_databases(
    pool: ConnectionPool,
    page_size: int = 50,
    page_token: str | None = None,
    db_whitelist: list[str] | None = None,
) -> str:
    """List all databases."""
    try:
        rows, _ = await pool.execute("SHOW DATABASES")
        databases = [r.get("Database") or r.get("database") or list(r.values())[0] for r in rows]

        # Filter internal databases
        databases = [d for d in databases if d and not d.startswith("__")]

        # Apply whitelist
        if db_whitelist:
            databases = [d for d in databases if d in db_whitelist]

        databases.sort()
        page, next_token, total = paginate(databases, page_size, page_token)
        meta: dict[str, Any] = {"total_count": total}
        if next_token:
            meta["next_page_token"] = next_token
        return success_response(page, meta)
    except Exception as e:
        return error_response(ErrorCode.CONNECTION_ERROR, str(e))


async def list_tables(
    pool: ConnectionPool,
    database: str,
    like: str | None = None,
    page_size: int = 50,
    page_token: str | None = None,
) -> str:
    """List table names in a database. Use describe_table for column detail."""
    try:
        sql = "SHOW TABLES"
        if like:
            sql += f" LIKE '{like}'"
        rows, _ = await pool.execute(sql, database=database)
        table_names = [list(r.values())[0] for r in rows]
        table_names.sort()

        page, next_token, total = paginate(table_names, page_size, page_token)
        meta: dict[str, Any] = {"total_count": total, "database": database}
        if next_token:
            meta["next_page_token"] = next_token
        return success_response(page, meta)
    except Exception as e:
        return error_response(ErrorCode.CONNECTION_ERROR, str(e))


async def describe_table(
    pool: ConnectionPool,
    database: str,
    table: str,
    detail_level: str = "summary",
) -> str:
    """Describe a table's structure."""
    try:
        # Basic columns
        rows, _ = await pool.execute(f"DESCRIBE `{table}`", database=database)
        columns = []
        for r in rows:
            col: dict[str, Any] = {
                "name": r.get("Field", ""),
                "type": r.get("Type", ""),
            }
            if detail_level in ("summary", "full"):
                col["null"] = r.get("Null", "")
                col["key"] = r.get("Key", "")
                col["default"] = r.get("Default")
                col["extra"] = r.get("Extra", "")
            columns.append(col)

        result: dict[str, Any] = {
            "database": database,
            "table": table,
            "columns": columns,
        }

        if detail_level == "full":
            # Get CREATE TABLE for partitions, distribution, properties
            try:
                ct_rows, _ = await pool.execute(
                    f"SHOW CREATE TABLE `{table}`", database=database
                )
                if ct_rows:
                    create_sql = list(ct_rows[0].values())[-1] if ct_rows[0] else ""
                    result["create_table"] = create_sql
            except Exception:
                result["create_table"] = None

            # Get partition info
            try:
                part_rows, _ = await pool.execute(
                    f"SHOW PARTITIONS FROM `{table}`", database=database
                )
                result["partitions"] = part_rows
            except Exception:
                result["partitions"] = []

        meta = {"database": database, "table": table}
        return success_response(result, meta)
    except Exception as e:
        return error_response(ErrorCode.CONNECTION_ERROR, str(e))
