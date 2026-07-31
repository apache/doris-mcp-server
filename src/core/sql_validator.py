"""SQL validation using sqlglot AST parsing for Doris dialect."""

from __future__ import annotations

import sqlglot
from sqlglot import exp

# Statement types allowed for execute_query (read-only)
_READONLY_TYPES = (
    exp.Select,
    exp.Union,
)

# Doris SHOW/DESCRIBE/EXPLAIN are parsed as Command by sqlglot
_READONLY_COMMAND_PREFIXES = (
    "SHOW",
    "DESCRIBE",
    "DESC",
    "EXPLAIN",
)


def validate_readonly(sql: str) -> tuple[bool, str]:
    """Validate that SQL is read-only (for execute_query).

    Returns (is_valid, error_message).
    """
    stripped = sql.strip().rstrip(";").strip()
    if not stripped:
        return False, "Empty SQL statement"

    # Check for multiple statements (stacked queries)
    try:
        statements = sqlglot.parse(stripped, dialect="doris")
    except sqlglot.errors.ParseError as e:
        # If sqlglot can't parse, fall back to prefix check for SHOW/DESC/EXPLAIN
        upper = stripped.upper().lstrip()
        for prefix in _READONLY_COMMAND_PREFIXES:
            if upper.startswith(prefix):
                return True, ""
        return False, f"SQL parse error: {e}"

    if len(statements) > 1:
        return False, "Multiple statements not allowed"

    if not statements or statements[0] is None:
        # sqlglot returned empty — try prefix-based check
        upper = stripped.upper().lstrip()
        for prefix in _READONLY_COMMAND_PREFIXES:
            if upper.startswith(prefix):
                return True, ""
        return False, "Unable to parse SQL statement"

    node = statements[0]

    # SELECT statements are allowed
    if isinstance(node, _READONLY_TYPES):
        return True, ""

    # Command nodes: SHOW, DESCRIBE, EXPLAIN etc.
    if isinstance(node, exp.Command):
        cmd = node.this
        if isinstance(cmd, str):
            upper_cmd = cmd.upper()
            for prefix in _READONLY_COMMAND_PREFIXES:
                if upper_cmd.startswith(prefix) or upper_cmd == prefix:
                    return True, ""

    # Also check raw text for SHOW/DESCRIBE/EXPLAIN that sqlglot may parse differently
    upper = stripped.upper().lstrip()
    for prefix in _READONLY_COMMAND_PREFIXES:
        if upper.startswith(prefix):
            return True, ""

    stmt_type = type(node).__name__
    return False, f"Statement type '{stmt_type}' not allowed in read-only mode"
