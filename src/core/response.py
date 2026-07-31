"""Unified response format for all MCP tools."""

from __future__ import annotations

import json
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from typing import Any


class ErrorCode(str, Enum):
    READONLY_VIOLATION = "READONLY_VIOLATION"
    UNAUTHENTICATED = "UNAUTHENTICATED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    INVALID_SQL = "INVALID_SQL"
    QUERY_TIMEOUT = "QUERY_TIMEOUT"
    CONNECTION_ERROR = "CONNECTION_ERROR"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    INVALID_PARAMS = "INVALID_PARAMS"
    METRIC_NOT_FOUND = "METRIC_NOT_FOUND"
    SERVICE_NOT_READY = "SERVICE_NOT_READY"
    SEMANTIC_DISABLED = "SEMANTIC_DISABLED"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class _Encoder(json.JSONEncoder):
    """JSON encoder handling Doris data types."""

    def default(self, o: Any) -> Any:
        if isinstance(o, Decimal):
            return float(o)
        if isinstance(o, datetime):
            return o.isoformat()
        if isinstance(o, date):
            return o.isoformat()
        if isinstance(o, bytes):
            return o.decode("utf-8", errors="replace")
        return super().default(o)


def success_response(
    data: Any,
    meta: dict[str, Any] | None = None,
) -> str:
    """Build a success response JSON string."""
    resp: dict[str, Any] = {"success": True, "data": data}
    if meta:
        resp["meta"] = meta
    return json.dumps(resp, cls=_Encoder, ensure_ascii=False)


def error_response(
    code: ErrorCode,
    message: str,
    details: dict[str, Any] | None = None,
) -> str:
    """Build an error response JSON string."""
    err: dict[str, Any] = {"code": code.value, "message": message}
    if details:
        err["details"] = details
    return json.dumps({"success": False, "error": err}, cls=_Encoder, ensure_ascii=False)
