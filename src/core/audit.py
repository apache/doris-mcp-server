"""Audit logging for all tool invocations."""

from __future__ import annotations

import json
import logging
import time
from logging.handlers import TimedRotatingFileHandler
from typing import Any

from core.sensitive_mask import mask_sensitive

_logger = logging.getLogger("doris_new_mcp.audit")

_initialized = False


def init_audit_log(
    path: str,
    when: str = "midnight",
    backup_count: int = 30,
) -> None:
    global _initialized
    if _initialized:
        return
    handler = TimedRotatingFileHandler(
        path, when=when, backupCount=backup_count, encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    _logger.setLevel(logging.INFO)
    _logger.addHandler(handler)
    _logger.propagate = False
    _initialized = True


def log_tool_call(
    tool_name: str,
    client_id: str | None = None,
    params: dict[str, Any] | None = None,
    success: bool = True,
    duration_ms: float = 0,
    error: str | None = None,
    metricflow: bool = False,
    mf_command: str | None = None,
) -> None:
    """Write a structured audit log entry.

    Args:
        client_id: Caller identity (static token ``name`` or JWT ``sub``).
            Not sensitive — recorded as-is without masking.
        metricflow: Whether this request was executed via MetricFlow.
        mf_command: The MetricFlow command used (e.g. "mf query --metrics revenue --dimensions metric_time__day").
    """
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "tool": tool_name,
        "client_id": client_id,
        "params": {k: mask_sensitive(str(v)) for k, v in params.items()} if params else {},
        "success": success,
        "duration_ms": round(duration_ms, 2),
        "query_path": "metricflow" if metricflow else "direct",
    }
    if metricflow and mf_command:
        entry["mf_command"] = mask_sensitive(mf_command)
    if error:
        entry["error"] = mask_sensitive(error)
    _logger.info(json.dumps(entry, ensure_ascii=False))
