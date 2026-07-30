# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""Central query-result and execution limits.

Configuration limits are deployment ceilings.  Tool arguments may request a
smaller budget, but cannot raise those ceilings.  Absolute constants remain a
last line of defence if configuration objects are constructed without running
``DorisConfig.validate()``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

ABSOLUTE_MAX_RESULT_ROWS = 100_000
ABSOLUTE_MAX_RESULT_BYTES = 16 * 1024 * 1024
ABSOLUTE_MAX_QUERY_TIMEOUT_SECONDS = 300
MIN_RESULT_BYTES = 256

DEFAULT_MAX_RESULT_ROWS = 10_000
DEFAULT_RESULT_ROWS = 100
DEFAULT_MAX_RESULT_BYTES = 1024 * 1024
DEFAULT_QUERY_TIMEOUT_SECONDS = 300


class ResultLimitError(ValueError):
    """Raised when a caller asks for an invalid or excessive result budget."""


@dataclass(frozen=True)
class ResultLimits:
    """Effective per-call query result and execution budgets."""

    max_rows: int
    max_bytes: int
    timeout_seconds: int


def _configured_positive_int(
    value: object,
    *,
    default: int,
    hard_maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return default
    return min(value, hard_maximum)


def configured_result_limits(config: object | None) -> ResultLimits:
    """Read bounded deployment ceilings from a Doris configuration object."""
    security = getattr(config, "security", None)
    performance = getattr(config, "performance", None)
    return ResultLimits(
        max_rows=_configured_positive_int(
            getattr(security, "max_result_rows", None),
            default=DEFAULT_MAX_RESULT_ROWS,
            hard_maximum=ABSOLUTE_MAX_RESULT_ROWS,
        ),
        max_bytes=_configured_positive_int(
            getattr(performance, "max_result_bytes", None),
            default=DEFAULT_MAX_RESULT_BYTES,
            hard_maximum=ABSOLUTE_MAX_RESULT_BYTES,
        ),
        timeout_seconds=_configured_positive_int(
            getattr(performance, "query_timeout", None),
            default=DEFAULT_QUERY_TIMEOUT_SECONDS,
            hard_maximum=ABSOLUTE_MAX_QUERY_TIMEOUT_SECONDS,
        ),
    )


def configured_default_result_rows(config: object | None) -> int:
    """Return the configured default row budget bounded by the deployment ceiling."""
    ceilings = configured_result_limits(config)
    performance = getattr(config, "performance", None)
    return _configured_positive_int(
        getattr(performance, "default_result_rows", None),
        default=min(DEFAULT_RESULT_ROWS, ceilings.max_rows),
        hard_maximum=ceilings.max_rows,
    )


def _requested_limit(
    value: object | None,
    *,
    name: str,
    configured_maximum: int,
    minimum: int = 1,
) -> int:
    if value is None:
        return configured_maximum
    if isinstance(value, bool) or not isinstance(value, int):
        raise ResultLimitError(f"{name} must be an integer")
    if value < minimum:
        raise ResultLimitError(f"{name} must be at least {minimum}")
    if value > configured_maximum:
        raise ResultLimitError(
            f"{name} exceeds the configured maximum of {configured_maximum}"
        )
    return value


def resolve_result_limits(
    config: object | None,
    *,
    max_rows: object | None,
    max_bytes: object | None,
    timeout_seconds: object | None,
) -> ResultLimits:
    """Resolve request budgets without allowing configuration escalation."""
    ceilings = configured_result_limits(config)
    return ResultLimits(
        max_rows=_requested_limit(
            max_rows,
            name="max_rows",
            configured_maximum=ceilings.max_rows,
        ),
        max_bytes=_requested_limit(
            max_bytes,
            name="max_bytes",
            configured_maximum=ceilings.max_bytes,
            minimum=MIN_RESULT_BYTES,
        ),
        timeout_seconds=_requested_limit(
            timeout_seconds,
            name="timeout",
            configured_maximum=ceilings.timeout_seconds,
        ),
    )


def json_array_row_size(row: dict[str, Any], *, first: bool) -> int:
    """Return a conservative UTF-8 JSON contribution for one result row.

    ``ensure_ascii=True`` intentionally counts escaped non-ASCII data, which is
    never smaller than the UTF-8 representation emitted by the MCP stack.
    Array brackets are accounted for separately by the caller.
    """
    encoded = json.dumps(
        row,
        ensure_ascii=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return len(encoded) + (0 if first else 1)
