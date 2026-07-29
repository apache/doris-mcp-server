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
"""Liveness and readiness response helpers."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any, Protocol

DEFAULT_READINESS_TIMEOUT_SECONDS = 2.0


class ReadinessProbe(Protocol):
    """Minimal dependency contract used by the HTTP readiness endpoint."""

    async def check_readiness(self, *, timeout_seconds: float) -> bool: ...


def liveness_payload(
    *,
    service: str,
    version: str,
    legacy: bool = False,
    details: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a database-independent liveness payload."""
    payload: dict[str, Any] = {
        "status": "healthy" if legacy else "alive",
        "service": service,
        "version": version,
        "checks": {"process": "alive"},
    }
    if details:
        payload.update(details)
    return payload


async def readiness_payload(
    connection_manager: ReadinessProbe | None,
    *,
    service: str,
    version: str,
    initialized: bool = True,
    details: Mapping[str, Any] | None = None,
    timeout_seconds: float = DEFAULT_READINESS_TIMEOUT_SECONDS,
) -> tuple[dict[str, Any], int]:
    """Build a bounded readiness payload and its HTTP status code."""
    doris_ready = False
    if initialized and connection_manager is not None:
        try:
            doris_ready = bool(
                await asyncio.wait_for(
                    connection_manager.check_readiness(
                        timeout_seconds=timeout_seconds,
                    ),
                    timeout=timeout_seconds,
                )
            )
        except Exception:
            doris_ready = False

    ready = initialized and doris_ready
    payload: dict[str, Any] = {
        "status": "ready" if ready else "not_ready",
        "service": service,
        "version": version,
        "checks": {
            "service": "ready" if initialized else "not_ready",
            "doris": "ready" if doris_ready else "not_ready",
        },
        "timeout_seconds": timeout_seconds,
    }
    if details:
        payload.update(details)
    return payload, 200 if ready else 503
