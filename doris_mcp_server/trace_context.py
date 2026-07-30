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
"""Safe W3C trace-context handling for MCP request ``_meta``."""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from dataclasses import replace
from typing import Any, cast
from urllib.parse import unquote_plus

from mcp.server import ServerRequestContext
from mcp.server.context import CallNext, HandlerResult
from mcp.types import RequestParamsMeta
from opentelemetry.trace import get_current_span
from opentelemetry.trace.propagation.tracecontext import (
    TraceContextTextMapPropagator,
)

from .utils.redaction import REDACTED, is_sensitive_key

TRACEPARENT_META_KEY = "traceparent"
TRACESTATE_META_KEY = "tracestate"
BAGGAGE_META_KEY = "baggage"

_TRACEPARENT_MAX_LENGTH = 512
_TRACESTATE_MAX_LENGTH = 512
_TRACESTATE_MAX_MEMBERS = 32
_BAGGAGE_MAX_LENGTH = 8192
_BAGGAGE_MAX_MEMBER_LENGTH = 4096
_BAGGAGE_MAX_MEMBERS = 180

# W3C Trace Context section 3.3.1.3. The expression intentionally mirrors
# the specification's ASCII bounds rather than accepting arbitrary Unicode.
_TRACESTATE_MEMBER_RE = re.compile(
    r"(?P<key>"
    r"[a-z][_0-9a-z\-*/]{0,255}"
    r"|[a-z0-9][_0-9a-z\-*/]{0,240}@[a-z][_0-9a-z\-*/]{0,13}"
    r")="
    r"[\x20-\x2b\x2d-\x3c\x3e-\x7e]{0,255}"
    r"[\x21-\x2b\x2d-\x3c\x3e-\x7e]"
    r"[ \t]*"
)
_LIST_DELIMITER_RE = re.compile(r"[ \t]*,[ \t]*")

# W3C Baggage section 3.2.1. The value expression includes optional
# semicolon-delimited properties and remains aligned with the OTel W3C
# propagator's accepted wire surface.
_BAGGAGE_KEY_RE = re.compile(
    r"[\x21\x23-\x27\x2a\x2b\x2d\x2e"
    r"\x30-\x39\x41-\x5a\x5e-\x7a\x7c\x7e]+"
)
_BAGGAGE_VALUE_RE = re.compile(
    r"[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*"
)
_BAGGAGE_PROPERTY_RE = re.compile(
    r"[ \t]*"
    r"[\x21\x23-\x27\x2a\x2b\x2d\x2e"
    r"\x30-\x39\x41-\x5a\x5e-\x7a\x7c\x7e]+"
    r"(?:[ \t]*=[ \t]*"
    r"[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*)?"
    r"[ \t]*"
)
_TRACEPARENT_PROPAGATOR = TraceContextTextMapPropagator()


def _valid_traceparent(value: object) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _TRACEPARENT_MAX_LENGTH
    ):
        return False
    context = _TRACEPARENT_PROPAGATOR.extract(
        {TRACEPARENT_META_KEY: value}
    )
    return get_current_span(context).get_span_context().is_valid


def _valid_tracestate(value: object) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _TRACESTATE_MAX_LENGTH
    ):
        return False
    members = _LIST_DELIMITER_RE.split(value)
    if len(members) > _TRACESTATE_MAX_MEMBERS:
        return False
    keys: set[str] = set()
    for member in members:
        match = _TRACESTATE_MEMBER_RE.fullmatch(member)
        if match is None or match.group("key") in keys:
            return False
        keys.add(match.group("key"))
    return True


def _sanitize_baggage(value: object) -> str | None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _BAGGAGE_MAX_LENGTH
    ):
        return None
    members = _LIST_DELIMITER_RE.split(value)
    if len(members) > _BAGGAGE_MAX_MEMBERS:
        return None
    sanitized_members: list[str] = []
    decoded_keys: set[str] = set()
    for member in members:
        if not member or len(member) > _BAGGAGE_MAX_MEMBER_LENGTH:
            return None
        try:
            key, raw_value = member.split("=", 1)
        except ValueError:
            return None
        if _BAGGAGE_KEY_RE.fullmatch(key) is None:
            return None
        decoded_key = unquote_plus(key).strip()
        if decoded_key in decoded_keys:
            return None
        decoded_keys.add(decoded_key)
        value_and_properties = raw_value.split(";")
        if _BAGGAGE_VALUE_RE.fullmatch(value_and_properties[0]) is None:
            return None
        if any(
            _BAGGAGE_PROPERTY_RE.fullmatch(item) is None
            for item in value_and_properties[1:]
        ):
            return None
        if is_sensitive_key(decoded_key):
            sanitized_members.append(f"{key}={REDACTED}")
            continue

        sanitized_properties: list[str] = []
        for item in value_and_properties[1:]:
            if "=" not in item:
                sanitized_properties.append(item)
                continue
            property_key, _property_value = item.split("=", 1)
            if is_sensitive_key(unquote_plus(property_key).strip()):
                sanitized_properties.append(
                    f"{property_key.rstrip()}={REDACTED}"
                )
            else:
                sanitized_properties.append(item)
        sanitized_members.append(
            ";".join(
                [
                    f"{key}={value_and_properties[0]}",
                    *sanitized_properties,
                ]
            )
        )
    return ",".join(sanitized_members)


def sanitize_trace_meta(
    meta: Mapping[str, Any] | None,
    *,
    logger: logging.Logger,
) -> RequestParamsMeta | None:
    """Drop malformed trace fields without logging their untrusted values."""
    if meta is None:
        return None

    sanitized = dict(meta)
    traceparent_valid = (
        TRACEPARENT_META_KEY not in sanitized
        or _valid_traceparent(sanitized[TRACEPARENT_META_KEY])
    )
    if not traceparent_valid:
        sanitized.pop(TRACEPARENT_META_KEY, None)
        logger.warning(
            "Ignoring invalid MCP trace metadata field %s",
            TRACEPARENT_META_KEY,
        )

    if TRACESTATE_META_KEY in sanitized:
        tracestate_valid = (
            traceparent_valid
            and TRACEPARENT_META_KEY in sanitized
            and _valid_tracestate(sanitized[TRACESTATE_META_KEY])
        )
        if not tracestate_valid:
            sanitized.pop(TRACESTATE_META_KEY, None)
            logger.warning(
                "Ignoring invalid MCP trace metadata field %s",
                TRACESTATE_META_KEY,
            )

    if BAGGAGE_META_KEY in sanitized:
        sanitized_baggage = _sanitize_baggage(sanitized[BAGGAGE_META_KEY])
        if sanitized_baggage is None:
            sanitized.pop(BAGGAGE_META_KEY, None)
            logger.warning(
                "Ignoring invalid MCP trace metadata field %s",
                BAGGAGE_META_KEY,
            )
        else:
            sanitized[BAGGAGE_META_KEY] = sanitized_baggage

    return cast(RequestParamsMeta, sanitized)


class TraceContextSanitizingMiddleware:
    """Sanitize trace carrier fields before the SDK OTel middleware runs."""

    def __init__(self, logger: logging.Logger) -> None:
        self._logger = logger

    async def __call__(
        self,
        ctx: ServerRequestContext[Any, Any],
        call_next: CallNext,
    ) -> HandlerResult:
        sanitized_meta = sanitize_trace_meta(ctx.meta, logger=self._logger)
        if sanitized_meta == ctx.meta:
            return await call_next(ctx)

        sanitized_params = ctx.params
        if ctx.params is not None and "_meta" in ctx.params:
            sanitized_params = dict(ctx.params)
            sanitized_params["_meta"] = sanitized_meta or {}
        return await call_next(
            replace(
                ctx,
                meta=sanitized_meta,
                params=sanitized_params,
            )
        )
