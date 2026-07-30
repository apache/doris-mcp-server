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
"""OpenTelemetry request ``_meta`` propagation and redaction tests."""

from __future__ import annotations

import json
import logging
import secrets
import sys
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import httpx2
import mcp.shared._otel as mcp_otel
import pytest
from mcp import Client, StdioServerParameters
from mcp.client.stdio import stdio_client
from opentelemetry.baggage import get_all
from opentelemetry.trace import (
    NonRecordingSpan,
    SpanContext,
    TraceFlags,
    get_current_span,
    use_span,
)

from doris_mcp_server.protocol import create_transport_security
from doris_mcp_server.trace_context import sanitize_trace_meta
from test.protocol.test_mcp_v2_protocol import (
    create_test_server,
    modern_tool_headers,
    modern_tool_request,
)

_TRACE_ID = "0af7651916cd43dd8448eb211c80319c"
_PARENT_SPAN_ID = "00f067aa0ba902b7"


class _CapturingTracer:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []

    @contextmanager
    def start_as_current_span(
        self,
        name: str,
        *,
        context: Any = None,
        attributes: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Generator[NonRecordingSpan]:
        del attributes, kwargs
        parent = get_current_span(context).get_span_context()
        trace_id = parent.trace_id if parent.is_valid else secrets.randbits(128) or 1
        child_context = SpanContext(
            trace_id=trace_id,
            span_id=secrets.randbits(64) or 1,
            is_remote=False,
            trace_flags=parent.trace_flags if parent.is_valid else TraceFlags(0),
            trace_state=parent.trace_state if parent.is_valid else None,
        )
        baggage = get_all(context=context)
        self.records.append(
            {
                "name": name,
                "parentTraceId": (
                    f"{parent.trace_id:032x}" if parent.is_valid else None
                ),
                "parentSpanId": (
                    f"{parent.span_id:016x}" if parent.is_valid else None
                ),
                "baggageCount": len(baggage),
                "redactedBaggageCount": sum(
                    value == "[REDACTED]" for value in baggage.values()
                ),
            }
        )
        span = NonRecordingSpan(child_context)
        with use_span(span, end_on_exit=False):
            yield span


def _trace_meta(*, baggage: str, tracestate: str = "vendor=opaque") -> dict:
    return {
        "traceparent": f"00-{_TRACE_ID}-{_PARENT_SPAN_ID}-01",
        "tracestate": tracestate,
        "baggage": baggage,
    }


@pytest.mark.parametrize(
    ("meta", "remaining_trace_keys"),
    [
        (
            {
                "traceparent": "not-a-traceparent",
                "tracestate": "vendor=opaque",
                "baggage": "tenant=blue",
            },
            {"baggage"},
        ),
        ({"tracestate": "vendor=opaque"}, set()),
        (
            {
                "traceparent": (
                    f"00-{_TRACE_ID}-{_PARENT_SPAN_ID}-01"
                ),
                "tracestate": "vendor=one,vendor=two",
            },
            {"traceparent"},
        ),
        (
            {
                "traceparent": (
                    f"00-{_TRACE_ID}-{_PARENT_SPAN_ID}-01"
                ),
                "baggage": "missing-value",
            },
            {"traceparent"},
        ),
        (
            {
                "traceparent": (
                    f"00-{_TRACE_ID}-{_PARENT_SPAN_ID}-01"
                ),
                "baggage": "key=" + "x" * 8193,
            },
            {"traceparent"},
        ),
    ],
)
def test_trace_meta_sanitizer_drops_only_invalid_carrier_fields(
    meta: dict[str, Any],
    remaining_trace_keys: set[str],
    caplog: pytest.LogCaptureFixture,
):
    secret = "sanitizer-must-not-log-values"
    supplied = {**meta, "custom": secret}
    logger = logging.getLogger("test.trace-context-sanitizer")
    caplog.set_level(logging.WARNING)

    sanitized = sanitize_trace_meta(supplied, logger=logger)

    assert sanitized is not None
    assert sanitized["custom"] == secret
    assert (
        {"traceparent", "tracestate", "baggage"} & set(sanitized)
        == remaining_trace_keys
    )
    assert secret not in caplog.text


def test_trace_meta_sanitizer_redacts_sensitive_baggage_values():
    logger = logging.getLogger("test.trace-context-sanitizer")

    sanitized = sanitize_trace_meta(
        {
            "baggage": (
                "tenant=blue,secret=must-not-propagate,"
                "token%2Dsecret=also-private,"
                "region=west;authorization=private;readonly"
            )
        },
        logger=logger,
    )

    assert sanitized is not None
    assert sanitized["baggage"] == (
        "tenant=blue,secret=[REDACTED],token%2Dsecret=[REDACTED],"
        "region=west;authorization=[REDACTED];readonly"
    )


@pytest.mark.asyncio
async def test_http_propagates_trace_context_without_model_or_log_leakage(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    tracer = _CapturingTracer()
    monkeypatch.setattr(mcp_otel, "_tracer", tracer)
    app = create_test_server().streamable_http_app(
        json_response=True,
        stateless_http=True,
        host="127.0.0.1",
        transport_security=create_transport_security("127.0.0.1"),
    )
    valid_secret = "http-valid-baggage-secret"
    invalid_secret = "http-invalid-baggage-secret"
    caplog.set_level(logging.WARNING)

    async with (
        app.router.lifespan_context(app),
        httpx2.ASGITransport(app) as transport,
        httpx2.AsyncClient(
            transport=transport,
            base_url="http://127.0.0.1:3000",
        ) as client,
    ):
        traced_request = modern_tool_request(1, "echo", {"value": "safe"})
        traced_request["params"]["_meta"].update(
            _trace_meta(baggage=f"tenant=blue,secret={valid_secret}")
        )
        traced = await client.post(
            "/mcp",
            json=traced_request,
            headers=modern_tool_headers("echo"),
        )
        assert traced.status_code == 200
        assert traced.json()["result"]["structuredContent"] == {
            "name": "echo",
            "arguments": {"value": "safe"},
        }
        assert _TRACE_ID not in traced.text
        assert valid_secret not in traced.text

        sanitized_request = modern_tool_request(2, "echo", {"value": "safe"})
        sanitized_request["params"]["_meta"].update(
            _trace_meta(
                baggage=f"secret={invalid_secret},missing-value",
                tracestate=f"vendor=opaque,{invalid_secret}",
            )
        )
        sanitized = await client.post(
            "/mcp",
            json=sanitized_request,
            headers=modern_tool_headers("echo"),
        )
        assert sanitized.status_code == 200
        assert invalid_secret not in sanitized.text

        untraced = await client.post(
            "/mcp",
            json=modern_tool_request(3, "echo", {"value": "safe"}),
            headers=modern_tool_headers("echo"),
        )
        assert untraced.status_code == 200

    tool_records = [
        record
        for record in tracer.records
        if record["name"] == "tools/call echo"
    ]
    assert tool_records == [
        {
            "name": "tools/call echo",
            "parentTraceId": _TRACE_ID,
            "parentSpanId": _PARENT_SPAN_ID,
            "baggageCount": 2,
            "redactedBaggageCount": 1,
        },
        {
            "name": "tools/call echo",
            "parentTraceId": _TRACE_ID,
            "parentSpanId": _PARENT_SPAN_ID,
            "baggageCount": 0,
            "redactedBaggageCount": 0,
        },
        {
            "name": "tools/call echo",
            "parentTraceId": None,
            "parentSpanId": None,
            "baggageCount": 0,
            "redactedBaggageCount": 0,
        },
    ]
    log_text = caplog.text
    assert "Ignoring invalid MCP trace metadata field tracestate" in log_text
    assert "Ignoring invalid MCP trace metadata field baggage" in log_text
    assert valid_secret not in log_text
    assert invalid_secret not in log_text


@pytest.mark.asyncio
async def test_true_subprocess_stdio_propagates_and_sanitizes_trace_meta(
    tmp_path: Path,
):
    server_script = Path(__file__).with_name("trace_context_server.py")
    observations = tmp_path / "trace-observations.jsonl"
    log_path = tmp_path / "trace-context.log"
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[str(server_script)],
        env={
            "DORIS_MCP_TRACE_OBSERVATIONS": str(observations),
            "DORIS_MCP_TRACE_LOG": str(log_path),
        },
    )
    valid_secret = "stdio-valid-baggage-secret"
    invalid_secret = "stdio-invalid-baggage-secret"

    async with Client(stdio_client(server_params)) as client:
        traced = await client.call_tool(
            "echo",
            {},
            meta=_trace_meta(
                baggage=f"tenant=blue,secret={valid_secret}"
            ),
        )
        assert traced.structured_content == {"ok": True}
        traced_wire = json.dumps(
            traced.model_dump(by_alias=True, mode="json"),
            sort_keys=True,
        )
        assert _TRACE_ID not in traced_wire
        assert valid_secret not in traced_wire

        sanitized = await client.call_tool(
            "echo",
            {},
            meta=_trace_meta(
                baggage=f"secret={invalid_secret},missing-value",
                tracestate=f"vendor=opaque,{invalid_secret}",
            ),
        )
        assert sanitized.structured_content == {"ok": True}

        untraced = await client.call_tool("echo", {})
        assert untraced.structured_content == {"ok": True}

    records = [
        json.loads(line)
        for line in observations.read_text(encoding="utf-8").splitlines()
    ]
    tool_records = [
        record for record in records if record["name"] == "tools/call echo"
    ]
    assert tool_records == [
        {
            "name": "tools/call echo",
            "parentTraceId": _TRACE_ID,
            "parentSpanId": _PARENT_SPAN_ID,
            "baggageCount": 2,
            "redactedBaggageCount": 1,
        },
        {
            "name": "tools/call echo",
            "parentTraceId": _TRACE_ID,
            "parentSpanId": _PARENT_SPAN_ID,
            "baggageCount": 0,
            "redactedBaggageCount": 0,
        },
        {
            "name": "tools/call echo",
            "parentTraceId": None,
            "parentSpanId": None,
            "baggageCount": 0,
            "redactedBaggageCount": 0,
        },
    ]
    observed_text = observations.read_text(encoding="utf-8")
    log_text = log_path.read_text(encoding="utf-8")
    assert valid_secret not in observed_text
    assert invalid_secret not in observed_text
    assert "Ignoring invalid MCP trace metadata field tracestate" in log_text
    assert "Ignoring invalid MCP trace metadata field baggage" in log_text
    assert valid_secret not in log_text
    assert invalid_secret not in log_text
