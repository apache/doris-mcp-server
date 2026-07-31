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

import pytest

from doris_mcp_server.auth.mcp_cors import (
    mcp_cors_preflight_response,
    send_with_mcp_cors,
)


def _scope(headers=None):
    return {
        "type": "http",
        "method": "POST",
        "path": "/mcp",
        "headers": headers or [(b"origin", b"https://client.example")],
    }


@pytest.mark.asyncio
async def test_send_with_mcp_cors_forwards_response_start_and_body():
    messages = []

    async def send(message):
        messages.append(message)

    await send_with_mcp_cors(
        _scope(),
        send,
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"application/json")],
        },
    )
    await send_with_mcp_cors(
        _scope(),
        send,
        {"type": "http.response.body", "body": b"ok"},
    )

    assert messages[0]["status"] == 200
    headers = dict(messages[0]["headers"])
    assert headers[b"access-control-allow-origin"] == b"https://client.example"
    assert headers[b"access-control-allow-credentials"] == b"true"
    assert headers[b"access-control-expose-headers"] == b"www-authenticate"
    assert messages[1]["body"] == b"ok"


@pytest.mark.asyncio
async def test_send_with_mcp_cors_does_not_duplicate_existing_headers_case_insensitively():
    messages = []

    async def send(message):
        messages.append(message)

    await send_with_mcp_cors(
        _scope(),
        send,
        {
            "type": "http.response.start",
            "status": 401,
            "headers": [(b"Access-Control-Allow-Origin", b"https://already.example")],
        },
    )

    header_names = [name.lower() for name, _ in messages[0]["headers"]]
    assert header_names.count(b"access-control-allow-origin") == 1
    assert dict(messages[0]["headers"])[b"Access-Control-Allow-Origin"] == b"https://already.example"


def test_mcp_cors_preflight_response_uses_origin_and_requested_headers():
    response = mcp_cors_preflight_response(
        _scope(
            [
                (b"origin", b"https://client.example"),
                (
                    b"access-control-request-headers",
                    b"authorization, mcp-protocol-version",
                ),
            ]
        )
    )

    assert response.status_code == 204
    assert response.headers["Access-Control-Allow-Origin"] == "https://client.example"
    assert response.headers["Access-Control-Allow-Credentials"] == "true"
    assert response.headers["Access-Control-Allow-Methods"] == "POST, OPTIONS"
    assert (
        response.headers["Access-Control-Allow-Headers"]
        == "authorization, mcp-protocol-version"
    )
    assert response.headers["Vary"] == "Origin"


def test_mcp_cors_preflight_defaults_advertise_only_modern_http_fields():
    response = mcp_cors_preflight_response(_scope())

    assert response.headers["Access-Control-Allow-Methods"] == "POST, OPTIONS"
    allowed_headers = response.headers["Access-Control-Allow-Headers"].split(", ")
    assert allowed_headers == [
        "authorization",
        "content-type",
        "mcp-protocol-version",
        "mcp-method",
        "mcp-name",
    ]
    assert "mcp-session-id" not in response.headers["Access-Control-Allow-Headers"]
