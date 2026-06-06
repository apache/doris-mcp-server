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
    assert headers[b"access-control-expose-headers"] == b"mcp-session-id, www-authenticate"
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
                (b"access-control-request-headers", b"authorization, mcp-session-id"),
            ]
        )
    )

    assert response.status_code == 204
    assert response.headers["Access-Control-Allow-Origin"] == "https://client.example"
    assert response.headers["Access-Control-Allow-Credentials"] == "true"
    assert response.headers["Access-Control-Allow-Methods"] == "GET, POST, DELETE, OPTIONS"
    assert response.headers["Access-Control-Allow-Headers"] == "authorization, mcp-session-id"
    assert response.headers["Vary"] == "Origin"
