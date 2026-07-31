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

from __future__ import annotations

import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import httpx2
import pytest
from mcp import Client, StdioServerParameters
from mcp.client.stdio import stdio_client

from doris_mcp_server.auth.mcp_auth_middleware import MCPAuthASGIMiddleware
from doris_mcp_server.auth.operation_policy import (
    OperationAuthorizationError,
    authorize_operation,
)
from doris_mcp_server.http_transport import DorisMCPHTTPTransport
from doris_mcp_server.protocol import create_transport_security
from doris_mcp_server.tools.doris_feature_matrix import (
    EXPECTED_DOMAIN_CHILDREN,
)
from doris_mcp_server.tools.tool_registry import (
    DORIS_OAUTH_EXPLAIN_TOOL_SET,
    DORIS_OAUTH_METADATA_TOOL_SET,
    DORIS_OAUTH_QUERY_TOOL_SET,
    RESTRICTED_TOOL_NAMES,
)
from doris_mcp_server.utils.auth_credentials import BearerCredentials
from doris_mcp_server.utils.config import EffectiveAuthConfig
from doris_mcp_server.utils.security import AuthContext
from test.protocol.tool_registry_server import create_registry_test_server

BASE_OPERATION_SCOPES = (
    ("list_tools", "tool:list"),
    ("list_resources", "resource:list"),
    ("read_resource", "resource:read"),
    ("list_prompts", "prompt:list"),
    ("get_prompt", "prompt:get"),
)
ALL_TOOL_NAMES = tuple(
    sorted(
        DORIS_OAUTH_METADATA_TOOL_SET
        | DORIS_OAUTH_QUERY_TOOL_SET
        | DORIS_OAUTH_EXPLAIN_TOOL_SET
        | RESTRICTED_TOOL_NAMES
    )
)
TOOL_OPERATION_SCOPES = tuple(
    (f"tool:{tool_name}", f"tool:call:{tool_name}")
    for tool_name in ALL_TOOL_NAMES
)
DOMAIN_OPERATION_SCOPES = tuple(
    (f"tool:{domain_name}", "tool:list")
    for domain_name in EXPECTED_DOMAIN_CHILDREN
)
ALL_OPERATION_SCOPES = (
    BASE_OPERATION_SCOPES
    + TOOL_OPERATION_SCOPES
    + DOMAIN_OPERATION_SCOPES
)


def _context(auth_method: str, scopes: Iterable[str] = ()) -> AuthContext:
    context = AuthContext(
        user_id=f"{auth_method}-user",
        auth_method=auth_method,
        oauth_scopes=list(scopes),
    )
    if auth_method == "doris_oauth":
        context.doris_oauth_db_tools_enabled = True
        context.doris_oauth_db_tool_allowlist = tuple(
            sorted(DORIS_OAUTH_METADATA_TOOL_SET)
        )
        context.doris_oauth_query_tools_enabled = True
        context.doris_oauth_query_tool_allowlist = tuple(
            sorted(DORIS_OAUTH_QUERY_TOOL_SET)
        )
        context.doris_oauth_explain_tools_enabled = True
        context.doris_oauth_explain_tool_allowlist = tuple(
            sorted(DORIS_OAUTH_EXPLAIN_TOOL_SET)
        )
    return context


def _external_oauth_config() -> EffectiveAuthConfig:
    return EffectiveAuthConfig(
        enable_token_auth=False,
        enable_jwt_auth=False,
        enable_external_oauth_auth=True,
        enable_doris_oauth_auth=False,
        auth_methods=("external_oauth",),
        oauth_discovery_mode="external_oauth",
        transport="http",
        requested_workers=1,
        effective_workers=1,
        legacy_auth_type="",
        external_oauth_issuer="https://issuer.example.test",
        external_oauth_resource="https://mcp.example.test/mcp",
        external_oauth_scopes=(
            "tool:list",
        ),
        external_oauth_required_scopes=("tool:list",),
    )


def _modern_request(
    request_id: int,
    method: str,
    *,
    name: str | None = None,
    arguments: dict[str, Any] | None = None,
) -> dict[str, Any]:
    params: dict[str, Any] = {
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": {
                "name": "auth-cross-matrix-test",
                "version": "1.0.0",
            },
        }
    }
    if name is not None:
        params["name"] = name
        params["arguments"] = arguments or {}
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": params,
    }


def _modern_headers(
    method: str,
    *,
    name: str | None = None,
    token: str,
) -> dict[str, str]:
    headers = {
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Mcp-Protocol-Version": "2026-07-28",
        "Mcp-Method": method,
    }
    if name is not None:
        headers["Mcp-Name"] = name
    return headers


@pytest.mark.parametrize(
    "auth_context",
    [
        None,
        _context("anonymous"),
        _context("token"),
        _context("jwt"),
    ],
    ids=["stdio-no-context", "anonymous", "token", "jwt"],
)
@pytest.mark.parametrize(
    "operation",
    [operation for operation, _ in ALL_OPERATION_SCOPES],
)
def test_non_oauth_auth_methods_do_not_apply_oauth_scope_policy(
    auth_context: AuthContext | None,
    operation: str,
) -> None:
    authorize_operation(auth_context, operation)


@pytest.mark.parametrize(("operation", "required_scope"), ALL_OPERATION_SCOPES)
def test_external_oauth_accepts_each_exact_operation_scope(
    operation: str,
    required_scope: str,
) -> None:
    authorize_operation(
        _context("external_oauth", [required_scope]),
        operation,
    )


@pytest.mark.parametrize(("operation", "required_scope"), ALL_OPERATION_SCOPES)
@pytest.mark.parametrize(
    "granted_scopes",
    [
        (),
        ("*",),
        ("wrong:scope",),
    ],
    ids=["missing", "wildcard", "wrong"],
)
def test_external_oauth_rejects_missing_or_inexact_operation_scope(
    operation: str,
    required_scope: str,
    granted_scopes: tuple[str, ...],
) -> None:
    with pytest.raises(OperationAuthorizationError) as exc:
        authorize_operation(
            _context("external_oauth", granted_scopes),
            operation,
        )

    assert exc.value.error_code == "PERMISSION_DENIED"
    assert exc.value.required_scope == required_scope
    assert exc.value.operation == operation


@pytest.mark.parametrize(
    ("operation", "required_scope"),
    (
        BASE_OPERATION_SCOPES[:3]
        + tuple(
            (f"tool:{tool_name}", f"tool:call:{tool_name}")
            for tool_name in sorted(
                DORIS_OAUTH_METADATA_TOOL_SET
                | DORIS_OAUTH_QUERY_TOOL_SET
                | DORIS_OAUTH_EXPLAIN_TOOL_SET
            )
        )
    ),
)
def test_doris_oauth_accepts_enabled_operations_with_exact_scope(
    operation: str,
    required_scope: str,
) -> None:
    authorize_operation(
        _context("doris_oauth", [required_scope]),
        operation,
    )


@pytest.mark.parametrize(
    "operation",
    ["list_prompts", "get_prompt"]
    + [f"tool:{tool_name}" for tool_name in sorted(RESTRICTED_TOOL_NAMES)],
)
def test_doris_oauth_keeps_unsupported_operations_denied(
    operation: str,
) -> None:
    required_scope = (
        f"tool:call:{operation.split(':', 1)[1]}"
        if operation.startswith("tool:")
        else "prompt:list"
        if operation == "list_prompts"
        else "prompt:get"
    )
    with pytest.raises(OperationAuthorizationError) as exc:
        authorize_operation(
            _context("doris_oauth", [required_scope]),
            operation,
        )

    assert exc.value.error_code == "UNSUPPORTED_FOR_DORIS_OAUTH"


def test_external_oauth_rejects_unknown_tool_before_dispatch() -> None:
    with pytest.raises(OperationAuthorizationError) as exc:
        authorize_operation(
            _context("external_oauth", ["tool:call:not_real"]),
            "tool:not_real",
        )

    assert exc.value.error_code == "UNKNOWN_OPERATION"
    assert exc.value.operation == "tool:not_real"


@pytest.mark.asyncio
async def test_streamable_http_enforces_external_oauth_tool_scope_before_dispatch() -> None:
    contexts = {
        "no-scope": _context("external_oauth"),
        "list-only": _context("external_oauth", ["tool:list"]),
    }

    class SecurityManager:
        async def authenticate_request(
            self,
            credentials: BearerCredentials,
        ) -> AuthContext:
            return contexts[credentials.token]

    server = create_registry_test_server()
    transport = DorisMCPHTTPTransport(
        app=server,
        security_settings=create_transport_security("127.0.0.1"),
    )
    app = MCPAuthASGIMiddleware(
        SecurityManager(),
        transport.handle_request,
        _external_oauth_config(),
    )

    async with (
        transport.run(),
        httpx2.ASGITransport(app) as asgi_transport,
        httpx2.AsyncClient(
            transport=asgi_transport,
            base_url="http://127.0.0.1:3000",
        ) as client,
    ):
        listed = await client.post(
            "/mcp",
            json=_modern_request(1, "tools/list"),
            headers=_modern_headers("tools/list", token="list-only"),
        )
        assert listed.status_code == 200
        assert {
            tool["name"] for tool in listed.json()["result"]["tools"]
        } == set(EXPECTED_DOMAIN_CHILDREN)

        denied = await client.post(
            "/mcp",
            json=_modern_request(
                2,
                "tools/call",
                name="doris_catalog",
                arguments={},
            ),
            headers=_modern_headers(
                "tools/call",
                name="doris_catalog",
                token="no-scope",
            ),
        )
        assert denied.status_code == 403
        assert denied.json()["error"] == "PERMISSION_DENIED"
        assert denied.json()["required_scope"] == "tool:list"
        assert 'error="insufficient_scope"' in denied.headers[
            "www-authenticate"
        ]
        assert 'scope="tool:list"' in denied.headers[
            "www-authenticate"
        ]

        allowed = await client.post(
            "/mcp",
            json=_modern_request(
                3,
                "tools/call",
                name="doris_catalog",
                arguments={},
            ),
            headers=_modern_headers(
                "tools/call",
                name="doris_catalog",
                token="list-only",
            ),
        )
        assert allowed.status_code == 200
        assert allowed.json()["result"]["structuredContent"]["mode"] == (
            "manifest"
        )
        assert allowed.json()["result"]["structuredContent"]["domain"] == (
            "doris_catalog"
        )


@pytest.mark.asyncio
async def test_true_subprocess_stdio_keeps_local_tool_and_resource_paths_scope_free() -> None:
    server_script = (
        Path(__file__).resolve().parents[1]
        / "protocol"
        / "tool_registry_server.py"
    )
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[str(server_script)],
    )

    async with Client(stdio_client(server_params)) as client:
        tools = await client.list_tools(cache_mode="bypass")
        assert {tool.name for tool in tools.tools} == set(
            EXPECTED_DOMAIN_CHILDREN
        )

        called = await client.call_tool("doris_catalog", {})
        assert called.structured_content["mode"] == "manifest"
        assert called.structured_content["domain"] == "doris_catalog"

        resources = await client.list_resources(cache_mode="bypass")
        assert resources.resources == []
        read = await client.read_resource(
            "doris://table/orders",
            cache_mode="bypass",
        )
        assert read.contents[0].uri == "doris://table/orders"
