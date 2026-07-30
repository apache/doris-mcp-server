<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
-->

# Custom tool providers

Doris MCP Server can expose an existing business API as an MCP tool without
adding business-specific code to this repository. The extension is a trusted
Python package installed in the same environment as the server and enabled by
an explicit deploy-time allowlist.

This boundary intentionally does not accept an arbitrary target URL, method,
headers, or credentials from MCP clients. Provider code executes inside the
server process and therefore has the same operating-system privileges as the
server. Install and enable only packages that the operator has reviewed.

## Provider contract

Declare a named entry point in the provider package:

```toml
[project.entry-points."doris_mcp_server.tool_providers"]
orders_api = "acme_doris_tools.provider:create_provider"
```

The entry-point target must be a zero-argument callable. It returns an object
whose `name` exactly matches the entry-point name and whose `tools()` method
returns one or more `CustomTool` definitions.

```python
from __future__ import annotations

import os
from typing import Any
from urllib.parse import quote

import httpx
from mcp.types import Tool

from doris_mcp_server.tools import CustomTool, ToolRateLimit


class OrdersApiProvider:
    name = "orders_api"

    def __init__(self) -> None:
        self._base_url = os.environ["ORDERS_API_BASE_URL"].rstrip("/")
        if not self._base_url.startswith("https://"):
            raise ValueError("ORDERS_API_BASE_URL must use HTTPS")
        self._token = os.environ["ORDERS_API_TOKEN"]
        self._client: httpx.AsyncClient | None = None

    async def start(self) -> None:
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers={"Authorization": f"Bearer {self._token}"},
            timeout=httpx.Timeout(5.0, connect=2.0),
            follow_redirects=False,
        )

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def tools(self) -> tuple[CustomTool, ...]:
        return (
            CustomTool(
                tool=Tool(
                    name="lookup_business_order",
                    description="Look up one order in the reviewed business API",
                    input_schema={
                        "type": "object",
                        "properties": {
                            "order_id": {
                                "type": "string",
                                "minLength": 1,
                                "maxLength": 128,
                            }
                        },
                        "required": ["order_id"],
                        "additionalProperties": False,
                    },
                ),
                handler=self._lookup_order,
                risk="medium",
                rate_limit=ToolRateLimit(
                    max_calls=10,
                    period_seconds=1,
                    scope="principal",
                ),
            ),
        )

    async def _lookup_order(
        self,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        if self._client is None:
            raise RuntimeError("provider is not started")
        order_id = arguments["order_id"]
        if not isinstance(order_id, str) or not order_id.strip():
            raise ValueError("order_id must be a non-empty string")

        response = await self._client.get(
            f"/v1/orders/{quote(order_id, safe='')}"
        )
        response.raise_for_status()
        if len(response.content) > 1_048_576:
            raise ValueError("upstream response is too large")
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("upstream response must be a JSON object")
        return payload


def create_provider() -> OrdersApiProvider:
    return OrdersApiProvider()
```

Install the provider package in the same virtual environment, then enable only
the reviewed entry-point name:

```bash
export MCP_TOOL_PROVIDERS=orders_api
doris-mcp-server --transport http --host 127.0.0.1 --port 3000
```

An empty `MCP_TOOL_PROVIDERS` value loads no custom code. Startup fails if a
configured provider is missing, has a mismatched name, returns an invalid
definition, or shadows a built-in or another custom tool.

Optional synchronous or asynchronous `start()` and `close()` methods can own
HTTP clients or other runtime resources. A partial startup failure closes
providers that were already started.

## Authentication and rate limits

Custom provider tools are available to local/stdio, static-token, and JWT
deployments under their existing authorization boundary. External OAuth and
Doris-backed OAuth hide custom tools and reject direct calls: they fail closed
until the project defines a reviewed dynamic scope and policy model.

`ToolRateLimit` is a bounded, process-local fixed-window limiter:

- `scope="principal"` separates callers by the authenticated user or token
  identity;
- `scope="tool"` applies one shared limit to the tool in that server process;
- rejected calls return `TOOL_RATE_LIMITED` and a bounded retry delay;
- the provider handler is not invoked for a rejected call.

Each worker and each replica has an independent limiter. For a global QPS,
concurrency, quota, or cost limit, enforce the limit in an API gateway or shared
rate-limit service. With four workers, a process-local limit can allow roughly
four times the configured rate.

## FastGPT and other MCP clients

Expose Doris MCP Server through its normal Streamable HTTP or stdio transport.
FastGPT and other MCP clients discover the custom schema through `tools/list`
and invoke it through `tools/call`; no provider-specific protocol is required.
The same MCP `2026-07-28` request metadata and HTTP headers described in the
main README still apply.

## Production checklist

- Keep target hosts and API paths fixed in reviewed provider code. Never accept
  an arbitrary URL, scheme, host, redirect target, or authorization header from
  MCP arguments.
- Use HTTPS and a network egress allowlist. Disable redirects unless every
  redirect target is separately validated.
- Read credentials from environment variables or a secret manager. Never place
  secrets in tool schemas, results, audit fields, or logs.
- Apply bounded connect/read/total timeouts and response-size limits. Validate
  the upstream content type and response structure.
- Return only fields the MCP caller is authorized to see. Treat upstream error
  bodies as sensitive; the server intentionally sanitizes uncaught exceptions.
- Define retry and idempotency behavior explicitly. Do not automatically retry
  unsafe mutations.
- Add upstream concurrency limits, circuit breaking, and global rate limiting
  outside the process when availability or cost requires them.
- Test provider lifecycle, input validation, tool-name collisions, rate-limit
  behavior, authentication visibility, audit metadata, and the real upstream
  failure modes before production deployment.
