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

# 自定义 Tool Provider

[English](custom-tool-providers.md) | [简体中文](custom-tool-providers.zh-CN.md)

Doris MCP Server 可以把既有业务 API 暴露为 MCP Tool，而不需要把业务专用
代码加入本仓库。扩展必须是安装在 Server 同一运行环境中的可信 Python 包，
并由部署方通过显式允许列表启用。

这条边界不允许 MCP Client 任意传入目标 URL、HTTP 方法、Header 或凭据。
Provider 代码运行在 Server 进程内，拥有与 Server 相同的操作系统权限，因此
只能安装和启用经过运维方审查的软件包。

## Provider 合同

在 Provider 包中声明一个具名 Entry Point：

```toml
[project.entry-points."doris_mcp_server.tool_providers"]
orders_api = "acme_doris_tools.provider:create_provider"
```

Entry Point 的目标必须是一个无参数可调用对象。它返回的对象，其 `name` 必须
与 Entry Point 名称完全一致，且 `tools()` 方法必须返回一个或多个
`CustomTool` 定义。

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

把 Provider 包安装到同一个虚拟环境，再只启用经过审查的 Entry Point 名称：

```bash
export MCP_TOOL_PROVIDERS=orders_api
doris-mcp-server --transport http --host 127.0.0.1 --port 3000
```

`MCP_TOOL_PROVIDERS` 为空时不加载任何自定义代码。若配置的 Provider 不存在、
名称不匹配、返回非法定义，或与内置 Tool / 其他自定义 Tool 重名，Server
都会启动失败。

Provider 可以通过可选的同步或异步 `start()`、`close()` 方法持有 HTTP Client
或其他运行资源。如果部分 Provider 启动失败，已经启动的 Provider 会被关闭。

## 认证与限流

在现有授权边界内，自定义 Provider Tool 可用于本地/stdio、静态 Token 和 JWT
部署。外部 OAuth 与 Doris-backed OAuth 会隐藏自定义 Tool 并拒绝直接调用；在
项目定义并审查动态 Scope 与 Policy 模型之前，这两种模式保持 Fail Closed。

`ToolRateLimit` 是有界、进程内、固定窗口限流器：

- `scope="principal"` 按已认证用户或 Token 身份隔离调用方；
- `scope="tool"` 对当前 Server 进程中的该 Tool 使用一个共享额度；
- 被拒绝的调用返回 `TOOL_RATE_LIMITED` 和有界重试延迟；
- 被拒绝时不会执行 Provider Handler。

每个 Worker、每个副本都有独立的限流器。如需全局 QPS、并发、配额或成本
限制，应在 API Gateway 或共享限流服务中执行。部署四个 Worker 时，进程内
限流可能允许约四倍于配置值的总速率。

## FastGPT 与其他 MCP Client

通过 Doris MCP Server 的标准 Streamable HTTP 或 stdio 传输对外提供服务。
FastGPT 和其他 MCP Client 通过 `tools/list` 发现自定义 Schema，再通过
`tools/call` 调用，无需 Provider 专用协议。主 README 中说明的 MCP
`2026-07-28` 请求 Metadata 和 HTTP Header 规则同样适用。

## 生产检查清单

- 在经过审查的 Provider 代码中固定目标 Host 与 API Path。绝不能接受 MCP
  参数传入的任意 URL、Scheme、Host、重定向目标或 Authorization Header。
- 使用 HTTPS 和网络出口允许列表。默认关闭重定向；若必须启用，应分别验证
  每个重定向目标。
- 从环境变量或 Secret Manager 读取凭据。不得在 Tool Schema、结果、审计
  字段或日志中写入 Secret。
- 设置有界连接、读取和总超时，以及响应大小上限；验证上游 Content-Type 和
  响应结构。
- 只返回 MCP 调用方获准查看的字段。上游错误 Body 视为敏感数据；Server 会
  清洗未捕获异常。
- 明确定义重试和幂等行为。不得自动重试不安全的写操作。
- 当可用性或成本需要时，在进程外增加上游并发限制、熔断和全局限流。
- 上线前验证 Provider 生命周期、输入校验、Tool 名冲突、限流、认证可见性、
  审计 Metadata，以及真实上游故障模式。
