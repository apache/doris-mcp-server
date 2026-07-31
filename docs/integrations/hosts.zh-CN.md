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

# Host 集成

[English](hosts.md) | 简体中文

MCP Host 负责模型、对话、Tool 注册和 Client 连接；Doris MCP Server 负责稳定工具
合同、授权后的渐进发现、能力证据与执行。两者边界是标准 MCP：能够遵循 1.0 调用
形态的 Host 不需要编写 Doris 专有代码。

## Host、Client 与 Server

| 组件 | 职责 |
|---|---|
| Host | 模型上下文、用户意图、Tool 选择、审批 UX、连接生命周期 |
| MCP Client | 传输 Frame、请求元数据、凭据、协议错误 |
| Doris MCP Server | Tool Schema、发现、授权、能力 Gate、只读执行 |
| Apache Doris | 元数据/查询执行与最终数据权限 |

Server 不会根据对话意图修改 Host 已注册的一级工具列表。8 个稳定领域足以让同一
对话立刻从“有哪些表”切换到“集群是否健康”。

## Hierarchical 交互

推荐 Host 算法：

1. 连接并调用 `tools/list`。
2. 使用返回 Description/Schema 注册 8 个领域 Tool。
3. 模型选择领域后，用 `{}` 调用它。
4. 把返回的已授权 Child Description 与精确 Schema 交给下一步模型/Tool 选择。
5. 用精确 `child_tool`、`arguments` 和 `manifest_version` 调用同一个领域。
6. 遇到 `CHILD_MANIFEST_STALE`，丢弃该领域缓存并重新发现。
7. 遇到 `callable=false`，向用户表达结构化 Availability 原因，不绕过 Server。

二级选择可以由模型完成，因为完整授权 Child 与精确 Schema 已经进入上下文。
Server 不使用概率 Intent Routing 去猜 Child。

## 快速意图切换

示例对话：

1. 用户询问有哪些表。
2. 模型用 `{}` 调用 `doris_catalog`，再调用 `list_tables`。
3. 用户马上询问集群是否健康。
4. 模型用 `{}` 调用已经注册的 `doris_cluster`，再调用
   `get_cluster_overview`。

不需要重新注册 MCP Tool。Domain Registration 稳定，只有选中领域的 Manifest
被渐进披露。Host 可以保留多个当前 Manifest，但每份都必须绑定返回代际和授权
上下文。

## Flat 回退

部分 Host 不能在选择最终操作前先做发现。Server 启动前配置：

```bash
export MCP_TOOL_EXPOSURE_MODE=flat
```

重启并重连后，`tools/list` 返回正式名称，例如：

- `doris_catalog_list_tables`
- `doris_query_execute_query`
- `doris_cluster_get_cluster_overview`

Flat 公开同一套经过授权的 47 Child Catalog 与 Availability。它不提供旧名称 Alias、
动态注册或安全绕过。上下文成本更高，因此优先 Hierarchical。

## stdio 配置

通用 Host 配置：

```json
{
  "mcpServers": {
    "doris": {
      "command": "doris-mcp-server",
      "args": ["--transport", "stdio"],
      "env": {
        "DORIS_HOST": "127.0.0.1",
        "DORIS_PORT": "9030",
        "DORIS_USER": "mcp_reader",
        "DORIS_PASSWORD": "<secret>",
        "DORIS_DATABASE": "information_schema",
        "MCP_TOOL_EXPOSURE_MODE": "hierarchical"
      }
    }
  }
}
```

不同产品的 Host 配置文件路径不同。应保留 Command、Args、Environment 和 MCP
`2026-07-28` 行为，不能盲目复制产品路径。

规则：

- GUI Host 的 `PATH` 不同时使用绝对 Executable Path；
- stdout 只传协议；
- 通过 Host Secret 机制或受保护环境注入凭据；
- Exposure Mode 或包版本变化后重启 Host。

## Streamable HTTP 配置

连接：

```text
http://127.0.0.1:3000/mcp
```

Client 必须实现[协议合同](../protocol/mcp-2026-07-28.zh-CN.md)中的现代请求元数据与
HTTP Header，并增加配置凭据，例如：

```text
Authorization: Bearer <token>
```

不能把凭据放 URL。远程访问需要 HTTPS 与已校验 Host/Origin/Proxy Policy。

## 内置命令行 Client

`doris-mcp-client` 用于连接与协议诊断。它不是 Server Executable，不能在 Host
配置中替代 `doris-mcp-server`。

使用已安装版本的 `--help` 查看精确参数：

```bash
doris-mcp-client --help
doris-mcp-server --help
```

## Host 的认证行为

- Static Token/JWT Host 发送相应 Bearer Credential。
- External OAuth Host 为规范 MCP Resource 与精确 Scope 获取 Access Token。
- Doris OAuth Host 使用 Server OAuth Metadata/Authorization 流程，获得 Resource
  绑定 Token。
- Host 应展示 `WWW-Authenticate`/Insufficient-scope 响应，不能静默匿名重连。
- 复用 Manifest 或 Cursor 时，Domain Discovery 与 Child Call 必须使用同一
  Principal。

## Schema 与结果处理

Host 应当：

- 信任活动 Server 返回的 Schema，不依赖复制的静态示例；
- 保留 Child 精确名称与大小写；
- 按 Child Input Schema 校验或构造参数；
- 把 Structured Content 作为权威机器可读结果；
- 向用户显示 Warning/Truncation；
- 使用类型化 Error Code 与 Retryability；
- 不把人类 Description 当作状态或 API Signature 解析；
- 把 Manifest/Cursor 当成不透明值。

## Host 兼容检查

| 要求 | Hierarchical | Flat |
|---|---:|---:|
| MCP `2026-07-28` Tool List/Call | 必需 | 必需 |
| 用 `{}` 调用领域 | 必需 | 不需要 |
| 把发现 Child Schema 交给模型 | 必需 | 不需要 |
| 处理 Structured Content | 推荐 | 推荐 |
| 处理 Stale-manifest Rediscovery | 必需 | Flat Call 通常不发送 |
| 47 Tool Context Budget | 不需要 | 必需 |
| Exposure Mode 变化后重启 | 必需 | 必需 |

如果 Host 既不能消费 Progressive Manifest，也容纳不了 47 个有界正式 Tool，它就
暂时无法接入完整 1.0 工具面。不能用概率 Server-side Routing 规避这个问题。

## Host 测试序列

1. 确认 `server/discover` Identity/Version。
2. 确认 `tools/list` 返回 8 Domain（Hierarchical），或在授权过滤前符合 47 Formal
   Child 基线（Flat）。
3. 发现 Catalog 并调用 `list_tables`。
4. 同一对话切换 Cluster，调用 Overview/Capabilities。
5. 发送无效 Child，确认确定性拒绝。
6. 发送写 SQL，确认只读 Guard。
7. Stage 中改变 Provider/Permission，确认 Stale Rediscovery。
8. 用真实请求身份测试 Doris Permission-denied 对象。

继续阅读[快速开始](../getting-started/quickstart.zh-CN.md)和
[请求生命周期](../architecture/request-lifecycle.zh-CN.md)。
