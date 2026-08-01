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

# Apache Doris MCP Server

[English](README.md) | 简体中文

Apache Doris MCP Server 通过 MCP `2026-07-28`，向 MCP Host 和 AI Agent
提供只读的 Apache Doris 能力。1.0 版本把过去庞大的扁平工具集合重构为 8 个
稳定一级领域和 55 个渐进披露的二级能力，同时明确表达运行时可用性、权限、输入
Schema、输出 Schema 与失败行为。

## 发布状态

当前包版本为 `1.0.0`。`master` 上的 MCP `2026-07-28` 协议兼容性已在
Streamable HTTP 和 stdio 两种传输上达到 **GA**。这个 GA 只针对协议兼容性；
Python 包分类仍为 **Beta**，已记录的部署限制仍然有效。

升级前请阅读 [1.0 发布说明](docs/releases/1.0.0.zh-CN.md)、
[1.0 迁移指南](docs/migration/1.0.0.zh-CN.md)和自动生成的
[8 领域 / 55 子能力目录](docs/tool-registry.md)。详细发布记录见
[Issue #189](https://github.com/apache/doris-mcp-server/issues/189)。

## 架构概览

```text
MCP Host
  -> stdio 或 Streamable HTTP
  -> 传输安全与身份认证
  -> MCP 协议校验与操作授权
  -> 稳定领域发现
  -> 面向实际 Doris 路由的能力探测
  -> 精确 Child 调度与只读运行时
  -> 请求级 Doris 路由与 RBAC
  -> 有界且通过 Schema 校验的结果
```

默认 `hierarchical` 模式公开以下领域：

| 领域 | Child 数量 | 职责 |
|---|---:|---|
| `doris_catalog` | 5 | Catalog、数据库、表、表上下文、大小 |
| `doris_query` | 7 | 查询、Explain、Profile、诊断、慢查询、显式 ADBC |
| `doris_cluster` | 11 | 节点、任务、指标、内存、缓存、Compaction、工作负载 |
| `doris_pipeline` | 5 | 导入、物化视图、新鲜度、依赖关系 |
| `doris_search` | 4 | 文本/向量/混合检索、分词、索引、诊断 |
| `doris_governance` | 8 | 质量、存储、血缘、审计、UDF、认证映射 |
| `doris_lakehouse` | 3 | 外部 Catalog、湖仓表、Variant |
| `doris_semantic` | 12 | 可选 Apache Ossie Grounding 与 MetricFlow 消费 |

使用 `{}` 调用一级领域，可以获得当前身份有权发现的 Child 和精确 Schema；
随后用 `child_tool`、`arguments` 和返回的 `manifest_version` 调用同一个领域。
无法使用渐进披露的 Host 可以在启动前设置 `MCP_TOOL_EXPOSURE_MODE=flat`，
以无冲突正式名称公开同样的 55 个 Child；该模式不会恢复 1.0 以前的旧名称。

详见[总体架构](docs/architecture/overview.zh-CN.md)、
[请求与数据链路](docs/architecture/request-lifecycle.zh-CN.md)和
[工具领域](docs/capabilities/tool-domains.zh-CN.md)。

## 快速开始

运行要求：

- Python 3.12 或更高版本；
- Apache Doris 2.0.0 或更高版本；
- 可以访问 Doris FE MySQL 端口，通常为 `9030`。

安装固定版本：

```bash
pip install doris-mcp-server==1.0.0
```

`doris-mcp-server` 用于启动 Server；`doris-mcp-client` 是独立客户端，
这两个命令不能互相替代。

配置 Doris 路由：

```bash
export DORIS_HOST=127.0.0.1
export DORIS_PORT=9030
export DORIS_USER=root
export DORIS_PASSWORD='replace-me'
export DORIS_DATABASE=information_schema
```

在回环地址启动 Streamable HTTP：

```bash
doris-mcp-server \
  --transport http \
  --host 127.0.0.1 \
  --port 3000
```

服务端点：

- MCP：`POST http://127.0.0.1:3000/mcp`
- 旧版 MCP（显式开启）：`POST http://127.0.0.1:3000/mcp/legacy`
- 存活检查：`GET http://127.0.0.1:3000/live`
- Doris 就绪检查：`GET http://127.0.0.1:3000/ready`

仅支持 Handshake-era Streamable HTTP 的 Host，包括使用 MCP `2025-06-18` 的
Dify 1.16.1，需要设置 `ENABLE_LEGACY_HTTP_ADAPTER=true` 并连接
`/mcp/legacy`。Adapter 只改变协议边界，仍使用相同的 1.0 Tool、授权、能力 Gate
和只读执行链路。

也可以为本地 Host 启动 stdio：

```bash
doris-mcp-server --transport stdio
```

详见[完整快速开始](docs/getting-started/quickstart.zh-CN.md)与
[Host 接入指南](docs/integrations/hosts.zh-CN.md)。

## 安全边界

- 1.0 内置目录全部只读；`doris_admin` 只做架构预留，不会注册。
- 静态 Token、JWT、外部 OAuth/OIDC 和 Doris 账号驱动的 OAuth 均有独立且
  互相校验的配置边界。
- 领域发现与 Child 执行使用精确授权标识。
- Doris RBAC 仍然是对象可见性与数据访问的最终权限边界。
- SQL 形态、标识符、参数、超时、行数、字节数和结果 Schema 都会被约束。
- Secret 与后端原始错误不会进入公开结果或日志。
- 非回环 HTTP 默认必须启用鉴权，除非显式开启危险的开发环境绕过开关。

详见[安全与权限模型](docs/security/security-model.zh-CN.md)和
[Doris 细粒度权限指南](docs/doris-fine-grained-access-control.zh-CN.md)。

## 可靠性边界

Server 使用确定性 Manifest 与错误模型、签名并带有效期的游标、路由级能力
快照、有界陈旧回退、请求级连接路由、多 FE 故障切换、存活/就绪分离、输出
Schema 校验以及清洗后的 Trace 传播。未支持或配置错误的 Child 仍可在有权限时
以 `callable=false` 被发现，真正调用时按 Fail Closed 处理。

当前限制包括：Doris OAuth 状态只存在于单进程；ADBC 默认关闭，只有用户明确
指定 ADBC/Arrow Flight SQL 时才能调用，并在 Token 路由上 Fail Closed；Ossie
只做可选只读 Grounding；MetricFlow 依赖可选编译 Sidecar，编译后的 SQL 必须
回到 MCP 有界查询运行时执行；原生血缘事件采用异步 Best-effort 投递。详见
[可靠性与限制](docs/operations/reliability.zh-CN.md)。

## 文档体系

根 README 只保留项目入口。完整双语文档索引：

- [English documentation](docs/README.md)
- [简体中文文档](docs/README.zh-CN.md)

主要指南：

- [总体架构](docs/architecture/overview.zh-CN.md)
- [请求与数据链路](docs/architecture/request-lifecycle.zh-CN.md)
- [工具领域](docs/capabilities/tool-domains.zh-CN.md)
- [能力可用性](docs/capabilities/availability.zh-CN.md)
- [Doris 版本能力矩阵](docs/capabilities/doris-version-matrix.zh-CN.md)
- [MetricFlow 接入](docs/integrations/metricflow.zh-CN.md)
- [MCP 2026-07-28 合同](docs/protocol/mcp-2026-07-28.zh-CN.md)
- [安全模型](docs/security/security-model.zh-CN.md)
- [部署](docs/operations/deployment.zh-CN.md)
- [可靠性与限制](docs/operations/reliability.zh-CN.md)
- [排障](docs/operations/troubleshooting.zh-CN.md)
- [配置参考](docs/reference/configuration.zh-CN.md)
- [Host 接入](docs/integrations/hosts.zh-CN.md)
- [自定义 Tool Provider](docs/custom-tool-providers.zh-CN.md)
- [贡献与验证](docs/development/contributing.zh-CN.md)

## 开发

```bash
git clone https://github.com/apache/doris-mcp-server.git
cd doris-mcp-server
uv sync --group dev
uv run pytest
```

自动生成的产物必须保持同步：

```bash
uv run python generate_tool_catalog.py --check
uv lock --check
```

详见[贡献与验证](docs/development/contributing.zh-CN.md)。

## 许可证

Apache License 2.0。参见 [LICENSE.txt](LICENSE.txt) 和 [NOTICE](NOTICE)。
