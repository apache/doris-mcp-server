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

# 快速开始

[English](quickstart.md) | 简体中文

这份指南用于启动本地 Apache Doris MCP Server 1.0.0、验证健康状态，并理解
Hierarchical Discovery 的调用形态。示例只使用回环地址与占位凭据。

## 1. 前置条件

- Python 3.12 或更高版本。
- Apache Doris 2.0.0 或更高版本；后续版本特性由运行时动态过滤。
- 可以访问 FE MySQL 端口，通常为 `9030`。
- 如需 Profile 与部分运维能力，可以访问 FE HTTP 端口，通常为 `8030`。
- 如需 BE 级监控，需要显式配置允许访问的 BE HTTP 地址。

确认 Python：

```bash
python3 --version
```

## 2. 安装

从 PyPI 安装：

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install doris-mcp-server==1.0.0
```

从源码安装：

```bash
git clone https://github.com/apache/doris-mcp-server.git
cd doris-mcp-server
uv sync --group dev
```

安装包提供两个程序：

- `doris-mcp-server`：启动 MCP Server。
- `doris-mcp-client`：连接已经运行的 Server。

两者不能互相替代。

## 3. 配置 Doris 路由

```bash
export DORIS_HOST=127.0.0.1
export DORIS_PORT=9030
export DORIS_USER=root
export DORIS_PASSWORD='replace-me'
export DORIS_DATABASE=information_schema
```

多 FE 路由示例：

```bash
export DORIS_HOSTS='fe-1.example:9030,fe-2.example:9030'
export DORIS_FE_HTTP_HOSTS='fe-1.example:8030,fe-2.example:8030'
```

生产环境应使用独立的最小权限 Doris 账号。不要提交密码、Bearer Token、
Client Secret、JWT Key 或 `.env` 文件。

## 4. 启动 Streamable HTTP

```bash
doris-mcp-server \
  --transport http \
  --host 127.0.0.1 \
  --port 3000
```

现代 MCP 端点：

```text
POST http://127.0.0.1:3000/mcp
```

对于已经验证的 Handshake-era Host，例如使用 MCP `2025-06-18` 的 Dify
1.16.1，请设置 `ENABLE_LEGACY_HTTP_ADAPTER=true` 后重启，并把 Host URL 配置为
`http://127.0.0.1:3000/mcp/legacy`。不能把旧协议流量发送到 `/mcp`。

健康端点：

```bash
curl --fail http://127.0.0.1:3000/live
curl --fail http://127.0.0.1:3000/ready
```

`/live` 只验证进程与协议服务；`/ready` 还会执行有界的 Doris 路由检查。
进程存活但未就绪时，应先诊断 Doris 连接，而不是直接重启。

HTTP 默认绑定回环地址。非回环地址至少需要启用一种鉴权模式，除非操作人员显式
打开危险的开发环境开关 `ALLOW_UNAUTHENTICATED_NON_LOOPBACK=true`。

## 5. 启动 stdio

当 Host 以子进程方式启动 Server 时：

```bash
doris-mcp-server --transport stdio
```

stdio 模式不能把普通应用输出写入 stdout。MCP Frame 使用 stdout；诊断日志应写入
stderr 或配置的日志文件。

## 6. 发现并调用 Child

默认 `hierarchical` 模式下，`tools/list` 返回 8 个领域 Tool。用下列参数调用
`doris_catalog` 进行发现：

```json
{}
```

返回结果包含当前身份有权发现的 Child、精确 Schema、Availability 与
`manifest_version`。后续仍调用同一个一级 Tool：

```json
{
  "child_tool": "list_tables",
  "arguments": {
    "database": "information_schema"
  },
  "manifest_version": "<发现阶段返回的值>"
}
```

如果 Server 返回 `CHILD_MANIFEST_STALE`，应再次用 `{}` 发现该领域并使用新
Manifest。若 Child 的 `callable=false`，应读取结构化 `reason_code`，不能只靠
Description 猜测可用性。

不支持渐进披露的 Host 可以设置：

```bash
export MCP_TOOL_EXPOSURE_MODE=flat
```

随后重启 Server 并让 Host 重新连接。Flat 模式使用
`doris_catalog_list_tables` 等正式名称公开同样的 55 个 Child。

## 7. 验证安装

```bash
doris-mcp-server --version
python -c "import doris_mcp_server; print(doris_mcp_server.__version__)"
```

源码仓库中还可以运行：

```bash
uv run pytest test/test_release_artifacts.py test/test_product_identity.py
uv run python generate_tool_catalog.py --check
```

## 下一步

- [接入 Host](../integrations/hosts.zh-CN.md)
- [理解总体架构](../architecture/overview.zh-CN.md)
- [查看工具领域](../capabilities/tool-domains.zh-CN.md)
- [配置鉴权](../security/security-model.zh-CN.md)
- [部署 Server](../operations/deployment.zh-CN.md)
- [排查问题](../operations/troubleshooting.zh-CN.md)
