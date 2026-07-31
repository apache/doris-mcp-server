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

# Doris MCP Server

[English](README.md) | [简体中文](README.zh-CN.md)

Doris MCP Server 是一个基于 [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) 的 [Apache Doris](https://doris.apache.org/) 查询服务。AI 客户端（Claude Desktop、Cursor、VS Code 等）通过内置的 **MetricFlow 语义指标层**以受治理的方式查询 Doris 数据，裸 SQL 作为兜底路径。附带管理语义模型的 Web UI 和脚本化 CLI 客户端。

## 核心特性

*   **语义指标层**：YAML 中一次定义指标（简单 / 比率 / 衍生 / 累计 / 漏斗转化），任意 MCP 客户端均可查询。MetricFlow 编译语义正确的 SQL，无需手写聚合查询。
*   **多工作区隔离**：完全隔离的逻辑租户，各自拥有独立的模型、编译器和 Doris 存储表。模型存储在 Doris 内（active + staging 两张表），多节点共享状态无需文件同步。
*   **Staging 工作流**：所有模型变更必经 *staging → validate → commit*，错误模型永远不会影响线上查询。
*   **引导式工具链**：10 个 MCP Tool，强制执行工作流（`get_query_guide` → `check_service_health` → 语义查询，或元数据发现 → 裸 SQL 兜底）。
*   **凭据透传**：`Authorization: Bearer <doris用户>:<密码>`——每条 SQL 都以调用者自己的 Doris 身份执行，每用户独立连接池，无共享 admin 凭据。
*   **Web UI**：Doris 凭据登录，在线编辑/验证/发布模型、管理工作区、一键部署示例，无需本地 YAML 工具链。
*   **CLI 客户端**：`mcp-client` 支持脚本和 CI/CD 中调用工具、推拉模型文件。
*   **多机部署就绪**：会话亲和在应用层完成（Cookie 后缀路由，或一行 `privateIp` 固定 Web UI 入口节点），nginx 只做哑代理。
*   **自包含打包**：Release 包自带 Python 3.10 运行时和全部依赖，目标机器无需网络、pip 或系统 Python。

## 系统要求

*   **服务器**：Linux x86_64 或 ARM64（运行 Release 包）
*   **数据库**：Doris FE MySQL 协议可达（默认 `127.0.0.1:9030`）
*   **源码构建**：curl/wget，或本地 Python 3.10.x（离线构建）

## 🚀 快速开始

### 1. 获取安装包

从 [Releases](../../releases) 下载最新版本：

```bash
tar xzf doris-mcp-server-<version>-linux-x64.tar.gz
cd doris-mcp-server
```

或从源码构建（见[源码构建](#源码构建)）。

### 2. 启动服务

默认配置期望同机 Doris FE 运行在 `127.0.0.1:9030`。如有需要编辑 `mcp-server.toml`，然后：

```bash
# 前台
./start-mcp-server.sh

# 后台
nohup ./start-mcp-server.sh > /dev/null 2>&1 &
```

服务默认监听 **3000** 端口。

### 3. 接入 MCP 客户端

认证方式是把 **Doris 用户名和密码**作为 Bearer token 传递：

```text
Authorization: Bearer <doris用户>:<doris密码>
```

**Claude Desktop / Claude Code：**

```bash
claude mcp add --transport http doris http://<host>:3000/mcp \
  --header "Authorization: Bearer <user>:<password>"
```

**Cursor / VS Code（`mcp.json`）：**

```json
{
  "mcpServers": {
    "doris": {
      "type": "http",
      "url": "http://<host>:3000/mcp",
      "headers": {
        "Authorization": "Bearer <user>:<password>"
      }
    }
  }
}
```

可直接复制的模板见 [`mcp.json.example`](mcp.json.example)。

**用 FastMCP CLI 冒烟测试：**

```bash
fastmcp call http://<host>:3000/mcp check_service_health \
  --auth "<user>:<password>" --json
```

### 4. 部署示例工作区（Web UI）

1. 浏览器打开 `http://<host>:3000/mcp/web`，用 Doris 凭据登录（需 admin 用户，默认为 `admin`）。
2. 点击 **example 部署** 按钮。部署在后台执行，页面自动轮询进度并在完成后跳转。
3. 回到 AI 客户端提问：*"查询各渠道的订单总额"*——Agent 会发现 `example` 工作区，并调用 `total_amount` 等指标按 `channel` 分组查询。

### 5. 管理语义模型

**Web UI**（`/mcp/web`）：新建/上传/编辑 YAML 模型 → **Validate** → **Commit**。只有验证通过的模型才会生效。

**CLI 客户端：**

```bash
export DORIS_MCP_SERVER=http://<host>:3000
export DORIS_MCP_TOKEN=<user>:<password>

./mcp-client.sh semantic push ./models -w my_workspace
./mcp-client.sh semantic pull -o ./backup -w my_workspace
./mcp-client.sh tool call list_metrics --json '{"workspace":"my_workspace"}'
```

## Agent 查询数据的流程

```
get_query_guide()              ← 1. 获取工作流指引（必调）
check_service_health()         ← 2. Doris 连通性 + 工作区状态
    │
    ├─ 语义层 healthy ──→ list_metrics → list_dimensions_for_metric → query_metric
    │                      （计数、求和、比率、排名、趋势）
    └─ 无匹配指标 ──────→ list_databases → list_tables → describe_table → execute_query
                           （裸 SQL 兜底，只读校验）
```

## 配置说明（`mcp-server.toml`）

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `server.mcp_host` / `server.mcp_port` | `0.0.0.0` / `3000` | HTTP 监听地址 |
| `server.fe_port` | `9030` | Doris FE MySQL 端口（同机） |
| `server.admin_users` | `["admin"]` | 可管理模型、部署 example 的用户列表 |
| `server.seed_example` | `false` | Admin 首次登录时自动部署 example |
| `server.privateIp` | 未设置 | 可选。所有节点填同一个 IP，将该节点固定为 Web UI 入口，全部 `/mcp/web` 请求（含登录）转发到该节点 |
| `query.db_whitelist` | `[]` | 可选的库白名单 |
| `query.query_timeout_seconds` | `600` | SQL 查询超时 |
| `query.query_max_rows` | `10000` | 单次查询最大返回行数 |

所有配置值支持 `${ENV_VAR}` 环境变量插值。

## 多机部署

多台 MCP Server 挂在同一负载均衡后即可工作：Web UI 会话由应用层按 Cookie 后缀 IP 自动转发，nginx 无需任何 Cookie 解析配置。

如需固定 Web UI 入口节点，在所有节点的 `mcp-server.toml` 填同一个 `privateIp`：

```toml
[server]
privateIp = "10.0.0.13"   # 所有节点填同一个 IP
```

此时全部 `/mcp/web` 请求（含登录）都会转发到该节点；`/mcp` MCP 协议流量仍由各节点本地处理。详见 [DESIGN.md](DESIGN.md) §8.3。

## 源码构建

```bash
./build.sh linux-x64      # Linux x86_64
./build.sh linux-arm64    # Linux ARM64（信创）
./build.sh macos-arm64    # macOS Apple Silicon
./build.sh clean          # 清理构建产物
```

构建会下载 Python 3.10 standalone 并生成自包含 tar.gz 到 `dist/`。GitHub 不可达时使用本地 Python 3.10：

```bash
DORIS_MCP_SYSTEM_PYTHON=/opt/miniconda3/bin/python ./build.sh linux-x64
```

**CI 发版**（`.github/workflows/release.yml`）：推送 `doris-mcp-server-x.y.z` 格式的 tag，自动构建 linux-x64 + linux-arm64 两个包并发布对应版本的 GitHub Release；也可以在 Actions 页面手动触发。

## 运行测试

```bash
bash test/run_all_tests.sh --offline   # 离线单元测试，无需启动服务
bash test/run_all_tests.sh --smoke     # 冒烟测试（快速）
bash test/run_all_tests.sh             # 全部测试（需本地 MCP Server）
```

## 文档

*   [DESIGN.md](DESIGN.md) — 架构设计与关键决策
*   [INSTALL.html](INSTALL.html) — 安装指南
*   [doris-mcp-docs.html](doris-mcp-docs.html) — 语义模型参考与用户指南
*   [README.md](README.md) — English Documentation

## License

基于 [Apache License, Version 2.0](LICENSE.txt) 开源。
本发行版内置了 MetricFlow（`src/metricflow/`），其许可证见 `src/metricflow/LICENSE` 与 `src/metricflow/NOTICE`。
