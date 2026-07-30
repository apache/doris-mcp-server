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

[English](README.md) | 简体中文

Doris MCP Server 是一个基于 Python 和 FastAPI 的
[Model Context Protocol（MCP）](https://modelcontextprotocol.io/) 服务。
它把 Apache Doris 的查询、元数据和分析能力以 MCP 工具、资源和提示词的形式
提供给 AI 客户端，可用于 NL2SQL、查询执行、元数据检索、性能分析和数据治理等
场景。

这份中文文档覆盖安装、启动、鉴权、客户端接入和常见排障。完整配置项、工具清单
和高级安全说明以[英文 README](README.md) 为准。

## 发布状态

当前包版本和最新 Git 标签为 `0.6.1`。`master` 分支还包含标签之后、尚未发布的
变更，这些内容记录在 [CHANGELOG 的 Unreleased 小节](CHANGELOG.md#unreleased)。

`master` 分支上的 MCP `2026-07-28` 协议兼容性已在 Streamable HTTP 和 stdio
两种传输上达到 GA。这个结论仅指协议兼容性；项目包元数据仍为 **Beta**，部署前
仍需评估[英文文档中的部署限制](README.md#deployment-constraints)。

## 核心能力

- 通过 Streamable HTTP 或 stdio 提供 MCP 服务；
- 执行 Doris SQL，并控制返回行数、响应大小和查询超时；
- 浏览 catalog、database、table、column、index 等元数据；
- 提供 SQL Explain、Profile、列分析、质量分析和监控工具；
- 支持 Doris 内部表及 Hive、MySQL 等外部 Catalog；
- 支持静态 Token、JWT、外部 OAuth/OIDC 和 Doris 账号驱动的 OAuth；
- 支持 Token 绑定独立 Doris 连接，避免不同租户共用数据库身份；
- 提供 SQL 安全检查、数据脱敏、审计日志和应用层权限控制；
- 对 `tools/list`、`resources/list`、`prompts/list` 提供有界分页；
- 支持 MCP `2026-07-28` 的无状态请求模型和请求级 Trace Context。

工具的唯一事实来源是
[`ToolDefinitionRegistry`](docs/tool-registry.md)。客户端应通过
`tools/list` 获取当前运行版本实际提供的工具和 JSON Schema，不要依赖手写的
静态工具列表。

## 运行要求

- Python 3.12 或更高版本；
- 可访问的 Apache Doris FE MySQL 端口，默认端口为 `9030`；
- 如需 Profile、表大小或 FE HTTP 工具，还需访问 FE HTTP 端口，默认 `8030`；
- 如需 BE 监控工具，应显式配置允许访问的 BE HTTP 地址。

## 快速开始

### 从 PyPI 安装

```bash
pip install doris-mcp-server==0.6.1
```

安装后会提供两个命令：

- `doris-mcp-server`：启动 MCP 服务；
- `doris-mcp-client`：连接已经启动的 MCP 服务。

这两个命令不能互相替代。

### 配置 Doris 连接

```bash
export DORIS_HOST=127.0.0.1
export DORIS_PORT=9030
export DORIS_USER=root
export DORIS_PASSWORD='your_password'
export DORIS_DATABASE=information_schema
```

也可以复制项目中的示例文件：

```bash
cp .env.example .env
```

然后在 `.env` 中填写连接参数。不要提交包含真实密码、Token 或客户端密钥的
`.env` 文件。

### 启动 Streamable HTTP

```bash
doris-mcp-server \
  --transport http \
  --host 127.0.0.1 \
  --port 3000 \
  --db-host 127.0.0.1 \
  --db-port 9030 \
  --db-user root \
  --db-password 'your_password'
```

服务端点：

- MCP：`POST http://127.0.0.1:3000/mcp`
- 存活检查：`GET http://127.0.0.1:3000/live`
- 就绪检查：`GET http://127.0.0.1:3000/ready`
- 兼容存活检查：`GET http://127.0.0.1:3000/health`

`/live` 只说明进程和协议服务正在运行；`/ready` 还会在短超时内执行 Doris
`SELECT 1`。因此 `/live` 返回 200、`/ready` 返回 503 时，应优先检查 Doris
连接，而不是重启 MCP 进程。

默认应绑定回环地址。若绑定非回环地址，服务启动时必须启用至少一种鉴权方式。
`ALLOW_UNAUTHENTICATED_NON_LOOPBACK=true` 只适合隔离的临时测试环境。

### 启动 stdio

```bash
doris-mcp-server --transport stdio
```

stdio 模式通常由 Cursor、Kiro 等 MCP 客户端直接拉起。stdout 专用于 MCP
协议消息，不要向 stdout 输出日志或调试文本。

### 验证安装

```bash
doris-mcp-server --version
doris-mcp-client --version
doris-mcp-server --help
curl --fail http://127.0.0.1:3000/live
curl --fail http://127.0.0.1:3000/ready
```

## 常用配置

### Doris 与查询

| 环境变量 | 用途 | 默认值 |
|:---------|:-----|:-------|
| `DORIS_HOST` | Doris FE MySQL 主机 | `localhost` |
| `DORIS_PORT` | Doris FE MySQL 端口 | `9030` |
| `DORIS_USER` | Doris 用户 | `root` |
| `DORIS_PASSWORD` | Doris 密码 | 空 |
| `DORIS_DATABASE` | 默认数据库 | `information_schema` |
| `DORIS_MIN_CONNECTIONS` | 最小连接数 | `5` |
| `DORIS_MAX_CONNECTIONS` | 最大连接数 | `20` |
| `DORIS_FE_HTTP_HOST` | FE HTTP 工具使用的主机 | 回退到 `DORIS_HOST` |
| `DORIS_FE_HTTP_PORT` | FE HTTP 端口 | `8030` |
| `DORIS_BE_HOSTS` | BE HTTP 主机白名单 | 空，表示禁用 BE HTTP 指标 |
| `MAX_RESULT_ROWS` | 查询返回行数上限 | `10000` |
| `DEFAULT_RESULT_ROWS` | 未传 `max_rows` 时的默认行数 | `100` |
| `QUERY_TIMEOUT` | 查询超时上限，单位秒 | `300` |
| `MAX_RESULT_BYTES` | 查询结果 UTF-8 JSON 大小上限 | `1048576` |

### MCP 与 HTTP

| 环境变量 | 用途 | 默认值 |
|:---------|:-----|:-------|
| `MCP_LIST_PAGE_SIZE` | 列表接口单页上限 | `100` |
| `MCP_STATE_HANDLE_TTL_SECONDS` | 显式状态句柄有效期 | `300` |
| `MCP_STATE_HANDLE_SECRET` | 多副本共享的状态句柄签名密钥 | 启动时生成 |
| `MCP_ALLOWED_HOSTS` | HTTP Host 白名单 | 回环地址 |
| `ENABLE_LEGACY_HTTP_ADAPTER` | 启用 `/mcp/legacy` 迁移端点 | `false` |

多副本经负载均衡提供分页时，应配置同一个高强度
`MCP_STATE_HANDLE_SECRET`。分页 Cursor 是带签名的状态句柄，客户端不应解析或
自行构造。

## MCP 2026-07-28 协议

### 兼容矩阵

| 客户端协议 | Streamable HTTP | stdio | 说明 |
|:-----------|:----------------|:------|:-----|
| `2026-07-28` | 支持并推荐 | 支持并推荐 | 无状态、请求自包含，不依赖初始化会话 |
| `2025-11-25` | 仅按需启用 `/mcp/legacy` | 支持迁移 | 兼容初始化流程，但不创建 HTTP 协议会话 |
| `2025-06-18` 及更早 | 不保证 | 不保证 | 应先升级客户端 |
| HTTP+SSE `2024-11-05` | 不支持 | 不适用 | 使用 `POST /mcp` 迁移到 Streamable HTTP |

现代请求必须在 `params._meta` 中携带：

- `io.modelcontextprotocol/protocolVersion`
- `io.modelcontextprotocol/clientCapabilities`
- 建议携带 `io.modelcontextprotocol/clientInfo`

HTTP 请求还必须携带与消息体一致的 `MCP-Protocol-Version` 和 `Mcp-Method`。
调用具名工具、资源或提示词时还需携带 `Mcp-Name`。完整请求示例和错误码见
[英文协议说明](README.md#mcp-2026-07-28-request-contract)。

从 `2025-11-25` 迁移时：

1. 升级到支持 `2026-07-28` 的 MCP SDK；
2. 每个 HTTP JSON-RPC 消息使用一次独立的 `POST /mcp`；
3. 移除 `initialize`、`notifications/initialized`、`Mcp-Session-Id` 和粘性会话；
4. 为每次请求补齐 `_meta` 和必要 HTTP 头；
5. 不再使用 HTTP GET 流、`Last-Event-ID` 或可恢复 SSE；
6. 同时验证 Streamable HTTP 和 stdio。

暂时不能迁移的 `2025-11-25` HTTP 客户端，需由运维显式设置
`ENABLE_LEGACY_HTTP_ADAPTER=true`，并改用 `/mcp/legacy`。现代 `/mcp` 端点
不会自动降级。

## 鉴权与数据权限

### 静态 Token

生成高强度 Token，并通过 `TOKEN_<ID>` 提供：

```bash
export ENABLE_TOKEN_AUTH=true
export TOKEN_ADMIN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
doris-mcp-server --transport http --host 127.0.0.1 --port 3000
```

客户端通过请求头发送：

```text
Authorization: Bearer <TOKEN_ADMIN 的实际值>
```

仓库不附带可用的默认 Token。启用静态 Token 后，如果没有至少一个有效、
不少于 32 个字符的 `TOKEN_<ID>`，服务会拒绝启动。

### Token 管理接口

HTTP Token 管理默认关闭，并且应只在本机开放：

```bash
export ENABLE_TOKEN_AUTH=true
export ENABLE_HTTP_TOKEN_MANAGEMENT=true
export TOKEN_MANAGEMENT_ADMIN_TOKEN="$(
  python -c 'import secrets; print(secrets.token_urlsafe(32))'
)"
export TOKEN_MANAGEMENT_ALLOWED_IPS=127.0.0.1,::1
```

管理 Token 只能放在 `Authorization` 请求头中，不能放在 URL 查询参数里：

```bash
curl \
  -H "Authorization: Bearer $TOKEN_MANAGEMENT_ADMIN_TOKEN" \
  http://127.0.0.1:3000/token/stats
```

### Token 绑定 Doris 连接

一个静态 Token 可以绑定一套独立的 Doris 主机、用户、密码和默认数据库。
请求通过该 Token 鉴权后，数据库操作使用它自己的连接池，不回退到全局服务账号。
这适合多租户或按客户隔离 Doris 身份的部署。

`tokens.json` v2 只保存 Bearer Token 的摘要，不保存可恢复的明文。托管创建接口
只返回一次明文，调用方必须立即存入客户端密钥存储。手工配置示例、迁移规则和
文件格式见[英文 Token 绑定说明](README.md#token-bound-database-configuration-new-in-v060)。

### 外部 OAuth/OIDC

外部 OAuth 使用受信任的 RFC 7662 Introspection 端点校验访问 Token，并检查
issuer、audience、resource、scope、subject 和有效期。用户信息接口不能单独
证明 Token 是为本 MCP 服务签发的。

最少需要配置：

```bash
export ENABLE_OAUTH_AUTH=true
export OAUTH_CLIENT_ID=your_client_id
export OAUTH_CLIENT_SECRET=your_client_secret
export OAUTH_ISSUER=https://issuer.example.com
export OAUTH_RESOURCE=https://mcp.example.com/mcp
export OAUTH_AUDIENCE=https://mcp.example.com/mcp
export OAUTH_INTROSPECTION_URL=https://issuer.example.com/introspect
export OAUTH_USERINFO_URL=https://issuer.example.com/userinfo
```

远程 issuer、discovery、introspection 和 userinfo URL 必须使用 HTTPS。
工具调用使用精确 scope，例如 `tool:list` 和
`tool:call:exec_query`；通配符不会满足操作权限。

### Doris 账号驱动的 OAuth

`ENABLE_DORIS_OAUTH_AUTH=true` 会让 Doris 自身成为用户认证和数据授权后端。
用户登录后，服务为该 Doris 用户创建独立连接池，`doa_` Token 的查询使用这个
用户的 Doris 身份：

- MCP scope 决定能调用哪些 MCP 操作；
- Doris RBAC 决定能访问哪些 Catalog、数据库、表、列和数据行。

该模式不能与外部 OAuth 同时启用，目前要求 `WORKERS=1`。Token、OAuth 客户端、
授权事务和用户连接池保存在进程内，进程重启后用户需要重新登录。生产配置和工具
开放边界见[英文 Doris OAuth 说明](README.md#doris-backed-oauth-authentication)。

### 权限边界

MCP 的角色、scope、安全级别、SQL 检查和数据脱敏属于应用层控制，不能替代
Doris 数据权限。生产环境必须使用 Doris 用户、角色、GRANT、视图和行级策略
落实最小权限。即使 OAuth 角色映射允许调用 `exec_query`，最终能读取的数据仍应
由 Doris 拒绝或允许。完整 SQL、MCP 身份路由方式和验收清单见
[Doris 细粒度访问控制指南](docs/doris-fine-grained-access-control.md)。

最小配置示例：

```sql
CREATE ROLE mcp_orders_east_reader;
CREATE USER 'mcp_orders_east'@'10.%'
IDENTIFIED BY '<generated-high-entropy-password>';
GRANT 'mcp_orders_east_reader' TO 'mcp_orders_east'@'10.%';

GRANT SELECT_PRIV(order_id, region_id, order_total, created_at)
ON internal.sales.orders
TO ROLE 'mcp_orders_east_reader';

CREATE ROW POLICY mcp_orders_east_only
ON sales.orders
AS RESTRICTIVE
TO ROLE mcp_orders_east_reader
USING (region_id = 'east');
```

列权限目前只支持 `SELECT_PRIV`。同一用户或角色不能再保留表级、库级或全局
`SELECT_PRIV`，否则更宽的授权会使列限制失效。Row Policy、列权限和 Ranger
脱敏都不能使用默认的 `root`、`admin` 用户验收；必须使用真实的受限业务用户，
并通过 Token 绑定连接或 Doris OAuth 让 MCP 请求使用该用户的连接池。

不要在日志、URL、Issue 或 Pull Request 中暴露：

- Doris 密码；
- Bearer Token、JWT、OAuth access/refresh token；
- OAuth authorization code、PKCE verifier 和客户端密钥；
- `tokens.json` 中的真实数据库密码。

## Docker 部署

只构建 MCP Server 镜像：

```bash
docker build -t doris-mcp-server .
docker run -d \
  -p 3000:3000 \
  -v /absolute/path/to/.env:/app/.env \
  --name doris-mcp-server \
  doris-mcp-server:latest
```

使用仓库自带 Compose 前，先创建五个被 Git 忽略的密钥文件：

```bash
mkdir -p .secrets
chmod 700 .secrets
python -c 'import secrets; print(secrets.token_urlsafe(32))' > .secrets/doris_password
python -c 'import secrets; print(secrets.token_urlsafe(32))' > .secrets/mcp_static_token
python -c 'import secrets; print(secrets.token_urlsafe(32))' > .secrets/redis_password
python -c 'import secrets; print(secrets.token_urlsafe(32))' > .secrets/grafana_admin_password
python -c 'import hashlib, pathlib; p=pathlib.Path(".secrets/doris_password").read_text().rstrip("\n").encode(); print("initial_root_password = *" + hashlib.sha1(hashlib.sha1(p).digest()).hexdigest().upper())' > .secrets/doris_fe_custom.conf
chmod 0444 .secrets/*
docker compose up -d
```

默认 MCP 端口为 `3000`，Grafana 端口为 `3003`。可在启动时覆盖：

```bash
MCP_HTTP_PORT=3100 GRAFANA_HTTP_PORT=3103 docker compose up -d
```

镜像级健康检查使用 `/live`；Compose 使用 `/ready`，只有 Doris 探测成功才把
服务标记为就绪。不要用浮动的 `latest` 替换 Compose 中锁定版本和摘要的第三方
镜像。

## 连接 MCP 客户端

### Cursor：stdio

先安装 PyPI 包，然后在 Cursor 的 MCP 配置文件中加入：

```json
{
  "mcpServers": {
    "doris-stdio": {
      "command": "doris-mcp-server",
      "args": ["--transport", "stdio"],
      "env": {
        "DORIS_HOST": "127.0.0.1",
        "DORIS_PORT": "9030",
        "DORIS_USER": "root",
        "DORIS_PASSWORD": "your_db_password"
      }
    }
  }
}
```

### Cursor：Streamable HTTP

先独立启动 HTTP 服务，再配置：

```json
{
  "mcpServers": {
    "doris-http": {
      "url": "http://127.0.0.1:3000/mcp"
    }
  }
}
```

如果服务启用了鉴权，还需按客户端支持的密钥和请求头配置方式提供凭证。不要把
Bearer Token 拼到 URL 中。

Kiro 的配置结构与 stdio 示例相同，默认配置文件是
`~/.kiro/settings/mcp.json`，项目级配置可放在 `.kiro/settings/mcp.json`。

## 从源码开发

```bash
git clone https://github.com/apache/doris-mcp-server.git
cd doris-mcp-server
uv sync --frozen --group dev
cp .env.example .env
```

常用检查：

```bash
uv run pytest -q -W error
uv run ruff check .
uv run mypy doris_mcp_server
uv run bandit -q -c pyproject.toml -r doris_mcp_server
```

新增工具时，应同时更新：

1. 工具实现；
2. `ToolDefinitionRegistry` 中的定义；
3. 输入和输出 JSON Schema；
4. 权限与审计元数据；
5. 单元测试及必要的真实 Doris 集成测试。

详细流程见[英文开发指南](README.md#developing-new-tools)。

## 常见问题

### `/live` 正常，但 `/ready` 返回 503

进程正常，Doris 探测失败。检查 `DORIS_HOST`、`DORIS_PORT`、账号密码、默认
数据库、网络和 Doris FE 状态。不要只通过反复重启服务掩盖连接问题。

### 非本机地址无法启动

非回环监听必须启用鉴权。优先启用静态 Token、外部 OAuth 或 Doris OAuth。
仅在隔离测试环境中使用 `ALLOW_UNAUTHENTICATED_NON_LOOPBACK=true`。

### 反向代理后收到 Host 或 Origin 拒绝

显式设置允许的域名和端口，例如：

```bash
export MCP_ALLOWED_HOSTS='mcp.example.com,mcp.example.com:*'
```

不接受允许全部来源的 `*`。对外流量必须使用 HTTPS，并只在受控代理后启用代理
请求头信任。

### Token 鉴权失败

确认 Token：

- 至少 32 个字符并有足够随机性；
- 未过期且处于启用状态；
- 通过 `Authorization: Bearer ...` 传递；
- 与 `tokens.json` 中摘要或对应 `TOKEN_<ID>` 一致；
- 没有把管理 Token 和业务访问 Token 混用。

### 查询超时或结果过大

检查 `QUERY_TIMEOUT`、`MAX_RESULT_ROWS`、`DEFAULT_RESULT_ROWS`、
`MAX_RESULT_BYTES` 和工具调用中的 `max_rows`。限制是部署上限，客户端不能通过
参数突破。还应检查 SQL 执行计划、Doris 资源组和网络情况。

### stdio 客户端无法解析响应

确认服务进程没有向 stdout 输出日志、banner 或调试信息。stdio 的 stdout
只能包含 MCP 协议消息；日志应写入 stderr 或日志文件。

### 老客户端仍在使用 SSE 或 Session ID

独立 HTTP+SSE 端点已经移除。升级客户端并改用无状态 `POST /mcp`。仅在迁移期
为 `2025-11-25` 客户端显式启用 `/mcp/legacy`，不要让新客户端依赖该端点。

## 参与贡献

欢迎通过 [Issues](https://github.com/apache/doris-mcp-server/issues) 和
[Pull Requests](https://github.com/apache/doris-mcp-server/pulls) 提交问题、
修复和改进。提交前请运行与变更范围匹配的测试和质量检查，并确保没有提交密码、
Token、`.env`、本地审计文档或其他内部资料。

## 许可证

本项目使用 [Apache License 2.0](LICENSE)。
