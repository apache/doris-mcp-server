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

[English](../../README.md) | [简体中文](README.zh-CN.md)

> 如中英文内容存在差异，以英文版 `README.md` 为准。

Doris MCP (Model Context Protocol) Server 是一个基于 Python 和 FastAPI 构建的后端服务，实现了 MCP 协议，客户端可以通过它暴露的 Tools、Resources 和 Prompts 与 Apache Doris 进行交互。它主要用于连接 Apache Doris 数据库，并可配合大语言模型完成 NL2SQL、SQL 执行、元数据管理和分析等任务。

## 🚀 v0.6.0 新特性

- **🔐 企业级认证体系**：支持 Token、JWT 和 OAuth，提供令牌绑定数据库配置能力，适合多租户场景。
- **⚡ 数据库即时校验**：在连接阶段实时校验数据库配置，避免查询阶段才暴露错误。
- **🔄 热加载配置管理**：`tokens.json` 支持无停机热更新、自动校验和失败回滚。
- **🏗️ 连接架构升级**：会话缓存、连接池优化和自动资源管理降低连接开销。
- **🌐 多 Worker 扩展能力**：支持无状态多 worker 水平扩展，适合并发和生产部署。
- **🔒 安全框架增强**：包含鉴权、授权、SQL 安全校验、注入检测和数据脱敏。
- **🛠️ 统一配置体系**：统一命令行参数、环境变量和 Docker 配置行为。
- **📊 Token 管理面板**：支持令牌创建、吊销、统计和审计。
- **🌐 Web 管理界面**：提供仅限 localhost 的 Token 管理界面，便于日常运维。

> v0.6.0 使该项目从一个通用 MCP Server，演进为可用于生产环境的 Doris 企业级认证与数据库管理服务。

### v0.5.1 同样包含的重要能力

- **🔥 `at_eof` 连接问题修复**：通过连接池重构和健康检查机制显著提升稳定性。
- **🔧 增强日志系统**：按级别拆分日志文件、自动清理、毫秒级时间戳。
- **📊 高级数据分析工具集**：新增 7 个企业级数据治理工具。
- **🏃‍♂️ ADBC 高性能集成**：基于 Apache Arrow Flight SQL，在大数据集传输上可获得 3-10 倍性能提升。
- **⚙️ 配置管理增强**：完善 ADBC 配置和参数校验。

## 核心能力

- **MCP 协议实现**：提供标准 MCP 接口，支持 Tools、Resources 和 Prompts。
- **Streamable HTTP 通信**：统一 HTTP 端点，同时支持请求响应和流式通信。
- **Stdio 通信**：适合和 Cursor 等 MCP 客户端直接集成。
- **企业级模块化架构**：
  - **Tools Manager**：集中式工具注册与路由。
  - **Monitoring Tools**：内存跟踪、监控指标采集、BE 节点发现。
  - **Query Information Tools**：SQL Explain/Profile、内容截断和文件导出。
  - **Resources Manager**：数据库元数据暴露。
  - **Prompts Manager**：数据分析 Prompt 模板管理。
- **数据库能力增强**：
  - **查询执行**：高性能 SQL 执行、缓存和自动重试。
  - **安全管理**：SQL 安全校验、关键字拦截、脱敏和统一安全配置。
  - **元数据提取**：支持 catalog federation 的元数据查询。
  - **性能分析**：列分析、性能监控、数据分析工具。
- **Catalog Federation**：支持 internal Doris 表和 Hive、MySQL 等外部 catalog。
- **企业安全能力**：认证、授权、SQL 注入防护、数据脱敏。
- **Web Token 管理**：提供仅限本机访问的 Token 生命周期管理界面。
- **统一配置框架**：通过 `config.py` 做集中式配置管理和校验。

## 系统要求

- **Python**：3.12+
- **数据库**：Apache Doris 实例，以及对应的 Host、Port、User、Password、Database 配置

## 🚀 快速开始

### 从 PyPI 安装

```bash
# 安装最新版
pip install doris-mcp-server

# 安装指定版本
pip install doris-mcp-server==0.6.0
```

> 安装完成后，`doris-mcp-server` 命令即可直接使用。

### 启动 Streamable HTTP 模式

这是默认推荐的服务模式，适合 web 场景和多客户端接入：

```bash
doris-mcp-server \
    --transport http \
    --host 0.0.0.0 \
    --port 3000 \
    --db-host 127.0.0.1 \
    --db-port 9030 \
    --db-user root \
    --db-password your_password
```

### 启动 Stdio 模式

适合被 Cursor 等 MCP 客户端直接托管：

```bash
doris-mcp-server --transport stdio
```

### 🌐 Token 管理界面

v0.6.0 新增 Web Token 管理面板，适合本机管理 Token 生命周期。

#### 安全访问要求

- **仅允许 localhost 访问**：默认限制在 `127.0.0.1` 和 `::1`
- **需要管理员认证**：通过 `TOKEN_MANAGEMENT_ADMIN_TOKEN` 控制
- **建议开启 Token 认证**：避免暴露无保护的管理接口

```bash
ENABLE_HTTP_TOKEN_MANAGEMENT=true
ENABLE_TOKEN_AUTH=true
TOKEN_MANAGEMENT_ADMIN_TOKEN=your_secure_admin_token
TOKEN_MANAGEMENT_ALLOWED_IPS=127.0.0.1,::1
```

#### 访问地址

```text
http://localhost:3000/token/management?admin_token=your_secure_admin_token
```

#### 支持的操作

- 查看 Token 实时统计信息
- 创建 Token，并绑定数据库连接参数
- 列出、吊销、清理过期 Token
- 所有操作自动持久化到 `tokens.json`

### 校验安装

```bash
# 查看帮助
doris-mcp-server --help

# 另开一个终端做健康检查
curl http://localhost:3000/health
```

### 环境变量

你也可以通过环境变量传参。下面列出最常用的一组：

```bash
# 基础数据库配置
export DORIS_HOST="127.0.0.1"
export DORIS_PORT="9030"
export DORIS_USER="root"
export DORIS_PASSWORD="your_password"

# Token 管理界面
export ENABLE_HTTP_TOKEN_MANAGEMENT=true
export ENABLE_TOKEN_AUTH=true
export TOKEN_MANAGEMENT_ADMIN_TOKEN="your_secure_admin_token"
export TOKEN_MANAGEMENT_ALLOWED_IPS="127.0.0.1,::1"

# 用简化命令启动
doris-mcp-server --transport http --host 0.0.0.0 --port 3000
```

#### 关键环境变量

- **数据库连接**
  - `DORIS_HOST`：数据库地址，默认 `localhost`
  - `DORIS_PORT`：数据库端口，默认 `9030`
  - `DORIS_USER`：数据库用户名，默认 `root`
  - `DORIS_PASSWORD`：数据库密码
  - `DORIS_DATABASE`：默认数据库，默认 `information_schema`
  - `DORIS_MIN_CONNECTIONS`：连接池最小连接数
  - `DORIS_MAX_CONNECTIONS`：连接池最大连接数
  - `DORIS_BE_HOSTS`：监控使用的 BE 节点列表，逗号分隔
  - `DORIS_BE_WEBSERVER_PORT`：BE Webserver 端口，默认 `8040`
- **认证配置**
  - `ENABLE_TOKEN_AUTH`：是否启用 Token 认证
  - `ENABLE_JWT_AUTH`：是否启用 JWT 认证
  - `ENABLE_OAUTH_AUTH`：是否启用 OAuth 认证
  - `TOKEN_FILE_PATH`：`tokens.json` 路径
  - `TOKEN_HOT_RELOAD`：是否启用 Token 热加载
  - `DEFAULT_ADMIN_TOKEN`：默认管理员 Token
  - `DEFAULT_ANALYST_TOKEN`：默认分析师 Token
  - `DEFAULT_READONLY_TOKEN`：默认只读 Token
- **安全配置**
  - `ENABLE_SECURITY_CHECK`：是否启用 SQL 安全校验
  - `BLOCKED_KEYWORDS`：禁止 SQL 关键字列表
  - `ENABLE_MASKING`：是否启用数据脱敏
  - `MAX_RESULT_ROWS`：最大返回行数
- **ADBC 配置**
  - `ADBC_ENABLED`：是否启用 ADBC 工具
  - `ADBC_DEFAULT_MAX_ROWS`：ADBC 默认返回行数
  - `ADBC_DEFAULT_TIMEOUT`：ADBC 默认超时秒数
  - `ADBC_DEFAULT_RETURN_FORMAT`：返回格式，支持 `arrow`、`pandas`、`dict`
- **性能配置**
  - `ENABLE_QUERY_CACHE`：是否启用查询缓存
  - `CACHE_TTL`：缓存 TTL
  - `MAX_CONCURRENT_QUERIES`：最大并发查询数
  - `MAX_RESPONSE_CONTENT_SIZE`：LLM 兼容的最大返回内容大小
- **日志配置**
  - `LOG_LEVEL`：日志级别
  - `LOG_FILE_PATH`：日志目录
  - `ENABLE_AUDIT`：是否启用审计日志
  - `ENABLE_LOG_CLEANUP`：是否启用自动清理
  - `LOG_MAX_AGE_DAYS`：日志保留天数
  - `LOG_CLEANUP_INTERVAL_HOURS`：清理检查周期

### 命令行参数

`doris-mcp-server` 支持如下常用参数：

| 参数 | 说明 | 默认值 | 必填 |
|:-----|:-----|:-------|:-----|
| `--transport` | 传输模式，`http` 或 `stdio` | `http` | 否 |
| `--host` | HTTP 服务绑定地址 | `0.0.0.0` | 否 |
| `--port` | HTTP 服务端口 | `3000` | 否 |
| `--db-host` | Doris 地址 | `localhost` | 否 |
| `--db-port` | Doris 端口 | `9030` | 否 |
| `--db-user` | Doris 用户名 | `root` | 否 |
| `--db-password` | Doris 密码 | 无 | 是，除非已通过环境变量传入 |

## 开发环境搭建

### 1. 克隆仓库

```bash
git clone https://github.com/apache/doris-mcp-server.git
cd doris-mcp-server
```

### 2. 安装依赖

```bash
pip install -r requirements.txt
```

### 3. 配置环境变量

复制 `.env.example` 到 `.env`，然后按本地环境修改：

```bash
cp .env.example .env
```

### 可用 MCP Tools

下面是当前主工具的概览：

| Tool 名称 | 说明 | 参数 |
|:----------|:-----|:-----|
| `exec_query` | 执行 SQL 并返回结果 | `sql`、`db_name`、`catalog_name`、`max_rows`、`timeout` |
| `get_table_schema` | 获取表结构详情 | `table_name`、`db_name`、`catalog_name` |
| `get_db_table_list` | 获取数据库表列表 | `db_name`、`catalog_name` |
| `get_db_list` | 获取数据库列表 | `catalog_name` |
| `get_table_comment` | 获取表注释 | `table_name`、`db_name`、`catalog_name` |
| `get_table_column_comments` | 获取列注释 | `table_name`、`db_name`、`catalog_name` |
| `get_table_indexes` | 获取表索引信息 | `table_name`、`db_name`、`catalog_name` |
| `get_recent_audit_logs` | 获取近期审计日志 | `days`、`limit` |
| `get_catalog_list` | 获取 catalog 列表 | `random_string` |
| `get_sql_explain` | 获取 SQL 执行计划 | `sql`、`verbose`、`db_name`、`catalog_name` |
| `get_sql_profile` | 获取 SQL Profile | `sql`、`db_name`、`catalog_name`、`timeout` |
| `get_table_data_size` | 通过 FE HTTP API 获取表大小 | `db_name`、`table_name`、`single_replica` |
| `get_monitoring_metrics_info` | 获取监控指标定义 | `role`、`monitor_type`、`priority` |
| `get_monitoring_metrics_data` | 获取实际监控指标数据 | `role`、`monitor_type`、`priority` |
| `get_realtime_memory_stats` | 获取实时内存统计 | `tracker_type`、`include_details` |
| `get_historical_memory_stats` | 获取历史内存统计 | `tracker_names`、`time_range` |
| `analyze_data_quality` | 数据质量分析 | `table_name`、`analysis_scope`、`sample_size`、`business_rules` |
| `trace_column_lineage` | 列血缘分析 | `target_columns`、`analysis_depth`、`include_transformations` |
| `monitor_data_freshness` | 数据新鲜度监控 | `table_names`、`freshness_threshold_hours`、`include_update_patterns` |
| `analyze_data_access_patterns` | 访问行为与安全异常分析 | `days`、`include_system_users`、`min_query_threshold` |
| `analyze_data_flow_dependencies` | 数据流依赖和影响分析 | `target_table`、`analysis_depth`、`include_views` |
| `analyze_slow_queries_topn` | 慢查询 TopN 分析 | `days`、`top_n`、`min_execution_time_ms`、`include_patterns` |
| `analyze_resource_growth_curves` | 资源增长曲线分析 | `days`、`resource_types`、`include_predictions` |
| `exec_adbc_query` | 使用 ADBC 执行高性能 SQL | `sql`、`max_rows`、`timeout`、`return_format` |
| `get_adbc_connection_info` | 获取 ADBC 连接诊断信息 | 无参数 |

> 所有元数据工具都支持多 catalog 环境。v0.5.0 起新增 7 个高级分析工具和 2 个 ADBC 工具。

### 4. 启动服务

```bash
./start_server.sh
```

该命令会启动带有 Streamable HTTP MCP 服务的 FastAPI 应用。

### 5. Docker 部署

如果你想只在 Docker 中运行 Doris MCP Server：

```bash
cd doris-mcp-server
docker build -t doris-mcp-server .
docker run -d -p <port>:<port> -v /*your-host*/doris-mcp-server/.env:/app/.env --name <your-mcp-server-name> -it doris-mcp-server:latest
```

**服务端点**

- **Streamable HTTP**：`http://<host>:<port>/mcp`
- **Health Check**：`http://<host>:<port>/health`

> Streamable HTTP 是统一的 web 通信接口，支持请求响应和流式处理。

## 使用方式

要与 Doris MCP Server 交互，需要一个 **MCP Client**。客户端连接到 `/mcp` 端点，并按 MCP 协议调用工具。

### 基本交互流程

1. 客户端向 `/mcp` 发送 `initialize`
2. 可选地调用 `tools/list` 查看工具列表
3. 通过 `tools/call` 传入 `name` 和 `arguments`
4. 处理结果：
   - 非流式：直接拿到 `content` 或 `isError`
   - 流式：先收到进度通知，再收到最终结果

### Catalog Federation 支持

Doris MCP Server 支持 **catalog federation**，可以在一个统一接口中访问 internal Doris 表和外部数据源。

#### 关键能力

- 所有元数据工具支持 `catalog_name`
- SQL 支持跨 catalog 查询
- 可通过 `get_catalog_list` 发现可用 catalog

#### 三段式命名要求

所有 SQL 里的表引用都必须使用三段式命名：

- **内部表**：`internal.database_name.table_name`
- **外部表**：`catalog_name.database_name.table_name`

#### 示例

1. **获取 catalog 列表**

```json
{
  "tool_name": "get_catalog_list",
  "arguments": {"random_string": "unique_id"}
}
```

2. **获取指定 catalog 下的数据库**

```json
{
  "tool_name": "get_db_list",
  "arguments": {"random_string": "unique_id", "catalog_name": "mysql"}
}
```

3. **查询 internal catalog**

```json
{
  "tool_name": "exec_query",
  "arguments": {
    "random_string": "unique_id",
    "sql": "SELECT COUNT(*) FROM internal.ssb.customer"
  }
}
```

4. **查询外部 catalog**

```json
{
  "tool_name": "exec_query",
  "arguments": {
    "random_string": "unique_id",
    "sql": "SELECT COUNT(*) FROM mysql.ssb.customer"
  }
}
```

5. **跨 catalog 查询**

```json
{
  "tool_name": "exec_query",
  "arguments": {
    "random_string": "unique_id",
    "sql": "SELECT i.c_name, m.external_data FROM internal.ssb.customer i JOIN mysql.test.user_info m ON i.c_custkey = m.customer_id"
  }
}
```

## 安全配置

该项目包含完整的企业级安全框架，覆盖认证、授权、SQL 校验和数据脱敏。

### 安全能力概览

- **🔐 多认证体系**：支持 Token、JWT、OAuth，并可独立开关
- **🔗 Token 绑定数据库**：每个 Token 可绑定各自数据库配置
- **🔄 热加载**：安全配置可在不停机情况下更新
- **⚡ 即时校验**：连接时校验数据库和认证配置
- **🛡️ 分级授权**：支持四级安全分类和 RBAC
- **🚫 SQL 安全**：增强型 SQL 注入检测和关键字拦截
- **🎭 数据脱敏**：按用户权限自动脱敏
- **📊 安全审计**：完整审计日志和安全监控

### 认证配置

```bash
# 单独控制认证方式
ENABLE_TOKEN_AUTH=true
ENABLE_JWT_AUTH=false
ENABLE_OAUTH_AUTH=false

# Token 管理
TOKEN_FILE_PATH=tokens.json
TOKEN_HOT_RELOAD=true

# 默认 Token
DEFAULT_ADMIN_TOKEN=doris_admin_token_123456
DEFAULT_ANALYST_TOKEN=doris_analyst_token_123456
DEFAULT_READONLY_TOKEN=doris_readonly_token_123456
```

### Token 绑定数据库配置

在 `tokens.json` 中可以为每个 Token 绑定独立数据库连接：

```json
{
  "version": "1.0",
  "tokens": [
    {
      "token_id": "customer-a-token",
      "token": "customer_a_secure_token_12345",
      "description": "Customer A dedicated database access",
      "expires_hours": null,
      "is_active": true,
      "database_config": {
        "host": "customer-a-db.example.com",
        "port": 9030,
        "user": "customer_a_user",
        "password": "secure_password",
        "database": "customer_a_data",
        "charset": "UTF8",
        "fe_http_port": 8030
      }
    }
  ]
}
```

### 热加载配置更新

系统会自动检测并应用 `tokens.json` 的变化：

- 每 10 秒轮询文件变化
- 新 Token 会先做数据库连接校验
- 更新过程具备原子性
- 失败时自动回滚
- 所有变化都会写入审计日志

#### Token 认证示例

```python
auth_info = {
    "type": "token",
    "token": "your_jwt_token",
    "session_id": "unique_session_id"
}
```

#### Basic 认证示例

```python
auth_info = {
    "type": "basic",
    "username": "analyst",
    "password": "secure_password",
    "session_id": "unique_session_id"
}
```

### 授权与安全等级

系统支持四级安全分层：

| 安全级别 | 访问范围 | 典型场景 |
|:---------|:---------|:---------|
| **Public** | 无限制 | 公共报表、一般统计 |
| **Internal** | 企业内部 | 内部看板、业务指标 |
| **Confidential** | 授权人员 | 客户数据、财务报表 |
| **Secret** | 高级管理者 | 战略数据、敏感分析 |

#### 角色配置示例

```python
role_permissions = {
    "data_analyst": {
        "security_level": "internal",
        "permissions": ["read_data", "execute_query"],
        "allowed_tables": ["sales", "products", "orders"]
    },
    "data_admin": {
        "security_level": "confidential",
        "permissions": ["read_data", "execute_query", "admin"],
        "allowed_tables": ["*"]
    }
}
```

### SQL 安全校验

系统会自动校验 SQL 查询的风险。

#### 被禁止的操作

```bash
ENABLE_SECURITY_CHECK=true
BLOCKED_KEYWORDS="DROP,DELETE,TRUNCATE,ALTER,CREATE,INSERT,UPDATE,GRANT,REVOKE,EXEC,EXECUTE,SHUTDOWN,KILL"
MAX_QUERY_COMPLEXITY=100
```

默认会拦截：

- **DDL**：`DROP`、`CREATE`、`ALTER`、`TRUNCATE`
- **DML**：`DELETE`、`INSERT`、`UPDATE`
- **DCL**：`GRANT`、`REVOKE`
- **系统操作**：`EXEC`、`EXECUTE`、`SHUTDOWN`、`KILL`

#### SQL 注入防护

系统会自动检测并阻止：

- `UNION SELECT`
- `OR 1=1`
- `SLEEP()`、`WAITFOR`
- `--`、`/**/`
- 通过 `;` 拼接的多语句

#### 安全校验示例

```python
# 会被拦截
dangerous_sql = "SELECT * FROM users WHERE id = 1; DROP TABLE users;"

# 会被允许
safe_sql = "SELECT name, email FROM users WHERE department = 'sales'"
```

### 数据脱敏配置

#### 内置脱敏规则

```python
masking_rules = [
    {
        "column_pattern": r".*phone.*|.*mobile.*",
        "algorithm": "phone_mask",
        "parameters": {
            "mask_char": "*",
            "keep_prefix": 3,
            "keep_suffix": 4
        },
        "security_level": "internal"
    },
    {
        "column_pattern": r".*email.*",
        "algorithm": "email_mask",
        "parameters": {"mask_char": "*"},
        "security_level": "internal"
    }
]
```

#### 脱敏算法

| 算法 | 说明 | 示例 |
|:-----|:-----|:-----|
| `phone_mask` | 手机号脱敏 | `138****5678` |
| `email_mask` | 邮箱脱敏 | `j***n@example.com` |
| `id_mask` | 证件号脱敏 | `110101****1234` |
| `name_mask` | 姓名脱敏 | `张*明` |
| `partial_mask` | 按比例部分脱敏 | `abc***xyz` |

#### 自定义脱敏规则

```python
custom_rule = {
    "column_pattern": r".*salary.*|.*income.*",
    "algorithm": "partial_mask",
    "parameters": {
        "mask_char": "*",
        "mask_ratio": 0.6
    },
    "security_level": "confidential"
}
```

### 安全最佳实践

1. 使用强认证和带过期时间的 Token
2. 遵循最小权限原则
3. 打开审计日志，定期回看
4. 保持 SQL 校验开启
5. 为表和字段做好安全分级
6. 定期更新安全规则和配置

### 安全监控示例

```python
{
    "timestamp": "2024-01-15T10:30:00Z",
    "user_id": "analyst_user",
    "action": "query_execution",
    "resource": "customer_data",
    "result": "blocked",
    "reason": "insufficient_permissions",
    "risk_level": "medium"
}
```

> 生产部署前，建议先在开发环境完整验证安全配置。

## 与 Cursor 集成

你可以通过 Stdio 模式或 Streamable HTTP 模式接入 Cursor。

### Stdio 模式

Stdio 模式下，Cursor 会直接管理服务进程。

#### 方式一：使用 PyPI 安装

```bash
pip install doris-mcp-server
```

在 Cursor 的 MCP 配置中加入：

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

#### 方式二：使用 `uv`

```bash
uv run --project /path/to/doris-mcp-server doris-mcp-server
```

对应 Cursor 配置：

```json
{
  "mcpServers": {
    "doris-stdio": {
      "command": "uv",
      "args": ["run", "--project", "/path/to/your/doris-mcp-server", "doris-mcp-server"],
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

### Streamable HTTP 模式

1. 先在项目根目录配置好 `.env`
2. 启动服务：

```bash
./start_server.sh
```

3. 在 Cursor 中加入：

```json
{
  "mcpServers": {
    "doris-http": {
      "url": "http://127.0.0.1:3000/mcp"
    }
  }
}
```

## 目录结构

```text
doris-mcp-server/
├── doris_mcp_server/                 # 主服务包
│   ├── main.py                       # 入口和 FastAPI 应用
│   ├── multiworker_app.py            # 多 worker 应用模块
│   ├── auth/                         # 鉴权模块
│   ├── tools/                        # MCP tools 实现
│   ├── utils/                        # 工具模块
│   └── __init__.py
├── doris_mcp_client/                 # MCP 客户端实现
├── logs/                             # 日志目录
├── tokens.json                       # Token 配置文件
├── README.md                         # 英文文档
├── README.zh-CN.md                   # 中文文档
├── requirements.txt                  # Python 依赖
├── pyproject.toml                    # 项目配置
├── uv.lock                           # UV 锁文件
├── generate_requirements.py          # 依赖生成脚本
├── start_server.sh                   # 启动脚本
└── test/                             # 测试目录
```

## 开发新工具

### 1. 复用现有工具模块

建议优先使用这些基础能力：

- `doris_mcp_server/utils/db.py`：连接管理和连接池
- `doris_mcp_server/utils/query_executor.py`：SQL 执行、缓存、性能监控
- `doris_mcp_server/utils/schema_extractor.py`：元数据提取
- `doris_mcp_server/utils/security.py`：SQL 校验和脱敏
- `doris_mcp_server/utils/analysis_tools.py`：数据分析能力
- `doris_mcp_server/utils/config.py`：配置管理
- `doris_mcp_server/utils/data_governance_tools.py`：数据治理工具
- `doris_mcp_server/utils/data_quality_tools.py`：数据质量分析
- `doris_mcp_server/utils/adbc_query_tools.py`：Arrow Flight SQL 高性能访问

### 2. 实现工具逻辑

把工具实现加到 `doris_mcp_server/tools/tools_manager.py` 中：

```python
async def your_new_analysis_tool(self, arguments: Dict[str, Any]) -> List[Dict[str, Any]]:
    try:
        result = await self.query_executor.execute_sql_for_mcp(
            sql="SELECT COUNT(*) FROM your_table",
            max_rows=arguments.get("max_rows", 100)
        )

        return [{
            "type": "text",
            "text": json.dumps(result, ensure_ascii=False, indent=2)
        }]

    except Exception as e:
        logger.error(f"Tool execution failed: {str(e)}", exc_info=True)
        return [{
            "type": "text",
            "text": f"Error: {str(e)}"
        }]
```

### 3. 注册工具

在同一个类中把工具注册到 MCP：

```python
@self.mcp.tool(
    name="your_new_analysis_tool",
    description="Description of your new analysis tool",
    inputSchema={
        "type": "object",
        "properties": {
            "parameter1": {
                "type": "string",
                "description": "Description of parameter1"
            },
            "parameter2": {
                "type": "integer",
                "description": "Description of parameter2",
                "default": 100
            }
        },
        "required": ["parameter1"]
    }
)
async def your_new_analysis_tool_wrapper(arguments: Dict[str, Any]) -> List[Dict[str, Any]]:
    return await self.your_new_analysis_tool(arguments)
```

### 4. 高级能力

- 查询缓存
- 企业级安全校验
- Prompt 模板管理
- Resource 元数据暴露
- 性能监控能力接入

### 5. 测试

可通过内置 MCP Client 测试：

```python
from doris_mcp_client.client import DorisUnifiedMCPClient

async def test_new_tool():
    client = DorisUnifiedMCPClient()
    result = await client.call_tool("your_new_analysis_tool", {
        "parameter1": "test_value",
        "parameter2": 50
    })
    print(result)
```

## MCP Client

项目内置了统一 MCP Client，位于 `doris_mcp_client/`，便于联调和集成测试。

详细说明见 `doris_mcp_client/README.md`。

## 贡献

欢迎通过 Issue 或 Pull Request 参与贡献。

## License

本项目基于 Apache 2.0 License 发布，详见 `LICENSE` 文件。

## FAQ

### Q: 为什么 Qwen3-32b 这类小参数模型调用工具时经常失败？

**A:** 这类模型通常需要更明确的工具调用指令。可以把下面这段提示词放进系统提示中：

```xml
<instruction>
尽可能使用MCP工具完成任务，仔细阅读每个工具的注解、方法名、参数说明等内容。请按照以下步骤操作：

1. 仔细分析用户的问题，从已有的Tools列表中匹配最合适的工具。
2. 确保工具名称、方法名和参数完全按照工具注释中的定义使用，不要自行创造工具名称或参数。
3. 传入参数时，严格遵循工具注释中规定的参数格式和要求。
4. 调用工具时，根据需要直接调用工具，但参数请求参考以下请求格式：{"mcp_sse_call_tool": {"tool_name": "$tools_name", "arguments": "{}"}}
5. 输出结果时，不要包含任何XML标签，仅返回纯文本内容。

<input>
用户问题：user_query
</input>

<output>
返回工具调用结果或最终答案，以及对结果的分析。
</output>
</instruction>
```

### Q: 如何配置不同的数据库连接？

**A:** 常见方式有三种：

1. **环境变量**

```bash
export DORIS_HOST="your_doris_host"
export DORIS_PORT="9030"
export DORIS_USER="root"
export DORIS_PASSWORD="your_password"
```

2. **命令行参数**

```bash
doris-mcp-server --db-host your_host --db-port 9030 --db-user root --db-password your_password
```

3. **配置文件**

直接修改 `.env` 中对应项。

### Q: 如何配置监控工具使用的 BE 节点？

**A:** 按部署场景选择：

**外网或显式配置**

```bash
DORIS_BE_HOSTS=10.1.1.100,10.1.1.101,10.1.1.102
DORIS_BE_WEBSERVER_PORT=8040
```

**内网自动发现**

```bash
# 不设置或留空
# DORIS_BE_HOSTS=
# 系统会用 SHOW BACKENDS 获取内部 IP
```

### Q: 如何把 SQL Explain/Profile 文件交给 LLM 做优化分析？

**A:** 推荐流程：

1. 先调用工具获取结果：

```json
{
  "content": "Truncated plan for immediate review",
  "file_path": "/tmp/explain_12345.txt",
  "is_content_truncated": true
}
```

2. 使用方法：
   - 先看截断内容，快速判断问题
   - 把完整文件上传给 LLM 作为附件
   - 让 LLM 给出优化建议或性能分析
   - 再回到 Doris 中验证这些建议

3. 可调节内容大小：

```bash
MAX_RESPONSE_CONTENT_SIZE=4096
```

### Q: 如何启用数据安全和脱敏？

```bash
ENABLE_MASKING=true
AUTH_TYPE=token
TOKEN_SECRET=your_secret_key
MAX_RESULT_ROWS=10000
```

### Q: Stdio 和 HTTP 模式有什么区别？

**A:**

- **Stdio 模式**：适合 Cursor 这类客户端直接管理服务进程
- **HTTP 模式**：独立运行的服务，适合生产环境和多客户端

建议：

- 开发和个人使用：优先 `stdio`
- 生产和多用户环境：优先 `http`

### Q: 连接超时怎么排查？

1. 增大超时：

```bash
QUERY_TIMEOUT=60
CONNECTION_TIMEOUT=30
```

2. 检查网络和服务：

```bash
curl http://localhost:3000/health
```

3. 调整连接池：

```bash
DORIS_MAX_CONNECTIONS=20
```

### Q: `at_eof` 连接错误怎么解决？

**A:** v0.5.0 已经通过连接池重构系统性修复。

#### 问题原因

- 连接池预创建导致状态脏化
- aiomysql reader 生命周期管理不一致
- 并发场景下连接池稳定性不足

#### 修复方案

1. **连接池策略调整**
   - `min_connections` 调整为 0
   - 按需创建连接
   - 优先获取新鲜连接，不做会话级缓存

2. **增强健康检查**
   - 3 秒超时校验
   - 后台定期检测连接池
   - 自动清理异常连接

3. **智能恢复**
   - 自动恢复连接池
   - 指数退避重试
   - 精确识别连接类错误

4. **性能优化**
   - 连接池预热
   - 后台清理过期连接
   - 实时诊断指标

#### 监控建议

```bash
tail -f logs/doris_mcp_server_info.log | grep -E "(pool|connection|at_eof)"
tail -f logs/doris_mcp_server_debug.log | grep "connection health"
curl http://localhost:8000/health
```

#### 推荐配置

```bash
DORIS_MAX_CONNECTIONS=20
CONNECTION_TIMEOUT=30
QUERY_TIMEOUT=60
HEALTH_CHECK_INTERVAL=60
```

### Q: MCP 版本兼容问题怎么处理？

**A:** v0.4.2 起引入了兼容层，可兼容 MCP 1.8.x 和 1.9.x。

问题背景：

- MCP 1.9.3 调整了 `RequestContext` 泛型参数
- 旧代码可能报 `TypeError: Too few arguments for RequestContext`

当前方案：

- 自动检测已安装 MCP 版本
- 自动兼容不同版本 API 差异
- 依赖约束为 `mcp>=1.8.0,<2.0.0`

```bash
pip install mcp==1.8.0
pip install mcp==1.9.3
```

查看当前使用版本：

```bash
doris-mcp-server --transport stdio
```

### Q: 如何启用 ADBC 高性能特性？

**A:** ADBC 基于 Arrow Flight SQL，适合大数据量查询传输。

1. v0.5.0+ 已默认包含依赖，无需单独安装
2. 配置端口：

```bash
FE_ARROW_FLIGHT_SQL_PORT=8096
BE_ARROW_FLIGHT_SQL_PORT=8097
```

3. 可选配置：

```bash
ADBC_DEFAULT_MAX_ROWS=200000
ADBC_DEFAULT_TIMEOUT=120
ADBC_DEFAULT_RETURN_FORMAT=pandas
```

4. 通过 `get_adbc_connection_info` 检查状态

### Q: 如何使用新的数据分析工具？

**A:** 下面是几类常见调用：

**数据质量分析**

```json
{
  "tool_name": "analyze_data_quality",
  "arguments": {
    "table_name": "customer_data",
    "analysis_scope": "comprehensive",
    "sample_size": 100000
  }
}
```

**列血缘跟踪**

```json
{
  "tool_name": "trace_column_lineage",
  "arguments": {
    "target_columns": ["users.email", "orders.customer_id"],
    "analysis_depth": 3
  }
}
```

**数据新鲜度监控**

```json
{
  "tool_name": "monitor_data_freshness",
  "arguments": {
    "freshness_threshold_hours": 24,
    "include_update_patterns": true
  }
}
```

**慢查询分析**

```json
{
  "tool_name": "analyze_slow_queries_topn",
  "arguments": {
    "days": 7,
    "top_n": 20,
    "include_patterns": true
  }
}
```

### Q: 新日志系统怎么使用？

**A:** v0.5.0 起日志系统支持按级别拆分和自动清理。

#### 日志结构

```text
logs/
├── doris_mcp_server_debug.log
├── doris_mcp_server_info.log
├── doris_mcp_server_warning.log
├── doris_mcp_server_error.log
├── doris_mcp_server_critical.log
├── doris_mcp_server_all.log
└── doris_mcp_server_audit.log
```

#### 查看日志

```bash
tail -f logs/doris_mcp_server_info.log
tail -f logs/doris_mcp_server_error.log
tail -f logs/doris_mcp_server_debug.log
tail -f logs/doris_mcp_server_all.log
tail -f logs/doris_mcp_server_audit.log
```

#### 常用配置

```bash
LOG_LEVEL=INFO
ENABLE_AUDIT=true
ENABLE_LOG_CLEANUP=true
LOG_MAX_AGE_DAYS=30
LOG_CLEANUP_INTERVAL_HOURS=24
LOG_FILE_PATH=logs
```

### Q: 新的 Token 绑定数据库配置怎么用？

**A:** 开启 Token 认证后，每个租户 Token 都可以绑定自己的数据库连接。

1. 启用 Token 认证：

```bash
ENABLE_TOKEN_AUTH=true
TOKEN_HOT_RELOAD=true
TOKEN_FILE_PATH=tokens.json
```

2. 在 `tokens.json` 中配置租户：

```json
{
  "version": "1.0",
  "tokens": [
    {
      "token_id": "tenant-alpha",
      "token": "tenant_alpha_secure_token_123",
      "description": "Tenant Alpha database access",
      "expires_hours": null,
      "is_active": true,
      "database_config": {
        "host": "tenant-alpha-db.company.com",
        "port": 9030,
        "user": "alpha_user",
        "password": "secure_password",
        "database": "alpha_analytics",
        "charset": "UTF8"
      }
    }
  ]
}
```

3. 优先级：
   - Token 绑定数据库配置
   - `.env` 环境变量
   - 两者都没有则报错

4. 多租户访问示例：

```bash
curl -H "Authorization: Bearer tenant_alpha_secure_token_123" http://localhost:3000/mcp
curl -H "Authorization: Bearer tenant_beta_secure_token_456" http://localhost:3000/mcp
```

### Q: Hot Reload 是怎么工作的？安全吗？

**A:** 设计目标就是可用于生产环境：

- 每 10 秒检测 `tokens.json`
- 新配置先校验数据库连通性
- 更新具备原子性
- 任一 Token 校验失败就整体回滚
- 每次更新都记录审计日志

推荐操作：

```bash
tail -f logs/doris_mcp_server_info.log | grep "hot reload"
cp tokens.json tokens.json.backup
```

### Q: Token 生命周期怎么管理更安全？

**A:** 推荐优先使用文件方式管理，再结合热加载。

#### 推荐方式

```bash
# 1. 直接修改 tokens.json
nano tokens.json

# 2. 系统会在 10 秒内自动热加载

# 3. 查看日志确认
tail -f logs/doris_mcp_server_info.log | grep "hot reload"
```

#### HTTP 管理端点

这些接口默认关闭，而且只允许本机访问：

```bash
export ENABLE_HTTP_TOKEN_MANAGEMENT=true
export TOKEN_MANAGEMENT_ADMIN_TOKEN=your_secure_admin_token
export REQUIRE_ADMIN_AUTH=true
export TOKEN_MANAGEMENT_ALLOWED_IPS=127.0.0.1,::1

curl -H "Authorization: Bearer your_secure_admin_token" http://127.0.0.1:3000/token/stats
```

#### 最佳实践

- 通过安全配置文件管理 Token
- 不要把管理端点暴露到外网
- 生产环境使用高强度随机 Token
- `tokens.json` 文件权限建议设为 `600` 或 `640`
- 定期审计有效 Token 和使用情况

如有其他问题，建议查看 GitHub Issues，或直接提交新 Issue。
