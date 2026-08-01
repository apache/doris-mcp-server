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

# 配置参考

[English](configuration.md) | 简体中文

完整权威示例是 [`.env.example`](../../.env.example)。本文按运维关注点解释主要
配置边界；默认值与校验仍以 `doris_mcp_server/utils/config.py` 为运行时事实源。

## 优先级与不变量

- 已支持 CLI Flag 覆盖对应环境默认值。
- 环境值在启动前归一化和校验。
- 安装包控制 `server_version`；`SERVER_VERSION` 不能覆盖产品身份。
- Exposure Mode、Authentication、Provider 与 Worker Model 是启动选项，不是请求
  级开关。
- 无效安全组合在服务流量前失败。
- 不能把真实 Secret 写入已提交 `.env`、Compose 或文档。

## Doris 路由

| 变量 | 用途 |
|---|---|
| `DORIS_HOST` | 主要 FE MySQL Host |
| `DORIS_HOSTS` | 有序 `host:port` FE MySQL 候选 |
| `DORIS_PORT` | FE MySQL 端口，通常 `9030` |
| `DORIS_USER` | 全局/服务 Doris 账号 |
| `DORIS_PASSWORD` | 全局/服务 Doris 密码 |
| `DORIS_DATABASE` | 默认数据库，常用 `information_schema` |
| `DORIS_FE_HTTP_HOST` | FE HTTP Host；空值可复用 `DORIS_HOST` |
| `DORIS_FE_HTTP_HOSTS` | 有序 FE HTTP 候选 |
| `DORIS_FE_HTTP_PORT` | FE HTTP 端口，通常 `8030` |
| `DORIS_BE_HOSTS` | 显式 BE HTTP Allowlist |
| `DORIS_BE_WEBSERVER_PORT` | BE HTTP 端口，通常 `8040` |

HTTP 安全：

| 变量 | 用途 |
|---|---|
| `DORIS_HTTP_CONNECT_TIMEOUT_SECONDS` | FE/BE HTTP 连接超时 |
| `DORIS_HTTP_READ_TIMEOUT_SECONDS` | 读取超时 |
| `DORIS_HTTP_TOTAL_TIMEOUT_SECONDS` | 总请求超时 |
| `DORIS_HTTP_MAX_RESPONSE_BYTES` | 最大 HTTP Response 字节数 |

连接池：

| 变量 | 用途 |
|---|---|
| `DORIS_MAX_CONNECTIONS` | 部署级 Pool 上限 |
| `DORIS_CONNECTION_TIMEOUT` | MySQL 连接超时 |
| `DORIS_HEALTH_CHECK_INTERVAL` | 连接健康间隔 |
| `DORIS_MAX_CONNECTION_AGE` | 可复用连接最大年龄 |

所有 FE/BE Destination 必须由操作人员配置，不能由调用方参数指定。

## Server 与协议

| 变量 | 用途 |
|---|---|
| `TRANSPORT` | `http` 或 `stdio` |
| `SERVER_HOST` | HTTP Bind Host |
| `SERVER_PORT` | HTTP Port |
| `WORKERS` | HTTP Worker 数；Doris OAuth 要求 `1` |
| `SERVER_NAME` | 产品实例名，不是产品版本 |
| `MCP_ALLOWED_HOSTS` | 已校验 HTTP Host Policy 输入 |
| `MCP_ALLOWED_ORIGINS` | 已校验 Origin Policy 输入 |
| `ENABLE_LEGACY_HTTP_ADAPTER` | 默认关闭的 `/mcp/legacy` Adapter，用于已验证的 `2025-06-18` 和 `2025-11-25` Client |
| `MCP_LIST_PAGE_SIZE` | 每个协议 List Page 条目数（`1`–`1000`） |
| `MCP_STATE_HANDLE_SECRET` | 独立 Replica 共享 HMAC Secret |
| `MCP_STATE_HANDLE_TTL_SECONDS` | 显式句柄有效期（`1`–`3600`） |
| `MCP_TOOL_EXPOSURE_MODE` | `hierarchical`（默认）或 `flat` |
| `ALLOW_UNAUTHENTICATED_NON_LOOPBACK` | 危险且只供测试的绑定绕过 |

`MCP_ADMIN_DOMAIN_ENABLED` 必须为 `false`，
`MCP_ADMIN_REQUIRE_CONFIRMATION` 必须为 `true`。1.0 会拒绝启用预留管理领域。

## Query、Response 与并发上限

| 变量 | 用途 |
|---|---|
| `ENABLE_SECURITY_CHECK` | 应用层只读 SQL Guard |
| `BLOCKED_KEYWORDS` | Parser 之外的兼容 Keyword Policy |
| `MAX_QUERY_COMPLEXITY` | 配置的复杂度上限 |
| `MAX_RESULT_ROWS` | 部署行数上限；另有绝对硬上限 |
| `DEFAULT_RESULT_ROWS` | 调用未指定时的默认行数 |
| `MAX_RESULT_BYTES` | UTF-8 JSON 行数据预算 |
| `QUERY_TIMEOUT` | 部署 Query Timeout；另有绝对硬上限 |
| `MAX_CONCURRENT_QUERIES` | 进程 Query 并发 |
| `MAX_RESPONSE_CONTENT_SIZE` | 有界 Text/Content Response Size |
| `ENABLE_MASKING` | 配置结果脱敏 |
| `ENABLE_QUERY_CACHE` | Query Cache 开关 |
| `CACHE_TTL` | Cache Lifetime |
| `MAX_CACHE_SIZE` | Cache Entry 上限 |

领域运行时可以比部署值更严格。提高一个变量不能移除绝对安全上限。

## 能力探测与领域

| 变量 | 用途 |
|---|---|
| `CAPABILITY_SNAPSHOT_TTL_SECONDS` | 路由私有 Snapshot Lifetime |
| `CAPABILITY_PROBE_TIMEOUT_SECONDS` | 有界 Probe Timeout |
| `CAPABILITY_STALE_GRACE_SECONDS` | 最大 Stale Fallback Window |
| `MCP_TOOL_PROVIDERS` | 逗号分隔的精确 Custom Provider Allowlist |

Governance：

- `GOVERNANCE_MAX_SAMPLE_RATIO`
- `GOVERNANCE_MAX_AUDIT_WINDOW_DAYS`
- `GOVERNANCE_MAX_LINEAGE_EDGES`
- `GOVERNANCE_LINEAGE_STORE_TABLE`
- `GOVERNANCE_LINEAGE_RECENT_EVENT_MINUTES`

Lakehouse：

- `LAKEHOUSE_MAX_CATALOG_OBJECTS`
- `LAKEHOUSE_MAX_CATALOG_DATABASES`
- `LAKEHOUSE_MAX_SNAPSHOTS`
- `LAKEHOUSE_MAX_PARTITIONS`
- `LAKEHOUSE_MAX_VARIANT_SAMPLE_ROWS`
- `LAKEHOUSE_MAX_VARIANT_PATHS`

它们只是 Evidence/Result 上限，不是 Doris Permission Grant。

## ADBC

| 变量 | 用途 |
|---|---|
| `ADBC_ENABLED` | 启用可选高级 ADBC Provider；默认 `false` |
| `FE_ARROW_FLIGHT_SQL_PORT` | FE Flight SQL Port |
| `BE_ARROW_FLIGHT_SQL_PORT` | 可选 BE Flight Port |
| `ADBC_DEFAULT_MAX_ROWS` | 默认 ADBC 行数 |
| `ADBC_DEFAULT_TIMEOUT` | 默认 ADBC 超时 |
| `ADBC_DEFAULT_RETURN_FORMAT` | `arrow`、`pandas` 或 `dict` |
| `ADBC_CONNECTION_TIMEOUT` | Flight 连接超时 |

ADBC 仍受全局结果上限约束，1.0 在 Token 绑定路由上 Fail Closed。启用 Provider
不代表允许自动选择：两个 ADBC Child 的 Schema 和运行时都会要求
`explicit_adbc=true`，Host 只应在终端用户明确要求 ADBC 或 Arrow Flight SQL 时
设置。普通查询使用 `doris_query.execute_query`。

## Apache Ossie 语义 Grounding

| 变量 | 用途 |
|---|---|
| `OSSIE_ENABLED` | 启用默认关闭的 Semantic Provider |
| `OSSIE_MODEL_DIRECTORY` | 已审查 UTF-8 YAML/JSON Model 目录 |
| `OSSIE_BINDING_MANIFEST` | Server 私有 Doris Binding 文件 |
| `OSSIE_MAX_FILE_BYTES` | 单文件加载上限 |
| `OSSIE_MAX_TOTAL_BYTES` | Model 总大小上限 |
| `OSSIE_MAX_MODELS` | Model 数量上限 |
| `OSSIE_MAX_DEPTH` | Model 结构深度 |
| `OSSIE_MAX_ALIASES` | Alias 数量上限 |
| `OSSIE_MAX_STRING_BYTES` | 字符串上限 |
| `OSSIE_MAX_EXPRESSION_BYTES` | Expression 文本上限 |
| `OSSIE_CONTEXT_MAX_BYTES` | 默认 Context 预算 |
| `OSSIE_CONTEXT_HARD_MAX_BYTES` | 绝对 Context 预算 |

OAuth 模式还要求显式 Semantic Channel 和 `semantic:read`。每个 Model-specific
调用仍需要精确 `model_ref`。

## MetricFlow 语义消费

| 变量 | 用途 |
|---|---|
| `METRICFLOW_ENABLED` | 启用默认关闭的 MetricFlow Consumer |
| `METRICFLOW_PROVIDER_COMMAND_JSON` | 以 JSON String Array 配置绝对 Executable 和固定参数 |
| `METRICFLOW_PROJECT_DIRECTORY` | 可选 Provider 绝对 Working Directory |
| `METRICFLOW_TIMEOUT_SECONDS` | Provider 进程超时，`1-120` 秒 |
| `METRICFLOW_MAX_OUTPUT_BYTES` | Provider stdout 上限，`1024-8388608` 字节 |

MetricFlow 启用时必须提供非空 Command，且 Executable 必须为绝对路径。Server
不经过 Shell，通过 `doris-mcp-metricflow/v1` 调用。Provider 可以读取 Model 与
编译 Doris SQL；所有执行必须回到有界 MCP Query Runtime。详见
[MetricFlow 接入](../integrations/metricflow.zh-CN.md)。

## 静态 Token 认证

| 变量 | 用途 |
|---|---|
| `ENABLE_TOKEN_AUTH` | 启用静态 Bearer Authentication |
| `TOKEN_FILE_PATH` | Managed Digest-only Token File |
| `ENABLE_TOKEN_EXPIRY` | 强制 Managed Token 过期 |
| `DEFAULT_TOKEN_EXPIRY_HOURS` | 默认 Managed Token Lifetime |
| `TOKEN_HASH_ALGORITHM` | 支持的持久化 Digest Algorithm |
| `TOKEN_DB_VALIDATION_TTL_SECONDS` | Token 绑定 Doris 路由校验 Cache |
| `TOKEN_<ID>` | 操作人员注入高强度 Static Token |

项目不会携带默认 Static Bearer Credential。

Token 管理：

| 变量 | 用途 |
|---|---|
| `ENABLE_HTTP_TOKEN_MANAGEMENT` | 启用高风险本地管理端点 |
| `TOKEN_MANAGEMENT_ADMIN_TOKEN` | 独立高强度 Admin Credential |
| `TOKEN_MANAGEMENT_ALLOWED_IPS` | 管理 IP/CIDR Allowlist |
| `REQUIRE_ADMIN_AUTH` | 生产必须保持 True |

没有必要时应关闭管理接口。

## JWT

主要配置包括：

- `ENABLE_JWT_AUTH`
- `JWT_SECRET_KEY`、`JWT_ALGORITHM`
- `JWT_ISSUER`、`JWT_AUDIENCE`
- `JWT_EXPIRATION_HOURS`
- Signature、Expiry、Issuer、Audience 校验开关
- 启用 Refresh 时的 Key/Lifetime
- User ID、Role、Permission、Security Level Claim 名称

使用受支持的非对称 Key 策略，或部署专属高强度共享 Key；替换所有示例占位值。

## 外部 OAuth/OIDC

主要配置包括：

- `ENABLE_OAUTH_AUTH`
- `OAUTH_PROVIDER_TYPE`、Client ID/Secret、Redirect URI
- 必需可信 `OAUTH_ISSUER` 和 `OAUTH_RESOURCE`
- `OAUTH_AUDIENCE`（默认等于 Resource）
- Discovery、Authorization、Token、Introspection、UserInfo、JWKS Endpoint
- 精确 Allow/Required Scope 和 Claim 名称
- 默认 Role/Security Level/Permission
- Trusted Domain 与 JSON Role Mapping
- Session/State Secret 与 Lifetime

RFC 7662 Introspection 属于信任边界。`.env.example` 中 Provider 示例只是模板；
没有配置 Issuer、Resource、Audience 与 Introspection 时，不能证明 Provider 安全。

## Doris OAuth

主要配置包括：

- `ENABLE_DORIS_OAUTH_AUTH`、`DORIS_OAUTH_BASE_URL`
- 精确 Child/Channel Switch 与 `domain.child` Allowlist
- Token、Refresh、Authorization-code、Client、GC Lifetime
- Preconfigured Client File 与 Redirect URI Policy
- DCR Mode 与显式 Production-DCR 开关
- 每 IP/User/Client/Transaction Rate Limit
- Insecure-HTTP、Trusted-proxy 与 Proxy-CIDR Policy

必需不变量：

- HTTP Transport；
- 一个有效 Worker；
- 关闭外部 OAuth；
- 配置全局/服务 Doris 账号；
- 非回环生产 URL 使用 HTTPS；
- 精确 Resource Binding 与 Scope。

## 日志与监控

| 变量 | 用途 |
|---|---|
| `LOG_LEVEL` | 进程 Log Level |
| `LOG_FILE_PATH` | 可选主日志路径 |
| `ENABLE_AUDIT` | Audit Logging |
| `AUDIT_FILE_PATH` | Audit Log 路径 |
| `LOG_MAX_FILE_SIZE`、`LOG_BACKUP_COUNT` | Rotation |
| `ENABLE_LOG_CLEANUP` | 自动清理 |
| `LOG_MAX_AGE_DAYS` | Retention |
| `LOG_CLEANUP_INTERVAL_HOURS` | 清理间隔 |
| `ENABLE_METRICS`、`METRICS_PORT` | Metrics Export |
| `HEALTH_CHECK_PORT` | 兼容监控端口 |
| `ENABLE_ALERTS`、`ALERT_WEBHOOK_URL` | 可选 Alerting |

日志配置诊断不能包含 Credential Value。

## 最小配置样例

本地 stdio：

```bash
TRANSPORT=stdio
DORIS_HOST=127.0.0.1
DORIS_PORT=9030
DORIS_USER=mcp_reader
DORIS_PASSWORD=<secret>
MCP_TOOL_EXPOSURE_MODE=hierarchical
```

已认证回环 HTTP：

```bash
TRANSPORT=http
SERVER_HOST=127.0.0.1
SERVER_PORT=3000
ENABLE_TOKEN_AUTH=true
TOKEN_OPERATOR=<generated-secret>
DORIS_HOST=127.0.0.1
DORIS_USER=mcp_reader
DORIS_PASSWORD=<secret>
```

在源码之外生成 Secret：

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

使用非回环配置前，请阅读[部署](../operations/deployment.zh-CN.md)和
[安全模型](../security/security-model.zh-CN.md)。
