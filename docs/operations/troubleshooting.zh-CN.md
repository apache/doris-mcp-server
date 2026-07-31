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

# 排障

[English](troubleshooting.md) | 简体中文

排障应从公开错误码、Request ID、当前领域 Manifest 和同一个请求级 Doris 身份
开始。不要把 Token、密码、原始 OAuth 响应或私有模型 Binding 复制到 Issue。

## 首轮检查

```bash
doris-mcp-server --version
curl --fail http://127.0.0.1:3000/live
curl --verbose http://127.0.0.1:3000/ready
```

记录：

- 包版本与 Commit/Image Digest；
- Transport 与 Exposure Mode；
- 归一化 Doris 版本与 Deployment Mode；
- Domain/Child 和公开 `reason_code`；
- Request ID 与时间；
- `/live` 与 `/ready` 是否不同；
- 同一 Doris 账号能否执行最小等价只读检查。

## Server 无法启动

### 非回环绑定没有鉴权

现象：启动拒绝 `0.0.0.0` 或其他非回环地址。

处理：启用一个经过审查的认证模式，部署在 TLS 后并验证 Host/Origin。只有隔离、
一次性测试才使用 `ALLOW_UNAUTHENTICATED_NON_LOOPBACK=true`。

### 认证模式冲突

外部 OAuth 与 Doris OAuth 不能同时启用。应选择一个信任模型，并核对必需 Issuer、
Resource、Key、Base URL、Proxy CIDR 和 Secret。

### Doris OAuth 拒绝 Worker 数

1.0 的 Doris OAuth 要求 Streamable HTTP 和 `WORKERS=1`，因为 Authorization 与
用户连接池状态都在进程内。

### 管理领域配置被拒绝

`doris_admin` 只做预留且故意不可用。移除启用配置；1.0 没有管理 Tool 绕过。

### 自定义 Provider 令启动失败

`MCP_TOOL_PROVIDERS` 中每个名称都必须解析到已安装、合法、名称不冲突且 Schema
有界的 Entry Point。移除名称或修复 Provider。Allowlist Provider 失败采用 Fail
Closed 是设计行为。

## `/live` 正常但 `/ready` 返回 503

进程存活，但有界 Doris Readiness 路由失败。

检查：

1. FE MySQL Host/Port 与网络策略。
2. 配置数据库存在且可见。
3. 凭据、账号锁定与过期。
4. Server 与 Doris 之间的 TLS/Proxy 要求。
5. Pool Exhaustion 或重复 Timeout Disposal。
6. 多 FE 候选中是否至少一个健康。

必须使用同一账号和网络路径测试。另一个 Admin 账号成功执行 `SELECT 1`，不能证明
MCP 身份可用。

## HTTP 请求被拒绝

### Host 或 Origin 被拒绝

Bind Address 不是 Allowlist。检查 Server 实际看到的 `Host`、`Origin`、Reverse
Proxy Rewrite、TLS Scheme 和 Trusted Proxy CIDR。不要全局信任 Forwarded Header。

### `HeaderMismatch`（`-32020`）

确认：

- `MCP-Protocol-Version` 与 `_meta` 一致；
- `Mcp-Method` 精确匹配 JSON-RPC `method`；
- `Mcp-Name` 匹配 Tool/Resource/Prompt 名称或 URI；
- `Accept` 同时包含 JSON 和 Event-stream Media Type；
- Proxy 保留上述 Header。

### 不支持协议（`-32022`）

使用 MCP `2026-07-28`。`2025-11-25` HTTP Client 必须连接显式启用的
`/mcp/legacy`；HTTP+SSE Client 必须迁移。

## Authentication 或 Authorization 失败

### 401 Authentication Required

确认凭据类型与启用模式一致，Token Active 且未过期，Issuer/Audience/Resource
匹配，并确认 Proxy 没有移除 Authorization Header。

### 403 Insufficient Scope

读取精确 Required Scope。Domain Discovery Grant 不等于 Child Call Grant。
1.0 以前名称与 Wildcard 猜测无效。

### Child 看起来不存在

未授权 Child 会故意与不存在 Child 表现相同。使用同一身份重新发现领域，核对
精确 Discovery/Call Scope 与 Channel Enablement。

### Doris Permission Denied

MCP 授权通过后，Doris RBAC 仍可能拒绝真实对象。使用同一 Doris 账号测试同等
SQL/Metadata View，再只授予最小所需权限。参见细粒度权限指南。

## 领域发现或 Child 执行失败

### `CHILD_MANIFEST_STALE`

重新用 `{}` 调用领域并使用新 Manifest。路由、权限、Provider、Model、Feature
Probe 或能力 Cache 代际可能已经变化。

### `CHILD_CAPABILITY_UNAVAILABLE`

使用结构化 `reason_code` 与 Evidence Source。常见原因：

- Doris 版本低于特性范围；
- 活动组件版本混合或未知；
- 系统表/函数/索引缺失；
- 可选 Provider 关闭或不健康；
- 请求账号无权读取元数据；
- Lineage Store 不完整；
- Stale Evidence 已超出允许窗口。

有权限时调用 `doris_cluster.get_runtime_capabilities`。不能修改 Description 或
绕过 `callable=false` 强制执行。

### Manifest 超预算

这表示 Catalog/Provider/Schema 漂移。内置 Manifest 与 Flat Tool 有硬预算。应
重新生成/检查目录并缩短 Provider Description/Schema，不能随意增大上限，因为
Host Context 属于产品合同。

## Query 失败

### `QUERY_READ_ONLY_VIOLATION`

提交一条只读语句。移除 DDL/DML/Administration、堆叠语句、不安全 Comment 或
不支持形态。Query Child 不是管理 SQL 逃生通道。

### `QUERY_ARGUMENT_INVALID`

使用精确发现 Schema。校验 Identifier、Parameter 名称/类型、Query Target、
Return Format 与 Limit。

### `QUERY_TIMEOUT`

缩小扫描、增加 Predicate、使用 Explain/Diagnosis、减少结果量，并检查 Doris
Workload。只有错误标记可重试时才重试。超时连接可能会被故意销毁。

### 结果截断或过大

使用更小 Page、减少列、加强 Filter、先聚合或降低 Limit。提高进程上限前要估算
序列化响应和模型 Context 成本。

### Profile 不可用

检查 FE HTTP Host/Port、Allowlist、路由身份、Profile Retention、Query ID 和
Doris 账号可见性。MySQL 路由可用不等于 FE HTTP 已配置。

## 分页与状态句柄

Cursor 无效可能来自过期、篡改、可见性变化、Principal 变化、List 类型错误、
State Secret 不同或 Snapshot 改变。应不带 Cursor 重新开始 List。

独立 Replica 要配置相同 `MCP_STATE_HANDLE_SECRET`。Host 不应解析或构造 Cursor。

## stdio 解析错误

- 确认 stdout 没有日志、Banner 或 Debug 输出。
- 启动 `doris-mcp-server`，不是 `doris-mcp-client`。
- 确认 Host 使用 MCP `2026-07-28` 请求元数据。
- 检查环境继承和 Executable Path。
- 用真实子进程复现，不使用会混合 Stream 的 Shell Pipeline。

## Provider 特定失败

### ADBC 不可用

检查 `ADBC_ENABLED`、Arrow Flight SQL 端口、Provider 安装与实时连通。ADBC 在
Token 绑定路由上故意 Fail Closed；适用时使用 MySQL 只读 Query Child。

### Ossie Model 不可用

检查 `OSSIE_ENABLED`、Model Directory、已审查 Schema Revision、精确
`model_ref`、私有 Binding Manifest、Semantic Scope 和 Doris 可见性。Server
不会猜模型。

### 原生血缘不可用

检查归一化 Doris 版本、Companion Producer 健康、可查询 Store、规范必需列和
请求权限。Trace 前先调用 `get_lineage_capability_status`。Audit Fallback 会明确
标记，也可能不可用或不完整。

## 安全 Support Bundle

可以包含：

- 版本、Commit/Image Digest、OS/Python；
- 清洗后的配置 Key（Secret 不提供 Value）；
- Domain Manifest Availability/Reason Code；
- Health 状态和时间；
- Request ID 和清洗后的日志行；
- 替换敏感标识/数据后的最小只读 SQL；
- 问题出现在 stdio、HTTP 或两者。

不能包含：

- Bearer/Admin Token、Password、JWT Key、OAuth Client Secret；
- Authorization Header、Token File、原始 Environment Dump；
- Private Ossie Binding、带凭据 Connection URL；
- 未经清洗和授权的客户 SQL/数据。
