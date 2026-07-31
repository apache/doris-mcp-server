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

# 安全与权限模型

[English](security-model.md) | 简体中文

安全采用分层设计。MCP 身份认证、精确操作授权、能力可见性、查询安全、传输策略和
Apache Doris RBAC 分别保护不同边界。启用其中一层不会取消其他层的必要性。

## 信任模型

```text
网络与代理
  -> HTTP Host/Origin/TLS 策略
  -> 凭据认证
  -> MCP 操作 Scope
  -> 领域发现 Scope
  -> 精确 Child 执行 Scope
  -> Provider Allowlist 与能力 Gate
  -> SQL/标识符/结果 Guard
  -> 请求级 Doris 身份与 RBAC
  -> 清洗且有界的响应
```

MCP Server 不是可以绕过 Doris 授权的代理。Catalog、数据库、表、列、行、UDF、
审计元数据和系统视图的最终权限仍由 Doris 决定。

## 身份认证模式

### 匿名本地开发

默认策略只允许在回环绑定上使用未鉴权 HTTP，它不是生产模式。非回环地址没有
启用鉴权时，启动会失败；除非操作人员显式设置危险的
`ALLOW_UNAUTHENTICATED_NON_LOOPBACK=true`。

stdio 依赖本地进程边界和 Host 提供的环境。应保护本地环境变量、配置文件和进程
访问权限。

### 静态 Bearer Token

通过 `ENABLE_TOKEN_AUTH=true` 启用。静态 Token 在 MCP 边界验证，也可以绑定
独立 Doris 路由。持久化记录使用自描述 SHA-256/SHA-512 Digest 与原子 Owner-only
写入；旧明文记录只进行单向迁移。

可选 HTTP Token 管理接口默认关闭，必须保持 Localhost-only、IP 限制，并使用
独立高强度 Admin 凭据保护。Admin 凭据只能放 Header，不能放 Query String。

### JWT

通过 `ENABLE_JWT_AUTH=true` 启用，并配置预期 Issuer、Key 与 Algorithm 边界。
私钥和共享 Secret 应由 Secret Manager 或受保护的进程环境注入，不能写入仓库。

### 外部 OAuth 2.0/OIDC

通过 `ENABLE_OAUTH_AUTH=true` 启用外部 Access Token 验证。Token 必须通过可信
Issuer、Audience/Resource、有效期、Active State 和精确 Scope 校验，之后才可
接受可选 UserInfo。无效或 Scope 不足的 Token 返回标准 Bearer Challenge，不泄露
Provider 内部信息。

Email/Domain 到 Role 的映射会归一化和校验。Domain Elevation 要求已验证身份；
Fallback Mapping 不能静默扩大精确 Child Scope。

### Doris 账号驱动的 OAuth

`ENABLE_DORIS_OAUTH_AUTH=true` 提供 OAuth 边界，最终请求身份拥有自己的 Doris
用户连接池。1.0 中它要求 HTTP、配置服务账号、公开 Resource/Base URL，且
`WORKERS=1`。外部 OAuth 与 Doris OAuth 互斥。

Authorization Code、Access Token、Client 与用户连接池状态都在进程内。Access
Token 绑定规范 MCP Resource；必需 RFC Resource、Redirect Policy、PKCE/Client
规则和 Application Type 都会校验。Doris 原始密码不会持久化到 Token Store。

数据库 Child 默认关闭，启用后使用显式 Feature-ID Allowlist 与精确 Scope。Doris
OAuth Token 的受保护数据调用不能静默回退到全局服务账号。

## 精确授权

授权会在多个阶段执行：

1. **MCP 操作：** 例如 `list_tools`、`call_tool`、`read_resource`。
2. **领域发现：** 身份是否有权知道某个 Child。
3. **Child 执行：** 例如精确策略
   `child:call:doris_query:execute_query`。
4. **Channel/Provider：** Doris OAuth、Semantic、ADBC 或自定义 Provider 是否
   启用且 Allowlist 允许。
5. **Doris RBAC：** 所选 Doris 身份是否能执行真实语句或读取真实元数据。

OAuth 路径要求精确 Domain/Child Scope。Wildcard 猜测和 1.0 以前 Scope 不会授权。
发现权限不等于执行权限。未授权 Child 从 Manifest 过滤，执行时表现为 Not Found，
避免泄露能力名称。

## Doris 身份与连接路由

路由管理器按明确顺序选择凭据：

1. Doris OAuth 请求身份及其用户连接池；
2. 静态 Token 绑定的 Doris 配置；
3. 允许使用全局路由时的服务账号。

连接池按规范路由身份隔离。超时、取消、凭据不匹配或不安全的 Owner/Pool 状态会
Fail Closed，不会落到更高权限连接池。Query、Metadata、FE HTTP 与能力证据必须
绑定同一个请求路由。

每个信任边界应使用独立最小权限 Doris 账号。Grant、Row Policy 和 Token 绑定
示例见 [Doris 细粒度权限控制](../doris-fine-grained-access-control.md)。

## SQL 与标识符安全

内置 1.0 领域全部只读，`doris_admin` 不注册。

共用 Query Guard 会：

- 解析并只接受一个受支持的只读语句；
- 拒绝 DDL、DML、管理命令、堆叠语句、违反策略的 Comment/Construct 和畸形参数；
- 校验/引用 Catalog、Database、Table、Column、Function 与 Metric 标识符；
- Driver 支持时绑定调用方值，避免拼接；
- 对 Explain/Diagnosis 的目标 SQL 与直接 Query 应用同样检查；
- 限制超时、行数、序列化字节、深度、集合与文本；
- 分类 Timeout/Read-only/Argument/Backend 错误，不返回原始后端异常文本。

结构化 Search 不接受任意 Filter SQL 或原始 Search DSL。允许的 FE/BE HTTP Client
校验配置目的地，阻止调用方控制的 SSRF Target。

## 结果与元数据安全

- Model-facing 返回前执行配置的脱敏规则。
- Sensitive Table/Column 策略可限制或转换数据。
- 当领域合同不需要时，移除或限界 Raw SQL、Client Address、Auth Mapping、对象
  Location、Catalog Property、Variant Sample 和后端错误。
- Query Result、Tool Input 和 Structured Output 都有绝对大小/深度限制。
- Schema 错误只报告 Path 与 Keyword，不回显被拒绝的 Secret 值。
- 凭据型 Trace Baggage Key 在传播前脱敏。
- 公开能力快照使用稳定原因码和清洗证据，不返回连接串或 Probe Exception 细节。

## 传输安全

- 本地开发绑定 `127.0.0.1`、`localhost` 或 `::1`。
- 同时校验 HTTP `Host` 与 `Origin`，降低 DNS Rebinding 风险。
- `0.0.0.0` 等 Bind Address 不是 Public Hostname Allowlist。
- 流量离开本机时使用 HTTPS。
- 接受 Forwarded Identity/Scheme Header 前配置可信 Proxy CIDR，不能全局信任代理
  Header。
- 凭据放 Authorization Header 或受保护环境/Secret Mount，不能放 URL。
- Token 管理接口与普通 MCP Access Policy 分开管理。

## 状态与 Secret 处理

- MCP 状态句柄使用 HMAC 签名，绑定 Principal/Scope/Expiry，不包含凭据或查询数据。
- 只有独立 Replica 共享流量时才配置共享高强度 `MCP_STATE_HANDLE_SECRET`，并按
  部署 Secret 轮换。
- Token Digest 不能反推出 Bearer Token。
- 日志使用已脱敏 Credential DTO 和安全 `repr`。
- Reverse Proxy 或 Process Supervisor 不能开启会序列化请求 Header/环境 Secret
  的 Debug 日志。
- `.env`、Token File、OAuth Client File、JWT Key 和私有 Ossie Binding
  Manifest 应为 Owner-only，且不能提交。

## 自定义 Provider

只有安装且列入 `MCP_TOOL_PROVIDERS` 的 Entry Point 会加载。Provider 名称、Tool
名称、Schema、Lifecycle、Audit Metadata 和有界 Rate Limit 都会校验。Allowlist
内 Provider 无效时启动 Fail Closed。Provider Tool 不能覆盖内置 Tool，也不会
静默继承内置授权。

启用扩展前请阅读[自定义 Tool Provider](../custom-tool-providers.md)。

## 1.0 安全限制

- Doris OAuth 仅单 Worker，状态在进程内。
- 自定义 Provider 的进程内限流不是分布式 Quota。
- ADBC 因 Flight Client 为进程全局，在 Token 绑定路由上 Fail Closed。
- 原生血缘异步 Best-effort，仅作为证据，不是事务授权源。
- 应用层 SQL Guard 不能替代 Doris Grant 与 Row Policy。
- Public Reverse Proxy 的 Host/Origin 形态必须显式验证，绑定 `0.0.0.0` 本身不会
  让它安全。

## 生产检查清单

- 使用 TLS 与经过认证的非回环部署。
- 使用最小权限 Doris 账号并测试 Negative Grant。
- 有意识地选择一种认证模式并校验精确 Scope。
- 不主动管理时关闭 Token 管理端点。
- Secret 放在源码之外并验证文件权限。
- 只配置可信 FE/BE/Provider 端点。
- 分别验证 `/live` 与 `/ready`。
- 在目标 Doris Patch 上运行只读与权限拒绝回归。
- 升级后检查 Availability 原因码。
- 监控审计日志，但不能记录 Bearer 值或原始敏感数据。
