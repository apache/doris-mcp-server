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

# 可靠性与限制

[English](reliability.md) | 简体中文

1.0 的可靠性目标是在部分失败时保持诚实。Provider 缺失、Doris Patch 过低、系统
表权限被拒绝、FE 不健康、超时或结果过大，都必须变成有界的类型化状态，而不是
编造空成功或触发无界重试。

## 可靠性原则

- 不安全配置令启动失败。
- 未知能力或授权状态按 Fail Closed 处理。
- 单个 Child 不可用时，领域发现仍可工作。
- 区分进程存活与 Doris 就绪。
- 所有集合、请求、Schema、查询和响应都有界。
- 不依赖协议 Session，也能保持请求身份与路由一致。
- 明确报告实际 Native/Fallback 证据路径。
- 对 Retryability 分类，不要求 Host 解析后端字符串。
- 成功 Structured Output 返回前必须通过 Schema 校验。

## 健康模型

| 端点 | 含义 | 编排系统是否应重启 |
|---|---|---|
| `/live` | 进程和协议路径存活 | 只有持续 Liveness 失败才重启 |
| `/ready` | 当前可以安全服务已配置 Doris 路径 | 先摘流并诊断路由，不直接重启 |
| `/health` | 兼容聚合视图 | 自动化应使用 `/live` 与 `/ready` |

`/live` 200 而 `/ready` 503 通常表示 Doris 连接、凭据、路由或初始化问题，不是
MCP 进程已经死亡。

## 连接与路由韧性

连接管理器为全局、静态 Token 绑定和 Doris OAuth 用户连接池维护规范路由身份，
并执行：

- 明确路由优先级；
- Auth Context 与 Pool 的 Owner 校验；
- 有界 Pool Size 和 Connection Lifetime；
- 健康检查与 Timeout-aware Disposal；
- Cancellation Cleanup；
- 连接损坏/过期后的安全重建；
- 多 FE 候选与 Failover；
- 请求级路由失败后不回退到更高权限池。

能力 Probe 使用独立的路由感知 Connection Context，避免一个不受支持的版本特定
语句污染后续证据。Probe 失败会释放连接，防止单连接路由饥饿。

## 能力韧性

能力快照按路由用有界 TTL 缓存，Singleflight 合并并发 Probe。Provider 与路由
代际进入 Manifest 指纹。

探测器区分：

- Supported；
- Unsupported；
- Unknown；
- Degraded；
- Misconfigured。

当无法安全选择 Variant 时，未知/混合基础状态 Fail Closed。配置的 Stale Fallback
有严格时间边界并明确标识，不能隐藏 Provider 代际变化或把缺失证据变成支持。

## 边界与背压

| 边界 | 机制 |
|---|---|
| 顶级 Host 上下文 | `tools/list` 序列化硬预算 |
| 领域发现 | Child 数、Description、Schema、Enum 与 Manifest 字节预算 |
| 协议 List | 稳定 Page Size + 签名 Cursor |
| 输入/输出 Schema | Node/Depth/Size/Reference 预算 |
| Tool 参数 | 编译 JSON Schema + 操作级上限 |
| SQL | 单只读语句、Timeout、Row、Byte、Parameter 边界 |
| Metadata/Search/Governance | 领域级 Row、Field、Depth、Window、Vector、Collection 上限 |
| HTTP/Provider | Allowlist Destination、Timeout、Response Size、Redirect Policy |
| 自定义 Provider | Schema 校验与有界进程内 Rate Limit |

截断必须在 Result Metadata 或 Warning 中明确表达。Server 不会静默丢弃数据后
返回一个看似完整的结果。

## 确定性失败模型

领域调用区分：

- Child 不存在/隐藏；
- 能力不可用；
- Manifest 陈旧；
- Argument/Schema 无效；
- 执行超时；
- 执行失败；
- 操作授权拒绝。

错误公开稳定 Reason Code、有界 Detail、Status Class，并在适用时标记
Retryability。Credential、原始 SQL 值、Connection URL 与后端异常文本不属于
公共错误合同。

未预期 Manager Exception 会写入内部日志，再转换成安全 Tool Execution Failure。
List 失败保持协议错误，不会变成成功空列表。

## 部分成功

部分操作会组合独立证据。例如 `get_table_context` 要求 `schema`，但 `basic`、
`comments`、`indexes` 可以 Partial 或 Unavailable。结果记录各 Section 状态、来源、
Warning 和整体 Partial 状态。

只有合同明确某组件可选时才允许 Partial Success。必需组件缺失仍是失败。

## Native 与 Fallback 路径

Fallback 选择确定且可观察：

- Cluster Task/Cache/Compaction 选择兼容的实时证据路径。
- Lakehouse 与 Variant 分开公开基础与高级 Facet。
- Governance Lineage 区分 Native Provider、Audit Primary、Audit Degraded
  Fallback 与 Unavailable。
- Search 能力区分函数/索引缺失与 Query Failure。

Fallback 不会被描述成 Native，也不会编造数字置信度。

## 可观测性

每个标准化 Child 结果包含 Request ID、Duration、Source、Truncation 与 Warning 等
有界元数据。清洗后的 W3C Trace Context 可以关联 MCP 操作与下游 Span。

操作人员应监控：

- Liveness/Readiness 变化；
- Authentication 与精确 Scope Denial；
- Capability Reason Code 变化；
- Timeout、Cancellation 与 Connection Disposal；
- Result Truncation 与 Response Size Rejection；
- FE Candidate Failover；
- Provider Health/Generation 变化；
- Audit Log 写入失败与日志清理；
- 进程内存与 Query Concurrency。

日志不能包含 Bearer Credential、Doris Password、原始 Private Binding 或面向模型的
敏感 Query Result。

## Multi-worker 与 Multi-instance

MCP `2026-07-28` HTTP 请求无状态，不需要 Sticky Session。共享启动 Secret 时，
签名 State Handle 可以跨 Worker；独立 Replica 需要显式共享 Secret 和兼容的
Policy/Catalog 状态。

限制：

- Doris OAuth 在 1.0 必须单 Worker、单实例边界。
- 内存 Custom-provider Quota 为每进程独立。
- Cache 只是本地优化，正确性不能依赖共享 Cache。
- Provider/Model/Binding File 必须在各 Replica 一致部署。

## 已知限制

- `doris_admin` 不注册。
- ADBC 在 Token 绑定路由上 Fail Closed。
- Ossie 只读 Grounding，不执行语义表达式。
- 原生血缘异步 Best-effort，需要可查询 Companion Provider/Store。
- Audit 血缘/依赖证据是有界推导，可能不完整。
- Runtime Capability Support 不等于 Release Certification。
- Public Reverse Proxy Host/Origin 需要部署级验证。
- 没有真实事件源时，不提供 Subscription/Change Notification。

## 故障恢复流程

1. 分别检查 `/live` 与 `/ready`。
2. 记录 Request ID、公开原因码、Domain/Child、路由类别和时间，不能记录 Token。
3. 重新发现领域，排除陈旧 Manifest。
4. 有权限时检查 `doris_cluster.get_runtime_capabilities`。
5. 用同一账号和路由验证 Doris，包括负向 RBAC。
6. 检查 FE Candidate 与 Provider Health。
7. 对时间/行数/字节上限缩小 Query/Result 范围。
8. 只有进程/配置/连接池恢复确实需要时才重启；不能用重启替代权限或未支持能力
   修复。

按症状处理见[排障](troubleshooting.zh-CN.md)。
