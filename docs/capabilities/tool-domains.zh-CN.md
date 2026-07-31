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

# 工具领域

[English](tool-domains.md) | 简体中文

1.0 只有一套内置只读目录：8 个顶级领域、55 个精确 Child。本文解释产品语义；
自动生成的[工具目录](../tool-registry.md)才是 Feature ID、Handler Binding、授权
标识、Variant 和迁移输入的权威事实源。

## 发现与执行形态

发现领域：

```json
{}
```

执行一个已发现 Child：

```json
{
  "child_tool": "<精确 Child 名称>",
  "arguments": {},
  "manifest_version": "<发现阶段返回的值>"
}
```

Availability 与运行时相关。下面列出的 Child 属于公共合同，但只有版本、特性、
Provider、权限、路由和配置条件全部通过时才可以调用。

## `doris_catalog`——元数据导航

| Child | 用途 | 重要行为 |
|---|---|---|
| `list_catalogs` | 列出内部与外部 Catalog。 | 有界、有序、可过滤；外部对象可见性服从 Doris 权限。 |
| `list_databases` | 列出指定 Catalog 中的数据库。 | 多 Catalog 路由必须使用精确 Catalog。 |
| `list_tables` | 列出数据库中的表与视图。 | 稳定过滤和签名游标分页。 |
| `get_table_context` | 组装表的 `basic`、`schema`、`comments`、`indexes` Section。 | `schema` 始终必需；可选 Section 可独立报告 `partial`/`unavailable`。 |
| `get_table_size` | 返回表与有界分区大小证据。 | 使用实时统计/元数据；通过截断标识替代无界扫描。 |

`get_table_context` 合并了 1.0 以前的 5 个顶级调用。它保留 Section 的来源和
Warning，不会把部分可用的元数据压成一个含义不清的对象。

## `doris_query`——只读查询与诊断

| Child | 用途 | 重要行为 |
|---|---|---|
| `execute_query` | 执行一条只读 SQL。 | SQL Guard、参数绑定、超时/行数/字节上限、脱敏、确定性错误。 |
| `explain_query` | 返回有界 Doris 查询计划。 | 目标 SQL 本身也必须通过只读 Guard。 |
| `get_query_profile` | 获取有界 FE Query Profile。 | 依赖 FE HTTP/Profile 证据，绝不返回凭据。 |
| `diagnose_query_performance` | 根据 Plan/Profile/Query 证据生成确定性结论。 | 基于规则与证据，不编造置信度。 |
| `list_slow_queries` | 列出有界慢查询证据。 | 需要可读审计历史，敏感 SQL 字段会清洗。 |
| `get_adbc_connection_info` | 报告 Arrow Flight SQL/ADBC 就绪状态。 | 高级能力，默认关闭；只有用户明确指定 ADBC 后才可使用。 |
| `execute_adbc_query` | 通过 ADBC 执行有界只读查询。 | 必须传 `explicit_adbc=true`；绝不替代普通 `execute_query`；Token 绑定路由 Fail Closed。 |

普通 SQL 始终使用 `execute_query`。两个 ADBC Child 只服务于用户明确点名 ADBC
或 Arrow Flight SQL 的高级请求；Schema 与运行时都会强制 `explicit_adbc=true`。
Query 领域允许 SQL，因为 SQL 是 Doris 原生查询接口；但不会公开 DDL、DML、
管理 SQL、任意堆叠语句或无界结果通道。

## `doris_cluster`——运行与资源状态

| Child | 用途 | 重要行为 |
|---|---|---|
| `get_cluster_overview` | 汇总部署、版本与节点健康。 | 保留混合版本/失效组件证据，但不会把失效节点当作活动 Gate。 |
| `list_cluster_nodes` | 列出 FE/BE 等组件清单。 | 返回清洗后的主机、状态和版本证据。 |
| `list_active_tasks` | 查看活动 Query/Load/Task 进度。 | 根据实证选择统一或旧版视图。 |
| `get_monitoring_metrics` | 获取 Allowlist 内的有界指标。 | 指标名、节点数和值都有限界。 |
| `get_memory_stats` | 查看 Memory Tracker 与使用量。 | 明确报告来源和部分可用状态。 |
| `get_cache_status` | 查看 File Cache/Cache 状态。 | 按 Patch 和实时元数据选择高级或基础证据。 |
| `get_compaction_status` | 查看 Compaction 状态。 | 使用系统表或允许的 HTTP 证据，并明确回退。 |
| `get_workload_group_status` | 查看 Workload Group 定义和指标。 | 需要可读 Workload Group 元数据。 |
| `get_compute_group_status` | 查看 Compute Group。 | Availability 取决于部署形态和元数据权限。 |
| `analyze_resource_growth` | 分析有界历史资源记录。 | 需要历史指标/审计证据，不做凭空预测。 |
| `get_runtime_capabilities` | 返回清洗后的能力快照。 | 公开有界原因/证据，不公开凭据或私有路由细节。 |

## `doris_pipeline`——导入与新鲜度

| Child | 用途 | 重要行为 |
|---|---|---|
| `get_ingestion_status` | 查看 Batch、Stream、Routine 与 Insert Job。 | 版本感知 Job View，集合有界。 |
| `diagnose_ingestion` | 诊断观察到的导入失败和状态。 | 基于返回证据执行确定性规则。 |
| `get_materialized_view_status` | 查看 MV 定义、Job、Task 和 Compute Context。 | 选择可用元数据路径并报告部分状态。 |
| `monitor_data_freshness` | 报告有界表新鲜度证据。 | 没有可观察时间戳/来源就不会声称“新鲜”。 |
| `analyze_data_dependencies` | 推导有界上下游依赖。 | 来自审计运行证据，不等于完整静态血缘证明。 |

## `doris_search`——文本、向量与混合检索

| Child | 用途 | 重要行为 |
|---|---|---|
| `search_data` | 执行结构化文本、向量或混合检索。 | 校验目标索引/字段、向量维度、Filter、Top-K 和返回字段。 |
| `preview_text_analysis` | 预览 Doris 分词器/Analyzer 输出。 | 输入文本和输出 Token 都有界。 |
| `inspect_search_indexes` | 查看倒排与 ANN 索引元数据。 | 不公开存储 Secret 或无关表属性。 |
| `diagnose_search_query` | Explain 并诊断 Search 执行。 | 必须使用已校验结构化请求和有界 Plan 证据。 |

调用方的值保持 Driver Binding。结构化 Search Child 不接受原始 Doris `SEARCH`
DSL 片段或任意 Filter SQL。

## `doris_governance`——质量、血缘、审计与访问

| Child | 用途 | 重要行为 |
|---|---|---|
| `analyze_columns` | 分析有界列统计与质量证据。 | 列数和 Sampling 有界；Doris 权限最终生效。 |
| `analyze_table_storage` | 查看分区、索引和存储形态。 | Model-facing 输出移除敏感 Location/Property。 |
| `get_lineage_capability_status` | 解释当前血缘路径及原因。 | 区分 Native、Audit Primary、Degraded Fallback 和 Unavailable。 |
| `trace_column_lineage` | 追踪可归因的有界血缘边。 | 符合条件时使用 Native Provider，否则保守审计推导。 |
| `analyze_data_access_patterns` | 汇总有界审计访问证据。 | 清洗原始 SQL、Client 和认证数据。 |
| `get_recent_audit_logs` | 返回有界近期审计事件。 | 时间窗口和结果数封顶，敏感字段脱敏。 |
| `list_udfs` | 查看可见 UDF 元数据。 | 版本感知 Function Family，不执行函数。 |
| `get_auth_mapping_status` | 查看清洗后的 LDAP/OIDC Role Mapping 就绪状态。 | 不公开 Bind 凭据、带 Secret 的规则或原始 Provider 错误。 |

原生血缘同时要求符合条件的 Doris 版本与健康可查询 Companion Store。仅有
`4.0.6+` 版本号不能让它变成可调用状态。

## `doris_lakehouse`——外部与半结构化数据

| Child | 用途 | 重要行为 |
|---|---|---|
| `inspect_external_catalog` | 查看可见外部 Catalog 元数据和就绪状态。 | Property 与 Location 会清洗。 |
| `inspect_lakehouse_table` | 查看表格式、Snapshot、分区、Lifecycle 和 Pushdown 证据。 | 4.1 Lifecycle 特征与基础元数据分开报告。 |
| `inspect_variant_column` | 查看 Variant 类型与有界 Shape 证据。 | 不返回 Sample Value/敏感 Path；高级 4.1 特征受能力 Gate。 |

## `doris_semantic`——可选语义消费者

| Child | 用途 | 重要行为 |
|---|---|---|
| `list_semantic_models` | 从配置 Provider 列出有界且已审查模型。 | 领域默认关闭，必须显式启用 Provider。 |
| `get_semantic_model_summary` | 为一个精确 `model_ref` 返回有界摘要。 | 不根据 Prompt 猜模型。 |
| `get_semantic_context` | 构建确定性的只读 Grounding Context。 | 需要精确模型、路由级映射与 Doris 可见性。 |
| `get_semantic_mapping_status` | 解释私有 Doris Binding 就绪状态。 | 返回状态/原因，不公开私有 Binding Manifest。 |
| `list_metricflow_models` | 列出已配置的 MetricFlow Model Reference。 | Provider 默认关闭；不根据 Prompt 猜模型。 |
| `get_metricflow_status` | 返回 Provider/Model 校验状态。 | 需要一个精确 `model_ref`。 |
| `list_metricflow_metrics` | 列出有界 Metric 和可选 Dimension。 | 需要精确 `model_ref`，支持有界过滤。 |
| `get_metricflow_group_bys` | 返回所选 Metric 可用的 Group-by Dimension。 | Provider 在精确模型内验证 Metric 集合。 |
| `list_metricflow_saved_queries` | 列出有界 Saved Query 元数据。 | 不执行 Saved Query。 |
| `get_metricflow_dimension_values` | 编译并执行有界 Dimension Value 查询。 | Provider 编译 Doris SQL，MCP SQL Guard 与 Query Runtime 执行。 |
| `compile_metricflow_query` | 把结构化 MetricFlow 请求编译为 Doris SQL。 | 只编译，不返回查询结果，也不能绕过 SQL Guard。 |
| `execute_metricflow_query` | 编译并执行有界 MetricFlow 请求。 | 执行必须回到 `DorisQueryRuntime`，统一处理路由、RBAC、限额、审计与脱敏。 |

Ossie 拥有语义定义；MetricFlow 拥有指标语义与查询编译。MCP Server 是受治理
消费者：不创作模型、不猜模型，也不允许 Provider 绕过 MCP Query Runtime 直接
执行 Doris SQL。详见 [MetricFlow 接入](../integrations/metricflow.zh-CN.md)。

## 预留与扩展面

- `doris_admin` 故意不注册。
- 自定义 Provider 是显式扩展，不计入 8/55。
- MCP Resource 与 Prompt 是独立协议面，不是隐藏 Child。
- 1.0 以前的 Tool 名称不是可调用 Alias。

每个 Child 如何成为 `callable=true` 或 `callable=false`，详见
[能力可用性](availability.zh-CN.md)。
