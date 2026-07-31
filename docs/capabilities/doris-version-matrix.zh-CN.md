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

# Doris 版本能力矩阵

[English](doris-version-matrix.md) | 简体中文

Doris MCP Server 的项目基线是 Apache Doris `2.0.0+`。这不表示每个版本都能
调用全部 Child。每个 Child 都由一组机器可读条件共同过滤：归一化三位数版本、
实时特性探测、Provider 就绪、部署形态、路由一致性、授权以及 Doris 对象可见性。

事实源是 `doris_feature_matrix.py`；本文汇总与公开 MCP 能力有关的 Release Note
审查结果，不替代完整 Apache Doris Release Note。

## 版本族

| Doris 范围 | MCP 相关能力基线 | 重要 Gate |
|---|---|---|
| `2.0.x` | Catalog 元数据、MySQL 只读 Query/Explain/Profile、Load/MV 证据、Workload Group、基于 Audit 的治理、外部 Catalog、倒排索引文本检索和可选语义 Provider。 | 每条路径仍需通过元数据、Endpoint、Provider 与权限探测。ADBC 和 Variant 因版本不可用。 |
| `2.1.0-2.1.4` | 增加 Arrow Flight SQL/ADBC 与 Variant 类型查看。 | 早期 Patch 的 ADBC 标为 `degraded`；仍需 Provider、Flight Endpoint、实时探测和用户明确指定 ADBC。 |
| `2.1.5-2.1.x` | 保留 2.1 能力，并改善 Flight SQL 空结果行为；后续 Patch 继续改善元数据、序列化与错误处理。 | `2.1.5+` 通过早期版本成熟度 Gate，但实时探测仍然必需。 |
| `3.x` | 支持 2.x 基础，并按连接 Patch 公开相应元数据/运行时改善。 | MCP 没有全局 3.x Gate，仍按 Child 和路由判断。 |
| `4.0.0-4.0.5` | 增加 ANN/向量以及向量+倒排混合检索 Variant，并增加 Plan/Index 特征。 | Index 类型、Metric、Dimension、函数和实际元数据必须匹配请求。 |
| `4.0.6` | 增加原生血缘事件路径和 Compaction Task Tracker 路径。 | 原生血缘还要求兼容 FE Plugin 与健康可查询 Companion Store；Audit Inference 是显式 Degraded 回退。 |
| `4.0.7` | 增强 Observability/Audit/Cache 证据和部分 MTMV Compute Group 证据。 | 精确探测字段；字段缺失时选择 Base 或 Degraded Variant。 |
| `4.1.0` | 增加 Storage V3/高级 Variant、湖仓 Lifecycle、Continuous Load 与高级 Cache Variant。 | 高级部分不可用时，基础 Child 仍可工作并单独报告状态。 |
| `4.1.1` | 增加统一 Task Progress 与 4.1 Compaction Task Tracker 路径。 | 必需对象不存在时回退到旧 Task/Compaction Summary。 |
| `4.1.2` | 增加 OIDC Role Mapping 证据和部分 MTMV Compute Group 支持。 | 必须通过 Provider、系统对象、部署形态与可见性探测。 |
| `4.1.3+` | 增加 Python UDF/UDAF/UDTF 家族元数据。 | Base UDF 元数据路径独立存在，旧版本仍可使用。 |

## Child 家族映射

| 公开 Child | 最低版本 | 后续 Variant 或 Provider 规则 |
|---|---:|---|
| `doris_catalog.*` | `2.0.0` | ANN/BM25 Context 要求 `4.0+`；Storage V3 Variant Context 要求 `4.1+`。 |
| `execute_query`、`explain_query`、`get_query_profile`、`diagnose_query_performance`、`list_slow_queries` | `2.0.0` | Query/Profile/Audit 证据独立探测；Search Plan 特征要求 `4.0+`。 |
| `get_adbc_connection_info`、`execute_adbc_query` | `2.1.0` | 默认关闭、必须显式指定；`2.1.0-2.1.4` Degraded；普通 SQL 绝不自动选择。 |
| `doris_cluster.*` | `2.0.0` | 新 Cache、Compaction、Observability、Task、Compute Group 特征按对应 Variant 选择。 |
| `doris_pipeline.*` | `2.0.0` | Continuous Load 要求 `4.1+`；部分 MTMV Compute Group 证据要求 `4.0.7` 或 `4.1.2+`。 |
| 倒排文本检索路径 | `2.0.0` | 要求兼容倒排索引和 Search/Tokenizer 语法探测。 |
| ANN/向量/混合检索路径 | `4.0.0` | 要求 ANN/Index/Metric/Dimension 证据兼容；文本回退可以继续调用。 |
| Governance 与 Audit 血缘 | `2.0.0` | `4.0.6` 前以 Audit Provider 为主；只有全部原生条件通过才优先 Native。 |
| 原生血缘 | `4.0.6` | 需要 Companion Plugin 与 Queryable Store；仅版本符合不够。 |
| `inspect_external_catalog`、基础 Lakehouse 查看 | `2.0.0` | 需要外部 Catalog Provider 与可见元数据。 |
| `inspect_variant_column` | `2.1.0` | Storage V3/Sparse/Doc Mode 特征要求 `4.1+`。 |
| Ossie Child | `2.0.0` 项目基线 | 默认关闭；要求精确 `model_ref`、已审查模型库、私有 Binding、Policy、Route 与权限探测。 |
| MetricFlow Child | `2.0.0` 项目基线 | 默认关闭；要求精确 `model_ref`、Provider 协议、模型元数据、Doris Dialect 编译、SQL Guard 与 Query Runtime 探测。 |

## ADBC 决策规则

ADBC 不是自动优化。两个 ADBC 正式调用都要求 `explicit_adbc=true`，Server 会
独立拒绝缺少该字段的请求。除非终端用户明确要求 ADBC 或 Arrow Flight SQL，
Host/模型都必须使用普通 `doris_query.execute_query`。这样可以避免工具选择歧义，
也明确 Flight Endpoint 与集群调参属于高级部署事项。

## 来源集合

矩阵记录稳定 Source ID 和审查日期。主要一手来源包括：

- [Doris 2.0.0 Release Note](https://doris.apache.org/docs/3.0/releasenotes/v2.0/release-2.0.0)
- [Doris 2.0.15 Release Note](https://doris.apache.org/docs/2.0/releasenotes/v2.0/release-2.0.15)
- [Doris 2.1.0 Release Note](https://doris.apache.org/docs/3.x/releasenotes/v2.1/release-2.1.0/)
- [Doris 2.1.11 Release Note](https://doris.apache.org/releases/v2.1/release-2.1.11/)
- [Doris 2.1 Arrow Flight SQL 指南](https://doris.apache.org/docs/2.1/db-connect/arrow-flight-sql-connect/)
- [Doris 3.0.0 Release Note](https://doris.apache.org/docs/3.x/releasenotes/v3.0/release-3.0.0/)
- [Doris 3.1.0 Release Note](https://doris.apache.org/docs/4.x/releasenotes/v3.1/release-3.1.0/)
- [Doris 3.x 文档](https://doris.apache.org/docs/3.x/)
- [Doris 4.0.0 Release Note](https://doris.apache.org/releases/v4.0/release-4.0.0/)
- [Doris 4.0.6 Release Note](https://doris.apache.org/releases/v4.0/release-4.0.6/)
- [Doris 4.0.7 Release Note](https://doris.apache.org/releases/v4.0/release-4.0.7/)
- [Doris 4.1.0 Release Note](https://doris.apache.org/releases/v4.1/release-4.1.0/)
- [Doris 4.x 文档](https://doris.apache.org/docs/4.x/)

Patch Certification 与 Runtime Support 相互独立。某个路由即使不是已认证目标，
仍可能被支持；对当前身份和路由而言，Runtime Manifest 才是权威结果。
