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

# 能力可用性

[English](availability.md) | 简体中文

公共目录描述 Doris MCP Server 1.0 能表达什么；运行时 Availability 描述当前
请求身份在当前 Apache Doris 路由上能安全调用什么。这两个概念被刻意分开。

## 证据模型

Availability 综合以下条件：

1. **Catalog 合同**——Child 存在于经过审查的 8/55 目录。
2. **归一化版本**——相关活动 Doris 组件满足声明的 `major.minor.patch` 范围。
3. **实时特性 Probe**——必需 SQL 元数据、系统表、函数或允许的 HTTP 端点可见。
4. **Provider 就绪**——可选 ADBC、Ossie、MetricFlow 或 Lineage Provider 已配置且健康。
5. **部署模式**——所需 Classic/Cloud/Compute 行为兼容。
6. **路由一致性**——活动组件版本和请求路由可以安全评估；未知或混合证据可能
   Fail Closed。
7. **授权**——身份有权发现和执行精确 Child。
8. **Doris 可见性**——请求级 Doris 账号可以看到必需元数据/数据。

任何单一条件，包括版本号，都不能覆盖其他条件。

## 版本解析

探测器执行 Doris 版本 Probe，并接受真实返回值，例如：

```text
Doris version doris-3.0.3-rc03-43f06a5e26 (Cloud Mode)
```

能力和认证只使用：

```text
3.0.3
```

RC/GA 标记、Commit Hash 和部署提示只保留为诊断元数据，不创建独立支持桶。
组件版本向量采用保守评估；失效组件仍显示在清单中，但不参与活动能力范围 Gate。

## 快照生命周期

`DorisCapabilitySnapshot` 私有绑定到一个已解析路由，包含：

- 路由指纹；
- 能力代际；
- Provider 代际；
- 清洗后的集群指纹；
- 组件版本向量；
- 部署模式与混合版本标识；
- 有界 Probe 结果与稳定原因码；
- 已探测领域；
- 创建、过期和 stale-until 时间。

探测器按有界 TTL 缓存快照，并使用 Singleflight 避免并发发现形成 Probe Storm。
领域证据扩展同一个一致基础代际。如果扩展过程中路由变化，操作会被拒绝，而不是
把两个路由混在一起。

陈旧快照只能在配置的有界 Stale Window 内、且满足探测器规定的失败条件时使用。
Stale 状态会改变代际指纹并明确可见，不会伪装成新鲜证据。

## Manifest 渲染

每个已授权 Child 都会获得 `Availability` 对象，例如：

```json
{
  "status": "available",
  "callable": true,
  "reason_code": "CAPABILITY_AVAILABLE",
  "evidence_sources": [
    "catalog_contract",
    "version_range",
    "runtime_probe"
  ]
}
```

典型状态包括 Available、Unavailable/Unsupported、Degraded、Misconfigured、
Unknown 和 Pending。精确 Wire Enum 与原因码由运行时模型定义；`callable` 才是
执行 Gate。

Description 可以增加短的动态前缀帮助模型理解状态，但 Description 不是权威；
Host 与应用必须读取结构化对象。

## 可发现但不可调用

当运行时条件不满足时，已授权 Child 仍保留在 Manifest 中，Host 因而可以解释：

- 当前 Doris Patch 太低；
- 必需系统表或函数不存在；
- Provider 未启用或不健康；
- Companion Lineage Store 不完整；
- MetricFlow 未启用、Sidecar 不健康或无法编译 Doris SQL；
- 虽然配置了 ADBC，但用户没有明确指定 ADBC；
- 路由存在混合或未知组件版本；
- Doris 身份看不到必需元数据；
- 配置缺失或无效。

如果直接删除这些 Child，合同会显得不稳定，也会隐藏可操作信息。未授权 Child 则
会被过滤，调用方无法区分它与不存在的名称。

## Manifest 版本

任何相关公共合同、授权、能力代际、Provider 代际或路由证据变化都会改变
`manifest_version`。Host 可以在 Child 调用中携带发现到的版本。版本不匹配时
返回 `CHILD_MANIFEST_STALE`，要求重新发现。

它防止模型在已经过期的 Provider 或能力说明下继续调用，缩小检查与使用之间的
时间差。

## Hierarchical 与 Flat 模式

Hierarchical 模式在领域发现时解析 Availability。Flat 模式也会先从当前授权
Manifest 获取每个正式 Child，再放入 `tools/list`。两者因此共用：

- 同样的 55 个 Child；
- 同样的精确 Scope；
- 同样的动态 Availability；
- 同样的 Schema 与 Dispatcher；
- 同样的执行 Gate。

Flat 是 Host 兼容回退，不是能力绕过。

## 认证与运行支持的区别

Release Certification 记录命名 Doris Patch 上收集的证据；Runtime Support 则
针对实际连接路由判断。

项目基线为 Doris `2.0.0+`。1.0 目标集合为 `2.0.15`、`2.1.11`、
`3.0.3`、`3.1.4`、`4.0.5`、`4.0.6`、`4.0.7`、`4.1.0`、`4.1.1`、
`4.1.2`、`4.1.3`。发布边界上，`4.0.5` 是首个
完整认证目标。`target_uncertified` 不等于必然不可用；运行时 Manifest 仍然是
该连接集群上观察到的权威结果。

基线不表示 2.0 可以调用所有 Child。后续版本才出现的功能仍然可发现，但会以
`callable=false`、稳定 Reason Code 以及所需版本/Provider/Probe 证据说明原因。
Release Note 映射见 [Doris 版本能力矩阵](doris-version-matrix.zh-CN.md)。

## 示例：血缘路径选择

对于 `trace_column_lineage`：

- Doris 4.0.6 以前，可读 Audit 证据可以让有界 Audit Inference 成为主要路径；
- Doris 4.0.6+ 的 Native 模式还要求配置 Companion Provider、Store 可读、
  必需列完整且健康；
- 如果预期 Native 但它不可用，而 Audit 可读，Child 可以在明确 Degraded
  Fallback 下继续调用；
- 两类来源都不可用时，Child 保持可发现但不可调用。

这也是所有版本/Provider 相关 Child 的设计模式：说明实际证据路径，不根据版本
单独推定成功，也不把一种证据静默冒充另一种证据。

## 示例：ADBC 选择

- Doris 2.0 路由仍能发现两个 ADBC Child，但不可调用；
- Doris 2.1.0 引入 Arrow Flight SQL；2.1.0-2.1.4 会标为 Degraded，因为后续
  2.1 Patch 修复了空结果与元数据行为；
- 所有符合版本的路由仍必须通过 Provider 安装、Flight Endpoint 配置和实时探测；
- 调用还必须传 `explicit_adbc=true`，表示终端用户明确指定了 ADBC 或 Arrow
  Flight SQL；
- 普通 SQL 请求始终使用 `doris_query.execute_query`。

## 操作人员检查清单

当 Child 不可调用时：

1. 在有权限时调用 `doris_cluster.get_runtime_capabilities`。
2. 读取 Child `reason_code` 和 Evidence Source。
3. 确认请求身份与精确 Scope。
4. 确认实际 Doris 路由和账号权限。
5. 确认可选 Provider 配置与健康。
6. 把归一化三位数版本与特性范围对照。
7. 变更配置、路由、Provider 或权限后重新发现。

按错误类型的处理流程见[排障](../operations/troubleshooting.zh-CN.md)。
