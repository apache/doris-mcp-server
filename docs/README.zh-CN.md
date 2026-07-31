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

# Apache Doris MCP Server 文档

[English](README.md) | 简体中文

这套文档描述 1.0 的公共合同。根 README 只作为快速入口；下面的文档将产品
架构、能力行为、协议、安全、运维、参考、集成、迁移和发布分开维护。

## 建议阅读顺序

| 目标 | 文档 |
|---|---|
| 安装并运行本地 Server | [快速开始](getting-started/quickstart.zh-CN.md) |
| 理解 1.0 设计 | [总体架构](architecture/overview.zh-CN.md) |
| 追踪一次完整请求 | [请求与数据链路](architecture/request-lifecycle.zh-CN.md) |
| 查看全部公开领域 | [工具领域](capabilities/tool-domains.zh-CN.md) |
| 理解运行时可用性 | [能力可用性](capabilities/availability.zh-CN.md) |
| 接入 MCP Host | [Host 集成](integrations/hosts.zh-CN.md) |
| 安全部署 | [部署](operations/deployment.zh-CN.md) |

## 架构

- [总体架构](architecture/overview.zh-CN.md)——组件边界、顶层设计、控制面、
  执行面与扩展边界。
- [请求与数据链路](architecture/request-lifecycle.zh-CN.md)——初始化、一级发现、
  领域发现、Child 执行、Doris 路由和响应构建。
- [ADR 0001：订阅依赖真实变更事件](decisions/0001-subscriptions-require-change-events.md)
- [ADR 0002：显式状态句柄](decisions/0002-explicit-state-handles.md)

## 能力

- [工具领域](capabilities/tool-domains.zh-CN.md)——8 领域 / 47 Child 合同。
- [能力可用性](capabilities/availability.zh-CN.md)——版本解析、Probe、Provider、
  权限、Manifest 和 Fail Closed 行为。
- [自动生成工具目录](tool-registry.md)——正式名称、Handler 绑定、授权标识、
  Variant 和迁移输入的唯一事实源。

## 协议

- [MCP 2026-07-28 合同](protocol/mcp-2026-07-28.zh-CN.md)——传输、分页、
  Schema、错误、状态句柄、Trace 和旧协议隔离。

## 安全

- [安全与权限模型](security/security-model.zh-CN.md)——认证、分层授权、查询安全、
  数据安全、Secret 与部署策略。
- [Doris 细粒度权限控制](doris-fine-grained-access-control.zh-CN.md)——Doris RBAC、
  行策略、Token 绑定身份和操作示例。

## 运维

- [部署](operations/deployment.zh-CN.md)——stdio、HTTP、Docker、代理、Worker、
  Secret 与发布检查。
- [可靠性与限制](operations/reliability.zh-CN.md)——健康检查、连接路由、故障切换、
  运行边界、可观测性、回退和已知限制。
- [排障](operations/troubleshooting.zh-CN.md)——启动、就绪、鉴权、能力、查询和
  传输诊断。

## 参考与集成

- [配置参考](reference/configuration.zh-CN.md)
- [Host 集成](integrations/hosts.zh-CN.md)
- [自定义 Tool Provider](custom-tool-providers.zh-CN.md)

## 开发、迁移与发布

- [贡献与验证](development/contributing.zh-CN.md)
- [迁移到 1.0](migration/1.0.0.zh-CN.md)
- [1.0 发布说明](releases/1.0.0.zh-CN.md)
- 兼容发布路径：[migration-1.0.0.md](migration-1.0.0.md) 与
  [release-notes-1.0.0.md](release-notes-1.0.0.md)
- [ChangeLog](../CHANGELOG.md)
- [1.0 详细发布 Issue](https://github.com/apache/doris-mcp-server/issues/189)

## 文档约束

- 运行时代码与自动生成目录的优先级高于说明文字。
- 英文和简体中文主题文档必须保持相同章节结构与操作语义。
- `tool-registry.md` 只能自动生成，不允许手工编辑。
- 示例只能使用占位凭据，不能写入可部署 Secret。
- 不能仅凭 Doris 版本范围就声称能力可用；运行时 Probe、Provider 状态和权限
  都属于可用性合同。
