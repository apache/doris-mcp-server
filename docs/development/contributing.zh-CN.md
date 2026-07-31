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

# 贡献与验证

[English](contributing.md) | 简体中文

Apache Doris MCP Server 把运行时 Catalog、Schema、安全策略、自动生成文档、测试和
Release Artifact 视为同一个公共合同。只有这些事实源保持一致，变更才算完成。

## 开发环境

```bash
git clone https://github.com/apache/doris-mcp-server.git
cd doris-mcp-server
uv sync --frozen --group dev
```

常用命令：

```bash
uv run pytest -q -W error
uv run ruff check .
uv run mypy doris_mcp_server
uv run bandit -q -c pyproject.toml -r doris_mcp_server doris_mcp_client
uv lock --check
uv build
```

先运行聚焦测试，再运行完整 Release Gate。单元测试成功不能证明
Host/Transport/Doris 边界真实可用。

## 事实源

| 合同 | 来源 |
|---|---|
| 产品版本 | `doris_mcp_server/_version.py` |
| Domain 与 Child 定义 | `doris_mcp_server/tools/domain_catalog.py` |
| 正式特性矩阵 | Doris Feature/Version Registry 模块 |
| Discovery/Availability | `domain_manifest.py`、`capability_detector.py` |
| 精确执行 | `domain_dispatcher.py`、领域 Runtime |
| Operation Authorization | `auth/operation_policy.py` 与 Catalog Policy |
| 配置 | `utils/config.py`、`.env.example` |
| 自动生成公开目录 | `docs/tool-registry.md` |
| 发布历史 | `CHANGELOG.md`、Release/Migration 文档 |

不能手工编辑 `docs/tool-registry.md`，必须由 Runtime Catalog 生成：

```bash
uv run python generate_tool_catalog.py
uv run python generate_tool_catalog.py --check
```

## 修改内置 Child

新增或修改 Child 前：

1. 确认操作属于现有领域。新顶级领域会改变稳定 Host 合同，需要架构 Review。
2. 内置操作保持只读。
3. 定义唯一 Feature ID、Child Name、Title、Canonical Description、Input/Output
   Schema、Annotation、Authorization Policy、Version Range、Variant 与
   Probe/Provider。
4. 增加一个精确 Handler Binding，不使用 Fuzzy Routing 或 Alias。
5. 在 Runtime 边界校验 Identifier、Caller Value、Time、Row、Byte、Collection
   和 Error Output。
6. 增加 Availability Evidence 与稳定 Reason Code；仅有版本号不够。
7. 测试授权发现、隐藏发现、精确执行、不可用执行、陈旧 Manifest、无效参数、成功
   Output Schema 和 Doris 负向权限。
8. 重新生成目录并更新英文/中文文档。
9. 同一 PR 更新 `CHANGELOG.md`。

当前 Release 合同是 8 Domain / 47 Child。数量变化属于有意识 API 工作，不是
普通 Handler 修改的副作用。

## 自定义 Provider

当能力属于外部业务 API 或部署专有扩展，而不是内置 Doris 合同时，使用自定义
Provider。Provider 必须：

- 注册已安装的 `doris_mcp_server.tool_providers` Entry Point；
- 通过 `MCP_TOOL_PROVIDERS` 显式启用；
- 使用唯一且有界的 Tool Name/Schema；
- 安全实现 Start/Stop Lifecycle；
- 声明安全 Audit Metadata 与可选 `ToolRateLimit`；
- 配置无效时 Fail Closed；
- 单独完成 Authentication/Authorization Review。

详见[自定义 Tool Provider](../custom-tool-providers.md)。

## 文档变更

- 根 `README.md` 和 `README.zh-CN.md` 保持精简且结构对齐。
- 细节进入对应 `docs/<area>/` Topic。
- 英文与 `.zh-CN.md` 文件保持等价 Heading 与语义。
- 保留发布打包/测试依赖的兼容路径。
- 使用相对仓库链接并运行 Internal-link Validator。
- 不在多份手工文档重复完整 Child Registry；精确 Binding/Policy 链接自动生成目录。
- 示例只能使用占位值，不能包含真实凭据或客户私有数据。

## 测试层次

### 聚焦单元与合同测试

- `test/tools/`——Domain Catalog、Manifest、Dispatcher、Capability、Runtime。
- `test/protocol/`——MCP Transport、Pagination、State、Schema、Trace、Error。
- `test/security/` 与 `test/auth/`——认证、授权、Secret、SQL 与数据安全。
- `test/deployment/`——Dependency、CI Contract、Packaging 与 Coverage Gate。

### Warnings-as-errors 全量测试

```bash
uv run pytest -q -W error
```

Coverage Gate 除全仓下限外，还包括 Protocol、Authentication 和 Core Manager 域。

### 真实 Doris 测试

真实 Doris 测试为 Opt-in，只能使用明确授权的测试集群/账号。它通过真实进程传输
执行，并且不能进行管理写入。验证：

- Streamable HTTP 与真实子进程 stdio；
- Hierarchical Discovery 与精确 Child Execution；
- 适用时验证 Flat Formal Name；
- 只读 Query、Metadata、FE/BE Monitoring；
- Row/Byte/Timeout 上限与 Cancellation Recovery；
- Doris Permission Denial 和 Secret-safe Error。

不能把破坏性或未审查测试指向共享集群。

### MCP Conformance

CI Checkout 固定提交的官方 MCP Conformance 项目，构建后运行
`server-stateless` 场景。Local Run 必须使用与 CI 相同的固定 Revision；随意使用
Latest Checkout 不能作为 Release Evidence。

### Build 与 Clean-wheel Smoke

```bash
uv build
```

在干净 Python 3.12 环境安装 Wheel，确认 Runtime Import/CLI Identity，并验证
Development-only Dependency 不进入运行时边界。

## Pull Request Gate

CI 必须通过：

1. **Quality：**Lock、Generated Catalog、Ruff、Mypy、Bandit。
2. **Tests：**Warnings-as-errors 全量测试与 Coverage Domain。
3. **Build and wheel smoke：**sdist/wheel 与 Clean Install。
4. **MCP 2026-07-28 conformance：**官方 Stateless Scenario。

影响 Doris Execution 的变更应在 PR 中增加真实集群证据，但不能暴露 Credential 或
Private Endpoint。

## Commit 与 PR 规范

- 每个 Branch 只承载一个完整变更。
- 最终 Review 前 Rebase 或 Merge 最新目标 Branch。
- Commit 前检查 `git status`、Staged Diff 和 Author Email。
- Commit Subject 与 PR Description 使用英文。
- 不提交本地台账、审计报告、Credential、`.env`、测试数据或 Runtime Log。
- 每个用户可见或 Release Engineering 变更都更新 `CHANGELOG.md`。
- 链接对应 Issue，并列出精确验证命令/结果。
- 解决冲突，不创建第二套竞争实现。

## Release 检查清单

- Product Version、CLI Identity、Package Metadata、Release Doc、Changelog 一致。
- 自动生成 8/47 Registry 与 Runtime 完全相同。
- 英文/中文文档链接有效。
- Target Doris Patch Certification 与证据一致。
- Known Limitation 保持明确。
- Full CI、Official Conformance、Clean Wheel 与必需 Real Doris Gate 全部通过。
- Release Tag 与 GitHub Release/Issue 指向最终文档。

继续阅读 [1.0 发布说明](../releases/1.0.0.zh-CN.md)和
[1.0 迁移](../migration/1.0.0.zh-CN.md)。
