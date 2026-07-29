# Apache Doris MCP Server：MCP 2026-07-28 / SDK 2.0 开发台账

> 建账日期：2026-07-29
> 目标协议：MCP `2026-07-28`
> 目标 Python SDK：`mcp==2.0.x`
> 起始仓库基线：`0e843ae3432115ea5895fbd90a97d495c77f911c`
> 审计依据：[MCP-2026-07-28-AUDIT-REPORT.zh-CN.md](./MCP-2026-07-28-AUDIT-REPORT.zh-CN.md)

## 1. 目标与发布边界

最终目标不是“依赖能安装”，而是：

1. STDIO 和 Streamable HTTP 均原生支持 MCP 2026-07-28；
2. 同一服务保留官方 SDK 2.0 提供的 legacy 协议兼容；
3. HTTP 现代路径无协议会话，旧版多 worker 路径不依赖粘性会话；
4. `server/discover`、逐请求 `_meta`、标准 Header、`resultType`、缓存提示和标准错误完整；
5. 合法、未知或畸形请求均不能终止服务进程；
6. 鉴权、Origin、resource/audience、缓存和跨 worker 状态符合最小权限；
7. 官方 Conformance、测试、类型、静态安全、wheel 和容器门禁全部可重复执行。

在 `REL-003` 完成前，不得对外宣称完整支持 MCP 2026-07-28。

## 2. 状态与证据规则

| 状态 | 含义 |
|---|---|
| `BACKLOG` | 已识别，尚未领取 |
| `READY` | 前置条件满足，可以开始 |
| `IN_PROGRESS` | 当前批次正在开发 |
| `BLOCKED` | 有明确外部阻塞，必须记录原因 |
| `VERIFY` | 实现完成，等待真实门禁 |
| `DONE` | 完成定义全部满足，证据已回填 |
| `DEFERRED` | 有意识延期，必须记录重新评估条件 |

证据只接受：

- 可重复命令及退出码；
- 自动化测试名称和结果；
- 真实 HTTP/STDIO 请求与响应；
- 构建产物安装后的 smoke；
- 真实 Doris/Redis/代理环境回执；
- 对应提交或明确工作区 diff。

“代码已写”“肉眼看起来正确”不算完成。

## 3. 当前开发批次

批次：`BATCH-01-PROTOCOL-CORE`（已完成）

目标：

- 锁定 MCP Python SDK 2.0；
- 建立单一 v2 低层协议工厂；
- 让 STDIO、单 worker HTTP、多 worker HTTP 复用同一组 handlers；
- HTTP 使用官方 v2 双时代 transport，现代请求无状态；
- `server/discover` 成功；
- 未知方法不影响后续请求；
- 默认不再开放任意 Origin CORS；
- 为现代与 legacy 调用补最小自动化回归。

本批领取：

| PBI | 状态 |
|---|---|
| `PROTO-001` | `DONE` |
| `PROTO-002` | `DONE` |
| `PROTO-003` | `DONE` |
| `PROTO-004` | `DONE` |
| `PROTO-005` | `DONE` |
| `PROTO-006` | `DONE` |
| `PROTO-007` | `DONE` |
| `PROTO-009` | `DONE` |
| `PROTO-010` | `DONE` |
| `SEC-001` | `DONE` |
| `SEC-002` | `DONE` |
| `CORE-002` | `DONE` |
| `TEST-001` | `DONE` |
| `TEST-002` | `DONE` |
| `TEST-004` | `DONE` |
| `PKG-001` | `DONE` |

## 4. 协议核心台账

| ID | 优先级 | 工作项 | 前置 | 完成定义 | 状态 |
|---|---|---|---|---|---|
| `PROTO-001` | P0 | 将 `mcp` 依赖和锁文件升级到 2.0.x | 无 | `uv lock --check`、导入和 build 通过；不再允许 1.x | `DONE` |
| `PROTO-002` | P0 | 建立单一 SDK v2 `Server` 工厂 | PROTO-001 | tools/resources/prompts 六类 handlers 只定义一次；Result 类型完整 | `DONE` |
| `PROTO-003` | P0 | HTTP 切换官方 v2 双时代 runner | PROTO-002 | `server/discover` 成功；现代请求无 session ID；legacy initialize 可用 | `DONE` |
| `PROTO-004` | P0 | STDIO 切换 v2 dual-era runner | PROTO-002 | 现代 discover 和 legacy initialize 均有自动化或真实探针 | `DONE` |
| `PROTO-005` | P0 | 单/多 worker 复用协议工厂 | PROTO-002 | 两种模式不再复制 MCP handlers；现代请求行为一致 | `DONE` |
| `PROTO-006` | P0 | 未知/畸形请求异常隔离 | PROTO-003 | 未知方法、错 Header、错版本、畸形 body 后服务仍可处理下一请求 | `DONE` |
| `PROTO-007` | P1 | 标准请求 Header 验证 | PROTO-003 | `Mcp-Method`、条件式 `Mcp-Name` 和 body 不一致返回 `-32020`/400 | `DONE` |
| `PROTO-008` | P1 | 逐请求 `_meta` 与版本错误 | PROTO-003 | 缺能力、版本不支持分别返回 `-32021/-32022` | `DONE` |
| `PROTO-009` | P1 | 所有 Result 的 `resultType` | PROTO-002 | 现代 wire 所有成功结果包含 `complete`；MRTR 为 `input_required` | `DONE` |
| `PROTO-010` | P1 | 缓存提示策略 | PROTO-002 | cacheable 结果都有 `ttlMs/cacheScope`；身份相关结果一律 private | `DONE` |
| `PROTO-011` | P1 | 删除核心 GET/SSE 兼容改写 | PROTO-003 | 现代核心只走规范 POST；legacy adapter 独立且默认关闭 | `BACKLOG` |
| `PROTO-012` | P1 | 资源/工具/Prompt 分页 | PROTO-002 | 大列表使用稳定 cursor；无重复、丢失和跨权限翻页 | `BACKLOG` |
| `PROTO-013` | P2 | `subscriptions/listen` 决策与实现 | PROTO-003 | 有真实变更源才实现；否则能力不虚报并记录 N/A | `BACKLOG` |
| `PROTO-014` | P2 | MRTR 输入流程 | PROTO-009 | 至少一个真实交互需求用 `InputRequiredResult` 完成新旧协议回归 | `DEFERRED` |
| `PROTO-015` | P2 | Tasks 扩展决策 | PROTO-003 | 形成 ADR；无真实长任务需求则保持不启用 | `DEFERRED` |
| `PROTO-016` | P1 | JSON Schema 2020-12 验证和资源上限 | PROTO-002 | schema 合法；外部 `$ref` 不自动抓取；组合复杂度有界 | `BACKLOG` |
| `PROTO-017` | P2 | OpenTelemetry `_meta` 传播 | PROTO-003 | trace 上下文传播且不进入模型内容；敏感字段脱敏 | `BACKLOG` |
| `PROTO-018` | P1 | 产品身份版本单一来源 | PROTO-001 | discover、legacy serverInfo、CLI、包版本一致，不再回报 SDK 版本 | `VERIFY` |

## 5. 安全与授权台账

| ID | 优先级 | 工作项 | 前置 | 完成定义 | 状态 |
|---|---|---|---|---|---|
| `SEC-001` | P0 | 收紧 Origin/Host/CORS | PROTO-003 | 默认 loopback allowlist；攻击 Origin/Host 被拒绝；无通配 credentials | `DONE` |
| `SEC-002` | P0 | 删除 MCP Bearer query token | 无 | `?token=` 不再认证；只接受 Authorization Header | `DONE` |
| `SEC-003` | P0 | 删除管理 query token | 无 | `?admin_token=` 不再认证或传播；管理 Header 测试通过 | `BACKLOG` |
| `SEC-004` | P0 | 删除固定默认令牌和 secret | 无 | 新安装没有可用默认凭证；启用时强制高熵配置 | `BACKLOG` |
| `SEC-005` | P0 | 非 loopback 无鉴权拒绝启动 | SEC-001, SEC-004 | 非本机绑定且 auth 关闭时 fail closed，危险开关需显式 | `BACKLOG` |
| `SEC-006` | P1 | 统一 Bearer 规范化结构 | 无 | static/JWT/external OAuth/Doris OAuth 使用同一 credentials DTO | `BACKLOG` |
| `SEC-007` | P1 | issuer/resource/audience/scope 强校验 | SEC-006 | 两 issuer、两 resource、三 scope 交叉矩阵全部最小权限 | `BACKLOG` |
| `SEC-008` | P1 | 修复 external OAuth Bearer 字段断裂 | SEC-006 | Header token 能进入 provider；错误 challenge 合规 | `BACKLOG` |
| `SEC-009` | P1 | Doris OAuth token resource 绑定 | SEC-007 | 非当前 MCP resource 的 token 被拒绝 | `BACKLOG` |
| `SEC-010` | P1 | DCR `application_type` | 无 | 注册时必填、校验、持久化，redirect URI 规则匹配 | `BACKLOG` |
| `SEC-011` | P1 | 授权响应 RFC 9207 `iss` | 无 | 成功和错误响应都有正确 iss；客户端测试验证 issuer | `BACKLOG` |
| `SEC-012` | P1 | token endpoint 二次校验 resource | SEC-009 | 授权码绑定值与兑换请求不一致时拒绝 | `BACKLOG` |
| `SEC-013` | P2 | Client ID Metadata Documents | SEC-010 | 增加推荐注册路径；DCR 仅保留兼容 | `BACKLOG` |
| `SEC-014` | P1 | 令牌不可逆存储 | 无 | 只存 digest，明文只在创建时显示一次 | `BACKLOG` |
| `SEC-015` | P1 | 多 worker 统一吊销和状态存储 | SEC-014 | 并发写无丢失；任意 worker 立即看到吊销 | `BACKLOG` |
| `SEC-016` | P1 | 日志与错误脱敏 | 无 | Authorization、密码、token、SQL 敏感值不进入日志和响应 | `BACKLOG` |
| `SEC-017` | P1 | SQL 动态构造逐 sink 审计 | 无 | B608 逐项分诊；source-validation-sink 清单和回归齐全 | `BACKLOG` |
| `SEC-018` | P2 | FE/BE 监控 SSRF 边界 | 无 | 只访问配置节点；拒绝 metadata/link-local；超时和响应上限 | `BACKLOG` |

## 6. 行为正确性与架构台账

| ID | 优先级 | 工作项 | 前置 | 完成定义 | 状态 |
|---|---|---|---|---|---|
| `CORE-001` | P1 | list 异常不再返回空列表 | PROTO-002 | DB/权限/内部错误与真实空列表可区分 | `BACKLOG` |
| `CORE-002` | P1 | Tool 错误使用 `isError=true` | PROTO-002 | 可恢复业务错误对模型可见；内部异常为稳定协议错误 | `DONE` |
| `CORE-003` | P1 | Resource not found 使用 `-32602` | PROTO-002 | 不存在 URI 返回 Invalid Params，不返回错误正文成功 | `READY` |
| `CORE-004` | P1 | Prompt 错误类型化 | PROTO-002 | 缺参数、未知 prompt、DB 上下文失败语义不同 | `READY` |
| `CORE-005` | P1 | 单一 Tool Definition Registry | PROTO-002 | schema、policy、handler、审计和文档同源 | `BACKLOG` |
| `CORE-006` | P1 | `/live` 与 `/ready` 分离 | 无 | Doris 不可用时 live 可真、ready 必假；探针有短超时 | `BACKLOG` |
| `CORE-007` | P1 | 显式跨调用 handle | PROTO-003, SEC-015 | 状态不依赖协议 session；handle 绑定 principal/expiry | `BACKLOG` |
| `CORE-008` | P2 | 大结果边界 | 无 | 行数、字节数、超时和取消可配置且有硬上限 | `BACKLOG` |
| `CORE-009` | P2 | manager 模块职责拆分 | CORE-005 | 不改变行为前提下缩小超大文件，模块边界有测试 | `BACKLOG` |
| `CORE-010` | P1 | 修复 SQL profile 分析未绑定 `auth_context` | 无 | 真实 Doris 调用不再触发局部变量未赋值；鉴权上下文覆盖测试通过 | `READY` |
| `CORE-011` | P1 | 修复数据新鲜度空阈值比较 | 无 | 阈值缺失或为 `None` 时返回类型化错误/默认值，不抛 `TypeError` | `READY` |
| `COMPAT-001` | P1 | Doris 4.0 元数据字段兼容 | 无 | Doris 4.0.5 的角色/权限查询不再依赖不存在的 `Default_role` 字段 | `READY` |
| `COMPAT-002` | P2 | FE/BE HTTP 端点独立配置 | SEC-018 | SQL、FE HTTP、BE HTTP 可分别配置主机/端口并通过代理/隧道环境测试 | `BACKLOG` |

## 7. 测试、构建和发布台账

| ID | 优先级 | 工作项 | 前置 | 完成定义 | 状态 |
|---|---|---|---|---|---|
| `TEST-001` | P0 | SDK v2 现代/legacy 协议单测 | PROTO-002 | discover、list/call/read/get、legacy initialize 自动化通过 | `DONE` |
| `TEST-002` | P0 | HTTP 进程存活回归 | PROTO-003 | 新版、未知、畸形请求后下一次请求成功 | `DONE` |
| `TEST-003` | P0 | 官方 Conformance `server-stateless` | PROTO-003 | 2026-07-28 场景全绿，回执入账 | `READY` |
| `TEST-004` | P1 | 修复 pytest 路径和 E2E fixture | 无 | 完整 pytest 无 setup error；外部测试自启或明确 skip | `DONE` |
| `TEST-005` | P1 | 真实 Doris 集成矩阵 | TEST-004 | 只读/写入、权限不足、故障恢复、超时均覆盖 | `IN_PROGRESS` |
| `TEST-006` | P1 | 鉴权交叉矩阵 | SEC-007 | auth method × scope × tool × resource 全覆盖 | `BACKLOG` |
| `TEST-007` | P1 | GitHub Actions | TEST-001 | sync、test、ruff、mypy、bandit、build、wheel smoke、conformance | `BACKLOG` |
| `TEST-008` | P2 | Ruff 存量清零 | 无 | 源码和测试 `ruff check` 零错误 | `BACKLOG` |
| `TEST-009` | P2 | Mypy 分层收紧 | PROTO-002 | 协议/鉴权 strict 先归零，再消除全部存量 | `BACKLOG` |
| `TEST-010` | P2 | Bandit 分诊 | SEC-017 | 所有 finding 有修复或精确豁免理由 | `BACKLOG` |
| `TEST-011` | P2 | 消除测试运行时与时间 API 告警 | TEST-004 | 无未 await coroutine；迁移 timezone-aware UTC；pytest warning 归零 | `IN_PROGRESS` |
| `TEST-012` | P1 | 真实 Doris 工具错误路径回归 | TEST-005 | CORE-010/011、COMPAT-001 的失败样例自动化并在真实环境转绿 | `READY` |
| `TEST-013` | P2 | 覆盖率分域提升 | TEST-004 | 协议/鉴权/核心 manager 先达 80%，再定义全仓门槛 | `BACKLOG` |
| `PKG-001` | P1 | 修复 `doris-mcp-client` wheel | 无 | 干净 venv 安装 wheel 后两个 CLI `--help` 成功 | `DONE` |
| `PKG-002` | P2 | 运行时/开发依赖分层 | PROTO-001 | runtime 不包含 pytest/lint/build 工具 | `BACKLOG` |
| `DEPLOY-001` | P1 | Compose 端口和 healthcheck | CORE-006 | 无端口冲突；health/readiness 指向真实端口 | `BACKLOG` |
| `DEPLOY-002` | P1 | Compose secrets 与镜像固定 | SEC-004 | 无仓库弱密码；镜像使用明确版本或 digest | `BACKLOG` |
| `DOC-001` | P1 | 协议支持矩阵和迁移指南 | PROTO-003 | README 明确现代/legacy 行为、Header、部署限制 | `BACKLOG` |
| `DOC-002` | P2 | 版本、命令和 CHANGELOG 对齐 | PROTO-018, PKG-001 | 示例、CLI、包、serverInfo、CHANGELOG 一致 | `BACKLOG` |

## 8. 发布门台账

| ID | 优先级 | 发布门 | 完成定义 | 状态 |
|---|---|---|---|---|
| `REL-001` | P0 | Alpha：协议骨架 | PROTO-001～010、SEC-001、TEST-001/002 全部完成 | `DONE` |
| `REL-002` | P0 | Beta：安全与真实 Doris | P0/P1 安全项、真实 Doris、Conformance、wheel、Compose 全绿 | `BACKLOG` |
| `REL-003` | P0 | GA：宣称支持 2026-07-28 | 完整测试绿；无未接受 P0/P1；文档和回执齐全 | `BACKLOG` |

## 9. 决策记录

### ADR-001：协议层使用 SDK v2 低层 `Server`

状态：`ACCEPTED`

理由：

- 当前工具 schema 是手工定义，低层 API 能原样保留；
- 当前已有统一 `call_tool(name, arguments)` 分派，适合一个 `on_call_tool`；
- 可以显式控制 `CallToolResult`、`is_error`、缓存和 `_meta`；
- 官方 v2 runner 仍自动提供 `server/discover`、双时代协议和现代 Header/元数据处理。

约束：

- 不继续复制 handlers；
- 不使用 SDK 私有模块或 monkey patch；
- 低层 handler 必须自行构造完整 Result；
- 参数 schema 验证将在 `PROTO-016` / `CORE-005` 补齐。

### ADR-002：HTTP legacy 路径使用 `stateless_http=True`

状态：`ACCEPTED`

理由：

- 当前 Doris 工具没有服务端反向请求依赖；
- 多 worker 不再需要粘性 session；
- 2026-07-28 现代路径本身始终无状态；
- 后续若增加 MRTR，由现代协议完成；legacy 交互能力需单独评估。

### ADR-003：缓存默认私有

状态：`ACCEPTED`

理由：

- tools/resources 可随身份、scope 和 Doris 用户变化；
- 在身份感知 cache key 完成前，公共缓存存在越权泄露风险；
- 初期宁可 `ttlMs=0`，不以性能换隔离性。

## 10. 验证回执

### 建账基线

```text
HEAD: 0e843ae3432115ea5895fbd90a97d495c77f911c
mcp locked: 1.9.3
full pytest: 319 passed / 45 failed / 12 skipped / 8 errors
coverage: 36%
2026 server/discover: HTTP 500, process exited
```

### BATCH-01

提交与 PR：

```text
commit: 5829ea3 feat: add MCP 2026-07-28 protocol core
PR: https://github.com/apache/doris-mcp-server/pull/93
```

#### 实现回执

- `mcp` 依赖已锁定为 `>=2.0.0,<2.1.0`，`uv.lock` 解析为 `mcp==2.0.0`；
- 新增 `doris_mcp_server/protocol.py`，六类 MCP handlers 由 STDIO、单 worker HTTP、多 worker HTTP 共用；
- 删除 SDK 1.x 私有行为改写和 transport monkey patch；
- HTTP 使用 SDK 2.0 双时代、无状态 runner，路由固定为 `/mcp`；
- STDIO 使用 SDK 2.0 dual-era runner；
- 多 worker 父进程将解析后的 Doris/Server 配置显式传给子进程，避免 worker 回退到默认连接；
- SDK 2.0 客户端迁移完成，`doris-mcp-client` 已作为 wheel 内可执行入口发布；
- MCP query-string token 已拒绝，Origin/Host 默认按 loopback allowlist 收紧；
- 测试发现的无事件循环 coroutine 泄漏已修复；pytest 收集目录已修正为 `test/`。

#### 自动化回执

```text
uv run pytest -q
331 passed / 57 skipped / 0 failed / 247 warnings
coverage: 36%

uv run pytest -q test/protocol/test_mcp_v2_protocol.py
3 passed

uv lock --check
resolved: 181 packages

ruff（本批协议、客户端、鉴权和新增测试文件）
All checks passed

python -m compileall
passed
```

协议回归覆盖：

- 现代 `server/discover`；
- legacy `initialize`；
- tools/resources/prompts 的 list/call/read/get；
- `resultType=complete`；
- 私有 `ttlMs=0/cacheScope=private`；
- tool 错误 `isError=true`；
- 未知 method `-32601`；
- malformed JSON `-32700`；
- Header/body 不一致 `-32020`；
- 不支持版本 `-32022`；
- 攻击 Origin `403`；
- 攻击 Host `421`；
- 失败请求后下一次 discover 仍成功。

#### 真实 Doris 回执

环境：

```text
host: 192.168.31.63
Doris FE MySQL: 9030
Doris FE HTTP: 8030
Doris BE HTTP: 8040
Doris: 4.0.5-rc01-59de8c4c524
database: hhm_dt_sim
current tables: 1008
org_tenant rows: 47040
```

连接通过既有 SSH key 和临时本地隧道完成；凭据未写入仓库、测试或台账。

真实矩阵：

| 入口 | 协议时代 | worker | tools | 真实查询 |
|---|---|---:|---:|---:|
| HTTP | `2026-07-28` | 1 | 25 | `org_tenant=47040` |
| HTTP | `2025-11-25` | 1 | 25 | `org_tenant=47040` |
| STDIO | `2026-07-28` | 1 | 25 | `org_tenant=47040` |
| STDIO | `2025-11-25` | 1 | 25 | `org_tenant=47040` |
| HTTP | `2026-07-28` | 2 | 25 | 4/4 成功 |
| HTTP | `2025-11-25` | 2 | 25 | 2/2 成功 |

多 worker health 并发探针同时观察到两个 worker PID；现代路径无 session ID，legacy 路径在 `stateless_http=True` 下无需粘性会话。

外部安全 API 套件通过显式环境变量接入当前 MCP 实例：

```text
test/security/test_sql_injection_api.py
45 passed
```

#### 构建回执

```text
uv build
dist/doris_mcp_server-0.6.1.tar.gz
dist/doris_mcp_server-0.6.1-py3-none-any.whl

isolated wheel install:
server package: 0.6.1
mcp SDK: 2.0.0
doris-mcp-server --help: passed
doris-mcp-client --help: passed
```

#### 真实环境新增缺陷

这些缺陷不是协议 runner 的失败，已分别登记，不能用 BATCH-01 的协议门禁掩盖：

1. `CORE-010`：SQL profile 分析路径存在未绑定 `auth_context`；
2. `CORE-011`：数据新鲜度路径可能对 `None` 阈值做数值比较；
3. `COMPAT-001`：部分权限分析 SQL 与 Doris 4.0.5 元数据字段不兼容；
4. `COMPAT-002`：FE/BE HTTP 与 SQL 连接端点需要独立配置，代理/隧道场景不能假设同一 host。

### PROTO-008

新增按 method 配置的客户端能力门禁。默认 Doris MCP handlers 不声明额外客户端能力；一旦某个 method 显式声明要求，现代协议请求缺少对应 capability 时返回：

```text
HTTP status: 400
JSON-RPC code: -32021
data.requiredCapabilities: 完整 ClientCapabilities
```

验证覆盖：

- HTTP 缺少 `clientCapabilities` 元数据返回 `-32602`；
- HTTP 缺少 method 所需 extension 返回 `-32021`；
- HTTP 携带所需 extension 后同一调用成功；
- STDIO 子进程缺少所需 extension 返回 `-32021`；
- STDIO 子进程使用不支持版本返回 `-32022` 及 `supported/requested`；
- HTTP 与 STDIO 都在错误后继续成功处理后续请求；
- legacy 协议不受现代能力门禁影响。

```text
test/protocol/test_mcp_v2_protocol.py
5 passed
```

## 11. 下一开发批次

批次：`BATCH-02-CONFORMANCE-AND-ERROR-SEMANTICS`

按以下顺序推进：

1. `CORE-003` / `CORE-004`：Resource 与 Prompt 错误类型化；
2. `CORE-010` / `CORE-011` / `COMPAT-001`：修复真实 Doris 已复现缺陷；
3. `TEST-003`：运行官方 `server-stateless` Conformance；
4. `TEST-005` / `TEST-012`：补权限不足、超时、故障恢复和工具错误路径；
5. `PROTO-018` / `DOC-001` / `DOC-002`：版本单一来源和迁移文档；
6. `SEC-003`～`SEC-005`：进入下一安全批，完成非 loopback fail-closed。

`REL-001` 已达成。`REL-002` 仍由官方 Conformance、完整真实 Doris 矩阵、P0/P1 安全项、Compose 和发布门阻塞。
