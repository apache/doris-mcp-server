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
| `CORE-003` | P1 | Resource not found 使用 `-32602` | PROTO-002 | 不存在 URI 返回 Invalid Params，不返回错误正文成功 | `DONE` |
| `CORE-004` | P1 | Prompt 错误类型化 | PROTO-002 | 缺参数、未知 prompt、DB 上下文失败语义不同 | `DONE` |
| `CORE-005` | P1 | 单一 Tool Definition Registry | PROTO-002 | schema、policy、handler、审计和文档同源 | `BACKLOG` |
| `CORE-006` | P1 | `/live` 与 `/ready` 分离 | 无 | Doris 不可用时 live 可真、ready 必假；探针有短超时 | `BACKLOG` |
| `CORE-007` | P1 | 显式跨调用 handle | PROTO-003, SEC-015 | 状态不依赖协议 session；handle 绑定 principal/expiry | `BACKLOG` |
| `CORE-008` | P2 | 大结果边界 | 无 | 行数、字节数、超时和取消可配置且有硬上限 | `BACKLOG` |
| `CORE-009` | P2 | manager 模块职责拆分 | CORE-005 | 不改变行为前提下缩小超大文件，模块边界有测试 | `BACKLOG` |
| `CORE-010` | P1 | 修复 SQL profile 分析未绑定 `auth_context` | 无 | 真实 Doris 调用不再触发局部变量未赋值；鉴权上下文覆盖测试通过 | `DONE` |
| `CORE-011` | P1 | 修复数据新鲜度空阈值比较 | 无 | 阈值缺失或为 `None` 时返回类型化错误/默认值，不抛 `TypeError` | `DONE` |
| `COMPAT-001` | P1 | Doris 4.0 元数据字段兼容 | 无 | Doris 4.0.5 的角色/权限查询不再依赖不存在的 `Default_role` 字段 | `DONE` |
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

提交与评审回执：

- commit：`6b5c779 feat: enforce MCP client capability requirements`
- Draft PR：[apache/doris-mcp-server#94](https://github.com/apache/doris-mcp-server/pull/94)

### CORE-003

资源读取错误不再只靠错误字符串判断。资源管理器为以下两类客户端请求错误增加稳定标记：

- `INVALID_RESOURCE_URI`
- `RESOURCE_NOT_FOUND`

现代 `2026-07-28` 协议边界只识别这两个标记，并返回标准 `-32602 Invalid Params`；普通 Doris 后端错误不会被误分类为参数错误。legacy 协议仍保留既有 JSON 错误正文，避免破坏旧客户端。

自动化验证：

- Streamable HTTP：不存在资源返回 HTTP 400 / JSON-RPC `-32602`；
- Streamable HTTP：错误后同一实例继续成功读取有效资源；
- 子进程 STDIO：不存在资源返回 `-32602`，错误后继续成功读取；
- STDIO legacy：继续收到带 `error_code` 的兼容错误正文；
- 资源管理器：非法 URI、缺失表和普通后端错误三类结果可区分；
- 完整 pytest：`336 passed / 57 skipped / 0 failed / 247 warnings`；
- `uv lock --check`、作用域 Ruff、`compileall`、`uv build` 全部通过。

真实 Doris 验证：

```text
environment: 192.168.31.63 / hhm_dt_sim
valid resource: doris://table/org_tenant
missing resource: doris://table/__core_003_missing__
```

- HTTP modern：`-32602` 后有效资源读取成功；
- HTTP legacy：兼容错误正文后有效资源读取成功；
- STDIO modern：`-32602` 后有效资源读取成功；
- STDIO legacy：兼容错误正文后有效资源读取成功。

连接通过 SSH key 和临时本地隧道完成；凭据未写入仓库或台账，探针完成后服务与隧道均已关闭。

提交与评审回执：

- commit：`5e57a2c fix: return invalid params for missing resources`
- Draft PR：[apache/doris-mcp-server#95](https://github.com/apache/doris-mcp-server/pull/95)

### CORE-004

Prompt 的三类失败现在拥有独立、稳定的协议语义：

| 场景 | JSON-RPC code | `promptErrorCode` |
|---|---:|---|
| 未知 Prompt | `-32602` | `UNKNOWN_PROMPT` |
| 缺少必填参数 | `-32602` | `MISSING_REQUIRED_ARGUMENT` |
| 数据库上下文不可用 | `-32603` | `DATABASE_CONTEXT_UNAVAILABLE` |

缺少必填参数时 `data.argument` 指明参数名。数据库异常详情只写服务端日志，协议正文不回传连接或堆栈细节。该语义同时适用于现代和 legacy 协议，旧客户端不再把 Prompt 故障误当成成功内容。

数据库上下文查询增加独立 10 秒预算，避免底层连接池恢复时间超过客户端请求预算；连接管理器的 context API 与旧式 get/release API 都保证在成功、异常和取消时归还连接。

自动化验证：

- Streamable HTTP：三类错误契约、错误后成功恢复；
- 真实子进程 STDIO：三类错误契约、错误后成功恢复；
- STDIO legacy：未知 Prompt 返回 `-32602`；
- manager：未知 Prompt、缺参数、DB 异常、超时和两类连接归还路径；
- 完整 pytest：`343 passed / 57 skipped / 0 failed / 247 warnings`；
- `uv lock --check`、作用域 Ruff、`compileall`、`uv build` 全部通过。

真实 Doris 与故障注入验证：

- HTTP modern/legacy：未知 Prompt、缺参数后均可继续从 `hhm_dt_sim` 生成真实数据库上下文；
- STDIO modern/legacy：未知 Prompt、缺参数后均可继续从 `hhm_dt_sim` 生成真实数据库上下文；
- HTTP 不可达端口故障注入：10 秒内返回 `-32603`，随后 `prompts/list` 成功；
- STDIO 子进程 manager 故障注入：返回 `-32603`，随后有效 Prompt 成功。

完全不可达 Doris 的真实 STDIO 进程会在协议协商前退出，无法进入 Prompt handler；这是启动/就绪与故障恢复边界，继续由 `CORE-006` / `TEST-005` 跟踪，未计作本项通过证据。

提交与评审回执：

- commit：`fc49a31 fix: type prompt retrieval failures`
- Draft PR：[apache/doris-mcp-server#96](https://github.com/apache/doris-mcp-server/pull/96)

### CORE-010

SQL Profile 分析现在会在所有分支进入数据库操作前统一绑定当前 `auth_context`。不再依赖 `catalog_name` 分支的局部赋值，因此“未指定 catalog”和“仅指定数据库”两条常见路径均不会触发 `UnboundLocalError`，同一个鉴权上下文会传递到上下文切换、session trace、profile 开关和真实 SQL。

自动化验证：

- 单元路径：未指定数据库、仅指定数据库两种场景均成功，并逐条断言执行调用收到同一个 Doris 鉴权上下文；
- Streamable HTTP：经生产 `SQLAnalyzer` 路径执行 Profile SQL，随后同一实例继续响应工具调用；
- 真实子进程 STDIO：modern/legacy 均经生产 `SQLAnalyzer` 路径执行 Profile SQL并保持进程可用；
- 完整 pytest：`347 passed / 57 skipped / 0 failed / 249 warnings`；
- `uv lock --check`、新增测试完整 Ruff、实现文件 `F821/F823` Ruff、`compileall`、`uv build` 全部通过。

真实 Doris 验证：

```text
environment: 192.168.31.63 / hhm_dt_sim
profile SQL: SELECT COUNT(*) AS row_count FROM org_tenant
recovery result: org_tenant=47040
```

- HTTP modern/legacy：Profile SQL 实际执行且包含 `execution_time`，无 `auth_context` 局部变量错误，随后真实查询成功；
- STDIO modern/legacy：Profile SQL 实际执行且包含 `execution_time`，无 `auth_context` 局部变量错误，随后真实查询成功；
- 当前隧道环境下 FE HTTP Profile 数据未取回，返回既有的“query ID unavailable”业务结果；SQL 执行与进程恢复均成功。FE HTTP 与 SQL 端点独立映射继续由 `COMPAT-002` 跟踪，不计作本项回归。

连接通过既有 SSH key 与临时 SQL/FE HTTP 隧道完成；凭据未写入仓库、测试或台账，探针结束后 MCP 服务与隧道均已关闭。

提交与评审回执：

- commit：`e2e90e0 fix: bind auth context for SQL profiles`
- Draft PR：[apache/doris-mcp-server#97](https://github.com/apache/doris-mcp-server/pull/97)

### CORE-011

数据新鲜度工具现在把缺省或显式为 `None` 的 `freshness_threshold_hours` 统一归一为 24 小时，并在业务实现入口再次兜底。无法从 Doris 推断更新时间时，`staleness_hours=None` 保持为明确的 `unknown` 状态，不再进入数值比较；只有真实数字且超过 72 小时时才生成“严重陈旧”数据流问题。

自动化验证：

- 路由层：显式 `None` 向业务层传递默认值 24；
- 分析层：`unknown + staleness_hours=None` 返回空问题列表，不抛 `TypeError`；
- Streamable HTTP：缺省阈值、未知更新时间返回结构化结果；
- 真实子进程 STDIO modern/legacy：同一未知状态和默认阈值契约；
- 完整 pytest：`351 passed / 57 skipped / 0 failed / 249 warnings`；
- `uv lock --check`、新增测试完整 Ruff、运行时严重错误规则 Ruff、`compileall`、`uv build` 全部通过。

真实 Doris 验证：

```text
environment: 192.168.31.63 / hhm_dt_sim
table: org_tenant
default threshold: 24
explicit null threshold: 24
freshness status: unknown
recovery result: org_tenant=47040
```

- HTTP modern/legacy：缺省与显式空阈值均返回 24，未知更新时间不抛异常，随后真实查询成功；
- STDIO modern/legacy：同样覆盖缺省与显式空阈值，随后真实查询成功；
- 连接通过既有 SSH key 和临时本地隧道完成；凭据未写入仓库、测试或台账，探针完成后服务与隧道均已关闭。

提交与评审回执：

- commit：`7fe79bc fix: handle unknown data freshness safely`
- Draft PR：[apache/doris-mcp-server#98](https://github.com/apache/doris-mcp-server/pull/98)

### COMPAT-001

Doris 4.0 角色分析改用公开 RBAC 元数据命令 `SHOW ALL GRANTS`，不再读取
`mysql.user.Default_role`。当当前账号无权查看全部授权时，降级为 `SHOW GRANTS`
读取当前用户授权。返回列会按列名归一化，支持多角色、空角色和带 host 的用户身份。

角色元数据属于内部控制数据：固定 SQL 仍然经过当前 `auth_context` 的 SQL 安全校验，
但通过显式 `mask_result=False` 跳过结果脱敏，避免 `UserIdentity` 被身份证规则破坏后使
角色分析全部退化为 `unknown`。普通查询默认仍然执行结果脱敏。

自动化验证：

- 单元路径：覆盖多角色、空角色默认值和 `SHOW ALL GRANTS` 无权限时的
  `SHOW GRANTS` 降级；
- 数据库连接层：断言关闭控制数据脱敏时仍会执行 SQL 安全校验；
- Streamable HTTP：生产角色分析路径返回 `operator -> root`；
- 真实子进程 STDIO modern/legacy：同一路径返回 `operator`，进程保持可用；
- 完整 pytest：`356 passed / 57 skipped / 0 failed / 252 warnings`；
- `uv lock --check`、新增测试完整 Ruff、运行时严重错误规则 Ruff、`compileall`、
  `uv build` 和 `git diff --check` 全部通过。

真实 Doris 验证：

```text
environment: 192.168.31.63 / hhm_dt_sim
Doris version: doris-4.0.5-rc01-59de8c4c524
root role: operator
hhm_nl2sql_reader role: hhm_nl2sql_readonly
recovery result: org_tenant=47040
```

- 实库确认 `mysql.user` 不存在 `Default_role`，`SHOW ALL GRANTS` 返回
  `UserIdentity` 和 `Roles`；
- 生产 `_get_user_roles` 直接读取真实 RBAC 映射成功；
- HTTP modern/legacy：`analyze_data_access_patterns` 返回 `operator -> root`，
  随后真实查询成功；
- STDIO modern/legacy：同样返回真实角色映射，随后真实查询成功；
- 连接通过既有 SSH key 和临时本地隧道完成；凭据未写入仓库、测试或台账，
  探针完成后服务与隧道均已关闭。

## 11. 下一开发批次

批次：`BATCH-02-CONFORMANCE-AND-ERROR-SEMANTICS`

按以下顺序推进：

1. `TEST-003`：运行官方 `server-stateless` Conformance；
2. `TEST-005` / `TEST-012`：补权限不足、超时、故障恢复和工具错误路径；
3. `PROTO-018` / `DOC-001` / `DOC-002`：版本单一来源和迁移文档；
4. `SEC-003`～`SEC-005`：进入下一安全批，完成非 loopback fail-closed。

`REL-001` 已达成。`REL-002` 仍由官方 Conformance、完整真实 Doris 矩阵、P0/P1 安全项、Compose 和发布门阻塞。
