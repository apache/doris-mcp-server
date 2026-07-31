# DESIGN.md — doris-mcp-server 设计文档

## 概述

**doris-mcp-server** 是一个基于 MCP（Model Context Protocol）协议的 Apache Doris 查询服务。它通过 FastMCP 的 streamable-http 传输层对外暴露 Doris 的数据查询能力，内置基于 MetricFlow v0.209.0 的语义指标层，支持多工作区隔离，并提供 Web UI 和 CLI 两套管理界面。

```
                         MCP 协议（streamable-http, 无状态）
┌──────────────────────────────────────────────────────────────────┐
│                       AI 客户端（LLM）                           │
│    Claude Desktop / Cursor / VeloDB / Codex / 自定义客户端       │
└─────────────────────────────┬────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│                     FastMCP 3.x 服务器                         │
│                                                                  │
│  ┌───────────────┐  ┌──────────────┐  ┌────────────────────────┐ │
│  │  10 个 Tool   │  │  Web UI      │  │  REST API              │ │
│  │  (LLM 调用)   │  │  /mcp/web/*  │  │  /mcp/web/semantic/*   │ │
│  └───────┬───────┘  └──────┬───────┘  └───────────┬────────────┘ │
│          │                 │                       │              │
│  ┌───────┴─────────────────┴───────────────────────┴────────────┐ │
│  │                       认证层                                  │ │
│  │  MCP:  Bearer username:password → CredentialVerifier → Doris │ │
│  │  Web:  会话 Cookie <session_id>.<节点IP>（24h TTL, httponly）│ │
│  │  缓存: 10 分钟内存凭证缓存；登录防爆破锁定（5 次/5 分钟）    │ │
│  │  连接: 每用户独立 aiomysql 连接池（无共享 admin 池）          │ │
│  └───────────────────────────┬──────────────────────────────────┘ │
│                              │                                    │
│  ┌───────────────────────────┴──────────────────────────────────┐ │
│  │                   多工作区管理器                               │ │
│  │  每工作区: Store → Manifest → Compiler (MetricFlow)          │ │
│  │  60s 轮询检测变更                                              │ │
│  │  自动发现新增/删除的工作区                                     │ │
│  │  MetricRouter: metric_name → (compiler, workspace)           │ │
│  └───────────────────────────┬──────────────────────────────────┘ │
└──────────────────────────────┼────────────────────────────────────┘
                               │ pymysql / aiomysql
                               ▼
                    ┌─────────────────────┐
                    │   Apache Doris FE   │
                    │   127.0.0.1:9030    │
                    │                     │
                    │  system_mcp.*       │  ← 工作区存储
                    │  dw.*               │  ← 用户数据表
                    └─────────────────────┘
```

---

## 1. 入口与生命周期

### 1.1 启动流程 (`src/main.py`)

```
main()
  ├─ 解析参数 (--config-dir, --env-file)
  ├─ AppConfig.load(mcp-server.toml)   ← TOML 配置文件，支持 ${VAR} 环境变量插值
  ├─ resolve_machine_ip(privateIp)     ← Web UI 节点身份（固定入口 / Cookie 亲和后缀）
  └─ create_server()
       ├─ MultiWorkspaceWatcher         ← 懒初始化：首个已认证请求时才扫描工作区
       ├─ PoolManager                   ← 每用户 aiomysql 连接池工厂（无共享 admin 池）
       ├─ CredentialVerifier            ← Bearer token → Doris 凭据验证（10 分钟缓存）
       ├─ 注册 10 个 MCP Tool
       ├─ 注册 Web UI 路由 (/mcp/web/*)
       └─ 注册 REST API 路由 (/mcp/web/semantic/*, /mcp/web/staging/*)
           ↓
mcp.run(transport="streamable-http", stateless_http=True, port=3000,
        middleware=[
          RequestLoggerMiddleware,        ← 请求/响应日志（敏感信息脱敏）
          SessionAffinityProxyMiddleware, ← Web UI 会话亲和（见 §8.3）
          CharsetMiddleware,              ← 字符集处理
        ])
```

### 1.2 关闭

`lifespan` 上下文管理器在服务器关闭时释放所有连接池。

---

## 2. 配置 (`src/config/loader.py`)

### 2.1 `mcp-server.toml`

```toml
[server]
mcp_name = "doris-new-mcp"      # MCP 服务名称
mcp_host = "0.0.0.0"            # 监听地址
mcp_port = 3000                 # HTTP 端口
fe_port = 9030                  # Doris FE MySQL 端口（同机 127.0.0.1）
seed_example = false            # 默认不部署；Admin 可在 WebUI 手动部署
admin_users = ["admin"]         # Admin 用户列表（WebUI 管理操作、example 部署）
# privateIp = "10.0.0.13"      # 可选：所有节点填同一 IP，/mcp/web 请求（含登录）
                                # 固定转发到该节点；不配置则按 Cookie 后缀亲和。见 §8.3

[logging]
level = "info"                  # debug|info|warning|error
audit_log = "./logs/audit.log"  # 审计日志路径
rotation_when = "midnight"      # 按天轮转
rotation_backup_count = 30      # 保留 30 天

[query]
pool_min_size = 0
pool_max_size = 10
pool_idle_timeout_seconds = 300
query_timeout_seconds = 600
# db_whitelist = ["dw", "system_mcp"]   # 可选：库白名单，限制可访问的数据库
query_max_rows = 10000           # 默认最大返回行数
```

### 2.2 配置类

| 类 | 职责 |
|---|------|
| `AppConfig` | 顶层，加载 TOML/YAML，正则替换 `${VAR}` 环境变量 |
| `McpConfig` | 服务名称、地址端口、日志配置、种子开关 |
| `ClusterConfig` | Doris FE 连接、连接池参数、查询限制、库白名单 |

---

## 3. MCP Tool（共 17 个）

### 3.1 Tool 清单

| # | Tool | 标注 | 用途 |
|---|------|------|------|
| 1 | `get_query_guide` | 只读, 幂等 | **第一步必调**。返回完整工作流指引，告知 AI 何时用语义层、何时用裸 SQL、工具调用顺序。 |
| 2 | `check_service_health` | 只读, 幂等 | **第二步必调**。Doris 连通性 + 每工作区状态 + 指标数量。 |
| 3 | `list_metrics` | 只读, 幂等 | 列出某工作区所有指标（名称+描述）。 |
| 4 | `list_dimensions_for_metric` | 只读, 幂等 | 返回某指标的可用 `group_by` 维度。 |
| 5 | `query_metric` | 只读 | **核心查询工具**。MetricFlow 编译 → 执行 SQL。支持 `metrics`/`group_by`/`where`/`order_by`/`limit`/`having`/`database`/`max_rows`。 |
| 6 | `list_databases` | 只读, 幂等 | 列出 Doris 数据库（分页）。 |
| 7 | `list_tables` | 只读, 幂等 | 列出某库的表（支持 `like` 模糊匹配，分页）。 |
| 8 | `describe_table` | 只读, 幂等 | 表结构（`names`/`summary`/`full` 三级详细程度）。 |
| 9 | `execute_query` | 只读 | 裸 SQL 兜底路径（仅允许 SELECT/SHOW/DESCRIBE/EXPLAIN）。 |
| 10 | `reload_semantic_layer` | 幂等 | 手动触发工作区重载。 |
| 11 | `list_semantic_providers` | 只读, 幂等 | 列出已注册的语义模型 provider（cube/lookml/metricflow）。 |
| 12 | `compile_semantic_model` | 幂等 | 上传语义模型文件 → validate/parse/compile → 存储编译产物（格式自动嗅探）。 |
| 13 | `list_semantic_artifacts` | 只读, 幂等 | 列出工作区内已编译的 artifact。 |
| 14 | `delete_semantic_artifact` | 幂等 | 删除编译产物。 |
| 15 | `get_semantic_metadata` | 只读, 幂等 | artifact 的指标/维度发现（可按指标过滤维度）。 |
| 16 | `generate_semantic_sql` | 只读, 幂等 | 干跑：生成 Doris SQL 不执行。 |
| 17 | `query_semantic_model` | 只读 | 生成 SQL → 只读校验 → 执行（结构化 filters，免疫注入）。 |

### 3.2 Agent 端工作流

系统对 AI 客户端强制执行严格的调用顺序：

```
get_query_guide()                    ← 第 1 步：获取工作流指引
    ↓
check_service_health()               ← 第 2 步：检查 Doris 和工作区状态
    ↓
    ├─ 语义层 healthy？ ──→ list_metrics() → list_dimensions_for_metric() → query_metric()
    │                      （常规路径：计数、求和、比率、排名、趋势）
    │
    └─ 语义层不可用 或 无匹配指标？
        └─→ list_databases() → list_tables() → describe_table() → execute_query()
            （兜底路径：裸 SQL + 元数据发现）
```

**关键规则：** 语义层 healthy 且有匹配指标时，绝不允许绕过 `query_metric` 直接用 `execute_query`。

### 3.3 Tool 实现模式

所有 Tool 遵循统一结构：

```python
@mcp.tool(annotations=ToolAnnotations(...))
async def tool_name(param: type, ...) -> str:
    auth = check_tool_access("tool_name")     # 1. 鉴权
    if auth.denied: return auth.denied
    start = time.monotonic()                  # 2. 计时
    pool = await _get_per_user_pool(auth.pool) # 3. 获取连接池
    result = await _implementation(pool, ...)  # 4. 执行
    log_tool_call("tool_name", ..., duration_ms=...) # 5. 审计
    return result
```

所有结果通过 `success_response()` / `error_response()` 序列化为 JSON。

---

## 4. 认证与授权

### 4.1 MCP 协议认证

```
Authorization: Bearer username:password
```

| 步骤 | 组件 | 操作 |
|------|------|------|
| 1 | `CredentialVerifier.verify_token()` | 取第一个 `:` 分割 username 和 password |
| 2 | `CredentialCache` | 查询 10 分钟 TTL 内存缓存 |
| 3 | `pymysql.connect(host=<机器IP>, user, password)` | 对 Doris 验证凭据 |
| 4 | 有效 → 缓存 → 返回 `AccessToken` | |
| 5 | 无效 → 返回 401 | |

验证时使用机器**非 127.0.0.1 的真实 IP**（通过 UDP 连接 8.8.8.8 探测），确保 Doris 侧使用真实用户身份。

### 4.2 Web UI 认证

```
GET  /mcp/web/login  → 渲染登录表单
POST /mcp/web/login  → 验证 Doris 凭据 → 设置 "doris_mcp_session" Cookie
                       格式: <session_id>.<节点IP>（24h TTL, httponly, samesite=lax）
GET  /mcp/web/logout → 清除会话和 Cookie
```

- **Cookie 后缀**：`<节点IP>` 是会话亲和路由依据（见 §8.3），由 `privateIp` 配置或自动探测决定
- **防爆破**：同一用户名连续失败 5 次锁定 5 分钟；锁定状态表现为"密码错误"，不泄露锁定事实
- **内存上限**：会话字典硬上限 1000 条，超出时逐出最旧会话；登录时顺带清理过期会话

### 4.3 权限模型

| 角色 | 判定方式 | 权限 |
|------|----------|------|
| **admin** | 用户名在 `server.admin_users` 配置列表中（默认 `["admin"]`） | 全部：上传/拉取/验证/提交/丢弃模型、创建/删除工作区、部署/删除 example、执行任意 SQL |
| **已认证用户** | 有效 Bearer token，通过 `_check_semantic_access()` | 只读：查看模型、列出/查询指标、执行 SQL（只读校验） |
| **未认证** | 无 token | 拒绝（401 或跳转登录页） |

### 4.4 每用户连接池

每个已认证用户获得独立的 `aiomysql` 连接池，通过机器非 loopback IP 连接。确保 Doris 侧正确应用用户级别授权。认证失败时自动清除凭证缓存，下次请求重新验证。

---

## 5. 工作区系统

### 5.1 概念

**工作区**是完全隔离的逻辑租户，包含：

- 独立的 YAML 模型文件
- 独立的 MetricFlow 编译器实例
- 独立的指标命名空间
- 独立的 Doris 存储表

工作区 A 的指标对工作区 B **完全不可见**。

**命名规范：** `^[a-zA-Z][a-zA-Z0-9_]*$`

### 5.2 工作区三种状态

| 状态 | 含义 | 触发条件 |
|------|------|----------|
| `healthy` | 正常运行，指标可查询 | YAML 已提交成功，bootstrap 解析通过，MetricFlow 引擎就绪 |
| `no_models` | 空工作区 | 新创建，或所有文件已删除 |
| `not_ready` | 加载失败 | YAML 语法错误、表不存在、缺少 project.yaml、MetricFlow 校验失败 |

```
  no_models  ──上传 YAML──→  not_ready  ──修复+提交──→  healthy
      ↑                            ↑                          │
      └──────────────────────── 上传错误 YAML ────────────────┘
```

### 5.3 存储架构 (`src/store/store.py`)

每个工作区在 `system_mcp` 库中有**两张** Doris 表：

```
system_mcp.active_store_{workspace}     ← 已生效的模型（只读）
  filename   VARCHAR(512) PRIMARY KEY
  updated_at DATETIME
  content    STRING

system_mcp.staging_store_{workspace}    ← 待提交的变更
  filename   VARCHAR(512) PRIMARY KEY
  action     VARCHAR(16)   -- 'upsert' | 'delete'
  updated_at DATETIME
  content    STRING（delete 时为 NULL）
```

### 5.4 更新流程

```
  用户编辑 YAML（WebUI/CLI）
           │
           ▼
  ┌─────────────────┐
  │  Staging Store  │   ← 文件进入暂存区，不影响正在运行的查询
  └────────┬────────┘
           │
   ┌───────┼───────┐
   ▼       ▼       ▼
验证    提交    丢弃
   │       │       │
   │  ┌────┴────┐  │
   │  │ Active  │  │
   │  │ Store   │  │
   │  └────┬────┘  │
   │       │       │
   │  自动重载     │
   │  （2-5 秒）   │
   │       │       │
   ▼       ▼       ▼
  ┌─────────────┐
  │   healthy   │
  └─────────────┘
```

**强制约束：** 必须先验证才能提交。"Staging must be validated before commit."

### 5.5 验证管道

```
validate_staging(workspace)
  1. staging_fetch()               → 合并 active + staging 到临时目录
  2. pre_validate_physical()       → YAML 语法、文件结构、表存在性
  3. bootstrap()                   → MetricFlow 构建到临时工作区
  4. SemanticManifest.load()       → 解析生成的 semantic_manifest.json
  5. _check_staging_duplicates()   → 跨文件检测重复度量/模型名
  6. 返回 (通过/失败, 消息, 含指标列表的详情)
```

### 5.6 多工作区管理器 (`src/store/watcher.py`)

```
MultiWorkspaceWatcher
├─ _init_all()                ← 扫描 system_mcp 中的 active_store_* 表
├─ _poll_loop()               ← 后台线程，60s 间隔
│   ├─ check_remote()         ← 通过 revision hash 检测版本变化
│   ├─ _reload_workspace()    ← fetch → bootstrap → manifest → compiler
│   └─ 发现新增/过期工作区     ← 扫描 system_mcp 中表的变化
├─ MetricRouter               ← metric_name → (compiler, workspace_name)
├─ force_reload()             ← 手动触发重载（API/Tool）
└─ commit_staging()           ← staging_commit() → force_reload()
```

**原子替换：** `RWLock.write_acquire()` 保护 manifest/compiler 的替换。任何请求都不会看到部分状态。

---

## 6. 语义层

### 6.1 MetricFlow 集成 (`src/store/compiler.py`)

```
YAML 模型（Doris active_store 中存储）
      │
      ▼
  bootstrap()          ← MetricFlow 构建（dbt 解析 + manifest 生成）
      │
      ▼
  semantic_manifest.json
      │
      ├── SemanticManifest.load()   ← 元数据：指标、维度、实体
      │
      └── MetricFlowCompiler
            │
            ├── MetricFlowEngine（仅编译模式）
            │     └── _DorisSqlClientStub  ← 满足 SqlClient 接口要求
            │           仅用于方言渲染，不执行真实查询
            │
            └── query_metric() 流程:
                  explain(sql) → Doris SQL → ConnectionPool.execute(sql) → rows
```

### 6.2 语义模型结构

一个 `semantic_model` YAML 文档包含：

| 字段 | 必填 | 说明 |
|------|:--:|------|
| `name` | ✅ | 全局唯一的模型名称 |
| `db_table` | ✅ | Doris 物理表（`库.表`） |
| `defaults.agg_time_dimension` | ✅ | 指标的默认时间维度 |
| `entities` | ✅ | 主键/外键/唯一键/自然键 |
| `dimensions` | ✅ | 时间维度（day/week/month/quarter/year/hour/minute）和分类维度 |
| `measures` | 推荐 | 聚合定义（sum/count/count_distinct/average/min/max/median/percentile/sum_boolean） |
| `description` | 可选 | 文字描述 |
| `primary_entity` | 条件 | 当 entities 中没有 `type: primary` 时必填 |

### 6.3 高级指标类型

除 `measures` 自动生成的简单指标外，YAML 支持四种高级类型：

| 类型 | 用途 | 示例 |
|------|------|------|
| `ratio` | 分子 ÷ 分母 | 转化率 = 下单数 / 访问数 |
| `derived` | 基于已有指标的表达式 | 环比增长、同比变化 |
| `cumulative` | 按时间窗口累计 | 近 7 天销售额、月累计注册 |
| `conversion` | 用户漏斗转化 | 访问→下单转化率 |

### 6.4 Manifest (`src/store/manifest.py`)

```python
SemanticManifest(semantic_manifest.json)
  .list_metrics()                    # → [{name, description}, ...]
  .get_metric(name)                  # → 完整指标定义
  .list_dimensions_for_metric(name)  # → [{name, type, description}, ...]
```

---

## 6A. 语义 Provider 插件框架 (`src/providers/`)

第 6 节描述的是内置 MetricFlow 语义层。本节描述在其之上的**通用语义模型编译器插件框架**——定位是 `Semantic Model → Doris SQL` 的编译运行时（类比 dbt compile + query engine + MCP interface），而不是语义交换标准。

### 6A.1 架构

```
        Build Time（上传模型）                    Runtime（Agent 查询）

  ModelSource(filename, content)          CompiledArtifact + QueryRequest
          │                                       │
  SemanticProvider                        SemanticRuntime
    validate() → parse() → compile()        get_metrics()
          │                                 get_dimensions(metric)
          ▼                                 generate_sql() → Doris SQL
  CompiledArtifact ──► ArtifactStore                │
  (provider 私有 payload,     (<workspace>/.artifacts/*.json)
   标准化 envelope)                                   ▼
                                            validate_readonly → 连接池执行
```

关键决策：

- **编译产物不跨 Provider 标准化**。envelope（provider/name/version/source_digest）统一，`payload` 由各家私有——我们是编译器框架，不是 exchange standard。
- **Provider 能力超过 Parser**：每个 provider 自带 parser + compiler + runtime SQL generator + metadata provider，类似数据库驱动（parser/planner/executor）。
- **结构化 Filter**：Agent 传 `{dimension, operator, value}` 而不是 SQL 片段；维度名对 artifact 校验、字面量转义，生成的 SQL 在构造上免疫注入（模型作者的 SQL 表达式除外，属于可信输入）。

### 6A.2 内置 Provider

| Provider | 格式 | 解析 | 运行时 |
|---|---|---|---|
| `cube` | cube-js YAML（cubes/measures/dimensions/many_to_one joins）| 自带（pyyaml）| 自带 Doris SQL 生成器 |
| `lookml` | Looker `.view.lkml`（views/dimensions/dimension_groups/measures）| `lkml`（MIT）| 编译时翻译成 Cube artifact 形状，**复用 Cube 运行时** |
| `metricflow` | dbt `semantic_models`/`metrics` YAML | 轻量解析做校验/预览 | `bind()` 挂接现有 MetricFlowCompiler（见第 6 节）|

格式自动嗅探：`provider.detect(source)` 返回置信度，≥0.5 路由；也可显式指定。

### 6A.3 MCP Tool（新增 7 个）

| Tool | 用途 |
|---|---|
| `list_semantic_providers` | 列出已注册的 provider |
| `compile_semantic_model` | 上传模型文件 → validate/parse/compile → 存 artifact |
| `list_semantic_artifacts` / `delete_semantic_artifact` | artifact 管理 |
| `get_semantic_metadata` | 指标/维度发现（可按指标过滤维度）|
| `generate_semantic_sql` | 干跑：生成 Doris SQL 不执行 |
| `query_semantic_model` | 生成 SQL → 只读校验 → 执行 |

### 6A.4 示例

`examples/semantic-models/` 下有 Cube 与 LookML 示例。典型 Agent 流程：

```
compile_semantic_model(workspace, "sales.cube.yaml", <content>)
  → artifact_id = "cube__orders"
get_semantic_metadata(workspace, "cube__orders", metric="revenue")
query_semantic_model(workspace, "cube__orders",
    metrics=["revenue"], dimensions=["country"],
    filters=[{"dimension":"create_time","operator":"between","value":["2025-01-01","2025-01-31"]}],
    order_by=["-revenue"], limit=100)
```

---

## 7. 连接管理

### 7.1 连接池 (`src/core/connection.py`)

```python
ConnectionPool
  ├─ aiomysql.Pool（懒初始化，asyncio.Lock 保护）
  ├─ execute(sql, database, max_rows, timeout) → ([{col: val}, ...], [col_names])
  ├─ 通过 PoolManager 按用户创建独立连接池（非 127.0.0.1 IP）
  └─ close() → pool.close() + wait_closed()
```

### 7.2 连接池类型

| 池 | 用户 | 最小/最大 | 用途 |
|----|------|-----------|------|
| 每用户池 | `<认证用户>` | 0/10 | 以用户身份执行 SQL 查询 |

**无共享 admin 池：** 所有 Doris 连接都使用请求自带的凭据（Bearer token 或 Web UI 会话中的用户名密码），请求间通过 `PoolManager` 复用同用户的池。空闲连接按 `pool_idle_timeout_seconds` 回收，失效凭据自动清除缓存并重建。

---

## 8. Web UI

### 8.1 路由表

| 路由 | 方法 | 认证 | 用途 |
|------|------|------|------|
| `/mcp/web/login` | GET | 无 | 登录表单 |
| `/mcp/web/login` | POST | 无 | 处理登录，设置会话 Cookie |
| `/mcp/web/logout` | GET | Session | 清除会话 |
| `/mcp/web` | GET | Session | 跳转到模型管理页 |
| `/mcp/web/models` | GET | Session | 已生效/待提交文件列表 + 工作区状态 |
| `/mcp/web/{filename}` | GET | Session | 编辑 YAML 文件 |
| `/mcp/web/new` | GET | Admin | 新建文件表单 |
| `/mcp/web/create` | POST | Admin | 创建新文件 |
| `/mcp/web/{filename}/save` | POST | Admin | 保存编辑的文件 |
| `/mcp/web/{filename}/delete` | GET | Admin | 标记文件为待删除 |
| `/mcp/web/upload` | POST | Admin | 上传 YAML 文件（multipart） |

### 8.2 REST API 路由表

| 路由 | 方法 | 认证 | 用途 |
|------|------|------|------|
| `/mcp/web/semantic/push` | POST | Admin (Bearer) | CLI：上传 YAML（multipart） |
| `/mcp/web/semantic/pull` | GET | Bearer | CLI：下载已生效 YAML（.tar.gz） |
| `/mcp/web/semantic/reload` | POST | Admin | HTTP：触发工作区重载 |
| `/mcp/web/semantic/files` | GET | Bearer | 列出已生效文件 |
| `/mcp/web/semantic/files/{filename}` | GET | Bearer | 获取文件内容 |
| `/mcp/web/semantic/files` | POST | Admin | 保存文件到 staging |
| `/mcp/web/semantic/files/{filename}` | DELETE | Admin | 从 staging 删除文件 |
| `/mcp/web/staging/validate` | POST | Admin | 验证待提交变更 |
| `/mcp/web/staging/commit` | POST | Admin | 提交到已生效 |
| `/mcp/web/staging/discard` | POST | Admin | 丢弃待提交变更 |
| `/mcp/web/workspace/create` | POST | Admin | 创建工作区 |
| `/mcp/web/workspace/delete` | POST | Admin | 删除工作区（DROP 存储表） |
| `/mcp/web/example/deployment` | POST | Admin (WebUI session) | 启动 example 部署/删除后台任务，立即返回 |
| `/mcp/web/example/deployment/status` | GET | Admin (WebUI session) | 轮询后台任务状态（idle/running/success/failed） |

### 8.3 多机部署与会话亲和

多台 MCP Server 挂在同一域名（ALB）后方时，Web UI 会话是单机内存态，需要保证同一浏览器的请求落到持有会话的机器。转发由 `SessionAffinityProxyMiddleware`（`src/core/session_affinity_proxy.py`）在**应用层**完成，nginx 只做哑代理（`proxy_pass http://127.0.0.1:3000`），无需任何 Cookie 解析配置。

**默认行为（不配置 `privateIp`）：** 登录在收到请求的节点本地处理，Cookie 写入 `session_id.<本机IP>`；后续请求落到其他节点时，中间件解析 Cookie 后缀 IP，经 httpx 转发到持有会话的节点。节点 IP 通过 UDP 路由探测（连接 8.8.8.8）自动获得。

**可选配置 `privateIp`：** 所有节点填同一个 IP 时，该节点成为 Web UI 固定入口——其余节点的 `/mcp/web` 请求（含登录）一律转发过去，session 只存在于这一台机器，各节点配置文件完全一致；`/mcp` 协议不受影响，仍由各节点本地处理。节点通过比对自身探测 IP 与 `privateIp` 判断自己是不是入口节点；探测失败时假定自己就是入口节点（单机/离线行为不变）。

**转发实现要点：** 共享 httpx.AsyncClient（禁 Set-Cookie、不跟随重定向、trust_env=False）；流式转发请求/响应体；内部跳转头 `x-doris-session-affinity-hop` 防止转发循环；上游超时/不可达时清除 Cookie 并 303 回登录页。

---

## 9. CLI 客户端 (`mcp-client/`)

独立的命令行客户端，作为单独 tar.gz 包分发。通过环境变量或 `doris-mcp-client.toml` 配置连接：

```bash
export DORIS_MCP_SERVER=http://<host>:<port>
export DORIS_MCP_TOKEN=admin:admin
```

**MCP Tool 调用：**
```bash
doris-mcp-client tool list
doris-mcp-client tool call list_metrics --json '{"workspace":"example"}'
doris-mcp-client tool call query_metric --json '{"metrics":["total_amount"],"group_by":["channel"]}'
```

**语义模型管理：**
```bash
doris-mcp-client semantic push ./models -w example
doris-mcp-client semantic pull -o ./backup -w example
doris-mcp-client semantic list -w example
doris-mcp-client semantic reload -w example
doris-mcp-client semantic status
```

---

## 10. 示例工作区

默认不部署 example。Admin 可通过 Reload 右侧的专属按钮手动部署或删除；
若显式设置 `seed_example=true`，Admin 首次登录 WebUI 时自动部署。

**异步部署：** 部署/删除是长耗时操作（建库建表 + 插数据 + GRANT + 编译模型，可能超过代理/LB 的 60s 空闲超时）。POST `/mcp/web/example/deployment` 只启动后台任务并立即返回，前端每 2s 轮询 GET `.../status` 直至 success/failed，避免同步等待触发 504 HTML 错误页。

**示例数据表：**

| 表 | 行数 | 说明 |
|----|------|------|
| `dw.orders` | 12 | 订单表，含 order_id/user_id/product_id/amount/channel/status/order_date |
| `dw.users` | 5 | 用户表，含 user_id/name/city/level/register_date |
| `dw.products` | 5 | 商品表，含 product_id/name/category/brand/price |
| `dw.dim_date` | 365 | 日期维度表，用于时间轴对齐 |

**5 个示例指标：** `total_amount`（订单总额）、`order_count`（订单数）、`avg_amount`（客单价）、`unique_users`（独立用户）、`user_count`（用户数）

---

## 11. 关键设计决策

| 决策 | 原因 |
|------|------|
| `stateless_http=True` | 不维护 MCP 会话状态。兼容不保持 session 的客户端（VeloDB 代理、Claude Desktop）。 |
| Doris 存储 YAML | 模型文件存在 Doris 表中而非文件系统。支持多服务器共享状态部署，无需文件同步。 |
| 两级存储（active + staging） | 防止错误模型影响线上。强制「先验证再提交」的卡控机制。 |
| 仅编译模式的 `_DorisSqlClientStub` | MetricFlow 需要 SqlClient 做方言渲染，实际查询通过 aiomysql 池以用户身份执行。 |
| 每用户连接池 | 每个认证用户获得独立 aiomysql 池，保留 Doris 原生用户级别授权。 |
| 内嵌 HTML 模板 | Web UI 无外部 CDN 依赖，单文件部署，支持代理/VPN 访问。 |
| Python 3.10 standalone 构建 | 通过 `python-build-standalone` 自包含分发。运行时不需要系统 Python。 |
| 审计日志（定时轮转） | 每次 Tool 调用记录 client_id、参数、耗时、成功/失败。按天轮转，保留 30 天。敏感信息（Cookie、密码、token）脱敏后落盘。 |
| Web UI 会话亲和在应用层 | `SessionAffinityProxyMiddleware` 按 Cookie 后缀 IP（或 `privateIp` 指定入口）转发，nginx 保持哑代理。多机部署不需要修改 nginx 配置，扩缩容节点零运维。 |
| example 部署异步化 | 部署可能超过代理 60s 空闲超时。后台任务 + 状态轮询，前端永不见 504 HTML。 |

---

## 12. 构建与分发

### 12.1 构建命令 (`build.sh`)

```bash
./build.sh linux-x64       # Linux x86_64
./build.sh linux-arm64     # Linux ARM64
./build.sh macos-x64       # macOS Intel
./build.sh macos-arm64     # macOS Apple Silicon
./build.sh                 # 自动检测当前平台
./build.sh clean           # 清理 python/、dist/、构建产物
```

从 `astral-sh/python-build-standalone` 下载 Python 3.10 独立发行版，根据 `requirements.txt` 安装依赖，生成一个自包含全量 tar.gz 包（server + client + 文档 + Python 运行时）到 `dist/`：

```
dist/
└── doris-mcp-server-{version}-{platform}.tar.gz    ← python/ + src/ + 配置 + mcp-client/
```

> 版本号单一事实源是 `pyproject.toml`；`build.sh` 的 `VERSION` 环境变量可覆盖（CI 从 Git tag 注入）。
> 注意 `cryptography>=45.0.1` 是按目标机 glibc 2.32 兼容性选定的下限，不要随意抬高。

### 12.2 CI 发版（`.github/workflows/release.yml`）

| 触发方式 | 行为 |
|----------|------|
| 手动打 tag `doris-mcp-server-x.y.z` | 按 tag 版本号构建并发 Release |
| Actions 手动触发 | 按输入版本号构建并发 Release |

每次发版产出 linux-x64 和 linux-arm64 两个包（私有仓库无免费 ARM runner，arm64 在 x64 runner 上经 `build.sh` 交叉构建）：

```
doris-mcp-server-0.2.3-linux-x64.tar.gz
doris-mcp-server-0.2.3-linux-arm64.tar.gz
```

两个包解压后顶层目录均为 `doris-mcp-server/`，部署脚本无需改动。

### 12.3 部署

```bash
# 1. 解压
tar xzf doris-mcp-server-{version}-linux-x64.tar.gz
cd doris-mcp-server

# 2. 配置（可选，默认 localhost:9030 即可）
vim mcp-server.toml

# 3. 启动
./start-mcp-server.sh                     # 前台
nohup ./start-mcp-server.sh > /tmp/doris-mcp.log 2>&1 &   # 后台
```

运行时无需网络、无需 pip、无需系统 Python。通过 `DORIS_MCP_PYTHON` 环境变量可覆盖自带 Python：

```bash
DORIS_MCP_PYTHON=/usr/bin/python3.10 ./start-mcp-server.sh
```

### 12.4 验证

```bash
# WebUI
curl http://<IP>:3000/mcp/web

# MCP Agent 接入
claude mcp add --transport http doris http://<IP>:3000/mcp \
  --header "Authorization: Bearer admin:admin"
```

---

## 13. 目录结构

```
doris-mcp-server/
├── build.sh                     # 构建脚本
├── requirements.txt             # Python 3.10 依赖
├── mcp-server.toml              # 服务配置
├── start-mcp-server.sh          # 启动脚本
├── mcp-client.sh                # 客户端启动脚本
├── INSTALL.html                 # 安装指南
├── doris-mcp-docs.html          # 完整文档（语义模型 + 用户指南）
├── DESIGN.md                    # 本文档
├── .github/workflows/
│   └── release.yml              # CI：PR 合入自动发版 / tag 发版（x64 + arm64）
├── src/
│   ├── main.py                  # 入口 + 中间件栈 + FastMCP.run()
│   ├── server.py                # 服务工厂、10 个 Tool、Web UI 路由、REST API
│   ├── auth/                    # 认证模块
│   │   ├── credential_cache.py  # 10 分钟 TTL 内存缓存
│   │   ├── credential_verifier.py # Bearer token → Doris 验证
│   │   └── guard.py             # Tool 级访问控制
│   ├── config/
│   │   └── loader.py            # TOML/YAML 配置 + ${VAR} 环境变量插值
│   ├── core/                    # 核心模块
│   │   ├── connection.py        # aiomysql 异步连接池
│   │   ├── pool_manager.py      # 每用户连接池工厂
│   │   ├── audit.py             # 定时轮转审计日志
│   │   ├── health.py            # 服务健康状态追踪
│   │   ├── response.py          # JSON 成功/错误响应
│   │   ├── sql_validator.py     # SQL 只读校验（基于 sqlglot）
│   │   ├── charset.py           # 字符集中间件
│   │   ├── request_logger.py    # 请求日志中间件
│   │   ├── pagination.py        # 游标分页
│   │   ├── sensitive_mask.py    # 敏感数据脱敏
│   │   └── session_affinity_proxy.py # Web UI 会话亲和 ASGI 反向代理（§8.3）
│   ├── store/                   # 工作区存储模块
│   │   ├── store.py             # DorisStore：每工作区 active/staging 表
│   │   ├── watcher.py           # MultiWorkspaceWatcher：轮询、重载、验证、提交
│   │   ├── compiler.py          # MetricFlowCompiler + _DorisSqlClientStub
│   │   ├── manifest.py          # SemanticManifest：解析 semantic_manifest.json
│   │   ├── bootstrap.py         # MetricFlow 构建（dbt 解析 + manifest 生成）
│   │   ├── seed.py              # 示例数据播种
│   │   └── version.py           # 工作区版本追踪
│   ├── tools/                   # Tool 实现
│   │   ├── dependency.py        # 跨文件依赖检测（安全删除 YAML 前校验）
│   │   ├── discovery.py         # list_databases、list_tables、describe_table
│   │   ├── query.py             # execute_query（SQL 执行）
│   │   └── semantic.py          # list_metrics、list_dimensions_for_metric、query_metric
│   ├── skills/
│   │   └── doris-mcp-skill.md   # 查询指引（get_query_guide 返回）
│   └── metricflow/              # 内置 MetricFlow 引擎（仅编译模式）
└── mcp-client/                  # CLI 客户端（独立包）
    └── client/
        ├── cli.py               # CLI 入口（typer 框架）
        ├── config.py            # 环境变量/文件配置
        ├── http_client.py       # HTTP API 客户端
        ├── mcp_client.py        # MCP streamable-http 传输层
        └── formatting.py        # 输出格式化
```
