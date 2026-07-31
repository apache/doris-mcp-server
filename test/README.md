# Test Cases — doris-new-mcp

基于 [DESIGN.md](../DESIGN.md)、[INSTALL.html](../INSTALL.html)、[doris-mcp-docs.html](../doris-mcp-docs.html) 生成。

## 文件说明

### 离线单元测试（无需 MCP Server / Doris）

| 文件 | 内容 |
|------|------|
| `test_sql_validator.py` | `core.sql_validator.validate_readonly` 只读 SQL 校验（放行/拦截/多语句/注释绕过/已知前缀行为） |
| `test_sensitive_mask.py` | `core.sensitive_mask` 密码/token 脱敏 |
| `test_pagination.py` | `core.pagination` 分页与 token TTL 行为 |
| `test_private_ip_config.py` | 私网 IP 配置读取与启动装配 |
| `test_deps.py` | 运行时依赖守卫（import 真实模块） |
| `test_cross_file_deps.py` | 删除前跨文件依赖检测 |
| `test_credential_pass.py` | 请求级凭据透传到 store 层 |
| `test_watcher.py` | `MultiWorkspaceWatcher.ensure_fresh` 冷却/重载/降级 |
| `test_web_session_cookie.py` | Web 会话 Cookie |
| `test_session_affinity_proxy_routing.py` | 会话亲和代理路由 |
| `test_session_affinity_proxy_streaming.py` | 会话亲和代理流式转发 |
| `test_session_affinity_proxy_relogin.py` | 会话亲和代理重登录 |
| `test_session_affinity_proxy_force_target.py` | 会话亲和代理强制目标 |

### 在线测试（需运行中的 MCP Server + Doris）

| 文件 | 内容 |
|------|------|
| `test_mcp_tools.py` | 全部 10 个 MCP Tool + 认证 + E2E（30 用例） |
| `test_web_api.py` | Web UI + REST API + 工作区管理（12 用例） |

### 入口脚本

| 文件 | 内容 |
|------|------|
| `run_all_tests.sh` | 一键运行脚本，支持 `--offline` / `--tools` / `--web` / `--smoke` |

## 环境要求

| 条件 | 说明 |
|------|------|
| MCP Server | 运行在 `localhost:3000`（仅在线测试需要） |
| Doris FE | 运行在 `127.0.0.1:9030`（仅在线测试需要） |
| 认证 | `admin:admin` |
| Python | 3.10+，离线测试使用项目 `.venv`（`PYTHONPATH=src`） |

可通过环境变量覆盖默认配置:
```bash
export MCP_URL=http://192.168.1.100:3000/mcp
export MCP_BASE_URL=http://192.168.1.100:3000
export MCP_TOKEN=admin:admin
export MCP_WORKSPACE=example
export DORIS_USER=admin          # test_web_api.py 登录凭据
export DORIS_PASS=admin
export DORIS_MCP_TEST_DESTRUCTIVE=1  # 允许破坏性用例（见下）
```

## 运行方式

```bash
# 仅离线单元测试（无需启动任何服务）
bash test/run_all_tests.sh --offline

# 或用 unittest discover 跑全部离线用例（在线文件无可收集用例，不影响）
PYTHONPATH=src .venv/bin/python -m unittest discover -s test -p 'test_*.py'

# 单个离线文件也可直接运行（已内置 sys.path 自举）
.venv/bin/python test/test_watcher.py

# 全部测试（需 MCP Server 在线）
bash test/run_all_tests.sh

# 仅冒烟测试 (快速, ~5秒)
bash test/run_all_tests.sh --smoke

# 仅 MCP Tool 测试
bash test/run_all_tests.sh --tools

# 仅 Web/API 测试
bash test/run_all_tests.sh --web

# 或直接运行 Python（服务器不可达时整体跳过，退出码 0）
python test/test_mcp_tools.py
python test/test_web_api.py
```

## 破坏性用例

`test_web_api.py` 中以下用例会影响共享服务器状态，**默认跳过**，
需显式设置 `DORIS_MCP_TEST_DESTRUCTIVE=1` 才执行：

- `test_api_staging_discard` — 会丢弃真实用户的暂存变更
- `test_api_workspace_create_and_delete` — 会创建/删除真实工作区

## 测试覆盖矩阵

### MCP Tool 测试 (10 个 Tool)

| Tool | 测试场景 | 验证点 |
|------|----------|--------|
| `get_query_guide` | 获取工作流指引 | 返回文本 >100字，含关键词 |
| `check_service_health` | 基础/详细 | Doris=connected, workspaces 存在 |
| `list_metrics` | 列表/分页 | data 数组, meta.total_count |
| `list_dimensions_for_metric` | 按指标查维度 | data 包含维度 |
| `query_metric` | 基础/group_by/where/order+limit | 4 种查询模式 |
| `list_databases` | 列表/分页 | dw,mysql,system_mcp,information_schema |
| `list_tables` | mysql库/dw种子上表/like模糊 | 4 张种子表验证 |
| `describe_table` | summary/full/names | 3 级详细程度 |
| `execute_query` | SELECT/VERSION/SHOW/EXPLAIN/max_rows/写拦截 | 7 种场景 |
| `reload_semantic_layer` | 手动重载 | 返回结构化 JSON，含 success 字段 |

注：语义层相关用例（`list_dimensions_for_metric`、`query_metric` 系列）
仅在 MCP Server 不可达（连接类异常）时跳过；语义层未就绪等断言失败
会如实计为 FAIL，不再静默跳过。

### Web UI & API 测试

| 分类 | 测试点 |
|------|--------|
| **Web UI** | 登录页面、登录提交、未认证拦截、模型管理页 |
| **REST API** | 语义文件列表、pull 下载、reload 重载、staging validate/discard |
| **工作区** | 创建 → 验证存在 → 删除 (完整生命周期，破坏性，默认跳过) |
| **认证** | admin 权限控制、Bearer token 格式验证 |

### 边界 & 错误测试

| 场景 | 预期 |
|------|------|
| 无 Authorization | 401/403 |
| 无效 Token | 401/403 |
| 写操作 SQL (INSERT) | 被拦截 |
| SQL 语法错误 | 友好错误信息 |
| 非 admin 创建工作区 | 403 |
| 不存在的指标 | 友好错误 |

### 端到端测试 (Agent 工作流)

```
get_query_guide → check_service_health → list_databases
  → list_tables → describe_table → execute_query
```
