#!/bin/bash
# =============================================================================
# test/run_all_tests.sh — 一键运行所有测试
#
# 用法:
#   bash test/run_all_tests.sh              # 运行全部测试（需 MCP Server）
#   bash test/run_all_tests.sh --offline    # 仅离线单元测试（无需 MCP Server）
#   bash test/run_all_tests.sh --tools      # 离线测试 + 仅 Tool 在线测试
#   bash test/run_all_tests.sh --web        # 离线测试 + 仅 Web/API 在线测试
#   bash test/run_all_tests.sh --smoke      # 离线测试 + 冒烟测试 (快速)
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
MCP_URL="${MCP_URL:-http://localhost:3000/mcp}"
MCP_BASE_URL="${MCP_BASE_URL:-http://localhost:3000}"

# 优先使用项目 venv 的解释器（离线测试依赖其中的第三方包）
PYTHON_BIN="${PYTHON_BIN:-$PROJECT_DIR/.venv/bin/python}"
if [ ! -x "$PYTHON_BIN" ]; then
    PYTHON_BIN="python3"
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# ── 检查 MCP Server 是否运行 ────────────────────
check_server() {
    if curl -s -o /dev/null -w "%{http_code}" "$MCP_BASE_URL/mcp/web/login" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ MCP Server 运行中${NC}"
    else
        echo -e "${RED}❌ MCP Server 未运行在 $MCP_BASE_URL${NC}"
        echo "   请先启动: cd $PROJECT_DIR && ./start-mcp-server.sh"
        exit 1
    fi
}

# ── 运行 Python 测试 ────────────────────────────
run_python_test() {
    local test_file="$1"
    local label="$2"
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}  $label${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    if "$PYTHON_BIN" "$test_file"; then
        echo -e "${GREEN}✅ $label 通过${NC}"
        return 0
    else
        echo -e "${RED}❌ $label 失败${NC}"
        return 1
    fi
}

# ── 冒烟测试 (快速) ────────────────────────────
smoke_test() {
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}  冒烟测试${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    # 1. Health check
    echo -n "  1. Health check ... "
    RESULT=$(curl -s -X POST "$MCP_URL" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        -H "Authorization: Bearer admin:admin" \
        -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"check_service_health","arguments":{}}}')
    if echo "$RESULT" | grep -q "connected"; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAIL${NC}: $RESULT"
        return 1
    fi

    # 2. List databases
    echo -n "  2. List databases ... "
    RESULT=$(curl -s -X POST "$MCP_URL" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        -H "Authorization: Bearer admin:admin" \
        -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_databases","arguments":{}}}')
    # SSE response has escaped JSON: \"success\": true
    if echo "$RESULT" | grep -qE 'success.*true'; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        return 1
    fi

    # 3. Execute query
    echo -n "  3. Execute query ... "
    RESULT=$(curl -s -X POST "$MCP_URL" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        -H "Authorization: Bearer admin:admin" \
        -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"execute_query","arguments":{"sql":"SELECT 1 AS n"}}}')
    if echo "$RESULT" | grep -qE 'n.*:.*1[^0-9]'; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAIL${NC}: $RESULT"
        return 1
    fi

    # 4. Web UI
    echo -n "  4. Web UI login page ... "
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$MCP_BASE_URL/mcp/web/login")
    if [ "$HTTP_CODE" = "200" ]; then
        echo -e "${GREEN}OK ($HTTP_CODE)${NC}"
    else
        echo -e "${RED}FAIL (HTTP $HTTP_CODE)${NC}"
        return 1
    fi

    echo -e "${GREEN}✅ 冒烟测试全部通过${NC}"
    return 0
}

# ── 离线单元测试（无需启动 MCP Server） ─────────
run_offline_unit_tests() {
    run_python_test "$SCRIPT_DIR/test_sql_validator.py" "SQL 只读校验离线单元测试" || ((FAIL_COUNT += 1))
    run_python_test "$SCRIPT_DIR/test_sensitive_mask.py" "敏感信息脱敏离线单元测试" || ((FAIL_COUNT += 1))
    run_python_test "$SCRIPT_DIR/test_pagination.py" "分页离线单元测试" || ((FAIL_COUNT += 1))
    run_python_test "$SCRIPT_DIR/test_private_ip_config.py" "私网 IP 配置离线单元测试" || ((FAIL_COUNT += 1))
    run_python_test "$SCRIPT_DIR/test_deps.py" "运行时依赖守卫离线单元测试" || ((FAIL_COUNT += 1))
    run_python_test "$SCRIPT_DIR/test_cross_file_deps.py" "跨文件依赖检测离线单元测试" || ((FAIL_COUNT += 1))
    run_python_test "$SCRIPT_DIR/test_credential_pass.py" "凭据透传离线单元测试" || ((FAIL_COUNT += 1))
    run_python_test "$SCRIPT_DIR/test_watcher.py" "工作区 Watcher 离线单元测试" || ((FAIL_COUNT += 1))
    run_python_test "$SCRIPT_DIR/test_manifest_dims.py" "指标维度提取离线单元测试" || ((FAIL_COUNT += 1))
    run_python_test "$SCRIPT_DIR/test_compiler_where.py" "WHERE 字面量处理离线单元测试" || ((FAIL_COUNT += 1))
    run_python_test "$SCRIPT_DIR/test_web_session_cookie.py" "Web 会话 Cookie 离线单元测试" || ((FAIL_COUNT += 1))
    run_python_test "$SCRIPT_DIR/test_session_affinity_proxy_routing.py" "会话亲和代理路由离线单元测试" || ((FAIL_COUNT += 1))
    run_python_test "$SCRIPT_DIR/test_session_affinity_proxy_streaming.py" "会话亲和代理流式离线单元测试" || ((FAIL_COUNT += 1))
    run_python_test "$SCRIPT_DIR/test_session_affinity_proxy_relogin.py" "会话亲和代理重登录离线单元测试" || ((FAIL_COUNT += 1))
    run_python_test "$SCRIPT_DIR/test_session_affinity_proxy_force_target.py" "会话亲和代理强制目标离线单元测试" || ((FAIL_COUNT += 1))
}

# ── Main ─────────────────────────────────────────
FAIL_COUNT=0
MODE="${1:-}"

# Keep these deterministic tests ahead of every live-server test stage.
run_offline_unit_tests

if [ "$MODE" = "--offline" ]; then
    : # 离线模式：不检查服务器、不跑在线阶段
else
    check_server
fi

case "$MODE" in
    --offline)
        ;;
    --tools)
        run_python_test "$SCRIPT_DIR/test_mcp_tools.py" "MCP Tools 测试" || ((FAIL_COUNT += 1))
        ;;
    --web)
        run_python_test "$SCRIPT_DIR/test_web_api.py" "Web UI & API 测试" || ((FAIL_COUNT += 1))
        ;;
    --smoke)
        smoke_test || ((FAIL_COUNT += 1))
        ;;
    "")
        # 全部运行
        smoke_test || ((FAIL_COUNT += 1))
        run_python_test "$SCRIPT_DIR/test_mcp_tools.py" "MCP Tools 测试" || ((FAIL_COUNT += 1))
        run_python_test "$SCRIPT_DIR/test_web_api.py" "Web UI & API 测试" || ((FAIL_COUNT += 1))
        ;;
    *)
        echo "Usage: $0 [--offline|--tools|--web|--smoke]"
        echo "  (no args)  运行全部测试（需 MCP Server）"
        echo "  --offline  仅离线单元测试（无需 MCP Server）"
        echo "  --tools    仅 MCP Tool 测试"
        echo "  --web      仅 Web UI & API 测试"
        echo "  --smoke    仅冒烟测试 (快速)"
        exit 1
        ;;
esac

echo ""
if [ "$FAIL_COUNT" -eq 0 ]; then
    echo -e "${GREEN}═══════════════════════════════════${NC}"
    echo -e "${GREEN}  🎉 全部测试通过!${NC}"
    echo -e "${GREEN}═══════════════════════════════════${NC}"
else
    echo -e "${RED}═══════════════════════════════════${NC}"
    echo -e "${RED}  ❌ $FAIL_COUNT 个测试失败${NC}"
    echo -e "${RED}═══════════════════════════════════${NC}"
    exit 1
fi
