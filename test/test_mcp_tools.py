#!/usr/bin/env python3
"""
MCP Tool 测试用例 — 覆盖全部 10 个 Tool

运行环境:
  - Doris FE 127.0.0.1:9030，admin:admin
  - MCP Server http://localhost:3000/mcp
  - Python 3.10+

用法:
  python -m pytest test/test_mcp_tools.py -v
  或直接: python test/test_mcp_tools.py
"""

import json
import os
import sys
import unittest
import urllib.request
import urllib.error

# ── 配置 ─────────────────────────────────────────
MCP_URL = os.environ.get("MCP_URL", "http://localhost:3000/mcp")
AUTH_TOKEN = os.environ.get("MCP_TOKEN", "admin:admin")
WORKSPACE = os.environ.get("MCP_WORKSPACE", "example")

HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
    "Authorization": f"Bearer {AUTH_TOKEN}",
}

# 仅连接类异常允许跳过测试；AssertionError 必须冒出来
_CONN_ERRORS = (urllib.error.URLError, ConnectionError, TimeoutError)


def _call_tool(name: str, arguments: dict) -> dict:
    """调用 MCP Tool，解析 SSE 响应"""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }
    req = urllib.request.Request(
        MCP_URL, data=json.dumps(payload).encode(), headers=HEADERS
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode()
    except urllib.error.HTTPError as e:
        return {"error": str(e.code), "body": e.read().decode()}

    # 解析 SSE: "event: message\ndata: <json>\n\n"
    data_json = body
    if body.startswith("event: message"):
        data_line = [l for l in body.split("\n") if l.startswith("data:")]
        if data_line:
            data_json = data_line[0][5:].strip()
    try:
        return json.loads(data_json)
    except json.JSONDecodeError:
        return {"raw": body}


def _assert_success(result: dict):
    """断言调用成功"""
    assert "result" in result, f"Expected 'result' key: {json.dumps(result, ensure_ascii=False)[:500]}"
    assert not result.get("isError"), f"Tool returned error: {json.dumps(result, ensure_ascii=False)[:500]}"
    content = result["result"]["content"][0]["text"]
    data = json.loads(content)
    assert data["success"], f"Tool failed: {data.get('error', data)}"
    return data


# ═══════════════════════════════════════════════════════
#  Tool #1: get_query_guide
# ═══════════════════════════════════════════════════════

def test_get_query_guide():
    """Tool #1: 获取工作流指引 — 第一步必调"""
    result = _call_tool("get_query_guide", {})
    assert "result" in result
    text = result["result"]["content"][0]["text"]
    assert len(text) > 100, f"Guide too short: {len(text)} chars"
    # 应包含关键指引内容，如语义层使用说明、工具调用顺序等
    assert any(kw in text.lower() for kw in ["指标", "语义", "metric", "query", "workspace"]), \
        f"Guide missing key content: {text[:200]}"
    print("  ✅ get_query_guide 返回有效指引")


# ═══════════════════════════════════════════════════════
#  Tool #2: check_service_health
# ═══════════════════════════════════════════════════════

def test_check_service_health_basic():
    """Tool #2: 基础健康检查"""
    data = _assert_success(_call_tool("check_service_health", {}))
    assert data["data"]["doris"] == "connected", f"Doris not connected: {data}"
    assert "workspaces" in data["data"], "Missing workspaces"
    print(f"  ✅ Doris 连接正常, workspaces: {list(data['data']['workspaces'].keys())}")


def test_check_service_health_detail():
    """Tool #2: 详细健康检查"""
    data = _assert_success(_call_tool("check_service_health", {"detail": True}))
    assert data["data"]["doris"] == "connected"
    print(f"  ✅ 详细健康检查通过")


# ═══════════════════════════════════════════════════════
#  Tool #3: list_metrics
# ═══════════════════════════════════════════════════════

def test_list_metrics():
    """Tool #3: 列出工作区指标"""
    data = _assert_success(
        _call_tool("list_metrics", {"workspace": WORKSPACE})
    )
    assert "data" in data
    print(f"  ✅ 指标列表: {data['data']}")


def test_list_metrics_pagination():
    """Tool #3: 分页测试"""
    data = _assert_success(
        _call_tool("list_metrics", {"workspace": WORKSPACE, "page_size": 2})
    )
    assert "meta" in data, "Missing pagination meta"
    print(f"  ✅ 分页正常, total_count={data.get('meta', {}).get('total_count', 'N/A')}")


# ═══════════════════════════════════════════════════════
#  Tool #4: list_dimensions_for_metric
# ═══════════════════════════════════════════════════════

def test_list_dimensions_for_metric():
    """Tool #4: 列出指标维度"""
    # 需要语义层就绪；仅在 MCP Server 不可达（连接类异常）时跳过
    try:
        data = _assert_success(
            _call_tool("list_dimensions_for_metric", {
                "workspace": WORKSPACE,
                "metric_name": "total_amount",
            })
        )
        assert "data" in data
        print(f"  ✅ total_amount 维度: {data['data']}")
    except _CONN_ERRORS as e:
        # 只有连接类异常才跳过；语义层未就绪等断言失败必须冒出来
        raise unittest.SkipTest(f"跳过：MCP Server 不可达: {e}")


# ═══════════════════════════════════════════════════════
#  Tool #5: query_metric
# ═══════════════════════════════════════════════════════

def test_query_metric_basic():
    """Tool #5: 核心 — 语义查询单个指标"""
    try:
        data = _assert_success(
            _call_tool("query_metric", {
                "workspace": WORKSPACE,
                "metrics": ["total_amount"],
            })
        )
        assert "data" in data
        print(f"  ✅ query_metric 结果: {data['data']}")
    except _CONN_ERRORS as e:
        # 只有连接类异常才跳过；语义层未就绪等断言失败必须冒出来
        raise unittest.SkipTest(f"跳过：MCP Server 不可达: {e}")


def test_query_metric_with_group_by():
    """Tool #5: 带 group_by 的语义查询"""
    try:
        data = _assert_success(
            _call_tool("query_metric", {
                "workspace": WORKSPACE,
                "metrics": ["total_amount", "order_count"],
                "group_by": ["channel"],
            })
        )
        assert "data" in data
        print(f"  ✅ 多指标+group_by 查询成功")
    except _CONN_ERRORS as e:
        # 只有连接类异常才跳过；语义层未就绪等断言失败必须冒出来
        raise unittest.SkipTest(f"跳过：MCP Server 不可达: {e}")


def test_query_metric_with_where():
    """Tool #5: 带 where 条件的语义查询"""
    try:
        data = _assert_success(
            _call_tool("query_metric", {
                "workspace": WORKSPACE,
                "metrics": ["total_amount"],
                "where": '{{ Dimension("user__city") }} = \'Beijing\'',
            })
        )
        print(f"  ✅ 带 where 条件的查询成功")
    except _CONN_ERRORS as e:
        # 只有连接类异常才跳过；语义层未就绪等断言失败必须冒出来
        raise unittest.SkipTest(f"跳过：MCP Server 不可达: {e}")


def test_query_metric_with_order_and_limit():
    """Tool #5: 排序+分页"""
    try:
        data = _assert_success(
            _call_tool("query_metric", {
                "workspace": WORKSPACE,
                "metrics": ["total_amount"],
                "group_by": ["channel"],
                "order_by": ["-total_amount"],
                "limit": 3,
            })
        )
        print(f"  ✅ 排序+分页查询成功")
    except _CONN_ERRORS as e:
        # 只有连接类异常才跳过；语义层未就绪等断言失败必须冒出来
        raise unittest.SkipTest(f"跳过：MCP Server 不可达: {e}")


# ═══════════════════════════════════════════════════════
#  Tool #6: list_databases
# ═══════════════════════════════════════════════════════

def test_list_databases():
    """Tool #6: 列出所有数据库"""
    data = _assert_success(_call_tool("list_databases", {}))
    databases = data["data"]
    assert isinstance(databases, list)
    assert len(databases) >= 2, f"Expected at least 2 databases, got {len(databases)}"
    expected = {"dw", "mysql", "information_schema", "system_mcp"}
    found = set(databases) & expected
    assert len(found) >= 2, f"Missing expected databases: {expected - found}"
    print(f"  ✅ 数据库列表: {databases}")


def test_list_databases_pagination():
    """Tool #6: 分页"""
    data = _assert_success(
        _call_tool("list_databases", {"page_size": 2})
    )
    assert "meta" in data
    assert data["meta"]["total_count"] >= 2
    print(f"  ✅ 分页: total={data['meta']['total_count']}")


# ═══════════════════════════════════════════════════════
#  Tool #7: list_tables
# ═══════════════════════════════════════════════════════

def test_list_tables_mysql():
    """Tool #7: 列出 mysql 库的表"""
    data = _assert_success(
        _call_tool("list_tables", {"database": "mysql"})
    )
    assert "data" in data
    assert "user" in data["data"], f"Expected 'user' table: {data['data']}"
    print(f"  ✅ mysql 表: {data['data']}")


def test_list_tables_dw():
    """Tool #7: 列出 dw 库的表"""
    data = _assert_success(
        _call_tool("list_tables", {"database": "dw"})
    )
    dw_tables = data["data"]
    expected = {"orders", "users", "products", "dim_date"}
    assert expected.issubset(set(dw_tables)), \
        f"Missing seed tables: {expected - set(dw_tables)}"
    print(f"  ✅ dw 种子表: {dw_tables}")


def test_list_tables_with_like():
    """Tool #7: 模糊匹配"""
    data = _assert_success(
        _call_tool("list_tables", {"database": "mysql", "like": "user%"})
    )
    assert "user" in data["data"]
    print(f"  ✅ like 匹配正常")


# ═══════════════════════════════════════════════════════
#  Tool #8: describe_table
# ═══════════════════════════════════════════════════════

def test_describe_table_summary():
    """Tool #8: 表结构 — summary 级别"""
    data = _assert_success(
        _call_tool("describe_table", {
            "database": "dw",
            "table": "orders",
            "detail_level": "summary",
        })
    )
    assert "data" in data
    print(f"  ✅ dw.orders 结构: {data['data']}")


def test_describe_table_full():
    """Tool #8: 表结构 — full 级别"""
    data = _assert_success(
        _call_tool("describe_table", {
            "database": "dw",
            "table": "orders",
            "detail_level": "full",
        })
    )
    assert "data" in data
    print(f"  ✅ dw.orders 完整结构")


def test_describe_table_names():
    """Tool #8: 表结构 — names 级别（仅列名）"""
    data = _assert_success(
        _call_tool("describe_table", {
            "database": "dw",
            "table": "orders",
            "detail_level": "names",
        })
    )
    assert "data" in data
    print(f"  ✅ dw.orders 列名")


# ═══════════════════════════════════════════════════════
#  Tool #9: execute_query
# ═══════════════════════════════════════════════════════

def test_execute_query_select():
    """Tool #9: 裸 SQL — 基本 SELECT"""
    data = _assert_success(
        _call_tool("execute_query", {"sql": "SELECT 1 AS n"})
    )
    assert data["data"]["rows"][0]["n"] == 1
    print(f"  ✅ SELECT 1 返回正确")


def test_execute_query_version():
    """Tool #9: 裸 SQL — Doris 版本"""
    data = _assert_success(
        _call_tool("execute_query", {"sql": "SELECT VERSION()"})
    )
    print(f"  ✅ Doris 版本: {data['data']['rows'][0]}")


def test_execute_query_with_database():
    """Tool #9: 裸 SQL — 指定数据库"""
    data = _assert_success(
        _call_tool("execute_query", {
            "sql": "SELECT count(*) AS cnt FROM orders",
            "database": "dw",
        })
    )
    assert data["data"]["rows"][0]["cnt"] == 12
    print(f"  ✅ dw.orders 有 12 条数据")


def test_execute_query_with_max_rows():
    """Tool #9: 裸 SQL — 限制返回行数"""
    data = _assert_success(
        _call_tool("execute_query", {
            "sql": "SELECT * FROM dw.dim_date",
            "max_rows": 5,
        })
    )
    assert data["meta"]["row_count"] <= 5
    print(f"  ✅ max_rows 限制生效, 返回 {data['meta']['row_count']} 行")


def test_execute_query_show():
    """Tool #9: 裸 SQL — SHOW 语句"""
    data = _assert_success(
        _call_tool("execute_query", {"sql": "SHOW DATABASES"})
    )
    assert len(data["data"]["rows"]) >= 2
    print(f"  ✅ SHOW DATABASES 成功")


def test_execute_query_explain():
    """Tool #9: 裸 SQL — EXPLAIN 语句"""
    data = _assert_success(
        _call_tool("execute_query", {
            "sql": "EXPLAIN SELECT count(*) FROM dw.orders"
        })
    )
    assert "data" in data
    print(f"  ✅ EXPLAIN 成功")


def test_execute_query_blocked_write():
    """Tool #9: 只读校验 — 拒绝 INSERT"""
    result = _call_tool("execute_query", {
        "sql": "INSERT INTO dw.orders VALUES (99,1,1,100,'online','done','2024-01-01')"
    })
    assert result.get("isError") or "error" in str(result).lower() or \
           "reject" in str(result).lower() or "not allowed" in str(result).lower() or \
           "forbidden" in str(result).lower() or "only" in str(result).lower(), \
        f"Should block write SQL: {result}"
    print(f"  ✅ 写操作被正确拦截")


# ═══════════════════════════════════════════════════════
#  Tool #10: reload_semantic_layer
# ═══════════════════════════════════════════════════════

def test_reload_semantic_layer():
    """Tool #10: 手动重载语义层"""
    result = _call_tool("reload_semantic_layer", {"workspace": WORKSPACE})
    # 必须返回合法的 JSON-RPC result，content 为可解析的结构化 JSON
    # （success_response / error_response 都带 success 字段）
    assert "result" in result, f"Expected JSON-RPC result: {json.dumps(result, ensure_ascii=False)[:500]}"
    content = result["result"]["content"][0]["text"]
    data = json.loads(content)
    assert "success" in data, f"Payload missing 'success' field: {data}"
    print(f"  ✅ reload 调用成功 (success={data['success']})")


# ═══════════════════════════════════════════════════════
#  认证/错误处理测试
# ═══════════════════════════════════════════════════════

def test_auth_required():
    """无 Authorization header 应拒绝"""
    payload = {
        "jsonrpc": "2.0", "id": 1,
        "method": "tools/call",
        "params": {"name": "list_databases", "arguments": {}},
    }
    no_auth_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }
    req = urllib.request.Request(
        MCP_URL, data=json.dumps(payload).encode(), headers=no_auth_headers
    )
    try:
        urllib.request.urlopen(req, timeout=10)
        assert False, "Should have returned error for unauthenticated request"
    except urllib.error.HTTPError as e:
        assert e.code in (401, 403), f"Expected 401/403, got {e.code}"
        print(f"  ✅ 未认证请求返回 {e.code}")


def test_invalid_token():
    """无效 Token 应被拒绝"""
    bad_headers = {**HEADERS, "Authorization": "Bearer fake:fake"}
    payload = {
        "jsonrpc": "2.0", "id": 1,
        "method": "tools/call",
        "params": {"name": "list_databases", "arguments": {}},
    }
    req = urllib.request.Request(
        MCP_URL, data=json.dumps(payload).encode(), headers=bad_headers
    )
    try:
        urllib.request.urlopen(req, timeout=10)
        assert False, "Should have rejected invalid credentials"
    except urllib.error.HTTPError as e:
        assert e.code in (401, 403), f"Expected 401/403, got {e.code}"
        print(f"  ✅ 无效 Token 返回 {e.code}")


def test_execute_query_syntax_error():
    """SQL 语法错误应返回友好错误"""
    result = _call_tool("execute_query", {"sql": "SELECTT 1"})
    # 可能是 error response 或 success=false
    is_error = (
        result.get("isError") or
        ("error" in str(result).lower()) or
        ("syntax" in str(result).lower())
    )
    assert is_error, f"Should report syntax error: {result}"
    print(f"  ✅ SQL 语法错误正确处理")


# ═══════════════════════════════════════════════════════
#  端到端工作流测试
# ═══════════════════════════════════════════════════════

def test_agent_workflow():
    """模拟 AI Agent 的标准工作流: guide → health → databases → tables → query"""
    # Step 1: guide
    r1 = _call_tool("get_query_guide", {})
    assert "result" in r1
    print("  Step 1: get_query_guide ✅")

    # Step 2: health
    r2 = _call_tool("check_service_health", {})
    assert "result" in r2
    print("  Step 2: check_service_health ✅")

    # Step 3: list databases
    r3 = _call_tool("list_databases", {})
    d3 = _assert_success(r3)
    assert "dw" in d3["data"]
    print("  Step 3: list_databases ✅")

    # Step 4: list tables
    r4 = _call_tool("list_tables", {"database": "dw"})
    d4 = _assert_success(r4)
    assert "orders" in d4["data"]
    print("  Step 4: list_tables ✅")

    # Step 5: describe
    r5 = _call_tool("describe_table", {
        "database": "dw", "table": "orders", "detail_level": "summary"
    })
    _assert_success(r5)
    print("  Step 5: describe_table ✅")

    # Step 6: query
    r6 = _call_tool("execute_query", {
        "sql": "SELECT channel, count(*) AS c FROM dw.orders GROUP BY channel"
    })
    _assert_success(r6)
    print("  Step 6: execute_query ✅")

    print("  🎉 完整 Agent 工作流通过!")


# ═══════════════════════════════════════════════════════
if __name__ == "__main__":
    print("=" * 60)
    print("MCP Tool 测试开始")
    print(f"  URL: {MCP_URL}")
    print(f"  Workspace: {WORKSPACE}")
    print("=" * 60)

    tests = [
        # Tool #1
        ("get_query_guide", test_get_query_guide),
        # Tool #2
        ("check_service_health (basic)", test_check_service_health_basic),
        ("check_service_health (detail)", test_check_service_health_detail),
        # Tool #3
        ("list_metrics", test_list_metrics),
        ("list_metrics (pagination)", test_list_metrics_pagination),
        # Tool #4
        ("list_dimensions_for_metric", test_list_dimensions_for_metric),
        # Tool #5
        ("query_metric (basic)", test_query_metric_basic),
        ("query_metric (group_by)", test_query_metric_with_group_by),
        ("query_metric (where)", test_query_metric_with_where),
        ("query_metric (order+limit)", test_query_metric_with_order_and_limit),
        # Tool #6
        ("list_databases", test_list_databases),
        ("list_databases (pagination)", test_list_databases_pagination),
        # Tool #7
        ("list_tables (mysql)", test_list_tables_mysql),
        ("list_tables (dw)", test_list_tables_dw),
        ("list_tables (like)", test_list_tables_with_like),
        # Tool #8
        ("describe_table (summary)", test_describe_table_summary),
        ("describe_table (full)", test_describe_table_full),
        ("describe_table (names)", test_describe_table_names),
        # Tool #9
        ("execute_query (SELECT)", test_execute_query_select),
        ("execute_query (VERSION)", test_execute_query_version),
        ("execute_query (database)", test_execute_query_with_database),
        ("execute_query (max_rows)", test_execute_query_with_max_rows),
        ("execute_query (SHOW)", test_execute_query_show),
        ("execute_query (EXPLAIN)", test_execute_query_explain),
        ("execute_query (block write)", test_execute_query_blocked_write),
        # Tool #10
        ("reload_semantic_layer", test_reload_semantic_layer),
        # 认证
        ("auth required", test_auth_required),
        ("invalid token", test_invalid_token),
        # 错误处理
        ("SQL syntax error", test_execute_query_syntax_error),
        # E2E
        ("Agent workflow", test_agent_workflow),
    ]

    passed = 0
    failed = 0
    skipped = 0

    for name, fn in tests:
        try:
            print(f"\n[{name}]")
            fn()
            passed += 1
        except AssertionError as e:
            print(f"  ❌ FAIL: {e}")
            failed += 1
        except Exception as e:
            if "跳过" in str(e) or "not_ready" in str(e):
                print(f"  ⚠️ SKIP: {e}")
                skipped += 1
            else:
                print(f"  ❌ ERROR: {e}")
                failed += 1

    print(f"\n{'='*60}")
    print(f"结果: {passed} passed, {failed} failed, {skipped} skipped")
    print(f"{'='*60}")

    if failed > 0:
        sys.exit(1)
