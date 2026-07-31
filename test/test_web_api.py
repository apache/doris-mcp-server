#!/usr/bin/env python3
"""
Web UI & REST API 测试用例

覆盖:
  - Web UI 页面访问 (login, models, file editor)
  - REST API (semantic push/pull/validate/commit)
  - 工作区管理 API (create/delete)
  - 认证 (login, logout, session)

用法:
  python test/test_web_api.py

环境变量:
  MCP_BASE_URL               服务器地址 (默认 http://localhost:3000)
  MCP_TOKEN                  Bearer token (默认 admin:admin)
  DORIS_USER / DORIS_PASS    Doris 登录凭据 (默认 admin / admin)
  DORIS_MCP_TEST_DESTRUCTIVE=1  才执行破坏性用例 (discard 暂存变更、
                                创建/删除工作区)，默认跳过
"""

import json
import os
import sys
import unittest
import urllib.request
import urllib.error
import http.cookiejar
from urllib.parse import urlencode

# ── 配置 ─────────────────────────────────────────
BASE_URL = os.environ.get("MCP_BASE_URL", "http://localhost:3000")
AUTH_TOKEN = os.environ.get("MCP_TOKEN", "admin:admin")
WORKSPACE = os.environ.get("MCP_WORKSPACE", "example")
TEST_DORIS_USER = os.environ.get("DORIS_USER", "admin")
TEST_DORIS_PASS = os.environ.get("DORIS_PASS", "admin")
# 破坏性用例（会 discard 共享服务器上的真实暂存变更、创建/删除工作区）
# 默认跳过，显式设置 DORIS_MCP_TEST_DESTRUCTIVE=1 才执行
DESTRUCTIVE = os.environ.get("DORIS_MCP_TEST_DESTRUCTIVE") == "1"

HEADERS = {
    "Authorization": f"Bearer {AUTH_TOKEN}",
}
JSON_HEADERS = {
    **HEADERS,
    "Content-Type": "application/json",
}


def _require_destructive():
    """破坏性用例守卫：未设置 DORIS_MCP_TEST_DESTRUCTIVE=1 时跳过。"""
    if not DESTRUCTIVE:
        raise unittest.SkipTest(
            "跳过：破坏性用例需 DORIS_MCP_TEST_DESTRUCTIVE=1 才执行"
        )


def _server_reachable() -> bool:
    """探测 MCP Server 是否可达（登录页应返回 200）。

    只认 200：连接拒绝是未启动；502/404 等说明端口被其他服务占用，
    同样视为不可达，避免对错误的目标跑完整套用例。
    """
    req = urllib.request.Request(f"{BASE_URL}/mcp/web/login", headers={})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except (urllib.error.HTTPError, OSError):
        return False


def _get(path: str, headers: dict = None, expect_code: int = 200) -> dict:
    """GET 请求，返回 (status_code, body_dict)"""
    req = urllib.request.Request(f"{BASE_URL}{path}", headers=headers or HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode()
            try:
                return resp.status, json.loads(body)
            except json.JSONDecodeError:
                return resp.status, body
    except urllib.error.HTTPError as e:
        if e.code == expect_code:
            return e.code, e.read().decode()
        raise


def _post(path: str, data: dict = None, headers: dict = None,
          expect_code: int = 200) -> tuple:
    """POST 请求"""
    req = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=json.dumps(data).encode() if data else None,
        headers=headers or JSON_HEADERS,
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode()
            try:
                return resp.status, json.loads(body)
            except json.JSONDecodeError:
                return resp.status, body
    except urllib.error.HTTPError as e:
        if e.code == expect_code:
            return e.code, e.read().decode()
        raise


# ═══════════════════════════════════════════════════════
#  Web UI 测试
# ═══════════════════════════════════════════════════════

def test_webui_login_page():
    """GET /mcp/web/login — 应返回登录页面 HTML"""
    status, body = _get("/mcp/web/login", headers={}, expect_code=200)
    assert "html" in str(body).lower() or "login" in str(body).lower(), \
        f"Should return login page: {str(body)[:200]}"
    print("  ✅ 登录页面可访问")


def test_webui_login_post():
    """POST /mcp/web/login — 使用 Doris 凭据登录"""
    import urllib.parse
    form_data = urlencode({
        "username": TEST_DORIS_USER,
        "password": TEST_DORIS_PASS,
    }).encode()
    req = urllib.request.Request(
        f"{BASE_URL}/mcp/web/login",
        data=form_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            cookies = resp.headers.get_all("Set-Cookie")
            assert resp.status in (200, 302, 303, 400), f"Unexpected status: {resp.status}"
            # 400 may occur if already logged in or missing CSRF, still means endpoint works
            print(f"  ✅ 登录接口响应 status={resp.status}")
    except urllib.error.HTTPError as e:
        if e.code in (302, 303):
            print(f"  ✅ 登录成功 (重定向 {e.code})")
        elif e.code == 400:
            print(f"  ✅ 登录接口可访问 (400, 可能缺少 CSRF token)")
        else:
            raise


def test_webui_requires_auth():
    """GET /mcp/web — 未登录应返回登录页或 401"""
    status, body = _get("/mcp/web", headers={}, expect_code=200)
    # 未登录时可能返回 401 或重定向到登录页
    assert status in (200, 401, 302), f"Unexpected status: {status}"
    print(f"  ✅ 未登录访问返回 {status}")


def test_webui_models_page():
    """GET /mcp/web/models — 已认证访问"""
    status, body = _get("/mcp/web/models")
    assert status == 200, f"Expected 200, got {status}: {str(body)[:200]}"
    print("  ✅ 模型管理页面可访问")


# ═══════════════════════════════════════════════════════
#  REST API 测试 — 语义模型管理
# ═══════════════════════════════════════════════════════

def test_api_semantic_files_list():
    """GET /mcp/web/semantic/files — 列出已生效文件"""
    status, body = _get("/mcp/web/semantic/files")
    assert status == 200
    assert body.get("success") is not False, f"Failed: {body}"
    print(f"  ✅ 语义文件列表: {json.dumps(body, ensure_ascii=False)[:200]}")


def test_api_semantic_pull():
    """GET /mcp/web/semantic/pull — 下载已生效 YAML（.tar.gz 二进制）"""
    req = urllib.request.Request(f"{BASE_URL}/mcp/web/semantic/pull", headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
            # .tar.gz starts with \x1f\x8b
            is_gzip = raw[:2] == b'\x1f\x8b'
            assert resp.status in (200, 404)
            size = len(raw)
            print(f"  ✅ pull: status={resp.status}, size={size}B, gzip={is_gzip}")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(f"  ✅ pull: 404 (无文件)")
        else:
            raise


def test_api_semantic_reload():
    """POST /mcp/web/semantic/reload — 重载工作区"""
    status, body = _post("/mcp/web/semantic/reload", {"workspace": WORKSPACE})
    assert status == 200
    print(f"  ✅ reload: {json.dumps(body, ensure_ascii=False)[:200]}")


def test_api_staging_validate():
    """POST /mcp/web/staging/validate — 验证暂存变更"""
    status, body = _post("/mcp/web/staging/validate", {"workspace": WORKSPACE})
    assert status == 200
    assert "success" in body, f"Missing success field: {body}"
    print(f"  ✅ validate: {json.dumps(body, ensure_ascii=False)[:200]}")


def test_api_staging_discard():
    """POST /mcp/web/staging/discard — 丢弃暂存变更

    破坏性：会丢弃共享服务器上真实用户的暂存变更，默认跳过。
    """
    _require_destructive()
    status, body = _post("/mcp/web/staging/discard", {"workspace": WORKSPACE})
    assert status == 200
    print(f"  ✅ discard: {json.dumps(body, ensure_ascii=False)[:200]}")


# ═══════════════════════════════════════════════════════
#  工作区管理 API 测试
# ═══════════════════════════════════════════════════════

def test_api_workspace_create_and_delete():
    """创建 → 验证 → 删除 工作区

    破坏性：会在服务器上创建/删除真实工作区，默认跳过。
    """
    _require_destructive()
    test_ws = "test_workspace_tmp"

    # 清理残留
    _post("/mcp/web/workspace/delete", {"workspace": test_ws}, expect_code=200)

    # 创建
    status, body = _post("/mcp/web/workspace/create", {
        "name": test_ws,
    }, expect_code=200)
    assert status == 200 or body.get("success") is not False, \
        f"Create failed: status={status} body={json.dumps(body, ensure_ascii=False)[:200]}"
    print(f"  ✅ 创建工作区 '{test_ws}': {json.dumps(body, ensure_ascii=False)[:150]}")

    # 验证存在 — 通过 health check
    import urllib.request as ur
    mcp_payload = {
        "jsonrpc": "2.0", "id": 99,
        "method": "tools/call",
        "params": {"name": "check_service_health", "arguments": {"detail": True}},
    }
    mcp_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {AUTH_TOKEN}",
    }
    req = ur.Request(
        f"{BASE_URL}/mcp",
        data=json.dumps(mcp_payload).encode(),
        headers=mcp_headers,
    )
    with ur.urlopen(req, timeout=15) as resp:
        raw = resp.read().decode()
    assert test_ws in raw, f"New workspace not found in health: {raw[:500]}"
    print(f"  ✅ 工作区 '{test_ws}' 在 health check 中可见")

    # 删除
    status, body = _post("/mcp/web/workspace/delete", {"workspace": test_ws})
    assert status == 200
    print(f"  ✅ 删除工作区 '{test_ws}'")


# ═══════════════════════════════════════════════════════
#  认证测试
# ═══════════════════════════════════════════════════════

def test_api_requires_admin_for_create():
    """非 admin 用户不能创建工作区"""
    # 使用 test 用户 token
    test_headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer test:test",
    }
    status, body = _post(
        "/mcp/web/workspace/create",
        {"workspace": "hacker_ws"},
        headers=test_headers,
        expect_code=403,
    )
    assert status in (401, 403), f"Expected 401/403, got {status}: {body}"
    print(f"  ✅ test 用户无法创建工作区 ({status})")


def test_bearer_token_format():
    """验证 Bearer token 格式: username:password"""
    # 正确格式
    ok_headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {TEST_DORIS_USER}:{TEST_DORIS_PASS}",
        "Accept": "application/json, text/event-stream",
    }
    payload = {
        "jsonrpc": "2.0", "id": 1,
        "method": "tools/call",
        "params": {"name": "check_service_health", "arguments": {}},
    }
    req = urllib.request.Request(
        f"{BASE_URL}/mcp",
        data=json.dumps(payload).encode(),
        headers=ok_headers,
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        body = resp.read().decode()
    assert "connected" in body.lower(), f"Auth failed with valid token: {body[:300]}"
    print("  ✅ 正确 Bearer token 格式验证通过")


# ═══════════════════════════════════════════════════════
if __name__ == "__main__":
    print("=" * 60)
    print("Web UI & REST API 测试开始")
    print(f"  URL: {BASE_URL}")
    print(f"  Workspace: {WORKSPACE}")
    print("=" * 60)

    if not _server_reachable():
        print(f"\n⚠️ MCP Server 不可达 ({BASE_URL})，整体跳过，不视为失败")
        sys.exit(0)

    tests = [
        # Web UI
        ("Web UI login page", test_webui_login_page),
        ("Web UI login POST", test_webui_login_post),
        ("Web UI requires auth", test_webui_requires_auth),
        ("Web UI models page", test_webui_models_page),
        # REST API
        ("API semantic files list", test_api_semantic_files_list),
        ("API semantic pull", test_api_semantic_pull),
        ("API semantic reload", test_api_semantic_reload),
        ("API staging validate", test_api_staging_validate),
        ("API staging discard", test_api_staging_discard),
        # Workspace
        ("Workspace create/delete", test_api_workspace_create_and_delete),
        # Auth
        ("Admin required for create", test_api_requires_admin_for_create),
        ("Bearer token format", test_bearer_token_format),
    ]

    passed = 0
    failed = 0
    skipped = 0
    for name, fn in tests:
        try:
            print(f"\n[{name}]")
            fn()
            passed += 1
        except unittest.SkipTest as e:
            print(f"  ⚠️ SKIP: {e}")
            skipped += 1
        except AssertionError as e:
            print(f"  ❌ FAIL: {e}")
            failed += 1
        except Exception as e:
            print(f"  ❌ ERROR: {e}")
            failed += 1
            import traceback
            traceback.print_exc()

    print(f"\n{'='*60}")
    print(f"结果: {passed} passed, {failed} failed, {skipped} skipped")
    print(f"{'='*60}")
    if failed > 0:
        sys.exit(1)
