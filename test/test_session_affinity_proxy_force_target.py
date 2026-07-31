"""离线测试：privateIp 配置后登录 Cookie 写入指定节点 IP。

配置 ``privateIp = "10.0.0.13"`` 后，在三台机器的任意一台上登录，
Cookie 都会写 ``session_id.10.0.0.13``，浏览器后续请求按 Cookie 亲和
走到该节点。
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

_src = Path(__file__).resolve().parent.parent / "src"
if str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

import server  # noqa: E402
from core.session_affinity_proxy import SessionAffinityProxy  # noqa: E402
from server import _encode_webui_session_cookie, resolve_machine_ip  # noqa: E402


class PrivateIpCookieTests(unittest.TestCase):
    """privateIp 控制的是 Cookie 里写哪个 IP，不是强制路由。"""

    def test_cookie_uses_webui_ip_when_private_ip_configured(self) -> None:
        """配了 privateIp → Cookie 带 privateIp，不是本机 IP。"""
        webui_ip = resolve_machine_ip("10.23.45.67")
        local_ip = resolve_machine_ip("10.0.0.1")

        self.assertEqual(webui_ip, "10.23.45.67")
        self.assertEqual(local_ip, "10.0.0.1")

        # Cookie 用 webui_ip 编码（模拟 login 逻辑）
        cookie = _encode_webui_session_cookie("test_session", webui_ip)
        self.assertEqual(cookie, "test_session.10.23.45.67")

        # Cookie 不会带本机 IP
        self.assertNotIn(local_ip, cookie)

    def test_cookie_uses_local_ip_when_private_ip_not_configured(self) -> None:
        """没配 privateIp → Cookie 带本机 IP。"""
        with patch.object(server, "get_machine_ip", return_value="10.0.0.1"):
            ip = resolve_machine_ip("")
            self.assertEqual(ip, "10.0.0.1")

            cookie = _encode_webui_session_cookie("test_session", ip)
            self.assertEqual(cookie, "test_session.10.0.0.1")

    def test_fallback_to_local_ip(self) -> None:
        """webui_ip 为 None 时回退到本机 IP（兼容旧调用）。"""
        with patch.object(server, "get_machine_ip", return_value="10.0.0.1"):
            local = resolve_machine_ip("")
        webui = local  # webui_ip is None → falls back to local

        cookie = _encode_webui_session_cookie("test_session", webui)
        self.assertEqual(cookie, "test_session.10.0.0.1")


class ForceTargetProxyTests(unittest.IsolatedAsyncioTestCase):
    """privateIp 钉死模式：所有 /mcp/web 请求（含登录）都转发到目标节点。"""

    TARGET_IP = "10.0.0.13"
    OTHER_IP = "10.0.0.11"

    def make_proxy(self, local_ip: str):
        local_scopes: list[dict] = []
        requests: list = []

        async def app(scope, receive, send):
            local_scopes.append(scope)
            if scope["type"] == "http":
                await send({"type": "http.response.start", "status": 200, "headers": [(b"x-local", b"yes")]})
                await send({"type": "http.response.body", "body": b"local", "more_body": False})

        def upstream(request):
            requests.append(request)
            return httpx.Response(200, headers=[("x-upstream", "yes")], content=b"upstream")

        client = httpx.AsyncClient(transport=httpx.MockTransport(upstream))

        def decoder(value):
            return ("session", self.TARGET_IP) if value == "s." + self.TARGET_IP else None

        proxy = SessionAffinityProxy(
            app,
            decoder=decoder,
            local_ip=local_ip,
            target_port=3000,
            client=client,
            force_target_ip=self.TARGET_IP,
        )
        return proxy, local_scopes, requests, client

    async def invoke(self, proxy, path="/mcp/web/login", headers=None):
        sent: list[dict] = []
        messages = [{"type": "http.request", "body": b"", "more_body": False}]

        async def receive():
            if messages:
                return messages.pop(0)
            return {"type": "http.disconnect"}

        async def send(message):
            sent.append(message)

        scope = {
            "type": "http",
            "path": path,
            "method": "GET",
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": headers or [],
        }
        await proxy(scope, receive, send)
        return sent

    async def test_non_target_node_forwards_login(self) -> None:
        """非目标节点：无 Cookie 的登录请求也转发到目标节点。"""
        proxy, local, requests, client = self.make_proxy(self.OTHER_IP)
        try:
            result = await self.invoke(proxy, path="/mcp/web/login")
            self.assertEqual(len(requests), 1)
            self.assertEqual(requests[0].url.host, self.TARGET_IP)
            self.assertEqual(local, [])  # 本地 app 未被调用
            self.assertEqual(result[0]["status"], 200)
        finally:
            await client.aclose()

    async def test_non_target_node_forwards_web_paths_without_cookie(self) -> None:
        """非目标节点：无 Cookie 的普通 Web 请求也转发（Cookie 亲和模式下会走本地）。"""
        proxy, local, requests, client = self.make_proxy(self.OTHER_IP)
        try:
            for path in ("/mcp/web", "/mcp/web/models", "/mcp/web/example/deployment"):
                await self.invoke(proxy, path=path)
            self.assertEqual(len(requests), 3)
            self.assertEqual(local, [])
        finally:
            await client.aclose()

    async def test_target_node_serves_locally(self) -> None:
        """目标节点自身：本地处理，不转发。"""
        proxy, local, requests, client = self.make_proxy(self.TARGET_IP)
        try:
            result = await self.invoke(proxy, path="/mcp/web/login")
            self.assertEqual(requests, [])
            self.assertEqual(len(local), 1)
            self.assertEqual(result[0]["status"], 200)
        finally:
            await client.aclose()

    async def test_force_target_hop_loop_guard(self) -> None:
        """已带内部跳转头的请求不再二次转发，直接 502。"""
        proxy, local, requests, client = self.make_proxy(self.OTHER_IP)
        try:
            result = await self.invoke(
                proxy, headers=[(b"x-doris-session-affinity-hop", b"1")]
            )
            self.assertEqual(result[0]["status"], 502)
            self.assertEqual(requests, [])
            self.assertEqual(local, [])
        finally:
            await client.aclose()

    async def test_mcp_protocol_passes_through_on_non_target(self) -> None:
        """非目标节点：/mcp 协议路径不转发，本地处理。"""
        proxy, local, requests, client = self.make_proxy(self.OTHER_IP)
        try:
            result = await self.invoke(proxy, path="/mcp")
            self.assertEqual(requests, [])
            self.assertEqual(len(local), 1)
            self.assertEqual(result[0]["status"], 200)
        finally:
            await client.aclose()


if __name__ == "__main__":
    unittest.main()
