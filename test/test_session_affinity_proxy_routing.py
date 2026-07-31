"""Offline routing and protocol tests for the session-affinity ASGI proxy."""

from __future__ import annotations

import sys
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx

_src = Path(__file__).resolve().parent.parent / "src"
if str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

from core.session_affinity_proxy import SessionAffinityProxy  # noqa: E402


REMOTE_IP = "10.23.45.67"
LOCAL_IP = "127.0.0.1"
COOKIE = "doris_mcp_session"


class SessionAffinityProxyRoutingTests(unittest.IsolatedAsyncioTestCase):
    def make_proxy(
        self, handler: Callable[[httpx.Request], httpx.Response] | None = None
    ) -> tuple[SessionAffinityProxy, list[dict[str, Any]], list[httpx.Request], httpx.AsyncClient]:
        local_scopes: list[dict[str, Any]] = []
        requests: list[httpx.Request] = []

        async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
            local_scopes.append(scope)
            if scope["type"] == "http":
                await send({"type": "http.response.start", "status": 201, "headers": [(b"x-local", b"yes")]})
                await send({"type": "http.response.body", "body": b"local", "more_body": False})

        def upstream(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if handler is not None:
                return handler(request)
            return httpx.Response(202, headers=[("x-upstream", "yes")], content=b"upstream")

        client = httpx.AsyncClient(transport=httpx.MockTransport(upstream))

        def decoder(value: str) -> tuple[str, str] | None:
            return {
                "remote": ("session", REMOTE_IP),
                "local": ("session", LOCAL_IP),
            }.get(value)

        return (
            SessionAffinityProxy(app, decoder=decoder, local_ip=LOCAL_IP, target_port=8080, client=client),
            local_scopes,
            requests,
            client,
        )

    async def invoke(
        self,
        proxy: SessionAffinityProxy,
        *,
        path: str = "/mcp/web",
        method: str = "GET",
        headers: list[tuple[bytes, bytes]] | None = None,
        body: bytes = b"",
        raw_path: bytes | None = None,
        query: bytes = b"",
        scope_type: str = "http",
    ) -> list[dict[str, Any]]:
        sent: list[dict[str, Any]] = []
        messages = ([{"type": "http.request", "body": body, "more_body": False}]
                    if scope_type == "http" else [])

        async def receive() -> dict[str, Any]:
            if messages:
                return messages.pop(0)
            return {"type": "http.disconnect"}

        async def send(message: dict[str, Any]) -> None:
            sent.append(message)

        scope: dict[str, Any] = {"type": scope_type, "path": path, "headers": headers or []}
        if scope_type == "http":
            scope.update({"method": method, "raw_path": raw_path or path.encode(), "query_string": query})
        await proxy(scope, receive, send)
        return sent

    @staticmethod
    def response_body(messages: list[dict[str, Any]]) -> bytes:
        return b"".join(message.get("body", b"") for message in messages if message["type"] == "http.response.body")

    async def test_non_http_is_passed_to_local_app(self) -> None:
        proxy, local, requests, client = self.make_proxy()
        try:
            await self.invoke(proxy, path="/mcp/web", scope_type="websocket")
            self.assertEqual([scope["type"] for scope in local], ["websocket"])
            self.assertEqual(requests, [])
        finally:
            await client.aclose()

    async def test_only_web_route_and_children_with_remote_cookie_are_proxied(self) -> None:
        proxy, local, requests, client = self.make_proxy()
        remote_headers = [(b"cookie", b"doris_mcp_session=remote")]
        try:
            for path in ("/mcp", "/mcp/webx"):
                result = await self.invoke(proxy, path=path, headers=remote_headers)
                self.assertEqual(result[0]["status"], 201)
            for path in ("/mcp/web", "/mcp/web/assets/app.js", "/mcp/web/logout"):
                result = await self.invoke(proxy, path=path, headers=remote_headers)
                self.assertEqual(result[0]["status"], 202)
            self.assertEqual([request.url.path for request in requests], ["/mcp/web", "/mcp/web/assets/app.js", "/mcp/web/logout"])
            self.assertEqual(len(local), 2)
        finally:
            await client.aclose()

    async def test_exact_login_is_local_for_get_and_post_despite_remote_cookie(self) -> None:
        proxy, local, requests, client = self.make_proxy()
        try:
            for method in ("GET", "POST"):
                result = await self.invoke(proxy, path="/mcp/web/login", method=method,
                                           headers=[(b"cookie", b"doris_mcp_session=remote")], body=b"credentials")
                self.assertEqual(result[0]["status"], 201)
            self.assertEqual(requests, [])
            self.assertEqual([scope["method"] for scope in local], ["GET", "POST"])
        finally:
            await client.aclose()

    async def test_missing_invalid_local_and_duplicate_cookie_stay_local_and_hide_internal_hop(self) -> None:
        proxy, local, requests, client = self.make_proxy()
        cases = [
            [],
            [(b"cookie", b"doris_mcp_session=invalid")],
            [(b"cookie", b"doris_mcp_session=local")],
            [(b"cookie", b"doris_mcp_session=remote; doris_mcp_session=remote")],
            [(b"cookie", b"doris_mcp_session=remote"), (b"cookie", b"doris_mcp_session=remote")],
            [(b"x-doris-session-affinity-hop", b"forged")],
        ]
        try:
            for headers in cases:
                result = await self.invoke(proxy, headers=headers)
                self.assertEqual(result[0]["status"], 201)
            self.assertEqual(requests, [])
            self.assertTrue(all(
                b"x-doris-session-affinity-hop" not in {name.lower() for name, _ in scope["headers"]}
                for scope in local
            ))
        finally:
            await client.aclose()

    async def test_proxy_preserves_request_parts_and_strips_routing_hop_headers(self) -> None:
        proxy, _, requests, client = self.make_proxy()
        headers = [
            (b"host", b"attacker.invalid"), (b"cookie", b"doris_mcp_session=remote"),
            (b"x-normal", b"one"), (b"x-normal", b"two"), (b"connection", b"x-remove, Keep-Alive"),
            (b"x-remove", b"gone"), (b"keep-alive", b"timeout=5"), (b"te", b"trailers"),
            (b"transfer-encoding", b"compress"), (b"upgrade", b"websocket"),
        ]
        try:
            result = await self.invoke(proxy, method="PATCH", path="/mcp/web/a b", raw_path=b"/mcp/web/a%2Fb",
                                       query=b"x=%2F&tag=one&tag=two", headers=headers, body=b"request-body")
            self.assertEqual(result[0]["status"], 202)
            request = self.assert_and_return_one_request(requests)
            self.assertEqual(request.method, "PATCH")
            self.assertEqual(str(request.url), f"http://{REMOTE_IP}:8080/mcp/web/a%2Fb?x=%2F&tag=one&tag=two")
            self.assertEqual(await request.aread(), b"request-body")
            raw = request.headers.raw
            self.assertIn((b"x-normal", b"one"), raw)
            self.assertIn((b"x-normal", b"two"), raw)
            self.assertIn((b"x-doris-session-affinity-hop", b"1"), raw)
            forwarded_names = {name.lower() for name, _ in raw}
            self.assertNotIn(b"x-remove", forwarded_names)
            # httpx may add its own Connection/Transfer-Encoding framing for a
            # streaming request, but none of the client-supplied hop values may survive.
            for header in [(b"connection", b"x-remove, Keep-Alive"), (b"keep-alive", b"timeout=5"),
                           (b"te", b"trailers"), (b"transfer-encoding", b"compress"),
                           (b"upgrade", b"websocket")]:
                self.assertNotIn(header, raw)
            self.assertEqual(request.headers["host"], f"{REMOTE_IP}:8080")
        finally:
            await client.aclose()

    def assert_and_return_one_request(self, requests: list[httpx.Request]) -> httpx.Request:
        self.assertEqual(len(requests), 1)
        return requests[0]

    async def test_remote_request_with_forged_or_existing_hop_is_502_without_upstream_call(self) -> None:
        proxy, _, requests, client = self.make_proxy()
        try:
            for value in (b"forged", b"1"):
                result = await self.invoke(proxy, headers=[(b"cookie", b"doris_mcp_session=remote"),
                                                           (b"x-doris-session-affinity-hop", value)])
                self.assertEqual(result[0]["status"], 502)
                self.assertEqual(self.response_body(result), b"Bad Gateway")
                self.assertNotIn(REMOTE_IP.encode(), self.response_body(result))
                self.assertNotIn(b"cookie", b"".join(value for _, value in result[0]["headers"]).lower())
            self.assertEqual(requests, [])
        finally:
            await client.aclose()

    async def test_upstream_response_filters_connection_nominated_headers_and_keeps_cookies(self) -> None:
        def handler(_: httpx.Request) -> httpx.Response:
            return httpx.Response(
                207,
                headers=[("X-Ordinary", "ok"), ("Set-Cookie", "a=1"), ("Set-Cookie", "b=2"),
                         ("Connection", "X-Remove"), ("X-Remove", "gone")],
                content=b"response",
            )

        proxy, _, _, client = self.make_proxy(handler)
        try:
            result = await self.invoke(proxy, headers=[(b"cookie", b"doris_mcp_session=remote")])
            self.assertEqual(result[0]["status"], 207)
            response_headers = result[0]["headers"]
            self.assertIn((b"x-ordinary", b"ok"), response_headers)
            self.assertEqual(
                [value for name, value in response_headers if name == b"set-cookie"],
                [b"a=1", b"b=2"],
            )
            self.assertNotIn(b"connection", {name.lower() for name, _ in response_headers})
            self.assertNotIn(b"x-remove", {name.lower() for name, _ in response_headers})
            self.assertTrue(all(name == name.lower() for name, _ in response_headers))
            self.assertEqual(self.response_body(result), b"response")
        finally:
            await client.aclose()

    async def test_upstream_connection_protocol_and_timeout_errors_clear_cookie_and_redirect(self) -> None:
        for error in (httpx.ConnectError("refused"), httpx.ProtocolError("bad protocol"),
                       httpx.ReadTimeout("slow")):
            def handler(request: httpx.Request, error: httpx.HTTPError = error) -> httpx.Response:
                raise error
            proxy, _, requests, client = self.make_proxy(handler)
            try:
                result = await self.invoke(proxy, headers=[(b"cookie", b"doris_mcp_session=remote")])
                self.assertEqual(result[0]["status"], 303)
                location = [v for n, v in result[0]["headers"] if n.lower() == b"location"]
                self.assertEqual(location, [b"/mcp/web/login"])
                wire = b"".join(value for _, value in result[0]["headers"]) + self.response_body(result)
                self.assertNotIn(REMOTE_IP.encode(), wire)
                self.assertEqual(len(requests), 1)
            finally:
                await client.aclose()


if __name__ == "__main__":
    unittest.main()
