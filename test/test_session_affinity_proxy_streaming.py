"""Offline streaming and ownership tests for the session-affinity proxy."""

import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import httpx

_src = Path(__file__).resolve().parent.parent / "src"
if str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

from core.session_affinity_proxy import SessionAffinityProxy  # noqa: E402
import core.session_affinity_proxy as proxy_module  # noqa: E402


class RecordingStream(httpx.AsyncByteStream):
    """An in-memory upstream stream that records whether it was closed."""

    def __init__(self, chunks=(), error=None):
        self.chunks = list(chunks)
        self.error = error
        self.closed = False

    async def __aiter__(self):
        for chunk in self.chunks:
            yield chunk
        if self.error is not None:
            raise self.error

    async def aclose(self):
        self.closed = True


class ConsumingTransport(httpx.AsyncBaseTransport):
    """A real httpx transport that records streamed request bytes."""

    def __init__(self):
        self.request_chunks = []
        self.response_stream = RecordingStream([b"first-response", b"second-response"])

    async def handle_async_request(self, request):
        self.request_chunks.append([chunk async for chunk in request.stream])
        return httpx.Response(209, stream=self.response_stream, request=request)


class FakeClient:
    """Small client double which consumes request streams without a network."""

    def __init__(self, response=None):
        self.response = response or httpx.Response(204)
        self.requests = []
        self.bodies = []
        self.closed = 0

    def build_request(self, method, url, *, headers, content):
        return httpx.Request(method, url, headers=headers, content=content)

    async def send(self, request, *, stream):
        self.requests.append(request)
        self.bodies.append([part async for part in request.stream])
        return self.response

    async def aclose(self):
        self.closed += 1


class SessionAffinityProxyStreamingTests(unittest.IsolatedAsyncioTestCase):
    def remote_proxy(self, client=None):
        async def local_app(scope, receive, send):
            raise AssertionError("remote session should be proxied")

        return SessionAffinityProxy(
            local_app,
            decoder=lambda cookie: ("session", "10.0.0.9"),
            local_ip="10.0.0.1",
            target_port=8080,
            client=client,
        )

    @staticmethod
    def remote_scope():
        return {
            "type": "http", "method": "POST", "path": "/mcp/web/query",
            "raw_path": b"/mcp/web/query", "query_string": b"",
            "headers": [(b"cookie", b"doris_mcp_session=value")],
        }

    @staticmethod
    def receiver(messages):
        messages = iter(messages)

        async def receive():
            return next(messages)

        return receive

    @staticmethod
    def sender(messages, error=None):
        async def send(message):
            messages.append(message)
            if error is not None and message["type"] == "http.response.body":
                raise error

        return send

    async def test_request_chunks_are_delivered_to_upstream_in_order(self):
        client = FakeClient(httpx.Response(201, stream=RecordingStream([b"ok"])))
        sent = []
        await self.remote_proxy(client)(
            self.remote_scope(),
            self.receiver([
                {"type": "http.request", "body": b"first-", "more_body": True},
                {"type": "http.request", "body": b"second", "more_body": False},
            ]),
            self.sender(sent),
        )
        self.assertEqual(client.bodies, [[b"first-", b"second"]])
        self.assertEqual(sent[-1], {"type": "http.response.body", "body": b"", "more_body": False})

    async def test_disconnect_during_upload_stops_proxy_without_response(self):
        client = FakeClient()
        sent = []
        await self.remote_proxy(client)(
            self.remote_scope(),
            self.receiver([
                {"type": "http.request", "body": b"partial", "more_body": True},
                {"type": "http.disconnect"},
            ]),
            self.sender(sent),
        )
        self.assertEqual(sent, [])
        self.assertEqual(client.bodies, [])

    async def test_response_chunks_are_sent_in_order_and_terminated(self):
        stream = RecordingStream([b"one", b"two"])
        sent = []
        await self.remote_proxy(FakeClient(httpx.Response(207, stream=stream)))(
            self.remote_scope(), self.receiver([{"type": "http.request", "more_body": False}]), self.sender(sent)
        )
        self.assertEqual([message["body"] for message in sent[1:]], [b"one", b"two", b""])
        self.assertEqual([message["more_body"] for message in sent[1:]], [True, True, False])
        self.assertTrue(stream.closed)

    async def test_upstream_response_is_closed_after_success(self):
        stream = RecordingStream([b"part"])
        await self.remote_proxy(FakeClient(httpx.Response(200, stream=stream)))(
            self.remote_scope(), self.receiver([{"type": "http.request", "more_body": False}]), self.sender([])
        )
        self.assertTrue(stream.closed)

    async def test_read_error_after_response_start_does_not_append_gateway_error(self):
        stream = RecordingStream([b"visible-part"], error=httpx.ReadError("broken upstream"))
        sent = []
        await self.remote_proxy(FakeClient(httpx.Response(200, stream=stream)))(
            self.remote_scope(), self.receiver([{"type": "http.request", "more_body": False}]), self.sender(sent)
        )
        starts = [message for message in sent if message["type"] == "http.response.start"]
        self.assertEqual(len(starts), 1)
        self.assertEqual(starts[0]["status"], 200)
        self.assertNotIn(502, [message["status"] for message in starts])
        self.assertNotIn(504, [message["status"] for message in starts])
        self.assertIn(b"visible-part", [message.get("body", b"") for message in sent])
        self.assertTrue(stream.closed)

    async def test_real_async_client_consumes_request_stream_and_returns_multi_chunk_response(self):
        transport = ConsumingTransport()
        client = httpx.AsyncClient(transport=transport)
        sent = []
        proxy = self.remote_proxy(client)
        try:
            await proxy(
                self.remote_scope(),
                self.receiver([
                    {"type": "http.request", "body": b"first-", "more_body": True},
                    {"type": "http.request", "body": b"second", "more_body": False},
                ]),
                self.sender(sent),
            )
        finally:
            await client.aclose()
        self.assertIs(proxy._client, client)
        self.assertEqual(transport.request_chunks, [[b"first-", b"second"]])
        self.assertEqual(
            [message["body"] for message in sent if message["type"] == "http.response.body"],
            [b"first-response", b"second-response", b""],
        )
        self.assertTrue(transport.response_stream.closed)
        self.assertTrue(client.is_closed)

    async def test_oserror_from_send_ends_normally_and_closes_upstream(self):
        stream = RecordingStream([b"part"])
        sent = []
        await self.remote_proxy(FakeClient(httpx.Response(200, stream=stream)))(
            self.remote_scope(), self.receiver([{"type": "http.request", "more_body": False}]),
            self.sender(sent, OSError("client socket closed")),
        )
        self.assertEqual([message["type"] for message in sent], ["http.response.start", "http.response.body"])
        self.assertTrue(stream.closed)

    async def test_response_send_cancellation_propagates_and_closes_upstream(self):
        stream = RecordingStream([b"part"])
        with self.assertRaises(asyncio.CancelledError):
            await self.remote_proxy(FakeClient(httpx.Response(200, stream=stream)))(
                self.remote_scope(), self.receiver([{"type": "http.request", "more_body": False}]),
                self.sender([], asyncio.CancelledError()),
            )
        self.assertTrue(stream.closed)

    async def test_default_timeout_has_all_four_expected_values(self):
        timeout = self.remote_proxy()._timeout
        self.assertEqual((timeout.connect, timeout.read, timeout.write, timeout.pool), (3.0, 60.0, 60.0, 5.0))

    async def test_owned_client_rejects_upstream_set_cookie(self):
        original_client = httpx.AsyncClient

        def handler(request):
            return httpx.Response(200, headers={"set-cookie": "upstream=sticky"}, content=b"ok")

        class CookieClient(original_client):
            instances = []

            def __init__(self, **kwargs):
                super().__init__(transport=httpx.MockTransport(handler), **kwargs)
                self.__class__.instances.append(self)

        sent = []
        with patch.object(proxy_module.httpx, "AsyncClient", CookieClient):
            proxy = self.remote_proxy()
            await proxy(self.remote_scope(), self.receiver([{"type": "http.request", "more_body": False}]), self.sender(sent))
            self.assertIsNone(CookieClient.instances[0].cookies.get("upstream"))
            await proxy.aclose()

    async def test_injected_client_is_never_closed_by_proxy(self):
        client = FakeClient()
        proxy = self.remote_proxy(client)
        await proxy.aclose()
        self.assertEqual(client.closed, 0)

    async def test_lifespan_creates_and_closes_owned_client_once(self):
        made = []

        class OwnedClient(FakeClient):
            def __init__(self, **kwargs):
                super().__init__()
                self.kwargs = kwargs
                made.append(self)

        async def lifespan_app(scope, receive, send):
            self.assertEqual((await receive())["type"], "lifespan.startup")
            await send({"type": "lifespan.startup.complete"})
            self.assertEqual((await receive())["type"], "lifespan.shutdown")
            await send({"type": "lifespan.shutdown.complete"})

        messages = []
        with patch.object(proxy_module.httpx, "AsyncClient", OwnedClient):
            proxy = SessionAffinityProxy(lifespan_app, decoder=lambda value: None, local_ip="10.0.0.1", target_port=8080)
            await proxy({"type": "lifespan"}, self.receiver([{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}]), self.sender(messages))
            await proxy.aclose()
        self.assertEqual(len(made), 1)
        self.assertFalse(made[0].kwargs["trust_env"])
        self.assertEqual(made[0].closed, 1)

    async def test_owned_client_is_reused_and_explicit_aclose_closes_it(self):
        made = []

        class OwnedClient(FakeClient):
            def __init__(self, **kwargs):
                super().__init__(httpx.Response(204))
                made.append(self)

        with patch.object(proxy_module.httpx, "AsyncClient", OwnedClient):
            proxy = self.remote_proxy()
            for _ in range(2):
                await proxy(self.remote_scope(), self.receiver([{"type": "http.request", "more_body": False}]), self.sender([]))
            self.assertEqual(len(made), 1)
            self.assertEqual(len(made[0].requests), 2)
            await proxy.aclose()
        self.assertEqual(made[0].closed, 1)


if __name__ == "__main__":
    unittest.main()
