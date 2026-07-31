"""ASGI session-affinity reverse proxy for the Web UI routes."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from http.cookiejar import CookieJar, DefaultCookiePolicy
from typing import Any, TypeAlias

import httpx

ASGIApp: TypeAlias = Callable[[dict[str, Any], Callable[[], Awaitable[dict[str, Any]]], Callable[[dict[str, Any]], Awaitable[None]]], Awaitable[None]]
SessionDecoder: TypeAlias = Callable[[str], tuple[str, str] | None]

logger = logging.getLogger(__name__)

_INTERNAL_HOP_HEADER = b"x-doris-session-affinity-hop"
_HOP_BY_HOP_HEADERS = {
    b"connection",
    b"keep-alive",
    b"proxy-authenticate",
    b"proxy-authorization",
    b"proxy-connection",
    b"te",
    b"trailer",
    b"transfer-encoding",
    b"upgrade",
}


class _ClientDisconnected(Exception):
    """The downstream ASGI server reported that its client went away."""


class _RejectSetCookiePolicy(DefaultCookiePolicy):
    """Keep a shared proxy client from learning state from any upstream."""

    def set_ok(self, cookie: Any, request: Any) -> bool:
        return False


_DEFAULT_TIMEOUT = httpx.Timeout(connect=3.0, read=60.0, write=60.0, pool=5.0)


def _connection_tokens(headers: list[tuple[bytes, bytes]]) -> set[bytes]:
    """Return lower-case header names nominated by Connection headers."""
    tokens: set[bytes] = set()
    for name, value in headers:
        if name.lower() == b"connection":
            tokens.update(token.strip().lower() for token in value.split(b",") if token.strip())
    return tokens


def _forward_headers(headers: list[tuple[bytes, bytes]], *, add_hop: bool = False) -> list[tuple[bytes, bytes]]:
    """Drop routing and hop-by-hop fields without flattening duplicate headers."""
    connection_headers = _connection_tokens(headers)
    excluded = _HOP_BY_HOP_HEADERS | connection_headers | {b"host", _INTERNAL_HOP_HEADER}
    result = [(name.lower(), value) for name, value in headers if name.lower() not in excluded]
    if add_hop:
        result.append((_INTERNAL_HOP_HEADER, b"1"))
    return result


def _without_internal_header(scope: dict[str, Any]) -> dict[str, Any]:
    """Do not expose the proxy control header to the local application."""
    headers = scope.get("headers", [])
    if not any(name.lower() == _INTERNAL_HOP_HEADER for name, _ in headers):
        return scope
    local_scope = dict(scope)
    local_scope["headers"] = [
        (name, value) for name, value in headers if name.lower() != _INTERNAL_HOP_HEADER
    ]
    return local_scope


def _cookie_value(headers: list[tuple[bytes, bytes]], cookie_name: str) -> str | None:
    """Read one named cookie, rejecting requests which provide it more than once."""
    wanted = cookie_name.encode("ascii")
    value: str | None = None
    for header_name, header_value in headers:
        if header_name.lower() != b"cookie":
            continue
        for item in header_value.split(b";"):
            name, separator, candidate = item.strip().partition(b"=")
            if separator and name == wanted:
                if value is not None:
                    return None
                value = candidate.decode("latin-1")
    return value


class SessionAffinityProxy:
    """Route a decoded Web UI session to the process which owns it.

    ``decoder`` is deliberately the only cookie-format dependency: a successful
    decoder result is trusted by this middleware.  ``target_port`` is local
    configuration, never data taken from the cookie.

    When ``force_target_ip`` is set and differs from ``local_ip``, **every**
    ``/mcp/web`` request (login included) is unconditionally forwarded to that
    node — cookie-based affinity is bypassed.  The node whose ``local_ip``
    equals ``force_target_ip`` handles requests locally (with normal
    cookie-affinity rules), so all Web UI sessions live on that one node.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        decoder: SessionDecoder,
        local_ip: str,
        target_port: int,
        cookie_name: str = "doris_mcp_session",
        client: httpx.AsyncClient | None = None,
        timeout: httpx.TimeoutTypes | None = None,
        force_target_ip: str | None = None,
    ) -> None:
        self.app = app
        self.decoder = decoder
        self.local_ip = local_ip
        self.target_port = target_port
        self.force_target_ip = force_target_ip
        self.cookie_name = cookie_name
        self._client = client
        self._owns_client = client is None
        self._timeout = _DEFAULT_TIMEOUT if timeout is None else timeout
        self._client_lock = asyncio.Lock()

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        scope_type = scope["type"]
        if scope_type == "lifespan":
            await self._run_lifespan(scope, receive, send)
            return
        if scope_type != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        # Only Web UI routes are affected; /mcp and everything else passes through.
        if path != "/mcp/web" and not path.startswith("/mcp/web/"):
            await self.app(scope, receive, send)
            return

        headers = scope.get("headers", [])

        # privateIp configured: every Web UI request (login included) goes
        # to the configured node, so sessions exist on exactly one machine.
        if self.force_target_ip is not None and self.force_target_ip != self.local_ip:
            if any(name.lower() == _INTERNAL_HOP_HEADER for name, _ in headers):
                await self._send_error(send, 502, b"Bad Gateway")
                return
            await self._proxy(scope, receive, send, self.force_target_ip)
            return

        # Login must stay local even if a stale cookie identifies another node.
        if path == "/mcp/web/login":
            await self.app(_without_internal_header(scope), receive, send)
            return

        cookie = _cookie_value(headers, self.cookie_name)
        try:
            decoded = self.decoder(cookie) if cookie is not None else None
        except Exception:  # A decoder rejection is treated exactly as an invalid cookie.
            logger.warning("Session-affinity cookie decoder rejected a cookie")
            decoded = None
        if decoded is None or decoded[1] == self.local_ip:
            await self.app(_without_internal_header(scope), receive, send)
            return

        if any(name.lower() == _INTERNAL_HOP_HEADER for name, _ in headers):
            await self._send_error(send, 502, b"Bad Gateway")
            return
        await self._proxy(scope, receive, send, decoded[1])

    async def _run_lifespan(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        # The server drives the lifespan coroutine through startup and shutdown;
        # retaining the client for that whole call gives one client per process.
        await self._get_client()
        try:
            await self.app(scope, receive, send)
        finally:
            await self.aclose()

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is not None:
            return self._client
        async with self._client_lock:
            if self._client is None:
                self._client = httpx.AsyncClient(
                    follow_redirects=False,
                    timeout=self._timeout,
                    cookies=CookieJar(policy=_RejectSetCookiePolicy()),
                    trust_env=False,
                )
        return self._client

    async def aclose(self) -> None:
        """Close the internally-created shared client, if this proxy owns it."""
        if not self._owns_client:
            return
        async with self._client_lock:
            client, self._client = self._client, None
        if client is not None:
            await client.aclose()

    async def _proxy(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
        target_ip: str,
    ) -> None:
        response: httpx.Response | None = None
        response_started = False
        response_start_attempted = False
        try:
            raw_path = scope.get("raw_path") or scope["path"].encode("utf-8")
            raw_query = scope.get("query_string", b"")
            # ASGI raw path/query are normally ASCII with non-ASCII octets
            # percent-encoded.  Constructing from that representation avoids
            # decoding and re-encoding escaped slash/query bytes.
            suffix = raw_path.decode("ascii")
            if raw_query:
                suffix += "?" + raw_query.decode("ascii")
            url = httpx.URL(f"http://{target_ip}:{self.target_port}{suffix}")
            client = await self._get_client()
            request = client.build_request(
                scope["method"],
                url,
                headers=_forward_headers(scope.get("headers", []), add_hop=True),
                content=self._request_body(receive),
            )
            response = await client.send(request, stream=True)
            response_start_attempted = True
            await self._send_downstream(send, {
                "type": "http.response.start",
                "status": response.status_code,
                "headers": _forward_headers(list(response.headers.raw)),
            })
            response_started = True
            await self._stream_response(response, send)
        except _ClientDisconnected:
            return
        except asyncio.CancelledError:
            raise
        except httpx.TimeoutException:
            logger.warning("Session-affinity upstream timed out")
            if not response_started and not response_start_attempted:
                await self._send_relogin(send)
        except (httpx.HTTPError, UnicodeError, ValueError):
            logger.warning("Session-affinity upstream request failed")
            if not response_started and not response_start_attempted:
                await self._send_relogin(send)
        finally:
            if response is not None:
                try:
                    await response.aclose()
                except asyncio.CancelledError:
                    raise
                except httpx.HTTPError:
                    logger.warning("Session-affinity upstream response close failed")

    async def _request_body(
        self, receive: Callable[[], Awaitable[dict[str, Any]]]
    ) -> AsyncIterator[bytes]:
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                raise _ClientDisconnected
            if message["type"] != "http.request":
                continue
            body = message.get("body", b"")
            if body:
                yield body
            if not message.get("more_body", False):
                return

    async def _stream_response(
        self,
        response: httpx.Response,
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        # During the response phase do not read ASGI receive: a second reader
        # races the server's request-body consumer.  Send failures and task
        # cancellation terminate the upstream stream instead.
        if response.is_stream_consumed:
            await self._send_downstream(send, {"type": "http.response.body", "body": response.content, "more_body": False})
            return
        async for chunk in response.aiter_raw():
            await self._send_downstream(send, {"type": "http.response.body", "body": chunk, "more_body": True})
        await self._send_downstream(send, {"type": "http.response.body", "body": b"", "more_body": False})

    @staticmethod
    async def _send_downstream(
        send: Callable[[dict[str, Any]], Awaitable[None]], message: dict[str, Any]
    ) -> None:
        """Translate downstream socket disconnects at the ASGI send boundary."""
        try:
            await send(message)
        except OSError as exc:
            raise _ClientDisconnected from exc

    @staticmethod
    async def _send_error(
        send: Callable[[dict[str, Any]], Awaitable[None]], status: int, body: bytes
    ) -> None:
        try:
            await SessionAffinityProxy._send_downstream(send, {
                "type": "http.response.start",
                "status": status,
                "headers": [(b"content-type", b"text/plain; charset=utf-8"), (b"content-length", str(len(body)).encode())],
            })
            await SessionAffinityProxy._send_downstream(
                send, {"type": "http.response.body", "body": body, "more_body": False}
            )
        except _ClientDisconnected:
            return

    async def _send_relogin(
        self, send: Callable[[dict[str, Any]], Awaitable[None]]
    ) -> None:
        """Clear the session cookie and redirect the browser to the login page.

        Login is always handled locally, so the redirect is safe regardless
        of which node receives it.
        """
        try:
            await self._send_downstream(send, {
                "type": "http.response.start",
                "status": 303,
                "headers": [
                    (b"location", b"/mcp/web/login"),
                    (b"set-cookie", self.cookie_name.encode("ascii") + b"=; Max-Age=0; Path=/mcp/web; HttpOnly; SameSite=Lax"),
                    (b"content-type", b"text/plain; charset=utf-8"),
                    (b"content-length", b"0"),
                ],
            })
            await self._send_downstream(
                send, {"type": "http.response.body", "body": b"", "more_body": False}
            )
        except _ClientDisconnected:
            return


# Explicit alias for integrations that name ASGI wrappers as middleware.
SessionAffinityProxyMiddleware = SessionAffinityProxy
