"""ASGI middleware to fix SSE response charset.

sse-starlette sends Content-Type: text/event-stream without charset=utf-8.
HTTP clients (like Python requests) default to ISO-8859-1 when charset is missing,
causing Chinese/non-ASCII text to be garbled.

This middleware adds charset=utf-8 to all text/event-stream responses.
"""

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Receive, Scope, Send


class CharsetMiddleware:
    """Add charset=utf-8 to text/event-stream responses."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            async def send_with_charset(message: dict) -> None:
                if message["type"] == "http.response.start":
                    headers = MutableHeaders(scope=message)
                    ct = headers.get("content-type", "")
                    if "text/event-stream" in ct and "charset" not in ct:
                        headers["content-type"] = "text/event-stream; charset=utf-8"
                await send(message)
            await self.app(scope, receive, send_with_charset)
        else:
            await self.app(scope, receive, send)
