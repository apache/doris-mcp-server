"""ASGI middleware to log all incoming HTTP requests (method, path, headers, body)."""

import json
import logging
import time

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from core.sensitive_mask import mask_dict, mask_sensitive

logger = logging.getLogger("doris_new_mcp.request_logger")
logger.setLevel(logging.DEBUG)

# Ensure at least one handler exists
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[%(asctime)s] %(message)s"))
    logger.addHandler(handler)


class RequestLoggerMiddleware:
    """Log method, path, headers, and body for every HTTP request."""

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "?")
        path = scope.get("path", "?")
        query = scope.get("query_string", b"").decode("utf-8", errors="replace")
        headers = {
            k.decode(): v.decode()
            for k, v in scope.get("headers", [])
        }

        # Collect request body
        body_chunks: list[bytes] = []
        body_complete = False

        async def receive_wrapper() -> Message:
            nonlocal body_complete
            message = await receive()
            if message["type"] == "http.request":
                body_chunks.append(message.get("body", b""))
                if not message.get("more_body", False):
                    body_complete = True
            return message

        # Log response status
        status_code = 0
        start_time = time.time()

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message.get("status", 0)
            await send(message)

        # Log request line (headers masked — they carry Authorization/Cookie)
        url = path + (f"?{query}" if query else "")
        logger.info("=" * 72)
        logger.info(f">>> {method} {url}")
        logger.info(f"    Headers: {json.dumps(mask_dict(headers), ensure_ascii=False, indent=None)}")

        await self.app(scope, receive_wrapper, send_wrapper)

        # Log body (after it has been consumed; masked — e.g. the WebUI
        # login form posts the Doris password in plaintext)
        raw_body = b"".join(body_chunks)
        if raw_body:
            try:
                body_text = raw_body.decode("utf-8")
                # Try to pretty-print JSON
                try:
                    body_json = json.loads(body_text)
                    logger.info(f"    Body: {mask_sensitive(json.dumps(body_json, ensure_ascii=False))}")
                except json.JSONDecodeError:
                    logger.info(f"    Body: {mask_sensitive(body_text[:2000])}")
            except UnicodeDecodeError:
                logger.info(f"    Body: <binary {len(raw_body)} bytes>")
        else:
            logger.info("    Body: <empty>")

        elapsed = (time.time() - start_time) * 1000
        logger.info(f"<<< {status_code} ({elapsed:.0f}ms)")
