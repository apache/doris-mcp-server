from __future__ import annotations

import asyncio
from typing import Any

import httpx
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport


def _httpx_async_factory(**kwargs) -> httpx.AsyncClient:
    from client.http_client import _use_system_proxy
    kwargs["trust_env"] = _use_system_proxy()
    return httpx.AsyncClient(**kwargs)


async def _run_with_client(server_url: str, token: str, coro_factory):
    transport = StreamableHttpTransport(
        f"{server_url}/mcp",
        headers={"Authorization": f"Bearer {token}"},
        httpx_client_factory=_httpx_async_factory,
    )
    async with Client(transport) as client:
        return await coro_factory(client)


def _run(server_url: str, token: str, op: str, coro_factory):
    try:
        return asyncio.run(_run_with_client(server_url, token, coro_factory))
    except httpx.InvalidURL as e:
        raise RuntimeError(f"Invalid URL '{server_url}': {e}") from None
    except httpx.UnsupportedProtocol:
        raise RuntimeError(
            f"Invalid URL '{server_url}': missing 'http://' or 'https://' scheme."
        ) from None
    except httpx.ConnectError:
        raise RuntimeError(
            f"Cannot connect to {server_url} ({op}). "
            "Check that the server is running and reachable."
        ) from None
    except httpx.TimeoutException:
        raise RuntimeError(f"Connection to {server_url} timed out during {op}.") from None
    except httpx.HTTPStatusError as e:
        code = e.response.status_code
        if code == 401:
            raise RuntimeError(
                f"Authentication failed (HTTP 401) during {op}. "
                "Credentials may be expired or rejected by the server."
            ) from None
        if code == 403:
            raise RuntimeError(
                f"Permission denied (HTTP 403) during {op}. "
                "Your token is valid but lacks permission for this operation."
            ) from None
        raise RuntimeError(
            f"Server error during {op}: HTTP {code}"
        ) from None
    except RuntimeError:
        raise
    except Exception as e:
        import os
        if os.environ.get("DORIS_MCP_DEBUG", "").strip().lower() in ("1", "true", "yes", "on"):
            raise RuntimeError(f"{op} failed: {type(e).__name__}: {e}") from None
        raise RuntimeError(f"{op} failed: {e}") from None


def validate_token(server_url: str, token: str) -> None:
    async def _check(client: Client):
        await client.list_tools()
    _run(server_url, token, "token validation", _check)


def tool_list(server_url: str, token: str) -> list[dict[str, Any]]:
    async def _tl(client: Client):
        tools = await client.list_tools()
        return [
            {"name": t.name, "description": t.description or ""}
            for t in tools
        ]
    return _run(server_url, token, "tool list", _tl)


def tool_describe(server_url: str, token: str, name: str) -> dict[str, Any]:
    async def _td(client: Client):
        tools = await client.list_tools()
        for t in tools:
            if t.name == name:
                return {
                    "name": t.name,
                    "description": t.description or "",
                    "inputSchema": t.inputSchema if hasattr(t, "inputSchema") else {},
                }
        raise ValueError(f"Tool '{name}' not found")
    return _run(server_url, token, "tool describe", _td)


def tool_call(
    server_url: str,
    token: str,
    name: str,
    arguments: dict[str, Any],
) -> Any:
    async def _tc(client: Client):
        return await client.call_tool(name, arguments)
    return _run(server_url, token, f"tool call '{name}'", _tc)
