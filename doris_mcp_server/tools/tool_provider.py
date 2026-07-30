# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""Explicit, deploy-time extension boundary for trusted custom MCP tools."""

from __future__ import annotations

import asyncio
import inspect
import logging
import re
import time
from collections.abc import Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass
from importlib import metadata
from typing import Any, Literal, Protocol

from mcp.types import Tool

CUSTOM_TOOL_PROVIDER_ENTRY_POINT = "doris_mcp_server.tool_providers"
MAX_PROVIDER_NAME_LENGTH = 128
MAX_RATE_LIMIT_KEYS = 10_000
_PROVIDER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
logger = logging.getLogger(__name__)

ToolHandler = Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]
ToolRisk = Literal["low", "medium", "high"]
RateLimitScope = Literal["tool", "principal"]


class ToolProviderError(ValueError):
    """Raised when an explicitly configured tool provider is invalid."""


@dataclass(frozen=True)
class ToolRateLimit:
    """Process-local fixed-window limit for one custom tool."""

    max_calls: int
    period_seconds: float
    scope: RateLimitScope = "principal"

    def __post_init__(self) -> None:
        if isinstance(self.max_calls, bool) or not 1 <= self.max_calls <= 1_000_000:
            raise ToolProviderError(
                "Custom tool rate limit max_calls must be in the range 1-1000000"
            )
        if (
            isinstance(self.period_seconds, bool)
            or not 0.1 <= self.period_seconds <= 3600
        ):
            raise ToolProviderError(
                "Custom tool rate limit period_seconds must be in the range 0.1-3600"
            )
        if self.scope not in {"tool", "principal"}:
            raise ToolProviderError(
                "Custom tool rate limit scope must be tool or principal"
            )


@dataclass(frozen=True)
class CustomTool:
    """One schema, handler, and bounded runtime policy supplied by a provider."""

    tool: Tool
    handler: ToolHandler
    risk: ToolRisk = "high"
    rate_limit: ToolRateLimit | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.tool, Tool):
            raise ToolProviderError("Custom tool schema must be an MCP Tool")
        if not callable(self.handler):
            raise ToolProviderError(
                f"Custom tool {self.tool.name!r} handler must be callable"
            )
        if self.risk not in {"low", "medium", "high"}:
            raise ToolProviderError(
                f"Custom tool {self.tool.name!r} risk must be low, medium, or high"
            )


class CustomToolProvider(Protocol):
    """Provider contract returned by an installed Python entry point."""

    name: str

    def tools(self) -> Iterable[CustomTool]:
        """Return immutable tool definitions without performing network I/O."""


@dataclass(frozen=True)
class LoadedToolProvider:
    """Validated provider and its materialized custom tool definitions."""

    name: str
    provider: CustomToolProvider
    tools: tuple[CustomTool, ...]


def normalize_tool_provider_names(raw_names: Iterable[str]) -> tuple[str, ...]:
    """Validate and deduplicate an explicit provider allowlist."""
    normalized: list[str] = []
    seen: set[str] = set()
    for raw_name in raw_names:
        if not isinstance(raw_name, str):
            raise ToolProviderError("Custom tool provider names must be strings")
        name = raw_name.strip()
        if not _PROVIDER_NAME.fullmatch(name):
            raise ToolProviderError(
                "Custom tool provider names must contain only letters, digits, "
                "dot, underscore, or hyphen and be at most "
                f"{MAX_PROVIDER_NAME_LENGTH} characters"
            )
        if name in seen:
            raise ToolProviderError(
                f"Duplicate custom tool provider in allowlist: {name}"
            )
        normalized.append(name)
        seen.add(name)
    return tuple(normalized)


def prepare_tool_provider(
    provider: CustomToolProvider,
    *,
    expected_name: str | None = None,
) -> LoadedToolProvider:
    """Validate one trusted provider before it reaches the tool registry."""
    provider_name = getattr(provider, "name", None)
    if not isinstance(provider_name, str):
        raise ToolProviderError("Custom tool provider must define a string name")
    name = normalize_tool_provider_names([provider_name])[0]
    if expected_name is not None and name != expected_name:
        raise ToolProviderError(
            f"Custom tool provider {expected_name!r} returned mismatched name {name!r}"
        )

    tools_factory = getattr(provider, "tools", None)
    if not callable(tools_factory):
        raise ToolProviderError(
            f"Custom tool provider {name!r} must define a tools() method"
        )
    try:
        tools = tuple(tools_factory())
    except Exception as exc:
        raise ToolProviderError(
            f"Custom tool provider {name!r} failed to define tools"
        ) from exc
    if not tools:
        raise ToolProviderError(
            f"Custom tool provider {name!r} must define at least one tool"
        )
    for tool in tools:
        if not isinstance(tool, CustomTool):
            raise ToolProviderError(
                f"Custom tool provider {name!r} returned an invalid tool definition"
            )
    return LoadedToolProvider(name=name, provider=provider, tools=tools)


def load_tool_providers(
    provider_names: Sequence[str],
) -> tuple[LoadedToolProvider, ...]:
    """Load only explicitly enabled installed entry points."""
    names = normalize_tool_provider_names(provider_names)
    if not names:
        return ()

    installed: dict[str, metadata.EntryPoint] = {}
    for entry_point in metadata.entry_points(
        group=CUSTOM_TOOL_PROVIDER_ENTRY_POINT
    ):
        if entry_point.name in installed:
            raise ToolProviderError(
                f"Duplicate installed custom tool provider: {entry_point.name}"
            )
        installed[entry_point.name] = entry_point

    loaded: list[LoadedToolProvider] = []
    for name in names:
        selected_entry_point = installed.get(name)
        if selected_entry_point is None:
            raise ToolProviderError(
                f"Configured custom tool provider is not installed: {name}"
            )
        try:
            factory = selected_entry_point.load()
            if not callable(factory):
                raise TypeError("entry point target is not callable")
            provider = factory()
        except Exception as exc:
            raise ToolProviderError(
                f"Unable to load custom tool provider: {name}"
            ) from exc
        loaded.append(prepare_tool_provider(provider, expected_name=name))
    return tuple(loaded)


async def call_provider_lifecycle_hook(
    loaded_provider: LoadedToolProvider,
    hook_name: Literal["start", "close"],
) -> None:
    """Call one optional synchronous or asynchronous provider lifecycle hook."""
    hook = getattr(loaded_provider.provider, hook_name, None)
    if hook is None:
        return
    if not callable(hook):
        raise ToolProviderError(
            f"Custom tool provider {loaded_provider.name!r} "
            f"{hook_name} attribute must be callable"
        )
    result = hook()
    if inspect.isawaitable(result):
        await result


@dataclass
class _RateWindow:
    calls: int
    expires_at: float


class LocalToolRateLimiter:
    """Bounded process-local fixed-window limiter for custom tools."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_keys: int = MAX_RATE_LIMIT_KEYS,
    ) -> None:
        self._clock = clock
        self._max_keys = max_keys
        self._windows: dict[tuple[str, str], _RateWindow] = {}
        self._lock = asyncio.Lock()

    async def retry_after(
        self,
        *,
        tool_name: str,
        principal: str,
        limit: ToolRateLimit,
    ) -> float | None:
        """Record an allowed call or return the retry delay for a rejected one."""
        key_principal = principal if limit.scope == "principal" else "*"
        key = (tool_name, key_principal)
        now = self._clock()

        async with self._lock:
            window = self._windows.get(key)
            if window is not None and window.expires_at <= now:
                self._windows.pop(key, None)
                window = None

            if window is None:
                if len(self._windows) >= self._max_keys:
                    self._discard_expired_keys(now)
                if len(self._windows) >= self._max_keys:
                    return limit.period_seconds
                self._windows[key] = _RateWindow(
                    calls=1,
                    expires_at=now + limit.period_seconds,
                )
                return None

            if window.calls >= limit.max_calls:
                return max(0.0, window.expires_at - now)
            window.calls += 1
            return None

    def _discard_expired_keys(self, now: float) -> None:
        empty_keys = [
            key
            for key, window in self._windows.items()
            if window.expires_at <= now
        ]
        for key in empty_keys:
            self._windows.pop(key, None)


class ToolProviderRuntime:
    """Own provider discovery, lifecycle, and process-local rate-limit state."""

    def __init__(self, providers: Sequence[LoadedToolProvider]) -> None:
        self.providers = tuple(providers)
        self._started: list[LoadedToolProvider] = []
        self._rate_limiter = LocalToolRateLimiter()

    @classmethod
    def create(
        cls,
        config: Any,
        providers: Iterable[CustomToolProvider] | None,
    ) -> ToolProviderRuntime:
        """Build a runtime from configuration or explicitly injected providers."""
        if providers is None:
            configured_names = getattr(config, "mcp_tool_providers", ())
            if not isinstance(configured_names, list | tuple):
                configured_names = ()
            loaded = load_tool_providers(configured_names)
        else:
            loaded = tuple(prepare_tool_provider(provider) for provider in providers)
        return cls(loaded)

    @property
    def provider_count(self) -> int:
        return len(self.providers)

    def custom_tools(self) -> Iterable[tuple[str, CustomTool]]:
        for loaded_provider in self.providers:
            for custom_tool in loaded_provider.tools:
                yield loaded_provider.name, custom_tool

    async def start(self) -> None:
        """Start providers in order and roll back completed starts on failure."""
        try:
            for loaded_provider in self.providers:
                await call_provider_lifecycle_hook(loaded_provider, "start")
                self._started.append(loaded_provider)
        except Exception:
            await self.close()
            raise

    async def close(self) -> None:
        """Close every started provider in reverse order."""
        for loaded_provider in reversed(self._started):
            try:
                await call_provider_lifecycle_hook(loaded_provider, "close")
            except Exception as exc:
                logger.error(
                    "Custom tool provider shutdown failed (%s)",
                    type(exc).__name__,
                )
        self._started.clear()

    async def retry_after(
        self,
        *,
        tool_name: str,
        auth_context: Any | None,
        limit: ToolRateLimit,
    ) -> float | None:
        """Apply one tool limit without retaining bearer credentials."""
        principal = "anonymous"
        if auth_context is not None:
            principal = (
                getattr(auth_context, "user_id", None)
                or getattr(auth_context, "token_id", None)
                or getattr(auth_context, "oauth_client_id", None)
                or getattr(auth_context, "auth_method", None)
                or principal
            )
        return await self._rate_limiter.retry_after(
            tool_name=tool_name,
            principal=principal,
            limit=limit,
        )
