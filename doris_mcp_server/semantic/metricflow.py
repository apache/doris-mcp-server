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
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Bounded MetricFlow consumer protocol for the Doris Semantic domain."""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol, cast

from ..utils.query_runtime import DorisQueryRuntime, ReadOnlySQLGuard
from .models import SEMANTIC_MODEL_REF_PATTERN
from .runtime import SemanticRuntimeFailure

METRICFLOW_PROVIDER_PROTOCOL = "doris-mcp-metricflow/v1"
_MODEL_REF_RE = re.compile(SEMANTIC_MODEL_REF_PATTERN)
_PROVIDER_OPERATIONS = frozenset(
    {
        "list_models",
        "get_status",
        "list_metrics",
        "get_group_bys",
        "list_saved_queries",
        "compile_dimension_values",
        "compile_query",
    }
)
_SIDECAR_ENVIRONMENT: Mapping[str, str] = MappingProxyType(
    {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONUNBUFFERED": "1",
    }
)


def _bool_config(section: Any, name: str, default: bool) -> bool:
    value = getattr(section, name, default)
    return value if isinstance(value, bool) else default


def _int_config(section: Any, name: str, default: int) -> int:
    value = getattr(section, name, default)
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return default


def _str_config(section: Any, name: str, default: str = "") -> str:
    value = getattr(section, name, default)
    return value if isinstance(value, str) else default


def _command_config(section: Any) -> tuple[str, ...]:
    value = getattr(section, "metricflow_provider_command", ())
    if not isinstance(value, list | tuple) or any(
        not isinstance(part, str) for part in value
    ):
        return ()
    return tuple(value)


class MetricFlowProvider(Protocol):
    """Compile and inspect MetricFlow models without executing Doris SQL."""

    async def request(
        self,
        operation: str,
        arguments: Mapping[str, Any],
    ) -> Mapping[str, Any]: ...


class MetricFlowProviderFailure(RuntimeError):
    """Stable internal provider failure before MCP error normalization."""

    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class MetricFlowSidecarProvider:
    """Invoke one administrator-configured JSON sidecar without a shell."""

    def __init__(
        self,
        command: Sequence[str],
        *,
        project_directory: str = "",
        timeout_seconds: int = 30,
        max_output_bytes: int = 2 * 1024 * 1024,
    ) -> None:
        normalized = tuple(str(part).strip() for part in command)
        if not normalized or any(not part for part in normalized):
            raise MetricFlowProviderFailure(
                "METRICFLOW_PROVIDER_NOT_CONFIGURED",
                "MetricFlow provider command is not configured.",
            )
        if not Path(normalized[0]).is_absolute():
            raise MetricFlowProviderFailure(
                "METRICFLOW_PROVIDER_COMMAND_INVALID",
                "MetricFlow provider executable must use an absolute path.",
            )
        self._command = normalized
        self._project_directory = project_directory or None
        self._timeout_seconds = timeout_seconds
        self._max_output_bytes = max_output_bytes

    async def request(
        self,
        operation: str,
        arguments: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        if operation not in _PROVIDER_OPERATIONS:
            raise MetricFlowProviderFailure(
                "METRICFLOW_OPERATION_UNSUPPORTED",
                "MetricFlow provider operation is unsupported.",
            )
        request_id = str(uuid.uuid4())
        payload = json.dumps(
            {
                "protocol_version": METRICFLOW_PROVIDER_PROTOCOL,
                "request_id": request_id,
                "operation": operation,
                "arguments": dict(arguments),
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        try:
            process = await asyncio.create_subprocess_exec(
                *self._command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self._project_directory,
                env=dict(_SIDECAR_ENVIRONMENT),
            )
        except (OSError, ValueError) as exc:
            raise MetricFlowProviderFailure(
                "METRICFLOW_PROVIDER_START_FAILED",
                "MetricFlow provider could not be started.",
            ) from exc
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(payload),
                timeout=self._timeout_seconds,
            )
        except TimeoutError as exc:
            process.kill()
            await process.wait()
            raise MetricFlowProviderFailure(
                "METRICFLOW_PROVIDER_TIMEOUT",
                "MetricFlow provider timed out.",
            ) from exc

        if len(stdout) > self._max_output_bytes or len(stderr) > 64 * 1024:
            raise MetricFlowProviderFailure(
                "METRICFLOW_PROVIDER_OUTPUT_LIMIT_EXCEEDED",
                "MetricFlow provider output exceeded its configured limit.",
            )
        if process.returncode != 0:
            raise MetricFlowProviderFailure(
                "METRICFLOW_PROVIDER_FAILED",
                "MetricFlow provider returned a failed status.",
            )
        try:
            response = json.loads(stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MetricFlowProviderFailure(
                "METRICFLOW_PROVIDER_RESPONSE_INVALID",
                "MetricFlow provider returned an invalid response.",
            ) from exc
        if not isinstance(response, Mapping):
            raise MetricFlowProviderFailure(
                "METRICFLOW_PROVIDER_RESPONSE_INVALID",
                "MetricFlow provider returned an invalid response.",
            )
        if (
            response.get("protocol_version") != METRICFLOW_PROVIDER_PROTOCOL
            or response.get("request_id") != request_id
        ):
            raise MetricFlowProviderFailure(
                "METRICFLOW_PROVIDER_PROTOCOL_MISMATCH",
                "MetricFlow provider protocol validation failed.",
            )
        if response.get("ok") is not True:
            error = response.get("error")
            reason_code = "METRICFLOW_PROVIDER_REQUEST_FAILED"
            if isinstance(error, Mapping):
                candidate = error.get("reason_code")
                if isinstance(candidate, str) and re.fullmatch(
                    r"[A-Z][A-Z0-9_]{0,127}", candidate
                ):
                    reason_code = candidate
            raise MetricFlowProviderFailure(
                reason_code,
                "MetricFlow provider rejected the request.",
            )
        data = response.get("data")
        if not isinstance(data, Mapping):
            raise MetricFlowProviderFailure(
                "METRICFLOW_PROVIDER_RESPONSE_INVALID",
                "MetricFlow provider response data must be an object.",
            )
        return cast(Mapping[str, Any], data)


class MetricFlowSemanticRuntime:
    """Expose MetricFlow metadata and compile-only operations to MCP."""

    def __init__(
        self,
        query_runtime: DorisQueryRuntime,
        *,
        enabled: bool,
        provider: MetricFlowProvider | None,
    ) -> None:
        self._query_runtime = query_runtime
        self._enabled = enabled
        self._provider = provider

    @classmethod
    def from_config(
        cls,
        query_runtime: DorisQueryRuntime,
        semantic_config: Any | None,
    ) -> MetricFlowSemanticRuntime:
        enabled = _bool_config(
            semantic_config,
            "metricflow_enabled",
            False,
        )
        provider: MetricFlowProvider | None = None
        if enabled:
            provider = MetricFlowSidecarProvider(
                _command_config(semantic_config),
                project_directory=_str_config(
                    semantic_config,
                    "metricflow_project_directory",
                ),
                timeout_seconds=_int_config(
                    semantic_config,
                    "metricflow_timeout_seconds",
                    30,
                ),
                max_output_bytes=_int_config(
                    semantic_config,
                    "metricflow_max_output_bytes",
                    2 * 1024 * 1024,
                ),
            )
        return cls(query_runtime, enabled=enabled, provider=provider)

    async def list_models(self) -> dict[str, Any]:
        data = await self._request("list_models", {})
        return _collection_result(data, "metricflow_model_registry")

    async def get_status(self, *, model_ref: str) -> dict[str, Any]:
        normalized_ref = _model_ref(model_ref)
        data = await self._request(
            "get_status",
            {"model_ref": normalized_ref},
        )
        return _detail_result(data, "metricflow_provider_status")

    async def list_metrics(
        self,
        *,
        model_ref: str,
        search: str | None,
        include_dimensions: bool,
        limit: int | None,
    ) -> dict[str, Any]:
        data = await self._request(
            "list_metrics",
            {
                "model_ref": _model_ref(model_ref),
                "search": search,
                "include_dimensions": include_dimensions,
                "limit": limit,
            },
        )
        return _collection_result(data, "metricflow_metric_registry")

    async def get_group_bys(
        self,
        *,
        model_ref: str,
        metrics: Sequence[str],
    ) -> dict[str, Any]:
        data = await self._request(
            "get_group_bys",
            {
                "model_ref": _model_ref(model_ref),
                "metrics": list(metrics),
            },
        )
        return _detail_result(data, "metricflow_group_by_registry")

    async def list_saved_queries(
        self,
        *,
        model_ref: str,
        search: str | None,
        limit: int | None,
    ) -> dict[str, Any]:
        data = await self._request(
            "list_saved_queries",
            {
                "model_ref": _model_ref(model_ref),
                "search": search,
                "limit": limit,
            },
        )
        return _collection_result(data, "metricflow_saved_query_registry")

    async def get_dimension_values(
        self,
        *,
        model_ref: str,
        metrics: Sequence[str],
        dimension: str,
        start_time: str | None,
        end_time: str | None,
        limit: int | None,
        timeout_ms: int | None,
    ) -> dict[str, Any]:
        compiled = await self._request(
            "compile_dimension_values",
            {
                "model_ref": _model_ref(model_ref),
                "metrics": list(metrics),
                "dimension": dimension,
                "start_time": start_time,
                "end_time": end_time,
                "limit": limit,
            },
        )
        return await self._execute_compiled(
            compiled,
            model_ref=model_ref,
            max_rows=limit,
            timeout_ms=timeout_ms,
        )

    async def compile_query(
        self,
        *,
        model_ref: str,
        request: Mapping[str, Any],
    ) -> dict[str, Any]:
        compiled = await self._compile(model_ref=model_ref, request=request)
        return _detail_result(compiled, "metricflow_doris_compile")

    async def execute_query(
        self,
        *,
        model_ref: str,
        request: Mapping[str, Any],
        max_rows: int | None,
        timeout_ms: int | None,
    ) -> dict[str, Any]:
        compiled = await self._compile(model_ref=model_ref, request=request)
        return await self._execute_compiled(
            compiled,
            model_ref=model_ref,
            max_rows=max_rows,
            timeout_ms=timeout_ms,
        )

    async def _compile(
        self,
        *,
        model_ref: str,
        request: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        return await self._request(
            "compile_query",
            {
                "model_ref": _model_ref(model_ref),
                "request": dict(request),
                "dialect": "doris",
            },
        )

    async def _execute_compiled(
        self,
        compiled: Mapping[str, Any],
        *,
        model_ref: str,
        max_rows: int | None,
        timeout_ms: int | None,
    ) -> dict[str, Any]:
        sql = compiled.get("sql")
        if not isinstance(sql, str) or not sql.strip():
            raise SemanticRuntimeFailure(
                "METRICFLOW_COMPILED_SQL_INVALID",
                "MetricFlow provider did not return executable SQL.",
                status_code=502,
            )
        statement = ReadOnlySQLGuard.validate(sql)
        result = await self._query_runtime.execute_query(
            sql=statement.sql,
            max_rows=max_rows,
            timeout_ms=timeout_ms,
        )
        metadata = result.get("metadata")
        if isinstance(metadata, dict):
            metadata.update(
                {
                    "semantic_provider": "metricflow",
                    "semantic_model_ref": _model_ref(model_ref),
                    "compile_execution_boundary": "mcp_query_runtime",
                }
            )
        return result

    async def _request(
        self,
        operation: str,
        arguments: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        if not self._enabled or self._provider is None:
            raise SemanticRuntimeFailure(
                "METRICFLOW_DISABLED",
                "MetricFlow provider is disabled.",
                status_code=503,
            )
        try:
            return await self._provider.request(operation, arguments)
        except MetricFlowProviderFailure as exc:
            raise SemanticRuntimeFailure(
                exc.reason_code,
                str(exc),
                retryable=exc.reason_code
                in {
                    "METRICFLOW_PROVIDER_TIMEOUT",
                    "METRICFLOW_PROVIDER_START_FAILED",
                },
                status_code=502,
            ) from exc


def _model_ref(value: str) -> str:
    if not isinstance(value, str) or _MODEL_REF_RE.fullmatch(value) is None:
        raise SemanticRuntimeFailure(
            "METRICFLOW_MODEL_REF_INVALID",
            "An exact MetricFlow model reference is required.",
        )
    return value


def _collection_result(data: Mapping[str, Any], source: str) -> dict[str, Any]:
    items = data.get("items")
    if not isinstance(items, list) or any(
        not isinstance(item, Mapping) for item in items
    ):
        raise SemanticRuntimeFailure(
            "METRICFLOW_PROVIDER_RESPONSE_INVALID",
            "MetricFlow provider collection response is invalid.",
            status_code=502,
        )
    truncated = bool(data.get("truncated", False))
    return {
        "status": "partial" if truncated else "success",
        "data": {
            "items": [dict(item) for item in items],
            "next_cursor": None,
            "truncated": truncated,
        },
        "warnings": (["METRICFLOW_RESULT_TRUNCATED"] if truncated else []),
        "metadata": {
            "source": source,
            "provider_protocol": METRICFLOW_PROVIDER_PROTOCOL,
        },
    }


def _detail_result(data: Mapping[str, Any], source: str) -> dict[str, Any]:
    return {
        "status": "success",
        "data": dict(data),
        "warnings": [],
        "metadata": {
            "source": source,
            "provider_protocol": METRICFLOW_PROVIDER_PROTOCOL,
        },
    }


__all__ = [
    "METRICFLOW_PROVIDER_PROTOCOL",
    "MetricFlowProvider",
    "MetricFlowProviderFailure",
    "MetricFlowSemanticRuntime",
    "MetricFlowSidecarProvider",
]
