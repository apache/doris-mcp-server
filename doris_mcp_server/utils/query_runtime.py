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

"""Strict read-only execution and evidence collection for the Query domain."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any
from urllib.parse import quote

import sqlparse
from sqlparse import tokens as sql_tokens

from ..result_limits import (
    ResultLimitError,
    ResultLimits,
    configured_default_result_rows,
    configured_result_limits,
    resolve_result_limits,
)
from .adbc_query_tools import DorisADBCQueryTools
from .db import DorisConnectionManager, QueryResult
from .doris_http_client import (
    DorisHTTPClient,
    DorisHTTPResponse,
    configured_fe_http_hosts,
    database_config_for_request,
)
from .security import get_current_auth_context
from .sql_security_utils import (
    SQLSecurityError,
    quote_identifier,
    validate_identifier,
)

_MAX_SQL_LENGTH = 1024 * 1024
_MAX_QUERY_ID_LENGTH = 128
_MAX_SLOW_QUERY_LIMIT = 1000
_MAX_SLOW_QUERY_WINDOW_MINUTES = 90 * 24 * 60
_MAX_SLOW_QUERY_TEXT = 8192
_QUERY_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_NAMED_PARAMETER_RE = re.compile(r"(?<!%)%\(([A-Za-z_][A-Za-z0-9_]*)\)s")
_POSITIONAL_PARAMETER_RE = re.compile(r"(?<!%)%s")
_SIDE_EFFECT_FUNCTIONS = (
    "BENCHMARK",
    "GET_LOCK",
    "LOAD_FILE",
    "MASTER_POS_WAIT",
    "RELEASE_LOCK",
    "SLEEP",
)


class QueryRuntimeFailure(RuntimeError):
    """Sanitized Query-domain failure with a stable reason code."""

    def __init__(
        self,
        message: str,
        *,
        reason_code: str,
        status_code: int,
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.status_code = status_code
        self.retryable = retryable


@dataclass(frozen=True, slots=True)
class ReadOnlyStatement:
    """One canonical, single-statement read-only SQL request."""

    sql: str
    operation: str


class ReadOnlySQLGuard:
    """Fail-closed SQL parser used by every formal Query execution path."""

    @classmethod
    def validate(
        cls,
        sql: str,
        *,
        query_target: bool = False,
    ) -> ReadOnlyStatement:
        if not isinstance(sql, str) or not sql.strip():
            raise _argument_failure("SQL must be a non-empty string.")
        if len(sql.encode("utf-8")) > _MAX_SQL_LENGTH:
            raise _argument_failure("SQL exceeds the maximum accepted size.")
        if "/*!" in sql:
            raise _read_only_failure("Executable version comments are not allowed.")

        statements = [
            statement
            for statement in sqlparse.parse(sql)
            if _has_executable_sql(statement)
        ]
        if len(statements) != 1:
            raise _read_only_failure("Exactly one read-only SQL statement is required.")

        statement = statements[0]
        canonical = str(statement).strip()
        if canonical.endswith(";"):
            canonical = canonical[:-1].rstrip()
        code_tokens = [
            token
            for token in statement.flatten()
            if not token.is_whitespace
            and token.ttype not in sql_tokens.Comment
            and token.ttype not in sql_tokens.Literal.String
        ]
        if not code_tokens:
            raise _argument_failure("SQL contains no executable statement.")

        parsed_type = statement.get_type().upper()
        first = str(code_tokens[0].value).strip().upper()
        operation = parsed_type if parsed_type != "UNKNOWN" else first
        if first == "WITH" and parsed_type == "SELECT":
            operation = "SELECT"
        if operation not in {"SELECT", "SHOW", "DESC", "DESCRIBE", "EXPLAIN"}:
            raise _read_only_failure(
                f"SQL operation {operation or 'UNKNOWN'} is not read-only."
            )
        if query_target and operation not in {"SELECT", "SHOW", "DESC", "DESCRIBE"}:
            raise _read_only_failure(
                "This operation requires a query target, not an EXPLAIN statement."
            )

        if operation == "EXPLAIN":
            executable_sql = "".join(
                str(token.value)
                for token in statement.flatten()
                if token.ttype not in sql_tokens.Comment
            )
            target = re.fullmatch(
                r"\s*EXPLAIN(?:\s+VERBOSE)?\s+(.+?)\s*",
                executable_sql,
                flags=re.IGNORECASE | re.DOTALL,
            )
            if target is None:
                raise _read_only_failure(
                    "EXPLAIN must contain one supported read-only query target."
                )
            cls.validate(target.group(1), query_target=True)

        code = " ".join(str(token.value) for token in code_tokens)
        upper_code = code.upper()
        if re.search(r"\bINTO\s+(OUTFILE|DUMPFILE)\b", upper_code):
            raise _read_only_failure("Result export clauses are not allowed.")
        if ":=" in code:
            raise _read_only_failure("Session-variable assignment is not allowed.")
        if re.search(r"\bFOR\s+UPDATE\b", upper_code):
            raise _read_only_failure("Locking reads are not allowed.")
        if re.search(r"\bLOCK\s+IN\s+SHARE\s+MODE\b", upper_code):
            raise _read_only_failure("Locking reads are not allowed.")

        if operation == "SELECT":
            contains_nested_mutation = any(
                (
                    token.ttype in sql_tokens.Keyword.DML
                    and str(token.value).strip().upper() != "SELECT"
                )
                or token.ttype in sql_tokens.Keyword.DDL
                for token in code_tokens
            )
            if contains_nested_mutation:
                raise _read_only_failure("SQL contains a disallowed operation.")
        for function_name in _SIDE_EFFECT_FUNCTIONS:
            if re.search(
                rf"\b{re.escape(function_name)}\s*\(",
                upper_code,
            ):
                raise _read_only_failure(
                    "SQL contains a disallowed side-effecting function."
                )

        return ReadOnlyStatement(sql=canonical, operation=operation)

    @staticmethod
    def validate_parameters(
        sql: str,
        parameters: Mapping[str, Any] | None,
    ) -> dict[str, Any] | None:
        parameter_code = _parameter_code(sql)
        placeholders = set(_NAMED_PARAMETER_RE.findall(parameter_code))
        if _POSITIONAL_PARAMETER_RE.search(parameter_code):
            raise _argument_failure(
                "Positional SQL parameters are not supported; use named "
                "%(name)s placeholders."
            )
        if parameters is None:
            if placeholders:
                raise _argument_failure("SQL parameters are missing.")
            return None
        if not isinstance(parameters, Mapping):
            raise _argument_failure("Query parameters must be an object.")

        normalized: dict[str, Any] = {}
        for raw_name, value in parameters.items():
            if not isinstance(raw_name, str) or not re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_]{0,63}",
                raw_name,
            ):
                raise _argument_failure("Query parameter names are invalid.")
            if value is not None and not isinstance(
                value,
                str | int | float | bool,
            ):
                raise _argument_failure("Query parameter values must be JSON scalars.")
            if isinstance(value, float) and not math.isfinite(value):
                raise _argument_failure("Query parameter numbers must be finite.")
            normalized[raw_name] = value

        supplied = set(normalized)
        if supplied != placeholders:
            raise _argument_failure(
                "SQL placeholders and supplied parameters must match exactly."
            )
        return normalized

    @staticmethod
    def prepare_driver_sql(
        sql: str,
        parameters: Mapping[str, Any] | None,
    ) -> str:
        """Escape non-placeholder percent signs for the PyMySQL formatter."""
        if parameters is None:
            return sql
        parameter_code = _parameter_code(sql)
        placeholder_ends = {
            match.start(): match.end()
            for match in _NAMED_PARAMETER_RE.finditer(parameter_code)
        }
        output: list[str] = []
        offset = 0
        while offset < len(sql):
            placeholder_end = placeholder_ends.get(offset)
            if placeholder_end is not None:
                output.append(sql[offset:placeholder_end])
                offset = placeholder_end
                continue
            character = sql[offset]
            output.append("%%" if character == "%" else character)
            offset += 1
        return "".join(output)


class DorisQueryRuntime:
    """Production Query-domain runtime shared by hierarchical and flat tools."""

    def __init__(
        self,
        connection_manager: DorisConnectionManager,
        adbc_query_tools: DorisADBCQueryTools,
    ) -> None:
        self._connection_manager = connection_manager
        self._adbc_query_tools = adbc_query_tools
        self._session_prefix = f"formal_query_{uuid.uuid4().hex[:8]}"

    async def execute_query(
        self,
        *,
        sql: str,
        catalog: str | None = None,
        database: str | None = None,
        parameters: Mapping[str, Any] | None = None,
        max_rows: int | None = None,
        timeout_ms: int | None = None,
    ) -> dict[str, Any]:
        """Execute one bounded read-only statement over the MySQL protocol."""
        statement = ReadOnlySQLGuard.validate(sql)
        bound_parameters = ReadOnlySQLGuard.validate_parameters(
            statement.sql,
            parameters,
        )
        driver_sql = ReadOnlySQLGuard.prepare_driver_sql(
            statement.sql,
            bound_parameters,
        )
        limits = self._resolve_limits(max_rows=max_rows, timeout_ms=timeout_ms)
        result = await self._execute_statement(
            driver_sql,
            parameters=bound_parameters,
            catalog=catalog,
            database=database,
            limits=limits,
            purpose="execute",
        )
        return _query_result(
            result,
            limits=limits,
            protocol="mysql",
            operation=statement.operation,
        )

    async def explain_query(
        self,
        *,
        sql: str,
        catalog: str | None = None,
        database: str | None = None,
        level: str | None = None,
    ) -> dict[str, Any]:
        """Return a bounded plan plus deterministic, evidence-only facets."""
        statement = ReadOnlySQLGuard.validate(sql, query_target=True)
        ReadOnlySQLGuard.validate_parameters(statement.sql, None)
        requested_level = "normal" if level is None else level
        if requested_level not in {"normal", "verbose", "costs"}:
            raise _argument_failure("Explain level is invalid.")

        warnings: list[str] = []
        effective_level = requested_level
        if requested_level == "normal":
            explain_prefix = "EXPLAIN"
        else:
            explain_prefix = "EXPLAIN VERBOSE"
            if requested_level == "costs":
                effective_level = "verbose"
                warnings.append(
                    "Doris has no EXPLAIN COSTS keyword; the verbose plan and "
                    "its reported cardinality/cost fields were returned."
                )

        explain_row_budget = min(
            10_000,
            configured_result_limits(self._connection_manager.config).max_rows,
        )
        limits = self._resolve_limits(
            max_rows=explain_row_budget,
            timeout_ms=None,
        )
        result = await self._execute_statement(
            f"{explain_prefix} {statement.sql}",
            parameters=None,
            catalog=catalog,
            database=database,
            limits=limits,
            purpose="explain",
            mask_result=False,
        )
        plan_rows = [_json_mapping(row) for row in (result.data or [])]
        plan_truncated = bool(result.metadata.get("truncated"))
        truncation_reason = result.metadata.get("truncation_reason")
        if plan_truncated:
            warnings.append(
                "The EXPLAIN output was truncated at the configured result "
                f"boundary ({truncation_reason or 'unknown limit'})."
            )
        plan_text = "\n".join(
            " | ".join(str(value) for value in row.values()) for row in plan_rows
        )
        data = {
            "requested_level": requested_level,
            "effective_level": effective_level,
            "plan_rows": plan_rows,
            "plan_text": plan_text,
            "facets": _explain_facets(plan_text),
        }
        metadata = {
            "source": "doris_explain",
            "plan_row_count": len(plan_rows),
            "plan_truncated": plan_truncated,
            "truncation_reason": truncation_reason,
            "execution_time_seconds": getattr(result, "execution_time", 0.0),
        }
        return _diagnostic_result(
            data,
            status="partial" if warnings else "success",
            warnings=warnings,
            metadata=metadata,
            evidence=(
                {
                    "source": "doris_sql",
                    "kind": "explain",
                    "operation": statement.operation,
                },
            ),
        )

    async def get_query_profile(
        self,
        *,
        query_id: str | None = None,
        sql: str | None = None,
        recent_window_minutes: int | None = None,
        include_operator_tree: bool = False,
        database: str | None = None,
    ) -> dict[str, Any]:
        """Read one profile by ID or execute one bounded query with profiling."""
        if bool(query_id) == bool(sql):
            raise _argument_failure("Provide exactly one of query_id or sql.")
        window = _bounded_integer(
            (60 if recent_window_minutes is None else recent_window_minutes),
            "recent_window_minutes",
            minimum=1,
            maximum=_MAX_SLOW_QUERY_WINDOW_MINUTES,
        )
        warnings: list[str] = []
        query_summary: dict[str, Any] | None = None
        resolved_query_id = query_id

        if query_id is not None:
            resolved_query_id = _validate_query_id(query_id)
        else:
            statement = ReadOnlySQLGuard.validate(str(sql), query_target=True)
            ReadOnlySQLGuard.validate_parameters(statement.sql, None)
            limits = self._resolve_limits(max_rows=1, timeout_ms=None)
            trace_id = str(uuid.uuid4())
            query_result = await self._execute_profiled_statement(
                statement.sql,
                trace_id=trace_id,
                database=database,
                limits=limits,
            )
            query_summary = {
                "row_count": len(query_result.data or []),
                "execution_time_seconds": query_result.execution_time,
                "truncated": bool(query_result.metadata.get("truncated")),
            }
            resolved_query_id = await self._wait_for_query_id(trace_id)
            if resolved_query_id is None:
                return _diagnostic_result(
                    {
                        "query_id": None,
                        "profile": None,
                        "operator_tree": [],
                        "query_summary": query_summary,
                    },
                    status="partial",
                    warnings=(
                        "The query completed, but Doris did not publish a "
                        "query ID before the bounded lookup expired.",
                    ),
                    metadata={
                        "source": "doris_profile_api",
                        "recent_window_minutes": window,
                    },
                    evidence=(
                        {
                            "source": "doris_sql",
                            "kind": "profiled_query",
                        },
                    ),
                )

        profile = await self._fetch_profile(_validate_query_id(resolved_query_id))
        profile_text = profile["profile_text"]
        maximum = _profile_text_limit(self._connection_manager.config)
        truncated = len(profile_text) > maximum
        visible_profile = profile_text[:maximum]
        if truncated:
            warnings.append(
                "Profile text was truncated at the configured response limit."
            )
        operator_tree = (
            _profile_operator_tree(visible_profile) if include_operator_tree else []
        )
        return _diagnostic_result(
            {
                "query_id": resolved_query_id,
                "profile": visible_profile,
                "profile_facets": _profile_facets(visible_profile),
                "operator_tree": operator_tree,
                "query_summary": query_summary,
            },
            status="partial" if warnings else "success",
            warnings=warnings,
            metadata={
                "source": "doris_profile_api",
                "profile_size": len(profile_text),
                "profile_truncated": truncated,
                "recent_window_minutes": window,
            },
            evidence=(
                {
                    "source": "doris_fe_http",
                    "kind": "query_profile",
                    "query_id": resolved_query_id,
                },
            ),
        )

    async def list_slow_queries(
        self,
        *,
        window_minutes: int | None = None,
        limit: int | None = None,
        min_duration_ms: int | None = None,
        database: str | None = None,
        user: str | None = None,
    ) -> dict[str, Any]:
        """List bounded audit-log records without swallowing provider failures."""
        window = _bounded_integer(
            60 if window_minutes is None else window_minutes,
            "window_minutes",
            minimum=1,
            maximum=_MAX_SLOW_QUERY_WINDOW_MINUTES,
        )
        row_limit = _bounded_integer(
            20 if limit is None else limit,
            "limit",
            minimum=1,
            maximum=_MAX_SLOW_QUERY_LIMIT,
        )
        duration = _bounded_integer(
            1000 if min_duration_ms is None else min_duration_ms,
            "min_duration_ms",
            minimum=0,
            maximum=86_400_000,
        )
        if database is not None:
            try:
                validate_identifier(database, "database name")
            except SQLSecurityError as exc:
                raise _argument_failure(
                    "Slow-query database filter is invalid."
                ) from exc
        if user is not None and (not user.strip() or len(user) > 128):
            raise _argument_failure("User filter is invalid.")

        start_time = datetime.now() - timedelta(minutes=window)
        normalized_user = user.strip() if user is not None else None
        sql = (
            "SELECT `query_id`, `time`, `user`, `catalog`, `db`, `state`, "
            "`query_time`, `cpu_time_ms`, `scan_bytes`, `scan_rows`, "
            "`return_rows`, `peak_memory_bytes`, `sql_hash`, `sql_digest`, "
            "`stmt` FROM internal.__internal_schema.audit_log "
            "WHERE `time` >= %s AND `query_time` >= %s AND `is_query` = 1 "
            "AND (%s IS NULL OR `db` = %s) "
            "AND (%s IS NULL OR `user` = %s) "
            "ORDER BY `query_time` DESC, `time` DESC, `query_id` "
            "LIMIT %s"
        )
        params = (
            start_time,
            duration,
            database,
            database,
            normalized_user,
            normalized_user,
            row_limit + 1,
        )
        limits = ResultLimits(
            max_rows=row_limit + 1,
            max_bytes=configured_result_limits(
                self._connection_manager.config
            ).max_bytes,
            timeout_seconds=min(
                30,
                configured_result_limits(
                    self._connection_manager.config
                ).timeout_seconds,
            ),
        )
        result = await self._execute_statement(
            sql,
            parameters=tuple(params),
            catalog=None,
            database=None,
            limits=limits,
            purpose="slow_queries",
            mask_result=False,
            trusted_internal=True,
        )
        raw_rows = list(result.data or [])
        truncated = len(raw_rows) > row_limit
        raw_rows = await self._mask_audit_rows(raw_rows)
        items = [_slow_query_item(row) for row in raw_rows[:row_limit]]
        return _collection_result(
            items,
            truncated=truncated,
            metadata={
                "source": "internal.__internal_schema.audit_log",
                "window_minutes": window,
                "min_duration_ms": duration,
                "returned_items": len(items),
            },
        )

    async def get_adbc_connection_info(
        self,
        *,
        explicit_adbc: bool,
    ) -> dict[str, Any]:
        """Return a secret-free summary of the optional ADBC provider."""
        _require_explicit_adbc_intent(explicit_adbc)
        raw = await self._adbc_query_tools.get_adbc_connection_info()
        if not isinstance(raw, Mapping):
            raise QueryRuntimeFailure(
                "ADBC provider returned an invalid status response.",
                reason_code="ADBC_PROVIDER_INVALID_RESPONSE",
                status_code=502,
            )
        port_status = raw.get("port_status")
        module_status = raw.get("module_status")
        port_data = port_status if isinstance(port_status, Mapping) else {}
        module_data = module_status if isinstance(module_status, Mapping) else {}
        configuration = raw.get("configuration")
        configuration_data = configuration if isinstance(configuration, Mapping) else {}
        status = str(raw.get("status", "not_ready"))
        data = {
            "enabled": bool(
                getattr(
                    getattr(self._connection_manager.config, "adbc", None),
                    "enabled",
                    False,
                )
            ),
            "status": status,
            "driver_ready": bool(module_data.get("success")),
            "flight_sql_reachable": bool(port_data.get("success")),
            "fe_port_configured": bool(configuration_data.get("fe_arrow_flight_port")),
            "be_port_configured": bool(configuration_data.get("be_arrow_flight_port")),
            "reachable_be_count": int(port_data.get("be_available_count", 0) or 0),
            "driver_versions": {
                "manager": str(module_data.get("adbc_manager_version", "unknown")),
                "flight_sql": str(module_data.get("flight_sql_version", "unknown")),
            },
        }
        warnings = (
            ()
            if status == "ready"
            else ("ADBC is not ready on the active Doris route.",)
        )
        return _detail_result(
            data,
            status="partial" if warnings else "success",
            warnings=warnings,
            metadata={"source": "adbc_runtime_probe"},
        )

    async def execute_adbc_query(
        self,
        *,
        explicit_adbc: bool,
        sql: str,
        max_rows: int | None = None,
        timeout_ms: int | None = None,
        result_format: str | None = None,
    ) -> dict[str, Any]:
        """Execute one strict read-only query through Arrow Flight SQL."""
        _require_explicit_adbc_intent(explicit_adbc)
        statement = ReadOnlySQLGuard.validate(sql)
        ReadOnlySQLGuard.validate_parameters(statement.sql, None)
        if result_format not in {None, "arrow", "pandas", "dict"}:
            raise _argument_failure("ADBC result format is invalid.")
        timeout = (
            math.ceil(
                _bounded_integer(
                    timeout_ms,
                    "timeout_ms",
                    minimum=1,
                    maximum=300_000,
                )
                / 1000
            )
            if timeout_ms is not None
            else None
        )
        raw = await self._adbc_query_tools.exec_adbc_query(
            statement.sql,
            max_rows=max_rows,
            timeout=timeout,
            return_format=result_format,
        )
        if not isinstance(raw, Mapping) or raw.get("success") is not True:
            raise _classify_adbc_failure(raw)

        result = raw.get("result")
        result_data = result if isinstance(result, Mapping) else {}
        column_names = list(result_data.get("column_names", []) or [])
        column_types = list(result_data.get("column_types", []) or [])
        rows_value = result_data.get("data")
        if not isinstance(rows_value, list):
            rows_value = result_data.get("data_preview")
        rows = [
            _json_mapping(row)
            for row in (rows_value if isinstance(rows_value, list) else [])
            if isinstance(row, Mapping)
        ]
        source_row_count = int(result_data.get("num_rows", len(rows)) or 0)
        representation_truncated = source_row_count > len(rows)
        truncated = bool(raw.get("truncated")) or representation_truncated
        warnings: list[str] = []
        if representation_truncated:
            warnings.append(
                "The Arrow representation exposes a bounded row preview in "
                "the MCP JSON response."
            )
        return _query_output(
            columns=[
                {
                    "name": str(name),
                    "type": (
                        str(column_types[index])
                        if index < len(column_types)
                        else "unknown"
                    ),
                }
                for index, name in enumerate(column_names)
            ],
            rows=rows,
            truncated=truncated,
            warnings=warnings,
            metadata={
                "source": "adbc_arrow_flight_sql",
                "protocol": "adbc",
                "result_format": str(result_data.get("format", result_format or "")),
                "source_row_count": source_row_count,
                "truncation_reason": raw.get("truncation_reason"),
                "execution_time_seconds": raw.get("execution_time"),
            },
        )

    async def diagnose_query_performance(
        self,
        *,
        query_id: str | None = None,
        sql: str | None = None,
        database: str | None = None,
        include_cluster_context: bool = False,
    ) -> dict[str, Any]:
        """Compose deterministic evidence without model-generated guesses."""
        if bool(query_id) == bool(sql):
            raise _argument_failure("Provide exactly one of query_id or sql.")

        audit_row: dict[str, Any] | None = None
        audit_record: dict[str, Any] | None = None
        resolved_query_id = query_id
        target_sql = sql
        resolved_catalog: str | None = None
        resolved_database = database
        warnings: list[str] = []
        steps: dict[str, Any] = {}

        if query_id is not None:
            resolved_query_id = _validate_query_id(query_id)
            audit_row = await self._find_audit_record(resolved_query_id)
            if audit_row is not None:
                audit_record = _slow_query_item(audit_row)
                candidate = audit_record.get("sql")
                target_sql = str(candidate) if candidate else None
                resolved_catalog = _optional_identifier(audit_record.get("catalog"))
                if resolved_database is None:
                    resolved_database = _optional_identifier(
                        audit_record.get("database")
                    )
            if not target_sql or bool(
                audit_record and audit_record.get("sql_truncated")
            ):
                target_sql = await self._fetch_query_sql(resolved_query_id)
            if not target_sql:
                raise QueryRuntimeFailure(
                    "Doris did not expose SQL evidence for the requested query ID.",
                    reason_code="QUERY_SQL_EVIDENCE_NOT_FOUND",
                    status_code=404,
                )

        statement = ReadOnlySQLGuard.validate(str(target_sql), query_target=True)
        explain = await self.explain_query(
            sql=statement.sql,
            catalog=resolved_catalog,
            database=resolved_database,
            level="verbose",
        )
        warnings.extend(_result_warnings(explain))
        steps["explain"] = {
            "status": explain["status"],
            "source": explain["metadata"].get("source"),
        }

        profile: dict[str, Any] | None = None
        try:
            profile = await self.get_query_profile(
                query_id=resolved_query_id,
                sql=None if resolved_query_id else statement.sql,
                include_operator_tree=True,
                database=resolved_database,
            )
        except QueryRuntimeFailure as exc:
            warnings.append(
                f"Query profile evidence is unavailable ({exc.reason_code})."
            )
            steps["profile"] = {
                "status": "unavailable",
                "reason_code": exc.reason_code,
            }
        else:
            warnings.extend(_result_warnings(profile))
            steps["profile"] = {
                "status": profile["status"],
                "source": profile["metadata"].get("source"),
            }
            if resolved_query_id is None:
                candidate_id = profile["data"].get("query_id")
                if isinstance(candidate_id, str):
                    resolved_query_id = candidate_id

        if audit_row is None and resolved_query_id is not None:
            audit_row = await self._find_audit_record(resolved_query_id)
            if audit_row is not None:
                audit_record = _slow_query_item(audit_row)
        steps["slow_query"] = {
            "status": "success" if audit_record is not None else "unavailable",
            "source": (
                "internal.__internal_schema.audit_log"
                if audit_record is not None
                else None
            ),
        }
        if audit_record is None:
            warnings.append("No matching audit-log evidence was found.")

        cluster_context: dict[str, Any] | None = None
        if include_cluster_context:
            cluster_context = {
                "status": "unavailable",
                "reason_code": "CLUSTER_DOMAIN_NOT_YET_IMPLEMENTED",
            }
            warnings.append(
                "Cluster context is deferred to the dedicated Cluster-domain "
                "implementation."
            )
        steps["cluster_context"] = (
            dict(cluster_context)
            if cluster_context is not None
            else {"status": "not_requested"}
        )

        explain_data = explain["data"]
        profile_data = profile["data"] if profile is not None else {}
        findings = _diagnostic_findings(
            explain_text=str(explain_data.get("plan_text", "")),
            profile_text=str(profile_data.get("profile") or ""),
            audit_record=audit_record,
        )
        recommendations = _diagnostic_recommendations(findings)
        evidence = list(explain.get("evidence", []))
        if profile is not None:
            evidence.extend(profile.get("evidence", []))
        if audit_record is not None:
            evidence.append(
                {
                    "source": "doris_audit_log",
                    "kind": "query_record",
                    "query_id": resolved_query_id,
                }
            )
        visible_audit_record = audit_record
        if audit_row is not None:
            visible_rows = await self._mask_audit_rows([audit_row])
            visible_audit_record = (
                _slow_query_item(visible_rows[0]) if visible_rows else None
            )
        warnings = list(dict.fromkeys(warnings))
        evidence_is_partial = any(
            step.get("status") == "partial"
            for step in steps.values()
            if isinstance(step, Mapping)
        )
        status = "partial" if warnings or evidence_is_partial else "success"
        return _diagnostic_result(
            {
                "query_id": resolved_query_id,
                "steps": steps,
                "findings": findings,
                "recommendations": recommendations,
                "audit_record": visible_audit_record,
                "cluster_context": cluster_context,
            },
            status=status,
            warnings=warnings,
            metadata={
                "source": "deterministic_query_diagnosis",
                "rule_version": "query-diagnosis-v1",
            },
            evidence=tuple(evidence),
        )

    async def _mask_audit_rows(
        self,
        rows: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Apply request-scoped masking before audit evidence becomes visible."""
        if not rows:
            return []
        auth_context = get_current_auth_context()
        security_manager = getattr(
            self._connection_manager,
            "security_manager",
            None,
        )
        if auth_context is None or security_manager is None:
            return [dict(row) for row in rows]
        masked = await security_manager.apply_data_masking(
            [dict(row) for row in rows],
            auth_context,
        )
        return [dict(row) for row in masked]

    def _resolve_limits(
        self,
        *,
        max_rows: int | None,
        timeout_ms: int | None,
    ) -> ResultLimits:
        default_rows = configured_default_result_rows(self._connection_manager.config)
        ceilings = configured_result_limits(self._connection_manager.config)
        if timeout_ms is None:
            timeout = min(30, ceilings.timeout_seconds)
        else:
            bounded_timeout_ms = _bounded_integer(
                timeout_ms,
                "timeout_ms",
                minimum=1,
                maximum=300_000,
            )
            timeout = math.ceil(bounded_timeout_ms / 1000)
        try:
            return resolve_result_limits(
                self._connection_manager.config,
                max_rows=max_rows if max_rows is not None else default_rows,
                max_bytes=None,
                timeout_seconds=timeout,
            )
        except ResultLimitError as exc:
            raise _argument_failure(str(exc)) from exc

    async def _execute_statement(
        self,
        sql: str,
        *,
        parameters: Mapping[str, Any] | tuple[Any, ...] | None,
        catalog: str | None,
        database: str | None,
        limits: ResultLimits,
        purpose: str,
        mask_result: bool = True,
        trusted_internal: bool = False,
    ) -> QueryResult:
        context_statements = _context_statements(catalog, database)
        auth_context = get_current_auth_context()
        session_id = f"{self._session_prefix}_{purpose}"
        try:
            async with asyncio.timeout(limits.timeout_seconds):
                async with (
                    self._connection_manager.get_connection_context_for_auth_context(
                        session_id,
                        auth_context,
                    ) as connection
                ):
                    try:
                        for context_sql in context_statements:
                            await connection.execute(
                                context_sql,
                                auth_context=None,
                                mask_result=False,
                                internal_session_control=True,
                            )
                        return await connection.execute(
                            sql,
                            params=parameters,
                            auth_context=(None if trusted_internal else auth_context),
                            mask_result=mask_result,
                            max_rows=limits.max_rows,
                            max_bytes=limits.max_bytes,
                        )
                    finally:
                        if context_statements:
                            connection.is_healthy = False
        except TimeoutError as exc:
            raise QueryRuntimeFailure(
                "Doris query execution timed out.",
                reason_code="QUERY_TIMEOUT",
                status_code=504,
                retryable=True,
            ) from exc
        except QueryRuntimeFailure:
            raise
        except Exception as exc:
            raise _classify_query_failure(exc) from exc

    async def _execute_profiled_statement(
        self,
        sql: str,
        *,
        trace_id: str,
        database: str | None,
        limits: ResultLimits,
    ) -> QueryResult:
        context_statements = _context_statements(None, database)
        auth_context = get_current_auth_context()
        session_id = f"{self._session_prefix}_profile"
        try:
            async with asyncio.timeout(limits.timeout_seconds):
                async with (
                    self._connection_manager.get_connection_context_for_auth_context(
                        session_id,
                        auth_context,
                    ) as connection
                ):
                    try:
                        for context_sql in context_statements:
                            await connection.execute(
                                context_sql,
                                auth_context=None,
                                mask_result=False,
                            )
                        await connection.execute(
                            f'SET session_context="trace_id:{trace_id}"',
                            auth_context=None,
                            mask_result=False,
                            internal_session_control=True,
                        )
                        await connection.execute(
                            "SET enable_profile=true",
                            auth_context=None,
                            mask_result=False,
                            internal_session_control=True,
                        )
                        return await connection.execute(
                            sql,
                            auth_context=auth_context,
                            max_rows=limits.max_rows,
                            max_bytes=limits.max_bytes,
                        )
                    finally:
                        connection.is_healthy = False
        except TimeoutError as exc:
            raise QueryRuntimeFailure(
                "Profiled Doris query timed out.",
                reason_code="QUERY_TIMEOUT",
                status_code=504,
                retryable=True,
            ) from exc
        except Exception as exc:
            raise _classify_query_failure(exc) from exc

    async def _wait_for_query_id(self, trace_id: str) -> str | None:
        for delay in (0.0, 0.2, 0.5):
            if delay:
                await asyncio.sleep(delay)
            query_id = await self._fetch_query_id(trace_id)
            if query_id is not None:
                return query_id
        return None

    async def _fetch_query_id(self, trace_id: str) -> str | None:
        response = await self._profile_http_get(
            f"/rest/v2/manager/query/trace_id/{quote(trace_id, safe='')}"
        )
        payload = _http_json_if_present(response)
        api_code = _api_code(payload) if payload is not None else None
        if api_code in {401, 403}:
            return None
        if api_code == 404 or response.status == 404:
            return None
        if response.status != 200:
            raise _profile_http_failure(response.status)
        if payload is None:
            raise QueryRuntimeFailure(
                "Doris query profile service returned an invalid response.",
                reason_code="QUERY_PROFILE_INVALID_RESPONSE",
                status_code=502,
            )
        if api_code not in {None, 0}:
            raise QueryRuntimeFailure(
                "Doris query profile service returned an invalid response.",
                reason_code="QUERY_PROFILE_INVALID_RESPONSE",
                status_code=502,
            )
        data = payload.get("data")
        if isinstance(data, str) and data:
            return _validate_query_id(data)
        if isinstance(data, Mapping):
            query_ids = data.get("query_ids")
            if isinstance(query_ids, list) and query_ids:
                return _validate_query_id(str(query_ids[0]))
        return None

    async def _fetch_profile(self, query_id: str) -> dict[str, str]:
        response = await self._profile_http_get(
            f"/rest/v2/manager/query/profile/text/{quote(query_id, safe='')}"
        )
        payload = _http_json_if_present(response)
        api_code = _api_code(payload) if payload is not None else None
        if api_code in {401, 403}:
            raise QueryRuntimeFailure(
                "Doris denied access to query profile evidence.",
                reason_code="QUERY_PROFILE_PERMISSION_DENIED",
                status_code=403,
            )
        if api_code == 404 or response.status == 404:
            raise QueryRuntimeFailure(
                "The requested Doris query profile was not found.",
                reason_code="QUERY_PROFILE_NOT_FOUND",
                status_code=404,
            )
        if response.status != 200:
            raise _profile_http_failure(response.status)
        text = response.text()
        if payload is not None:
            if api_code not in {None, 0}:
                raise QueryRuntimeFailure(
                    "Doris query profile service returned an invalid response.",
                    reason_code="QUERY_PROFILE_INVALID_RESPONSE",
                    status_code=502,
                )
            data = payload.get("data")
            if isinstance(data, str):
                text = data
            elif isinstance(data, Mapping):
                text = str(data.get("profile", ""))
        if not text.strip():
            raise QueryRuntimeFailure(
                "The requested Doris query profile was not found.",
                reason_code="QUERY_PROFILE_NOT_FOUND",
                status_code=404,
            )
        return {"query_id": query_id, "profile_text": text}

    async def _fetch_query_sql(self, query_id: str) -> str:
        response = await self._profile_http_get(
            f"/rest/v2/manager/query/sql/{quote(query_id, safe='')}"
        )
        payload = _http_json_if_present(response)
        api_code = _api_code(payload) if payload is not None else None
        if api_code in {401, 403}:
            raise QueryRuntimeFailure(
                "Doris denied access to query SQL evidence.",
                reason_code="QUERY_PROFILE_PERMISSION_DENIED",
                status_code=403,
            )
        if api_code == 404 or response.status == 404:
            raise QueryRuntimeFailure(
                "SQL evidence for the requested Doris query was not found.",
                reason_code="QUERY_SQL_EVIDENCE_NOT_FOUND",
                status_code=404,
            )
        if response.status != 200:
            raise _profile_http_failure(response.status)
        if payload is None:
            raise QueryRuntimeFailure(
                "Doris query profile service returned an invalid response.",
                reason_code="QUERY_PROFILE_INVALID_RESPONSE",
                status_code=502,
            )
        if api_code not in {None, 0}:
            raise QueryRuntimeFailure(
                "Doris query profile service returned an invalid response.",
                reason_code="QUERY_PROFILE_INVALID_RESPONSE",
                status_code=502,
            )
        data = payload.get("data")
        sql = str(data.get("sql", "")) if isinstance(data, Mapping) else str(data or "")
        if not sql.strip():
            raise QueryRuntimeFailure(
                "SQL evidence for the requested Doris query was not found.",
                reason_code="QUERY_SQL_EVIDENCE_NOT_FOUND",
                status_code=404,
            )
        return sql

    async def _profile_http_get(self, path: str) -> DorisHTTPResponse:
        try:
            auth_context = get_current_auth_context()
            if auth_context is not None and auth_context.auth_method == "doris_oauth":
                raise QueryRuntimeFailure(
                    "Query profile HTTP access is unavailable for this "
                    "credential route.",
                    reason_code="QUERY_PROFILE_CREDENTIAL_ROUTE_UNAVAILABLE",
                    status_code=503,
                )
            db_config = database_config_for_request(self._connection_manager)
            hosts = configured_fe_http_hosts(db_config)
            client = DorisHTTPClient.from_database_config(db_config)
            return await client.get_first_available(
                role="fe",
                hosts=hosts,
                port=db_config.fe_http_port,
                path=path,
                headers={"Accept": "application/json, text/plain"},
            )
        except QueryRuntimeFailure:
            raise
        except Exception as exc:
            raise QueryRuntimeFailure(
                "Doris query profile service is temporarily unavailable.",
                reason_code="QUERY_PROFILE_BACKEND_UNAVAILABLE",
                status_code=503,
                retryable=True,
            ) from exc

    async def _find_audit_record(
        self,
        query_id: str,
    ) -> dict[str, Any] | None:
        limits = ResultLimits(
            max_rows=1,
            max_bytes=configured_result_limits(
                self._connection_manager.config
            ).max_bytes,
            timeout_seconds=min(
                30,
                configured_result_limits(
                    self._connection_manager.config
                ).timeout_seconds,
            ),
        )
        sql = (
            "SELECT `query_id`, `time`, `user`, `catalog`, `db`, `state`, "
            "`query_time`, `cpu_time_ms`, `scan_bytes`, `scan_rows`, "
            "`return_rows`, `peak_memory_bytes`, `sql_hash`, `sql_digest`, "
            "`stmt` FROM internal.__internal_schema.audit_log "
            "WHERE `query_id` = %s ORDER BY `time` DESC LIMIT 1"
        )
        try:
            result = await self._execute_statement(
                sql,
                parameters=(query_id,),
                catalog=None,
                database=None,
                limits=limits,
                purpose="query_audit",
                mask_result=False,
                trusted_internal=True,
            )
        except QueryRuntimeFailure:
            return None
        if not result.data:
            return None
        return dict(result.data[0])


def _argument_failure(message: str) -> QueryRuntimeFailure:
    return QueryRuntimeFailure(
        message,
        reason_code="QUERY_ARGUMENT_INVALID",
        status_code=400,
    )


def _parameter_code(sql: str) -> str:
    """Return executable SQL text while blanking comments and string literals."""
    statements = sqlparse.parse(sql)
    if len(statements) != 1:
        return sql
    return "".join(
        (
            " " * len(str(token.value))
            if token.ttype in sql_tokens.Comment
            or token.ttype in sql_tokens.Literal.String
            else str(token.value)
        )
        for token in statements[0].flatten()
    )


def _has_executable_sql(statement: Any) -> bool:
    """Return whether a parsed statement contains more than comments or delimiters."""
    return any(
        not token.is_whitespace
        and token.ttype not in sql_tokens.Comment
        and not (
            token.ttype in sql_tokens.Punctuation and str(token.value).strip() == ";"
        )
        for token in statement.flatten()
    )


def _optional_identifier(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip()


def _result_warnings(result: Mapping[str, Any]) -> list[str]:
    warnings = result.get("warnings")
    if not isinstance(warnings, list | tuple):
        return []
    return [str(warning) for warning in warnings if str(warning).strip()]


def _read_only_failure(message: str) -> QueryRuntimeFailure:
    return QueryRuntimeFailure(
        message,
        reason_code="QUERY_READ_ONLY_VIOLATION",
        status_code=400,
    )


def _validate_query_id(query_id: str) -> str:
    if (
        not isinstance(query_id, str)
        or len(query_id) > _MAX_QUERY_ID_LENGTH
        or _QUERY_ID_RE.fullmatch(query_id.strip()) is None
    ):
        raise _argument_failure("Query ID is invalid.")
    return query_id.strip()


def _bounded_integer(
    value: Any,
    name: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _argument_failure(f"{name} must be an integer.")
    if not minimum <= value <= maximum:
        raise _argument_failure(f"{name} must be between {minimum} and {maximum}.")
    return int(value)


def _context_statements(
    catalog: str | None,
    database: str | None,
) -> tuple[str, ...]:
    statements: list[str] = []
    try:
        if catalog is not None:
            validate_identifier(catalog, "catalog name")
            statements.append(f"SWITCH {quote_identifier(catalog, 'catalog name')}")
        if database is not None:
            validate_identifier(database, "database name")
            statements.append(f"USE {quote_identifier(database, 'database name')}")
    except SQLSecurityError as exc:
        raise _argument_failure("Doris query context is invalid.") from exc
    return tuple(statements)


def _query_result(
    result: QueryResult,
    *,
    limits: ResultLimits,
    protocol: str,
    operation: str,
) -> dict[str, Any]:
    rows = [
        _json_mapping(row) for row in (result.data or []) if isinstance(row, Mapping)
    ]
    raw_columns = result.metadata.get("columns", [])
    columns = [
        column if isinstance(column, dict) else {"name": str(column)}
        for column in (
            raw_columns
            if isinstance(raw_columns, list)
            else list(rows[0])
            if rows
            else []
        )
    ]
    truncated = bool(result.metadata.get("truncated"))
    return _query_output(
        columns=columns,
        rows=rows,
        truncated=truncated,
        metadata={
            "source": "doris_query",
            "protocol": protocol,
            "operation": operation,
            "execution_time_seconds": result.execution_time,
            "result_bytes": result.metadata.get("result_bytes"),
            "truncation_reason": result.metadata.get("truncation_reason"),
            "limits": {
                "max_rows": limits.max_rows,
                "max_bytes": limits.max_bytes,
                "timeout_seconds": limits.timeout_seconds,
            },
        },
    )


def _query_output(
    *,
    columns: list[dict[str, Any]],
    rows: list[dict[str, Any]],
    truncated: bool,
    warnings: list[str] | tuple[str, ...] = (),
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    warning_list = list(warnings)
    return {
        "status": "partial" if warning_list or truncated else "success",
        "data": {
            "columns": columns,
            "rows": rows,
            "row_count": len(rows),
            "truncated": truncated,
        },
        "warnings": warning_list,
        "metadata": dict(metadata or {}),
    }


def _detail_result(
    data: Mapping[str, Any],
    *,
    status: str = "success",
    warnings: list[str] | tuple[str, ...] = (),
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "status": status,
        "data": dict(data),
        "warnings": list(warnings),
        "metadata": dict(metadata or {}),
    }


def _diagnostic_result(
    data: Mapping[str, Any],
    *,
    status: str = "success",
    warnings: list[str] | tuple[str, ...] = (),
    metadata: Mapping[str, Any] | None = None,
    evidence: tuple[Mapping[str, Any], ...] = (),
) -> dict[str, Any]:
    return {
        **_detail_result(
            data,
            status=status,
            warnings=warnings,
            metadata=metadata,
        ),
        "evidence": [dict(item) for item in evidence],
    }


def _collection_result(
    items: list[dict[str, Any]],
    *,
    truncated: bool,
    metadata: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "status": "partial" if truncated else "success",
        "data": {
            "items": items,
            "next_cursor": None,
            "truncated": truncated,
        },
        "warnings": (
            ["Additional slow-query records matched the bounded request."]
            if truncated
            else []
        ),
        "metadata": dict(metadata),
    }


def _json_mapping(value: Mapping[str, Any]) -> dict[str, Any]:
    return {str(key): _json_value(item) for key, item in value.items()}


def _json_value(value: Any) -> Any:
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, Mapping):
        return _json_mapping(value)
    if isinstance(value, list | tuple):
        return [_json_value(item) for item in value]
    return str(value)


def _slow_query_item(row: Mapping[str, Any]) -> dict[str, Any]:
    normalized = {str(key).lower(): value for key, value in row.items()}
    sql = str(normalized.get("stmt") or "")
    return {
        "query_id": _json_value(normalized.get("query_id")),
        "time": _json_value(normalized.get("time")),
        "user": _json_value(normalized.get("user")),
        "catalog": _json_value(normalized.get("catalog")),
        "database": _json_value(normalized.get("db")),
        "state": _json_value(normalized.get("state")),
        "duration_ms": _optional_int(normalized.get("query_time")),
        "cpu_time_ms": _optional_int(normalized.get("cpu_time_ms")),
        "scan_bytes": _optional_int(normalized.get("scan_bytes")),
        "scan_rows": _optional_int(normalized.get("scan_rows")),
        "return_rows": _optional_int(normalized.get("return_rows")),
        "peak_memory_bytes": _optional_int(normalized.get("peak_memory_bytes")),
        "sql_hash": _json_value(normalized.get("sql_hash")),
        "sql_digest": _json_value(normalized.get("sql_digest")),
        "sql": sql[:_MAX_SLOW_QUERY_TEXT],
        "sql_truncated": len(sql) > _MAX_SLOW_QUERY_TEXT,
        "statement_fingerprint": hashlib.sha256(sql.encode("utf-8")).hexdigest()[:16],
    }


def _optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _explain_facets(plan_text: str) -> dict[str, Any]:
    upper = plan_text.upper()
    return {
        "has_join": "JOIN" in upper,
        "has_cross_join": "CROSS JOIN" in upper,
        "has_sort": "SORT" in upper or "ORDER BY" in upper,
        "has_exchange": "EXCHANGE" in upper,
        "has_runtime_filter": "RUNTIME FILTER" in upper,
        "has_partition_pruning": ("PARTITION" in upper and "PRUN" in upper),
        "mentions_inverted_index": "INVERTED" in upper,
        "mentions_ann_index": "ANN" in upper or "HNSW" in upper,
    }


def _profile_operator_tree(profile_text: str) -> list[str]:
    lines = []
    for raw_line in profile_text.splitlines():
        line = raw_line.rstrip()
        upper = line.upper()
        if any(
            marker in upper
            for marker in (
                "SCAN",
                "JOIN",
                "AGGREGATE",
                "EXCHANGE",
                "SORT",
                "SINK",
            )
        ):
            lines.append(line[:512])
        if len(lines) >= 256:
            break
    return lines


def _profile_facets(profile_text: str) -> dict[str, Any]:
    upper = profile_text.upper()
    return {
        "mentions_spill": "SPILL" in upper,
        "mentions_shuffle": "SHUFFLE" in upper or "EXCHANGE" in upper,
        "mentions_runtime_filter": "RUNTIME FILTER" in upper,
        "mentions_cache": "CACHE" in upper,
        "mentions_peak_memory": "PEAKMEMORY" in upper or "PEAK MEMORY" in upper,
    }


def _diagnostic_findings(
    *,
    explain_text: str,
    profile_text: str,
    audit_record: Mapping[str, Any] | None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    upper_plan = explain_text.upper()
    upper_profile = profile_text.upper()
    if "CROSS JOIN" in upper_plan:
        findings.append(
            {
                "code": "CROSS_JOIN_OBSERVED",
                "severity": "high",
                "evidence": "The Doris explain plan contains CROSS JOIN.",
            }
        )
    if "SPILL" in upper_profile and not re.search(
        r"SPILL[^\n]*[:=]\s*0(?:\D|$)",
        upper_profile,
    ):
        findings.append(
            {
                "code": "PROFILE_SPILL_OBSERVED",
                "severity": "medium",
                "evidence": "The Doris profile reports spill-related operators.",
            }
        )
    if audit_record is not None:
        scan_rows = _optional_int(audit_record.get("scan_rows")) or 0
        return_rows = _optional_int(audit_record.get("return_rows")) or 0
        duration = _optional_int(audit_record.get("duration_ms")) or 0
        peak_memory = _optional_int(audit_record.get("peak_memory_bytes")) or 0
        if scan_rows >= 1_000_000 and scan_rows > max(return_rows, 1) * 100:
            findings.append(
                {
                    "code": "HIGH_SCAN_TO_RETURN_RATIO",
                    "severity": "medium",
                    "evidence": {
                        "scan_rows": scan_rows,
                        "return_rows": return_rows,
                    },
                }
            )
        if duration >= 10_000:
            findings.append(
                {
                    "code": "LONG_RECORDED_DURATION",
                    "severity": "medium",
                    "evidence": {"duration_ms": duration},
                }
            )
        if peak_memory >= 1024**3:
            findings.append(
                {
                    "code": "HIGH_PEAK_MEMORY",
                    "severity": "medium",
                    "evidence": {"peak_memory_bytes": peak_memory},
                }
            )
    return findings


def _diagnostic_recommendations(
    findings: list[dict[str, Any]],
) -> list[dict[str, str]]:
    recommendations = {
        "CROSS_JOIN_OBSERVED": (
            "Review join predicates and verify that the Cartesian join is intentional."
        ),
        "PROFILE_SPILL_OBSERVED": (
            "Inspect high-cardinality joins, aggregations, and memory limits "
            "for the spilling operator."
        ),
        "HIGH_SCAN_TO_RETURN_RATIO": (
            "Review partition pruning, predicate pushdown, and available indexes."
        ),
        "LONG_RECORDED_DURATION": (
            "Compare operator time in the profile with scan and shuffle evidence."
        ),
        "HIGH_PEAK_MEMORY": (
            "Inspect operator cardinality estimates and memory-intensive joins "
            "or aggregations."
        ),
    }
    return [
        {
            "finding_code": str(finding["code"]),
            "recommendation": recommendations[str(finding["code"])],
        }
        for finding in findings
        if str(finding.get("code")) in recommendations
    ]


def _profile_text_limit(config: Any) -> int:
    performance = getattr(config, "performance", None)
    value = getattr(performance, "max_response_content_size", 4096)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return 4096
    return min(value, 1024 * 1024)


def _http_json(response: DorisHTTPResponse) -> Mapping[str, Any]:
    try:
        payload = json.loads(response.text())
    except json.JSONDecodeError as exc:
        raise QueryRuntimeFailure(
            "Doris query profile service returned an invalid response.",
            reason_code="QUERY_PROFILE_INVALID_RESPONSE",
            status_code=502,
        ) from exc
    if not isinstance(payload, Mapping):
        raise QueryRuntimeFailure(
            "Doris query profile service returned an invalid response.",
            reason_code="QUERY_PROFILE_INVALID_RESPONSE",
            status_code=502,
        )
    return payload


def _http_json_if_present(
    response: DorisHTTPResponse,
) -> Mapping[str, Any] | None:
    content_type = response.headers.get("content-type", "")
    text = response.text()
    if "json" not in content_type.lower() and not text.lstrip().startswith("{"):
        return None
    return _http_json(response)


def _api_code(payload: Mapping[str, Any]) -> int | None:
    value = payload.get("code")
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return -1


def _profile_http_failure(status: int) -> QueryRuntimeFailure:
    if status in {401, 403}:
        return QueryRuntimeFailure(
            "Doris denied access to query profile evidence.",
            reason_code="QUERY_PROFILE_PERMISSION_DENIED",
            status_code=403,
        )
    return QueryRuntimeFailure(
        "Doris query profile service is temporarily unavailable.",
        reason_code="QUERY_PROFILE_BACKEND_UNAVAILABLE",
        status_code=503,
        retryable=True,
    )


def _require_explicit_adbc_intent(explicit_adbc: bool) -> None:
    if explicit_adbc is not True:
        raise QueryRuntimeFailure(
            "ADBC requires an explicit end-user request for ADBC or Arrow "
            "Flight SQL; use doris_query.execute_query for normal queries.",
            reason_code="ADBC_EXPLICIT_USER_INTENT_REQUIRED",
            status_code=400,
        )


def _classify_adbc_failure(raw: Any) -> QueryRuntimeFailure:
    error_type = str(raw.get("error_type", "")) if isinstance(raw, Mapping) else ""
    if error_type in {
        "invalid_result_limits",
        "security_violation",
    }:
        return QueryRuntimeFailure(
            "ADBC rejected the query request.",
            reason_code=(
                "QUERY_READ_ONLY_VIOLATION"
                if error_type == "security_violation"
                else "QUERY_ARGUMENT_INVALID"
            ),
            status_code=400,
        )
    if error_type == "timeout":
        return QueryRuntimeFailure(
            "ADBC query execution timed out.",
            reason_code="QUERY_TIMEOUT",
            status_code=504,
            retryable=True,
        )
    if error_type in {
        "missing_fe_port_config",
        "missing_be_port_config",
        "missing_adbc_manager",
        "missing_flight_sql_driver",
        "token_bound_adbc_unsupported",
    }:
        return QueryRuntimeFailure(
            "ADBC is not configured for the active Doris route.",
            reason_code="ADBC_PROVIDER_NOT_CONFIGURED",
            status_code=503,
        )
    return QueryRuntimeFailure(
        "ADBC query execution failed.",
        reason_code="ADBC_EXECUTION_FAILED",
        status_code=502,
    )


def _classify_query_failure(exc: Exception) -> QueryRuntimeFailure:
    if isinstance(exc, QueryRuntimeFailure):
        return exc
    if isinstance(exc, SQLSecurityError | ResultLimitError):
        return _argument_failure("Query arguments are invalid.")
    numeric_code = next(
        (value for value in getattr(exc, "args", ()) if isinstance(value, int)),
        None,
    )
    message = str(exc).lower()
    if numeric_code in {1044, 1045, 1142, 1227} or any(
        marker in message
        for marker in (
            "access denied",
            "permission denied",
            "not authorized",
            "privilege",
        )
    ):
        return QueryRuntimeFailure(
            "Doris denied the query on the active route.",
            reason_code="QUERY_PERMISSION_DENIED",
            status_code=403,
        )
    if numeric_code in {1049, 1054, 1146} or any(
        marker in message
        for marker in (
            "doesn't exist",
            "does not exist",
            "unknown column",
            "unknown database",
            "unknown table",
        )
    ):
        return QueryRuntimeFailure(
            "A referenced Doris query object was not found.",
            reason_code="QUERY_OBJECT_NOT_FOUND",
            status_code=404,
        )
    if numeric_code == 1064 or "syntax error" in message:
        return QueryRuntimeFailure(
            "Doris rejected the SQL syntax.",
            reason_code="QUERY_SYNTAX_ERROR",
            status_code=400,
        )
    if isinstance(exc, TimeoutError | asyncio.TimeoutError):
        return QueryRuntimeFailure(
            "Doris query execution timed out.",
            reason_code="QUERY_TIMEOUT",
            status_code=504,
            retryable=True,
        )
    if isinstance(exc, ConnectionError | OSError) or any(
        marker in message
        for marker in (
            "connection reset",
            "broken pipe",
            "server has gone away",
            "lost connection",
        )
    ):
        return QueryRuntimeFailure(
            "Doris query execution is temporarily unavailable.",
            reason_code="QUERY_BACKEND_UNAVAILABLE",
            status_code=503,
            retryable=True,
        )
    return QueryRuntimeFailure(
        "Doris query execution failed.",
        reason_code="QUERY_EXECUTION_FAILED",
        status_code=502,
    )


__all__ = [
    "DorisQueryRuntime",
    "QueryRuntimeFailure",
    "ReadOnlySQLGuard",
    "ReadOnlyStatement",
]
