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

"""Strict, evidence-bearing runtime for the read-only Search domain."""

from __future__ import annotations

import json
import math
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .db import DorisConnectionManager, QueryResult
from .query_runtime import (
    DorisQueryRuntime,
    QueryRuntimeFailure,
    ReadOnlySQLGuard,
)
from .redaction import redact_sensitive_data
from .security import get_current_auth_context
from .sql_security_utils import (
    SQLSecurityError,
    build_table_reference,
    quote_identifier,
    validate_identifier,
)

_MAX_BYTES = 2 * 1024 * 1024
_MAX_QUERY_TEXT_BYTES = 16 * 1024
_MAX_PREVIEW_TEXT_BYTES = 64 * 1024
_MAX_TOP_K = 1_000
_DEFAULT_TOP_K = 10
_MAX_VECTOR_DIMENSION = 4_096
_MAX_FIELDS = 32
_MAX_RETURN_FIELDS = 64
_MAX_FILTERS = 32
_MAX_FILTER_VALUES = 100
_MAX_EXPLAIN_ROWS = 2_000
_BUILT_IN_ANALYZERS = frozenset(
    {
        "none",
        "standard",
        "english",
        "chinese",
        "unicode",
        "icu",
        "basic",
        "ik",
    }
)
_BACKWARD_COMPATIBLE_PARSERS = frozenset(
    {
        "english",
        "chinese",
        "unicode",
    }
)
_MATCH_OPERATORS = {
    "any": "MATCH_ANY",
    "all": "MATCH_ALL",
    "phrase": "MATCH_PHRASE",
    "phrase_prefix": "MATCH_PHRASE_PREFIX",
}
_FILTER_OPERATORS = {
    "eq": "=",
    "ne": "!=",
    "gt": ">",
    "gte": ">=",
    "lt": "<",
    "lte": "<=",
}
_NULL_FILTER_OPERATORS = {
    "is_null": "IS NULL",
    "is_not_null": "IS NOT NULL",
}
_SET_FILTER_OPERATORS = {
    "in": "IN",
    "not_in": "NOT IN",
}
_VECTOR_METRICS = {
    "l2_distance": ("l2_distance_approximate", "ASC"),
    "inner_product": ("inner_product_approximate", "DESC"),
}
_PROPERTY_PAIR = re.compile(
    r'"(?P<key>[A-Za-z_][A-Za-z0-9_]*)"\s*=\s*"(?P<value>(?:[^"\\]|\\.)*)"'
)
_SIMPLE_SOURCE = re.compile(
    r"\bFROM\s+"
    r"(?:(?P<database>`?[A-Za-z_][A-Za-z0-9_]*`?)\s*\.\s*)?"
    r"(?P<table>`?[A-Za-z_][A-Za-z0-9_]*`?)",
    re.IGNORECASE,
)


class SearchRuntimeFailure(RuntimeError):
    """Sanitized Search-domain failure with a stable reason code."""

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
class _SearchIndex:
    name: str
    index_type: str
    columns: tuple[str, ...]
    properties: Mapping[str, str]
    comment: str | None

    @property
    def is_inverted(self) -> bool:
        return self.index_type == "INVERTED"

    @property
    def is_ann(self) -> bool:
        return self.index_type == "ANN"

    def to_wire(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "index_type": self.index_type,
            "columns": list(self.columns),
            "properties": dict(self.properties),
            "comment": self.comment,
            "parser": self.properties.get("parser"),
            "analyzer": (
                self.properties.get("analyzer")
                or self.properties.get("built_in_analyzer")
            ),
            "metric_type": self.properties.get("metric_type"),
            "dimension": _as_int(self.properties.get("dim")),
        }


@dataclass(frozen=True, slots=True)
class _CompiledSearch:
    sql: str
    params: tuple[Any, ...]
    database: str
    table: str
    mode: str
    top_k: int
    text_fields: tuple[str, ...]
    vector_field: str | None
    vector_metric: str | None
    vector_dimension: int | None
    return_fields: tuple[str, ...]
    indexes: tuple[_SearchIndex, ...]


class DorisSearchRuntime:
    """Run bounded Doris-native text, vector, hybrid, and diagnostic reads."""

    def __init__(
        self,
        connection_manager: DorisConnectionManager,
        query_runtime: DorisQueryRuntime,
    ) -> None:
        self._connection_manager = connection_manager
        self._query_runtime = query_runtime
        self._session_prefix = f"formal_search_{uuid.uuid4().hex[:8]}"

    async def search_data(
        self,
        *,
        database: str,
        table: str,
        query: str | None,
        mode: str,
        fields: Sequence[str] | None,
        vector: Sequence[Any] | None,
        vector_field: str | None,
        text_operator: str | None,
        top_k: int | None,
        filters: Mapping[str, Any] | None,
        return_fields: Sequence[str] | None,
    ) -> dict[str, Any]:
        """Execute one target-index-validated, bounded search request."""
        compiled = await self._compile_search(
            {
                "database": database,
                "table": table,
                "query": query,
                "mode": mode,
                "fields": fields,
                "vector": vector,
                "vector_field": vector_field,
                "text_operator": text_operator,
                "top_k": top_k,
                "filters": filters,
                "return_fields": return_fields,
            }
        )
        result = await self._execute(
            compiled.sql,
            params=compiled.params,
            max_rows=compiled.top_k + 1,
            mask_result=True,
        )
        rows = [
            dict(row)
            for row in (result.data or ())
            if isinstance(row, Mapping)
        ]
        driver_truncated = bool(result.metadata.get("truncated"))
        overfetched = len(rows) > compiled.top_k
        visible_rows = rows[: compiled.top_k]
        columns = [
            {"name": str(name)}
            for name in result.metadata.get(
                "columns",
                list(visible_rows[0]) if visible_rows else [],
            )
        ]
        warnings: list[str] = []
        if driver_truncated:
            warnings.append(
                "Doris stopped reading at the configured response boundary."
            )
        evidence: list[Mapping[str, Any]] = [
            {
                "source": "SHOW INDEX",
                "kind": "target_index_metadata",
                "indexes": [
                    index.name
                    for index in compiled.indexes
                    if (
                        index.is_inverted
                        and set(index.columns) & set(compiled.text_fields)
                    )
                    or (
                        index.is_ann
                        and compiled.vector_field in index.columns
                    )
                ],
            },
            {
                "source": "doris_sql",
                "kind": "bounded_search",
                "mode": compiled.mode,
            },
        ]
        return _result(
            {
                "columns": columns,
                "rows": visible_rows,
                "row_count": len(visible_rows),
                "truncated": driver_truncated or overfetched,
            },
            source="doris_native_search",
            warnings=warnings,
            metadata={
                "database": compiled.database,
                "table": compiled.table,
                "mode": compiled.mode,
                "top_k": compiled.top_k,
                "text_fields": list(compiled.text_fields),
                "vector_field": compiled.vector_field,
                "vector_metric": compiled.vector_metric,
                "vector_dimension": compiled.vector_dimension,
                "return_fields": list(compiled.return_fields),
                "invented_scores": False,
                "execution_time_seconds": result.execution_time,
            },
            evidence=evidence,
        )

    async def preview_text_analysis(
        self,
        *,
        text: str,
        analyzer: str | None,
        tokenizer: str | None,
        token_filters: Sequence[str] | None,
    ) -> dict[str, Any]:
        """Run Doris ``TOKENIZE`` without creating analyzer components."""
        normalized_text = _required_text(
            text,
            "text",
            maximum_bytes=_MAX_PREVIEW_TEXT_BYTES,
        )
        requested_filters = _identifier_sequence(
            token_filters,
            "token filter",
            maximum=16,
        )
        properties: dict[str, str]
        component_evidence: list[dict[str, Any]] = []

        if analyzer is not None:
            analyzer_name = _required_identifier(analyzer, "analyzer name")
            analyzer_key = analyzer_name.casefold()
            if analyzer_key in _BUILT_IN_ANALYZERS:
                if tokenizer is not None or requested_filters:
                    raise _argument_failure(
                        "Built-in analyzers cannot be combined with custom "
                        "tokenizer or token-filter names."
                    )
                properties = _built_in_analyzer_properties(analyzer_key)
            else:
                definition = await self._custom_analyzer_definition(
                    analyzer_name
                )
                if definition is None:
                    raise SearchRuntimeFailure(
                        "The requested custom Doris analyzer does not exist.",
                        reason_code="SEARCH_ANALYZER_NOT_FOUND",
                        status_code=404,
                    )
                observed_tokenizer = _optional_identifier_value(
                    _value(definition, "tokenizer")
                )
                observed_filters = _split_component_names(
                    _value(
                        definition,
                        "token_filter",
                        "token_filters",
                        "tokenfilters",
                    )
                )
                if tokenizer is not None:
                    tokenizer_name = _required_identifier(
                        tokenizer,
                        "tokenizer name",
                    )
                    if tokenizer_name.casefold() != (
                        observed_tokenizer or ""
                    ).casefold():
                        raise _argument_failure(
                            "The requested tokenizer does not match the "
                            "recorded custom analyzer definition."
                        )
                if requested_filters and tuple(
                    item.casefold() for item in requested_filters
                ) != tuple(item.casefold() for item in observed_filters):
                    raise _argument_failure(
                        "The requested token filters do not match the recorded "
                        "custom analyzer definition."
                    )
                properties = {"analyzer": analyzer_name}
                component_evidence.append(
                    {
                        "source": "SHOW INVERTED INDEX ANALYZER",
                        "analyzer": analyzer_name,
                        "tokenizer": observed_tokenizer,
                        "token_filters": list(observed_filters),
                    }
                )
        else:
            tokenizer_name = (
                "unicode"
                if tokenizer is None
                else _required_identifier(tokenizer, "tokenizer name").casefold()
            )
            if tokenizer_name not in _BUILT_IN_ANALYZERS:
                raise _argument_failure(
                    "A custom tokenizer must be referenced through an existing "
                    "custom analyzer."
                )
            if requested_filters:
                raise _argument_failure(
                    "Token filters require an existing custom analyzer; this "
                    "read-only tool does not create analyzer components."
                )
            properties = _built_in_analyzer_properties(tokenizer_name)

        property_string = ",".join(
            f'"{key}"="{_escape_property_value(value)}"'
            for key, value in properties.items()
        )
        result = await self._execute(
            "SELECT TOKENIZE(%s, %s) AS tokens",
            params=(normalized_text, property_string),
            max_rows=1,
            mask_result=False,
        )
        raw_tokens = (
            _value(result.data[0], "tokens")
            if result.data and isinstance(result.data[0], Mapping)
            else None
        )
        tokens = _normalize_tokens(raw_tokens)
        return _result(
            {
                "tokens": tokens,
                "token_count": len(tokens),
                "analysis": {
                    "properties": properties,
                    "custom_analyzer": properties.get("analyzer"),
                },
            },
            source="doris_tokenize",
            metadata={
                "input_bytes": len(normalized_text.encode("utf-8")),
                "invented_tokens": False,
            },
            evidence=[
                {
                    "source": "doris_sql",
                    "kind": "TOKENIZE",
                    "properties": properties,
                },
                *component_evidence,
            ],
        )

    async def inspect_search_indexes(
        self,
        *,
        database: str,
        table: str,
        index: str | None,
    ) -> dict[str, Any]:
        """Return normalized inverted/ANN metadata and recorded build tasks."""
        database_name = _required_identifier(database, "database name")
        table_name = _required_identifier(table, "table name")
        index_name = (
            None
            if index is None
            else _required_identifier(index, "index name")
        )
        indexes = await self._read_indexes(database_name, table_name)
        selected = tuple(
            candidate
            for candidate in indexes
            if index_name is None
            or candidate.name.casefold() == index_name.casefold()
        )
        if index_name is not None and not selected:
            raise SearchRuntimeFailure(
                "The requested Doris search index does not exist.",
                reason_code="SEARCH_INDEX_NOT_FOUND",
                status_code=404,
            )

        build_tasks: list[dict[str, Any]] = []
        warnings: list[str] = []
        try:
            build_result = await self._execute(
                "SHOW BUILD INDEX WHERE TableName = %s",
                params=(table_name,),
                max_rows=200,
                mask_result=False,
                database_context=database_name,
            )
        except SearchRuntimeFailure as exc:
            warnings.append(
                "Index build-task evidence is unavailable "
                f"({exc.reason_code})."
            )
        else:
            build_tasks = [
                _normalized_build_task(row)
                for row in (build_result.data or ())
                if isinstance(row, Mapping)
            ]

        inverted = [candidate for candidate in selected if candidate.is_inverted]
        ann = [candidate for candidate in selected if candidate.is_ann]
        capabilities = {
            "text": bool(inverted),
            "vector": bool(ann),
            "hybrid": bool(inverted and ann),
            "metrics": sorted(
                {
                    metric
                    for candidate in ann
                    if (
                        metric := candidate.properties.get("metric_type")
                    )
                }
            ),
        }
        return _result(
            {
                "items": [candidate.to_wire() for candidate in selected],
                "build_tasks": build_tasks,
                "capabilities": capabilities,
                "truncated": False,
            },
            source="doris_search_index_metadata",
            warnings=warnings,
            metadata={
                "database": database_name,
                "table": table_name,
                "index_filter": index_name,
                "index_count": len(selected),
                "build_task_count": len(build_tasks),
            },
            evidence=[
                {
                    "source": "SHOW INDEX",
                    "rows_observed": len(indexes),
                },
                {
                    "source": "SHOW BUILD INDEX",
                    "rows_observed": len(build_tasks),
                    "available": not warnings,
                },
            ],
        )

    async def diagnose_search_query(
        self,
        *,
        sql: str | None,
        search_request: Mapping[str, Any] | None,
        include_profile: bool,
    ) -> dict[str, Any]:
        """Combine target index metadata, EXPLAIN, and optional profile facts."""
        if bool(sql) == bool(search_request):
            raise _argument_failure(
                "Provide exactly one of sql or search_request."
            )

        compiled: _CompiledSearch | None = None
        database: str | None = None
        table: str | None = None
        params: tuple[Any, ...] | None = None
        warnings: list[str] = []
        evidence: list[dict[str, Any]] = []
        indexes: tuple[_SearchIndex, ...] = ()

        if search_request is not None:
            compiled = await self._compile_search(search_request)
            query_sql = compiled.sql
            params = compiled.params
            database = compiled.database
            table = compiled.table
            indexes = compiled.indexes
        else:
            try:
                statement = ReadOnlySQLGuard.validate(
                    str(sql),
                    query_target=True,
                )
            except QueryRuntimeFailure as exc:
                raise SearchRuntimeFailure(
                    str(exc),
                    reason_code="SEARCH_ARGUMENT_INVALID",
                    status_code=400,
                ) from exc
            if statement.operation != "SELECT":
                raise _argument_failure(
                    "Search diagnosis accepts a SELECT query only."
                )
            query_sql = statement.sql
            source = _simple_source(statement.sql)
            if source is not None:
                database, table = source
                if database is not None:
                    try:
                        indexes = await self._read_indexes(database, table)
                    except SearchRuntimeFailure as exc:
                        warnings.append(
                            "Target index metadata is unavailable "
                            f"({exc.reason_code})."
                        )
            if not indexes:
                warnings.append(
                    "Raw SQL diagnosis could not bind authoritative target "
                    "index metadata; provide search_request for exact coverage."
                )

        explain = await self._execute(
            f"EXPLAIN {query_sql}",
            params=params,
            max_rows=_MAX_EXPLAIN_ROWS,
            mask_result=False,
            database_context=database,
        )
        plan_rows = [
            dict(row)
            for row in (explain.data or ())
            if isinstance(row, Mapping)
        ]
        plan_text = "\n".join(
            " | ".join(str(value) for value in row.values())
            for row in plan_rows
        )
        facets = _search_plan_facets(plan_text)
        evidence.append(
            {
                "source": "doris_sql",
                "kind": "EXPLAIN",
                "plan_rows": len(plan_rows),
            }
        )
        if indexes:
            evidence.append(
                {
                    "source": "SHOW INDEX",
                    "kind": "target_index_metadata",
                    "indexes": [candidate.name for candidate in indexes],
                }
            )

        findings = _diagnostic_findings(
            compiled=compiled,
            indexes=indexes,
            facets=facets,
            query_sql=query_sql,
        )
        profile: Mapping[str, Any] | None = None
        if include_profile:
            if search_request is not None:
                warnings.append(
                    "Profile execution is not performed for parameter-bound "
                    "structured requests; EXPLAIN and index evidence are "
                    "returned without weakening parameter safety."
                )
            else:
                try:
                    profile_result = await self._query_runtime.get_query_profile(
                        sql=query_sql,
                        database=database,
                        include_operator_tree=False,
                    )
                except QueryRuntimeFailure as exc:
                    warnings.append(
                        "Query-profile evidence is unavailable "
                        f"({exc.reason_code})."
                    )
                else:
                    profile = profile_result.get("data")
                    evidence.extend(profile_result.get("evidence", []))
                    warnings.extend(profile_result.get("warnings", []))

        if not facets["ann_pushdown_observed"] and compiled is not None and (
            compiled.mode in {"vector", "hybrid"}
        ):
            warnings.append(
                "The plan did not expose Doris ANN SORT INFO for the "
                "requested vector path."
            )
        return _result(
            {
                "scope": {
                    "database": database,
                    "table": table,
                    "mode": compiled.mode if compiled is not None else "raw_sql",
                },
                "indexes": [candidate.to_wire() for candidate in indexes],
                "explain": {
                    "facets": facets,
                    "plan_rows": plan_rows,
                    "truncated": bool(explain.metadata.get("truncated")),
                },
                "profile": profile,
                "findings": findings,
            },
            source="deterministic_search_diagnosis",
            warnings=warnings,
            metadata={
                "include_profile": include_profile,
                "profile_observed": profile is not None,
                "invented_index_hits": False,
                "execution_time_seconds": explain.execution_time,
            },
            evidence=evidence,
        )

    async def _compile_search(
        self,
        request: Mapping[str, Any],
    ) -> _CompiledSearch:
        if not isinstance(request, Mapping):
            raise _argument_failure("search_request must be an object.")
        database = _required_identifier(
            request.get("database"),
            "database name",
        )
        table = _required_identifier(request.get("table"), "table name")
        mode = str(request.get("mode", "")).casefold()
        if mode not in {"text", "vector", "hybrid"}:
            raise _argument_failure(
                "mode must be text, vector, or hybrid."
            )
        top_k = _bounded_integer(
            request.get("top_k"),
            default=_DEFAULT_TOP_K,
            minimum=1,
            maximum=_MAX_TOP_K,
            label="top_k",
        )
        columns = await self._read_columns(database, table)
        column_names = set(columns)
        indexes = await self._read_indexes(database, table)

        text_fields: tuple[str, ...] = ()
        query: str | None = None
        match_operator = _MATCH_OPERATORS.get(
            str(request.get("text_operator") or "any").casefold()
        )
        if match_operator is None:
            raise _argument_failure("text_operator is invalid.")
        if mode in {"text", "hybrid"}:
            query = _required_text(
                request.get("query"),
                "query",
                maximum_bytes=_MAX_QUERY_TEXT_BYTES,
            )
            text_fields = _identifier_sequence(
                request.get("fields"),
                "search field",
                maximum=_MAX_FIELDS,
                required=True,
            )
            _require_known_columns(text_fields, column_names)
            indexed_text_fields = {
                column
                for candidate in indexes
                if candidate.is_inverted
                for column in candidate.columns
            }
            missing_indexes = [
                field
                for field in text_fields
                if field not in indexed_text_fields
            ]
            if missing_indexes:
                raise SearchRuntimeFailure(
                    "Every requested text field must have a visible inverted "
                    "index.",
                    reason_code="SEARCH_TEXT_INDEX_REQUIRED",
                    status_code=409,
                )
        elif request.get("query") not in (None, ""):
            raise _argument_failure(
                "query is only valid for text or hybrid mode."
            )

        vector_field: str | None = None
        vector_values: tuple[float, ...] = ()
        metric: str | None = None
        vector_dimension: int | None = None
        if mode in {"vector", "hybrid"}:
            vector_values = _vector(request.get("vector"))
            vector_field = _resolve_vector_field(
                request.get("vector_field"),
                indexes,
            )
            if vector_field not in column_names:
                raise _argument_failure(
                    "The requested vector field is not visible on the table."
                )
            ann_index = _ann_index_for_field(indexes, vector_field)
            if ann_index is None:
                raise SearchRuntimeFailure(
                    "The requested vector field must have a visible ANN index.",
                    reason_code="SEARCH_ANN_INDEX_REQUIRED",
                    status_code=409,
                )
            metric = str(
                ann_index.properties.get("metric_type", "")
            ).casefold()
            if metric not in _VECTOR_METRICS:
                raise SearchRuntimeFailure(
                    "The ANN index uses an unsupported or missing metric.",
                    reason_code="SEARCH_ANN_METRIC_UNSUPPORTED",
                    status_code=501,
                )
            vector_dimension = _as_int(ann_index.properties.get("dim"))
            if vector_dimension is None:
                raise SearchRuntimeFailure(
                    "The ANN index does not expose a valid vector dimension.",
                    reason_code="SEARCH_ANN_DIMENSION_UNKNOWN",
                    status_code=409,
                )
            if len(vector_values) != vector_dimension:
                raise _argument_failure(
                    "The query vector dimension does not match the ANN index."
                )
        elif request.get("vector") not in (None, []):
            raise _argument_failure(
                "vector is only valid for vector or hybrid mode."
            )

        return_fields = _return_fields(
            request.get("return_fields"),
            columns,
            vector_field=vector_field,
        )
        select_parts = [
            quote_identifier(field, "return field")
            for field in return_fields
        ]
        where_parts: list[str] = []
        select_params: list[Any] = []
        where_params: list[Any] = []
        if text_fields and query is not None:
            field_predicates = [
                f"{quote_identifier(field, 'search field')} "
                f"{match_operator} %s"
                for field in text_fields
            ]
            where_parts.append("(" + " OR ".join(field_predicates) + ")")
            where_params.extend(query for _ in field_predicates)

        filter_sql, filter_params = _compile_filters(
            request.get("filters"),
            column_names,
        )
        where_parts.extend(filter_sql)
        where_params.extend(filter_params)

        order_sql = ""
        if vector_field is not None and metric is not None:
            function_name, direction = _VECTOR_METRICS[metric]
            distance_alias = "__mcp_vector_distance"
            if distance_alias in column_names:
                raise SearchRuntimeFailure(
                    "The table uses a reserved Search result alias.",
                    reason_code="SEARCH_RESULT_ALIAS_CONFLICT",
                    status_code=409,
                )
            vector_expression = "CAST(%s AS ARRAY<FLOAT>)"
            # SQL sink audit: field is validated and quoted; function, alias,
            # and ordering are selected from fixed local maps; the vector is a
            # bound JSON value before DorisConnection.execute.
            select_parts.append(  # nosec B608
                f"{function_name}("
                f"{quote_identifier(vector_field, 'vector field')}, "
                f"{vector_expression}) AS `{distance_alias}`"
            )
            select_params.append(
                json.dumps(
                    list(vector_values),
                    ensure_ascii=True,
                    separators=(",", ":"),
                )
            )
            order_sql = f" ORDER BY `{distance_alias}` {direction}"

        table_reference = build_table_reference(
            table,
            db_name=database,
        )
        where_sql = (
            " WHERE " + " AND ".join(where_parts)
            if where_parts
            else ""
        )
        # SQL sink audit: all identifiers pass quote_identifier or
        # build_table_reference; predicates/operators are local allowlists;
        # every caller value remains bound at connection.execute; limit is a
        # bounded integer.
        sql = (
            f"SELECT {', '.join(select_parts)} FROM {table_reference}"  # nosec B608
            f"{where_sql}{order_sql} LIMIT {top_k + 1}"
        )
        return _CompiledSearch(
            sql=sql,
            params=(*select_params, *where_params),
            database=database,
            table=table,
            mode=mode,
            top_k=top_k,
            text_fields=text_fields,
            vector_field=vector_field,
            vector_metric=metric,
            vector_dimension=vector_dimension,
            return_fields=return_fields,
            indexes=indexes,
        )

    async def _read_columns(
        self,
        database: str,
        table: str,
    ) -> dict[str, str]:
        result = await self._execute(
            (
                "SELECT COLUMN_NAME, DATA_TYPE "
                "FROM information_schema.columns "
                "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s "
                "ORDER BY ORDINAL_POSITION LIMIT 2048"
            ),
            params=(database, table),
            max_rows=2_048,
            mask_result=False,
        )
        columns = {
            str(_value(row, "column_name", "COLUMN_NAME")): str(
                _value(row, "data_type", "DATA_TYPE") or ""
            )
            for row in (result.data or ())
            if isinstance(row, Mapping)
            and _value(row, "column_name", "COLUMN_NAME") not in (None, "")
        }
        if not columns:
            raise SearchRuntimeFailure(
                "The requested Doris table does not exist or is not visible.",
                reason_code="SEARCH_TABLE_NOT_FOUND",
                status_code=404,
            )
        return columns

    async def _read_indexes(
        self,
        database: str,
        table: str,
    ) -> tuple[_SearchIndex, ...]:
        table_reference = build_table_reference(
            table,
            db_name=database,
        )
        # SQL sink audit: build_table_reference validates and quotes both
        # identifiers before _execute sends this metadata read to
        # connection.execute; no caller values are interpolated.
        result = await self._execute(
            f"SHOW INDEX FROM {table_reference}",  # nosec B608
            max_rows=512,
            mask_result=False,
        )
        grouped: dict[tuple[str, str], dict[str, Any]] = {}
        for row in result.data or ():
            index_type = str(
                _value(row, "index_type", "Index_type") or ""
            ).upper()
            if index_type not in {"INVERTED", "ANN"}:
                continue
            name = str(_value(row, "key_name", "Key_name") or "")
            column = str(
                _value(row, "column_name", "Column_name") or ""
            )
            if not name or not column:
                continue
            key = (name, index_type)
            state = grouped.setdefault(
                key,
                {
                    "columns": [],
                    "properties": {},
                    "comment": None,
                },
            )
            if column not in state["columns"]:
                state["columns"].append(column)
            state["properties"].update(
                _parse_properties(
                    _value(row, "properties", "Properties")
                )
            )
            comment = _value(row, "comment", "Comment")
            if comment not in (None, ""):
                state["comment"] = str(comment)
        return tuple(
            _SearchIndex(
                name=name,
                index_type=index_type,
                columns=tuple(state["columns"]),
                properties=dict(state["properties"]),
                comment=state["comment"],
            )
            for (name, index_type), state in sorted(grouped.items())
        )

    async def _custom_analyzer_definition(
        self,
        analyzer_name: str,
    ) -> Mapping[str, Any] | None:
        result = await self._execute(
            "SHOW INVERTED INDEX ANALYZER",
            max_rows=512,
            mask_result=False,
        )
        for row in result.data or ():
            normalized = _normalized_row(row)
            name = _value(
                normalized,
                "name",
                "analyzer_name",
                "analyzer",
            )
            if (
                isinstance(name, str)
                and name.casefold() == analyzer_name.casefold()
            ):
                properties = _parse_properties(
                    _value(normalized, "properties")
                )
                return {**normalized, **properties}
        return None

    async def _execute(
        self,
        sql: str,
        *,
        params: Mapping[str, Any] | tuple[Any, ...] | None = None,
        max_rows: int,
        mask_result: bool,
        database_context: str | None = None,
    ) -> QueryResult:
        auth_context = get_current_auth_context()
        session_id = f"{self._session_prefix}:{uuid.uuid4().hex[:8]}"
        try:
            async with (
                self._connection_manager.get_connection_context_for_auth_context(
                    session_id,
                    auth_context,
                ) as connection
            ):
                if database_context is not None:
                    safe_database = quote_identifier(
                        database_context,
                        "database name",
                    )
                    await connection.execute(
                        f"USE {safe_database}",
                        auth_context=auth_context,
                        mask_result=False,
                        max_rows=1,
                        max_bytes=1_024,
                    )
                return await connection.execute(
                    sql,
                    params=params,
                    auth_context=auth_context,
                    mask_result=mask_result,
                    max_rows=max_rows,
                    max_bytes=_MAX_BYTES,
                )
        except Exception as exc:
            raise _classify_failure(exc) from exc


def _result(
    data: Mapping[str, Any],
    *,
    source: str,
    warnings: Sequence[str] = (),
    metadata: Mapping[str, Any] | None = None,
    evidence: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    unique_warnings = list(dict.fromkeys(str(item) for item in warnings))
    response: dict[str, Any] = {
        "status": "partial" if unique_warnings else "success",
        "data": redact_sensitive_data(dict(data)),
        "warnings": unique_warnings,
        "metadata": {
            "source": source,
            **dict(metadata or {}),
        },
    }
    if evidence is not None:
        response["evidence"] = [
            redact_sensitive_data(dict(item)) for item in evidence
        ]
    return response


def _required_identifier(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise _argument_failure(f"{label} must be a non-empty string.")
    try:
        return validate_identifier(value, label)
    except SQLSecurityError as exc:
        raise _argument_failure(f"{label} is invalid.") from exc


def _required_text(
    value: Any,
    label: str,
    *,
    maximum_bytes: int,
) -> str:
    if not isinstance(value, str) or not value.strip():
        raise _argument_failure(f"{label} must be a non-empty string.")
    normalized = value.strip()
    if len(normalized.encode("utf-8")) > maximum_bytes:
        raise _argument_failure(f"{label} exceeds the maximum accepted size.")
    return normalized


def _bounded_integer(
    value: Any,
    *,
    default: int,
    minimum: int,
    maximum: int,
    label: str,
) -> int:
    if value is None:
        return default
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < minimum
        or value > maximum
    ):
        raise _argument_failure(
            f"{label} must be between {minimum} and {maximum}."
        )
    return int(value)


def _identifier_sequence(
    values: Any,
    label: str,
    *,
    maximum: int,
    required: bool = False,
) -> tuple[str, ...]:
    if values is None:
        if required:
            raise _argument_failure(f"At least one {label} is required.")
        return ()
    if (
        not isinstance(values, Sequence)
        or isinstance(values, str | bytes)
        or not values
        or len(values) > maximum
    ):
        raise _argument_failure(
            f"{label} values must be a non-empty bounded array."
        )
    normalized = tuple(
        _required_identifier(value, label)
        for value in values
    )
    if len(set(normalized)) != len(normalized):
        raise _argument_failure(f"{label} values must be unique.")
    return normalized


def _vector(value: Any) -> tuple[float, ...]:
    if (
        not isinstance(value, Sequence)
        or isinstance(value, str | bytes)
        or not value
        or len(value) > _MAX_VECTOR_DIMENSION
    ):
        raise _argument_failure(
            "vector must be a non-empty bounded numeric array."
        )
    normalized: list[float] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int | float):
            raise _argument_failure("vector values must be numbers.")
        number = float(item)
        if not math.isfinite(number):
            raise _argument_failure("vector values must be finite.")
        normalized.append(number)
    return tuple(normalized)


def _return_fields(
    values: Any,
    columns: Mapping[str, str],
    *,
    vector_field: str | None,
) -> tuple[str, ...]:
    if values is None:
        selected = tuple(
            name
            for name, data_type in columns.items()
            if name != vector_field
            and not data_type.casefold().startswith("array<float")
        )[:_MAX_RETURN_FIELDS]
        if not selected:
            raise _argument_failure(
                "return_fields is required when no scalar columns are visible."
            )
        return selected
    selected = _identifier_sequence(
        values,
        "return field",
        maximum=_MAX_RETURN_FIELDS,
        required=True,
    )
    _require_known_columns(selected, set(columns))
    return selected


def _require_known_columns(
    requested: Sequence[str],
    available: set[str],
) -> None:
    if any(column not in available for column in requested):
        raise _argument_failure(
            "One or more requested fields are not visible on the table."
        )


def _resolve_vector_field(
    requested: Any,
    indexes: Sequence[_SearchIndex],
) -> str:
    if requested is not None:
        return _required_identifier(requested, "vector field")
    candidates = sorted(
        {
            column
            for index in indexes
            if index.is_ann
            for column in index.columns
        }
    )
    if len(candidates) != 1:
        raise _argument_failure(
            "vector_field is required unless exactly one ANN-indexed field "
            "is visible."
        )
    return candidates[0]


def _ann_index_for_field(
    indexes: Sequence[_SearchIndex],
    field: str,
) -> _SearchIndex | None:
    candidates = [
        index
        for index in indexes
        if index.is_ann and field in index.columns
    ]
    if len(candidates) != 1:
        return None
    return candidates[0]


def _compile_filters(
    value: Any,
    columns: set[str],
) -> tuple[list[str], list[Any]]:
    if value is None:
        return [], []
    if not isinstance(value, Mapping) or len(value) > _MAX_FILTERS:
        raise _argument_failure("filters must be a bounded object.")
    predicates: list[str] = []
    params: list[Any] = []
    for raw_field, raw_rule in value.items():
        field = _required_identifier(raw_field, "filter field")
        if field not in columns:
            raise _argument_failure(
                "One or more filter fields are not visible on the table."
            )
        quoted = quote_identifier(field, "filter field")
        if not isinstance(raw_rule, Mapping):
            _validate_scalar(raw_rule)
            predicates.append(f"{quoted} = %s")
            params.append(raw_rule)
            continue

        unknown = set(raw_rule) - {"operator", "value", "values"}
        if unknown:
            raise _argument_failure(
                "Filter rules contain unsupported properties."
            )
        operator = str(raw_rule.get("operator", "")).casefold()
        if operator in _FILTER_OPERATORS:
            if "value" not in raw_rule or "values" in raw_rule:
                raise _argument_failure(
                    "Scalar filter operators require exactly one value."
                )
            scalar = raw_rule["value"]
            _validate_scalar(scalar)
            predicates.append(
                f"{quoted} {_FILTER_OPERATORS[operator]} %s"
            )
            params.append(scalar)
            continue
        if operator in _SET_FILTER_OPERATORS:
            values = raw_rule.get("values")
            if (
                not isinstance(values, Sequence)
                or isinstance(values, str | bytes)
                or not values
                or len(values) > _MAX_FILTER_VALUES
                or "value" in raw_rule
            ):
                raise _argument_failure(
                    "Set filter operators require a bounded values array."
                )
            for scalar in values:
                _validate_scalar(scalar)
            placeholders = ", ".join("%s" for _ in values)
            predicates.append(
                f"{quoted} {_SET_FILTER_OPERATORS[operator]} "
                f"({placeholders})"
            )
            params.extend(values)
            continue
        if operator in _NULL_FILTER_OPERATORS:
            if "value" in raw_rule or "values" in raw_rule:
                raise _argument_failure(
                    "Null filter operators do not accept values."
                )
            predicates.append(
                f"{quoted} {_NULL_FILTER_OPERATORS[operator]}"
            )
            continue
        raise _argument_failure("Filter operator is invalid.")
    return predicates, params


def _validate_scalar(value: Any) -> None:
    if value is not None and not isinstance(
        value,
        str | int | float | bool,
    ):
        raise _argument_failure("Filter values must be JSON scalars.")
    if isinstance(value, float) and not math.isfinite(value):
        raise _argument_failure("Filter numbers must be finite.")
    if isinstance(value, str) and len(value.encode("utf-8")) > 8_192:
        raise _argument_failure("Filter text exceeds the maximum accepted size.")


def _parse_properties(value: Any) -> dict[str, str]:
    if isinstance(value, Mapping):
        return {
            str(key).casefold(): str(item)
            for key, item in value.items()
        }
    if not isinstance(value, str):
        return {}
    return {
        match.group("key").casefold(): match.group("value")
        .replace('\\"', '"')
        .replace("\\\\", "\\")
        for match in _PROPERTY_PAIR.finditer(value)
    }


def _normalized_build_task(row: Mapping[str, Any]) -> dict[str, Any]:
    normalized = _normalized_row(row)
    return {
        "job_id": normalized.get("job_id"),
        "table": normalized.get("table_name"),
        "partition": normalized.get("partition_name"),
        "state": normalized.get("state"),
        "progress": normalized.get("progress"),
        "message": normalized.get("msg"),
        "create_time": _json_value(normalized.get("create_time")),
        "finish_time": _json_value(normalized.get("finish_time")),
        "alter_indexes": normalized.get("alter_inverted_indexes"),
    }


def _normalize_tokens(value: Any) -> list[dict[str, Any]]:
    parsed = value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise SearchRuntimeFailure(
                "Doris TOKENIZE returned an invalid payload.",
                reason_code="SEARCH_TOKENIZE_INVALID_RESPONSE",
                status_code=502,
            ) from exc
    if not isinstance(parsed, Sequence) or isinstance(parsed, str | bytes):
        raise SearchRuntimeFailure(
            "Doris TOKENIZE returned an invalid payload.",
            reason_code="SEARCH_TOKENIZE_INVALID_RESPONSE",
            status_code=502,
        )
    tokens: list[dict[str, Any]] = []
    for offset, item in enumerate(parsed):
        if isinstance(item, Mapping):
            token = item.get("token")
            if token is None:
                continue
            normalized: dict[str, Any] = {"term": str(token)}
            if item.get("position") is not None:
                normalized["position"] = item["position"]
            if item.get("type") is not None:
                normalized["type"] = item["type"]
        else:
            normalized = {"term": str(item), "position": offset}
        tokens.append(normalized)
        if len(tokens) >= 10_000:
            break
    return tokens


def _built_in_analyzer_properties(name: str) -> dict[str, str]:
    key = "parser" if name in _BACKWARD_COMPATIBLE_PARSERS else (
        "built_in_analyzer"
    )
    return {key: name}


def _split_component_names(value: Any) -> tuple[str, ...]:
    parsed = value
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith("["):
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError:
                parsed = value
        if isinstance(parsed, str):
            return tuple(
                item.strip()
                for item in parsed.split(",")
                if item.strip()
            )
    if isinstance(parsed, Sequence) and not isinstance(parsed, str | bytes):
        return tuple(
            str(item).strip()
            for item in parsed
            if str(item).strip()
        )
    return ()


def _optional_identifier_value(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return validate_identifier(value, "component name")
    except SQLSecurityError:
        return None


def _escape_property_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _search_plan_facets(plan_text: str) -> dict[str, Any]:
    upper = plan_text.upper()
    match_operators = sorted(
        {
            operator
            for operator in (
                "MATCH_ANY",
                "MATCH_ALL",
                "MATCH_PHRASE",
                "MATCH_PHRASE_PREFIX",
                "SEARCH",
            )
            if operator in upper
        }
    )
    return {
        "ann_pushdown_observed": "ANN SORT INFO" in upper,
        "ann_sort_limit_observed": "ANN SORT LIMIT" in upper,
        "text_match_predicate_observed": bool(match_operators),
        "match_operators": match_operators,
        "olap_scan_observed": "OLAPSCANNODE" in upper,
        "profile_required_for_inverted_hit_confirmation": True,
    }


def _diagnostic_findings(
    *,
    compiled: _CompiledSearch | None,
    indexes: Sequence[_SearchIndex],
    facets: Mapping[str, Any],
    query_sql: str,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if compiled is not None and compiled.text_fields:
        findings.append(
            {
                "severity": "info",
                "code": "TEXT_INDEX_CONFIGURED_AND_MATCH_PLANNED",
                "message": (
                    "Visible inverted indexes cover the requested text fields "
                    "and EXPLAIN preserves a MATCH predicate. Query Profile is "
                    "required to prove runtime inverted-index filtering."
                ),
            }
        )
    if compiled is not None and compiled.vector_field is not None:
        if facets.get("ann_pushdown_observed"):
            findings.append(
                {
                    "severity": "info",
                    "code": "ANN_PUSHDOWN_OBSERVED",
                    "message": "Doris EXPLAIN reports ANN SORT INFO.",
                }
            )
        else:
            findings.append(
                {
                    "severity": "high",
                    "code": "ANN_PUSHDOWN_NOT_OBSERVED",
                    "message": (
                        "The vector query has ANN metadata, but EXPLAIN did "
                        "not expose ANN SORT INFO."
                    ),
                }
            )
    if compiled is None:
        upper = query_sql.upper()
        if "MATCH" not in upper and "SEARCH(" not in upper and (
            "_DISTANCE" not in upper
        ):
            findings.append(
                {
                    "severity": "medium",
                    "code": "SEARCH_OPERATOR_NOT_OBSERVED",
                    "message": (
                        "The submitted SQL does not expose a recognized Doris "
                        "text or vector search operator."
                    ),
                }
            )
        if not indexes:
            findings.append(
                {
                    "severity": "medium",
                    "code": "INDEX_METADATA_NOT_BOUND",
                    "message": (
                        "No authoritative target index metadata was bound to "
                        "the raw SQL diagnosis."
                    ),
                }
            )
    return findings


def _simple_source(sql: str) -> tuple[str | None, str] | None:
    match = _SIMPLE_SOURCE.search(sql)
    if match is None:
        return None
    database = _unquote_identifier(match.group("database"))
    table = _unquote_identifier(match.group("table"))
    if table is None:
        return None
    try:
        table = validate_identifier(table, "table name")
        if database is not None:
            database = validate_identifier(database, "database name")
    except SQLSecurityError:
        return None
    return database, table


def _unquote_identifier(value: str | None) -> str | None:
    if value is None:
        return None
    return value[1:-1] if value.startswith("`") and value.endswith("`") else value


def _normalized_row(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        str(key).strip().replace(" ", "_").casefold(): value
        for key, value in row.items()
    }


def _value(row: Mapping[str, Any], *names: str) -> Any:
    normalized = _normalized_row(row)
    for name in names:
        key = name.strip().replace(" ", "_").casefold()
        if key in normalized:
            return normalized[key]
    return None


def _json_value(value: Any) -> Any:
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _as_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _argument_failure(message: str) -> SearchRuntimeFailure:
    return SearchRuntimeFailure(
        message,
        reason_code="SEARCH_ARGUMENT_INVALID",
        status_code=400,
    )


def _classify_failure(exc: Exception) -> SearchRuntimeFailure:
    if isinstance(exc, SearchRuntimeFailure):
        return exc
    if isinstance(exc, QueryRuntimeFailure | SQLSecurityError):
        return _argument_failure("Search arguments are invalid.")
    numeric_code = next(
        (
            value
            for value in getattr(exc, "args", ())
            if isinstance(value, int)
        ),
        None,
    )
    message = str(exc).casefold()
    if numeric_code in {1044, 1045, 1142, 1227} or any(
        marker in message
        for marker in ("access denied", "permission denied", "privilege")
    ):
        return SearchRuntimeFailure(
            "Doris denied access to Search data or metadata.",
            reason_code="SEARCH_PERMISSION_DENIED",
            status_code=403,
        )
    if numeric_code in {1064, 1109, 1146} or any(
        marker in message
        for marker in (
            "doesn't exist",
            "does not exist",
            "not supported",
            "unsupported",
            "unknown table",
            "unknown function",
            "no viable alternative",
        )
    ):
        return SearchRuntimeFailure(
            "The requested Doris Search capability is unsupported.",
            reason_code="SEARCH_CAPABILITY_UNSUPPORTED",
            status_code=501,
        )
    if isinstance(exc, TimeoutError | ConnectionError | OSError):
        return SearchRuntimeFailure(
            "Doris Search is temporarily unavailable.",
            reason_code="SEARCH_BACKEND_UNAVAILABLE",
            status_code=503,
            retryable=True,
        )
    return SearchRuntimeFailure(
        "Doris Search execution failed.",
        reason_code="SEARCH_EXECUTION_FAILED",
        status_code=502,
    )


__all__ = ["DorisSearchRuntime", "SearchRuntimeFailure"]
