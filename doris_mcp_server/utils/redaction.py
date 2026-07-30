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
"""Secret redaction helpers for logs and public error payloads."""

from __future__ import annotations

import logging
import re
import traceback
from collections.abc import Mapping
from types import TracebackType
from typing import Any

REDACTED = "[REDACTED]"

_SENSITIVE_KEYS = frozenset(
    {
        "authorization",
        "proxyauthorization",
        "password",
        "passwd",
        "pwd",
        "dbpassword",
        "admintoken",
        "customtoken",
        "token",
        "authtoken",
        "sessiontoken",
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "bearertoken",
        "secret",
        "secretkey",
        "clientsecret",
        "tokensecret",
        "apikey",
        "privatekey",
        "credential",
        "credentials",
        "cookie",
        "setcookie",
    }
)
_SQL_KEYS = frozenset({"sql", "query", "statement", "sqltext", "querytext"})
_ERROR_DROP_KEYS = frozenset(
    {
        "arguments",
        "headers",
        "payload",
        "rawrequest",
        "request",
        "requestbody",
    }
)

_TEXT_SENSITIVE_KEY = (
    r"(?:authorization|proxy[-_ ]authorization|password|passwd|pwd|"
    r"db[-_ ]password|admin[-_ ]token|custom[-_ ]token|auth[-_ ]token|"
    r"session[-_ ]token|token|secret|secret[-_ ]key|"
    r"access[-_ ]token|refresh[-_ ]token|id[-_ ]token|bearer[-_ ]token|"
    r"client[-_ ]secret|token[-_ ]secret|api[-_ ]key|private[-_ ]key|"
    r"cookie|set[-_ ]cookie)"
)
_QUOTED_KEY_VALUE_RE = re.compile(
    rf"(?i)(?P<prefix>[\"']?{_TEXT_SENSITIVE_KEY}[\"']?\s*[:=]\s*)"
    r"(?P<quote>[\"'])(?P<value>.*?)(?P=quote)"
)
_AUTHORIZATION_VALUE_RE = re.compile(
    r"(?i)(?P<prefix>\b(?:authorization|proxy[-_ ]authorization)"
    r"\s*[:=]\s*)(?:(?:bearer|basic|token)\s+)?"
    r"(?P<value>[^\s,;\"'}]+)"
)
_UNQUOTED_KEY_VALUE_RE = re.compile(
    rf"(?i)(?P<prefix>\b{_TEXT_SENSITIVE_KEY}\b\s*[:=]\s*)"
    r"(?P<value>(?![\"'\[])[^\s,;&}\]]+)"
)
_AUTH_SCHEME_RE = re.compile(
    r"(?i)\b(?P<scheme>bearer|basic|token)\s+"
    r"(?P<value>[A-Za-z0-9._~+/=-]+)"
)
_QUERY_SECRET_RE = re.compile(
    rf"(?i)(?P<prefix>[?&]{_TEXT_SENSITIVE_KEY}=)(?P<value>[^&#\s]*)"
)
_DSN_PASSWORD_RE = re.compile(
    r"(?i)(?P<prefix>[a-z][a-z0-9+.-]*://[^:/@\s]+:)"
    r"(?P<password>[^@\s/]+)(?P<suffix>@)"
)

_SQL_KEYWORD_RE = re.compile(
    r"(?i)\b(?:select|insert|update|delete|replace|merge|create|alter|drop|"
    r"truncate|explain|with)\b"
)
_SQL_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_SQL_LINE_COMMENT_RE = re.compile(r"--[^\r\n]*")
_SQL_SINGLE_QUOTED_RE = re.compile(r"'(?:''|\\.|[^'])*'")
_SQL_DOUBLE_QUOTED_RE = re.compile(r'"(?:""|\\.|[^"])*"')
_SQL_HEX_RE = re.compile(r"(?i)\b(?:0x[0-9a-f]+|x'[0-9a-f]+')\b")
_SQL_NUMBER_RE = re.compile(r"(?<![\w.])[-+]?\d+(?:\.\d+)?(?![\w.])")

_ERROR_DETAIL_RE = re.compile(
    r"(?is)^(?P<prefix>.*?\b(?:failed|failure|error|exception)\b"
    r"[^:\n]{0,160}:)\s*.+$"
)


def _normalized_key(key: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).casefold())


def is_sensitive_key(key: object) -> bool:
    """Return whether a semantic field name is treated as credential data."""
    return _normalized_key(key) in _SENSITIVE_KEYS


def redact_sql_literals(value: str) -> str:
    """Remove values and comments from SQL while retaining diagnostic shape."""
    if not _SQL_KEYWORD_RE.search(value):
        return value
    value = _SQL_BLOCK_COMMENT_RE.sub("/* [REDACTED] */", value)
    value = _SQL_LINE_COMMENT_RE.sub("-- [REDACTED]", value)
    value = _SQL_HEX_RE.sub(REDACTED, value)
    value = _SQL_SINGLE_QUOTED_RE.sub(f"'{REDACTED}'", value)
    value = _SQL_DOUBLE_QUOTED_RE.sub(f'"{REDACTED}"', value)
    return _SQL_NUMBER_RE.sub("?", value)


def redact_sensitive_text(value: str) -> str:
    """Redact recognized credentials, secret fields, URIs, and SQL literals."""

    def quoted_replacement(match: re.Match[str]) -> str:
        return f"{match.group('prefix')}{match.group('quote')}{REDACTED}{match.group('quote')}"

    value = _AUTHORIZATION_VALUE_RE.sub(
        lambda match: f"{match.group('prefix')}{REDACTED}",
        value,
    )
    value = _QUOTED_KEY_VALUE_RE.sub(quoted_replacement, value)
    value = _UNQUOTED_KEY_VALUE_RE.sub(
        lambda match: f"{match.group('prefix')}{REDACTED}",
        value,
    )
    value = _AUTH_SCHEME_RE.sub(
        lambda match: f"{match.group('scheme')} {REDACTED}",
        value,
    )
    value = _QUERY_SECRET_RE.sub(
        lambda match: f"{match.group('prefix')}{REDACTED}",
        value,
    )
    value = _DSN_PASSWORD_RE.sub(
        lambda match: (f"{match.group('prefix')}{REDACTED}{match.group('suffix')}"),
        value,
    )
    return redact_sql_literals(value)


def redact_log_message(value: str) -> str:
    """Redact a log message and suppress untrusted exception detail suffixes."""
    redacted = redact_sensitive_text(value)
    match = _ERROR_DETAIL_RE.match(redacted)
    if match is None:
        return redacted
    return f"{match.group('prefix')} {REDACTED}"


def redact_sensitive_data(value: Any, *, key: object | None = None) -> Any:
    """Recursively redact data by semantic key and recognizable string format."""
    normalized_key = _normalized_key(key) if key is not None else ""
    if normalized_key in _SENSITIVE_KEYS or normalized_key in _SQL_KEYS:
        return REDACTED
    if isinstance(value, Mapping):
        return {
            item_key: redact_sensitive_data(item_value, key=item_key)
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [redact_sensitive_data(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_sensitive_data(item) for item in value)
    if isinstance(value, set):
        return {redact_sensitive_data(item) for item in value}
    if isinstance(value, BaseException):
        return value.__class__.__name__
    if isinstance(value, str):
        return redact_sensitive_text(value)
    if isinstance(value, bytes):
        return redact_sensitive_text(value.decode("utf-8", errors="replace")).encode()
    return value


def redact_error_payload(value: Any) -> Any:
    """Sanitize an error-only response without touching successful results."""
    if isinstance(value, Mapping):
        sanitized = {}
        for key, item_value in value.items():
            normalized_key = _normalized_key(key)
            if normalized_key in _ERROR_DROP_KEYS:
                continue
            sanitized[key] = redact_error_payload(
                REDACTED
                if normalized_key in _SENSITIVE_KEYS or normalized_key in _SQL_KEYS
                else item_value
            )
        return sanitized
    if isinstance(value, list):
        return [redact_error_payload(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_error_payload(item) for item in value)
    if isinstance(value, str):
        return redact_sensitive_text(value)
    return value


def redact_uri(value: str) -> str:
    """Redact credential-bearing URI components without changing safe URIs."""
    return redact_sensitive_text(value)


def _safe_exception_text(
    exc_info: tuple[
        type[BaseException],
        BaseException,
        TracebackType | None,
    ],
) -> str:
    exception_type, _exception, traceback_value = exc_info
    frames = traceback.format_list(traceback.extract_tb(traceback_value))
    frames.append(f"{exception_type.__name__}: {REDACTED}\n")
    return "".join(frames)


class SensitiveDataFilter(logging.Filter):
    """Apply defense-in-depth redaction before any configured log handler."""

    def filter(self, record: logging.LogRecord) -> bool:
        dropped_error_details = False
        if isinstance(record.msg, str):
            sanitized_message = redact_sensitive_text(record.msg)
            dropped_error_details = (
                _ERROR_DETAIL_RE.match(sanitized_message) is not None
            )
            record.msg = redact_log_message(record.msg)
        else:
            record.msg = redact_sensitive_data(record.msg)

        if dropped_error_details:
            record.args = ()
        elif isinstance(record.args, Mapping):
            record.args = redact_sensitive_data(record.args)
        elif isinstance(record.args, tuple):
            record.args = tuple(
                redact_sensitive_data(argument) for argument in record.args
            )

        if (
            record.exc_info
            and record.exc_info[0] is not None
            and record.exc_info[1] is not None
        ):
            record.exc_text = _safe_exception_text(record.exc_info)
        if record.stack_info:
            record.stack_info = redact_sensitive_text(record.stack_info)
        return True
