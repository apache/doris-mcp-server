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

import io
import json
import logging
from unittest.mock import Mock

import pytest

from doris_mcp_server.tools.domain_dispatcher import (
    ToolExposureMode,
    ToolNotFoundError,
)
from doris_mcp_server.tools.domain_manifest import DomainManifestService
from doris_mcp_server.tools.resources_manager import DorisResourcesManager
from doris_mcp_server.tools.tools_manager import DorisToolsManager
from doris_mcp_server.utils.redaction import (
    REDACTED,
    SensitiveDataFilter,
    redact_error_payload,
    redact_sensitive_data,
    redact_sensitive_text,
)

AUTH_SECRET = "auth-secret-sec-016"
PASSWORD_SECRET = "password-secret-sec-016"
TOKEN_SECRET = "token-secret-sec-016"
URI_SECRET = "uri-secret-sec-016"
SQL_SECRET = "customer-secret-sec-016"


def assert_secrets_absent(value) -> None:
    serialized = (
        value
        if isinstance(value, str)
        else json.dumps(value, ensure_ascii=False, default=str)
    )
    for secret in (
        AUTH_SECRET,
        PASSWORD_SECRET,
        TOKEN_SECRET,
        URI_SECRET,
        SQL_SECRET,
    ):
        assert secret not in serialized


def test_recursive_redaction_uses_keys_without_hiding_safe_token_ids():
    payload = {
        "Authorization": f"Bearer {AUTH_SECRET}",
        "database": {"user": "alice", "password": PASSWORD_SECRET},
        "access_token": TOKEN_SECRET,
        "secret_key": TOKEN_SECRET,
        "token_id": "public-token-id",
        "sql": f"SELECT * FROM customer WHERE email = '{SQL_SECRET}'",
    }

    redacted = redact_sensitive_data(payload)

    assert redacted["Authorization"] == REDACTED
    assert redacted["database"]["password"] == REDACTED
    assert redacted["access_token"] == REDACTED
    assert redacted["secret_key"] == REDACTED
    assert redacted["token_id"] == "public-token-id"
    assert redacted["sql"] == REDACTED
    assert_secrets_absent(redacted)


def test_text_redaction_covers_headers_dsn_query_parameters_and_sql_literals():
    message = (
        f"Authorization: Bearer {AUTH_SECRET}; "
        f"password='{PASSWORD_SECRET}'; "
        f"mysql://alice:{URI_SECRET}@db.example.test/analytics"
        f"?access_token={TOKEN_SECRET}; "
        f"SELECT * FROM customer WHERE email = '{SQL_SECRET}' AND id = 42"
    )

    redacted = redact_sensitive_text(message)

    assert redacted.count(REDACTED) >= 5
    assert "id = ?" in redacted
    assert_secrets_absent(redacted)


def test_error_payload_drops_request_material_and_preserves_safe_diagnostics():
    payload = {
        "error": (
            f"Access denied password={PASSWORD_SECRET}; "
            f"SELECT * FROM customer WHERE email='{SQL_SECRET}'"
        ),
        "error_code": "QUERY_FAILED",
        "arguments": {
            "Authorization": f"Bearer {AUTH_SECRET}",
            "token": TOKEN_SECRET,
        },
        "details": {"access_token": TOKEN_SECRET},
    }

    redacted = redact_error_payload(payload)

    assert redacted["error_code"] == "QUERY_FAILED"
    assert "arguments" not in redacted
    assert redacted["details"]["access_token"] == REDACTED
    assert_secrets_absent(redacted)


def test_logging_filter_redacts_arguments_and_exception_tracebacks():
    output = io.StringIO()
    handler = logging.StreamHandler(output)
    handler.addFilter(SensitiveDataFilter())
    handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    logger = logging.Logger("sec-016-redaction-test")
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

    logger.info(
        "request headers=%s payload=%s",
        {"Authorization": f"Bearer {AUTH_SECRET}"},
        {
            "password": PASSWORD_SECRET,
            "token": TOKEN_SECRET,
            "sql": f"SELECT '{SQL_SECRET}'",
        },
    )
    try:
        raise RuntimeError(
            f"backend echoed password={PASSWORD_SECRET} and token={TOKEN_SECRET}"
        )
    except RuntimeError:
        logger.exception("Backend operation failed")

    rendered = output.getvalue()
    assert REDACTED in rendered
    assert "RuntimeError" in rendered
    assert_secrets_absent(rendered)


@pytest.mark.asyncio
async def test_removed_tool_name_returns_safe_not_found_without_arguments():
    manager = object.__new__(DorisToolsManager)
    manager._tool_exposure_mode = ToolExposureMode.HIERARCHICAL
    manager._domain_manifest_service = DomainManifestService()

    with pytest.raises(ToolNotFoundError) as exc_info:
        await manager.call_tool(
            "exec_query",
            {
                "sql": f"SELECT '{SQL_SECRET}'",
                "password": PASSWORD_SECRET,
                "token": TOKEN_SECRET,
            },
        )

    assert exc_info.value.name == "exec_query"
    assert str(exc_info.value) == "Tool not found"
    assert_secrets_absent(str(exc_info.value))


@pytest.mark.asyncio
async def test_resource_error_redacts_uri_and_backend_exception():
    manager = DorisResourcesManager(Mock())

    def fail_to_parse(uri):
        del uri
        raise RuntimeError(
            f"password={PASSWORD_SECRET}; token={TOKEN_SECRET}; SELECT '{SQL_SECRET}'"
        )

    manager._parse_resource_uri = fail_to_parse
    result = await manager.read_resource(
        f"doris://table/orders?access_token={URI_SECRET}"
    )
    payload = json.loads(result)

    assert payload["error"] == "Resource read failed"
    assert payload["uri"].endswith(f"access_token={REDACTED}")
    assert_secrets_absent(payload)
