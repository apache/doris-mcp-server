#!/usr/bin/env python3
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
"""Regression tests for static-token database route validation."""

from unittest.mock import AsyncMock

import pytest

from doris_mcp_server.auth.token_manager import DatabaseConfig, TokenInfo
from doris_mcp_server.utils.config import (
    AuthConfigError,
    DorisConfig,
    normalize_effective_auth_config,
)
from doris_mcp_server.utils.secret_policy import (
    is_static_token_environment_variable,
)
from doris_mcp_server.utils.security import DorisSecurityManager


def _token_info(password: str = "tenant-password") -> TokenInfo:
    return TokenInfo(
        token_id="tenant-alpha",
        database_config=DatabaseConfig(
            host="tenant-fe",
            port=9030,
            user="tenant-reader",
            password=password,
            database="tenant-db",
            charset="UTF8",
        ),
    )


@pytest.mark.asyncio
async def test_successful_token_database_validation_is_cached(test_config):
    connection_manager = AsyncMock()
    connection_manager.configure_for_token.return_value = (True, "token-bound")
    test_config.security.token_db_validation_ttl_seconds = 30
    manager = DorisSecurityManager(test_config, connection_manager)
    token_info = _token_info()

    await manager._validate_token_database_config("high-entropy-token", token_info)
    await manager._validate_token_database_config("high-entropy-token", token_info)

    connection_manager.configure_for_token.assert_awaited_once_with(
        "high-entropy-token"
    )


@pytest.mark.asyncio
async def test_database_credential_rotation_invalidates_validation_cache(test_config):
    connection_manager = AsyncMock()
    connection_manager.configure_for_token.return_value = (True, "token-bound")
    test_config.security.token_db_validation_ttl_seconds = 30
    manager = DorisSecurityManager(test_config, connection_manager)

    await manager._validate_token_database_config(
        "high-entropy-token",
        _token_info("password-v1"),
    )
    await manager._validate_token_database_config(
        "high-entropy-token",
        _token_info("password-v2"),
    )

    assert connection_manager.configure_for_token.await_count == 2


@pytest.mark.asyncio
async def test_failed_token_database_validation_is_not_cached(test_config):
    connection_manager = AsyncMock()
    connection_manager.configure_for_token.side_effect = [
        RuntimeError("Doris unavailable"),
        (True, "token-bound"),
    ]
    test_config.security.token_db_validation_ttl_seconds = 30
    manager = DorisSecurityManager(test_config, connection_manager)
    token_info = _token_info()

    with pytest.raises(ValueError, match="Doris unavailable"):
        await manager._validate_token_database_config(
            "high-entropy-token",
            token_info,
        )
    await manager._validate_token_database_config("high-entropy-token", token_info)

    assert connection_manager.configure_for_token.await_count == 2


def test_token_database_validation_ttl_loads_from_environment(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setenv("TOKEN_DB_VALIDATION_TTL_SECONDS", "45")

    config = DorisConfig.from_env(str(tmp_path / "missing.env"))

    assert config.security.token_db_validation_ttl_seconds == 45


def test_token_database_validation_ttl_is_not_treated_as_a_bearer_token():
    assert (
        is_static_token_environment_variable(
            "TOKEN_DB_VALIDATION_TTL_SECONDS"
        )
        is False
    )


def test_token_database_validation_ttl_rejects_out_of_range_values():
    config = DorisConfig()
    config.security.token_db_validation_ttl_seconds = 3601

    with pytest.raises(AuthConfigError, match="TOKEN_DB_VALIDATION_TTL_SECONDS"):
        normalize_effective_auth_config(config)
