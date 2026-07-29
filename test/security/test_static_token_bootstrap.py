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

import json
import os
from pathlib import Path

import pytest

from doris_mcp_server.auth.token_manager import TokenManager
from doris_mcp_server.utils.config import (
    AuthConfigError,
    DorisConfig,
    _mark_source,
    normalize_effective_auth_config,
)
from doris_mcp_server.utils.secret_policy import (
    is_static_token_environment_variable,
)

STATIC_TOKEN = "V4nK8qR2mT7xP5cL9sD3hF6jY1uB0eG4iW8aN2zQ"
MANAGEMENT_TOKEN = "Q7cM2vR9kL4xT8pD5sF1hJ6uB3eG0iW9aN2zY8qP"


def _config(tmp_path: Path) -> DorisConfig:
    config = DorisConfig()
    config.security.token_file_path = str(tmp_path / "tokens.json")
    return config


def _clear_static_token_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in list(os.environ):
        if is_static_token_environment_variable(name):
            monkeypatch.delenv(name, raising=False)


def test_repository_token_template_contains_no_credentials():
    token_file = Path(__file__).parents[2] / "tokens.json"

    token_data = json.loads(token_file.read_text(encoding="utf-8"))

    assert token_data["tokens"] == []
    assert "No usable credential is shipped" in token_data["notes"][0]


def test_legacy_token_secret_has_no_default():
    assert DorisConfig().security.token_secret == ""


def test_static_auth_rejects_missing_active_credentials(tmp_path, monkeypatch):
    _clear_static_token_environment(monkeypatch)
    config = _config(tmp_path)
    config.security.enable_token_auth = True
    _mark_source(config, "enable_token_auth", "env")

    with pytest.raises(AuthConfigError, match="at least one active high-entropy"):
        normalize_effective_auth_config(config)


def test_static_auth_rejects_weak_environment_token(tmp_path, monkeypatch):
    _clear_static_token_environment(monkeypatch)
    config = _config(tmp_path)
    config.security.enable_token_auth = True
    _mark_source(config, "enable_token_auth", "env")
    monkeypatch.setenv("TOKEN_ADMIN", "short-token")

    with pytest.raises(AuthConfigError, match="at least 32 characters"):
        normalize_effective_auth_config(config)


def test_management_settings_are_not_loaded_as_static_tokens(tmp_path, monkeypatch):
    _clear_static_token_environment(monkeypatch)
    config = _config(tmp_path)
    config.security.enable_token_auth = True
    _mark_source(config, "enable_token_auth", "env")
    monkeypatch.setenv("TOKEN_MANAGEMENT_ADMIN_TOKEN", MANAGEMENT_TOKEN)
    monkeypatch.setenv("TOKEN_MANAGEMENT_ALLOWED_IPS", "127.0.0.1")

    with pytest.raises(AuthConfigError, match="at least one active high-entropy"):
        normalize_effective_auth_config(config)


@pytest.mark.asyncio
async def test_strong_environment_token_bootstraps_static_auth(tmp_path, monkeypatch):
    _clear_static_token_environment(monkeypatch)
    config = _config(tmp_path)
    config.security.enable_token_auth = True
    _mark_source(config, "enable_token_auth", "env")
    monkeypatch.setenv("TOKEN_ADMIN", STATIC_TOKEN)

    normalize_effective_auth_config(config)
    manager = TokenManager(config)
    try:
        result = await manager.validate_token(STATIC_TOKEN)
        assert result.is_valid is True
        assert result.token_info.token_id == "admin"
        assert len(manager._tokens) == 1
    finally:
        manager.stop_hot_reload()


@pytest.mark.asyncio
async def test_manager_does_not_create_credentials_when_auth_is_disabled(
    tmp_path,
    monkeypatch,
):
    _clear_static_token_environment(monkeypatch)
    manager = TokenManager(_config(tmp_path))
    try:
        assert manager._tokens == {}
        assert manager._token_ids == {}
    finally:
        manager.stop_hot_reload()


@pytest.mark.asyncio
async def test_custom_static_token_must_follow_secret_policy(tmp_path, monkeypatch):
    _clear_static_token_environment(monkeypatch)
    manager = TokenManager(_config(tmp_path))
    try:
        with pytest.raises(ValueError, match="at least 32 characters"):
            await manager.create_token("weak", custom_token="short-token")

        generated = await manager.create_token("generated")
        assert len(generated) >= 32
        assert (await manager.validate_token(generated)).is_valid is True
    finally:
        manager.stop_hot_reload()


@pytest.mark.parametrize(
    ("admin_token", "error"),
    [
        ("", "is required"),
        ("short-token", "at least 32 characters"),
        ("a" * 40, "distinct characters"),
    ],
)
def test_http_token_management_rejects_weak_admin_secret(admin_token, error):
    config = DorisConfig()
    config.security.enable_http_token_management = True
    config.security.require_admin_auth = True
    config.security.token_management_admin_token = admin_token

    with pytest.raises(AuthConfigError, match=error):
        normalize_effective_auth_config(config)


def test_http_token_management_accepts_high_entropy_admin_secret():
    config = DorisConfig()
    config.security.enable_http_token_management = True
    config.security.require_admin_auth = True
    config.security.token_management_admin_token = MANAGEMENT_TOKEN

    effective = normalize_effective_auth_config(config)

    assert effective.auth_methods == ()
