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
import subprocess
import sys
from pathlib import Path

import pytest

from doris_mcp_server.main import DorisServer, _multiworker_environment
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


def _http_config(host: str) -> DorisConfig:
    config = DorisConfig()
    config.transport = "http"
    config.server_host = host
    _mark_source(config, "transport", "test")
    return config


def _clear_auth_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in list(os.environ):
        if is_static_token_environment_variable(name) or name in {
            "ALLOW_UNAUTHENTICATED_NON_LOOPBACK",
            "AUTH_TYPE",
            "ENABLE_DORIS_OAUTH_AUTH",
            "ENABLE_JWT_AUTH",
            "ENABLE_OAUTH_AUTH",
            "ENABLE_TOKEN_AUTH",
            "OAUTH_ENABLED",
        }:
            monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize(
    "host",
    [
        "localhost",
        "LOCALHOST.",
        "127.0.0.1",
        "127.42.0.1",
        "::1",
        "[::1]",
    ],
)
def test_unauthenticated_http_accepts_explicit_loopback_hosts(host):
    effective = normalize_effective_auth_config(_http_config(host))

    assert effective.auth_methods == ()
    assert effective.auth_config_warnings == ()


@pytest.mark.parametrize(
    "host",
    [
        "",
        "0.0.0.0",
        "::",
        "192.168.1.20",
        "mcp.example.test",
    ],
)
def test_unauthenticated_http_rejects_non_loopback_hosts(host):
    with pytest.raises(
        AuthConfigError,
        match="Refusing unauthenticated HTTP bind to non-loopback",
    ):
        normalize_effective_auth_config(_http_config(host))


def test_stdio_does_not_apply_http_bind_policy():
    config = DorisConfig()
    config.server_host = "0.0.0.0"

    effective = normalize_effective_auth_config(config)

    assert effective.transport == "stdio"
    assert effective.auth_methods == ()


def test_authenticated_http_accepts_non_loopback_host(tmp_path, monkeypatch):
    _clear_auth_environment(monkeypatch)
    config = _http_config("0.0.0.0")
    config.security.token_file_path = str(tmp_path / "tokens.json")
    config.security.enable_token_auth = True
    _mark_source(config, "enable_token_auth", "test")
    monkeypatch.setenv("TOKEN_ADMIN", STATIC_TOKEN)

    effective = normalize_effective_auth_config(config)

    assert effective.auth_methods == ("token",)
    assert effective.auth_config_warnings == ()


def test_explicit_dangerous_override_allows_startup_with_warning():
    config = _http_config("0.0.0.0")
    config.security.allow_unauthenticated_non_loopback = True

    effective = normalize_effective_auth_config(config)

    assert effective.auth_methods == ()
    assert any(
        "DANGEROUS: ALLOW_UNAUTHENTICATED_NON_LOOPBACK=true" in warning
        for warning in effective.auth_config_warnings
    )


def test_environment_loads_explicit_dangerous_override(tmp_path, monkeypatch):
    _clear_auth_environment(monkeypatch)
    monkeypatch.setenv("TRANSPORT", "http")
    monkeypatch.setenv("SERVER_HOST", "0.0.0.0")
    monkeypatch.setenv("ALLOW_UNAUTHENTICATED_NON_LOOPBACK", "true")

    config = DorisConfig.from_env(str(tmp_path / "missing.env"))
    effective = normalize_effective_auth_config(config)

    assert config.security.allow_unauthenticated_non_loopback is True
    assert effective.auth_config_warnings


def test_config_file_preserves_server_host_and_dangerous_override(tmp_path):
    config_file = tmp_path / "config.json"
    config_file.write_text(
        json.dumps(
            {
                "transport": "http",
                "server_host": "0.0.0.0",
                "security": {
                    "allow_unauthenticated_non_loopback": True,
                },
            }
        ),
        encoding="utf-8",
    )

    config = DorisConfig.from_file(str(config_file))
    effective = normalize_effective_auth_config(config)

    assert config.server_host == "0.0.0.0"
    assert effective.auth_config_warnings


@pytest.mark.asyncio
async def test_start_http_rechecks_the_actual_bind_host():
    config = _http_config("127.0.0.1")
    normalize_effective_auth_config(config)
    server = object.__new__(DorisServer)
    server.config = config

    with pytest.raises(
        AuthConfigError,
        match="Refusing unauthenticated HTTP bind to non-loopback",
    ):
        await server.start_http(host="0.0.0.0", port=0, workers=1)


def test_multiworker_environment_preserves_dangerous_override():
    config = _http_config("0.0.0.0")
    config.security.allow_unauthenticated_non_loopback = True

    environment = _multiworker_environment(
        config,
        host="0.0.0.0",
        port=3000,
        workers=2,
    )

    assert environment["ALLOW_UNAUTHENTICATED_NON_LOOPBACK"] == "true"


def test_cli_process_fails_before_unauthenticated_non_loopback_startup():
    environment = os.environ.copy()
    for name in list(environment):
        if is_static_token_environment_variable(name) or name in {
            "ALLOW_UNAUTHENTICATED_NON_LOOPBACK",
            "AUTH_TYPE",
            "ENABLE_DORIS_OAUTH_AUTH",
            "ENABLE_JWT_AUTH",
            "ENABLE_OAUTH_AUTH",
            "ENABLE_TOKEN_AUTH",
            "OAUTH_ENABLED",
        }:
            environment.pop(name, None)

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "doris_mcp_server",
            "--transport",
            "http",
            "--host",
            "0.0.0.0",
            "--port",
            "0",
        ],
        cwd=Path(__file__).parents[2],
        env=environment,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )

    assert result.returncode == 1
