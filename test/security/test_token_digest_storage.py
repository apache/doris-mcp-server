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
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest

from doris_mcp_server.auth.token_manager import DatabaseConfig, TokenManager
from doris_mcp_server.utils.config import (
    AuthConfigError,
    DorisConfig,
    _mark_source,
    normalize_effective_auth_config,
)
from doris_mcp_server.utils.secret_policy import (
    build_token_digest,
    is_static_token_environment_variable,
)

STATIC_TOKEN = "V4nK8qR2mT7xP5cL9sD3hF6jY1uB0eG4iW8aN2zQ"


def _config(tmp_path: Path, *, algorithm: str = "sha256") -> DorisConfig:
    config = DorisConfig()
    config.security.token_file_path = str(tmp_path / "tokens.json")
    config.security.token_hash_algorithm = algorithm
    return config


def _clear_static_token_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in list(os.environ):
        if is_static_token_environment_variable(name):
            monkeypatch.delenv(name, raising=False)


@pytest.mark.asyncio
async def test_created_token_is_returned_once_and_persisted_as_digest(
    tmp_path,
    monkeypatch,
):
    _clear_static_token_environment(monkeypatch)
    config = _config(tmp_path)
    manager = TokenManager(config)
    try:
        raw_token = await manager.create_token(
            "generated",
            expires_hours=24,
            description="one-time display",
        )
        token_path = Path(config.security.token_file_path)
        token_text = token_path.read_text(encoding="utf-8")
        token_data = json.loads(token_text)
        stored = token_data["tokens"][0]

        assert token_data["version"] == "2.0"
        assert raw_token not in token_text
        assert "token" not in stored
        assert stored["token_digest"].startswith("sha256:")
        assert len(stored["token_digest"]) == len("sha256:") + 64
        assert stat.S_IMODE(token_path.stat().st_mode) == 0o600

        listed = await manager.list_tokens()
        assert raw_token not in json.dumps(listed)
        assert "token_digest" not in listed[0]
        assert (await manager.validate_token(raw_token)).is_valid is True
    finally:
        manager.stop_hot_reload()

    reloaded = TokenManager(config)
    try:
        result = await reloaded.validate_token(raw_token)
        assert result.is_valid is True
        assert result.token_info.token_id == "generated"
        assert result.token_info.description == "one-time display"
    finally:
        reloaded.stop_hot_reload()


@pytest.mark.asyncio
async def test_token_database_fe_candidates_round_trip(
    tmp_path,
    monkeypatch,
):
    _clear_static_token_environment(monkeypatch)
    config = _config(tmp_path)
    manager = TokenManager(config)
    try:
        raw_token = await manager.create_token(
            "multi-fe",
            database_config=DatabaseConfig(
                host="fe-1.internal",
                hosts=["fe-1.internal", "fe-2.internal"],
                user="tenant_reader",
                password="tenant-password",
                database="analytics",
                fe_http_hosts=["fe-http-1.internal", "fe-http-2.internal"],
                be_hosts=["be-1.internal", "be-2.internal"],
            ),
        )
        stored = json.loads(
            Path(config.security.token_file_path).read_text(encoding="utf-8")
        )["tokens"][0]["database_config"]

        assert stored["hosts"] == ["fe-1.internal", "fe-2.internal"]
        assert stored["fe_http_hosts"] == [
            "fe-http-1.internal",
            "fe-http-2.internal",
        ]
        assert stored["be_hosts"] == ["be-1.internal", "be-2.internal"]

        selected = manager.get_database_config_by_token(raw_token)
        assert selected is not None
        assert selected.hosts == ["fe-1.internal", "fe-2.internal"]
        assert selected.fe_http_hosts == [
            "fe-http-1.internal",
            "fe-http-2.internal",
        ]
    finally:
        manager.stop_hot_reload()

    reloaded = TokenManager(config)
    try:
        result = await reloaded.validate_token(raw_token)
        assert result.is_valid is True
        assert result.token_info.token_id == "multi-fe"
        assert result.token_info.database_config is not None
        assert result.token_info.database_config.hosts == [
            "fe-1.internal",
            "fe-2.internal",
        ]
    finally:
        reloaded.stop_hot_reload()


@pytest.mark.asyncio
async def test_legacy_plaintext_file_is_atomically_migrated_without_expiry_extension(
    tmp_path,
    monkeypatch,
):
    _clear_static_token_environment(monkeypatch)
    token_path = tmp_path / "tokens.json"
    token_path.write_text(
        json.dumps(
            {
                "version": "1.0",
                "token": STATIC_TOKEN,
                "tokens": [
                    {
                        "token_id": "legacy",
                        "token": STATIC_TOKEN,
                        "legacy_raw_copy": STATIC_TOKEN,
                        "created_at": "2026-07-01T00:00:00Z",
                        "expires_hours": 720,
                        "description": "legacy deployment",
                        "is_active": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    config = _config(tmp_path)
    manager = TokenManager(config)
    try:
        migrated_text = token_path.read_text(encoding="utf-8")
        migrated = json.loads(migrated_text)
        stored = migrated["tokens"][0]

        assert migrated["version"] == "2.0"
        assert STATIC_TOKEN not in migrated_text
        assert "token" not in stored
        assert stored["token_digest"] == build_token_digest(STATIC_TOKEN, "sha256")
        assert stored["created_at"] == "2026-07-01T00:00:00Z"
        assert stored["expires_at"] == "2026-07-31T00:00:00Z"
        assert stat.S_IMODE(token_path.stat().st_mode) == 0o600
        assert list(tmp_path.glob(".tokens.json.*.tmp")) == []
    finally:
        manager.stop_hot_reload()

    sha512_default = _config(tmp_path, algorithm="sha512")
    reloaded = TokenManager(sha512_default)
    try:
        result = await reloaded.validate_token(STATIC_TOKEN)
        assert result.is_valid is True
        assert result.token_info.created_at == datetime(2026, 7, 1, tzinfo=UTC)
        assert result.token_info.expires_at == datetime(2026, 7, 31, tzinfo=UTC)
    finally:
        reloaded.stop_hot_reload()


def test_legacy_plaintext_file_fails_closed_when_migration_cannot_be_written(
    tmp_path,
    monkeypatch,
):
    _clear_static_token_environment(monkeypatch)
    token_path = tmp_path / "tokens.json"
    token_path.write_text(
        json.dumps(
            {
                "version": "1.0",
                "tokens": [
                    {
                        "token_id": "legacy",
                        "token": STATIC_TOKEN,
                        "is_active": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        TokenManager,
        "_atomic_write_token_file",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("read only")),
    )

    with pytest.raises(ValueError, match="digest-only storage"):
        TokenManager(_config(tmp_path))
    assert STATIC_TOKEN in token_path.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_digest_file_bootstraps_static_auth_with_embedded_algorithm(
    tmp_path,
    monkeypatch,
):
    _clear_static_token_environment(monkeypatch)
    token_path = tmp_path / "tokens.json"
    token_path.write_text(
        json.dumps(
            {
                "version": "2.0",
                "tokens": [
                    {
                        "token_id": "sha512-record",
                        "token_digest": build_token_digest(STATIC_TOKEN, "sha512"),
                        "created_at": "2026-07-29T00:00:00Z",
                        "expires_at": None,
                        "last_used": None,
                        "is_active": True,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    config = _config(tmp_path, algorithm="sha256")
    config.security.enable_token_auth = True
    _mark_source(config, "enable_token_auth", "test")

    normalize_effective_auth_config(config)
    manager = TokenManager(config)
    try:
        assert (await manager.validate_token(STATIC_TOKEN)).is_valid is True
    finally:
        manager.stop_hot_reload()


@pytest.mark.parametrize(
    "entry,error",
    [
        ({"token_id": "missing"}, "exactly one"),
        (
            {
                "token_id": "both",
                "token": STATIC_TOKEN,
                "token_digest": build_token_digest(STATIC_TOKEN, "sha256"),
            },
            "exactly one",
        ),
        (
            {"token_id": "invalid", "token_digest": "sha256:not-a-digest"},
            "64 hexadecimal",
        ),
    ],
)
def test_static_auth_rejects_invalid_digest_records(
    tmp_path,
    monkeypatch,
    entry,
    error,
):
    _clear_static_token_environment(monkeypatch)
    token_path = tmp_path / "tokens.json"
    token_path.write_text(json.dumps({"tokens": [entry]}), encoding="utf-8")
    config = _config(tmp_path)
    config.security.enable_token_auth = True
    _mark_source(config, "enable_token_auth", "test")

    with pytest.raises(AuthConfigError, match=error):
        normalize_effective_auth_config(config)


def test_static_auth_rejects_unsupported_digest_algorithm(tmp_path):
    config = _config(tmp_path, algorithm="md5")

    with pytest.raises(AuthConfigError, match="TOKEN_HASH_ALGORITHM"):
        normalize_effective_auth_config(config)


@pytest.mark.asyncio
async def test_create_rolls_back_when_digest_file_cannot_be_persisted(
    tmp_path,
    monkeypatch,
):
    _clear_static_token_environment(monkeypatch)
    manager = TokenManager(_config(tmp_path))
    monkeypatch.setattr(
        manager,
        "_atomic_write_token_file",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("disk full")),
    )
    try:
        with pytest.raises(OSError, match="disk full"):
            await manager.create_token("not-persisted", custom_token=STATIC_TOKEN)
        assert manager._tokens == {}
        assert manager._token_ids == {}
        assert manager._digest_algorithms == set()
        assert (await manager.validate_token(STATIC_TOKEN)).is_valid is False
    finally:
        manager.stop_hot_reload()


@pytest.mark.asyncio
async def test_revoke_keeps_live_token_when_digest_file_cannot_be_persisted(
    tmp_path,
    monkeypatch,
):
    _clear_static_token_environment(monkeypatch)
    manager = TokenManager(_config(tmp_path))
    try:
        raw_token = await manager.create_token("still-live")
        monkeypatch.setattr(
            manager,
            "_remove_token_from_file",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("read only")),
        )

        assert await manager.revoke_token("still-live") is False
        assert (await manager.validate_token(raw_token)).is_valid is True
    finally:
        manager.stop_hot_reload()


@pytest.mark.asyncio
async def test_revoke_and_export_keep_every_record_digest_only(
    tmp_path,
    monkeypatch,
):
    _clear_static_token_environment(monkeypatch)
    config = _config(tmp_path)
    manager = TokenManager(config)
    try:
        first = await manager.create_token("first")
        second = await manager.create_token("second")
        assert await manager.revoke_token("first") is True

        primary_text = Path(config.security.token_file_path).read_text(encoding="utf-8")
        primary = json.loads(primary_text)
        assert first not in primary_text
        assert second not in primary_text
        assert [entry["token_id"] for entry in primary["tokens"]] == ["second"]
        assert set(primary["tokens"][0]) >= {"token_id", "token_digest"}
        assert "token" not in primary["tokens"][0]

        export_path = tmp_path / "exported-tokens.json"
        assert await manager.save_tokens_to_file(str(export_path)) is True
        exported_text = export_path.read_text(encoding="utf-8")
        exported = json.loads(exported_text)
        assert first not in exported_text
        assert second not in exported_text
        assert exported["version"] == "2.0"
        assert "token" not in exported["tokens"][0]
        assert stat.S_IMODE(export_path.stat().st_mode) == 0o600
    finally:
        manager.stop_hot_reload()
