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

import asyncio
import json
import multiprocessing
import os
import secrets
import stat
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pytest

from doris_mcp_server.auth.token_manager import TokenManager
from doris_mcp_server.utils.config import DorisConfig
from doris_mcp_server.utils.secret_policy import (
    is_static_token_environment_variable,
)


def _config(
    token_path: str | Path,
    *,
    algorithm: str = "sha256",
) -> DorisConfig:
    config = DorisConfig()
    config.security.token_file_path = str(token_path)
    config.security.token_hash_algorithm = algorithm
    return config


def _clear_static_token_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in list(os.environ):
        if is_static_token_environment_variable(name):
            monkeypatch.delenv(name, raising=False)


async def _create_token_in_worker(
    token_path: str,
    token_id: str,
    raw_token: str,
) -> str:
    manager = TokenManager(_config(token_path))
    try:
        await manager.create_token(
            token_id,
            custom_token=raw_token,
        )
        return "created"
    except ValueError as exc:
        return str(exc)
    finally:
        manager.stop_hot_reload()


def _process_create_token(
    token_path: str,
    token_id: str,
    raw_token: str,
) -> str:
    return asyncio.run(_create_token_in_worker(token_path, token_id, raw_token))


async def _revoke_token_in_worker(
    token_path: str,
    token_id: str,
) -> bool:
    manager = TokenManager(_config(token_path))
    try:
        return await manager.revoke_token(token_id)
    finally:
        manager.stop_hot_reload()


def _process_revoke_token(token_path: str, token_id: str) -> bool:
    return asyncio.run(_revoke_token_in_worker(token_path, token_id))


@pytest.mark.asyncio
async def test_workers_observe_create_and_revoke_on_the_next_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_static_token_environment(monkeypatch)
    token_path = tmp_path / "tokens.json"
    first_worker = TokenManager(_config(token_path, algorithm="sha512"))
    second_worker = TokenManager(_config(token_path))
    first_worker.hot_reload_interval = 3600
    second_worker.hot_reload_interval = 3600
    try:
        raw_token = await first_worker.create_token("shared-service")

        observed = await second_worker.validate_token(raw_token)
        assert observed.is_valid is True
        assert observed.token_info is not None
        assert observed.token_info.token_id == "shared-service"

        assert await second_worker.revoke_token("shared-service") is True
        rejected = await first_worker.validate_token(raw_token)
        assert rejected.is_valid is False
        assert rejected.error_message == "Invalid token"

        shared_state = json.loads(token_path.read_text(encoding="utf-8"))
        assert shared_state["tokens"] == []
        assert len(shared_state["revoked_tokens"]) == 1
        assert raw_token not in token_path.read_text(encoding="utf-8")
        assert stat.S_IMODE(token_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(Path(f"{token_path}.lock").stat().st_mode) == 0o600
    finally:
        first_worker.stop_hot_reload()
        second_worker.stop_hot_reload()


@pytest.mark.asyncio
async def test_environment_token_revocation_is_shared_and_persistent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_static_token_environment(monkeypatch)
    raw_token = secrets.token_urlsafe(40)
    monkeypatch.setenv("TOKEN_SHARED_ENV", raw_token)
    token_path = tmp_path / "tokens.json"
    first_worker = TokenManager(_config(token_path, algorithm="sha512"))
    second_worker = TokenManager(_config(token_path))
    try:
        assert (await second_worker.validate_token(raw_token)).is_valid
        assert await first_worker.revoke_token("shared_env") is True
        assert (await second_worker.validate_token(raw_token)).is_valid is False

        restarted_worker = TokenManager(_config(token_path))
        try:
            assert (await restarted_worker.validate_token(raw_token)).is_valid is False
            with pytest.raises(
                ValueError,
                match="revoked token value",
            ):
                await restarted_worker.create_token(
                    "replayed",
                    custom_token=raw_token,
                )
        finally:
            restarted_worker.stop_hot_reload()

        stored_text = token_path.read_text(encoding="utf-8")
        stored = json.loads(stored_text)
        assert stored["tokens"] == []
        assert stored["revoked_tokens"][0]["token_id"] == "shared_env"
        assert raw_token not in stored_text
    finally:
        first_worker.stop_hot_reload()
        second_worker.stop_hot_reload()


@pytest.mark.asyncio
async def test_concurrent_worker_creates_do_not_lose_updates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_static_token_environment(monkeypatch)
    token_path = tmp_path / "tokens.json"
    entries = [(f"worker-{index}", secrets.token_urlsafe(40)) for index in range(8)]
    context = multiprocessing.get_context("spawn")

    with ProcessPoolExecutor(
        max_workers=4,
        mp_context=context,
    ) as executor:
        futures = [
            executor.submit(
                _process_create_token,
                str(token_path),
                token_id,
                raw_token,
            )
            for token_id, raw_token in entries
        ]
        assert [future.result(timeout=30) for future in futures] == ["created"] * len(
            entries
        )

    manager = TokenManager(_config(token_path))
    try:
        listed = await manager.list_tokens()
        assert {item["token_id"] for item in listed} == {
            token_id for token_id, _raw_token in entries
        }
        for _token_id, raw_token in entries:
            assert (await manager.validate_token(raw_token)).is_valid
    finally:
        manager.stop_hot_reload()

    stored_text = token_path.read_text(encoding="utf-8")
    stored = json.loads(stored_text)
    assert len(stored["tokens"]) == len(entries)
    assert all(raw_token not in stored_text for _, raw_token in entries)


@pytest.mark.asyncio
async def test_concurrent_create_and_revoke_preserve_both_updates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_static_token_environment(monkeypatch)
    token_path = tmp_path / "tokens.json"
    old_token = secrets.token_urlsafe(40)
    new_token = secrets.token_urlsafe(40)
    manager = TokenManager(_config(token_path))
    try:
        await manager.create_token(
            "old-service",
            custom_token=old_token,
        )
    finally:
        manager.stop_hot_reload()

    context = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(
        max_workers=2,
        mp_context=context,
    ) as executor:
        create_future = executor.submit(
            _process_create_token,
            str(token_path),
            "new-service",
            new_token,
        )
        revoke_future = executor.submit(
            _process_revoke_token,
            str(token_path),
            "old-service",
        )
        assert create_future.result(timeout=30) == "created"
        assert revoke_future.result(timeout=30) is True

    verifier = TokenManager(_config(token_path))
    try:
        assert (await verifier.validate_token(old_token)).is_valid is False
        assert (await verifier.validate_token(new_token)).is_valid is True
    finally:
        verifier.stop_hot_reload()

    stored = json.loads(token_path.read_text(encoding="utf-8"))
    assert [token["token_id"] for token in stored["tokens"]] == ["new-service"]
    assert [revoked["token_id"] for revoked in stored["revoked_tokens"]] == [
        "old-service"
    ]


@pytest.mark.asyncio
async def test_concurrent_duplicate_token_id_has_one_winner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_static_token_environment(monkeypatch)
    token_path = tmp_path / "tokens.json"
    entries = [
        ("same-id", secrets.token_urlsafe(40)),
        ("same-id", secrets.token_urlsafe(40)),
    ]
    context = multiprocessing.get_context("spawn")

    with ProcessPoolExecutor(
        max_workers=2,
        mp_context=context,
    ) as executor:
        futures = [
            executor.submit(
                _process_create_token,
                str(token_path),
                token_id,
                raw_token,
            )
            for token_id, raw_token in entries
        ]
        results = [future.result(timeout=30) for future in futures]

    assert results.count("created") == 1
    assert sum("already exists" in result for result in results) == 1
    stored = json.loads(token_path.read_text(encoding="utf-8"))
    assert [token["token_id"] for token in stored["tokens"]] == ["same-id"]
