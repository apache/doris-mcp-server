# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""JWT lifecycle coverage for supported authentication runtime behavior."""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import jwt
import pytest

from doris_mcp_server.auth import jwt_manager as jwt_manager_module
from doris_mcp_server.auth.jwt_manager import JWTManager

JWT_SECRET = "test-only-jwt-signing-key-with-sufficient-length"


def _security_config() -> SimpleNamespace:
    return SimpleNamespace(
        jwt_algorithm="HS256",
        jwt_issuer="doris-mcp-test",
        jwt_audience="doris-mcp-clients",
        jwt_access_token_expiry=300,
        jwt_refresh_token_expiry=600,
        enable_token_refresh=True,
        enable_token_revocation=True,
        jwt_verify_signature=True,
        jwt_require_exp=True,
        jwt_require_iat=True,
        jwt_require_nbf=False,
        jwt_verify_audience=True,
        jwt_verify_issuer=True,
        jwt_leeway=0,
    )


def _manager(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[JWTManager, SimpleNamespace, SimpleNamespace]:
    key_manager = SimpleNamespace(
        key_rotation_interval=0,
        initialize=AsyncMock(return_value=True),
        get_private_key=Mock(return_value=JWT_SECRET),
        get_public_key=Mock(return_value=JWT_SECRET),
        is_key_expired=AsyncMock(return_value=False),
        rotate_keys=AsyncMock(),
        get_key_info=AsyncMock(return_value={"key_id": "test-key"}),
        export_public_key_pem=AsyncMock(return_value="test-public-key"),
    )

    async def validate_claims(payload: dict) -> dict:
        return {"valid": True, "user_id": payload.get("sub"), "payload": payload}

    validator = SimpleNamespace(
        start=AsyncMock(),
        stop=AsyncMock(),
        validate_claims=AsyncMock(side_effect=validate_claims),
        revoke_token=AsyncMock(),
        get_validation_stats=AsyncMock(return_value={"validated": 1}),
    )
    monkeypatch.setattr(
        jwt_manager_module,
        "KeyManager",
        Mock(return_value=key_manager),
    )
    monkeypatch.setattr(
        jwt_manager_module,
        "TokenValidator",
        Mock(return_value=validator),
    )

    manager = JWTManager(SimpleNamespace(security=_security_config()))
    return manager, key_manager, validator


@pytest.mark.asyncio
async def test_jwt_manager_initializes_and_shuts_down_owned_tasks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, key_manager, validator = _manager(monkeypatch)

    assert await manager.initialize() is True
    key_manager.initialize.assert_awaited_once()
    validator.start.assert_awaited_once()

    manager._key_rotation_task = asyncio.create_task(asyncio.sleep(60))
    await manager.shutdown()

    assert manager._key_rotation_task.cancelled()
    validator.stop.assert_awaited_once()


@pytest.mark.asyncio
async def test_jwt_manager_full_token_lifecycle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, _, validator = _manager(monkeypatch)
    user = {
        "user_id": "reader-1",
        "roles": ["reader"],
        "permissions": ["read_data"],
        "security_level": "internal",
    }

    tokens = await manager.generate_tokens(user, {"tenant": "tenant-a"})

    assert tokens["token_type"] == "Bearer"
    assert tokens["user_id"] == "reader-1"
    assert tokens["refresh_token"]
    validated = await manager.validate_token(tokens["access_token"])
    assert validated["payload"]["tenant"] == "tenant-a"

    refreshed = await manager.refresh_token(tokens["refresh_token"])
    assert refreshed["user_id"] == "reader-1"

    token_info = await manager.get_token_info(tokens["access_token"])
    assert token_info["sub"] == "reader-1"
    assert token_info["token_type"] == "access"
    assert token_info["is_expired"] is False

    revocable = jwt.encode(
        {"jti": "revocable", "exp": int(time.time()) + 60},
        JWT_SECRET,
        algorithm="HS256",
    )
    assert await manager.revoke_token(revocable) is True
    validator.revoke_token.assert_awaited_once_with(
        "revocable",
        pytest.approx(time.time() + 60, abs=2),
    )

    assert await manager.get_public_key_info() == {
        "algorithm": "HS256",
        "public_key_pem": "test-public-key",
        "key_info": {"key_id": "test-key"},
    }
    stats = await manager.get_manager_stats()
    assert stats["jwt_config"]["enable_refresh"] is True
    assert stats["key_manager"] == {"key_id": "test-key"}
    assert stats["validator"] == {"validated": 1}


@pytest.mark.asyncio
async def test_jwt_manager_rejects_invalid_lifecycle_inputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, key_manager, _ = _manager(monkeypatch)
    current_time = int(time.time())

    wrong_type = jwt.encode(
        {
            "iss": manager.issuer,
            "aud": manager.audience,
            "iat": current_time,
            "exp": current_time + 60,
            "token_type": "refresh",
        },
        JWT_SECRET,
        algorithm="HS256",
    )
    with pytest.raises(ValueError, match="Invalid token type"):
        await manager.validate_token(wrong_type)

    expired = jwt.encode(
        {
            "iss": manager.issuer,
            "aud": manager.audience,
            "iat": current_time - 120,
            "exp": current_time - 60,
            "token_type": "access",
        },
        JWT_SECRET,
        algorithm="HS256",
    )
    with pytest.raises(ValueError, match="Token has expired"):
        await manager.validate_token(expired)
    with pytest.raises(ValueError, match="Invalid token"):
        await manager.validate_token("not-a-jwt")

    key_manager.get_public_key.return_value = None
    with pytest.raises(ValueError, match="verification key is not initialized"):
        await manager.validate_token(wrong_type)
    key_manager.get_public_key.return_value = JWT_SECRET

    key_manager.get_private_key.return_value = None
    with pytest.raises(RuntimeError, match="signing key is not initialized"):
        await manager.generate_tokens({"user_id": "reader-1"})
    key_manager.get_private_key.return_value = JWT_SECRET

    manager.enable_refresh = False
    with pytest.raises(ValueError, match="refresh is disabled"):
        await manager.refresh_token("unused")

    manager.enable_revocation = False
    assert await manager.revoke_token("unused") is False
    manager.enable_revocation = True
    missing_claims = jwt.encode(
        {"exp": current_time + 60},
        JWT_SECRET,
        algorithm="HS256",
    )
    assert await manager.revoke_token(missing_claims) is False
    assert await manager.revoke_token("not-a-jwt") is False

    with pytest.raises(jwt.InvalidTokenError):
        await manager.decode_token_unsafe("not-a-jwt")


@pytest.mark.asyncio
async def test_jwt_manager_initialization_failure_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, key_manager, validator = _manager(monkeypatch)

    key_manager.initialize.return_value = False
    assert await manager.initialize() is False
    validator.start.assert_not_awaited()

    key_manager.initialize.side_effect = RuntimeError("key store unavailable")
    assert await manager.initialize() is False

    validator.stop.side_effect = RuntimeError("validator shutdown failed")
    await manager.shutdown()


@pytest.mark.asyncio
async def test_jwt_manager_rotates_expired_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, key_manager, _ = _manager(monkeypatch)
    key_manager.is_key_expired.return_value = True

    async def cancel_after_iteration(_delay: float) -> None:
        raise asyncio.CancelledError

    monkeypatch.setattr(jwt_manager_module.asyncio, "sleep", cancel_after_iteration)

    await manager._auto_key_rotation()

    key_manager.rotate_keys.assert_awaited_once()
