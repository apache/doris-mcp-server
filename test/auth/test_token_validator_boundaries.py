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
"""Claim, blacklist, and rate-limit boundaries for JWT validation."""

from __future__ import annotations

import time
from types import SimpleNamespace

import pytest

from doris_mcp_server.auth.token_validators import (
    RateLimiter,
    TokenBlacklist,
    TokenValidator,
)


def _security_config() -> SimpleNamespace:
    return SimpleNamespace(
        jwt_verify_signature=True,
        jwt_verify_audience=True,
        jwt_verify_issuer=True,
        jwt_require_exp=True,
        jwt_require_iat=True,
        jwt_require_nbf=False,
        jwt_leeway=0,
        jwt_audience="doris-mcp-clients",
        jwt_issuer="doris-mcp-test",
    )


def _validator() -> TokenValidator:
    return TokenValidator(SimpleNamespace(security=_security_config()))


def _valid_payload(**overrides: object) -> dict[str, object]:
    now = time.time()
    payload: dict[str, object] = {
        "iss": "doris-mcp-test",
        "aud": "doris-mcp-clients",
        "exp": now + 120,
        "iat": now,
        "jti": "token-1",
        "sub": "reader-1",
    }
    payload.update(overrides)
    return payload


@pytest.mark.asyncio
async def test_blacklist_lifecycle_and_cleanup() -> None:
    blacklist = TokenBlacklist(cleanup_interval=1)
    now = time.time()

    await blacklist.add_token("expired", now - 1)
    await blacklist.add_token("active", now + 60)
    assert await blacklist.is_blacklisted("active") is True
    assert await blacklist.remove_token("missing") is False

    stats = await blacklist.get_stats()
    assert stats["total_blacklisted"] == 2
    assert stats["active_blacklisted"] == 1
    assert stats["expired_blacklisted"] == 1
    assert await blacklist.cleanup_expired() == 1
    assert await blacklist.remove_token("active") is True

    await blacklist.start()
    assert blacklist._cleanup_task is not None
    await blacklist.stop()
    assert blacklist._cleanup_task.cancelled()


@pytest.mark.asyncio
async def test_rate_limiter_enforces_window_and_reports_usage() -> None:
    limiter = RateLimiter(max_requests=1, time_window=60)

    assert await limiter.is_allowed("reader-1") is True
    assert await limiter.is_allowed("reader-1") is False
    usage = await limiter.get_usage("reader-1")
    assert usage == {
        "user_id": "reader-1",
        "requests_in_window": 1,
        "max_requests": 1,
        "time_window": 60,
        "remaining_requests": 0,
    }

    limiter._request_history["reader-2"] = [0.0]
    assert await limiter.is_allowed("reader-2") is True


@pytest.mark.asyncio
async def test_validator_accepts_valid_claims_and_reports_runtime_stats() -> None:
    validator = _validator()
    payload = _valid_payload(aud=["another-client", "doris-mcp-clients"])

    result = await validator.validate_claims(payload)

    assert result == {
        "valid": True,
        "user_id": "reader-1",
        "payload": payload,
    }
    await validator.revoke_token("revoked", time.time() + 60)
    stats = await validator.get_validation_stats()
    assert stats["blacklist"]["active_blacklisted"] == 1
    assert stats["validation_config"]["verify_signature"] is True
    usage = await validator.get_user_rate_limit_info("reader-1")
    assert usage["requests_in_window"] == 1

    await validator.start()
    await validator.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (_valid_payload(iss="wrong"), "Invalid issuer"),
        (_valid_payload(aud="wrong"), "Invalid audience"),
        (_valid_payload(aud=["wrong"]), "not in"),
        (_valid_payload(exp=None), "Missing 'exp' claim"),
        (_valid_payload(exp=1), "Token has expired"),
        (_valid_payload(nbf=None), "Missing 'nbf' claim"),
        (_valid_payload(nbf=time.time() + 60), "Token not yet valid"),
        (_valid_payload(iat=None), "Missing 'iat' claim"),
        (_valid_payload(iat=time.time() + 60), "Token issued in the future"),
    ],
)
async def test_validator_rejects_invalid_registered_claims(
    payload: dict[str, object],
    message: str,
) -> None:
    validator = _validator()

    with pytest.raises(ValueError, match=message):
        await validator.validate_claims(payload)


@pytest.mark.asyncio
async def test_validator_rejects_revoked_and_rate_limited_tokens() -> None:
    validator = _validator()
    await validator.blacklist.add_token("token-1", time.time() + 60)
    with pytest.raises(ValueError, match="revoked"):
        await validator.validate_claims(_valid_payload())

    validator = _validator()
    validator.rate_limiter.max_requests = 0
    with pytest.raises(ValueError, match="Rate limit exceeded"):
        await validator.validate_claims(_valid_payload())


def test_validator_accepts_direct_security_config() -> None:
    validator = TokenValidator(_security_config())

    assert validator.expected_audience == "doris-mcp-clients"
    assert validator.expected_issuer == "doris-mcp-test"
