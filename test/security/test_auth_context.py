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

from datetime import UTC, datetime

import pytest

from doris_mcp_server.auth.auth_middleware import AuthMiddleware
from doris_mcp_server.utils import sql_security_utils
from doris_mcp_server.utils.auth_credentials import BearerCredentials
from doris_mcp_server.utils.security import (
    AuthContext,
    get_current_auth_context,
    reset_auth_context,
    set_current_auth_context,
)


def test_sql_security_utils_uses_shared_contextvar():
    auth_context = AuthContext(user_id="u1", auth_method="token")

    token = set_current_auth_context(auth_context)
    try:
        assert sql_security_utils.auth_context_var is not None
        assert sql_security_utils.get_auth_context() is auth_context
        assert get_current_auth_context() is auth_context
    finally:
        reset_auth_context(token)

    assert get_current_auth_context() is None


@pytest.mark.asyncio
async def test_jwt_auth_context_does_not_store_raw_token():
    class FakeJWTManager:
        async def validate_token(self, token, token_type):
            assert token == "jwt.raw.token"
            assert token_type == "access"
            return {
                "payload": {
                    "jti": "jwt-id",
                    "sub": "jwt-user",
                    "roles": ["reader"],
                    "permissions": ["read_data"],
                    "security_level": "internal",
                    "iat": int(datetime.now(UTC).timestamp()),
                }
            }

    middleware = AuthMiddleware(FakeJWTManager())
    auth_context = await middleware.authenticate_request(
        BearerCredentials(scheme="bearer", token="jwt.raw.token")
    )

    assert auth_context.auth_method == "jwt"
    assert auth_context.token == ""
    assert auth_context.pool_key == "global"
    assert auth_context.token_id == "jwt-id"
