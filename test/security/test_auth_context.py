from datetime import datetime

import pytest

from doris_mcp_server.auth.auth_middleware import AuthMiddleware
from doris_mcp_server.utils.security import (
    AuthContext,
    get_current_auth_context,
    reset_auth_context,
    set_current_auth_context,
)
from doris_mcp_server.utils import sql_security_utils


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
                    "iat": int(datetime.utcnow().timestamp()),
                }
            }

    middleware = AuthMiddleware(FakeJWTManager())
    auth_context = await middleware.authenticate_request(
        {"authorization": "Bearer jwt.raw.token"}
    )

    assert auth_context.auth_method == "jwt"
    assert auth_context.token == ""
    assert auth_context.pool_key == "global"
    assert auth_context.token_id == "jwt-id"
