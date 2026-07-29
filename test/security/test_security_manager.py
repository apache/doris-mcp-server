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
"""
Security manager integration tests
"""

import pytest
import pytest_asyncio

from doris_mcp_server.utils.config import normalize_effective_auth_config
from doris_mcp_server.utils.security import (
    AuthContext,
    DorisSecurityManager,
    SecurityLevel,
)

STATIC_TOKEN = "3e5f98dbed994130b60186dbe83fb0c76c5e6d0da81a4441a4615fbe7bdc7562"


class TestDorisSecurityManager:
    """Doris security manager integration tests"""

    @pytest.fixture
    def security_manager(self, test_config):
        """Create a security manager for non-authentication behavior."""
        return DorisSecurityManager(test_config)

    @pytest_asyncio.fixture
    async def token_security_manager(self, test_config, monkeypatch, tmp_path):
        """Create a manager with an explicit high-entropy static token."""
        monkeypatch.setenv("TOKEN_SECURITY_MANAGER", STATIC_TOKEN)
        test_config.security.enable_token_auth = True
        test_config.security.token_file_path = str(tmp_path / "tokens.json")
        normalize_effective_auth_config(test_config)
        manager = DorisSecurityManager(test_config)
        try:
            yield manager
        finally:
            manager.auth_provider.token_manager.stop_hot_reload()

    @pytest.mark.asyncio
    async def test_complete_security_workflow(
        self,
        token_security_manager,
        sample_data,
    ):
        """Test complete security workflow"""
        # 1. Authentication
        auth_info = {
            "type": "token",
            "token": STATIC_TOKEN,
        }

        auth_context = await token_security_manager.authenticate_request(auth_info)
        assert isinstance(auth_context, AuthContext)
        assert auth_context.security_level == SecurityLevel.INTERNAL
        auth_context.roles.append("data_analyst")

        # 2. Authorization
        resource_uri = "/api/table/public_reports"
        has_access = await token_security_manager.authorize_resource_access(
            auth_context,
            resource_uri,
        )
        assert has_access is True

        # 3. SQL Validation
        safe_sql = "SELECT name, email FROM users WHERE department = 'sales'"
        validation_result = await token_security_manager.validate_sql_security(
            safe_sql,
            auth_context,
        )
        assert validation_result.is_valid is True

        # 4. Data Masking
        masked_data = await token_security_manager.apply_data_masking(
            sample_data,
            auth_context,
        )
        assert masked_data[0]["phone"] == "138****5678"  # Should be masked

    @pytest.mark.asyncio
    async def test_secret_level_authorization_and_masking(
        self,
        security_manager,
        sample_data,
    ):
        """Test authorization and masking with a trusted secret-level context."""
        auth_context = AuthContext(
            token_id="trusted-admin",
            user_id="trusted-admin",
            roles=["data_admin"],
            permissions=["admin"],
            security_level=SecurityLevel.SECRET,
            auth_method="test",
        )

        resource_uri = "/api/table/payment_records"
        has_access = await security_manager.authorize_resource_access(
            auth_context, resource_uri
        )
        assert has_access is True

        masked_data = await security_manager.apply_data_masking(
            sample_data, auth_context
        )
        assert masked_data[0]["phone"] == "13812345678"

    @pytest.mark.asyncio
    async def test_security_violation_detection(self, token_security_manager):
        """Test security violation detection"""
        # Authenticate as regular user
        auth_info = {
            "type": "token",
            "token": STATIC_TOKEN,
        }

        auth_context = await token_security_manager.authenticate_request(auth_info)

        # Try to access confidential resource (user_info is CONFIDENTIAL, user is INTERNAL)
        # INTERNAL(1) should not access CONFIDENTIAL(2) resource
        resource_uri = "/api/table/user_info"
        has_access = await token_security_manager.authorize_resource_access(
            auth_context,
            resource_uri,
        )
        assert has_access is False

        # Try dangerous SQL
        dangerous_sql = "DROP TABLE users"
        validation_result = await token_security_manager.validate_sql_security(
            dangerous_sql,
            auth_context,
        )
        assert validation_result.is_valid is False
        assert "DROP" in validation_result.blocked_operations

    @pytest.mark.asyncio
    async def test_sql_injection_prevention(self, token_security_manager):
        """Test SQL injection prevention"""
        auth_info = {
            "type": "token",
            "token": STATIC_TOKEN,
        }

        auth_context = await token_security_manager.authenticate_request(auth_info)

        # Test various injection attempts
        injection_attempts = [
            "SELECT * FROM users WHERE id = 1; DROP TABLE users;",
            "SELECT * FROM users UNION SELECT password FROM admin_users",
            "SELECT * FROM users WHERE id = 1 OR 1=1",
            "SELECT * FROM users WHERE name = 'test' -- AND password = 'secret'",
        ]

        for sql in injection_attempts:
            result = await token_security_manager.validate_sql_security(
                sql,
                auth_context,
            )
            assert result.is_valid is False
            assert result.risk_level in ["medium", "high"]

    @pytest.mark.asyncio
    async def test_authentication_failure_handling(self, token_security_manager):
        """Test authentication failure handling"""
        invalid_auth_info = {"type": "token", "token": "invalid_token"}

        with pytest.raises(ValueError, match="Authentication failed"):
            await token_security_manager.authenticate_request(invalid_auth_info)

    @pytest.mark.asyncio
    async def test_configuration_loading(self, security_manager):
        """Test security configuration loading"""
        # Test blocked keywords loading
        assert "DROP" in security_manager.blocked_keywords
        assert "DELETE" in security_manager.blocked_keywords

        # Test sensitive tables loading
        assert SecurityLevel.CONFIDENTIAL in security_manager.sensitive_tables.values()
        assert SecurityLevel.SECRET in security_manager.sensitive_tables.values()

        # Test masking rules loading
        assert len(security_manager.masking_rules) > 0
        phone_rules = [
            rule
            for rule in security_manager.masking_rules
            if "phone" in rule.column_pattern
        ]
        assert len(phone_rules) > 0

    def test_security_level_hierarchy(self, security_manager):
        """Test security level hierarchy"""
        # Test that hierarchy is correctly defined
        levels = [
            SecurityLevel.PUBLIC,
            SecurityLevel.INTERNAL,
            SecurityLevel.CONFIDENTIAL,
            SecurityLevel.SECRET,
        ]

        # Each level should be properly defined
        for level in levels:
            assert isinstance(level, SecurityLevel)
            assert level.value in ["public", "internal", "confidential", "secret"]
