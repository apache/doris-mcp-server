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
Authorization module tests
"""

import pytest

from doris_mcp_server.utils.security import (
    AuthContext,
    AuthorizationProvider,
    SecurityLevel,
)


class TestAuthorizationProvider:
    """Authorization provider tests"""

    @pytest.fixture
    def authz_provider(self, test_config):
        """Create authorization provider instance"""
        return AuthorizationProvider(test_config)

    @pytest.fixture
    def analyst_context(self):
        """Create analyst auth context"""
        return AuthContext(
            user_id="analyst1",
            roles=["data_analyst"],
            permissions=["read_data"],
            session_id="session_123",
            security_level=SecurityLevel.INTERNAL
        )

    @pytest.fixture
    def admin_context(self):
        """Create admin auth context"""
        return AuthContext(
            user_id="admin1",
            roles=["data_admin"],
            permissions=["admin"],
            session_id="session_456",
            security_level=SecurityLevel.SECRET
        )

    @pytest.mark.asyncio
    async def test_analyst_access_public_resource(self, authz_provider, analyst_context):
        """Test analyst accessing public resource"""
        resource_uri = "/api/table/public_reports"

        result = await authz_provider.check_permission(analyst_context, resource_uri, "read")

        assert result is True

    @pytest.mark.asyncio
    async def test_analyst_denied_confidential_resource(self, authz_provider):
        """Test analyst denied access to confidential resource"""
        # Create analyst with lower security level
        analyst_context = AuthContext(
            user_id="analyst1",
            roles=["data_analyst"],
            permissions=["read_data"],
            session_id="session_123",
            security_level=SecurityLevel.PUBLIC  # Lower than CONFIDENTIAL
        )

        resource_uri = "/api/table/user_info"

        result = await authz_provider.check_permission(analyst_context, resource_uri, "read")

        assert result is False

    @pytest.mark.asyncio
    async def test_admin_access_secret_resource(self, authz_provider, admin_context):
        """Test admin accessing secret resource"""
        resource_uri = "/api/table/payment_records"

        result = await authz_provider.check_permission(admin_context, resource_uri, "read")

        assert result is True

    @pytest.mark.asyncio
    async def test_role_based_permission(self, authz_provider):
        """Test role-based permission check"""
        # Create analyst context
        analyst_context = AuthContext(
            user_id="analyst1",
            roles=["data_analyst"],
            permissions=["read_data"],
            session_id="session_123",
            security_level=SecurityLevel.INTERNAL
        )

        resource_uri = "/api/table/some_table"

        # Analyst should have read permission
        result = await authz_provider.check_permission(analyst_context, resource_uri, "read")
        assert result is True

        # Analyst should not have write permission
        result = await authz_provider.check_permission(analyst_context, resource_uri, "write")
        assert result is False

    @pytest.mark.asyncio
    async def test_admin_override(self, authz_provider, admin_context):
        """Test admin permission override"""
        resource_uri = "/api/table/any_table"

        # Admin should have all permissions
        result = await authz_provider.check_permission(admin_context, resource_uri, "read")
        assert result is True

        result = await authz_provider.check_permission(admin_context, resource_uri, "write")
        assert result is True

    def test_parse_resource_uri(self, authz_provider):
        """Test resource URI parsing"""
        uri = "/api/table/user_info/default"

        result = authz_provider._parse_resource_uri(uri)

        assert result["type"] == "table"
        assert result["name"] == "user_info"
        assert result["schema"] == "default"

    def test_get_resource_security_level(self, authz_provider):
        """Test getting resource security level"""
        resource_info = {"name": "user_info", "type": "table"}

        level = authz_provider._get_resource_security_level(resource_info)

        assert level == SecurityLevel.CONFIDENTIAL
