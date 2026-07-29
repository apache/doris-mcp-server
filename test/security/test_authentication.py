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
Authentication module tests
"""

import pytest

from doris_mcp_server.utils.security import AuthenticationProvider


class TestAuthenticationProvider:
    """Authentication provider tests"""

    @pytest.fixture
    def auth_provider(self, test_config):
        """Create authentication provider instance"""
        return AuthenticationProvider(test_config)

    @pytest.mark.asyncio
    async def test_token_authentication_has_no_fixed_legacy_fallback(
        self, auth_provider
    ):
        """Direct token auth fails closed without a configured token manager."""
        auth_provider.token_manager = None
        auth_info = {
            "type": "token",
            "token": "repository-must-not-accept-this-token",
        }

        with pytest.raises(
            ValueError,
            match="Token authentication is not enabled|Token manager is not initialized",
        ):
            await auth_provider.authenticate(auth_info)

    @pytest.mark.asyncio
    async def test_token_authentication_failure(self, auth_provider):
        """Test failed token authentication"""
        auth_info = {
            "type": "token",
            "token": "invalid_token",
        }

        with pytest.raises(ValueError):
            await auth_provider.authenticate(auth_info)

    @pytest.mark.asyncio
    async def test_basic_authentication_is_not_backed_by_fixed_credentials(
        self, auth_provider
    ):
        """Legacy direct Basic auth is explicitly unsupported."""
        auth_info = {
            "type": "basic",
            "username": "admin",
            "password": "any-value",
        }

        with pytest.raises(ValueError, match="Basic authentication is not supported"):
            await auth_provider.authenticate(auth_info)

    @pytest.mark.asyncio
    async def test_unsupported_auth_type(self, auth_provider):
        """Test unsupported authentication type"""
        auth_info = {
            "type": "oauth",
            "token": "oauth_token",
        }

        with pytest.raises(ValueError):
            await auth_provider.authenticate(auth_info)
