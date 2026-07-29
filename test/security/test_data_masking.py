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
Data masking tests
"""

import pytest

from doris_mcp_server.utils.security import (
    AuthContext,
    DataMaskingProcessor,
    MaskingRule,
    SecurityLevel,
)


class TestDataMaskingProcessor:
    """Data masking processor tests"""

    @pytest.fixture
    def masking_processor(self, test_config):
        """Create data masking processor instance"""
        return DataMaskingProcessor(test_config)

    @pytest.fixture
    def internal_user_context(self):
        """Create internal user auth context"""
        return AuthContext(
            user_id="internal_user",
            roles=["data_analyst"],
            permissions=["read_data"],
            session_id="session_123",
            security_level=SecurityLevel.INTERNAL
        )

    @pytest.fixture
    def admin_context(self):
        """Create admin auth context"""
        return AuthContext(
            user_id="admin",
            roles=["data_admin"],
            permissions=["admin"],
            session_id="session_456",
            security_level=SecurityLevel.SECRET
        )

    @pytest.mark.asyncio
    async def test_phone_masking_for_internal_user(self, masking_processor, internal_user_context, sample_data):
        """Test phone number masking for internal user"""
        result = await masking_processor.process(sample_data, internal_user_context)

        # Phone numbers should be masked
        assert result[0]["phone"] == "138****5678"
        assert result[1]["phone"] == "139****4321"

    @pytest.mark.asyncio
    async def test_email_masking_for_internal_user(self, masking_processor, internal_user_context, sample_data):
        """Test email masking for internal user"""
        result = await masking_processor.process(sample_data, internal_user_context)

        # Emails should be masked
        assert result[0]["email"] == "z******n@example.com"
        assert result[1]["email"] == "l**i@example.com"

    @pytest.mark.asyncio
    async def test_no_masking_for_admin(self, masking_processor, admin_context, sample_data):
        """Test no masking for admin user"""
        result = await masking_processor.process(sample_data, admin_context)

        # Admin should see original data
        assert result[0]["phone"] == "13812345678"
        assert result[0]["email"] == "zhangsan@example.com"
        assert result[1]["phone"] == "13987654321"
        assert result[1]["email"] == "lisi@example.com"

    @pytest.mark.asyncio
    async def test_id_card_masking_for_confidential_data(self, masking_processor, internal_user_context, sample_data):
        """Test ID card masking for confidential data"""
        # Internal user should not see ID card details (confidential level)
        result = await masking_processor.process(sample_data, internal_user_context)

        # ID cards should be masked for internal users
        assert result[0]["id_card"] == "110101********1234"
        assert result[1]["id_card"] == "110101********2345"

    @pytest.mark.asyncio
    async def test_empty_data_handling(self, masking_processor, internal_user_context):
        """Test empty data handling"""
        empty_data = []

        result = await masking_processor.process(empty_data, internal_user_context)

        assert result == []

    @pytest.mark.asyncio
    async def test_null_value_handling(self, masking_processor, internal_user_context):
        """Test null value handling"""
        data_with_nulls = [
            {
                "id": 1,
                "name": "张三",
                "phone": None,
                "email": None,
                "id_card": None
            }
        ]

        result = await masking_processor.process(data_with_nulls, internal_user_context)

        # Null values should remain null
        assert result[0]["phone"] is None
        assert result[0]["email"] is None
        assert result[0]["id_card"] is None

    def test_phone_masking_algorithm(self, masking_processor):
        """Test phone masking algorithm"""
        params = {"mask_char": "*", "keep_prefix": 3, "keep_suffix": 4}

        result = masking_processor._mask_phone("13812345678", params)

        assert result == "138****5678"

    def test_email_masking_algorithm(self, masking_processor):
        """Test email masking algorithm"""
        params = {"mask_char": "*"}

        result = masking_processor._mask_email("zhangsan@example.com", params)

        assert result == "z******n@example.com"

    def test_id_card_masking_algorithm(self, masking_processor):
        """Test ID card masking algorithm"""
        params = {"mask_char": "*", "keep_prefix": 6, "keep_suffix": 4}

        result = masking_processor._mask_id_card("110101199001011234", params)

        assert result == "110101********1234"

    def test_name_masking_algorithm(self, masking_processor):
        """Test name masking algorithm"""
        params = {"mask_char": "*"}

        # Test 2-character name
        result = masking_processor._mask_name("张三", params)
        assert result == "张*"

        # Test 3-character name
        result = masking_processor._mask_name("李小明", params)
        assert result == "李*明"

    def test_partial_masking_algorithm(self, masking_processor):
        """Test partial masking algorithm"""
        params = {"mask_char": "*", "mask_ratio": 0.5}

        result = masking_processor._mask_partial("1234567890", params)

        # Should mask middle 50% of the string
        assert "*" in result
        assert len(result) == 10

    def test_should_apply_rule_logic(self, masking_processor, internal_user_context, admin_context):
        """Test masking rule application logic"""
        rule = MaskingRule(
            column_pattern=r".*phone.*",
            algorithm="phone_mask",
            parameters={"mask_char": "*", "keep_prefix": 3, "keep_suffix": 4},
            security_level=SecurityLevel.INTERNAL
        )

        # Internal user should have rule applied
        assert masking_processor._should_apply_rule(rule, internal_user_context) is True

        # Admin should not have rule applied
        assert masking_processor._should_apply_rule(rule, admin_context) is False

    def test_get_applicable_rules(self, masking_processor, internal_user_context):
        """Test getting applicable rules"""
        rules = masking_processor._get_applicable_rules(internal_user_context)

        # Should return some rules for internal user
        assert len(rules) > 0
        assert all(isinstance(rule, MaskingRule) for rule in rules)
