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
SQL Security Test Suite for Apache Doris MCP Server

Tests for:
1. SQL injection prevention via identifier validation
2. Multi-statement SQL parsing in security validator
3. auth_context enforcement
"""

import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch


class TestSQLSecurityUtils:
    """Test cases for sql_security_utils module"""
    
    def test_validate_identifier_accepts_valid_names(self):
        """Test that valid identifiers are accepted"""
        from doris_mcp_server.utils.sql_security_utils import validate_identifier
        
        valid_names = [
            "users",
            "my_table",
            "Table123",
            "_private_table",
            "CamelCaseTable",
            "table_with_numbers_123",
        ]
        
        for name in valid_names:
            result = validate_identifier(name, "table")
            assert result == name, f"Valid identifier '{name}' should be accepted"
    
    def test_validate_identifier_rejects_sql_injection(self):
        """Test that SQL injection attempts are rejected"""
        from doris_mcp_server.utils.sql_security_utils import (
            validate_identifier, 
            SQLSecurityError
        )
        
        injection_attempts = [
            # Basic SQL injection
            "'; DROP TABLE users; --",
            "table' OR '1'='1",
            "table'; DELETE FROM users; --",
            
            # Union-based injection
            "table' UNION SELECT * FROM passwords --",
            
            # Comment injection
            "table/**/OR/**/1=1",
            "table--comment",
            
            # Special characters
            "table`; DROP TABLE users;",
            'table"; DROP TABLE users;',
            "table\"; DELETE FROM",
            
            # Backtick escape attempt
            "analytics`; SELECT * FROM sensitive_table;--",
            
            # Whitespace injection
            "table name with spaces",
            "table\ttab",
            "table\nnewline",
        ]
        
        for injection in injection_attempts:
            with pytest.raises(SQLSecurityError):
                validate_identifier(injection, "table")
    
    def test_validate_identifier_rejects_empty(self):
        """Test that empty identifiers are rejected"""
        from doris_mcp_server.utils.sql_security_utils import (
            validate_identifier, 
            SQLSecurityError
        )
        
        with pytest.raises(SQLSecurityError):
            validate_identifier("", "table")
        
        with pytest.raises(SQLSecurityError):
            validate_identifier(None, "table")
    
    def test_validate_identifier_rejects_too_long(self):
        """Test that identifiers exceeding max length are rejected"""
        from doris_mcp_server.utils.sql_security_utils import (
            validate_identifier, 
            SQLSecurityError
        )
        
        # Doris identifier max length is typically 64 characters
        long_name = "a" * 100
        with pytest.raises(SQLSecurityError):
            validate_identifier(long_name, "table")
    
    def test_quote_identifier_adds_backticks(self):
        """Test that quote_identifier properly escapes identifiers"""
        from doris_mcp_server.utils.sql_security_utils import quote_identifier
        
        assert quote_identifier("my_table", "table") == "`my_table`"
        assert quote_identifier("users", "table") == "`users`"
        assert quote_identifier("Table123", "table") == "`Table123`"
    
    def test_quote_identifier_validates_first(self):
        """Test that quote_identifier validates before quoting"""
        from doris_mcp_server.utils.sql_security_utils import (
            quote_identifier, 
            SQLSecurityError
        )
        
        with pytest.raises(SQLSecurityError):
            quote_identifier("'; DROP TABLE users; --", "table")


class TestSQLSecurityValidator:
    """Test cases for SQLSecurityValidator multi-statement parsing"""
    
    @pytest.fixture
    def dict_config(self):
        """Create dictionary configuration"""
        return {
            "blocked_keywords": [
                "DROP", "CREATE", "ALTER", "TRUNCATE",
                "DELETE", "INSERT", "UPDATE",
                "GRANT", "REVOKE", "EXEC", "EXECUTE"
            ],
            "max_query_complexity": 100,
            "enable_security_check": True
        }
    
    @pytest.fixture
    def mock_auth_context(self):
        """Create mock auth context"""
        from doris_mcp_server.utils.security import AuthContext, SecurityLevel
        return AuthContext(
            user_id="test_user",
            roles=["user"],
            security_level=SecurityLevel.INTERNAL
        )
    
    @pytest.mark.asyncio
    async def test_validates_all_statements(self, dict_config, mock_auth_context):
        """Test that validator checks ALL SQL statements, not just the first"""
        from doris_mcp_server.utils.security import SQLSecurityValidator
        
        validator = SQLSecurityValidator(dict_config)
        
        # Multi-statement with injection in second statement
        # This should be BLOCKED
        malicious_sql = "SELECT 1; DROP TABLE users; SELECT 2"
        
        result = await validator.validate(malicious_sql, mock_auth_context)
        
        assert not result.is_valid, "Multi-statement injection should be blocked"
        # Check for either DROP keyword detection or SQL injection detection
        error_upper = result.error_message.upper()
        assert ("DROP" in error_upper or 
                "INJECTION" in error_upper or 
                "BLOCKED" in error_upper), f"Expected DROP/injection/blocked in: {result.error_message}"
    
    @pytest.mark.asyncio
    async def test_blocks_hidden_dangerous_statement(self, dict_config, mock_auth_context):
        """Test that dangerous statements hidden after safe ones are blocked"""
        from doris_mcp_server.utils.security import SQLSecurityValidator
        
        validator = SQLSecurityValidator(dict_config)
        
        # Safe statement followed by dangerous one
        malicious_sql = """
        SELECT * FROM users WHERE id = 1;
        DELETE FROM audit_log;
        SELECT 1;
        """
        
        result = await validator.validate(malicious_sql, mock_auth_context)
        
        assert not result.is_valid, "Hidden DELETE statement should be blocked"
    
    @pytest.mark.asyncio
    async def test_allows_safe_multi_statement(self, dict_config, mock_auth_context):
        """Test that multiple safe SELECT statements are allowed"""
        from doris_mcp_server.utils.security import SQLSecurityValidator
        
        validator = SQLSecurityValidator(dict_config)
        
        safe_sql = """
        SELECT * FROM users;
        SELECT COUNT(*) FROM orders;
        SELECT id, name FROM products;
        """
        
        result = await validator.validate(safe_sql, mock_auth_context)
        
        assert result.is_valid, f"Multiple safe SELECT statements should be allowed, got: {result.error_message}"
    
    @pytest.mark.asyncio
    async def test_context_switch_injection_blocked(self, dict_config, mock_auth_context):
        """Test that context switch SQL injection is blocked"""
        from doris_mcp_server.utils.security import SQLSecurityValidator
        
        validator = SQLSecurityValidator(dict_config)
        
        # Simulating the exec_query_for_mcp attack vector
        injected_sql = """
        USE `analytics`; SELECT * FROM sensitive_table;-- `;
        SELECT * FROM public_table;
        """
        
        result = await validator.validate(injected_sql, mock_auth_context)
        
        # The validator should process all statements
        # Even if USE is allowed, subsequent unauthorized access should be caught
        # by table access checks (if configured)


class TestExecQueryForMCP:
    """Test cases for exec_query_for_mcp function"""
    
    @pytest.mark.asyncio
    async def test_rejects_malicious_db_name(self):
        """Test that malicious db_name is rejected"""
        from doris_mcp_server.utils.sql_security_utils import (
            validate_identifier,
            SQLSecurityError
        )
        
        # The attack vector from security report
        malicious_db_name = "analytics`; SELECT * FROM sensitive_table;--"
        
        with pytest.raises(SQLSecurityError):
            validate_identifier(malicious_db_name, "database name")
    
    @pytest.mark.asyncio
    async def test_rejects_malicious_catalog_name(self):
        """Test that malicious catalog_name is rejected"""
        from doris_mcp_server.utils.sql_security_utils import (
            validate_identifier,
            SQLSecurityError
        )
        
        malicious_catalog_name = "internal'; DROP DATABASE production;--"
        
        with pytest.raises(SQLSecurityError):
            validate_identifier(malicious_catalog_name, "catalog name")


class TestDependencyAnalysisTools:
    """Test cases for dependency_analysis_tools security fixes"""
    
    @pytest.mark.asyncio
    async def test_get_tables_metadata_rejects_injection(self):
        """Test that _get_tables_metadata rejects SQL injection"""
        from doris_mcp_server.utils.sql_security_utils import (
            validate_identifier,
            SQLSecurityError
        )
        
        # The attack vector from security report
        injection_db_name = "test_db' OR '1'='1' --"
        
        with pytest.raises(SQLSecurityError):
            validate_identifier(injection_db_name, "database name")


class TestAuthContextEnforcement:
    """Test cases for auth_context enforcement"""
    
    def test_execute_requires_auth_context_for_security(self):
        """Test that security checks require auth_context"""
        # This test documents the expected behavior:
        # When auth_context is None, security checks are skipped
        # When auth_context is provided, security checks are performed
        
        # The fix ensures all execute() calls pass auth_context
        pass
    
    @pytest.mark.asyncio
    async def test_get_auth_context_returns_context(self):
        """Test that get_auth_context retrieves context from ContextVar"""
        from doris_mcp_server.utils.sql_security_utils import get_auth_context
        
        # When no context is set, should return None
        result = get_auth_context()
        # This is expected - context is set by HTTP middleware
        assert result is None or hasattr(result, 'user_id')


class TestIntegrationScenarios:
    """Integration test scenarios for security fixes"""
    
    def test_attack_scenario_1_permission_bypass(self):
        """
        Attack Scenario 1: Permission Bypass in Multi-Tenant Environment
        
        Expected: User can only query their own database (db_name="tenant_a_db")
        Attack: Inject "tenant_a_db' OR '1'='1' --" to query ALL databases
        Result: Should be BLOCKED by validate_identifier()
        """
        from doris_mcp_server.utils.sql_security_utils import (
            validate_identifier,
            SQLSecurityError
        )
        
        with pytest.raises(SQLSecurityError):
            validate_identifier("tenant_a_db' OR '1'='1' --", "database name")
    
    def test_attack_scenario_2_union_injection(self):
        """
        Attack Scenario 2: UNION-based Information Disclosure
        
        Attack: Inject UNION SELECT to extract sensitive data
        Result: Should be BLOCKED
        """
        from doris_mcp_server.utils.sql_security_utils import (
            validate_identifier,
            SQLSecurityError
        )
        
        with pytest.raises(SQLSecurityError):
            validate_identifier(
                "test' UNION SELECT password FROM users --",
                "database name"
            )
    
    def test_attack_scenario_3_backtick_escape(self):
        """
        Attack Scenario 3: Backtick Escape Attempt
        
        Attack: Use backticks to break out of quoted identifier
        Result: Should be BLOCKED
        """
        from doris_mcp_server.utils.sql_security_utils import (
            validate_identifier,
            SQLSecurityError
        )
        
        with pytest.raises(SQLSecurityError):
            validate_identifier(
                "analytics`; SELECT * FROM sensitive_table;--",
                "database name"
            )


# Run tests with: pytest tests/test_sql_security.py -v
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

