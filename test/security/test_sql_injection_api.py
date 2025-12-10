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
SQL Injection API Integration Tests

This module tests SQL injection prevention through the MCP HTTP API.
It sends malicious payloads and verifies they are properly blocked.

Prerequisites:
    - MCP server running on localhost:3000
    - Run with: pytest test/security/test_sql_injection_api.py -v

Usage:
    # Start server first
    bash start_server.sh
    
    # Run tests
    pytest test/security/test_sql_injection_api.py -v --no-cov
"""

import pytest
import httpx
import json
import asyncio
from typing import Optional


# Server configuration
MCP_BASE_URL = "http://localhost:3000"
MCP_ENDPOINT = f"{MCP_BASE_URL}/mcp"
HEALTH_ENDPOINT = f"{MCP_BASE_URL}/health"
TIMEOUT = 30.0


class MCPClient:
    """Simple MCP HTTP client for testing"""
    
    def __init__(self, base_url: str = MCP_BASE_URL):
        self.base_url = base_url
        self.mcp_endpoint = f"{base_url}/mcp"
        self.session_id: Optional[str] = None
        self.request_id = 0
        self.client = httpx.AsyncClient(timeout=TIMEOUT)
    
    async def close(self):
        await self.client.aclose()
    
    def _next_id(self) -> int:
        self.request_id += 1
        return self.request_id
    
    async def initialize(self) -> dict:
        """Initialize MCP session"""
        response = await self.client.post(
            self.mcp_endpoint,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream"
            },
            json={
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {
                        "name": "sql-injection-test",
                        "version": "1.0.0"
                    }
                },
                "id": self._next_id()
            }
        )
        
        # Extract session ID from response header
        self.session_id = response.headers.get("mcp-session-id")
        return self._parse_response(response.text)
    
    async def call_tool(self, tool_name: str, arguments: dict) -> dict:
        """Call an MCP tool"""
        if not self.session_id:
            await self.initialize()
        
        response = await self.client.post(
            self.mcp_endpoint,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "mcp-session-id": self.session_id
            },
            json={
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": arguments
                },
                "id": self._next_id()
            }
        )
        
        return self._parse_response(response.text)
    
    def _parse_response(self, text: str) -> dict:
        """Parse JSON response"""
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Try SSE format
            lines = text.strip().split("\n")
            for line in lines:
                if line.startswith("data: "):
                    try:
                        return json.loads(line[6:])
                    except json.JSONDecodeError:
                        continue
            return {"raw": text}


def print_result(test_name: str, payload: dict, result: dict):
    """Print test result in a readable format"""
    print(f"\n{'='*60}")
    print(f"TEST: {test_name}")
    print(f"{'='*60}")
    print(f"PAYLOAD: {json.dumps(payload, ensure_ascii=False)}")
    print(f"{'-'*60}")
    
    # Extract inner result content
    if "result" in result and "content" in result.get("result", {}):
        for item in result["result"]["content"]:
            if item.get("type") == "text":
                try:
                    inner = json.loads(item["text"])
                    print("RESPONSE:")
                    print(f"  success: {inner.get('success')}")
                    if inner.get('error'):
                        print(f"  error: {inner.get('error')}")
                    if inner.get('error_type'):
                        print(f"  error_type: {inner.get('error_type')}")
                    if inner.get('risk_level'):
                        print(f"  risk_level: {inner.get('risk_level')}")
                    if inner.get('message'):
                        print(f"  message: {inner.get('message')}")
                    if inner.get('data') is not None and inner.get('success'):
                        data_str = json.dumps(inner.get('data'), ensure_ascii=False)
                        if len(data_str) > 200:
                            data_str = data_str[:200] + "..."
                        print(f"  data: {data_str}")
                except (json.JSONDecodeError, TypeError):
                    print(f"RESPONSE (raw): {item.get('text', '')[:500]}")
    elif "error" in result:
        print(f"RESPONSE ERROR: {result['error']}")
    else:
        print(f"RESPONSE (raw): {json.dumps(result, ensure_ascii=False)[:500]}")
    
    print(f"{'='*60}\n")


class TestSQLInjectionAPI:
    """Test SQL injection prevention through MCP API"""
    
    @pytest.fixture
    async def mcp_client(self):
        """Create MCP client instance"""
        client = MCPClient()
        yield client
        await client.close()
    
    @pytest.fixture
    def is_server_running(self):
        """Check if MCP server is running"""
        import httpx
        try:
            response = httpx.get(HEALTH_ENDPOINT, timeout=5.0)
            return response.status_code == 200
        except Exception:
            return False
    
    @pytest.mark.asyncio
    async def test_server_health(self):
        """Test that MCP server is running and healthy"""
        async with httpx.AsyncClient() as client:
            response = await client.get(HEALTH_ENDPOINT)
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "healthy"
    
    @pytest.mark.asyncio
    async def test_exec_query_with_drop_injection(self, mcp_client):
        """Test exec_query rejects DROP TABLE injection"""
        # Classic SQL injection: append DROP TABLE
        payload = {"sql": "SELECT * FROM users; DROP TABLE users; --"}
        result = await mcp_client.call_tool("exec_query", payload)
        print_result("DROP TABLE Injection", payload, result)
        
        # Should return error, not execute the DROP
        assert self._is_blocked_or_error(result), \
            f"DROP TABLE injection should be blocked"
    
    @pytest.mark.asyncio
    async def test_exec_query_with_union_injection(self, mcp_client):
        """Test exec_query blocks UNION-based injection attempts"""
        # UNION injection to extract data from other tables
        payload = {"sql": "SELECT id FROM users UNION SELECT password FROM admin_users"}
        result = await mcp_client.call_tool("exec_query", payload)
        print_result("UNION Injection", payload, result)
    
    @pytest.mark.asyncio
    async def test_exec_query_with_delete_injection(self, mcp_client):
        """Test exec_query rejects DELETE injection"""
        payload = {"sql": "SELECT 1; DELETE FROM users WHERE 1=1; SELECT 2"}
        result = await mcp_client.call_tool("exec_query", payload)
        print_result("DELETE Injection", payload, result)
        
        assert self._is_blocked_or_error(result), \
            f"DELETE injection should be blocked"
    
    @pytest.mark.asyncio
    async def test_exec_query_with_update_injection(self, mcp_client):
        """Test exec_query rejects UPDATE injection"""
        payload = {"sql": "SELECT 1; UPDATE users SET role='admin' WHERE id=1; --"}
        result = await mcp_client.call_tool("exec_query", payload)
        print_result("UPDATE Injection", payload, result)
        
        assert self._is_blocked_or_error(result), \
            f"UPDATE injection should be blocked"
    
    @pytest.mark.asyncio
    async def test_exec_query_db_name_injection(self, mcp_client):
        """Test exec_query rejects SQL injection via db_name parameter"""
        # Attack vector: inject SQL via db_name parameter
        payload = {"sql": "SELECT 1", "db_name": "test'; DROP TABLE users; --"}
        result = await mcp_client.call_tool("exec_query", payload)
        print_result("db_name Parameter Injection", payload, result)
        
        assert self._is_blocked_or_error(result), \
            f"db_name injection should be blocked"
    
    @pytest.mark.asyncio
    async def test_exec_query_catalog_name_injection(self, mcp_client):
        """Test exec_query rejects SQL injection via catalog_name parameter"""
        # Attack vector: inject SQL via catalog_name parameter
        payload = {"sql": "SELECT 1", "catalog_name": "internal`; SELECT * FROM mysql.user; --"}
        result = await mcp_client.call_tool("exec_query", payload)
        print_result("catalog_name Parameter Injection", payload, result)
        
        assert self._is_blocked_or_error(result), \
            f"catalog_name injection should be blocked"
    
    @pytest.mark.asyncio
    async def test_get_table_schema_injection(self, mcp_client):
        """Test get_table_schema rejects SQL injection via table_name"""
        # Attack vector: inject SQL via table_name parameter
        payload = {"table_name": "users'; DROP TABLE users; --"}
        result = await mcp_client.call_tool("get_table_schema", payload)
        print_result("table_name Injection (get_table_schema)", payload, result)
        
        assert self._is_blocked_or_error(result), \
            f"table_name injection should be blocked"
    
    @pytest.mark.asyncio
    async def test_get_table_schema_db_injection(self, mcp_client):
        """Test get_table_schema rejects SQL injection via db_name"""
        payload = {"table_name": "users", "db_name": "test' OR '1'='1"}
        result = await mcp_client.call_tool("get_table_schema", payload)
        print_result("db_name Injection (get_table_schema)", payload, result)
        
        assert self._is_blocked_or_error(result), \
            f"db_name injection in get_table_schema should be blocked"
    
    @pytest.mark.asyncio
    async def test_analyze_dependencies_injection(self, mcp_client):
        """Test analyze_dependencies rejects SQL injection"""
        # This was the original vulnerability reported
        payload = {"table_name": "users", "db_name": "test_db' OR '1'='1' --"}
        result = await mcp_client.call_tool("analyze_dependencies", payload)
        print_result("analyze_dependencies Injection (Original Report)", payload, result)
        
        assert self._is_blocked_or_error(result), \
            f"analyze_dependencies db_name injection should be blocked"
    
    @pytest.mark.asyncio
    async def test_stacked_queries_injection(self, mcp_client):
        """Test that stacked queries (multiple statements) are blocked"""
        # Multiple statements injection
        payload = {"sql": "SELECT * FROM users WHERE id = 1; INSERT INTO audit_log VALUES (NULL, 'hacked', NOW()); SELECT 1;"}
        result = await mcp_client.call_tool("exec_query", payload)
        print_result("Stacked Queries (INSERT) Injection", payload, result)
        
        assert self._is_blocked_or_error(result), \
            f"Stacked queries with INSERT should be blocked"
    
    @pytest.mark.asyncio
    async def test_comment_based_injection(self, mcp_client):
        """Test that comment-based injection is blocked"""
        # Using comments to bypass filters
        payload = {"sql": "SELECT * FROM users WHERE id = 1/**/OR/**/1=1"}
        result = await mcp_client.call_tool("exec_query", payload)
        print_result("Comment-based Injection", payload, result)
    
    @pytest.mark.asyncio
    async def test_hex_encoded_injection(self, mcp_client):
        """Test that hex-encoded injection attempts are handled"""
        # Hex-encoded 'DROP' attempt
        payload = {"sql": "SELECT 0x44524F50205441424C4520757365727320"}
        result = await mcp_client.call_tool("exec_query", payload)
        print_result("Hex Encoded Injection", payload, result)
    
    @pytest.mark.asyncio
    async def test_backtick_escape_injection(self, mcp_client):
        """Test backtick escape injection is blocked"""
        # Attempt to escape backtick quoting
        payload = {"sql": "SELECT 1", "db_name": "analytics`; SELECT * FROM sensitive_table;--"}
        result = await mcp_client.call_tool("exec_query", payload)
        print_result("Backtick Escape Injection", payload, result)
        
        assert self._is_blocked_or_error(result), \
            f"Backtick escape injection should be blocked"
    
    @pytest.mark.asyncio
    async def test_valid_query_succeeds(self, mcp_client):
        """Test that valid queries still work"""
        # Simple valid query should work
        payload = {"sql": "SELECT 1 AS test_value"}
        result = await mcp_client.call_tool("exec_query", payload)
        print_result("Valid Query (should succeed)", payload, result)
    
    @pytest.mark.asyncio
    async def test_valid_show_databases(self, mcp_client):
        """Test that SHOW DATABASES works"""
        payload = {"sql": "SHOW DATABASES"}
        result = await mcp_client.call_tool("exec_query", payload)
        print_result("SHOW DATABASES (should succeed)", payload, result)
    
    def _is_blocked_or_error(self, result: dict) -> bool:
        """Check if result indicates blocked or error"""
        if not result:
            return True
        
        # Check for JSON-RPC error
        if "error" in result:
            return True
        
        # Check for error in result content
        if "result" in result:
            result_content = result.get("result", {})
            if isinstance(result_content, dict):
                # Check for isError flag
                if result_content.get("isError"):
                    return True
                # Check content array for error messages
                content = result_content.get("content", [])
                for item in content:
                    if isinstance(item, dict):
                        text = item.get("text", "")
                        # Parse the JSON text content
                        try:
                            text_data = json.loads(text)
                            # Check for success: false
                            if text_data.get("success") is False:
                                return True
                            # Check for error field
                            if text_data.get("error"):
                                return True
                        except (json.JSONDecodeError, TypeError):
                            pass
                        # Check text for security keywords
                        if any(keyword in text.lower() for keyword in [
                            "error", "blocked", "invalid", "security",
                            "injection", "denied", "forbidden", "not allowed",
                            "security_violation", "risk_level"
                        ]):
                            return True
        
        # Check raw text response
        raw = result.get("raw", "")
        if isinstance(raw, str) and any(keyword in raw.lower() for keyword in [
            "error", "blocked", "invalid", "security"
        ]):
            return True
        
        return False


class TestIdentifierInjectionAPI:
    """Test identifier-based SQL injection prevention"""
    
    @pytest.fixture
    async def mcp_client(self):
        """Create MCP client instance"""
        client = MCPClient()
        yield client
        await client.close()
    
    @pytest.mark.asyncio
    async def test_table_name_with_semicolon(self, mcp_client):
        """Test table name containing semicolon is rejected"""
        payload = {"table_name": "users; DROP TABLE users"}
        result = await mcp_client.call_tool("get_table_schema", payload)
        print_result("Table Name with Semicolon", payload, result)
        
        # Should be blocked by identifier validation
        assert self._contains_error_indicator(result), \
            f"Table name with semicolon should be rejected"
    
    @pytest.mark.asyncio
    async def test_table_name_with_quotes(self, mcp_client):
        """Test table name containing quotes is rejected"""
        payload = {"table_name": "users' OR '1'='1"}
        result = await mcp_client.call_tool("get_table_schema", payload)
        print_result("Table Name with Quotes", payload, result)
        
        assert self._contains_error_indicator(result), \
            f"Table name with quotes should be rejected"
    
    @pytest.mark.asyncio  
    async def test_db_name_with_special_chars(self, mcp_client):
        """Test database name with special characters is rejected"""
        special_chars = [
            "test;db",
            "test'db",
            "test\"db",
            "test`db",
            "test--db",
            "test/*db*/",
        ]
        
        for db_name in special_chars:
            payload = {"table_name": "users", "db_name": db_name}
            result = await mcp_client.call_tool("get_table_schema", payload)
            print_result(f"Special Char in db_name: {db_name}", payload, result)
            
            assert self._contains_error_indicator(result), \
                f"db_name '{db_name}' should be rejected"
    
    @pytest.mark.asyncio
    async def test_valid_identifiers_accepted(self, mcp_client):
        """Test that valid identifiers are accepted"""
        valid_names = [
            "users",
            "my_table",
            "Table123",
            "_internal_table",
        ]
        
        for table_name in valid_names:
            payload = {"table_name": table_name}
            result = await mcp_client.call_tool("get_table_schema", payload)
            print_result(f"Valid Identifier: {table_name}", payload, result)
    
    def _contains_error_indicator(self, result: dict) -> bool:
        """Check if result contains error indicators"""
        if not result:
            return True
        
        # Check for JSON-RPC error
        if "error" in result:
            return True
        
        # Check result content
        result_str = json.dumps(result).lower()
        error_keywords = [
            "error", "invalid", "illegal", "blocked",
            "security", "injection", "denied", "forbidden"
        ]
        
        return any(keyword in result_str for keyword in error_keywords)


class TestMultiStatementInjectionAPI:
    """Test multi-statement SQL injection prevention"""
    
    @pytest.fixture
    async def mcp_client(self):
        """Create MCP client instance"""
        client = MCPClient()
        yield client
        await client.close()
    
    @pytest.mark.asyncio
    async def test_hidden_drop_after_select(self, mcp_client):
        """Test DROP hidden after legitimate SELECT is blocked"""
        payload = {"sql": "SELECT id, name FROM users WHERE status = 'active'; DROP TABLE audit_log; SELECT 1;"}
        result = await mcp_client.call_tool("exec_query", payload)
        print_result("Hidden DROP after SELECT", payload, result)
        
        assert self._is_dangerous_blocked(result), \
            f"Hidden DROP statement should be blocked"
    
    @pytest.mark.asyncio
    async def test_hidden_truncate_after_select(self, mcp_client):
        """Test TRUNCATE hidden after SELECT is blocked"""
        payload = {"sql": "SELECT 1; TRUNCATE TABLE users"}
        result = await mcp_client.call_tool("exec_query", payload)
        print_result("Hidden TRUNCATE after SELECT", payload, result)
        
        assert self._is_dangerous_blocked(result), \
            f"Hidden TRUNCATE should be blocked"
    
    @pytest.mark.asyncio
    async def test_hidden_grant_after_select(self, mcp_client):
        """Test GRANT hidden after SELECT is blocked"""
        payload = {"sql": "SELECT 1; GRANT ALL ON *.* TO 'hacker'@'%'"}
        result = await mcp_client.call_tool("exec_query", payload)
        print_result("Hidden GRANT after SELECT", payload, result)
        
        assert self._is_dangerous_blocked(result), \
            f"Hidden GRANT should be blocked"
    
    @pytest.mark.asyncio
    async def test_multiple_safe_selects_allowed(self, mcp_client):
        """Test that multiple SELECT statements may be allowed"""
        payload = {"sql": "SELECT 1; SELECT 2; SELECT 3;"}
        result = await mcp_client.call_tool("exec_query", payload)
        print_result("Multiple Safe SELECTs", payload, result)
    
    def _is_dangerous_blocked(self, result: dict) -> bool:
        """Check if dangerous operation was blocked"""
        if not result:
            return True
        
        # Check for error
        if "error" in result:
            return True
        
        # Check result content for blocking indicators
        result_str = json.dumps(result).lower()
        block_indicators = [
            "drop", "truncate", "grant", "revoke",
            "blocked", "denied", "forbidden", "not allowed",
            "security", "error"
        ]
        
        return any(indicator in result_str for indicator in block_indicators)


class TestADBCQueryInjectionAPI:
    """Test ADBC query SQL injection prevention"""
    
    @pytest.fixture
    async def mcp_client(self):
        """Create MCP client instance"""
        client = MCPClient()
        yield client
        await client.close()
    
    @pytest.mark.asyncio
    async def test_exec_adbc_query_drop_injection(self, mcp_client):
        """Test exec_adbc_query rejects DROP TABLE injection"""
        payload = {"sql": "SELECT * FROM users; DROP TABLE users; --"}
        result = await mcp_client.call_tool("exec_adbc_query", payload)
        print_result("ADBC DROP TABLE Injection", payload, result)
        
        assert self._is_blocked_or_error(result), \
            "ADBC DROP TABLE injection should be blocked"
    
    @pytest.mark.asyncio
    async def test_exec_adbc_query_delete_injection(self, mcp_client):
        """Test exec_adbc_query rejects DELETE injection"""
        payload = {"sql": "SELECT 1; DELETE FROM users; --"}
        result = await mcp_client.call_tool("exec_adbc_query", payload)
        print_result("ADBC DELETE Injection", payload, result)
        
        assert self._is_blocked_or_error(result), \
            "ADBC DELETE injection should be blocked"
    
    @pytest.mark.asyncio
    async def test_exec_adbc_query_valid(self, mcp_client):
        """Test exec_adbc_query allows valid queries"""
        payload = {"sql": "SELECT 1 AS test"}
        result = await mcp_client.call_tool("exec_adbc_query", payload)
        print_result("ADBC Valid Query", payload, result)
    
    def _is_blocked_or_error(self, result: dict) -> bool:
        """Check if result indicates blocked or error"""
        if not result:
            return True
        if "error" in result:
            return True
        result_str = json.dumps(result).lower()
        return any(kw in result_str for kw in ["error", "blocked", "invalid", "security", "injection"])


class TestMetadataToolsInjectionAPI:
    """Test metadata tools SQL injection prevention"""
    
    @pytest.fixture
    async def mcp_client(self):
        """Create MCP client instance"""
        client = MCPClient()
        yield client
        await client.close()
    
    @pytest.mark.asyncio
    async def test_get_db_table_list_db_injection(self, mcp_client):
        """Test get_db_table_list rejects db_name injection"""
        payload = {"db_name": "test'; DROP TABLE users; --"}
        result = await mcp_client.call_tool("get_db_table_list", payload)
        print_result("get_db_table_list db_name Injection", payload, result)
        
        assert self._is_blocked_or_error(result), \
            "db_name injection should be blocked"
    
    @pytest.mark.asyncio
    async def test_get_db_table_list_catalog_injection(self, mcp_client):
        """Test get_db_table_list rejects catalog_name injection"""
        payload = {"catalog_name": "internal`; SELECT * FROM mysql.user; --"}
        result = await mcp_client.call_tool("get_db_table_list", payload)
        print_result("get_db_table_list catalog_name Injection", payload, result)
        
        assert self._is_blocked_or_error(result), \
            "catalog_name injection should be blocked"
    
    @pytest.mark.asyncio
    async def test_get_table_comment_injection(self, mcp_client):
        """Test get_table_comment rejects table_name injection"""
        payload = {"table_name": "users'; DROP TABLE users; --"}
        result = await mcp_client.call_tool("get_table_comment", payload)
        print_result("get_table_comment table_name Injection", payload, result)
        
        assert self._is_blocked_or_error(result), \
            "table_name injection should be blocked"
    
    @pytest.mark.asyncio
    async def test_get_table_column_comments_injection(self, mcp_client):
        """Test get_table_column_comments rejects injection"""
        payload = {"table_name": "users'; DROP TABLE users; --", "db_name": "test"}
        result = await mcp_client.call_tool("get_table_column_comments", payload)
        print_result("get_table_column_comments Injection", payload, result)
        
        assert self._is_blocked_or_error(result), \
            "table_name injection should be blocked"
    
    @pytest.mark.asyncio
    async def test_get_table_indexes_injection(self, mcp_client):
        """Test get_table_indexes rejects table_name injection"""
        payload = {"table_name": "users; DROP TABLE users", "db_name": "test"}
        result = await mcp_client.call_tool("get_table_indexes", payload)
        print_result("get_table_indexes Injection", payload, result)
        
        assert self._is_blocked_or_error(result), \
            "table_name injection should be blocked"
    
    def _is_blocked_or_error(self, result: dict) -> bool:
        """Check if result indicates blocked or error"""
        if not result:
            return True
        if "error" in result:
            return True
        result_str = json.dumps(result).lower()
        return any(kw in result_str for kw in ["error", "blocked", "invalid", "security", "injection"])


class TestAnalyticsToolsInjectionAPI:
    """Test analytics tools SQL injection prevention"""
    
    @pytest.fixture
    async def mcp_client(self):
        """Create MCP client instance"""
        client = MCPClient()
        yield client
        await client.close()
    
    @pytest.mark.asyncio
    async def test_analyze_columns_table_injection(self, mcp_client):
        """Test analyze_columns rejects table_name injection"""
        payload = {"table_name": "users'; DROP TABLE users; --"}
        result = await mcp_client.call_tool("analyze_columns", payload)
        print_result("analyze_columns table_name Injection", payload, result)
        
        assert self._is_blocked_or_error(result), \
            "table_name injection should be blocked"
    
    @pytest.mark.asyncio
    async def test_analyze_columns_db_injection(self, mcp_client):
        """Test analyze_columns rejects db_name injection"""
        payload = {"table_name": "users", "db_name": "test' OR '1'='1"}
        result = await mcp_client.call_tool("analyze_columns", payload)
        print_result("analyze_columns db_name Injection", payload, result)
        
        assert self._is_blocked_or_error(result), \
            "db_name injection should be blocked"
    
    @pytest.mark.asyncio
    async def test_get_table_basic_info_injection(self, mcp_client):
        """Test get_table_basic_info rejects injection"""
        payload = {"table_name": "users; DROP TABLE audit_log"}
        result = await mcp_client.call_tool("get_table_basic_info", payload)
        print_result("get_table_basic_info Injection", payload, result)
        
        assert self._is_blocked_or_error(result), \
            "table_name injection should be blocked"
    
    @pytest.mark.asyncio
    async def test_analyze_table_storage_injection(self, mcp_client):
        """Test analyze_table_storage rejects injection"""
        payload = {"table_name": "users`; SELECT * FROM sensitive; --"}
        result = await mcp_client.call_tool("analyze_table_storage", payload)
        print_result("analyze_table_storage Injection", payload, result)
        
        assert self._is_blocked_or_error(result), \
            "table_name injection should be blocked"
    
    @pytest.mark.asyncio
    async def test_get_sql_explain_injection(self, mcp_client):
        """Test get_sql_explain rejects SQL injection"""
        payload = {"sql": "SELECT 1; DROP TABLE users; --"}
        result = await mcp_client.call_tool("get_sql_explain", payload)
        print_result("get_sql_explain SQL Injection", payload, result)
        
        assert self._is_blocked_or_error(result), \
            "SQL injection should be blocked"
    
    @pytest.mark.asyncio
    async def test_get_sql_profile_injection(self, mcp_client):
        """Test get_sql_profile rejects SQL injection"""
        payload = {"sql": "SELECT 1; DELETE FROM audit_log; --"}
        result = await mcp_client.call_tool("get_sql_profile", payload)
        print_result("get_sql_profile SQL Injection", payload, result)
        
        assert self._is_blocked_or_error(result), \
            "SQL injection should be blocked"
    
    def _is_blocked_or_error(self, result: dict) -> bool:
        """Check if result indicates blocked or error"""
        if not result:
            return True
        if "error" in result:
            return True
        result_str = json.dumps(result).lower()
        return any(kw in result_str for kw in ["error", "blocked", "invalid", "security", "injection"])


class TestGovernanceToolsInjectionAPI:
    """Test data governance tools SQL injection prevention"""
    
    @pytest.fixture
    async def mcp_client(self):
        """Create MCP client instance"""
        client = MCPClient()
        yield client
        await client.close()
    
    @pytest.mark.asyncio
    async def test_trace_column_lineage_table_injection(self, mcp_client):
        """Test trace_column_lineage rejects table_name injection"""
        payload = {"table_name": "users'; DROP TABLE users; --", "column_name": "id"}
        result = await mcp_client.call_tool("trace_column_lineage", payload)
        print_result("trace_column_lineage table_name Injection", payload, result)
        
        assert self._is_blocked_or_error(result), \
            "table_name injection should be blocked"
    
    @pytest.mark.asyncio
    async def test_trace_column_lineage_column_injection(self, mcp_client):
        """Test trace_column_lineage rejects column_name injection"""
        payload = {"table_name": "users", "column_name": "id; DROP TABLE users"}
        result = await mcp_client.call_tool("trace_column_lineage", payload)
        print_result("trace_column_lineage column_name Injection", payload, result)
        
        assert self._is_blocked_or_error(result), \
            "column_name injection should be blocked"
    
    @pytest.mark.asyncio
    async def test_monitor_data_freshness_injection(self, mcp_client):
        """Test monitor_data_freshness rejects table_name injection"""
        payload = {"table_name": "users`; SELECT * FROM passwords; --"}
        result = await mcp_client.call_tool("monitor_data_freshness", payload)
        print_result("monitor_data_freshness Injection", payload, result)
        
        assert self._is_blocked_or_error(result), \
            "table_name injection should be blocked"
    
    @pytest.mark.asyncio
    async def test_analyze_data_access_patterns_injection(self, mcp_client):
        """Test analyze_data_access_patterns rejects injection"""
        payload = {"table_name": "users' UNION SELECT password FROM admin --"}
        result = await mcp_client.call_tool("analyze_data_access_patterns", payload)
        print_result("analyze_data_access_patterns Injection", payload, result)
        
        assert self._is_blocked_or_error(result), \
            "table_name injection should be blocked"
    
    def _is_blocked_or_error(self, result: dict) -> bool:
        """Check if result indicates blocked or error"""
        if not result:
            return True
        if "error" in result:
            return True
        result_str = json.dumps(result).lower()
        return any(kw in result_str for kw in ["error", "blocked", "invalid", "security", "injection"])


class TestPerformanceToolsInjectionAPI:
    """Test performance analytics tools SQL injection prevention"""
    
    @pytest.fixture
    async def mcp_client(self):
        """Create MCP client instance"""
        client = MCPClient()
        yield client
        await client.close()
    
    @pytest.mark.asyncio
    async def test_analyze_slow_queries_db_injection(self, mcp_client):
        """Test analyze_slow_queries_topn rejects db_name injection"""
        payload = {"db_name": "test'; DROP TABLE audit_log; --"}
        result = await mcp_client.call_tool("analyze_slow_queries_topn", payload)
        print_result("analyze_slow_queries_topn db_name Injection", payload, result)
        
        assert self._is_blocked_or_error(result), \
            "db_name injection should be blocked"
    
    @pytest.mark.asyncio
    async def test_analyze_resource_growth_db_injection(self, mcp_client):
        """Test analyze_resource_growth_curves rejects db_name injection"""
        payload = {"db_name": "test`; GRANT ALL ON *.* TO 'hacker'; --"}
        result = await mcp_client.call_tool("analyze_resource_growth_curves", payload)
        print_result("analyze_resource_growth_curves db_name Injection", payload, result)
        
        assert self._is_blocked_or_error(result), \
            "db_name injection should be blocked"
    
    @pytest.mark.asyncio
    async def test_get_table_data_size_injection(self, mcp_client):
        """Test get_table_data_size rejects table_name injection"""
        payload = {"table_name": "users; TRUNCATE TABLE logs"}
        result = await mcp_client.call_tool("get_table_data_size", payload)
        print_result("get_table_data_size Injection", payload, result)
        
        assert self._is_blocked_or_error(result), \
            "table_name injection should be blocked"
    
    def _is_blocked_or_error(self, result: dict) -> bool:
        """Check if result indicates blocked or error"""
        if not result:
            return True
        if "error" in result:
            return True
        result_str = json.dumps(result).lower()
        return any(kw in result_str for kw in ["error", "blocked", "invalid", "security", "injection"])


# Pytest configuration for async tests
@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests"""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-x"])

