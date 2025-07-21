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
Tools Manager Client-Server Integration Tests

Tests the tools functionality through actual MCP client-server communication
Assumes the server is already running and configured properly
"""

import asyncio
import json
import pytest
import os
import sys
from typing import Dict, Any

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from test.test_config_loader import get_test_config, create_test_client, test_server_connectivity


class TestToolsClientServer:
    """Test tools functionality through client-server communication"""

    @pytest.fixture
    def test_config(self):
        """Get test configuration"""
        return get_test_config()

    @pytest.fixture
    async def client(self, test_config):
        """Create test client"""
        return create_test_client()

    @pytest.fixture(scope="class", autouse=True)
    async def check_server_connectivity(self):
        """Check server connectivity before running tests"""
        is_connected = await test_server_connectivity()
        if not is_connected:
            pytest.skip("Server is not running or not accessible")

    @pytest.mark.asyncio
    async def test_list_tools_via_client(self, client, test_config):
        """Test listing tools through client-server communication"""
        expected_tools = test_config.get_expected_tools()
        
        async def test_callback(client_instance):
            tools = await client_instance.list_all_tools()
            
            # Verify we got tools back
            assert len(tools) > 0, "No tools returned from server"
            
            # Verify expected tools are present
            tool_names = [tool.name for tool in tools]
            for expected_tool in expected_tools:
                assert expected_tool in tool_names, f"Expected tool '{expected_tool}' not found"
            
            return tools
        
        await client.connect_and_run(test_callback)

    @pytest.mark.asyncio
    async def test_call_tool_exec_query_via_client(self, client, test_config):
        """Test calling exec_query tool through client"""
        sample_queries = test_config.get_sample_queries()
        
        async def test_callback(client_instance):
            # Test with a simple query
            result = await client_instance.call_tool("exec_query", {
                "sql": sample_queries[0],  # "SELECT 1 as test_value"
                "max_rows": 100
            })
            
            # Verify result structure
            assert "success" in result, "Result should contain 'success' field"
            
            if result["success"]:
                assert "data" in result, "Successful result should contain 'data' field"
            else:
                assert "error" in result, "Failed result should contain 'error' field"
            
            return result
        
        await client.connect_and_run(test_callback)

    @pytest.mark.asyncio
    async def test_call_tool_get_db_list_via_client(self, client, test_config):
        """Test calling get_db_list tool through client"""
        async def test_callback(client_instance):
            result = await client_instance.call_tool("get_db_list", {})
            
            # Verify result structure
            assert "success" in result, "Result should contain 'success' field"
            
            if result["success"]:
                assert "result" in result, "Successful result should contain 'result' field"
                assert isinstance(result["result"], list), "Database list should be a list"
            
            return result
        
        await client.connect_and_run(test_callback)

    @pytest.mark.asyncio
    async def test_call_tool_get_table_schema_via_client(self, client, test_config):
        """Test calling get_table_schema tool through client"""
        test_tables = test_config.get_test_tables()
        
        async def test_callback(client_instance):
            result = await client_instance.call_tool("get_table_schema", {
                "table_name": test_tables[0],  # "users"
                "db_name": "information_schema"  # Use a database that should exist
            })
            
            # Verify result structure
            assert "success" in result, "Result should contain 'success' field"
            return result
        
        await client.connect_and_run(test_callback)

    @pytest.mark.asyncio
    async def test_tool_error_handling_via_client(self, client, test_config):
        """Test tool error handling through client"""
        async def test_callback(client_instance):
            # Try to call a tool with invalid parameters
            result = await client_instance.call_tool("exec_query", {
                "sql": "INVALID SQL SYNTAX HERE"
            })
            
            # Should get a result (either success or error)
            assert "success" in result, "Result should contain 'success' field"
            return result
        
        await client.connect_and_run(test_callback)

    @pytest.mark.asyncio
    async def test_tool_with_auth_token_via_client(self, client, test_config):
        """Test tool calls with authentication token"""
        if not test_config.is_security_tests_enabled():
            pytest.skip("Security tests are disabled")
        
        auth_tokens = test_config.get_auth_tokens()
        
        async def test_callback(client_instance):
            result = await client_instance.call_tool("get_db_list", {
                "auth_token": auth_tokens["valid_token"]
            })
            
            # Verify result structure
            assert "success" in result, "Result should contain 'success' field"
            return result
        
        await client.connect_and_run(test_callback)
