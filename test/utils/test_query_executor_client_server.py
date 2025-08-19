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
Query Executor Client-Server Integration Tests

Tests the query execution functionality through actual MCP client-server communication
Assumes the server is already running and configured properly
"""

import pytest
import os
import sys
from typing import Dict, Any

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from test.test_config_loader import get_test_config, create_test_client, test_server_connectivity


class TestQueryExecutorClientServer:
    """Test query execution functionality through client-server communication"""

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
    async def test_simple_select_query_via_client(self, client, test_config):
        """Test simple SELECT query through client"""
        sample_queries = test_config.get_sample_queries()
        
        async def test_callback(client_instance):
            result = await client_instance.execute_sql(sample_queries[0])  # "SELECT 1 as test_value"
            
            # Verify result structure
            assert "success" in result, "Result should contain 'success' field"
            
            if result["success"]:
                assert "data" in result, "Successful result should contain 'data' field"
            else:
                assert "error" in result, "Failed result should contain 'error' field"
            
            return result
        
        await client.connect_and_run(test_callback)

    @pytest.mark.asyncio
    async def test_show_databases_query_via_client(self, client, test_config):
        """Test SHOW DATABASES query through client"""
        sample_queries = test_config.get_sample_queries()
        
        async def test_callback(client_instance):
            result = await client_instance.execute_sql(sample_queries[1])  # "SHOW DATABASES"
            
            # Verify result structure
            assert "success" in result, "Result should contain 'success' field"
            return result
        
        await client.connect_and_run(test_callback)

    @pytest.mark.asyncio
    async def test_information_schema_query_via_client(self, client, test_config):
        """Test information_schema query through client"""
        sample_queries = test_config.get_sample_queries()
        
        async def test_callback(client_instance):
            result = await client_instance.execute_sql(sample_queries[2])  # "SELECT COUNT(*) FROM information_schema.tables"
            
            # Verify result structure
            assert "success" in result, "Result should contain 'success' field"
            return result
        
        await client.connect_and_run(test_callback)

    @pytest.mark.asyncio
    async def test_query_with_max_rows_parameter_via_client(self, client, test_config):
        """Test query with max_rows parameter through client"""
        async def test_callback(client_instance):
            result = await client_instance.call_tool("exec_query", {
                "sql": "SELECT 1 as test_value",
                "max_rows": 10
            })
            
            # Verify result structure
            assert "success" in result, "Result should contain 'success' field"
            return result
        
        await client.connect_and_run(test_callback)

    @pytest.mark.asyncio
    async def test_query_error_handling_via_client(self, client, test_config):
        """Test query error handling through client"""
        async def test_callback(client_instance):
            result = await client_instance.execute_sql("INVALID SQL SYNTAX")
            
            # Should get a result (either success or error)
            assert "success" in result, "Result should contain 'success' field"
            return result
        
        await client.connect_and_run(test_callback)

    @pytest.mark.asyncio
    async def test_query_with_auth_token_via_client(self, client, test_config):
        """Test query with authentication token"""
        if not test_config.is_security_tests_enabled():
            pytest.skip("Security tests are disabled")
        
        auth_tokens = test_config.get_auth_tokens()
        
        async def test_callback(client_instance):
            result = await client_instance.call_tool("exec_query", {
                "sql": "SELECT 1 as test_value",
                "auth_token": auth_tokens["valid_token"]
            })
            
            # Verify result structure
            assert "success" in result, "Result should contain 'success' field"
            return result
        
        await client.connect_and_run(test_callback)
