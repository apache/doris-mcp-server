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

import os
import sys

import pytest

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from test.test_config_loader import (
    create_test_client,
    get_test_config,
    test_server_connectivity,
)


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
    async def test_call_query_child_via_client(self, client, test_config):
        """Test calling the exact query child through the client."""
        sample_queries = test_config.get_sample_queries()

        async def test_callback(client_instance):
            result = await client_instance.execute_sql(
                sample_queries[0],
                max_rows=100,
            )

            assert result.get("mode") in {"result", "error"}

            return result

        await client.connect_and_run(test_callback)

    @pytest.mark.asyncio
    async def test_call_database_list_child_via_client(self, client, test_config):
        """Test calling the exact database-list child through the client."""
        async def test_callback(client_instance):
            result = await client_instance.get_database_list()

            assert result.get("mode") in {"result", "error"}

            return result

        await client.connect_and_run(test_callback)

    @pytest.mark.asyncio
    async def test_call_table_context_schema_via_client(self, client, test_config):
        """Test calling the schema section of table context."""
        test_tables = test_config.get_test_tables()

        async def test_callback(client_instance):
            result = await client_instance.get_table_schema(
                test_tables[0],
                "information_schema",
            )

            assert result.get("mode") in {"result", "error"}
            return result

        await client.connect_and_run(test_callback)

    @pytest.mark.asyncio
    async def test_tool_error_handling_via_client(self, client, test_config):
        """Test tool error handling through client"""
        async def test_callback(client_instance):
            result = await client_instance.execute_sql(
                "INVALID SQL SYNTAX HERE"
            )

            assert result.get("mode") in {"result", "error"}
            return result

        await client.connect_and_run(test_callback)

    @pytest.mark.asyncio
    async def test_tool_with_auth_token_via_client(self, client, test_config):
        """Test tool calls with authentication token"""
        if not test_config.is_security_tests_enabled():
            pytest.skip("Security tests are disabled")

        async def test_callback(client_instance):
            result = await client_instance.get_database_list()

            assert result.get("mode") in {"result", "error"}
            return result

        await client.connect_and_run(test_callback)

    @pytest.mark.asyncio
    async def test_call_invalid_tool_via_client(self, client, test_config):
        """Test calling an invalid tool name through client"""
        async def test_callback(client_instance):
            result = await client_instance.call_tool("nonexistent_tool", {})

            # Should return a result (either success or error)
            assert "success" in result or "error" in result, "Result should contain 'success' or 'error' field"
            if "error" in result:
                assert "Unknown tool" in result["error"] or "not found" in result["error"].lower()
            return result

        await client.connect_and_run(test_callback)

    @pytest.mark.asyncio
    async def test_exec_query_missing_sql_param_via_client(self, client, test_config):
        """Test exec_query called without required sql parameter"""
        async def test_callback(client_instance):
            result = await client_instance.call_tool("exec_query", {})

            assert "success" in result or "error" in result, "Result should contain 'success' or 'error' field"
            if result.get("success") is False:
                assert "error" in result, "Failed result should contain 'error' field"
            return result

        await client.connect_and_run(test_callback)

    @pytest.mark.asyncio
    async def test_get_db_table_list_via_client(self, client, test_config):
        """Test calling get_db_table_list tool through client"""
        async def test_callback(client_instance):
            result = await client_instance.call_tool("get_db_table_list", {"db_name": "information_schema"})

            assert "success" in result, "Result should contain 'success' field"
            if result["success"]:
                assert "result" in result, "Successful result should contain 'result' field"
                assert isinstance(result["result"], list), "Database table list should be a list"
            else:
                assert "error" in result, "Failed result should contain 'error' field"
            return result

        await client.connect_and_run(test_callback)

    @pytest.mark.asyncio
    async def test_catalog_list_tool_via_client(self, client, test_config):
        """Test get_catalog_list tool"""
        async def test_callback(client_instance):
            # Catalog list
            cat_result = await client_instance.call_tool("get_catalog_list", {})
            assert "success" in cat_result, "Result should contain 'success' field"
            return cat_result

        await client.connect_and_run(test_callback)
