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
Tools manager tests
"""

from unittest.mock import AsyncMock, Mock, patch

import pytest

from doris_mcp_server.schema_validation import ToolSchemaGuard
from doris_mcp_server.tools.domain_dispatcher import ToolNotFoundError
from doris_mcp_server.tools.doris_feature_matrix import (
    EXPECTED_DOMAIN_CHILDREN,
)
from doris_mcp_server.tools.tools_manager import DorisToolsManager
from doris_mcp_server.utils.config import DorisConfig


class TestDorisToolsManager:
    """Doris tools manager tests"""

    @pytest.fixture
    def mock_config(self):
        """Create mock configuration"""
        from doris_mcp_server.utils.config import DatabaseConfig, SecurityConfig

        config = Mock(spec=DorisConfig)

        # Add database config
        config.database = Mock(spec=DatabaseConfig)
        config.database.host = "localhost"
        config.database.port = 9030
        config.database.user = "test_user"
        config.database.password = "test_password"
        config.database.database = "test_db"
        config.database.health_check_interval = 60
        config.database.max_connections = 20
        config.database.connection_timeout = 30
        config.database.max_connection_age = 3600

        # Add security config
        config.security = Mock(spec=SecurityConfig)
        config.security.enable_masking = True
        config.security.auth_type = "token"
        config.security.token_secret = "test_secret"
        config.security.token_expiry = 3600

        return config

    @pytest.fixture
    def tools_manager(self, mock_config):
        """Create tools manager instance"""
        # Create a proper mock connection manager
        mock_connection_manager = Mock()
        mock_connection_manager.get_connection = AsyncMock()
        mock_connection_manager.config.adbc.default_max_rows = 1000
        mock_connection_manager.config.adbc.default_timeout = 30
        mock_connection_manager.config.adbc.default_return_format = "dict"
        return DorisToolsManager(mock_connection_manager)

    @pytest.mark.asyncio
    async def test_get_available_tools(self, tools_manager):
        """Test getting available tools"""
        tools = await tools_manager.list_tools()

        tool_names = [tool.name for tool in tools]
        assert tool_names == list(EXPECTED_DOMAIN_CHILDREN)

    @pytest.mark.asyncio
    async def test_exec_query_tool(self, tools_manager):
        """Test exec_query tool"""
        with patch.object(
            tools_manager.metadata_extractor,
            "exec_query_for_mcp",
        ) as mock_execute:
            mock_execute.return_value = {
                "success": True,
                "data": [
                    {"id": 1, "name": "张三"},
                    {"id": 2, "name": "李四"}
                ],
                "row_count": 2,
                "execution_time": 0.15
            }

            arguments = {
                "sql": "SELECT id, name FROM users LIMIT 2",
                "max_rows": 100
            }

            result = await tools_manager._exec_query_tool(arguments)

            assert result["success"] is True
            assert len(result["data"]) == 2
            mock_execute.assert_awaited_once_with(
                arguments["sql"],
                None,
                None,
                100,
                30,
                max_bytes=None,
            )

    @pytest.mark.asyncio
    async def test_exec_query_with_error(self, tools_manager):
        """Test exec_query tool with error"""
        with patch.object(
            tools_manager.metadata_extractor,
            "exec_query_for_mcp",
        ) as mock_execute:
            mock_execute.side_effect = Exception("Database connection failed")

            arguments = {
                "sql": "SELECT * FROM users"
            }

            with pytest.raises(Exception, match="Database connection failed"):
                await tools_manager._exec_query_tool(arguments)

    @pytest.mark.asyncio
    async def test_get_db_list_tool(self, tools_manager):
        """Test get_db_list tool"""
        expected = {
            "success": True,
            "databases": ["test_db", "information_schema", "mysql"],
        }
        with patch.object(
            tools_manager.metadata_extractor,
            "get_db_list_for_mcp",
            return_value=expected,
        ) as mock_execute:
            result = await tools_manager._get_db_list_tool({})

        assert result == expected
        mock_execute.assert_awaited_once_with(None)

    @pytest.mark.asyncio
    async def test_get_db_table_list_tool(self, tools_manager):
        """Test get_db_table_list tool"""
        expected = {"success": True, "tables": ["users", "orders", "products"]}
        with patch.object(
            tools_manager.metadata_extractor,
            "get_db_table_list_for_mcp",
            return_value=expected,
        ) as mock_execute:
            arguments = {"db_name": "test_db"}
            result = await tools_manager._get_db_table_list_tool(arguments)

        assert result == expected
        mock_execute.assert_awaited_once_with("test_db", None)

    @pytest.mark.asyncio
    async def test_get_table_schema_tool(self, tools_manager):
        """Test get_table_schema tool"""
        expected = {
            "success": True,
            "schema": [
                {
                    "Field": "id",
                    "Type": "int(11)",
                    "Null": "NO",
                    "Key": "PRI",
                    "Default": None,
                    "Extra": "auto_increment"
                },
                {
                    "Field": "name",
                    "Type": "varchar(100)",
                    "Null": "YES",
                    "Key": "",
                    "Default": None,
                    "Extra": ""
                }
            ],
        }
        with patch.object(
            tools_manager.metadata_extractor,
            "get_table_schema_for_mcp",
            return_value=expected,
        ) as mock_execute:
            arguments = {"table_name": "users"}
            result = await tools_manager._get_table_schema_tool(arguments)

        assert result == expected
        mock_execute.assert_awaited_once_with("users", None, None)

    @pytest.mark.asyncio
    async def test_get_catalog_list_tool(self, tools_manager):
        """Test get_catalog_list tool"""
        expected = {
            "success": True,
            "catalogs": ["internal", "hive_catalog", "iceberg_catalog"],
        }
        with patch.object(
            tools_manager.metadata_extractor,
            "get_catalog_list_for_mcp",
            return_value=expected,
        ) as mock_execute:
            result = await tools_manager._get_catalog_list_tool(
                {"random_string": "test_123"}
            )

        assert result == expected
        mock_execute.assert_awaited_once_with()


    @pytest.mark.asyncio
    async def test_invalid_tool_name(self, tools_manager):
        """Test calling invalid tool"""
        with pytest.raises(ToolNotFoundError, match="Tool not found") as exc_info:
            await tools_manager.call_tool("invalid_tool", {})
        assert exc_info.value.name == "invalid_tool"

    @pytest.mark.asyncio
    async def test_missing_required_arguments(self, tools_manager):
        """Test handler rejects missing required arguments."""
        with pytest.raises(ValueError, match="sql"):
            await tools_manager._exec_query_tool({})

    @pytest.mark.asyncio
    async def test_tool_definitions_structure(self, tools_manager):
        """Test tool definitions have correct structure"""
        tools = await tools_manager.list_tools()

        for tool in tools:
            # Each tool should have required fields
            assert hasattr(tool, 'name')
            assert hasattr(tool, 'description')
            assert hasattr(tool, 'input_schema')

            # Input schema should have properties
            assert 'properties' in tool.input_schema

            # Required fields should be defined
            if 'required' in tool.input_schema:
                assert isinstance(tool.input_schema['required'], list)

    @pytest.mark.asyncio
    async def test_all_production_tool_schemas_compile_as_bounded_2020_12(
        self,
        tools_manager,
    ):
        tools = await tools_manager.list_tools()
        compiled = ToolSchemaGuard().compile_catalog(tools)

        assert set(compiled) == {tool.name for tool in tools}
