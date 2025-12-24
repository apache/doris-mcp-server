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
Query executor tests
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch

from doris_mcp_server.utils.query_executor import DorisQueryExecutor
from doris_mcp_server.utils.config import DorisConfig


class TestDorisQueryExecutor:
    """Doris query executor tests"""

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
    def query_executor(self, mock_config):
        """Create query executor instance"""
        # Create a mock connection manager
        mock_connection_manager = Mock()
        return DorisQueryExecutor(mock_connection_manager, mock_config)

    @pytest.mark.asyncio
    async def test_execute_query_success(self, query_executor):
        """Test successful query execution using MCP interface"""
        with patch.object(query_executor, 'execute_sql_for_mcp') as mock_execute:
            mock_execute.return_value = {
                "success": True,
                "data": [
                    {"id": 1, "name": "张三", "email": "zhangsan@example.com"},
                    {"id": 2, "name": "李四", "email": "lisi@example.com"}
                ],
                "row_count": 2,
                "execution_time": 0.15,
                "columns": ["id", "name", "email"]
            }
            
            sql = "SELECT id, name, email FROM users LIMIT 2"
            result = await query_executor.execute_sql_for_mcp(sql)
            
            # Verify results
            assert result["success"] is True
            assert result["row_count"] == 2
            assert len(result["data"]) == 2
            assert result["data"][0]["id"] == 1
            assert result["data"][0]["name"] == "张三"
            assert result["data"][1]["email"] == "lisi@example.com"

    @pytest.mark.asyncio
    async def test_execute_query_with_parameters(self, query_executor):
        """Test query execution with parameters"""
        with patch.object(query_executor, 'execute_sql_for_mcp') as mock_execute:
            mock_execute.return_value = {
                "success": True,
                "data": [{"id": 1, "name": "张三"}],
                "row_count": 1,
                "execution_time": 0.1
            }
            
            sql = "SELECT id, name FROM users WHERE department = 'sales'"
            result = await query_executor.execute_sql_for_mcp(sql)
            
            # Verify results
            assert result["success"] is True
            assert result["row_count"] == 1
            assert len(result["data"]) == 1

    @pytest.mark.asyncio
    async def test_execute_query_connection_error(self, query_executor):
        """Test query execution with connection error"""
        with patch.object(query_executor, 'execute_sql_for_mcp') as mock_execute:
            mock_execute.return_value = {
                "success": False,
                "error": "Connection failed",
                "data": None
            }
            
            sql = "SELECT * FROM users"
            result = await query_executor.execute_sql_for_mcp(sql)
            
            assert result["success"] is False
            assert "Connection failed" in result["error"]

    @pytest.mark.asyncio
    async def test_execute_query_sql_error(self, query_executor):
        """Test query execution with SQL error"""
        with patch.object(query_executor, 'execute_sql_for_mcp') as mock_execute:
            mock_execute.return_value = {
                "success": False,
                "error": "SQL syntax error",
                "data": None
            }
            
            sql = "SELECT * FROM non_existent_table"
            result = await query_executor.execute_sql_for_mcp(sql)
            
            assert result["success"] is False
            assert "SQL syntax error" in result["error"]

    @pytest.mark.asyncio
    async def test_execute_query_empty_result(self, query_executor):
        """Test query execution with empty result"""
        with patch.object(query_executor, 'execute_sql_for_mcp') as mock_execute:
            mock_execute.return_value = {
                "success": True,
                "data": [],
                "row_count": 0,
                "execution_time": 0.05
            }
            
            sql = "SELECT * FROM users WHERE id = 999"
            result = await query_executor.execute_sql_for_mcp(sql)
            
            assert result["success"] is True
            assert result["data"] == []
            assert result["row_count"] == 0

    @pytest.mark.asyncio
    async def test_execute_query_max_rows_limit(self, query_executor):
        """Test query execution with max rows limit"""
        with patch.object(query_executor, 'execute_sql_for_mcp') as mock_execute:
            # Mock large result set limited to 100 rows
            limited_result = [{"id": i, "name": f"user_{i}"} for i in range(100)]
            mock_execute.return_value = {
                "success": True,
                "data": limited_result,
                "row_count": 100,
                "execution_time": 0.2
            }
            
            sql = "SELECT id, name FROM users"
            result = await query_executor.execute_sql_for_mcp(sql, limit=100)
            
            # Should be limited to max_rows
            assert result["success"] is True
            assert len(result["data"]) == 100

    @pytest.mark.asyncio
    async def test_execute_sql_for_mcp_interface(self, query_executor):
        """Test the MCP interface method directly"""
        with patch.object(query_executor.connection_manager, 'get_connection') as mock_get_conn:
            # Mock connection and result
            mock_connection = AsyncMock()
            mock_connection.execute.return_value = Mock(
                data=[{"id": 1, "name": "张三"}],
                row_count=1,
                execution_time=0.1,
                metadata={}
            )
            mock_get_conn.return_value = mock_connection
            
            sql = "SELECT id, name FROM users LIMIT 1"
            result = await query_executor.execute_sql_for_mcp(sql)
            
            # Should return success format
            assert "success" in result
            if result["success"]:
                assert "data" in result
                assert "row_count" in result 

    @pytest.mark.asyncio
    async def test_execute_multi_sql_statements(self, query_executor):
        """Test execution of multiple SQL statements"""
        from doris_mcp_server.utils.query_executor import QueryResult
        
        # Disable security check for this test
        query_executor.connection_manager.config.security.enable_security_check = False
        
        with patch.object(query_executor, 'execute_query') as mock_execute:
            # Mock results for three SQL statements
            mock_execute.side_effect = [
                QueryResult(
                    data=[{"id": 1, "name": "张三"}],
                    row_count=1,
                    execution_time=0.1,
                    sql="SELECT id, name FROM users WHERE id = 1",
                    metadata={"columns": ["id", "name"]}
                ),
                QueryResult(
                    data=[{"id": 2, "name": "李四"}],
                    row_count=1,
                    execution_time=0.12,
                    sql="SELECT id, name FROM users WHERE id = 2",
                    metadata={"columns": ["id", "name"]}
                ),
                QueryResult(
                    data=[{"count": 100}],
                    row_count=1,
                    execution_time=0.08,
                    sql="SELECT COUNT(*) as count FROM users",
                    metadata={"columns": ["count"]}
                )
            ]
            
            # Execute multiple SQL statements separated by semicolons
            multi_sql = """
                SELECT id, name FROM users WHERE id = 1;
                SELECT id, name FROM users WHERE id = 2;
                SELECT COUNT(*) as count FROM users;
            """
            
            result = await query_executor.execute_sql_for_mcp(multi_sql)
            
            # Verify the result structure for multiple statements
            assert result["success"] is True
            assert result["multiple_results"] is True
            assert "results" in result
            assert len(result["results"]) == 3
            
            # Verify first query result
            assert result["results"][0]["data"] == [{"id": 1, "name": "张三"}]
            assert result["results"][0]["row_count"] == 1
            assert result["results"][0]["metadata"]["columns"] == ["id", "name"]
            assert result["results"][0]["metadata"]["query"] == "SELECT id, name FROM users WHERE id = 1"
            
            # Verify second query result
            assert result["results"][1]["data"] == [{"id": 2, "name": "李四"}]
            assert result["results"][1]["row_count"] == 1
            assert result["results"][1]["metadata"]["columns"] == ["id", "name"]
            assert result["results"][1]["metadata"]["query"] == "SELECT id, name FROM users WHERE id = 2"
            
            # Verify third query result
            assert result["results"][2]["data"] == [{"count": 100}]
            assert result["results"][2]["row_count"] == 1
            assert result["results"][2]["metadata"]["columns"] == ["count"]
            assert result["results"][2]["metadata"]["query"] == "SELECT COUNT(*) as count FROM users"
            
            # Verify execute_query was called three times
            assert mock_execute.call_count == 3
