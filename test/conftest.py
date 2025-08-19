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
Pytest configuration and fixtures for Doris MCP Server tests
"""

import asyncio
import logging
import sys
from pathlib import Path

import pytest

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Configure logging for tests
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def test_config():
    """Test configuration fixture"""
    from doris_mcp_server.utils.config import DorisConfig, DatabaseConfig, SecurityConfig
    
    config = DorisConfig()
    
    # Database configuration
    config.database.host = "localhost"
    config.database.port = 9030
    config.database.user = "test_user"
    config.database.password = "test_password"
    config.database.database = "test_db"
    config.database.health_check_interval = 60
    config.database.max_connections = 20
    config.database.connection_timeout = 30
    config.database.max_connection_age = 3600
    
    # Security configuration
    config.security.enable_masking = True
    config.security.auth_type = "token"
    config.security.token_secret = "test_secret"
    config.security.token_expiry = 3600
    
    return config


@pytest.fixture
def sample_data():
    """Provide sample test data"""
    return [
        {
            "id": 1,
            "name": "张三",
            "phone": "13812345678",
            "email": "zhangsan@example.com",
            "id_card": "110101199001011234",
            "salary": 50000
        },
        {
            "id": 2,
            "name": "李四",
            "phone": "13987654321",
            "email": "lisi@example.com",
            "id_card": "110101199002022345",
            "salary": 60000
        }
    ]


@pytest.fixture
def test_sql_queries():
    """Provide test SQL queries"""
    return {
        "safe_select": "SELECT name, email FROM users WHERE department = 'sales'",
        "dangerous_drop": "DROP TABLE users",
        "sql_injection": "SELECT * FROM users WHERE id = 1; DROP TABLE users;",
        "union_injection": "SELECT name FROM users UNION SELECT password FROM admin_users",
        "comment_injection": "SELECT * FROM users WHERE id = 1 -- AND password = 'secret'",
        "complex_query": """
            SELECT u.name, u.email, d.department_name
            FROM users u
            JOIN departments d ON u.department_id = d.id
            WHERE u.status = 'active'
            ORDER BY u.created_at DESC
        """
    }
