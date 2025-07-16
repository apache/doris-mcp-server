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
Test Configuration Loader

Loads test configuration and provides methods to connect to running servers
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional
import logging

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from doris_mcp_client.client import DorisUnifiedClient, DorisClientConfig

logger = logging.getLogger(__name__)


class TestConfigLoader:
    """Test configuration loader and client factory"""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize with config file path"""
        if config_path is None:
            config_path = os.path.join(os.path.dirname(__file__), "test_config.json")
        
        self.config_path = Path(config_path)
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from JSON file"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            logger.info(f"Loaded test configuration from {self.config_path}")
            return config
        except FileNotFoundError:
            logger.error(f"Test configuration file not found: {self.config_path}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in test configuration: {e}")
            raise
    
    def get_http_client_config(self) -> DorisClientConfig:
        """Get HTTP client configuration"""
        http_config = self.config["server_endpoints"]["http"]
        return DorisClientConfig.http(
            url=http_config["url"],
            timeout=http_config["timeout"]
        )
    
    def get_stdio_client_config(self) -> DorisClientConfig:
        """Get stdio client configuration"""
        stdio_config = self.config["server_endpoints"]["stdio"]
        return DorisClientConfig.stdio(
            command=stdio_config["command"],
            args=stdio_config["args"]
        )
    
    def get_default_client_config(self) -> DorisClientConfig:
        """Get default client configuration based on test settings"""
        transport = self.config["test_settings"]["default_transport"]
        if transport == "http":
            return self.get_http_client_config()
        elif transport == "stdio":
            return self.get_stdio_client_config()
        else:
            raise ValueError(f"Unknown transport type: {transport}")
    
    def create_client(self, transport: Optional[str] = None) -> DorisUnifiedClient:
        """Create MCP client instance"""
        if transport is None:
            client_config = self.get_default_client_config()
        elif transport == "http":
            client_config = self.get_http_client_config()
        elif transport == "stdio":
            client_config = self.get_stdio_client_config()
        else:
            raise ValueError(f"Unknown transport type: {transport}")
        
        return DorisUnifiedClient(client_config)
    
    def get_test_settings(self) -> Dict[str, Any]:
        """Get test settings"""
        return self.config["test_settings"]
    
    def get_test_data(self) -> Dict[str, Any]:
        """Get test data"""
        return self.config["test_data"]
    
    def get_expected_tools(self) -> list[str]:
        """Get expected tools list"""
        return self.config["expected_tools"]
    
    def get_expected_resources(self) -> list[str]:
        """Get expected resources list"""
        return self.config["expected_resources"]
    
    def get_expected_prompts(self) -> list[str]:
        """Get expected prompts list"""
        return self.config["expected_prompts"]
    
    def get_sample_queries(self) -> list[str]:
        """Get sample queries for testing"""
        return self.config["test_data"]["sample_queries"]
    
    def get_auth_tokens(self) -> Dict[str, str]:
        """Get authentication tokens for testing"""
        return self.config["test_data"]["auth_tokens"]
    
    def get_test_databases(self) -> list[str]:
        """Get test databases list"""
        return self.config["test_data"]["test_databases"]
    
    def get_test_tables(self) -> list[str]:
        """Get test tables list"""
        return self.config["test_data"]["test_tables"]
    
    def is_performance_tests_enabled(self) -> bool:
        """Check if performance tests are enabled"""
        return self.config["test_settings"]["enable_performance_tests"]
    
    def is_security_tests_enabled(self) -> bool:
        """Check if security tests are enabled"""
        return self.config["test_settings"]["enable_security_tests"]
    
    def get_retry_config(self) -> Dict[str, Any]:
        """Get retry configuration"""
        return {
            "attempts": self.config["test_settings"]["retry_attempts"],
            "delay": self.config["test_settings"]["retry_delay"]
        }
    
    def get_test_timeout(self) -> int:
        """Get test timeout in seconds"""
        return self.config["test_settings"]["test_timeout"]


# Global test config instance
_test_config = None

def get_test_config() -> TestConfigLoader:
    """Get global test configuration instance"""
    global _test_config
    if _test_config is None:
        _test_config = TestConfigLoader()
    return _test_config


def create_test_client(transport: Optional[str] = None) -> DorisUnifiedClient:
    """Create test client with default configuration"""
    return get_test_config().create_client(transport)


async def test_server_connectivity(transport: Optional[str] = None) -> bool:
    """Test server connectivity"""
    try:
        client = create_test_client(transport)
        
        async def test_connection(client_instance):
            try:
                # Try to list tools as a connectivity test
                tools = await client_instance.list_all_tools()
                return len(tools) > 0
            except Exception as e:
                logger.error(f"Connectivity test failed: {e}")
                return False
        
        await client.connect_and_run(test_connection)
        return True

    except Exception as e:
        logger.error(f"Failed to test server connectivity: {e}")
        return False


if __name__ == "__main__":
    # Test configuration loading
    import asyncio
    
    async def main():
        config = get_test_config()
        print("Test Configuration Loaded:")
        print(f"  Default transport: {config.get_test_settings()['default_transport']}")
        print(f"  Expected tools: {len(config.get_expected_tools())}")
        print(f"  Sample queries: {len(config.get_sample_queries())}")
        
        # Test connectivity
        print("\nTesting server connectivity...")
        http_ok = await test_server_connectivity("http")
        print(f"  HTTP connectivity: {'✓' if http_ok else '✗'}")
        
        stdio_ok = await test_server_connectivity("stdio")
        print(f"  Stdio connectivity: {'✓' if stdio_ok else '✗'}")
    
    asyncio.run(main()) 
