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
Apache Doris Database Connection Management Module

Provides high-performance database connection pool management, automatic reconnection mechanism and connection health check functionality
Supports asynchronous operations and concurrent connection management, ensuring stability and performance for enterprise applications
"""

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional

import aiomysql
from aiomysql import Connection, Pool

from .logger import get_logger




@dataclass
class ConnectionMetrics:
    """Connection pool performance metrics"""

    total_connections: int = 0
    active_connections: int = 0
    idle_connections: int = 0
    failed_connections: int = 0
    connection_errors: int = 0
    avg_connection_time: float = 0.0
    last_health_check: datetime | None = None


@dataclass
class QueryResult:
    """Query result wrapper"""

    data: list[dict[str, Any]]
    metadata: dict[str, Any]
    execution_time: float
    row_count: int
    sql: str


class DorisConnection:
    """Doris database connection wrapper class"""

    def __init__(self, connection: Connection, session_id: str, security_manager=None):
        self.connection = connection
        self.session_id = session_id
        self.created_at = datetime.utcnow()
        self.last_used = datetime.utcnow()
        self.query_count = 0
        self.is_healthy = True
        self.security_manager = security_manager
        self.logger = get_logger(__name__)

    async def execute(self, sql: str, params: tuple | None = None, auth_context=None) -> QueryResult:
        """Execute SQL query"""
        start_time = time.time()

        try:
            # If security manager exists, perform SQL security check
            security_result = None
            if self.security_manager and auth_context:
                validation_result = await self.security_manager.validate_sql_security(sql, auth_context)
                if not validation_result.is_valid:
                    raise ValueError(f"SQL security validation failed: {validation_result.error_message}")
                security_result = {
                    "is_valid": validation_result.is_valid,
                    "risk_level": validation_result.risk_level,
                    "blocked_operations": validation_result.blocked_operations
                }

            async with self.connection.cursor(aiomysql.DictCursor) as cursor:
                await cursor.execute(sql, params)

                # Check if it's a query statement (statement that returns result set)
                # FIX for Issue #62 Bug 5: Added WITH support for Common Table Expressions (CTE)
                sql_upper = sql.strip().upper()
                if (sql_upper.startswith("SELECT") or
                    sql_upper.startswith("SHOW") or
                    sql_upper.startswith("DESCRIBE") or
                    sql_upper.startswith("DESC") or
                    sql_upper.startswith("EXPLAIN") or
                    sql_upper.startswith("WITH")):  # FIX: Support CTE queries
                    data = await cursor.fetchall()
                    row_count = len(data)
                else:
                    data = []
                    row_count = cursor.rowcount

                execution_time = time.time() - start_time
                self.last_used = datetime.utcnow()
                self.query_count += 1

                # Get column information
                columns = []
                if cursor.description:
                    columns = [desc[0] for desc in cursor.description]

                # If security manager exists and has auth context, apply data masking
                final_data = list(data) if data else []
                if self.security_manager and auth_context and final_data:
                    final_data = await self.security_manager.apply_data_masking(final_data, auth_context)

                metadata = {"columns": columns, "query": sql, "params": params}
                if security_result:
                    metadata["security_check"] = security_result

                return QueryResult(
                    data=final_data,
                    metadata=metadata,
                    execution_time=execution_time,
                    row_count=row_count,
                    sql=sql
                )

        except Exception as e:
            self.is_healthy = False
            logging.error(f"Query execution failed: {e}")
            raise

    async def ping(self) -> bool:
        """Check connection health status with enhanced at_eof error detection"""
        try:
            # Check 1: Connection exists and is not closed
            if not self.connection or self.connection.closed:
                self.is_healthy = False
                return False
            
            # Check 2: Use ONLY safe operations - avoid internal state access
            # Instead of checking _reader state directly, use a simple query test
            try:
                # Use a simple query with timeout instead of ping() to avoid at_eof issues
                async with asyncio.timeout(3):  # 3 second timeout
                    async with self.connection.cursor() as cursor:
                        await cursor.execute("SELECT 1")
                        result = await cursor.fetchone()
                        if result and result[0] == 1:
                            self.is_healthy = True
                            return True
                        else:
                            self.logger.debug(f"Connection {self.session_id} ping query returned unexpected result")
                            self.is_healthy = False
                            return False
            
            except asyncio.TimeoutError:
                self.logger.debug(f"Connection {self.session_id} ping timed out")
                self.is_healthy = False
                return False
            except Exception as query_error:
                # Check for specific at_eof related errors
                error_str = str(query_error).lower()
                if 'at_eof' in error_str or 'nonetype' in error_str:
                    self.logger.debug(f"Connection {self.session_id} ping failed with at_eof error: {query_error}")
                else:
                    self.logger.debug(f"Connection {self.session_id} ping failed: {query_error}")
                self.is_healthy = False
                return False
            
        except Exception as e:
            # Catch any other unexpected errors
            self.logger.debug(f"Connection {self.session_id} ping failed with unexpected error: {e}")
            self.is_healthy = False
            return False

    async def close(self):
        """Close connection"""
        try:
            if self.connection and not self.connection.closed:
                await self.connection.ensure_closed()
        except Exception as e:
            logging.error(f"Error occurred while closing connection: {e}")


class DorisSessionCache:
    """Doris database session cache

    Save doris session in memory and get session by session id.
    Provide cache_system_session/cache_user_session to specify whether to save system/user type sessions.
    By default, only session_id is "query" or "system" will be saved.
    """

    def __init__(self, connection_manager=None, cache_system_session=True, cache_user_session=False):
        self.logger = get_logger(__name__)
        self.cached = {}
        self.connection_manager = connection_manager
        self.cache_system_session = cache_system_session
        self.cache_user_session = cache_user_session
        self.logger.info(f"Session  Cache initialized, save system session: {self.cache_system_session}, save user session: {self.cache_user_session}")

    def save(self, connection: DorisConnection):
        if self._should_cache(connection.session_id):
            self.cached[connection.session_id] = connection

    def get(self, session_id: str) -> Optional[DorisConnection]:
        self.logger.debug(f"Use cached connection: {session_id}")
        return self.cached.get(session_id)

    def remove(self, session_id):
        if session_id in self.cached:
            del self.cached[session_id]
            self.logger.debug(f"Removed session {session_id} from cache.")
        else:
            if self._should_cache(session_id):
                self.logger.warning(f"Session {session_id} is not existed.")

    def clear(self):
        if self.connection_manager:
            for k, v in self.cached.items():
                self.connection_manager.release_connection(k, v)
        self.cached = {}

    def _is_system_session(self, session_id) -> bool:
        return session_id in ["query", "system"]

    def _should_cache(self, session_id):
        return (self.cache_system_session and self._is_system_session(session_id)) or (self.cache_user_session and not self._is_system_session(session_id))


class DorisConnectionManager:
    """Doris database connection manager - Enhanced Strategy

    Uses direct connection pool management with proper synchronization
    Implements connection pool health monitoring and proactive cleanup
    Supports token-bound database configurations for multi-tenant access
    """


    def __init__(self, config, security_manager=None, token_manager=None):
        self.config = config
        self.pool: Pool | None = None
        self.logger = get_logger(__name__)
        self.security_manager = security_manager
        self.token_manager = token_manager  # Token manager for token-bound DB config

        # FIX for Issue #58 Problem 1: Disable session caching to prevent connection sharing
        # Session caching causes multiple threads to share the same MySQL connection,
        # leading to race conditions and deadlocks in multi-threaded environments
        # By disabling caching, each request gets a fresh connection from the pool
        self.session_cache = DorisSessionCache(
            self,
            cache_system_session=False,  # Disabled to prevent multi-thread issues
            cache_user_session=False     # Disabled to prevent multi-thread issues
        )
        
        # Store original database config for fallback
        self.original_db_config = {
            'host': config.database.host,
            'port': config.database.port, 
            'user': config.database.user,
            'password': config.database.password,
            'database': config.database.database,
            'charset': config.database.charset
        }
        
        # Current active database config (may be overridden by token-bound config)
        self.active_db_config = self.original_db_config.copy()

        # Connection pool state management
        self.pool_recovering = False
        self.pool_health_check_task = None
        self.pool_cleanup_task = None
        
        # Metrics tracking
        self.metrics = ConnectionMetrics()
        
        # 🔧 FIX: Add connection acquisition lock to prevent race conditions
        self._connection_lock = asyncio.Lock()
        self._recovery_lock = asyncio.Lock()
        
        # 🔧 FIX: Add connection acquisition queue to serialize requests
        self._connection_semaphore = asyncio.Semaphore(value=20)  # Max concurrent acquisitions
        
        # Database connection parameters from config.database
        self.pool_recovery_lock = self._recovery_lock  # Compatibility alias
        self._update_db_params_from_config(self.active_db_config)
        self.connect_timeout = config.database.connection_timeout
        
        # Connection pool parameters - more conservative settings
        self.minsize = config.database.min_connections  # This is always 0
        self.maxsize = config.database.max_connections or 20
        self.pool_recycle = config.database.max_connection_age or 3600  # 1 hour, more conservative
        
        # 🔧 FIX: Add missing monitoring parameters that were removed during refactoring
        self.health_check_interval = 30  # seconds
        self.pool_warmup_size = 3  # connections to maintain
    
    def _update_db_params_from_config(self, db_config: dict):
        """Update database connection parameters from config dictionary"""
        self.host = db_config['host']
        self.port = db_config['port']
        self.user = db_config['user']
        self.password = db_config['password']
        self.database = db_config['database']
        # Convert charset to aiomysql compatible format
        charset_map = {"UTF8": "utf8", "UTF8MB4": "utf8mb4"}
        self.charset = charset_map.get(db_config['charset'].upper(), db_config['charset'].lower())
    
    def _is_config_empty(self, config_value) -> bool:
        """Check if a config value is empty (None, empty string, or 'null')"""
        return config_value is None or config_value == '' or str(config_value).lower() == 'null'
    
    def _has_valid_global_config(self) -> bool:
        """Check if global database configuration is valid and non-empty"""
        return (not self._is_config_empty(self.original_db_config['host']) and
                not self._is_config_empty(self.original_db_config['user']))
    
    def _find_available_token_with_db_config(self) -> str:
        """Find the first available token with database configuration
        
        Returns:
            Raw token string if found, empty string if not found
        """
        if not self.token_manager:
            return ""
            
        try:
            for token_hash, token_info in self.token_manager._tokens.items():
                if (token_info.database_config and 
                    token_info.is_active and
                    not self._is_config_empty(token_info.database_config.host) and
                    not self._is_config_empty(token_info.database_config.user)):
                    
                    # We need to find the raw token from the hash
                    # This is a bit tricky since we only store hashes
                    # We'll need to use the admin token from tokens.json if it has db config
                    if token_info.token_id == 'admin-token':
                        # Try the known admin token
                        return 'doris_admin_token_123456'
                    elif 'tenant' in token_info.token_id:
                        # For tenant tokens, we'll need a different approach
                        # For now, skip these as we don't know the raw token
                        continue
                        
            return ""
        except Exception as e:
            self.logger.error(f"Error finding available token: {e}")
            return ""
    
    async def configure_for_token(self, token: str) -> tuple[bool, str]:
        """Configure connection manager for token with new priority logic
        
        Priority: Token-bound DB config > .env config > error
        
        Args:
            token: Authentication token to get database config for
            
        Returns:
            (success: bool, config_source: str): Result and which config was used
            
        Raises:
            RuntimeError: If no valid database configuration is available
        """
        try:
            # Priority 1: Try token-bound database config first
            if self.token_manager:
                db_config = self.token_manager.get_database_config_by_token(token)
                if db_config:
                    # Convert DatabaseConfig to dictionary
                    token_db_config = {
                        'host': db_config.host,
                        'port': db_config.port,
                        'user': db_config.user,
                        'password': db_config.password,
                        'database': db_config.database,
                        'charset': db_config.charset
                    }
                    
                    # Check if token-bound config is valid
                    if (not self._is_config_empty(token_db_config['host']) and
                        not self._is_config_empty(token_db_config['user'])):
                        self.logger.info(f"Using token-bound database configuration for host: {token_db_config['host']}")
                        self.active_db_config = token_db_config
                        self._update_db_params_from_config(self.active_db_config)
                        
                        # Create/recreate connection pool with token-bound config
                        await self._ensure_pool_with_current_config()
                        
                        return True, "token-bound"
            
            # Priority 2: Use global .env config if available
            if self._has_valid_global_config():
                self.logger.info("Using global .env database configuration")
                self.active_db_config = self.original_db_config.copy()
                self._update_db_params_from_config(self.active_db_config)
                
                # Create/recreate connection pool with global config
                await self._ensure_pool_with_current_config()
                
                return True, "global-env"
            
            # Priority 3: No valid configuration available
            error_msg = (
                "No valid database configuration available for this token. "
                "Please contact administrator to:\n"
                "1. Add database configuration to tokens.json for this token, OR\n"
                "2. Configure valid global database settings in .env file\n"
                "Required fields: DB_HOST, DB_USER"
            )
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)
            
        except Exception as e:
            self.logger.error(f"Failed to configure database for token: {e}")
            raise
    
    async def _ensure_pool_with_current_config(self):
        """Ensure connection pool exists with current configuration"""
        try:
            # If pool exists with different config, need to recreate it
            # If no pool exists, create one with current config
            if self.pool and not self.pool.closed:
                # Since we can't reliably check pool config attributes, 
                # we'll recreate the pool if we detect a potential config change
                # by checking if current config differs from what we stored
                pool_needs_recreation = False
                
                # Compare current config with what we might have used before
                if hasattr(self, '_last_pool_config'):
                    current_config = {
                        'host': self.host,
                        'port': self.port, 
                        'user': self.user,
                        'database': self.database
                    }
                    if current_config != self._last_pool_config:
                        pool_needs_recreation = True
                
                if pool_needs_recreation:
                    self.logger.info("Database configuration changed, recreating connection pool")
                    await self._recreate_pool()
            elif not self.pool:
                self.logger.info("Creating connection pool with current configuration")
                await self._create_pool_with_current_config()
                
            # Test the connection immediately
            if not await self._test_pool_health():
                raise RuntimeError(f"Database connection test failed for {self.host}:{self.port}")
                
        except Exception as e:
            self.logger.error(f"Failed to ensure connection pool: {e}")
            raise
    
    async def _create_pool_with_current_config(self):
        """Create connection pool with current database configuration"""
        try:
            self.pool = await aiomysql.create_pool(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                db=self.database,
                charset=self.charset,
                minsize=self.minsize,
                maxsize=self.maxsize,
                pool_recycle=self.pool_recycle,
                connect_timeout=self.connect_timeout,
                autocommit=True
            )
            
            # Store the current config for comparison later
            self._last_pool_config = {
                'host': self.host,
                'port': self.port,
                'user': self.user,
                'database': self.database
            }
            
            # Test initial connection
            if not await self._test_pool_health():
                raise RuntimeError("Connection pool health check failed")

            # Start background monitoring tasks if not already running
            if not self.pool_health_check_task or self.pool_health_check_task.done():
                self.pool_health_check_task = asyncio.create_task(self._pool_health_monitor())
            if not self.pool_cleanup_task or self.pool_cleanup_task.done():
                self.pool_cleanup_task = asyncio.create_task(self._pool_cleanup_monitor())
            
            # Perform initial pool warmup
            await self._warmup_pool()
            
            self.logger.info(f"Connection pool created successfully with {self.host}:{self.port}")
            
        except Exception as e:
            self.logger.error(f"Failed to create connection pool: {e}")
            raise

    async def _recreate_pool(self):
        """Recreate connection pool with current database configuration"""
        try:
            # Close existing pool
            if self.pool and not self.pool.closed:
                self.pool.close()
                await self.pool.wait_closed()
                self.pool = None
            
            # Create new pool with current config
            await self._create_pool_with_current_config()
            
        except Exception as e:
            self.logger.error(f"Failed to recreate connection pool: {e}")
            raise

    def validate_database_configuration(self) -> tuple[bool, str]:
        """Validate database configuration completeness
        
        Returns:
            (is_valid, error_message): Configuration validation result
        """
        # Check if Token authentication is enabled
        token_auth_enabled = getattr(self.config.security, 'enable_token_auth', False)
        
        # Check if tokens.json exists and has valid tokens with database configs
        tokens_file_available = False
        token_bound_configs_available = False
        
        if self.token_manager:
            try:
                # Check if tokens.json file exists
                import os
                tokens_file_path = getattr(self.token_manager, 'token_file_path', 'tokens.json')
                tokens_file_available = os.path.exists(tokens_file_path)
                
                # Check if any tokens have database configurations
                if tokens_file_available or self.token_manager._tokens:
                    for token_hash, token_info in self.token_manager._tokens.items():
                        if token_info.database_config:
                            token_bound_configs_available = True
                            break
            except Exception:
                pass
        
        # Validate .env database configuration
        env_config_valid = self._has_valid_global_config()
        
        # Decision logic
        if token_auth_enabled:
            if tokens_file_available:
                # tokens.json exists - either .env OR token-bound config must be valid
                if env_config_valid or token_bound_configs_available:
                    return True, "Configuration valid"
                else:
                    return False, (
                        "Token authentication is enabled and tokens.json exists, but no valid database "
                        "configuration found. Please provide either:\n"
                        "1. Valid database configuration in .env file (DB_HOST, DB_USER, etc.)\n"
                        "2. Database configuration in tokens.json for at least one token"
                    )
            else:
                # tokens.json does not exist - must have valid .env config
                if env_config_valid:
                    return True, "Configuration valid"
                else:
                    return False, (
                        "Token authentication is enabled but tokens.json file not found. "
                        "Either:\n"
                        "1. Create tokens.json file with token configurations\n"
                        "2. Provide valid database configuration in .env file (DB_HOST, DB_USER, etc.)"
                    )
        else:
            # Token auth is disabled, must have valid .env config
            if env_config_valid:
                return True, "Configuration valid"
            else:
                return False, (
                    "Token authentication is disabled. Valid database configuration is required "
                    "in .env file (DB_HOST, DB_USER, etc.)"
                )

    async def initialize(self):
        """Initialize connection pool with health monitoring"""
        try:
            # First validate configuration
            is_valid, error_message = self.validate_database_configuration()
            if not is_valid:
                self.logger.error(f"Database configuration validation failed: {error_message}")
                raise RuntimeError(f"Database configuration validation failed:\n{error_message}")
            
            self.logger.info(f"Database configuration validated successfully")
            self.logger.info(f"Initializing connection pool to {self.host}:{self.port}")
            
            # Only create connection pool if we have valid global config
            # Token-bound configs will be handled dynamically during requests
            if not self._has_valid_global_config():
                self.logger.info("No valid global database config, pool will be created dynamically for token-bound configs")
                return
            
            # Create connection pool
            self.pool = await aiomysql.create_pool(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                db=self.database,
                charset=self.charset,
                minsize=self.minsize,
                maxsize=self.maxsize,
                pool_recycle=self.pool_recycle,
                connect_timeout=self.connect_timeout,
                autocommit=True
            )
            
            # Test initial connection
            if not await self._test_pool_health():
                raise RuntimeError("Connection pool health check failed")

            # Start background monitoring tasks
            self.pool_health_check_task = asyncio.create_task(self._pool_health_monitor())
            self.pool_cleanup_task = asyncio.create_task(self._pool_cleanup_monitor())
            
            # Perform initial pool warmup
            await self._warmup_pool()
            
            self.logger.info(f"Connection pool initialized successfully, min connections: {self.minsize}, max connections: {self.maxsize}")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize connection pool: {e}")
            raise

    async def initialize_for_stdio_mode(self, timeout: float = 30.0) -> None:
        """
        Initialize connection pool for stdio mode with strict validation
        
        stdio mode requires a working database connection because:
        - No HTTP authentication mechanism to support token-bound configs
        - All database operations depend on the global connection pool
        
        Args:
            timeout: Maximum time to wait for connection establishment
            
        Raises:
            RuntimeError: If configuration is invalid or connection fails
        """
        try:
            # Validate that we have valid global configuration
            if not self._has_valid_global_config():
                error_msg = (
                    "stdio mode requires valid global database configuration. "
                    "Please set DORIS_HOST and DORIS_USER in environment variables or .env file. "
                    f"Current config: host='{self.host}', user='{self.user}'"
                )
                self.logger.error(error_msg)
                raise RuntimeError(error_msg)
            
            self.logger.info(f"stdio mode database config validated: {self.host}:{self.port}")
            
            # Validate configuration format
            is_valid, error_message = self.validate_database_configuration()
            if not is_valid:
                error_msg = f"Database configuration validation failed: {error_message}"
                self.logger.error(error_msg)
                raise RuntimeError(error_msg)
            
            # Test connectivity with timeout
            self.logger.info("Testing database connectivity for stdio mode...")
            if not await self._test_connectivity_with_timeout(timeout):
                error_msg = (
                    f"Failed to connect to Doris database within {timeout} seconds. "
                    f"Please check if Doris is running at {self.host}:{self.port} "
                    f"and verify network connectivity."
                )
                self.logger.error(error_msg)
                raise RuntimeError(error_msg)
            
            # Initialize the connection pool
            await self._create_connection_pool()
            
            # Verify that we have a working connection pool
            if not self.pool:
                error_msg = "Database connection pool was not created successfully."
                self.logger.error(error_msg)
                raise RuntimeError(error_msg)
            
            # Start background monitoring tasks
            self.pool_health_check_task = asyncio.create_task(self._pool_health_monitor())
            self.pool_cleanup_task = asyncio.create_task(self._pool_cleanup_monitor())
            
            # Perform initial pool warmup
            await self._warmup_pool()
            
            self.logger.info("Database connection established successfully for stdio mode")
            
        except Exception as e:
            self.logger.error(f"stdio mode database initialization failed: {e}")
            raise
    
    async def initialize_for_http_mode(self) -> bool:
        """
        Initialize connection pool for HTTP mode with graceful degradation
        
        HTTP mode can work without global database configuration because:
        - Supports token-bound database configurations
        - Can handle authentication and use per-request database configs
        - Has fallback mechanisms for database operations
        
        Returns:
            bool: True if global database pool was created, False if gracefully degraded
        """
        try:
            # First validate configuration format if we have one
            if self._has_valid_global_config():
                is_valid, error_message = self.validate_database_configuration()
                if not is_valid:
                    self.logger.warning(f"Global database configuration invalid: {error_message}")
                    self.logger.info("HTTP mode will rely on token-bound database configurations")
                    return False
                
                # Try to establish global connection pool
                self.logger.info(f"Attempting to create global connection pool: {self.host}:{self.port}")
                
                try:
                    # Test connectivity with shorter timeout for HTTP mode
                    if await self._test_connectivity_with_timeout(10.0):
                        await self._create_connection_pool()
                        
                        if self.pool:
                            # Start background monitoring tasks
                            self.pool_health_check_task = asyncio.create_task(self._pool_health_monitor())
                            self.pool_cleanup_task = asyncio.create_task(self._pool_cleanup_monitor())
                            
                            # Perform initial pool warmup
                            await self._warmup_pool()
                            
                            self.logger.info("Global database connection pool created successfully for HTTP mode")
                            return True
                    else:
                        self.logger.warning("Global database connection test failed, will use token-bound configs")
                        return False
                        
                except Exception as pool_error:
                    self.logger.warning(f"Failed to create global connection pool: {pool_error}")
                    self.logger.info("HTTP mode will rely on token-bound database configurations")
                    return False
            else:
                self.logger.info("No valid global database config found, HTTP mode will use token-bound configurations")
                return False
                
        except Exception as e:
            self.logger.warning(f"HTTP mode database initialization encountered error: {e}")
            self.logger.info("HTTP mode will rely on token-bound database configurations")
            return False
    
    async def _test_connectivity_with_timeout(self, timeout: float) -> bool:
        """
        Test database connectivity with timeout
        
        Args:
            timeout: Maximum time to wait for connection test
            
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            await asyncio.wait_for(self._test_basic_connectivity(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            self.logger.error(f"Database connectivity test timed out after {timeout} seconds")
            return False
        except Exception as e:
            self.logger.error(f"Database connectivity test failed: {e}")
            return False
    
    async def _test_basic_connectivity(self) -> None:
        """
        Test basic database connectivity without connection pool
        
        Raises:
            Exception: If connection fails
        """
        import aiomysql
        
        conn = None
        try:
            conn = await aiomysql.connect(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                db=self.database,
                charset=self.charset,
                connect_timeout=self.connect_timeout,
                autocommit=True
            )
            
            async with conn.cursor() as cursor:
                await cursor.execute("SELECT 1")
                result = await cursor.fetchone()
                if not result or result[0] != 1:
                    raise RuntimeError("Database connectivity test query failed")
                    
        except Exception as e:
            raise RuntimeError(f"Database connectivity test failed: {e}")
        finally:
            if conn:
                conn.close()
    
    async def _create_connection_pool(self) -> None:
        """
        Create the connection pool
        
        Raises:
            Exception: If pool creation fails
        """
        self.pool = await aiomysql.create_pool(
            host=self.host,
            port=self.port,
            user=self.user,
            password=self.password,
            db=self.database,
            charset=self.charset,
            minsize=self.minsize,
            maxsize=self.maxsize,
            pool_recycle=self.pool_recycle,
            connect_timeout=self.connect_timeout,
            autocommit=True
        )
        
        # Test pool health
        if not await self._test_pool_health():
            # Clean up the pool if health test fails
            if self.pool:
                self.pool.close()
                await self.pool.wait_closed()
                self.pool = None
            raise RuntimeError("Connection pool health check failed")

    async def _test_pool_health(self) -> bool:
        """Test connection pool health"""
        try:
            async with self.pool.acquire() as conn:
                async with conn.cursor() as cursor:
                    await cursor.execute("SELECT 1")
                    result = await cursor.fetchone()
                    return result and result[0] == 1
        except Exception as e:
            self.logger.error(f"Pool health test failed: {e}")
            return False

    async def _warmup_pool(self):
        """Warm up connection pool by creating initial connections"""
        self.logger.info(f"🔥 Warming up connection pool with {self.pool_warmup_size} connections")
        
        warmup_connections = []
        try:
            # Acquire connections to force pool to create them
            for i in range(self.pool_warmup_size):
                try:
                    conn = await self.pool.acquire()
                    warmup_connections.append(conn)
                    self.logger.debug(f"Warmed up connection {i+1}/{self.pool_warmup_size}")
                except Exception as e:
                    self.logger.warning(f"Failed to warm up connection {i+1}: {e}")
                    break
            
            # Release all warmup connections back to pool
            for conn in warmup_connections:
                try:
                    self.pool.release(conn)
                except Exception as e:
                    self.logger.warning(f"Failed to release warmup connection: {e}")
            
            self.logger.info(f"✅ Pool warmup completed, {len(warmup_connections)} connections created")

        except Exception as e:
            self.logger.error(f"Pool warmup failed: {e}")
            # Clean up any remaining connections
            for conn in warmup_connections:
                try:
                    await conn.ensure_closed()
                except Exception:
                    pass

    async def _pool_health_monitor(self):
        """Background task to monitor pool health"""
        self.logger.info("🩺 Starting pool health monitor")
        
        while True:
            try:
                await asyncio.sleep(self.health_check_interval)
                await self._check_pool_health()
            except asyncio.CancelledError:
                self.logger.info("Pool health monitor stopped")
                break
            except Exception as e:
                self.logger.error(f"Pool health monitor error: {e}")

    async def _pool_cleanup_monitor(self):
        """Background task to clean up stale connections"""
        self.logger.info("🧹 Starting pool cleanup monitor")
        
        while True:
            try:
                await asyncio.sleep(self.health_check_interval * 2)  # Less frequent cleanup
                await self._cleanup_stale_connections()
            except asyncio.CancelledError:
                self.logger.info("Pool cleanup monitor stopped")
                break
            except Exception as e:
                self.logger.error(f"Pool cleanup monitor error: {e}")

    async def _check_pool_health(self):
        """Check and maintain pool health"""
        try:
            # Skip health check if already recovering
            if self.pool_recovering:
                self.logger.debug("Pool recovery in progress, skipping health check")
                return
                
            # Test pool with a simple query
            health_ok = await self._test_pool_health()
            
            if health_ok:
                self.logger.debug("✅ Pool health check passed")
                self.metrics.last_health_check = datetime.utcnow()
            else:
                self.logger.warning("❌ Pool health check failed, attempting recovery")
                await self._recover_pool()
                
        except Exception as e:
            self.logger.error(f"Pool health check error: {e}")
            await self._recover_pool()

    async def _cleanup_stale_connections(self):
        """Proactively clean up potentially stale connections"""
        try:
            self.logger.debug("🧹 Checking for stale connections")
            
            # Get pool statistics
            pool_size = self.pool.size
            pool_free = self.pool.freesize
            
            # If pool has idle connections, test some of them
            if pool_free > 0:
                test_count = min(pool_free, 2)  # Test up to 2 idle connections
                
                for i in range(test_count):
                    try:
                        # Acquire connection, test it, and release
                        conn = await asyncio.wait_for(self.pool.acquire(), timeout=5)
                        
                        # Quick test
                        async with conn.cursor() as cursor:
                            await asyncio.wait_for(cursor.execute("SELECT 1"), timeout=3)
                            await cursor.fetchone()
                        
                        # Connection is healthy, release it
                        self.pool.release(conn)
                        
                    except asyncio.TimeoutError:
                        self.logger.debug(f"Stale connection test {i+1} timed out")
                        try:
                            await conn.ensure_closed()
                        except Exception:
                            pass
                    except Exception as e:
                        self.logger.debug(f"Stale connection test {i+1} failed: {e}")
                        try:
                            await conn.ensure_closed()
                        except Exception:
                            pass
                
                self.logger.debug(f"Stale connection cleanup completed, tested {test_count} connections")
                
        except Exception as e:
            self.logger.error(f"Stale connection cleanup error: {e}")

    async def _recover_pool(self):
        """Recover connection pool when health check fails"""
        # Use lock to prevent concurrent recovery attempts
        async with self.pool_recovery_lock:
            # Check if another recovery is already in progress
            if self.pool_recovering:
                self.logger.debug("Pool recovery already in progress, waiting...")
                return
                
            try:
                self.pool_recovering = True
                max_retries = 3
                retry_delay = 5  # seconds
                
                for attempt in range(max_retries):
                    try:
                        self.logger.info(f"🔄 Attempting pool recovery (attempt {attempt + 1}/{max_retries})")
                        
                        # Try to close existing pool with timeout
                        if self.pool:
                            try:
                                if not self.pool.closed:
                                    self.pool.close()
                                    await asyncio.wait_for(self.pool.wait_closed(), timeout=3.0)
                                self.logger.debug("Old pool closed successfully")
                            except asyncio.TimeoutError:
                                self.logger.warning("Pool close timeout, forcing cleanup")
                            except Exception as e:
                                self.logger.warning(f"Error closing old pool: {e}")
                            finally:
                                self.pool = None
                        
                        # Wait before creating new pool (reduced delay)
                        if attempt > 0:
                            await asyncio.sleep(2)  # Reduced from 5 to 2 seconds
                        
                        # Recreate pool with timeout
                        self.logger.debug("Creating new connection pool...")
                        self.pool = await asyncio.wait_for(
                            aiomysql.create_pool(
                                host=self.host,
                                port=self.port,
                                user=self.user,
                                password=self.password,
                                db=self.database,
                                charset=self.charset,
                                minsize=self.minsize,
                                maxsize=self.maxsize,
                                pool_recycle=self.pool_recycle,
                                connect_timeout=self.connect_timeout,
                                autocommit=True
                            ),
                            timeout=10.0
                        )
                        
                        # Test recovered pool with timeout
                        if await asyncio.wait_for(self._test_pool_health(), timeout=5.0):
                            self.logger.info(f"✅ Pool recovery successful on attempt {attempt + 1}")
                            # Re-warm the pool with timeout
                            try:
                                await asyncio.wait_for(self._warmup_pool(), timeout=5.0)
                            except asyncio.TimeoutError:
                                self.logger.warning("Pool warmup timeout, but recovery successful")
                            return
                        else:
                            self.logger.warning(f"❌ Pool recovery health check failed on attempt {attempt + 1}")
                            
                    except asyncio.TimeoutError:
                        self.logger.error(f"Pool recovery attempt {attempt + 1} timed out")
                        if self.pool:
                            try:
                                self.pool.close()
                            except:
                                pass
                            self.pool = None
                    except Exception as e:
                        self.logger.error(f"Pool recovery error on attempt {attempt + 1}: {e}")
                        
                        # Clean up failed pool
                        if self.pool:
                            try:
                                self.pool.close()
                                await asyncio.wait_for(self.pool.wait_closed(), timeout=2.0)
                            except Exception:
                                pass
                            finally:
                                self.pool = None
                
                # All recovery attempts failed
                self.logger.error("❌ Pool recovery failed after all attempts")
                self.pool = None
                
            finally:
                self.pool_recovering = False
    
    async def _recover_pool_with_lock(self):
        """🔧 FIX: Recovery method that uses the new recovery lock to prevent races"""
        async with self._recovery_lock:
            if not self.pool_recovering:  # Only recover if not already in progress
                await self._recover_pool()

    async def get_connection(self, session_id: str) -> DorisConnection:
        """🔧 FIX: Simplified connection acquisition without double locking
        
        Uses only semaphore to prevent too many concurrent acquisitions.
        If the connection is successfully obtained, it will be added to the connection pool cache.
        """
        cached_conn = self.session_cache.get(session_id)
        if cached_conn:
            return cached_conn

        # 🔧 FIX: Use only semaphore to limit concurrent acquisitions (remove double locking)
        async with self._connection_semaphore:
            try:
                # Wait for any ongoing recovery to complete
                if self.pool_recovering:
                    self.logger.debug(f"Pool recovery in progress, waiting for completion...")
                    # Wait for recovery to complete (max 10 seconds)
                    start_wait = time.time()
                    while self.pool_recovering and (time.time() - start_wait) < 10:
                        await asyncio.sleep(0.1)  # More frequent checks
                    
                    if self.pool_recovering:
                        self.logger.error("Pool recovery is taking too long, proceeding anyway")
                        # Continue but log the issue
                
                # Check if pool is available
                if not self.pool:
                    self.logger.warning("Connection pool is not available, attempting recovery...")
                    
                    # Try to use token-bound configuration if available
                    if self.token_manager and not self._has_valid_global_config():
                        available_token = self._find_available_token_with_db_config()
                        if available_token:
                            self.logger.info(f"Using token-bound configuration for pool creation: {available_token}")
                            try:
                                await self.configure_for_token(available_token)
                            except Exception as e:
                                self.logger.error(f"Failed to configure with token-bound config: {e}")
                    
                    # Fallback to recovery
                    if not self.pool:
                        await self._recover_pool_with_lock()
                    
                    if not self.pool:
                        raise RuntimeError("Connection pool is not available and recovery failed")
                
                # Check if pool is closed
                if self.pool.closed:
                    self.logger.warning("Connection pool is closed, attempting recovery...")
                    await self._recover_pool_with_lock()
                    
                    if not self.pool or self.pool.closed:
                        raise RuntimeError("Connection pool is closed and recovery failed")
                
                # 🔧 FIX: Increased timeout to prevent hanging
                try:
                    raw_conn = await asyncio.wait_for(self.pool.acquire(), timeout=10.0)
                except asyncio.TimeoutError:
                    self.logger.error(f"Connection acquisition timed out for session {session_id}")
                    # Try one recovery attempt
                    await self._recover_pool_with_lock()
                    if self.pool and not self.pool.closed:
                        try:
                            raw_conn = await asyncio.wait_for(self.pool.acquire(), timeout=5.0)
                        except asyncio.TimeoutError:
                            raise RuntimeError("Connection acquisition timed out after recovery")
                    else:
                        raise RuntimeError("Connection acquisition timed out")
                
                # Wrap in DorisConnection
                doris_conn = DorisConnection(raw_conn, session_id, self.security_manager)
                
                # Basic validation - check if connection is open
                if raw_conn.closed:
                    # Return connection and raise error
                    try:
                        self.pool.release(raw_conn)
                    except Exception:
                        pass
                    raise RuntimeError("Acquired connection is already closed")
                
                self.logger.debug(f"✅ Acquired fresh connection for session {session_id}")

                self.session_cache.save(doris_conn)
                return doris_conn
                
            except Exception as e:
                self.logger.error(f"Failed to get connection for session {session_id}: {e}")
                raise

    async def release_connection(self, session_id: str, connection: DorisConnection):
        """🔧 FIX: Release connection back to pool with proper error handling"""
        cached_conn = self.session_cache.get(session_id)
        if cached_conn:
            self.session_cache.remove(session_id)
            if not (cached_conn is connection):
                self.logger.warning("Invalid connection")
                connection = cached_conn

        if not connection or not connection.connection:
            self.logger.debug(f"No connection to release for session {session_id}")
            return
            
        try:
            # Check pool availability before attempting release
            if not self.pool or self.pool.closed:
                self.logger.warning(f"Pool unavailable during release for session {session_id}, force closing connection")
                try:
                    await connection.connection.ensure_closed()
                except Exception:
                    pass
                return
            
            # Check connection state before release
            if connection.connection.closed:
                self.logger.debug(f"Connection already closed for session {session_id}")
                return
            
            # 🔧 FIX: Simplified release operation without thread wrapper
            try:
                self.pool.release(connection.connection)
                self.logger.debug(f"✅ Released connection for session {session_id}")
            except Exception as release_error:
                self.logger.warning(f"Connection release failed for session {session_id}: {release_error}, force closing")
                await connection.connection.ensure_closed()

        except Exception as e:
            self.logger.error(f"Error releasing connection for session {session_id}: {e}")
            # Force close if release fails
            try:
                await connection.connection.ensure_closed()
            except Exception as close_error:
                self.logger.debug(f"Error force closing connection: {close_error}")

    async def close(self):
        """Close connection manager"""
        try:
            # Cancel background tasks
            if self.pool_health_check_task:
                self.pool_health_check_task.cancel()
                try:
                    await self.pool_health_check_task
                except asyncio.CancelledError:
                    pass

            if self.pool_cleanup_task:
                self.pool_cleanup_task.cancel()
                try:
                    await self.pool_cleanup_task
                except asyncio.CancelledError:
                    pass

            # Close connection pool
            if self.pool:
                self.pool.close()
                await self.pool.wait_closed()

            self.logger.info("Connection manager closed successfully")

        except Exception as e:
            self.logger.error(f"Error closing connection manager: {e}")

    async def test_connection(self) -> bool:
        """Test database connection using robust connection test"""
        return await self._test_pool_health()

    async def get_metrics(self) -> ConnectionMetrics:
        """Get connection pool metrics - Simplified Strategy"""
        try:
            if self.pool:
                self.metrics.idle_connections = self.pool.freesize
                self.metrics.active_connections = self.pool.size - self.pool.freesize
            else:
                self.metrics.idle_connections = 0
                self.metrics.active_connections = 0
            
            return self.metrics
        except Exception as e:
            self.logger.error(f"Error getting metrics: {e}")
            return self.metrics

    async def execute_query(
        self, session_id: str, sql: str, params: tuple | None = None, auth_context=None
    ) -> QueryResult:
        """Execute query - Simplified Strategy with automatic connection management

        FIX for Issue #62 Bug 1: Configure token-bound database before query execution
        """
        connection = None
        try:
            # FIX: Configure database for token BEFORE getting connection
            # This ensures token-bound database configuration is used instead of global config
            if auth_context and hasattr(auth_context, 'token') and auth_context.token:
                try:
                    success, config_source = await self.configure_for_token(auth_context.token)
                    if success:
                        self.logger.info(f"Session {session_id}: Using {config_source} database configuration")
                    else:
                        self.logger.warning(f"Session {session_id}: Token configuration failed, may use global config")
                except Exception as token_config_error:
                    # SECURITY: If token should have config but configuration fails, don't fallback
                    # This prevents privilege escalation (using high-privilege default user)
                    if self.token_manager:
                        self.logger.error(f"Session {session_id}: Token database configuration failed: {token_config_error}")
                        raise RuntimeError(
                            f"Failed to configure database for authenticated token. "
                            f"This is a security measure to prevent using default high-privilege credentials. "
                            f"Error: {token_config_error}"
                        )
                    else:
                        # No token manager, can use global config
                        self.logger.warning(f"Session {session_id}: No token manager, using global config")

            # Always get fresh connection from pool (with configured database)
            connection = await self.get_connection(session_id)

            # Execute query
            result = await connection.execute(sql, params, auth_context)

            return result

        except Exception as e:
            self.logger.error(f"Query execution failed for session {session_id}: {e}")
            raise
        finally:
            # Always release connection back to pool
            if connection:
                await self.release_connection(session_id, connection)

    @asynccontextmanager
    async def get_connection_context(self, session_id: str):
        """Get connection context manager - Simplified Strategy"""
        connection = None
        try:
            connection = await self.get_connection(session_id)
            yield connection
        finally:
            if connection:
                await self.release_connection(session_id, connection)

    async def diagnose_connection_health(self) -> Dict[str, Any]:
        """Diagnose connection pool health - Simplified Strategy"""
        diagnosis = {
            "timestamp": datetime.utcnow().isoformat(),
            "pool_status": "unknown",
            "pool_info": {},
            "recommendations": []
        }
        
        try:
            # Check pool status
            if not self.pool:
                diagnosis["pool_status"] = "not_initialized"
                diagnosis["recommendations"].append("Initialize connection pool")
                return diagnosis
            
            if self.pool.closed:
                diagnosis["pool_status"] = "closed"
                diagnosis["recommendations"].append("Recreate connection pool")
                return diagnosis
            
            diagnosis["pool_status"] = "healthy"
            diagnosis["pool_info"] = {
                "size": self.pool.size,
                "free_size": self.pool.freesize,
                "min_size": self.pool.minsize,
                "max_size": self.pool.maxsize
            }
            
            # Generate recommendations based on pool status
            if self.pool.freesize == 0 and self.pool.size >= self.pool.maxsize:
                diagnosis["recommendations"].append("Connection pool exhausted - consider increasing max_connections")
            
            # Test pool health
            if await self._test_pool_health():
                diagnosis["pool_health"] = "healthy"
            else:
                diagnosis["pool_health"] = "unhealthy"
                diagnosis["recommendations"].append("Pool health check failed - may need recovery")
            
            return diagnosis
            
        except Exception as e:
            diagnosis["error"] = str(e)
            diagnosis["recommendations"].append("Manual intervention required")
            return diagnosis


class ConnectionPoolMonitor:
    """Connection pool monitor

    Provides detailed monitoring and reporting capabilities for connection pool status
    """

    def __init__(self, connection_manager: DorisConnectionManager):
        self.connection_manager = connection_manager
        self.logger = get_logger(__name__)

    async def get_pool_status(self) -> dict[str, Any]:
        """Get connection pool status"""
        metrics = await self.connection_manager.get_metrics()
        
        status = {
            "pool_size": self.connection_manager.pool.size if self.connection_manager.pool else 0,
            "free_connections": self.connection_manager.pool.freesize if self.connection_manager.pool else 0,
            "active_connections": metrics.active_connections,
            "idle_connections": metrics.idle_connections,
            "total_connections": metrics.total_connections,
            "failed_connections": metrics.failed_connections,
            "connection_errors": metrics.connection_errors,
            "avg_connection_time": metrics.avg_connection_time,
            "last_health_check": metrics.last_health_check.isoformat() if metrics.last_health_check else None,
        }
        
        return status

    async def get_session_details(self) -> list[dict[str, Any]]:
        """Get session connection details - Simplified Strategy (No session caching)"""
        # In simplified strategy, we don't maintain session connections
        # Return empty list as connections are managed by the pool directly
        return []

    async def generate_health_report(self) -> dict[str, Any]:
        """Generate connection health report - Simplified Strategy"""
        pool_status = await self.get_pool_status()
        
        # Calculate pool utilization
        pool_utilization = 1.0 - (pool_status["free_connections"] / pool_status["pool_size"]) if pool_status["pool_size"] > 0 else 0.0
        
        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "pool_status": pool_status,
            "pool_utilization": pool_utilization,
            "recommendations": [],
        }
        
        # Add recommendations based on pool status
        if pool_status["connection_errors"] > 10:
            report["recommendations"].append("High connection error rate detected, review connection configuration")
        
        if pool_utilization > 0.9:
            report["recommendations"].append("Connection pool utilization is high, consider increasing pool size")
        
        if pool_status["free_connections"] == 0:
            report["recommendations"].append("No free connections available, consider increasing pool size")
        
        return report
