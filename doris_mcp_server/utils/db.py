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
from typing import Any, Dict, List

import aiomysql
from aiomysql import Connection, Pool




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
        self.logger = logging.getLogger(__name__)

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
                sql_upper = sql.strip().upper()
                if (sql_upper.startswith("SELECT") or 
                    sql_upper.startswith("SHOW") or 
                    sql_upper.startswith("DESCRIBE") or 
                    sql_upper.startswith("DESC") or 
                    sql_upper.startswith("EXPLAIN")):
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
            
            # Check 2: Comprehensive internal state validation
            # This is critical for detecting at_eof issues before they cause errors
            if not hasattr(self.connection, '_reader') or self.connection._reader is None:
                self.logger.debug(f"Connection {self.session_id} has invalid _reader state")
                self.is_healthy = False
                return False
            
            # Check 3: Verify transport state
            if (hasattr(self.connection._reader, '_transport') and 
                self.connection._reader._transport is None):
                self.logger.debug(f"Connection {self.session_id} has invalid transport state")
                self.is_healthy = False
                return False
            
            # Check 4: Additional stream state validation
            if (hasattr(self.connection._reader, 'at_eof') and 
                callable(self.connection._reader.at_eof)):
                try:
                    # If the stream is already at EOF, the connection is broken
                    if self.connection._reader.at_eof():
                        self.logger.debug(f"Connection {self.session_id} reader is at EOF")
                        self.is_healthy = False
                        return False
                except Exception:
                    # If we can't even check at_eof, the connection is problematic
                    self.logger.debug(f"Connection {self.session_id} cannot check at_eof state")
                    self.is_healthy = False
                    return False
            
            # Check 5: Try to ping the connection with timeout
            try:
                await asyncio.wait_for(self.connection.ping(), timeout=5)
            except asyncio.TimeoutError:
                self.logger.debug(f"Connection {self.session_id} ping timeout")
                self.is_healthy = False
                return False
            except Exception as ping_error:
                # Check for specific error patterns
                error_str = str(ping_error).lower()
                if any(keyword in error_str for keyword in ['at_eof', 'nonetype', 'reader', 'transport']):
                    self.logger.debug(f"Connection {self.session_id} ping failed with connection state error: {ping_error}")
                else:
                    self.logger.debug(f"Connection {self.session_id} ping failed: {ping_error}")
                self.is_healthy = False
                return False
            
            # Check 6: Final validation with a simple query
            try:
                async with self.connection.cursor() as cursor:
                    await asyncio.wait_for(cursor.execute("SELECT 1"), timeout=3)
                    result = await asyncio.wait_for(cursor.fetchone(), timeout=3)
                    if not result or result[0] != 1:
                        self.logger.debug(f"Connection {self.session_id} test query returned invalid result")
                        self.is_healthy = False
                        return False
            except Exception as query_error:
                error_str = str(query_error).lower()
                if any(keyword in error_str for keyword in ['at_eof', 'nonetype', 'reader', 'transport']):
                    self.logger.debug(f"Connection {self.session_id} test query failed with connection state error: {query_error}")
                else:
                    self.logger.debug(f"Connection {self.session_id} test query failed: {query_error}")
                self.is_healthy = False
                return False
            
            # If all checks pass, the connection is healthy
            self.is_healthy = True
            return True
            
        except Exception as e:
            # Any uncaught exception means the connection is not healthy
            error_str = str(e).lower()
            if any(keyword in error_str for keyword in ['at_eof', 'nonetype', 'reader', 'transport']):
                self.logger.debug(f"Connection {self.session_id} ping failed with connection state error: {e}")
            else:
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


class DorisConnectionManager:
    """Doris database connection manager

    Provides connection pool management, connection health monitoring, fault recovery and other functions
    Supports session-level connection reuse and intelligent load balancing
    Integrates security manager to provide unified security validation and data masking
    """

    def __init__(self, config, security_manager=None):
        self.config = config
        self.pool: Pool | None = None
        self.session_connections: dict[str, DorisConnection] = {}
        self.metrics = ConnectionMetrics()
        self.logger = logging.getLogger(__name__)
        self.security_manager = security_manager

        # Enhanced health check configuration for long-connection issues
        # Reduce health check interval to detect stale connections faster
        self.health_check_interval = min(config.database.health_check_interval or 60, 30)  # Max 30 seconds
        self.max_connection_age = config.database.max_connection_age or 3600
        self.connection_timeout = config.database.connection_timeout or 30
        
        # Add stale connection detection threshold (much shorter than MySQL's wait_timeout)
        self.stale_connection_threshold = 900  # 15 minutes - connections older than this are considered stale
        
        # Start background tasks
        self._health_check_task = None
        self._cleanup_task = None

    async def initialize(self):
        """Initialize connection manager"""
        try:
            self.logger.info(f"Initializing connection pool to {self.config.database.host}:{self.config.database.port}")
            
            # Validate configuration
            if not self.config.database.host:
                raise ValueError("Database host is required")
            if not self.config.database.user:
                raise ValueError("Database user is required")
            if not self.config.database.password:
                self.logger.warning("Database password is empty, this may cause connection issues")
            
            # Create connection pool with aggressive connection recycling to prevent at_eof issues
            # Key changes:
            # 1. Reduce pool_recycle to 30 minutes (1800 seconds) - much shorter than MySQL's wait_timeout
            # 2. Add shorter connect_timeout to fail fast on bad connections
            # 3. Enable autocommit to avoid transaction state issues
            self.pool = await aiomysql.create_pool(
                host=self.config.database.host,
                port=self.config.database.port,
                user=self.config.database.user,
                password=self.config.database.password,
                db=self.config.database.database,
                charset="utf8",
                minsize=self.config.database.min_connections,  # Always 0 per configuration to avoid at_eof issues
                maxsize=self.config.database.max_connections or 20,
                autocommit=True,
                connect_timeout=15,  # Shorter timeout to fail fast
                # Aggressive connection recycling to prevent stale connections
                pool_recycle=1800,  # Recycle connections every 30 minutes instead of 2 hours
                echo=False,  # Don't echo SQL statements
            )

            # Test the connection pool with a more robust test
            if not await self._robust_connection_test():
                raise RuntimeError("Connection pool robust test failed")

            self.logger.info(
                f"Connection pool initialized successfully with aggressive recycling (30min), "
                f"min connections: {self.config.database.min_connections}, "
                f"max connections: {self.config.database.max_connections or 20}"
            )

            # Start background monitoring tasks with more frequent health checks
            self._health_check_task = asyncio.create_task(self._health_check_loop())
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())

        except Exception as e:
            self.logger.error(f"Connection pool initialization failed: {e}")
            # Clean up partial initialization
            if self.pool:
                try:
                    self.pool.close()
                    await self.pool.wait_closed()
                except Exception:
                    pass
                self.pool = None
            raise

    async def _robust_connection_test(self) -> bool:
        """Perform a robust connection test that validates full connection health"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                self.logger.debug(f"Testing connection pool (attempt {attempt + 1}/{max_retries})")
                
                # Test connection creation and validation
                test_conn = await self._create_raw_connection_with_validation()
                if test_conn:
                    # Test basic query execution
                    async with test_conn.cursor() as cursor:
                        await cursor.execute("SELECT 1")
                        result = await cursor.fetchone()
                        if result and result[0] == 1:
                            self.logger.debug("Connection pool test successful")
                            # Return connection to pool
                            if self.pool:
                                self.pool.release(test_conn)
                            return True
                        else:
                            self.logger.warning("Connection test query returned unexpected result")
                    
                    # Close test connection if we get here
                    await test_conn.ensure_closed()
                
            except Exception as e:
                self.logger.warning(f"Connection test attempt {attempt + 1} failed: {e}")
                if attempt == max_retries - 1:
                    self.logger.error("All connection test attempts failed")
                    return False
                else:
                    # Wait before retry
                    await asyncio.sleep(1.0 * (attempt + 1))
        
        return False

    async def _create_raw_connection_with_validation(self, max_retries: int = 3):
        """Create a raw connection with comprehensive validation"""
        for attempt in range(max_retries):
            try:
                if not self.pool:
                    raise RuntimeError("Connection pool not initialized")

                # Acquire connection from pool
                raw_connection = await self.pool.acquire()
                
                # Basic connection validation
                if not raw_connection:
                    self.logger.warning(f"Pool returned None connection (attempt {attempt + 1})")
                    continue
                
                if raw_connection.closed:
                    self.logger.warning(f"Pool returned closed connection (attempt {attempt + 1})")
                    continue
                
                # Enhanced connection validation with multiple checks
                try:
                    # Check 1: Verify connection object internal state
                    if not hasattr(raw_connection, '_reader') or raw_connection._reader is None:
                        self.logger.warning(f"Connection has invalid _reader state (attempt {attempt + 1})")
                        await raw_connection.ensure_closed()
                        continue
                        
                    # Check 2: Verify transport state
                    if (hasattr(raw_connection._reader, '_transport') and 
                        raw_connection._reader._transport is None):
                        self.logger.warning(f"Connection has invalid transport state (attempt {attempt + 1})")
                        await raw_connection.ensure_closed()
                        continue
                    
                    # Check 3: Perform ping test to verify server-side connectivity
                    await raw_connection.ping()
                    
                    # Check 4: Test with actual query execution
                    async with raw_connection.cursor() as cursor:
                        await cursor.execute("SELECT 1")
                        result = await cursor.fetchone()
                        if result and result[0] == 1:
                            self.logger.debug(f"Successfully created and validated raw connection (attempt {attempt + 1})")
                            return raw_connection
                        else:
                            self.logger.warning(f"Connection test query failed (attempt {attempt + 1})")
                            await raw_connection.ensure_closed()
                            continue
                            
                except Exception as e:
                    # Enhanced error detection for connection issues
                    error_str = str(e).lower()
                    
                    # Check for various connection-related errors
                    connection_error_keywords = [
                        'at_eof', 'nonetype', 'connection', 'transport', 'reader', 
                        'lost connection', 'broken pipe', 'connection reset',
                        'timed out', 'connection refused', 'host unreachable'
                    ]
                    
                    is_connection_error = any(keyword in error_str for keyword in connection_error_keywords)
                    
                    if is_connection_error:
                        self.logger.warning(f"Connection validation failed with connection error (attempt {attempt + 1}): {e}")
                    else:
                        self.logger.warning(f"Connection validation failed (attempt {attempt + 1}): {e}")
                    
                    try:
                        await raw_connection.ensure_closed()
                    except Exception:
                        pass  # Ignore cleanup errors
                    continue
                
            except Exception as e:
                self.logger.warning(f"Raw connection creation attempt {attempt + 1} failed: {e}")
                if attempt == max_retries - 1:
                    raise RuntimeError(f"Failed to create valid connection after {max_retries} attempts: {e}")
                else:
                    # Exponential backoff with jitter to avoid thundering herd
                    base_delay = 0.5 * (2 ** attempt)
                    jitter = base_delay * 0.1 * (0.5 - asyncio.get_running_loop().time() % 1)
                    await asyncio.sleep(base_delay + jitter)
        
        raise RuntimeError("Failed to create valid connection")

    async def get_connection(self, session_id: str) -> DorisConnection:
        """Get database connection with enhanced reliability

        Supports session-level connection reuse to improve performance and consistency
        """
        # Check if there's an existing session connection
        if session_id in self.session_connections:
            conn = self.session_connections[session_id]
            # Enhanced connection health check
            if await self._comprehensive_connection_health_check(conn):
                return conn
            else:
                # Connection is unhealthy, clean up and create new one
                self.logger.debug(f"Existing connection unhealthy for session {session_id}, creating new one")
                await self._cleanup_session_connection(session_id)

        # Create new connection with retry logic
        return await self._create_new_connection_with_retry(session_id)

    async def _comprehensive_connection_health_check(self, conn: DorisConnection) -> bool:
        """Perform comprehensive connection health check"""
        try:
            # Check basic connection state
            if not conn.connection or conn.connection.closed:
                return False
            
            # Instead of checking internal state, perform a simple ping test
            # This is more reliable and less dependent on aiomysql internals
            if not await conn.ping():
                return False
            
            return True
            
        except Exception as e:
            # Check for at_eof errors specifically
            error_str = str(e).lower()
            if 'at_eof' in error_str:
                self.logger.debug(f"Connection health check failed with at_eof error: {e}")
            else:
                self.logger.debug(f"Connection health check failed: {e}")
            return False

    async def _create_new_connection_with_retry(self, session_id: str, max_retries: int = 3) -> DorisConnection:
        """Create new database connection with retry logic"""
        for attempt in range(max_retries):
            try:
                # Get validated raw connection
                raw_connection = await self._create_raw_connection_with_validation()
                
                # Create wrapped connection
                doris_conn = DorisConnection(raw_connection, session_id, self.security_manager)
                
                # Comprehensive connection test
                if await self._comprehensive_connection_health_check(doris_conn):
                    # Store in session connections
                    self.session_connections[session_id] = doris_conn
                    self.metrics.total_connections += 1
                    self.logger.debug(f"Successfully created new connection for session: {session_id}")
                    return doris_conn
                else:
                    # Connection failed health check, clean up and retry
                    self.logger.warning(f"New connection failed health check for session {session_id} (attempt {attempt + 1})")
                    try:
                        await doris_conn.close()
                    except Exception:
                        pass
                    
            except Exception as e:
                self.logger.warning(f"Connection creation attempt {attempt + 1} failed for session {session_id}: {e}")
                if attempt == max_retries - 1:
                    self.metrics.connection_errors += 1
                    raise RuntimeError(f"Failed to create connection for session {session_id} after {max_retries} attempts: {e}")
                else:
                    # Exponential backoff
                    await asyncio.sleep(0.5 * (2 ** attempt))
        
        raise RuntimeError(f"Unexpected failure in connection creation for session {session_id}")

    async def release_connection(self, session_id: str):
        """Release session connection"""
        if session_id in self.session_connections:
            await self._cleanup_session_connection(session_id)

    async def _cleanup_session_connection(self, session_id: str):
        """Clean up session connection with enhanced safety"""
        if session_id in self.session_connections:
            conn = self.session_connections[session_id]
            try:
                # Simplified connection validation before returning to pool
                connection_healthy = False
                
                if (self.pool and 
                    conn.connection and 
                    not conn.connection.closed):
                    
                    # Test if connection is still healthy with a simple check
                    try:
                        # Quick ping test to see if connection is usable
                        async with conn.connection.cursor() as cursor:
                            await cursor.execute("SELECT 1")
                            await cursor.fetchone()
                        connection_healthy = True
                    except Exception as test_error:
                        self.logger.debug(f"Connection health test failed for session {session_id}: {test_error}")
                        connection_healthy = False
                
                if connection_healthy:
                    # Connection appears healthy, return to pool
                    try:
                        self.pool.release(conn.connection)
                        self.logger.debug(f"Successfully returned connection to pool for session {session_id}")
                    except Exception as pool_error:
                        self.logger.debug(f"Failed to return connection to pool for session {session_id}: {pool_error}")
                        try:
                            await conn.connection.ensure_closed()
                        except Exception:
                            pass
                else:
                    # Connection is unhealthy, force close
                    self.logger.debug(f"Connection unhealthy for session {session_id}, force closing")
                    try:
                        if conn.connection and not conn.connection.closed:
                            await conn.connection.ensure_closed()
                    except Exception:
                        pass  # Ignore errors during forced close
                
                # Close connection wrapper
                await conn.close()
                
            except Exception as e:
                self.logger.error(f"Error cleaning up connection for session {session_id}: {e}")
                # Force close if normal cleanup fails
                try:
                    if conn.connection and not conn.connection.closed:
                        await conn.connection.ensure_closed()
                except Exception:
                    pass  # Ignore errors during forced close
            finally:
                # Remove from session connections
                del self.session_connections[session_id]
                self.logger.debug(f"Cleaned up connection for session: {session_id}")

    async def _health_check_loop(self):
        """Background health check loop"""
        while True:
            try:
                await asyncio.sleep(self.health_check_interval)
                await self._perform_health_check()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Health check error: {e}")

    async def _perform_health_check(self):
        """Perform enhanced health check with aggressive stale connection detection"""
        try:
            unhealthy_sessions = []
            stale_sessions = []
            current_time = datetime.utcnow()
            
            # Enhanced health check with comprehensive validation
            for session_id, conn in self.session_connections.items():
                try:
                    # Check 1: Basic connection health
                    if not await self._comprehensive_connection_health_check(conn):
                        unhealthy_sessions.append(session_id)
                        self.logger.debug(f"Session {session_id} marked as unhealthy")
                        continue
                    
                    # Check 2: Stale connection detection (much more aggressive)
                    time_since_last_use = (current_time - conn.last_used).total_seconds()
                    connection_age = (current_time - conn.created_at).total_seconds()
                    
                    # Mark as stale if:
                    # 1. Last used more than 15 minutes ago, OR
                    # 2. Connection age exceeds maximum age, OR  
                    # 3. Connection hasn't been used in a while and is old
                    if (time_since_last_use > self.stale_connection_threshold or
                        connection_age > self.max_connection_age or
                        (time_since_last_use > 300 and connection_age > 1800)):  # 5 min unused + 30 min old
                        
                        # For stale connections, do an extra validation
                        try:
                            # Try a more aggressive ping test
                            async with conn.connection.cursor() as cursor:
                                await asyncio.wait_for(cursor.execute("SELECT 1"), timeout=3)
                                await asyncio.wait_for(cursor.fetchone(), timeout=3)
                            # If we get here, connection is actually healthy despite being stale
                            self.logger.debug(f"Stale connection {session_id} passed extra validation")
                        except Exception as stale_test_error:
                            stale_sessions.append(session_id)
                            self.logger.debug(f"Session {session_id} marked as stale: {stale_test_error}")
                            continue
                    
                except Exception as check_error:
                    # If we can't even check the connection, it's definitely problematic
                    self.logger.warning(f"Health check failed for session {session_id}: {check_error}")
                    unhealthy_sessions.append(session_id)
            
            all_problematic_sessions = list(set(unhealthy_sessions + stale_sessions))
            
            # Clean up problematic connections
            cleanup_results = {"success": 0, "failed": 0}
            for session_id in all_problematic_sessions:
                try:
                    await self._cleanup_session_connection(session_id)
                    cleanup_results["success"] += 1
                    self.metrics.failed_connections += 1
                except Exception as cleanup_error:
                    cleanup_results["failed"] += 1
                    self.logger.error(f"Failed to cleanup session {session_id}: {cleanup_error}")
            
            # Update metrics
            await self._update_connection_metrics()
            self.metrics.last_health_check = datetime.utcnow()
            
            # Log results
            if all_problematic_sessions:
                self.logger.warning(
                    f"Health check: cleaned up {len(unhealthy_sessions)} unhealthy and "
                    f"{len(stale_sessions)} stale connections "
                    f"(success: {cleanup_results['success']}, failed: {cleanup_results['failed']})"
                )
            else:
                self.logger.debug(f"Health check: all {len(self.session_connections)} connections healthy")
            
            # If we have a lot of connection failures, log some diagnostic info
            if self.metrics.connection_errors > 50:  # Threshold for diagnostic logging
                self.logger.warning(
                    f"High connection error count detected: {self.metrics.connection_errors}. "
                    f"This may indicate persistent connectivity issues with the database."
                )

        except Exception as e:
            self.logger.error(f"Health check failed: {e}")
            # If health check fails, try to diagnose the issue
            try:
                diagnosis = await self.diagnose_connection_health()
                self.logger.error(f"Connection diagnosis: {diagnosis}")
            except Exception:
                pass  # Don't let diagnosis failure crash health check

    async def _cleanup_loop(self):
        """Background cleanup loop with more frequent execution"""
        while True:
            try:
                # Run cleanup more frequently - every 2 minutes instead of 5
                await asyncio.sleep(120)  # Run every 2 minutes
                await self._cleanup_idle_connections()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Cleanup loop error: {e}")

    async def _cleanup_idle_connections(self):
        """Clean up idle connections with more aggressive criteria"""
        current_time = datetime.utcnow()
        idle_sessions = []
        
        for session_id, conn in self.session_connections.items():
            try:
                # Enhanced idle connection detection
                connection_age = (current_time - conn.created_at).total_seconds()
                time_since_last_use = (current_time - conn.last_used).total_seconds()
                
                # Mark as idle if:
                # 1. Connection has exceeded maximum age, OR
                # 2. Connection hasn't been used for more than 20 minutes, OR
                # 3. Connection is old and hasn't been used recently
                should_cleanup = (
                    connection_age > self.max_connection_age or
                    time_since_last_use > 1200 or  # 20 minutes unused
                    (connection_age > 1800 and time_since_last_use > 600)  # 30 min old + 10 min unused
                )
                
                if should_cleanup:
                    # Before marking for cleanup, try a quick health check
                    try:
                        # Quick validation - if this fails, definitely cleanup
                        if not conn.connection or conn.connection.closed:
                            idle_sessions.append(session_id)
                            continue
                            
                        # Quick ping test with timeout
                        await asyncio.wait_for(conn.connection.ping(), timeout=2)
                        
                        # If ping succeeds but connection is still very old, cleanup anyway
                        if connection_age > self.max_connection_age:
                            idle_sessions.append(session_id)
                            self.logger.debug(f"Cleaning up old but healthy connection for session {session_id}")
                        else:
                            self.logger.debug(f"Keeping healthy connection for session {session_id}")
                            
                    except Exception as health_error:
                        # Health check failed, definitely cleanup
                        idle_sessions.append(session_id)
                        self.logger.debug(f"Cleanup marking session {session_id} due to health check failure: {health_error}")
                        
            except Exception as e:
                self.logger.warning(f"Error checking connection {session_id} for cleanup: {e}")
                # If we can't even check it, it's probably broken
                idle_sessions.append(session_id)
        
        # Clean up idle connections
        cleanup_results = {"success": 0, "failed": 0}
        for session_id in idle_sessions:
            try:
                await self._cleanup_session_connection(session_id)
                cleanup_results["success"] += 1
            except Exception as cleanup_error:
                cleanup_results["failed"] += 1
                self.logger.error(f"Failed to cleanup idle session {session_id}: {cleanup_error}")
        
        if idle_sessions:
            self.logger.info(
                f"Cleaned up {len(idle_sessions)} idle connections "
                f"(success: {cleanup_results['success']}, failed: {cleanup_results['failed']})"
            )

    async def _update_connection_metrics(self):
        """Update connection metrics"""
        self.metrics.active_connections = len(self.session_connections)
        if self.pool:
            self.metrics.idle_connections = self.pool.freesize

    async def get_metrics(self) -> ConnectionMetrics:
        """Get connection metrics"""
        await self._update_connection_metrics()
        return self.metrics

    async def execute_query(
        self, session_id: str, sql: str, params: tuple | None = None, auth_context=None
    ) -> QueryResult:
        """Execute query with enhanced error handling and retry logic"""
        max_retries = 2
        for attempt in range(max_retries):
            try:
                conn = await self.get_connection(session_id)
                return await conn.execute(sql, params, auth_context)
            except Exception as e:
                error_msg = str(e).lower()
                # Check for connection-related errors that warrant retry
                is_connection_error = any(keyword in error_msg for keyword in [
                    'at_eof', 'connection', 'closed', 'nonetype', 'reader', 'transport'
                ])
                
                if is_connection_error and attempt < max_retries - 1:
                    self.logger.warning(f"Connection error during query execution (attempt {attempt + 1}): {e}")
                    # Clean up the problematic connection
                    await self.release_connection(session_id)
                    # Wait before retry
                    await asyncio.sleep(0.5 * (attempt + 1))
                    continue
                else:
                    # Not a connection error or final retry - re-raise
                    raise

    @asynccontextmanager
    async def get_connection_context(self, session_id: str):
        """Get connection context manager"""
        conn = await self.get_connection(session_id)
        try:
            yield conn
        finally:
            # Connection will be reused, no need to close here
            pass

    async def close(self):
        """Close connection manager"""
        try:
            # Cancel background tasks
            if self._health_check_task:
                self._health_check_task.cancel()
                try:
                    await self._health_check_task
                except asyncio.CancelledError:
                    pass

            if self._cleanup_task:
                self._cleanup_task.cancel()
                try:
                    await self._cleanup_task
                except asyncio.CancelledError:
                    pass

            # Clean up all session connections
            for session_id in list(self.session_connections.keys()):
                await self._cleanup_session_connection(session_id)

            # Close connection pool
            if self.pool:
                self.pool.close()
                await self.pool.wait_closed()

            self.logger.info("Connection manager closed successfully")

        except Exception as e:
            self.logger.error(f"Error closing connection manager: {e}")

    async def test_connection(self) -> bool:
        """Test database connection using robust connection test"""
        return await self._robust_connection_test()

    async def diagnose_connection_health(self) -> Dict[str, Any]:
        """Diagnose connection pool and session health"""
        diagnosis = {
            "timestamp": datetime.utcnow().isoformat(),
            "pool_status": "unknown",
            "session_connections": {},
            "problematic_connections": [],
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
            
            # Check session connections
            problematic_sessions = []
            for session_id, conn in self.session_connections.items():
                conn_status = {
                    "session_id": session_id,
                    "created_at": conn.created_at.isoformat(),
                    "last_used": conn.last_used.isoformat(),
                    "query_count": conn.query_count,
                    "is_healthy": conn.is_healthy
                }
                
                # Detailed connection checks
                if conn.connection:
                    conn_status["connection_closed"] = conn.connection.closed
                    conn_status["has_reader"] = hasattr(conn.connection, '_reader') and conn.connection._reader is not None
                    
                    if hasattr(conn.connection, '_reader') and conn.connection._reader:
                        conn_status["reader_transport"] = conn.connection._reader._transport is not None
                    else:
                        conn_status["reader_transport"] = False
                else:
                    conn_status["connection_closed"] = True
                    conn_status["has_reader"] = False
                    conn_status["reader_transport"] = False
                
                # Check if connection is problematic
                if (not conn.is_healthy or 
                    conn_status["connection_closed"] or 
                    not conn_status["has_reader"] or 
                    not conn_status["reader_transport"]):
                    problematic_sessions.append(session_id)
                    diagnosis["problematic_connections"].append(conn_status)
                
                diagnosis["session_connections"][session_id] = conn_status
            
            # Generate recommendations
            if problematic_sessions:
                diagnosis["recommendations"].append(f"Clean up {len(problematic_sessions)} problematic connections")
            
            if self.pool.freesize == 0 and self.pool.size >= self.pool.maxsize:
                diagnosis["recommendations"].append("Connection pool exhausted - consider increasing max_connections")
            
            # Auto-cleanup problematic connections
            for session_id in problematic_sessions:
                try:
                    await self._cleanup_session_connection(session_id)
                    self.logger.info(f"Auto-cleaned problematic connection for session: {session_id}")
                except Exception as e:
                    self.logger.error(f"Failed to auto-clean session {session_id}: {e}")
            
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
        self.logger = logging.getLogger(__name__)

    async def get_pool_status(self) -> dict[str, Any]:
        """Get connection pool status"""
        metrics = await self.connection_manager.get_metrics()
        
        status = {
            "pool_size": self.connection_manager.pool.size if self.connection_manager.pool else 0,
            "free_connections": self.connection_manager.pool.freesize if self.connection_manager.pool else 0,
            "active_sessions": len(self.connection_manager.session_connections),
            "total_connections": metrics.total_connections,
            "failed_connections": metrics.failed_connections,
            "connection_errors": metrics.connection_errors,
            "avg_connection_time": metrics.avg_connection_time,
            "last_health_check": metrics.last_health_check.isoformat() if metrics.last_health_check else None,
        }
        
        return status

    async def get_session_details(self) -> list[dict[str, Any]]:
        """Get session connection details"""
        sessions = []
        
        for session_id, conn in self.connection_manager.session_connections.items():
            session_info = {
                "session_id": session_id,
                "created_at": conn.created_at.isoformat(),
                "last_used": conn.last_used.isoformat(),
                "query_count": conn.query_count,
                "is_healthy": conn.is_healthy,
                "connection_age": (datetime.utcnow() - conn.created_at).total_seconds(),
            }
            sessions.append(session_info)
        
        return sessions

    async def generate_health_report(self) -> dict[str, Any]:
        """Generate connection health report"""
        pool_status = await self.get_pool_status()
        session_details = await self.get_session_details()
        
        # Calculate health statistics
        healthy_sessions = sum(1 for s in session_details if s["is_healthy"])
        total_sessions = len(session_details)
        health_ratio = healthy_sessions / total_sessions if total_sessions > 0 else 1.0
        
        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "pool_status": pool_status,
            "session_summary": {
                "total_sessions": total_sessions,
                "healthy_sessions": healthy_sessions,
                "health_ratio": health_ratio,
            },
            "session_details": session_details,
            "recommendations": [],
        }
        
        # Add recommendations based on health status
        if health_ratio < 0.8:
            report["recommendations"].append("Consider checking database connectivity and network stability")
        
        if pool_status["connection_errors"] > 10:
            report["recommendations"].append("High connection error rate detected, review connection configuration")
        
        if pool_status["active_sessions"] > pool_status["pool_size"] * 0.9:
            report["recommendations"].append("Connection pool utilization is high, consider increasing pool size")
        
        return report


