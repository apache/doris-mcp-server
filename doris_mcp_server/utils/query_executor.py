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
Doris Query Execution Module
Implements query optimization, cache management and performance monitoring functionality
"""

import asyncio
import hashlib
import json
import logging
import time
import os
import uuid
import traceback
from dataclasses import dataclass
from datetime import datetime, timedelta, date
from typing import Any, Dict
from decimal import Decimal

from .db import DorisConnectionManager, QueryResult
from .logger import get_logger


@dataclass
class QueryRequest:
    """Query request wrapper"""

    sql: str
    session_id: str
    user_id: str
    parameters: dict[str, Any] | None = None
    timeout: int | None = None
    cache_enabled: bool = True


@dataclass
class CachedQuery:
    """Cached query result"""

    result: QueryResult
    created_at: datetime
    ttl: int
    access_count: int = 0
    last_accessed: datetime | None = None

    def is_expired(self) -> bool:
        """Check if cache is expired"""
        if self.ttl <= 0:
            return False
        return (datetime.utcnow() - self.created_at).total_seconds() > self.ttl

    def access(self):
        """Record access"""
        self.access_count += 1
        self.last_accessed = datetime.utcnow()


@dataclass
class QueryMetrics:
    """Query performance metrics"""

    total_queries: int = 0
    successful_queries: int = 0
    failed_queries: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    avg_execution_time: float = 0.0
    total_execution_time: float = 0.0
    slow_queries: int = 0
    concurrent_queries: int = 0


class QueryCache:
    """Query result cache manager"""

    def __init__(self, max_size: int = 1000, default_ttl: int = 300):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.cache: dict[str, CachedQuery] = {}
        self.logger = get_logger(__name__)

    def _generate_cache_key(
        self, sql: str, parameters: dict[str, Any] | None = None
    ) -> str:
        """Generate cache key"""
        cache_data = {"sql": sql.strip().lower(), "parameters": parameters or {}}
        cache_string = json.dumps(cache_data, sort_keys=True)
        return hashlib.md5(cache_string.encode()).hexdigest()

    async def get(
        self, sql: str, parameters: dict[str, Any] | None = None
    ) -> CachedQuery | None:
        """Get cached query result"""
        cache_key = self._generate_cache_key(sql, parameters)

        if cache_key in self.cache:
            cached_query = self.cache[cache_key]

            if not cached_query.is_expired():
                cached_query.access()
                self.logger.debug(f"Cache hit: {cache_key}")
                return cached_query
            else:
                # Clean up expired cache
                del self.cache[cache_key]
                self.logger.debug(f"Cache expired, cleaned up: {cache_key}")

        return None

    async def set(
        self,
        sql: str,
        result: QueryResult,
        parameters: dict[str, Any] | None = None,
        ttl: int | None = None,
    ) -> str:
        """Set query result cache"""
        cache_key = self._generate_cache_key(sql, parameters)

        # Check cache size limit
        if len(self.cache) >= self.max_size:
            await self._evict_oldest()

        cached_query = CachedQuery(
            result=result, created_at=datetime.utcnow(), ttl=ttl or self.default_ttl
        )

        self.cache[cache_key] = cached_query
        self.logger.debug(f"Cache set: {cache_key}")

        return cache_key

    async def _evict_oldest(self):
        """Clean up oldest cache item"""
        if not self.cache:
            return

        # Find oldest cache item
        oldest_key = min(self.cache.keys(), key=lambda k: self.cache[k].created_at)

        del self.cache[oldest_key]
        self.logger.debug(f"Cleaned up oldest cache: {oldest_key}")

    async def clear_expired(self):
        """Clean up all expired cache"""
        expired_keys = [
            key for key, cached_query in self.cache.items() if cached_query.is_expired()
        ]

        for key in expired_keys:
            del self.cache[key]

        if expired_keys:
            self.logger.info(f"Cleaned up {len(expired_keys)} expired cache items")

    async def clear_all(self):
        """Clean up all cache"""
        cache_count = len(self.cache)
        self.cache.clear()
        self.logger.info(f"Cleaned up all cache, total {cache_count} items")

    def get_stats(self) -> dict[str, Any]:
        """Get cache statistics"""
        total_access = sum(cached.access_count for cached in self.cache.values())

        return {
            "cache_size": len(self.cache),
            "max_size": self.max_size,
            "total_access": total_access,
            "hit_rate": 0.0
            if total_access == 0
            else sum(cached.access_count for cached in self.cache.values())
            / total_access,
        }


class QueryOptimizer:
    """Query optimizer"""

    def __init__(self, config):
        self.config = config
        self.logger = get_logger(__name__)
        self.optimization_rules = self._load_optimization_rules()

    def _load_optimization_rules(self) -> list[dict[str, Any]]:
        """Load query optimization rules"""
        return [
            {
                "name": "add_limit_clause",
                "description": "Add default limit for SELECT queries without LIMIT",
                "pattern": r"^select\s+.*(?!.*limit\s+\d+)",
                "action": "add_limit",
                "params": {"default_limit": 1000},
            },
            {
                "name": "optimize_count_query",
                "description": "Optimize COUNT queries",
                "pattern": r"select\s+count\(\*\)\s+from\s+(\w+)",
                "action": "optimize_count",
                "params": {},
            },
        ]

    async def optimize_query(self, sql: str, context: dict[str, Any]) -> str:
        """Apply query optimization"""
        optimized_sql = sql

        for rule in self.optimization_rules:
            if self._should_apply_rule(rule, optimized_sql, context):
                optimized_sql = await self._apply_optimization_rule(
                    optimized_sql, rule, context
                )
                self.logger.debug(f"Applied optimization rule: {rule['name']}")

        return optimized_sql

    def _should_apply_rule(
        self, rule: dict[str, Any], sql: str, context: dict[str, Any]
    ) -> bool:
        """Check if optimization rule should be applied"""
        import re

        # Check pattern match
        if "pattern" in rule:
            if not re.search(rule["pattern"], sql, re.IGNORECASE):
                return False

        # Check conditions
        if "conditions" in rule:
            for condition in rule["conditions"]:
                if not self._check_condition(condition, context):
                    return False

        return True

    def _check_condition(
        self, condition: dict[str, Any], context: dict[str, Any]
    ) -> bool:
        """Check optimization condition"""
        condition_type = condition.get("type")

        if condition_type == "user_role":
            required_roles = condition.get("roles", [])
            user_roles = context.get("user_roles", [])
            return any(role in user_roles for role in required_roles)

        elif condition_type == "query_size":
            max_size = condition.get("max_size", 1000)
            return len(context.get("sql", "")) <= max_size

        return True

    async def _apply_optimization_rule(
        self, sql: str, rule: dict[str, Any], context: dict[str, Any]
    ) -> str:
        """Apply optimization rule"""
        action = rule.get("action")
        params = rule.get("params", {})

        if action == "add_limit":
            return await self._add_limit_clause(sql, params)
        elif action == "optimize_count":
            return await self._optimize_count_query(sql, params)
        elif action == "add_hints":
            return await self._add_query_hints(sql, params)

        return sql

    async def _add_limit_clause(self, sql: str, params: dict[str, Any]) -> str:
        """Add LIMIT clause to query"""
        import re

        default_limit = params.get("default_limit", 1000)

        # Check if LIMIT already exists
        if re.search(r"\blimit\s+\d+", sql, re.IGNORECASE):
            return sql

        # Add LIMIT clause
        if sql.strip().endswith(";"):
            sql = sql.strip()[:-1]

        return f"{sql} LIMIT {default_limit}"

    async def _optimize_count_query(self, sql: str, params: dict[str, Any]) -> str:
        """Optimize COUNT query"""
        # For COUNT queries, we can add optimization hints
        return sql.replace("COUNT(*)", "COUNT(1)")

    async def _add_query_hints(self, sql: str, params: dict[str, Any]) -> str:
        """Add query hints"""
        hints = params.get("hints", [])
        if not hints:
            return sql

        hint_string = "/*+ " + " ".join(hints) + " */"
        return f"{hint_string} {sql}"


class DorisQueryExecutor:
    """Doris query executor with caching and optimization"""

    def __init__(self, connection_manager: DorisConnectionManager, config=None):
        self.connection_manager = connection_manager
        self.config = config or self._create_default_config()
        self.logger = get_logger(__name__)

        # Initialize components
        cache_config = getattr(self.config, 'performance', None)
        if cache_config:
            cache_size = getattr(cache_config, 'max_cache_size', 1000)
            cache_ttl = getattr(cache_config, 'cache_ttl', 300)
        else:
            cache_size = 1000
            cache_ttl = 300

        self.query_cache = QueryCache(max_size=cache_size, default_ttl=cache_ttl)
        self.query_optimizer = QueryOptimizer(self.config)
        self.metrics = QueryMetrics()

        # Performance monitoring
        self.slow_query_threshold = 5.0  # seconds
        self.max_concurrent_queries = getattr(
            getattr(self.config, 'performance', None), 'max_concurrent_queries', 50
        ) if hasattr(self.config, 'performance') else 50

        # Background tasks
        self._background_tasks = []
        self._start_background_tasks()

    def _create_default_config(self):
        """Create default configuration"""
        class DefaultConfig:
            def __init__(self):
                self.performance = DefaultPerformanceConfig()
                
        class DefaultPerformanceConfig:
            def __init__(self):
                self.max_cache_size = 1000
                self.cache_ttl = 300
                self.max_concurrent_queries = 50

        return DefaultConfig()

    def _start_background_tasks(self):
        """Start background tasks"""
        try:
            # Cache cleanup task
            cleanup_task = asyncio.create_task(self._cache_cleanup_loop())
            self._background_tasks.append(cleanup_task)
        except RuntimeError:
            # No event loop running (e.g., in tests), skip background tasks
            self.logger.debug("No event loop running, skipping background tasks")

    async def _cache_cleanup_loop(self):
        """Background cache cleanup loop"""
        while True:
            try:
                await asyncio.sleep(300)  # Run every 5 minutes
                await self.query_cache.clear_expired()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Cache cleanup error: {e}")

    async def execute_query(
        self, query_request: QueryRequest, auth_context=None
    ) -> QueryResult:
        """Execute query with caching and optimization"""
        start_time = time.time()
        self.metrics.total_queries += 1
        self.metrics.concurrent_queries += 1

        try:
            # Check cache first
            if query_request.cache_enabled:
                cached_result = await self.query_cache.get(
                    query_request.sql, query_request.parameters
                )
                if cached_result:
                    self.metrics.cache_hits += 1
                    self.logger.debug(f"Cache hit for query: {query_request.sql[:50]}...")
                    return cached_result.result

            self.metrics.cache_misses += 1

            # Execute query
            result = await self._execute_query_internal(query_request, auth_context)

            # Cache result if enabled
            if query_request.cache_enabled and result.row_count > 0:
                await self.query_cache.set(
                    query_request.sql, result, query_request.parameters
                )

            self.metrics.successful_queries += 1
            return result

        except Exception as e:
            self.metrics.failed_queries += 1
            self.logger.error(f"Query execution failed: {e}")
            raise

        finally:
            execution_time = time.time() - start_time
            self.metrics.concurrent_queries -= 1
            self._update_execution_metrics(execution_time)

    async def _execute_query_internal(
        self, query_request: QueryRequest, auth_context
    ) -> QueryResult:
        """Internal query execution"""
        
        # Database configuration should already be handled during authentication
        # No need to configure again during query execution
        
        # Optimize query
        optimized_sql = await self.query_optimizer.optimize_query(
            query_request.sql, {"user_roles": getattr(auth_context, 'roles', [])}
        )

        # Execute query
        # Set timeout if specified
        if query_request.timeout:
            try:
                result = await asyncio.wait_for(
                    self.connection_manager.execute_query(query_request.session_id, optimized_sql, query_request.parameters, auth_context),
                    timeout=query_request.timeout
                )
            except asyncio.TimeoutError:
                raise Exception(f"Query timeout after {query_request.timeout} seconds")
        else:
            result = await self.connection_manager.execute_query(query_request.session_id, optimized_sql, query_request.parameters, auth_context)

        return result

    def _update_execution_metrics(self, execution_time: float):
        """Update execution metrics"""
        self.metrics.total_execution_time += execution_time

        # Update average execution time
        if self.metrics.successful_queries > 0:
            self.metrics.avg_execution_time = (
                self.metrics.total_execution_time / self.metrics.successful_queries
            )

        # Check for slow queries
        if execution_time > self.slow_query_threshold:
            self.metrics.slow_queries += 1
            self.logger.warning(
                f"Slow query detected: {execution_time:.2f}s (threshold: {self.slow_query_threshold}s)"
            )

    async def execute_batch_queries(
        self, query_requests: list[QueryRequest], auth_context=None
    ) -> list[QueryResult]:
        """Execute multiple queries in batch"""
        results = []

        # Check concurrent query limit
        if len(query_requests) > self.max_concurrent_queries:
            raise Exception(
                f"Batch size {len(query_requests)} exceeds maximum concurrent queries {self.max_concurrent_queries}"
            )

        # Execute queries concurrently
        tasks = [
            self.execute_query(request, auth_context) for request in query_requests
        ]

        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)
        except Exception as e:
            self.logger.error(f"Batch query execution failed: {e}")
            raise

        return results

    async def explain_query(self, sql: str, session_id: str) -> dict[str, Any]:
        """Get query execution plan"""
        explain_sql = f"EXPLAIN {sql}"

        connection = await self.connection_manager.get_connection(session_id)
        result = await connection.execute(explain_sql)

        return {
            "query": sql,
            "execution_plan": result.data,
            "estimated_cost": "N/A",  # Doris doesn't provide cost estimates
        }

    async def get_query_stats(self) -> dict[str, Any]:
        """Get query execution statistics"""
        cache_stats = self.query_cache.get_stats()

        return {
            "query_metrics": {
                "total_queries": self.metrics.total_queries,
                "successful_queries": self.metrics.successful_queries,
                "failed_queries": self.metrics.failed_queries,
                "success_rate": (
                    self.metrics.successful_queries / self.metrics.total_queries
                    if self.metrics.total_queries > 0
                    else 0.0
                ),
                "avg_execution_time": self.metrics.avg_execution_time,
                "slow_queries": self.metrics.slow_queries,
                "concurrent_queries": self.metrics.concurrent_queries,
            },
            "cache_metrics": {
                "cache_hits": self.metrics.cache_hits,
                "cache_misses": self.metrics.cache_misses,
                "hit_rate": (
                    self.metrics.cache_hits
                    / (self.metrics.cache_hits + self.metrics.cache_misses)
                    if (self.metrics.cache_hits + self.metrics.cache_misses) > 0
                    else 0.0
                ),
                **cache_stats,
            },
        }

    async def clear_cache(self):
        """Clear query cache"""
        await self.query_cache.clear_all()

    async def execute_sql_for_mcp(
        self, 
        sql: str, 
        limit: int = 1000, 
        timeout: int = 30,
        session_id: str = "mcp_session",
        user_id: str = "mcp_user"
    ) -> Dict[str, Any]:
        """Execute SQL query for MCP interface - unified method"""
        max_retries = 2
        retry_count = 0
        
        while retry_count <= max_retries:
            try:
                if not sql:
                    return {
                        "success": False,
                        "error": "SQL query is required",
                        "data": None
                    }

                # Import required security modules
                from .security import DorisSecurityManager, AuthContext, SecurityLevel

                # Create proper auth context with read-only permissions
                auth_context = AuthContext(
                    user_id=user_id,
                    roles=["read_only_user"],  # Restrictive role for MCP interface
                    permissions=["read_data"],  # Only read permissions
                    session_id=session_id,
                    security_level=SecurityLevel.INTERNAL
                )

                # Perform SQL security validation if enabled
                if hasattr(self.connection_manager, 'config') and hasattr(self.connection_manager.config, 'security'):
                    if self.connection_manager.config.security.enable_security_check:
                        try:
                            security_manager = DorisSecurityManager(self.connection_manager.config)
                            validation_result = await security_manager.validate_sql_security(sql, auth_context)
                            
                            if not validation_result.is_valid:
                                self.logger.warning(f"SQL security validation failed for query: {sql[:100]}...")
                                return {
                                    "success": False,
                                    "error": f"SQL security validation failed: {validation_result.error_message}",
                                    "error_type": "security_violation",
                                    "blocked_operations": validation_result.blocked_operations,
                                    "risk_level": validation_result.risk_level,
                                    "data": None,
                                    "metadata": {
                                        "query": sql,
                                        "validation_details": {
                                            "blocked_operations": validation_result.blocked_operations,
                                            "risk_level": validation_result.risk_level
                                        }
                                    }
                                }
                            else:
                                self.logger.debug(f"SQL security validation passed for query: {sql[:100]}...")
                        except Exception as security_error:
                            self.logger.error(f"Security validation error: {str(security_error)}")
                            # In case of security validation error, fail safe
                            return {
                                "success": False,
                                "error": f"Security validation system error: {str(security_error)}",
                                "error_type": "security_system_error",
                                "data": None,
                                "metadata": {
                                    "query": sql,
                                    "security_error": str(security_error)
                                }
                            }
                    else:
                        self.logger.info("SQL security check is disabled in configuration")
                else:
                    self.logger.warning("Security configuration not found, proceeding without validation")

                # Add LIMIT if not present and it's a SELECT query
                if sql.upper().startswith("SELECT") and "LIMIT" not in sql.upper():
                    if sql.endswith(";"):
                        sql = sql[:-1]
                    sql = f"{sql} LIMIT {limit}"
                
                # Create query request
                query_request = QueryRequest(
                    sql=sql,
                    session_id=session_id,
                    user_id=user_id,
                    timeout=timeout,
                    cache_enabled=False  # Disable cache for MCP calls to ensure fresh data
                )
                
                # Execute query with retry logic
                result = await self.execute_query(query_request, auth_context)
                
                # Serialize data for JSON response
                serialized_data = []
                for row in result.data:
                    serialized_data.append(self._serialize_row_data(row))

                return {
                    "success": True,
                    "data": serialized_data,
                    "row_count": result.row_count,
                    "execution_time": result.execution_time,
                    "metadata": {
                        "columns": result.metadata.get("columns", []),
                        "query": sql
                    }
                }
                
            except Exception as e:
                error_msg = str(e)
                error_str = error_msg.lower()
                
                # Check if it's a connection-related error that we should retry
                connection_errors = [
                    "at_eof", "connection", "closed", "nonetype", 
                    "transport", "reader", "broken pipe", "connection reset"
                ]
                
                is_connection_error = any(err in error_str for err in connection_errors)
                
                if is_connection_error and retry_count < max_retries:
                    retry_count += 1
                    self.logger.warning(f"Connection error detected, retrying ({retry_count}/{max_retries}): {e}")
                    
                    # Release the problematic connection
                    try:
                        await self.connection_manager.release_connection(session_id)
                    except Exception:
                        pass  # Ignore cleanup errors
                    
                    # Wait a bit before retry
                    await asyncio.sleep(0.5 * retry_count)
                    continue
                else:
                    # If we've exhausted retries or it's not a connection error, return error
                    error_analysis = self._analyze_error(error_msg)
                    
                    return {
                        "success": False,
                        "error": error_analysis.get("user_message", error_msg),
                        "error_type": error_analysis.get("error_type", "general_error"),
                        "data": None,
                        "metadata": {
                            "query": sql,
                            "error_details": error_msg,
                            "retry_count": retry_count
                        }
                    }
        
        # This should never be reached, but just in case
        return {
            "success": False,
            "error": "Maximum retries exceeded",
            "data": None,
            "metadata": {
                "query": sql,
                "retry_count": retry_count
            }
        }

    def _serialize_row_data(self, row_data: Dict[str, Any]) -> Dict[str, Any]:
        """Serialize row data for JSON response"""
        serialized = {}
        
        for key, value in row_data.items():
            if value is None:
                serialized[key] = None
            elif isinstance(value, (str, int, float, bool)):
                serialized[key] = value
            elif isinstance(value, Decimal):
                serialized[key] = float(value)
            elif isinstance(value, (datetime, date)):
                serialized[key] = value.isoformat()
            elif isinstance(value, bytes):
                try:
                    serialized[key] = value.decode('utf-8')
                except UnicodeDecodeError:
                    serialized[key] = str(value)
            else:
                serialized[key] = str(value)
                
        return serialized

    def _analyze_error(self, error_message: str) -> Dict[str, str]:
        """Analyze error message and provide user-friendly feedback"""
        error_msg_lower = error_message.lower()
        
        if "at_eof" in error_msg_lower or "nonetype" in error_msg_lower and "at_eof" in error_msg_lower:
            return {
                "error_type": "connection_lost",
                "user_message": "Database connection was lost. The query has been automatically retried. If this persists, please restart the server."
            }
        elif "table" in error_msg_lower and "doesn't exist" in error_msg_lower:
            return {
                "error_type": "table_not_found",
                "user_message": "The specified table does not exist. Please check the table name and database."
            }
        elif "column" in error_msg_lower and ("unknown" in error_msg_lower or "doesn't exist" in error_msg_lower):
            return {
                "error_type": "column_not_found", 
                "user_message": "One or more columns in the query do not exist. Please check column names."
            }
        elif "syntax error" in error_msg_lower or "sql syntax" in error_msg_lower:
            return {
                "error_type": "syntax_error",
                "user_message": "SQL syntax error. Please check your query syntax."
            }
        elif "access denied" in error_msg_lower or "permission" in error_msg_lower:
            return {
                "error_type": "permission_denied",
                "user_message": "Access denied. You don't have permission to execute this query."
            }
        elif "timeout" in error_msg_lower:
            return {
                "error_type": "timeout",
                "user_message": "Query execution timed out. Try simplifying your query or adding more specific filters."
            }
        elif "connection" in error_msg_lower and ("closed" in error_msg_lower or "reset" in error_msg_lower):
            return {
                "error_type": "connection_error",
                "user_message": "Database connection was interrupted. The query has been automatically retried."
            }
        else:
            return {
                "error_type": "general_error",
                "user_message": f"Query execution failed: {error_message}"
            }

    async def close(self):
        """Close query executor and cleanup resources"""
        # Cancel background tasks
        for task in self._background_tasks:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        # Clear cache
        await self.query_cache.clear_all()

        self.logger.info("Query executor closed")


class QueryPerformanceMonitor:
    """Query performance monitor"""

    def __init__(self, query_executor: DorisQueryExecutor):
        self.query_executor = query_executor
        self.logger = get_logger(__name__)
        self.performance_records = []

    async def record_query_performance(
        self, query_request: QueryRequest, result: QueryResult, execution_time: float
    ):
        """Record query performance"""
        record = {
            "timestamp": datetime.utcnow(),
            "sql": query_request.sql,
            "user_id": query_request.user_id,
            "session_id": query_request.session_id,
            "execution_time": execution_time,
            "row_count": result.row_count,
            "cache_hit": False,  # This would need to be passed from executor
        }

        self.performance_records.append(record)

        # Keep only recent records (last 1000)
        if len(self.performance_records) > 1000:
            self.performance_records = self.performance_records[-1000:]

    async def get_performance_report(
        self, time_range_minutes: int = 60
    ) -> dict[str, Any]:
        """Get performance report"""
        cutoff_time = datetime.utcnow() - timedelta(minutes=time_range_minutes)

        recent_records = [
            record
            for record in self.performance_records
            if record["timestamp"] >= cutoff_time
        ]

        if not recent_records:
            return {"message": "No performance data available for the specified time range"}

        # Calculate statistics
        execution_times = [record["execution_time"] for record in recent_records]
        row_counts = [record["row_count"] for record in recent_records]

        return {
            "time_range_minutes": time_range_minutes,
            "total_queries": len(recent_records),
            "avg_execution_time": sum(execution_times) / len(execution_times),
            "max_execution_time": max(execution_times),
            "min_execution_time": min(execution_times),
            "avg_row_count": sum(row_counts) / len(row_counts),
            "query_distribution": self._analyze_query_distribution(recent_records),
        }

    def _analyze_query_distribution(
        self, records: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Analyze query distribution"""
        query_types = {}
        user_distribution = {}

        for record in records:
            # Analyze query type
            sql_upper = record["sql"].strip().upper()
            if sql_upper.startswith("SELECT"):
                query_type = "SELECT"
            elif sql_upper.startswith("INSERT"):
                query_type = "INSERT"
            elif sql_upper.startswith("UPDATE"):
                query_type = "UPDATE"
            elif sql_upper.startswith("DELETE"):
                query_type = "DELETE"
            else:
                query_type = "OTHER"

            query_types[query_type] = query_types.get(query_type, 0) + 1

            # Analyze user distribution
            user_id = record["user_id"]
            user_distribution[user_id] = user_distribution.get(user_id, 0) + 1

        return {"query_types": query_types, "user_distribution": user_distribution}


# Unified convenience function for MCP integration
async def execute_sql_query(sql: str, connection_manager: DorisConnectionManager, **kwargs) -> Dict[str, Any]:
    """Execute SQL query - unified convenience function for MCP tools
    
    This function now includes security validation to ensure safe query execution.
    All queries are validated against the configured security policies before execution.
    """
    try:
        # Create query executor with the connection manager's configuration
        executor = DorisQueryExecutor(connection_manager)
        
        try:
            # Extract parameters from kwargs or use defaults
            limit = kwargs.get("limit", 1000)
            timeout = kwargs.get("timeout", 30)
            session_id = kwargs.get("session_id", "mcp_session")
            user_id = kwargs.get("user_id", "mcp_user")
            
            # The execute_sql_for_mcp method now includes security validation
            result = await executor.execute_sql_for_mcp(
                sql=sql,
                limit=limit,
                timeout=timeout,
                session_id=session_id,
                user_id=user_id
            )
            return result
        finally:
            await executor.close()
            
    except Exception as e:
        return {
            "success": False,
            "error": f"Query execution failed: {str(e)}",
            "error_type": "execution_error",
            "data": None,
            "metadata": {
                "query": sql,
                "execution_error": str(e)
            }
        }
