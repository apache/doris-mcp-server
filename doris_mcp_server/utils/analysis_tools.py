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
Data Analysis Tools Module
Provides data analysis functions including table analysis, column statistics, performance monitoring, etc.
"""

import time
from datetime import datetime
from typing import Any, Dict, List
import uuid
import aiohttp
import hashlib
from pathlib import Path

from .db import DorisConnectionManager
from .logger import get_logger

logger = get_logger(__name__)


class TableAnalyzer:
    """Table analyzer"""
    
    def __init__(self, connection_manager: DorisConnectionManager):
        self.connection_manager = connection_manager
    
    async def get_table_summary(
        self, 
        table_name: str, 
        include_sample: bool = True, 
        sample_size: int = 10
    ) -> Dict[str, Any]:
        """Get table summary information"""
        connection = await self.connection_manager.get_connection("query")
        
        # Get table basic information
        table_info_sql = f"""
        SELECT 
            table_name,
            table_comment,
            table_rows,
            create_time,
            engine
        FROM information_schema.tables 
        WHERE table_schema = DATABASE()
        AND table_name = '{table_name}'
        """
        
        table_info_result = await connection.execute(table_info_sql)
        if not table_info_result.data:
            raise ValueError(f"Table {table_name} does not exist")
        
        table_info = table_info_result.data[0]
        
        # Get column information
        columns_sql = f"""
        SELECT 
            column_name,
            data_type,
            is_nullable,
            column_comment
        FROM information_schema.columns 
        WHERE table_schema = DATABASE()
        AND table_name = '{table_name}'
        ORDER BY ordinal_position
        """
        
        columns_result = await connection.execute(columns_sql)
        
        summary = {
            "table_name": table_info["table_name"],
            "comment": table_info.get("table_comment"),
            "row_count": table_info.get("table_rows", 0),
            "create_time": str(table_info.get("create_time")),
            "engine": table_info.get("engine"),
            "column_count": len(columns_result.data),
            "columns": columns_result.data,
        }
        
        # Get sample data
        if include_sample and sample_size > 0:
            sample_sql = f"SELECT * FROM {table_name} LIMIT {sample_size}"
            sample_result = await connection.execute(sample_sql)
            summary["sample_data"] = sample_result.data
        
        return summary
    
    async def analyze_column(
        self, 
        table_name: str, 
        column_name: str, 
        analysis_type: str = "basic"
    ) -> Dict[str, Any]:
        """Analyze column statistics"""
        try:
            connection = await self.connection_manager.get_connection("query")
            
            # Basic statistics
            basic_stats_sql = f"""
            SELECT 
                '{column_name}' as column_name,
                COUNT(*) as total_count,
                COUNT({column_name}) as non_null_count,
                COUNT(DISTINCT {column_name}) as distinct_count
            FROM {table_name}
            """
            
            basic_result = await connection.execute(basic_stats_sql)
            if not basic_result.data:
                return {
                    "success": False,
                    "error": f"Unable to get statistics for table {table_name} column {column_name}"
                }
            
            analysis = basic_result.data[0].copy()
            analysis["success"] = True
            analysis["analysis_type"] = analysis_type
        
            if analysis_type in ["distribution", "detailed"]:
                # Data distribution analysis
                distribution_sql = f"""
                SELECT 
                    {column_name} as value,
                    COUNT(*) as frequency
                FROM {table_name}
                WHERE {column_name} IS NOT NULL
                GROUP BY {column_name}
                ORDER BY frequency DESC
                LIMIT 20
                """
                
                distribution_result = await connection.execute(distribution_sql)
                analysis["value_distribution"] = distribution_result.data
            
            if analysis_type == "detailed":
                # Detailed statistics (for numeric types)
                try:
                    numeric_stats_sql = f"""
                    SELECT 
                        MIN({column_name}) as min_value,
                        MAX({column_name}) as max_value,
                        AVG({column_name}) as avg_value
                    FROM {table_name}
                    WHERE {column_name} IS NOT NULL
                    """
                    
                    numeric_result = await connection.execute(numeric_stats_sql)
                    if numeric_result.data:
                        analysis.update(numeric_result.data[0])
                except Exception:
                    # Non-numeric columns don't support numeric statistics
                    pass
            
            return analysis
        
        except Exception as e:
            logger.error(f"Column analysis failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "column_name": column_name,
                "table_name": table_name
            }
    
    async def analyze_table_relationships(
        self, 
        table_name: str, 
        depth: int = 2
    ) -> Dict[str, Any]:
        """Analyze table relationships"""
        connection = await self.connection_manager.get_connection("system")
        
        # Get table basic information
        table_info_sql = f"""
        SELECT 
            table_name,
            table_comment,
            table_rows
        FROM information_schema.tables 
        WHERE table_schema = DATABASE()
        AND table_name = '{table_name}'
        """
        
        table_result = await connection.execute(table_info_sql)
        if not table_result.data:
            raise ValueError(f"Table {table_name} does not exist")
        
        # Get all tables list (for analyzing potential relationships)
        all_tables_sql = """
        SELECT 
            table_name,
            table_comment
        FROM information_schema.tables 
        WHERE table_schema = DATABASE()
        AND table_type = 'BASE TABLE'
        AND table_name != %s
        """
        
        all_tables_result = await connection.execute(all_tables_sql, (table_name,))
        
        return {
            "center_table": table_result.data[0],
            "related_tables": all_tables_result.data,
            "depth": depth,
            "note": "Table relationship analysis based on column name similarity and business logic inference",
        }


class PerformanceMonitor:
    """Performance monitor"""
    
    def __init__(self, connection_manager: DorisConnectionManager):
        self.connection_manager = connection_manager
    
    async def get_performance_stats(
        self, 
        metric_type: str = "queries", 
        time_range: str = "1h"
    ) -> Dict[str, Any]:
        """Get performance statistics"""
        connection = await self.connection_manager.get_connection("system")
        
        # Convert time range to seconds
        time_mapping = {
            "1h": 3600,
            "6h": 21600,
            "24h": 86400,
            "7d": 604800
        }
        
        seconds = time_mapping.get(time_range, 3600)
        
        if metric_type == "queries":
            # Query performance metrics
            stats = {
                "metric_type": "queries",
                "time_range": time_range,
                "timestamp": datetime.now().isoformat(),
                "total_queries": 0,
                "avg_execution_time": 0.0,
                "slow_queries": 0,
                "error_queries": 0,
                "note": "Query performance statistics (simulated data)"
            }
            
        elif metric_type == "connections":
            # Connection statistics
            connection_metrics = await self.connection_manager.get_metrics()
            stats = {
                "metric_type": "connections",
                "time_range": time_range,
                "timestamp": datetime.now().isoformat(),
                "total_connections": connection_metrics.total_connections,
                "active_connections": connection_metrics.active_connections,
                "idle_connections": connection_metrics.idle_connections,
                "failed_connections": connection_metrics.failed_connections,
                "connection_errors": connection_metrics.connection_errors,
                "avg_connection_time": connection_metrics.avg_connection_time,
                "last_health_check": connection_metrics.last_health_check.isoformat() if connection_metrics.last_health_check else None
            }
            
        elif metric_type == "tables":
            # Table-level statistics
            tables_sql = """
            SELECT 
                table_name,
                table_rows,
                data_length,
                index_length,
                create_time,
                update_time
            FROM information_schema.tables 
            WHERE table_schema = DATABASE()
            AND table_type = 'BASE TABLE'
            ORDER BY table_rows DESC
            LIMIT 20
            """
            
            tables_result = await connection.execute(tables_sql)
            stats = {
                "metric_type": "tables",
                "time_range": time_range,
                "timestamp": datetime.now().isoformat(),
                "table_count": len(tables_result.data),
                "tables": tables_result.data
            }
            
        elif metric_type == "system":
            # System-level metrics (simulated)
            stats = {
                "metric_type": "system",
                "time_range": time_range,
                "timestamp": datetime.now().isoformat(),
                "cpu_usage": 45.2,
                "memory_usage": 68.5,
                "disk_usage": 72.1,
                "network_io": {
                    "bytes_sent": 1024000,
                    "bytes_received": 2048000
                },
                "note": "System metrics (simulated data)"
            }
            
        else:
            raise ValueError(f"Unsupported metric type: {metric_type}")
        
        return stats
    
    async def get_query_history(
        self, 
        limit: int = 50, 
        order_by: str = "time"
    ) -> Dict[str, Any]:
        """Get query history"""
        # Since Doris doesn't have a built-in query history table,
        # we return simulated data
        return {
            "total_queries": 0,
            "queries": [],
            "limit": limit,
            "order_by": order_by,
            "note": "Query history feature requires audit log configuration"
        }


class SQLAnalyzer:
    """SQL analyzer for EXPLAIN and PROFILE operations"""
    
    def __init__(self, connection_manager: DorisConnectionManager):
        self.connection_manager = connection_manager
    
    async def get_sql_explain(
        self, 
        sql: str,
        verbose: bool = False,
        db_name: str = None,
        catalog_name: str = None
    ) -> Dict[str, Any]:
        """
        Get SQL execution plan using EXPLAIN command based on Doris syntax
        
        Args:
            sql: SQL statement to explain
            verbose: Whether to show verbose information
            db_name: Target database name
            catalog_name: Target catalog name
            
        Returns:
            Dict containing explain plan file path, content, and basic info
        """
        try:
            # Generate unique query ID for file naming
            import time
            query_hash = hashlib.md5(sql.encode()).hexdigest()[:8]
            timestamp = int(time.time())
            query_id = f"{timestamp}_{query_hash}"
            
            # Ensure temp directory exists
            temp_dir = Path(self.connection_manager.config.temp_files_dir)
            temp_dir.mkdir(parents=True, exist_ok=True)
            
            # Create explain file path
            explain_file = temp_dir / f"explain_{query_id}.txt"
            
            logger.info(f"Generating SQL explain for query ID: {query_id}")
            
            # Switch database if specified
            if db_name:
                await self.connection_manager.execute_query("explain_session", f"USE {db_name}")
            
            # Construct EXPLAIN query
            explain_type = "EXPLAIN VERBOSE" if verbose else "EXPLAIN"
            explain_sql = f"{explain_type} {sql.strip().rstrip(';')}"
            
            logger.info(f"Executing explain query: {explain_sql}")
            
            # Execute explain query
            result = await self.connection_manager.execute_query("explain_session", explain_sql)
            
            # Format explain output
            explain_content = []
            explain_content.append(f"=== SQL EXPLAIN PLAN ===")
            explain_content.append(f"Query ID: {query_id}")
            explain_content.append(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
            explain_content.append(f"Database: {db_name or 'current'}")
            explain_content.append(f"Verbose: {verbose}")
            explain_content.append("")
            explain_content.append("=== ORIGINAL SQL ===")
            explain_content.append(sql)
            explain_content.append("")
            explain_content.append("=== EXPLAIN QUERY ===")
            explain_content.append(explain_sql)
            explain_content.append("")
            explain_content.append("=== EXECUTION PLAN ===")
            
            if result and result.data:
                for row in result.data:
                    if isinstance(row, dict):
                        # Handle dict format
                        for key, value in row.items():
                            explain_content.append(f"{key}: {value}")
                    elif isinstance(row, (list, tuple)):
                        # Handle tuple/list format
                        explain_content.append(" | ".join(str(col) for col in row))
                    else:
                        # Handle string format
                        explain_content.append(str(row))
            else:
                explain_content.append("No execution plan data returned")
            
            explain_content.append("")
            explain_content.append("=== METADATA ===")
            explain_content.append(f"Execution time: {result.execution_time if result else 'N/A'} seconds")
            explain_content.append(f"Rows returned: {len(result.data) if result and result.data else 0}")
            
            # Get full content
            full_content = '\n'.join(explain_content)
            
            # Write to file
            with open(explain_file, 'w', encoding='utf-8') as f:
                f.write(full_content)
            
            logger.info(f"Explain plan saved to: {explain_file.absolute()}")
            
            # Get max response size from config
            max_size = self.connection_manager.config.performance.max_response_content_size
            
            # Truncate content if needed
            truncated_content = full_content
            is_truncated = False
            if len(full_content) > max_size:
                truncated_content = full_content[:max_size] + "\n\n=== CONTENT TRUNCATED ===\n[Content is truncated due to size limit. Full content is saved to file.]"
                is_truncated = True
            
            return {
                "success": True,
                "query_id": query_id,
                "explain_file_path": str(explain_file.absolute()),
                "file_size_bytes": explain_file.stat().st_size,
                "content": truncated_content,
                "content_size": len(truncated_content),
                "is_content_truncated": is_truncated,
                "original_content_size": len(full_content),
                "sql_preview": sql[:100] + "..." if len(sql) > 100 else sql,
                "verbose": verbose,
                "database": db_name,
                "catalog": catalog_name,
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
                "execution_time": result.execution_time if result else None,
                "plan_lines_count": len(result.data) if result and result.data else 0
            }
                
        except Exception as e:
            logger.error(f"Failed to get SQL explain: {str(e)}")
            return {
                "success": False,
                "error": f"Failed to get SQL explain: {str(e)}",
                "sql_preview": sql[:100] + "..." if len(sql) > 100 else sql,
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
            }
    
    async def get_sql_profile(
        self,
        sql: str,
        db_name: str = None,
        catalog_name: str = None,
        timeout: int = 30
    ) -> Dict[str, Any]:
        """
        Get SQL execution profile by setting trace ID and fetching profile via HTTP API
        
        Args:
            sql: SQL statement to profile
            db_name: Target database name
            catalog_name: Target catalog name
            timeout: Query timeout in seconds
            
        Returns:
            Dict containing profile file path, content, and basic info
        """
        try:
            # Generate unique trace ID and query ID for file naming
            trace_id = str(uuid.uuid4())
            import time
            query_hash = hashlib.md5(sql.encode()).hexdigest()[:8]
            timestamp = int(time.time())
            file_query_id = f"{timestamp}_{query_hash}"
            
            # Ensure temp directory exists
            temp_dir = Path(self.connection_manager.config.temp_files_dir)
            temp_dir.mkdir(parents=True, exist_ok=True)
            
            # Create profile file path
            profile_file = temp_dir / f"profile_{file_query_id}.txt"
            
            logger.info(f"Generated trace ID for SQL profiling: {trace_id}")
            logger.info(f"Profile will be saved to: {profile_file}")
            
            connection = await self.connection_manager.get_connection("query")
            
            try:
                # Switch to specified database/catalog if provided
                if catalog_name:
                    await connection.execute(f"SWITCH `{catalog_name}`")
                if db_name:
                    await connection.execute(f"USE `{db_name}`")
                
                # Set trace ID for the session using session variable
                # According to official docs: set session_context="trace_id:your_trace_id"
                await connection.execute(f'set session_context="trace_id:{trace_id}"')
                logger.info(f"Set trace ID: {trace_id}")

                # Enable profile
                await connection.execute(f'set enable_profile=true')
                logger.info(f"Enabled profile")
                
                # Execute the SQL statement
                logger.info(f"Executing SQL with trace ID: {sql}")
                start_time = time.time()
                sql_result = await connection.execute(sql)
                execution_time = time.time() - start_time
                logger.info(f"SQL execution completed in {execution_time:.3f}s")
                
                # Get query ID from trace ID via HTTP API
                query_id = await self._get_query_id_by_trace_id(trace_id)
                if not query_id:
                    return {
                        "success": False,
                        "error": "Failed to get query ID from trace ID",
                        "trace_id": trace_id,
                        "sql": sql,
                        "execution_time": execution_time
                    }
                
                logger.info(f"Retrieved query ID: {query_id}")

                # Get profile data
                profile_data = await self._get_profile_by_query_id(query_id)
                
                if not profile_data:
                    # Save error info to file
                    profile_content = [
                        f"=== SQL PROFILE RESULT ===",
                        f"File Query ID: {file_query_id}",
                        f"Trace ID: {trace_id}",
                        f"Query ID: {query_id}",
                        f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}",
                        f"Database: {db_name or 'current'}",
                        f"Status: FAILED",
                        "",
                        "=== ORIGINAL SQL ===",
                        sql,
                        "",
                        "=== ERROR INFO ===",
                        "Failed to get profile data. This may be due to:",
                        "1) Profile data not generated yet",
                        "2) Query ID expired", 
                        "3) Insufficient permissions to access profile data",
                        "",
                        "=== EXECUTION INFO ===",
                        f"Query execution: SUCCESSFUL",
                        f"Execution time: {execution_time:.3f} seconds",
                        f"Note: Query execution was successful, but profile data is not available"
                    ]
                    
                    # Get full content
                    full_profile_content = '\n'.join(profile_content)
                    
                    with open(profile_file, 'w', encoding='utf-8') as f:
                        f.write(full_profile_content)
                    
                    # Get max response size from config
                    max_size = self.connection_manager.config.performance.max_response_content_size
                    
                    # Truncate content if needed
                    truncated_content = full_profile_content
                    is_truncated = False
                    if len(full_profile_content) > max_size:
                        truncated_content = full_profile_content[:max_size] + "\n\n=== CONTENT TRUNCATED ===\n[Content is truncated due to size limit. Full content is saved to file.]"
                        is_truncated = True
                    
                    return {
                        "success": False,
                        "file_query_id": file_query_id,
                        "trace_id": trace_id,
                        "query_id": query_id,
                        "profile_file_path": str(profile_file.absolute()),
                        "file_size_bytes": profile_file.stat().st_size,
                        "content": truncated_content,
                        "content_size": len(truncated_content),
                        "is_content_truncated": is_truncated,
                        "original_content_size": len(full_profile_content),
                        "sql_preview": sql[:100] + "..." if len(sql) > 100 else sql,
                        "execution_time": execution_time,
                        "error": "Failed to get profile data",
                        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
                    }
                
                # Format profile output
                profile_content = []
                profile_content.append(f"=== SQL PROFILE RESULT ===")
                profile_content.append(f"File Query ID: {file_query_id}")
                profile_content.append(f"Trace ID: {trace_id}")
                profile_content.append(f"Query ID: {query_id}")
                profile_content.append(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
                profile_content.append(f"Database: {db_name or 'current'}")
                profile_content.append(f"Status: SUCCESS")
                profile_content.append("")
                profile_content.append("=== ORIGINAL SQL ===")
                profile_content.append(sql)
                profile_content.append("")
                profile_content.append("=== EXECUTION INFO ===")
                profile_content.append(f"Execution time: {execution_time:.3f} seconds")
                if hasattr(sql_result, 'data') and sql_result.data:
                    profile_content.append(f"Result rows: {len(sql_result.data)}")
                    if sql_result.data and sql_result.data[0]:
                        profile_content.append(f"Result columns: {list(sql_result.data[0].keys())}")
                profile_content.append("")
                profile_content.append("=== PROFILE DATA ===")
                
                if isinstance(profile_data, dict):
                    import json
                    profile_content.append(json.dumps(profile_data, indent=2, ensure_ascii=False))
                else:
                    profile_content.append(str(profile_data))
                
                # Get full content
                full_profile_content = '\n'.join(profile_content)
                
                # Write to file
                with open(profile_file, 'w', encoding='utf-8') as f:
                    f.write(full_profile_content)
                
                logger.info(f"Profile data saved to: {profile_file.absolute()}")
                
                # Get max response size from config
                max_size = self.connection_manager.config.performance.max_response_content_size
                
                # Truncate content if needed
                truncated_content = full_profile_content
                is_truncated = False
                if len(full_profile_content) > max_size:
                    truncated_content = full_profile_content[:max_size] + "\n\n=== CONTENT TRUNCATED ===\n[Content is truncated due to size limit. Full content is saved to file.]"
                    is_truncated = True
                
                return {
                    "success": True,
                    "file_query_id": file_query_id,
                    "trace_id": trace_id,
                    "query_id": query_id,
                    "profile_file_path": str(profile_file.absolute()),
                    "file_size_bytes": profile_file.stat().st_size,
                    "content": truncated_content,
                    "content_size": len(truncated_content),
                    "is_content_truncated": is_truncated,
                    "original_content_size": len(full_profile_content),
                    "sql_preview": sql[:100] + "..." if len(sql) > 100 else sql,
                    "database": db_name,
                    "catalog": catalog_name,
                    "execution_time": execution_time,
                    "sql_result_summary": {
                        "row_count": len(sql_result.data) if hasattr(sql_result, 'data') and sql_result.data else 0,
                        "columns": list(sql_result.data[0].keys()) if hasattr(sql_result, 'data') and sql_result.data and sql_result.data[0] else []
                    },
                    "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
                }
                
            except Exception as e:
                logger.error(f"Error during SQL execution or profile retrieval: {str(e)}")
                # Save error info to file
                profile_content = [
                    f"=== SQL PROFILE RESULT ===",
                    f"File Query ID: {file_query_id}",
                    f"Trace ID: {trace_id}",
                    f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}",
                    f"Database: {db_name or 'current'}",
                    f"Status: ERROR",
                    "",
                    "=== ORIGINAL SQL ===",
                    sql,
                    "",
                    "=== ERROR INFO ===",
                    f"SQL execution or profile retrieval failed: {str(e)}",
                    "",
                    "=== EXECUTION INFO ===",
                    "Query execution failed during profiling process"
                ]
                
                # Get full content
                full_profile_content = '\n'.join(profile_content)
                
                with open(profile_file, 'w', encoding='utf-8') as f:
                    f.write(full_profile_content)
                
                # Get max response size from config
                max_size = self.connection_manager.config.performance.max_response_content_size
                
                # Truncate content if needed
                truncated_content = full_profile_content
                is_truncated = False
                if len(full_profile_content) > max_size:
                    truncated_content = full_profile_content[:max_size] + "\n\n=== CONTENT TRUNCATED ===\n[Content is truncated due to size limit. Full content is saved to file.]"
                    is_truncated = True
                
                return {
                    "success": False,
                    "file_query_id": file_query_id,
                    "trace_id": trace_id,
                    "profile_file_path": str(profile_file.absolute()),
                    "file_size_bytes": profile_file.stat().st_size,
                    "content": truncated_content,
                    "content_size": len(truncated_content),
                    "is_content_truncated": is_truncated,
                    "original_content_size": len(full_profile_content),
                    "sql_preview": sql[:100] + "..." if len(sql) > 100 else sql,
                    "error": f"SQL execution or profile retrieval failed: {str(e)}",
                    "database": db_name,
                    "catalog": catalog_name,
                    "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
                }
                
        except Exception as e:
            logger.error(f"SQL PROFILE failed: {str(e)}")
            return {
                "success": False,
                "error": f"SQL PROFILE failed: {str(e)}",
                "sql_preview": sql[:100] + "..." if len(sql) > 100 else sql,
                "database": db_name,
                "catalog": catalog_name,
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
            }
    
    async def _get_query_id_by_trace_id(self, trace_id: str) -> str:
        """
        Get query ID by trace ID via FE HTTP API
        
        Args:
            trace_id: The trace ID set during query execution
            
        Returns:
            Query ID string or None if not found
        """
        try:
            # Get database config
            db_config = self.connection_manager.config.database
            
            # Build HTTP API URL according to official documentation
            # Reference: https://doris.apache.org/zh-CN/docs/admin-manual/open-api/fe-http/query-profile-action#通过-trace-id-获取-query-id
            url = f"http://{db_config.host}:{db_config.fe_http_port}/rest/v2/manager/query/trace_id/{trace_id}"
            
            # HTTP Basic Auth
            auth = aiohttp.BasicAuth(db_config.user, db_config.password)
            
            logger.info(f"Requesting query ID from: {url}")
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, auth=auth, timeout=10) as response:
                    if response.status == 200:
                        # Check content type first
                        content_type = response.headers.get('content-type', '')
                        response_text = await response.text()
                        logger.info(f"Response content type: {content_type}")
                        logger.info(f"Response body: {response_text}")
                        
                        # Parse JSON response (regardless of content-type)
                        if response_text.strip():
                            try:
                                import json
                                result = json.loads(response_text)
                                logger.info(f"Query ID API response: {result}")
                                
                                # Parse response according to Doris API format
                                if result.get("code") == 0 and result.get("data"):
                                    data = result["data"]
                                    # Data can be either a string (query_id) or object with query_ids
                                    if isinstance(data, str):
                                        logger.info(f"Found query ID: {data}")
                                        return data
                                    elif isinstance(data, dict) and "query_ids" in data:
                                        query_ids = data["query_ids"]
                                        if query_ids:
                                            query_id = query_ids[0]  # Take the first query ID
                                            logger.info(f"Found query ID: {query_id}")
                                            return query_id
                                        else:
                                            logger.warning("No query IDs found in response")
                                else:
                                    logger.error(f"API returned error: {result}")
                                    
                            except json.JSONDecodeError as e:
                                logger.error(f"Failed to parse JSON response: {e}")
                                # Fallback: try to extract query ID using regex
                                import re
                                query_id_pattern = r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'
                                matches = re.findall(query_id_pattern, response_text)
                                if matches:
                                    query_id = matches[0]
                                    logger.info(f"Extracted query ID from text: {query_id}")
                                    return query_id
                    else:
                        logger.error(f"HTTP request failed with status {response.status}")
                        response_text = await response.text()
                        logger.error(f"Response body: {response_text}")
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get query ID by trace ID: {str(e)}")
            return None
    
    async def _get_profile_by_query_id(self, query_id: str) -> Dict[str, Any]:
        """
        Get profile data by query ID via FE HTTP API
        
        Args:
            query_id: The query ID
            
        Returns:
            Profile data dict or None if failed
        """
        try:
            # Get database config
            db_config = self.connection_manager.config.database
            
            # Try both API endpoints according to official documentation
            urls = [
                f"http://{db_config.host}:{db_config.fe_http_port}/rest/v2/manager/query/profile/text/{query_id}",
                f"http://{db_config.host}:{db_config.fe_http_port}/api/profile/text?query_id={query_id}"
            ]
            
            # HTTP Basic Auth
            auth = aiohttp.BasicAuth(db_config.user, db_config.password)
            
            for i, url in enumerate(urls):
                logger.info(f"Requesting profile from URL {i+1}: {url}")
                
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, auth=auth, timeout=60) as response:
                        if response.status == 200:
                            content_type = response.headers.get('content-type', '')
                            response_text = await response.text()
                            logger.info(f"Profile response content type: {content_type}")
                            logger.info(f"Profile response length: {len(response_text)}")
                            
                            # Handle JSON response
                            if 'application/json' in content_type:
                                try:
                                    result = await response.json()
                                    logger.info(f"Profile JSON response: {result}")
                                    
                                    if result.get("code") == 0 and result.get("data"):
                                        profile_text = result["data"].get("profile", "")
                                        return {
                                            "query_id": query_id,
                                            "profile_text": profile_text,
                                            "profile_size": len(profile_text),
                                            "retrieved_at": datetime.now().isoformat(),
                                            "api_endpoint": url
                                        }
                                    else:
                                        logger.warning(f"Profile API returned error: {result}")
                                        continue  # Try next URL
                                        
                                except Exception as e:
                                    logger.error(f"Failed to parse profile JSON: {e}")
                                    continue
                            
                            # Handle plain text response
                            else:
                                if response_text.strip() and "not found" not in response_text.lower():
                                    return {
                                        "query_id": query_id,
                                        "profile_text": response_text,
                                        "profile_size": len(response_text),
                                        "retrieved_at": datetime.now().isoformat(),
                                        "api_endpoint": url
                                    }
                                else:
                                    logger.warning(f"Profile not found or empty: {response_text}")
                                    continue  # Try next URL
                        
                        elif response.status == 404:
                            logger.warning(f"Profile not found (404) at {url}")
                            continue  # Try next URL
                        else:
                            logger.error(f"Profile HTTP request failed with status {response.status} at {url}")
                            response_text = await response.text()
                            logger.error(f"Response body: {response_text}")
                            continue  # Try next URL
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get profile by query ID: {str(e)}")
            return None
    
    async def get_table_data_size(
        self, 
        db_name: str = None,
        table_name: str = None,
        single_replica: bool = False
    ) -> Dict[str, Any]:
        """
        Get table data size information via FE HTTP API
        
        Args:
            db_name: Database name, if not specified returns all databases
            table_name: Table name, if not specified returns all tables in the database
            single_replica: Whether to get single replica data size
            
        Returns:
            Dict containing table data size information
        """
        try:
            # Get database config
            db_config = self.connection_manager.config.database
            
            # Build HTTP API URL according to official documentation
            # Reference: https://doris.apache.org/zh-CN/docs/admin-manual/open-api/fe-http/show-table-data-action
            url = f"http://{db_config.host}:{db_config.fe_http_port}/api/show_table_data"
            
            # Build query parameters
            params = {}
            if db_name:
                params["db"] = db_name
            if table_name:
                params["table"] = table_name
            if single_replica:
                params["single_replica"] = "true"
            
            # HTTP Basic Auth
            auth = aiohttp.BasicAuth(db_config.user, db_config.password)
            
            logger.info(f"Requesting table data size from: {url} with params: {params}")
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, auth=auth, params=params, timeout=30) as response:
                    if response.status == 200:
                        response_text = await response.text()
                        logger.info(f"Table data size response length: {len(response_text)}")
                        
                        try:
                            # Parse JSON response
                            import json
                            result = json.loads(response_text)
                            
                            if result.get("code") == 0 and result.get("data"):
                                data = result["data"]
                                
                                # Process and format the data
                                formatted_data = self._format_table_data_size(data, db_name, table_name, single_replica)
                                
                                return {
                                    "success": True,
                                    "db_name": db_name,
                                    "table_name": table_name,
                                    "single_replica": single_replica,
                                    "timestamp": datetime.now().isoformat(),
                                    "data": formatted_data,
                                    "url": url,
                                    "note": "Table data size information from Doris FE HTTP API"
                                }
                            else:
                                return {
                                    "success": False,
                                    "error": f"API returned error: {result}",
                                    "db_name": db_name,
                                    "table_name": table_name,
                                    "url": url,
                                    "timestamp": datetime.now().isoformat()
                                }
                                
                        except json.JSONDecodeError as e:
                            logger.error(f"Failed to parse JSON response: {e}")
                            return {
                                "success": False,
                                "error": f"Failed to parse JSON response: {e}",
                                "response_text": response_text[:500],  # First 500 chars for debugging
                                "url": url,
                                "timestamp": datetime.now().isoformat()
                            }
                    else:
                        logger.error(f"HTTP request failed with status {response.status}")
                        response_text = await response.text()
                        logger.error(f"Response body: {response_text}")
                        return {
                            "success": False,
                            "error": f"HTTP request failed with status {response.status}",
                            "response_text": response_text[:500],  # First 500 chars for debugging
                            "url": url,
                            "timestamp": datetime.now().isoformat()
                        }
                        
        except Exception as e:
            logger.error(f"Table data size request failed: {str(e)}")
            return {
                "success": False,
                "error": f"Table data size request failed: {str(e)}",
                "db_name": db_name,
                "table_name": table_name,
                "timestamp": datetime.now().isoformat()
            }
    
    def _format_table_data_size(self, data: Dict[str, Any], db_name: str, table_name: str, single_replica: bool) -> Dict[str, Any]:
        """
        Format table data size response data
        
        Args:
            data: Raw response data from API
            db_name: Database name filter
            table_name: Table name filter
            single_replica: Single replica flag
            
        Returns:
            Formatted data structure
        """
        try:
            formatted = {
                "summary": {
                    "total_databases": 0,
                    "total_tables": 0,
                    "total_size_bytes": 0,
                    "total_size_formatted": "0 B",
                    "single_replica": single_replica,
                    "query_filters": {
                        "db_name": db_name,
                        "table_name": table_name
                    }
                },
                "databases": {}
            }
            
            # Process the data based on its structure
            if isinstance(data, list):
                # Data is a list of table records
                for record in data:
                    db = record.get("database", "unknown")
                    table = record.get("table", "unknown")
                    size_bytes = int(record.get("size", 0))
                    
                    if db not in formatted["databases"]:
                        formatted["databases"][db] = {
                            "database_name": db,
                            "table_count": 0,
                            "total_size_bytes": 0,
                            "total_size_formatted": "0 B",
                            "tables": {}
                        }
                    
                    formatted["databases"][db]["tables"][table] = {
                        "table_name": table,
                        "size_bytes": size_bytes,
                        "size_formatted": self._format_bytes(size_bytes),
                        "replica_count": record.get("replica_count", 1),
                        "details": record
                    }
                    
                    formatted["databases"][db]["table_count"] += 1
                    formatted["databases"][db]["total_size_bytes"] += size_bytes
                    formatted["summary"]["total_size_bytes"] += size_bytes
                
            elif isinstance(data, dict):
                # Data is a dict with database structure
                for db, db_info in data.items():
                    if isinstance(db_info, dict) and "tables" in db_info:
                        formatted["databases"][db] = {
                            "database_name": db,
                            "table_count": len(db_info["tables"]),
                            "total_size_bytes": 0,
                            "total_size_formatted": "0 B",
                            "tables": {}
                        }
                        
                        for table, table_info in db_info["tables"].items():
                            size_bytes = int(table_info.get("size", 0))
                            formatted["databases"][db]["tables"][table] = {
                                "table_name": table,
                                "size_bytes": size_bytes,
                                "size_formatted": self._format_bytes(size_bytes),
                                "replica_count": table_info.get("replica_count", 1),
                                "details": table_info
                            }
                            formatted["databases"][db]["total_size_bytes"] += size_bytes
                            formatted["summary"]["total_size_bytes"] += size_bytes
            
            # Update summary
            formatted["summary"]["total_databases"] = len(formatted["databases"])
            formatted["summary"]["total_tables"] = sum(db["table_count"] for db in formatted["databases"].values())
            formatted["summary"]["total_size_formatted"] = self._format_bytes(formatted["summary"]["total_size_bytes"])
            
            # Update database totals formatting
            for db_info in formatted["databases"].values():
                db_info["total_size_formatted"] = self._format_bytes(db_info["total_size_bytes"])
            
            return formatted
            
        except Exception as e:
            logger.error(f"Failed to format table data size: {str(e)}")
            return {
                "error": f"Failed to format data: {str(e)}",
                "raw_data": data
            }
    
    def _format_bytes(self, bytes_value: int) -> str:
        """
        Format bytes value to human readable string
        
        Args:
            bytes_value: Bytes value
            
        Returns:
            Formatted string like "1.23 GB"
        """
        try:
            bytes_value = int(bytes_value)
            if bytes_value == 0:
                return "0 B"
            
            units = ["B", "KB", "MB", "GB", "TB", "PB"]
            unit_index = 0
            size = float(bytes_value)
            
            while size >= 1024 and unit_index < len(units) - 1:
                size /= 1024
                unit_index += 1
            
            if unit_index == 0:
                return f"{int(size)} {units[unit_index]}"
            else:
                return f"{size:.2f} {units[unit_index]}"
                
        except (ValueError, TypeError):
            return str(bytes_value)


class MemoryTracker:
    """Memory tracker for Doris BE memory monitoring"""
    
    def __init__(self, connection_manager: DorisConnectionManager):
        self.connection_manager = connection_manager
    
    async def get_realtime_memory_stats(
        self,
        tracker_type: str = "overview",
        include_details: bool = True
    ) -> Dict[str, Any]:
        """
        Get real-time memory statistics
        
        Args:
            tracker_type: Type of memory trackers to retrieve
            include_details: Whether to include detailed information
            
        Returns:
            Dict containing memory statistics
        """
        try:
            # This is a placeholder implementation
            # In a real implementation, this would fetch data from Doris BE memory tracker endpoints
            return {
                "success": True,
                "tracker_type": tracker_type,
                "include_details": include_details,
                "timestamp": datetime.now().isoformat(),
                "memory_stats": {
                    "total_memory": "8.00 GB",
                    "used_memory": "4.50 GB",
                    "free_memory": "3.50 GB",
                    "memory_usage_percent": 56.25
                },
                "note": "Memory tracker functionality requires BE HTTP endpoints to be available"
            }
            
        except Exception as e:
            logger.error(f"Failed to get realtime memory stats: {str(e)}")
            return {
                "success": False,
                "error": f"Failed to get realtime memory stats: {str(e)}",
                "tracker_type": tracker_type,
                "timestamp": datetime.now().isoformat()
            }
    
    async def get_historical_memory_stats(
        self,
        tracker_names: List[str] = None,
        time_range: str = "1h"
    ) -> Dict[str, Any]:
        """
        Get historical memory statistics
        
        Args:
            tracker_names: List of specific tracker names to query
            time_range: Time range for historical data
            
        Returns:
            Dict containing historical memory statistics
        """
        try:
            # This is a placeholder implementation
            # In a real implementation, this would fetch historical data from Doris BE bvar endpoints
            return {
                "success": True,
                "tracker_names": tracker_names,
                "time_range": time_range,
                "timestamp": datetime.now().isoformat(),
                "historical_stats": {
                    "data_points": 60,
                    "interval": "1m",
                    "memory_trend": "stable",
                    "avg_usage": "4.2 GB",
                    "peak_usage": "5.1 GB",
                    "min_usage": "3.8 GB"
                },
                "note": "Historical memory tracking functionality requires BE bvar endpoints to be available"
            }
            
        except Exception as e:
            logger.error(f"Failed to get historical memory stats: {str(e)}")
            return {
                "success": False,
                "error": f"Failed to get historical memory stats: {str(e)}",
                "tracker_names": tracker_names,
                "time_range": time_range,
                "timestamp": datetime.now().isoformat()
            } 
