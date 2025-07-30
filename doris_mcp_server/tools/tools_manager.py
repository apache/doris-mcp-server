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
Apache Doris MCP Tools Manager
Responsible for tool registration, management, scheduling and routing, does not contain specific business logic implementation
"""

import json
import time
from datetime import datetime
from typing import Any, Dict, List

from mcp.types import Tool

from ..utils.db import DorisConnectionManager
from ..utils.query_executor import DorisQueryExecutor
from ..utils.analysis_tools import TableAnalyzer, SQLAnalyzer, MemoryTracker
from ..utils.monitoring_tools import DorisMonitoringTools
from ..utils.schema_extractor import MetadataExtractor
from ..utils.data_governance_tools import DataGovernanceTools
from ..utils.data_exploration_tools import DataExplorationTools
from ..utils.data_quality_tools import DataQualityTools
from ..utils.security_analytics_tools import SecurityAnalyticsTools
from ..utils.dependency_analysis_tools import DependencyAnalysisTools
from ..utils.performance_analytics_tools import PerformanceAnalyticsTools
from ..utils.adbc_query_tools import DorisADBCQueryTools
from ..utils.logger import get_logger

logger = get_logger(__name__)



class DorisToolsManager:
    """Apache Doris Tools Manager"""
    
    def __init__(self, connection_manager: DorisConnectionManager):
        self.connection_manager = connection_manager
        
        # Initialize business logic processors
        self.query_executor = DorisQueryExecutor(connection_manager)
        self.table_analyzer = TableAnalyzer(connection_manager)
        self.sql_analyzer = SQLAnalyzer(connection_manager)
        self.metadata_extractor = MetadataExtractor(connection_manager=connection_manager)
        self.monitoring_tools = DorisMonitoringTools(connection_manager)
        self.memory_tracker = MemoryTracker(connection_manager)
        
        # Initialize v0.5.0 advanced analytics tools
        self.data_governance_tools = DataGovernanceTools(connection_manager)
        self.data_exploration_tools = DataExplorationTools(connection_manager)
        self.data_quality_tools = DataQualityTools(connection_manager, connection_manager.config)
        self.security_analytics_tools = SecurityAnalyticsTools(connection_manager)
        self.dependency_analysis_tools = DependencyAnalysisTools(connection_manager)
        self.performance_analytics_tools = PerformanceAnalyticsTools(connection_manager)
        
        # Initialize ADBC query tools
        self.adbc_query_tools = DorisADBCQueryTools(connection_manager)
        
        logger.info("DorisToolsManager initialized with business logic processors, v0.5.0 analytics tools, and ADBC query tools")
    
    async def register_tools_with_mcp(self, mcp):
        """Register all tools to MCP server"""
        logger.info("Starting to register MCP tools")

        
        # SQL query execution tool (supports catalog federation queries)
        @mcp.tool(
            "exec_query",
            description="""[Function Description]: Execute SQL query and return result command with catalog federation support.

[Parameter Content]:

- sql (string) [Required] - SQL statement to execute. MUST use three-part naming for all table references: 'catalog_name.db_name.table_name'. For internal tables use 'internal.db_name.table_name', for external tables use 'catalog_name.db_name.table_name'

- db_name (string) [Optional] - Target database name, defaults to the current database

- catalog_name (string) [Optional] - Reference catalog name for context, defaults to current catalog

- max_rows (integer) [Optional] - Maximum number of rows to return, default 100

- timeout (integer) [Optional] - Query timeout in seconds, default 30
""",
        )
        async def exec_query_tool(
            sql: str,
            db_name: str = None,
            catalog_name: str = None,
            max_rows: int = 100,
            timeout: int = 30,
        ) -> str:
            """Execute SQL query (supports federation queries)"""
            return await self.call_tool("exec_query", {
                "sql": sql,
                "db_name": db_name,
                "catalog_name": catalog_name,
                "max_rows": max_rows,
                "timeout": timeout
            })

        # Get table schema tool
        @mcp.tool(
            "get_table_schema",
            description="""[Function Description]: Get detailed structure information of the specified table (columns, types, comments, etc.).

[Parameter Content]:

- table_name (string) [Required] - Name of the table to query

- db_name (string) [Optional] - Target database name, defaults to the current database

- catalog_name (string) [Optional] - Target catalog name for federation queries, defaults to current catalog
""",
        )
        async def get_table_schema_tool(
            table_name: str, db_name: str = None, catalog_name: str = None
        ) -> str:
            """Get table schema information"""
            return await self.call_tool("get_table_schema", {
                "table_name": table_name,
                "db_name": db_name,
                "catalog_name": catalog_name
            })

        # Get database table list tool
        @mcp.tool(
            "get_db_table_list",
            description="""[Function Description]: Get a list of all table names in the specified database.

[Parameter Content]:

- db_name (string) [Optional] - Target database name, defaults to the current database

- catalog_name (string) [Optional] - Target catalog name for federation queries, defaults to current catalog
""",
        )
        async def get_db_table_list_tool(
            db_name: str = None, catalog_name: str = None
        ) -> str:
            """Get database table list"""
            return await self.call_tool("get_db_table_list", {
                "db_name": db_name,
                "catalog_name": catalog_name
            })

        # Get database list tool
        @mcp.tool(
            "get_db_list",
            description="""[Function Description]: Get a list of all database names on the server.

[Parameter Content]:

- catalog_name (string) [Optional] - Target catalog name for federation queries, defaults to current catalog
""",
        )
        async def get_db_list_tool(catalog_name: str = None) -> str:
            """Get database list"""
            return await self.call_tool("get_db_list", {
                "catalog_name": catalog_name
            })

        # Get table comment tool
        @mcp.tool(
            "get_table_comment",
            description="""[Function Description]: Get the comment information for the specified table.

[Parameter Content]:

- table_name (string) [Required] - Name of the table to query

- db_name (string) [Optional] - Target database name, defaults to the current database

- catalog_name (string) [Optional] - Target catalog name for federation queries, defaults to current catalog
""",
        )
        async def get_table_comment_tool(
            table_name: str, db_name: str = None, catalog_name: str = None
        ) -> str:
            """Get table comment"""
            return await self.call_tool("get_table_comment", {
                "table_name": table_name,
                "db_name": db_name,
                "catalog_name": catalog_name
            })

        # Get table column comments tool
        @mcp.tool(
            "get_table_column_comments",
            description="""[Function Description]: Get comment information for all columns in the specified table.

[Parameter Content]:

- table_name (string) [Required] - Name of the table to query

- db_name (string) [Optional] - Target database name, defaults to the current database

- catalog_name (string) [Optional] - Target catalog name for federation queries, defaults to current catalog
""",
        )
        async def get_table_column_comments_tool(
            table_name: str, db_name: str = None, catalog_name: str = None
        ) -> str:
            """Get table column comments"""
            return await self.call_tool("get_table_column_comments", {
                "table_name": table_name,
                "db_name": db_name,
                "catalog_name": catalog_name
            })

        # Get table indexes tool
        @mcp.tool(
            "get_table_indexes",
            description="""[Function Description]: Get index information for the specified table.

[Parameter Content]:

- table_name (string) [Required] - Name of the table to query

- db_name (string) [Optional] - Target database name, defaults to the current database

- catalog_name (string) [Optional] - Target catalog name for federation queries, defaults to current catalog
""",
        )
        async def get_table_indexes_tool(
            table_name: str, db_name: str = None, catalog_name: str = None
        ) -> str:
            """Get table indexes"""
            return await self.call_tool("get_table_indexes", {
                "table_name": table_name,
                "db_name": db_name,
                "catalog_name": catalog_name
            })

        # Get audit logs tool
        @mcp.tool(
            "get_recent_audit_logs",
            description="""[Function Description]: Get audit log records for a recent period.

[Parameter Content]:

- days (integer) [Optional] - Number of recent days of logs to retrieve, default is 7

- limit (integer) [Optional] - Maximum number of records to return, default is 100
""",
        )
        async def get_recent_audit_logs_tool(
            days: int = 7, limit: int = 100
        ) -> str:
            """Get audit logs"""
            return await self.call_tool("get_recent_audit_logs", {
                "days": days,
                "limit": limit
            })

        # Get catalog list tool
        @mcp.tool(
            "get_catalog_list",
            description="""[Function Description]: Get a list of all catalog names on the server.

[Parameter Content]:

- random_string (string) [Required] - Unique identifier for the tool call
""",
        )
        async def get_catalog_list_tool(random_string: str) -> str:
            """Get catalog list"""
            return await self.call_tool("get_catalog_list", {
                "random_string": random_string
            })

        # Get table summary tool
        @mcp.tool(
            "get_table_summary",
                    description="""[Function Description]: Get table summary information.

[Parameter Content]:

- table_name (string) [Required] - Target table name to analyze

- db_name (string) [Optional] - Target database name, if not specified, defaults to being the same as the environment variable DB_DATABASE

- include_sample (boolean) [Optional] - Whether to include sample data, default is true

- sample_size (integer) [Optional] - sample data size, default value is 10
""",
        )
        async def get_table_summary_tool(table_name: str, db_name: str, include_sample: bool = True, sample_size: int = 10) -> str:
            """Get table summary"""
            return await self.call_tool("get_table_summary", {
                "table_name": table_name,
                "db_name": db_name,
                "include_sample": include_sample,
                "sample_size": sample_size,
            })

        # SQL Explain tool
        @mcp.tool(
            "get_sql_explain",
            description="""[Function Description]: Get SQL execution plan using EXPLAIN command based on Doris syntax.

[Parameter Content]:

- sql (string) [Required] - SQL statement to explain

- verbose (boolean) [Optional] - Whether to show verbose information, default is false

- db_name (string) [Optional] - Target database name, defaults to the current database

- catalog_name (string) [Optional] - Target catalog name for federation queries, defaults to current catalog
""",
        )
        async def get_sql_explain_tool(
            sql: str,
            verbose: bool = False,
            db_name: str = None,
            catalog_name: str = None
        ) -> str:
            """Get SQL execution plan"""
            return await self.call_tool("get_sql_explain", {
                "sql": sql,
                "verbose": verbose,
                "db_name": db_name,
                "catalog_name": catalog_name
            })

        # SQL Profile tool
        @mcp.tool(
            "get_sql_profile",
            description="""[Function Description]: Get SQL execution profile by setting trace ID and fetching profile via FE HTTP API.

[Parameter Content]:

- sql (string) [Required] - SQL statement to profile

- db_name (string) [Optional] - Target database name, defaults to the current database

- catalog_name (string) [Optional] - Target catalog name for federation queries, defaults to current catalog

- timeout (integer) [Optional] - Query timeout in seconds, default is 30
""",
        )
        async def get_sql_profile_tool(
            sql: str,
            db_name: str = None,
            catalog_name: str = None,
            timeout: int = 30
        ) -> str:
            """Get SQL execution profile"""
            return await self.call_tool("get_sql_profile", {
                "sql": sql,
                "db_name": db_name,
                "catalog_name": catalog_name,
                "timeout": timeout
            })

        # Table data size tool
        @mcp.tool(
            "get_table_data_size",
            description="""[Function Description]: Get table data size information via FE HTTP API.

[Parameter Content]:

- db_name (string) [Optional] - Database name, if not specified returns all databases

- table_name (string) [Optional] - Table name, if not specified returns all tables in the database

- single_replica (boolean) [Optional] - Whether to get single replica data size, default is false
""",
        )
        async def get_table_data_size_tool(
            db_name: str = None,
            table_name: str = None, 
            single_replica: bool = False
        ) -> str:
            """Get table data size information"""
            return await self.call_tool("get_table_data_size", {
                "db_name": db_name,
                "table_name": table_name,
                "single_replica": single_replica
            })

        # Unified Monitoring Metrics Tool (combines definitions and data)
        @mcp.tool(
            "get_monitoring_metrics",
            description="""[Function Description]: Get comprehensive Doris monitoring metrics including definitions and/or actual data from FE and BE nodes.

[Parameter Content]:

- content_type (string) [Optional] - Type of monitoring content to retrieve, default is "data"
  * "definitions": Only metric definitions and descriptions
  * "data": Only actual metric data from nodes
  * "both": Both definitions and data

- role (string) [Optional] - Node role to monitor, default is "all"
  * "fe": Only FE nodes/metrics
  * "be": Only BE nodes/metrics
  * "all": Both FE and BE nodes/metrics

- monitor_type (string) [Optional] - Type of monitoring metrics, default is "all"
  * "process": Process monitoring metrics
  * "jvm": JVM monitoring metrics (FE only)
  * "machine": Machine monitoring metrics
  * "all": All monitoring types

- priority (string) [Optional] - Metric priority level, default is "core"
  * "core": Only core essential metrics (10-12 items for production use)
  * "p0": Only P0 (highest priority) metrics
  * "all": All metrics (P0 and non-P0)

- include_raw_metrics (boolean) [Optional] - Whether to include raw detailed metrics data (can be very large), default is false
""",
        )
        async def get_monitoring_metrics_tool(
            content_type: str = "data",
            role: str = "all",
            monitor_type: str = "all",
            priority: str = "core",
            include_raw_metrics: bool = False
        ) -> str:
            """Get comprehensive monitoring metrics (definitions and/or data)"""
            return await self.call_tool("get_monitoring_metrics", {
                "content_type": content_type,
                "role": role,
                "monitor_type": monitor_type,
                "priority": priority,
                "include_raw_metrics": include_raw_metrics
            })

        # Unified Memory Statistics Tool (combines real-time and historical)
        @mcp.tool(
            "get_memory_stats",
            description="""[Function Description]: Get comprehensive memory statistics from Doris BE nodes, supporting both real-time and historical data.

[Parameter Content]:

- data_type (string) [Optional] - Type of memory data to retrieve, default is "realtime"
  * "realtime": Real-time memory statistics via Memory Tracker web interface
  * "historical": Historical memory statistics via Bvar interface
  * "both": Both real-time and historical data

- tracker_type (string) [Optional] - Type of memory trackers to retrieve (for real-time), default is "overview"
  * "overview": Overview type trackers (process memory, tracked memory summary)
  * "global": Global shared memory trackers (cache, metadata)
  * "query": Query-related memory trackers
  * "load": Load-related memory trackers  
  * "compaction": Compaction-related memory trackers
  * "all": All memory tracker types

- tracker_names (array) [Optional] - List of specific tracker names for historical data
  * Example: ["process_resident_memory", "global", "query", "load", "compaction"]

- time_range (string) [Optional] - Time range for historical data, default is "1h"
  * "1h": Last 1 hour
  * "6h": Last 6 hours
  * "24h": Last 24 hours

- include_details (boolean) [Optional] - Whether to include detailed tracker information and definitions, default is true
""",
        )
        async def get_memory_stats_tool(
            data_type: str = "realtime",
            tracker_type: str = "overview",
            tracker_names: List[str] = None,
            time_range: str = "1h",
            include_details: bool = True
        ) -> str:
            """Get comprehensive memory statistics (real-time and/or historical)"""
            return await self.call_tool("get_memory_stats", {
                "data_type": data_type,
                "tracker_type": tracker_type,
                "tracker_names": tracker_names,
                "time_range": time_range,
                "include_details": include_details
            })

        # ==================== v0.5.0 Advanced Analytics Tools ====================
        
        # 🔄 Unified Data Quality Analysis Tool (New in v0.5.0)
        @mcp.tool(
            "get_table_basic_info",
            description="""[Function Description]: Get basic information about a table including row count, column count, partitions, and size.

[Parameter Content]:

- table_name (string) [Required] - Name of the table to analyze
- catalog_name (string) [Optional] - Target catalog name
- db_name (string) [Optional] - Target database name
""",
        )
        async def get_table_basic_info_tool(
            table_name: str,
            catalog_name: str = None,
            db_name: str = None
        ) -> str:
            """Get table basic information"""
            return await self.call_tool("get_table_basic_info", {
                "table_name": table_name,
                "catalog_name": catalog_name,
                "db_name": db_name
            })

        @mcp.tool(
            "analyze_columns",
            description="""[Function Description]: Analyze completeness and distribution of specified columns in a table.

[Parameter Content]:

- table_name (string) [Required] - Name of the table to analyze
- columns (array) [Required] - List of column names to analyze
- analysis_types (array) [Optional] - Types of analysis to perform, default is ["both"]
  * "completeness": Only completeness analysis (null rates, non-null counts)
  * "distribution": Only distribution analysis (statistical patterns by data type)
  * "both": Both completeness and distribution analysis
- sample_size (integer) [Optional] - Maximum number of rows to sample, default is 100000
- catalog_name (string) [Optional] - Target catalog name
- db_name (string) [Optional] - Target database name
- detailed_response (boolean) [Optional] - Whether to return detailed response including raw data, default is false
""",
        )
        async def analyze_columns_tool(
            table_name: str,
            columns: List[str],
            analysis_types: List[str] = None,
            sample_size: int = 100000,
            catalog_name: str = None,
            db_name: str = None,
            detailed_response: bool = False
        ) -> str:
            """Analyze table columns"""
            return await self.call_tool("analyze_columns", {
                "table_name": table_name,
                "columns": columns,
                "analysis_types": analysis_types or ["both"],
                "sample_size": sample_size,
                "catalog_name": catalog_name,
                "db_name": db_name,
                "detailed_response": detailed_response
            })

        @mcp.tool(
            "analyze_table_storage",
            description="""[Function Description]: Analyze table's physical distribution and storage information.

[Parameter Content]:

- table_name (string) [Required] - Name of the table to analyze
- catalog_name (string) [Optional] - Target catalog name
- db_name (string) [Optional] - Target database name
- detailed_response (boolean) [Optional] - Whether to return detailed response including raw data, default is false
""",
        )
        async def analyze_table_storage_tool(
            table_name: str,
            catalog_name: str = None,
            db_name: str = None,
            detailed_response: bool = False
        ) -> str:
            """Analyze table storage"""
            return await self.call_tool("analyze_table_storage", {
                "table_name": table_name,
                "catalog_name": catalog_name,
                "db_name": db_name,
                "detailed_response": detailed_response
            })



        @mcp.tool(
            "trace_column_lineage",
            description="""[Function Description]: Trace data lineage for specified columns through SQL analysis and dependency mapping.

[Parameter Content]:

- target_columns (array) [Required] - List of column specifications in format "table.column" or "db.table.column"
- analysis_depth (integer) [Optional] - Maximum depth for lineage tracing, default is 3
- include_transformations (boolean) [Optional] - Whether to include transformation details, default is true
- catalog_name (string) [Optional] - Target catalog name
""",
        )
        async def trace_column_lineage_tool(
            target_columns: List[str],
            analysis_depth: int = 3,
            include_transformations: bool = True,
            catalog_name: str = None
        ) -> str:
            """Trace column data lineage"""
            return await self.call_tool("trace_column_lineage", {
                "target_columns": target_columns,
                "analysis_depth": analysis_depth,
                "include_transformations": include_transformations,
                "catalog_name": catalog_name
            })

        @mcp.tool(
            "monitor_data_freshness",
            description="""[Function Description]: Monitor data freshness and staleness patterns for specified tables.

[Parameter Content]:

- table_names (array) [Optional] - List of table names to monitor, if not specified monitors all tables
- freshness_threshold_hours (integer) [Optional] - Freshness threshold in hours, default is 24
- include_update_patterns (boolean) [Optional] - Whether to include update pattern analysis, default is true
- catalog_name (string) [Optional] - Target catalog name
- db_name (string) [Optional] - Target database name
""",
        )
        async def monitor_data_freshness_tool(
            table_names: List[str] = None,
            freshness_threshold_hours: int = 24,
            include_update_patterns: bool = True,
            catalog_name: str = None,
            db_name: str = None
        ) -> str:
            """Monitor data freshness and staleness"""
            return await self.call_tool("monitor_data_freshness", {
                "table_names": table_names,
                "freshness_threshold_hours": freshness_threshold_hours,
                "include_update_patterns": include_update_patterns,
                "catalog_name": catalog_name,
                "db_name": db_name
            })



        # Security Analytics Tools
        @mcp.tool(
            "analyze_data_access_patterns",
            description="""[Function Description]: Analyze user data access patterns, security anomalies, and access behavior.

[Parameter Content]:

- days (integer) [Optional] - Number of days to analyze, default is 7
- include_system_users (boolean) [Optional] - Whether to include system users in analysis, default is false
- min_query_threshold (integer) [Optional] - Minimum queries for user inclusion, default is 5
""",
        )
        async def analyze_data_access_patterns_tool(
            days: int = 7,
            include_system_users: bool = False,
            min_query_threshold: int = 5
        ) -> str:
            """Analyze data access patterns and security insights"""
            return await self.call_tool("analyze_data_access_patterns", {
                "days": days,
                "include_system_users": include_system_users,
                "min_query_threshold": min_query_threshold
            })

        # Dependency Analysis Tools
        @mcp.tool(
            "analyze_data_flow_dependencies",
            description="""[Function Description]: Analyze data flow dependencies and impact relationships between tables.

[Parameter Content]:

- target_table (string) [Optional] - Specific table to analyze, if not specified analyzes all tables
- analysis_depth (integer) [Optional] - Maximum depth for dependency traversal, default is 3
- include_views (boolean) [Optional] - Whether to include views in analysis, default is true
- catalog_name (string) [Optional] - Target catalog name
- db_name (string) [Optional] - Target database name
""",
        )
        async def analyze_data_flow_dependencies_tool(
            target_table: str = None,
            analysis_depth: int = 3,
            include_views: bool = True,
            catalog_name: str = None,
            db_name: str = None
        ) -> str:
            """Analyze data flow dependencies and impact"""
            return await self.call_tool("analyze_data_flow_dependencies", {
                "target_table": target_table,
                "analysis_depth": analysis_depth,
                "include_views": include_views,
                "catalog_name": catalog_name,
                "db_name": db_name
            })

        # Performance Analytics Tools
        @mcp.tool(
            "analyze_slow_queries_topn",
            description="""[Function Description]: Analyze top N slowest queries and identify performance patterns and issues.

[Parameter Content]:

- days (integer) [Optional] - Number of days to analyze, default is 7
- top_n (integer) [Optional] - Number of top slow queries to return, default is 20
- min_execution_time_ms (integer) [Optional] - Minimum execution time threshold in milliseconds, default is 1000
- include_patterns (boolean) [Optional] - Whether to include query pattern analysis, default is true
""",
        )
        async def analyze_slow_queries_topn_tool(
            days: int = 7,
            top_n: int = 20,
            min_execution_time_ms: int = 1000,
            include_patterns: bool = True
        ) -> str:
            """Analyze top N slow queries and performance patterns"""
            return await self.call_tool("analyze_slow_queries_topn", {
                "days": days,
                "top_n": top_n,
                "min_execution_time_ms": min_execution_time_ms,
                "include_patterns": include_patterns
            })

        @mcp.tool(
            "analyze_resource_growth_curves",
            description="""[Function Description]: Analyze resource growth patterns and trends for capacity planning.

[Parameter Content]:

- days (integer) [Optional] - Number of days to analyze, default is 30
- resource_types (array) [Optional] - Types of resources to analyze, default is ["storage", "query_volume", "user_activity"]
- include_predictions (boolean) [Optional] - Whether to include growth predictions, default is false
- detailed_response (boolean) [Optional] - Whether to return detailed data including daily breakdowns, default is false
""",
        )
        async def analyze_resource_growth_curves_tool(
            days: int = 30,
            resource_types: List[str] = None,
            include_predictions: bool = False,
            detailed_response: bool = False
        ) -> str:
            """Analyze resource growth patterns and capacity planning"""
            return await self.call_tool("analyze_resource_growth_curves", {
                "days": days,
                "resource_types": resource_types or ["storage", "query_volume", "user_activity"],
                "include_predictions": include_predictions,
                "detailed_response": detailed_response
            })

        # ==================== ADBC Query Tools ====================
        
        # ADBC Query Execution Tool
        @mcp.tool(
            "exec_adbc_query",
            description=f"""[Function Description]: Execute SQL query using ADBC (Arrow Flight SQL) protocol for high-performance data transfer.

[Parameter Content]:

- sql (string) [Required] - SQL statement to execute
- max_rows (integer) [Optional] - Maximum number of rows to return, default is {self.connection_manager.config.adbc.default_max_rows}
- timeout (integer) [Optional] - Query timeout in seconds, default is {self.connection_manager.config.adbc.default_timeout}
- return_format (string) [Optional] - Format for returned data, default is "{self.connection_manager.config.adbc.default_return_format}"
  * "arrow": Return Arrow format with metadata
  * "pandas": Return Pandas DataFrame format 
  * "dict": Return dictionary format

[Prerequisites]:
- Environment variables FE_ARROW_FLIGHT_SQL_PORT and BE_ARROW_FLIGHT_SQL_PORT must be configured
- Required Python packages: adbc_driver_manager, adbc_driver_flightsql
- Arrow Flight SQL services must be running on FE and BE nodes
""",
        )
        async def exec_adbc_query_tool(
            sql: str,
            max_rows: int = None,
            timeout: int = None,
            return_format: str = None
        ) -> str:
            """Execute SQL query using ADBC (Arrow Flight SQL) protocol"""
            return await self.call_tool("exec_adbc_query", {
                "sql": sql,
                "max_rows": max_rows,
                "timeout": timeout,
                "return_format": return_format
            })

        # ADBC Connection Information Tool
        @mcp.tool(
            "get_adbc_connection_info",
            description="""[Function Description]: Get ADBC (Arrow Flight SQL) connection information and status.

[Parameter Content]:

No parameters required. Returns connection status, configuration, and diagnostic information.
""",
        )
        async def get_adbc_connection_info_tool() -> str:
            """Get ADBC connection information and status"""
            return await self.call_tool("get_adbc_connection_info", {})

        logger.info("Successfully registered 25 tools to MCP server (14 basic + 9 advanced analytics + 2 ADBC tools)")

    async def list_tools(self) -> List[Tool]:
        """List all available query tools (for stdio mode)"""
        # Get ADBC configuration defaults
        adbc_config = self.connection_manager.config.adbc
        
        tools = [
            Tool(
                name="exec_query",
                description="""[Function Description]: Execute SQL query and return result command with catalog federation support.

[Parameter Content]:

- sql (string) [Required] - SQL statement to execute. MUST use three-part naming for all table references: 'catalog_name.db_name.table_name'. For internal tables use 'internal.db_name.table_name', for external tables use 'catalog_name.db_name.table_name'

- db_name (string) [Optional] - Target database name, defaults to the current database

- catalog_name (string) [Optional] - Reference catalog name for context, defaults to current catalog

- max_rows (integer) [Optional] - Maximum number of rows to return, default 100

- timeout (integer) [Optional] - Query timeout in seconds, default 30
""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "sql": {"type": "string", "description": "SQL statement to execute, must use three-part naming"},
                        "db_name": {"type": "string", "description": "Target database name"},
                        "catalog_name": {"type": "string", "description": "Catalog name"},
                        "max_rows": {"type": "integer", "description": "Maximum number of rows to return", "default": 100},
                        "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 30},
                    },
                    "required": ["sql"],
                },
            ),
            Tool(
                name="get_table_schema",
                description="""[Function Description]: Get detailed structure information of the specified table (columns, types, comments, etc.).

[Parameter Content]:

- table_name (string) [Required] - Name of the table to query

- db_name (string) [Optional] - Target database name, defaults to the current database

- catalog_name (string) [Optional] - Target catalog name for federation queries, defaults to current catalog
""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "table_name": {"type": "string", "description": "Table name"},
                        "db_name": {"type": "string", "description": "Database name"},
                        "catalog_name": {"type": "string", "description": "Catalog name"},
                    },
                    "required": ["table_name"],
                },
            ),
            Tool(
                name="get_db_table_list",
                description="""[Function Description]: Get a list of all table names in the specified database.

[Parameter Content]:

- db_name (string) [Optional] - Target database name, defaults to the current database

- catalog_name (string) [Optional] - Target catalog name for federation queries, defaults to current catalog
""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "db_name": {"type": "string", "description": "Database name"},
                        "catalog_name": {"type": "string", "description": "Catalog name"},
                    },
                },
            ),
            Tool(
                name="get_db_list",
                description="""[Function Description]: Get a list of all database names on the server.

[Parameter Content]:

- catalog_name (string) [Optional] - Target catalog name for federation queries, defaults to current catalog
""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "catalog_name": {"type": "string", "description": "Catalog name"},
                    },
                },
            ),
            Tool(
                name="get_table_comment",
                description="""[Function Description]: Get the comment information for the specified table.

[Parameter Content]:

- table_name (string) [Required] - Name of the table to query

- db_name (string) [Optional] - Target database name, defaults to the current database

- catalog_name (string) [Optional] - Target catalog name for federation queries, defaults to current catalog
""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "table_name": {"type": "string", "description": "Table name"},
                        "db_name": {"type": "string", "description": "Database name"},
                        "catalog_name": {"type": "string", "description": "Catalog name"},
                    },
                    "required": ["table_name"],
                },
            ),
            Tool(
                name="get_table_column_comments",
                description="""[Function Description]: Get comment information for all columns in the specified table.

[Parameter Content]:

- table_name (string) [Required] - Name of the table to query

- db_name (string) [Optional] - Target database name, defaults to the current database

- catalog_name (string) [Optional] - Target catalog name for federation queries, defaults to current catalog
""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "table_name": {"type": "string", "description": "Table name"},
                        "db_name": {"type": "string", "description": "Database name"},
                        "catalog_name": {"type": "string", "description": "Catalog name"},
                    },
                    "required": ["table_name"],
                },
            ),
            Tool(
                name="get_table_indexes",
                description="""[Function Description]: Get index information for the specified table.

[Parameter Content]:

- table_name (string) [Required] - Name of the table to query

- db_name (string) [Optional] - Target database name, defaults to the current database

- catalog_name (string) [Optional] - Target catalog name for federation queries, defaults to current catalog
""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "table_name": {"type": "string", "description": "Table name"},
                        "db_name": {"type": "string", "description": "Database name"},
                        "catalog_name": {"type": "string", "description": "Catalog name"},
                    },
                    "required": ["table_name"],
                },
            ),
            Tool(
                name="get_recent_audit_logs",
                description="""[Function Description]: Get audit log records for a recent period.

[Parameter Content]:

- days (integer) [Optional] - Number of recent days of logs to retrieve, default is 7

- limit (integer) [Optional] - Maximum number of records to return, default is 100
""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "days": {"type": "integer", "description": "Number of recent days", "default": 7},
                        "limit": {"type": "integer", "description": "Maximum number of records", "default": 100},
                    },
                },
            ),
            Tool(
                name="get_catalog_list",
                description="""[Function Description]: Get a list of all catalog names on the server.

[Parameter Content]:

- random_string (string) [Required] - Unique identifier for the tool call
""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "random_string": {"type": "string", "description": "Unique identifier"},
                    },
                    "required": ["random_string"],
                },
            ),
            Tool(
                name="get_table_summary",
                description="""[Function Description]: Get table summary information.

[Parameter Content]:

- table_name (string) [Required] - Target table name to analyze

- db_name (string) [Optional] - Target database name, if not specified, defaults to being the same as the environment variable DB_DATABASE

- include_sample (boolean) [Optional] - Whether to include sample data, default is true

- sample_size (integer) [Optional] - sample data size, default value is 10
""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "table_name": {"type": "string", "description": "Target table name to analyze"},
                        "db_name": {"type": "string", "description": "Target database name"},
                        "include_sample": {"type": "boolean", "description": "Whether to include sample data", "default": True},
                        "sample_size": {"type": "integer", "description": "sample data size", "default": 10},
                    },
                    "required": ["table_name", "db_name"],
                },
            ),
            Tool(
                name="get_sql_explain",
                description="""[Function Description]: Get SQL execution plan using EXPLAIN command based on Doris syntax.

[Parameter Content]:

- sql (string) [Required] - SQL statement to explain

- verbose (boolean) [Optional] - Whether to show verbose information, default is false

- db_name (string) [Optional] - Target database name, defaults to the current database

- catalog_name (string) [Optional] - Target catalog name for federation queries, defaults to current catalog
""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "sql": {"type": "string", "description": "SQL statement to explain"},
                        "verbose": {"type": "boolean", "description": "Whether to show verbose information", "default": False},
                        "db_name": {"type": "string", "description": "Database name"},
                        "catalog_name": {"type": "string", "description": "Catalog name"},
                    },
                    "required": ["sql"],
                },
            ),
            Tool(
                name="get_sql_profile",
                description="""[Function Description]: Get SQL execution profile by setting trace ID and fetching profile via FE HTTP API.

[Parameter Content]:

- sql (string) [Required] - SQL statement to profile

- db_name (string) [Optional] - Target database name, defaults to the current database

- catalog_name (string) [Optional] - Target catalog name for federation queries, defaults to current catalog

- timeout (integer) [Optional] - Query timeout in seconds, default is 30
""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "sql": {"type": "string", "description": "SQL statement to profile"},
                        "db_name": {"type": "string", "description": "Database name"},
                        "catalog_name": {"type": "string", "description": "Catalog name"},
                        "timeout": {"type": "integer", "description": "Query timeout in seconds", "default": 30},
                    },
                    "required": ["sql"],
                },
            ),
            Tool(
                name="get_table_data_size",
                description="""[Function Description]: Get table data size information via FE HTTP API.

[Parameter Content]:

- db_name (string) [Optional] - Database name, if not specified returns all databases

- table_name (string) [Optional] - Table name, if not specified returns all tables in the database

- single_replica (boolean) [Optional] - Whether to get single replica data size, default is false
""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "db_name": {"type": "string", "description": "Database name"},
                        "table_name": {"type": "string", "description": "Table name"},
                        "single_replica": {"type": "boolean", "description": "Whether to get single replica data size", "default": False},
                    },
                },
            ),
            Tool(
                name="get_monitoring_metrics",
                description="""[Function Description]: Get comprehensive Doris monitoring metrics including definitions and/or actual data from FE and BE nodes.

[Parameter Content]:

- content_type (string) [Optional] - Type of monitoring content to retrieve, default is "data"
  * "definitions": Only metric definitions and descriptions
  * "data": Only actual metric data from nodes
  * "both": Both definitions and data

- role (string) [Optional] - Node role to monitor, default is "all"
  * "fe": Only FE nodes/metrics
  * "be": Only BE nodes/metrics
  * "all": Both FE and BE nodes/metrics

- monitor_type (string) [Optional] - Type of monitoring metrics, default is "all"
  * "process": Process monitoring metrics
  * "jvm": JVM monitoring metrics (FE only)
  * "machine": Machine monitoring metrics
  * "all": All monitoring types

- priority (string) [Optional] - Metric priority level, default is "core"
  * "core": Only core essential metrics (10-12 items for production use)
  * "p0": Only P0 (highest priority) metrics
  * "all": All metrics (P0 and non-P0)

- include_raw_metrics (boolean) [Optional] - Whether to include raw detailed metrics data (can be very large), default is false
""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "content_type": {"type": "string", "enum": ["definitions", "data", "both"], "description": "Type of monitoring content to retrieve", "default": "data"},
                        "role": {"type": "string", "enum": ["fe", "be", "all"], "description": "Node role to monitor", "default": "all"},
                        "monitor_type": {"type": "string", "enum": ["process", "jvm", "machine", "all"], "description": "Type of monitoring metrics", "default": "all"},
                        "priority": {"type": "string", "enum": ["core", "p0", "all"], "description": "Metric priority level", "default": "core"},
                        "include_raw_metrics": {"type": "boolean", "description": "Whether to include raw detailed metrics data (can be very large)", "default": False},
                    },
                },
            ),
            Tool(
                name="get_memory_stats",
                description="""[Function Description]: Get comprehensive memory statistics from Doris BE nodes, supporting both real-time and historical data.

[Parameter Content]:

- data_type (string) [Optional] - Type of memory data to retrieve, default is "realtime"
  * "realtime": Real-time memory statistics via Memory Tracker web interface
  * "historical": Historical memory statistics via Bvar interface
  * "both": Both real-time and historical data

- tracker_type (string) [Optional] - Type of memory trackers to retrieve (for real-time), default is "overview"
  * "overview": Overview type trackers (process memory, tracked memory summary)
  * "global": Global shared memory trackers (cache, metadata)
  * "query": Query-related memory trackers
  * "load": Load-related memory trackers  
  * "compaction": Compaction-related memory trackers
  * "all": All memory tracker types

- tracker_names (array) [Optional] - List of specific tracker names for historical data
  * Example: ["process_resident_memory", "global", "query", "load", "compaction"]

- time_range (string) [Optional] - Time range for historical data, default is "1h"
  * "1h": Last 1 hour
  * "6h": Last 6 hours
  * "24h": Last 24 hours

- include_details (boolean) [Optional] - Whether to include detailed tracker information and definitions, default is true
""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "data_type": {"type": "string", "enum": ["realtime", "historical", "both"], "description": "Type of memory data to retrieve", "default": "realtime"},
                        "tracker_type": {"type": "string", "enum": ["overview", "global", "query", "load", "compaction", "all"], "description": "Type of memory trackers to retrieve (for real-time)", "default": "overview"},
                        "tracker_names": {"type": "array", "items": {"type": "string"}, "description": "List of specific tracker names for historical data"},
                        "time_range": {"type": "string", "enum": ["1h", "6h", "24h"], "description": "Time range for historical data", "default": "1h"},
                        "include_details": {"type": "boolean", "description": "Whether to include detailed tracker information and definitions", "default": True},
                    },
                },
            ),
            # ==================== v0.5.0 Advanced Analytics Tools ====================
            # Atomic Data Quality Analysis Tools
            Tool(
                name="get_table_basic_info",
                description="""[Function Description]: Get basic information about a table including row count, column count, partitions, and size.

[Parameter Content]:

- table_name (string) [Required] - Name of the table to analyze
- catalog_name (string) [Optional] - Target catalog name
- db_name (string) [Optional] - Target database name
""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "table_name": {"type": "string", "description": "Name of the table to analyze"},
                        "catalog_name": {"type": "string", "description": "Target catalog name"},
                        "db_name": {"type": "string", "description": "Target database name"},
                    },
                    "required": ["table_name"],
                },
            ),
            Tool(
                name="analyze_columns",
                description="""[Function Description]: Analyze completeness and distribution of specified columns in a table.

[Parameter Content]:

- table_name (string) [Required] - Name of the table to analyze
- columns (array) [Required] - List of column names to analyze
- analysis_types (array) [Optional] - Types of analysis to perform, default is ["both"]
  * "completeness": Only completeness analysis (null rates, non-null counts)
  * "distribution": Only distribution analysis (statistical patterns by data type)
  * "both": Both completeness and distribution analysis
- sample_size (integer) [Optional] - Maximum number of rows to sample, default is 100000
- catalog_name (string) [Optional] - Target catalog name
- db_name (string) [Optional] - Target database name
- detailed_response (boolean) [Optional] - Whether to return detailed response including raw data, default is false
""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "table_name": {"type": "string", "description": "Name of the table to analyze"},
                        "columns": {"type": "array", "items": {"type": "string"}, "description": "List of column names to analyze"},
                        "analysis_types": {"type": "array", "items": {"type": "string", "enum": ["completeness", "distribution", "both"]}, "description": "Types of analysis to perform", "default": ["both"]},
                        "sample_size": {"type": "integer", "description": "Maximum number of rows to sample", "default": 100000},
                        "catalog_name": {"type": "string", "description": "Target catalog name"},
                        "db_name": {"type": "string", "description": "Target database name"},
                        "detailed_response": {"type": "boolean", "description": "Whether to return detailed response including raw data", "default": False},
                    },
                    "required": ["table_name", "columns"],
                },
            ),
            Tool(
                name="analyze_table_storage",
                description="""[Function Description]: Analyze table's physical distribution and storage information.

[Parameter Content]:

- table_name (string) [Required] - Name of the table to analyze
- catalog_name (string) [Optional] - Target catalog name
- db_name (string) [Optional] - Target database name
- detailed_response (boolean) [Optional] - Whether to return detailed response including raw data, default is false
""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "table_name": {"type": "string", "description": "Name of the table to analyze"},
                        "catalog_name": {"type": "string", "description": "Target catalog name"},
                        "db_name": {"type": "string", "description": "Target database name"},
                        "detailed_response": {"type": "boolean", "description": "Whether to return detailed response including raw data", "default": False},
                    },
                    "required": ["table_name"],
                },
            ),
            Tool(
                name="trace_column_lineage",
                description="""[Function Description]: Trace data lineage for specified columns through SQL analysis and dependency mapping.

[Parameter Content]:

- target_columns (array) [Required] - List of column specifications in format "table.column" or "db.table.column"
- analysis_depth (integer) [Optional] - Maximum depth for lineage tracing, default is 3
- include_transformations (boolean) [Optional] - Whether to include transformation details, default is true
- catalog_name (string) [Optional] - Target catalog name
""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "target_columns": {"type": "array", "items": {"type": "string"}, "description": "List of column specifications"},
                        "analysis_depth": {"type": "integer", "description": "Maximum depth for lineage tracing", "default": 3},
                        "include_transformations": {"type": "boolean", "description": "Whether to include transformation details", "default": True},
                        "catalog_name": {"type": "string", "description": "Target catalog name"},
                    },
                    "required": ["target_columns"],
                },
            ),
            Tool(
                name="monitor_data_freshness",
                description="""[Function Description]: Monitor data freshness and staleness patterns for specified tables.

[Parameter Content]:

- table_names (array) [Optional] - List of table names to monitor, if not specified monitors all tables
- freshness_threshold_hours (integer) [Optional] - Freshness threshold in hours, default is 24
- include_update_patterns (boolean) [Optional] - Whether to include update pattern analysis, default is true
- catalog_name (string) [Optional] - Target catalog name
- db_name (string) [Optional] - Target database name
""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "table_names": {"type": "array", "items": {"type": "string"}, "description": "List of table names to monitor"},
                        "freshness_threshold_hours": {"type": "integer", "description": "Freshness threshold in hours", "default": 24},
                        "include_update_patterns": {"type": "boolean", "description": "Whether to include update pattern analysis", "default": True},
                        "catalog_name": {"type": "string", "description": "Target catalog name"},
                        "db_name": {"type": "string", "description": "Target database name"},
                    },
                },
            ),

            Tool(
                name="analyze_data_access_patterns",
                description="""[Function Description]: Analyze user data access patterns, security anomalies, and access behavior.

[Parameter Content]:

- days (integer) [Optional] - Number of days to analyze, default is 7
- include_system_users (boolean) [Optional] - Whether to include system users in analysis, default is false
- min_query_threshold (integer) [Optional] - Minimum queries for user inclusion, default is 5
""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "days": {"type": "integer", "description": "Number of days to analyze", "default": 7},
                        "include_system_users": {"type": "boolean", "description": "Whether to include system users", "default": False},
                        "min_query_threshold": {"type": "integer", "description": "Minimum queries for user inclusion", "default": 5},
                    },
                },
            ),
            Tool(
                name="analyze_data_flow_dependencies",
                description="""[Function Description]: Analyze data flow dependencies and impact relationships between tables.

[Parameter Content]:

- target_table (string) [Optional] - Specific table to analyze, if not specified analyzes all tables
- analysis_depth (integer) [Optional] - Maximum depth for dependency traversal, default is 3
- include_views (boolean) [Optional] - Whether to include views in analysis, default is true
- catalog_name (string) [Optional] - Target catalog name
- db_name (string) [Optional] - Target database name
""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "target_table": {"type": "string", "description": "Specific table to analyze"},
                        "analysis_depth": {"type": "integer", "description": "Maximum depth for dependency traversal", "default": 3},
                        "include_views": {"type": "boolean", "description": "Whether to include views in analysis", "default": True},
                        "catalog_name": {"type": "string", "description": "Target catalog name"},
                        "db_name": {"type": "string", "description": "Target database name"},
                    },
                },
            ),
            Tool(
                name="analyze_slow_queries_topn",
                description="""[Function Description]: Analyze top N slowest queries and identify performance patterns and issues.

[Parameter Content]:

- days (integer) [Optional] - Number of days to analyze, default is 7
- top_n (integer) [Optional] - Number of top slow queries to return, default is 20
- min_execution_time_ms (integer) [Optional] - Minimum execution time threshold in milliseconds, default is 1000
- include_patterns (boolean) [Optional] - Whether to include query pattern analysis, default is true
""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "days": {"type": "integer", "description": "Number of days to analyze", "default": 7},
                        "top_n": {"type": "integer", "description": "Number of top slow queries to return", "default": 20},
                        "min_execution_time_ms": {"type": "integer", "description": "Minimum execution time threshold in milliseconds", "default": 1000},
                        "include_patterns": {"type": "boolean", "description": "Whether to include query pattern analysis", "default": True},
                    },
                },
            ),
            Tool(
                name="analyze_resource_growth_curves",
                description="""[Function Description]: Analyze resource growth patterns and trends for capacity planning.

[Parameter Content]:

- days (integer) [Optional] - Number of days to analyze, default is 30
- resource_types (array) [Optional] - Types of resources to analyze, default is ["storage", "query_volume", "user_activity"]
- include_predictions (boolean) [Optional] - Whether to include growth predictions, default is false
""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "days": {"type": "integer", "description": "Number of days to analyze", "default": 30},
                        "resource_types": {"type": "array", "items": {"type": "string"}, "description": "Types of resources to analyze"},
                        "include_predictions": {"type": "boolean", "description": "Whether to include growth predictions", "default": False},
                        "detailed_response": {"type": "boolean", "description": "Whether to return detailed data including daily breakdowns", "default": False},
                    },
                },
            ),
            # ==================== ADBC Query Tools ====================
            Tool(
                name="exec_adbc_query",
                description=f"""[Function Description]: Execute SQL query using ADBC (Arrow Flight SQL) protocol for high-performance data transfer.

[Parameter Content]:

- sql (string) [Required] - SQL statement to execute
- max_rows (integer) [Optional] - Maximum number of rows to return, default is {adbc_config.default_max_rows}
- timeout (integer) [Optional] - Query timeout in seconds, default is {adbc_config.default_timeout}
- return_format (string) [Optional] - Format for returned data, default is "{adbc_config.default_return_format}"
  * "arrow": Return Arrow format with metadata
  * "pandas": Return Pandas DataFrame format 
  * "dict": Return dictionary format

[Prerequisites]:
- Environment variables FE_ARROW_FLIGHT_SQL_PORT and BE_ARROW_FLIGHT_SQL_PORT must be configured
- Required Python packages: adbc_driver_manager, adbc_driver_flightsql
- Arrow Flight SQL services must be running on FE and BE nodes
""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "sql": {"type": "string", "description": "SQL statement to execute"},
                        "max_rows": {"type": "integer", "description": "Maximum number of rows to return", "default": adbc_config.default_max_rows},
                        "timeout": {"type": "integer", "description": "Query timeout in seconds", "default": adbc_config.default_timeout},
                        "return_format": {"type": "string", "enum": ["arrow", "pandas", "dict"], "description": "Format for returned data", "default": adbc_config.default_return_format},
                    },
                    "required": ["sql"],
                },
            ),
            Tool(
                name="get_adbc_connection_info",
                description="""[Function Description]: Get ADBC (Arrow Flight SQL) connection information and status.

[Parameter Content]:

No parameters required. Returns connection status, configuration, and diagnostic information.
""",
                inputSchema={
                    "type": "object",
                    "properties": {},
                },
            ),
        ]
        
        return tools
        
    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> str:
        """
        Call the specified query tool (tool routing and scheduling center)
        """
        try:
            start_time = time.time()
            
            # Tool routing - dispatch requests to corresponding business logic processors
            if name == "exec_query":
                result = await self._exec_query_tool(arguments)
            elif name == "get_table_schema":
                result = await self._get_table_schema_tool(arguments)
            elif name == "get_db_table_list":
                result = await self._get_db_table_list_tool(arguments)
            elif name == "get_db_list":
                result = await self._get_db_list_tool(arguments)
            elif name == "get_table_comment":
                result = await self._get_table_comment_tool(arguments)
            elif name == "get_table_column_comments":
                result = await self._get_table_column_comments_tool(arguments)
            elif name == "get_table_indexes":
                result = await self._get_table_indexes_tool(arguments)
            elif name == "get_recent_audit_logs":
                result = await self._get_recent_audit_logs_tool(arguments)
            elif name == "get_catalog_list":
                result = await self._get_catalog_list_tool(arguments)
            elif name == "get_table_summary":
                result = await self._get_table_summary_tool(arguments)
            elif name == "get_sql_explain":
                result = await self._get_sql_explain_tool(arguments)
            elif name == "get_sql_profile":
                result = await self._get_sql_profile_tool(arguments)
            elif name == "get_table_data_size":
                result = await self._get_table_data_size_tool(arguments)
            elif name == "get_monitoring_metrics":
                result = await self._get_monitoring_metrics_tool(arguments)
            elif name == "get_memory_stats":
                result = await self._get_memory_stats_tool(arguments)
            # Legacy support for old tool names (deprecated)
            elif name == "get_monitoring_metrics_info":
                arguments["content_type"] = "definitions"
                result = await self._get_monitoring_metrics_tool(arguments)
            elif name == "get_monitoring_metrics_data":
                arguments["content_type"] = "data"
                result = await self._get_monitoring_metrics_tool(arguments)
            elif name == "get_realtime_memory_stats":
                arguments["data_type"] = "realtime"
                result = await self._get_memory_stats_tool(arguments)
            elif name == "get_historical_memory_stats":
                arguments["data_type"] = "historical"
                result = await self._get_memory_stats_tool(arguments)
            # v0.5.0 Advanced Analytics Tools - Atomic Data Quality Tools
            elif name == "get_table_basic_info":
                result = await self._get_table_basic_info_tool(arguments)
            elif name == "analyze_columns":
                result = await self._analyze_columns_tool(arguments)
            elif name == "analyze_table_storage":
                result = await self._analyze_table_storage_tool(arguments)
            elif name == "trace_column_lineage":
                result = await self._trace_column_lineage_tool(arguments)
            elif name == "monitor_data_freshness":
                result = await self._monitor_data_freshness_tool(arguments)
            elif name == "analyze_data_access_patterns":
                result = await self._analyze_data_access_patterns_tool(arguments)
            elif name == "analyze_data_flow_dependencies":
                result = await self._analyze_data_flow_dependencies_tool(arguments)
            elif name == "analyze_slow_queries_topn":
                result = await self._analyze_slow_queries_topn_tool(arguments)
            elif name == "analyze_resource_growth_curves":
                result = await self._analyze_resource_growth_curves_tool(arguments)
            # ADBC Query Tools
            elif name == "exec_adbc_query":
                result = await self._exec_adbc_query_tool(arguments)
            elif name == "get_adbc_connection_info":
                result = await self._get_adbc_connection_info_tool(arguments)
            else:
                raise ValueError(f"Unknown tool: {name}")
            
            execution_time = time.time() - start_time
            
            # Add execution information
            if isinstance(result, dict):
                result["_execution_info"] = {
                    "tool_name": name,
                    "execution_time": round(execution_time, 3),
                    "timestamp": datetime.now().isoformat(),
                }
            
            return json.dumps(result, ensure_ascii=False, indent=2)
            
        except Exception as e:
            logger.error(f"Tool call failed {name}: {str(e)}")
            error_result = {
                "error": str(e),
                "tool_name": name,
                "arguments": arguments,
                "timestamp": datetime.now().isoformat(),
            }
            return json.dumps(error_result, ensure_ascii=False, indent=2)
    
    
    async def _exec_query_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """SQL query execution tool routing (supports federation queries)"""
        sql = arguments.get("sql")
        db_name = arguments.get("db_name")
        catalog_name = arguments.get("catalog_name")
        max_rows = arguments.get("max_rows", 100)
        timeout = arguments.get("timeout", 30)
        
        # Delegate to metadata extractor for processing
        return await self.metadata_extractor.exec_query_for_mcp(
            sql, db_name, catalog_name, max_rows, timeout
        )
    
    async def _get_table_schema_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get table schema tool routing"""
        table_name = arguments.get("table_name")
        db_name = arguments.get("db_name")
        catalog_name = arguments.get("catalog_name")
        
        # Delegate to metadata extractor for processing
        return await self.metadata_extractor.get_table_schema_for_mcp(
            table_name, db_name, catalog_name
        )
    
    async def _get_db_table_list_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get database table list tool routing"""
        db_name = arguments.get("db_name")
        catalog_name = arguments.get("catalog_name")
        
        # Delegate to metadata extractor for processing
        return await self.metadata_extractor.get_db_table_list_for_mcp(db_name, catalog_name)
    
    async def _get_db_list_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get database list tool routing"""
        catalog_name = arguments.get("catalog_name")
        
        # Delegate to metadata extractor for processing
        return await self.metadata_extractor.get_db_list_for_mcp(catalog_name)
    
    async def _get_table_comment_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get table comment tool routing"""
        table_name = arguments.get("table_name")
        db_name = arguments.get("db_name")
        catalog_name = arguments.get("catalog_name")
        
        # Delegate to metadata extractor for processing
        return await self.metadata_extractor.get_table_comment_for_mcp(
            table_name, db_name, catalog_name
        )
    
    async def _get_table_column_comments_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get table column comments tool routing"""
        table_name = arguments.get("table_name")
        db_name = arguments.get("db_name")
        catalog_name = arguments.get("catalog_name")
        
        # Delegate to metadata extractor for processing
        return await self.metadata_extractor.get_table_column_comments_for_mcp(
            table_name, db_name, catalog_name
        )
    
    async def _get_table_indexes_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get table indexes tool routing"""
        table_name = arguments.get("table_name")
        db_name = arguments.get("db_name")
        catalog_name = arguments.get("catalog_name")
        
        # Delegate to metadata extractor for processing
        return await self.metadata_extractor.get_table_indexes_for_mcp(
            table_name, db_name, catalog_name
        )
    
    async def _get_recent_audit_logs_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get audit logs tool routing"""
        days = arguments.get("days", 7)
        limit = arguments.get("limit", 100)
        
        # Delegate to metadata extractor for processing
        return await self.metadata_extractor.get_recent_audit_logs_for_mcp(days, limit)
    
    async def _get_catalog_list_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get catalog list tool routing"""
        # random_string parameter is required in the source project, but not actually used in business logic
        # Here we ignore it and directly call business logic
        
        # Delegate to metadata extractor for processing
        return await self.metadata_extractor.get_catalog_list_for_mcp() 

    async def _get_table_summary_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Table summary tool routing"""
        table_name = arguments.get("table_name")
        db_name = arguments.get("db_name")
        include_sample = arguments.get("include_sample", True)
        sample_size = arguments.get("sample_size", 10)

        # Delegate to Table analzyer for processing
        return await self.table_analyzer.get_table_summary(table_name, db_name, include_sample, sample_size)
    
    async def _get_sql_explain_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """SQL Explain tool routing"""
        sql = arguments.get("sql")
        verbose = arguments.get("verbose", False)
        db_name = arguments.get("db_name")
        catalog_name = arguments.get("catalog_name")
        
        # Delegate to SQL analyzer for processing
        return await self.sql_analyzer.get_sql_explain(
            sql, verbose, db_name, catalog_name
        )
    
    async def _get_sql_profile_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """SQL Profile tool routing"""
        sql = arguments.get("sql")
        db_name = arguments.get("db_name")
        catalog_name = arguments.get("catalog_name")
        timeout = arguments.get("timeout", 30)
        
        # Delegate to SQL analyzer for processing
        return await self.sql_analyzer.get_sql_profile(
            sql, db_name, catalog_name, timeout
        )

    async def _get_table_data_size_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Table data size tool routing"""
        db_name = arguments.get("db_name")
        table_name = arguments.get("table_name")
        single_replica = arguments.get("single_replica", False)
        
        # Delegate to SQL analyzer for processing
        return await self.sql_analyzer.get_table_data_size(
            db_name, table_name, single_replica
        )

    async def _get_monitoring_metrics_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Unified monitoring metrics tool routing"""
        content_type = arguments.get("content_type", "data")
        role = arguments.get("role", "all")
        monitor_type = arguments.get("monitor_type", "all")
        priority = arguments.get("priority", "core")
        include_raw_metrics = arguments.get("include_raw_metrics", False)
        
        if content_type == "definitions":
            # Only get definitions
            return await self.monitoring_tools.get_monitoring_metrics(
                role, monitor_type, priority, info_only=True, format_type="prometheus"
            )
        elif content_type == "data":
            # Only get data
            return await self.monitoring_tools.get_monitoring_metrics(
                role, monitor_type, priority, info_only=False, format_type="prometheus", include_raw_metrics=include_raw_metrics
            )
        elif content_type == "both":
            # Get both definitions and data
            definitions = await self.monitoring_tools.get_monitoring_metrics(
                role, monitor_type, priority, info_only=True, format_type="prometheus"
            )
            data = await self.monitoring_tools.get_monitoring_metrics(
                role, monitor_type, priority, info_only=False, format_type="prometheus", include_raw_metrics=include_raw_metrics
            )
            return {
                "content_type": "both",
                "definitions": definitions,
                "data": data,
                "timestamp": data.get("timestamp"),
                "_execution_info": {
                    "combined_response": True,
                    "definitions_available": definitions.get("success", False),
                    "data_available": data.get("success", False)
                }
            }
        else:
            return {"error": f"Invalid content_type: {content_type}. Must be 'definitions', 'data', or 'both'"}

    async def _get_memory_stats_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Unified memory statistics tool routing"""
        data_type = arguments.get("data_type", "realtime")
        tracker_type = arguments.get("tracker_type", "overview")
        tracker_names = arguments.get("tracker_names")
        time_range = arguments.get("time_range", "1h")
        include_details = arguments.get("include_details", True)
        
        if data_type == "realtime":
            # Only get real-time data
            return await self.memory_tracker.get_realtime_memory_stats(
                tracker_type, include_details
            )
        elif data_type == "historical":
            # Only get historical data
            return await self.memory_tracker.get_historical_memory_stats(
                tracker_names, time_range
            )
        elif data_type == "both":
            # Get both real-time and historical data
            realtime = await self.memory_tracker.get_realtime_memory_stats(
                tracker_type, include_details
            )
            historical = await self.memory_tracker.get_historical_memory_stats(
                tracker_names, time_range
            )
            return {
                "data_type": "both",
                "realtime": realtime,
                "historical": historical,
                "timestamp": realtime.get("timestamp"),
                "_execution_info": {
                    "combined_response": True,
                    "realtime_available": realtime.get("success", False),
                    "historical_available": historical.get("success", False)
                }
            }
        else:
            return {"error": f"Invalid data_type: {data_type}. Must be 'realtime', 'historical', or 'both'"}

    # Legacy tool methods (for backward compatibility)
    async def _get_monitoring_metrics_info_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """[DEPRECATED] Use get_monitoring_metrics with content_type='definitions'"""
        arguments["content_type"] = "definitions"
        return await self._get_monitoring_metrics_tool(arguments)

    async def _get_monitoring_metrics_data_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """[DEPRECATED] Use get_monitoring_metrics with content_type='data'"""
        arguments["content_type"] = "data"
        return await self._get_monitoring_metrics_tool(arguments)

    async def _get_realtime_memory_stats_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """[DEPRECATED] Use get_memory_stats with data_type='realtime'"""
        arguments["data_type"] = "realtime"
        return await self._get_memory_stats_tool(arguments)

    async def _get_historical_memory_stats_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """[DEPRECATED] Use get_memory_stats with data_type='historical'"""
        arguments["data_type"] = "historical"
        return await self._get_memory_stats_tool(arguments)
    
    # ==================== v0.5.0 Advanced Analytics Tools Private Methods ====================
    
    async def _get_table_basic_info_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get table basic information tool routing"""
        try:
            table_name = arguments.get("table_name")
            catalog_name = arguments.get("catalog_name")
            db_name = arguments.get("db_name")
            
            # Delegate to atomic data quality tools
            result = await self.data_quality_tools.get_table_basic_info(
                table_name=table_name,
                catalog_name=catalog_name,
                db_name=db_name
            )
            
            return result
            
        except Exception as e:
            return {
                "error": str(e),
                "analysis_type": "table_basic_info",
                "timestamp": datetime.now().isoformat()
            }
    
    async def _analyze_columns_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze columns tool routing"""
        try:
            table_name = arguments.get("table_name")
            columns = arguments.get("columns")
            analysis_types = arguments.get("analysis_types", ["both"])
            sample_size = arguments.get("sample_size", 100000)
            catalog_name = arguments.get("catalog_name")
            db_name = arguments.get("db_name")
            detailed_response = arguments.get("detailed_response", False)
            
            # Delegate to atomic data quality tools
            result = await self.data_quality_tools.analyze_columns(
                table_name=table_name,
                columns=columns,
                analysis_types=analysis_types,
                sample_size=sample_size,
                catalog_name=catalog_name,
                db_name=db_name,
                detailed_response=detailed_response
            )
            
            return result
            
        except Exception as e:
            return {
                "error": str(e),
                "analysis_type": "columns_analysis",
                "timestamp": datetime.now().isoformat()
            }
    
    async def _analyze_table_storage_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze table storage tool routing"""
        try:
            table_name = arguments.get("table_name")
            catalog_name = arguments.get("catalog_name")
            db_name = arguments.get("db_name")
            detailed_response = arguments.get("detailed_response", False)
            
            # Delegate to atomic data quality tools
            result = await self.data_quality_tools.analyze_table_storage(
                table_name=table_name,
                catalog_name=catalog_name,
                db_name=db_name,
                detailed_response=detailed_response
            )
            
            return result
            
        except Exception as e:
            return {
                "error": str(e),
                "analysis_type": "table_storage_analysis",
                "timestamp": datetime.now().isoformat()
            }
    

    
    async def _trace_column_lineage_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Column lineage tracing tool routing"""
        target_columns = arguments.get("target_columns")
        analysis_depth = arguments.get("analysis_depth", 3)
        include_transformations = arguments.get("include_transformations", True)
        catalog_name = arguments.get("catalog_name")
        
        if not target_columns:
            return {"error": "target_columns parameter is required"}
        
        # Handle multi-column lineage tracing
        if isinstance(target_columns, list):
            results = {}
            for column_spec in target_columns:
                try:
                    # Parse column specification: "table.column" or "db.table.column"
                    parts = column_spec.split(".")
                    if len(parts) == 2:
                        table_name, column_name = parts
                        db_name = None
                    elif len(parts) == 3:
                        db_name, table_name, column_name = parts
                    else:
                        results[column_spec] = {"error": f"Invalid column specification format: {column_spec}. Expected 'table.column' or 'db.table.column'"}
                        continue
                    
                    result = await self.data_governance_tools.trace_column_lineage(
                        table_name=table_name,
                        column_name=column_name,
                        depth=analysis_depth,
                        catalog_name=catalog_name,
                        db_name=db_name
                    )
                    results[column_spec] = result
                    
                except Exception as e:
                    results[column_spec] = {"error": f"Failed to trace lineage for {column_spec}: {str(e)}"}
            
            return {
                "multi_column_lineage": True,
                "column_count": len(target_columns),
                "analysis_timestamp": list(results.values())[0].get("analysis_timestamp") if results else None,
                "results": results
            }
        else:
            # Single column analysis
            column_spec = target_columns
            parts = column_spec.split(".")
            if len(parts) == 2:
                table_name, column_name = parts
                db_name = None
            elif len(parts) == 3:
                db_name, table_name, column_name = parts
            else:
                return {"error": f"Invalid column specification format: {column_spec}. Expected 'table.column' or 'db.table.column'"}
            
            return await self.data_governance_tools.trace_column_lineage(
                table_name=table_name,
                column_name=column_name,
                depth=analysis_depth,
                catalog_name=catalog_name,
                db_name=db_name
            )
    
    async def _monitor_data_freshness_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Data freshness monitoring tool routing"""
        table_names = arguments.get("table_names")
        freshness_threshold_hours = arguments.get("freshness_threshold_hours", 24)
        include_update_patterns = arguments.get("include_update_patterns", True)
        catalog_name = arguments.get("catalog_name")
        db_name = arguments.get("db_name")
        
        # Delegate to data governance tools for processing
        return await self.data_governance_tools.monitor_data_freshness(
            tables=table_names, 
            time_threshold_hours=freshness_threshold_hours, 
            catalog_name=catalog_name, 
            db_name=db_name
        )
    

    
    async def _analyze_data_access_patterns_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Data access patterns analysis tool routing"""
        days = arguments.get("days", 7)
        include_system_users = arguments.get("include_system_users", False)
        min_query_threshold = arguments.get("min_query_threshold", 5)
        
        # Delegate to security analytics tools for processing
        return await self.security_analytics_tools.analyze_data_access_patterns(
            days, include_system_users, min_query_threshold
        )
    
    async def _analyze_data_flow_dependencies_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Data flow dependencies analysis tool routing"""
        target_table = arguments.get("target_table")
        analysis_depth = arguments.get("analysis_depth", 3)
        include_views = arguments.get("include_views", True)
        catalog_name = arguments.get("catalog_name")
        db_name = arguments.get("db_name")
        
        # Delegate to dependency analysis tools for processing
        return await self.dependency_analysis_tools.analyze_data_flow_dependencies(
            target_table, analysis_depth, include_views, catalog_name, db_name
        )
    
    async def _analyze_slow_queries_topn_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Slow queries Top-N analysis tool routing"""
        days = arguments.get("days", 7)
        top_n = arguments.get("top_n", 20)
        min_execution_time_ms = arguments.get("min_execution_time_ms", 1000)
        include_patterns = arguments.get("include_patterns", True)
        
        # Delegate to performance analytics tools for processing
        return await self.performance_analytics_tools.analyze_slow_queries_topn(
            days, top_n, min_execution_time_ms, include_patterns
        )
    
    async def _analyze_resource_growth_curves_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Resource growth curves analysis tool routing"""
        days = arguments.get("days", 30)
        resource_types = arguments.get("resource_types", ["storage", "query_volume", "user_activity"])
        include_predictions = arguments.get("include_predictions", False)
        detailed_response = arguments.get("detailed_response", False)
        
        # Delegate to performance analytics tools for processing
        return await self.performance_analytics_tools.analyze_resource_growth_curves(
            days, resource_types, include_predictions, detailed_response
        )
    
    # ==================== ADBC Query Tools Private Methods ====================
    
    async def _exec_adbc_query_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """ADBC query execution tool routing"""
        sql = arguments.get("sql")
        max_rows = arguments.get("max_rows", 100000)
        timeout = arguments.get("timeout", 60)
        return_format = arguments.get("return_format", "arrow")
        
        # Delegate to ADBC query tools for processing
        return await self.adbc_query_tools.exec_adbc_query(
            sql, max_rows, timeout, return_format
        )
    
    async def _get_adbc_connection_info_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """ADBC connection information tool routing"""
        # Delegate to ADBC query tools for processing
        return await self.adbc_query_tools.get_adbc_connection_info()
