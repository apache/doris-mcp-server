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
        
        logger.info("DorisToolsManager initialized with business logic processors")
    
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

        # Monitoring metrics definition tool
        @mcp.tool(
            "get_monitoring_metrics_info",
            description="""[Function Description]: Get Doris monitoring metrics definitions and descriptions without executing queries.

[Parameter Content]:

- role (string) [Optional] - Node role to get metric definitions for, default is "all"
  * "fe": Only FE metrics definitions
  * "be": Only BE metrics definitions  
  * "all": Both FE and BE metrics definitions

- monitor_type (string) [Optional] - Type of monitoring metrics, default is "all"
  * "process": Process monitoring metrics
  * "jvm": JVM monitoring metrics (FE only)
  * "machine": Machine monitoring metrics
  * "all": All monitoring types

- priority (string) [Optional] - Metric priority level, default is "core"
  * "core": Only core essential metrics (10-12 items for production use)
  * "p0": Only P0 (highest priority) metrics definitions
  * "all": All metrics definitions (P0 and non-P0)
""",
        )
        async def get_monitoring_metrics_info_tool(
            role: str = "all",
            monitor_type: str = "all",
            priority: str = "core"
        ) -> str:
            """Get Doris monitoring metrics definitions"""
            return await self.call_tool("get_monitoring_metrics_info", {
                "role": role,
                "monitor_type": monitor_type,
                "priority": priority
            })

        # Monitoring metrics data tool
        @mcp.tool(
            "get_monitoring_metrics_data",
            description="""[Function Description]: Get actual Doris monitoring metrics data from FE and BE nodes via HTTP API.

[Parameter Content]:

- role (string) [Optional] - Node role to monitor, default is "all"
  * "fe": Only FE nodes
  * "be": Only BE nodes  
  * "all": Both FE and BE nodes

- monitor_type (string) [Optional] - Type of monitoring metrics, default is "all"
  * "process": Process monitoring metrics
  * "jvm": JVM monitoring metrics (FE only)
  * "machine": Machine monitoring metrics
  * "all": All monitoring types

- priority (string) [Optional] - Metric priority level, default is "core"
  * "core": Only core essential metrics (10-12 items for production use)
  * "p0": Only P0 (highest priority) metrics
  * "all": All metrics (P0 and non-P0)

- include_raw_metrics (boolean) [Optional] - Whether to include raw detailed metrics data (can be very large)
""",
        )
        async def get_monitoring_metrics_data_tool(
            role: str = "all",
            monitor_type: str = "all",
            priority: str = "core",
            include_raw_metrics: bool = False
        ) -> str:
            """Get Doris monitoring metrics data"""
            return await self.call_tool("get_monitoring_metrics_data", {
                "role": role,
                "monitor_type": monitor_type,
                "priority": priority,
                "include_raw_metrics": include_raw_metrics
            })

        # Real-time memory tracker tool
        @mcp.tool(
            "get_realtime_memory_stats",
            description="""[Function Description]: Get real-time memory statistics via Doris BE Memory Tracker web interface.

[Parameter Content]:

- tracker_type (string) [Optional] - Type of memory trackers to retrieve, default is "overview"
  * "overview": Overview type trackers (process memory, tracked memory summary)
  * "global": Global shared memory trackers (cache, metadata)
  * "query": Query-related memory trackers
  * "load": Load-related memory trackers  
  * "compaction": Compaction-related memory trackers
  * "all": All memory tracker types

- include_details (boolean) [Optional] - Whether to include detailed tracker information and definitions, default is true
""",
        )
        async def get_realtime_memory_stats_tool(
            tracker_type: str = "overview",
            include_details: bool = True
        ) -> str:
            """Get real-time memory statistics tool"""
            return await self.call_tool("get_realtime_memory_stats", {
                "tracker_type": tracker_type,
                "include_details": include_details
            })

        # Historical memory tracker tool
        @mcp.tool(
            "get_historical_memory_stats",
            description="""[Function Description]: Get historical memory statistics via Doris BE Bvar interface.

[Parameter Content]:

- tracker_names (array) [Optional] - List of specific tracker names to query, if not specified will get common trackers
  * Example: ["process_resident_memory", "global", "query", "load", "compaction"]

- time_range (string) [Optional] - Time range for historical data, default is "1h"
  * "1h": Last 1 hour
  * "6h": Last 6 hours
  * "24h": Last 24 hours
""",
        )
        async def get_historical_memory_stats_tool(
            tracker_names: List[str] = None,
            time_range: str = "1h"
        ) -> str:
            """Get historical memory statistics tool"""
            return await self.call_tool("get_historical_memory_stats", {
                "tracker_names": tracker_names,
                "time_range": time_range
            })

        # Get table partition info tool
        @mcp.tool(
            "get_table_partition_info",
            description="""[Function Description]: Get partition information for the specified table.

[Parameter Content]:

- table_name (string) [Required] - Name of the table to query

- db_name (string) [Optional] - Target database name, defaults to the current database

- catalog_name (string) [Optional] - Target catalog name for federation queries, defaults to current catalog
""",
        )
        async def get_table_partition_info_tool(
            table_name: str, db_name: str = None, catalog_name: str = None
        ) -> str:
            """Get table partition information"""
            return await self.call_tool("get_table_partition_info", {
                "table_name": table_name,
                "db_name": db_name,
                "catalog_name": catalog_name
            })

            # Table sample data tool
            @mcp.tool(
                "table_sample_data",
                description="""[Function Description]: Sample data from specified table with various sampling methods.

[Parameter Content]:

- table_name (string) [Required] - Name of the table to sample
- db_name (string) [Optional] - Target database name, defaults to current database
- catalog_name (string) [Optional] - Target catalog name for federation queries
- sample_method (string) [Optional] - Sampling method (SYSTEM|BERNOULLI|RANDOM), default SYSTEM
- sample_size (number) [Required] - Sample size or ratio (e.g. 100 or 0.1 for 10%)
- columns (string) [Optional] - Columns to return, comma separated
- where_condition (string) [Optional] - Filter condition before sampling
- cache_ttl (integer) [Optional] - Result cache TTL in seconds, default 300
""",
            )
            async def table_sample_data_tool(
                table_name: str,
                sample_size: float,
                db_name: str = None,
                catalog_name: str = None,
                sample_method: str = "SYSTEM",
                columns: str = None,
                where_condition: str = None,
                cache_ttl: int = 300
            ) -> str:
                """Table data sampling tool"""
                return await self.call_tool("table_sample_data", {
                    "table_name": table_name,
                    "db_name": db_name,
                    "catalog_name": catalog_name,
                    "sample_method": sample_method,
                    "sample_size": sample_size,
                    "columns": columns,
                    "where_condition": where_condition,
                    "cache_ttl": cache_ttl
                })

            logger.info("Successfully registered 18 tools to MCP server")

    async def list_tools(self) -> List[Tool]:
        """List all available query tools (for stdio mode)"""
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
                name="get_monitoring_metrics_info",
                description="""[Function Description]: Get Doris monitoring metrics definitions and descriptions without executing queries.

[Parameter Content]:

- role (string) [Optional] - Node role to get metric definitions for, default is "all"
  * "fe": Only FE metrics definitions
  * "be": Only BE metrics definitions  
  * "all": Both FE and BE metrics definitions

- monitor_type (string) [Optional] - Type of monitoring metrics, default is "all"
  * "process": Process monitoring metrics
  * "jvm": JVM monitoring metrics (FE only)
  * "machine": Machine monitoring metrics
  * "all": All monitoring types

- priority (string) [Optional] - Metric priority level, default is "core"
  * "core": Only core essential metrics (10-12 items for production use)
  * "p0": Only P0 (highest priority) metrics definitions
  * "all": All metrics definitions (P0 and non-P0)
""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "role": {"type": "string", "enum": ["fe", "be", "all"], "description": "Node role to get metric definitions for", "default": "all"},
                        "monitor_type": {"type": "string", "enum": ["process", "jvm", "machine", "all"], "description": "Type of monitoring metrics", "default": "all"},
                        "priority": {"type": "string", "enum": ["core", "p0", "all"], "description": "Metric priority level", "default": "core"},
                    },
                },
            ),
            Tool(
                name="get_monitoring_metrics_data",
                description="""[Function Description]: Get actual Doris monitoring metrics data from FE and BE nodes via HTTP API.

[Parameter Content]:

- role (string) [Optional] - Node role to monitor, default is "all"
  * "fe": Only FE nodes
  * "be": Only BE nodes  
  * "all": Both FE and BE nodes

- monitor_type (string) [Optional] - Type of monitoring metrics, default is "all"
  * "process": Process monitoring metrics
  * "jvm": JVM monitoring metrics (FE only)
  * "machine": Machine monitoring metrics
  * "all": All monitoring types

- priority (string) [Optional] - Metric priority level, default is "core"
  * "core": Only core essential metrics (10-12 items for production use)
  * "p0": Only P0 (highest priority) metrics
  * "all": All metrics (P0 and non-P0)

- include_raw_metrics (boolean) [Optional] - Whether to include raw detailed metrics data (can be very large)
""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "role": {"type": "string", "enum": ["fe", "be", "all"], "description": "Node role to monitor", "default": "all"},
                        "monitor_type": {"type": "string", "enum": ["process", "jvm", "machine", "all"], "description": "Type of monitoring metrics", "default": "all"},
                        "priority": {"type": "string", "enum": ["core", "p0", "all"], "description": "Metric priority level", "default": "core"},
                        "include_raw_metrics": {"type": "boolean", "description": "Whether to include raw detailed metrics data (can be very large)", "default": False},
                    },
                },
            ),
            Tool(
                name="get_realtime_memory_stats",
                description="""[Function Description]: Get real-time memory statistics via Doris BE Memory Tracker web interface.

[Parameter Content]:

- tracker_type (string) [Optional] - Type of memory trackers to retrieve, default is "overview"
  * "overview": Overview type trackers (process memory, tracked memory summary)
  * "global": Global shared memory trackers (cache, metadata)
  * "query": Query-related memory trackers
  * "load": Load-related memory trackers  
  * "compaction": Compaction-related memory trackers
  * "all": All memory tracker types

- include_details (boolean) [Optional] - Whether to include detailed tracker information and definitions, default is true
""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "tracker_type": {"type": "string", "enum": ["overview", "global", "query", "load", "compaction", "all"], "description": "Type of memory trackers to retrieve", "default": "overview"},
                        "include_details": {"type": "boolean", "description": "Whether to include detailed tracker information and definitions", "default": True},
                    },
                },
            ),
            Tool(
                name="get_historical_memory_stats",
                description="""[Function Description]: Get historical memory statistics via Doris BE Bvar interface.

[Parameter Content]:

- tracker_names (array) [Optional] - List of specific tracker names to query, if not specified will get common trackers
  * Example: ["process_resident_memory", "global", "query", "load", "compaction"]

- time_range (string) [Optional] - Time range for historical data, default is "1h"
  * "1h": Last 1 hour
  * "6h": Last 6 hours  
  * "24h": Last 24 hours
""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "tracker_names": {"type": "array", "items": {"type": "string"}, "description": "List of specific tracker names to query"},
                        "time_range": {"type": "string", "enum": ["1h", "6h", "24h"], "description": "Time range for historical data", "default": "1h"},
                    },
                },
            ),
            Tool(
                name="get_table_partition_info",
                description="""[Function Description]: Get partition information for the specified table.

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
                name="table_sample_data",
                description="""[Function Description]: Sample data from specified table with various sampling methods.

[Parameter Content]:

- table_name (string) [Required] - Name of the table to sample
- db_name (string) [Optional] - Target database name, defaults to current database
- catalog_name (string) [Optional] - Target catalog name for federation queries
- sample_method (string) [Optional] - Sampling method (SYSTEM|BERNOULLI|RANDOM), default SYSTEM
- sample_size (number) [Required] - Sample size or ratio (e.g. 100 or 0.1 for 10%)
- columns (string) [Optional] - Columns to return, comma separated
- where_condition (string) [Optional] - Filter condition before sampling
- cache_ttl (integer) [Optional] - Result cache TTL in seconds, default 300
""",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "table_name": {"type": "string", "description": "Table name to sample"},
                        "db_name": {"type": "string", "description": "Database name"},
                        "catalog_name": {"type": "string", "description": "Catalog name"},
                        "sample_method": {"type": "string", "enum": ["SYSTEM", "BERNOULLI", "RANDOM"], "default": "SYSTEM"},
                        "sample_size": {"type": "number", "description": "Sample size or ratio"},
                        "columns": {"type": "string", "description": "Columns to return, comma separated"},
                        "where_condition": {"type": "string", "description": "Filter condition before sampling"},
                        "cache_ttl": {"type": "integer", "description": "Result cache TTL in seconds", "default": 300}
                    },
                    "required": ["table_name", "sample_size"],
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
            elif name == "get_sql_explain":
                result = await self._get_sql_explain_tool(arguments)
            elif name == "get_sql_profile":
                result = await self._get_sql_profile_tool(arguments)
            elif name == "get_table_data_size":
                result = await self._get_table_data_size_tool(arguments)
            elif name == "get_monitoring_metrics_info":
                result = await self._get_monitoring_metrics_info_tool(arguments)
            elif name == "get_monitoring_metrics_data":
                result = await self._get_monitoring_metrics_data_tool(arguments)
            elif name == "get_realtime_memory_stats":
                result = await self._get_realtime_memory_stats_tool(arguments)
            elif name == "get_historical_memory_stats":
                result = await self._get_historical_memory_stats_tool(arguments)
            elif name == "get_table_partition_info":
                result = await self._get_table_partition_info_tool(arguments)
            elif name == "table_sample_data":
                result = await self._table_sample_data_tool(arguments)
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
            
            # Serialize datetime objects before JSON conversion
            serialized_result = self._serialize_datetime_objects(result)
            return json.dumps(serialized_result, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"Tool call failed {name}: {str(e)}")
            error_result = {
                "error": str(e),
                "tool_name": name,
                "arguments": arguments,
                "timestamp": datetime.now().isoformat(),
            }
            return json.dumps(error_result, ensure_ascii=False, indent=2)

    def _serialize_datetime_objects(self, data):
        """Serialize datetime objects to JSON compatible format"""
        if isinstance(data, list):
            return [self._serialize_datetime_objects(item) for item in data]
        elif isinstance(data, dict):
            return {key: self._serialize_datetime_objects(value) for key, value in data.items()}
        elif hasattr(data, 'isoformat'):  # datetime, date, time objects
            return data.isoformat()
        elif hasattr(data, 'strftime'):  # pandas Timestamp objects
            return data.strftime('%Y-%m-%d %H:%M:%S')
        else:
            return data
    
    
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

    async def _get_monitoring_metrics_info_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Monitoring metrics info tool routing"""
        role = arguments.get("role", "all")
        monitor_type = arguments.get("monitor_type", "all")
        priority = arguments.get("priority", "p0")
        
        # Delegate to monitoring tools for processing (info_only=True)
        return await self.monitoring_tools.get_monitoring_metrics(
            role, monitor_type, priority, info_only=True, format_type="prometheus"
        )

    async def _get_monitoring_metrics_data_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Monitoring metrics data tool routing"""
        role = arguments.get("role", "all")
        monitor_type = arguments.get("monitor_type", "all")
        priority = arguments.get("priority", "p0")
        include_raw_metrics = arguments.get("include_raw_metrics", False)
        
        # Delegate to monitoring tools for processing (info_only=False)
        return await self.monitoring_tools.get_monitoring_metrics(
            role, monitor_type, priority, info_only=False, format_type="prometheus", include_raw_metrics=include_raw_metrics
        )

    async def _get_realtime_memory_stats_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Real-time memory statistics tool routing"""
        tracker_type = arguments.get("tracker_type", "overview")
        include_details = arguments.get("include_details", True)
        
        # Delegate to memory tracker for processing
        return await self.memory_tracker.get_realtime_memory_stats(
            tracker_type, include_details
        )

    async def _get_historical_memory_stats_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Historical memory statistics tool routing"""
        tracker_names = arguments.get("tracker_names")
        time_range = arguments.get("time_range", "1h")
        
        # Delegate to memory tracker for processing
        return await self.memory_tracker.get_historical_memory_stats(
            tracker_names, time_range
        )

    async def _get_table_partition_info_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Get table partition information tool routing"""
        table_name = arguments.get("table_name")
        db_name = arguments.get("db_name")
        catalog_name = arguments.get("catalog_name")
        
        # Delegate to metadata extractor for processing
        result = await self.metadata_extractor.get_table_partition_info_for_mcp(
            db_name, table_name
        )
        
        return result

    async def _table_sample_data_tool(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Table sample data tool routing"""
        table_name = arguments.get("table_name")
        db_name = arguments.get("db_name")
        catalog_name = arguments.get("catalog_name")
        sample_method = arguments.get("sample_method", "SYSTEM")
        sample_size = arguments.get("sample_size")
        columns = arguments.get("columns")
        where_condition = arguments.get("where_condition")
        cache_ttl = arguments.get("cache_ttl", 300)
        
        # Delegate to metadata extractor for processing
        return await self.metadata_extractor.get_table_sample_data_for_mcp(
            table_name=table_name,
            db_name=db_name,
            catalog_name=catalog_name,
            sample_method=sample_method,
            sample_size=sample_size,
            columns=columns,
            where_condition=where_condition,
            cache_ttl=cache_ttl
        )
