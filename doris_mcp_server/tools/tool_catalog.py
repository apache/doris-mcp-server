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
"""Immutable MCP tool catalog, separate from manager lifecycle and routing."""

from collections.abc import Iterable
from typing import Any

from mcp.types import Tool

from ..result_limits import configured_default_result_rows, configured_result_limits
from ..utils.config import ADBCConfig
from .tool_provider import CustomTool
from .tool_registry import ToolDefinitionRegistry


def build_tool_registry(
    handler_owner: Any,
    config: Any | None,
    custom_tools: Iterable[tuple[str, CustomTool]] = (),
) -> ToolDefinitionRegistry:
    """Build immutable tool metadata and bind it to a handler owner."""
    adbc_config = getattr(config, "adbc", None) or ADBCConfig()
    result_limits = configured_result_limits(config)
    default_result_rows = configured_default_result_rows(config)
    adbc_default_max_rows = min(
        adbc_config.default_max_rows,
        result_limits.max_rows,
    )
    adbc_default_timeout = min(
        adbc_config.default_timeout,
        result_limits.timeout_seconds,
    )

    tools = [
        Tool(
            name="exec_query",
            description="""[Function Description]: Execute SQL query and return result command with catalog federation support.

[Parameter Content]:

- sql (string) [Required] - SQL statement to execute. MUST use three-part naming for all table references: 'catalog_name.db_name.table_name'. For internal tables use 'internal.db_name.table_name', for external tables use 'catalog_name.db_name.table_name'

- db_name (string) [Optional] - Target database name, defaults to the current database

- catalog_name (string) [Optional] - Reference catalog name for context, defaults to current catalog

- max_rows (integer) [Optional] - Maximum number of rows to return, defaults to the configured DEFAULT_RESULT_ROWS value

- max_bytes (integer) [Optional] - Maximum UTF-8 JSON bytes for returned row data

- timeout (integer) [Optional] - Query timeout in seconds, default 30
""",
            input_schema={
                "type": "object",
                "properties": {
                    "sql": {
                        "type": "string",
                        "description": "SQL statement to execute, must use three-part naming",
                    },
                    "db_name": {
                        "type": "string",
                        "description": "Target database name",
                    },
                    "catalog_name": {
                        "type": "string",
                        "description": "Catalog name",
                    },
                    "max_rows": {
                        "type": "integer",
                        "description": "Maximum number of rows to return",
                        "default": default_result_rows,
                        "minimum": 1,
                        "maximum": result_limits.max_rows,
                    },
                    "max_bytes": {
                        "type": "integer",
                        "description": "Maximum UTF-8 JSON bytes for returned row data",
                        "default": result_limits.max_bytes,
                        "minimum": 256,
                        "maximum": result_limits.max_bytes,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Timeout in seconds",
                        "default": 30,
                        "minimum": 1,
                        "maximum": result_limits.timeout_seconds,
                    },
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
            input_schema={
                "type": "object",
                "properties": {
                    "table_name": {"type": "string", "description": "Table name"},
                    "db_name": {"type": "string", "description": "Database name"},
                    "catalog_name": {
                        "type": "string",
                        "description": "Catalog name",
                    },
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
            input_schema={
                "type": "object",
                "properties": {
                    "db_name": {"type": "string", "description": "Database name"},
                    "catalog_name": {
                        "type": "string",
                        "description": "Catalog name",
                    },
                },
            },
        ),
        Tool(
            name="get_db_list",
            description="""[Function Description]: Get a list of all database names on the server.

[Parameter Content]:

- catalog_name (string) [Optional] - Target catalog name for federation queries, defaults to current catalog
""",
            input_schema={
                "type": "object",
                "properties": {
                    "catalog_name": {
                        "type": "string",
                        "description": "Catalog name",
                    },
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
            input_schema={
                "type": "object",
                "properties": {
                    "table_name": {"type": "string", "description": "Table name"},
                    "db_name": {"type": "string", "description": "Database name"},
                    "catalog_name": {
                        "type": "string",
                        "description": "Catalog name",
                    },
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
            input_schema={
                "type": "object",
                "properties": {
                    "table_name": {"type": "string", "description": "Table name"},
                    "db_name": {"type": "string", "description": "Database name"},
                    "catalog_name": {
                        "type": "string",
                        "description": "Catalog name",
                    },
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
            input_schema={
                "type": "object",
                "properties": {
                    "table_name": {"type": "string", "description": "Table name"},
                    "db_name": {"type": "string", "description": "Database name"},
                    "catalog_name": {
                        "type": "string",
                        "description": "Catalog name",
                    },
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
            input_schema={
                "type": "object",
                "properties": {
                    "days": {
                        "type": "integer",
                        "description": "Number of recent days",
                        "default": 7,
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of records",
                        "default": 100,
                    },
                },
            },
        ),
        Tool(
            name="get_catalog_list",
            description="""[Function Description]: Get a list of all catalog names on the server.

[Parameter Content]:

- random_string (string) [Required] - Unique identifier for the tool call
""",
            input_schema={
                "type": "object",
                "properties": {
                    "random_string": {
                        "type": "string",
                        "description": "Unique identifier",
                    },
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
            input_schema={
                "type": "object",
                "properties": {
                    "sql": {
                        "type": "string",
                        "description": "SQL statement to explain",
                    },
                    "verbose": {
                        "type": "boolean",
                        "description": "Whether to show verbose information",
                        "default": False,
                    },
                    "db_name": {"type": "string", "description": "Database name"},
                    "catalog_name": {
                        "type": "string",
                        "description": "Catalog name",
                    },
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
            input_schema={
                "type": "object",
                "properties": {
                    "sql": {
                        "type": "string",
                        "description": "SQL statement to profile",
                    },
                    "db_name": {"type": "string", "description": "Database name"},
                    "catalog_name": {
                        "type": "string",
                        "description": "Catalog name",
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Query timeout in seconds",
                        "default": 30,
                    },
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
            input_schema={
                "type": "object",
                "properties": {
                    "db_name": {"type": "string", "description": "Database name"},
                    "table_name": {"type": "string", "description": "Table name"},
                    "single_replica": {
                        "type": "boolean",
                        "description": "Whether to get single replica data size",
                        "default": False,
                    },
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
            input_schema={
                "type": "object",
                "properties": {
                    "content_type": {
                        "type": "string",
                        "enum": ["definitions", "data", "both"],
                        "description": "Type of monitoring content to retrieve",
                        "default": "data",
                    },
                    "role": {
                        "type": "string",
                        "enum": ["fe", "be", "all"],
                        "description": "Node role to monitor",
                        "default": "all",
                    },
                    "monitor_type": {
                        "type": "string",
                        "enum": ["process", "jvm", "machine", "all"],
                        "description": "Type of monitoring metrics",
                        "default": "all",
                    },
                    "priority": {
                        "type": "string",
                        "enum": ["core", "p0", "all"],
                        "description": "Metric priority level",
                        "default": "core",
                    },
                    "include_raw_metrics": {
                        "type": "boolean",
                        "description": "Whether to include raw detailed metrics data (can be very large)",
                        "default": False,
                    },
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
            input_schema={
                "type": "object",
                "properties": {
                    "data_type": {
                        "type": "string",
                        "enum": ["realtime", "historical", "both"],
                        "description": "Type of memory data to retrieve",
                        "default": "realtime",
                    },
                    "tracker_type": {
                        "type": "string",
                        "enum": [
                            "overview",
                            "global",
                            "query",
                            "load",
                            "compaction",
                            "all",
                        ],
                        "description": "Type of memory trackers to retrieve (for real-time)",
                        "default": "overview",
                    },
                    "tracker_names": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of specific tracker names for historical data",
                    },
                    "time_range": {
                        "type": "string",
                        "enum": ["1h", "6h", "24h"],
                        "description": "Time range for historical data",
                        "default": "1h",
                    },
                    "include_details": {
                        "type": "boolean",
                        "description": "Whether to include detailed tracker information and definitions",
                        "default": True,
                    },
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
            input_schema={
                "type": "object",
                "properties": {
                    "table_name": {
                        "type": "string",
                        "description": "Name of the table to analyze",
                    },
                    "catalog_name": {
                        "type": "string",
                        "description": "Target catalog name",
                    },
                    "db_name": {
                        "type": "string",
                        "description": "Target database name",
                    },
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
            input_schema={
                "type": "object",
                "properties": {
                    "table_name": {
                        "type": "string",
                        "description": "Name of the table to analyze",
                    },
                    "columns": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of column names to analyze",
                    },
                    "analysis_types": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["completeness", "distribution", "both"],
                        },
                        "description": "Types of analysis to perform",
                        "default": ["both"],
                    },
                    "sample_size": {
                        "type": "integer",
                        "description": "Maximum number of rows to sample",
                        "default": 100000,
                    },
                    "catalog_name": {
                        "type": "string",
                        "description": "Target catalog name",
                    },
                    "db_name": {
                        "type": "string",
                        "description": "Target database name",
                    },
                    "detailed_response": {
                        "type": "boolean",
                        "description": "Whether to return detailed response including raw data",
                        "default": False,
                    },
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
            input_schema={
                "type": "object",
                "properties": {
                    "table_name": {
                        "type": "string",
                        "description": "Name of the table to analyze",
                    },
                    "catalog_name": {
                        "type": "string",
                        "description": "Target catalog name",
                    },
                    "db_name": {
                        "type": "string",
                        "description": "Target database name",
                    },
                    "detailed_response": {
                        "type": "boolean",
                        "description": "Whether to return detailed response including raw data",
                        "default": False,
                    },
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
            input_schema={
                "type": "object",
                "properties": {
                    "target_columns": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of column specifications",
                    },
                    "analysis_depth": {
                        "type": "integer",
                        "description": "Maximum depth for lineage tracing",
                        "default": 3,
                    },
                    "include_transformations": {
                        "type": "boolean",
                        "description": "Whether to include transformation details",
                        "default": True,
                    },
                    "catalog_name": {
                        "type": "string",
                        "description": "Target catalog name",
                    },
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
            input_schema={
                "type": "object",
                "properties": {
                    "table_names": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of table names to monitor",
                    },
                    "freshness_threshold_hours": {
                        "type": "integer",
                        "description": "Freshness threshold in hours",
                        "default": 24,
                    },
                    "include_update_patterns": {
                        "type": "boolean",
                        "description": "Whether to include update pattern analysis",
                        "default": True,
                    },
                    "catalog_name": {
                        "type": "string",
                        "description": "Target catalog name",
                    },
                    "db_name": {
                        "type": "string",
                        "description": "Target database name",
                    },
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
            input_schema={
                "type": "object",
                "properties": {
                    "days": {
                        "type": "integer",
                        "description": "Number of days to analyze",
                        "default": 7,
                    },
                    "include_system_users": {
                        "type": "boolean",
                        "description": "Whether to include system users",
                        "default": False,
                    },
                    "min_query_threshold": {
                        "type": "integer",
                        "description": "Minimum queries for user inclusion",
                        "default": 5,
                    },
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
            input_schema={
                "type": "object",
                "properties": {
                    "target_table": {
                        "type": "string",
                        "description": "Specific table to analyze",
                    },
                    "analysis_depth": {
                        "type": "integer",
                        "description": "Maximum depth for dependency traversal",
                        "default": 3,
                    },
                    "include_views": {
                        "type": "boolean",
                        "description": "Whether to include views in analysis",
                        "default": True,
                    },
                    "catalog_name": {
                        "type": "string",
                        "description": "Target catalog name",
                    },
                    "db_name": {
                        "type": "string",
                        "description": "Target database name",
                    },
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
            input_schema={
                "type": "object",
                "properties": {
                    "days": {
                        "type": "integer",
                        "description": "Number of days to analyze",
                        "default": 7,
                    },
                    "top_n": {
                        "type": "integer",
                        "description": "Number of top slow queries to return",
                        "default": 20,
                    },
                    "min_execution_time_ms": {
                        "type": "integer",
                        "description": "Minimum execution time threshold in milliseconds",
                        "default": 1000,
                    },
                    "include_patterns": {
                        "type": "boolean",
                        "description": "Whether to include query pattern analysis",
                        "default": True,
                    },
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
            input_schema={
                "type": "object",
                "properties": {
                    "days": {
                        "type": "integer",
                        "description": "Number of days to analyze",
                        "default": 30,
                    },
                    "resource_types": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Types of resources to analyze",
                    },
                    "include_predictions": {
                        "type": "boolean",
                        "description": "Whether to include growth predictions",
                        "default": False,
                    },
                    "detailed_response": {
                        "type": "boolean",
                        "description": "Whether to return detailed data including daily breakdowns",
                        "default": False,
                    },
                },
            },
        ),
        # ==================== ADBC Query Tools ====================
        Tool(
            name="exec_adbc_query",
            description=f"""[Function Description]: Execute SQL query using ADBC (Arrow Flight SQL) protocol for high-performance data transfer.

[Parameter Content]:

- sql (string) [Required] - SQL statement to execute
- max_rows (integer) [Optional] - Maximum number of rows to return, default is {adbc_default_max_rows}
- max_bytes (integer) [Optional] - Maximum UTF-8 JSON bytes for returned row data, default is {result_limits.max_bytes}
- timeout (integer) [Optional] - Query timeout in seconds, default is {adbc_default_timeout}
- return_format (string) [Optional] - Format for returned data, default is "{adbc_config.default_return_format}"
  * "arrow": Return Arrow format with metadata
  * "pandas": Return Pandas DataFrame format
  * "dict": Return dictionary format

[Prerequisites]:
- Environment variables FE_ARROW_FLIGHT_SQL_PORT and BE_ARROW_FLIGHT_SQL_PORT must be configured
- Required Python packages: adbc_driver_manager, adbc_driver_flightsql
- Arrow Flight SQL services must be running on FE and BE nodes
""",
            input_schema={
                "type": "object",
                "properties": {
                    "sql": {
                        "type": "string",
                        "description": "SQL statement to execute",
                    },
                    "max_rows": {
                        "type": "integer",
                        "description": "Maximum number of rows to return",
                        "minimum": 1,
                        "maximum": result_limits.max_rows,
                        "default": adbc_default_max_rows,
                    },
                    "max_bytes": {
                        "type": "integer",
                        "description": "Maximum UTF-8 JSON result bytes",
                        "minimum": 256,
                        "maximum": result_limits.max_bytes,
                        "default": result_limits.max_bytes,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Query timeout in seconds",
                        "minimum": 1,
                        "maximum": result_limits.timeout_seconds,
                        "default": adbc_default_timeout,
                    },
                    "return_format": {
                        "type": "string",
                        "enum": ["arrow", "pandas", "dict"],
                        "description": "Format for returned data",
                        "default": adbc_config.default_return_format,
                    },
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
            input_schema={
                "type": "object",
                "properties": {},
            },
        ),
    ]

    return ToolDefinitionRegistry.from_tools(
        tools,
        handler_owner,
        custom_tools=custom_tools,
    )
