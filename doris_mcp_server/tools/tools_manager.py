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
import math
import time
from collections.abc import Iterable
from datetime import datetime
from typing import Any

from mcp.types import Tool

from ..auth.operation_policy import (
    OperationAuthorizationError,
    authorize_operation,
    filter_tools_for_auth_context,
)
from ..result_limits import configured_default_result_rows
from ..utils.adbc_query_tools import DorisADBCQueryTools
from ..utils.analysis_tools import MemoryTracker, SQLAnalyzer, TableAnalyzer
from ..utils.data_exploration_tools import DataExplorationTools
from ..utils.data_governance_tools import DataGovernanceTools
from ..utils.data_quality_tools import DataQualityTools
from ..utils.db import DorisConnectionManager
from ..utils.dependency_analysis_tools import DependencyAnalysisTools
from ..utils.logger import get_audit_logger, get_logger
from ..utils.monitoring_tools import DorisMonitoringTools
from ..utils.performance_analytics_tools import PerformanceAnalyticsTools
from ..utils.query_executor import DorisQueryExecutor
from ..utils.schema_extractor import MetadataExtractor
from ..utils.security import get_current_auth_context
from ..utils.security_analytics_tools import SecurityAnalyticsTools
from .tool_catalog import build_tool_registry
from .tool_provider import CustomToolProvider, ToolProviderRuntime
from .tool_registry import ToolDefinition, ToolDefinitionRegistry

logger = get_logger(__name__)


class DorisToolsManager:
    """Apache Doris Tools Manager"""

    def __init__(
        self,
        connection_manager: DorisConnectionManager,
        *,
        tool_providers: Iterable[CustomToolProvider] | None = None,
    ) -> None:
        self.connection_manager = connection_manager
        config = getattr(connection_manager, "config", None)
        self._tool_provider_runtime = ToolProviderRuntime.create(config, tool_providers)
        self.query_executor = DorisQueryExecutor(connection_manager)
        self.table_analyzer = TableAnalyzer(connection_manager)
        self.sql_analyzer = SQLAnalyzer(connection_manager)
        self.metadata_extractor = MetadataExtractor(
            connection_manager=connection_manager
        )
        self.monitoring_tools = DorisMonitoringTools(connection_manager)
        self.memory_tracker = MemoryTracker(connection_manager)

        # Initialize v0.5.0 advanced analytics tools
        self.data_governance_tools = DataGovernanceTools(connection_manager)
        self.data_exploration_tools = DataExplorationTools(connection_manager)
        self.data_quality_tools = DataQualityTools(
            connection_manager, connection_manager.config
        )
        self.security_analytics_tools = SecurityAnalyticsTools(connection_manager)
        self.dependency_analysis_tools = DependencyAnalysisTools(connection_manager)
        self.performance_analytics_tools = PerformanceAnalyticsTools(connection_manager)

        # Initialize ADBC query tools
        self.adbc_query_tools = DorisADBCQueryTools(connection_manager)
        self._tool_registry = self._build_tool_registry()

        logger.info(
            "DorisToolsManager initialized with business logic processors, v0.5.0 "
            "analytics tools, ADBC query tools, and %d custom tool providers",
            self._tool_provider_runtime.provider_count,
        )

    async def start(self) -> None:
        """Start runtime resources owned by the tools manager."""
        await self.query_executor.start()
        try:
            await self._tool_provider_runtime.start()
        except Exception:
            await self.query_executor.close()
            raise

    async def close(self) -> None:
        """Stop runtime resources owned by the tools manager."""
        await self._tool_provider_runtime.close()
        await self.query_executor.close()

    @staticmethod
    def _required_string(arguments: dict[str, Any], name: str) -> str:
        value = arguments.get(name)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")
        return value

    @staticmethod
    def _required_string_list(
        arguments: dict[str, Any],
        name: str,
    ) -> list[str]:
        value = arguments.get(name)
        if (
            not isinstance(value, list)
            or not value
            or any(not isinstance(item, str) or not item.strip() for item in value)
        ):
            raise ValueError(f"{name} must be a non-empty list of strings")
        return value

    def _build_tool_registry(self) -> ToolDefinitionRegistry:
        """Build the registry from the standalone immutable catalog."""
        provider_runtime = getattr(self, "_tool_provider_runtime", None)
        custom_tools = provider_runtime.custom_tools() if provider_runtime else ()
        return build_tool_registry(
            self,
            getattr(
                getattr(self, "connection_manager", None),
                "config",
                None,
            ),
            custom_tools=custom_tools,
        )

    @property
    def tool_registry(self) -> ToolDefinitionRegistry:
        """Return the registry, constructing it for legacy test fixtures."""
        registry = getattr(self, "_tool_registry", None)
        if registry is None:
            registry = self._build_tool_registry()
            self._tool_registry = registry
        return registry

    async def list_tools(self) -> list[Tool]:
        """List tools visible to the current authorization context."""
        return filter_tools_for_auth_context(
            get_current_auth_context(),
            self.tool_registry.listed_tools(),
        )

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> str:
        """
        Call the specified query tool (tool routing and scheduling center)
        """
        authorize_operation(get_current_auth_context(), f"tool:{name}")
        definition: ToolDefinition | None = None
        start_time = time.time()
        try:
            definition = self.tool_registry.resolve(name)
            if definition.rate_limit is not None:
                retry_after = await self._tool_provider_runtime.retry_after(
                    tool_name=definition.name,
                    auth_context=get_current_auth_context(),
                    limit=definition.rate_limit,
                )
                if retry_after is not None:
                    execution_time = time.time() - start_time
                    self._audit_tool_call(
                        definition,
                        arguments=arguments,
                        status="rate_limited",
                        execution_time=execution_time,
                    )
                    return json.dumps(
                        {
                            "error": "Tool rate limit exceeded",
                            "error_code": "TOOL_RATE_LIMITED",
                            "retry_after_seconds": max(
                                1,
                                math.ceil(retry_after),
                            ),
                            "timestamp": datetime.now().isoformat(),
                        },
                        ensure_ascii=False,
                        indent=2,
                    )
            handler = definition.bind_handler(self)
            prepared_arguments = definition.prepare_arguments(arguments)
            result = await handler(prepared_arguments)
            execution_time = time.time() - start_time

            # Add execution information
            if isinstance(result, dict) and definition.provider_name is None:
                result["_execution_info"] = {
                    "tool_name": name,
                    "canonical_tool_name": definition.canonical_name,
                    "audit_event": definition.audit.event_name,
                    "execution_time": round(execution_time, 3),
                    "timestamp": datetime.now().isoformat(),
                }

            self._audit_tool_call(
                definition,
                arguments=prepared_arguments,
                status="success",
                execution_time=execution_time,
            )
            return json.dumps(result, ensure_ascii=False, indent=2)

        except OperationAuthorizationError:
            raise
        except Exception as e:
            if definition is not None:
                self._audit_tool_call(
                    definition,
                    arguments=arguments,
                    status="error",
                    execution_time=time.time() - start_time,
                )
            logger.error(
                "Tool call failed (%s)",
                type(e).__name__,
            )
            error_result = {
                "error": "Tool execution failed",
                "error_code": "TOOL_EXECUTION_FAILED",
                "timestamp": datetime.now().isoformat(),
            }
            return json.dumps(error_result, ensure_ascii=False, indent=2)

    @staticmethod
    def _audit_tool_call(
        definition: ToolDefinition,
        *,
        arguments: dict[str, Any],
        status: str,
        execution_time: float,
    ) -> None:
        audit = definition.audit
        provided_names = sorted(
            set(arguments).intersection(audit.argument_names)
        )
        get_audit_logger().info(
            "event=%s tool=%s canonical_tool=%s category=%s risk=%s "
            "status=%s duration_ms=%d argument_names=%s",
            audit.event_name,
            definition.name,
            definition.canonical_name,
            audit.category,
            audit.risk,
            status,
            round(execution_time * 1000),
            ",".join(provided_names),
        )

    async def _exec_query_tool(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """SQL query execution tool routing (supports federation queries)"""
        sql = self._required_string(arguments, "sql")
        db_name = arguments.get("db_name")
        catalog_name = arguments.get("catalog_name")
        max_rows = arguments.get(
            "max_rows",
            configured_default_result_rows(self.connection_manager.config),
        )
        max_bytes = arguments.get("max_bytes")
        timeout = arguments.get("timeout", 30)

        # Delegate to metadata extractor for processing
        return await self.metadata_extractor.exec_query_for_mcp(
            sql,
            db_name,
            catalog_name,
            max_rows,
            timeout,
            max_bytes=max_bytes,
        )

    async def _get_table_schema_tool(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Get table schema tool routing"""
        table_name = self._required_string(arguments, "table_name")
        db_name = arguments.get("db_name")
        catalog_name = arguments.get("catalog_name")

        # Delegate to metadata extractor for processing
        return await self.metadata_extractor.get_table_schema_for_mcp(
            table_name, db_name, catalog_name
        )

    async def _get_db_table_list_tool(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Get database table list tool routing"""
        db_name = arguments.get("db_name")
        catalog_name = arguments.get("catalog_name")

        # Delegate to metadata extractor for processing
        return await self.metadata_extractor.get_db_table_list_for_mcp(
            db_name, catalog_name
        )

    async def _get_db_list_tool(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Get database list tool routing"""
        catalog_name = arguments.get("catalog_name")

        # Delegate to metadata extractor for processing
        return await self.metadata_extractor.get_db_list_for_mcp(catalog_name)

    async def _get_table_comment_tool(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Get table comment tool routing"""
        table_name = self._required_string(arguments, "table_name")
        db_name = arguments.get("db_name")
        catalog_name = arguments.get("catalog_name")

        # Delegate to metadata extractor for processing
        return await self.metadata_extractor.get_table_comment_for_mcp(
            table_name, db_name, catalog_name
        )

    async def _get_table_column_comments_tool(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Get table column comments tool routing"""
        table_name = self._required_string(arguments, "table_name")
        db_name = arguments.get("db_name")
        catalog_name = arguments.get("catalog_name")

        # Delegate to metadata extractor for processing
        return await self.metadata_extractor.get_table_column_comments_for_mcp(
            table_name, db_name, catalog_name
        )

    async def _get_table_indexes_tool(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Get table indexes tool routing"""
        table_name = self._required_string(arguments, "table_name")
        db_name = arguments.get("db_name")
        catalog_name = arguments.get("catalog_name")

        # Delegate to metadata extractor for processing
        return await self.metadata_extractor.get_table_indexes_for_mcp(
            table_name, db_name, catalog_name
        )

    async def _get_recent_audit_logs_tool(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Get audit logs tool routing"""
        days = arguments.get("days", 7)
        limit = arguments.get("limit", 100)

        # Delegate to metadata extractor for processing
        return await self.metadata_extractor.get_recent_audit_logs_for_mcp(days, limit)

    async def _get_catalog_list_tool(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Get catalog list tool routing"""
        # random_string parameter is required in the source project, but not actually used in business logic
        # Here we ignore it and directly call business logic

        # Delegate to metadata extractor for processing
        return await self.metadata_extractor.get_catalog_list_for_mcp()

    async def _get_sql_explain_tool(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """SQL Explain tool routing"""
        sql = self._required_string(arguments, "sql")
        verbose = arguments.get("verbose", False)
        db_name = arguments.get("db_name")
        catalog_name = arguments.get("catalog_name")

        # Delegate to SQL analyzer for processing
        return await self.sql_analyzer.get_sql_explain(
            sql, verbose, db_name, catalog_name
        )

    async def _get_sql_profile_tool(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """SQL Profile tool routing"""
        sql = self._required_string(arguments, "sql")
        db_name = arguments.get("db_name")
        catalog_name = arguments.get("catalog_name")
        timeout = arguments.get("timeout", 30)

        # Delegate to SQL analyzer for processing
        return await self.sql_analyzer.get_sql_profile(
            sql, db_name, catalog_name, timeout
        )

    async def _get_table_data_size_tool(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Table data size tool routing"""
        db_name = arguments.get("db_name")
        table_name = arguments.get("table_name")
        single_replica = arguments.get("single_replica", False)

        # Delegate to SQL analyzer for processing
        return await self.sql_analyzer.get_table_data_size(
            db_name, table_name, single_replica
        )

    async def _get_monitoring_metrics_tool(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
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
                role,
                monitor_type,
                priority,
                info_only=False,
                format_type="prometheus",
                include_raw_metrics=include_raw_metrics,
            )
        elif content_type == "both":
            # Get both definitions and data
            definitions = await self.monitoring_tools.get_monitoring_metrics(
                role, monitor_type, priority, info_only=True, format_type="prometheus"
            )
            data = await self.monitoring_tools.get_monitoring_metrics(
                role,
                monitor_type,
                priority,
                info_only=False,
                format_type="prometheus",
                include_raw_metrics=include_raw_metrics,
            )
            return {
                "content_type": "both",
                "definitions": definitions,
                "data": data,
                "timestamp": data.get("timestamp"),
                "_execution_info": {
                    "combined_response": True,
                    "definitions_available": definitions.get("success", False),
                    "data_available": data.get("success", False),
                },
            }
        else:
            return {
                "error": f"Invalid content_type: {content_type}. Must be 'definitions', 'data', or 'both'"
            }

    async def _get_memory_stats_tool(self, arguments: dict[str, Any]) -> dict[str, Any]:
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
                    "historical_available": historical.get("success", False),
                },
            }
        else:
            return {
                "error": f"Invalid data_type: {data_type}. Must be 'realtime', 'historical', or 'both'"
            }

    # Legacy tool methods (for backward compatibility)
    async def _get_monitoring_metrics_info_tool(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """[DEPRECATED] Use get_monitoring_metrics with content_type='definitions'"""
        arguments["content_type"] = "definitions"
        return await self._get_monitoring_metrics_tool(arguments)

    async def _get_monitoring_metrics_data_tool(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """[DEPRECATED] Use get_monitoring_metrics with content_type='data'"""
        arguments["content_type"] = "data"
        return await self._get_monitoring_metrics_tool(arguments)

    async def _get_realtime_memory_stats_tool(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """[DEPRECATED] Use get_memory_stats with data_type='realtime'"""
        arguments["data_type"] = "realtime"
        return await self._get_memory_stats_tool(arguments)

    async def _get_historical_memory_stats_tool(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """[DEPRECATED] Use get_memory_stats with data_type='historical'"""
        arguments["data_type"] = "historical"
        return await self._get_memory_stats_tool(arguments)

    # ==================== v0.5.0 Advanced Analytics Tools Private Methods ====================

    async def _get_table_basic_info_tool(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Get table basic information tool routing"""
        try:
            table_name = self._required_string(arguments, "table_name")
            catalog_name = arguments.get("catalog_name")
            db_name = arguments.get("db_name")

            # Delegate to atomic data quality tools
            result = await self.data_quality_tools.get_table_basic_info(
                table_name=table_name, catalog_name=catalog_name, db_name=db_name
            )

            return result

        except Exception as e:
            return {
                "error": str(e),
                "analysis_type": "table_basic_info",
                "timestamp": datetime.now().isoformat(),
            }

    async def _analyze_columns_tool(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Analyze columns tool routing"""
        try:
            table_name = self._required_string(arguments, "table_name")
            columns = self._required_string_list(arguments, "columns")
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
                detailed_response=detailed_response,
            )

            return result

        except Exception as e:
            return {
                "error": str(e),
                "analysis_type": "columns_analysis",
                "timestamp": datetime.now().isoformat(),
            }

    async def _analyze_table_storage_tool(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Analyze table storage tool routing"""
        try:
            table_name = self._required_string(arguments, "table_name")
            catalog_name = arguments.get("catalog_name")
            db_name = arguments.get("db_name")
            detailed_response = arguments.get("detailed_response", False)

            # Delegate to atomic data quality tools
            result = await self.data_quality_tools.analyze_table_storage(
                table_name=table_name,
                catalog_name=catalog_name,
                db_name=db_name,
                detailed_response=detailed_response,
            )

            return result

        except Exception as e:
            return {
                "error": str(e),
                "analysis_type": "table_storage_analysis",
                "timestamp": datetime.now().isoformat(),
            }

    async def _trace_column_lineage_tool(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Column lineage tracing tool routing"""
        target_columns = arguments.get("target_columns")
        analysis_depth = arguments.get("analysis_depth", 3)
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
                        results[column_spec] = {
                            "error": f"Invalid column specification format: {column_spec}. Expected 'table.column' or 'db.table.column'"
                        }
                        continue

                    result = await self.data_governance_tools.trace_column_lineage(
                        table_name=table_name,
                        column_name=column_name,
                        depth=analysis_depth,
                        catalog_name=catalog_name,
                        db_name=db_name,
                    )
                    results[column_spec] = result

                except Exception as e:
                    results[column_spec] = {
                        "error": f"Failed to trace lineage for {column_spec}: {str(e)}"
                    }

            return {
                "multi_column_lineage": True,
                "column_count": len(target_columns),
                "analysis_timestamp": list(results.values())[0].get(
                    "analysis_timestamp"
                )
                if results
                else None,
                "results": results,
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
                return {
                    "error": f"Invalid column specification format: {column_spec}. Expected 'table.column' or 'db.table.column'"
                }

            return await self.data_governance_tools.trace_column_lineage(
                table_name=table_name,
                column_name=column_name,
                depth=analysis_depth,
                catalog_name=catalog_name,
                db_name=db_name,
            )

    async def _monitor_data_freshness_tool(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Data freshness monitoring tool routing"""
        table_names = arguments.get("table_names")
        freshness_threshold_hours = arguments.get("freshness_threshold_hours", 24)
        if freshness_threshold_hours is None:
            freshness_threshold_hours = 24
        catalog_name = arguments.get("catalog_name")
        db_name = arguments.get("db_name")

        # Delegate to data governance tools for processing
        return await self.data_governance_tools.monitor_data_freshness(
            tables=table_names,
            time_threshold_hours=freshness_threshold_hours,
            catalog_name=catalog_name,
            db_name=db_name,
        )

    async def _analyze_data_access_patterns_tool(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Data access patterns analysis tool routing"""
        days = arguments.get("days", 7)
        include_system_users = arguments.get("include_system_users", False)
        min_query_threshold = arguments.get("min_query_threshold", 5)

        # Delegate to security analytics tools for processing
        return await self.security_analytics_tools.analyze_data_access_patterns(
            days, include_system_users, min_query_threshold
        )

    async def _analyze_data_flow_dependencies_tool(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
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

    async def _analyze_slow_queries_topn_tool(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Slow queries Top-N analysis tool routing"""
        days = arguments.get("days", 7)
        top_n = arguments.get("top_n", 20)
        min_execution_time_ms = arguments.get("min_execution_time_ms", 1000)
        include_patterns = arguments.get("include_patterns", True)

        # Delegate to performance analytics tools for processing
        return await self.performance_analytics_tools.analyze_slow_queries_topn(
            days, top_n, min_execution_time_ms, include_patterns
        )

    async def _analyze_resource_growth_curves_tool(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Resource growth curves analysis tool routing"""
        days = arguments.get("days", 30)
        resource_types = arguments.get(
            "resource_types", ["storage", "query_volume", "user_activity"]
        )
        include_predictions = arguments.get("include_predictions", False)
        detailed_response = arguments.get("detailed_response", False)

        # Delegate to performance analytics tools for processing
        return await self.performance_analytics_tools.analyze_resource_growth_curves(
            days, resource_types, include_predictions, detailed_response
        )

    # ==================== ADBC Query Tools Private Methods ====================

    async def _exec_adbc_query_tool(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """ADBC query execution tool routing"""
        sql = self._required_string(arguments, "sql")
        max_rows = arguments.get("max_rows")
        max_bytes = arguments.get("max_bytes")
        timeout = arguments.get("timeout")
        return_format = arguments.get("return_format")

        # Delegate to ADBC query tools for processing
        return await self.adbc_query_tools.exec_adbc_query(
            sql,
            max_rows=max_rows,
            timeout=timeout,
            return_format=return_format,
            max_bytes=max_bytes,
        )

    async def _get_adbc_connection_info_tool(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """ADBC connection information tool routing"""
        # Delegate to ADBC query tools for processing
        return await self.adbc_query_tools.get_adbc_connection_info()
