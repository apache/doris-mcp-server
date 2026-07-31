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

import secrets
from collections.abc import Iterable
from datetime import datetime
from typing import Any

from mcp.types import Tool

from ..auth.operation_policy import authorize_operation
from ..state_handles import StateHandleCodec
from ..utils.adbc_query_tools import DorisADBCQueryTools
from ..utils.analysis_tools import SQLAnalyzer, TableAnalyzer
from ..utils.data_exploration_tools import DataExplorationTools
from ..utils.data_governance_tools import DataGovernanceTools
from ..utils.data_quality_tools import DataQualityTools
from ..utils.db import DorisConnectionManager
from ..utils.dependency_analysis_tools import DependencyAnalysisTools
from ..utils.logger import get_audit_logger, get_logger
from ..utils.monitoring_tools import DorisMonitoringTools
from ..utils.query_executor import DorisQueryExecutor
from ..utils.schema_extractor import MetadataExtractor
from ..utils.security import get_current_auth_context
from ..utils.security_analytics_tools import SecurityAnalyticsTools
from .capability_detector import DorisCapabilityDetector
from .capability_registry import (
    CapabilityEvaluator,
    CapabilityProviderRegistry,
    CapabilityRegistry,
)
from .catalog_handlers import CatalogToolHandlersMixin
from .cluster_handlers import ClusterToolHandlersMixin
from .domain_catalog import CURRENT_FLAT_TOOL_NAMES
from .domain_dispatcher import (
    BoundHandlerAvailabilityProvider,
    DomainDispatcher,
    ToolExposureMode,
    ToolNotFoundError,
    serialize_dispatch_result,
)
from .domain_manifest import (
    DomainAvailabilityProvider,
    DomainManifestManagerMixin,
    DomainManifestService,
)
from .doris_feature_matrix import DORIS_FEATURE_MATRIX
from .query_handlers import QueryToolHandlersMixin
from .tool_provider import CustomToolProvider, ToolProviderRuntime
from .tool_registry import ToolRegistryError

logger = get_logger(__name__)


class DorisToolsManager(
    QueryToolHandlersMixin,
    CatalogToolHandlersMixin,
    ClusterToolHandlersMixin,
    DomainManifestManagerMixin,
):
    """Apache Doris Tools Manager"""

    def __init__(
        self,
        connection_manager: DorisConnectionManager,
        *,
        tool_providers: Iterable[CustomToolProvider] | None = None,
        domain_availability_provider: DomainAvailabilityProvider | None = None,
        tool_exposure_mode: str | ToolExposureMode | None = None,
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
        self._initialize_catalog_handlers(connection_manager)
        self.monitoring_tools = DorisMonitoringTools(connection_manager)
        self._initialize_cluster_handlers(
            connection_manager,
            self.monitoring_tools,
        )

        # Initialize v0.5.0 advanced analytics tools
        self.data_governance_tools = DataGovernanceTools(connection_manager)
        self.data_exploration_tools = DataExplorationTools(connection_manager)
        self.data_quality_tools = DataQualityTools(
            connection_manager, connection_manager.config
        )
        self.security_analytics_tools = SecurityAnalyticsTools(connection_manager)
        self.dependency_analysis_tools = DependencyAnalysisTools(connection_manager)

        # Initialize ADBC query tools
        self.adbc_query_tools = DorisADBCQueryTools(connection_manager)
        self._initialize_query_handlers(
            connection_manager,
            self.adbc_query_tools,
        )
        self._capability_registry: CapabilityRegistry | None = None
        if domain_availability_provider is None:
            bound_handlers = BoundHandlerAvailabilityProvider(self)
            capability_config = getattr(config, "capability", None)
            detector = DorisCapabilityDetector(
                connection_manager,
                probe_timeout_seconds=getattr(
                    capability_config,
                    "probe_timeout_seconds",
                    5,
                ),
                snapshot_ttl_seconds=getattr(
                    capability_config,
                    "snapshot_ttl_seconds",
                    300,
                ),
                stale_grace_seconds=getattr(
                    capability_config,
                    "stale_grace_seconds",
                    900,
                ),
                adbc_query_tools=self.adbc_query_tools,
            )
            provider_registry = CapabilityProviderRegistry.from_runtime(
                matrix=DORIS_FEATURE_MATRIX,
                bound_handlers=bound_handlers,
                config=config,
            )
            self._capability_registry = CapabilityRegistry(
                detector=detector,
                provider_registry=provider_registry,
                evaluator=CapabilityEvaluator(
                    matrix=DORIS_FEATURE_MATRIX,
                    bound_handlers=bound_handlers,
                ),
            )
            domain_availability_provider = self._capability_registry
        self._domain_manifest_service = DomainManifestService(
            availability_provider=domain_availability_provider,
        )
        configured_mode = getattr(
            getattr(config, "tool_exposure", None),
            "mode",
            ToolExposureMode.HIERARCHICAL.value,
        )
        if not isinstance(configured_mode, str | ToolExposureMode):
            configured_mode = ToolExposureMode.HIERARCHICAL.value
        self._tool_exposure_mode = ToolExposureMode.parse(
            tool_exposure_mode or configured_mode
        )
        state_handle_secret = getattr(
            config,
            "mcp_state_handle_secret",
            None,
        )
        if not isinstance(state_handle_secret, str | bytes) or len(
            state_handle_secret
        ) < 32:
            state_handle_secret = secrets.token_urlsafe(32)
        state_handle_ttl = getattr(
            config,
            "mcp_state_handle_ttl_seconds",
            300,
        )
        if not isinstance(state_handle_ttl, int):
            state_handle_ttl = 300
        self._domain_dispatcher = DomainDispatcher(
            self,
            self._domain_manifest_service,
            state_handle_codec=StateHandleCodec(
                state_handle_secret,
                default_ttl_seconds=state_handle_ttl,
            ),
        )
        self._validate_custom_tool_names()

        logger.info(
            "DorisToolsManager initialized with business logic processors, v0.5.0 "
            "analytics tools, ADBC query tools, %s tool exposure, and %d custom "
            "tool providers",
            self._tool_exposure_mode.value,
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
        if self._capability_registry is not None:
            await self._capability_registry.close()
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

    @property
    def tool_exposure_mode(self) -> ToolExposureMode:
        """Return the exact configured public tool-list shape."""
        return self._tool_exposure_mode

    @property
    def domain_dispatcher(self) -> DomainDispatcher:
        """Return the sole production child dispatcher."""
        return self._domain_dispatcher

    def _validate_custom_tool_names(self) -> None:
        """Reserve every 1.0 public and removed pre-1.0 tool name."""
        reserved = (
            set(self.domain_manifest_service.domain_names)
            | set(self._domain_dispatcher.formal_flat_names)
            | set(CURRENT_FLAT_TOOL_NAMES)
        )
        custom_names: set[str] = set()
        for _, custom_tool in self._tool_provider_runtime.custom_tools():
            name = custom_tool.tool.name
            if name in reserved or name in custom_names:
                raise ToolRegistryError(f"Duplicate tool definition: {name}")
            custom_names.add(name)

    async def list_tools(self) -> list[Tool]:
        """List either eight domains or 47 formal flat children."""
        if self._tool_exposure_mode is ToolExposureMode.HIERARCHICAL:
            return await super().list_tools()
        return await self._domain_dispatcher.list_flat_tools(
            get_current_auth_context()
        )

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> str:
        """Call only a registered domain or formal flat child by exact name."""
        auth_context = get_current_auth_context()
        if self._tool_exposure_mode is ToolExposureMode.HIERARCHICAL:
            if not self.domain_manifest_service.handles(name):
                raise ToolNotFoundError(name)
            authorize_operation(auth_context, f"tool:{name}")
            result = await self._domain_dispatcher.call_domain(
                name,
                arguments,
                auth_context,
            )
            if getattr(result, "mode", None) == "manifest":
                get_audit_logger().info(
                    "event=mcp.tool.call.%s tool=%s category=domain "
                    "risk=metadata status=success argument_names=%s",
                    name,
                    name,
                    ",".join(sorted(arguments)),
                )
            return serialize_dispatch_result(result)

        if not self._domain_dispatcher.handles_flat(name):
            raise ToolNotFoundError(name)
        result = await self._domain_dispatcher.call_flat(
            name,
            arguments,
            auth_context,
        )
        return serialize_dispatch_result(result)

    async def _get_recent_audit_logs_tool(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Get audit logs tool routing"""
        days = arguments.get("days", 7)
        limit = arguments.get("limit", 100)

        # Delegate to metadata extractor for processing
        return await self.metadata_extractor.get_recent_audit_logs_for_mcp(days, limit)

    async def _get_monitoring_metrics_tool(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Route the migrated metric child through the strict Cluster runtime."""
        return await self.cluster_runtime.get_monitoring_metrics(
            metric_names=arguments.get("metric_names"),
            node_ids=arguments.get("node_ids"),
            window=arguments.get("window"),
        )

    async def _get_memory_stats_tool(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Route the migrated memory child without placeholder values."""
        detail = {
            "overview": "summary",
            "all": "trackers",
        }.get(
            str(arguments.get("tracker_type", "")),
            arguments.get("detail", "summary"),
        )
        return await self.cluster_runtime.get_memory_stats(
            node_ids=arguments.get("node_ids"),
            detail=detail,
        )

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

    async def _analyze_resource_growth_curves_tool(
        self, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Route the migrated growth child through recorded Doris evidence."""
        resource_types = arguments.get("resource_types")
        resource = (
            resource_types[0]
            if isinstance(resource_types, list) and len(resource_types) == 1
            else arguments.get("resource")
        )
        return await self.cluster_runtime.analyze_resource_growth(
            resource=resource,
            window_days=arguments.get("days", arguments.get("window_days")),
            granularity=arguments.get("granularity"),
        )
