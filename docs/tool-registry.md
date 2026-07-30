# Doris MCP Tool Registry

<!-- Generated from ToolDefinitionRegistry; do not edit by hand. -->

| Tool | Policy | Risk | Handler | Audit event | Parameters |
|---|---|---|---|---|---|
| `exec_query` | `query` | `query` | `_exec_query_tool` | `mcp.tool.call.exec_query` | `catalog_name`, `db_name`, `max_bytes`, `max_rows`, `sql`*, `timeout` |
| `get_table_schema` | `metadata` | `metadata` | `_get_table_schema_tool` | `mcp.tool.call.get_table_schema` | `catalog_name`, `db_name`, `table_name`* |
| `get_db_table_list` | `metadata` | `metadata` | `_get_db_table_list_tool` | `mcp.tool.call.get_db_table_list` | `catalog_name`, `db_name` |
| `get_db_list` | `metadata` | `metadata` | `_get_db_list_tool` | `mcp.tool.call.get_db_list` | `catalog_name` |
| `get_table_comment` | `metadata` | `metadata` | `_get_table_comment_tool` | `mcp.tool.call.get_table_comment` | `catalog_name`, `db_name`, `table_name`* |
| `get_table_column_comments` | `metadata` | `metadata` | `_get_table_column_comments_tool` | `mcp.tool.call.get_table_column_comments` | `catalog_name`, `db_name`, `table_name`* |
| `get_table_indexes` | `metadata` | `metadata` | `_get_table_indexes_tool` | `mcp.tool.call.get_table_indexes` | `catalog_name`, `db_name`, `table_name`* |
| `get_recent_audit_logs` | `restricted` | `high` | `_get_recent_audit_logs_tool` | `mcp.tool.call.get_recent_audit_logs` | `days`, `limit` |
| `get_catalog_list` | `metadata` | `metadata` | `_get_catalog_list_tool` | `mcp.tool.call.get_catalog_list` | `random_string`* |
| `get_sql_explain` | `explain` | `explain` | `_get_sql_explain_tool` | `mcp.tool.call.get_sql_explain` | `catalog_name`, `db_name`, `sql`*, `verbose` |
| `get_sql_profile` | `restricted` | `high` | `_get_sql_profile_tool` | `mcp.tool.call.get_sql_profile` | `catalog_name`, `db_name`, `sql`*, `timeout` |
| `get_table_data_size` | `restricted` | `high` | `_get_table_data_size_tool` | `mcp.tool.call.get_table_data_size` | `db_name`, `single_replica`, `table_name` |
| `get_monitoring_metrics` | `restricted` | `high` | `_get_monitoring_metrics_tool` | `mcp.tool.call.get_monitoring_metrics` | `content_type`, `include_raw_metrics`, `monitor_type`, `priority`, `role` |
| `get_memory_stats` | `restricted` | `high` | `_get_memory_stats_tool` | `mcp.tool.call.get_memory_stats` | `data_type`, `include_details`, `time_range`, `tracker_names`, `tracker_type` |
| `get_table_basic_info` | `restricted` | `high` | `_get_table_basic_info_tool` | `mcp.tool.call.get_table_basic_info` | `catalog_name`, `db_name`, `table_name`* |
| `analyze_columns` | `restricted` | `high` | `_analyze_columns_tool` | `mcp.tool.call.analyze_columns` | `analysis_types`, `catalog_name`, `columns`*, `db_name`, `detailed_response`, `sample_size`, `table_name`* |
| `analyze_table_storage` | `restricted` | `high` | `_analyze_table_storage_tool` | `mcp.tool.call.analyze_table_storage` | `catalog_name`, `db_name`, `detailed_response`, `table_name`* |
| `trace_column_lineage` | `restricted` | `high` | `_trace_column_lineage_tool` | `mcp.tool.call.trace_column_lineage` | `analysis_depth`, `catalog_name`, `include_transformations`, `target_columns`* |
| `monitor_data_freshness` | `restricted` | `high` | `_monitor_data_freshness_tool` | `mcp.tool.call.monitor_data_freshness` | `catalog_name`, `db_name`, `freshness_threshold_hours`, `include_update_patterns`, `table_names` |
| `analyze_data_access_patterns` | `restricted` | `high` | `_analyze_data_access_patterns_tool` | `mcp.tool.call.analyze_data_access_patterns` | `days`, `include_system_users`, `min_query_threshold` |
| `analyze_data_flow_dependencies` | `restricted` | `high` | `_analyze_data_flow_dependencies_tool` | `mcp.tool.call.analyze_data_flow_dependencies` | `analysis_depth`, `catalog_name`, `db_name`, `include_views`, `target_table` |
| `analyze_slow_queries_topn` | `restricted` | `high` | `_analyze_slow_queries_topn_tool` | `mcp.tool.call.analyze_slow_queries_topn` | `days`, `include_patterns`, `min_execution_time_ms`, `top_n` |
| `analyze_resource_growth_curves` | `restricted` | `high` | `_analyze_resource_growth_curves_tool` | `mcp.tool.call.analyze_resource_growth_curves` | `days`, `detailed_response`, `include_predictions`, `resource_types` |
| `exec_adbc_query` | `restricted` | `high` | `_exec_adbc_query_tool` | `mcp.tool.call.exec_adbc_query` | `max_bytes`, `max_rows`, `return_format`, `sql`*, `timeout` |
| `get_adbc_connection_info` | `restricted` | `high` | `_get_adbc_connection_info_tool` | `mcp.tool.call.get_adbc_connection_info` | None |

Required parameters are marked with `*`. Tool descriptions and JSON Schemas are exposed directly by MCP `tools/list` from the same registry entries.
