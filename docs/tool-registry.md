<!--
  ~ Licensed to the Apache Software Foundation (ASF) under one
  ~ or more contributor license agreements.  See the NOTICE file
  ~ distributed with this work for additional information
  ~ regarding copyright ownership.  The ASF licenses this file
  ~ to you under the Apache License, Version 2.0 (the
  ~ "License"); you may not use this file except in compliance
  ~ with the License.  You may obtain a copy of the License at
  ~
  ~   http://www.apache.org/licenses/LICENSE-2.0
  ~
  ~ Unless required by applicable law or agreed to in writing,
  ~ software distributed under the License is distributed on an
  ~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  ~ KIND, either express or implied.  See the License for the
  ~ specific language governing permissions and limitations
  ~ under the License.
-->

# Doris MCP Hierarchical Domain Catalog

<!-- Generated from DorisDomainCatalog; do not edit by hand. -->

| Domain | Child count | Enablement | Discovery |
|---|---:|---|---|
| `doris_catalog` | 5 | `readonly_domain_enabled` | `authorized_child_discovery` |
| `doris_query` | 7 | `readonly_domain_enabled` | `authorized_child_discovery` |
| `doris_cluster` | 11 | `readonly_domain_enabled` | `authorized_child_discovery` |
| `doris_pipeline` | 5 | `readonly_domain_enabled` | `authorized_child_discovery` |
| `doris_search` | 4 | `readonly_domain_enabled` | `authorized_child_discovery` |
| `doris_governance` | 8 | `readonly_domain_enabled` | `authorized_child_discovery` |
| `doris_lakehouse` | 3 | `readonly_domain_enabled` | `authorized_child_discovery` |
| `doris_semantic` | 12 | `readonly_domain_enabled` | `authorized_child_discovery` |

## Formal child tools

| Feature ID | Handler binding | Authorization | Variants |
|---|---|---|---|
| `doris_catalog.list_catalogs` | `child:doris_catalog:list_catalogs` | `child:call:doris_catalog:list_catalogs` | `catalog_metadata` |
| `doris_catalog.list_databases` | `child:doris_catalog:list_databases` | `child:call:doris_catalog:list_databases` | `database_metadata` |
| `doris_catalog.list_tables` | `child:doris_catalog:list_tables` | `child:call:doris_catalog:list_tables` | `table_metadata` |
| `doris_catalog.get_table_context` | `child:doris_catalog:get_table_context` | `child:call:doris_catalog:get_table_context` | `base_sections`, `vector_search_metadata`, `variant_v3_metadata` |
| `doris_catalog.get_table_size` | `child:doris_catalog:get_table_size` | `child:call:doris_catalog:get_table_size` | `partition_statistics` |
| `doris_query.execute_query` | `child:doris_query:execute_query` | `child:call:doris_query:execute_query` | `mysql_read_only` |
| `doris_query.explain_query` | `child:doris_query:explain_query` | `child:call:doris_query:explain_query` | `base_explain`, `search_plan_facets` |
| `doris_query.get_query_profile` | `child:doris_query:get_query_profile` | `child:call:doris_query:get_query_profile` | `query_profile` |
| `doris_query.diagnose_query_performance` | `child:doris_query:diagnose_query_performance` | `child:call:doris_query:diagnose_query_performance` | `deterministic_query_diagnosis` |
| `doris_query.list_slow_queries` | `child:doris_query:list_slow_queries` | `child:call:doris_query:list_slow_queries` | `audit_slow_queries` |
| `doris_query.get_adbc_connection_info` | `child:doris_query:get_adbc_connection_info` | `child:call:doris_query:get_adbc_connection_info` | `adbc_flight_sql` |
| `doris_query.execute_adbc_query` | `child:doris_query:execute_adbc_query` | `child:call:doris_query:execute_adbc_query` | `adbc_read_only` |
| `doris_cluster.get_cluster_overview` | `child:doris_cluster:get_cluster_overview` | `child:call:doris_cluster:get_cluster_overview` | `cluster_summary` |
| `doris_cluster.list_cluster_nodes` | `child:doris_cluster:list_cluster_nodes` | `child:call:doris_cluster:list_cluster_nodes` | `cluster_nodes` |
| `doris_cluster.list_active_tasks` | `child:doris_cluster:list_active_tasks` | `child:call:doris_cluster:list_active_tasks` | `unified_task_progress`, `legacy_task_views` |
| `doris_cluster.get_monitoring_metrics` | `child:doris_cluster:get_monitoring_metrics` | `child:call:doris_cluster:get_monitoring_metrics` | `observability_4_0_7`, `base_metrics` |
| `doris_cluster.get_memory_stats` | `child:doris_cluster:get_memory_stats` | `child:call:doris_cluster:get_memory_stats` | `memory_trackers` |
| `doris_cluster.get_cache_status` | `child:doris_cluster:get_cache_status` | `child:call:doris_cluster:get_cache_status` | `advanced_cache_types`, `file_cache_queue_metrics`, `file_cache` |
| `doris_cluster.get_compaction_status` | `child:doris_cluster:get_compaction_status` | `child:call:doris_cluster:get_compaction_status` | `compaction_task_tracker`, `legacy_compaction_summary` |
| `doris_cluster.get_workload_group_status` | `child:doris_cluster:get_workload_group_status` | `child:call:doris_cluster:get_workload_group_status` | `workload_group_metrics` |
| `doris_cluster.get_compute_group_status` | `child:doris_cluster:get_compute_group_status` | `child:call:doris_cluster:get_compute_group_status` | `compute_group` |
| `doris_cluster.analyze_resource_growth` | `child:doris_cluster:analyze_resource_growth` | `child:call:doris_cluster:analyze_resource_growth` | `historical_resource_metrics` |
| `doris_cluster.get_runtime_capabilities` | `child:doris_cluster:get_runtime_capabilities` | `child:call:doris_cluster:get_runtime_capabilities` | `capability_snapshot` |
| `doris_pipeline.get_ingestion_status` | `child:doris_pipeline:get_ingestion_status` | `child:call:doris_pipeline:get_ingestion_status` | `load_jobs`, `continuous_load` |
| `doris_pipeline.diagnose_ingestion` | `child:doris_pipeline:diagnose_ingestion` | `child:call:doris_pipeline:diagnose_ingestion` | `deterministic_ingestion_diagnosis` |
| `doris_pipeline.get_materialized_view_status` | `child:doris_pipeline:get_materialized_view_status` | `child:call:doris_pipeline:get_materialized_view_status` | `materialized_view_metadata`, `mtmv_compute_group` |
| `doris_pipeline.monitor_data_freshness` | `child:doris_pipeline:monitor_data_freshness` | `child:call:doris_pipeline:monitor_data_freshness` | `freshness_evidence` |
| `doris_pipeline.analyze_data_dependencies` | `child:doris_pipeline:analyze_data_dependencies` | `child:call:doris_pipeline:analyze_data_dependencies` | `audit_sql_dependencies` |
| `doris_search.search_data` | `child:doris_search:search_data` | `child:call:doris_search:search_data` | `vector_hybrid_search`, `inverted_text_search` |
| `doris_search.preview_text_analysis` | `child:doris_search:preview_text_analysis` | `child:call:doris_search:preview_text_analysis` | `tokenizer_preview` |
| `doris_search.inspect_search_indexes` | `child:doris_search:inspect_search_indexes` | `child:call:doris_search:inspect_search_indexes` | `ann_index_metadata`, `inverted_index_metadata` |
| `doris_search.diagnose_search_query` | `child:doris_search:diagnose_search_query` | `child:call:doris_search:diagnose_search_query` | `search_query_diagnosis` |
| `doris_governance.analyze_columns` | `child:doris_governance:analyze_columns` | `child:call:doris_governance:analyze_columns` | `column_statistics` |
| `doris_governance.analyze_table_storage` | `child:doris_governance:analyze_table_storage` | `child:call:doris_governance:analyze_table_storage` | `base_storage`, `storage_v3_variant` |
| `doris_governance.get_lineage_capability_status` | `child:doris_governance:get_lineage_capability_status` | `child:call:doris_governance:get_lineage_capability_status` | `audit_lineage_status`, `native_lineage_status` |
| `doris_governance.trace_column_lineage` | `child:doris_governance:trace_column_lineage` | `child:call:doris_governance:trace_column_lineage` | `audit_sql_inference_primary`, `native_lineage_events`, `audit_sql_inference_fallback` |
| `doris_governance.analyze_data_access_patterns` | `child:doris_governance:analyze_data_access_patterns` | `child:call:doris_governance:analyze_data_access_patterns` | `audit_access_history` |
| `doris_governance.get_recent_audit_logs` | `child:doris_governance:get_recent_audit_logs` | `child:call:doris_governance:get_recent_audit_logs` | `audit_log`, `audit_log_4_0_7` |
| `doris_governance.list_udfs` | `child:doris_governance:list_udfs` | `child:call:doris_governance:list_udfs` | `base_udf_metadata`, `python_udf_family` |
| `doris_governance.get_auth_mapping_status` | `child:doris_governance:get_auth_mapping_status` | `child:call:doris_governance:get_auth_mapping_status` | `ldap_mapping`, `oidc_role_mapping` |
| `doris_lakehouse.inspect_external_catalog` | `child:doris_lakehouse:inspect_external_catalog` | `child:call:doris_lakehouse:inspect_external_catalog` | `external_catalog_metadata` |
| `doris_lakehouse.inspect_lakehouse_table` | `child:doris_lakehouse:inspect_lakehouse_table` | `child:call:doris_lakehouse:inspect_lakehouse_table` | `lakehouse_lifecycle_4_1`, `lakehouse_table_metadata` |
| `doris_lakehouse.inspect_variant_column` | `child:doris_lakehouse:inspect_variant_column` | `child:call:doris_lakehouse:inspect_variant_column` | `variant_advanced_4_1`, `variant_type` |
| `doris_semantic.list_semantic_models` | `child:doris_semantic:list_semantic_models` | `child:call:doris_semantic:list_semantic_models` | `ossie_model_registry` |
| `doris_semantic.get_semantic_model_summary` | `child:doris_semantic:get_semantic_model_summary` | `child:call:doris_semantic:get_semantic_model_summary` | `ossie_model_summary` |
| `doris_semantic.get_semantic_context` | `child:doris_semantic:get_semantic_context` | `child:call:doris_semantic:get_semantic_context` | `ossie_semantic_context` |
| `doris_semantic.get_semantic_mapping_status` | `child:doris_semantic:get_semantic_mapping_status` | `child:call:doris_semantic:get_semantic_mapping_status` | `ossie_doris_mapping` |
| `doris_semantic.list_metricflow_models` | `child:doris_semantic:list_metricflow_models` | `child:call:doris_semantic:list_metricflow_models` | `metricflow_model_registry` |
| `doris_semantic.get_metricflow_status` | `child:doris_semantic:get_metricflow_status` | `child:call:doris_semantic:get_metricflow_status` | `metricflow_model_status` |
| `doris_semantic.list_metricflow_metrics` | `child:doris_semantic:list_metricflow_metrics` | `child:call:doris_semantic:list_metricflow_metrics` | `metricflow_metric_registry` |
| `doris_semantic.get_metricflow_group_bys` | `child:doris_semantic:get_metricflow_group_bys` | `child:call:doris_semantic:get_metricflow_group_bys` | `metricflow_group_by_registry` |
| `doris_semantic.list_metricflow_saved_queries` | `child:doris_semantic:list_metricflow_saved_queries` | `child:call:doris_semantic:list_metricflow_saved_queries` | `metricflow_saved_query_registry` |
| `doris_semantic.get_metricflow_dimension_values` | `child:doris_semantic:get_metricflow_dimension_values` | `child:call:doris_semantic:get_metricflow_dimension_values` | `metricflow_dimension_value_query` |
| `doris_semantic.compile_metricflow_query` | `child:doris_semantic:compile_metricflow_query` | `child:call:doris_semantic:compile_metricflow_query` | `metricflow_doris_compile` |
| `doris_semantic.execute_metricflow_query` | `child:doris_semantic:execute_metricflow_query` | `child:call:doris_semantic:execute_metricflow_query` | `metricflow_compile_mcp_execute` |

## Pre-1.0 migration coverage

| Flat tool | Handler | Formal feature | Mode | Section |
|---|---|---|---|---|
| `exec_query` | `_exec_query_tool` | `doris_query.execute_query` | `adapted` | - |
| `get_table_schema` | `_get_table_schema_tool` | `doris_catalog.get_table_context` | `composite_section` | `schema` |
| `get_db_table_list` | `_get_db_table_list_tool` | `doris_catalog.list_tables` | `adapted` | - |
| `get_db_list` | `_get_db_list_tool` | `doris_catalog.list_databases` | `adapted` | - |
| `get_table_comment` | `_get_table_comment_tool` | `doris_catalog.get_table_context` | `composite_section` | `comments` |
| `get_table_column_comments` | `_get_table_column_comments_tool` | `doris_catalog.get_table_context` | `composite_section` | `comments` |
| `get_table_indexes` | `_get_table_indexes_tool` | `doris_catalog.get_table_context` | `composite_section` | `indexes` |
| `get_recent_audit_logs` | `_get_recent_audit_logs_tool` | `doris_governance.get_recent_audit_logs` | `adapted` | - |
| `get_catalog_list` | `_get_catalog_list_tool` | `doris_catalog.list_catalogs` | `adapted` | - |
| `get_sql_explain` | `_get_sql_explain_tool` | `doris_query.explain_query` | `adapted` | - |
| `get_sql_profile` | `_get_sql_profile_tool` | `doris_query.get_query_profile` | `adapted` | - |
| `get_table_data_size` | `_get_table_data_size_tool` | `doris_catalog.get_table_size` | `adapted` | - |
| `get_monitoring_metrics` | `_get_monitoring_metrics_tool` | `doris_cluster.get_monitoring_metrics` | `adapted` | - |
| `get_memory_stats` | `_get_memory_stats_tool` | `doris_cluster.get_memory_stats` | `adapted` | - |
| `get_table_basic_info` | `_get_table_basic_info_tool` | `doris_catalog.get_table_context` | `composite_section` | `basic` |
| `analyze_columns` | `_analyze_columns_tool` | `doris_governance.analyze_columns` | `adapted` | - |
| `analyze_table_storage` | `_analyze_table_storage_tool` | `doris_governance.analyze_table_storage` | `adapted` | - |
| `trace_column_lineage` | `_trace_column_lineage_tool` | `doris_governance.trace_column_lineage` | `adapted` | - |
| `monitor_data_freshness` | `_monitor_data_freshness_tool` | `doris_pipeline.monitor_data_freshness` | `adapted` | - |
| `analyze_data_access_patterns` | `_analyze_data_access_patterns_tool` | `doris_governance.analyze_data_access_patterns` | `adapted` | - |
| `analyze_data_flow_dependencies` | `_analyze_data_flow_dependencies_tool` | `doris_pipeline.analyze_data_dependencies` | `adapted` | - |
| `analyze_slow_queries_topn` | `_analyze_slow_queries_topn_tool` | `doris_query.list_slow_queries` | `adapted` | - |
| `analyze_resource_growth_curves` | `_analyze_resource_growth_curves_tool` | `doris_cluster.analyze_resource_growth` | `adapted` | - |
| `exec_adbc_query` | `_exec_adbc_query_tool` | `doris_query.execute_adbc_query` | `adapted` | - |
| `get_adbc_connection_info` | `_get_adbc_connection_info_tool` | `doris_query.get_adbc_connection_info` | `atomic` | - |

This document describes internal 1.0 routing contracts. The pre-1.0 flat names are migration inputs, not registered 1.0 tool aliases.
