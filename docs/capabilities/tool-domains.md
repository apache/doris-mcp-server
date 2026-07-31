<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
-->

# Tool domains

[English](tool-domains.md) | [简体中文](tool-domains.zh-CN.md)

Version 1.0 has one built-in read-only catalog: eight top-level domains and
fifty-five exact children. This page explains product intent. The generated
[tool registry](../tool-registry.md) is authoritative for formal feature IDs,
handler bindings, authorization identifiers, variants, and migration inputs.

## Discovery and execution shape

Discover a domain:

```json
{}
```

Execute one discovered child:

```json
{
  "child_tool": "<exact child name>",
  "arguments": {},
  "manifest_version": "<returned by discovery>"
}
```

Availability is runtime-specific. A child listed below is part of the public
contract, but it is callable only when its version, feature, provider,
permission, route, and configuration predicates pass.

## `doris_catalog` — metadata navigation

| Child | Purpose | Important behavior |
|---|---|---|
| `list_catalogs` | List internal and external catalogs. | Bounded, ordered, filterable; external visibility follows Doris privileges. |
| `list_databases` | List databases in one catalog. | Requires an exact catalog when the route uses multiple catalogs. |
| `list_tables` | List tables/views in one database. | Stable filtering and signed cursor pagination. |
| `get_table_context` | Assemble table `basic`, `schema`, `comments`, and `indexes` sections. | `schema` is always required; optional sections can report `partial`/`unavailable` independently. |
| `get_table_size` | Return table and bounded partition size evidence. | Uses live statistics/metadata; reports truncation rather than unbounded scans. |

`get_table_context` replaces five pre-1.0 top-level calls. It keeps section
provenance and warnings instead of flattening partially available metadata into
one ambiguous object.

## `doris_query` — read-only query and diagnostics

| Child | Purpose | Important behavior |
|---|---|---|
| `execute_query` | Execute one read-only SQL statement. | SQL guard, bound parameters, timeout/row/byte ceilings, masking, deterministic errors. |
| `explain_query` | Return a bounded Doris query plan. | The target SQL must itself pass the read-only guard. |
| `get_query_profile` | Retrieve a bounded FE query profile. | Requires FE HTTP/profile evidence and never returns credentials. |
| `diagnose_query_performance` | Produce deterministic findings from plan/profile/query evidence. | Evidence-based rules; no invented confidence score. |
| `list_slow_queries` | List bounded slow-query evidence. | Requires readable audit history; raw sensitive SQL fields are sanitized. |
| `get_adbc_connection_info` | Report Arrow Flight SQL/ADBC readiness. | Advanced, default-off, and valid only after explicit user intent selects ADBC. |
| `execute_adbc_query` | Execute a bounded read-only query through ADBC. | Requires `explicit_adbc=true`; never substitutes for ordinary `execute_query`; fail-closed on token-bound routes. |

Ordinary SQL always uses `execute_query`. The two ADBC children are an
advanced path for requests that explicitly name ADBC or Arrow Flight SQL;
their schemas require `explicit_adbc=true`, and the runtime independently
enforces the same condition. The query domain accepts SQL because SQL is the native Doris query interface,
but it does not expose DDL, DML, administrative SQL, arbitrary stacked
statements, or an unbounded result channel.

## `doris_cluster` — runtime and resource state

| Child | Purpose | Important behavior |
|---|---|---|
| `get_cluster_overview` | Summarize deployment, versions, and node health. | Preserves mixed/dead component evidence without treating dead nodes as active gates. |
| `list_cluster_nodes` | List FE/BE and relevant component inventory. | Sanitized host/state/version evidence. |
| `list_active_tasks` | Inspect active query/load/task progress. | Selects unified or legacy views from live evidence. |
| `get_monitoring_metrics` | Retrieve allowlisted bounded metrics. | Metric names, node count, and values are bounded. |
| `get_memory_stats` | Inspect memory trackers and use. | Reports source and partial availability. |
| `get_cache_status` | Inspect file/cache status. | Selects advanced or base evidence by patch and live metadata. |
| `get_compaction_status` | Inspect compaction state. | Uses system table or allowlisted HTTP evidence, with explicit fallback. |
| `get_workload_group_status` | Inspect workload-group definitions and metrics. | Requires readable workload-group metadata. |
| `get_compute_group_status` | Inspect compute groups. | Availability depends on deployment and readable metadata. |
| `analyze_resource_growth` | Analyze bounded recorded resource history. | Requires historical metrics/audit evidence; no speculative forecast. |
| `get_runtime_capabilities` | Return a sanitized capability snapshot. | Exposes bounded reasons/evidence, not credentials or private route internals. |

## `doris_pipeline` — ingestion and freshness

| Child | Purpose | Important behavior |
|---|---|---|
| `get_ingestion_status` | Inspect batch, stream, routine, and insert jobs. | Version-aware job views; bounded collections. |
| `diagnose_ingestion` | Diagnose observed ingestion failures/state. | Deterministic rules over returned evidence. |
| `get_materialized_view_status` | Inspect MV definitions, jobs, tasks, and compute context. | Selects available metadata paths and reports partial state. |
| `monitor_data_freshness` | Report bounded table freshness evidence. | Does not claim freshness without an observable timestamp/source. |
| `analyze_data_dependencies` | Infer bounded upstream/downstream dependencies. | Audit-derived runtime evidence; not a complete static lineage proof. |

## `doris_search` — text, vector, and hybrid retrieval

| Child | Purpose | Important behavior |
|---|---|---|
| `search_data` | Run structured text, vector, or hybrid retrieval. | Validates target indexes/fields, vector dimensions, filters, top-k, and output fields. |
| `preview_text_analysis` | Preview Doris tokenization/analyzer output. | Input text and output tokens are bounded. |
| `inspect_search_indexes` | Inspect inverted and ANN index metadata. | Does not expose storage secrets or unrelated table properties. |
| `diagnose_search_query` | Explain and diagnose search execution. | Requires a validated structured request and bounded plan evidence. |

Caller values remain driver-bound. The domain does not accept raw Doris
`SEARCH` DSL fragments or arbitrary filter SQL through the structured search
child.

## `doris_governance` — quality, lineage, audit, and access

| Child | Purpose | Important behavior |
|---|---|---|
| `analyze_columns` | Analyze bounded column statistics and quality evidence. | Column count and sampling are bounded; Doris permission remains final. |
| `analyze_table_storage` | Inspect partitions, indexes, and storage shape. | Sensitive locations/properties are removed from model-facing output. |
| `get_lineage_capability_status` | Explain which lineage path is active and why. | Separates native, audit-primary, degraded fallback, and unavailable states. |
| `trace_column_lineage` | Trace attributable bounded lineage edges. | Native provider on eligible routes; conservative audit inference otherwise. |
| `analyze_data_access_patterns` | Summarize bounded audit access evidence. | Raw SQL/client/auth data is sanitized. |
| `get_recent_audit_logs` | Return bounded recent audit events. | Time window/result count are capped; sensitive fields redacted. |
| `list_udfs` | Inspect visible UDF metadata. | Version-aware function family metadata; no function execution. |
| `get_auth_mapping_status` | Inspect sanitized LDAP/OIDC role mapping readiness. | Does not expose bind credentials, rules containing secrets, or raw provider errors. |

Native lineage requires both an eligible Doris version and a healthy queryable
companion store. Version `4.0.6+` alone does not make it callable.

## `doris_lakehouse` — external and semi-structured data

| Child | Purpose | Important behavior |
|---|---|---|
| `inspect_external_catalog` | Inspect visible external catalog metadata and readiness. | Properties and locations are sanitized. |
| `inspect_lakehouse_table` | Inspect table format, snapshots, partitions, lifecycle, and pushdown evidence. | 4.1 lifecycle facets are reported separately from base metadata. |
| `inspect_variant_column` | Inspect Variant type and bounded shape evidence. | Sample values and sensitive paths are excluded; advanced 4.1 facets are capability-gated. |

## `doris_semantic` — optional semantic consumers

| Child | Purpose | Important behavior |
|---|---|---|
| `list_semantic_models` | List bounded reviewed models from the configured provider. | Domain is default-off and requires explicit provider enablement. |
| `get_semantic_model_summary` | Return a bounded summary for one exact `model_ref`. | No prompt-based model guessing. |
| `get_semantic_context` | Build deterministic read-only grounding context. | Requires exact model, route-aware mapping, and Doris visibility. |
| `get_semantic_mapping_status` | Explain private Doris binding readiness. | Reports status/reasons without exposing the private binding manifest. |
| `list_metricflow_models` | List configured MetricFlow model references. | Provider is default-off; model selection never uses prompt guessing. |
| `get_metricflow_status` | Return provider/model validation status. | Requires one exact `model_ref`. |
| `list_metricflow_metrics` | List bounded metrics and optional dimensions. | Requires one exact `model_ref`; supports bounded filtering. |
| `get_metricflow_group_bys` | Return valid group-by dimensions for selected metrics. | Provider validates the metric set against the exact model. |
| `list_metricflow_saved_queries` | List bounded saved-query metadata. | Does not execute saved queries. |
| `get_metricflow_dimension_values` | Compile and execute a bounded dimension-value query. | Provider compiles Doris SQL; MCP SQL guard and Query runtime execute it. |
| `compile_metricflow_query` | Compile a structured MetricFlow request to Doris SQL. | Compile-only; returns no query result and does not bypass the SQL guard. |
| `execute_metricflow_query` | Compile and execute a bounded MetricFlow request. | Execution always returns to `DorisQueryRuntime` for routing, RBAC, limits, audit, and redaction. |

Ossie owns semantic definitions. MetricFlow owns metric semantics and query
compilation. The MCP Server is a governed consumer: it does not author either
model, does not guess a model, and does not permit a provider to execute Doris
SQL outside the MCP Query runtime. See [MetricFlow integration](../integrations/metricflow.md).

## Reserved and extension surfaces

- `doris_admin` is intentionally not registered.
- Custom providers are explicit extensions and not counted in 8/55.
- MCP resources and prompts remain separate protocol surfaces; they are not
  hidden child tools.
- Pre-1.0 tool names are not callable aliases.

See [Capability availability](availability.md) for how each child becomes
`callable=true` or `callable=false`.
