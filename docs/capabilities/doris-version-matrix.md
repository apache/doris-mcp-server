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

# Doris version capability matrix

[English](doris-version-matrix.md) | [简体中文](doris-version-matrix.zh-CN.md)

Doris MCP Server supports Apache Doris `2.0.0+` as its project baseline. This
is not a promise that every child is callable on every release. Each child is
filtered by a machine-readable conjunction of normalized three-part version,
live feature probes, provider readiness, deployment mode, route coherence,
authorization, and Doris object visibility.

The source of truth is `doris_feature_matrix.py`; this page summarizes the
release-note review relevant to the public MCP surface. It is not a replacement
for the complete Apache Doris release notes.

## Release families

| Doris range | MCP-relevant capability baseline | Important gates |
|---|---|---|
| `2.0.x` | Catalog metadata, MySQL read-only query/Explain/Profile, load and MV evidence, workload groups, audit-based governance, external catalogs, inverted-index text search, and optional semantic providers. | Every path still requires its live metadata, endpoint, provider, and permission probes. ADBC and Variant are unavailable by version. |
| `2.1.0-2.1.4` | Adds Arrow Flight SQL/ADBC and Variant type inspection. | ADBC is `degraded` on these early patches and still requires an installed provider, Flight endpoints, live probes, and explicit end-user ADBC intent. |
| `2.1.5-2.1.x` | Keeps the 2.1 surface with improved Flight SQL result behavior; later patches improve metadata and serialization/error behavior. | `2.1.5+` clears the early-release maturity gate, but runtime probes remain mandatory. |
| `3.x` | All supported 2.x foundations plus the metadata/runtime improvements exposed by the connected patch. | There is no global 3.x-only MCP gate. Availability remains per child and per route. |
| `4.0.0-4.0.5` | Adds ANN/vector and vector-plus-inverted hybrid search variants and plan/index facets. | Index type, metric, dimension, functions, and actual metadata must match the request. |
| `4.0.6` | Adds the native lineage event path and compaction task-tracker path. | Native lineage also requires compatible FE plugins and a healthy queryable companion store. Audit inference remains an explicit degraded fallback. |
| `4.0.7` | Adds enhanced observability/audit/cache evidence and selected MTMV compute-group evidence. | Exact metadata/metrics fields are probed; absent fields select base or degraded variants. |
| `4.1.0` | Adds Storage V3/advanced Variant facets, lakehouse lifecycle facets, continuous-load evidence, and advanced cache variants. | Base children remain available when advanced facets are absent; advanced sections report their own status. |
| `4.1.1` | Adds unified task progress and the 4.1 compaction task-tracker path. | Falls back to legacy task or compaction summaries when the required objects are absent. |
| `4.1.2` | Adds OIDC role-mapping evidence and selected MTMV compute-group support. | Provider, system object, deployment-mode, and visibility probes are required. |
| `4.1.3+` | Adds Python UDF/UDAF/UDTF family metadata. | The base UDF metadata path remains separate and can work on older releases. |

## Child-family mapping

| Public children | Minimum version | Later variant or provider rule |
|---|---:|---|
| `doris_catalog.*` | `2.0.0` | ANN/BM25 context facets require `4.0+`; Storage V3 Variant context requires `4.1+`. |
| `execute_query`, `explain_query`, `get_query_profile`, `diagnose_query_performance`, `list_slow_queries` | `2.0.0` | Query/profile/audit evidence is probed independently. Search plan facets require `4.0+`. |
| `get_adbc_connection_info`, `execute_adbc_query` | `2.1.0` | Default-off, explicit-only advanced path; `2.1.0-2.1.4` degraded; never chosen for ordinary SQL. |
| `doris_cluster.*` | `2.0.0` | Newer cache, compaction, observability, task, and compute-group facets select their documented variants. |
| `doris_pipeline.*` | `2.0.0` | Continuous load requires `4.1+`; selected MTMV compute-group evidence requires `4.0.7` or `4.1.2+`. |
| Inverted text search paths | `2.0.0` | Requires compatible inverted index and search/tokenizer syntax probes. |
| ANN/vector/hybrid search paths | `4.0.0` | Requires compatible ANN/index/metric/dimension evidence; text-only fallback can remain callable. |
| Governance and audit-based lineage | `2.0.0` | Audit provider is primary before `4.0.6`; native lineage is preferred only when all native prerequisites pass. |
| Native lineage | `4.0.6` | Requires companion plugin plus queryable store; version alone is insufficient. |
| `inspect_external_catalog`, base lakehouse inspection | `2.0.0` | Requires an external-catalog provider and visible metadata. |
| `inspect_variant_column` | `2.1.0` | Storage V3/sparse/doc-mode facets require `4.1+`. |
| Ossie children | `2.0.0` project baseline | Default-off; exact `model_ref`, reviewed model store, private binding, policy, route, and permission probes. |
| MetricFlow children | `2.0.0` project baseline | Default-off; exact `model_ref`, provider protocol, model metadata, Doris-dialect compilation, SQL guard, and Query runtime probes. |

## ADBC decision rule

ADBC is intentionally not an automatic optimization. Both formal ADBC calls
require `explicit_adbc=true`; the Server rejects the call otherwise. A Host or
model must use ordinary `doris_query.execute_query` unless the end user
explicitly asks for ADBC or Arrow Flight SQL. This prevents ambiguous tool
selection and acknowledges that Flight endpoints and cluster tuning are an
advanced deployment concern.

## Source set

The matrix records stable source identifiers and verification dates. Primary
sources include:

- [Doris 2.0.0 release notes](https://doris.apache.org/docs/3.0/releasenotes/v2.0/release-2.0.0)
- [Doris 2.0.15 release notes](https://doris.apache.org/docs/2.0/releasenotes/v2.0/release-2.0.15)
- [Doris 2.1.0 release notes](https://doris.apache.org/docs/3.x/releasenotes/v2.1/release-2.1.0/)
- [Doris 2.1.11 release notes](https://doris.apache.org/releases/v2.1/release-2.1.11/)
- [Doris 2.1 Arrow Flight SQL guide](https://doris.apache.org/docs/2.1/db-connect/arrow-flight-sql-connect/)
- [Doris 3.0.0 release notes](https://doris.apache.org/docs/3.x/releasenotes/v3.0/release-3.0.0/)
- [Doris 3.1.0 release notes](https://doris.apache.org/docs/4.x/releasenotes/v3.1/release-3.1.0/)
- [Doris 3.x documentation](https://doris.apache.org/docs/3.x/)
- [Doris 4.0.0 release notes](https://doris.apache.org/releases/v4.0/release-4.0.0/)
- [Doris 4.0.6 release notes](https://doris.apache.org/releases/v4.0/release-4.0.6/)
- [Doris 4.0.7 release notes](https://doris.apache.org/releases/v4.0/release-4.0.7/)
- [Doris 4.1.0 release notes](https://doris.apache.org/releases/v4.1/release-4.1.0/)
- [Doris 4.x documentation](https://doris.apache.org/docs/4.x/)

Patch certification and runtime support are separate. A route can be supported
without being a certified release target; the runtime manifest remains the
authority for the current identity and route.
