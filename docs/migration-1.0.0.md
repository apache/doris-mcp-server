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

# Migrating to Doris MCP Server 1.0.0

Expanded guides: [English](migration/1.0.0.md) |
[Simplified Chinese](migration/1.0.0.zh-CN.md)

Version 1.0.0 replaces the pre-1.0 direct tool surface with one validated
read-only catalog. This is an intentional breaking change: pre-1.0 tool names
are not registered as aliases and cannot be called after the upgrade.

## Exposure modes

The default `hierarchical` mode exposes eight stable domain tools:

- `doris_catalog`
- `doris_query`
- `doris_cluster`
- `doris_pipeline`
- `doris_search`
- `doris_governance`
- `doris_lakehouse`
- `doris_semantic`

Call a domain with an empty object to receive its authorized child manifest.
Use the returned exact child name, input schema, and manifest version for the
next call:

```json
{}
```

```json
{
  "child_tool": "list_tables",
  "arguments": {
    "database": "analytics"
  },
  "manifest_version": "<value returned by discovery>"
}
```

Hosts that cannot use progressive disclosure may set
`MCP_TOOL_EXPOSURE_MODE=flat` before startup. Flat mode exposes 55
collision-free formal names such as `doris_catalog_list_tables` and
`doris_query_execute_query`. Changing the mode requires a Server restart and a
Host reconnect. Flat mode does not restore pre-1.0 names.

The generated [tool catalog](tool-registry.md) is the authoritative list of
all eight domains, 55 children, and 25 pre-1.0 migration inputs.

## Required Host changes

1. Remove cached pre-1.0 tool definitions.
2. Restart the Server after selecting the exposure mode.
3. Reconnect the Host and run `tools/list`.
4. In hierarchical mode, discover a domain before calling a child.
5. Use exact schemas from the current manifest; do not infer arguments from a
   previous release.
6. Rediscover when the Server returns a stale-manifest response.

Top-level registration remains stable across user intent changes. A Host can
move from catalog discovery to cluster inspection by calling another already
registered domain; it does not need dynamic tool re-registration.

## Common tool migrations

| Pre-1.0 call | Hierarchical 1.0 child | Flat 1.0 name |
|---|---|---|
| `exec_query` | `doris_query.execute_query` | `doris_query_execute_query` |
| `get_db_list` | `doris_catalog.list_databases` | `doris_catalog_list_databases` |
| `get_db_table_list` | `doris_catalog.list_tables` | `doris_catalog_list_tables` |
| `get_catalog_list` | `doris_catalog.list_catalogs` | `doris_catalog_list_catalogs` |
| `get_sql_explain` | `doris_query.explain_query` | `doris_query_explain_query` |
| `get_sql_profile` | `doris_query.get_query_profile` | `doris_query_get_query_profile` |
| `exec_adbc_query` | `doris_query.execute_adbc_query` | `doris_query_execute_adbc_query` |
| `analyze_data_flow_dependencies` | `doris_pipeline.analyze_data_dependencies` | `doris_pipeline_analyze_data_dependencies` |

Five pre-1.0 table calls now contribute to sections of
`doris_catalog.get_table_context`:

- `get_table_basic_info` becomes section `basic`.
- `get_table_schema` becomes section `schema`.
- `get_table_comment` and `get_table_column_comments` become section
  `comments`.
- `get_table_indexes` becomes section `indexes`.

Use the generated catalog for the complete mapping. Migration entries document
internal handler reuse; they do not make the old call names discoverable or
callable.

## Authorization changes

OAuth discovery and call scopes use exact domain and child identifiers.
Pre-1.0 tool scopes and wildcard guesses are rejected. Discovery permission
does not imply execution permission, and Doris RBAC remains the final data
authorization boundary.

The optional Ossie semantic domain is default-off. Every model-specific call
requires the exact `model_ref` returned by discovery; the Server does not
guess a model from the prompt.

## Protocol and transport

MCP `2026-07-28` is the modern protocol on Streamable HTTP and stdio. The
isolated `2025-11-25` HTTP migration adapter remains default-off at
`/mcp/legacy` and does not restore pre-1.0 tool names. Enable it only for a
bounded protocol migration by setting `ENABLE_LEGACY_HTTP_ADAPTER=true`.

## Doris version handling

The minimum supported Doris version is `2.0.0`. Patch certification uses only
the normalized `major.minor.patch` value. RC or GA labels, commit hashes, and
deployment hints remain diagnostic evidence. They do not affect capability
ranges or create separate certification buckets.

At the 1.0.0 release boundary, `4.0.5` is evidence-backed and certified. The
other target versions remain explicitly `target_uncertified` until their real
cluster gates are complete. Runtime capability discovery is authoritative for
each connected cluster.

## Safety boundary

Version 1.0.0 exposes read-only domains. The reserved `doris_admin` domain is
not registered, and no management write operation is available. Custom
providers remain explicit, allowlisted extensions rather than members of the
built-in 8/55 contract.
