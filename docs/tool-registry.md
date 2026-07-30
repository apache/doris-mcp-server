# Doris MCP Domain Tool Registry

<!-- Generated from DomainManifestService; do not edit by hand. -->

| Domain tool | Read-only boundary | Child count | Discovery |
|---|---|---:|---|
| `doris_catalog` | Explore Doris catalogs, databases, tables, schemas, comments, indexes, key models, storage metadata, and object sizes. | 5 | Call with `{}` |
| `doris_query` | Execute read-only Doris SQL, inspect plans and profiles, review slow queries, and use the optional ADBC provider. | 7 | Call with `{}` |
| `doris_cluster` | Inspect Doris health, nodes, tasks, monitoring, memory, cache, compaction, workload, compute groups, and runtime capabilities. | 11 | Call with `{}` |
| `doris_pipeline` | Inspect ingestion, load health, materialized views, data freshness, and upstream or downstream dependencies. | 5 | Call with `{}` |
| `doris_search` | Search Doris data with text, vector, or hybrid retrieval and inspect or diagnose search analyzers and indexes. | 4 | Call with `{}` |
| `doris_governance` | Analyze columns and storage, inspect lineage and access evidence, read audit metadata, and review UDF or authentication mappings. | 8 | Call with `{}` |
| `doris_lakehouse` | Inspect external catalogs, lakehouse tables, snapshots, partitions, pushdown behavior, and Variant semi-structured columns. | 3 | Call with `{}` |
| `doris_semantic` | Discover validated Ossie models bound to Doris and read permission-filtered semantic summaries, context, and mapping status. | 4 | Call with `{}` |

MCP `tools/list` exposes only these eight stable read-only domains. Call a domain with an empty object to receive its authorized, bounded child manifest. The manifest contains exact child names, schemas, version support, availability, evidence, and risk annotations.

A discoverable child that is not supported by the current runtime remains in the manifest with `callable=false`. A child without discovery permission is omitted entirely. Internal handlers, custom providers, and pre-1.0 flat names are not advertised by `tools/list`.
