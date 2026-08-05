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

# Apache Doris MCP Server

[English](README.md) | [简体中文](README.zh-CN.md)

Apache Doris MCP Server exposes read-only Apache Doris capabilities to MCP
Hosts and AI agents over MCP `2026-07-28`. Version 1.0 replaces a large flat
tool surface with eight stable domains and fifty-five progressively disclosed
child capabilities, while keeping runtime availability, authorization, input
schemas, output schemas, and failure behavior explicit.

## Release status

The package version is `1.0.0`. MCP `2026-07-28` protocol compatibility on
`master` is **Generally Available (GA)** on Streamable HTTP and stdio.
This GA statement is scoped to protocol compatibility; the Python package
classifier remains **Beta**, and the documented deployment limits still apply.

Before upgrading, read the [1.0 release notes](docs/release-notes-1.0.0.md),
the [1.0 migration guide](docs/migration-1.0.0.md), and the generated
[8-domain/55-child registry](docs/tool-registry.md). The detailed release
record is [Issue #189](https://github.com/apache/doris-mcp-server/issues/189).

## Architecture at a glance

```text
MCP Host
  -> stdio or Streamable HTTP
  -> transport security and authentication
  -> MCP protocol validation and authorization
  -> stable domain discovery
  -> route-aware Doris capability detection
  -> exact child dispatch and read-only runtime
  -> request-specific Doris route and RBAC
  -> bounded, schema-validated result
```

The default `hierarchical` mode exposes these domains:

| Domain | Children | Responsibility |
|---|---:|---|
| `doris_catalog` | 5 | catalogs, databases, tables, table context, size |
| `doris_query` | 7 | query, explain, profile, diagnosis, slow queries, explicit ADBC |
| `doris_cluster` | 11 | nodes, tasks, metrics, memory, cache, compaction, workloads |
| `doris_pipeline` | 5 | ingestion, materialized views, freshness, dependencies |
| `doris_search` | 4 | text/vector/hybrid search, analyzers, indexes, diagnosis |
| `doris_governance` | 8 | quality, storage, lineage, audit, UDFs, auth mapping |
| `doris_lakehouse` | 3 | external catalogs, lakehouse tables, Variant |
| `doris_semantic` | 12 | optional Apache Ossie grounding and MetricFlow consumption |

Call a domain with `{}` to discover its authorized children and exact schemas.
Call the same domain again with `child_tool`, `arguments`, and the returned
`manifest_version`. Hosts that cannot use progressive disclosure may set
`MCP_TOOL_EXPOSURE_MODE=flat` before startup; this exposes the same 55 children
under collision-free formal names and does not restore pre-1.0 aliases.

See [Architecture](docs/architecture/overview.md),
[Request lifecycle](docs/architecture/request-lifecycle.md), and
[Tool domains](docs/capabilities/tool-domains.md).

## Quick start

Requirements:

- Python 3.12 or later;
- Apache Doris 2.0.0 or later;
- network access to the Doris FE MySQL endpoint, normally port `9030`.

Install the pinned release:

```bash
pip install doris-mcp-server==1.0.0
```

`doris-mcp-server` starts the Server. `doris-mcp-client` is a separate client;
the two commands are not interchangeable.

Configure a Doris route:

```bash
export DORIS_HOST=127.0.0.1
export DORIS_PORT=9030
export DORIS_USER=mcp_reader
export DORIS_PASSWORD='replace-me'
export DORIS_DATABASE=information_schema
```

Start Streamable HTTP on loopback:

```bash
doris-mcp-server \
  --transport http \
  --host 127.0.0.1 \
  --port 3000
```

Endpoints:

- MCP: `POST http://127.0.0.1:3000/mcp`
- legacy MCP (opt-in): `POST http://127.0.0.1:3000/mcp/legacy`
- liveness: `GET http://127.0.0.1:3000/live`
- Doris-backed readiness: `GET http://127.0.0.1:3000/ready`

Hosts limited to handshake-era Streamable HTTP, including Dify 1.16.1 with
MCP `2025-06-18`, must set `ENABLE_LEGACY_HTTP_ADAPTER=true` and connect to
`/mcp/legacy`. The adapter changes only the protocol boundary; it preserves the
same 1.0 tools, authorization, capability gates, and read-only execution.

Or run stdio for a local Host:

```bash
doris-mcp-server --transport stdio
```

See the complete [Quick start](docs/getting-started/quickstart.md) and
[Host integration guide](docs/integrations/hosts.md).

## Security boundary

- The built-in 1.0 catalog is read-only; `doris_admin` is reserved and not
  registered.
- Static tokens, JWT, external OAuth/OIDC, and Doris-backed OAuth are supported
  under mutually validated configuration boundaries.
- Domain discovery and child execution use exact authorization identifiers.
- Doris RBAC remains the final authority for visible objects and data.
- SQL shape, identifiers, parameters, timeout, rows, bytes, and result schemas
  are bounded before data leaves the Server.
- Secrets and backend errors are redacted from public results and logs.
- Non-loopback HTTP requires authentication unless an explicit dangerous
  development override is enabled.

Read the [Security and permission model](docs/security/security-model.md) and
the [Doris fine-grained access guide](docs/doris-fine-grained-access-control.md).

## Reliability boundary

The Server uses deterministic manifests and errors, signed expiring cursors,
route-aware capability snapshots, bounded stale fallback, request-specific
connection routing, multi-FE failover, liveness/readiness separation, output
Schema validation, and sanitized trace propagation. Unsupported or
misconfigured capabilities remain discoverable with `callable=false` and fail
closed when called.

Current limits include process-local Doris-backed OAuth, explicit-only ADBC
that is disabled by default and fail-closed on token-bound routes, optional
read-only Ossie grounding, an optional MetricFlow compiler sidecar whose SQL
must execute through the bounded MCP query runtime, and best-effort native
lineage delivery. See [Reliability and limits](docs/operations/reliability.md).

## Documentation

The root README is intentionally an entry point. The bilingual documentation
system is indexed at:

- [English documentation](docs/README.md)
- [简体中文文档](docs/README.zh-CN.md)

Primary guides:

- [Architecture](docs/architecture/overview.md)
- [Request and data flow](docs/architecture/request-lifecycle.md)
- [Tool domains](docs/capabilities/tool-domains.md)
- [Capability availability](docs/capabilities/availability.md)
- [Doris version capability matrix](docs/capabilities/doris-version-matrix.md)
- [MetricFlow integration](docs/integrations/metricflow.md)
- [MCP 2026-07-28 contract](docs/protocol/mcp-2026-07-28.md)
- [Security model](docs/security/security-model.md)
- [Deployment](docs/operations/deployment.md)
- [Reliability and limits](docs/operations/reliability.md)
- [Troubleshooting](docs/operations/troubleshooting.md)
- [Configuration reference](docs/reference/configuration.md)
- [Host integrations](docs/integrations/hosts.md)
- [Custom tool providers](docs/custom-tool-providers.md)
- [Contributing](docs/development/contributing.md)

## Development

```bash
git clone https://github.com/apache/doris-mcp-server.git
cd doris-mcp-server
uv sync --group dev
uv run pytest
```

Generated artifacts must remain synchronized:

```bash
uv run python generate_tool_catalog.py --check
uv lock --check
```

See [Contributing and verification](docs/development/contributing.md).

## License

Apache License 2.0. See [LICENSE.txt](LICENSE.txt) and [NOTICE](NOTICE).
