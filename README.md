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

# Doris MCP Server

[English](README.md) | [简体中文](README.zh-CN.md)

Doris MCP Server is a backend service that exposes [Apache Doris](https://doris.apache.org/) through the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/). AI clients (Claude Desktop, Cursor, VS Code, and others) can query Doris data through a governed **semantic metrics layer** built on [MetricFlow](https://github.com/dbt-labs/metricflow), with raw-SQL discovery as a fallback path. It ships with a Web UI for managing semantic models and a CLI client for scripting.

## Core Features

*   **Semantic Metrics Layer**: Define metrics once in YAML (simple / ratio / derived / cumulative / conversion), query them from any MCP client. MetricFlow compiles semantically correct SQL — no hand-written aggregation queries.
*   **Multi-Workspace Isolation**: Fully isolated tenants with their own models, compiler, and Doris storage tables. Models are stored in Doris itself (`active` + `staging` tables), so multiple server nodes share state without file sync.
*   **Staging Workflow**: All model changes go through *staging → validate → commit*; broken models can never affect running queries.
*   **Guided Tooling**: 10 MCP tools with an enforced workflow (`get_query_guide` → `check_service_health` → semantic query, or metadata discovery → raw SQL fallback).
*   **Credential Pass-Through**: `Authorization: Bearer <doris-user>:<password>` — every query runs under the caller's own Doris identity with per-user connection pools. No shared admin credentials.
*   **Web UI**: Login with Doris credentials to edit/validate/publish models, manage workspaces, and deploy the bundled example — no YAML tooling required.
*   **CLI Client**: `mcp-client` for calling tools and pushing/pulling model files from scripts and CI/CD.
*   **Multi-Node Ready**: Session affinity is handled in-app (cookie-suffix routing, or a fixed Web UI entry node via one `privateIp` line); nginx stays a plain reverse proxy.
*   **Self-Contained Packaging**: Release tarballs bundle a Python 3.10 runtime and all dependencies. No network, no pip, no system Python required on target machines.

## System Requirements

*   **Server host**: Linux x86_64 or ARM64 (for running the release package)
*   **Database**: Apache Doris FE reachable via MySQL protocol (default `127.0.0.1:9030`)
*   **Building from source**: curl/wget, or a local Python 3.10.x for offline builds

## 🚀 Quick Start

### 1. Get the package

Download the latest release from [Releases](../../releases):

```bash
tar xzf doris-mcp-server-<version>-linux-x64.tar.gz
cd doris-mcp-server
```

Or build from source (see [Building from Source](#building-from-source)).

### 2. Start the server

The default configuration expects a Doris FE on the same host (`127.0.0.1:9030`). Edit `mcp-server.toml` if needed, then:

```bash
# Foreground
./start-mcp-server.sh

# Background
nohup ./start-mcp-server.sh > /dev/null 2>&1 &
```

The server listens on port **3000** by default.

### 3. Connect your MCP client

Authentication is your **Doris username and password** passed as a Bearer token:

```text
Authorization: Bearer <doris-user>:<doris-password>
```

**Claude Desktop / Claude Code:**

```bash
claude mcp add --transport http doris http://<host>:3000/mcp \
  --header "Authorization: Bearer <user>:<password>"
```

**Cursor / VS Code (`mcp.json`):**

```json
{
  "mcpServers": {
    "doris": {
      "type": "http",
      "url": "http://<host>:3000/mcp",
      "headers": {
        "Authorization": "Bearer <user>:<password>"
      }
    }
  }
}
```

A ready-to-copy template is provided at [`mcp.json.example`](mcp.json.example).

**Smoke-test the connection with the FastMCP CLI:**

```bash
fastmcp call http://<host>:3000/mcp check_service_health \
  --auth "<user>:<password>" --json
```

### 4. Deploy the example workspace (Web UI)

1. Open `http://<host>:3000/mcp/web` and log in with your Doris credentials (an admin user — `admin` by default).
2. Click the **example deploy** button. Deployment runs in the background; the page polls progress and redirects when done.
3. Back in your AI client, ask: *"查询各渠道的订单总额"* — the agent will discover the `example` workspace and query metrics like `total_amount` grouped by `channel`.

### 5. Manage semantic models

**Web UI** (`/mcp/web`): create/upload/edit YAML models → **Validate** → **Commit**. Only validated models go live.

**CLI client:**

```bash
export DORIS_MCP_SERVER=http://<host>:3000
export DORIS_MCP_TOKEN=<user>:<password>

./mcp-client.sh semantic push ./models -w my_workspace
./mcp-client.sh semantic pull -o ./backup -w my_workspace
./mcp-client.sh tool call list_metrics --json '{"workspace":"my_workspace"}'
```

## How the Agent Queries Data

```
get_query_guide()              ← 1. workflow instructions (always first)
check_service_health()         ← 2. Doris connectivity + workspace status
    │
    ├─ semantic layer healthy ─→ list_metrics → list_dimensions_for_metric → query_metric
    │                             (counts, sums, ratios, rankings, trends)
    └─ no matching metric ─────→ list_databases → list_tables → describe_table → execute_query
                                  (raw SQL fallback, read-only validated)
```

## Configuration (`mcp-server.toml`)

| Key | Default | Description |
|-----|---------|-------------|
| `server.mcp_host` / `server.mcp_port` | `0.0.0.0` / `3000` | HTTP listen address |
| `server.fe_port` | `9030` | Doris FE MySQL port (same host) |
| `server.admin_users` | `["admin"]` | Users allowed to manage models / deploy the example |
| `server.seed_example` | `false` | Auto-deploy the example on first admin login |
| `server.privateIp` | *(unset)* | Optional. Set the same IP on every node to make it the fixed Web UI entry; all `/mcp/web` requests (login included) are forwarded there |
| `query.db_whitelist` | `[]` | Optional database allow-list |
| `query.query_timeout_seconds` | `600` | SQL query timeout |
| `query.query_max_rows` | `10000` | Max rows per query |

All values support `${ENV_VAR}` interpolation.

## Multi-Node Deployment

Multiple server nodes behind one load balancer work out of the box: Web UI sessions are routed in-app by the session cookie's IP suffix — nginx needs no cookie parsing.

To pin the Web UI to a single entry node, set the same `privateIp` in every node's `mcp-server.toml`:

```toml
[server]
privateIp = "10.0.0.13"   # identical on all nodes
```

All `/mcp/web` requests (login included) are then forwarded to that node; `/mcp` MCP traffic stays node-local. See [DESIGN.md](DESIGN.md) §8.3 for details.

## Building from Source

```bash
./build.sh linux-x64      # Linux x86_64
./build.sh linux-arm64    # Linux ARM64
./build.sh macos-arm64    # macOS Apple Silicon
./build.sh clean          # remove build artifacts
```

The build downloads a standalone Python 3.10 and produces a self-contained tarball in `dist/`. If GitHub is unreachable, point to a local Python 3.10:

```bash
DORIS_MCP_SYSTEM_PYTHON=/opt/miniconda3/bin/python ./build.sh linux-x64
```

**CI releases** (`.github/workflows/release.yml`): pushing a tag named `doris-mcp-server-x.y.z` builds linux-x64 + linux-arm64 packages and publishes a GitHub Release for that version. A release can also be triggered manually from the Actions page.

## Running Tests

```bash
bash test/run_all_tests.sh --offline   # unit tests, no server needed
bash test/run_all_tests.sh --smoke     # quick smoke test
bash test/run_all_tests.sh             # full suite (needs a local server)
```

## Documentation

*   [DESIGN.md](DESIGN.md) — architecture and design decisions
*   [INSTALL.html](INSTALL.html) — installation guide
*   [doris-mcp-docs.html](doris-mcp-docs.html) — semantic model reference and user guide
*   [README.zh-CN.md](README.zh-CN.md) — 中文文档

## License

Licensed under the [Apache License, Version 2.0](LICENSE.txt).
This distribution vendors MetricFlow (`src/metricflow/`), which carries its own license — see `src/metricflow/LICENSE` and `src/metricflow/NOTICE`.
