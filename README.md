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

Doris MCP (Model Context Protocol) Server is a backend service built with Python and FastAPI. It implements the MCP, allowing clients to interact with it through defined "Tools". It's primarily designed to connect to Apache Doris databases, potentially leveraging Large Language Models (LLMs) for tasks like converting natural language queries to SQL (NL2SQL), executing queries, and performing metadata management and analysis.

## Release Status

The current package metadata and latest Git tag are `0.6.1`. The `master`
branch also contains changes made after that tag; those changes are recorded
under [Unreleased](CHANGELOG.md#unreleased) until the next version is selected
and published.

MCP `2026-07-28` protocol compatibility on `master` is **Generally Available
(GA)** for Streamable HTTP and stdio. The supported protocol contract has
passed the full test suite with warnings treated as errors, the official
stateless conformance suite, clean wheel installation, and real Apache Doris
tests over both transports.

This GA statement is scoped to protocol compatibility on the supported
transports. The project package metadata remains **Beta**, and it does not
expand the supported deployment shapes or remove the documented operational
constraints. Review the [changelog](CHANGELOG.md), the
[protocol support matrix](#protocol-and-transport-matrix), and the
[deployment constraints](#deployment-constraints) before deploying it outside
a controlled environment.

## Highlights from v0.6.0

- **🔐 Enterprise Authentication System**: **Revolutionary token-bound database configuration** with comprehensive Token, JWT, and OAuth authentication support, enabling secure multi-tenant access with granular control switches and enterprise-grade security defaults
- **⚡ Immediate Database Validation**: **Real-time database configuration validation at connection time**, reducing query-time blocking and providing earlier feedback for invalid configurations
- **🔄 Hot Reload Configuration Management**: **Runtime configuration updates** with intelligent hot reloading of tokens.json, automatic token revalidation, and comprehensive error handling with rollback mechanisms
- **🏗️ Advanced Connection Architecture**: **Session caching and connection pool optimization** with intelligent pool recreation and automatic resource management
- **🌐 Multi-Worker Scalability**: Stateless HTTP request handling with multi-worker support; authentication-specific worker limits still apply
- **🔒 Enhanced Security Framework**: **Comprehensive access control and SQL security validation** with immediate validation, role-based permissions, and enhanced injection detection patterns
- **🛠️ Unified Configuration System**: **Streamlined configuration management** with proper command-line precedence, Docker compatibility improvements, and cross-platform deployment support
- **📊 Token Management Dashboard**: **Complete token lifecycle management** with creation, revocation, statistics, and comprehensive audit trails for enterprise token governance
- **🌐 Web-Based Management Interface**: **Secure localhost-only token administration** with intuitive dashboard, database binding configuration, real-time operations, and enterprise-grade access controls

> **Release note**: v0.6.0 introduced the authentication, token management,
> connection, and multi-worker features summarized above. These features do not
> remove the Beta status or the deployment limits documented for the current
> codebase.

### What's Also Included from v0.5.1

- **🔥 Critical at_eof Connection Fix**: Complete elimination of connection pool errors with intelligent health monitoring and self-healing recovery
- **🔧 Enterprise Logging System**: Level-based file separation with automatic cleanup and millisecond precision timestamps
- **📊 Advanced Data Analytics Suite**: 7 enterprise-grade data governance tools including quality analysis, lineage tracking, and performance monitoring
- **🏃‍♂️ High-Performance ADBC Integration**: Apache Arrow Flight SQL support with 3-10x performance improvements for large datasets
- **⚙️ Enhanced Configuration Management**: Complete ADBC configuration system with intelligent parameter validation

## Core Features

*   **MCP Protocol Implementation**: Provides standard MCP interfaces, supporting tool calls, resource management, and prompt interactions.
*   **Streamable HTTP Communication**: Unified HTTP endpoint supporting both request/response and streaming communication for optimal performance and reliability.
*   **Stdio Communication**: Standard input/output mode for direct integration with MCP clients like Cursor.
*   **Enterprise-Grade Architecture**: Modular design with comprehensive functionality:
    *   **Tools Manager**: Centralized tool registration and routing with unified interfaces (`doris_mcp_server/tools/tools_manager.py`)
    *   **Enhanced Monitoring Tools Module**: Advanced memory tracking, metrics collection, and flexible BE node discovery with modular, extensible design
    *   **Query Information Tools**: Enhanced SQL explain and profiling with configurable content truncation, file export for LLM attachments, and advanced query analytics
    *   **Resources Manager**: Resource management and metadata exposure (`doris_mcp_server/tools/resources_manager.py`)
    *   **Prompts Manager**: Intelligent prompt templates for data analysis (`doris_mcp_server/tools/prompts_manager.py`)
*   **Advanced Database Features**:
    *   **Query Execution**: High-performance SQL execution with advanced caching and optimization, enhanced connection stability and automatic retry mechanisms (`doris_mcp_server/utils/query_executor.py`)
    *   **Security Management**: Comprehensive SQL security validation with configurable blocked keywords, SQL injection protection, data masking, and unified security configuration management (`doris_mcp_server/utils/security.py`)
    *   **Metadata Extraction**: Comprehensive database metadata with catalog federation support (`doris_mcp_server/utils/schema_extractor.py`)
    *   **Performance Analysis**: Advanced column analysis, performance monitoring, and data analysis tools (`doris_mcp_server/utils/analysis_tools.py`)
*   **Catalog Federation Support**: Full support for multi-catalog environments (internal Doris tables and external data sources like Hive, MySQL, etc.)
*   **Enterprise Security**: Comprehensive security framework with authentication, authorization, SQL injection protection, and data masking capabilities with environment variable configuration support
*   **Web-Based Token Management**: Secure localhost-only interface for complete token lifecycle management with database binding, real-time statistics, and enterprise-grade access controls (`doris_mcp_server/auth/token_handlers.py`)
*   **Unified Configuration Framework**: Centralized configuration management through `config.py` with comprehensive validation, standardized parameter naming, and smart default database handling with automatic fallback to `information_schema`

## System Requirements

*   **Python**: 3.12+
*   **Database**: Apache Doris connection details (Host, Port, User, Password, Database)

## 🚀 Quick Start

### Installation from PyPI

```bash
# Install the latest version
pip install doris-mcp-server

# Install specific version
pip install doris-mcp-server==0.6.1
```

> **💡 Packaged Commands**: `doris-mcp-server` starts the MCP server.
> `doris-mcp-client` is a separate client for connecting to a server over
> Streamable HTTP or stdio; the two commands are not interchangeable.

### Start Streamable HTTP Mode (Web Service)

The primary communication mode offering optimal performance and reliability:

```bash
# Full configuration with database connection
doris-mcp-server \
    --transport http \
    --host 127.0.0.1 \
    --port 3000 \
    --db-host 127.0.0.1 \
    --db-port 9030 \
    --db-user root \
    --db-password your_password 
```

### Start Stdio Mode (for Cursor and other MCP clients)

Standard input/output mode for direct integration with MCP clients:

```bash
# For direct integration with MCP clients like Cursor
doris-mcp-server --transport stdio
```

### 🌐 Token Management Interface (New in v0.6.0)

Access the **Web-Based Token Management Dashboard** for enterprise-grade token administration:

#### **Secure Access Requirements**
- **Localhost Access Only**: Interface restricted to `127.0.0.1` and `::1` for maximum security
- **Admin Authentication**: Requires `TOKEN_MANAGEMENT_ADMIN_TOKEN` for access
- **Configuration Prerequisites**:
  ```bash
  # Generate separate high-entropy credentials; do not commit them.
  export TOKEN_ADMIN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
  export TOKEN_MANAGEMENT_ADMIN_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
  export ENABLE_HTTP_TOKEN_MANAGEMENT=true
  export ENABLE_TOKEN_AUTH=true
  export TOKEN_MANAGEMENT_ALLOWED_IPS=127.0.0.1,::1
  ```

#### **Interface Access**

Management requests accept the admin token only in an HTTP header. Query-string
tokens are rejected and must not be placed in URLs, browser history, or access
logs.

```bash
curl -H "Authorization: Bearer $TOKEN_MANAGEMENT_ADMIN_TOKEN" \
  http://127.0.0.1:3000/token/stats
```

The optional `/token/management` page must be opened through a client or local
proxy that supplies the same header. Its API requests use an in-page password
field and do not persist or propagate the token in URLs.

#### **Available Operations**
- **📊 Token Statistics**: Real-time overview of active, expired, and total tokens
- **➕ Create Tokens**: 
  - Basic information (ID, description, expiration)
  - **Database binding** (host, port, user, password, database)
  - Custom token values or auto-generated secure tokens
- **📋 Token Management**:
  - List all tokens with database binding status
  - One-click token revocation
  - Automated expired token cleanup
- **🔒 Enterprise Security**: 
  - All operations require admin authentication
  - Real-time IP validation
  - Complete audit logging
  - **Digest-only persistence** to `tokens.json`; plaintext is returned once
    when a token is created
  - **Multi-worker consistency** through a process-shared lock, atomic
    read-modify-write updates, and digest-only revocation records

> **🔐 Security Note**: The interface is designed for localhost administration only. It cannot be accessed remotely, ensuring maximum security for token management operations.

### Verify Installation

```bash
# Check installation
doris-mcp-server --version
doris-mcp-client --version
doris-mcp-server --help
doris-mcp-client --help

# Test HTTP mode (in another terminal)
curl --fail http://localhost:3000/live
curl --fail http://localhost:3000/ready
```

### Environment Variables (Optional)

Instead of command-line arguments, you can use environment variables:

```bash
# Basic Database Configuration
export DORIS_HOST="127.0.0.1"
export DORIS_PORT="9030"
export DORIS_USER="root"
export DORIS_PASSWORD="your_password"

# Keep the isolated legacy HTTP migration adapter disabled unless an
# identified 2025-11-25 client still needs /mcp/legacy.
export ENABLE_LEGACY_HTTP_ADAPTER=false

# Bound each resources/list, tools/list, and prompts/list response.
export MCP_LIST_PAGE_SIZE=100
# Expose eight progressive-disclosure domains by default. Set flat to expose
# the same 47 children under exact collision-free formal names.
export MCP_TOOL_EXPOSURE_MODE=hierarchical
# Load only these installed custom tool providers. Empty disables extensions.
export MCP_TOOL_PROVIDERS="orders_api"
# A launch-local key is generated automatically. Configure one shared
# high-entropy value when independently launched replicas share traffic.
export MCP_STATE_HANDLE_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export MCP_STATE_HANDLE_TTL_SECONDS=300

# Token Management Interface (Security-Critical)
export TOKEN_ADMIN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export TOKEN_MANAGEMENT_ADMIN_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export ENABLE_HTTP_TOKEN_MANAGEMENT=true
export ENABLE_TOKEN_AUTH=true
export TOKEN_MANAGEMENT_ALLOWED_IPS="127.0.0.1,::1"

# Then start with simplified command
doris-mcp-server --transport http --host 127.0.0.1 --port 3000
```

### Command Line Arguments

The `doris-mcp-server` command supports the following arguments:

| Argument | Description | Default | Required |
|:---------|:------------|:--------|:---------|
| `--transport` | Transport mode: `http` or `stdio` | `http` | No |
| `--host` | HTTP server host (HTTP mode only) | `localhost` | No |
| `--port` | HTTP server port (HTTP mode only) | `3000` | No |
| `--db-host` | Doris database host | `localhost` | No |
| `--db-port` | Doris database port | `9030` | No |
| `--db-user` | Doris database username | `root` | No |
| `--db-password` | Doris database password | - | Yes (unless in env) |

## Development Setup

For developers who want to build from source:

### 1. Clone the Repository

```bash
# Replace with the actual repository URL if different
git clone https://github.com/apache/doris-mcp-server.git
cd doris-mcp-server
```

### 2. Install Dependencies

The `dev` dependency group contains the test and quality tools used by CI:

```bash
uv sync --frozen --group dev
```

For pip-based workflows, `requirements.txt` contains production dependencies
only. `requirements-dev.txt` includes that runtime manifest and adds the same
lean test and quality toolchain:

```bash
pip install -r requirements-dev.txt
```

Production images and runtime environments must install only the package or
`requirements.txt`; pytest, linters, type checkers, and build backends are not
runtime dependencies.

### 3. Configure Environment Variables

Copy the `.env.example` file to `.env` and modify the settings according to your environment:

```bash
cp .env.example .env
```

**Key Environment Variables:**

*   **Database Connection**:
    *   `DORIS_HOST`: Database hostname (default: localhost)
    *   `DORIS_HOSTS`: Ordered FE MySQL failover hosts for one Doris cluster (comma-separated; `DORIS_HOST` is prepended when both are set)
    *   `DORIS_PORT`: Database port (default: 9030)
    *   `DORIS_USER`: Database username (default: root)
    *   `DORIS_PASSWORD`: Database password
    *   `DORIS_DATABASE`: Default database name (default: information_schema)
    *   `DORIS_MIN_CONNECTIONS`: Minimum connection pool size (default: 5)
    *   `DORIS_MAX_CONNECTIONS`: Maximum connection pool size (default: 20)
    *   `DORIS_FE_HTTP_HOST`: Independent FE HTTP host for profile, table-size, and monitoring tools (default: empty, falling back to `DORIS_HOST`)
    *   `DORIS_FE_HTTP_HOSTS`: Ordered FE HTTP failover hosts for the same Doris cluster (comma-separated)
    *   `DORIS_FE_HTTP_PORT`: Independent FE HTTP API port (default: 8030)
    *   `DORIS_BE_HOSTS`: Explicit BE HTTP allowlist for monitoring (comma-separated; BE HTTP metrics are disabled when empty)
    *   `DORIS_BE_WEBSERVER_PORT`: BE webserver port for monitoring tools (default: 8040)
    *   `DORIS_HTTP_CONNECT_TIMEOUT_SECONDS`: FE/BE HTTP connection timeout (default: 3)
    *   `DORIS_HTTP_READ_TIMEOUT_SECONDS`: FE/BE HTTP socket read timeout (default: 15)
    *   `DORIS_HTTP_TOTAL_TIMEOUT_SECONDS`: FE/BE HTTP total timeout (default: 30; hard maximum: 60)
    *   `DORIS_HTTP_MAX_RESPONSE_BYTES`: FE/BE HTTP response limit (default: 4 MiB; hard maximum: 16 MiB)
    *   `FE_ARROW_FLIGHT_SQL_PORT`: Frontend Arrow Flight SQL port for ADBC (New in v0.5.0)
    *   `BE_ARROW_FLIGHT_SQL_PORT`: Backend Arrow Flight SQL port for ADBC (New in v0.5.0)
*   **MCP HTTP Configuration**:
    *   `ENABLE_LEGACY_HTTP_ADAPTER`: Expose the isolated
        `2025-11-25` migration adapter at `/mcp/legacy` (default: false);
        modern traffic always uses `POST /mcp`
    *   `MCP_LIST_PAGE_SIZE`: Maximum resources, tools, or prompts returned
        per protocol page (default: 100; range: 1-1000)
    *   `MCP_TOOL_EXPOSURE_MODE`: Tool exposure mode. `hierarchical` returns
        eight domain tools with progressive child discovery; `flat` returns
        the same 47 children under exact collision-free formal names
        (default: hierarchical)
    *   `MCP_TOOL_PROVIDERS`: Comma-separated allowlist of installed
        `doris_mcp_server.tool_providers` entry points (default: empty)
    *   `MCP_STATE_HANDLE_SECRET`: Optional shared high-entropy key (at least
        32 bytes) used to authenticate explicit cross-call state handles
    *   `MCP_STATE_HANDLE_TTL_SECONDS`: Lifetime of an explicit state handle
        (default: 300 seconds; range: 1-3600)
*   **Authentication Configuration (Enhanced in v0.6.0)**:
    *   `ENABLE_TOKEN_AUTH`: Enable token-based authentication (default: false)
    *   `ENABLE_JWT_AUTH`: Enable JWT authentication (default: false)
    *   `ENABLE_OAUTH_AUTH`: Enable OAuth authentication (default: false)
    *   `OAUTH_ISSUER`: Exact external authorization-server issuer
    *   `OAUTH_RESOURCE`: Canonical MCP protected-resource URI
    *   `OAUTH_AUDIENCE`: Expected access-token audience (defaults to `OAUTH_RESOURCE`)
    *   `OAUTH_INTROSPECTION_URL`: Trusted RFC 7662 token-introspection endpoint
    *   `OAUTH_SCOPE` / `OAUTH_REQUIRED_SCOPE`: Allowed and mandatory external OAuth scopes
    *   `ENABLE_DORIS_OAUTH_AUTH`: Enable Doris-backed OAuth authentication (default: false)
    *   `DORIS_OAUTH_BASE_URL`: Public base URL used by Doris-backed OAuth discovery and token endpoints
    *   `DORIS_OAUTH_CIMD_FETCH_TIMEOUT_SECONDS`: Client ID Metadata Document fetch timeout (default: 5)
    *   `DORIS_OAUTH_CIMD_MAX_DOCUMENT_BYTES`: Maximum Client ID Metadata Document size (default: 5120)
    *   `DORIS_OAUTH_CIMD_DEFAULT_CACHE_SECONDS`: Cache lifetime when the document does not provide one (default: 300)
    *   `DORIS_OAUTH_CIMD_MAX_CACHE_SECONDS`: Maximum accepted document cache lifetime (default: 3600)
    *   `DORIS_OAUTH_CIMD_MAX_CLIENTS`: Maximum discovered Client ID Metadata clients held in memory (default: 1000)
    *   `TOKEN_FILE_PATH`: Path to tokens.json file for token management (default: tokens.json)
    *   `TOKEN_HOT_RELOAD`: Enable hot reloading of token configuration (default: true)
    *   `TOKEN_HASH_ALGORITHM`: Digest algorithm for newly created static tokens (`sha256` or `sha512`; default: `sha256`)
    *   `TOKEN_<ID>`: Explicit static bearer token; each active token must be a
        securely generated value of at least 32 characters
*   **Legacy Security Configuration**:
    *   `AUTH_TYPE`: Legacy authentication type (token/basic/oauth, deprecated - use individual switches)
    *   `ENABLE_SECURITY_CHECK`: Enable/disable SQL security validation (default: true)
    *   `BLOCKED_KEYWORDS`: Comma-separated list of blocked SQL keywords
    *   `ENABLE_MASKING`: Enable data masking (default: true)
    *   `MAX_RESULT_ROWS`: Deployment ceiling for returned query rows
        (default: 10000; absolute hard cap: 100000)
    *   `DEFAULT_RESULT_ROWS`: Default row budget when
        `doris_query.execute_query.max_rows`
        is omitted (default: 100; cannot exceed `MAX_RESULT_ROWS`)
*   **ADBC Configuration (New in v0.5.0)**:
    *   `ADBC_DEFAULT_MAX_ROWS`: Default maximum rows for ADBC queries
        (default: 10000; cannot exceed `MAX_RESULT_ROWS`)
    *   `ADBC_DEFAULT_TIMEOUT`: Default ADBC query timeout in seconds (default: 60)
    *   `ADBC_DEFAULT_RETURN_FORMAT`: Default return format - arrow/pandas/dict (default: arrow)
    *   `ADBC_CONNECTION_TIMEOUT`: ADBC connection timeout in seconds (default: 30)
    *   `ADBC_ENABLED`: Enable/disable ADBC tools (default: true)
*   **Performance Configuration**:
    *   `ENABLE_QUERY_CACHE`: Enable query caching (default: true)
    *   `CACHE_TTL`: Cache time-to-live in seconds (default: 300)
    *   `MAX_CONCURRENT_QUERIES`: Maximum concurrent queries (default: 50)
    *   `QUERY_TIMEOUT`: Deployment ceiling for query execution time
        (default and absolute hard cap: 300 seconds)
    *   `MAX_RESULT_BYTES`: Deployment ceiling for UTF-8 JSON row data
        (default: 1048576; allowed range: 256-16777216 bytes)
    *   `MAX_RESPONSE_CONTENT_SIZE`: Maximum response content size for LLM compatibility (default: 4096, New in v0.4.0)
*   **Enhanced Logging Configuration (Improved in v0.5.0)**:
    *   `LOG_LEVEL`: Log level (DEBUG/INFO/WARNING/ERROR, default: INFO)
    *   `LOG_FILE_PATH`: Log file path (automatically organized by level)
    *   `ENABLE_AUDIT`: Enable audit logging (default: true)
    *   `ENABLE_LOG_CLEANUP`: Enable automatic log cleanup (default: true, Enhanced in v0.5.0)
    *   `LOG_MAX_AGE_DAYS`: Maximum age of log files in days (default: 30, Enhanced in v0.5.0)
    *   `LOG_CLEANUP_INTERVAL_HOURS`: Log cleanup check interval in hours (default: 24, Enhanced in v0.5.0)
    *   **New Features in v0.5.0**:
        *   **Level-based File Separation**: Automatic separation into `debug.log`, `info.log`, `warning.log`, `error.log`, `critical.log`
        *   **Timestamped Format**: Enhanced formatting with millisecond precision and proper alignment
        *   **Background Cleanup Scheduler**: Automatic cleanup with configurable retention policies
        *   **Audit Trail**: Dedicated `audit.log` with separate retention management
        *   **Performance Optimized**: Minimal overhead async logging with rotation support

### Available MCP Tools

MCP `tools/list` exposes eight stable read-only domain tools. Call a domain
with an empty object to progressively discover its exact authorized child
tools, schemas, version support, availability, evidence, and risk annotations.
See [docs/tool-registry.md](docs/tool-registry.md). The checked-in catalog is
generated from the same validated domain definitions used at runtime.

`tool:list` authorizes domain-manifest discovery for OAuth sessions; it does
not authorize child execution. Children without discovery permission are
omitted, while authorized but unavailable children remain visible with
`callable=false`. Doris RBAC remains the final data authorization backend for
all Doris object access.

### 4. Run the Service

Execute the following command to start the server:

```bash
./start_server.sh
```
This command starts the FastAPI application with Streamable HTTP MCP service.
### 5. Deploying on docker

If you want to run only Doris MCP Server in docker:


```bash
cd doris-mcp-server
docker build -t doris-mcp-server .
docker run -d -p <host-port>:3000 -v /*your-host*/doris-mcp-server/.env:/app/.env --name <your-mcp-server-name> doris-mcp-server:latest
```

The container always listens on port `3000`. The bundled Compose deployment
publishes it on host port `3000` by default and publishes Grafana on host port
`3003`, so the two services do not contend for the same port. Override those
defaults with `MCP_HTTP_PORT` and `GRAFANA_HTTP_PORT`:

```bash
MCP_HTTP_PORT=3100 GRAFANA_HTTP_PORT=3103 docker compose up -d
```

Before starting the bundled stack, create the five ignored secret files used
by Compose. No database, MCP, Redis, or Grafana credential is stored in
`docker-compose.yml`, `.env.example`, or the rendered service environment:

```bash
mkdir -p .secrets
chmod 700 .secrets
python -c 'import secrets; print(secrets.token_urlsafe(32))' > .secrets/doris_password
python -c 'import secrets; print(secrets.token_urlsafe(32))' > .secrets/mcp_static_token
python -c 'import secrets; print(secrets.token_urlsafe(32))' > .secrets/redis_password
python -c 'import secrets; print(secrets.token_urlsafe(32))' > .secrets/grafana_admin_password
python -c 'import hashlib, pathlib; p=pathlib.Path(".secrets/doris_password").read_text().rstrip("\n").encode(); print("initial_root_password = *" + hashlib.sha1(hashlib.sha1(p).digest()).hexdigest().upper())' > .secrets/doris_fe_custom.conf
chmod 0444 .secrets/*
docker compose up -d
```

`doris_fe_custom.conf` contains Doris's two-stage SHA-1 password verifier, not
the plaintext password, and is mounted as the FE initial-root configuration.
The matching plaintext file is mounted only into the services that must
authenticate to Doris. Treat both files as credentials. The parent directory
remains mode `0700`, while the files are host-read-only and container-readable
for the non-root MCP process. To keep secret files elsewhere, copy
`.env.example` to `.env` and change only the `COMPOSE_*_FILE` host paths.

All third-party images in the Compose model use an explicit upstream version
and an immutable OCI digest. Upgrade them deliberately by changing both the
version tag and digest, then rerun the deployment contract and transport tests;
do not replace them with `latest` or another floating tag.

The image-level Docker health check uses `/live`, so a temporary Doris outage
does not cause the MCP process to be treated as dead. Compose overrides that
probe with `/ready` and only marks the service ready after the bounded Doris
probe succeeds. Both probes use the actual internal listener on port `3000`.

Compose allows `127.0.0.1:*` and `localhost:*` Host headers by default. A
deployment reached through another hostname, IP address, or reverse proxy must
set an explicit comma-separated allowlist; an allow-all `*` value is rejected:

```bash
MCP_ALLOWED_HOSTS='mcp.example.com,mcp.example.com:*' docker compose up -d
```

**Service Endpoints:**

*   **Streamable HTTP**: `http://<host>:<port>/mcp` (MCP messages use `POST`; do not depend on `GET` or `DELETE` compatibility behavior)
*   **Liveness**: `http://<host>:<port>/live` — process and protocol service are running; does not depend on Doris
*   **Readiness**: `http://<host>:<port>/ready` — returns 200 only when a bounded Doris `SELECT 1` probe succeeds; otherwise returns 503
*   **Legacy Health Check**: `http://<host>:<port>/health` — backward-compatible liveness alias; do not use it to decide whether to route database work

The readiness probe has a fixed short timeout and exposes only stable status
fields, not connection errors or credentials. Stdio mode has no HTTP health
surface; supervise the process and use the MCP initialization/discovery
handshake for transport-level availability.

> **Note**: The server uses Streamable HTTP for web-based communication, providing unified request/response and streaming capabilities.

## MCP Protocol Support and Migration

Doris MCP Server uses the official Python SDK v2 protocol core for both
Streamable HTTP and stdio. The MCP protocol revision used on the wire is
independent of the Doris MCP Server package version and the Python SDK package
version.

The authoritative protocol references are the
[MCP 2026-07-28 specification](https://modelcontextprotocol.io/specification/2026-07-28),
[2026-07-28 key changes](https://modelcontextprotocol.io/specification/2026-07-28/changelog),
and [Streamable HTTP transport specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http).

### Protocol and Transport Matrix

| Client protocol | Streamable HTTP | stdio | Connection behavior | Doris MCP Server status |
|:----------------|:----------------|:------|:--------------------|:------------------------|
| `2026-07-28` | Supported and preferred | Supported and preferred | Stateless, self-contained requests; no initialization handshake or protocol session | Covered by modern HTTP and real-process stdio tests |
| `2025-11-25` | Opt-in at `/mcp/legacy` | Supported for migration | Legacy `initialize` is accepted, but the server remains stateless and does not issue `Mcp-Session-Id` | HTTP adapter is disabled by default; covered by legacy HTTP and stdio tests |
| `2025-06-18` and older | Not guaranteed | Not guaranteed | Older negotiation and transport behavior is outside the supported compatibility contract | Upgrade the client before connecting |
| HTTP+SSE (`2024-11-05`) | Not supported | Not applicable | The retired separate SSE endpoint is not exposed | Migrate to Streamable HTTP at `/mcp` |

The HTTP compatibility path for `2025-11-25` is isolated from the modern
endpoint and disabled by default. New integrations should target `2026-07-28`
at `POST /mcp`.

### MCP 2026-07-28 Request Contract

Modern clients may call `server/discover` before any other method to inspect the
supported protocol versions, capabilities, and server identity. Discovery is
optional; every normal request is still self-contained.

Every modern request must carry these values in `params._meta`:

* `io.modelcontextprotocol/protocolVersion`: `2026-07-28`
* `io.modelcontextprotocol/clientCapabilities`: the capabilities available for
  that request, or an empty object
* `io.modelcontextprotocol/clientInfo`: the client name and version; this is
  recommended by the specification

For Streamable HTTP, send one JSON-RPC request per `POST /mcp` and include:

| Header | Required | Value |
|:-------|:---------|:------|
| `Content-Type` | Yes | `application/json` |
| `Accept` | Yes | Both `application/json` and `text/event-stream` |
| `MCP-Protocol-Version` | Yes | Must match the protocol version in `_meta` |
| `Mcp-Method` | Yes | Must match the JSON-RPC `method` |
| `Mcp-Name` | For `tools/call`, `resources/read`, and `prompts/get` | Must match `params.name` or `params.uri` |

Header names are case-insensitive, but method and name values are not. A
required header that is missing or disagrees with the request body is rejected
with HTTP 400 and the protocol `HeaderMismatch` error (`-32020`). Unsupported
protocol versions are rejected with `UnsupportedProtocolVersion` (`-32022`).
If a name or URI is not safe as a plain ASCII header value, encode its UTF-8
bytes as Base64 and send `Mcp-Name: =?base64?{value}?=` as defined by the
transport specification.

Example discovery request:

```bash
curl --request POST http://127.0.0.1:3000/mcp \
  --header 'Content-Type: application/json' \
  --header 'Accept: application/json, text/event-stream' \
  --header 'MCP-Protocol-Version: 2026-07-28' \
  --header 'Mcp-Method: server/discover' \
  --data '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "server/discover",
    "params": {
      "_meta": {
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": {
          "name": "example-client",
          "version": "1.0.0"
        }
      }
    }
  }'
```

Stdio carries the same JSON-RPC request metadata in the message body, but it
does not use HTTP headers. Do not write logs or other diagnostics to stdout in
stdio mode; stdout is reserved for MCP protocol messages.

### OpenTelemetry Trace Context

Clients may propagate the W3C `traceparent`, `tracestate`, and `baggage`
carrier fields in `params._meta`, as defined by
[MCP SEP-414](https://modelcontextprotocol.io/seps/414-request-meta),
[W3C Trace Context](https://www.w3.org/TR/trace-context/), and
[W3C Baggage](https://www.w3.org/TR/baggage/). The same message-level carrier
works on Streamable HTTP and stdio; these values are not separate MCP HTTP
headers.

When an OpenTelemetry provider and exporter are configured, each MCP operation
span is parented to the valid incoming trace context. The active context is
available to instrumented downstream work for the lifetime of that operation
and is reset before the next request. Trace carrier fields are never passed to
the Doris tool, resource, or prompt managers and are never copied into model
content or structured results.

The server validates trace carrier values before the SDK propagator sees them.
Malformed, oversized, duplicate, or orphaned fields are ignored independently,
and warning logs identify only the field name—never its supplied value.
Values under credential-like baggage keys such as `token`, `secret`, or
`authorization` are replaced with `[REDACTED]` before propagation. `baggage`
can still contain other deployment-sensitive correlation data, so clients
should send only values approved by their telemetry data-handling policy.

### List Pagination

`resources/list`, `tools/list`, and `prompts/list` return at most
`MCP_LIST_PAGE_SIZE` entries per response on both Streamable HTTP and stdio.
Results are ordered by their stable resource URI, tool name, or prompt name.
When `nextCursor` is present, pass that opaque value as the next request's
`cursor`; do not parse or construct cursors.

A cursor is an HMAC-authenticated explicit state handle bound to its list type,
scope, resource, current visible-list snapshot, authorization context, and
expiry. It does not depend on an MCP protocol session, transport connection, or
worker-local memory. Reusing it for another list, after visibility changes,
after expiry, after modification, or under another principal returns
`Invalid Params`. Restart the listing without a cursor in that case. This
prevents a multi-page traversal from silently duplicating, dropping, or
crossing permission-scoped entries.

The server generates a launch-local handle secret by default and passes it to
all workers created by the same CLI process. Set one shared
`MCP_STATE_HANDLE_SECRET` on independently launched replicas when a load
balancer can route consecutive pages to different instances. Handle payloads
contain bounded continuation metadata and are signed rather than encrypted;
credentials, SQL text, and query results must never be placed in them. See
[ADR 0002](docs/decisions/0002-explicit-state-handles.md).

List failures are never represented as successful empty collections. A Doris
metadata outage returns `List backend unavailable`; a Doris metadata permission
failure returns `List operation permission denied`; and an unexpected
tool/resource/prompt registry failure returns `Internal server error`. These
responses use JSON-RPC code `-32603` and include only the list operation and a
bounded error category/code, never backend exception text. A successful
response with an empty `resources`, `tools`, or `prompts` array therefore means
that the caller's visible collection is genuinely empty. The same contract
applies to Streamable HTTP and stdio, and a failed request does not prevent the
next list request from succeeding.

### Subscriptions and Change Notifications

The server does not currently advertise or serve `subscriptions/listen`.
Tools and prompts have no runtime mutation channel, and Doris catalog metadata
does not provide this process with a reliable cross-worker change-event source.
Cache expiry and periodic catalog polling are not treated as change events.

Consequently, MCP 2026-07-28 discovery reports `listChanged: false` for tools,
prompts, and resources and `subscribe: false` for resources. A
`subscriptions/listen` request returns `Method not found`; clients should
refresh lists explicitly. Streamable HTTP and true subprocess stdio tests
enforce this boundary. See
[the subscription decision record](docs/decisions/0001-subscriptions-require-change-events.md)
for the conditions required before the capability can be enabled.

### Tool JSON Schema Validation

Tool `inputSchema` and `outputSchema` use JSON Schema 2020-12. The server
validates every visible tool definition before advertising or executing it,
then validates each call's arguments before invoking Doris. Invalid arguments
return `Invalid Params` without echoing rejected values. Successful structured
results are also checked whenever a tool declares `outputSchema`; a server-side
schema mismatch is hidden behind `Internal error`.

Schemas are self-contained. Only same-document `$ref` and `$dynamicRef`
fragments are accepted; the server never fetches a schema over HTTP, from a
file URI, or from a relative URI. Recursive references are rejected by the
bounded validation policy. The default hard limits per schema are 64 KiB,
2,048 nodes, depth 32, 64 composition branches, and 64 references. Each input
or structured output is limited to 1 MiB, 10,000 nodes, depth 32, and 262,144
characters per string. At most 16 validation violations are reported, and
reports contain only instance paths and failed keywords.

These checks run in the shared protocol handler, so Streamable HTTP, modern
stdio, and legacy stdio use the same enforcement. MCP 2026-07-28 clients can
also receive array, string, number, or boolean `structuredContent` when a
matching `outputSchema` is declared.

### Migrating from MCP 2025-11-25

1. Upgrade the client to a `2026-07-28`-capable MCP SDK.
2. Continue using the `/mcp` endpoint for Streamable HTTP, but send every
   JSON-RPC message as its own POST request.
3. Remove `initialize`, `notifications/initialized`, `Mcp-Session-Id`, and any
   sticky-session dependency.
4. Add the protocol version and client capabilities to every request's `_meta`.
   Add client identity on every request where possible.
5. Add `MCP-Protocol-Version` and `Mcp-Method` to every HTTP request, plus
   `Mcp-Name` for named tool, resource, and prompt requests.
6. Stop using the removed HTTP GET stream, `Last-Event-ID`, and resumable SSE
   behavior. Reissue an interrupted request with a new JSON-RPC request ID.
7. Accept the required `resultType` field in modern results and handle
   protocol-defined errors such as `-32020`, `-32021`, and `-32022`.
8. Validate the migrated client against both Streamable HTTP and stdio if the
   integration supports both transports.

Clients that cannot migrate immediately may keep the `2025-11-25`
`initialize` flow over stdio. For Streamable HTTP, an operator must explicitly
set `ENABLE_LEGACY_HTTP_ADAPTER=true` and point that client to
`/mcp/legacy`; `/mcp` never falls back to the legacy transport. The adapter
remains stateless and does not create an HTTP protocol session.

### Deployment Constraints

* Bind local deployments to `127.0.0.1`, `localhost`, or `::1`. The transport
  validates both `Host` and `Origin` to protect against DNS rebinding.
* A bind address is not a public service identity. In particular,
  `0.0.0.0` does not authorize arbitrary Host or Origin values.
* The current Host/Origin policy does not provide an operator-configured public
  allowlist. Public hostnames and reverse proxies that rewrite Host or Origin
  are therefore not a supported deployment shape yet.
* HTTP startup fails when the bind host is not loopback and no authentication
  method is enabled. `ALLOW_UNAUTHENTICATED_NON_LOOPBACK=true` is an explicit
  dangerous override for isolated testing only; do not use it as a deployment
  shortcut.
* Stateless MCP requests do not require sticky HTTP sessions and can use
  multiple workers. Authentication modes can have stricter limits:
  Doris-backed OAuth stores tokens and per-user pools in process memory and
  must run with `WORKERS=1`.
* Use HTTPS whenever traffic leaves the local machine, and keep credentials in
  headers or process environment rather than URLs.

## Usage

Interaction with the Doris MCP Server requires an **MCP Client**. The client connects to the server's Streamable HTTP endpoint and sends requests according to the MCP specification to invoke the server's tools.

**Main Interaction Flow:**

1.  **(Optional) Discover the Server**: A modern client can call `server/discover` to inspect supported protocol versions, capabilities, and identity.
2.  **Discover Domains**: In the default `hierarchical` mode, `tools/list`
    returns the eight bounded read-only domains. Call a domain without
    arguments to discover its exact child names, schemas, and availability.
3.  **Call an Exact Child**: Call the same domain with `child_tool`,
    `arguments`, and the discovered `manifest_version`.
    *   **Example: Get the Table Schema Section**
        *   `name`: `doris_catalog`
        *   `child_tool`: `get_table_context`
        *   `arguments`: Include `database`, `table`, optional `catalog`, and
            `sections: ["schema"]`.
    *   In `flat` mode, call the collision-free formal name
        `doris_catalog_get_table_context` with the child arguments directly.
4.  **Handle Response**:
    *   **Non-streaming**: The client receives a response containing `content` or `isError`.
    *   **Streaming**: The client receives a series of progress notifications, followed by a final response.

Legacy `2025-11-25` stdio clients initialize as before. HTTP clients require
the explicitly enabled `/mcp/legacy` adapter and remain subject to the
stateless compatibility limits described above.

### Catalog Federation Support

The Doris MCP Server supports **catalog federation**, enabling interaction with multiple data catalogs (internal Doris tables and external data sources like Hive, MySQL, etc.) within a unified interface.

#### Key Features:

*   **Multi-Catalog Metadata Access**: The `doris_catalog` children accept an
    optional `catalog` argument where applicable.
*   **Cross-Catalog SQL Queries**: Use
    `doris_query.execute_query` with three-part table naming.
*   **Catalog Discovery**: Use `doris_catalog.list_catalogs`.

#### Three-Part Naming Requirement:

**All SQL queries MUST use three-part naming for table references:**

*   **Internal Tables**: `internal.database_name.table_name`
*   **External Tables**: `catalog_name.database_name.table_name`

#### Examples:

1.  **Get Available Catalogs:**
    ```json
    {
      "tool_name": "doris_catalog",
      "arguments": {
        "child_tool": "list_catalogs",
        "manifest_version": "<value returned by domain discovery>",
        "arguments": {}
      }
    }
    ```

2.  **Get Databases in Specific Catalog:**
    ```json
    {
      "tool_name": "doris_catalog",
      "arguments": {
        "child_tool": "list_databases",
        "manifest_version": "<value returned by domain discovery>",
        "arguments": {"catalog": "mysql"}
      }
    }
    ```

3.  **Query Internal Catalog:**
    ```json
    {
      "tool_name": "doris_query",
      "arguments": {
        "child_tool": "execute_query",
        "manifest_version": "<value returned by domain discovery>",
        "arguments": {
          "sql": "SELECT COUNT(*) FROM internal.ssb.customer"
        }
      }
    }
    ```

4.  **Query External Catalog:**
    ```json
    {
      "tool_name": "doris_query",
      "arguments": {
        "child_tool": "execute_query",
        "manifest_version": "<value returned by domain discovery>",
        "arguments": {
          "sql": "SELECT COUNT(*) FROM mysql.ssb.customer"
        }
      }
    }
    ```

5.  **Cross-Catalog Query:**
    ```json
    {
      "tool_name": "doris_query",
      "arguments": {
        "child_tool": "execute_query",
        "arguments": {
          "sql": "SELECT i.c_name, m.external_data FROM internal.ssb.customer i JOIN mysql.test.user_info m ON i.c_custkey = m.customer_id"
        }
      }
    }
    ```

## Security Configuration

The Doris MCP Server includes a comprehensive enterprise-grade security framework with advanced authentication, authorization, SQL security validation, and data masking capabilities enhanced in v0.6.0.

### Security Features (Enhanced in v0.6.0)

*   **🔐 Multi-Authentication System**: Complete Token, JWT, and OAuth authentication with independent control switches
*   **🔗 Token-Bound Database Configuration**: Revolutionary approach allowing tokens to carry their own database connection parameters
*   **🔄 Hot Reload Security**: Zero-downtime security configuration updates with intelligent token revalidation
*   **⚡ Route-Safe Validation**: Token-bound Doris routes are validated through their dedicated pools, with a short success cache so pings do not reconnect on every request
*   **🛡️ Role-Based Authorization**: Advanced RBAC with four-tier security classification
*   **🚫 Enhanced SQL Security**: Advanced SQL injection protection with improved pattern detection
*   **🎭 Intelligent Data Masking**: Automatic sensitive data masking with user-based permissions
*   **📊 Security Analytics**: Comprehensive audit trails and security monitoring

### Authentication Configuration (v0.6.0)

Configure the new authentication system with granular control:

```bash
# Generate a deployment-specific token before enabling static authentication.
export TOKEN_ADMIN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"

# Individual Authentication Control (New in v0.6.0)
ENABLE_TOKEN_AUTH=true          # Enable token-based authentication
ENABLE_JWT_AUTH=false           # Enable JWT authentication  
ENABLE_OAUTH_AUTH=false         # Enable OAuth authentication

# Token Management (New in v0.6.0)
TOKEN_FILE_PATH=tokens.json     # Token configuration file
TOKEN_HOT_RELOAD=true          # Enable hot reloading
TOKEN_DB_VALIDATION_TTL_SECONDS=30  # Cache successful Doris route checks

# Legacy Configuration (Deprecated)
# AUTH_TYPE=token               # Use individual switches instead
```

The repository ships no usable static token or legacy secret. Startup fails
when static token authentication is enabled without at least one active,
high-entropy `TOKEN_<ID>` value or an equivalent entry in `TOKEN_FILE_PATH`.

### External OAuth/OIDC Access Token Validation

External OAuth is fail-closed. Before the server requests user information, it
uses a trusted RFC 7662 introspection endpoint and requires an active,
unexpired token with the exact configured issuer, expected audience, MCP
resource binding, required scopes, and a subject. A successful userinfo request
is not accepted as proof that a token was issued for this MCP server. The
userinfo subject must also match the introspected token subject.

`OAUTH_RESOURCE` is sent on authorization-code and refresh-token requests.
`OAUTH_AUDIENCE` defaults to that resource URI. `OAUTH_REQUIRED_SCOPE` defaults
to all scopes in `OAUTH_SCOPE`; scopes returned by the authorization server but
not present in `OAUTH_SCOPE` are excluded from the authentication context.

```bash
ENABLE_OAUTH_AUTH=true
OAUTH_CLIENT_ID=your_oauth_client_id
OAUTH_CLIENT_SECRET=your_oauth_client_secret
OAUTH_REDIRECT_URI=https://mcp.example.com/auth/callback

OAUTH_ISSUER=https://issuer.example.com
OAUTH_RESOURCE=https://mcp.example.com/mcp
OAUTH_AUDIENCE=https://mcp.example.com/mcp
OAUTH_INTROSPECTION_URL=https://issuer.example.com/introspect
OAUTH_USERINFO_URL=https://issuer.example.com/userinfo

OAUTH_SCOPE="tool:list tool:call:exec_query resource:list resource:read"
OAUTH_REQUIRED_SCOPE="tool:list resource:read"
```

An authorization-server discovery document may provide the introspection and
userinfo endpoints, but its `issuer` must exactly match `OAUTH_ISSUER`.
Dedicated `OAUTH_INTROSPECTION_CLIENT_ID` and
`OAUTH_INTROSPECTION_CLIENT_SECRET` values may be configured; otherwise the
regular OAuth client credentials are used. Remote issuer, discovery,
introspection, and userinfo URLs must use HTTPS.

For HTTP deployments, the server publishes RFC 9728 metadata at
`/.well-known/oauth-protected-resource`. Missing or invalid credentials receive
an HTTP 401 Bearer challenge containing `resource_metadata` and the minimum
configured scopes. A valid token that lacks an operation scope receives HTTP
403 with `error="insufficient_scope"` and the exact scope required for
step-up authorization. Access tokens and provider-internal error details are
not copied into these responses. These HTTP OAuth challenges do not apply to
stdio transport, where credentials are supplied through the local process
environment.

External OAuth operation scopes are exact: listing tools requires `tool:list`,
calling a tool requires `tool:call:<tool-name>`, listing and reading resources
require `resource:list` and `resource:read`, and Prompt operations require
`prompt:list` and `prompt:get`. Add every callable tool scope to
`OAUTH_SCOPE`; `*` and unrelated scopes never satisfy an operation check.
Static token, JWT, anonymous loopback, and local stdio authorization keep
their existing non-OAuth permission behavior.

### Doris-Backed OAuth Authentication

Doris-backed OAuth is a separate OAuth mode where Doris itself is the authorization backend. The MCP client discovers this server's OAuth metadata, the user signs in with a Doris username and password, the server validates those credentials by creating a per-user Doris connection pool, and issued `doa_` access tokens route tool calls through that Doris user's pool. MCP scopes control which MCP operations can be called; Doris RBAC controls which catalogs, databases, tables, and metadata the user can see.

This mode is not the same as external OAuth/OIDC. `ENABLE_DORIS_OAUTH_AUTH=true` conflicts with `ENABLE_OAUTH_AUTH=true`, `OAUTH_ENABLED=true`, and legacy `AUTH_TYPE=oauth`; startup fails fast if both modes are configured. A standard MCP agent enters one MCP URL and should discover exactly one OAuth behavior for that URL, so the existing `/auth/*` external OAuth login flow is not used in Doris-backed OAuth mode.

Each Doris OAuth token record is bound to the resource selected during
authorization. The protected MCP endpoint accepts only the exact canonical
resource `${DORIS_OAUTH_BASE_URL}/mcp`; a token issued for the authorization
server or any other resource is rejected with an `invalid_token` challenge
before a per-user Doris pool is used. Clients must send that canonical
`resource` in both the authorization request and authorization-code token
request. The token endpoint returns RFC 8707 `invalid_target` if the value is
missing or does not exactly match the resource bound to the authorization code.

#### Minimal Local Configuration

The following example is for local development on a single worker:

```bash
TRANSPORT=http
WORKERS=1

DORIS_HOST=localhost
DORIS_PORT=9030
DORIS_USER=root
DORIS_PASSWORD=<service-account-password>
DORIS_DATABASE=information_schema

ENABLE_DORIS_OAUTH_AUTH=true
DORIS_OAUTH_BASE_URL=http://localhost:3000
ENABLE_OAUTH_AUTH=false

DORIS_OAUTH_DB_TOOLS_ENABLED=true
DORIS_OAUTH_DB_TOOL_ALLOWLIST=get_db_list,get_db_table_list,get_table_schema,get_table_comment,get_table_column_comments,get_table_indexes,get_catalog_list
DORIS_OAUTH_QUERY_TOOLS_ENABLED=true
DORIS_OAUTH_EXPLAIN_TOOLS_ENABLED=true

# Optional: let Doris RBAC, not the legacy MCP SQL guard, decide DDL/DML.
ENABLE_SECURITY_CHECK=false
```

The configured service Doris account is still required by startup validation and by non-Doris-OAuth compatibility paths. Doris-backed OAuth requests are fail-closed if the per-user pool is missing and must not fall back to the service/global account.

#### Doris OAuth Tool Access

`DORIS_OAUTH_DB_TOOLS_ENABLED=true` opens the reviewed metadata bucket. The reviewed tools are:

*   `get_db_list`
*   `get_db_table_list`
*   `get_table_schema`
*   `get_table_comment`
*   `get_table_column_comments`
*   `get_table_indexes`
*   `get_catalog_list`

For normal MCP OAuth flows, clients do not need to pass a long `--scopes` list. If the OAuth request omits scope, the server grants the configured Doris OAuth capability envelope. For MySQL-channel operations, Doris RBAC decides whether the logged-in Doris user can actually read metadata, run SQL, or explain SQL.

`DORIS_OAUTH_QUERY_TOOLS_ENABLED=true` opens `exec_query`. `DORIS_OAUTH_EXPLAIN_TOOLS_ENABLED=true` opens `get_sql_explain`. If `ENABLE_SECURITY_CHECK=true`, the legacy MCP SQL security layer can still reject some SQL before Doris sees it. Set `ENABLE_SECURITY_CHECK=false` when the intended policy is to let Doris RBAC decide SQL/DDL/DML.

Doris-backed OAuth still does not open prompts, ADBC, FE HTTP profile/monitoring, audit/governance, or performance analytics in this phase unless those paths are separately routed through per-user credentials or given an explicit service-account/admin design.

#### OAuth Client Registration

The preferred client-registration order is:

1. Use a client configured by the operator when one is available.
2. Use a Client ID Metadata Document (CIMD) by sending its HTTPS URL as
   `client_id`.
3. Use Dynamic Client Registration (DCR) only as a compatibility fallback.

Authorization-server metadata advertises
`client_id_metadata_document_supported=true`. A CIMD must be a JSON object whose
`client_id` exactly equals the requested URL and whose `client_name` and
`redirect_uris` are valid. This server currently accepts public CIMD clients
with `token_endpoint_auth_method=none`, authorization-code plus optional
refresh-token grants, the `code` response type, and exact redirect URI
matching. Native clients may use a reverse-domain custom scheme or loopback
HTTP URI; web clients must use non-loopback HTTPS.

CIMD retrieval is fail-closed. The URL must use HTTPS, contain a path, and have
no userinfo, fragment, backslash, or dot path segment. The resolver rejects
special-use destination addresses, pins validated DNS results for the request,
does not follow redirects, requires JSON, limits the response to 5 KiB by
default, rejects embedded shared secrets or private key material, and caches
only valid documents according to HTTP cache controls. Loopback metadata hosts
are accepted only when the Doris OAuth issuer is itself a loopback development
issuer. The login page displays the client and redirect hostnames and warns
before a localhost redirect.

The CIMD controls can be adjusted with
`DORIS_OAUTH_CIMD_FETCH_TIMEOUT_SECONDS`,
`DORIS_OAUTH_CIMD_MAX_DOCUMENT_BYTES`,
`DORIS_OAUTH_CIMD_DEFAULT_CACHE_SECONDS`,
`DORIS_OAUTH_CIMD_MAX_CACHE_SECONDS`, and
`DORIS_OAUTH_CIMD_MAX_CLIENTS`.

DCR remains available for older clients when
`DORIS_OAUTH_DYNAMIC_CLIENT_REGISTRATION_MODE` permits it. DCR requests must
include `application_type` as either `native` or `web`; the same type-specific
and exact redirect URI rules apply. Production DCR still requires
`ENABLE_DORIS_OAUTH_PRODUCTION_DCR=true`.

Authorization success and redirectable error responses include the exact
authorization-server issuer in the RFC 9207 `iss` parameter. Discovery
advertises `authorization_response_iss_parameter_supported=true`; clients must
compare the returned value with the discovered issuer without URI
normalization before accepting the response.

#### Current Operational Limits

Doris-backed OAuth is currently single-process and single-worker:

*   `WORKERS=1` is required. `WORKERS=0` expands to CPU count and fails when Doris-backed OAuth is enabled.
*   OAuth clients, authorization transactions, authorization codes, access tokens, refresh tokens, and DCR clients are memory-only and process-local.
*   Per-user Doris connection pools are process-local.
*   Process restart requires users to sign in again.
*   Tokens and pools are not shared across workers, processes, or nodes.
*   Stateless horizontal scaling and multi-node deployment are not supported for Doris-backed OAuth yet.

If an access token is otherwise valid but its Doris user pool is gone, the request fails with login required / `DORIS_OAUTH_POOL_MISSING`. The server does not store raw Doris passwords for automatic pool reconstruction.

#### Production Hardening

For production deployments:

*   Use an HTTPS `DORIS_OAUTH_BASE_URL` for any non-loopback address.
*   Keep `DORIS_OAUTH_ALLOW_INSECURE_HTTP=false`; non-loopback `http://` is rejected unless explicitly overridden for development.
*   Enable `DORIS_OAUTH_TRUST_PROXY_HEADERS` only behind a controlled reverse proxy and set `DORIS_OAUTH_TRUSTED_PROXY_CIDRS`.
*   Keep login, authorize, token, refresh, revoke, and DCR rate limits enabled.
*   Use Doris RBAC as the final data authorization boundary and grant Doris users only the data they should inspect.
*   Do not log Doris passwords, authorization headers, access tokens, refresh tokens, authorization codes, PKCE verifiers, or client secrets.
*   Treat the `doa_` prefix as reserved for Doris-backed OAuth access tokens; static tokens and JWT bearer values must not use it.
*   Prefer preconfigured clients or Client ID Metadata Documents. Keep DCR as a compatibility fallback; production DCR requires `ENABLE_DORIS_OAUTH_PRODUCTION_DCR=true`.

### Token-Bound Database Configuration (New in v0.6.0)

Managed token creation returns the bearer value once and writes only its digest
to `tokens.json`. For manual provisioning, generate the bearer value and digest
outside the repository, store the bearer value in the client secret store, and
place only the digest in the server file:

```bash
python - <<'PY'
import hashlib
import secrets

token = secrets.token_urlsafe(32)
print(f"Bearer token (store once): {token}")
print(f"token_digest: sha256:{hashlib.sha256(token.encode()).hexdigest()}")
PY
```

The v2 file format uses the generated digest:

```json
{
  "version": "2.0",
  "tokens": [
    {
      "token_id": "customer-a-token",
      "token_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
      "created_at": "2026-07-29T00:00:00Z",
      "expires_at": null,
      "last_used": null,
      "description": "Customer A dedicated database access",
      "is_active": true,
      "database_config": {
        "host": "customer-a-db.example.com",
        "port": 9030,
        "user": "customer_a_user",
        "password": "secure_password",
        "database": "customer_a_data",
        "charset": "UTF8",
        "fe_http_port": 8030
      }
    }
  ]
}
```

Replace the all-zero example with the generated digest; it is intentionally not
a usable credential. Managed writes are atomic and set the file mode to `0600`.
Version 1 files containing `token` plaintext are accepted once for migration,
then immediately replaced with version 2 digest-only records. The server cannot
recover or display the original bearer value from `token_digest`.

### Hot Reload Configuration Updates (New in v0.6.0)

The system automatically detects and applies configuration changes:

- **Automatic Detection**: File modification monitoring every 10 seconds
- **Instant Validation**: Immediate database configuration validation for new tokens
- **Zero Downtime**: Configuration updates without service interruption
- **Rollback Protection**: Automatic rollback on configuration errors
- **Audit Trail**: Complete logging of configuration changes

#### Token Authentication Example

```python
# Client authentication with token
auth_info = {
    "type": "token",
    "token": "your_jwt_token",
    "session_id": "unique_session_id"
}
```

#### Basic Authentication Example

```python
# Client authentication with username/password
auth_info = {
    "type": "basic",
    "username": "analyst",
    "password": "secure_password",
    "session_id": "unique_session_id"
}
```

### Authorization & Security Levels

The system supports four security levels with hierarchical access control:

| Security Level | Access Scope | Typical Use Cases |
|:---------------|:-------------|:------------------|
| **Public** | Unrestricted access | Public reports, general statistics |
| **Internal** | Company employees | Internal dashboards, business metrics |
| **Confidential** | Authorized personnel | Customer data, financial reports |
| **Secret** | Senior management | Strategic data, sensitive analytics |

#### Role Configuration

External OAuth role mapping is configured through environment variables:

```env
# Roles supplied when the provider returns no role claim
OAUTH_DEFAULT_ROLES=oauth_user

# Fallbacks for users whose roles do not occur in the JSON mappings
OAUTH_DEFAULT_SECURITY_LEVEL=internal
OAUTH_DEFAULT_PERMISSIONS=read_data

# Exact domains only. Domain elevation is applied only when the provider
# returns email_verified=true.
OAUTH_TRUSTED_DOMAINS=example.com,internal.example.com
OAUTH_TRUSTED_DOMAIN_SECURITY_LEVEL=confidential

# Each JSON value replaces the complete built-in mapping.
OAUTH_ROLE_SECURITY_LEVELS_JSON={"analyst":"internal","executive":"secret"}
OAUTH_ROLE_PERMISSIONS_JSON={"analyst":["read_data","query_database"],"executive":["read_data","query_database","admin"]}
```

Role names and trusted domains are matched case-insensitively. Supported
security levels are `public`, `internal`, `confidential`, and `secret`. An
explicit empty permission array denies application permissions for that role;
an empty `OAUTH_DEFAULT_PERMISSIONS` value makes unknown roles fail closed.

The built-in role defaults preserve previous behavior for `admin`,
`administrator`, `data_admin`, `super_admin`, `data_analyst`, `developer`,
`manager`, `viewer`, `user`, and `oauth_user`. No email domain is trusted by
default.

These settings govern MCP application permissions and security classification.
Database, table, column, and row access must still be enforced with Doris users,
roles, grants, views, and row policies; OAuth mapping does not bypass Doris
authorization. See the
[Doris fine-grained access-control guide](docs/doris-fine-grained-access-control.md)
for an end-to-end column and row policy example, MCP identity-routing choices,
and a verification checklist.

### SQL Security Validation

The system automatically validates SQL queries for security risks:

#### Blocked Operations

Configure blocked SQL operations using environment variables (New in v0.4.2):

```bash
# Enable/disable SQL security check (New in v0.4.2)
ENABLE_SECURITY_CHECK=true

# Customize blocked keywords via environment variable (New in v0.4.2)
BLOCKED_KEYWORDS="DROP,DELETE,TRUNCATE,ALTER,CREATE,INSERT,UPDATE,GRANT,REVOKE,EXEC,EXECUTE,SHUTDOWN,KILL"

# Maximum query complexity score
MAX_QUERY_COMPLEXITY=100
```

**Default Blocked Keywords (Unified in v0.4.2):**
- **DDL Operations**: DROP, CREATE, ALTER, TRUNCATE
- **DML Operations**: DELETE, INSERT, UPDATE  
- **DCL Operations**: GRANT, REVOKE
- **System Operations**: EXEC, EXECUTE, SHUTDOWN, KILL

#### SQL Injection Protection

The system automatically detects and blocks:

*   **Union-based injections**: `UNION SELECT` attacks
*   **Boolean-based injections**: `OR 1=1` patterns  
*   **Time-based injections**: `SLEEP()`, `WAITFOR` functions
*   **Comment injections**: `--`, `/**/` patterns
*   **Stacked queries**: Multiple statements separated by `;`

#### Example Security Validation

```python
# This query would be blocked
dangerous_sql = "SELECT * FROM users WHERE id = 1; DROP TABLE users;"

# This query would be allowed
safe_sql = "SELECT name, email FROM users WHERE department = 'sales'"
```

### Data Masking Configuration

Configure automatic data masking for sensitive information:

#### Built-in Masking Rules

```python
# Default masking rules
masking_rules = [
    {
        "column_pattern": r".*phone.*|.*mobile.*",
        "algorithm": "phone_mask",
        "parameters": {
            "mask_char": "*",
            "keep_prefix": 3,
            "keep_suffix": 4
        },
        "security_level": "internal"
    },
    {
        "column_pattern": r".*email.*", 
        "algorithm": "email_mask",
        "parameters": {"mask_char": "*"},
        "security_level": "internal"
    },
    {
        "column_pattern": r".*id_card.*|.*identity.*",
        "algorithm": "id_mask", 
        "parameters": {
            "mask_char": "*",
            "keep_prefix": 6,
            "keep_suffix": 4
        },
        "security_level": "confidential"
    }
]
```

#### Masking Algorithms

| Algorithm | Description | Example |
|:----------|:------------|:--------|
| `phone_mask` | Masks phone numbers | `138****5678` |
| `email_mask` | Masks email addresses | `j***n@example.com` |
| `id_mask` | Masks ID card numbers | `110101****1234` |
| `name_mask` | Masks personal names | `张*明` |
| `partial_mask` | Partial masking with ratio | `abc***xyz` |

#### Custom Masking Rules

Add custom masking rules in your configuration:

```python
# Custom masking rule
custom_rule = {
    "column_pattern": r".*salary.*|.*income.*",
    "algorithm": "partial_mask",
    "parameters": {
        "mask_char": "*",
        "mask_ratio": 0.6
    },
    "security_level": "confidential"
}
```

### Security Configuration Examples

#### Environment Variables

```bash
# Generate this outside source control, then inject it into the process.
export TOKEN_SECURITY_ADMIN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export ENABLE_TOKEN_AUTH=true
ENABLE_MASKING=true
MAX_RESULT_ROWS=10000
BLOCKED_SQL_OPERATIONS=DROP,DELETE,TRUNCATE,ALTER
MAX_QUERY_COMPLEXITY=100
ENABLE_AUDIT=true
```

#### Sensitive Tables Configuration

```python
# Configure sensitive tables with security levels
sensitive_tables = {
    "user_profiles": "confidential",
    "payment_records": "secret", 
    "employee_salaries": "secret",
    "customer_data": "confidential",
    "public_reports": "public"
}
```

### Security Best Practices

1. **🔑 Strong Authentication**: Use JWT tokens with proper expiration
2. **🎯 Principle of Least Privilege**: Grant minimum required permissions
3. **🔍 Regular Auditing**: Enable audit logging for security monitoring
4. **🛡️ Input Validation**: All SQL queries are automatically validated
5. **🎭 Data Classification**: Properly classify data with security levels
6. **🔄 Regular Updates**: Keep security rules and configurations updated
7. **Doris-backed OAuth Hardening**: Use HTTPS, keep external OAuth disabled in this mode, keep `WORKERS=1`, rely on Doris RBAC for MySQL-channel data access, and expose only operations that are configured and verified to use the logged-in Doris user's credentials.

### Security Monitoring

The system provides comprehensive security monitoring:

```python
# Security audit log example
{
    "timestamp": "2024-01-15T10:30:00Z",
    "user_id": "analyst_user",
    "action": "query_execution", 
    "resource": "customer_data",
    "result": "blocked",
    "reason": "insufficient_permissions",
    "risk_level": "medium"
}
```

> **⚠️ Important**: Always test security configurations in a development environment before deploying to production. Regularly review and update security policies based on your organization's requirements.

## Connecting with Cursor

You can connect Cursor to this MCP server using Stdio mode (recommended) or Streamable HTTP mode.

### Stdio Mode

Stdio mode allows Cursor to manage the server process directly. Configuration is done within Cursor's MCP Server settings file (typically `~/.cursor/mcp.json` or similar).

### Method 1: Using PyPI Installation (Recommended)

Install the package from PyPI and configure Cursor to use it:

```bash
pip install doris-mcp-server
```

**Configure Cursor:** Add an entry like the following to your Cursor MCP configuration:

```json
{
  "mcpServers": {
    "doris-stdio": {
      "command": "doris-mcp-server",
      "args": ["--transport", "stdio"],
      "env": {
        "DORIS_HOST": "127.0.0.1",
        "DORIS_PORT": "9030",
        "DORIS_USER": "root",
        "DORIS_PASSWORD": "your_db_password"
      }
    }
  }
}
```

### Method 2: Using uv (Development)

If you have `uv` installed and want to run from source:

```bash
uv run --project /path/to/doris-mcp-server doris-mcp-server
```

**Note:** Replace `/path/to/doris-mcp-server` with the actual absolute path to your project directory.

**Configure Cursor:** Add an entry like the following to your Cursor MCP configuration:

```json
{
  "mcpServers": {
    "doris-stdio": {
      "command": "uv",
      "args": ["run", "--project", "/path/to/your/doris-mcp-server", "doris-mcp-server"],
      "env": {
        "DORIS_HOST": "127.0.0.1",
        "DORIS_PORT": "9030",
        "DORIS_USER": "root",
        "DORIS_PASSWORD": "your_db_password"
      }
    }
  }
}
```

### Streamable HTTP Mode

Streamable HTTP mode requires you to run the MCP server independently first, and then configure Cursor to connect to it.

1.  **Configure `.env`:** Ensure your database credentials and any other necessary settings are correctly configured in the `.env` file within the project directory.
2.  **Start the Server:** Run the server from your terminal in the project's root directory:
    ```bash
    ./start_server.sh
    ```
    This script reads the `.env` file and starts the Streamable HTTP server on
    `127.0.0.1` by default. A non-loopback listener requires at least one
    authentication method.
3.  **Configure Cursor:** Add an entry like the following to your Cursor MCP configuration, pointing to the running server's Streamable HTTP endpoint:

    ```json
    {
      "mcpServers": {
        "doris-http": {
           "url": "http://127.0.0.1:3000/mcp"
        }
      }
    }
    ```
    
    > **Note**: Adjust the host/port if your server runs on a different address. The `/mcp` endpoint is the unified Streamable HTTP interface.

After configuring either mode in Cursor, you should be able to select the server (e.g., `doris-stdio` or `doris-http`) and use its tools.

## Connecting with Kiro

[![Add to Kiro](https://kiro.dev/images/add-to-kiro.svg)](https://kiro.dev/launch/mcp/add?name=doris-mcp&config=%7B%22command%22%3A%22doris-mcp-server%22%2C%22args%22%3A%5B%22--transport%22%2C%22stdio%22%5D%2C%22env%22%3A%7B%22DORIS_HOST%22%3A%22127.0.0.1%22%2C%22DORIS_PORT%22%3A%229030%22%2C%22DORIS_USER%22%3A%22root%22%2C%22DORIS_PASSWORD%22%3A%22your_db_password%22%7D%7D)

Or add the following to your Kiro MCP config file (`~/.kiro/settings/mcp.json` for global, or `.kiro/settings/mcp.json` for project-scoped). See the [Kiro MCP documentation](https://kiro.dev/docs/mcp/) for more details.

```json
{
  "mcpServers": {
    "doris-stdio": {
      "command": "doris-mcp-server",
      "args": ["--transport", "stdio"],
      "env": {
        "DORIS_HOST": "127.0.0.1",
        "DORIS_PORT": "9030",
        "DORIS_USER": "root",
        "DORIS_PASSWORD": "your_db_password"
      }
    }
  }
}
```

## Directory Structure

```
doris-mcp-server/
├── doris_mcp_server/           # Main server package
│   ├── main.py                 # Main entry point and FastAPI app
│   ├── multiworker_app.py      # Multi-worker application module (New in v0.6.0)
│   ├── auth/                   # Authentication modules (New in v0.6.0)
│   │   ├── token_manager.py    # Enterprise token management with hot reload
│   │   ├── jwt_manager.py      # JWT authentication provider
│   │   ├── oauth_provider.py   # OAuth authentication provider  
│   │   ├── oauth_handlers.py   # OAuth HTTP endpoint handlers
│   │   ├── token_handlers.py   # Token management HTTP endpoints
│   │   ├── auth_middleware.py  # Authentication middleware
│   │   └── __init__.py
│   ├── tools/                  # MCP tools implementation
│   │   ├── tools_manager.py    # Centralized tools management and registration
│   │   ├── resources_manager.py # Resource management and metadata exposure
│   │   ├── prompts_manager.py  # Intelligent prompt templates for data analysis
│   │   └── __init__.py
│   ├── utils/                  # Core utility modules
│   │   ├── config.py           # Configuration management with validation
│   │   ├── db.py               # Enhanced database connection management with token binding (Enhanced in v0.6.0)
│   │   ├── query_executor.py   # High-performance SQL execution with caching
│   │   ├── security.py         # Advanced security management and authentication (Enhanced in v0.6.0)
│   │   ├── schema_extractor.py # Metadata extraction with catalog federation
│   │   ├── analysis_tools.py   # Data analysis and performance monitoring
│   │   ├── data_governance_tools.py  # Data lineage and freshness monitoring (v0.5.0)
│   │   ├── data_quality_tools.py     # Comprehensive data quality analysis (v0.5.0)
│   │   ├── data_exploration_tools.py # Advanced statistical analysis (v0.5.0)
│   │   ├── security_analytics_tools.py # Access pattern analysis (v0.5.0)
│   │   ├── dependency_analysis_tools.py # Impact analysis and dependency mapping (v0.5.0)
│   │   ├── performance_analytics_tools.py # Query optimization and capacity planning (v0.5.0)
│   │   ├── adbc_query_tools.py       # High-performance Arrow Flight SQL operations (v0.5.0)
│   │   ├── logger.py           # Logging configuration
│   │   └── __init__.py
│   └── __init__.py
├── doris_mcp_client/           # MCP client implementation
│   ├── client.py               # Unified MCP client for testing and integration
│   ├── README.md               # Client documentation
│   └── __init__.py
├── logs/                       # Log files directory
├── tokens.json                 # Token configuration file (New in v0.6.0)
├── README.md                   # This documentation
├── CHANGELOG.md                 # Tagged release history and unreleased changes
├── .env.example                # Environment variables template
├── requirements.txt            # Runtime-only Python dependencies
├── requirements-dev.txt        # Runtime plus test and quality dependencies
├── pyproject.toml              # Project configuration and entry points
├── uv.lock                     # UV package manager lock file
├── generate_requirements.py    # Requirements generation script
├── start_server.sh             # Server startup script
└── restart_server.sh           # Server restart script
```

## Developing New Tools

This section outlines the process for adding new MCP tools to the Doris MCP Server, based on the unified modular architecture with centralized tool management.

Existing business APIs do not need to be built into this repository. Package
them as explicitly installed, allowlisted custom tool providers instead. The
[custom tool provider guide](docs/custom-tool-providers.md) defines the entry
point contract, lifecycle, process-local QPS limits, authentication boundary,
FastGPT integration, and production security checklist.

### 1. Leverage Existing Utility Modules

The server provides comprehensive utility modules for common database operations:

*   **`doris_mcp_server/utils/db.py`**: Database connection management with connection pooling and health monitoring.
*   **`doris_mcp_server/utils/query_executor.py`**: High-performance SQL execution with advanced caching, optimization, and performance monitoring.
*   **`doris_mcp_server/utils/schema_extractor.py`**: Metadata extraction with full catalog federation support.
*   **`doris_mcp_server/utils/security.py`**: Comprehensive security management, SQL validation, and data masking.
*   **`doris_mcp_server/utils/analysis_tools.py`**: Advanced data analysis and statistical tools.
*   **`doris_mcp_server/utils/config.py`**: Configuration management with validation.
*   **`doris_mcp_server/utils/data_governance_tools.py`**: Data lineage tracking and freshness monitoring (New in v0.5.0).
*   **`doris_mcp_server/utils/data_quality_tools.py`**: Comprehensive data quality analysis framework (New in v0.5.0).
*   **`doris_mcp_server/utils/adbc_query_tools.py`**: High-performance Arrow Flight SQL operations (New in v0.5.0).

### 2. Implement Tool Logic

Add a private handler to `DorisToolsManager` in
`doris_mcp_server/tools/tools_manager.py`. Handler names follow
`_<tool_name>_tool`; the registry resolves this name and validates that the
handler exists during manager construction.

**Example:** Adding a new analysis tool:

```python
# In doris_mcp_server/tools/tools_manager.py

async def _your_new_analysis_tool(
    self,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    """
    Your new analysis tool implementation
    
    Args:
        arguments: Tool arguments from MCP client
        
    Returns:
        JSON-serializable tool result
    """
    try:
        # Use existing utilities
        result = await self.query_executor.execute_sql_for_mcp(
            sql="SELECT COUNT(*) FROM your_table",
            max_rows=arguments.get("max_rows", 100)
        )
        
        return result
        
    except Exception as e:
        logger.error(f"Tool execution failed: {str(e)}", exc_info=True)
        return {"success": False, "error": "Analysis failed"}
```

### 3. Add the Registry Definition

Add one `Tool` schema to
`doris_mcp_server/tools/tool_catalog.py::build_tool_registry`, then classify its
policy once in `doris_mcp_server/tools/tool_registry.py`. Do not add a decorator
wrapper or an `if/elif` dispatch branch:

```python
# In doris_mcp_server/tools/tool_catalog.py

Tool(
    name="your_new_analysis_tool",
    description="Description of your new analysis tool",
    input_schema={
        "type": "object",
        "properties": {
            "parameter1": {
                "type": "string",
                "description": "Description of parameter1"
            },
            "parameter2": {
                "type": "integer", 
                "description": "Description of parameter2",
                "default": 100
            }
        },
        "required": ["parameter1"],
    },
)
```

Custom providers are internal capability sources and do not create additional
top-level MCP tools. Integrate each provider capability into one formal domain
child with a support contract, authorization policy, input/output schemas, and
a deterministic handler binding. The test suite rejects public catalog drift.

### 4. Advanced Features

For more complex tools, you can leverage the comprehensive framework:

*   **Advanced Caching**: Use the query executor's built-in caching for enhanced performance
*   **Enterprise Security**: Apply comprehensive SQL validation and data masking through the security manager
*   **Intelligent Prompts**: Use the prompts manager for advanced query generation
*   **Resource Management**: Expose metadata through the resources manager
*   **Performance Monitoring**: Integrate with the analysis tools for monitoring capabilities

### 5. Testing

Test your new tool using the included MCP client:

```python
# Using doris_mcp_client/client.py
from doris_mcp_client.client import DorisUnifiedMCPClient

async def test_new_tool():
    client = DorisUnifiedMCPClient()
    result = await client.call_tool("your_new_analysis_tool", {
        "parameter1": "test_value",
        "parameter2": 50
    })
    print(result)
```

Run the release test gate with:

```bash
uv run pytest -q -W error
uv run coverage json -o coverage.json
uv run python test/deployment/check_coverage_domains.py coverage.json
```

The test suite enforces at least 55% coverage across the repository. The
generated coverage report is also checked at an 80% floor for the protocol,
authentication, and core manager domains, so high-risk runtime code cannot be
hidden by unrelated coverage.

## MCP Client

The project includes a unified MCP client (`doris_mcp_client/`) for testing and integration purposes. The client supports multiple connection modes and provides a convenient interface for interacting with the MCP server.

For detailed client documentation, see [`doris_mcp_client/README.md`](doris_mcp_client/README.md).

## Contributing

Contributions are welcome via Issues or Pull Requests.

## License

This project is licensed under the Apache 2.0 License. See the LICENSE file for details. 

## FAQ

### Q: Why do Qwen3-32b and other small parameter models always fail when calling tools?

**A:** This is a common issue. The main reason is that these models need more explicit guidance to correctly use MCP tools. It's recommended to add the following instruction prompt for the model:

- Chinese version：

```xml
<instruction>
尽可能使用MCP工具完成任务，仔细阅读每个工具的注解、方法名、参数说明等内容。请按照以下步骤操作：

1. 仔细分析用户的问题，从已有的Tools列表中匹配最合适的工具。
2. 确保工具名称、方法名和参数完全按照工具注释中的定义使用，不要自行创造工具名称或参数。
3. 传入参数时，严格遵循工具注释中规定的参数格式和要求。
4. 调用工具时，根据需要直接调用工具，但参数请求参考以下请求格式：{"mcp_sse_call_tool": {"tool_name": "$tools_name", "arguments": "{}"}}
5. 输出结果时，不要包含任何XML标签，仅返回纯文本内容。

<input>
用户问题：user_query
</input>

<output>
返回工具调用结果或最终答案，以及对结果的分析。
</output>
</instruction>
```
- English version：

```xml
<instruction>
Use MCP tools to complete tasks as much as possible. Carefully read the annotations, method names, and parameter descriptions of each tool. Please follow these steps:

1. Carefully analyze the user's question and match the most appropriate tool from the existing Tools list.
2. Ensure tool names, method names, and parameters are used exactly as defined in the tool annotations. Do not create tool names or parameters on your own.
3. When passing parameters, strictly follow the parameter format and requirements specified in the tool annotations.
4. When calling tools, call them directly as needed, but refer to the following request format for parameters: {"mcp_sse_call_tool": {"tool_name": "$tools_name", "arguments": "{}"}}
5. When outputting results, do not include any XML tags, return plain text content only.

<input>
User question: user_query
</input>

<output>
Return tool call results or final answer, along with analysis of the results.
</output>
</instruction>
```

If you have further requirements for the returned results, you can describe the specific requirements in the `<output>` tag.

### Q: How to configure different database connections?

**A:** You can configure database connections in several ways:

1. **Environment Variables** (Recommended):
   ```bash
   export DORIS_HOST="your_doris_host"
   export DORIS_PORT="9030"
   export DORIS_USER="root"
   export DORIS_PASSWORD="your_password"
   ```

2. **Command Line Arguments**:
   ```bash
   doris-mcp-server --db-host your_host --db-port 9030 --db-user root --db-password your_password
   ```

3. **Configuration File**:
   Modify the corresponding configuration items in the `.env` file.

### Q: How to configure BE nodes for monitoring tools?

**A:** Configure SQL, FE HTTP, and BE HTTP endpoints independently when a
proxy, tunnel, or split network exposes them at different addresses:

```bash
# SQL/MySQL protocol endpoint
DORIS_HOST=sql-gateway.internal
DORIS_HOSTS=sql-gateway.internal,fe-2.internal,fe-3.internal
DORIS_PORT=9030

# FE HTTP endpoint; omit DORIS_FE_HTTP_HOST to reuse DORIS_HOST
DORIS_FE_HTTP_HOST=fe-http-proxy.internal
DORIS_FE_HTTP_HOSTS=fe-http-proxy.internal,fe-2.internal,fe-3.internal
DORIS_FE_HTTP_PORT=8030

# Explicit BE HTTP allowlist
DORIS_BE_HOSTS=10.1.1.100,10.1.1.101,10.1.1.102
DORIS_BE_WEBSERVER_PORT=8040
```

BE HTTP endpoints are never inferred from `SHOW BACKENDS`: SQL metadata is not
an outbound HTTP allowlist. If `DORIS_BE_HOSTS` is empty, BE HTTP metrics are
disabled. `DORIS_FE_HTTP_HOST` falls back to `DORIS_HOST` only for backward
compatibility; an explicit value is used for every FE monitoring, profile,
trace, and table-size HTTP request. FE and BE requests use only configured
hosts and ports, pin validated DNS results for each request, reject
metadata/link-local destinations, disable redirects, and enforce
connection/read/total timeouts plus a response byte limit. Private and loopback
addresses remain available for normal internal Doris deployments and SSH
tunnels.

`DORIS_HOSTS` and `DORIS_FE_HTTP_HOSTS` are ordered failover lists, not
load-balancing or cluster-discovery settings. Every host in one list must
belong to the same Doris cluster and use the configured shared port and
credentials. The server probes candidates in order during global/static-token
pool creation and recovery; FE HTTP requests move to the next configured
endpoint only on a transport error or `502`/`503`/`504`. Doris-backed OAuth
tries the candidates during sign-in, but an established per-user pool cannot
be reconstructed after failure because the server intentionally does not
retain the user's raw password; the user must sign in again. A stable load
balancer or SQL gateway is still recommended for large production deployments.

### Q: How to use SQL Explain/Profile files with LLM for optimization?

**A:** The tools provide both truncated content and complete files for LLM analysis:

1. **Get Analysis Results:**
   ```json
   {
     "content": "Truncated plan for immediate review",
     "file_path": "/tmp/explain_12345.txt",
     "is_content_truncated": true
   }
   ```

2. **LLM Analysis Workflow:**
   - Review truncated content for quick insights
   - Upload the complete file to your LLM as an attachment
   - Request optimization suggestions or performance analysis
   - Implement recommended improvements

3. **Configure Content Size:**
   ```bash
   MAX_RESPONSE_CONTENT_SIZE=4096  # Adjust as needed
   ```

### Q: How to enable data security and masking features?

**A:** Set the following configurations in your `.env` file:

```bash
# Enable data masking
ENABLE_MASKING=true
# Set maximum result rows
MAX_RESULT_ROWS=10000
```

### Q: What's the difference between Stdio mode and HTTP mode?

**A:** 

- **Stdio Mode**: Suitable for direct integration with MCP clients (like Cursor), where the client manages the server process
- **HTTP Mode**: Independent web service that supports multiple client connections, suitable for production environments

Recommendations:
- Development and personal use: Stdio mode
- Production and multi-user environments: HTTP mode

### Q: How to resolve connection timeout issues?

**A:** Try the following solutions:

1. **Increase timeout settings**:
   ```bash
   # Set in .env file
   QUERY_TIMEOUT=60
   CONNECTION_TIMEOUT=30
   ```

2. **Check network connectivity**:
   ```bash
   # /live verifies the process; /ready also verifies Doris
   curl --fail http://localhost:3000/live
   curl --fail http://localhost:3000/ready
   ```

3. **Optimize connection pool configuration**:
   ```bash
   DORIS_MAX_CONNECTIONS=20
   ```

### Q: How to resolve `at_eof` connection errors? (Completely Fixed in v0.5.0)

**A:** Version 0.5.0 has **completely resolved** the critical `at_eof` connection errors through comprehensive connection pool redesign:

#### The Problem:
- `at_eof` errors occurred due to connection pool pre-creation and improper connection state management
- MySQL aiomysql reader state becoming inconsistent during connection lifecycle
- Connection pool instability under concurrent load

#### The Solution (v0.5.0):
1. **Connection Pool Strategy Overhaul**:
   - **Zero Minimum Connections**: Changed `min_connections` from default to 0 to prevent pre-creation issues
   - **On-Demand Connection Creation**: Connections created only when needed, eliminating stale connection problems
   - **Fresh Connection Strategy**: Always acquire fresh connections from pool, no session-level caching

2. **Enhanced Health Monitoring**:
   - **Timeout-Based Health Checks**: 3-second timeout for connection validation queries
   - **Background Health Monitor**: Continuous pool health monitoring every 30 seconds
   - **Proactive Stale Detection**: Automatic detection and cleanup of problematic connections

3. **Intelligent Recovery System**:
   - **Automatic Pool Recovery**: Self-healing pool with comprehensive error handling
   - **Exponential Backoff Retry**: Smart retry mechanism with up to 3 attempts
   - **Connection-Specific Error Detection**: Precise identification of connection-related errors

4. **Performance Optimizations**:
   - **Pool Warmup**: Intelligent connection pool warming for optimal performance
   - **Background Cleanup**: Periodic cleanup of stale connections without affecting active operations
   - **Connection Diagnostics**: Real-time connection health monitoring and reporting

#### Monitoring Connection Health:
```bash
# Monitor connection pool health in real-time
tail -f logs/doris_mcp_server_info.log | grep -E "(pool|connection|at_eof)"

# Check detailed connection diagnostics
tail -f logs/doris_mcp_server_debug.log | grep "connection health"

# Check process liveness and Doris readiness
curl --fail http://localhost:8000/live
curl --fail http://localhost:8000/ready
```

#### Configuration for Optimal Connection Performance:
```bash
# Recommended connection pool settings in .env
DORIS_MAX_CONNECTIONS=20          # Adjust based on workload
CONNECTION_TIMEOUT=30             # Connection establishment timeout
QUERY_TIMEOUT=60                  # Query execution timeout

# Health monitoring settings
HEALTH_CHECK_INTERVAL=60          # Pool health check frequency
```

**Result**: The redesigned lifecycle reduces stale-connection failures and
improves recovery behavior. Validate the configured pool under the target
workload before production use.

### Q: Which MCP protocol revisions are supported?

**A:** New integrations should use MCP `2026-07-28`. Doris MCP Server accepts
the `2025-11-25` initialization flow over stdio and, when
`ENABLE_LEGACY_HTTP_ADAPTER=true`, at the isolated `/mcp/legacy` HTTP
endpoint. The modern `/mcp` endpoint is POST-only and never falls back to the
legacy transport. Older revisions and the retired HTTP+SSE transport are not
part of the supported compatibility contract.

Do not infer wire-protocol support from the Doris MCP Server package version or
the Python `mcp` dependency version. See
[MCP Protocol Support and Migration](#mcp-protocol-support-and-migration) for
the request metadata, HTTP headers, migration steps, and deployment limits.

### Q: How to enable ADBC high-performance features? (New in v0.5.0)

**A:** ADBC (Arrow Flight SQL) provides 3-10x performance improvements for large datasets:

1. **ADBC Dependencies** (automatically included in v0.5.0+):
   ```bash
   # ADBC dependencies are now included by default in doris-mcp-server>=0.5.0
   # No separate installation required
   ```

2. **Configure Arrow Flight SQL Ports**:
   ```bash
   # Add to your .env file
   FE_ARROW_FLIGHT_SQL_PORT=8096
   BE_ARROW_FLIGHT_SQL_PORT=8097
   ```

3. **Optional ADBC Customization**:
   ```bash
   # Customize ADBC behavior (optional)
   ADBC_DEFAULT_MAX_ROWS=10000
   ADBC_DEFAULT_TIMEOUT=120
   ADBC_DEFAULT_RETURN_FORMAT=pandas  # arrow/pandas/dict
   ```

4. **Test ADBC Connection**:
   ```bash
   # Discover doris_query, then call its get_adbc_connection_info child
   # Should show "status": "ready" and port connectivity
   ```

### Q: How to use the data governance and pipeline tools?

**A:** Discover the relevant domain first, retain its `manifest_version`, and
then call an exact child with schema-valid arguments:

**Column Analysis:**
```json
{
  "tool_name": "doris_governance",
  "arguments": {
    "child_tool": "analyze_columns",
    "manifest_version": "<value returned by domain discovery>",
    "arguments": {
      "database": "analytics",
      "table": "customer_data",
      "sample_ratio": 0.1
    }
  }
}
```

**Column Lineage Tracking:**
```json
{
  "tool_name": "doris_governance",
  "arguments": {
    "child_tool": "trace_column_lineage",
    "manifest_version": "<value returned by domain discovery>",
    "arguments": {
      "object": "internal.analytics.orders",
      "column": "customer_id",
      "direction": "both",
      "depth": 3
    }
  }
}
```

**Data Freshness Monitoring:**
```json
{
  "tool_name": "doris_pipeline",
  "arguments": {
    "child_tool": "monitor_data_freshness",
    "manifest_version": "<value returned by domain discovery>",
    "arguments": {
      "database": "analytics",
      "table": "orders",
      "threshold_seconds": 86400
    }
  }
}
```

**Performance Analytics:**
```json
{
  "tool_name": "doris_query",
  "arguments": {
    "child_tool": "list_slow_queries",
    "manifest_version": "<value returned by domain discovery>",
    "arguments": {
      "window_minutes": 10080,
      "limit": 20
    }
  }
}
```

### Q: How to use the enhanced logging system? (Improved in v0.5.0)

**A:** Version 0.5.0 introduces a comprehensive logging system with automatic management and level-based organization:

#### Log File Structure (New in v0.5.0):
```bash
logs/
├── doris_mcp_server_debug.log      # DEBUG level messages
├── doris_mcp_server_info.log       # INFO level messages  
├── doris_mcp_server_warning.log    # WARNING level messages
├── doris_mcp_server_error.log      # ERROR level messages
├── doris_mcp_server_critical.log   # CRITICAL level messages
├── doris_mcp_server_all.log        # Combined log (all levels)
└── doris_mcp_server_audit.log      # Audit trail (separate)
```

#### Enhanced Logging Features:
1. **Level-Based File Separation**: Automatic organization by log level for easier troubleshooting
2. **Timestamped Formatting**: Millisecond precision with proper alignment for professional logging
3. **Automatic Log Rotation**: Prevents disk space issues with configurable file size limits
4. **Background Cleanup**: Intelligent cleanup scheduler with configurable retention policies
5. **Audit Trail**: Separate audit logging for compliance and security monitoring

#### Viewing Logs:
```bash
# View real-time logs by level
tail -f logs/doris_mcp_server_info.log     # General operational info
tail -f logs/doris_mcp_server_error.log    # Error tracking
tail -f logs/doris_mcp_server_debug.log    # Detailed debugging

# View all activity in combined log
tail -f logs/doris_mcp_server_all.log

# Monitor specific operations
tail -f logs/doris_mcp_server_info.log | grep -E "(query|connection|tool)"

# View audit trail
tail -f logs/doris_mcp_server_audit.log
```

#### Configuration:
```bash
# Enhanced logging configuration in .env
LOG_LEVEL=INFO                         # Base log level
ENABLE_AUDIT=true                      # Enable audit logging
ENABLE_LOG_CLEANUP=true                # Enable automatic cleanup
LOG_MAX_AGE_DAYS=30                    # Keep logs for 30 days
LOG_CLEANUP_INTERVAL_HOURS=24          # Check for cleanup daily

# Advanced settings
LOG_FILE_PATH=logs                     # Log directory (auto-organized)
```

#### Troubleshooting with Enhanced Logs:
```bash
# Debug connection issues
grep -E "(connection|pool|at_eof)" logs/doris_mcp_server_error.log

# Monitor tool performance
grep "execution_time" logs/doris_mcp_server_info.log

# Check system health
tail -20 logs/doris_mcp_server_warning.log

# View recent critical issues
cat logs/doris_mcp_server_critical.log
```

#### Log Cleanup Management:
- **Automatic**: Background scheduler removes files older than `LOG_MAX_AGE_DAYS`
- **Manual**: Logs are automatically rotated when they reach 10MB
- **Backup**: Keeps 5 backup files for each log level
- **Performance**: Minimal impact on server performance

### Q: How to use the new Token-Bound Database Configuration? (New in v0.6.0)

**A:** The revolutionary token-bound database configuration allows each token to carry its own database connection parameters for secure multi-tenant access:

1. **Enable Token Authentication**:
   ```bash
   # In your .env file
   ENABLE_TOKEN_AUTH=true
   TOKEN_HOT_RELOAD=true
   TOKEN_FILE_PATH=tokens.json
   ```

2. **Create the bearer token once and store only its digest in tokens.json**:
   ```json
   {
     "version": "2.0",
     "tokens": [
       {
         "token_id": "tenant-alpha",
         "token_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
         "created_at": "2026-07-29T00:00:00Z",
         "expires_at": null,
         "last_used": null,
         "description": "Tenant Alpha database access",
         "is_active": true,
         "database_config": {
           "host": "tenant-alpha-db.company.com",
           "hosts": [
             "tenant-alpha-fe-1.company.com",
             "tenant-alpha-fe-2.company.com"
           ],
           "port": 9030,
           "user": "alpha_user",
           "password": "secure_password",
           "database": "alpha_analytics",
           "charset": "UTF8",
           "fe_http_hosts": [
             "tenant-alpha-fe-1.company.com",
             "tenant-alpha-fe-2.company.com"
           ],
           "fe_http_port": 8030
         }
       }
     ]
   }
   ```
   Generate the real bearer token and digest with the command in
   [Token-Bound Database Configuration](#token-bound-database-configuration-new-in-v060).
   The all-zero value above is deliberately unusable. Give the bearer value to
   the client once; do not place it in the file.

3. **Configuration Priority** (New in v0.6.0):
   - **Token-bound DB config** (highest priority)
   - **Environment variables (.env)**
   - **Error if neither available**

4. **Hot Reload Benefits**:
   - Add new tenants without service restart
   - Update database credentials in real-time
   - Automatic validation and rollback on errors
   - Complete audit trail of changes

5. **Multi-Tenant Usage**:
   ```bash
   # Different tokens access different databases automatically
   curl -H "Authorization: Bearer $TOKEN_TENANT_ALPHA" http://localhost:3000/mcp
   curl -H "Authorization: Bearer $TOKEN_TENANT_BETA" http://localhost:3000/mcp
   ```

   Each token may bind a different Doris cluster. Within one token binding,
   `hosts` and `fe_http_hosts` are ordered FE candidates for that same cluster.
   The authenticated token fixes the route; MCP tool arguments cannot select
   or override another cluster. This multi-instance mode requires the HTTP
   transport with static-token authentication. A stdio process has one global
   database route, so run separate stdio processes when clients need separate
   clusters. `exec_adbc_query` is intentionally fail-closed on token-bound
   routes because the current Arrow Flight client is process-global; use
   `doris_query.execute_query` or a separate MCP process for that cluster.

### Q: How is Doris-backed OAuth different from external OAuth/OIDC?

**A:** External OAuth/OIDC delegates identity to an external provider such as Google, Azure AD, GitHub, GitLab, or Keycloak. Doris-backed OAuth is issued by this MCP server after the user signs in with Doris credentials. The server validates the Doris username/password, creates a per-user Doris connection pool, issues `doa_` access and refresh tokens, and lets Doris RBAC decide what data and metadata that user can access.

These modes are mutually exclusive on one MCP URL. Do not enable `ENABLE_DORIS_OAUTH_AUTH=true` together with `ENABLE_OAUTH_AUTH=true`, `OAUTH_ENABLED=true`, or `AUTH_TYPE=oauth`; startup fails fast if both OAuth modes are configured.

Doris-backed OAuth currently exposes MCP resources with disabled resources metadata cache. It exposes reviewed metadata tools when `DORIS_OAUTH_DB_TOOLS_ENABLED=true`, `exec_query` when `DORIS_OAUTH_QUERY_TOOLS_ENABLED=true`, and SQL explain when `DORIS_OAUTH_EXPLAIN_TOOLS_ENABLED=true`. Normal clients do not need to pass a long scope list; omitted OAuth scope grants the configured Doris OAuth capability envelope. Doris RBAC remains the final data authorization backend for these MySQL-channel operations.

### Q: Can Doris-backed OAuth run with multiple workers or multiple nodes?

**A:** Not in the current implementation. Doris-backed OAuth uses a memory-only OAuth store and process-local per-user Doris pools. Access tokens, refresh tokens, authorization codes, DCR clients, and pools are not shared between workers, processes, or nodes.

Use `WORKERS=1` with Doris-backed OAuth. `WORKERS=0` expands to CPU count and fails because it would create multiple effective workers. Stateless horizontal scaling, shared token storage, shared encrypted Doris credentials, sticky-session recovery, and pool reconstruction are future designs, not current capabilities.

### Q: How does Hot Reload work and is it safe? (New in v0.6.0)

**A:** The hot reload system is designed for enterprise production environments with comprehensive safety measures:

**How It Works:**
- **Request-time synchronization**: Every token lookup compares the shared
  file signature, so another local worker's create or revoke is observed on
  the next authenticated request rather than waiting for the polling interval
- **Background monitoring**: A 10-second monitor still refreshes idle workers
- **Serialized updates**: `tokens.json.lock` protects every managed
  read-modify-write operation across local worker processes
- **Atomic updates**: A same-directory temporary file is flushed and replaced
  atomically with owner-only permissions
- **Rollback protection**: Invalid externally edited state does not partially
  replace a worker's current in-memory view
- **Shared revocation**: `revoked_tokens` stores only token digests and also
  disables matching `TOKEN_<ID>` environment credentials in every worker

**Safety Features:**
- **No lost updates**: Concurrent create/revoke operations reload the latest
  document while holding the process-shared lock
- **No bearer-token plaintext persistence**: Live and revoked bearer values
  are represented only by self-describing digests
- **Owner-only state files**: Managed state and lock files use mode `0600`
- **Error isolation**: Invalid state is rejected before it can replace the
  complete local token map

**Best Practices:**
```bash
# Monitor hot reload activity
tail -f logs/doris_mcp_server_info.log | grep "hot reload"

# Test configuration before applying
cp tokens.json tokens.json.backup
# Make changes to tokens.json
# System will automatically validate and apply or rollback
```

### Q: How to manage Token lifecycle and security? (New in v0.6.0)

**A:** Token management uses a secure, file-based approach with optional administrative endpoints that have comprehensive security controls.

**Primary Token Management Method (Recommended):**
```bash
# 1. Keep the management endpoint disabled unless local administration is needed.
# 2. When enabled, create a token through the protected localhost endpoint.
curl -X POST \
  -H "Authorization: Bearer $TOKEN_MANAGEMENT_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"token_id":"service-a","expires_hours":720}' \
  http://127.0.0.1:3000/token/create

# 3. Capture the returned bearer token once and place it in the client secret store.
# 4. The server writes only token_digest to tokens.json.
# 5. Monitor hot reload in logs.
tail -f logs/doris_mcp_server_info.log | grep "hot reload"
```

For deployments without HTTP token management, use a high-entropy `TOKEN_<ID>`
environment secret or generate a bearer/digest pair offline as shown above.
Manual `tokens.json` entries must use `token_digest`; plaintext `token` entries
exist only for one-way migration from version 1.

The file backend coordinates multiple worker processes on one host. Every
worker must use the same `TOKEN_FILE_PATH`, and the underlying filesystem must
provide reliable file locking and atomic rename semantics. Multiple hosts or
containers without a shared locking filesystem require an external
transactional state backend; copying separate `tokens.json` files does not
provide cluster-wide revocation.

**Administrative Endpoints (Secure, Local Access Only):**

🛡️ **SECURITY**: These endpoints are protected by comprehensive security controls and are **disabled by default**.

```bash
# Security Requirements (ALL must be met):
# ✓ HTTP token management explicitly enabled in configuration
# ✓ Access only from localhost (127.0.0.1/::1) - IP restrictions enforced
# ✓ Valid admin authentication token required
# ✓ Admin authentication enabled in configuration

# Enable HTTP token management (disabled by default)
export TOKEN_MANAGEMENT_ADMIN_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
export ENABLE_HTTP_TOKEN_MANAGEMENT=true
export REQUIRE_ADMIN_AUTH=true
export TOKEN_MANAGEMENT_ALLOWED_IPS=127.0.0.1,::1

# Access with proper authentication
curl -H "Authorization: Bearer $TOKEN_MANAGEMENT_ADMIN_TOKEN" http://127.0.0.1:3000/token/stats

# Demo page (local access only, with authentication)
# Access: http://127.0.0.1:3000/token/demo
```

**Recommended Token Management Workflow:**

1. **Development/Testing**:
   ```json
   // tokens.json
   {
     "version": "2.0",
     "tokens": [
       {
         "token_id": "dev-token",
         "token_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
         "created_at": "2026-07-29T00:00:00Z",
         "expires_at": "2026-07-30T00:00:00Z",
         "last_used": null,
         "description": "Development environment access",
         "is_active": true
       }
     ]
   }
   ```
   Replace the all-zero digest with one derived from a securely generated
   bearer token, and keep that bearer token outside the server file.

2. **Production Deployment**:
   ```bash
   # Use secure token generation
   openssl rand -hex 32  # Generate secure token
   
   # Store in secure configuration management
   # Never commit tokens to version control
   # Use environment variables for sensitive tokens
   ```

**Security Features:**
- **Digest-Only Persistence**: Bearer plaintext is returned only when created;
  version 2 files contain self-describing SHA-256/SHA-512 digests
- **Atomic File Management**: Managed writes use same-directory replacement and
  force owner-only `0600` permissions
- **Hot Reload**: Automatic configuration updates without service interruption
- **Legacy Migration**: Version 1 plaintext entries are replaced by digest-only
  records on first successful load
- **Audit Trail**: Complete logging of all token operations and changes
- **Expiration Management**: Automatic cleanup of expired tokens
- **Local Admin Only**: Management endpoints restricted to localhost access
- **Configuration Validation**: Immediate validation of token and database configurations

**Security Best Practices:**
- Store bearer values in client-side secret management; keep only digests on
  the server
- Never expose token management endpoints to external networks
- Use strong, randomly generated tokens for production
- Keep manually managed `tokens.json` files owner-readable only; managed writes
  enforce `0600`
- Regular audit of active tokens and their usage patterns
- Monitor hot reload logs for unauthorized configuration changes

For other issues, please check GitHub Issues or submit a new issue. 
