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

# Quick start

[English](quickstart.md) | [简体中文](quickstart.zh-CN.md)

This guide starts a local Apache Doris MCP Server 1.0.0, verifies health, and
shows the hierarchical discovery call shape. It intentionally uses loopback
addresses and placeholder credentials.

## 1. Prerequisites

- Python 3.12 or later.
- Apache Doris 3.0.0 or later.
- FE MySQL endpoint access, normally port `9030`.
- FE HTTP endpoint access, normally port `8030`, for profile and selected
  operational capabilities.
- Explicit BE HTTP hosts when BE-level monitoring is required.

Confirm Python:

```bash
python3 --version
```

## 2. Install

From PyPI:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install doris-mcp-server==1.0.0
```

From a source checkout:

```bash
git clone https://github.com/apache/doris-mcp-server.git
cd doris-mcp-server
uv sync --group dev
```

The package installs two programs:

- `doris-mcp-server`: starts the MCP Server.
- `doris-mcp-client`: connects to an existing Server.

They are not interchangeable.

## 3. Configure the Doris route

```bash
export DORIS_HOST=127.0.0.1
export DORIS_PORT=9030
export DORIS_USER=root
export DORIS_PASSWORD='replace-me'
export DORIS_DATABASE=information_schema
```

For multi-FE routing:

```bash
export DORIS_HOSTS='fe-1.example:9030,fe-2.example:9030'
export DORIS_FE_HTTP_HOSTS='fe-1.example:8030,fe-2.example:8030'
```

Use a dedicated least-privileged Doris account in production. Do not commit
passwords, bearer tokens, client secrets, JWT keys, or `.env` files.

## 4. Start Streamable HTTP

```bash
doris-mcp-server \
  --transport http \
  --host 127.0.0.1 \
  --port 3000
```

The modern MCP endpoint is:

```text
POST http://127.0.0.1:3000/mcp
```

Health endpoints:

```bash
curl --fail http://127.0.0.1:3000/live
curl --fail http://127.0.0.1:3000/ready
```

`/live` verifies process and protocol availability. `/ready` also checks a
bounded Doris route operation. A live-but-not-ready Server should be diagnosed
before it is restarted.

HTTP binds to loopback by default. A non-loopback bind requires at least one
authentication mode unless the operator explicitly enables the dangerous
`ALLOW_UNAUTHENTICATED_NON_LOOPBACK=true` development override.

## 5. Start stdio

For a Host that launches the Server as a child process:

```bash
doris-mcp-server --transport stdio
```

Do not write ordinary application output to stdout in stdio mode. MCP frames
use stdout; diagnostic logs belong on stderr or in configured log files.

## 6. Discover and call a child

In the default `hierarchical` mode, `tools/list` returns eight domain tools.
Discover the catalog domain by calling `doris_catalog` with:

```json
{}
```

The result contains authorized children, exact schemas, availability, and a
`manifest_version`. A subsequent call uses the same top-level tool:

```json
{
  "child_tool": "list_tables",
  "arguments": {
    "database": "information_schema"
  },
  "manifest_version": "<value returned by discovery>"
}
```

If the Server reports `CHILD_MANIFEST_STALE`, call the domain with `{}` again
and use the new manifest. If a child has `callable=false`, inspect its
structured `reason_code`; do not infer availability from its description.

Hosts without progressive-disclosure support may set:

```bash
export MCP_TOOL_EXPOSURE_MODE=flat
```

Restart the Server and reconnect the Host. Flat mode exposes the same 47
children under formal names such as `doris_catalog_list_tables`.

## 7. Verify the installation

```bash
doris-mcp-server --version
python -c "import doris_mcp_server; print(doris_mcp_server.__version__)"
```

From a source checkout:

```bash
uv run pytest test/test_release_artifacts.py test/test_product_identity.py
uv run python generate_tool_catalog.py --check
```

## Next steps

- [Connect a Host](../integrations/hosts.md)
- [Understand the architecture](../architecture/overview.md)
- [Review the tool domains](../capabilities/tool-domains.md)
- [Configure authentication](../security/security-model.md)
- [Deploy the Server](../operations/deployment.md)
- [Troubleshoot failures](../operations/troubleshooting.md)
