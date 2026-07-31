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

# Testing Doris MCP Server

This directory verifies the 1.0 public contract: MCP `2026-07-28`, the stable
8-domain/47-child capability surface, authentication and authorization,
read-only execution, bounded results, transports, packaging, documentation,
and optional real Doris integration.

The complete contributor workflow and gate definitions are maintained in
[Contributing and verification](../docs/development/contributing.md).

## Local setup

```bash
uv sync --group dev
```

Run the complete warning-clean suite:

```bash
uv run pytest -q -W error
```

Run focused release and documentation contracts while editing docs:

```bash
uv run pytest -q -W error \
  test/test_documentation_system.py \
  test/test_release_artifacts.py \
  test/test_product_identity.py
```

## Static and generated gates

```bash
uv run python generate_tool_catalog.py --check
uv lock --check
uv run ruff check .
uv run mypy doris_mcp_server
uv run bandit -q -c pyproject.toml -r doris_mcp_server generate_tool_catalog.py
uv build
```

The generated [tool registry](../docs/tool-registry.md) is authoritative and
must not be edited by hand.

## Test boundaries

- Unit tests isolate one contract or implementation boundary.
- Integration tests exercise real Server composition, authentication,
  transport, routing, and Child dispatch.
- Protocol tests assert the exact MCP version, schemas, errors, pagination,
  metadata, state handles, and compatibility isolation.
- Security tests cover positive and negative authorization paths, SQL safety,
  secret redaction, identity routing, and bounded failures.
- Release tests align product identity, generated artifacts, source
  distributions, and documentation.
- Real Doris tests are opt-in and require a disposable reviewed environment.

Do not replace real boundary tests with mocks when the behavior depends on a
transport, package artifact, process boundary, or Doris permission. Do not run
destructive SQL against a shared cluster.

## Real Doris verification

The opt-in process suite uses environment-provided Doris connection settings
and exercises both stdio and Streamable HTTP through the formal 1.0 Tool
surface. It verifies allowed reads, denied reads, query bounds, timeout and
cancellation recovery, and capability behavior against the actual cluster.

Use only a least-privilege test account and follow the repository's current
real-Doris test module instructions. Credentials belong in the environment or
a secret manager, never in fixtures, logs, documentation, or commits.

## Adding a test

1. Identify the public contract or failure mode being protected.
2. Prefer deterministic inputs and bounded outputs.
3. Assert both success and denied/error behavior where authorization or
   availability is involved.
4. Keep transport-specific claims behind real transport tests.
5. Run the focused file, then the full warning-clean suite.
6. Update generated artifacts and ChangeLog when the public contract changes.
