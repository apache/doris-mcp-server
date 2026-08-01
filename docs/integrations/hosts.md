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

# Host integrations

[English](hosts.md) | [简体中文](hosts.zh-CN.md)

An MCP Host owns the model, conversation, tool registration, and client
connection. Doris MCP Server owns the stable tool contract, authorized
progressive discovery, capability evidence, and execution. The boundary is
standard MCP; a Host does not need Doris-specific code when it can follow the
1.0 call shape.

## Host, client, and Server

| Component | Responsibility |
|---|---|
| Host | model context, user intent, tool selection, approval UX, connection lifecycle |
| MCP client | transport framing, request metadata, credentials, protocol errors |
| Doris MCP Server | tool schemas, discovery, authorization, capability gates, read-only execution |
| Apache Doris | metadata/query execution and final data permission |

The Server never changes a Host's registered top-level tool list in response
to conversational intent. Eight stable domains are enough to move from a table
question to a cluster question immediately.

## Hierarchical interaction

Recommended Host algorithm:

1. Connect and call `tools/list`.
2. Register the eight domain tools with their returned descriptions/schemas.
3. When the model selects a domain, call it with `{}`.
4. Feed the returned authorized child descriptions and exact schemas into the
   next model/tool-selection step.
5. Call the same domain with exact `child_tool`, `arguments`, and
   `manifest_version`.
6. On `CHILD_MANIFEST_STALE`, discard that domain's cached manifest and
   rediscover.
7. On `callable=false`, present the structured availability reason instead of
   trying to bypass the Server.

The second-level selection can be model-driven because the full authorized
child list and exact schemas are now present. The Server does not use
probabilistic intent routing to guess a child.

## Fast intent switching

Example conversation:

1. User asks which tables exist.
2. Model calls `doris_catalog` with `{}`, then `list_tables`.
3. User immediately asks whether the cluster is healthy.
4. Model calls the already registered `doris_cluster` with `{}`, then
   `get_cluster_overview`.

No MCP re-registration is needed. Domain registration is stable; only the
selected domain's manifest is progressively disclosed. A Host may retain
multiple current manifests, but it must bind each to its returned generation
and authorization context.

## Flat fallback

Some Hosts cannot perform a discovery call before selecting a final operation.
Configure the Server before startup:

```bash
export MCP_TOOL_EXPOSURE_MODE=flat
```

After restart and reconnect, `tools/list` returns formal names such as:

- `doris_catalog_list_tables`
- `doris_query_execute_query`
- `doris_cluster_get_cluster_overview`

Flat mode exposes the same authorized 55-child catalog and availability. It
does not provide pre-1.0 aliases, dynamic registration, or a security bypass.
The context cost is higher, so hierarchical mode is preferred.

## stdio configuration

Generic Host configuration:

```json
{
  "mcpServers": {
    "doris": {
      "command": "doris-mcp-server",
      "args": ["--transport", "stdio"],
      "env": {
        "DORIS_HOST": "127.0.0.1",
        "DORIS_PORT": "9030",
        "DORIS_USER": "mcp_reader",
        "DORIS_PASSWORD": "<secret>",
        "DORIS_DATABASE": "information_schema",
        "MCP_TOOL_EXPOSURE_MODE": "hierarchical"
      }
    }
  }
}
```

Host config file names differ across products. Preserve the command, args,
environment, and MCP `2026-07-28` behavior rather than copying a product path
blindly.

Rules:

- use an absolute executable path if the GUI Host has a different `PATH`;
- keep stdout protocol-only;
- inject secrets through the Host secret mechanism or protected environment;
- restart the Host after changing exposure mode or package version.

## Streamable HTTP configuration

Connect to:

```text
http://127.0.0.1:3000/mcp
```

The Client must implement the modern request metadata and HTTP headers in the
[protocol contract](../protocol/mcp-2026-07-28.md). Add the configured
credential, for example:

```text
Authorization: Bearer <token>
```

Do not put credentials in the URL. Remote access requires HTTPS and validated
Host/Origin/proxy policy.

## Protocol endpoint compatibility

Choose the endpoint from the Host's implemented MCP protocol. Do not rely on
automatic downgrade or send an old handshake to the modern endpoint.

| Host profile | Protocol | Endpoint | Status |
|---|---|---|---|
| Modern MCP Host | `2026-07-28` | `/mcp` | Preferred and release-gated |
| Dify 1.16.1 | `2025-06-18` | `/mcp/legacy` | Validated with initialize, tool discovery, and tool calls |
| Legacy SDK v2 client | `2025-11-25` | `/mcp/legacy` | Regression-tested migration path |

Enable the compatibility endpoint explicitly:

```bash
export ENABLE_LEGACY_HTTP_ADAPTER=true
doris-mcp-server --transport http --host 127.0.0.1 --port 3000
```

The legacy endpoint is a protocol adapter over the same Server. It does not
restore removed tool names, weaken authentication or authorization, bypass
Doris capability checks, or change read-only execution. Tool exposure mode is
an independent startup choice; use `hierarchical` unless the Host specifically
requires `flat`.

## Built-in command-line client

`doris-mcp-client` is useful for connection and protocol diagnostics. It is not
the Server executable and cannot replace `doris-mcp-server` in Host process
configuration.

Use `--help` for the installed version's exact flags:

```bash
doris-mcp-client --help
doris-mcp-server --help
```

## Authentication behavior for Hosts

- Static token/JWT Hosts send the appropriate bearer credential.
- External OAuth Hosts obtain an access token for the canonical MCP resource
  and exact scopes.
- Doris OAuth Hosts use the Server's OAuth metadata/authorization flow and
  receive a resource-bound access token.
- A Host should surface `WWW-Authenticate`/insufficient-scope responses rather
  than silently reconnecting anonymously.
- Domain discovery and child calls must use the same principal when reusing a
  manifest or cursor.

## Schema and result handling

Hosts should:

- trust schemas returned by the active Server, not copied static examples;
- preserve exact child names and case;
- validate or construct arguments from the child input Schema;
- accept structured content as the authoritative machine-readable result;
- display warnings/truncation to the user;
- use typed error codes and retryability;
- avoid parsing human descriptions as status or API signatures;
- keep manifest/cursor values opaque.

## Host compatibility checklist

| Requirement | Hierarchical | Flat |
|---|---:|---:|
| tool list/call on the selected protocol endpoint | required | required |
| call a domain with `{}` | required | not required |
| feed discovered child schemas to model | required | not required |
| handle structured content | recommended | recommended |
| handle stale-manifest rediscovery | required | not normally sent by flat call |
| context budget for 55 tools | not required | required |
| restart after exposure-mode change | required | required |

If a Host cannot consume progressive manifests and also cannot accommodate 55
bounded formal tools, it is not currently compatible with the full 1.0 tool
surface. Do not solve this by probabilistic Server-side routing.

## Host test sequence

1. Confirm `server/discover` identity/version.
2. Confirm `tools/list` returns 8 domains (hierarchical) or 55 formal children
   before authorization filtering (flat contract baseline).
3. Discover Catalog and call `list_tables`.
4. Switch to Cluster in the same conversation and call overview/capabilities.
5. Send an invalid child name and confirm deterministic rejection.
6. Send write SQL and confirm the read-only guard.
7. Change provider/permission in staging and confirm stale rediscovery.
8. Test a permission-denied Doris object with the real request identity.

See [Quick start](../getting-started/quickstart.md) and
[Request lifecycle](../architecture/request-lifecycle.md).
