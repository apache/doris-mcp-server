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

# Deployment

[English](deployment.md) | [简体中文](deployment.zh-CN.md)

This guide covers supported 1.0 deployment shapes. Start from loopback, add an
intentional authentication mode, and validate the real Apache Doris route
before exposing the Server to a Host.

## Choose a transport

| Shape | Use when | Process model | Authentication boundary |
|---|---|---|---|
| stdio | One local Host launches one Server | child process | local OS/process boundary plus Doris credentials |
| Streamable HTTP, loopback | Local tools share a service | one or more workers, subject to auth mode | token/JWT/OAuth optional but recommended |
| Streamable HTTP behind TLS proxy | Controlled remote access | proxy + Server workers | authenticated HTTP, trusted proxy policy, TLS |

The retired standalone SSE transport is not supported. New HTTP integrations
use `POST /mcp` and MCP `2026-07-28`.

## stdio deployment

Example Host command:

```json
{
  "command": "doris-mcp-server",
  "args": ["--transport", "stdio"],
  "env": {
    "DORIS_HOST": "127.0.0.1",
    "DORIS_PORT": "9030",
    "DORIS_USER": "mcp_reader",
    "DORIS_PASSWORD": "<secret>",
    "DORIS_DATABASE": "information_schema"
  }
}
```

Operational rules:

- stdout is reserved for MCP frames;
- logs must use stderr or configured files;
- the Host owns process restart and environment injection;
- do not share the process with unrelated users when credentials are in the
  environment;
- stdio initialization establishes a working Doris route before accepting
  ordinary work.

## Streamable HTTP deployment

Local command:

```bash
export TRANSPORT=http
export SERVER_HOST=127.0.0.1
export SERVER_PORT=3000
export DORIS_HOST=127.0.0.1
export DORIS_PORT=9030
export DORIS_USER=mcp_reader
export DORIS_PASSWORD='<secret>'

doris-mcp-server --transport http --host 127.0.0.1 --port 3000
```

Endpoints:

- `POST /mcp` — modern MCP requests;
- `GET /live` — process/protocol liveness;
- `GET /ready` — bounded Doris-backed readiness;
- `GET /health` — compatibility health view;
- `/mcp/legacy` — default-off protocol migration adapter.

Enable `/mcp/legacy` only for validated handshake-era clients such as Dify
1.16.1 (`2025-06-18`) or SDK v2 clients using `2025-11-25`:

```bash
export ENABLE_LEGACY_HTTP_ADAPTER=true
```

Configure those Hosts with the exact `/mcp/legacy` URL. Keep modern
`2026-07-28` Hosts on `/mcp`; the Server never silently downgrades that
endpoint.

Keep the Server on loopback until authentication, Host/Origin policy, proxy
behavior, TLS termination, timeouts, and secret injection are tested together.

## Authentication and worker count

Stateless MCP requests do not require sticky sessions. Authentication and
provider modes can impose tighter constraints:

| Mode | Worker guidance |
|---|---|
| static token | multiple workers are possible with shared token/state configuration |
| JWT | multiple workers are possible with consistent keys/policy |
| external OAuth/OIDC | multiple workers require consistent validation and mapping configuration |
| Doris-backed OAuth | exactly one worker in 1.0; tokens and user pools are process-local |
| custom provider rate limiting | quotas are per process unless the provider supplies external state |

Independently launched replicas behind a load balancer must share the same
high-entropy `MCP_STATE_HANDLE_SECRET` so pagination/state handles remain valid
across instances. They must also share compatible authorization policy and
visible catalogs. Do not share Doris OAuth traffic across replicas in 1.0.

## Docker

Build locally:

```bash
docker build -t doris-mcp-server:1.0.0 .
```

Run with an environment file stored outside the image:

```bash
docker run --rm \
  --env-file /secure/path/doris-mcp.env \
  --publish 127.0.0.1:3000:3000 \
  doris-mcp-server:1.0.0
```

Or review `docker-compose.yml` and `.env.example` before using Compose. The
checked-in examples contain placeholders and security assertions; they are not
production credentials. Provision the default `mcp_reader` account with only
the required Doris read privileges before starting the MCP service; do not
replace it with `root` outside an isolated bootstrap environment.

Container requirements:

- pin the image/release rather than deploying mutable `latest`;
- mount secret files read-only with owner-restricted permissions;
- keep `/live` and `/ready` as separate probes;
- set memory/CPU limits compatible with query concurrency and result ceilings;
- allow only required FE MySQL, FE HTTP, BE HTTP, OAuth, and provider egress;
- avoid publishing the port on all interfaces until the proxy/auth boundary is
  complete.

## Reverse proxy and TLS

When traffic leaves the machine:

1. terminate TLS with a controlled proxy or in the platform ingress;
2. preserve required MCP headers and request body without method/name rewrite;
3. configure exact public Host/Origin behavior;
4. configure trusted proxy CIDRs before honoring forwarded headers;
5. reject oversized requests before they reach the process, while keeping
   limits compatible with MCP Schema/instance ceilings;
6. disable buffering/timeouts that would truncate valid Streamable HTTP
   responses;
7. never log bearer or admin authorization headers.

Binding `0.0.0.0` only selects a network interface. It does not authorize a
public hostname, proxy, or Origin.

## Apache Doris routing

Single FE:

```bash
export DORIS_HOST=fe.example
export DORIS_PORT=9030
export DORIS_FE_HTTP_HOST=fe.example
export DORIS_FE_HTTP_PORT=8030
```

Multiple FE candidates:

```bash
export DORIS_HOSTS='fe-1.example:9030,fe-2.example:9030'
export DORIS_FE_HTTP_HOSTS='fe-1.example:8030,fe-2.example:8030'
```

Explicit BE HTTP allowlist:

```bash
export DORIS_BE_HOSTS='be-1.example:8040,be-2.example:8040'
```

The route manager validates candidates and preserves route identity. Do not
allow MCP callers to supply arbitrary FE/BE hostnames. Network policy should
restrict egress to the configured cluster and reviewed providers.

## Exposure mode

Default:

```bash
export MCP_TOOL_EXPOSURE_MODE=hierarchical
```

Host compatibility fallback:

```bash
export MCP_TOOL_EXPOSURE_MODE=flat
```

Changing the mode requires process restart and Host reconnect. It is a startup
contract, not a per-request switch.

## Optional providers

- **ADBC:** enable the default-off advanced provider and configure Arrow Flight
  SQL ports; ordinary queries still use MySQL, and ADBC calls require explicit
  end-user intent plus `explicit_adbc=true`.
- **Ossie:** set `OSSIE_ENABLED=true`, mount reviewed models and private Doris
  bindings, and grant explicit semantic scopes.
- **MetricFlow:** configure an absolute reviewed sidecar command and project;
  validate Doris-dialect compilation and real Doris read-only/negative-write
  behavior before enabling it.
- **Native lineage:** configure the canonical queryable store/provider and
  verify required columns and delivery health.
- **Custom tools:** install the package and list its exact provider name in
  `MCP_TOOL_PROVIDERS`.

An optional provider that is absent should make relevant children unavailable,
not prevent unrelated domains from working. An explicitly allowlisted but
invalid custom provider fails startup.

## Rollout procedure

1. Pin the package/image and capture configuration hashes without secrets.
2. Validate startup configuration offline/in a staging process.
3. Check `/live` and `/ready` independently.
4. Run `server/discover` and `tools/list` from the target Host.
5. Discover all authorized domains and record `callable` states/reason codes.
6. Execute a read-only `SELECT 1` through the formal Query child.
7. Execute negative tests: write SQL rejection, unauthorized child, invalid
   cursor, permission-denied table, result/timeout ceiling.
8. Validate FE failover and readiness if multiple FE routes are configured.
9. Compare the generated tool registry and release artifacts with the deployed
   package version.
10. Enable production traffic gradually and monitor typed failures/truncation.

## Upgrade and rollback

- Read [Migrating to 1.0](../migration/1.0.0.md) before replacing a pre-1.0
  Server.
- Restart Hosts so cached pre-1.0 schemas disappear.
- Treat exposure-mode changes as an API change requiring reconnect.
- Roll back package/image and configuration together.
- A rollback does not make 1.0 state handles or manifests valid on an older
  process; Hosts must rediscover.
- Do not use the legacy HTTP adapter as a permanent mixed-version deployment.

See [Configuration reference](../reference/configuration.md) and
[Reliability and limits](reliability.md).
