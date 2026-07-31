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

# Configuration reference

[English](configuration.md) | [简体中文](configuration.zh-CN.md)

The authoritative exhaustive example is [`.env.example`](../../.env.example).
This guide groups the operationally important settings and explains their
boundaries. Defaults and validation in `doris_mcp_server/utils/config.py` remain
the runtime source of truth.

## Precedence and invariants

- Supported CLI flags override corresponding environment defaults.
- Environment values are normalized and validated before startup.
- The installed package controls `server_version`; `SERVER_VERSION` cannot
  override product identity.
- Exposure mode, authentication shape, providers, and worker model are startup
  choices—not per-request switches.
- Invalid security combinations fail before serving traffic.
- Never place real secret values in checked-in `.env`, Compose, or docs files.

## Doris route

| Variable | Purpose |
|---|---|
| `DORIS_HOST` | primary FE MySQL hostname |
| `DORIS_HOSTS` | ordered `host:port` FE MySQL candidates |
| `DORIS_PORT` | FE MySQL port, normally `9030` |
| `DORIS_USER` | global/service Doris account |
| `DORIS_PASSWORD` | global/service Doris password |
| `DORIS_DATABASE` | default database, commonly `information_schema` |
| `DORIS_FE_HTTP_HOST` | FE HTTP host; empty may reuse `DORIS_HOST` |
| `DORIS_FE_HTTP_HOSTS` | ordered FE HTTP candidates |
| `DORIS_FE_HTTP_PORT` | FE HTTP port, normally `8030` |
| `DORIS_BE_HOSTS` | explicit BE HTTP allowlist |
| `DORIS_BE_WEBSERVER_PORT` | BE HTTP port, normally `8040` |

HTTP safety:

| Variable | Purpose |
|---|---|
| `DORIS_HTTP_CONNECT_TIMEOUT_SECONDS` | FE/BE HTTP connect timeout |
| `DORIS_HTTP_READ_TIMEOUT_SECONDS` | read timeout |
| `DORIS_HTTP_TOTAL_TIMEOUT_SECONDS` | total request timeout |
| `DORIS_HTTP_MAX_RESPONSE_BYTES` | maximum accepted HTTP response bytes |

Connection pools:

| Variable | Purpose |
|---|---|
| `DORIS_MAX_CONNECTIONS` | deployment pool ceiling |
| `DORIS_CONNECTION_TIMEOUT` | MySQL connection timeout |
| `DORIS_HEALTH_CHECK_INTERVAL` | connection health interval |
| `DORIS_MAX_CONNECTION_AGE` | maximum reusable connection age |

All FE/BE destinations are operator configuration, never caller arguments.

## Server and protocol

| Variable | Purpose |
|---|---|
| `TRANSPORT` | `http` or `stdio` |
| `SERVER_HOST` | HTTP bind host |
| `SERVER_PORT` | HTTP port |
| `WORKERS` | HTTP worker count; Doris OAuth requires `1` |
| `SERVER_NAME` | product instance name, not product version |
| `MCP_ALLOWED_HOSTS` | validated HTTP Host policy inputs |
| `MCP_ALLOWED_ORIGINS` | validated Origin policy inputs |
| `ENABLE_LEGACY_HTTP_ADAPTER` | default-off `/mcp/legacy` adapter |
| `MCP_LIST_PAGE_SIZE` | entries per protocol list page (`1`–`1000`) |
| `MCP_STATE_HANDLE_SECRET` | shared HMAC secret for independent replicas |
| `MCP_STATE_HANDLE_TTL_SECONDS` | explicit handle lifetime (`1`–`3600`) |
| `MCP_TOOL_EXPOSURE_MODE` | `hierarchical` (default) or `flat` |
| `ALLOW_UNAUTHENTICATED_NON_LOOPBACK` | dangerous test-only bind override |

`MCP_ADMIN_DOMAIN_ENABLED` must remain `false` and
`MCP_ADMIN_REQUIRE_CONFIRMATION` must remain `true`. 1.0 rejects an attempt to
enable the reserved administration domain.

## Query, response, and concurrency limits

| Variable | Purpose |
|---|---|
| `ENABLE_SECURITY_CHECK` | application read-only SQL guard |
| `BLOCKED_KEYWORDS` | compatibility keyword policy in addition to parsing |
| `MAX_QUERY_COMPLEXITY` | configured complexity ceiling |
| `MAX_RESULT_ROWS` | deployment row ceiling; absolute hard cap also applies |
| `DEFAULT_RESULT_ROWS` | default query rows when omitted |
| `MAX_RESULT_BYTES` | UTF-8 JSON row-data budget |
| `QUERY_TIMEOUT` | deployment query timeout; absolute hard cap applies |
| `MAX_CONCURRENT_QUERIES` | process query concurrency |
| `MAX_RESPONSE_CONTENT_SIZE` | bounded text/content response size |
| `ENABLE_MASKING` | configured result masking |
| `ENABLE_QUERY_CACHE` | query cache switch |
| `CACHE_TTL` | cache lifetime |
| `MAX_CACHE_SIZE` | cache entry ceiling |

Operation-specific runtime bounds can be stricter than deployment values.
Increasing one variable does not remove the absolute safety cap.

## Capability detection and domains

| Variable | Purpose |
|---|---|
| `CAPABILITY_SNAPSHOT_TTL_SECONDS` | route-private snapshot lifetime |
| `CAPABILITY_PROBE_TIMEOUT_SECONDS` | bounded probe timeout |
| `CAPABILITY_STALE_GRACE_SECONDS` | maximum stale fallback window |
| `MCP_TOOL_PROVIDERS` | comma-separated exact custom provider allowlist |

Governance:

- `GOVERNANCE_MAX_SAMPLE_RATIO`
- `GOVERNANCE_MAX_AUDIT_WINDOW_DAYS`
- `GOVERNANCE_MAX_LINEAGE_EDGES`
- `GOVERNANCE_LINEAGE_STORE_TABLE`
- `GOVERNANCE_LINEAGE_RECENT_EVENT_MINUTES`

Lakehouse:

- `LAKEHOUSE_MAX_CATALOG_OBJECTS`
- `LAKEHOUSE_MAX_CATALOG_DATABASES`
- `LAKEHOUSE_MAX_SNAPSHOTS`
- `LAKEHOUSE_MAX_PARTITIONS`
- `LAKEHOUSE_MAX_VARIANT_SAMPLE_ROWS`
- `LAKEHOUSE_MAX_VARIANT_PATHS`

These are evidence/result bounds, not Doris permission grants.

## ADBC

| Variable | Purpose |
|---|---|
| `ADBC_ENABLED` | enable the optional advanced ADBC provider; default `false` |
| `FE_ARROW_FLIGHT_SQL_PORT` | FE Flight SQL port |
| `BE_ARROW_FLIGHT_SQL_PORT` | optional BE Flight port |
| `ADBC_DEFAULT_MAX_ROWS` | default ADBC row limit |
| `ADBC_DEFAULT_TIMEOUT` | default ADBC timeout |
| `ADBC_DEFAULT_RETURN_FORMAT` | `arrow`, `pandas`, or `dict` |
| `ADBC_CONNECTION_TIMEOUT` | Flight connection timeout |

ADBC remains subject to global result limits and fails closed on token-bound
routes in 1.0. Enabling the provider does not authorize automatic selection:
both ADBC child schemas and the runtime require `explicit_adbc=true`, which a
Host should set only when the end user explicitly requests ADBC or Arrow
Flight SQL. Ordinary queries use `doris_query.execute_query`.

## Apache Ossie semantic grounding

| Variable | Purpose |
|---|---|
| `OSSIE_ENABLED` | enable the default-off semantic provider |
| `OSSIE_MODEL_DIRECTORY` | directory of reviewed UTF-8 YAML/JSON models |
| `OSSIE_BINDING_MANIFEST` | server-private Doris binding file |
| `OSSIE_MAX_FILE_BYTES` | per-file loader bound |
| `OSSIE_MAX_TOTAL_BYTES` | aggregate model bound |
| `OSSIE_MAX_MODELS` | model count bound |
| `OSSIE_MAX_DEPTH` | model structure depth |
| `OSSIE_MAX_ALIASES` | alias count bound |
| `OSSIE_MAX_STRING_BYTES` | string bound |
| `OSSIE_MAX_EXPRESSION_BYTES` | expression text bound |
| `OSSIE_CONTEXT_MAX_BYTES` | default context budget |
| `OSSIE_CONTEXT_HARD_MAX_BYTES` | absolute context budget |

OAuth modes also require explicit semantic-channel enablement and
`semantic:read`. Every model-specific call still needs exact `model_ref`.

## MetricFlow semantic consumption

| Variable | Purpose |
|---|---|
| `METRICFLOW_ENABLED` | enable the default-off MetricFlow consumer |
| `METRICFLOW_PROVIDER_COMMAND_JSON` | absolute executable plus fixed arguments as a JSON string array |
| `METRICFLOW_PROJECT_DIRECTORY` | optional absolute working directory for the provider |
| `METRICFLOW_TIMEOUT_SECONDS` | provider process timeout, `1-120` seconds |
| `METRICFLOW_MAX_OUTPUT_BYTES` | provider stdout limit, `1024-8388608` bytes |

An enabled MetricFlow provider requires a non-empty command whose executable
is absolute. The Server invokes it without a shell using protocol
`doris-mcp-metricflow/v1`. The provider may inspect models and compile Doris
SQL; all execution returns to the bounded MCP Query runtime. See
[MetricFlow integration](../integrations/metricflow.md).

## Static token authentication

| Variable | Purpose |
|---|---|
| `ENABLE_TOKEN_AUTH` | enable static bearer authentication |
| `TOKEN_FILE_PATH` | managed digest-only token file |
| `ENABLE_TOKEN_EXPIRY` | enforce managed-token expiry |
| `DEFAULT_TOKEN_EXPIRY_HOURS` | default managed-token lifetime |
| `TOKEN_HASH_ALGORITHM` | supported persisted digest algorithm |
| `TOKEN_DB_VALIDATION_TTL_SECONDS` | token-bound Doris route validation cache |
| `TOKEN_<ID>` | operator-injected high-entropy static token |

No static bearer credential ships with the project.

Token management:

| Variable | Purpose |
|---|---|
| `ENABLE_HTTP_TOKEN_MANAGEMENT` | enable powerful local management endpoints |
| `TOKEN_MANAGEMENT_ADMIN_TOKEN` | separate high-entropy admin credential |
| `TOKEN_MANAGEMENT_ALLOWED_IPS` | management IP/CIDR allowlist |
| `REQUIRE_ADMIN_AUTH` | must remain true in production |

Keep management disabled unless required.

## JWT

Key settings include:

- `ENABLE_JWT_AUTH`
- `JWT_SECRET_KEY`, `JWT_ALGORITHM`
- `JWT_ISSUER`, `JWT_AUDIENCE`
- `JWT_EXPIRATION_HOURS`
- verification switches for signature, expiry, issuer, and audience
- refresh-token keys/lifetime when refresh is enabled
- claim names for user ID, roles, permissions, and security level

Use a supported asymmetric key strategy or a deployment-specific high-entropy
shared key. Replace every example placeholder.

## External OAuth/OIDC

Key settings include:

- `ENABLE_OAUTH_AUTH`
- `OAUTH_PROVIDER_TYPE`, client ID/secret, redirect URI
- mandatory trusted `OAUTH_ISSUER` and `OAUTH_RESOURCE`
- `OAUTH_AUDIENCE` (defaults to resource)
- discovery, authorization, token, introspection, userinfo, and JWKS endpoints
- exact allowed/required scopes and claim names
- default roles/security level/permissions
- trusted domains and JSON role mappings
- session/state secrets and lifetimes

RFC 7662 introspection is part of the trust boundary. Provider examples in
`.env.example` are templates, not proof that a provider is safe without issuer,
resource, audience, and introspection configuration.

## Doris-backed OAuth

Key settings include:

- `ENABLE_DORIS_OAUTH_AUTH`, `DORIS_OAUTH_BASE_URL`
- exact child/channel switches and `domain.child` allowlists
- token, refresh, authorization-code, client, and GC lifetimes
- preconfigured client file and redirect URI policy
- DCR mode and explicit production-DCR switch
- per-IP/user/client/transaction rate limits
- insecure-HTTP, trusted-proxy, and trusted-proxy-CIDR policy

Required invariants:

- HTTP transport;
- one effective worker;
- external OAuth disabled;
- configured service/global Doris account;
- HTTPS for non-loopback production URL;
- exact resource binding and scopes.

## Logging and monitoring

| Variable | Purpose |
|---|---|
| `LOG_LEVEL` | process log level |
| `LOG_FILE_PATH` | optional main log path |
| `ENABLE_AUDIT` | audit logging |
| `AUDIT_FILE_PATH` | audit log path |
| `LOG_MAX_FILE_SIZE`, `LOG_BACKUP_COUNT` | rotation |
| `ENABLE_LOG_CLEANUP` | automatic cleanup |
| `LOG_MAX_AGE_DAYS` | retention |
| `LOG_CLEANUP_INTERVAL_HOURS` | cleanup interval |
| `ENABLE_METRICS`, `METRICS_PORT` | metrics export |
| `HEALTH_CHECK_PORT` | compatibility monitoring port |
| `ENABLE_ALERTS`, `ALERT_WEBHOOK_URL` | optional alerting |

Never include credential values in log configuration diagnostics.

## Minimal profiles

Local stdio:

```bash
TRANSPORT=stdio
DORIS_HOST=127.0.0.1
DORIS_PORT=9030
DORIS_USER=mcp_reader
DORIS_PASSWORD=<secret>
MCP_TOOL_EXPOSURE_MODE=hierarchical
```

Authenticated loopback HTTP:

```bash
TRANSPORT=http
SERVER_HOST=127.0.0.1
SERVER_PORT=3000
ENABLE_TOKEN_AUTH=true
TOKEN_OPERATOR=<generated-secret>
DORIS_HOST=127.0.0.1
DORIS_USER=mcp_reader
DORIS_PASSWORD=<secret>
```

Generate secrets outside source control:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

See [Deployment](../operations/deployment.md) and
[Security model](../security/security-model.md) before using non-loopback
configuration.
