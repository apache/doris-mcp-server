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

# Security and permission model

[English](security-model.md) | [简体中文](security-model.zh-CN.md)

Security is layered. MCP authentication, exact operation authorization,
capability visibility, query safety, transport policy, and Apache Doris RBAC
each protect a different boundary. Enabling one layer does not remove the need
for the others.

## Trust model

```text
Network and proxy
  -> HTTP Host/Origin/TLS policy
  -> credential authentication
  -> MCP operation scope
  -> domain discovery scope
  -> exact child execution scope
  -> provider allowlist and capability gate
  -> SQL/identifier/result guard
  -> request-specific Doris identity and RBAC
  -> sanitized bounded response
```

The MCP Server is not an authorization proxy that can grant more data access
than Doris. Doris remains the final authority for catalogs, databases, tables,
columns, rows, UDFs, audit metadata, and system views.

## Authentication modes

### Anonymous local development

Unauthenticated HTTP is permitted only on a loopback bind under the default
policy. It is not a production mode. Non-loopback startup without an enabled
authentication method fails unless the operator sets the explicit dangerous
`ALLOW_UNAUTHENTICATED_NON_LOOPBACK=true` override.

stdio relies on the local process boundary and environment supplied by the
Host. Protect local environment variables, config files, and process access.

### Static bearer tokens

Enable with `ENABLE_TOKEN_AUTH=true`. Static tokens are validated at the MCP
boundary and can be bound to a dedicated Doris route. Persisted token records
use self-describing SHA-256/SHA-512 digests and atomic owner-only writes;
plaintext legacy records are migrated one way.

The optional HTTP token-management interface is disabled by default and must
remain localhost-only, IP-restricted, and protected by a separate high-entropy
admin credential. Admin credentials belong in headers, never query strings.

### JWT

Enable with `ENABLE_JWT_AUTH=true` and configure the expected issuer/key/
algorithm boundary. Private signing keys and shared secrets must be injected
from a secret manager or protected process environment. Do not store real keys
in the repository.

### External OAuth 2.0/OIDC

Enable external access-token validation with `ENABLE_OAUTH_AUTH=true`. Tokens
must pass trusted issuer, audience/resource, lifetime, active-state, and exact
scope validation before optional user information is accepted. An invalid or
insufficient token returns a standards-aligned Bearer challenge without
exposing provider internals.

Email/domain-to-role mappings are normalized and validated. Domain elevation
requires verified identity evidence; fallback mappings do not silently widen
exact child scopes.

### Doris-backed OAuth

`ENABLE_DORIS_OAUTH_AUTH=true` provides an OAuth boundary whose resulting
request identity owns a Doris user connection pool. It requires HTTP, a
configured service account, a public resource/base URL, and `WORKERS=1` in
1.0. External OAuth and Doris-backed OAuth are mutually exclusive.

Authorization codes, access tokens, clients, and user pool state are
process-local. Access tokens are bound to the canonical MCP resource. Required
RFC resource values, redirect policies, PKCE/client rules, and application type
are validated. Raw Doris passwords are not persisted in the token store.

Database-backed child access is disabled by default and uses explicit
feature-ID allowlists and exact scopes when enabled. A Doris OAuth token cannot
silently fall back to the global service account for a protected data call.

## Exact authorization

Authorization is performed more than once:

1. **MCP operation:** for example `list_tools`, `call_tool`, `read_resource`.
2. **Domain discovery:** whether the identity can learn about a child.
3. **Child execution:** exact policy such as
   `child:call:doris_query:execute_query`.
4. **Channel/provider:** whether Doris OAuth, semantic, ADBC, or custom
   provider access is enabled and allowlisted.
5. **Doris RBAC:** whether the selected Doris identity can execute the actual
   statement or read the actual metadata.

OAuth paths require exact domain/child scopes. Wildcard guesses and pre-1.0
tool scopes do not grant access. Discovery does not imply execution.
Unauthorized children are filtered from manifests and execute as not found to
avoid capability-name disclosure.

## Doris identities and connection routing

The route manager selects credentials in explicit order:

1. Doris OAuth request identity and its user-owned pool;
2. static-token-bound Doris configuration;
3. global service account for configurations that permit it.

Pools are isolated by canonical route identity. Timeout, cancellation,
credential mismatch, or unsafe owner/pool state fails closed rather than
falling through to a more privileged pool. Query, metadata, FE HTTP, and
capability evidence must remain aligned to the same request route.

Use a dedicated least-privileged Doris account for every trust boundary. See
[Doris fine-grained access control](../doris-fine-grained-access-control.md)
for grants, row policies, and token-bound examples.

## SQL and identifier safety

The built-in 1.0 domains are read-only. `doris_admin` is not registered.

The shared query guard:

- parses and accepts one supported read-only statement;
- rejects DDL, DML, administrative commands, stacked statements, comments or
  constructs that violate policy, and malformed parameters;
- validates/quotes catalog, database, table, column, function, and metric
  identifiers;
- binds caller values instead of concatenating them where the driver permits;
- checks query target SQL used by Explain/diagnosis as well as direct queries;
- applies timeout, row, serialized-byte, depth, collection, and text limits;
- classifies timeout/read-only/argument/backend failures without returning raw
  backend exception text.

Structured Search never accepts arbitrary filter SQL or a raw search DSL.
Allowlisted FE/BE HTTP clients validate configured destinations and prevent
caller-controlled SSRF targets.

## Result and metadata safety

- Configured masking rules run before model-facing results are returned.
- Sensitive table/column policies can restrict or transform data.
- Raw SQL, client addresses, authentication mappings, object locations,
  catalog properties, Variant samples, and backend errors are removed or
  bounded where the domain contract does not require them.
- Query results, tool inputs, and structured outputs have absolute size/depth
  limits.
- Schema validation errors report paths and keywords, not rejected secret
  values.
- Trace baggage keys resembling credentials are redacted before propagation.
- Public capability snapshots use stable reason codes and sanitized evidence,
  not connection strings or probe exception details.

## Transport security

- Bind local development to `127.0.0.1`, `localhost`, or `::1`.
- Validate both HTTP `Host` and `Origin` to mitigate DNS rebinding.
- A bind address such as `0.0.0.0` is not a public hostname allowlist.
- Use HTTPS when traffic leaves the machine.
- Configure trusted proxy CIDRs before accepting forwarded identity/scheme
  headers; never trust proxy headers globally.
- Keep credentials in authorization headers or protected environment/secret
  mounts, never URLs.
- Run the management interface separately from ordinary MCP access policy.

## State and secret handling

- MCP state handles are HMAC signed, principal/scope/expiry bound, and contain
  no credentials or query data.
- Set a shared high-entropy `MCP_STATE_HANDLE_SECRET` only when independent
  replicas share traffic; rotate it as a deployment secret.
- Token digests are not reversible bearer credentials.
- Logs use redacted credential DTOs and safe representations.
- Do not enable debug logging that serializes request headers or environment
  secrets at the reverse proxy or process supervisor.
- `.env`, token files, OAuth client files, JWT keys, and private Ossie binding
  manifests require owner-only access and must not be committed.

## Custom providers

Only installed entry points named in `MCP_TOOL_PROVIDERS` load. Provider names,
tool names, schemas, lifecycle, audit metadata, and bounded rate limits are
validated. Startup fails closed on an invalid allowlisted provider. Provider
tools cannot shadow built-in tools or silently inherit built-in authorization.

Review [Custom tool providers](../custom-tool-providers.md) before enabling an
extension.

## Security limitations in 1.0

- Doris-backed OAuth is single-worker and process-local.
- Process-local custom-provider rate limits are not a distributed quota.
- ADBC is fail-closed for token-bound routes because the Flight client is
  process-global.
- Native lineage delivery is asynchronous best effort; it is evidence, not a
  transactional authorization source.
- Application-level SQL guards do not replace Doris grants and row policies.
- Public reverse-proxy host/origin shapes require explicit validation and are
  not made safe merely by binding `0.0.0.0`.

## Production checklist

- Use TLS and an authenticated non-loopback deployment.
- Use least-privileged Doris accounts and test negative grants.
- Select one intentional authentication mode and validate exact scopes.
- Keep token-management endpoints disabled unless actively administered.
- Store secrets outside source control and verify filesystem permissions.
- Configure only trusted FE/BE/provider endpoints.
- Verify `/live` and `/ready` separately.
- Run read-only and permission-denial regression tests against the target
  Doris patch.
- Review availability reason codes after upgrades.
- Monitor audit logs without logging bearer values or raw sensitive data.
