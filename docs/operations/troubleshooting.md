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

# Troubleshooting

[English](troubleshooting.md) | [简体中文](troubleshooting.zh-CN.md)

Start with the public error code, request ID, current domain manifest, and the
same request-specific Doris identity. Do not copy tokens, passwords, raw OAuth
responses, or private model bindings into an issue.

## First checks

```bash
doris-mcp-server --version
curl --fail http://127.0.0.1:3000/live
curl --verbose http://127.0.0.1:3000/ready
```

Record:

- package version and commit/image digest;
- transport and exposure mode;
- normalized Doris version and deployment mode;
- domain/child and public `reason_code`;
- request ID and timestamp;
- whether `/live` and `/ready` differ;
- whether the same Doris account can run a minimal equivalent read-only check.

## Server does not start

### Non-loopback bind without authentication

Symptom: startup refuses `0.0.0.0` or another non-loopback address.

Resolution: enable one reviewed authentication mode and deploy behind TLS with
validated Host/Origin. Use `ALLOW_UNAUTHENTICATED_NON_LOOPBACK=true` only for
isolated disposable testing.

### Authentication modes conflict

External OAuth and Doris-backed OAuth cannot be active together. Select one
trust model. Also verify required issuers, resources, keys, base URLs, proxy
CIDRs, and secrets.

### Doris OAuth rejects worker count

Doris-backed OAuth requires Streamable HTTP and `WORKERS=1` in 1.0 because its
authorization and per-user pool state are process-local.

### Administration-domain configuration is rejected

`doris_admin` is reserved and intentionally unavailable. Remove attempts to
enable it; there is no 1.0 management-tool bypass.

### Custom provider fails startup

Every name in `MCP_TOOL_PROVIDERS` must resolve to an installed, valid entry
point with non-colliding bounded schemas. Remove the name or repair the
provider. Allowlisted provider failures are fail-closed by design.

## `/live` works but `/ready` returns 503

The process is alive, but the bounded Doris readiness route failed.

Check:

1. FE MySQL host/port and network policy.
2. The configured database exists and is visible.
3. Credentials and account lock/expiry.
4. TLS/proxy requirements between Server and Doris.
5. Pool exhaustion or repeated timeout disposal.
6. Multi-FE candidates and whether at least one is healthy.

Test with the same account and network path. Do not treat a different admin
account's successful `SELECT 1` as proof that the MCP identity works.

## HTTP request rejected

### Host or Origin denied

The bind address is not an allowlist. Confirm the actual `Host` and `Origin`
seen by the Server, reverse-proxy rewrites, TLS scheme, and trusted proxy CIDR.
Avoid globally trusting forwarded headers.

### `HeaderMismatch` (`-32020`)

Ensure:

- `MCP-Protocol-Version` matches `_meta`;
- `Mcp-Method` exactly matches JSON-RPC `method`;
- `Mcp-Name` matches the tool/resource/prompt name or URI;
- `Accept` includes JSON and event-stream media types;
- the proxy preserves these headers.

### Unsupported protocol (`-32022`)

Use MCP `2026-07-28`. A `2025-11-25` HTTP client must use the explicitly
enabled `/mcp/legacy` endpoint. HTTP+SSE clients must migrate.

## Authentication or authorization fails

### 401 authentication required

Confirm the credential type matches the enabled mode, the token is active and
unexpired, issuer/audience/resource match, and the proxy does not remove the
Authorization header.

### 403 insufficient scope

Read the exact required scope. A domain discovery grant does not imply a child
call grant. Pre-1.0 names and wildcard guesses are invalid.

### Child appears missing

An unauthorized child is intentionally indistinguishable from a nonexistent
child. Re-run domain discovery under the same identity and verify exact
discovery/call scopes and channel enablement.

### Doris permission denied

MCP authorization may pass while Doris RBAC denies the actual object. Test the
same SQL/metadata view with the same Doris account, then grant only the minimum
required privilege. See the fine-grained access guide.

## Domain discovery or child execution fails

### `CHILD_MANIFEST_STALE`

Call the domain with `{}` again and use the new manifest. Route, permission,
provider, model, feature probe, or capability cache generation may have
changed.

### `CHILD_CAPABILITY_UNAVAILABLE`

Use structured `reason_code` and evidence sources. Common causes:

- Doris version below the feature range;
- mixed or unknown active component versions;
- missing system table/function/index;
- disabled or unhealthy optional provider;
- unreadable metadata for the request account;
- incomplete lineage store;
- stale evidence outside its allowed window.

Call `doris_cluster.get_runtime_capabilities` when authorized. Do not edit the
description or force execution around `callable=false`.

### Manifest over budget

This indicates catalog/provider/schema drift. Built-in manifests and flat
tools have hard budgets. Regenerate/check the tool catalog and reduce provider
descriptions/schemas; do not raise limits casually because Host context is a
product contract.

## Query failures

### `QUERY_READ_ONLY_VIOLATION`

Submit one read-only statement. Remove DDL/DML/administration, stacked
statements, unsafe comments, or unsupported query shape. The Query child is not
an administrative SQL escape hatch.

### `QUERY_ARGUMENT_INVALID`

Use the exact discovered schema. Validate identifier fields, parameter names
and types, query target shape, requested format, and limits.

### `QUERY_TIMEOUT`

Reduce scanned data, add predicates, use Explain/diagnosis, lower requested
result volume, and inspect Doris workload state. Retry only when the error says
it is retryable. A timed-out connection may be disposed intentionally.

### Result truncated or too large

Use smaller pages, narrower columns, stronger filters, aggregation, or a lower
limit. Do not increase process limits before estimating serialized response
size and model context impact.

### Profile unavailable

Check FE HTTP host/port, allowlist, route identity, profile retention, query ID,
and the Doris account's visibility. A working MySQL route does not prove FE
HTTP is configured.

## Pagination and state handles

An invalid cursor can mean expiry, tampering, visibility change, principal
change, wrong list type, different state secret, or a changed snapshot. Restart
the list without a cursor.

With independent replicas, configure the same
`MCP_STATE_HANDLE_SECRET`. Do not decode or construct cursors in the Host.

## stdio parsing errors

- Ensure no log/banner/debug output is written to stdout.
- Launch `doris-mcp-server`, not `doris-mcp-client`.
- Confirm the Host uses MCP `2026-07-28` request metadata.
- Check environment inheritance and executable path.
- Reproduce with a true subprocess, not a shell pipeline that mixes streams.

## Provider-specific failures

### ADBC unavailable

Confirm `ADBC_ENABLED`, Arrow Flight SQL ports, provider installation, and live
connectivity. Confirm the end-user request explicitly selected ADBC and the
call includes `explicit_adbc=true`. ADBC execution intentionally fails closed
on token-bound routes. Use the MySQL read-only query child for ordinary SQL.

### Ossie model unavailable

Confirm `OSSIE_ENABLED`, model directory, reviewed schema revision, exact
`model_ref`, private binding manifest, semantic scopes, and Doris visibility.
The Server never guesses a model.

### MetricFlow model or compile unavailable

Confirm `METRICFLOW_ENABLED`, the absolute provider command, project directory,
sidecar protocol version, exact `model_ref`, Doris-dialect support, timeout and
output bounds, semantic scopes, and Doris visibility. Provider stderr is
intentionally hidden; inspect operator logs with secrets removed. The sidecar
must compile only—Doris SQL execution belongs to the MCP Query runtime.

### Native lineage unavailable

Check normalized Doris version, companion producer health, queryable store,
required canonical columns, and request permissions. Use
`get_lineage_capability_status` before tracing. Audit fallback is explicit and
may be unavailable or incomplete.

## Safe support bundle

Include:

- version, commit/image digest, OS/Python;
- sanitized configuration keys (no values for secrets);
- domain manifest availability/reason codes;
- health status and timestamps;
- request IDs and sanitized log lines;
- minimal reproducible read-only SQL with sensitive identifiers/data replaced;
- whether the failure reproduces on stdio, HTTP, or both.

Exclude:

- bearer/admin tokens, passwords, JWT keys, OAuth client secrets;
- Authorization headers, token files, raw environment dumps;
- private Ossie bindings, connection URLs with credentials;
- customer SQL/data unless explicitly sanitized and approved.
