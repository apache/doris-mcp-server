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

# Reliability and limits

[English](reliability.md) | [简体中文](reliability.zh-CN.md)

Reliability in 1.0 means the Server remains honest under partial failure. A
missing provider, old Doris patch, denied system table, unhealthy FE, timeout,
or oversized result must become a bounded typed state—not a fabricated empty
success or an unbounded retry loop.

## Reliability principles

- Fail startup on unsafe configuration.
- Fail closed on unknown capability or authorization state.
- Keep discovery available when an individual child is unavailable.
- Separate process liveness from Doris-backed readiness.
- Bound every collection, request, schema, query, and response.
- Preserve request identity and route affinity without protocol sessions.
- Report the active native/fallback evidence path.
- Classify retryability rather than asking Hosts to parse backend strings.
- Validate successful structured output before returning it.

## Health model

| Endpoint | Meaning | Should orchestrator restart? |
|---|---|---|
| `/live` | process and protocol path are alive | only after repeated liveness failure |
| `/ready` | Server can safely serve the configured Doris-backed path now | remove from traffic; diagnose route before restart |
| `/health` | compatibility aggregate | use `/live` and `/ready` for precise automation |

A `/live` 200 with `/ready` 503 commonly indicates Doris connectivity,
credentials, route, or initialization state—not a dead MCP process.

## Connection and route resilience

The connection manager maintains canonical route identities for global,
static-token-bound, and Doris OAuth user pools. It enforces:

- explicit route priority;
- ownership checks between auth context and pool;
- bounded pool size and connection lifetime;
- health checks and timeout-aware disposal;
- cancellation cleanup;
- safe pool recreation after broken/expired connections;
- multi-FE candidate selection and failover;
- no privilege-widening fallback after a request-specific route failure.

Capability probes use independent route-aware connection contexts so one
unsupported version-specific statement does not poison later evidence. A
failed probe releases its connection to avoid starving a single-connection
route.

## Capability resilience

Capability snapshots are cached per route with a bounded TTL. Singleflight
coalesces concurrent probes. Provider and route generations are included in
the manifest fingerprint.

The detector distinguishes:

- supported;
- unsupported;
- unknown;
- degraded;
- misconfigured.

An unknown/mixed base state fails closed when a safe variant cannot be chosen.
A configured stale fallback is time-bounded and marked stale. It cannot hide a
provider generation change or turn missing evidence into support.

## Bounds and backpressure

| Boundary | Mechanism |
|---|---|
| top-level Host context | hard serialized `tools/list` budget |
| domain discovery | child count, description, schema, enum, and manifest byte budgets |
| protocol lists | stable page size plus signed cursor |
| input/output schemas | node/depth/size/reference budgets |
| tool arguments | compiled JSON Schema and operation-specific limits |
| SQL | one read-only statement, timeout, rows, bytes, parameter bounds |
| metadata/search/governance | domain-specific row, field, depth, window, vector, and collection caps |
| HTTP/provider calls | allowlisted destination, timeout, response-size, and redirect policy |
| custom providers | schema checks and bounded process-local rate limits |

Truncation is explicit in result metadata and/or warnings. The Server does not
return an apparently complete result after silently dropping data.

## Deterministic failure model

Domain calls distinguish:

- child not found/hidden;
- capability unavailable;
- manifest stale;
- argument/schema invalid;
- execution timeout;
- execution failed;
- operation authorization denied.

Errors expose stable reason codes, bounded details, status class, and
retryability where applicable. Credentials, raw SQL values, connection URLs,
and backend exception text are not part of the public error contract.

Unexpected manager exceptions are logged internally and converted to a safe
tool execution failure. List failures keep protocol error semantics rather
than returning a successful empty list.

## Partial success

Some operations intentionally compose independent evidence. For example,
`get_table_context` requires `schema`, while `basic`, `comments`, and `indexes`
may be partial or unavailable. The result records per-section status, source,
warnings, and overall partial state.

Partial success is allowed only when the contract identifies optional
components. A missing required component remains a failure.

## Native and fallback paths

Fallback selection is deterministic and observable:

- Cluster task/cache/compaction views select compatible live evidence paths.
- Lakehouse and Variant expose base and advanced facets separately.
- Governance lineage distinguishes native provider, audit-primary, audit
  degraded fallback, and unavailable state.
- Search capability distinguishes missing functions/indexes from query failure.

No fallback is described as native, and no numeric confidence is invented.

## Observability

Every normalized child result includes bounded metadata such as request ID,
duration, source, truncation, and warnings. Sanitized W3C trace context can
connect MCP work to instrumented downstream spans.

Operators should monitor:

- liveness/readiness transitions;
- authentication and exact-scope denials;
- capability reason-code changes;
- timeout, cancellation, and connection disposal;
- result truncation and response-size rejection;
- FE candidate failover;
- provider health/generation changes;
- audit log write failures and log cleanup;
- process memory and query concurrency.

Logs must never contain bearer credentials, Doris passwords, raw private
bindings, or model-facing sensitive query results.

## Multi-worker and multi-instance behavior

MCP `2026-07-28` HTTP requests are stateless and do not require sticky
sessions. Signed state handles can cross workers when they share the launch
secret. Independent replicas require an explicitly shared secret and
compatible policy/catalog state.

Limitations:

- Doris-backed OAuth must use one worker and one instance boundary in 1.0.
- In-memory custom-provider quotas are per process.
- Cache contents are local optimizations; correctness cannot depend on a shared
  cache.
- Provider/model/binding files and MetricFlow sidecar commands/projects must be
  consistently deployed across replicas.

## Known limits

- `doris_admin` is not registered.
- ADBC is default-off, requires explicit end-user ADBC intent on every call,
  and fails closed on token-bound routes.
- Ossie is read-only grounding and does not execute semantic expressions.
- MetricFlow support is a provider protocol, not a bundled Doris adapter. The
  provider compiles only; SQL execution stays in the bounded Query runtime.
- Native lineage delivery is asynchronous best effort and needs a queryable
  companion provider/store.
- Audit-derived lineage/dependency evidence is bounded inference and may be
  incomplete.
- Runtime capability support does not equal release certification.
- Public reverse-proxy Host/Origin configurations require deployment-specific
  validation.
- Subscription/change notifications remain unavailable without a real event
  source.

## Failure recovery playbook

1. Check `/live` and `/ready` separately.
2. Capture the request ID, public reason code, domain/child, route category, and
   timestamp—never the token.
3. Rediscover the domain to rule out a stale manifest.
4. Inspect `doris_cluster.get_runtime_capabilities` when authorized.
5. Validate Doris with the same account and route, including negative RBAC.
6. Check FE candidates and provider health.
7. Reduce query/result scope for bounded time/row/byte failures.
8. Restart only when process/config/pool recovery is indicated; do not use
   restart as a substitute for fixing permissions or unsupported capabilities.

See [Troubleshooting](troubleshooting.md) for symptom-specific procedures.
