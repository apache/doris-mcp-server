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

# Changelog

All notable changes to Doris MCP Server are recorded here. The product version
is defined in `doris_mcp_server/_version.py`. Changes after the latest tag stay
under **Unreleased** until a new version is selected and published.

## [Unreleased]

### Added

- Added an explicit Dify 1.16.1 compatibility profile for MCP `2025-06-18`
  through the default-off `/mcp/legacy` endpoint, with initialize, stateless
  tool-discovery, and tool-call regression coverage.
- Added eight default-off MetricFlow consumer children to `doris_semantic`
  for exact-model discovery, status, metrics, group-bys, saved queries,
  dimension values, Doris SQL compilation, and bounded execution through the
  existing MCP Query runtime.
- Added a bounded `doris-mcp-metricflow/v1` sidecar contract and bilingual
  Doris 2.0+ version capability matrix.

### Changed

- Expanded the stable public contract from 47 to 55 children while retaining
  the same eight top-level domains and progressive-disclosure budgets.
- Lowered the project-wide Doris baseline from 3.0.0 to 2.0.0 and moved
  version-dependent behavior into per-child release, runtime-probe, provider,
  route, and permission gates.
- Made ADBC an advanced default-off path that requires explicit end-user
  ADBC/Arrow Flight SQL intent and `explicit_adbc=true`; ordinary queries use
  `doris_query.execute_query`.

- Rebuilt the root English and Simplified Chinese READMEs as concise 1.0 entry
  points instead of mixing architecture, operations, integration, and release
  material in one document.
- Added a categorized bilingual documentation system for architecture,
  request flow, capabilities, protocol behavior, security, operations,
  configuration, Host integration, development, migration, and release
  guidance.
- Published the detailed 1.0 release record in
  [Issue #189](https://github.com/apache/doris-mcp-server/issues/189), including
  the complete 8-domain/55-child surface, capability detection, security,
  reliability, compatibility, migration, and verification boundaries.
- Added Simplified Chinese editions of the custom Tool Provider and Doris
  fine-grained access-control guides, and included the complete documentation
  tree in source distributions.

### Fixed

- Accepted `+` revision metadata in exact Ossie and MetricFlow model
  references across binding loading, runtime lookup, and public Child schemas.
- Enforced the canonical read-only SQL allowlist again at the production
  connection boundary, including calls without an authentication context, and
  restricted internal session changes to an exact `USE`/`SWITCH`/profile
  allowlist. Doris administrative, export, load, plugin, credential, backup,
  restore, and other state-changing statements now fail closed before the
  database driver.
- Raised vulnerable runtime dependency floors and refreshed the lock file,
  including `aiohttp`, `aiomysql`, `cryptography`, `python-multipart`,
  `sqlparse`, `starlette`, and their affected transitive dependencies. Removed
  the unused `python-jose` and `fastapi` dependency chains.
- Bounded auxiliary OAuth and token-management POST bodies before form or JSON
  parsing, and stopped trusting spoofable forwarding headers for token
  management IP allowlists.
- Bound direct Compose service ports to loopback and changed the MCP service's
  default Doris identity from `root` to the dedicated `mcp_reader` account.
- Added explicit, mutually exclusive top-level domain boundaries and a
  single-domain discovery rule, preventing Hosts from speculatively expanding
  unrelated manifests for ambiguous operational questions. Unqualified cluster
  history requests now preserve every usable recorded series.
- Declared the exact `storage`, `query_volume`, and `user_activity` selectors
  for resource-growth analysis, including their recorded evidence sources, so
  Hosts reject ambiguous values before dispatching a Doris query.
- Kept resource-growth analysis callable in degraded mode when only audit-log
  history or partition-creation history is readable, instead of hiding every
  selector behind the audit-log capability probe.
- Updated JWT decoding type contracts for PyJWT 2.13 while preserving the
  existing signature, claim, audience, issuer, and unsafe-debug validation
  behavior.
- Documented the strict `/mcp` versus `/mcp/legacy` endpoint boundary in the
  protocol, Host, quick-start, deployment, troubleshooting, migration, and
  release guides without restoring pre-1.0 tool names or weakening security.
- Classified Doris runtime probe errors whose messages explicitly report
  denied access or missing privileges as permission failures, including Doris
  error 1105 responses, instead of exposing a generic probe failure.
- Replaced the Query Profile capability check that used a synthetic query ID
  with an owned, bounded profiled query and trace lookup, preventing valid Doris
  Profile APIs from being hidden by a false-negative probe.
- Added the Apache SkyWalking Eyes release gate, its bounded repository
  configuration, and the missing ASF license headers required for source
  release verification.
- Kept the fully available 12-child Semantic manifest below the 16 KiB
  progressive-disclosure budget by publishing only the child call signature;
  the Server still applies the complete validation schema at execution time.
- Added real Doris HTTP and stdio coverage for all eight MetricFlow consumer
  children, including compile-only behavior and guarded execution of compiled
  SQL through the standard Query runtime.
- Migrated the opt-in real Doris process integration suite from removed legacy
  tool names to the 1.0 hierarchical domain discovery and exact Child
  execution contract across Streamable HTTP and stdio.
- Added real Doris regression coverage for the Query read-only guard, runtime
  row, byte, and timeout ceilings, cancellation recovery, and database-level
  read permission denial through the formal `doris_query` Child surface.

## [1.0.0] - 2026-08-01

### Added

- MCP `2026-07-28` stateless protocol support on Streamable HTTP and stdio,
  with HTTP migration paths for `2025-06-18` and `2025-11-25`.
- Doris-backed OAuth with per-user Doris connection pools and operation gates.
- Client ID Metadata Document discovery for Doris-backed OAuth, including
  bounded retrieval, DNS pinning, cache-control handling, and consent-screen
  client/redirect host context.
- Per-request client capability enforcement, cache hints, typed protocol
  errors, and deterministic product identity.
- Permission-bound cursor pagination for resources, tools, and prompts on
  Streamable HTTP and stdio.
- HMAC-authenticated explicit state handles with principal, scope, resource,
  expiry, and shared-worker key binding instead of protocol-session state.
- W3C `traceparent`, `tracestate`, and `baggage` propagation from request
  `_meta`, with value-safe validation, credential-like baggage redaction,
  per-request isolation, and no trace metadata in model-facing results.
- Explicitly installed and allowlisted custom tool providers for existing
  business APIs, with lifecycle management, schema validation, safe audit
  metadata, and bounded process-local rate limits.
- Bounded query result streaming with deployment and absolute ceilings for
  rows, serialized bytes, and execution time, plus cancellation-safe database
  connection disposal.
- A read-only Cluster domain with eleven capability-gated children for node
  inventory, active tasks, metrics, memory, cache, compaction, workload and
  compute groups, recorded resource growth, and sanitized runtime evidence.
- A read-only Pipeline domain with five capability-gated children for
  ingestion status and diagnosis, materialized-view refresh state, recorded
  table freshness, and bounded upstream or downstream dependency evidence.
- A read-only Search domain with four capability-gated children for
  target-index-validated text, vector, and hybrid retrieval, Doris-native
  tokenizer previews, search-index inspection, and evidence-based diagnosis.
- A read-only Governance domain with eight capability-gated children for
  column quality, table storage, lineage capability and tracing, access
  patterns, audit events, user-defined functions, and authentication mappings.
- An explicit queryable lineage-provider contract and canonical Doris lineage
  event-store schema for companion-plugin deployments.
- A read-only Lakehouse domain with capability-gated external-catalog,
  lakehouse-table, snapshot, partition, pushdown, and Variant-shape
  inspection.
- An experimental read-only Semantic domain with four Apache Ossie Core
  grounding children, eight MetricFlow consumer children, revisioned
  model-summary resources, and explicit server-private Doris bindings.
- A fail-closed `doris_admin` architecture reservation that defines future
  high-risk action, scope, preview/execute, confirmation, idempotency, and
  rollback contracts without registering any management capability.
- Real Doris process tests covering Streamable HTTP and stdio.

### Changed

- Consolidated tools, resources, and prompts on the Python SDK v2 protocol
  core.
- Declared MCP `2026-07-28` protocol compatibility generally available on
  Streamable HTTP and stdio after the full release gate passed; the project
  package classification and documented deployment constraints remain
  unchanged.
- Restricted the modern `/mcp` endpoint to 2026-07-28 POST requests and moved
  legacy HTTP migration traffic to a default-off `/mcp/legacy` adapter.
- Unified package metadata, CLI output, `server/discover`, legacy
  `serverInfo`, and health endpoints on one product version source.
- Documented the modern request headers, migration steps, and deployment
  constraints.
- Recorded `subscriptions/listen` as intentionally unavailable until a real
  cross-worker Doris change-event source exists, with discovery kept
  capability-honest.
- Added bounded JSON Schema 2020-12 validation for tool definitions, arguments,
  and declared structured outputs without external reference fetching.
- Consolidated tool schemas, execution handlers, Doris OAuth policy, safe
  audit metadata, compatibility aliases, and generated documentation in one
  validated Tool Definition Registry.
- Separated immutable tool metadata into a standalone catalog while keeping
  lifecycle, authorization, audit, and execution routing in the tools manager.
- Positioned Dynamic Client Registration as a compatibility fallback behind
  preconfigured clients and Client ID Metadata Documents.
- Persisted static bearer tokens as self-describing SHA-256/SHA-512 digests,
  with atomic owner-only writes and one-way migration from legacy plaintext
  token files.
- Added coverage gates for the protocol, authentication, and core manager
  domains at 80%, alongside a 55% whole-repository floor.
- Separated production dependencies from test, lint, type-check, and build
  tooling across package metadata, generated requirements, Docker, and clean
  wheel verification.
- Selected Governance lineage providers deterministically from observed Doris
  versions and live plugin, store, and audit evidence: Doris 4.0.6 and later
  can use native companion-plugin events, while audit inference remains the
  primary path before 4.0.6 and an explicit degraded fallback afterward.
- Selected Lakehouse and Variant capability variants from observed Doris
  component versions and live metadata probes, with 4.1 lifecycle and
  advanced Variant facets reported separately from target-level evidence.
- Pinned Ossie model loading to the reviewed `0.2.0.dev0` schema, exact
  `model_ref` selection, bounded deterministic context construction, and
  route-aware Doris permission filtering without compiling or executing model
  expressions.
- Aligned semantic OAuth discovery, execution, resource exposure, and Doris
  OAuth scope issuance on explicit channel opt-in plus `semantic:read`.
- Rejected 1.0 configuration attempts to enable the reserved administration
  domain or disable its mandatory confirmation invariant.
- Enforced a 24 KiB hard budget for the stable eight-domain `tools/list`, with
  cross-domain and separate-worker determinism gates for Hosts that do not
  support dynamic tool re-registration.
- Added an evidence-backed Doris patch certification matrix keyed by normalized
  three-part versions, with complete Host-quadrant proof requirements and
  fail-closed runtime disclosure for unknown or mixed component versions;
  Doris `4.0.5` is the first certified target.
- Normalized all Doris capability, range, and certification decisions to
  `major.minor.patch`; RC, GA, commit, and deployment metadata remain evidence
  only and never create a separate support result.
- Published the 1.0 migration guide and release notes, and generated the exact
  8-domain/55-child tool catalog from the runtime catalog as a checked-in,
  CI-verified release artifact.

### Fixed

- Released failed capability-probe connections from their captured owner pools
  so a single-connection route cannot starve subsequent domain calls.
- Isolated Doris domain probe statements in independent route-aware connection
  contexts so one unsupported version-specific statement cannot poison later
  capability evidence.
- Kept Search filters, identifiers, vectors, and result fields structured and
  bounded, with caller values remaining driver-bound instead of accepting raw
  search SQL or Doris `SEARCH` DSL through the structured retrieval child.
- Classified missing Doris Search functions as unsupported capability evidence
  and preserved analyzer terms without colliding with credential-token
  redaction.
- Bound hybrid Search vector, text, and structured-filter parameters in exact
  SQL placeholder order.
- Kept Governance sampling, audit windows, lineage traversals, identifiers,
  and result collections bounded, and redacted raw SQL, client addresses,
  authentication rules, secrets, and error messages from model-facing output.
- Emitted lineage edges only from attributable native events or conservative
  direct-column audit evidence, without placeholder sources or invented
  numeric confidence scores.
- Kept catalog property values, storage locations, raw plans, and sampled
  Variant values out of model-facing output while bounding object, snapshot,
  partition, path, and type-shape evidence.
- Kept semantic discovery, resources, summaries, mappings, metrics, and
  relationships fail-closed when a configured route, binding, physical
  dependency, or Doris permission cannot be verified.
- Preserved configured Governance and Lakehouse runtime limits across the
  multi-worker parent-to-worker environment handoff.
- Preserved configured semantic loader, context, and OAuth exposure limits
  across the multi-worker parent-to-worker environment handoff.
- Excluded explicitly dead Doris components from active version gating while
  preserving them in node inventory, and kept live runtime manifests within
  the 16 KiB domain budget.
- Limited public detected-version evidence to each child's actual Doris
  component scope, preventing real Cluster manifests from overflowing the
  16 KiB budget and breaking Flat-mode `tools/list`.
- Preserved service availability after malformed requests, unknown methods,
  header mismatches, unsupported versions, and missing capabilities.
- Kept static-token Doris pools usable after repeated query timeouts, and
  stopped per-request token validation from mutating the shared global pool.
- Stopped list operations from converting Doris, permission, or internal
  failures into successful empty resource, tool, or prompt collections.
- Corrected resource and prompt error semantics and tool `isError` results.
- Removed admin-token query authentication and dashboard URL propagation;
  management endpoints now accept admin credentials only in headers.
- Removed shipped static credentials and the legacy default secret; static and
  management token modes now require explicit high-entropy credentials.
- Refused unauthenticated HTTP startup on non-loopback bind addresses unless
  the operator sets an explicit dangerous override.
- Normalized bearer credentials once at the MCP authentication boundary and
  passed the same redacted DTO to static token, JWT, external OAuth, and Doris
  OAuth providers.
- Required external OAuth access tokens to pass trusted RFC 7662
  issuer/resource/audience, lifetime, and scope validation before userinfo is
  used.
- Preserved external OAuth token failures through the authentication boundary
  and returned RFC 6750/RFC 9728 Bearer challenges, protected-resource
  metadata, and operation-specific insufficient-scope responses.
- Enforced exact external OAuth scopes across tool, resource, and Prompt
  operations before modern HTTP dispatch while preserving static token, JWT,
  anonymous loopback, and local stdio behavior.
- Bound Doris OAuth access tokens to the canonical MCP resource and rejected
  tokens issued for any other resource before per-user pool access.
- Rejected Doris OAuth authorization-code exchanges whose required RFC 8707
  `resource` is missing or differs from the authorization grant.
- Required Doris OAuth DCR clients to declare a persisted `application_type`
  and enforced type-matched redirect URI rules for native and web clients.
- Added RFC 9207 `iss` identification to Doris OAuth authorization success and
  redirectable error responses, with matching discovery metadata.
- Released Doris connections on SQL profile, data freshness, and access
  analysis paths.
- Improved Doris 4 role metadata compatibility and query recovery behavior.

## [0.6.1] - 2025-12-24

### Added

- Batch SQL execution support.

### Changed

- Improved stdio and Streamable HTTP startup behavior.
- Improved multi-worker operation and token authentication.

### Fixed

- Corrected token authentication and related security issues.

## [0.6.0] - 2025-09-03

### Added

- Token, JWT, and OAuth authentication.
- Token management and token-bound Doris database configuration.
- Connection session caching and concurrent HTTP startup support.

### Fixed

- Improved SQL injection detection, schema loading, connection release, and
  configuration handling.

## [0.5.1] - 2025-07-15

### Fixed

- Corrected tool behavior introduced in 0.5.0.

## [0.5.0] - 2025-07-11

### Added

- Nine data analysis, governance, quality, and ADBC tools.
- Cursor and Dify integration examples.

### Changed

- Redesigned logging and asynchronous Doris connection lifecycle handling.

### Fixed

- Addressed recurring `at_eof` connection failures and MCP SDK startup
  compatibility.

## [0.4.2] - 2025-06-27

### Changed

- Updated the PyPI project name, packaging metadata, startup commands, and
  installation documentation.

## [0.3.0] - 2025-06-09

- First tagged release in this repository.

[Unreleased]: https://github.com/apache/doris-mcp-server/compare/1.0.0...HEAD
[1.0.0]: https://github.com/apache/doris-mcp-server/compare/0.6.1...1.0.0
[0.6.1]: https://github.com/apache/doris-mcp-server/compare/0.6.0...0.6.1
[0.6.0]: https://github.com/apache/doris-mcp-server/compare/0.5.1...0.6.0
[0.5.1]: https://github.com/apache/doris-mcp-server/compare/0.5.0...0.5.1
[0.5.0]: https://github.com/apache/doris-mcp-server/compare/0.4.2...0.5.0
[0.4.2]: https://github.com/apache/doris-mcp-server/compare/0.3.0...0.4.2
[0.3.0]: https://github.com/apache/doris-mcp-server/releases/tag/0.3.0
