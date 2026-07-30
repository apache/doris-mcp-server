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

- MCP `2026-07-28` stateless protocol support on Streamable HTTP and stdio,
  with a `2025-11-25` migration path.
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
- Real Doris process tests covering Streamable HTTP and stdio.

### Changed

- Consolidated tools, resources, and prompts on the Python SDK v2 protocol
  core.
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
- Positioned Dynamic Client Registration as a compatibility fallback behind
  preconfigured clients and Client ID Metadata Documents.
- Persisted static bearer tokens as self-describing SHA-256/SHA-512 digests,
  with atomic owner-only writes and one-way migration from legacy plaintext
  token files.

### Fixed

- Preserved service availability after malformed requests, unknown methods,
  header mismatches, unsupported versions, and missing capabilities.
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

[Unreleased]: https://github.com/apache/doris-mcp-server/compare/0.6.1...HEAD
[0.6.1]: https://github.com/apache/doris-mcp-server/compare/0.6.0...0.6.1
[0.6.0]: https://github.com/apache/doris-mcp-server/compare/0.5.1...0.6.0
[0.5.1]: https://github.com/apache/doris-mcp-server/compare/0.5.0...0.5.1
[0.5.0]: https://github.com/apache/doris-mcp-server/compare/0.4.2...0.5.0
[0.4.2]: https://github.com/apache/doris-mcp-server/compare/0.3.0...0.4.2
[0.3.0]: https://github.com/apache/doris-mcp-server/releases/tag/0.3.0
