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
- Per-request client capability enforcement, cache hints, typed protocol
  errors, and deterministic product identity.
- Real Doris process tests covering Streamable HTTP and stdio.

### Changed

- Consolidated tools, resources, and prompts on the Python SDK v2 protocol
  core.
- Unified package metadata, CLI output, `server/discover`, legacy
  `serverInfo`, and health endpoints on one product version source.
- Documented the modern request headers, migration steps, and deployment
  constraints.

### Fixed

- Preserved service availability after malformed requests, unknown methods,
  header mismatches, unsupported versions, and missing capabilities.
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
