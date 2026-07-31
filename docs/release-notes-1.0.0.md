<!--
  ~ Licensed to the Apache Software Foundation (ASF) under one
  ~ or more contributor license agreements.  See the NOTICE file
  ~ distributed with this work for additional information
  ~ regarding copyright ownership.  The ASF licenses this file
  ~ to you under the Apache License, Version 2.0 (the
  ~ "License"); you may not use this file except in compliance
  ~ with the License.  You may obtain a copy of the License at
  ~
  ~   http://www.apache.org/licenses/LICENSE-2.0
  ~
  ~ Unless required by applicable law or agreed to in writing,
  ~ software distributed under the License is distributed on an
  ~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  ~ KIND, either express or implied.  See the License for the
  ~ specific language governing permissions and limitations
  ~ under the License.
-->

# Doris MCP Server 1.0.0 Release Notes

Expanded guides: [English](releases/1.0.0.md) |
[Simplified Chinese](releases/1.0.0.zh-CN.md)

Doris MCP Server 1.0.0 establishes the first versioned public contract for
progressive, capability-aware Apache Doris tooling over MCP `2026-07-28`.

The MCP protocol contract is generally available on Streamable HTTP and stdio.
The Python package retains its Beta deployment classifier because several
distributed deployment shapes remain intentionally constrained.

## Highlights

- Eight stable, read-only top-level domains with progressive child discovery.
- Fifty-five collision-free child capabilities across catalog, query,
  cluster, pipeline, search, governance, lakehouse, and semantic concerns.
- A startup-time `flat` fallback for Hosts that cannot use progressive
  disclosure.
- Runtime Doris version, feature, provider, permission, and availability
  evidence with fail-closed behavior.
- Native Doris lineage integration for 4.0.6 and later when the companion
  provider is available, with explicit audit-based fallback behavior.
- Optional Apache Ossie semantic grounding with exact `model_ref` selection.
- Optional MetricFlow consumption with exact `model_ref`, a compile-only
  sidecar, and MCP-governed Doris execution.
- MCP `2026-07-28` stateless request handling, bounded schemas and results,
  trace propagation, and deterministic product identity.
- Static token, JWT, external OAuth/OIDC, and Doris-backed OAuth boundaries.

The generated [tool catalog](tool-registry.md) contains the exact 8-domain and
55-child release surface.

## Breaking changes

- Pre-1.0 direct tool names are removed without an alias window.
- Hierarchical discovery is the default exposure mode.
- Flat mode uses formal names such as `doris_query_execute_query`, not
  pre-1.0 names.
- Authorization uses exact domain and child scope identifiers.
- Semantic model-specific calls require an explicit `model_ref`.
- The modern HTTP endpoint accepts MCP `2026-07-28`; the isolated legacy
  protocol adapter is default-off.

See the [migration guide](migration-1.0.0.md) for call shapes, Host behavior,
configuration, and old-to-new mappings.

## Doris compatibility

The project minimum is Doris `2.0.0`. The 1.0 target patch set is:

- `2.0.15`
- `2.1.11`
- `3.0.3`
- `3.1.4`
- `4.0.5`
- `4.0.6`
- `4.0.7`
- `4.1.0`
- `4.1.1`
- `4.1.2`
- `4.1.3`

Capability ranges and certification are keyed only by `major.minor.patch`;
RC or GA labels do not affect the result or create separate buckets. Doris
`4.0.5` is the first evidence-backed certified target. Every other target
remains `target_uncertified` until the same real cluster gate is complete.
This status is a certification statement, not a claim that all other versions
are unusable.

## Verified release boundaries

The release gate covers:

- warnings-as-errors unit and integration tests;
- Ruff, Mypy, Bandit, and lock-file validation;
- source distribution and clean-wheel installation;
- official MCP `2026-07-28` stateless conformance;
- stdio and Streamable HTTP;
- hierarchical and Flat exposure;
- stable 8-domain and 55-child contracts across processes;
- real read-only Doris calls with zero management writes.

## Known limits

- `doris_admin` is reserved but not registered.
- Doris-backed OAuth uses process-local state and is not a multi-worker or
  multi-node mode.
- ADBC is default-off and requires explicit user intent plus
  `explicit_adbc=true`; execution is fail-closed on token-bound routes because
  the current Arrow Flight client is process-global.
- Ossie semantic grounding is optional, read-only, and does not compile or
  execute semantic model expressions.
- MetricFlow support requires an operator-supplied Doris-capable compiler
  provider; the provider cannot bypass MCP-governed query execution.
- Native lineage requires a queryable companion provider; audit inference is
  the primary path before Doris 4.0.6 and a degraded fallback afterward.
