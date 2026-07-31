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

# Apache Doris MCP Server Documentation

[English](README.md) | [简体中文](README.zh-CN.md)

This documentation describes the 1.0 public contract. The root README is a
quick entry point; the documents below separate product architecture,
capability behavior, protocol, security, operations, reference, integration,
migration, and release concerns.

## Start here

| Goal | Document |
|---|---|
| Install and run a local Server | [Quick start](getting-started/quickstart.md) |
| Understand the 1.0 design | [Architecture overview](architecture/overview.md) |
| Follow one request end to end | [Request and data flow](architecture/request-lifecycle.md) |
| See every public domain | [Tool domains](capabilities/tool-domains.md) |
| Understand runtime availability | [Capability availability](capabilities/availability.md) |
| Connect an MCP Host | [Host integrations](integrations/hosts.md) |
| Deploy safely | [Deployment](operations/deployment.md) |

## Architecture

- [Architecture overview](architecture/overview.md) — component boundaries,
  top-level design, control plane, execution plane, and extension boundaries.
- [Request and data flow](architecture/request-lifecycle.md) — initialization,
  top-level discovery, domain discovery, child execution, Doris routing, and
  response construction.
- [ADR 0001: subscriptions require change events](decisions/0001-subscriptions-require-change-events.md)
- [ADR 0002: explicit state handles](decisions/0002-explicit-state-handles.md)

## Capabilities

- [Tool domains](capabilities/tool-domains.md) — the 8-domain/47-child contract.
- [Capability availability](capabilities/availability.md) — version parsing,
  probes, providers, permissions, manifests, and fail-closed behavior.
- [Generated tool registry](tool-registry.md) — authoritative generated names,
  handler bindings, authorization identifiers, variants, and migration inputs.

## Protocol

- [MCP 2026-07-28 contract](protocol/mcp-2026-07-28.md) — transports,
  pagination, schemas, errors, state handles, tracing, and legacy isolation.

## Security

- [Security and permission model](security/security-model.md) — authentication,
  authorization layers, query safety, data safety, secrets, and deployment
  policy.
- [Doris fine-grained access control](doris-fine-grained-access-control.md) —
  Doris RBAC, row policies, token-bound identities, and operational examples.

## Operations

- [Deployment](operations/deployment.md) — stdio, HTTP, Docker, proxies,
  workers, secrets, and rollout checks.
- [Reliability and limits](operations/reliability.md) — health, connection
  routing, failover, bounds, observability, fallbacks, and known limits.
- [Troubleshooting](operations/troubleshooting.md) — startup, readiness,
  authentication, capability, query, and transport diagnostics.

## Reference and integrations

- [Configuration reference](reference/configuration.md)
- [Host integrations](integrations/hosts.md)
- [Custom tool providers](custom-tool-providers.md)

## Development, migration, and releases

- [Contributing and verification](development/contributing.md)
- [Migrating to 1.0](migration/1.0.0.md)
- [1.0 release notes](releases/1.0.0.md)
- Compatibility release paths: [migration-1.0.0.md](migration-1.0.0.md) and
  [release-notes-1.0.0.md](release-notes-1.0.0.md)
- [Changelog](../CHANGELOG.md)
- [Detailed 1.0 release issue](https://github.com/apache/doris-mcp-server/issues/189)

## Documentation rules

- Runtime behavior and generated catalogs take precedence over prose.
- English and Simplified Chinese topic guides must keep the same section
  structure and operational meaning.
- The generated `tool-registry.md` must not be edited by hand.
- Examples must use placeholders rather than deployable credentials.
- A capability must not be documented as available solely because its Doris
  version range matches; runtime probes, provider state, and permissions are
  part of the contract.
