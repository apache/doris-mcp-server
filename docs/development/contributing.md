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

# Contributing and verification

[English](contributing.md) | [简体中文](contributing.zh-CN.md)

Apache Doris MCP Server treats the runtime catalog, schemas, safety policy,
generated documentation, tests, and release artifacts as one public contract.
A change is complete only when these sources remain aligned.

## Development setup

```bash
git clone https://github.com/apache/doris-mcp-server.git
cd doris-mcp-server
uv sync --frozen --group dev
```

Common commands:

```bash
uv run pytest -q -W error
uv run ruff check .
uv run mypy doris_mcp_server
uv run bandit -q -c pyproject.toml -r doris_mcp_server doris_mcp_client
uv lock --check
uv build
```

Run a focused test first, then the full release gate. Do not use a successful
unit test as proof that the Host/transport/Doris boundary works.

## Sources of truth

| Contract | Source |
|---|---|
| product version | `doris_mcp_server/_version.py` |
| domain and child definitions | `doris_mcp_server/tools/domain_catalog.py` |
| formal feature matrix | Doris feature/version registry modules |
| discovery/availability | `domain_manifest.py`, `capability_detector.py` |
| exact execution | `domain_dispatcher.py`, domain runtimes |
| operation authorization | `auth/operation_policy.py` and catalog policies |
| configuration | `utils/config.py`, `.env.example` |
| generated public catalog | `docs/tool-registry.md` |
| release history | `CHANGELOG.md`, release/migration docs |

Do not hand-edit `docs/tool-registry.md`. Regenerate it from the runtime
catalog:

```bash
uv run python generate_tool_catalog.py
uv run python generate_tool_catalog.py --check
```

## Changing a built-in child

Before adding or changing a child:

1. Confirm the operation belongs in an existing domain. A new top-level domain
   changes the stable Host contract and requires architecture review.
2. Keep the built-in operation read-only.
3. Define one exact feature ID, child name, title, canonical description,
   input/output Schema, annotations, authorization policy, version range,
   variants, and probes/providers.
4. Add one exact handler binding. Do not use fuzzy routing or aliases.
5. Validate identifiers, caller values, time, rows, bytes, collections, and
   error output at the runtime boundary.
6. Add availability evidence and stable reason codes. Version alone is
   insufficient.
7. Test authorized discovery, hidden discovery, exact execution, unavailable
   execution, stale manifest, invalid arguments, successful output Schema, and
   negative Doris permissions.
8. Regenerate the catalog and update English/Chinese documentation.
9. Update `CHANGELOG.md` in the same pull request.

The current release contract is eight domains and fifty-five children. A
change to those counts is intentional API work, not an incidental handler edit.

## Custom providers

Use a custom provider when the capability belongs to an external business API
or deployment-specific extension rather than the built-in Doris contract.
Providers must:

- register an installed `doris_mcp_server.tool_providers` entry point;
- be explicitly enabled through `MCP_TOOL_PROVIDERS`;
- use unique bounded tool names/schemas;
- implement start/stop lifecycle safely;
- declare safe audit metadata and optional `ToolRateLimit`;
- fail closed on invalid configuration;
- add their own authentication/authorization review.

See [Custom tool providers](../custom-tool-providers.md).

## Documentation changes

- Keep root `README.md` and `README.zh-CN.md` concise and structurally aligned.
- Put detailed content in the matching `docs/<area>/` topic.
- Maintain English and `.zh-CN.md` pairs with equivalent headings/meaning.
- Keep compatibility paths required by release packaging/tests.
- Use relative repository links and run the internal-link validator.
- Do not copy the complete child registry into multiple manually maintained
  documents; link the generated registry for exact bindings/policies.
- Examples must contain placeholders, never real credentials or private
  customer data.

## Test layers

### Focused unit and contract tests

- `test/tools/` — domain catalog, manifests, dispatcher, capabilities, runtimes.
- `test/protocol/` — MCP transport, pagination, state, schemas, trace, errors.
- `test/security/` and `test/auth/` — authentication, authorization, secrets,
  SQL and data safety.
- `test/deployment/` — dependencies, CI contract, packaging and coverage gates.

### Full warnings-as-errors suite

```bash
uv run pytest -q -W error
```

Coverage floors include protocol, authentication, and core manager domains in
addition to the repository-wide floor.

### Real Doris suite

The real Doris tests are opt-in and must use an explicitly authorized test
cluster/account. They exercise actual process transports and must perform zero
management writes. Validate:

- Streamable HTTP and true subprocess stdio;
- hierarchical discovery and exact child execution;
- flat formal names when relevant;
- read-only query, metadata, FE/BE monitoring paths;
- row/byte/timeout ceilings and cancellation recovery;
- Doris permission denial and secret-safe errors.

Never point destructive or unreviewed tests at a shared cluster.

### MCP conformance

CI checks out the pinned official MCP Conformance project, builds it, and runs
the `server-stateless` scenario against the repository fixture. A local run
must use the same pinned revision as CI; an arbitrary latest checkout is not
release evidence.

### Build and clean-wheel smoke

```bash
uv build
```

Install the built wheel in a clean Python 3.12 environment, confirm runtime
imports/CLI identity, and verify that development-only dependencies are absent
from the runtime boundary.

## Pull request gate

CI must pass:

1. **Quality:** lock, generated catalog, Ruff, Mypy, Bandit.
2. **Tests:** full warnings-as-errors suite and coverage domains.
3. **Build and wheel smoke:** sdist/wheel plus clean installation.
4. **MCP 2026-07-28 conformance:** official stateless scenario.

For changes that affect Doris execution, add real-cluster evidence in the PR
without exposing credentials or private endpoints.

## Commit and pull request hygiene

- Keep one coherent change per branch.
- Rebase or merge the latest target branch before asking for final review.
- Inspect `git status`, staged diff, and author email before commit.
- Use English commit subjects and pull request descriptions.
- Do not commit local ledgers, audit reports, credentials, `.env`, test data,
  or generated runtime logs.
- Update `CHANGELOG.md` for every user-visible or release-engineering change.
- Link the relevant issue and list exact verification commands/results.
- Resolve conflicts rather than creating a second competing implementation.

## Release checklist

- Product version, CLI identity, package metadata, release docs, and Changelog
  agree.
- Generated 8/55 registry matches runtime exactly.
- English/Chinese documentation links are valid.
- Target Doris patch certification claims match collected evidence.
- Known limitations remain explicit.
- Full CI, official conformance, clean wheel, and required real Doris gates pass.
- Release tag and GitHub release/issue point to the final documentation.

See [1.0 release notes](../releases/1.0.0.md) and
[1.0 migration](../migration/1.0.0.md).
