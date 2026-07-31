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

# Capability availability

[English](availability.md) | [简体中文](availability.zh-CN.md)

The public catalog states what Doris MCP Server 1.0 can represent. Runtime
availability states what the current request identity can safely call on the
current Apache Doris route. These are deliberately different concepts.

## Evidence model

Availability combines:

1. **Catalog contract** — the child exists in the reviewed 8/47 catalog.
2. **Normalized version** — the relevant active Doris component satisfies the
   declared `major.minor.patch` range.
3. **Live feature probe** — required SQL metadata, system table, function, or
   allowlisted HTTP endpoint is observable.
4. **Provider readiness** — optional ADBC, Ossie, or lineage provider is
   configured and healthy.
5. **Deployment mode** — required classic/cloud/compute behavior is compatible.
6. **Route coherence** — active component versions and request route can be
   evaluated safely; unknown or mixed evidence may fail closed.
7. **Authorization** — the identity can discover and execute the exact child.
8. **Doris visibility** — Doris allows the request-specific account to observe
   the required metadata/data.

No single predicate, including the version number, overrides the others.

## Version parsing

The detector issues the Doris version probe and accepts real-world comments
such as:

```text
Doris version doris-3.0.3-rc03-43f06a5e26 (Cloud Mode)
```

Capability and certification keys use only:

```text
3.0.3
```

RC/GA labels, commit hashes, and deployment hints remain diagnostic metadata.
They do not create a separate support bucket. Component version vectors are
evaluated conservatively; dead components remain visible in inventory but do
not gate active capability ranges.

## Snapshot lifecycle

A `DorisCapabilitySnapshot` is private to one resolved route and contains:

- route fingerprint;
- capability generation;
- provider generation;
- sanitized cluster fingerprint;
- component version vector;
- deployment mode and mixed-version flag;
- bounded probe results and stable reason codes;
- probed domains;
- creation, expiry, and stale-until timestamps.

The detector caches snapshots for a bounded TTL and uses singleflight so
concurrent discovery does not issue duplicate probe storms. Domain-specific
evidence extends the coherent base generation. If the route changes during
extension, the operation is rejected rather than combining routes.

A stale snapshot is eligible only inside the configured bounded stale window
and only for the detector's documented failure conditions. Stale state changes
the generation fingerprint and remains visible; it is not presented as fresh.

## Manifest rendering

For every authorized child, the manifest returns an `Availability` object with
fields such as:

```json
{
  "status": "available",
  "callable": true,
  "reason_code": "CAPABILITY_AVAILABLE",
  "evidence_sources": [
    "catalog_contract",
    "version_range",
    "runtime_probe"
  ]
}
```

Typical status classes are available, unavailable/unsupported, degraded,
misconfigured, unknown, and pending. The exact wire enum and reason codes are
defined by the runtime models. `callable` is the execution gate.

The description may receive a short dynamic prefix to help a model read the
state, but descriptions are not authoritative. Hosts and applications must use
the structured object.

## Discoverable but not callable

An authorized child stays in the manifest when its runtime predicates fail.
This design lets the Host explain:

- the connected Doris patch is too old;
- a required system table or function is absent;
- a provider is disabled or unhealthy;
- a companion lineage store is incomplete;
- a route has mixed/unknown component versions;
- the Doris identity cannot observe required metadata;
- configuration is missing or invalid.

Removing such children would make the contract appear unstable and would hide
actionable operator information. Unauthorized children, by contrast, are
filtered out and cannot be distinguished from nonexistent names.

## Manifest version

`manifest_version` changes when any relevant public contract, authorization,
capability generation, provider generation, or route evidence changes. A Host
may send the discovered version with a child call. A mismatch returns
`CHILD_MANIFEST_STALE` and requires rediscovery.

This prevents a time-of-check/time-of-use gap in which a model calls a child
under an obsolete provider or capability description.

## Hierarchical and flat modes

Hierarchical mode resolves availability during domain discovery. Flat mode
also obtains each formal child from the current authorized manifest before
returning it in `tools/list`. Both modes therefore share:

- the same 47 children;
- the same exact scopes;
- the same dynamic availability;
- the same schemas and dispatcher;
- the same execution gate.

Flat mode is a Host compatibility fallback, not a capability bypass.

## Certification versus runtime support

Release certification records evidence gathered against named Doris patch
targets. Runtime support is decided for the connected route.

The 1.0 target set is `3.0.3`, `3.1.4`, `4.0.5`, `4.0.6`, `4.0.7`, `4.1.0`,
`4.1.1`, `4.1.2`, and `4.1.3`. At the release boundary, `4.0.5` is the first
fully certified target. A target marked `target_uncertified` is not treated as
automatically broken; its runtime manifests remain authoritative and honest
about observed support.

## Example: lineage selection

For `trace_column_lineage`:

- before Doris 4.0.6, readable audit evidence can make bounded audit inference
  the primary path;
- on Doris 4.0.6+, native mode additionally requires the configured companion
  provider, a readable store, required columns, and healthy evidence;
- if native mode is expected but unavailable and audit is readable, the child
  can remain callable in explicit degraded fallback mode;
- if neither source is usable, it remains discoverable but not callable.

This is the intended pattern for every version- and provider-dependent child:
state the active evidence path, do not infer success from version alone, and
never silently substitute one evidence class for another.

## Operator checklist

When a child is not callable:

1. Call `doris_cluster.get_runtime_capabilities` if authorized.
2. Read the child `reason_code` and evidence sources.
3. Confirm the request identity and exact scope.
4. Confirm the selected Doris route and account privileges.
5. Confirm optional provider configuration and health.
6. Compare the normalized three-part version with the required feature range.
7. Rediscover after changing configuration, route, provider, or permissions.

See [Troubleshooting](../operations/troubleshooting.md) for failure-specific
procedures.
