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

# Subscriptions require a real change-event source

- Status: Accepted
- Date: 2026-07-30
- Protocol: MCP 2026-07-28

## Context

MCP 2026-07-28 delivers server change notifications through the long-lived
`subscriptions/listen` request. Registering that request handler also causes
the SDK to advertise `listChanged` for tools, prompts, and resources, plus
resource subscription support.

Doris MCP Server currently has no event source that can uphold those
capabilities:

- tools and prompts are assembled when the process starts and have no runtime
  mutation channel;
- Doris resources are read from catalog metadata on demand;
- the bounded metadata cache has time-based expiry, but expiry is not evidence
  that a catalog object changed;
- Doris DDL can be performed outside this server, so observing only tool calls
  made through this process would miss changes;
- multiple workers and replicas have no shared catalog-event bus.

Polling a full catalog and treating cache expiry as a change event would create
false positives, detection gaps, identity-scoping ambiguity, and inconsistent
behavior across replicas. A handler that never publishes events would be worse:
discovery would promise a capability that cannot work.

## Decision

Doris MCP Server does not register `subscriptions/listen` until it has a
reliable change-event source.

For MCP 2026-07-28:

- discovery reports `listChanged: false` for tools, prompts, and resources;
- discovery reports `subscribe: false` for resources;
- `subscriptions/listen` returns the standard `Method not found` error;
- Streamable HTTP and a true subprocess stdio test enforce this boundary and
  verify that a rejected listen request does not affect later requests.

The older `resources/subscribe` request is not used as a substitute on the
modern protocol.

## Revisit criteria

Subscription support may be added when all of the following exist:

1. a change source that detects Doris catalog changes regardless of whether
   they originated through this server;
2. identity-aware resource filtering that cannot reveal a URI after the
   principal loses access;
3. shared fan-out for every configured worker and replica;
4. bounded buffering, disconnect cleanup, and explicit no-replay behavior;
5. Streamable HTTP, subprocess stdio, multiworker, authorization, and failure
   recovery tests against the real event source.

At that point the SDK subscription bus and listen handler can carry typed
events. Capability flags must be enabled only for event kinds the server can
actually publish.

## Consequences

Clients must refresh lists explicitly. They can rely on discovery rather than
opening a stream that will remain silent. The server avoids background catalog
polling and does not claim unsupported real-time behavior.
