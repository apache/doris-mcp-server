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

# ADR 0002: Cross-call state uses explicit principal-bound handles

## Status

Accepted.

## Context

MCP `2026-07-28` has no protocol session or `Mcp-Session-Id`. A server cannot
attach continuation state to a transport connection or assume that a later
request reaches the same worker.

The current Doris MCP Server needs cross-call state only for list pagination.
The previous cursor encoded its list position, visible snapshot, and
authorization fingerprint as unsigned Base64URL JSON. It was permission-bound,
but it had no expiry and a client could alter its fields.

## Decision

Cross-call state is carried by an explicit ordinary request/response value:

- the server returns a state handle, currently as `nextCursor`;
- the client passes that handle back as an ordinary `cursor` parameter;
- the handle is HMAC authenticated and binds its kind, scope, resource,
  authorization fingerprint, expiry, and bounded JSON state;
- the authorization fingerprint excludes protocol session identifiers, client
  address, raw bearer values, and request timing;
- the default lifetime is 300 seconds and the hard maximum is 3600 seconds;
- expired, modified, cross-principal, cross-scope, and cross-resource handles
  fail as `Invalid Params`;
- the handle secret is generated per server launch unless
  `MCP_STATE_HANDLE_SECRET` supplies at least 32 bytes;
- the CLI parent passes one resolved secret to every local Uvicorn worker.
  Independently launched replicas must be configured with the same secret if a
  load balancer may route successive calls to different replicas.

Handle payloads are signed, not encrypted. Only bounded continuation metadata
may be placed in them. Secrets, SQL text, query results, and credentials must
not be stored in a handle.

## Consequences

List pagination works across modern Streamable HTTP, legacy migration traffic,
stdio, and local workers without sticky protocol sessions. A server restart or
secret rotation invalidates outstanding handles, so clients restart the list
from its first page. Future cross-call workflows must reuse this boundary or
introduce a shared transactional state backend; they must not use worker-local
memory or revive protocol sessions.
