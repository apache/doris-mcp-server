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

# MetricFlow integration

[English](metricflow.md) | [简体中文](metricflow.zh-CN.md)

The `doris_semantic` domain can consume MetricFlow models through an optional,
administrator-configured sidecar. MetricFlow remains the owner of metric
semantics and query compilation. Doris MCP Server owns MCP discovery,
authorization, route selection, Doris RBAC, read-only SQL validation, query
limits, execution, audit metadata, redaction, and result schemas.

The project does not bundle a native Doris MetricFlow/dbt adapter. An operator
must supply a reviewed provider that can load the selected MetricFlow project
and compile requests to valid Doris SQL. The MCP integration is therefore a
stable consumer boundary, not a claim that stock MetricFlow can connect to
Doris without an adapter or dialect implementation.

## Public children

| Child | Provider operation | Execution behavior |
|---|---|---|
| `list_metricflow_models` | `list_models` | Metadata only; no `model_ref` is guessed. |
| `get_metricflow_status` | `get_status` | Validates one exact `model_ref`. |
| `list_metricflow_metrics` | `list_metrics` | Bounded metric/dimension metadata. |
| `get_metricflow_group_bys` | `get_group_bys` | Returns valid group-by choices for selected metrics. |
| `list_metricflow_saved_queries` | `list_saved_queries` | Metadata only; does not execute saved queries. |
| `get_metricflow_dimension_values` | `compile_dimension_values` | Provider compiles; MCP Query runtime executes bounded read-only SQL. |
| `compile_metricflow_query` | `compile_query` | Compile-only; returns provider evidence and Doris SQL. |
| `execute_metricflow_query` | `compile_query` | Provider compiles; MCP Query runtime validates and executes. |

Every model-specific call requires an exact `model_ref`. The Server does not
rank, infer, or select a model from natural-language text.

## Compile and execution boundary

```text
MCP Host
  -> doris_semantic child + exact model_ref
  -> authorization and dynamic availability
  -> MetricFlow sidecar: model inspection or Doris SQL compilation only
  -> MCP ReadOnlySQLGuard
  -> request-specific DorisQueryRuntime
  -> Doris route, RBAC, timeout/row/byte limits, audit and redaction
  -> schema-validated MCP result
```

The sidecar never receives Doris credentials from this protocol and is not
allowed to return an already executed query result for compile operations.
`execute_metricflow_query` and `get_metricflow_dimension_values` accept only
compiled SQL and send it through the same bounded runtime as
`doris_query.execute_query`.

## Sidecar protocol

The Server starts the configured executable without a shell, sends one JSON
object on stdin, reads one bounded JSON object from stdout, and then waits for
the process to exit. The Server supplies only a fixed locale and unbuffered-I/O
environment, so Doris credentials, bearer tokens, OAuth/JWT secrets, and
unrelated server configuration are not inherited. The protocol version is
`doris-mcp-metricflow/v1`.

Request:

```json
{
  "protocol_version": "doris-mcp-metricflow/v1",
  "request_id": "server-generated-uuid",
  "operation": "compile_query",
  "arguments": {
    "model_ref": "commerce/main",
    "dialect": "doris",
    "request": {
      "metrics": ["orders"],
      "group_by": ["customer__country"]
    }
  }
}
```

Success response:

```json
{
  "protocol_version": "doris-mcp-metricflow/v1",
  "request_id": "same-server-generated-uuid",
  "ok": true,
  "data": {
    "sql": "SELECT ..."
  }
}
```

Failure response:

```json
{
  "protocol_version": "doris-mcp-metricflow/v1",
  "request_id": "same-server-generated-uuid",
  "ok": false,
  "error": {
    "reason_code": "METRICFLOW_MODEL_NOT_FOUND"
  }
}
```

The Server verifies operation allowlisting, request correlation, protocol
version, process status, timeout, UTF-8/JSON structure, response type, and
output limits. Provider stderr and raw internal errors are not returned to the
model.

Collection operations return `data.items` as an array and may set
`data.truncated=true`. Compile operations must return a non-empty `data.sql`.
The SQL must pass the MCP read-only guard before it can execute.

## Configuration

```bash
export METRICFLOW_ENABLED=true
export METRICFLOW_PROVIDER_COMMAND_JSON='["/opt/doris-mcp/bin/metricflow-provider"]'
export METRICFLOW_PROJECT_DIRECTORY=/srv/dbt
export METRICFLOW_TIMEOUT_SECONDS=30
export METRICFLOW_MAX_OUTPUT_BYTES=2097152
```

The executable and optional project directory must use absolute paths. The
command is stored as a JSON array to preserve argument boundaries and avoid
shell interpretation. Configuration validation rejects an enabled provider
without a command, relative executables, empty command arrays, invalid bounds,
and malformed JSON.

## Availability and authorization

The eight MetricFlow children stay in the stable catalog. When the provider is
disabled or unhealthy they remain discoverable to an authorized identity with
`callable=false` and a stable reason code. Model-dependent probes are evaluated
at call time because an empty domain discovery request cannot validate an
unknown future `model_ref`.

OAuth deployments must explicitly enable semantic tools and grant
`semantic:read` plus the exact discovery/execution scope. Doris RBAC remains
the final authority once compiled SQL reaches the request-specific route.

## Provider acceptance checklist

- Load only operator-approved MetricFlow projects and exact model references.
- Implement every advertised operation or report a stable failure code.
- Compile with `dialect=doris`; never silently emit SQL for another dialect.
- Never execute Doris SQL or accept Doris credentials in the sidecar protocol.
- Bound model enumeration, metric lists, saved queries, group-bys, and SQL size.
- Produce deterministic output for the same model revision and request.
- Validate against real Doris with read-only and negative-write tests before
  enabling the provider in production.

MetricFlow command semantics are documented by
[dbt Labs](https://docs.getdbt.com/docs/build/metricflow-commands); the engine
source is available in the [MetricFlow repository](https://github.com/dbt-labs/metricflow).
