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

# Doris fine-grained access control for MCP

[English](doris-fine-grained-access-control.md) | [简体中文](doris-fine-grained-access-control.zh-CN.md)

This guide explains how to enforce table, column, and row access for Doris MCP
Server. The enforcement point is Apache Doris, not the language model or an MCP
prompt.

The examples use an `orders` table and an east-region reader. Replace all
names, hosts, and predicates with values reviewed for your deployment. Test
the statements against the exact Doris version you run before production use.

## Control-plane and data-plane boundaries

Doris MCP Server has two distinct authorization layers:

1. MCP authorization decides whether a principal may list or call a tool,
   resource, or prompt.
2. Doris authorization decides which catalogs, databases, tables, columns, and
   rows the database identity may access.

An OAuth scope such as `child:call:doris_query:execute_query` permits one MCP
child operation. It does not grant `SELECT_PRIV` in Doris and does not override
a Doris row policy.
Likewise, MCP security levels, SQL validation, and response masking are
defense-in-depth controls rather than replacements for Doris RBAC.

Fine-grained Doris policy works only when the MCP request reaches Doris as the
intended restricted identity:

| MCP database route | Doris identity used | Suitable for per-principal data policy |
|:-------------------|:--------------------|:---------------------------------------|
| Global service configuration | One shared service user | No; every caller receives that user's Doris policy |
| Token-bound database configuration | Doris user bound to that static token | Yes; create a separate least-privilege binding per policy set |
| Doris-backed OAuth | Doris user who signed in | Yes; MySQL-channel tools use that user's dedicated pool |
| External OAuth with only MCP role/scope mapping | Usually the shared service user | No; add a reviewed Doris identity-routing design or use another route above |

Never rely on a client-supplied tenant, region, or user filter as the
authorization boundary. The client can omit or change it. Enforce the
predicate in Doris.

## Choose the Doris mechanism

| Requirement | Doris mechanism | Behavior |
|:------------|:----------------|:---------|
| Allow only selected tables | Table-level `SELECT_PRIV` | Other tables fail authorization |
| Allow only selected columns | Column-level `SELECT_PRIV(column, ...)` | Reading another column fails authorization |
| Allow only selected rows | Row Policy | Doris automatically adds a filter predicate |
| Return masked values instead of denying a column | Apache Ranger Data Masking | Doris returns a transformed value |

Column permissions currently support only `SELECT_PRIV`. Apache Doris supports
column data masking through Apache Ranger; MCP response masking is not an
authoritative substitute because other Doris clients would bypass it.

The default Doris `root` and `admin` users bypass the fine-grained mechanisms
described here. Do not use them to verify column permissions, Row Policies, or
Ranger masking.

## End-to-end example

Assume the protected table is:

```sql
CREATE DATABASE IF NOT EXISTS sales;

CREATE TABLE IF NOT EXISTS sales.orders (
    order_id BIGINT,
    tenant_id VARCHAR(64),
    region_id VARCHAR(32),
    customer_name VARCHAR(128),
    customer_phone VARCHAR(32),
    order_total DECIMAL(18, 2),
    created_at DATETIME
)
DUPLICATE KEY(order_id)
DISTRIBUTED BY HASH(order_id) BUCKETS 1
PROPERTIES ("replication_num" = "1");
```

The restricted identity must be a normal business user. Limit its host pattern
to the MCP runtime network rather than using `%` when the deployment topology
allows it:

```sql
CREATE ROLE mcp_orders_east_reader;

CREATE USER 'mcp_orders_east'@'10.%'
IDENTIFIED BY '<generated-high-entropy-password>';

GRANT 'mcp_orders_east_reader' TO 'mcp_orders_east'@'10.%';
```

### Table-level read access

If the user may read every column in the table, grant table-level read access:

```sql
GRANT SELECT_PRIV
ON internal.sales.orders
TO ROLE 'mcp_orders_east_reader';
```

Do not add this grant when the goal is column restriction. Doris privileges are
additive; a table-, database-, catalog-, or global-level `SELECT_PRIV` would
also allow the sensitive columns.

### Column-level access

To expose only non-sensitive fields, grant `SELECT_PRIV` on the explicit
columns:

```sql
GRANT SELECT_PRIV(
    order_id,
    tenant_id,
    region_id,
    order_total,
    created_at
)
ON internal.sales.orders
TO ROLE 'mcp_orders_east_reader';
```

The role can select the listed columns. A query that includes
`customer_name`, `customer_phone`, or `SELECT *` must fail authorization.

Before depending on this restriction, inspect and revoke any broader grants
held directly by the user or inherited from another role:

```sql
SHOW GRANTS FOR 'mcp_orders_east'@'10.%';
SHOW ROLES;
```

For example, if an earlier table-level grant exists:

```sql
REVOKE SELECT_PRIV
ON internal.sales.orders
FROM ROLE 'mcp_orders_east_reader';
```

Then apply only the explicit column grant.

### Row-level access

Add a restrictive Row Policy for the same role:

```sql
CREATE ROW POLICY mcp_orders_east_region
ON sales.orders
AS RESTRICTIVE
TO ROLE 'mcp_orders_east_reader'
USING (region_id = 'east');
```

Doris appends the policy predicate to queries made by identities holding that
role. Keep the predicate deterministic, review its null behavior, and use
stable identifiers rather than display labels.

Multiple `RESTRICTIVE` policies are combined with `AND`. Multiple `PERMISSIVE`
policies are combined with `OR`, and the restrictive and permissive groups are
then combined. Review the full effective policy set whenever a user inherits
multiple roles.

Inspect the configured policies:

```sql
SHOW ROW POLICY;
SHOW ROW POLICY FOR ROLE mcp_orders_east_reader;
```

An administrator can also use `EXPLAIN` on a representative query to inspect
the rewritten plan. The decisive test is still a query made as the restricted
business user.

## Route MCP requests through the restricted user

### Token-bound database configuration

Create or manage a static token whose `database_config` uses the restricted
Doris user:

```json
{
  "database_config": {
    "host": "doris-fe-1.internal.example",
    "hosts": [
      "doris-fe-1.internal.example",
      "doris-fe-2.internal.example"
    ],
    "port": 9030,
    "user": "mcp_orders_east",
    "password": "<secret-store-value>",
    "database": "sales",
    "charset": "UTF8",
    "fe_http_hosts": [
      "doris-fe-1.internal.example",
      "doris-fe-2.internal.example"
    ],
    "fe_http_port": 8030
  }
}
```

Token-bound database configuration validates and uses a dedicated connection
pool for this route. It must not fall back to the global Doris account. Store
only a token digest in `tokens.json`, keep the file at mode `0600`, and protect
the Doris password as a secret.

All entries in `hosts` and `fe_http_hosts` must be FE nodes of the same Doris
cluster. Use separate static-token bindings for separate clusters; the bearer
token selects the route and a tool call cannot override it.

Do not bind a fine-grained token to `root`, `admin`, or a service account that
has global/table-level privileges.

### Doris-backed OAuth

With `ENABLE_DORIS_OAUTH_AUTH=true`, the user signs in with Doris credentials.
The issued `doa_` token is associated with that user's dedicated Doris pool.
Enable only reviewed formal child capabilities:

```bash
ENABLE_DORIS_OAUTH_AUTH=true
WORKERS=1

DORIS_OAUTH_CHILD_TOOLS_ENABLED=true
DORIS_OAUTH_CHILD_TOOL_ALLOWLIST=doris_catalog.list_databases,doris_query.execute_query,doris_query.explain_query
```

Only exact allowlisted children with exact child scopes then reach Doris as the
signed-in user. Legacy flat names and `tool:call:<legacy-name>` scopes are not
accepted. Doris-backed OAuth must fail closed if its per-user pool is missing;
it must never use the global service account as a fallback.
When multiple FE candidates are configured, sign-in tries them in order.
If an established per-user pool later fails, the user must sign in again:
the server intentionally does not retain the raw Doris password needed to
reconstruct that pool.

The current Doris-backed OAuth implementation is single-process and requires
`WORKERS=1`. See the main README for its complete operational limits.

### External OAuth

External OAuth roles and scopes regulate MCP operations. They do not
automatically map the external subject to a Doris user. If external OAuth
requests still use one global Doris account, all users share that account's
column and row policy.

Use token-bound Doris credentials, Doris-backed OAuth, or a separately reviewed
identity broker before claiming per-user Doris isolation with external OAuth.

## Verification checklist

Run the following tests as `mcp_orders_east`, not as `root` or `admin`.

Confirm the effective identity and grants:

```sql
SELECT CURRENT_USER();
SHOW GRANTS;
```

Confirm allowed columns and rows:

```sql
SELECT order_id, tenant_id, region_id, order_total, created_at
FROM sales.orders
ORDER BY order_id
LIMIT 20;

SELECT COUNT(*) AS forbidden_region_rows
FROM sales.orders
WHERE region_id <> 'east';
```

Expected:

- the first query succeeds;
- every returned row has `region_id = 'east'`;
- `forbidden_region_rows` is zero.

Confirm sensitive columns are denied:

```sql
SELECT customer_phone
FROM sales.orders
LIMIT 1;

SELECT *
FROM sales.orders
LIMIT 1;
```

Both queries must fail authorization.

Then repeat the checks through the MCP route:

1. Authenticate using the token binding or Doris OAuth user.
2. Call `doris_query.execute_query` with the allowed-column query.
3. Call `doris_query.execute_query` for `customer_phone` and confirm a bounded
   permission error, without backend credentials or exception text.
4. Query for another region and confirm no rows are returned.
5. Run catalog children and confirm they do not reveal inaccessible objects or
   columns beyond what the Doris version exposes to that user.
6. Repeat over every supported transport used by the deployment.

An MCP test that uses the global service account does not prove fine-grained
isolation, even if the MCP caller has a different role or token.

## Safe policy changes and rollback

Authorization changes should be reviewed, versioned outside the secret store,
tested with a non-production user, and applied before issuing the matching MCP
credential.

To remove the example:

```sql
DROP ROW POLICY mcp_orders_east_region
ON sales.orders
FOR ROLE mcp_orders_east_reader;

REVOKE SELECT_PRIV(
    order_id,
    tenant_id,
    region_id,
    order_total,
    created_at
)
ON internal.sales.orders
FROM ROLE 'mcp_orders_east_reader';

REVOKE 'mcp_orders_east_reader'
FROM 'mcp_orders_east'@'10.%';

DROP USER 'mcp_orders_east'@'10.%';
DROP ROLE mcp_orders_east_reader;
```

Revoke or disable the associated MCP token before dropping the Doris user.
Hot-reloaded token configuration should be observed until all workers have
stopped accepting the old binding.

## Common mistakes

- Testing with `root` or `admin`, which bypass fine-grained controls.
- Granting column privileges and also retaining a broader table/database
  `SELECT_PRIV`.
- Filtering by tenant only in generated SQL or a prompt.
- Mapping OAuth scopes but still querying Doris with one global account.
- Treating MCP response masking as equivalent to Doris/Ranger enforcement.
- Logging `tokens.json`, Doris passwords, bearer tokens, or failed SQL values.
- Assuming a Row Policy applies to FE HTTP tools that use a service account.
  Only operations routed through the intended Doris identity inherit its data
  authorization.
- Deploying before testing both allowed and denied cases through the real MCP
  transport.

## Apache Doris references

- [Built-in authorization](https://doris.apache.org/docs/4.x/admin-manual/auth/authorization/internal/)
- [Data access control](https://doris.apache.org/docs/4.x/admin-manual/auth/authorization/data/)
- [GRANT](https://doris.apache.org/docs/4.x/sql-manual/sql-statements/account-management/GRANT-TO/)
- [REVOKE](https://doris.apache.org/docs/4.x/sql-manual/sql-statements/account-management/REVOKE-FROM/)
- [CREATE ROW POLICY](https://doris.apache.org/docs/4.x/sql-manual/sql-statements/data-governance/CREATE-ROW-POLICY/)
- [SHOW ROW POLICY](https://doris.apache.org/docs/4.x/sql-manual/sql-statements/data-governance/SHOW-ROW-POLICY/)
- [Apache Ranger authorization](https://doris.apache.org/docs/4.x/admin-manual/auth/authorization/ranger/)
