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

# Doris MCP 细粒度权限控制

[English](doris-fine-grained-access-control.md) | [简体中文](doris-fine-grained-access-control.zh-CN.md)

本文说明如何为 Doris MCP Server 强制执行表、列和行级访问控制。权威执行点
是 Apache Doris，而不是大模型或 MCP Prompt。

示例使用 `orders` 表和东区只读用户。请把所有名称、Host 与 Predicate 替换为
经过部署审查的值，并在生产使用前针对实际 Doris 版本验证 SQL。

## 控制面与数据面边界

Doris MCP Server 有两个独立的授权层：

1. MCP 授权决定 Principal 是否可以发现或调用某个 Tool、Resource 或 Prompt。
2. Doris 授权决定数据库身份可以访问哪些 Catalog、Database、Table、Column
   和 Row。

OAuth Scope `child:call:doris_query:execute_query` 只允许调用一个 MCP Child，
不会在 Doris 中授予 `SELECT_PRIV`，也不能绕过 Doris Row Policy。同样，MCP
安全等级、SQL 校验和响应脱敏只是纵深防御，不能替代 Doris RBAC。

只有当 MCP 请求以预期受限身份到达 Doris 时，细粒度 Doris Policy 才有效：

| MCP 数据库路由 | 使用的 Doris 身份 | 是否适合按 Principal 执行数据策略 |
|:---|:---|:---|
| 全局服务配置 | 一个共享服务用户 | 否；所有调用方继承该用户的 Doris Policy |
| Token 绑定数据库配置 | 与静态 Token 绑定的 Doris 用户 | 是；每套 Policy 使用独立的最小权限绑定 |
| Doris-backed OAuth | 登录的 Doris 用户 | 是；MySQL Channel Tool 使用该用户的独立连接池 |
| 仅把外部 OAuth 映射为 MCP Role/Scope | 通常仍是共享服务用户 | 否；应增加经过审查的 Doris 身份路由，或使用上面两种路由 |

绝不能把 Client 传入的 Tenant、Region 或 User Filter 当作授权边界，因为
Client 可以删除或修改这些过滤条件。Predicate 必须在 Doris 中执行。

## 选择 Doris 权限机制

| 需求 | Doris 机制 | 行为 |
|:---|:---|:---|
| 只允许指定表 | 表级 `SELECT_PRIV` | 访问其他表时授权失败 |
| 只允许指定列 | 列级 `SELECT_PRIV(column, ...)` | 读取其他列时授权失败 |
| 只允许指定行 | Row Policy | Doris 自动追加过滤 Predicate |
| 返回脱敏值而不是拒绝列 | Apache Ranger Data Masking | Doris 返回转换后的值 |

列权限当前只支持 `SELECT_PRIV`。Apache Doris 通过 Apache Ranger 支持列数据
脱敏；MCP 响应脱敏不是权威替代方案，因为其他 Doris Client 可以绕过它。

Doris 默认的 `root` 与 `admin` 用户会绕过本文描述的细粒度机制。验证列权限、
Row Policy 或 Ranger 脱敏时，不得使用这两个用户。

## 端到端示例

假定受保护的表为：

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

受限身份必须是普通业务用户。在部署拓扑允许时，把 Host Pattern 限制为 MCP
运行网络，不要使用 `%`：

```sql
CREATE ROLE mcp_orders_east_reader;

CREATE USER 'mcp_orders_east'@'10.%'
IDENTIFIED BY '<generated-high-entropy-password>';

GRANT 'mcp_orders_east_reader' TO 'mcp_orders_east'@'10.%';
```

### 表级只读权限

如果用户可以读取表的全部列，授予表级读权限：

```sql
GRANT SELECT_PRIV
ON internal.sales.orders
TO ROLE 'mcp_orders_east_reader';
```

需要限制列时不要增加这项授权。Doris 权限是累加的；表级、数据库级、Catalog
级或全局 `SELECT_PRIV` 同样会允许读取敏感列。

### 列级权限

只暴露非敏感字段时，对明确列授予 `SELECT_PRIV`：

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

该 Role 可以查询列出的字段；包含 `customer_name`、`customer_phone` 或
`SELECT *` 的查询必须授权失败。

依赖这项限制前，应检查并撤销直接授予用户或从其他 Role 继承的更宽权限：

```sql
SHOW GRANTS FOR 'mcp_orders_east'@'10.%';
SHOW ROLES;
```

例如，如果之前存在表级授权：

```sql
REVOKE SELECT_PRIV
ON internal.sales.orders
FROM ROLE 'mcp_orders_east_reader';
```

然后只应用明确的列授权。

### 行级权限

为同一个 Role 增加 Restrictive Row Policy：

```sql
CREATE ROW POLICY mcp_orders_east_region
ON sales.orders
AS RESTRICTIVE
TO ROLE 'mcp_orders_east_reader'
USING (region_id = 'east');
```

Doris 会为持有该 Role 的身份追加 Policy Predicate。Predicate 应保持确定性，
必须审查 NULL 行为，并使用稳定标识而不是展示名称。

多个 `RESTRICTIVE` Policy 以 `AND` 组合；多个 `PERMISSIVE` Policy 以 `OR`
组合，然后再组合 Restrictive 与 Permissive 两组。当用户继承多个 Role 时，
必须检查完整的有效 Policy 集合。

查看已配置策略：

```sql
SHOW ROW POLICY;
SHOW ROW POLICY FOR ROLE mcp_orders_east_reader;
```

管理员也可以对代表性查询使用 `EXPLAIN` 检查重写后的 Plan，但决定性验证仍然
是以受限业务用户实际执行查询。

## 让 MCP 请求使用受限用户

### Token 绑定数据库配置

创建或管理一个静态 Token，使其 `database_config` 使用受限 Doris 用户：

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

Token 绑定数据库配置会验证该路由并使用独立连接池，绝不能回退到全局 Doris
账号。`tokens.json` 中只保存 Token Digest，文件权限保持 `0600`，Doris 密码
必须作为 Secret 保护。

`hosts` 和 `fe_http_hosts` 中的全部节点必须属于同一个 Doris 集群。不同集群
应使用不同静态 Token 绑定；Bearer Token 负责选择路由，Tool 调用不能覆盖它。

不要把细粒度 Token 绑定到 `root`、`admin` 或具有全局/表级权限的服务账号。

### Doris-backed OAuth

启用 `ENABLE_DORIS_OAUTH_AUTH=true` 后，用户使用 Doris 凭据登录，签发的
`doa_` Token 与该用户的独立 Doris 连接池绑定。只启用经过审查的正式 Child：

```bash
ENABLE_DORIS_OAUTH_AUTH=true
WORKERS=1

DORIS_OAUTH_CHILD_TOOLS_ENABLED=true
DORIS_OAUTH_CHILD_TOOL_ALLOWLIST=doris_catalog.list_databases,doris_query.execute_query,doris_query.explain_query
```

此时只有精确允许的 Child 和精确 Child Scope 能以登录用户身份到达 Doris。
不接受旧 Flat Name 或 `tool:call:<legacy-name>` Scope。若用户连接池缺失，
Doris-backed OAuth 必须 Fail Closed，绝不能回退到全局服务账号。

配置多个 FE Candidate 时，登录会按顺序尝试。已经建立的用户连接池如果随后
失效，用户必须重新登录：Server 不保留重建连接池所需的 Doris 明文密码。

当前 Doris-backed OAuth 是单进程实现，要求 `WORKERS=1`。完整操作限制见主
README。

### 外部 OAuth

外部 OAuth Role 与 Scope 只管理 MCP 操作，不会自动把外部 Subject 映射为
Doris 用户。如果外部 OAuth 请求仍使用一个全局 Doris 账号，所有用户会共享
该账号的列与行 Policy。

在声称外部 OAuth 具备用户级 Doris 隔离前，应采用 Token 绑定 Doris 凭据、
Doris-backed OAuth，或单独设计并审查身份 Broker。

## 验证清单

以下测试必须以 `mcp_orders_east` 执行，不能使用 `root` 或 `admin`。

确认有效身份与授权：

```sql
SELECT CURRENT_USER();
SHOW GRANTS;
```

确认允许的列与行：

```sql
SELECT order_id, tenant_id, region_id, order_total, created_at
FROM sales.orders
ORDER BY order_id
LIMIT 20;

SELECT COUNT(*) AS forbidden_region_rows
FROM sales.orders
WHERE region_id <> 'east';
```

预期结果：

- 第一条查询成功；
- 返回的每一行都满足 `region_id = 'east'`；
- `forbidden_region_rows` 为零。

确认敏感列被拒绝：

```sql
SELECT customer_phone
FROM sales.orders
LIMIT 1;

SELECT *
FROM sales.orders
LIMIT 1;
```

两条查询都必须授权失败。

然后通过 MCP 路由重复验证：

1. 使用 Token 绑定或 Doris OAuth 用户认证。
2. 调用 `doris_query.execute_query` 执行允许列查询。
3. 调用 `doris_query.execute_query` 查询 `customer_phone`，确认返回有界权限错误，
   且不包含后端凭据或异常文本。
4. 查询其他 Region，确认不返回任何行。
5. 执行 Catalog Child，确认不会泄露超出该 Doris 版本对该用户所暴露范围的
   不可访问对象或列。
6. 对部署使用的每一种受支持传输重复验证。

即使 MCP 调用方使用不同 Role 或 Token，以全局服务账号执行的 MCP 测试也不能
证明细粒度隔离。

## 安全变更与回滚

授权变更应经过审查，在 Secret Store 之外进行版本管理，先以非生产用户测试，
再签发与之匹配的 MCP 凭据。

删除本示例：

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

删除 Doris 用户前，应先撤销或禁用对应 MCP Token。Token 配置热更新后，应持续
观察，直到所有 Worker 都不再接受旧绑定。

## 常见错误

- 使用会绕过细粒度控制的 `root` 或 `admin` 进行测试。
- 授予列权限的同时保留更宽的表级/数据库级 `SELECT_PRIV`。
- 只在生成 SQL 或 Prompt 中按 Tenant 过滤。
- 映射 OAuth Scope 后仍用一个全局账号查询 Doris。
- 把 MCP 响应脱敏等同于 Doris/Ranger 权威执行。
- 记录 `tokens.json`、Doris 密码、Bearer Token 或失败 SQL 值。
- 假设使用服务账号的 FE HTTP Tool 会继承某个用户的 Row Policy。只有通过
  预期 Doris 身份路由的操作才继承其数据授权。
- 未通过真实 MCP 传输验证允许与拒绝两类情况就部署上线。

## Apache Doris 参考资料

- [内置授权](https://doris.apache.org/docs/4.x/admin-manual/auth/authorization/internal/)
- [数据访问控制](https://doris.apache.org/docs/4.x/admin-manual/auth/authorization/data/)
- [GRANT](https://doris.apache.org/docs/4.x/sql-manual/sql-statements/account-management/GRANT-TO/)
- [REVOKE](https://doris.apache.org/docs/4.x/sql-manual/sql-statements/account-management/REVOKE-FROM/)
- [CREATE ROW POLICY](https://doris.apache.org/docs/4.x/sql-manual/sql-statements/data-governance/CREATE-ROW-POLICY/)
- [SHOW ROW POLICY](https://doris.apache.org/docs/4.x/sql-manual/sql-statements/data-governance/SHOW-ROW-POLICY/)
- [Apache Ranger 授权](https://doris.apache.org/docs/4.x/admin-manual/auth/authorization/ranger/)
