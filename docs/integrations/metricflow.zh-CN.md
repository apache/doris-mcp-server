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

# MetricFlow 接入

[English](metricflow.md) | 简体中文

`doris_semantic` 可以通过可选、由管理员配置的 Sidecar 消费 MetricFlow Model。
MetricFlow 继续拥有指标语义与查询编译；Doris MCP Server 负责 MCP 发现、授权、
路由选择、Doris RBAC、只读 SQL 校验、查询限额、执行、审计元数据、脱敏和结果
Schema。

项目不内置 Doris 原生 MetricFlow/dbt Adapter。操作人员必须提供经过审查、能加载
指定 MetricFlow Project 并编译合法 Doris SQL 的 Provider。因此这里提供的是稳定
Consumer 边界，不代表原版 MetricFlow 无需 Adapter 或 Dialect 实现就能连接 Doris。

## 公开 Child

| Child | Provider Operation | 执行行为 |
|---|---|---|
| `list_metricflow_models` | `list_models` | 只读元数据，不猜 `model_ref`。 |
| `get_metricflow_status` | `get_status` | 校验一个精确 `model_ref`。 |
| `list_metricflow_metrics` | `list_metrics` | 有界 Metric/Dimension 元数据。 |
| `get_metricflow_group_bys` | `get_group_bys` | 返回所选 Metric 的合法 Group-by 选项。 |
| `list_metricflow_saved_queries` | `list_saved_queries` | 只读元数据，不执行 Saved Query。 |
| `get_metricflow_dimension_values` | `compile_dimension_values` | Provider 编译，MCP Query Runtime 执行有界只读 SQL。 |
| `compile_metricflow_query` | `compile_query` | 只编译，返回 Provider 证据与 Doris SQL。 |
| `execute_metricflow_query` | `compile_query` | Provider 编译，MCP Query Runtime 校验并执行。 |

每个 Model 相关调用都要求精确 `model_ref`。Server 不会从自然语言里排序、推断或
选择模型。

## 编译与执行边界

```text
MCP Host
  -> doris_semantic Child + 精确 model_ref
  -> 授权与动态 Availability
  -> MetricFlow Sidecar：只做模型读取或 Doris SQL 编译
  -> MCP ReadOnlySQLGuard
  -> 请求级 DorisQueryRuntime
  -> Doris Route、RBAC、超时/行数/字节限额、审计与脱敏
  -> 通过 Schema 校验的 MCP Result
```

协议不会向 Sidecar 传 Doris 凭据；Compile Operation 也不允许返回已执行结果。
`execute_metricflow_query` 和 `get_metricflow_dimension_values` 只接受编译 SQL，
并把它送入与 `doris_query.execute_query` 相同的有界运行时。

## Sidecar 协议

Server 不经过 Shell 启动配置的可执行文件，在 stdin 写一个 JSON Object，从 stdout
读取一个有界 JSON Object，并等待进程退出。协议版本是
`doris-mcp-metricflow/v1`。

请求：

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

成功响应：

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

失败响应：

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

Server 会校验 Operation Allowlist、Request Correlation、协议版本、进程状态、超时、
UTF-8/JSON 结构、响应类型和输出上限。Provider stderr 与原始内部错误不会返回模型。

Collection Operation 返回 `data.items` Array，可设置 `data.truncated=true`。
Compile Operation 必须返回非空 `data.sql`，SQL 通过 MCP Read-only Guard 后才可执行。

## 配置

```bash
export METRICFLOW_ENABLED=true
export METRICFLOW_PROVIDER_COMMAND_JSON='["/opt/doris-mcp/bin/metricflow-provider"]'
export METRICFLOW_PROJECT_DIRECTORY=/srv/dbt
export METRICFLOW_TIMEOUT_SECONDS=30
export METRICFLOW_MAX_OUTPUT_BYTES=2097152
```

Executable 和可选 Project Directory 必须使用绝对路径。Command 使用 JSON Array
保存参数边界并避免 Shell 解释。配置校验会拒绝：启用后缺少 Command、相对
Executable、空 Command Array、越界值和非法 JSON。

## Availability 与授权

8 个 MetricFlow Child 始终属于稳定 Catalog。Provider 关闭或不健康时，授权身份
仍能发现它们，但会得到 `callable=false` 和稳定 Reason Code。Model 相关 Probe 在
调用时校验，因为空参数的 Domain Discovery 无法提前校验未来未知的 `model_ref`。

OAuth 部署必须显式启用 Semantic Tool，并授予 `semantic:read` 以及精确发现/执行
Scope。编译 SQL 到达请求路由后，Doris RBAC 仍是最终权限边界。

## Provider 验收清单

- 只加载操作人员批准的 MetricFlow Project 与精确 Model Reference。
- 实现所有声明 Operation，或返回稳定 Failure Code。
- 使用 `dialect=doris` 编译，不静默输出其他 Dialect SQL。
- Sidecar 协议不执行 Doris SQL，也不接收 Doris 凭据。
- 对 Model、Metric、Saved Query、Group-by 与 SQL 大小全部设限。
- 同一 Model Revision 与请求产生确定性结果。
- 上生产前用真实 Doris 通过只读与负向写入测试。

MetricFlow Command 语义见 [dbt Labs 文档](https://docs.getdbt.com/docs/build/metricflow-commands)，
引擎源码见 [MetricFlow Repository](https://github.com/dbt-labs/metricflow)。
