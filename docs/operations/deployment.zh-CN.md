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

# 部署

[English](deployment.md) | 简体中文

本文描述 1.0 支持的部署形态。建议先从回环地址开始，增加有意识选择的认证模式，
并在向 Host 暴露前验证真实 Apache Doris 路由。

## 选择传输

| 形态 | 适用场景 | 进程模型 | 认证边界 |
|---|---|---|---|
| stdio | 单个本地 Host 启动单个 Server | 子进程 | 本地 OS/进程边界 + Doris 凭据 |
| Streamable HTTP 回环 | 本地工具共享服务 | 一个或多个 Worker，受鉴权模式约束 | Token/JWT/OAuth 可选但推荐 |
| TLS Proxy 后的 Streamable HTTP | 受控远程访问 | Proxy + Server Worker | 已认证 HTTP、可信 Proxy 策略、TLS |

独立 SSE 传输已退役。新 HTTP 集成使用 `POST /mcp` 和 MCP `2026-07-28`。

## stdio 部署

Host 配置示例：

```json
{
  "command": "doris-mcp-server",
  "args": ["--transport", "stdio"],
  "env": {
    "DORIS_HOST": "127.0.0.1",
    "DORIS_PORT": "9030",
    "DORIS_USER": "mcp_reader",
    "DORIS_PASSWORD": "<secret>",
    "DORIS_DATABASE": "information_schema"
  }
}
```

运维规则：

- stdout 只用于 MCP Frame；
- 日志写 stderr 或配置文件；
- Host 负责进程重启与环境注入；
- 凭据在环境中时，不要与不相关用户共享进程；
- stdio 初始化会先建立可用 Doris 路由，再接受普通工作。

## Streamable HTTP 部署

本地命令：

```bash
export TRANSPORT=http
export SERVER_HOST=127.0.0.1
export SERVER_PORT=3000
export DORIS_HOST=127.0.0.1
export DORIS_PORT=9030
export DORIS_USER=mcp_reader
export DORIS_PASSWORD='<secret>'

doris-mcp-server --transport http --host 127.0.0.1 --port 3000
```

端点：

- `POST /mcp`——现代 MCP 请求；
- `GET /live`——进程/协议存活；
- `GET /ready`——有界 Doris 就绪检查；
- `GET /health`——兼容健康视图；
- `/mcp/legacy`——默认关闭的协议迁移 Adapter。

在认证、Host/Origin、Proxy、TLS、Timeout 和 Secret 注入经过联合测试前，Server
应保持回环绑定。

## 鉴权与 Worker 数量

无状态 MCP 请求不需要 Sticky Session，但认证/Provider 模式有更严格约束：

| 模式 | Worker 建议 |
|---|---|
| 静态 Token | 共享 Token/状态配置后可使用多 Worker |
| JWT | Key/Policy 一致时可使用多 Worker |
| 外部 OAuth/OIDC | Validation 与 Mapping 配置一致时可使用多 Worker |
| Doris OAuth | 1.0 必须单 Worker；Token 与用户池在进程内 |
| 自定义 Provider 限流 | 除非 Provider 使用外部状态，否则 Quota 为每进程独立 |

独立 Replica 位于负载均衡后时，要共享高强度 `MCP_STATE_HANDLE_SECRET`，保证分页
和状态句柄跨实例有效；授权策略与可见 Catalog 也必须兼容。1.0 不允许 Doris
OAuth 流量在多个 Replica 间共享。

## Docker

本地构建：

```bash
docker build -t doris-mcp-server:1.0.0 .
```

使用镜像之外的环境文件运行：

```bash
docker run --rm \
  --env-file /secure/path/doris-mcp.env \
  --publish 127.0.0.1:3000:3000 \
  doris-mcp-server:1.0.0
```

也可以使用 `docker-compose.yml`，但必须先检查 `.env.example`。仓库示例只有占位
配置和安全断言，不包含生产凭据。

容器要求：

- 固定 Image/Release，不部署可变 `latest`；
- 以只读、Owner 限权方式挂载 Secret File；
- `/live` 和 `/ready` 使用不同 Probe；
- CPU/Memory Limit 要兼容查询并发与结果上限；
- 只放通必需 FE MySQL、FE HTTP、BE HTTP、OAuth 与 Provider Egress；
- 在 Proxy/Auth 边界完整前，不向全部接口发布端口。

## Reverse Proxy 与 TLS

流量离开本机时：

1. 在受控 Proxy 或平台 Ingress 终止 TLS；
2. 保留必需 MCP Header 与请求 Body，不改写 Method/Name；
3. 配置精确 Public Host/Origin；
4. 接受 Forwarded Header 前配置可信 Proxy CIDR；
5. 在请求进入进程前拒绝超大 Payload，同时与 MCP Schema/Instance 上限兼容；
6. 避免 Buffer/Timeout 截断合法 Streamable HTTP 响应；
7. 不记录 Bearer 或 Admin Authorization Header。

绑定 `0.0.0.0` 只是在选择网络接口，不等于授权 Public Hostname、Proxy 或 Origin。

## Apache Doris 路由

单 FE：

```bash
export DORIS_HOST=fe.example
export DORIS_PORT=9030
export DORIS_FE_HTTP_HOST=fe.example
export DORIS_FE_HTTP_PORT=8030
```

多个 FE 候选：

```bash
export DORIS_HOSTS='fe-1.example:9030,fe-2.example:9030'
export DORIS_FE_HTTP_HOSTS='fe-1.example:8030,fe-2.example:8030'
```

显式 BE HTTP Allowlist：

```bash
export DORIS_BE_HOSTS='be-1.example:8040,be-2.example:8040'
```

路由管理器校验候选地址并保留路由身份。不能让 MCP 调用方提供任意 FE/BE Host。
网络策略只应放通配置集群与经过审查的 Provider。

## 暴露模式

默认：

```bash
export MCP_TOOL_EXPOSURE_MODE=hierarchical
```

Host 兼容回退：

```bash
export MCP_TOOL_EXPOSURE_MODE=flat
```

变更模式需要重启进程并让 Host 重连；它是启动合同，不是请求级开关。

## 可选 Provider

- **ADBC：**显式启用并配置 Arrow Flight SQL 端口，上生产前测试路由隔离。
- **Ossie：**设置 `OSSIE_ENABLED=true`，挂载已审查 Model 和私有 Doris Binding，
  并授权精确 Semantic Scope。
- **原生血缘：**配置规范可查询 Store/Provider，验证必需列和投递健康。
- **自定义 Tool：**安装包，并把精确 Provider 名写入 `MCP_TOOL_PROVIDERS`。

可选 Provider 缺失时只应令相关 Child 不可用，不影响其他领域。显式 Allowlist 的
自定义 Provider 无效时则启动失败。

## 发布流程

1. 固定 Package/Image，记录不含 Secret 的配置 Hash。
2. 在离线/Stage 进程验证启动配置。
3. 分别检查 `/live` 与 `/ready`。
4. 从目标 Host 调用 `server/discover` 和 `tools/list`。
5. 发现所有已授权领域，记录 `callable` 与原因码。
6. 通过正式 Query Child 执行只读 `SELECT 1`。
7. 执行负向测试：写 SQL、未授权 Child、无效 Cursor、无权限表、结果/超时上限。
8. 配置多 FE 时验证 Failover 与 Readiness。
9. 对比自动生成工具目录、Release Artifact 与部署包版本。
10. 渐进开放生产流量并监控类型化失败和截断。

## 升级与回滚

- 从 1.0 以前版本升级前阅读[迁移到 1.0](../migration/1.0.0.zh-CN.md)。
- 重启 Host，清除缓存的旧 Schema。
- 暴露模式变化按 API 变更处理，必须重连。
- Package/Image 与配置一起回滚。
- 回滚不会让 1.0 State Handle/Manifest 在旧进程上有效；Host 必须重新发现。
- 不把 Legacy HTTP Adapter 当作长期混合版本方案。

继续阅读[配置参考](../reference/configuration.zh-CN.md)和
[可靠性与限制](reliability.zh-CN.md)。
