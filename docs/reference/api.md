# API 与协议参考

本文说明 SysArmor 当前 API 边界、端点分类和版本演进规则。精确请求/响应字段以 `apps/manager/internal/adapters/inbound/http/manager/` 的 handler 与测试、`packages/contracts/proto/` 的 protobuf 为准。

## 信任边界

```text
Browser -> same-origin Manager Console BFF -> Manager HTTP API
Agent -> mTLS Gateway gRPC -> Kafka -> Worker
sysarmorctl -> local Agent Unix gRPC 或 Manager HTTP API
```

- 浏览器不直接访问 Manager，也不持有 Manager JWT。
- BFF 验证 Auth.js session，签发短期 RS256 JWT；Manager 从 JWT principal 获取 tenant 和 role。
- Operator API 不信任身份 header；显式 tenant 与 principal 冲突时拒绝请求。
- install script 使用只能兑换一次的 bootstrap ticket；enrollment artifact 和 certificate 使用短期 enrollment token，不使用 Operator JWT。
- Agent 数据面和控制面通过证书 URI SAN 绑定 tenant 与 Agent ID。

## Manager HTTP API

Manager 默认监听容器端口 `9443`，本地 Compose 映射为 `19443`。除公开健康和 enrollment token 流程外，`/api/v1/` 路由要求可信 principal。

### UI 聚合接口

| Method | Path | 用途 |
|---|---|---|
| `GET` | `/api/v1/ui/overview` | 总览计数和服务健康 |
| `GET` | `/api/v1/ui/deploy/options` | artifact、channel、profile 与部署选项 |
| `POST` | `/api/v1/ui/deploy/agent-command` | 创建 enrollment 并生成安装命令 |
| `GET` | `/api/v1/search/fields` | 可搜索字段元数据 |
| `POST` | `/api/v1/search` | tenant 约束的 Event/Signal 搜索 |
| `POST` | `/api/v1/search/histogram` | 当前搜索的时间桶聚合 |

### 控制与分发接口

| Path | 主要方法 | 用途 |
|---|---|---|
| `/api/v1/policies` | `GET`、`POST` | Policy 查询和写入 |
| `/api/v1/policy-publish` | `POST` | 发布状态变更 |
| `/api/v1/policy-audit` | `GET` | Policy 审计 |
| `/api/v1/policy-assignments` | `GET`、`POST` | Policy 分配与可选下发 |
| `/api/v1/effective-policy` | `GET` | 解析 Agent/scope 有效 Policy |
| `/api/v1/artifacts`、`/api/v1/artifacts/{id}/...` | `GET`、`POST` | 上传、列出、激活或吊销 artifact |
| `/api/v1/channels` | `GET`、`POST` | channel 绑定 |
| `/api/v1/enrollments` | `GET`、`POST` | 一次性 enrollment |
| `/api/v1/control-commands` | `GET`、`POST` | Policy/content 控制命令及生命周期 |
| `/api/v1/responses` | `GET`、`POST` | 响应命令和审计 |
| `/api/v1/response-decisions` | `POST` | 响应决策 |
| `/api/v1/response-approvals` | `POST` | 响应审批 |
| `/api/v1/evidence-pullbacks` | `GET`、`POST` | Evidence 回拉请求 |

### 状态与数据接口

| Method | Path | 用途 |
|---|---|---|
| `GET` | `/healthz` | Manager 健康 |
| `GET` | `/api/v1/agents` | Agent inventory |
| `GET` | `/api/v1/agent-health` | Agent 最近健康状态 |
| `GET` | `/api/v1/agent-sessions` | 数据/控制 session |
| `GET` | `/api/v1/events` | Event 查询 |
| `GET` | `/api/v1/signals` | Signal 查询 |
| `GET` | `/api/v1/incidents` | Incident 列表或按 `incident_id` 查询 |
| `GET` | `/api/v1/metrics` | Manager 指标 |
| `GET` | `/api/v1/store-status` | 存储状态 |
| `GET` | `/api/v1/rarity-baseline` | rarity 基线 |
| `GET` | `/api/v1/data-resume` | Agent 上传续传 cursor |

测试和维护接口 `/api/v1/reset`、`/api/v1/recompute` 不应作为稳定产品集成契约。

创建 enrollment 会同时返回手工注册 token 和 `install_url`。`install_url` 中的 bootstrap ticket 只能读取一次；兑换时 Manager 轮换 enrollment token，因此创建响应中的手工 token 随即失效。安装脚本通过 `Authorization: Enrollment <token>` 获取受保护 artifact，并用 token 与 CSR 请求证书。相同 token 与相同公钥的证书请求幂等返回原证书，不同公钥返回冲突。tenant、Agent ID、Gateway 和 TLS server name 只取 Manager enrollment，CSR subject 不参与授权。

查询规则：tenant 以 principal 为准；字段、alias、时间范围和分页受 handler 白名单及上限约束；精确 ID 和 label 使用 exact-match；空结果是成功，依赖失败必须保留 HTTP 状态和结构化错误。

当前 Console 的 Overview、Deploy、Agents 和 Event/Signal Search 已接入 Manager。Incident 页面仍使用本地 mock data；未接入前不能描述为实时调查工作流。

## BFF 约定

浏览器调用 `/api/manager/<path>`，Next.js route 校验 session 后转发到 Manager `/api/v1/<path>`。BFF 必须保留 Manager 的状态码和错误正文。UI 只能通过 `apps/console/lib/api/` 中的 typed client 调用，不在页面组件内拼 URL 或授权 header。

## gRPC 服务

| 服务 | 位置 | 作用 |
|---|---|---|
| `AgentControlPlaneService` | Agent 本地 Unix socket 与 Gateway 双向控制流 | health、capability、Policy/content、watch、enroll、response、Evidence 回拉 |
| `AgentDataPlaneService` | Gateway `9444` mTLS | 追加 `DataBatch` 并返回 cursor/重试语义 |

本地 CLI 默认连接 `/run/sysarmor/agent/control.sock`。Gateway 健康 HTTP 默认监听 `9445`，提供 `/healthz` 与 `/metrics`。

## Protobuf 包

| 包 | 主要契约 |
|---|---|
| `sysarmor.event.v1` | 规范化 `CanonicalEvent` |
| `sysarmor.signal.v1` | `Signal`、Entity、Evidence、Response intent |
| `sysarmor.incident.v1` | Incident、Evidence 子图和 converge trace |
| `sysarmor.dataplane.v1` | `DataBatch`、序列、drop/parse delta 和 ack |
| `sysarmor.controlplane.v1` | Agent 本地及远程控制帧 |
| `sysarmor.policy.v1` | Policy wire model |

当前数据面 `schema_version` 为 `sysarmor.dataplane/v1`；新 producer 必须在每个 `DataBatch` 中设置。

## 版本演进

SysArmor 使用彼此独立的版本轴：

- `schema_version`：序列化和传输契约；决定 consumer 能否处理消息。
- `analysis_version`：生成 Incident 的分析规则和语义；参与报告身份。
- OpenSearch 物理索引版本：只描述搜索 mapping，不等于前两者。

Protobuf 规则：

1. 已发布 field number 和含义不可改变。
2. 新字段使用新编号；删除字段前先 deprecated，删除后同时 reserve 编号和名称。
3. 不得复用编号或名称。
4. 老 consumer 可忽略的 optional 新字段不提升 Schema major。
5. 删除字段、改变类型/含义、把 optional 变 required 时提升 major。
6. 仅通过 `make api` 更新生成的 Go 文件。

Worker 不以“protobuf 能解码”替代兼容性检查。空或不支持的版本是永久错误 `unsupported_schema_version`；只有 DLQ 写入成功后才提交源 Kafka offset。

未来 v2 的顺序必须是：先部署同时接受 v1/v2 的 consumer，再部署 v2 producer；等待 Kafka 保留窗口内 v1 流量归零，最后在后续版本移除 v1。

HTTP API 优先添加字段。字段重命名或语义变化要求 Manager、typed client 和 UI 协同修改，并用 handler 测试锁定错误和权限语义。
