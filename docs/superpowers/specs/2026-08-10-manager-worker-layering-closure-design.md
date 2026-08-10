# Manager and Worker Layering Closure Design

## 1. 结论

Task 6 和 Task 8 采用垂直切片硬切换方式正式收口。Manager、Gateway 和 Worker
只保留 PostgreSQL 生产路径；旧内存/文件 Store、`ManagerStore`、`store.Store`、
`ingest.Processor` 以及为这些抽象保留的兼容构造器和测试路径全部删除。

公开 HTTP 路由、JSON 字段、状态码和 Protobuf 语义保持不变。内部 Go API 不承担
向后兼容责任。每个业务切片在新 Application 路径接管生产流量后立即删除旧写路径，
禁止长期双写或双读。

## 2. 范围

### 2.1 Task 6

完成 Manager 控制面的剩余切片：

- Enrollment、证书签发和取消注册；
- Control Command 和 Evidence Pullback；
- Response 创建、审批和确认；
- Artifact、Channel、安装材料和部署选项；
- 尚未迁移的 Telemetry、Incident、Search 和运行状态查询入口；
- Manager HTTP Bootstrap 和 PostgreSQL 装配。

Policy 和 Identity 已有分层实现作为参考，不重写其业务语义，只移除旧 fallback。

### 2.2 Task 8

完成 Worker 和 Analytics 的剩余迁移：

- Kafka 消息解码和错误分类进入 inbound Adapter；
- 批次处理、重试、DLQ 和 offset 决策进入 Worker Application；
- Telemetry claim、History、Rarity 和 Projection 通过消费者侧 Ports；
- Correlation、Convergence、Rarity、Entity、Graph、Evidence 和 Incident 进入纯 Domain；
- PostgreSQL、OpenSearch 和 Kafka 只由 outbound/inbound Adapters 使用；
- Worker 配置、资源创建和关闭进入 `bootstrap.NewWorker`。

### 2.3 不在本轮范围

- Agent Domain 和 `AgentRuntime` 迁移；
- 公开协议版本或产品功能变更；
- 引入新的数据库、中间件、DI 框架或分布式事务；
- 与 Task 6/8 无关的前端和检测规则改造。

## 3. 目标依赖结构

稳定依赖方向为：

```text
cmd -> bootstrap -> adapters -> application -> domain
                         |             |
                         +---- ports <-+
```

- Domain 只依赖同产品 Domain 和允许的标准库。
- Application 只依赖 Domain、Application、Ports 和允许的标准库。
- Ports 由消费者定义，不暴露 SQL、Protobuf、OpenSearch 或旧 Store 类型。
- Adapters 完成 HTTP、Protobuf、SQL、Kafka 和 OpenSearch 映射。
- Bootstrap 只负责配置校验、对象组装、资源关闭和进程生命周期。
- `cmd` 只解析参数、调用 Bootstrap、报告顶层错误并设置退出码。

## 4. Manager 切片设计

每个切片包含 Domain、Application、Ports、PostgreSQL Adapter 和 HTTP Adapter。
HTTP Adapter 将已认证请求转换为强类型 `manager.RequestContext`，Application 执行授权、
状态转换和事务编排，PostgreSQL Adapter 执行持久化。

### 4.1 Enrollment

Domain 持有 Enrollment、Bootstrap Token、Certificate 和 Unenrollment 状态机。
Application 提供创建注册、消费一次性 Token、签发证书、发起取消注册和确认端点完成用例。
签发事务原子提交 Token 消耗、Enrollment 状态和证书记录；数据库提交失败不得返回有效注册结果。

### 4.2 Control

Domain 持有 Command 和 Evidence Pullback 的状态转换。Application 提供创建、发送、确认、
重试、取消、过期和回拉完成用例。所有状态变化使用乐观冲突检查，并在同一事务记录审计信息。

### 4.3 Response

Domain 持有 Response Decision、Approval 和 Command 状态。Application 强制角色、多审批、
拒绝、命令创建和确认规则。审批结果、控制命令和审计记录在一个 PostgreSQL 事务内提交。

### 4.4 Artifact

Domain 持有 Artifact、Channel 和发布状态。Application 提供查询、登记和 Channel 更新用例。
归档解析、签名读取和 HTTP DTO 映射属于 Adapter；Domain 不读取文件或环境变量。

### 4.5 Query 和 Telemetry

Events、Signals、Incidents、Search、Overview 和运行状态均通过 tenant-scoped Query Ports。
OpenSearch 查询由 outbound Adapter 实现；所有租户级方法强制接收非空 `tenant.ID`。
`/healthz` 只表达进程健康，不绕过租户边界返回业务数据。

## 5. Worker 数据流

```text
Kafka RawMessage
  -> Kafka inbound Adapter: decode + schema/identity validation
  -> Worker Application: claim + process + retry/disposition
  -> Analytics Domain: deterministic analysis
  -> PostgreSQL/OpenSearch outbound Adapters
  -> success commit offset | permanent failure publish DLQ then commit | retryable no commit
```

Worker Application 保持以下不变量：

1. 同一租户和批次身份只允许一个有效 claim；重复已完成批次按成功处理。
2. 处理最多尝试三次；可重试失败不提交 Kafka offset。
3. 永久失败只有在 DLQ 可靠发布后才提交 offset。
4. Projection 部分失败不得把批次标记为完成。
5. History、Rarity、Policy 和 Projection 调用始终携带强类型租户。
6. Analytics 输入输出使用 Domain 模型，不导入 Protobuf。

## 6. PostgreSQL 唯一生产路径

删除 `--store-backend`、文件路径和 memory/file 分支。Manager、Gateway 和 Worker 的 Bootstrap
直接要求 PostgreSQL driver 和 DSN，启动时完成配置校验和迁移检查。缺失或不可用时 fail closed，
不得退回内存状态。

单元测试使用 Fake Ports 和 Fake Unit of Work；Adapter 契约测试使用现有 PostgreSQL fake driver
或受控 PostgreSQL。测试便利性不构成保留产品内存 Store 的理由。

## 7. 错误处理

- Domain 返回稳定 `failure.Kind`，不包含 HTTP、gRPC 或 SQL 状态。
- Application 保留 InvalidArgument、Unauthenticated、PermissionDenied、NotFound、Conflict、
  FailedPrecondition、ResourceExhausted、RetryableDependency 和 Internal 分类。
- HTTP Adapter 统一映射状态码和现有 JSON 错误格式。
- PostgreSQL、Kafka 和 OpenSearch Adapter 映射技术错误，不吞掉上下文取消或事务失败。
- Worker 只在明确永久错误时进入 DLQ；未知依赖错误默认可重试。

## 8. 删除边界

Task 6/8 完成后必须删除：

- `apps/manager/internal/api` 中被新 HTTP Adapter 替代的业务 Handler 和 `ManagerStore`；
- `apps/manager/internal/store`、`internal/store/backend` 和旧 PostgreSQL Store facade；
- `apps/manager/internal/ingest`；
- `apps/manager/internal/analytics`；
- `apps/manager/internal/platform/kafka`、`platform/redis` 及其他已迁移 platform 实现；
- memory/file backend flags、构造器、fixtures 和只验证旧路径的测试；
- Task 6/8 对应的架构契约 legacy exemptions。

若迁移或 schema 工具仍有真实调用方，直接移动到 PostgreSQL Adapter 下，不保留转发包。

## 9. 实施顺序

1. 按 Enrollment、Control、Response、Artifact、Query/Telemetry 顺序迁移 Manager 切片。
2. 每个切片先写 Application/Adapter 失败测试，再切换生产路由并删除旧方法。
3. 建立 `bootstrap.NewManager`，让 Manager `cmd` 脱离旧 API/Store 装配。
4. 迁移 Analytics Domain 和 Worker batch use case。
5. 建立 `bootstrap.NewWorker`，让 Worker `cmd` 脱离 Protobuf、Kafka、OpenSearch 和 SQL 细节。
6. 删除 Store、Ingest、Analytics、Platform 遗留根目录及所有兼容入口。
7. 收紧架构契约并执行完整门禁。

## 10. 验收标准

以下条件必须全部满足：

1. Manager 和 Worker 生产入口只使用 Bootstrap 和 PostgreSQL 配置。
2. Task 6 的所有公开 HTTP 行为由新 Application/Adapter 路径提供。
3. Worker offset、DLQ、claim、projection 和 retry 语义通过故障矩阵测试。
4. Analytics Domain 不导入 Protobuf、SQL、Kafka 或 OpenSearch。
5. 不存在 Task 6/8 新旧双写或 fallback。
6. 产品代码不再命中 `store.Store`、`ManagerStore`、`SaveState` 或 `ingest.Processor`。
7. `internal/store`、`internal/ingest`、`internal/analytics` 和已迁移 platform 根目录不存在。
8. Task 6/8 的架构 legacy exemptions 全部删除。
9. 非生成 Go 文件不超过 500 行，新增或修改函数不超过 50 行。
10. 架构契约、`go vet ./...`、`go test ./...`、Manager/Worker race 和相关集成测试通过。

