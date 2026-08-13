# SysArmor Domain、Application、Ports、Adapters 架构重构设计

## 1. 结论与设计思路

SysArmor 将采用 Domain、Application、Ports、Adapters 架构重构 Agent、Manager、Gateway 和 Worker。目标不是把现有目录机械地改名，而是建立可由代码和测试强制执行的依赖方向，使安全规则、业务流程、传输协议和基础设施实现能够独立演进。

本次重构遵循以下高层设计：

1. **领域规则居中。** 策略版本、管理状态、租户隔离、批次确认、响应审批等不变量由纯 Domain 模型表达，不依赖 HTTP、gRPC、Protobuf、SQL 或具体运行环境。
2. **用例显式化。** 策略发布、Agent 注册、控制确认、批次处理等流程由 Application Service 编排，输入 Adapter 不再直接组合 Store 操作。
3. **依赖反转。** Application 通过 Ports 声明所需能力，PostgreSQL、OpenSearch、Kafka、Redis、SQLite、Tetragon 等 Adapters 实现这些能力。
4. **边界内聚。** Agent 和 Manager 分别维护自己的 Domain。跨进程共享的是版本化 Contract，不共享可变领域对象。
5. **安全默认关闭风险。** 租户上下文必须显式传递；Gateway 生产模式必须使用 mTLS；空租户、缺失身份或缺失安全配置不得降级为全局或匿名访问。
6. **事务围绕用例。** 一个业务操作的状态变化、审计和待下发命令在同一事务中提交，不再依赖全局内存快照和事后 `Save()`。
7. **目标一次确定，实施增量可验。** 目标架构一次设计完成，代码按垂直业务切片迁移。每个阶段必须保持仓库可构建、关键链路可测试、现有协议可兼容。

重构完成后的稳定依赖方向为：

```text
cmd / bootstrap
       |
       v
inbound adapters ---> application ---> domain
                         |
                         v
                       ports
                         ^
                         |
                 outbound adapters
```

Domain 不认识外层；Application 只认识 Domain 和 Ports；Adapters 负责外部技术与内部模型的转换；Bootstrap 是唯一可以同时看见所有层的装配位置。

## 2. 目标与成功标准

### 2.1 目标

- 把安全与业务不变量从 Handler、Runtime、Store 和 SQL 中集中到 Domain。
- 把跨组件业务流程整理为可单独测试的 Application Use Case。
- 用最小 Ports 替代 `store.Store`、`ManagerStore`、`gateway.Backend` 等全能接口。
- 隔离 Domain、Wire Contract 和 Storage Record 三类模型。
- 将租户、权限、事务、可靠确认和错误分类变成接口契约，而不是调用方约定。
- 允许 Agent、Manager、Gateway、Worker 和各基础设施 Adapter 独立扩展。
- 保持 standalone Agent 离线自治、可靠上传和策略原子切换等既有架构不变量。

### 2.2 成功标准

1. Domain 包不导入 Protobuf、HTTP、gRPC、SQL、操作系统或具体基础设施包。
2. Application 包不导入 PostgreSQL、OpenSearch、Kafka、Redis、SQLite、Tetragon、HTTP 或 gRPC 实现。
3. 所有租户级 Repository 和查询 Port 强制接收非空 `tenant.ID`。
4. Manager、Gateway 和 Worker 不再共享可变的 `*store.Store`。
5. 删除 `SaveState`、全局 `Save()` 和用空租户表示全局查询的产品接口。
6. Gateway 缺失 mTLS 配置时拒绝以生产模式启动。
7. 策略发布、策略分配、注册签发、响应审批和取消注册具有明确事务边界。
8. Kafka 消费结果明确区分成功、可重试失败和永久失败，只有成功或可靠 DLQ 后提交 offset。
9. 手写文件不超过 500 行；函数原则上不超过 50 行。
10. 架构依赖契约、Domain 单元测试、Application 用例测试、Adapter 集成测试和端到端测试全部通过。

## 3. 当前架构与目标架构差距

### 3.1 总体差距

| 维度 | 当前状态 | 目标状态 | 主要影响 |
|---|---|---|---|
| Domain | 分散在 `management`、`policy`、`analytics`、`store` 和 Runtime | Agent、Manager 各自拥有纯 Domain | 规则重复且容易被传输或存储细节改变 |
| Application | 流程隐藏在 HTTP Handler、gRPC Handler、Daemon、Gateway Runtime 和 Processor | 每个业务操作有显式 Command、Use Case 和 Result | 流程难以独立测试，事务边界不清晰 |
| Ports | 已有 `ManagerStore`、`ControlStore` 等接口，但接口大且泄露 Store 类型 | 消费者侧最小接口，使用 Domain 或 Port 自有边界类型 | 调用者获得超出职责的能力 |
| Adapters | `platform/*`、API、LocalStore、Sensor 已有雏形 | 明确分为 inbound 与 outbound，并实现 Ports | 技术实现直接进入业务编排 |
| 模型 | Protobuf 类型贯穿检测、分析、Store 和 API | Domain Model、Wire DTO、Storage Record 隔离 | 协议变更扩散到核心逻辑 |
| 租户 | 裸字符串、可省略参数、Handler 负责过滤 | 强类型租户上下文，Port 强制租户 | 已出现跨租户查询和全局统计泄露 |
| 事务 | 修改内存对象后调用 `Save()`，部分路径全量投影 | Application 通过 Unit of Work 原子提交用例 | 内存与 PostgreSQL 语义不一致 |
| 可靠性 | Kafka、OpenSearch、Store 错误分类散落 | Application 返回稳定错误分类，Adapter 决定 retry/DLQ | 失败处理难以统一验证 |
| 生命周期 | `AgentRuntime`、`gateway.Runtime` 持有大量共享状态 | 小型 Application Service，由 Bootstrap 组装 | 修改半径大，并发状态难推理 |
| 装配 | `main.go` 包含配置、重试和运行逻辑 | `cmd` 只解析入口，`bootstrap` 完成装配 | 启动逻辑难测试、开发模式可能误入生产 |
| 架构治理 | 依靠开发者阅读约定 | 自动检查 import、文件规模和接口边界 | 边界容易随功能迭代退化 |

### 3.2 当前核心对象与目标替代物

| 当前对象 | 当前问题 | 目标替代物 |
|---|---|---|
| `daemon.AgentRuntime` | 同时承担生命周期、身份、策略、检测、内容、Sensor、Telemetry 和 API | 多个 Application Service 加 `bootstrap.Agent` |
| `store.Store` | 全局锁、全领域状态、内存实现、持久化门面和业务方法混合 | 领域 Repository Ports、Unit of Work 和独立 Adapters |
| `managerapi.ManagerStore` | HTTP 层定义巨型存储接口，包含多个业务领域 | HTTP Adapter 依赖按用例定义的 Application 接口 |
| `gateway.Backend` / `ControlStore` | gRPC、业务和持久化边界混合 | Gateway Application Use Cases 和最小 Ports |
| `gateway.handleFrame` | 单函数分派并执行全部控制业务 | gRPC Decoder、Dispatcher、独立 Command Handler |
| `ingest.Processor` | 解码、历史查询、分析、投影、Metrics 和持久化混合 | `ProcessDataBatch` Use Case 加 History/Projection Ports |
| `packages/policy` | 同时作为跨进程数据、Agent 运行模型和 Manager 控制模型 | Contract DTO、Agent Policy Domain、Manager Policy Domain |
| `packages/response` | Manager 审批与 Agent 执行共享同一可变模型 | Manager Response Domain、Contract DTO、Agent Action Domain |

### 3.3 现有目录与目标目录差距

当前目录主要按技术或历史功能增长：

```text
apps/agent/internal/{daemon,control,localstore,localapi,remoteapi,...}
apps/manager/internal/{api,gateway,ingest,analytics,store,platform,...}
```

目标目录明确架构层和进程装配：

```text
apps/<product>/internal/
├── domain
├── application
├── ports
├── adapters
└── bootstrap
```

目录不是架构本身，但它将作为 Go `internal` 可见性和 import 契约的物理边界。

## 4. 边界上下文与模型策略

### 4.1 Agent 边界上下文

Agent 包含以下领域：

- `management`：standalone/managed 生命周期、Authority 和身份来源。
- `policy`：Collection、Detection、Telemetry、Response 的端点有效策略。
- `detection`：规则编译、CEP 状态、条件执行、Signal 生成依据。
- `content`：签名内容、Layer、Patch、Snapshot 和激活不变量。
- `event`：端点行为事实、上下文和规范化语义。
- `telemetry`：批次、checkpoint、重试资格和有界队列规则。
- `health`：组件健康、降级和失败暴露规则。
- `response`：端点允许执行的受控动作及其结果。

### 4.2 Manager 边界上下文

Manager、Gateway 和 Worker 共享同一产品代码库，但按领域和用例隔离：

- `tenant`：租户标识、Actor、Role 和访问作用域。
- `identity`：Agent 身份、证书、Session 和健康快照。
- `enrollment`：注册令牌、CSR 签发、取消注册和证书撤销。
- `policy`：策略版本、发布、分配、审计和 Rollout。
- `control`：控制命令、发送状态、确认、重试和过期。
- `response`：响应决策、审批规则、执行命令和回执。
- `artifact`：制品、通道、签名元数据和分发约束。
- `audit`：安全操作审计记录及其不可变性要求。
- `telemetry`：批次身份、可靠接收、搜索作用域和指标。
- `detection`：云侧关联、稀有度、收敛和稳定重算。
- `investigation`：Entity、Graph、Evidence 和 Incident。

### 4.3 三类模型

| 模型 | 所属层 | 用途 | 禁止事项 |
|---|---|---|---|
| Domain Model | Domain | 表达业务状态和不变量 | 不包含 JSON/SQL/gRPC 行为，不依赖生成代码 |
| Application DTO | Application | Command、Query、Result 和分页参数 | 不泄露 HTTP、gRPC、Kafka 或 SQL 类型 |
| Wire/Storage DTO | Adapters/Contracts | Protobuf、HTTP JSON、Kafka Envelope、数据库 Record | 不承载领域决策逻辑 |

所有边界转换由 Adapter Mapper 完成。禁止为了减少映射代码而让 Domain 直接复用 Protobuf Message。

## 5. 目标目录

### 5.1 Agent

```text
apps/agent/
├── cmd/
│   ├── sysarmor-agent/
│   └── sysarmor-content-sign/
└── internal/
    ├── domain/
    │   ├── management/
    │   ├── policy/
    │   ├── detection/
    │   │   ├── compiler/
    │   │   ├── runtime/
    │   │   └── matcher/
    │   ├── content/
    │   ├── event/
    │   ├── telemetry/
    │   ├── health/
    │   └── response/
    ├── application/
    │   ├── lifecycle/
    │   ├── enrollment/
    │   ├── policy/
    │   ├── content/
    │   ├── detection/
    │   ├── pipeline/
    │   ├── telemetry/
    │   ├── health/
    │   └── diagnostics/
    ├── ports/
    ├── adapters/
    │   ├── inbound/unix/
    │   ├── inbound/grpc/
    │   ├── outbound/grpc/
    │   ├── outbound/jsonl/
    │   ├── config/
    │   ├── sqlite/
    │   ├── segments/
    │   ├── filesystem/
    │   ├── sensor/tetragon/
    │   ├── sensor/fake/
    │   └── system/
    └── bootstrap/
```

### 5.2 Manager、Gateway 和 Worker

```text
apps/manager/
├── cmd/
│   ├── sysarmor-manager/
│   ├── sysarmor-gateway/
│   └── sysarmor-worker/
└── internal/
    ├── domain/
    │   ├── tenant/
    │   ├── identity/
    │   ├── enrollment/
    │   ├── policy/
    │   ├── control/
    │   ├── response/
    │   ├── artifact/
    │   ├── audit/
    │   ├── telemetry/
    │   ├── detection/
    │   └── investigation/
    ├── application/
    │   ├── manager/
    │   ├── gateway/
    │   └── worker/
    ├── ports/
    ├── adapters/
    │   ├── inbound/http/
    │   ├── inbound/grpc/
    │   ├── inbound/kafka/
    │   ├── outbound/postgres/
    │   ├── outbound/opensearch/
    │   ├── outbound/kafka/
    │   ├── outbound/redis/
    │   ├── outbound/pki/
    │   ├── outbound/archive/
    │   └── observability/
    └── bootstrap/
```

### 5.3 共享 Contracts

```text
packages/
├── contracts/
│   ├── proto/
│   └── schema/
├── sensor-sdk/
└── observability/   # 仅在产生真实跨产品复用后创建
```

共享包只保存跨进程或对外发布的稳定契约。Agent 与 Manager 不共享业务实体实现。

## 6. 各层职责与接口清单

以下接口是设计级稳定边界。具体文件拆分可以在实现计划中调整，但语义和依赖方向不得改变。

### 6.1 Domain 层

Domain 对外提供实体、值对象、领域服务和领域错误，不提供基础设施接口。

#### Agent Domain

```go
// domain/management
type State string
type Authority string
type Context struct { /* state and authority */ }

func Resolve(state State) (Context, error)
func ValidateTransition(from, to State) error
func (c Context) AuthorizePolicyWrite(origin PolicyWriteOrigin) error

// domain/policy
type EndpointPolicy struct { /* four policy sections and identity */ }
type ActivationCandidate struct { /* compiled immutable candidate */ }

func ValidateVersion(current, candidate EndpointPolicy) error
func BuildActivationCandidate(policy EndpointPolicy, inputs ActivationInputs) (ActivationCandidate, error)

// domain/detection
type Program struct { /* immutable compiled rules */ }
type RuntimeState struct { /* bounded mutable CEP state */ }
type Match struct { /* rule match without wire DTO */ }

func Compile(policy Policy, content ContentSnapshot, capabilities Capabilities) (Program, CompileReport)
func Evaluate(program Program, state *RuntimeState, event Event) ([]Match, error)

// domain/content
func VerifyEnvelope(envelope Envelope, trust TrustMaterial) (VerifiedContent, error)
func ResolveLayers(base Snapshot, updates []VerifiedContent) (Snapshot, error)

// domain/telemetry
func ClassifyAck(ack Ack) (CheckpointDecision, error)
func CanEvict(segment SegmentState, pressure StoragePressure) EvictionDecision
```

#### Manager Domain

```go
// domain/tenant
type ID string
type Actor struct { Subject string; TenantID ID; Roles RoleSet }

func NewID(value string) (ID, error)
func (a Actor) Require(role Role) error

// domain/policy
func Publish(current Policy, candidate Policy, actor tenant.Actor, now time.Time) (Policy, AuditRecord, error)
func Assign(policy Policy, target Target, actor tenant.Actor, now time.Time) (Assignment, error)

// domain/control
func MarkSent(command Command, now time.Time) (Command, error)
func Acknowledge(command Command, ack Ack, now time.Time) (Command, error)
func Retry(command Command, actor tenant.Actor, now time.Time) (Command, error)

// domain/enrollment
func Issue(enrollment Enrollment, csr CSR, identity AgentIdentity, now time.Time) (CertificateGrant, error)
func AuthorizeUnenrollment(enrollment Enrollment, certificate Certificate, now time.Time) (Unenrollment, error)

// domain/response
func Decide(policy Policy, signal SignalRef, actor tenant.Actor, now time.Time) (Decision, error)
func Approve(command Command, approval Approval, now time.Time) (Command, error)

// domain/detection and investigation
func Correlate(events []Event, signals []Signal, policy DetectionPolicy) Correlation
func Converge(correlation Correlation, baseline Baseline) Analysis
func BuildIncident(analysis Analysis, scope Scope) (Incident, EvidenceGraph, error)
```

Domain 方法必须是确定性的。当前时间、随机 ID 和外部数据由调用者传入。

### 6.2 Application 层

Application 使用 Command/Query/Result 表达用例。它负责授权、加载聚合、调用 Domain、事务编排和调用 Ports。

#### Agent Application Use Cases

```go
type EnrollAgent interface {
    Execute(context.Context, EnrollCommand) (EnrollResult, error)
}

type UnenrollAgent interface {
    Execute(context.Context, UnenrollCommand) (UnenrollResult, error)
}

type ActivatePolicy interface {
    Prepare(context.Context, ActivatePolicyCommand) (PreparedPolicy, error)
    Commit(context.Context, PreparedPolicy) (ActivatePolicyResult, error)
}

type ActivateContent interface {
    Execute(context.Context, ActivateContentCommand) (ActivateContentResult, error)
}

type ProcessSensorEvent interface {
    Execute(context.Context, SensorEventCommand) (ProcessEventResult, error)
}

type FlushTelemetry interface {
    Execute(context.Context, FlushCommand) (FlushResult, error)
}

type ReportHealth interface {
    Snapshot(context.Context) (HealthSnapshot, error)
}
```

#### Manager Application Use Cases

```go
type PublishPolicy interface {
    Execute(context.Context, RequestContext, PublishPolicyCommand) (PublishPolicyResult, error)
}

type AssignPolicy interface {
    Execute(context.Context, RequestContext, AssignPolicyCommand) (AssignPolicyResult, error)
}

type CreateEnrollment interface {
    Execute(context.Context, RequestContext, CreateEnrollmentCommand) (CreateEnrollmentResult, error)
}

type IssueAgentCertificate interface {
    Execute(context.Context, IssueCertificateCommand) (IssueCertificateResult, error)
}

type DecideResponse interface {
    Execute(context.Context, RequestContext, DecideResponseCommand) (DecideResponseResult, error)
}

type SearchTelemetry interface {
    Execute(context.Context, RequestContext, SearchTelemetryQuery) (SearchTelemetryResult, error)
}

type GetOverview interface {
    Execute(context.Context, RequestContext, OverviewQuery) (OverviewResult, error)
}
```

#### Gateway Application Use Cases

```go
type AcceptDataBatch interface {
    Execute(context.Context, AuthenticatedAgent, DataBatchCommand) (DataBatchResult, error)
}

type OpenControlSession interface {
    Execute(context.Context, AuthenticatedAgent, OpenSessionCommand) (OpenSessionResult, error)
}

type HandleControlFrame interface {
    Execute(context.Context, AuthenticatedAgent, ControlCommand) ([]ControlResult, error)
}

type RevokeEnrollment interface {
    Execute(context.Context, AuthenticatedAgent, RevokeEnrollmentCommand) (RevokeEnrollmentResult, error)
}
```

`HandleControlFrame` 只作为 Dispatcher 接口存在；每一种 `ControlCommand` 必须委派给独立 Handler，不允许重新形成单个巨型 switch 用例。

#### Worker Application Use Cases

```go
type ProcessDataBatch interface {
    Execute(context.Context, ProcessDataBatchCommand) (ProcessDataBatchResult, error)
}

type RecomputeScope interface {
    Execute(context.Context, RecomputeScopeCommand) (RecomputeScopeResult, error)
}
```

`ProcessDataBatchResult` 必须明确携带处理结论：

```go
type ProcessingDisposition string

const (
    ProcessingAccepted  ProcessingDisposition = "accepted"
    ProcessingRetryable ProcessingDisposition = "retryable"
    ProcessingRejected  ProcessingDisposition = "rejected"
)
```

### 6.3 Ports 层

Ports 按消费者需求定义，不按基础设施产品定义。接口参数只使用 Domain 类型或 Port 自己定义的边界类型，不能反向导入 Application。

#### 通用 Ports

```go
type Clock interface {
    Now() time.Time
}

type IDGenerator interface {
    New() string
}

type MetricsRecorder interface {
    Increment(name string, labels map[string]string)
    Observe(name string, value float64, labels map[string]string)
}
```

#### Agent Ports

```go
type Sensor interface {
    Probe(context.Context) (domain.Capabilities, error)
    Subscribe(context.Context, domain.CollectionIntent) (<-chan domain.SensorEvent, error)
    Apply(context.Context, domain.CollectionIntent) (domain.ApplyReport, error)
}

type AgentStateRepository interface {
    DeviceIdentity(context.Context) (domain.DeviceIdentity, error)
    ManagementState(context.Context) (domain.ManagementState, error)
    EffectivePolicy(context.Context) (domain.EndpointPolicy, error)
    SaveEffectivePolicy(context.Context, domain.EndpointPolicy) error
}

type EventSpool interface {
    Append(context.Context, domain.TelemetryBatch) (domain.SpoolPosition, error)
    ReadPending(context.Context, domain.Checkpoint, int) ([]domain.StoredBatch, error)
    CommitCheckpoint(context.Context, domain.Checkpoint) error
    EnforceCapacity(context.Context, domain.StoragePolicy) (domain.CapacityReport, error)
}

type ContentRepository interface {
    Current(context.Context) (domain.ContentSnapshot, error)
    Replace(context.Context, domain.ContentSnapshot) error
}

type DataAppender interface {
    Append(context.Context, DataBatch) (DataAck, error)
}

type ControlChannel interface {
    Connect(context.Context, ControlIdentity) (ControlStream, error)
}
```

#### Manager Repository Ports

```go
type AgentRepository interface {
    Get(context.Context, tenant.ID, identity.AgentID) (identity.Agent, error)
    List(context.Context, tenant.ID, identity.AgentFilter) ([]identity.Agent, error)
    Upsert(context.Context, identity.Agent) error
}

type AgentHealthRepository interface {
    Get(context.Context, tenant.ID, identity.AgentID) (identity.Health, error)
    List(context.Context, tenant.ID, identity.HealthFilter) ([]identity.Health, error)
    Upsert(context.Context, identity.Health) error
}

type AgentSessionRepository interface {
    Get(context.Context, tenant.ID, identity.AgentID) (identity.AgentSession, error)
    Touch(context.Context, identity.AgentSession) error
    Close(context.Context, tenant.ID, identity.AgentID, time.Time) error
}

type PolicyRepository interface {
    Get(context.Context, tenant.ID, policy.ID, policy.Version) (policy.Policy, error)
    Current(context.Context, tenant.ID, policy.ID) (policy.Policy, error)
    List(context.Context, tenant.ID, policy.Filter) ([]policy.Policy, error)
    Put(context.Context, policy.Policy) error
}

type AssignmentRepository interface {
    Effective(context.Context, tenant.ID, policy.Target) (policy.Assignment, error)
    List(context.Context, tenant.ID, policy.AssignmentFilter) ([]policy.Assignment, error)
    Put(context.Context, policy.Assignment) error
}

type ControlRepository interface {
    Get(context.Context, tenant.ID, control.CommandID) (control.Command, error)
    Pending(context.Context, tenant.ID, identity.AgentID) ([]control.Command, error)
    Put(context.Context, control.Command) error
}

type ResponseRepository interface {
    Get(context.Context, tenant.ID, response.CommandID) (response.Command, error)
    List(context.Context, tenant.ID, response.Filter) ([]response.Command, error)
    Put(context.Context, response.Command) error
}

type EnrollmentRepository interface {
    GetByTokenHash(context.Context, enrollment.TokenHash) (enrollment.Enrollment, error)
    Get(context.Context, tenant.ID, enrollment.ID) (enrollment.Enrollment, error)
    Put(context.Context, enrollment.Enrollment) error
}

type CertificateRepository interface {
    GetBySerial(context.Context, tenant.ID, identity.CertificateSerial) (identity.Certificate, error)
    Put(context.Context, identity.Certificate) error
}

type AuditRepository interface {
    Append(context.Context, tenant.ID, audit.Record) error
}
```

所有租户级 Port 必须验证 `tenant.ID` 非空。需要跨租户运维时定义独立 `System*Repository`，并只注入平台系统用例。

#### 搜索、投影和消息 Ports

```go
type TelemetryHistory interface {
    Read(context.Context, tenant.ID, telemetry.Scope, telemetry.TimeWindow) (telemetry.History, error)
}

type TelemetrySearch interface {
    Search(context.Context, tenant.ID, TelemetrySearchQuery) (TelemetrySearchResult, error)
}

type TelemetryProjector interface {
    Project(context.Context, tenant.ID, []telemetry.Document) error
}

type BatchPublisher interface {
    Publish(context.Context, tenant.ID, telemetry.RawBatch) error
}

type DeadLetterPublisher interface {
    PublishRejected(context.Context, RejectedMessage) error
}

type SessionCache interface {
    Touch(context.Context, identity.AgentSession) error
    Remove(context.Context, tenant.ID, identity.AgentID) error
}

type CertificateAuthority interface {
    SignAgentCSR(context.Context, enrollment.SigningRequest) (enrollment.SignedCertificate, error)
}
```

`DataBatch`、`DataAck`、`ControlIdentity`、`TelemetrySearchQuery`、`TelemetrySearchResult` 和 `RejectedMessage` 定义在 Ports 层，是技术无关的边界类型。Application 负责把自己的 Command/Result 映射为这些类型，Adapters 再映射为 Protobuf、JSON 或 Kafka Record。

#### Unit of Work

Unit of Work 也按用例族定义，禁止通过一个事务对象暴露所有 Repository：

```go
type PolicyTransaction interface {
    Policies() PolicyRepository
    Assignments() AssignmentRepository
    Controls() ControlRepository
    Audits() AuditRepository
}

type PolicyUnitOfWork interface {
    Execute(context.Context, func(context.Context, PolicyTransaction) error) error
}

type EnrollmentTransaction interface {
    Enrollments() EnrollmentRepository
    Certificates() CertificateRepository
    Agents() AgentRepository
    Audits() AuditRepository
}

type EnrollmentUnitOfWork interface {
    Execute(context.Context, func(context.Context, EnrollmentTransaction) error) error
}

type ResponseTransaction interface {
    Responses() ResponseRepository
    Controls() ControlRepository
    Audits() AuditRepository
}

type ResponseUnitOfWork interface {
    Execute(context.Context, func(context.Context, ResponseTransaction) error) error
}

type ControlTransaction interface {
    Controls() ControlRepository
    Sessions() AgentSessionRepository
    Audits() AuditRepository
}

type ControlUnitOfWork interface {
    Execute(context.Context, func(context.Context, ControlTransaction) error) error
}
```

各 `*Transaction` 只在事务回调内有效，不得缓存到 Application Service 字段或跨 goroutine 使用。新的事务接口只有在某个用例确实需要新的 Repository 组合时才能增加。

### 6.4 Adapters 层

Inbound Adapters：

- HTTP：JWT 验证、请求限额、JSON DTO、租户上下文绑定、错误到状态码映射。
- gRPC：mTLS 身份解析、Protobuf 映射、流控、序列号与协议响应。
- Kafka Consumer：消息读取、Contract 解码、Application 调用、offset/DLQ 决策。
- Unix Socket：本地权限、Protobuf/JSON 编解码、Watch 流输出。

Outbound Adapters：

- PostgreSQL：Repository、Unit of Work、迁移和并发约束。
- OpenSearch：租户强制过滤、历史读取、查询和确定性投影。
- Kafka Producer：原始批次与 DLQ 发布。
- Redis：短期 Session Cache；不可成为控制面事实来源。
- SQLite/Segments：Agent 本地身份、策略、checkpoint 和有界事件段。
- Tetragon：Sensor Port、能力探测、策略渲染和进程监督。
- PKI/Filesystem/Archive：证书签发、内容与制品文件读写和归档验证。

Adapter 必须显式处理外部错误，禁止静默回退到 Noop 实现。Noop/Fake 只能由测试或显式开发 Bootstrap 注入。

### 6.5 Bootstrap 与 Cmd

Bootstrap 负责：

1. 加载并验证配置。
2. 创建具体 Adapters。
3. 创建 Application Services。
4. 注册 Inbound Adapters。
5. 管理启动、健康、优雅关闭和资源释放。

`cmd/*/main.go` 只负责命令选择、调用 Bootstrap、输出顶层错误并设置退出码。生产和开发 Bootstrap 必须使用不同的显式构造入口，例如：

```go
func NewProductionGateway(Config) (*Gateway, error)
func NewDevelopmentGateway(Config) (*Gateway, error)
```

生产入口不得因配置缺失自动选择开发 Adapter。

## 7. 事务边界

### 7.1 事务原则

- 事务由 Application Use Case 定义，而不是由 HTTP/gRPC Handler 或 Repository 自行拼接。
- 同一 PostgreSQL 事务只包含控制面关系数据，不跨 Kafka、Redis 或 OpenSearch 建立伪分布式事务。
- 跨存储可靠交接使用 Outbox、确定性 ID、幂等写入和 checkpoint，不使用“先写一半再 Save 全局快照”。
- 所有事务操作携带调用方 `context.Context`，禁止在请求路径中改用 `context.Background()`。

### 7.2 控制面事务

| 用例 | 同一事务内的写入 | 事务外动作 |
|---|---|---|
| 发布策略 | Policy 状态、Policy Audit | 无；Gateway 后续读取待生效状态 |
| 分配策略 | Assignment、Audit、可选 Control Command | Session Cache 通知可以事务后执行 |
| 创建响应 | Response Decision、Response Command、Audit | Gateway 后续下发 |
| 审批响应 | Approval、Command 状态、Audit | 达到条件后由 Gateway 下发 |
| 创建注册 | Enrollment、Token Hash、Audit | 返回一次性明文令牌 |
| 签发证书 | 消耗 Bootstrap、Enrollment 状态、Certificate | CA 签名应在受控流程中完成，数据库提交失败不得暴露有效注册结果 |
| 取消注册 | Certificate 撤销、Unenrollment 状态、Receipt | Agent 完成回报作为独立幂等事务 |
| 控制确认 | Command/Ack 状态、Session cursor、Audit | Redis Touch 在提交后执行 |

证书签名涉及外部私钥操作。Application 先在事务外验证 CSR 和候选身份，再执行签名，并在单一事务中以幂等 key 提交签发结果。若提交失败，重试必须复用或安全替换候选证书，不能产生两个同时有效的业务授权。

### 7.3 数据面可靠交接

Gateway 接收批次：

```text
mTLS 身份验证
  -> 批次身份和限额校验
  -> 幂等性检查
  -> Kafka 可靠发布
  -> 记录 Session/checkpoint
  -> 返回 accepted/duplicate
```

只有 Kafka 可靠发布成功，或确认同一批次已经发布，才能返回 `accepted`/`duplicate`。Redis 更新失败不得改变可靠接收结论，但必须产生可观测错误。

Worker 处理批次：

```text
读取 Kafka
  -> Contract 解码与永久格式校验
  -> 读取租户限定历史和策略
  -> Domain 分析
  -> OpenSearch 确定性投影
  -> 保存必要控制面 Metrics
  -> commit offset
```

- 临时依赖错误：不提交 offset，返回 retryable。
- 永久非法消息：可靠写入 DLQ 后提交 offset。
- 投影局部失败：使用确定性文档 ID 重试，不把部分成功报告为整批成功。

### 7.4 Agent 本地原子边界

策略或内容激活分为 Prepare 和 Commit：

```text
读取当前快照
  -> 解析、展开、编译和能力校验
  -> 生成不可变 Candidate
  -> 原子持久化 Candidate
  -> 切换 Runtime 引用
  -> 报告 Ack 和 Health
```

Prepare 失败不得改变持久化状态或运行时。持久化失败不得切换运行时。运行时切换后的上报失败可以重试，但不得回滚已经持久化并成功应用的有效策略。

Checkpoint 只有在远端返回 accepted 或 duplicate 后推进；retryable、rejected、超时和未知响应均不得推进。

## 8. 禁止依赖规则

### 8.1 允许依赖矩阵

| 来源 | Domain | Application | Ports | Adapters | Bootstrap/Cmd | Contracts |
|---|---:|---:|---:|---:|---:|---:|
| Domain | 是 | 否 | 否 | 否 | 否 | 否 |
| Application | 是 | 是 | 是 | 否 | 否 | 否 |
| Ports | 是 | 否 | 是 | 否 | 否 | 否 |
| Adapters | 是 | 是 | 是 | 是 | 否 | 是 |
| Bootstrap/Cmd | 是 | 是 | 是 | 是 | 是 | 是 |
| Contracts | 否 | 否 | 否 | 否 | 否 | 同层 |

### 8.2 明确禁止项

1. Domain 禁止导入：
   - `net/http`、gRPC、Kafka、SQL、Redis、OpenSearch 客户端；
   - `packages/contracts/proto/*` 和任何生成代码；
   - `os`、`flag`、具体文件路径或环境变量读取；
   - Application、Ports、Adapters、Bootstrap。
2. Application 禁止导入：
   - `database/sql`、PostgreSQL driver；
   - OpenSearch、Kafka、Redis、Tetragon 具体包；
   - HTTP/gRPC Handler 和 Protobuf Message；
   - `context.Background()`，除应用根生命周期构造外。
3. Ports 禁止：
   - 返回 `sql.Row`、HTTP Request/Response、gRPC Stream、Kafka Message；
   - 使用具体 Adapter 配置；
   - 通过空租户或布尔参数隐藏全局权限。
4. Adapters 禁止：
   - 决定策略版本、审批资格、状态迁移等领域规则；
   - 绕过 Application 直接组合多个 Repository 完成业务用例；
   - 在生产配置缺失时静默使用 Noop/Fake/Insecure 实现。
5. Bootstrap/Cmd 禁止：
   - 承载业务分支；
   - 执行 Repository 查询或写入；
   - 复制 Application 流程。
6. 跨产品禁止：
   - Agent 导入 `apps/manager/internal/*`；
   - Manager 导入 `apps/agent/internal/*`；
   - 通过 `packages` 共享可变领域实体；
   - Console 或 CLI 直接读取内部数据库格式。

### 8.3 自动化治理

新增架构契约测试，基于 `go list -json` 检查项目内 import：

- `*/internal/domain/*` 只能导入标准库允许子集和同产品 Domain。
- `*/internal/application/*` 只能导入同产品 Domain、Ports 和标准库。
- `*/internal/ports/*` 不得导入 Adapters、Bootstrap 或 Cmd。
- 非 Adapter 包不得导入具体平台实现。
- `apps/agent` 与 `apps/manager` 之间不得直接依赖。

CI 同时检查：

- 非生成 `.go` 文件不超过 500 行；
- 新增或修改函数原则上不超过 50 行；
- 禁止新增 `SaveState`、全局 `Save()` 和无租户 Repository API；
- 禁止 Domain 导入 Protobuf 生成包。

## 9. 现有包迁移映射

迁移类型定义：

- **直接迁移**：职责清晰，主要调整目录和移除少量类型依赖。
- **拆分迁移**：保留实现，但按 Domain、Application、Port、Adapter 拆开。
- **废弃重写**：废弃当前抽象，复用业务规则、测试和底层实现，建立新用例边界。

### 9.1 Agent

| 现有包 | 类型 | 目标位置 |
|---|---|---|
| `management` | 直接迁移 | `domain/management` |
| `event/context` | 直接迁移 | `domain/event/processcontext` |
| `detection/matcher` | 直接迁移 | `domain/detection/matcher` |
| `sensors/fake` | 直接迁移 | `adapters/sensor/fake` |
| `telemetry/ringbuffer` | 直接迁移 | `application/telemetry/buffer` |
| `config` | 拆分迁移 | `adapters/config`、`bootstrap/config` |
| `content` | 拆分迁移 | `domain/content`、`application/content`、`adapters/filesystem` |
| `control` | 拆分迁移 | `domain/policy`、`application/{policy,enrollment,response}` |
| `detection` | 拆分迁移 | `domain/detection/{compiler,runtime}`、`application/detection` |
| `event/normalize` | 拆分迁移 | `domain/event`、`application/pipeline`、Contract Mapper |
| `localstore` | 拆分迁移 | Agent Ports、`adapters/{sqlite,segments}` |
| `localapi` | 拆分迁移 | `adapters/inbound/unix` |
| `remoteapi` | 拆分迁移 | `adapters/{inbound,outbound}/grpc` |
| `policy` | 拆分迁移 | `domain/policy`、`application/policy` |
| `sensors/runtime` | 拆分迁移 | `application/sensor`、Sensor Port |
| `sensors/linux/tetragon` | 拆分迁移 | `adapters/sensor/tetragon`、`adapters/system/process` |
| `tamper` | 拆分迁移 | `domain/health`、`adapters/system/tamper` |
| `telemetry` | 拆分迁移 | `domain/telemetry`、`application/telemetry` |
| `telemetry/dataappend` | 拆分迁移 | DataAppender Port、gRPC/JSONL Adapters |
| `daemon` | 废弃重写 | Application Services、`bootstrap/agent.go` |

`daemon.AgentRuntime` 在全部调用方迁移后删除，不保留兼容型全局容器。

### 9.2 Manager、Gateway 和 Worker

| 现有包 | 类型 | 目标位置 |
|---|---|---|
| `auth` | 直接迁移 | `adapters/inbound/http/auth` |
| `platform/redis` | 直接迁移 | `adapters/outbound/redis` |
| `store/migrations` | 直接迁移 | `adapters/outbound/postgres/migrations` |
| `analytics/converge` | 拆分迁移 | `domain/detection/convergence` |
| `analytics/correlate` | 拆分迁移 | `domain/detection/correlation` |
| `analytics/entity` | 拆分迁移 | `domain/investigation/entity` |
| `analytics/graph` | 拆分迁移 | `domain/investigation/graph` |
| `analytics/evidence` | 拆分迁移 | `domain/investigation/evidence` |
| `analytics/incident` | 拆分迁移 | `domain/investigation/incident` |
| `analytics/rarity` | 拆分迁移 | `domain/detection/rarity` |
| `distribution` | 拆分迁移 | `domain/artifact`、`application/manager/artifact`、Archive Adapter |
| `platform/kafka` | 拆分迁移 | inbound/outbound Kafka Adapters |
| `platform/opensearch` | 拆分迁移 | Search、History、Projection Adapters |
| `store/postgres` | 拆分迁移 | PostgreSQL Repository 与 UnitOfWork Adapters |
| `analytics/ingest` | 废弃重写 | Worker Application 分析用例 |
| `api` | 废弃重写 | HTTP Adapter 加 Manager Application Use Cases |
| `gateway` | 废弃重写 | gRPC Adapter 加 Gateway Application Use Cases |
| `ingest` | 废弃重写 | Kafka Adapter 加 Worker Application Use Cases |
| `store/backend` | 废弃重写 | `bootstrap/storage.go` |
| `store` | 废弃重写 | Manager Domain、Ports 和各 Repository |

### 9.3 共享 Packages 与外部入口

| 现有模块 | 类型 | 目标位置或处理 |
|---|---|---|
| `contracts/proto/*` | 直接保留 | Wire Contract，不进入 Domain |
| `contracts/schema` | 直接保留 | Contract 校验工具 |
| `sensor-sdk/contract` | 拆分迁移 | 公共插件契约保留，Agent 内部规则移出 |
| `tlsconfig` | 拆分迁移 | TLS 加载工具保留，安全模式进入 Bootstrap/Application |
| `eventmodel` | 拆分迁移 | 稳定行为标识保留，能力矩阵进入 Agent Domain |
| `policy` | 废弃重写 | Contract、Agent Policy Domain、Manager Policy Domain |
| `response` | 废弃重写 | Contract、Manager Response Domain、Agent Response Domain |
| `contracts/controlmodel` | 废弃重写 | Wire DTO 与两侧 Domain 分离 |
| `contracts/health` | 拆分迁移 | Wire Health DTO 与两侧 Health Domain 分离 |
| 四个 `cmd` | 拆分迁移 | 薄入口加各自 Bootstrap |
| `apps/cli` | 拆分迁移 | 命令解析与 HTTP/Unix Client Adapters |
| `apps/console` | 直接保留 | 独立前端和 BFF，只依赖 Manager HTTP Contract |

## 10. 安全、错误和可观测性

### 10.1 安全上下文

Manager HTTP Adapter 从验证后的 JWT 构建 `tenant.Actor`；Gateway gRPC Adapter 从验证后的 mTLS 证书构建 `AuthenticatedAgent`。调用者请求体、Header 或 Protobuf 中自报的 tenant/agent 只能用于一致性校验，不能建立身份。

所有 Application Command 均包含经 Adapter 建立的安全上下文。Application 不接受匿名的租户级操作。

### 10.2 Gateway 安全模式

生产 Gateway 必须具备服务端证书、私钥、Client CA 和客户端证书强制校验。无 TLS 或 Token-only 模式只能通过显式 Development Bootstrap 启动，并默认限制在 loopback。

### 10.3 错误分类

Domain 和 Application 使用稳定错误类别：

```text
InvalidArgument
Unauthenticated
PermissionDenied
NotFound
Conflict
FailedPrecondition
ResourceExhausted
RetryableDependency
Internal
```

Adapter 将其映射为 HTTP Status、gRPC Code 或 Kafka disposition。Domain 错误不得包含 SQL、URL、密钥路径或外部响应正文。

### 10.4 可观测性

- Application 在用例开始和结束记录结构化结果，不记录敏感载荷。
- Adapter 记录传输、依赖延迟和错误类别。
- Domain 不直接写日志或 Metrics。
- Metrics label 禁止包含不受限的 Agent ID、请求 ID 或路径等高基数字段。
- 数据丢弃、队列溢出、解析失败、策略激活失败和 DLQ 写入必须显式进入 Health、Audit 或 Metrics。

## 11. 测试策略

| 层 | 测试重点 | 外部依赖 |
|---|---|---|
| Domain | 状态机、不变量、算法、边界条件、属性测试 | 无 |
| Application | 授权、调用顺序、事务、失败传播、幂等 | Fake Ports、Fake Clock |
| Ports Contract | 所有 Adapter 实现的共同语义 | 内存与真实 Adapter 契约套件 |
| Adapters | SQL、映射、协议、限额、错误分类 | PostgreSQL/OpenSearch/Kafka 等受控环境 |
| Bootstrap | 安全默认值、配置完整性、资源关闭 | 进程级测试 |
| E2E | standalone、managed、策略、上传、调查、响应 | VM/容器拓扑 |

必须新增以下回归矩阵：

1. 两租户 Agent、Health、Event、Signal、Incident、Overview、Metrics 和 Rarity 隔离。
2. Gateway 无 mTLS、错误证书、撤销证书、身份不一致和合法证书矩阵。
3. 策略 Prepare/Commit 每个失败点均保留上一有效版本。
4. Kafka 发布、OpenSearch 投影、DLQ 和 offset 提交的故障注入矩阵。
5. PostgreSQL 与内存测试 Repository 的同一 Port Contract。
6. 重复命令、重复批次、重连和超时后的幂等行为。

## 12. 实施策略

目标架构一次确定，实施按以下垂直切片推进：

1. 建立架构契约测试、Domain 基础值对象、Clock、ID 和错误类型。
2. 修复租户查询、全局 Metrics/Overview 和 reset 语义，建立租户强制 Ports。
3. 建立生产/开发 Bootstrap，Gateway 默认 fail closed。
4. 迁移 Manager Policy 用例和 PostgreSQL Unit of Work，作为完整参考切片。
5. 迁移 Enrollment、Control、Response、Identity 和 Artifact。
6. 迁移 Gateway 数据面和控制面。
7. 迁移 Worker 与 Analytics Domain，隔离 Protobuf 和 OpenSearch。
8. 迁移 Agent Management、Policy、Content 和 Detection。
9. 迁移 Agent Event Pipeline、Telemetry、Local API、Remote API 和 Sensor Adapters。
10. 删除旧 `Store`、`Daemon`、共享业务模型和兼容 Facade，收敛目录与文档。

每个切片遵循：先写失败测试、引入新接口、迁移一个完整调用链、删除对应旧路径、运行单元/集成/E2E 测试、原子提交。禁止长期维护新旧两套可写路径。

## 13. 风险与控制

| 风险 | 控制措施 |
|---|---|
| 巨大重构导致长期不可合并 | 按垂直用例切片，每个切片保持可运行 |
| 模型映射增加样板代码 | 只在真实边界映射，不为同层对象重复建 DTO |
| Go 循环依赖 | Domain 按上下文拆包；Ports 使用稳定领域类型；Bootstrap 单向装配 |
| 新旧路径状态分叉 | 每个切片迁移后立即删除旧写路径 |
| 事务与 Kafka/OpenSearch 不一致 | Outbox/幂等 ID/checkpoint，不构造跨系统事务 |
| 性能退化 | 保留基准测试，对 Detection、Batch、Projection 建立预算 |
| 架构形式化过度 | 接口只建立在进程、存储、传输、时间和高风险业务边界 |
| 安全修复被目录移动掩盖 | `fix` 与 `refactor` 分开提交，先安全修复后结构迁移 |

## 14. 不在本设计范围

- 不改变公开 Protobuf 的业务语义或版本兼容策略；需要变更时另立 Contract 设计。
- 不新增微服务或拆分部署单元；Manager、Gateway、Worker 仍保持现有进程边界。
- 不引入通用 DI 框架、事件溯源框架或分布式事务框架。
- 不因为重构新增产品功能、检测规则或 UI 页面。
- 不把 OpenSearch、Redis 或 Kafka 提升为控制面事实来源。
- 不要求一次提交完成全部迁移；“一步到位”指统一目标架构，不指巨型不可验证提交。

## 15. 最终验收

1. 目标目录、接口和依赖规则全部落地，架构契约测试通过。
2. 旧 `AgentRuntime`、`store.Store`、`ManagerStore`、Gateway 大 Backend 和 Ingest Processor 抽象被删除。
3. Agent、Manager、Gateway、Worker 的 `cmd` 均为薄入口。
4. Domain 不依赖 Contracts 或基础设施，Application 不依赖具体 Adapter。
5. PostgreSQL 事务边界与本文用例表一致，不存在全量快照回写。
6. 租户隔离和 Gateway mTLS 安全矩阵全部通过。
7. standalone 离线自治、策略原子切换、可靠 checkpoint、Worker offset/DLQ 不变量保持成立。
8. 单元、竞态、集成、功能、检测、性能和发布测试达到仓库既有验收要求。
9. `docs/architecture.md`、配置参考、开发文档和测试文档更新为实现后的实际架构。
10. 所有非生成核心文件和函数满足仓库规模治理要求。
