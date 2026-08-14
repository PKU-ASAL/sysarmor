# Task 11 Shared Business Model Closure Design

## 结论

Task 11 采用按产品归属清理共享业务模型的方案：删除无消费者的 `packages/eventmodel`，将仅由 Agent 使用的 `packages/policy` 和 `packages/response` 迁入 Agent Domain，保留仍由 Agent 与 Manager 共同使用的 `packages/contracts/controlmodel` 和 `packages/contracts/health`。

迁移不引入 alias、forwarding package 或双生产路径。Protobuf、JSON、SQLite 和其他外部格式转换留在 Adapter；Domain 只保留纯业务规则和产品模型。

## 当前证据

- `packages/eventmodel` 没有 Agent、Manager、packages、test 的生产消费者。
- `packages/policy` 的消费者全部位于 Agent；该包包含默认策略、Endpoint、Collection、Detection 和 Telemetry 业务模型，并直接依赖 Protobuf 与 `packages/response`。
- `packages/response` 的消费者全部位于 Agent；该包包含响应授权、审批、作用域和决策规则，属于 Agent 业务模型而非跨产品协议。
- `packages/contracts/controlmodel` 同时被 Agent SQLite 和 Manager PostgreSQL policy mapper 使用，属于跨产品 Control 持久化/协议边界。
- `packages/contracts/health` 同时被 Agent Runtime/Adapter 和 Manager HTTP/identity 使用，属于跨产品健康投影契约。

## 目标结构

```text
apps/agent/internal/domain/policy/
  model.go
  defaults.go
  validation.go

apps/agent/internal/domain/response/
  model.go
  decision.go

apps/agent/internal/adapters/contracts/
  policy.go
  response.go
  health.go        # 保留并明确为跨产品契约

packages/contracts/controlmodel/  # 保留跨产品契约
packages/contracts/health/        # 保留跨产品契约
```

`domain/policy` 和 `domain/response` 不得导入 Protobuf、SQLite、Tetragon、网络、文件系统、JSON/YAML 或其他 `packages` 业务模型。需要 JSON/Protobuf 的输入输出由 Adapter mapper 完成。

## 迁移顺序

1. 为目标 Domain API 搬运并补齐现有 policy/response 行为测试，先观察目标 API 的 RED。
2. 迁移 policy 纯模型、默认值、验证和响应引用，拆除对 Protobuf 与 `packages/response` 的直接依赖。
3. 迁移 response 决策、审批、作用域和授权规则到 Agent Domain。
4. 在 Agent Adapter 中建立旧 JSON/Protobuf 与 Domain 类型之间的显式 mapper，切换所有 Agent 生产调用方。
5. 扫描确认 `packages/policy`、`packages/response` 无消费者后删除两个目录。
6. 删除无消费者的 `packages/eventmodel`，并清理其文档或测试引用。
7. 对 `controlmodel`、`health` 增加跨产品契约合同和 README 归属说明，不迁移、不复制、不建立兼容别名。

## 行为与兼容边界

- 默认策略、策略版本、策略作用域、Collection/Detection/Telemetry 语义保持不变。
- 响应默认 observe-only、授权判断、审批阈值、角色判断和作用域匹配语义保持不变。
- 既有 JSON 字段、Protobuf 字段、SQLite 持久化内容和 Manager/Agent Control 合同保持不变；兼容转换只能存在于 Adapter。
- `controlmodel` 的 `legacy_mtls` 和 completion 协议常量继续保留，因为它们属于已发布跨产品协议，不是旧业务实现。
- `health` 继续作为跨产品健康投影契约存在，不在 Agent Domain 中复制一份同名共享模型。

## 错误处理

- Domain 验证返回显式错误或不可变 Decision，不静默采用另一套策略或响应默认值。
- Adapter mapper 对非法外部输入返回带字段上下文的错误。
- 删除共享包前必须保证所有调用方已切换；禁止通过 alias 或 forwarding 保持旧 import 可用。

## 测试与验收

### Domain

- policy 默认值、JSON 语义等行为迁移为 Domain 行为测试。
- policy 版本、作用域、规则覆盖和模式验证测试。
- response 默认策略、破坏性动作拒绝、审批阈值/角色去重、作用域匹配测试。

### Adapter

- policy/response Protobuf 和 JSON mapper round-trip 测试。
- 非法字段、缺失版本、未知响应动作的显式错误测试。

### 架构合同

- `packages/policy`、`packages/response`、`packages/eventmodel` 不存在。
- Agent Domain 不导入 `packages/*` 业务模型或基础设施。
- `controlmodel`、`health` 仍有 Manager 与 Agent 消费者，且被标记为跨产品契约。
- 不存在 Agent legacy exemption、alias 或 forwarding package。

### 全量门禁

- `go test ./apps/agent/... ./apps/manager/... -count=1`
- `go test -race ./apps/agent/... ./apps/manager/... -count=1`
- `go vet ./apps/agent/... ./apps/manager/...`
- 架构/布局合同
- standalone endpoint、managed topology、Detection 矩阵
- `git diff --check` 和工作树清洁

Task 11 完成后，Task 12 再负责最终性能门禁、文档更新和 Tasks 9-12 的总体验收；本设计不扩大到新的检测规则、响应动作或 PostgreSQL 并发测试。
