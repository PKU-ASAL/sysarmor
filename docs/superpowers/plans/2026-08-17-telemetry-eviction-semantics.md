# Telemetry Eviction Semantics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use test-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将观察流 Ring Buffer 淘汰与真实数据丢失完全拆分，避免 eviction 导致 Agent health degraded。

**Architecture:** Bus 只产生 eviction 统计，Streams 是 eviction 的唯一对外契约；Health Application 只把 Batcher drop 汇总为 Telemetry drop。Proto 删除错误字段并 reserve 原 field numbers，性能报告改读 Streams。

**Tech Stack:** Go、Protocol Buffers、Python unittest。

## Global Constraints

- 不保留旧字段映射或双字段。
- 不通过扩大 Ring Buffer 隐藏问题。
- Sensor、Batcher、Storage 的真实 drop 仍必须触发 degraded。

### Task 1: 锁定 Health 与 Bus 语义

**Files:**
- Modify: `apps/agent/internal/application/health/service_test.go`
- Modify: `apps/agent/internal/adapters/telemetry/bus_test.go`

- [ ] 增加 eviction-only 为 ok、batcher drop 为 degraded 的测试。
- [ ] 将 Bus 覆盖测试的期望 API 改为 `EventEvicted/SignalEvicted`。
- [ ] 运行定向测试，确认因旧实现或旧字段而失败。

### Task 2: 迁移内部类型和 Application 语义

**Files:**
- Modify: `apps/agent/internal/adapters/telemetry/bus.go`
- Modify: `apps/agent/internal/domain/health/model.go`
- Modify: `apps/agent/internal/application/health/service.go`
- Modify: `apps/agent/internal/bootstrap/runtime/health_source.go`

- [ ] 重命名 Bus adapter 统计为 eviction。
- [ ] 删除 Domain Bus drop 字段。
- [ ] Health Application 仅聚合 Batcher drop。
- [ ] Streams 从 Bus eviction 读取统计。
- [ ] 运行 Agent health/telemetry 测试。

### Task 3: 收口对外 Contracts

**Files:**
- Modify: `packages/contracts/proto/controlplane/v1/agentcontrol.proto`
- Generate: `packages/contracts/proto/controlplane/v1/agentcontrol.pb.go`
- Modify: `packages/contracts/health/health.go`
- Modify: `apps/agent/internal/adapters/contracts/health.go`
- Modify: `apps/agent/internal/bootstrap/runtime/local_control_status.go`
- Modify corresponding tests.

- [ ] 删除 `TelemetryBusHealth` drop 字段并 reserve 3、7 和旧字段名。
- [ ] 运行 `make api` 更新生成代码。
- [ ] 删除 JSON/adapter/local-control 旧字段映射。
- [ ] 运行 contracts 与 runtime 测试。

### Task 4: 更新报告并完成验收

**Files:**
- Modify: `test/suites/performance/endpoint/human_report.py`
- Modify: `test/suites/performance/endpoint/test_human_report.py`

- [ ] 测试报告从 Streams 展示 eviction，同时展示真实 drop 和 sender sent 数。
- [ ] 修改报告实现并重新生成现有 medium 报告。
- [ ] 运行 Endpoint performance tests、`go test ./apps/agent/...` 和 `go test ./packages/contracts/...`。
- [ ] 搜索确认旧 Bus drop 字段无残留并整理原子提交。
