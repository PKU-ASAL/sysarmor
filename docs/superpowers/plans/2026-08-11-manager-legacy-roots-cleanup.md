# Manager Legacy Roots Cleanup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 清理 Manager 空目录和历史根包，将 HTTP/JWT 能力迁入 inbound adapter，并为纯 Worker Application Engine 增加 domain 单元测试。

**Architecture:** HTTP composition 与 JWT verifier 位于 `adapters/inbound/http`，无生产调用方的平台 package 直接删除。Worker application 只接收 domain 类型，测试不经过 Protobuf 或 mapper。

## Global Constraints

- 不保留旧 `internal/api`、`internal/auth`、`internal/platform` 的兼容转发包。
- Application/domain/ports 不得依赖 HTTP、JWT、Kafka、Redis 或 OpenSearch 实现。
- 每一项行为变更先写失败测试，再实现最小代码。

### Task 1: Add Worker Engine domain tests

**Files:** `apps/manager/internal/application/worker/processing/engine_test.go`.

- [ ] Add tests for empty engine, enabled cloud analysis, disabled cloud rule, and rarity baseline injection.
- [ ] Run the focused package tests and confirm the new assertions fail for missing behavior.
- [ ] Adjust only the minimal Engine behavior needed; rerun focused tests.

### Task 2: Migrate HTTP and JWT roots

**Files:** `apps/manager/internal/adapters/inbound/http/auth/*`, `.../manager/*`, `bootstrap`, cmd and tests.

- [ ] Move auth files to inbound HTTP auth package and update imports.
- [ ] Move API composition files to inbound HTTP manager package and update bootstrap/cmd/tests.
- [ ] Remove old root directories and update architecture exemptions.
- [ ] Run manager tests and architecture contracts.

### Task 3: Delete unused platform and empty roots

**Files:** `apps/manager/internal/platform/kafka`, `redis`, `opensearch`, `adapters/outbound/store`, related contracts/docs.

- [ ] Prove each package has no production imports.
- [ ] Delete the unused packages and empty directories.
- [ ] Remove stale layout exemptions and run full repository tests, race, vet, and diff checks.

