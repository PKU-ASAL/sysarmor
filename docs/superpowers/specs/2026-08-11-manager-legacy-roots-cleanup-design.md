# Manager Legacy Roots Cleanup Design

## 目标

彻底清理 Manager 分层架构之外的空目录和历史根包，将仍有效的 HTTP/JWT 能力迁入 inbound adapter，删除无生产调用方的 platform facade，并为纯 Worker Application Engine 建立直接的 domain 单元测试。

## 目录归属

- `apps/manager/internal/auth` 迁移到 `apps/manager/internal/adapters/inbound/http/auth`。
- `apps/manager/internal/api` 迁移到 `apps/manager/internal/adapters/inbound/http/manager`。
- `apps/manager/internal/platform/kafka`、`platform/redis` 及空的 `platform/opensearch` 直接删除。
- `apps/manager/internal/adapters/outbound/store` 等空目录直接删除。
- 不保留旧 import path 的类型别名、转发包或兼容 facade。

## 依赖方向

Bootstrap 和 cmd 只依赖新的 inbound HTTP manager/auth adapter。HTTP manager adapter 可以依赖 application、ports、domain 和其他 adapter contract，但 application/domain/ports 不得反向依赖 HTTP/JWT 实现。

平台能力只允许存在于 `adapters/inbound`、`adapters/outbound` 或 bootstrap 组装代码中。没有生产调用方的旧 platform package 不迁移、不抽象，直接删除。

## Worker Engine 测试

测试直接向 `application/worker/processing.Engine` 输入 domain Event、Signal 和 detection Policy，不经过 Protobuf 或 contract mapper。至少覆盖：

1. nil/空 Engine 返回空分析结果。
2. 满足关联条件时产生 cloud signal 和 incident。
3. Detection Policy 禁用对应 cloud rule 时不产生派生结果。
4. rarity baseline 注入会参与 analyzer 评分路径，且不引入 adapter 依赖。

## 兼容与行为

HTTP 路由、JWT 校验、公开 JSON/HTTP 语义保持不变。仅改变内部 Go import path 和目录归属。旧 `internal/api`、`internal/auth`、`internal/platform` 路径在完成后必须物理不存在。

## 验收

- `rg` 不再发现生产代码导入旧根包。
- 分层架构契约不再将 Manager `api/auth/platform` 列为 legacy exemption。
- `go test ./apps/manager/... -count=1`、`go test ./... -count=1`、目标 race tests、`go vet ./apps/manager/...` 全部通过。
- `git diff --check` 通过，工作区无空 legacy 目录。
