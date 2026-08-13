# Tenant Telemetry Transaction Design

## 1. 结论

租户 Metrics 与 Rarity 以 PostgreSQL 为唯一事实源。每个 DataBatch 以
`(tenant_id, batch_id)` 作为幂等键，在一个数据库事务中完成批次登记、指标增量与
Rarity 增量。重复批次返回成功的 duplicate 结果，不执行分析、索引投影或任何累计更新。

不保留全局 Metrics/Rarity、进程内快照覆盖、事务外二次保存等兼容路径。

## 2. 当前问题

| 问题 | 根因 | 后果 |
| --- | --- | --- |
| Worker 重启后累计归零 | 进程内 map 覆盖数据库快照 | 历史计数丢失 |
| 多 Worker 丢更新 | 多进程对同一 JSON 快照 last-write-wins | 指标与基线不可信 |
| 重试重复累计 | 状态写入缺少 batch 幂等键 | 同一批次重复计数 |
| 部分提交 | `Save()` 与 `SaveMetrics()` 分属两个事务 | 返回失败但数据已部分提交 |
| Rarity 重载行为变化 | 数据库 `global` 被转换为空键 | 未知 workload 回退失效 |

## 3. 目标边界

### 3.1 Application Port

```go
type TelemetryStateRepository interface {
    BeginBatch(context.Context, tenant.ID, BatchID) (BatchDisposition, error)
    CommitBatch(context.Context, TelemetryBatchDelta) error
    Metrics(context.Context, tenant.ID) (Metrics, error)
    Rarity(context.Context, tenant.ID) (rarity.Baseline, error)
}
```

实现阶段可将 `BeginBatch` 与 `CommitBatch` 收敛为一个 adapter 原子方法，但 application
必须能在分析和索引前判断 duplicate。为避免“预登记后进程崩溃”造成批次永久跳过，批次账本
使用 `processing/completed` 状态和 lease；只有 completed 才判定为 duplicate，过期 processing
允许重试。

### 3.2 PostgreSQL Adapter

新增 `telemetry_batches`：

- 主键：`tenant_id, batch_id`
- 字段：`status, lease_until, created_at, completed_at`
- 状态：`processing, completed`

正常数据流：

1. `ClaimBatch` 短事务插入 processing；已 completed 返回 duplicate；未过期 processing 返回 busy/retryable；过期 processing 重新 claim。
2. 执行纯分析与幂等 OpenSearch 投影。
3. `CommitBatch` 单事务锁定 processing 记录，合并 Metrics，原子累加 Rarity，并更新为 completed。
4. 任一步失败回滚；processing lease 到期后可以安全重试。

Metrics 使用行锁读取和写回单租户 JSON；Rarity 使用
`ON CONFLICT ... DO UPDATE SET signal_count = signal_count + EXCLUDED.signal_count`。

### 3.3 非 PostgreSQL Adapter

Memory/File adapter 实现同一状态机。File adapter 在一个原子 rename 中持久化账本、Metrics
和 Rarity；仅用于开发和测试，不承担多进程并发。

## 4. Processor 数据流

```text
validate identity
  -> claim batch
     -> duplicate: return success without side effects
     -> busy: return retryable
     -> claimed: load tenant rarity
        -> analyze
        -> idempotent OpenSearch bulk projection
        -> commit metrics + rarity + completed atomically
```

Processor 不再调用 `RecordDataBatchIngestForTenant`、`ObserveRaritySignalsForTenant`、
`SaveMetrics` 或通过完整 Store 快照投影 telemetry。

## 5. 事务与失败语义

| 失败点 | 结果 |
| --- | --- |
| claim 失败 | 无分析、无投影、无累计 |
| 分析失败 | processing 保留至 lease 到期，无累计 |
| OpenSearch 失败 | processing 保留至 lease 到期，无累计 |
| telemetry commit 失败 | Metrics、Rarity、completed 全部回滚 |
| completed 批次重放 | 成功 duplicate，无副作用 |

OpenSearch 文档 ID 必须由 tenant、batch 和业务稳定标识生成，重试覆盖同一文档，不追加重复文档。

## 6. 禁止规则

- 禁止以进程内累计值覆盖 PostgreSQL 租户累计值。
- 禁止在完整平台状态快照中投影 PostgreSQL telemetry。
- 禁止一个批次通过两个数据库事务提交 Metrics 与 Rarity。
- 禁止吞掉 telemetry repository 错误并返回零值。
- 禁止将 `default` 或全局累计作为多租户兼容路径。
- 禁止依赖对象指针同步 tenant/global Signal 视图。

## 7. 验收标准

- Worker 重启后同一租户继续累计，不丢历史。
- 两个 Store 并发提交不同 batch，最终计数等于两者之和。
- 相同 batch 并发或重放只累计一次。
- Metrics、Rarity 或 completed 任一写入失败时全部回滚。
- Rarity 的 `global` 回退在重启前后一致。
- 重复批次不执行分析和 OpenSearch 投影。
- 全仓测试与架构依赖契约通过。
