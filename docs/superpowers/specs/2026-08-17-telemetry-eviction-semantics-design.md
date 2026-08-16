# Telemetry Eviction 语义收口设计

## 结论

Telemetry Bus 的固定容量历史窗口发生覆盖时，只记录为 stream eviction，不视为端到端数据丢失，也不触发 Agent `degraded`。只有 Sensor、Batcher 或 Storage 发生真实 drop 时才触发降级。

## 契约

- 删除 Bus `EventDropped` 和 `SignalDropped`，不保留旧字段映射。
- Bus adapter 内部统一使用 `EventEvicted` 和 `SignalEvicted`。
- eviction 只通过 `Streams.EventEvicted` 和 `Streams.SignalEvicted` 对外暴露。
- `Telemetry.DroppedEvents` 只聚合 `Batcher.DroppedEvents`；`Telemetry.DroppedSignals` 只聚合 `Batcher.DroppedSignals`。
- Proto `TelemetryBusHealth` 删除 `event_dropped` 和 `signal_dropped`，并保留 field number 3、7 及字段名，禁止未来复用。
- JSON `TelemetryBusHealth` 同步删除旧字段。

## 健康语义

- stream eviction：Health 保持 `ok`。
- Sensor 超过配置 drop/parse threshold：Health 为 `degraded`。
- Batcher dropped batch/event/signal：Health 为 `degraded`。
- Storage dropped event：Health 为 `degraded`。

## 报告

性能报告从 `streams.eventEvicted` 读取观察窗口淘汰量，并与 Sensor drop、Batcher drop、Sender sentEvents 分开展示。报告不再读取或解释 `telemetryBus.eventDropped`。

## 验收

- eviction-only 单元测试返回 `ok`。
- batcher-drop 单元测试返回 `degraded`。
- Bus 容量覆盖测试验证 `EventEvicted/SignalEvicted`。
- 生成后的 Proto、Agent、contracts 和 performance report 测试全部通过。
- 全仓搜索不再存在 Bus `EventDropped/SignalDropped` 或 JSON `eventDropped/signalDropped`。
- 使用现有 medium artifacts 重新生成报告时，显示 stream eviction，但不误称主链路丢失。
