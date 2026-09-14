# SysArmor 云端溯源检测性能调优复盘

## 汇报结论

本轮完成了云端 Detection 的平台化、可观测化和性能治理。主要长尾并非 Nodlink 本身，而是 DetectionState 在同一批次内对乱序 Event 反复全量重建 Provenance Graph。将重建延迟到批次结束并合并后，fresh hybrid E2E 的 Detection p95 从 632.7 ms 降至 158.6 ms，p99 从 1,592.9 ms 降至 174.4 ms，apply 最大单批从 1,565.3 ms 降至 143.2 ms。

端云链路也已恢复闭环：Agent 模型加载、Candidate 上传、Kafka/Flink 处理、Cloud Conclusion 和 Incident 投影均可验证。最终 fresh hybrid 产生 95 个 Cloud Candidate、4 个 Cloud Conclusion 和 4 个 Incident。

## 问题与证据

早期 hybrid 运行曾出现单窗口 10 秒到 30 秒长尾、Kafka lag 和 Cloud Conclusion 缺失。逐 Detector 指标显示 Nodlink 单批最大约 15 ms，而 apply 阶段占主要耗时。

优化前的 fresh run（`20260914T130042Z-hybrid-fresh`）中，22 个窗口的分段数据为：

| 分段 | 累计耗时 | 最大单批 |
|---|---:|---:|
| apply：状态更新、排序、淘汰、建图 | 2763.8 ms | 1565.3 ms |
| Detector analysis | 99.5 ms | 29.2 ms |
| artifact 构建 | 22.3 ms | 5.1 ms |

最慢批次一次触发 36 次图重建，Nodlink 仅耗时 1.79 ms。隔离复现中，预置 2000 条 Event 后加入 36 条乱序 Event，顺序输入不重建图，乱序输入触发 36 次重建。

## 架构演进

当前云侧保持 Normalize、Detection、Projection 三 Job 边界。Detection 通过 `DetectorInputs`、`DetectorDelta`、`DetectionResult`、`DetectionFinding` 和 `StateRequirements` 提供统一插件合同；Registry 负责按策略选择 Detector 和判断触发条件。Campaign、Terminal、ISG 保留在 Nodlink 内部，避免把某一种图算法固化为平台核心。

平台统一负责输入标准化、事件时间、窗口、状态恢复、失败诊断、指标和投影；Detector 负责算法、私有状态、Finding 和 Evidence。生产与实验 Job 使用独立资源命名空间，支持相同规范化输入下的效果和成本对比。

## 已实施优化

1. 普通 Event 在没有受影响 Detector 时跳过分析。
2. Detector 按声明的输入变化触发，Nodlink 消费增量 Candidate。
3. ProvenanceGraph 提供一次有界 BFS 和短期路径缓存。
4. DetectionState 在批次内累计 graph dirty，批末只执行一次 `from_events()`。
5. 指标改为真实 `graph_rebuild_calls`，不再累计逐记录 dirty 标志。
6. Agent spool 读取使用 `event_seq_end` 对比 `ManagedFromSequence`，纯 Signal batch 不受 Event cursor 过滤。
7. benchmark 默认使用 fresh VM/enrollment，避免历史 spool、checkpoint 和 epoch 污染。
8. Candidate 报告区分累计值与 `created_delta`、`spooled_delta`、`accepted_unique_delta`、`duplicate_ack_delta`。

## 性能结果

| 指标 | 优化前 | 优化后 |
|---|---:|---:|
| Detection p50 | 27.5 ms | 26.6 ms |
| Detection p95 | 632.7 ms | **158.6 ms** |
| Detection p99 | 1592.9 ms | **174.4 ms** |
| apply 最大单批 | 1565.3 ms | **143.2 ms** |
| Nodlink 最大单批 | 15.0 ms | 持续观测 |

优化后 fresh run（`20260914T151352Z-hybrid-rebuild-batched`）产生 4 个 Cloud Conclusion 和 4 个 Incident；Candidate 上传、Gateway 接收和 Projection 均有产物。

## 端云问题复盘

- VM platform source 排除 `dist/` 导致 artifact feed 404；已显式复制 `dist/release`。
- release config 合并丢失 `learning` 段；已沿用现有配置合并框架保留模型路径和 trust keys。
- 重复 enrollment 和同名策略版本冲突；已支持已发布 seed policy 复用，并为 benchmark policy 使用 run 级后缀。
- 复用 Agent 时累计 Candidate 计数污染 cohort；已记录 before snapshot 并计算 delta。
- Manager 查询曾受短 TTL JWT 影响；benchmark 默认 TTL 提升到 3600 秒，并延长分析等待。

## 遗留风险

当前 p99 样本量仍较小，不能直接作为长期生产 SLO。`accepted_unique_delta` 仍可能包含 drain 时清理的历史 backlog，严格 cohort 需要按 Signal ID、Batch ID 和 enrollment epoch 做集合级核对。

Graph 仍是有界拓扑关联：尚未实现有向因果路径、时间单调约束、完整路径排序、Steiner Tree 和攻击阶段推理。大规模 Graph 全量重建、多租户热点和状态公平性仍需持续 profiling。

## 下一步建议

1. 让 Metrics 同时输出 graph rebuild 原因、图节点/边数量和路径缓存命中率。
2. 以相同 NormalizedTelemetry 和 truth labels 建立 Detector baseline/experiment 对照矩阵。
3. 接入第二个独立 Detector，验证新增算法无需修改平台核心。
4. 将 Candidate cohort 从计数差分升级为 Signal/Batch 集合守恒。
5. 在有证据的热点上再引入节点/边倒排索引、连通分量或 Java Operator；不先扩大架构复杂度。

## 验证记录

- streaming 领域测试：193 个通过。
- Candidate/策略/运行时合同测试：相关测试通过。
- fresh hybrid E2E：Cloud Candidate、Conclusion、Incident 均成功生成。
- 历史结果目录：`test/.results/performance-endpoint/20260914T130042Z-hybrid-fresh`、`test/.results/performance-endpoint/20260914T151352Z-hybrid-rebuild-batched`。
