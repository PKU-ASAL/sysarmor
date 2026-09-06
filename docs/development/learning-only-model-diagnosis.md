# Learning-only 模型诊断设计

## 目的

在调整训练数据、模型参数或阈值前，先解释 managed learning-only 中“正常候选率 3.56%，攻击召回 0”的直接原因。诊断必须区分模型未命中与观测、身份、引用、投递链路缺口。

## 范围

本阶段只增强离线报告诊断，不改变 Agent 推理、模型包、阈值或门禁。输入沿用一次 managed run 已生成的 Event、Model Candidate、ProcessProfile 映射及 truth labels；输出进入 summary 的结构化诊断字段。

## 诊断模型

以 truth campaign 覆盖的全部 ProcessProfile 为 attack cohort，而不是只取直接承载 truth Event 的进程；其余 profile 为 normal cohort。对每个 attack profile 输出：

- profile id 与 campaign id；
- 关联的 truth event ids；
- 是否观察到 Model Candidate；
- Candidate id、score 与 event refs；
- 未命中原因。

未命中原因按可行动性排序，只选择一个主原因：

1. `truth_event_unmapped`：truth Event 无法映射到 ProcessProfile；
2. `candidate_observation_incomplete`：端侧观察 cohort 不完整，无法判断 profile 是否产生 Candidate；
3. `candidate_observation_unavailable`：缺少 frozen Candidate 总数，无法判断观察是否完整；
4. `profile_not_candidate`：端侧观察完整，profile 已建立但没有 Model Candidate；
5. `candidate_not_projected`：端侧 Candidate 已产生但 managed 投影中缺失；
6. `candidate_missing_truth_ref`：缺少 campaign 映射时，Candidate 已投影但未引用 direct truth Event；
7. `detected`：truth campaign 内任一 profile 的 Candidate 已投影，与现有 campaign seed recall 门禁一致。

每个 profile 另外输出 `projected_truth_candidate_ids` 和 `pending_truth_candidate_ids`。它们用于区分“campaign 已 seed”和“直接引用 truth Event 的 Candidate 是否仍在 backlog”，不改变 campaign 级主状态。

全局 identity gap、event-ref eviction、observation gap 和 stream backlog 作为运行级上下文展示，不能在没有逐 profile 证据时冒充根因。

## 验收标准

- 现有 `20260831T104939Z` learning-only 产物能给每个 attack profile 一个确定状态；
- 报告能区分“模型未候选”和“候选未投影/未关联”；
- 缺少可选诊断 artifact 时返回明确的 unavailable/unknown 信息，不影响既有门禁计算；
- 现有 learning 报告测试全部通过。

## 后续决策

- 若主因是 `profile_not_candidate`，再分析 attack/normal score 分布并扩大 calibration 数据；
- 若主因是映射、引用或投影缺口，先修运行时链路，禁止用调阈值掩盖；
- 只有链路完整后，才以独立 normal calibration 与 attack holdout 重新训练和校准。

## 已验证结论

`20260831T104939Z` 的失败不是攻击未越过模型阈值。端侧观察到 6 个攻击 campaign Candidate，其中 3 个直接属于 truth profile，score 分别为 `-6.812546`、`-7.573028` 和 `-7.600223`，均高于阈值 `-7.703413`。但 600 个 Gateway accepted Candidate 仅有 148 个完成 Stream projection，剩余 452 个形成 backlog；攻击 Candidate 位于后段，因此报告为 0 recall。

候选洪泛源于不具代表性的 6-profile training/calibration 数据。用独立 benchmark normal_activity 窗口重新训练后，406-profile calibration 的候选率为 `0.493%`；第三次正常 holdout 为 `0.513%`，4 个 truth attack profile 中有 2 个越过阈值，campaign seed recall 为 `1.0`。

## 数据准备

Training 与 calibration 必须来自不同 benchmark run，且只截取正常活动窗口：

```bash
python3 tools/learning_detector/pipeline.py collect \
  --input /path/to/events.scope.ndjson \
  --markers /path/to/markers.ndjson \
  --start-phase normal_activity_start \
  --end-phase normal_activity_done \
  --output /path/to/normal-training.ndjson
```

Calibration profile 数量必须至少为 `ceil(1 / target_rate)`。默认 `target_rate=0.005` 时至少需要 200 个 profile；不足时模型准备会显式失败，不再生成统计上无效的阈值。

## Detection 增量状态

DetectionState 以 `tenant + NUL + analysis_scope_key` 作为 Flink key 的同构缓存键。首次处理或发生 TTL/容量淘汰时从持久状态重建 ProvenanceGraph；普通 Event 只向已有图追加一条边。普通追加直接使用 ListState `add`，乱序或淘汰才全量重写。只有 `MODEL+CANDIDATE Signal` 的 scope 收到普通 Event 时不重新运行当前未声明相关输入的 Detector；出现匹配的 Signal 或图变化后恢复完整分析。

scope 只是计算范围，不是事件族。RuleCorrelation 仍要求 lineage 或图/实体关系，因而无共享 lineage、file、socket 的信号不会被增量路径合并。

learning-only RSS 门禁为 Agent steady RSS 绝对上限 `100 MiB`；hybrid 仍使用 rule-only steady RSS 加 `16 MiB` 的相对上限。

## 增量化验证

增量版 DetectionState 在 quick managed 采集中将 learning-only Candidate 收敛从 `12/17` 提升到 `17/17`，`stream_pending_backlog` 从 `5` 降为 `0`。本地 10,000 条“Model Candidate 后普通 Event”微基准耗时约 `0.148s`，吞吐约 `6.8 万条/s`；同一输入的增量图与强制全量重建结果一致。

Candidate cohort 超时现在会额外保存 `stream-jobs.json` 和 `stream-lag.txt`：前者来自 Flink JobManager，后者来自 Kafka consumer group describe，包含 Normalize、Detection、Projection 的运行状态和各 partition lag。这样固定等待窗口耗尽时，可以直接定位消费瓶颈，而不是只看到 Candidate 数量不足。
