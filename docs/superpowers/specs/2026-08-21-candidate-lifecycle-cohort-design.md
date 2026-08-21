# Candidate 生命周期精确 Cohort 设计

## 结论

Candidate 生命周期验收必须证明各阶段处理的是同一组 Candidate，不能用累计计数相等代替身份一致性。

实现采用两条互补合同：

1. Agent 在实验结束后只读取一次正式健康快照，冻结 Candidate 计数和 Event sequence 截止点。
2. Worker 在 PostgreSQL 中按现有 Signal ID 持久化 correlated、projected、reference rejected 结果，并基于正式 Signal/Event 身份生成验收结果。

测试探针产生的 Event 位于冻结截止点之后，不属于实验 cohort，不能填补实验窗口内的 backlog。

## 目标

- 精确区分 `agent_created`、`agent_spooled`、`gateway_accepted_unique`、`gateway_duplicate_ack`、`gateway_rejected`、`worker_correlated`、`worker_projected`、`worker_reference_rejected` 和 `worker_pending_backlog`。
- Candidate subject 与当前触发 Event subject 不一致时，在正式 DataBatch 合同边界明确拒绝。
- 缺失指标返回 unavailable 或使门禁失败，禁止将缺失静默解释为零。
- Ring Buffer observation gap 仅表示测试观察覆盖；Endpoint Store 淘汰属于正式数据损失，必须阻断。
- 保持 PostgreSQL 为 Manager/Worker 唯一生产路径，不增加兼容实现。

## 非目标

- 不改变 Learning 模型、特征、阈值或 Candidate 生成算法。
- 不把 benchmark run ID、测试时间窗等实验概念加入生产 Signal 合同。
- 不为了指标拆分破坏 Worker 对一个 DataBatch 的业务投影原子性。
- 不处理 learning-only 正常 Candidate 率和 RSS 优化。

## Cohort 定义

实验 cohort 由以下条件共同确定：

- tenant、agent、policy 和正式标签与当前实验一致；
- Signal 是 endpoint Model Candidate；
- Candidate 具有唯一 subject；
- Candidate 的当前触发 Event 位于同一 DataBatch；
- 触发 Event sequence 不大于实验冻结的 `eventSequenceCutoff`。

冻结快照只读取一次。快照保存：

- `created`
- `spooled`
- `gatewayAccepted`
- `gatewayDuplicateAck`
- `contractRejected`
- `gatewayRejected`
- `eventSequenceCutoff`

Agent 快照不再轮询。若冻结时 Agent 阶段尚未收敛，门禁按真实 backlog 失败，不允许后来由探针 Candidate 补数。

## Worker 生命周期状态

Candidate 不引入独立实体或 ID。它始终表示 `stage=CANDIDATE` 的 Signal，生命周期身份就是现有 `Signal.id`。

PostgreSQL 新增正式的 `worker_signal_processing` 记录，以 `(tenant_id, signal_id)` 为幂等键，仅记录 endpoint Model Candidate Signal，至少保存：

- DataBatch ID；
- subject process ID；
- 当前触发 Event ID 和 Event sequence；
- correlated、projected 或 reference rejected 处理状态；
- failure class；
- 更新时间。

correlated/projected 状态必须具有完整 subject 和当前触发 Event 身份。reference rejected 状态允许对应字段为空，用 failure class 明确记录缺失或冲突原因；这不是兼容路径，而是拒绝事实本身。

`correlated` 表示 Candidate 已通过 DataBatch 引用合同并进入分析结果；`projected` 表示对应 Worker projection 已成功提交。两者必须来自不同的业务事实，不能再由同一个 Candidate 总数同时赋值。

引用合同成功后，Worker 先用独立的幂等事务记录 correlated 状态；进程若在投影前失败，状态仍可观察，批次仍保持 processing 并由 lease 机制重试。projected 状态随正式业务投影和批次完成在同一事务提交。这样不拆散业务投影原子性，同时能真实区分“已关联、未投影”。所有状态迁移受 batch claim token 和单调状态约束保护，失败重试不得重复累计或倒退状态。

## 数据流

1. Agent 创建 Candidate，并校验 subject 与当前 Event 身份。
2. Candidate 进入正式 DataBatch，Agent 分别记录 created 和 spooled。
3. Gateway 校验 DataBatch，唯一接收与 duplicate ACK 分开计数。
4. Worker 按 batch claim 处理：引用合同成功后，以 Signal ID 幂等记录 correlated 事实。
5. Worker projection 成功提交后，在业务投影事务内推进 projected 状态；引用失败按 Signal ID 记录 reference rejected。
6. 实验在 workload/cooldown 后读取一次 Agent 快照，冻结 Event sequence。
7. 报告从 Worker 正式结果中按 cohort 条件过滤 Candidate，计算各阶段和 backlog。

## 门禁语义

生命周期通过必须同时满足：

- Agent contract rejected = 0；
- Agent spool backlog = 0；
- Gateway rejected = 0；
- Agent delivery backlog = 0；
- Worker reference rejected = 0；
- Worker pending backlog = 0；
- cohort correlated = cohort projected；
- Endpoint Store drop = 0；
- 所有必需产物和指标存在。

`gatewayDuplicateAck` 是可靠重试的诊断指标，不单独导致失败。`observationGap` 是测试观察能力指标，不等价于生产链路丢失，也不单独导致失败。

## 错误处理

- Agent 冻结快照缺少任一必需字段：实验无效。
- Worker 生命周期文件或数据库字段缺失：unavailable，并导致 managed 生命周期门禁失败。
- 数量为负、projected 大于 correlated、同一 batch 状态冲突：合同错误，明确失败。
- 超时：保留冻结 cohort 和最后 Worker 状态，报告 pending backlog，不回退到动态累计水位。

## 测试与验收

TDD 必须先覆盖：

- health 查询新增 Candidate 不能填补冻结 cohort backlog；
- 超时仍保留冻结 cutoff；
- Worker 指标文件缺失或字段缺失不能解释为零；
- correlated 成功、projected 失败可被独立观察；
- Worker 重试不会重复累计；
- Endpoint Store drop 使门禁失败；
- Ring Buffer observation gap 不使生命周期门禁失败；
- Candidate subject/Event subject 不一致被 Agent、Gateway、Worker 合同拒绝。

最终验收：

- 相关 Go/Python/Shell 测试全部通过；
- PostgreSQL 集成测试验证状态迁移和幂等；
- managed quick VM 中 learning-only 与 hybrid 生命周期收敛；
- hybrid graph recall 和 conclusion recall 均不低于 0.90；
- 报告中 Model Candidate 样本数与冻结 cohort 的 Worker projection 数一致。
