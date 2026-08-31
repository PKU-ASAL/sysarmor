# 调查指南

本文说明如何从 Event、Signal 和 Evidence 调查 Incident，并明确当前产品边界。概念定义见[安全数据模型](../concepts/security-data-model.md)，生产流见[系统架构](../architecture.md)，接口字段和查询参数以 [API 参考](../reference/api.md)为准。

## 调查目标

调查不是从一条“告警”直接跳到结论，而是回答四个问题：

1. 发生了什么可复核事实？
2. 哪些行为被提炼为 Signal，依据是什么？
3. 哪些 Signal 在什么作用域与时间窗口内形成 Incident？
4. 证据是否足以支持处置，仍缺少什么？

对应的数据路径是：

```text
Event -> Endpoint Signal -> Cloud Signal -> Incident
   \          |                |             /
    +----------+---- Evidence --+------------+
```

Signal 是检测发现，可以处于 Candidate 或 Conclusion 阶段，不天然等同于恶意告警。Incident 是可重复的安全分析报告，不是人工案件或工单。

## 调查前先固定边界

开始关联前确认：

- `tenant_id`：任何查询和关联都不能跨租户；
- Agent 与主机身份：Endpoint Signal 的平台文档身份按 tenant、Agent 和 Signal 隔离；
- 分析作用域：以 Agent 身份为锚，可选由 `scenario`、`workload` 标签细分；
- 时间范围：当前 Worker 使用以批次上界为终点的 15 分钟历史窗口；
- 策略与分析版本：相同数据在不同规则、内容或分析版本下可能产生不同派生结果。

分析作用域不是模糊的“相似数据”集合。缺少细分标签的数据按 Agent 身份隔离，不会自动被拼接进另一个场景；lineage 和实体用于解释上下文，但不是绕过 tenant 与作用域边界的通用关联许可。

## 第一步：阅读 Incident

从 Incident 获取当前调查入口：摘要、严重度、首次与末次观察时间、lineage、结论实体、correlation key、analysis version、贡献 Signal、Evidence 子图，以及收敛方法、分数和控制条件。Schema 还预留了 MITRE、seed 和 path 字段，但当前 Incident Builder 不填充它们，不能将空值解释为“没有对应技术或路径”。

先验证稳定身份，而不是先相信摘要：

- Incident ID 是否与 tenant、关联键和分析版本一致；
- 是否因重复批次或重试产生重复逻辑报告；
- 贡献 Signal 是否属于同一 tenant 和分析作用域；
- 首末观察时间是否覆盖预期行为阶段；
- 当前收敛方法、分数和 controls 是否与有效策略匹配；
- MITRE、seed 或 path 等预留字段是否确有数据来源，不能仅凭 Schema 存在就用于结论。

Incident 的确定性投影意味着相同语义输入会更新同一报告。报告内容可能随同一窗口内的新数据重算，但不应因 Kafka 重试而复制。

## 第二步：解释贡献 Signal

逐条检查 Endpoint Signal 和 Cloud Signal。下表描述 Signal Schema 可承载的信息；字段为空时必须回到具体生成器确认，不能假设所有 Signal 类型都会填充：

| 检查项 | 目的 |
|---|---|
| `where` | 区分端点低延迟判断与云侧关联结果 |
| `name`、`rule_id`、`rule_version` | 确认是什么规则产生，能否复算 |
| `severity`、`confidence`、`mode` | 区分风险表达、置信度和观察/执行模式 |
| `event_refs`、`signal_refs` | 回到输入事实或上游 Signal |
| `entities`、`lineage_id` | 理解主体、客体和进程关系 |
| `context_refs`、`ioc_refs` | 确认所用内容及版本 |
| `stage`、`detector_kind`、`cross_lineage` | 区分候选/结论、检测器来源和跨 lineage 意图 |
| `response_intent` | 查看建议，不将其误作已执行动作 |

Endpoint Signal 在本地行为流附近生成，适合解释低延迟规则命中。Cloud Signal 来自当前批次和同作用域历史窗口的组合。当前 Cloud Signal 构造器填充稳定 ID、名称、位置、阶段、检测器类型、风险、稀有度、实体、标签和上游 Signal 引用，尚未填充 `rule_id`、`rule_version`、`event_refs`、严重度、置信度和模式；调查时必须从 Incident 的贡献 Signal、有效策略和分析作用域补充验证。完整派生引用链是需要补齐的工程约束。

一个 Signal 可以表示值得保留的行为或异常，而非确定恶意。只有规则语义、上下文、Evidence 和收敛条件共同支持时，才应升级调查结论。

## 第三步：回到 Event

Event 是调查中的原子事实。检查行为类型、发生时间、Agent/主机、进程主体、对象、父进程稳定 ID、lineage、运行作用域、容器身份、标签和原始引用。

回看 Event 时重点验证：

- 时间顺序是否符合行为链，时间缺失是否影响推断；
- 进程、文件、socket 等实体是否由稳定标识连接；
- Event 是否来自同一 Agent 与运行作用域；
- Signal 引用是否存在，是否因本地淘汰而只能使用平台副本；
- 原始引用是否可用，规范化结果是否足以复核；
- collection、存储或 telemetry 是否报告丢弃和解析错误。
- `identity_status` 是否为 `unavailable`，以及 Evidence 中是否存在相应 gap/incomplete。

缺少 Event 不应被静默解释成“行为未发生”。应结合有效 collection policy、Agent health、storage-drop、batch drop、解析错误和上传 checkpoint 判断是未采集、未保存、未上传，还是确实不存在。

## 第四步：使用 Evidence

Evidence 按目标模型分为三个层次：

1. Signal 自带的轻量引用：Event、上游 Signal、实体和 raw reference。
2. Incident 的 Evidence 子图：由 Event 构建关系边，贡献 Signal 只选择调查种子。
3. 受控回拉的原始材料：目标能力，用于高风险调查补充，而不是生成 Incident 的前提。

当前控制面已经具备 Evidence pullback 请求、下发和结果回传通道，但 Agent 只根据 `target` 返回一个实体占位子图，不读取 Event、`raw_ref` 或其他原始材料。该结果只能验证控制链路，不能作为“原始证据已回拉”的证明。

当前 Worker 将同一 tenant、分析作用域和时间窗口内的当前与历史 Event 组织为进程、文件和 socket 图。进程执行形成父进程到子进程的边，文件写入和网络连接形成进程到对象的边；贡献 Signal 只提供最多 32 个种子。Evidence 取这些种子在最多 100,000 条 Event 上的最短路径并集。它可以回答“哪些已观测事实连接了这些发现”，但不是完整 Steiner Tree，也不能单独证明攻击意图或唯一攻击路径。

使用图结果时遵守：

- 每条生产图边必须带可追踪的 `event_refs`，Signal 不能单独生成因果边；
- 最短路径是拓扑结果，不等于最可能攻击路径；
- K-hop 是邻域裁剪，不等于因果边界；
- `gap` 节点和 `incomplete` 边表示身份无法恢复，缺失节点还可能源于策略、保留、上传或回拉限制；
- 补充 Evidence 不能修改原始 Event 或伪造既有引用。

## 第五步：判断结论与缺口

调查结果至少分为三类：

| 结论 | 条件 | 后续动作 |
|---|---|---|
| 证据充分 | 行为事实、Signal 来源、实体关系和策略版本相互一致 | 按授权流程响应或进入外部案件管理 |
| 需要补证 | 结论合理，但缺少关键 Event、原始材料或时间上下文 | 使用现有 Event 查询核对，或发布有限时间的加深采集策略；不要把当前 Evidence pullback 占位结果当作原始材料 |
| 不支持结论 | 作用域错误、规则不匹配、证据矛盾或关键假设无法成立 | 记录原因，修正规则或分析，不升级处置 |

临时加深采集必须通过版本化策略控制面，限定 tenant、Agent、行为、资源预算和结束条件。当前系统已具备策略发布能力和 Evidence pullback 控制链路，但实质原始材料采集、风险自动触发、窗口自动恢复和 Agentic 调查闭环仍是目标能力。

## 响应前检查

Signal 中的 response intent 只表达建议。执行前确认：

1. Incident 与 Evidence 是否支持该动作；
2. 动作是否在有效 Response Policy 的允许列表内；
3. tenant、Agent 和目标作用域是否精确；
4. 操作者、原因、审批和审计是否完整；
5. 动作是否可逆，如何撤销或恢复；
6. 重试是否幂等，Agent 是否返回最终确认。

当前 Incident 不保存人工案件状态。需要分派、评论、SLA 和关闭流程时，应交给独立案件管理系统，避免修改可重复分析报告的语义。

## 查询边界

本地排障与端点测试可通过 Agent Unix socket 查看健康、Event 和 Signal。包含 Gateway 与 Manager 的部署应通过 Manager API 查询平台数据；不要直接查询 Agent SQLite、事件段、PostgreSQL 表或 OpenSearch 内部索引作为稳定用户接口。

平台查询必须携带 tenant 上下文。派生数据通过稳定投影键去重；如果查询结果缺失，先检查 Gateway 接收确认、Kafka/Worker 状态、dead-letter、OpenSearch 必需写入以及分析作用域，而不是直接重放并忽略根因。

## 当前能力与限制

| 状态 | 调查能力 |
|---|---|
| 当前已具备 | Event、Endpoint/Cloud Signal 查询基础，15 分钟同作用域历史关联，稳定 Incident，贡献 Signal，Event provenance Evidence 子图，显式 gap/incomplete，K-hop 与最短路径算法，Evidence pullback 控制链路，确定性重算与投影 |
| 工程基础已具备但仍需产品化 | 从 Incident 连续下钻到所有原始材料、完整 Incident UI、调查过程中统一展示健康与数据缺口 |
| 目标能力 | 实质原始材料回拉、完整派生引用链、跨保留缺口的完整因果路径恢复、Steiner Tree、候选路径排序、攻击阶段推理、自然语言根因解释、分析员反馈学习、受约束的 Agentic 调查与策略建议 |

目标能力不能作为当前结论的证据。现阶段调查必须以可查询 Event、Signal、Evidence、策略版本和运行健康为准。

## 调查记录建议

外部案件或调查笔记至少记录：

- tenant、Agent、Incident ID、correlation key 和 analysis version；
- 查询时间范围和分析作用域；
- 关键 Signal、Event 与 Evidence 引用；
- 有效策略、规则和内容版本；
- 数据丢弃、解析、重试或回拉限制；
- 结论、未证实假设和下一步动作；
- 响应命令、审批、确认和恢复结果。

这样即使派生报告在同一窗口内重算，调查过程仍可复核。
