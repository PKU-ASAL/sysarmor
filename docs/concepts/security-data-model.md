# 安全数据模型

Event 是事实，Signal 是发现，Evidence 是依据，Incident 是安全分析报告。

本文是 SysArmor 核心安全数据概念的唯一正式定义。系统架构解释这些对象如何流动，调查指南解释如何使用它们，Protobuf 定义精确 wire contract。

## Event：事实

Event 是 Agent 或 sensor 实际观察到的一次规范化行为事实，例如进程执行、文件访问、网络连接或身份变化。

Event 不表达恶意判断。采集策略、sensor 能力、资源预算和数据丢失都可能使事实不完整；缺少 Event 不能直接证明行为没有发生。后续检测和分析只能引用 Event，不能修改它来迎合结论。

## Signal：发现

Signal 是系统从 Event、既有 Signal、运行状态或实体关系中提炼出的检测发现。Signal 不等同于传统告警，也不天然表示恶意。

每个生产 Signal 必须回答三个正交问题：

| 维度 | 回答的问题 | 取值 |
|---|---|---|
| `detector_kind` | 使用什么检测方法？ | Rule、Model、Graph、System |
| `stage` | 发现成熟到哪一步？ | Candidate、Conclusion |
| `where` | 在哪里产生？ | Endpoint、Cloud |

三个维度互不替代。端侧可以产生 Conclusion，云侧也可以产生 Candidate；Model 表示检测方法，不表示对象类型。

## Stage：发现成熟度

| Stage | 含义 | Incident 收敛 |
|---|---|---|
| Candidate | 值得保留，但仍需关联或验证的候选发现 | 不能单独参与 |
| Conclusion | 已满足明确检测条件的结论性发现 | 可以参与 |

Candidate 和 Conclusion 是 Signal 的阶段，不是独立数据对象。Candidate 后续被提升时必须产生新的 Conclusion Signal，并通过 `signal_refs` 引用上游 Candidate；不得原地修改既有 Signal 的 Stage。

## DetectorKind：检测方法

| DetectorKind | 含义 | 当前能力 |
|---|---|---|
| Rule | 确定性规则或关联规则 | Endpoint/Cloud Candidate 与 Conclusion 已实现 |
| Model | Learning Model 异常检测 | Endpoint Candidate 已实现 |
| Graph | 图结构或路径算法检测 | 合同已定义，生产生成器尚未实现 |
| System | Agent 健康、自保护或篡改检测 | Endpoint Conclusion 已实现 |

正式文档和报告使用 `<DetectorKind> <Stage>` 描述具体发现：

- Rule Candidate
- Rule Conclusion
- Model Candidate
- Graph Conclusion
- System Conclusion

Model Candidate 的对象类型仍然是 Signal，其当前完整语义是：

```text
detector_kind = Model
stage = Candidate
where = Endpoint
```

不使用 Learning Signal、Model Signal 或 Terminal Signal 作为替代名称。

## Where：产生位置

`Endpoint` 表示 Signal 由 Agent 端侧产生，`Cloud` 表示 Signal 由 Worker 云侧分析产生。Where 只记录产生位置，不推导 Stage、DetectorKind 或可信度。

## Evidence：可复核依据

Evidence 是支持 Signal 或 Incident 的可复核依据，不是独立检测阶段，也不会脱离来源成为新的事实或结论。

当前有三种具体形态：

| 形态 | 内容 |
|---|---|
| Signal Evidence Bundle | Event、上游 Signal、实体、raw reference 和摘要 |
| Incident Evidence Subgraph | 贡献 Signal 形成的实体与关系子图 |
| Evidence Pullback Result | 通过受控流程获取的补充材料 |

当前 Evidence Pullback 已具备请求、下发和回传控制通道，但端侧结果仍是实体占位子图，不能表述为已经回拉真实 Event、raw reference 或原始文件。

## Incident：安全分析报告

Incident 是由相关 Conclusion Signal 和 Evidence 在明确 tenant、分析作用域、时间窗口和分析版本内收敛出的可重复安全分析报告。

Incident 不是人工案件或工单，不承载负责人、评论、SLA 和关闭状态。需要这些能力时应由独立 Case Management 管理，不能改变 Incident 的可重复分析语义。

## 数据流与引用

```text
Event
  -> Rule Candidate / Model Candidate / System Conclusion
  -> Rule Conclusion / future Graph Conclusion
  -> Evidence
  -> Incident
```

Signal 使用 `event_refs` 引用事实，使用 `signal_refs` 引用上游发现，并保留实体、lineage、规则或模型 provenance。Incident 保留贡献 Conclusion、Evidence 子图和稳定分析身份。

Event 与 Signal 不会因为重试而改变语义身份。新的输入可以使同一分析窗口重新计算 Incident，但不能把 Candidate 原地改成 Conclusion。

## 当前能力与目标能力

当前已具备 Rule Candidate、Rule Conclusion、Model Candidate、System Conclusion、Incident 收敛和初始 Evidence 子图。

Graph Conclusion、NodLink Hopset、Steiner Tree、完整因果路径恢复和真实原始材料回拉属于目标能力。Proto 中存在 Graph 枚举不表示这些生产能力已经实现。

Detection 产品语义中不存在 Terminal。该单词只允许用于：

- Protobuf 对历史字段号和名称的 `reserved` 声明；
- 一次性 OpenSearch 迁移测试的最小旧数据输入；
- 控制命令和协议拒绝等普通生命周期状态；
- 未来 Steiner Tree 算法内部的 `SteinerTerminal`。

## 不变量

- 生产 Signal 必须明确设置 `stage`、`detector_kind` 和 `where`。
- 可信边界必须拒绝 `UNSPECIFIED`。
- Model 当前只能产生 Endpoint Candidate。
- Model Candidate 必须包含完整模型 provenance 和有效 Event 引用。
- Model Candidate 不能携带 Rule provenance、Response Intent 或 Global Rarity。
- Incident 至少需要一个合法 Conclusion。
- Candidate 提升产生新 Signal，不修改旧 Signal。
- Evidence 必须可以回到其来源，缺失依据不能被静默解释成事实不存在。

