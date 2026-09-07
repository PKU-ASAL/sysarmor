# Streaming Detection Concepts

本文用一条完整链路介绍 SysArmor Streaming 的检测概念：事实如何变成 Signal，Detector
如何形成 Finding，Nodlink 如何把多个异常节点组织成 Campaign，最终怎样生成 Incident。

## 一、最短链路

```text
Event
  -> Endpoint/Cloud Signal
  -> Detector
  -> DetectionFinding
  -> EvidenceSubgraph + Conclusion Signal
  -> Incident
```

Nodlink 在 Detector 内部额外维护：

```text
MODEL+CANDIDATE Signal
  -> Terminal
  -> Campaign
  -> HopSet / ISG
  -> DetectionFinding
```

## 二、公共领域对象

### Event

Event 是系统中已经发生的不可变事实，例如进程执行、文件写入、网络连接。

Event 只回答“发生了什么”，不直接回答“是不是攻击”。它是 Normalize 之后的最小事实
原子，云端图和 Detector 都从 Event 派生视图。

### Signal

Signal 是规则、模型、图或系统检测方法产生的统一消息。Signal 不是 Candidate 的
同义词，也不是 ModelCandidate 的独立消息类型。

Signal 的两个正交字段决定分类：

```text
detector_kind = RULE / MODEL / GRAPH / SYSTEM
stage         = CANDIDATE / CONCLUSION
```

常见例子：

| 分类 | 含义 |
|---|---|
| `ENDPOINT + MODEL + CANDIDATE` | Agent 发现的进程异常线索 |
| `ENDPOINT + RULE + CANDIDATE` | Agent 规则产生的候选线索 |
| `CLOUD + RULE + CONCLUSION` | 云端规则关联结论 |
| `CLOUD + GRAPH + CONCLUSION` | Nodlink 产生的图结论 |

Signal 是公共传输和查询对象，会进入 Kafka、Projection 或 OpenSearch。

### Incident

Incident 是平台面向调查和响应的案件对象。它可以由一个或多个 DetectionFinding
组成，拥有稳定 ID、状态、首次/最后观察时间、证据和响应生命周期。

当前实现按 Finding 驱动：Nodlink 为每个 Campaign 输出独立 `DetectionFinding`，
Investigation 以稳定 `correlation_key` 生成对应 Incident。

## 三、证据对象

### Evidence

Evidence 是支撑检测判断的总称，不是单一 protobuf 类型。它可以是 Event 引用、实体
引用、摘要或图结构。

### Signal EvidenceBundle

Signal 内嵌的 `EvidenceBundle` 用于解释单个 Signal：包含 `event_refs`、实体和摘要。

它适合表达“这个规则为什么命中”。

### EvidenceSubgraph

`EvidenceSubgraph` 是节点和边组成的精简溯源图：

```text
EvidenceSubgraph
├── GraphNode[]
└── GraphEdge[]
```

每条 `GraphEdge` 带 `event_refs`，因此可以从图边追溯回原始 Event。Nodlink 对外输出
的精简攻击图位于每个 `DetectionFinding.evidence`。

EvidenceSubgraph 是 Finding 或 Incident 携带的证据字段。最短路径逻辑作为可复用的
Evidence Provider，由结论型 Detector 组合进自己的 Finding。

## 四、Detector SDK 对象

### Detector

Detector 是纯算法组件，声明输入、状态和版本，读取标准事实并返回 DetectionResult。
Detector 不直接读 Kafka、OpenSearch、PostgreSQL 或 Agent 私有状态。

### DetectionResult

DetectionResult 是一次 Detector 调用的运行时返回信封，包含：

```text
algorithm_name/version
derived_signals
findings[]
diagnostics
state_update
```

每个 `DetectionFinding` 必须同时携带一个结论 Signal、一个 EvidenceSubgraph、
contributors 和可审计引用。Nodlink 和 `rule-correlation-v1` 都按此输出；最短路径
只提供图连接能力，由这两个结论型 Detector 组合进自己的 Finding。
运行时结构为：

```text
DetectionResult
├── findings: DetectionFinding[]
├── diagnostics
└── state_update
```

### DetectionFinding

DetectionFinding 是一个完整、自洽的检测发现，结构为：

```text
DetectionFinding
├── correlation_key
├── conclusion: Signal
├── evidence: EvidenceSubgraph
├── contributors: Signal[]
├── event_refs
├── edge_refs
├── signal_refs
└── node_scores
```

一个 Finding 必须能独立回答：

1. 检测结论是什么；
2. 哪些上游 Signal 贡献了结论；
3. 哪张图证明了结论；
4. 后续 Incident 应该用哪个稳定关联键更新。

Finding 是 Streaming 内部合同，不新增独立 Kafka Topic。Conclusion Signal 和
Evidence 仍通过现有 `AnalysisArtifact` 投影。

## 五、Nodlink 私有对象

### Terminal

Terminal 是 Nodlink 在图内标记的异常目标节点。它通常来自一条合法的
`ENDPOINT + MODEL + CANDIDATE Signal`，包含：

```text
process node_id
model signal_id
local anomaly score
event_refs
model_digest
```

Terminal 不是 Signal 字段，也不会单独写入 Kafka。

### Campaign

Campaign 是 Nodlink 判断“这些 Terminal 可能属于同一条攻击链”的内部状态。它拥有
稳定 `campaign_id`、Terminal 集合、选中节点/边、模型版本和更新时间。

Campaign 可以跨多个 Batch 演化，但不等于 Incident：

```text
Campaign：算法内部假设
Finding：达到门槛后的完整检测发现
Incident：面向调查和响应的案件
```

无关 Terminal 应形成不同 Campaign；不同 `model_digest` 默认不合并；过期和 graph
rebuild 会重建相关 Campaign。

### HopSet

HopSet 是某个 Terminal 的有界局部邻域和路径集合。当前实现使用最多 10 个节点的
在线 Steiner 贪心基线，不是论文完整的 IV/HAS/Grubbs 实现。

### ISG

ISG（Information Subgraph）是 Nodlink 当前 Campaign 选中的节点和边的紧凑子图。它
来自共享 `ProvenanceGraph`，但属于 Nodlink 私有派生状态。

## 六、对象是否持久化

| 对象 | 位置 | 用途 |
|---|---|---|
| Event | Kafka、Flink state、OpenSearch | 事实和回放 |
| Signal | Kafka、Flink state、OpenSearch | 线索和结论 |
| Detector | Streaming Python 进程 | 算法执行 |
| DetectionResult | Detector 调用栈 | 一次计算返回值 |
| DetectionFinding | Streaming 内部合同 | 绑定结论、图和 contributors |
| Terminal | Nodlink keyed state | 图内异常节点 |
| Campaign | Nodlink keyed state | 跨 Batch 攻击链状态 |
| HopSet/ISG | Nodlink keyed state | 有界图搜索结果 |
| Incident | AnalysisArtifact/OpenSearch | 调查和响应案件 |

## 七、当前状态与目标

当前已经完成：

- Nodlink 输出真实 `EvidenceSubgraph`；
- 图包含真实节点、边和 `event_refs`；
- Campaign 有界、可跨 Batch、可过期和恢复；
- Conclusion Signal 和 Incident 已打通；
- Replay 可以重放真实 managed 产物。

当前缺口：

- Incident 的 first_seen/last_seen/revision 稳定 upsert 仍需完善；
- Nodlink 的 HAS、Grubbs 和完整 IV 论文增强仍未实现；
- Evidence pullback 仍是控制链路，尚未回拉真实原始材料；
- Detector SDK 尚未提取为独立可复用包。
