# 溯源图检测平台下一阶段开发计划

术语统一见 [Streaming Detection Concepts](streaming-concepts-glossary.md)。本文中的
Detector 是算法组件，Signal 是统一消息，Campaign 是 Nodlink 私有状态，Incident 是
案件对象；Detector 的完整单次发现使用 `DetectionFinding` 表示。

本文定义 SysArmor 下一阶段的工程目标、模块边界、交付顺序和验收标准。计划对标 NodLink 等溯源图检测方法，但以真实端点效果、资源约束和可运维性为最终判断依据。

## 目标

下一阶段形成以下稳定链路：

    Agent 轻量预处理
      -> 标准化 Event
      -> ProvenanceEdge
      -> 可插拔 Detector
      -> Evidence / Conclusion
      -> Incident / Projection

目标不是复制论文实现，而是建立适合 SysArmor 的云端溯源检测平台：

- 在真实端点数据上保持可用的检测效果；
- 在 CPU、内存、网络和状态存储预算内运行；
- 用统一场景同时验证完整性、召回率、误报和延迟；
- 允许多个图检测算法独立接入、比较、灰度和部署；
- 保持控制平面、数据接入、流式检测和查询投影相互隔离。

## 工作分工

### Agent：事实采集和轻量预处理

Agent 负责：

- Event 采集策略和 ProcessProfile 生命周期；
- 进程、文件、Socket 的身份连续性；
- 因果骨架 Event；
- Endpoint Rule Signal 和 `MODEL+CANDIDATE Signal`；
- 本地有界存储、spool 和可靠上传；
- 端侧 CPU、RSS、EPS 和丢失指标。

Agent 不负责完整攻击图、Steiner Tree、长期跨主机关联或最终 Incident 结论。

### Streaming 基础层：统一数据和状态

Normalize、Provenance 和 Flink Runtime 负责：

- Kafka Topic 合同和规范化 Event；
- Event 到 ProvenanceEdge 的确定性转换；
- tenant、analysis scope、watermark 和 late Event；
- state TTL、checkpoint、恢复和明确淘汰；
- rejection、DLQ、backpressure 和运行时指标。

基础层不实现具体算法结论，也不访问 PostgreSQL。

### Detector：图上的异常发现

Detector 负责从统一 Event、ProvenanceEdge 和 Signal 中发现异常，输出统一的
DetectionResult/DetectionFinding。Candidate 只是 `Signal.stage`，Model 只是 `Signal.detector_kind`，
不存在独立的 ModelCandidate 消息类型。Detector 不直接读写 Kafka、OpenSearch 或
PostgreSQL。

首批 Detector：

| Detector | 用途 |
|---|---|
| rule-correlation-v1 | 当前规则关联基线 |
| shortest-path provider | 当前最短路径 Evidence 基线，由结论型 Detector 复用 |
| nodlink | 将端侧模型 Signal 映射为 Terminal，执行 ISG/Hopset/Campaign 检测 |
| steiner-approx-v1 | 近似 Steiner Tree |
| risk-propagation-v1 | 风险沿 ProvenanceEdge 传播 |
| graph-ml-v1 | 后续图特征或图模型实验 |

### Investigation：证据和案件

Investigation 负责：

- Evidence 子图和 ProvenanceEdge 引用；
- Detector 结论的聚合、去重和引用校验；
- Incident 和调查解释。

Nodlink Detector 自己负责 Terminal 映射、ISG、Hopset、路径和 Campaign 判断；
Investigation 不理解算法私有状态，只负责把标准 DetectionResult 组织为案件。
Projection 只负责确定性写入外部查询系统。

### 评测与运维：证明效果和成本

每个 Detector 必须在相同 Event、workload、攻击场景、时间窗口和资源约束下比较：

- graph recall；
- conclusion recall；
- precision 和误报率；
- detection latency；
- CPU、RSS、EPS；
- state size、checkpoint 和恢复时间；
- Evidence 节点、边和引用数量；
- `MODEL+CANDIDATE Signal` 生命周期和数据缺口。

## 统一模块合同

### 输入合同

所有 Detector 只接受统一的：

    NormalizedEvent
    ProvenanceEdge
    Signal
    AnalysisContext

AnalysisContext 至少包含 tenant、analysis scope、时间窗口、策略版本和输入 watermark。
端侧模型发现使用统一 `Signal` 表示，其分类为
`where=ENDPOINT + detector_kind=MODEL + stage=CANDIDATE`。Nodlink 根据该 Signal 的
process entity 和 `event_refs` 映射内部 Terminal；Terminal 不是公共消息字段。

### Detector 合同

逻辑接口应保持以下形态：

    Detector
    ├── name
    ├── version
    ├── required_inputs
    ├── state_requirements
    ├── analyze(...)
    └── diagnostics

### 输出合同

所有算法统一输出：

    DetectionResult
    ├── derived_signals
    ├── evidence
    ├── conclusions
    ├── incidents
    ├── event_refs
    ├── edge_refs
    ├── signal_refs
    ├── algorithm_name
    └── algorithm_version

每个结果还必须携带 policy ID/version、输入窗口、watermark 和状态诊断，确保结果可审计、可重算、可比较。

## 模块边界

    Normalize
      只负责格式和身份标准化

    Provenance Builder
      只负责 Event -> ProvenanceEdge

    Detector
      只负责从事实和图中发现异常

    Investigation
      只负责 Evidence、Conclusion、Incident

    Projection
      只负责写入 OpenSearch 和下游结果 Topic

    Control Plane
      只负责租户、Agent、Enrollment、Policy、Response 和 Audit

必须保持以下约束：

1. Detector 不访问 PostgreSQL、OpenSearch 或 Agent 本地状态。
2. Detector 不依赖 Agent 私有结构和传输格式。
3. Projection 不按算法名称复制特殊写入分支。
4. 算法失败不能阻塞其他算法和基础 Normalize。
5. 每个算法必须有独立单元、回放、状态恢复和性能测试。
6. 算法状态必须有明确 TTL、watermark、checkpoint 和版本语义。
7. 不恢复旧 Worker、旧 Topic、双写或兼容读取路径。

## 分阶段交付

### 阶段一：统一底座和 Detector 合同

交付：

1. 定义 NormalizedEvent、ProvenanceEdge、AnalysisContext。
2. 定义 Detector 和 DetectionResult。
3. 将现有规则关联迁移为 rule-correlation-v1。
4. 将现有最短路径逻辑收敛为可复用 Evidence provider，不单独发布没有结论的 Detector。
5. 建立 Detector Registry。
6. 为结果补充算法版本、输入窗口和引用。
7. 建立单元测试、回放测试和状态测试。

退出标准：

- 现有 graph/conclusion recall 不下降；
- 新增 Detector 不需要修改 Normalize 和 Projection；
- 每个 Detector 可以单独启用、禁用和比较；
- 现有 managed quick/medium 链路保持通过。

### 阶段二：内置 Nodlink Detector

交付：

1. 复用 Agent 的 FastText、VAE 和 SV 输出，不在云端运行第二套异常模型；
2. 校验 `MODEL+CANDIDATE Signal` 的模型身份、process entity 和 `event_refs`；
3. 将端侧模型 Signal 映射为算法内部 Terminal；
4. 构建有界 ISG，并实现 Hopset 或等价路径索引；
5. 连接跨窗口 Terminal，形成候选攻击链；
6. 基于 Terminal 异常度、时间和图结构计算 Campaign 分数；
7. 输出带完整节点、边和 Signal 引用的 Evidence 与 `GRAPH+CONCLUSION Signal`；
8. 显式处理 late Event、身份 gap、缺失父进程、TTL 和状态恢复。

退出标准：

| 指标 | 目标 |
|---|---|
| graph recall | >= 0.90，并持续提升 |
| conclusion recall | >= 0.90 |
| Evidence 冗余 | 低于最短路径并集基线 |
| 处理延迟 | 在 watermark SLA 内 |
| 状态增长 | 有界且可预测 |
| checkpoint 恢复 | 恢复前后结果一致 |
| 缺失身份 | 使用显式 gap，不制造关系 |

### 阶段三：多算法生产化

交付：

1. 允许多个 Detector 消费同一标准化输入；
2. 建立统一算法级资源和效果指标；
3. 按 Policy Bundle、tenant 和 scope 选择 Detector；
4. 支持灰度、回放和 A/B 比较；
5. 隔离算法失败、状态和 checkpoint；
6. 对资源差异明显的算法拆分独立 Flink Job；
7. 建立版本化状态迁移和长期基准数据集。

## 部署策略

首版内置 Nodlink 在同一 Detection Job 内通过 Registry 运行，共享标准化 Event 和 Provenance 状态，避免重复消费 Kafka 和重复维护基础图状态。

当算法出现明显不同的 CPU、内存、状态、checkpoint、GPU 或发布周期要求时，再拆成独立 Flink Job。独立 Job 只消费版本化标准化 Topic，输出统一分析结果，不创建算法私有的安全数据存储。

## 后续优先级

1. 完善 Incident 稳定 upsert：first_seen、last_seen、revision 和 status。
2. 增加 Finding 级 truth evaluation 和 Campaign duplication 指标。
3. 完善 Nodlink IV、HAS、Grubbs 与独立 HopSet 索引。
4. 将 Detector 合同提取为可复用 SDK 和 testkit。
5. 决定高成本算法是否按实测拆分独立 Flink Job。

## 责任闭环

    Agent         负责事实完整、端侧 Signal 及时、上传可靠
    Streaming     负责 Event 标准化、图状态和流处理正确
    Detector      负责算法发现有效
    Investigation 负责证据和案件可信
    评测体系       负责效果和性能可证明
    控制平面       负责策略、版本和审计可追溯

每项交付必须同时提交代码、测试、运行指标和文档更新。只有在真实场景和资源门禁均通过后，才能将阶段标记为已验证。
