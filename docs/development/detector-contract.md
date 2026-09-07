# Detector 合同与模块设计

本文定义 SysArmor 云端 Detector 的输入/输出合同、模块边界和首批实现。设计对标 [provenance-detection-plan](provenance-detection-plan.md) 的阶段一，借鉴 PIDSMaker 的可插拔工程模式；Nodlink 的算法边界以原始端云流程为准，不照搬 PIDSMaker 的统一图学习适配。目标是：**新增一个 Detector 不修改 Normalize、Provenance Builder、Investigation 和 Projection**。

## 1. 目标与原则

两条硬约束决定所有取舍：

1. **兼容性**：现有 `rule-correlation` 与 `provenance-shortest-path` 无缝迁移成 Detector，graph/conclusion recall 不下降，managed quick/medium 保持通过。
2. **可拓展性**：后续 `nodlink`、`steiner-approx`、`risk-propagation`、`graph-ml` 只增不改基础层。

从 PIDSMaker 吸收的三条机制：

| PIDSMaker 机制 | 我们采纳 |
|---|---|
| 声明式配置（`used_methods`）+ 工厂分发（字符串→类） | Detector 由 policy 声明启用，`DetectorRegistry` 按 name 实例化 |
| 数据准备层可插拔（construction/featurization/batching） | 输入以「最小事实原子」为底，视图分级，重量模型可自建数据视角 |
| 算法输出统一、内部实现自由 | `DetectionResult` 统一承载 Signal、Evidence、引用及可选 `node_scores`，Incident 由 Investigation 聚合 |

## 2. 输入合同：最小事实原子 + 分级视图

### 2.1 普适底层是 `NormalizedEvent`

Detector 只接受标准化输入，不碰 Kafka、protobuf 解码、原始日志。**`NormalizedEvent` 是「最小事实原子」**——图、序列、特征、时序图都能从事件流派生。所以只要提供事件流，任何模型都能自给自足，合同不需要预判每个模型要什么视角。

```python
@dataclass
class DetectorInputs:
    events: EventWindow             # 普适底层：窗口内 NormalizedEvent 流（任何模型都能从中构建一切）
    signals: tuple[Signal, ...]     # 所有 Signal，统一存储，见 2.3
    graph: ProvenanceGraph | None   # 便捷视图：基础层预构建，可选（None = 框架不构建）
    context: AnalysisContext
    policy: DetectionPolicy | None  # 平台经 Broadcast State 分发的策略上下文（cloud_rules/endpoint_rules/converge），不在 required_inputs 里
    delta: DetectorDelta            # 本次新增、过期及图变化；旧 Detector 可继续读取完整快照
```

`DetectorDelta` 包含 `new_events`、`new_signals`、过期引用、受影响节点/边及
`graph_rebuilt`。框架按 `required_inputs` 与本次变化的交集调度 Detector；未使用
Delta 的 Detector 仍可读取有 TTL/容量上限的完整快照。Nodlink 等增量算法应优先
消费 changed node/edge，只传播受影响区域。

Event 会同时标记 `NORMALIZED_EVENT` 与 `PROVENANCE_EDGE` 发生变化。框架只判断
变化集合与 Detector 声明是否相交，不按 RULE/MODEL/GRAPH/SYSTEM 硬编码调度分支；
因此仅依赖图的 Detector，以及消费任意类型 Signal 的图 Detector，都不会被快捷
路径漏掉。执行前还要求声明的输入类别在当前窗口内齐备，例如 `SIGNAL +
PROVENANCE_EDGE` Detector 在窗口尚无 Signal 时不会被纯 Event 空转唤醒。
该 eligibility 判断在快速路径和逐 Detector 编排中复用同一实现；若变化命中但输入
暂不齐备，框架只保留 `graph_rebuilt=True`，待输入齐备后从完整快照重建，不积累
重复 Event 对象。

### 2.2 三级抽象与成本分级

| 抽象 | 谁构建 | 成本 | 对应 PIDSMaker | 适用 Detector |
|---|---|---|---|---|
| `events`（原始事实） | Normalize | 一次、流式共享 | 原始日志 | 任何模型自给自足 |
| `graph`（便捷视图） | Provenance Builder | 一次、多 Detector 共享 | 默认构图 | 轻量 Detector（rule/shortest-path） |
| Detector 自建视图 | Detector 自己 | 每个算法独立 | 独立 construction | 专用派生状态（如 nodlink 的 ISG/Hopset） |

- `graph` 是**可选优化，不是强制**：Detector 在 `required_inputs` 里声明要 `events`、`graph` 还是两者。Nodlink 首版复用共享 ProvenanceGraph，再从中维护算法私有的 ISG/Hopset；其他模型只有确有不同构图语义时才从 Event 自建视图。
- 自建视图的成本先靠 `state_requirements` 约束和指标观测；只有实测需要时才拆独立 Job（见第 8 节），守住「数据只消费一次」的流式底线。

### 2.3 `signals` 统一存储，派生视图过滤

**Candidate 不是独立消息类型**。所有检测发现都使用 `Signal`；`stage` 表示发现的成熟度，`detector_kind` 表示产生方式：

```proto
enum DetectorKind { UNSPECIFIED=0; RULE=1; MODEL=2; GRAPH=3; SYSTEM=4; }
enum SignalStage  { UNSPECIFIED=0; CANDIDATE=1; CONCLUSION=2; }
```

例如，端侧模型输出是 `where=ENDPOINT + detector_kind=MODEL + stage=CANDIDATE` 的
`Signal`，下文简称 `MODEL+CANDIDATE Signal`。规则候选、模型候选和图检测结论
不是三种消息，而是同一数据结构的不同分类。

`DetectorKind` 已有 5 个值（GRAPH/SYSTEM 预留给未来），因此输入统一为一个
`signals` 集合，框架只提供便捷的派生视图：

```python
@property
def candidates(self):   # detector_kind==MODEL and stage==CANDIDATE
    return tuple(s for s in self.signals
                 if s.detector_kind == MODEL and s.stage == CANDIDATE)

@property
def conclusions(self):  # stage==CONCLUSION
    return tuple(s for s in self.signals if s.stage == CONCLUSION)
```

- 存储统一、访问便捷（Detector 不手写 filter）、可拓展（GRAPH/SYSTEM 自动进入 signals）。
- **保留的区分只在一处**：数据层对 `MODEL+CANDIDATE Signal` 做强引用校验（Normalize/Gateway 要求其 `event_ref` 必须解析到当前批次）。这是数据完整性合同，本质是「字段过滤 + 校验」，不产生新的消息类型。
- **Terminal 不是 Signal 字段**：Terminal 是 Nodlink 在图内赋予节点的算法角色。Detector 根据 `MODEL+CANDIDATE Signal` 的 process entity 和 `event_refs` 映射 Terminal，不把算法内部状态写回公共输入合同。

### 2.4 `required_inputs` 开放枚举

```python
class RequiredInput(StrEnum):
    NORMALIZED_EVENT = "normalized_event"
    SIGNAL = "signal"              # 所有 Signal（细分用派生视图）
    PROVENANCE_EDGE = "provenance_edge"
```

未来可扩展（如 `PROVENANCE_GRAPH_SNAPSHOT`），不改已有 Detector。

## 3. Detector 合同

逻辑接口（Python Protocol，PyFlink Job 内抽象，不进 Kafka，无需 proto）：

```python
class Detector(Protocol):
    name: str                  # 如 "rule-correlation-v1"
    version: str               # 如 "1"
    required_inputs: tuple[RequiredInput, ...]
    signal_kinds: frozenset[int] | None  # 可激活本 Detector 的 Signal kind；None 表示全部
    state_requirements: StateRequirements
    def analyze(self, inputs: DetectorInputs) -> DetectionResult: ...
    def diagnostics(self) -> dict: ...
```

`DetectorInputs` 是框架按 `required_inputs` 组装的只读视图——Detector 声明了什么，就只拿到什么，不暴露多余运行时状态。`NORMALIZED_EVENT` 控制 `events`，`SIGNAL` 控制 `signals`，`PROVENANCE_EDGE` 控制 `graph` 及节点/边变化；`context`、`policy`、`delta` 和该 Detector 自己的 `detector_state` 始终由框架提供。

### Factory 与声明式选择

启用/禁用由 **policy bundle** 声明，`DetectorRegistry` 按 name 实例化：

```python
# 现在（规则级）
policy.cloud_rules = ["dropped_payload_executed_and_connects"]

# 目标（detector 级，声明式）
policy.detectors = ["rule-correlation-v1", "nodlink"]

registry = DetectorRegistry.register({
    "rule-correlation-v1": RuleCorrelationDetector,
    "nodlink": NodlinkDetector,
})
detectors = registry.build(policy.detectors)   # 未知 name 当场报错（白名单）
```

`name → constructor` 用 dict 映射（而非 PIDSMaker 的 if/elif），因为 Detector 数量会持续增长。灰度、A/B、按 tenant/scope 选择都退化为「改 policy 名单」。运行时由 `DetectorRegistry.build(policy.detectors)` 实例化；空名单才使用平台内置默认名单，未知名称立即失败。

`signal_kinds` 是 Detector 自己声明的轻量激活条件，不是 Flink 的算法分支，也不会
过滤传入的统一 Signal 快照。当前 rule-correlation 声明 RULE，Nodlink 声明 MODEL；
最短路径是 Evidence provider，不是 Detector。输入 Signal 本身的 AnalysisArtifact
投影与云端 Detector 调度相互独立，因此没有可运行云端算法时，端侧模型 Signal 仍会
正常投影。

### 状态需求

```python
@dataclass
class StateRequirements:
    keyed: bool            # 是否独立 keyed state
    ttl_ns: int = 0        # 0 表示复用基础层 TTL
    version: int = 1       # 状态版本，升级触发迁移
```

有状态 Detector 通过纯函数合同读写状态：`DetectorInputs.detector_state` 是框架从
Flink keyed MapState 恢复的不透明 bytes，`DetectionResult.state_update` 是本次更新。
状态 key 为 `name@algorithm-version/state-state-version`；未声明 `keyed=True` 却返回
状态会显式失败。每个状态另存独立 expiry；`ttl_ns=0` 复用 Agent 基础 TTL，非零值
使用 Detector 自己的 TTL，timer 和下一次输入都会删除过期状态。首次无精确版本状态
或发现同名旧版本时，框架删除旧 key，并以空状态和 `graph_rebuilt=True` 传入当前完整
有界快照；不做隐式状态迁移。发生 restore 或 timer 后图重建时，Detector 也必须以
当前有界快照重建自己的派生状态，不能继续沿用过期节点。

Flink keyed state 的逻辑边界是 `tenant_id + agent_id`。`scenario`、`workload` 等只
作为标签参与查询和报告，不切割 Agent 内跨进程攻击链。AgentAnalysisContext 负责
有限窗口内的 Event、Signal、ProvenanceGraph 和发射去重状态；scope 不是事件族，
事件是否属于同一攻击链仍由 lineage、共享实体和可验证图路径决定。

Flink keyed state 是权威状态。TaskManager Python 堆中的 AgentAnalysisContext 只是
LRU 加速缓存，同时限制为最多 64 个 scope、合计最多 100000 条记录；单个活跃 scope
可以独占记录上限。淘汰后从 keyed state 恢复，并强制 `graph_rebuilt=True`。乱序
Event 会先按 event-time 重排内存窗口，再全量重建图，避免到达顺序改变等长路径
选择或把已重写的 ListState 再次追加乱序。

Normalize 将一个上行 `DataBatch` 封装为一个 `NormalizedTelemetryBatch`，Detection
按 Batch 而不是按单条 normalized record 调用 Python 状态逻辑。Batch 保留每条
Event/Signal 的 context、sequence 和引用。标准流只接受 Batch 合同，不保留旧版单条
`NormalizedTelemetry` 解码分支。Flink 的 Batch 边界来自上行最多 256 条的合同，
Detection 不新增 Kafka topic，也不在 Python 堆里维护未 checkpoint 的长期缓冲。
Flink managed `ListState` 内部仍按单条 `NormalizedTelemetry` 保存记录，这是运行时状态
布局，不是 Kafka 输入兼容；恢复使用独立的内部解码函数，不能与 wire Batch 解码混用。

每个 Agent 只维护一个最早 cleanup timer，并把 expiry 向上合并到 1 秒桶。timer 到期
后一次淘汰该桶内全部记录，再登记下一个桶；状态最多额外保留不到 1 秒。禁止为每条
Event 注册独立 timer，否则窗口到期时会出现逐 Event 全量恢复/过滤/重写的 O(n²)
timer 风暴。
Timer 回调先按 Flink current key 查询 LRU；命中时直接清理内存上下文，不从
ListState 逐条恢复 protobuf。只有 cache miss 才从 Flink 权威状态恢复，避免活跃
单 Agent 在 Beam state channel 上重复搬运整个窗口。

## 4. 输出合同：DetectionResult 与 DetectionFinding

所有算法统一输出。`DetectionResult.findings` 是 Detector 的唯一语义结果；每个 Finding
绑定一个结论、一张 EvidenceSubgraph 和它的 contributors。Nodlink 与
`rule-correlation-v1` 已按此输出，最短路径只作为 Evidence provider 被复用。术语和
对象层次见 [streaming-concepts-glossary](streaming-concepts-glossary.md)。

```python
@dataclass
class DetectionResult:
    algorithm_name: str
    algorithm_version: str
    derived_signals: tuple[Signal, ...]      # 新 Cloud Signal
    findings: tuple[DetectionFinding, ...]
    diagnostics: dict                        # 状态诊断
```

Finding 合同：

```python
@dataclass
class DetectionFinding:
    correlation_key: str
    conclusion: Signal
    evidence: EvidenceSubgraph
    contributors: tuple[Signal, ...]
    event_refs: tuple[str, ...]
    edge_refs: tuple[str, ...]
    signal_refs: tuple[str, ...]
    node_scores: dict[str, float]

@dataclass
class DetectionResult:
    algorithm_name: str
    algorithm_version: str
    findings: tuple[DetectionFinding, ...]
    diagnostics: dict
    state_update: bytes | None
```

Nodlink 可将端侧 `local_rarity` 按 Terminal 节点记录到 `node_scores`，供 Investigation
解释结果；rule 类 Detector 可以留空。`node_scores` 不是第二套云端模型的接口，也不
改变统一 Signal/Evidence 输出。每个结果必须携带 policy ID/version、输入窗口、
watermark，保证可审计、可重算、可比较。

跨进程传输仍走 `AnalysisArtifact`（只载 signal/incident），Detector 不直接写 OpenSearch。
Investigation 只消费通用 `DetectionResult`：每个 Finding 自带 contributors 和 evidence，
Investigation 不扫描整个 Agent 窗口，也不把无关 Conclusion 拼进同一个 Incident。Investigation
不导入具体 Detector，也不重新执行某个 Detector 的算法。

## 5. 平台能力（Detector 不碰的八件事）

| 能力 | 实现层 |
|---|---|
| 数据接入与标准化（NormalizedEvent） | Normalize Job |
| 图构建与维护（Event→ProvenanceEdge、身份连续性、gap、TTL 淘汰） | Provenance Builder |
| 状态持久化（keyed state / checkpoint / savepoint / 恢复） | Flink Runtime |
| 时间语义（watermark、late data、窗口推进） | Flink Runtime |
| 策略分发与 Detector 选择 | Broadcast State + Factory |
| 失败隔离（单算法崩溃不阻塞他算法与 Normalize） | 框架 try/catch |
| 指标采集（CPU/RSS/state size/延迟/backpressure） | OpenTelemetry |
| 输出投影（DetectionResult → OpenSearch） | Projection Job |

Detector 只写「声明 + analyze」，不读 PostgreSQL/OpenSearch/Agent 私有结构。

## 6. 首批 Detector

| Detector | 迁移来源 | required_inputs | 输出重点 |
|---|---|---|---|
| `rule-correlation-v1` | `analysis.py` 的 `_cloud_matches` | EDGE + SIGNAL | derived_signals |
| Evidence provider | `provenance.py` 的 `connecting_evidence` | EDGE + SIGNAL | 被结论型 Detector 组合进 Finding |
| `nodlink` | 原始 NodLink 的 Terminal/ISG/Hopset/Campaign 阶段 | SIGNAL + EDGE | derived_signals + findings |

`rule-correlation-v1` 的 `signal_kinds={RULE}`；`nodlink` 的值为 `{MODEL}`。

命名统一不带 `-v1` 后缀的 `nodlink`（降低理解门槛）；版本号放在 `version` 字段，算法升级改 version 而非新名字。

## 7. Nodlink 定位：端侧识别 Terminal，云端关联攻击链

SysArmor 只保留一套进程异常模型。Agent 已实现 FastText、VAE reconstruction score
和 SV 稳定性修正，负责从单个进程行为画像产生 `MODEL+CANDIDATE Signal`。云端
Nodlink 不训练、不加载、也不运行第二套 FastText/VAE/GLSTM 模型。

| 阶段 | Agent | 云端 Nodlink Detector |
|---|---|---|
| 进程画像与向量化 | ProcessProfile + FastText | 不重复计算 |
| 异常评分 | VAE reconstruction score + SV | 不重复计算 |
| Terminal Identification | 发出带 process entity、`local_rarity` 和 `event_refs` 的 `MODEL+CANDIDATE Signal` | 将 Signal 映射为图内 Terminal 节点 |
| 图关联 | 只上传构成因果关系的 Event | 构建 ISG、Hopset 和跨窗口攻击链 |
| 最终发现 | 不下云端结论 | 发出 `GRAPH+CONCLUSION Signal` 和 Evidence |

`nodlink.analyze()` 的在线链路为：

```text
NormalizedEvent + ProvenanceEdge + MODEL+CANDIDATE Signal
  -> 校验模型身份和 process/event 引用
  -> 将端侧模型 Signal 映射为 Terminal
  -> 更新有界 ISG 和 Hopset 状态
  -> 跨窗口连接可能属于同一攻击链的 Terminal
  -> 计算路径与 Campaign 分数
  -> 输出 Evidence 和 GRAPH+CONCLUSION Signal
```

`local_rarity` 是端侧模型已经计算出的 Terminal 异常分。云端可以把它记录到
`node_scores` 以便解释，但不能把它描述成云端图 VAE 的重建误差。ISG、Hopset、路径
分数和 Campaign 分数属于 Detector 私有状态或 diagnostics；只有可审计的节点、边和
引用进入 Evidence。PIDSMaker 的 `SumAggregation + NodLink decoder` 可作为离线研究
基线，但不是这条生产链路的运行时依赖。

当前在线实现先落地有界 Steiner 贪心基线：每个新 Terminal 只连接同模型、局部可达的
Campaign，否则建立新 Campaign。单次搜索最多包含 10 个节点；每个 Agent 最多保留
64 个 Campaign，每个 Campaign 最多 128 个节点和 128 个 Terminal。Signal 过期时同步
清理 Terminal 并重建相关子图。首版使用 Terminal 数、行为种类、跨进程、路径长度和
不完整边组成可解释结构分，达到 70 分才输出结论。该门槛不是论文最终检测器；完成 HAS 历史
分布和 Grubbs 校准前，不应把当前结果标记为完整 NodLink 复现。

## 8. 成本分级与独立 Job（扇出，不链式）

首版 `nodlink` 作为 `apps/streaming` 内置 Detector，与其他 Detector 共享标准化输入和
基础 ProvenanceGraph；它只额外维护 ISG/Hopset/Campaign 有界状态。没有性能数据前
不拆独立 Job，也不创建算法私有 topic。

若后续观测到 Nodlink 的 CPU、状态大小、checkpoint 或发布周期显著影响轻量 Detector，
再按相同合同拆成独立 Job：

```
                    ┌─→ Detection Job（轻量：rule-correlation、shortest-path）
                    │    共享图状态，吃 graph 视图，输出 artifact topic
normalized topic ────┤
                    └─→ Nodlink Job（按实测需要拆分）
                         吃同一标准流，维护私有 ISG/Hopset，输出 artifact topic
```

三条原则：

1. **扇出，不是链式**：独立 Job 消费「同一版本化 normalized topic」（不是重放原始 Kafka）。Normalize 只做一次，重量 Job 复用标准流。
2. **端侧模型结果直接复用**：拆分后 Nodlink 仍消费 `MODEL+CANDIDATE Signal`，不在云端重复 FastText/VAE，也不创建「图特征 topic」。
3. **链式（预处理复用）是阶段三的优化**：只有当多个重量模型共享同一套昂贵预处理时，才考虑抽前置 Job（`normalized → 图/特征 topic → 多个 Detector Job`）。阶段一/二不引入。

## 9. 兼容性与可拓展性保障

- **新增 Detector 不改基础层**：`required_inputs` 开放枚举 + Factory dict + Finding 合同，新算法只增类 + 注册 + policy 名单。
- **迁移不改行为**：阶段一 M2/M3 先「纯提取」规则关联与最短路径到 Detector（行为不变），M4 才引入 Factory 动态编排，每步可独立验证 graph/conclusion recall 不下降。
- **算法失败隔离**：Engine 逐个 try/catch，单 Detector 抛错只记 `detector_diagnostics`，不阻塞其他 Detector 与 Normalize；合同违规（例如未声明 keyed state 却返回状态）仍显式失败。
- **状态版本语义**：精确版本正常恢复；缺失或升级时删除旧版本，并从当前有界快照明确重建，不做隐式迁移。
- **版本化合同**：`name` 唯一，`version` 标识算法版本；评测框架按 `(name, version)` 对齐结果。
- **Python 版本约束**：Flink 部署镜像（`flink:1.20.2`，Ubuntu 22.04）实际运行 Python 3.10，而本地 `uv` 用 3.11 开发。Detector/streaming 代码必须兼容 Python 3.10，不得依赖 3.11+ 运行时特性（如 `StrEnum`、`tomllib`、`except*`、`typing.Self`）——本地单测用 3.11 无法暴露这类问题，只有端到端（VM）才会炸。

## 10. 落地顺序（阶段一任务映射）

```
M1 本合同的 contracts.py + DetectorRegistry + 白名单校验
M2 rule-correlation-v1（纯提取）
M3 最短路径 Evidence provider（纯提取 + ProvenanceGraph 瘦身）
M4 analyze() 编排化 + investigation.py（动态 Registry 才引入）
M5 DetectionResult 与 DetectionFinding 补算法版本/窗口/引用
M6 回放/状态/端到端验收
```

每项交付同时提交代码、测试、运行指标和本文档更新。
