# Detector 合同与模块设计

本文定义 SysArmor 云端 Detector 的输入/输出合同、模块边界和首批实现。设计对标 [provenance-detection-plan](provenance-detection-plan.md) 的阶段一，并吸收 PIDSMaker（NodLink 开源实现）的可插拔模式。目标是：**新增一个 Detector 不修改 Normalize、Provenance Builder、Investigation 和 Projection**。

## 1. 目标与原则

两条硬约束决定所有取舍：

1. **兼容性**：现有 `rule-correlation` 与 `provenance-shortest-path` 无缝迁移成 Detector，graph/conclusion recall 不下降，managed quick/medium 保持通过。
2. **可拓展性**：后续 `nodlink`、`steiner-approx`、`risk-propagation`、`graph-ml` 只增不改基础层。

从 PIDSMaker 吸收的三条机制：

| PIDSMaker 机制 | 我们采纳 |
|---|---|
| 声明式配置（`used_methods`）+ 工厂分发（字符串→类） | Detector 由 policy 声明启用，`DetectorFactory` 按 name 实例化 |
| 数据准备层可插拔（construction/featurization/batching） | 输入以「最小事实原子」为底，视图分级，重量模型可自建数据视角 |
| 检测输出是**逐节点分数**，不是图级是/否 | `DetectionResult` 携带 `node_scores`，Incident 由 Investigation 聚合 |

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
```

### 2.2 三级抽象与成本分级

| 抽象 | 谁构建 | 成本 | 对应 PIDSMaker | 适用 Detector |
|---|---|---|---|---|
| `events`（原始事实） | Normalize | 一次、流式共享 | 原始日志 | 任何模型自给自足 |
| `graph`（便捷视图） | Provenance Builder | 一次、多 Detector 共享 | 默认构图 | 轻量 Detector（rule/shortest-path） |
| Detector 自建视图 | Detector 自己 | 每个模型独立 | 独立 construction | 重量模型（nodlink 自定义构图/特征） |

- `graph` 是**可选优化，不是强制**：Detector 在 `required_inputs` 里声明要 `events` 还是 `graph` 还是两者。轻量 Detector 用共享图省状态，重量 Detector 声明只要 `events`，框架就不为它构建共享图。
- 自建视图的成本靠 `state_requirements` + 独立 Job 隔离（见第 8 节），守住「数据只消费一次」的流式底线。

### 2.3 `signals` 统一存储，派生视图过滤

**不把 signal/candidate 拆成两个输入字段**——它们在 proto 层本来就是同一个 `Signal`，区别只靠两个正交枚举：

```proto
enum DetectorKind { UNSPECIFIED=0; RULE=1; MODEL=2; GRAPH=3; SYSTEM=4; }
enum SignalStage  { UNSPECIFIED=0; CANDIDATE=1; CONCLUSION=2; }
```

`DetectorKind` 已有 5 个值（GRAPH/SYSTEM 预留给未来），硬拆二元字段反而装不下。所以统一成一个 `signals`，框架提供派生视图：

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
- **保留的区分只在一处**：数据层的 candidate 强引用校验（Normalize/Gateway 对 `MODEL+CANDIDATE` 的 `event_ref` 必须解析到当前批次）。这是数据完整性合同，本质是「字段过滤 + 校验」，与输入层是否分字段无关，不受合并影响。

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
    state_requirements: StateRequirements
    def analyze(self, inputs: DetectorInputs) -> DetectionResult: ...
    def diagnostics(self) -> dict: ...
```

`DetectorInputs` 是框架按 `required_inputs` 组装的只读视图——Detector 声明了什么，就只拿到什么，不暴露多余运行时状态。

### Factory 与声明式选择

启用/禁用由 **policy bundle** 声明，`DetectorFactory` 按 name 实例化：

```python
# 现在（规则级）
policy.cloud_rules = ["dropped_payload_executed_and_connects"]

# 目标（detector 级，声明式）
policy.detectors = ["rule-correlation-v1", "provenance-shortest-path-v1"]

factory = DetectorFactory.register({
    "rule-correlation-v1": RuleCorrelationDetector,
    "provenance-shortest-path-v1": ShortestPathDetector,
    "nodlink": NodLinkDetector,
})
detectors = factory.build(policy.detectors)   # 未知 name 当场报错（白名单）
```

`name → constructor` 用 dict 映射（而非 PIDSMaker 的 if/elif），因为 Detector 数量会持续增长。灰度、A/B、按 tenant/scope 选择都退化为「改 policy 名单」。

### 状态需求

```python
@dataclass
class StateRequirements:
    keyed: bool            # 是否独立 keyed state
    ttl_ns: int = 0        # 0 表示复用基础层 TTL
    version: int = 1       # 状态版本，升级触发迁移
```

## 4. 输出合同：DetectionResult

所有算法统一输出，字段按 PIDSMaker 的「逐节点分数」扩展：

```python
@dataclass
class DetectionResult:
    algorithm_name: str
    algorithm_version: str
    derived_signals: tuple[Signal, ...]      # 新 Cloud Signal
    evidence: EvidenceSubgraph               # GraphNode/GraphEdge 子图
    conclusions: tuple[Signal, ...]
    incidents: tuple[Incident, ...]
    event_refs: tuple[str, ...]
    edge_refs: tuple[str, ...]
    signal_refs: tuple[str, ...]
    node_scores: dict[str, float]            # 逐节点异常分数（ML Detector 填，rule 留空）
    diagnostics: dict                        # 状态诊断
```

`node_scores` 是关键增量：让 `nodlink` 输出「每个节点的异常分」，`investigation` 再把高分节点/边聚合成 Incident。rule 类 Detector 留空，不影响投影。每个结果必须携带 policy ID/version、输入窗口、watermark，保证可审计、可重算、可比较。

跨进程传输仍走 `AnalysisArtifact`（只载 signal/incident），Detector 不直接写 OpenSearch。

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
| `provenance-shortest-path-v1` | `provenance.py` 的 `connecting_evidence` | EDGE + SIGNAL | evidence |
| `nodlink` | 端侧 learning + PIDSMaker GLSTM | EVENT + EDGE + SIGNAL | node_scores + evidence |

命名统一不带 `-v1` 后缀的 `nodlink`（降低理解门槛）；版本号放在 `version` 字段，算法升级改 version 而非新名字。

## 7. NodLink 定位：复用端侧 VAE，补图结构传播

端侧 learning 已经是 NodLink 的「进程级退化版」——FastText token 化、VAE mean 重建、`score=log(MSE/SV)` 都已实现并验证。缺失的只有 GLSTM 的「沿边传播」，即把孤立进程的表示在图上按边类型传播、让「下载→执行→连外网」的因果链进入节点表示。

| 环节 | 端侧（现状） | nodlink（云侧） |
|---|---|---|
| 特征 | FastText token→句向量 | 复用同一分词/子词合同 |
| 编码 | VAE mean 确定性重建 | 复用 VAE 结构 |
| **图传播** | **❌ 无（孤立进程）** | **✅ GLSTM 沿边传播（edge-type-aware）** |
| 检测 | MSE/SV → 逐进程 candidate | 重建误差 → **逐节点 score** |

`nodlink` 的 `analyze`：

```
NormalizedEvent 序列 + ProvenanceEdge + ModelCandidate
  → FastText 节点特征（复用端侧合同）
  → GLSTM 沿边传播（edge-type-aware，新增）
  → VAE 重建误差 = node_scores（复用端侧 VAE）
  → 高分节点/边 → evidence，超阈值 → derived_signals
```

这直接补 learning-only「攻击召回 0」的候选方向：端侧孤立看进程看不到因果链，图级传播正是补这一块。`nodlink` 属于阶段二，但其合同（`required_inputs` 含 EVENT、输出 `node_scores`）从阶段一的合同里就预留。

## 8. 成本分级与独立 Job（扇出，不链式）

轻量 Detector 共享一个图状态（便宜），重量 Detector 自己维护图/特征状态（贵），贵的拆独立 Job，别拖累轻量的：

```
                    ┌─→ Detection Job（轻量：rule-correlation、shortest-path）
                    │    共享图状态，吃 graph 视图，输出 artifact topic
normalized topic ────┤
                    └─→ NodLink Job（重量：自己构图 + 特征化）
                         吃 events，独立 checkpoint/consumer group，输出 artifact topic
```

三条原则：

1. **扇出，不是链式**：独立 Job 消费「同一版本化 normalized topic」（不是重放原始 Kafka）。Normalize 只做一次，重量 Job 复用标准流。
2. **预处理在独立 Job 内部做**：nodlink 的构图 + FastText 特征化是 Job 内部算子的职责，不写成「图/特征 topic」让下游消费——那需要额外的版本化、去重、checkpoint 对齐，太重。
3. **链式（预处理复用）是阶段三的优化**：只有当多个重量模型共享同一套昂贵预处理时，才考虑抽前置 Job（`normalized → 图/特征 topic → 多个 Detector Job`）。阶段一/二不引入。

## 9. 兼容性与可拓展性保障

- **新增 Detector 不改基础层**：`required_inputs` 开放枚举 + Factory dict + `node_scores` 可选字段，新算法只增类 + 注册 + policy 名单。
- **迁移不改行为**：阶段一 M2/M3 先「纯提取」规则关联与最短路径到 Detector（行为不变），M4 才引入 Factory 动态编排，每步可独立验证 graph/conclusion recall 不下降。
- **算法失败隔离**：编排器逐个 try/catch，单 Detector 抛错只记 diagnostics，不阻塞其他 Detector 与 Normalize。
- **状态版本语义**：`StateRequirements.version` 决定 checkpoint 恢复与升级迁移；缺版本时明确失败，不回退默认。
- **版本化合同**：`name` 唯一，`version` 标识算法版本；评测框架按 `(name, version)` 对齐结果。

## 10. 落地顺序（阶段一任务映射）

```
M1 本合同的 contracts.py + DetectorFactory + 白名单校验
M2 rule-correlation-v1（纯提取）
M3 provenance-shortest-path-v1（纯提取 + ProvenanceGraph 瘦身）
M4 analyze() 编排化 + investigation.py（动态 Registry 才引入）
M5 DetectionResult 补算法版本/窗口/引用/node_scores
M6 回放/状态/端到端验收
```

每项交付同时提交代码、测试、运行指标和本文档更新。
