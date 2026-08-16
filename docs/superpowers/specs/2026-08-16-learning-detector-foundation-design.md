# Learning Detector Foundation Design

**结论：** SysArmor 采用 Agent 发现异常候选、Worker 完成图检测的混合架构。实现前先一次性迁移 Signal 语义：`SignalStage` 表示候选或结论，`DetectorKind` 表示规则、模型、图算法或系统检测；Detection 业务不再使用 `Terminal`。

## 目标

1. Event 是事实，Signal 是发现，Evidence 是依据，Incident 是案件。
2. `SignalStageCandidate` 表示需要后续关联的中间发现。
3. `SignalStageConclusion` 表示可参与 Incident 收敛的最终发现。
4. Agent 模型只输出 Candidate；Worker 图算法输出 Conclusion。
5. `SteinerTerminal` 只作为 Worker 图算法内部术语，不进入产品契约。
6. 第一版使用自采正常数据训练简单模型，真实跑通模型制品、Agent 推理和 Candidate 上报，不承诺生产检测效果。

## 非目标

- 第一版不在 Agent 实现 Hopset 或 Steiner Tree。
- 第一版不做端侧在线训练或自动模型参数更新。
- 第一版不由模型 Signal 创建 Incident 或触发自动响应。
- 不保留 `terminal` 字段、查询参数、Policy 写法、双读或 fallback。
- 不同时维护两个生产推理引擎。

## Signal 语义

```text
Event
  -> Signal{detector_kind=model, stage=candidate}
  -> Worker SteinerTerminal
  -> Signal{detector_kind=graph, stage=conclusion}
  -> Evidence
  -> Incident
```

协议定义：

```proto
enum SignalStage {
  SIGNAL_STAGE_UNSPECIFIED = 0;
  SIGNAL_STAGE_CANDIDATE = 1;
  SIGNAL_STAGE_CONCLUSION = 2;
}

enum DetectorKind {
  DETECTOR_KIND_UNSPECIFIED = 0;
  DETECTOR_KIND_RULE = 1;
  DETECTOR_KIND_MODEL = 2;
  DETECTOR_KIND_GRAPH = 3;
  DETECTOR_KIND_SYSTEM = 4;
}
```

`UNSPECIFIED` 是无效生产输入，不是兼容路径。Agent、Gateway 和 Worker 的可信边界必须拒绝未指定值。

现有 Detection Signal 的迁移规则：

| 旧语义 | SignalStage | DetectorKind |
|---|---|---|
| Endpoint 普通规则命中 | Candidate | Rule |
| Endpoint 最终规则命中 | Conclusion | Rule |
| Cloud 规则或分析发现 | Candidate 或 Conclusion，由产生者明确指定 | Rule |
| Agent health/tamper | Conclusion | System |
| Agent 模型异常 | Candidate | Model |
| Worker 图攻击链 | Conclusion | Graph |

Conclusion 是新 Signal，并通过 `signal_refs` 引用促成它的 Candidate。Signal 不原地改变 Stage。

## 一次性契约和数据迁移

`signal.proto` 保留旧字段号和名称：

```proto
reserved 11;
reserved "terminal";
SignalStage stage = 25;
DetectorKind detector_kind = 26;
```

不得复用字段号 11，否则旧 `terminal=true` 的 varint 可能被误解码为新的枚举值。

Incident 的 `terminals` 同样退出产品语义，替换为 `conclusion_entities`；旧字段号和名称保留，不做运行时兼容。

OpenSearch 新建 `sysarmor-signals-v2`，把 v1 文档一次性转换为 `stage` 和 `detectorKind`，删除 `terminal`，校验文档总数后原子切换 read/write alias。迁移失败时 alias 保持在 v1，Manager/Worker 启动失败并显式报告；成功后不再读取 v1。旧物理索引在验证窗口结束后显式删除，不由应用运行时静默删除。

新部署直接创建 v2。迁移脚本可重入：alias 已指向 v2 时只校验，不重复 reindex。

## Agent Candidate Pipeline

最小 pipeline 使用确定性的逐 Event `FeatureSchemaV1`，固定编码 Behavior bucket、Argv 数量，以及 Subject、父进程、文件对象、Socket 对象四个存在位。Python 训练/replay 与 Go 推理使用相同的 float32 运算顺序、摘要规范和 golden replay；缺失字段显式编码，不猜测或用空字符串冒充正常值。

短时间窗口 `ProcessObservation`、Binary/UID/Lineage 实值特征和窗口计数属于下一阶段模型效果工作，不混入本次 pipeline 地基。引入时必须发布新的 FeatureSchema，不能改变 `FeatureSchemaV1` 的含义。

离线训练使用 Python/uv，输出带版本、digest、特征 schema、归一化参数和阈值的待签名模型 Bundle。发布工具使用模型专用 Ed25519 密钥签名；Agent 只加载可信签名且 FeatureSchema 兼容的 Bundle。模型不可用时 Learning Detector 报告 degraded，规则检测和事件采集继续运行，不加载内存默认模型。

Agent 输出：

```text
Signal{
  detector_kind: model,
  stage: candidate,
  local_rarity: anomaly score,
  event_refs: supporting events,
  entities: process and related objects,
  lineage_id: local lineage,
  model provenance: ref/version/digest/schema,
}
```

模型来源字段必须是类型安全的正式契约，不能塞入 `rule_id` 或 labels。

## Worker 图检测边界

Worker 把 Model Candidate 转换为内部 `SteinerTerminal`，基于 Event 构建 Process/File/Socket 图，在有界缓存中执行 ISG/Hopset，输出 Graph Conclusion 和 Evidence。第一步只验证单主机图；跨主机图必须先证明网络五元组、主机身份和时间关联数据完整。

## 可靠性和安全

- 模型输入、输出、缓存容量和单事件推理时间必须有硬上限。
- 异常窗口不参与端侧基线更新；第一版不更新模型参数。
- 模型加载、切换和回滚必须原子化。
- Candidate 不能创建 Incident 或触发响应。
- 所有 Signal 必须有明确 Stage 和 DetectorKind。
- 规则、模型和图检测失败分别计入健康状态和 metrics，不静默失败。

## 验收

Signal 地基验收：旧 Detection `Terminal` 生产字段和接口为零，Protobuf/Domain/Policy/查询/OpenSearch/测试全部使用 Stage，数据迁移可重入且 alias 切换安全，全量合同、Go、race 和功能测试通过。

最小模型 pipeline 验收：自采正常数据可重复转换为训练集，模型 Bundle 可生成并被 Agent 校验加载，replay 能产生可追溯的 Model Candidate，规则检测结果不变，Endpoint quick 的丢事件率和解析错误率仍为零，并记录 CPU/RSS/延迟基线。
