# Streaming Architecture Refactor Implementation Plan

**Goal:** 将 Flink 应用迁移到 `apps/streaming/src/streaming`，收紧 Detector/Engine/Investigation 边界，并为 Nodlink 接入建立清晰的贡献接口。

**Architecture:** `jobs` 只组装 DAG；`preprocessing` 只做标准化和基础事实转换；`engine` 负责调度、状态和公共 Provenance；`detectors` 只实现算法；`investigation` 只消费 DetectionResult；`runtime` 只封装 Kafka、Flink 和外部投影。首版不保留旧单条 normalized record 兼容路径。

**Tech Stack:** Python 3.10/3.11、PyFlink 1.20.2、Kafka、protobuf、uv、pytest。

## Global Constraints

- Python streaming 代码兼容部署端 Python 3.10。
- 不直接修改 `dev`/`main`，不回滚已有工作区修改。
- Detector 使用统一 `Signal`、`DetectionResult` 和版本化 keyed state。
- 新 Detector 不修改 Normalize、Flink DAG、Investigation 和 Projection。

### Task 1: Package migration

迁移 `streaming/` 到 `apps/streaming/`，将 import package 从 `sysarmor_streaming` 改为 `streaming`，同步 Docker、Compose、Makefile、架构测试和所有 Python imports。

验证：所有 streaming 单测与 architecture contract 通过。

### Task 2: Layer split

将 `operators` 中的代码按职责迁移到 `preprocessing`、`engine`、`investigation` 和 `runtime`，保留 `jobs` 只做 DAG 装配；拆分超过 500 行的 detection/state 文件。

验证：模块依赖方向测试通过，Detector 不反向依赖 Job/Runtime。

### Task 3: Detector registry and policy selection

新增显式 `detectors.registry`，Policy 增加 Detector 名单；运行时由名单构建 Detector，不再无条件构建全部 Detector。将输入调度从 Registry 移入 Engine，并按声明裁剪 DetectorInputs。

验证：启用/禁用、未知名称、输入可用性和 Signal kind 测试通过。

### Task 4: Isolation and investigation boundary

逐 Detector 捕获异常并输出失败诊断；Investigation 只消费 DetectionResult，不导入具体 Detector 私有函数；Convergence 改为基于通用结论 Signal/Result。

验证：单 Detector 失败不阻塞其他 Detector，Incident 使用 Detector Evidence。

### Task 5: Remove obsolete compatibility

删除 Detection/Normalize 对旧单条 normalized record 的回退解码和相关测试；标准 Kafka 流只接受 `NormalizedTelemetryBatch`。

验证：旧单条输入明确失败，Batch quick/medium E2E 通过。

### Task 6: Nodlink contribution skeleton

新增内置 `detectors/nodlink`，先实现合同、Terminal 映射和状态接口占位，再接入 ISG/Hopset/Campaign；新增 `tools/nodlink` replay/calibration/evaluation 入口。

验证：Nodlink 单测、回放测试和 managed hybrid E2E 通过。

当前进度：已完成内置 `nodlink` 的严格 Terminal 映射、有界局部搜索、多 Campaign
版本化跨批次状态、过期清理、结构评分、完整引用及通用 Incident 链路。新 Terminal
只合并局部可达、`model_digest` 相同且 Policy 允许 lineage 关联的 Campaign；否则新建
Campaign。当前搜索是连接现有 Campaign 最近节点的在线 Steiner 贪心基线，`theta=10`；尚未实现论文
完整的 IV（异常分、距离、fan-out）优先搜索、HopSet HAS 历史分布与 Grubbs 多轮异常
检验。离线 replay/calibration/evaluation 工具仍待下一阶段实现。

状态与引用约束：只接受 `ENDPOINT+MODEL+CANDIDATE Signal`；graph rebuild 从当前
Signal 快照重建 Terminal；过期或淘汰 Terminal 时重建 ISG；只有实际进入同一 ISG 的
Terminal 才能参与 Campaign；跨 lineage 必须由 Policy 显式允许；Incident 只合并实际
产出本次 Conclusion 的 DetectionResult Evidence。每个 Agent 最多 64 个 Campaign，
每个 Campaign 最多 128 个节点和 128 个 Terminal，Campaign 按最近更新时间淘汰。

Replay：`tools/nodlink/replay.py` 读取 managed `events.scope.ndjson` 与
`signals.scope.ndjson`，按 Agent、时间和 Batch 重放生产 `DetectionState`，输出
`summary.json`、`campaigns.ndjson`、`conclusions.ndjson`、`incidents.ndjson` 和
`evidence.ndjson`。工具只做输入适配和结果导出，不复制 Detector 算法。
