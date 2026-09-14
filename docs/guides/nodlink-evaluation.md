# Nodlink 端到端评测

本文说明如何运行 Nodlink 的完整 managed 实验，以及如何阅读准确率、性能和链路可靠性指标。

## 为什么同时跑三种模式

实验依次运行 `rule-only`、`learning-only` 和 `hybrid`，让效果与成本具有共同基线：

| 模式 | 回答的问题 |
|---|---|
| `rule-only` | 端侧规则基线的效果和资源成本是多少？ |
| `learning-only` | 端侧模型能否产生有效 Candidate，额外成本是多少？ |
| `hybrid` | Rule 与 Learning 同时启用后，Nodlink 能否形成 Evidence、Conclusion 和 Incident？ |

三种模式使用相同 workload、攻击场景和 fresh VM 生命周期。这样可以区分模型漏检、
传输积压、云端图关联失败和资源回归，而不是把所有失败都归因给 Nodlink。

## 前置条件

先检查 Docker、Vagrant、libvirt、`vagrant-libvirt` 和 Tetragon：

```bash
make test-doctor
```

实验需要独立的训练集和校准集：

- 两个文件均为 Canonical Event NDJSON；
- Event ID 和 ProcessProfile ID 不得重叠；
- 校准集至少包含 `ceil(1 / target_rate)` 个 Profile；默认 `target_rate=0.005`，即至少 200 个；
- 合成数据适合验证链路，不用于证明生产模型质量。

## 运行实验

```bash
make test-performance DOMAIN=learning PROFILE=medium \
  TRAINING_DATA=/absolute/path/to/training.ndjson \
  CALIBRATION_DATA=/absolute/path/to/calibration.ndjson
```

受限环境中如果用户目录不可写，可以复用已安装 provider 的临时 Vagrant 目录：

```bash
cp -a ~/.vagrant.d /tmp/sysarmor-vagrant-home
VAGRANT_HOME=/tmp/sysarmor-vagrant-home \
LIBVIRT_DEFAULT_URI=qemu:///system \
make test-performance DOMAIN=learning PROFILE=medium \
  TRAINING_DATA=/absolute/path/to/training.ndjson \
  CALIBRATION_DATA=/absolute/path/to/calibration.ndjson
```

完整数据流为：

```text
Scenario / Workload
  -> Tetragon
  -> Agent Event / Rule Signal / Model Candidate
  -> Gateway
  -> Kafka
  -> Flink Normalize / Detection / Projection
  -> Nodlink Finding / Evidence / Conclusion / Incident
  -> OpenSearch
  -> Manager API
  -> Learning report
```

## 输出

汇总报告位于：

```text
test/.results/learning-detector/<run-id>/report.md
test/.results/learning-detector/<run-id>/summary.json
```

每种模式的原始产物位于：

```text
test/.results/performance-endpoint/<run-id>-<mode>/<policy>/
```

重点产物：

| 文件 | 用途 |
|---|---|
| `events.scope.ndjson` | 当前实验作用域内的 Event |
| `signals.scope.ndjson` | Agent 观察到的 Endpoint Signal |
| `managed-signals.json` | 完成 Stream projection 的 Model Candidate |
| `managed-conclusions.json` | Cloud Conclusion Signal |
| `managed-incidents.json` | Incident 与 EvidenceSubgraph |
| `stream-processing.json` | Candidate 的 correlated/projected/reference-rejected 状态 |
| `stream-jobs.json` | Flink Job 状态诊断 |
| `stream-lag.txt` | Kafka consumer lag 诊断 |
| `nodlink-metrics.json` | 可选的 Detector processing/state runtime 指标 |

测试结束后确认环境已清理：

```bash
make -C test down ENV=vm-topology
```

## 指标解读

| 指标 | 含义 |
|---|---|
| `normal_candidate_rate` | 正常 Profile 被模型选为 Candidate 的比例 |
| `attack_campaign_seed_recall` | 攻击 Campaign 是否获得模型 Candidate seed |
| `stream_graph_recall` | truth Event 是否进入 Incident Evidence |
| `conclusion_recall` | truth Campaign 是否形成最终 Incident |
| `nodlink_evidence_precision` | Evidence Event 中属于 truth 的比例 |
| `nodlink_campaign_duplication` | 同一 Campaign 被重复输出的比例 |
| `nodlink_latency_p95_ms` | Candidate 到 Nodlink Conclusion 的 p95 延迟 |
| `nodlink_detector_processing_ms` | Detection Job 导出的 Nodlink 处理耗时 |
| `nodlink_detector_state_bytes` | Detection Job 导出的 Nodlink 状态大小 |
| `stream_pending_backlog` | Gateway 已接受但尚未完成 Stream projection 的 Candidate 数 |

`unavailable` 表示实验缺少形成该指标所需的真实产物，不等于零。

## 最近一次 Smoke 实验

运行 ID：`20260907T-learning-nodlink-metrics`。

本次使用 256 个训练 Profile 和 256 个校准 Profile 的合成正常数据，目的只是验证完整链路和
报告能力。校准 Candidate rate 为 `0.390625%`，满足 `0.5%` 的校准约束；该模型不代表生产质量。

| 指标 | rule-only | learning-only | hybrid |
|---|---:|---:|---:|
| Agent CPU | 5.45% | 19.05% | 10.34% |
| Agent steady RSS | 58.43 MiB | 109.79 MiB | 76.37 MiB |
| EPS | 18.25 | 338.02 | 71.91 |
| Model Candidate | 0 | 10 | 16 projected / 65 created |
| Normal Candidate rate | 0 | 0.0021% | 0.0386% |
| Attack seed recall | baseline | 0 | 0 |
| Stream pending backlog | 0 | 0 | 49 |
| Graph recall | baseline | not applicable | 0 |
| Conclusion recall | baseline | not applicable | 0 |

结论：规则基线和 Rule 等价性通过；合成模型没有命中攻击 Profile，因此 Nodlink 没有形成目标
Campaign、Evidence 和 Conclusion。Hybrid 另外存在 49 个 Candidate 的 drain backlog；
learning-only RSS 超过 100 MiB，hybrid RSS 超过相对基线 16 MiB。由于没有 Nodlink Conclusion
和 runtime metrics 产物，Evidence precision、Campaign duplication、延迟和 Detector 独立成本
显示为 `unavailable`。

下一次用于模型质量结论的实验应使用真实正常业务训练/校准数据，并先确保 Candidate cohort
完全 drain，再评估 Nodlink 图和结论指标。
