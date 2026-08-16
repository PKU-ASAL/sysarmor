# Learning Detector Performance Experiment Design

**结论：** 新增独立的 Learning Detector A/B 实验套件，复用 Endpoint 单次性能测试能力，以完全相同的 fresh VM、采集策略和串行活动比较 Learning disabled 与 enabled。实验对模型链路、正常噪声、可靠性和性能设置硬门禁；攻击召回在第一版只建立可追溯基线，不作为阻断条件。

## 目标

1. 使用自采且互不重叠的正常数据完成模型训练和阈值校准。
2. 以 `normal Candidate rate <= 0.5%` 冻结模型阈值。
3. 使用同一份签名模型完成 disabled/enabled 两次 fresh VM medium 对照。
4. 分别测量正常负载性能和已知攻击场景的 Model Candidate 效果。
5. 验证启用 Learning Detector 不改变 Rule Signal 的既有 truth 语义。
6. 自动生成机器可读结果和一份运行级、人类可读的横向比较报告。

## 非目标

- 第一版不把攻击召回率作为发布门禁。
- 不评价 Worker 图检测、Graph Conclusion、Evidence 或 Incident 效果。
- 不做端侧在线训练、运行中阈值调整或模型参数更新。
- 不自动选择“最新”训练结果或隐式复用历史数据。
- 不引入生产模型信任密钥，也不保留实验签名私钥。
- 不在 Endpoint runner 内实现训练、校准或 A/B 决策。
- 不保留旧参数、旧报告格式或双路径兼容逻辑。

## 实验原则

### 唯一变量

两个正式 variant 必须固定以下条件：

- 相同 Git commit 和构建产物；
- 相同 `vm-endpoint` 环境与 VM 资源；
- 相同 `medium` profile 和阶段时长；
- 相同 `collection-balanced` 采集策略；
- 相同 Detection policy、Tetragon 配置和业务活动；
- 相同签名模型 provenance；
- 每个 variant 均从 fresh VM 开始。

唯一变量是 Agent 是否配置并加载签名 Learning model：

- A：`disabled`，不上传 Bundle，不写入 learning model/trust 配置；
- B：`enabled`，上传冻结 Bundle 和对应 public trust key。

### 两阶段活动

每个 variant 在同一个 Agent 生命周期内串行执行：

1. `business-normal`：测量资源、吞吐和正常 Candidate rate；
2. `apt-fileless-c2-local`：测量 Candidate 对 truth Event 的命中，并验证 Rule Signal 语义。

Endpoint runner 新增通用的 serial activity mode。Recorder marker 明确记录正常活动和攻击场景的开始、结束时间，报告只按 marker 时间窗口归属 Event、Signal 和资源样本，不通过名称或数量猜测阶段。

## 组件边界

新增 `test/suites/performance/learning/`：

### `run.sh`

负责实验级编排：

1. 校验显式输入和环境；
2. 调用模型准备与签名；
3. 依次执行 disabled 和 enabled Endpoint medium run；
4. 调用严格报告生成；
5. 根据硬门禁返回成功或失败。

它不解析模型算法细节，也不重新实现 Endpoint 的 VM、Policy、Recorder 或 workload 生命周期。

### `prepare_model.py`

负责：

- 校验 training/calibration dataset；
- 使用 `FeatureSchemaV1` 的既有特征与 float32 打分语义训练模型；
- 在 calibration dataset 上确定阈值；
- 输出模型 provenance 和 calibration summary。

特征提取、打分、Bundle 摘要必须复用 `tools/learning_detector/pipeline.py` 的正式实现，不能复制第二套算法。

### `report.py`

负责读取两次 Endpoint 结构化产物并生成：

- `summary.json`：机器可读判定；
- `report.md`：运行级横向报告。

报告器不读取 Agent 内部状态数据库，不从日志文本推导主指标。

### Endpoint runner

仍只表示“一次 Endpoint 性能运行”，仅增加通用能力：

- 可选 Learning model、trust key 和 variant 参数透传；
- serial activity mode；
- Learning 配置与模型 provenance 的 manifest 记录；
- normal/scenario 独立 recorder markers。

Endpoint runner 不知道另一侧 variant，也不判断 A/B 结果。

### VM Agent sync

`sync-agent.sh` 接收可选的实验模型和 trust key：

- disabled 时二者必须均未设置，Agent 配置不得出现 learning model 路径或 trust key；
- enabled 时二者必须同时存在，上传到固定测试路径并写入 Agent learning 配置；
- 半配置、文件缺失或上传失败必须显式退出。

## 模型数据与校准

### 输入合同

调用者必须显式提供：

- training dataset：只用于拟合 `mean/scale`；
- calibration dataset：只用于选择阈值。

两个文件均为 Event NDJSON。准备阶段要求：

- 每条 Event 的 ID 非空；
- 文件内部 Event ID 唯一；
- 两个文件的 Event ID 交集为空；
- 文件非空且所有 Event 可由正式 pipeline 解析。

实验记录规范化文件路径、Event 数量和文件 SHA-256。任何校验失败都发生在启动 VM 之前。

### 确定性阈值

目标比率固定为 `0.005`。设 calibration Event 数为 `N`，允许 Candidate 数为：

```text
K = floor(N * 0.005)
```

使用与 Agent 一致的 float32 计算路径得到所有 calibration score，并按降序排列。阈值选择为排除第 `K + 1` 个 Candidate 边界分数的最小可表示 float32；当边界存在同分时宁可减少 Candidate，也不能超过 K。`K = 0` 时阈值高于 calibration 最大 score 的一个 float32 单位。

冻结前必须使用生成的 Bundle replay calibration dataset，并断言：

```text
candidate_count <= K
candidate_count / N <= 0.005
```

阈值、K、实际 Candidate 数、实际比率和 score 分位数写入 calibration summary。正式 A/B 期间不得根据结果重新校准。

## 签名与制品

每次实验生成独立 Ed25519 key pair：

- private key 权限为 `0600`；
- 仅用于签署本次冻结 Bundle；
- 签名完成并验证后立即删除；
- public key、签名 Bundle 和 provenance 保留在结果目录；
- private key、Bundle 或实验路径不得写入仓库配置。

Bundle 的 model ref、version、digest、payload digest、Feature Schema 和 threshold 必须在模型目录、Endpoint manifest、Agent health 及 Candidate provenance 间一致。

## 运行流程

结果根目录：

```text
test/.results/learning-detector/<run-id>/
```

流程如下：

```text
validate inputs
  -> train
  -> calibrate and replay
  -> sign and verify
  -> disabled fresh-VM medium run
  -> enabled fresh-VM medium run
  -> strict aggregate report
  -> gate verdict
```

disabled 运行失败时停止，不启动 enabled。任一正式子运行或汇总失败时保留已有产物并生成 partial report；顶层命令必须返回非零。准备阶段失败时不得启动 VM。

## 指标与判定

### 模型链路硬门禁

- training/calibration 数据满足不相交合同；
- calibration 正常 Candidate rate `<= 0.5%`；
- Bundle 签名、digest 和 schema 验证通过；
- disabled health 明确显示 Learning `disabled`，Model Candidate 数为 0；
- enabled health 明确显示相同模型 `loaded`，不得是 degraded 或默认 fallback；
- enabled 的每个 Model Signal 均为 `stage=candidate`、`detectorKind=model`；
- Candidate 包含完整 model provenance；
- Candidate 的全部 `event_refs` 均能解析到本次采集 Event。

### 可靠性硬门禁

两个 variant 均要求：

- final health 为 `ok`；
- Sensor drop 为 0；
- Batcher drop 为 0；
- parse error 为 0。

Stream eviction 独立报告，仅表示观察流 Ring Buffer 覆盖，不作为真实丢数。

### Rule 回归硬门禁

`apt-fileless-c2-local` truth 要求的 Rule Signal 名称及其 truth Event 关联必须在 disabled/enabled 两侧均满足。背景 Rule Signal 总数可能受运行噪声影响，只做差异报告，不要求逐条完全相同。

### 性能硬门禁

以 normal activity start/done marker 的半开时间窗口 `[start, done)` 比较低扰动 recorder 指标：CPU 使用 `agent_cpu_pct` 平均值，RSS 使用 `agent_rss_mb` 最大值，EPS 使用窗口内 Event 增量除以窗口秒数。窗口缺失、顺序错误或没有资源样本均使实验无效。

```text
enabled_cpu <= max(disabled_cpu + 1 percentage point, disabled_cpu * 1.15)
enabled_rss <= max(disabled_rss + 32 MiB, disabled_rss * 1.15)
enabled_eps >= disabled_eps * 0.90
```

判定阈值同时写入顶层 manifest 和报告，不作为隐藏常量。

### 效果观察指标

第一版记录但不阻断：

- truth Event 被 Model Candidate 命中的比例；
- 每个 truth step 的 Candidate 数与 score；
- 非 truth Candidate 数量与 score 分布；
- normal/scenario 的 Candidate per 1000 Events；
- Rule/Model Signal 数量差异。

攻击召回不足时报告标记 `needs-improvement`，但不改变硬门禁 verdict。

## 报告结构

顶层产物：

```text
manifest.json
summary.json
report.md
model/
disabled/
enabled/
```

`disabled/` 和 `enabled/` 记录 Endpoint 子运行 ID、manifest 和相对产物引用，不复制 `raw.tar` 等大文件。

`report.md` 按以下顺序输出：

1. 总结与硬门禁 verdict；
2. 系统环境和实验条件；
3. 训练、校准和模型 provenance；
4. disabled/enabled 性能及 delta 表；
5. Health、drop、parse error 和 stream eviction；
6. normal phase Candidate 数量、比率和 score 分布；
7. attack truth step 与 Candidate 命中矩阵；
8. Rule Signal 回归结果；
9. 有界的 Event、Rule Signal、Model Candidate samples；
10. `needs-improvement`、partial failure 和复现信息。

报告 sample 必须限制数量并对长字段截断，不能把完整事件流嵌入 Markdown。

## 错误处理

- 输入、模型、签名和配置错误必须显式失败，不提供默认模型。
- missing marker、缺失结构化产物或无法解析的 event ref 属于实验无效，不降级为 warning。
- partial report 必须区分 `failed`、`not-run` 和 `unavailable`，不能用 0 代替缺失数据。
- 只有攻击召回不足和背景数量波动可作为非阻断观察结论。
- 顶层报告生成失败必须使实验返回非零。

## 测试策略

遵循 TDD，按以下顺序实施：

1. `prepare_model.py` 单测：输入交集、重复/空 ID、float32 边界、同分阈值、确定性摘要和比率上限；
2. `report.py` fixture 测试：DetectorKind 分离、marker window、truth eventRefs、性能边界和 partial failure；
3. `run.sh` 合同测试：fresh VM、disabled/enabled 顺序、固定 policy、serial mode、参数透传和失败停止；
4. Endpoint/VM 合同测试：disabled 零配置、enabled 上传与 trust 配置、manifest provenance；
5. 相关 Python、Shell 和 Go 测试；
6. 全仓 `go test ./...`；
7. 一次真实 medium Learning A/B 验收并生成最终 `report.md`。

## 验收标准

实现完成需同时满足：

- 一条命令可从两份显式正常数据生成冻结签名模型并完成 A/B；
- 两个 variant 使用 fresh VM、同 commit、同 policy 和相同串行活动；
- 所有硬门禁自动判定且失败返回非零；
- 攻击召回作为可追溯 baseline 输出，不冒充生产效果；
- `summary.json` 与 `report.md` 对相同指标和 verdict 给出一致结果；
- 不存在隐式数据选择、默认模型、运行中调参或兼容分支；
- 单元、合同、Go 全量测试和真实 medium 验收通过。
