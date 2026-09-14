# Learning Detector Pipeline

本目录实现 SysArmor `FeatureSchemaV2` Learning Detector 的离线训练、校准和推理参考实现。模型在这里离线生成，Agent 只负责加载签名 Bundle 并对 `ProcessProfile` 做端侧推理。

## Pipeline

```text
Canonical Event NDJSON
        |
        v
重建 ProcessProfile
        |
        +--> FastText token/子词 embedding
        +--> 文件/网络 IDF 权重
        +--> VAE 重建模型
        +--> DBSCAN 进程稳定性值（SV）
        +--> 独立校准集计算 threshold
        v
未签名 model-bundle.json
        |
        v
Ed25519 签名
        |
        v
Agent learning.model_path + learning.trust_keys
```

训练工具只接受事件事实，不接受已有 Candidate 作为训练标签。每个输入文件会按 `(agent_id, subject_proc.stable_id)` 重建一个有界 Profile，最多保留 32 个文件、16 个网络地址和 16 个 Event 引用。

## 构造数据

输入是 NDJSON，每行可以直接是 Event，也可以是包含 `event` 的观察包装。最小 Event 示例：

```json
{"id":"event-001","agentId":"agent-a","behavior":"process.exec","occurredAtNs":"1700000000000000000","subjectProc":{"stableId":"proc-001","binary":"/usr/bin/curl","argv":["curl","https://example.test"]},"object":{"kind":"process"}}
```

训练数据应覆盖目标环境中的正常进程、命令参数、文件路径和网络地址；不要把攻击数据混入正常训练集。校准数据用于估计正常分数分布，必须与训练集完全独立。

数据校验要求：

- Event ID 非空且在单个数据集内唯一；
- `subjectProc.stableId` 非空；同一 Agent 下 Profile 身份可稳定重建；
- 训练集和校准集的 Event ID、`agent_id:stable_id` Profile ID 不得重叠；
- 校准 Profile 数量至少为 `ceil(1 / target_rate)`；默认 `target_rate=0.005` 时至少 200 个；
- Event 至少包含可提取的文本特征，否则训练会失败。

现成样例位于 `test/data/learning/normal-events.ndjson`、`observed-events.ndjson` 和 `replay-events.ndjson`。合成样例只用于验证链路，不代表生产模型质量。

## 安装依赖

使用 uv 管理独立训练环境：

```bash
cd tools/learning_detector
uv sync
```

依赖包括 FastText（gensim）、PyTorch CPU、NumPy 和 scikit-learn。训练要求 Python 3.11 或更高版本。

## 训练和校准

```bash
cd tools/learning_detector
uv run python prepare_model.py \
  --training /absolute/path/training.ndjson \
  --calibration /absolute/path/calibration.ndjson \
  --target-rate 0.005 \
  --output /absolute/path/model-bundle.json
```

命令会执行以下步骤：

1. 校验两份数据并计算 SHA-256；
2. 从 Event 重建 ProcessProfile；
3. 训练 FastText token 和 3～4 字符子词向量；
4. 计算文件、网络特征的 IDF；
5. 训练确定性 VAE；
6. 使用 DBSCAN 计算进程稳定性值；
7. 在校准集上计算异常分数和 threshold；
8. 校验模型摘要和 payload 摘要后写出 Bundle。

默认配置定义在 `training.py` 的 `TrainingConfig`：embedding 维度 16、隐藏层 12、潜变量 8、80 个 epoch、固定随机种子 7。需要改变模型结构时，应同步更新 Go Agent 的推理合同和 `FeatureSchema`，不能只修改训练脚本。

训练输出旁建议保存校准元数据：

```bash
uv run python prepare_model.py ... > calibration.json
```

输出包含数据摘要、允许的校准 Candidate 数、实际 Candidate 数和分数分位数。校准 Candidate rate 超过目标值时命令失败。

## 签名和发布

训练输出是未签名 Bundle，生产 Agent 不应直接加载。使用模型专用 Ed25519 私钥签名：

```bash
openssl genpkey -algorithm ED25519 -out model-signing.key
chmod 600 model-signing.key
./dist/bin/sysarmor-model-sign \
  --key model-signing.key \
  --key-id learning-release-2026-09 \
  --input model-bundle.json \
  --output model-bundle.signed.json
```

签名私钥不能提交到 Git 或写入镜像。发布 Bundle 时同时保存：模型版本、`model_digest`、`payload_digest`、训练/校准数据摘要、代码提交和签名 Key ID。

## Agent 部署和更新

Agent 配置使用独立的 Learning 权限域：

```yaml
learning:
  model_path: /etc/sysarmor/agent/learning/model-bundle.json
  trust_keys: learning-release-2026-09=<base64-ed25519-public-key>
```

更新步骤：

1. 生成并校验新的 signed Bundle；
2. 将 Bundle 放到 Agent 的 `learning.model_path`；
3. 将对应公钥加入 `learning.trust_keys`；
4. 重启或按现有 Agent 安装流程重新加载配置；
5. 确认健康状态为 `learning.status=loaded`；
6. 发布 Detection Policy 时，`learning_model.ref`、`version`、`digest` 必须与已加载 Bundle 完全匹配。

开发环境可以使用现有同步脚本：

```bash
SYSARMOR_VM_ENV=vm-topology \
SYSARMOR_VM_INCLUDE_BENCH_CONTENT=1 \
SYSARMOR_LEARNING_MODEL=/absolute/path/model-bundle.signed.json \
SYSARMOR_LEARNING_TRUST_KEYS='learning-release-2026-09=<public-key>' \
bash test/shared/vm/sync-agent.sh
```

部署失败时 Agent 应保留上一个有效模型或进入 `degraded`，不能静默加载未签名、摘要不匹配或身份不匹配的 Bundle。更新前后都应记录模型 digest，便于回滚和调查。

## 推理语义

训练侧和 Go Agent 侧必须使用同一合同：Unicode token 化、FastText 子词、`float32` 累加、VAE mean 分支和阈值比较。Profile 分数为：

```text
MSE = VAE 重建均方误差
score = log(MSE / SV)
```

当 `score >= threshold` 时，Agent 生成 `Model Candidate`。Candidate 必须带有模型 provenance、唯一 Process subject 和至少一个触发 EventRef，随后才会进入云端 Nodlink 关联。

## 验证和回放

训练工具测试：

```bash
cd tools/learning_detector
uv run pytest -q
```

端云模型回放：

```bash
make nodlink-replay \
  EVENTS=test/data/learning/replay-events.ndjson \
  SIGNALS=test/data/learning/replay-signals.ndjson \
  OUTPUT=/tmp/nodlink-replay
```

回放用于检查 Candidate、Campaign、Conclusion 和 Evidence 的可重复性；它不替代真实 Flink 的 checkpoint、watermark、Kafka lag 和资源成本测试。效果评测至少同时观察正常 Candidate rate、攻击 Seed recall、Evidence precision、Conclusion recall、重复率、端到端延迟和状态大小。

## 更新原则

- 新模型必须提高或解释效果指标，不能只看 Candidate 数量；
- 训练集、校准集和模型 Bundle 必须可通过 digest 复现；
- 修改特征或模型结构时递增 `feature_schema` 或模型版本；
- 同一 Agent 同时只启用一个明确身份的模型；
- 模型加载、策略匹配、Candidate 引用和云端投影失败都必须可观测；
- 生产更新保留上一版本 Bundle、公钥和校准报告，支持快速回滚。
