# 测试指南

SysArmor 将基础逻辑、产品功能、检测质量、资源成本和发行兼容性分开验证。五类测试
使用不同证据和通过条件；Release 只聚合发布所需门禁，不重复实现测试。

## 测试边界

| Suite | 回答的问题 | 主要证据 | 不证明什么 |
|---|---|---|---|
| Unit | 独立代码单元和模块边界是否正确 | Go 单测、聚焦契约 | 完整部署和产品链路 |
| Functional | 组件或产品链路是否工作 | 合约断言、健康状态、真实链路输出 | 检测准确率、长期资源成本 |
| Detection | 恶意与良性行为是否产生预期安全结果 | truth labels、Event、Signal；Incident 仅作诊断采集 | Incident 正确性、长期性能、全部产品功能 |
| Performance | 给定环境和负载下成本是多少 | CPU、RSS、吞吐、丢弃、时间线 | 检测覆盖完整、所有功能正确 |
| Distribution | 制品能否校验、安装和运行 | 包结构、签名、安装事务、多系统镜像 | 全部产品功能和发布决策 |

此外，`make test-unit` 运行本地 Go 测试；module benchmark 用于定位代码级性能，
不等同于真实 Agent 或平台基准。

## 开始之前

从仓库根目录执行：

```bash
make test-doctor
```

统一预检会验证 Go、Docker、Vagrant、Virsh、`vagrant-libvirt` provider、libvirt
连接以及 Tetragon archive。任何 VM Suite 都应先通过该检查。失败信息会同时给出修复
建议，常见处理如下：

| 问题 | 修复方向 |
|---|---|
| 缺少工具 | 安装对应工具并加入 `PATH` |
| 无法读取 Vagrant 插件 | 确认 `VAGRANT_HOME` 可写，取消指向空目录的临时配置 |
| 缺少 `vagrant-libvirt` | `vagrant plugin install vagrant-libvirt` |
| 无法连接 libvirt | 启动 libvirt 服务，确认当前用户属于 `libvirt` 组 |
| 找不到 Tetragon 包 | 设置 `SYSARMOR_TETRAGON_ARCHIVE`，或放到仓库 `.cache/` |

默认 libvirt URI 是 `qemu:///system`；需要其他连接时显式设置
`LIBVIRT_DEFAULT_URI`。不要通过临时清空 `VAGRANT_HOME` 绕过插件或权限问题，这会让
已安装的 provider 看起来像“未安装”。

完整命令列表以 Makefile 为准：

```bash
make test-help
```

## 常用入口

根 Makefile 提供日常入口：

```bash
make test-unit
make test-doctor
make test-functional DOMAIN=endpoint
make test-detection
make test-performance DOMAIN=endpoint PROFILE=medium \
  WORKLOAD=business-normal \
  SCENARIO=apt-fileless-c2-local \
  POLICIES='test/data/policies/collection-balanced.json'
make test-distribution SOURCE=local
make test-release STAGE=pre-publish
```

公共入口按测试分类组织；分类内使用语义明确的参数选择测试对象：

```bash
make test-functional DOMAIN=endpoint|platform|topology|all
make test-performance DOMAIN=endpoint|platform|modules|all
make test-distribution SOURCE=local|published
make test-release STAGE=pre-publish|post-publish
```

`DOMAIN` 表示系统领域，`SOURCE` 表示发行产物来源，`STAGE` 表示发布门禁阶段。
参数缺失或取值不合法时 Make 会打印完整用法并退出，不会静默选择默认测试。

## 测试环境

| 环境 | 形态 | 主要用途 | 关键依赖 |
|---|---|---|---|
| Local | 当前开发机 | Go 单测、合约、microbenchmark | Go |
| `container` | 本地 Docker Compose | 快速平台合约、容器产品链路 | Docker |
| `vm-endpoint` | 单个受保护 VM | 真实 Agent/Tetragon、端侧 CPU/RSS | Vagrant、libvirt、Tetragon |
| `vm-topology` | `mgr`、`node-a`、`attacker` | 分发、注册、mTLS、端云检测、平台成本 | 完整 VM 与平台依赖 |

`vm-topology` 的角色：

```text
mgr       Manager、Gateway、Flink 和平台存储
node-a    安装 Agent 的受保护主机
attacker  C2 和攻击场景支持节点
```

Suite 通常自行管理环境生命周期。诊断时可以手工管理：

```bash
make -C test up ENV=container
make -C test up ENV=vm-endpoint
make -C test up ENV=vm-topology
make -C test status ENV=vm-endpoint
make -C test down-all
```

VM 会创建特权基础设施，并可能传输较大的镜像和 sensor 包。诊断结束后必须执行对应
`down`。`test/environments/vm-topology/deploy/` 仅保存可再生成的 `platform/` 和
`images/` 部署缓存；所有测试结果仍写入 `test/.results/`。

## Functional 测试

Functional Suite 证明“系统通不通”。

| 内部目标 | 边界 | Sensor/输入 |
|---|---|---|
| `functional-endpoint-local` | 本地状态和容器入口运行行为 | fake binary/本地契约 |
| `functional-endpoint` | 安装 standalone Agent，验证真实 Event、Signal、关联引用和重启恢复 | owned real Tetragon |
| `functional-endpoint-container` | 容器 Agent 的 `namespace/self` 隔离 | Manager 分发的容器 Agent |
| `functional-platform` | Manager、Gateway、Flink、PostgreSQL、Policy、Response 合约 | 构造或 fake 输入 |
| `functional-platform-full` | 容器内 Event、Signal、Incident 产品路径 | Tetragon container |
| `functional-topology` | 三 VM 分发、注册、证书和接入链路 | Manager 分发真实 Agent |

公共入口：

```bash
make test-functional DOMAIN=endpoint
make test-functional DOMAIN=platform
make test-functional DOMAIN=topology
make test-functional DOMAIN=all
```

`functional-endpoint-local`、`functional-endpoint-container` 和 `functional-platform-full`
是开发测试实现使用的内部目标，不作为稳定公共入口。

`functional-topology` 验证：

```text
signed artifact -> channel -> one-time enrollment -> verified install
-> CSR/certificate issuance -> systemd Agent -> authenticated platform connection
```

它验证 Manager 可见的 health/session 和 Agent 重启，但不证明内核遥测质量、攻击检测
准确率或平台资源成本。需要 truth-label 检测结论时运行 Detection；需要资源结论时
运行 Performance。

## Detection 测试

### Agent 模式边界

测试中的 `sensor.mode: managed` 只表示 Agent 管理 Tetragon sensor，不表示 Agent 已注册到 Manager。
Agent enrollment 模式按测试目标明确区分：

| 目标 | Agent enrollment 模式 | 数据验收源 |
|---|---|---|
| Endpoint functional/performance | `standalone` | Agent 本地 Event、Signal 和资源指标 |
| Topology functional | `managed` | Manager health/session 和接入状态 |
| Detection topology | `managed` | Gateway -> Kafka -> Flink -> OpenSearch -> Manager 查询 |

Learning managed 性能实验在负载结束后发布 `rule-only` drain Policy，停止产生新的 Model Candidate，同时保持 Agent spool、Gateway 和 Flink 运行。Agent 只冻结一次 Candidate 计数和 Event sequence cutoff；Flink 按同一 `Signal.id` 形成 correlated/projected 结果并写入 OpenSearch。`events.scope.ndjson` 与 `signals.scope.ndjson` 是有界观察流，只用于 truth、样本和诊断；Ring Buffer eviction 记为 `observation_gap`，不能单独证明生产 DataBatch 丢失。报告不截断或补齐计数，并分别展示端侧 storage drop、Gateway reject、Stream backlog 和引用拒绝。

Detection topology 的每个 fresh VM case 会先创建一次性 enrollment，并通过 `sysarmorctl enroll` 切换 Agent 到 managed；collection/detection 策略通过 Manager publish/assign 下发，benchmark 内容在安装阶段签名进入 Agent 默认内容。这样 `EVALUATION_SCOPE=manager` 验收的是实际云端 Flink 链路，而不是 standalone 本地 spool。Standalone 端点能力由 Endpoint functional/performance 单独验收。

Detection 的默认 `alert_score`/`evidence_score` 门槛为 `0.9`，同时仍要求所有真值文件中的 required Event/Signal 全部命中。可通过 `SYSARMOR_DETECTION_MIN_SCORE` 临时提高或降低分数门槛；降低门槛不会放宽 required 标签检查。

Detection Suite 在真实端云链路上判断恶意和良性行为是否产生预期 Event 和
Signal：

```bash
make test-detection
```

默认组合：

- Workload：`business-normal`；
- Scenario：`apt-fileless-c2`、`apt-staged-drop`、`benign-ci-noise`；
- Policy：`collection-balanced`、`collection-deep`。

`collection-minimal` 有意缩窄可见性，不进入默认完整检测门禁。自定义矩阵：

```bash
make test-detection \
  POLICIES='test/data/policies/collection-balanced.json' \
  WORKLOADS='business-normal' \
  SCENARIOS='apt-fileless-c2 apt-staged-drop benign-ci-noise'
```

Manager 查询结果是 topology 数据源：

```text
manager.events.json
manager.signals.json
manager.incidents.json
```

脚本将三者转换为对应的 `.ndjson` 文件。当前评分器只消费 Event、Signal 以及
Conclusion/forbidden Signal；Incident 文件会被采集并记录到报告路径，但不参与评分或
门禁。因此 Detection 通过不能证明 Incident 数量、内容或 Evidence 子图正确。
本地 Agent watch 文件只用于诊断，不是默认评分源。恶意场景缺少 required truth，或
良性场景产生 forbidden detection，均应使门禁失败。完整报告包括：

```text
test/.results/detection-topology/<run-id>/
  manifest.json
  matrix.csv

test/.results/detection/<run-id>/
  matrix.csv
  truth_steps.csv
```

Detection 运行中采集到的 CPU/RSS 只提供上下文，不构成正式性能基线。

## Performance 测试

Performance Suite 将三种成本分开测量：

| 范围 | 入口 | 测量对象 |
|---|---|---|
| Endpoint | `performance-endpoint` | `node-a` 上 Agent、sensor 和两者汇总 |
| Platform | `performance-platform` | `mgr` 上 Manager、Gateway、Flink 和基础设施 |
| Module | `performance-modules` | rule engine、matcher 等本地 Go 模块 |

### Endpoint

日常可比运行：

```bash
make test-performance DOMAIN=endpoint \
  PROFILE=medium \
  WORKLOAD=business-normal \
  SCENARIO=apt-fileless-c2-local \
  POLICIES='test/data/policies/collection-balanced.json'
```

Profile 的结论边界：

| Profile | 用途 | 可否作为资源结论 |
|---|---|---|
| `quick` | 验证 benchmark 接线、发现明显回归 | 否 |
| `medium` | 日常检测与性能关联，单 Policy 约十分钟 | 可用于同条件日常比较 |
| `long` | 长窗口端侧 CPU/RSS 基线 | 是 |

`quick`、`medium`、`long` 只定义实验持续时间和采样条件，不是产品保护模式。产品模式由
Manager 的 `EndpointProtectionMode` 选择：`rule-only`、`learning-only` 或 `hybrid`。

Endpoint 采样指标包括 Agent/Sensor/EDR CPU 与 RSS、Event/Signal、吞吐、丢弃、
解析错误和 phase 时间线。阶段语义：

| Phase | 含义 |
|---|---|
| `startup` | 安装、Agent 启动、Policy 应用和 sensor reload |
| `steady` | 无 benchmark Workload 的稳定运行期 |
| `workload` | 完整背景负载窗口 |
| `activity` | 显式 Scenario 执行窗口 |
| `persistence` | Scenario 后观察窗口 |
| `overall` | 包含启动峰值的完整记录区间 |

正式比较优先使用 `steady` 和 `workload`。`overall` 受部署和启动活动影响，只用于解释
总运行成本。Profiling 默认关闭；只有定位阶段性 CPU 根因时才设置
`SYSARMOR_BENCH_PROFILE_AGENT=1`，profiling 结果不能作为低扰动基线。

典型输出：

```text
test/.results/performance-endpoint/<run-id>/
  manifest.json
  matrix.csv

test/.results/recordings/performance-endpoint/<run-id>/<policy>/
  timeline.csv
  markers.ndjson
  events.ndjson
  signals.ndjson
  summary.json
  raw/
  profiles/
```

### Platform

```bash
make test-performance DOMAIN=platform \
  SYSARMOR_PLATFORM_PERF_DURATION=600 \
  SYSARMOR_PLATFORM_PERF_INTERVAL=5
```

平台侧采集 Manager、Gateway、Flink、Kafka、PostgreSQL、Redis、对象存储和 OpenSearch，输出：

```text
test/.results/performance-platform/<run-id>/
  platform.resources.csv
  platform.summary.json
  raw/
    manager.healthz.{start,end}.json
    gateway.healthz.{start,end}.json
    manager.metrics.{start,end}.json
    platform.compose.ps.txt
```

Endpoint 与 Platform 是两个独立成本面，不能相加，也不能互相替代。原始健康和 metrics
快照应与汇总一起保留。Platform runner 使用测试 PKI 签发的短期 Manager JWT 获取 metrics，
令牌只通过标准输入进入 VM 内进程，不写入命令参数或结果文件。Docker 资源与 Compose 状态
采集失败会使测试失败，不能以空状态文件或匿名 metrics 请求作为成功证据。

### Module

```bash
make test-performance DOMAIN=modules BENCHTIME=200ms COUNT=1
```

Module benchmark 适合定位算法回归，不包含 sensor、VM、网络或平台成本。

### Endpoint Protection Mode 矩阵

Learning 实验在相同 Endpoint Medium 和相同场景下依次运行 `rule-only`、`learning-only`、
`hybrid`，每个模式由 Policy Resolver 选择自己的 Collection Policy，并生成一份运行级
`report.md`。默认使用 managed Agent 与 `vm-topology`，从 Manager 抓取 Incident；只有显式
设置 `SYSARMOR_LEARNING_AGENT_MODE=standalone` 时才跳过 Flink 与端到端门禁。执行时必须
提供训练集和独立校准集：

```bash
make test-performance DOMAIN=learning PROFILE=medium \
  TRAINING_DATA=/path/to/training.ndjson \
  CALIBRATION_DATA=/path/to/calibration.ndjson
```

检测效果分三层验收，不能用上游结果替代下游结果：

| 层级 | 指标 | 数据来源 | 门禁语义 |
|---|---|---|---|
| Agent 发现 | `attack_campaign_seed_recall` | Endpoint Event、ProcessProfile、Model Candidate | 始终 blocking，默认至少 0.90 |
| Flink 构图 | `stream_graph_recall` | truth graph Event 与 Incident Evidence `event_refs` | managed `hybrid` 时 blocking，默认至少 0.90 |
| 最终结论 | `conclusion_recall` | truth campaign 与 Incident campaign | managed `hybrid` 时 blocking，默认至少 0.90 |

“缺失字段”和“空结果”含义不同：standalone 没有 Flink 产物时报告 unavailable 且不阻断；managed `hybrid` 缺少 Incident artifact 或 truth 时明确失败，合法空 Incident 则使 graph/conclusion recall 为 0 并失败。`learning-only` 只验收 Model Candidate，不借助不存在的 Incident 声称 Flink 图或最终结论覆盖率；完整 Provenance graph 与 Conclusion 由 `hybrid` 验收。报告同时保留三模式 CPU、稳定期 RSS、EPS、drop/parse error、hybrid 相对 rule-only 的 Rule 等价性、ProcessProfile 生命周期和身份缺口，以及 Profile observation、feature update、模型评分、纯生命周期观察和 suppressed checkpoint 五个 Learning 语义调度计数。只有 blocking 门禁全部通过，运行结论才是 passed。

训练侧 Python 与 Agent 侧 Go 必须通过同一真实 Bundle 和 ProcessProfile 的推理合同：特征向量固定，score 按 `float32` 语义一致，且 `score >= threshold` 的 Candidate 结论一致。两端各自单测通过不能替代这项跨语言合同。

## Distribution 测试

Distribution 验证发行包和安装兼容性，不承担发布决策：

| 来源 | 边界 |
|---|---|
| `SOURCE=local` | 当前源码生成的本地签名包、标准路径、安装事务和发布工作流契约 |
| `SOURCE=published` | 指定公开安装地址在 Ubuntu 22.04、Ubuntu 24.04 和 Debian 12 中的真实安装与运行 |

```bash
make test-distribution SOURCE=local
make test-distribution SOURCE=published \
  URL=https://git.pku.edu.cn/oslab/sysarmor/releases/download/<tag>/install.sh
```

Published 测试必须显式指定待验收 tag 的 URL，避免误测其他 pre-release。详细镜像和场景
说明见 `test/suites/distribution/published/README.md`。

## Release 门禁

Release 不拥有独立测试实现，只组合已有分类：

```bash
make test-release STAGE=pre-publish
make test-release STAGE=post-publish URL=https://.../install.sh
```

发布前门禁包含 Unit、核心 Functional、Detection、选定的模块 Performance 基线和
本地 Distribution。发布后门禁运行已发布产物的 Distribution 验收。

## 测试数据

测试输入遵循四类契约：

| 类型 | 含义 |
|---|---|
| Policy | 选择 collection、detection、telemetry、response 和资源行为 |
| Workload | 产生可重复背景活动，不带安全断言 |
| Scenario | 执行恶意或良性行为，携带 truth labels |
| Content | 提供 IOC、上下文集合和规则包 |

格式、目录和新增要求见[测试数据契约](../../test/data/README.md)。

## 结果有效性

一个测试进程退出码为零，并不自动意味着结果可用于发布结论。至少检查：

1. `manifest.json` 完整记录环境、Policy、Workload、Scenario、持续时间和 run ID。
2. Workload 与 Scenario 按预期退出，时间线和必要结果文件非空。
3. watcher 没有未解释退出；drop 和 parse error 必须显式为零或解释原因。
4. Detection 的 required/forbidden truth 全部得到判定。
5. 性能对比使用相同 Profile、Policy、Workload、Scenario 和 VM 生命周期。
6. 发布汇总时保留原始数据，并同时说明该测试不证明什么。

禁止将复用 VM 与全新 VM 作为严格回归对比，也禁止用 `quick` 的短窗口形成稳定 CPU、
RSS 结论。重复运行应固定输入并报告样本数、聚合方法和异常值处理方式。

## 新增测试

新增测试时按问题选择位置：

- 产品功能或链路断言：`test/suites/functional/`；
- truth-label 检测断言：`test/suites/detection/`；
- 资源、吞吐或算法成本：`test/suites/performance/`；
- 发行包和安装兼容性：`test/suites/distribution/`；
- 多 Suite 共用机制：`test/shared/`；
- 可复用输入：`test/data/`。

`test/shared/` 中的 helper 只提供机制，错误必须显式返回，不编码单个 Scenario 的预期
安全结果。新增公共命令时更新 `test/Makefile help`；新增测试方法时更新本文；新增
fixture 格式时更新 `test/data/README.md`。Suite 子目录不再新建 README。

## 故障排查

### Tetragon 文件事件可能缺少进程身份

真实测试曾观察到少量 `file.read` Event 的 Tetragon `Process` 对象缺少 binary、argv 和父进程身份，涉及 sensor 启动前已存在的进程、CRON fork 子进程和长生命周期 sshd。当前证据只确认缺失值来自上游对象，不能直接归因于进程退出过快或缓存淘汰。

身份缺失时必须保留原始 Event 和相关 Signal，不将空 binary 视为可信，也不猜测程序路径。定位时分别复现 sensor 启动前进程、fork 后 exec 前读取和长生命周期进程读取，并保存原始 gRPC Process 对象、Tetragon 版本和进程缓存指标。

先运行：

```bash
make test-doctor
make -C test status ENV=vm-endpoint
```

需要保留环境诊断时，可使用：

```bash
make -C test diag-endpoint SYSARMOR_BENCH_WORKLOAD=business-normal
make -C test capture-endpoint SCENARIO=apt-fileless-c2-local DUR=30
```

手工 recorder 仅用于定位问题：

```bash
make -C test recorder-start RUN_ID=my-run
make -C test recorder-mark RUN_ID=my-run PHASE=activity DETAIL='manual check'
make -C test recorder-stop RUN_ID=my-run
make -C test recorder-report RUN_ID=my-run
```

诊断结束后执行 `make -C test down-all`。若结果无效，应保留 manifest、原始输出和错误
日志，不得只保留一份看似正常的 summary。
