# 测试数据契约

`test/data/` 是 SysArmor 测试的可复用输入目录。这里保存 Policy、Workload、
Scenario 和 Content；测试实现、生成结果和临时部署缓存不属于测试数据。

## 数据模型

| 类型 | 目录 | 职责 | 安全断言 |
|---|---|---|---|
| Policy | `policies/` | 控制采集、检测、资源、遥测和响应行为 | 否 |
| Workload | `workloads/` | 产生可重复的正常业务或系统活动压力 | 否 |
| Scenario | `scenarios/` | 执行恶意或良性行为并声明预期结果 | 是 |
| Content | `content/` | 提供 IOC、上下文集合和规则包 | 否 |

Detection 测试组合 Policy、Workload 和 Scenario 判断检测结果；Performance
测试以 Workload 形成资源窗口，并可增加 Scenario 关联检测活动与资源成本。

## Policy

Policy 是 SysArmor 控制平面的测试输入，不等同于 Tetragon TracingPolicy：

| 类型 | 读取者 | 作用 |
|---|---|---|
| SysArmor Policy | Agent 或 Manager 控制面 | 表达 collection、detection、resource、telemetry、response 语义 |
| TracingPolicy | Tetragon 等 sensor | 配置底层内核采集行为 |

当前样例：

| 文件 | 用途 |
|---|---|
| `collection-minimal.json` | 最小常开采集面，作为低成本下界 |
| `collection-balanced.json` | 默认平衡采集面，适合日常测试 |
| `collection-deep.json` | 调查或高风险窗口采集面，成本更高 |
| `collection-learning.json` | Learning/Hybrid 实验使用的完整因果骨架采集面 |
| `collection-hybrid.json` | Hybrid 实验使用的 Rule 采集面与 Learning 因果骨架并集 |
| `collection.yaml` | collection intent 设计样例 |
| `detection.yaml` | 检测规则和收敛参数样例 |
| `detection-additive.yaml` | 误报对照用 additive threshold 样例 |
| `detection-cep-endpoint.json` | 端侧 CEP 检测样例 |
| `resource.yaml` | 端侧资源上限样例 |
| `telemetry.yaml` | telemetry 批量和刷新配置样例 |
| `response.yaml` | response intent 样例，当前以 observe/audit 为主 |

新增 Policy 时：

1. 使用当前配置 Schema，不保留已废弃字段或路径。
2. 文件名表达用途或采集深度，不使用 `test1` 一类无语义名称。
3. 说明适用 Suite 以及与现有 Policy 的差异。
4. 性能对比必须记录完整文件路径和内容版本。
5. 只有验证底层 sensor 边界的测试才临时生成 TracingPolicy。

## Workload

Workload 只制造稳定背景压力，不表达攻击意图，也不负责判断检测成功。

```text
workloads/
  vm/<workload>/run.sh
  vm/<workload>/labels.yaml
```

当前 Workload：

| 名称 | 目的 |
|---|---|
| `business-normal` | 常规业务噪声，适合日常 benchmark |
| `host-activity-heavy` | 主机进程和普通文件活动压力 |
| `edr-activity-heavy` | exec、file、network 等 EDR 关注面活动压力 |

`run.sh` 接受统一运行参数：

```bash
DURATION=60 REPEAT=0 CONCURRENCY=1 ./run.sh
```

脚本只通过退出码和 stdout/stderr 报告执行情况，不直接写 benchmark summary；
Recorder 负责采样，Suite 负责按 phase 汇总。

`labels.yaml` 至少声明 `name`、`kind` 和 `window`。正常 Workload 的
`kind` 为 `benign`，若禁止终止型 Signal，应通过 `policy` 明确写出。

Collection 文件名描述采集面，不是产品保护模式。Manager 的
`EndpointProtectionMode` 只有 `rule-only`、`learning-only`、`hybrid`；Learning 性能矩阵
统一使用 `collection-learning.json` 隔离 Detection 成本，rule-only 生产 Bundle 仍应按
Ruleset 需要声明更小的 Collection。

## Scenario

Scenario 表达一个可重复的恶意或良性安全行为：

```text
scenarios/<environment>/<scenario>/
  attack.sh
  labels.yaml
  expected.yaml
```

文件职责：

| 文件 | 职责 |
|---|---|
| `attack.sh` | 执行场景并以退出码报告执行是否成功 |
| `labels.yaml` | Detection 评分使用的 truth labels 和关联要求 |
| `expected.yaml` | 端到端期望契约，包括更完整的 Event、Signal、Evidence/Incident 语义 |

`labels.yaml` 的核心结构是：

```yaml
name: apt-fileless-c2
kind: malicious
window: workload
objectives:
  alert:
    required_events: [reverse_c2]
    required_signals: [reverse_shell_pattern]
  evidence:
    required_events: [payload_write, payload_exec, reverse_c2]
    required_signals: [payload_dropped, reverse_shell_pattern]
labels:
  events: []
  signals: []
```

约束如下：

- 恶意场景必须声明至少一个可评分目标；良性场景必须声明禁止结果或零终止型
  Signal/Incident 约束。
- Event label 描述行为事实和匹配条件；Signal label 描述行为信号、实体和关联
  Event，不把 Signal 简化为传统告警。
- Evidence 通过 Signal 与 Event 的链接、实体以及 Incident 子图进行验证；需要新增
  独立 Evidence Schema 时，应先更新评分器，再扩展 fixture。
- `expected.yaml` 不得代替实际评分输入；只有评分器消费的字段才构成自动化门禁。
- 环境相关实现放在 `container/` 或 `vm/` 下；同名场景应保持语义一致。
- 场景不得依赖互联网、不可控时间源或未声明的宿主机状态。

## Content

`content/` 保存可版本化的检测内容，目前包括：

- C2 IP 与端口 IOC feed；
- 凭据、payload、持久化和 secret volume 路径前缀；
- 端侧 CEP rule pack。

新增 Content 时必须提供稳定 ID、明确语义和可离线复现的数据。外部 feed 不能在
测试运行时直接下载；应固定为仓库内 fixture，避免结果随外部状态漂移。

## 作用域标签

跨 Agent、Policy、Workload 和 Scenario 查询必须使用稳定标签隔离数据。常用标签：

```text
benchmark_run=<run-id>
policy_profile=<policy-name>
workload=<workload-name>
scenario=<scenario-name>
variant=<variant>
matcher_strategy=<strategy>
```

每次运行必须使用唯一 `run-id`。Manager 查询和本地 recorder 输出应使用同一组作用域
标签，避免旧事件进入当前结果。

## 使用示例

端侧性能：

```bash
make test-performance DOMAIN=endpoint \
  PROFILE=medium \
  WORKLOAD=business-normal \
  SCENARIO=apt-fileless-c2-local \
  POLICIES='test/data/policies/collection-balanced.json'
```

Detection 矩阵：

```bash
make test-detection \
  POLICIES='test/data/policies/collection-balanced.json' \
  WORKLOADS='business-normal' \
  SCENARIOS='apt-fileless-c2 apt-staged-drop benign-ci-noise'
```

测试运行和结果解释见[测试指南](../../docs/development/testing.md)。
