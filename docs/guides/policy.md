# 统一策略指南

本文解释如何使用统一策略协调 collection、detection、telemetry 和 response。核心对象与 Signal 分类见[安全数据模型](../concepts/security-data-model.md)；字段、默认值和 Schema 以[配置参考](../reference/configuration.md)为准。

## 为什么必须统一

主机安全策略不是一组互不相关的开关。采集范围决定检测可见性，检测结果决定哪些数据值得上传，telemetry 预算限制云侧可获得的上下文，response 又必须依赖可解释的 Signal 和 Evidence。

因此，SysArmor 将四部分放在同一个端点策略版本中：

| 层面 | 回答的问题 | 主要代价或风险 |
|---|---|---|
| Collection | 观察哪些行为、实体和作用域？ | CPU、内存、磁盘和事件量 |
| Detection | 哪些行为被提炼为 Signal？ | 计算成本、漏报和误报 |
| Telemetry | 如何组成批次并可靠上传？ | 网络、队列、云侧存储和时延 |
| Response | 允许哪些动作、模式和作用域？ | 业务影响与操作风险 |

单独调整其中一层容易产生不可解释状态。例如扩大 detection 规则却不采集所需行为不会增加可见性；提高 collection 粒度却不调整 telemetry 预算可能只会增加本地丢弃；生成 response intent 并不代表端点被授权执行动作。

## 保护模式与策略解析

Manager 使用 `EndpointProtectionMode` 管理一组完整策略，默认值是 `rule-only`。它位于四层 Policy 之上，只决定如何解析 Bundle，不进入 Agent 运行时：

| Mode | Detection | Collection | 状态 |
|---|---|---|---|
| `rule-only` | 至少一个启用的 Ruleset，不允许模型引用 | Bundle 明确声明的规则采集面 | 默认、生产 |
| `learning-only` | 只允许版本化 `learning_model` | 自动并入完整因果骨架 | 实验、observe-only |
| `hybrid` | Ruleset 与 `learning_model` 同时存在 | 规则采集面与因果骨架并集 | 生产 |

正式链路是 `EndpointProtectionMode -> Policy Resolver -> Versioned Policy Bundle -> 四层 EndpointPolicy`。Manager 保存的新 Bundle 必须显式包含 `protection_mode`、`collection`、`detection`、`telemetry` 和 `response_policy`；缺字段、能力与 Mode 不一致或模型身份不完整都会拒绝保存。系统不推断旧格式，也不使用 `minimal/balanced/deep` 等名称映射保护模式。

Resolver 生成的下发文档只包含 `policy_id`、`version` 和四层 Endpoint Policy。Agent 不知道 Mode；Detection 未携带 `learning_model` 时，即使本机预装了模型也不会评分。携带模型引用时，ref、version 和 digest 必须与已验证 Bundle 完全一致，否则应用失败并保留上一有效策略。

## 策略生命周期

```text
编写意图
  -> explain / capability 检查
  -> Schema 与语义校验
  -> collection 和 detection 编译
  -> 分配给 tenant、Agent 或作用域
  -> Agent 原子应用并持久化
  -> 上报有效版本、健康和确认
  -> 根据效果与资源指标继续调整
```

端点策略要求非空 `policy_id`、正整数 `version`，并同时包含四个部分。Manager Bundle 及 Detection 顶层采用严格解析；Collection 子结构当前仍可能忽略未知字段，因此发布前必须使用 explain/dry-run 验证，不能把“未报错”当成字段已经生效。更新只有在完整策略可解析、可校验并可编译时才能替换有效策略；失败时保留上一有效版本。

发布新策略时应由调用方递增版本，并记录明确、可审计的变更原因；Manager 和 Agent 当前不会强制拒绝降级版本。修改 collection 或 response 时尤其应先在有限作用域验证，不能依赖覆盖发布来掩盖失败。

## Collection：控制观察面

Collection 描述行为类别、选择器、运行作用域和 observe-only 意图。当前 Linux/Tetragon 后端能够将部分选择器下推到 sensor，其余受支持选择器由 Agent 处理；不支持的选择器应在编译报告中显式出现。

策略设计从“检测需要什么事实”反推，而不是从“sensor 能提供什么”正向堆叠：

1. 列出目标 Signal 所需的最小 Event 和实体关系。
2. 选择可在 sensor 下推的作用域和前缀，减少进入 Agent 的无效数据。
3. 对无法下推但可由 Agent 判断的条件评估 CPU 与事件量。
4. 用 Functional 测试验证链路，用 Detection 测试验证必要结果，用 Performance 测试验证资源预算。

常开策略应保持小而稳定。更深的文件读取、广泛网络或高频系统行为适合受控场景，而不是默认无限采集。策略样例位于 `test/data/policies/`，它们用于测试预算和场景，不是生产基线的自动承诺。

## Detection：把事实提炼为 Signal

Detection 选择端点与云侧规则、规则集、内容引用、IOC 引用、覆盖参数和运行模式。Endpoint Rule 贴近行为流产生低延迟 Signal；Cloud Rule 在同一 tenant 和分析作用域内结合历史 Event 与 Endpoint Signal，产生 Cloud Signal 或参与 Incident 收敛。

Signal 是结构化行为信号，不等同于告警。规则应明确：

- 输入需要哪些 Event、Signal、实体或内容版本；
- 输出 Signal 的稳定身份、名称、风险、严重度和置信度；
- Event、上游 Signal、实体、lineage 和 Evidence 引用如何保留；
- 输出是 Candidate 还是 Conclusion、检测器类型、是否允许跨 lineage，以及何时只观察不响应；
- 重放同一输入时是否生成同一语义结果。

规则内容与策略分离：策略引用有版本的 ruleset、context 和 IOC；规则覆盖只表达启停、模式、严重度、作用域、响应意图和参数等有意差异。这样可以审计“使用了什么内容”与“如何应用内容”。

## Telemetry：控制传输成本

当前 Telemetry Policy 控制 DataBatch 边界：最大条目数、最大字节数和刷新间隔。它影响上传时延、网络开销和队列压力，但不会改变 collection 产生哪些 Event，也不是长期数据保留策略。

调整时应同时观察：

- pending Event、Signal 和字节数；
- 队列容量、批次丢弃以及 Event/Signal 丢弃；
- 按条目、字节、间隔和关闭触发的 flush 次数；
- 已发送、重试和拒绝批次；
- Agent CPU、RSS、磁盘与端到端延迟。

更大的批次通常减少请求开销，但增加时延和瞬时内存；更短的刷新间隔降低等待时间，但提高网络与处理频率。不存在脱离 workload 的通用最优值。

按 Signal 价值设置上传优先级、动态速率、选择性原始材料上传和风险窗口目前属于目标能力，不能与现有批次边界控制混为一谈。

## Response：限定可执行边界

Response Policy 定义允许的动作和模式。Signal 可以携带 response intent、推荐动作、置信度和原因，但 intent 只是建议，不等于执行授权。实际命令必须经过控制平面，绑定 tenant、Agent、动作、模式、作用域、操作者和审计记录，并由 Agent 返回确认。

当前默认策略以 observe 为主，允许的动作范围有限。设计响应时遵守：

- 默认最小权限，动作和作用域必须显式允许；
- 高风险动作需要审批，不能由规则命中直接扩权；
- 可逆动作应定义撤销或超时；
- 不可逆动作必须有更严格审批和恢复预案；
- 重试必须幂等，结果必须确认和审计；
- Agentic 系统只能在相同边界内建议或执行。

## 作用域与分配

策略不得只靠文件位置表达作用域。Manager 分配记录绑定 tenant、Agent 或选择器、策略 ID 和版本；Agent 实际应用的版本必须可查询。Collection 内部还可以限定运行目标，例如 namespace 等 sensor 支持的作用域。

平台云侧关联另有分析作用域：以 Agent 身份为锚，可选由 `scenario`、`workload` 标签细分。它与策略分配作用域用途不同：前者防止无关数据被拼接，后者决定谁接收策略。两者都不能跨 tenant。

## 推荐调优流程

### 1. 建立基线

从最小可观测面开始，记录 Agent 与 sensor 的 CPU、RSS、Event/Signal 速率、队列、磁盘、上传和丢弃指标。基线必须对应明确 workload 和策略版本。

### 2. 验证安全结果

确认恶意场景产生必需 Signal 或 Incident，良性场景不产生禁止结果。缺失时先检查 collection 是否提供规则输入，再检查规则、内容和分析作用域；不要直接扩大全部采集。

### 3. 定位预算瓶颈

区分 sensor 产生过多、Agent 过滤或检测成本、批次队列压力、网络重试和云侧处理延迟。不同瓶颈对应不同策略层，避免用 telemetry 参数修复 collection 问题。

### 4. 小范围发布

增加版本，在有限 tenant、Agent 或运行作用域应用；观察有效版本、健康、丢弃和安全结果。验证通过后再扩大分配范围。

### 5. 保留回退路径

策略失败时保留上一有效版本。发布前记录可回退版本、内容依赖和变更原因；响应能力变化还要确认撤销或恢复流程。

## 当前基础与目标能力

| 状态 | 范围 |
|---|---|
| 当前已具备 | 四部分统一端点策略、严格解析、编译后原子替换、有效策略持久化、Manager 分配与下发、能力/健康/确认、规则与内容引用、受限 response 命令与审计 |
| 当前主要限制 | Telemetry 主要控制批次边界；常开与加深采集依赖人工策略发布；响应范围以 observe 和有限动作优先 |
| 目标能力 | 风险触发的临时采集窗口、上传优先级与动态速率、策略自动恢复、基于效果和预算的 Agentic 策略建议与受控执行 |

目标能力仍必须通过同一版本、校验、分配、确认和审计链路实现，不能建立旁路控制面。

## 验证清单

每次策略变更至少回答：

1. 哪些 tenant、Agent 和运行目标会受到影响？
2. 四层之间的输入输出是否匹配？
3. Agent 是否支持所需 collection 能力和选择器？
4. 预计增加多少 CPU、RSS、磁盘、网络和云侧成本？
5. 必需 Signal/Incident 与禁止结果是什么？
6. 丢弃、解析、重试和失败如何被观察？
7. 哪个版本可回退，response 如何撤销或恢复？
8. Agent 实际应用的版本是否与分配一致？

测试方法见[测试指南](../development/testing.md)，系统运行边界见[系统架构](../architecture.md)。
