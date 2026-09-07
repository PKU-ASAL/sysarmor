# SysArmor Roadmap

本文定义 SysArmor 的中长期建设重点。路线图围绕需要解决的核心矛盾组织，不是完整功能清单，也不承诺未经评估的发布日期。

阶段是否完成，以可重复验证的退出标准为准。具体任务、负责人和排期由 Forgejo/GitHub Issue 与 Milestone 管理。

## 总体路径

| 阶段 | 核心问题 | 目标结果 | 状态 |
|---|---|---|---|
| 1. 端点可信运行与自保护 | Agent 和 Sensor 自身可能退出、失明或被停止 | 可恢复、可发现、可保护 | 当前重点 |
| 2. 信息效能与证据完整性 | 行为粒度、资源成本和调查价值相互制约 | 来源完整、成本可测、证据可复核 | 后续 |
| 3. 端云调查闭环 | 端侧局部判断与云侧全局关联缺少连续证据链 | 稳定关联、连续下钻、缺口显式 | 后续 |
| 4. 受控响应与动态博弈 | 固定策略与纯人工响应难以适应持续对抗 | 有界自动化、临时加深、自动恢复 | 后续 |

路线图落实三项[设计原则](design-principles.md)：动态博弈决定系统如何调整，效能平衡决定观察和传输多少，端云协同决定计算、数据和决策放在哪里。核心对象与当前能力边界以[安全数据模型](concepts/security-data-model.md)为准。

## 阶段 1：端点可信运行与自保护

Agent 和 Sensor 是所有安全能力的执行基础。系统不能只依靠 Agent 自己证明“仍然健康”，也不能把进程重启等同于完整自保护。

### 当前基础

- systemd 使用 `Restart=always` 恢复 Agent；
- Agent 管理 Tetragon 生命周期，并报告运行、重启、丢弃和解析状态；
- 端侧能够产生 Sensor 篡改或失明 Signal；
- 真实 VM 测试已验证 Agent 收到 `SIGTERM` 后恢复，并重新建立 Tetragon、策略和健康状态。

### 关键交付

1. **外部可发现：** Manager 根据健康时间戳和控制连接新鲜度判定 offline，不沿用过期的 `healthy` 状态。
2. **稳定可恢复：** 增加 systemd watchdog、启动限额、OOM 倾向、最小权限和 `SIGKILL`、卡死、连续崩溃测试。
3. **能力可判断：** 明确报告 BPF LSM 是否编译、启用，`task_kill` 是否可用以及保护策略是否加载。
4. **终止可观察：** 先以 observe-only 记录针对 Agent service cgroup 的信号发送者、目标、信号和结果。
5. **保护可渐进：** systemd 独立管理 Tetragon 与 bootstrap protection policy；验证维护放行和恢复路径后，再拒绝未经授权的终止。

### 退出标准

- Agent 失联后在 3 个健康上报周期内且最长 60 秒被 Manager 标记为 offline；
- Agent 被 `SIGKILL`、发生可检测卡死或 Sensor 退出时，能够自动恢复或明确进入 degraded/offline；
- observe-only 测试能够稳定记录终止尝试；
- enforcement 能够拒绝未授权终止，同时允许受审计、限时的安装、升级、停止和卸载；
- 不支持 BPF LSM 的主机能够 fail-open，并明确报告降级原因；
- Functional 测试覆盖启动、终止、卡死、连续崩溃、维护、重启和策略恢复。

### 当前证据

- [systemd Agent unit](../deployments/agent/systemd/sysarmor-agent.service)
- [Sensor 篡改与失明检测](../apps/agent/internal/domain/health/tamper.go)
- [真实 Tetragon Agent 生命周期测试](../test/suites/functional/endpoint/e2e-real-tetragon-owned-vm.sh)

### 边界

本阶段不宣称阻止宿主机 root 或内核级攻击者，不将自保护作为普通租户响应动作，也不会在缺少维护逃生路径时默认开启阻断。

## 阶段 2：信息效能与证据完整性

更细采集会增加 CPU、内存、磁盘和传输成本；只上传告警又会失去复核依据。本阶段让分层数据模型真正承担信息压缩与证据保真的职责。

### 当前基础

Agent 已具备有界 Event/Signal 保存、端侧规则与 ProcessProfile 模型检测、批量上传和资源健康指标；Manager 通过 `rule-only`、`learning-only`、`hybrid` 三种保护模式解析完整四层策略，Agent 只消费解析后的 Endpoint Policy。云侧已具备 Signal、Incident 和初始 Evidence 子图；medium 性能矩阵可在相同采集与场景条件下横向比较三种模式。

### 关键交付

1. 补齐 Cloud Signal 的规则、上游 Event/Signal、严重度、置信度和模式字段。
2. 将 Evidence pullback 从占位控制链路升级为受约束的真实 Event、raw reference 或原始材料回拉。
3. 为 collection、detection、telemetry 建立统一资源预算、回压和过载行为，禁止静默丢失。
4. 持续报告 Event 率、Signal 压缩比、CPU、内存、磁盘、网络和回拉成本。

### 退出标准

- Signal 和 Incident 的贡献来源可以稳定回溯；
- 高风险调查可以按授权回拉真实材料；
- quick/medium 性能档案具有明确预算和失败阈值；
- 所有丢弃、降级和引用缺口均可查询。

本阶段不以单一吞吐数字代替安全有效性，不默认上传全部原始事件，也不把缺失引用解释为行为未发生。

## 阶段 3：端云调查闭环

端侧拥有低延迟局部上下文，云侧拥有跨时间和跨实体视角。本阶段把两者连接为可重复、可解释的调查链路。

当前数据批次具备稳定身份和重试语义；云侧已经提供限定作用域的历史关联、实体图、K-hop、最短路径和确定性 Incident 投影。这些是调查闭环的算法与数据基础，不等同于完整因果溯源。

### 关键交付

1. 统一 Endpoint Signal、Cloud Signal 的派生引用和策略版本语义。
2. 将实体连接、时间顺序、检测依据和数据缺口共同纳入 Evidence。
3. 建立从 Incident 到 Signal、Event、有效策略和运行健康的连续调查路径。
4. 对候选攻击路径进行可解释排序，明确区分相关性、时间顺序和因果结论。

### 退出标准

- 代表性攻击场景可以从 Incident 稳定下钻到贡献 Signal 和可用原始事实；
- 重复输入和重试收敛到同一逻辑结果；
- 数据缺口会改变置信表达，而不是被静默忽略；
- 调查结论包含可机器验证的生成依据。

本阶段不把最短路径直接称为攻击路径，不把 Incident 变成人工工单，也不让自然语言解释替代 Evidence。

### 下一阶段专项计划

端云调查闭环的当前专项基础已经落地为 Flink Detector 平台和内置 Nodlink；后续重点是完整 Steiner Tree、路径排序、攻击阶段推理和真实原始材料回拉。模块合同和当前边界见[Detector 合同](development/detector-contract.md)与[溯源图检测平台计划](development/provenance-detection-plan.md)。

## 阶段 4：受控响应与动态博弈

自动化必须提高响应速度，但不能绕过权限、证据和生产安全边界。本阶段使 collection、detection、telemetry、response 能够在统一约束下随风险调整。

当前 Endpoint Policy 已包含四层策略；Manager 支持版本、分配、确认和响应审计；Agent 能够原子应用策略并报告有效状态。真实阻断尚未实现，response 默认保持 observe-only。

### 关键交付

1. 统一 response action、Sensor capability 和执行回执，实现至少一种可验证、可恢复的真实响应动作。
2. 根据高价值 Signal 在限定作用域、预算和时间窗口内临时加深采集或 Evidence 保留，并自动恢复。
3. telemetry 根据调查价值、风险和回压状态调整上传范围、优先级和速率。
4. Agentic 能力只生成带依据、影响范围和回滚条件的策略建议，发布仍受审批和策略约束。

### 退出标准

- 真实响应具备能力检查、审批、幂等、超时、审计和恢复验证；
- 临时策略能够按触发条件生效并按结束条件恢复；
- 策略变化可以关联到触发 Signal、资源影响和最终结果；
- 应用失败不会替换最后一个有效策略。

本阶段不允许模型绕过审批执行破坏性动作，不允许临时策略无限期生效，也不以自动化数量衡量动态防御能力。

## 维护规则

- 任一时刻只有一个“当前重点”阶段；其他阶段可以建设基础能力，但不争夺路线图主状态。
- 不使用完成百分比。只有全部退出标准具有可重复证据时，阶段才标记为“已验证”。
- Issue 关闭不代表阶段完成；退出标准仍失败时，状态不得提前更新。
- roadmap 只记录稳定目标和已存在证据；代码级任务、负责人和时间安排留在 Issue 与 Milestone。
- 当前能力以[系统架构](architecture.md)、Reference、代码和测试为事实来源；本路线图不把目标能力描述为当前事实。
