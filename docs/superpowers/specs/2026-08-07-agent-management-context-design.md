# Agent Management Context 设计

## 结论

Agent 新增一个轻量的内部 `management` 领域模块，集中解释 standalone 与 managed 管理关系。模块只负责回答当前控制权、身份来源和网络方式，不负责策略执行、网络连接、凭据存储或 Sensor 生命周期。

注册凭据成功持久化并进入 `enrolling` 后，Manager 立即取得唯一策略写权限。首份 managed policy 激活前，Agent 可以继续执行已有 standalone policy，保证端点防护不中断；该策略只是当前有效快照，不代表本地仍有控制权。

本设计不修改对外 API、控制协议、SQLite schema 或 Sensor 接口。

## 背景

当前 `EnrollmentState` 同时被 identity、network 和 policy authority 直接解释。不同模块对 `enrolling` 的语义不一致：网络已经使用 managed 通道，本地策略写入已经被禁止，但运行时身份仍使用 standalone identity。这使 Manager 首次下发的默认策略因 tenant 和 agent identity 不匹配而被拒绝，Enrollment 无法晋升为 `managed`。

该问题不是单个条件分支错误，而是管理语义缺少唯一解释入口。继续在各模块增加状态判断会保留同类漂移风险。

## 设计原则

1. 管理关系是持久化事实，运行时行为是该事实的可重建投影。
2. 策略控制权与当前有效策略来源分离。
3. Manager 在线状态不改变管理关系，避免状态组合爆炸。
4. Store 先提交，运行时随后幂等 reconcile；进程崩溃后可从 Store 恢复。
5. 非法或不可读取的状态 fail closed：保留最后有效防护，拒绝新的策略写入。
6. `management` 保持 Agent 内部，不进入跨产品 `packages/`。

## 领域边界

```text
localapi ----+
             +--> control use cases --> management domain
remoteapi ---+                              |
                                             v
                                      runtime adapters
                                identity / network / policy
                                             |
                                             v
                                         sensors
```

各模块职责：

- `management`：管理状态、派生上下文、策略写入授权和简单转换校验。
- `control`：注册、首份 managed policy 激活和退管用例编排。
- `localstore`：Enrollment 与 policy slot/activation 的事务持久化。
- `daemon`：将管理上下文应用到 identity、network 和运行时组件。
- `sensors`：只消费最终 Collection Intent，不感知管理模式。

`management` 禁止包含：

- Manager HTTP/gRPC 客户端；
- 证书签发、文件写入和密钥处理；
- 策略解析、编译和激活；
- 网络连接和重试实现；
- Sensor 生命周期；
- Health 汇总或 Telemetry 上传。

## 领域模型

首期保持模型最小，不引入通用状态机、事件总线或每状态一个 Strategy。

```go
type State string

const (
    StateStandalone  State = "standalone"
    StateEnrolling   State = "enrolling"
    StateManaged     State = "managed"
    StateUnenrolling State = "unenrolling"
)

type Authority string
type IdentitySource string
type TransportMode string
type PolicyWriteOrigin string

type Context struct {
    State          State
    Authority      Authority
    IdentitySource IdentitySource
    Transport      TransportMode
}

func Resolve(state State) (Context, error)
func (c Context) Authorize(origin PolicyWriteOrigin) error
func ValidateTransition(from, to State) error
```

`Context` 是纯派生值，不写入数据库。`Resolve` 和 `Authorize` 不产生副作用，使用表驱动测试覆盖全部输入。

## 状态语义

| Lifecycle | 策略控制权 | 身份来源 | 网络方式 | 本地策略修改 | 正常有效策略来源 |
| --- | --- | --- | --- | --- | --- |
| `standalone` | Local | 本地设备身份 | Standalone | 允许 | standalone |
| `enrolling` | Manager | Enrollment 身份 | Managed | 禁止 | 当前 activation，可能仍为 standalone |
| `managed` | Manager | Enrollment 身份 | Managed | 禁止 | managed |
| `unenrolling` | Manager | Enrollment 身份 | Managed | 禁止 | managed，直到退管事务完成 |

有效策略来源不放入 `Context`。它继续由 `policy_activation` 表独立记录，因为 `enrolling` 不能唯一决定当前策略来源。

Manager 连接是否在线属于 Health observation，不增加 `managed_online`、`managed_offline` 等管理状态。

## 状态转换

合法转换保持为四条：

```text
standalone  -> enrolling
enrolling   -> managed
managed     -> unenrolling
unenrolling -> standalone
```

注册准备失败发生在持久化之前，状态保持 `standalone`。进入 `enrolling` 后不因 Manager 暂时不可达、策略被拒绝或 Agent 重启而自动回退 `standalone`。

Store 使用带旧状态条件的更新保证并发一致性。`ValidateTransition` 只统一业务语义，不代替数据库 CAS。

## 注册流程

```text
1. 端点生成或复用待签发私钥并申请证书。
2. 凭据写入独立版本目录并完成校验。
3. 在 authority 临界区内将 Enrollment 持久化为 enrolling。
4. 从已提交状态 Resolve Context。
5. 使用 Enrollment identity 和 managed transport 启动控制通道。
6. 保持当前有效策略运行，但禁止本地策略修改。
7. 接收、验证并准备 Manager 默认策略。
8. 原子激活 managed policy，并将 Enrollment 更新为 managed。
9. 根据最新持久化状态再次 reconcile 运行时。
```

步骤 3 成功后 Manager 已是唯一策略权威。步骤 5 至 8 失败时保持 `enrolling`，由重连和策略重试恢复。

## 退管流程

```text
1. Manager 授权退管，Agent 持久化 unenrolling。
2. 保持 Manager authority、Enrollment identity 和 managed transport。
3. Manager 完成证书吊销并返回可验证确认。
4. Store 事务内激活保留的 standalone policy，并切换为 standalone。
5. 从已提交状态 reconcile 本地 identity 和 standalone transport。
6. 删除失效凭据并上报 endpoint completion；上报失败可重试。
```

在步骤 4 提交前，不允许本地策略修改，也不提前使用本地身份。

## 运行时 Reconcile

新增一个单一入口执行管理状态投影，调用方不能分别手写状态条件：

```go
func (r *AgentRuntime) reconcileManagementContext(enrollment localstore.Enrollment) error
```

其职责限定为：

1. 调用 `management.Resolve`；
2. 根据 `IdentitySource` 切换 normalizer、telemetry 和控制上下文身份；
3. 根据 `Transport` 幂等应用 network supervisor；
4. 暴露当前投影供 Health 使用。

策略激活由 policy controller 和 Store 事务负责，不由 reconcile 隐式修改。

启动、注册提交、managed policy 晋升和退管提交后都调用同一个 reconcile 入口。持久化已成功而运行时应用失败时，记录 transition error 并保持 fail closed，重启或下一次协调循环重新应用。

## 错误处理

- Manager 不可达：保持 `enrolling` 或 `managed`，继续执行最后有效策略并重试连接。
- 首份 managed policy 无效：保持 `enrolling`，记录 desired/pending 或 rejected 状态，不恢复本地权限。
- Enrollment state 非法：停止状态转换和新的策略写入，不自动解释为 standalone。
- Store 读取失败：拒绝本地与远端策略写入；已加载的检测和 Sensor 继续运行。
- Identity 应用失败：不得启动使用错误 identity 的 managed 控制会话。
- Network 应用失败：Health 标记 degraded，保持持久化管理关系并重试。

## 可观测性

Health 应从同一 `management.Context` 输出：

- `management_state`；
- `policy_authority`；
- `identity_source`；
- `transport_mode`；
- `effective_policy_source`；
- `desired_managed_policy_status`；
- `transition_phase` 和 `last_transition_error`。

字段命名遵循现有 Health 契约。若现有契约缺少对应字段，首期优先复用已存在的结构；新增对外字段需单独评估兼容性，不作为修复 P0 的前置条件。

## 测试与验收

### 单元测试

- 四种状态的完整 `Resolve` 表；
- local/manager 两类策略来源的授权矩阵；
- 所有合法和非法状态转换；
- 非法、空状态 fail closed；
- `enrolling` 必须选择 Enrollment identity 和 managed transport；
- Store 不可用时策略 mutation 不得被静默允许。

### Coordinator 测试

- 凭据准备失败保持 standalone；
- SetEnrolling 失败回滚凭据和网络；
- 进入 enrolling 后禁止本地修改；
- 首份 managed policy 失败保持 enrolling 和旧有效策略；
- 首份 managed policy 成功后原子晋升 managed；
- unenrolling 在吊销完成前保持 Manager authority；
- 重启可从每个过渡状态恢复。

### 集成与 E2E

- standalone 安装、策略应用、Event/Signal 和重启恢复；
- standalone 注册后成功接收 Manager 默认策略；
- enrolling 阶段 Manager 短暂不可达后恢复；
- managed 状态拒绝 localapi 策略写入；
- Manager 授权退管、证书吊销、恢复 standalone；
- topology、detection topology 和相关 release candidate 门禁全部通过。

## 实施分段

1. 新增最小 `management` 模型和失败优先的状态矩阵测试。
2. 将 identity、network 和 local policy mutation 收口到统一 Context。
3. 增加单一 runtime reconcile，并替换注册、启动、晋升和退管后的分散调用。
4. 补齐 Health 投影和过渡状态测试。
5. 修复并重跑真实 topology 与 detection E2E。

每一段独立提交，不同时处理 release 内容签名、性能测试版本或容器 JWT 等其他终审问题。

## 非目标

- 不增加 break-glass 本地修改；
- 不支持 managed 模式手工覆盖 Manager policy；
- 不改变 Manager 默认 policy 覆盖语义；
- 不引入多 Manager、控制权租约或离线授权策略；
- 不改造 Sensor 管理模型；
- 不建立通用工作流或状态机框架。

## 验收结论

完成后，任何 Enrollment state 在所有模块中只有一套管理语义。特别是 `enrolling` 必须同时满足 Manager authority、Enrollment identity、managed transport、本地写入禁止和旧策略持续运行，直到首份 managed policy 成功激活。
