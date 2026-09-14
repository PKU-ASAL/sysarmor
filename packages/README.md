# Shared Packages Governance

`packages/` 只承载跨产品的稳定契约和无单一产品归属的共享能力。它不是通用 helper 目录，也不是代码暂存区。

## 准入条件

新增 package 必须至少满足以下一项，并同时满足其余约束：

1. 已有两个或以上真实产品消费者，例如 Agent、Manager、CLI 或 Console 中的两个边界。
2. 承载明确版本化的跨产品稳定契约，例如 protobuf、schema 或 Sensor contract。

所有共享 package 还必须：

- 不依赖 `apps/` 下的任何产品实现；
- 不读取产品配置，不管理产品进程或生命周期；
- API 保持最小，并显式定义失败语义；
- 具备可独立运行的兼容性和行为测试。

## 禁止内容

以下代码默认保留在所属 `apps/*/internal`：

- 只有一个调用方的复用候选或临时 helper；
- Agent、Manager、CLI 或 Console 的产品配置；
- daemon、连接、任务或进程生命周期编排；
- PostgreSQL、SQLite、OpenSearch 等产品存储实现；
- 页面、组件和其他产品 UI 实现。

出现真实第二消费者后再提取共享能力，不为假设中的未来复用提前抽象。

## 当前业务模型归属

`contracts/controlmodel` 由 Agent SQLite 与 Manager PostgreSQL 共同消费，`contracts/health` 由 Agent Runtime 与 Manager HTTP/identity 共同消费，因此二者属于跨产品稳定契约。

只有 Agent 消费的 Policy、Event、Response 业务模型归属 `apps/agent/internal/domain`。不得通过 alias、forwarding package 或兼容 facade 维持旧共享路径；出现真实第二产品消费者时，再以独立契约评审决定是否提取。

## 依赖方向

```text
apps/* -> packages/*
packages/* -X-> apps/*
```

共享 package 可以依赖标准库、明确批准的第三方库或其他更基础的共享 package，但不得通过回调、注册表或生成代码绕过上述方向。

## 评审清单

新增或扩大共享 package 时，评审者必须确认：

- 真实消费者和跨产品价值已经明确；
- API 表达稳定领域语义，而不是产品实现细节；
- 错误、兼容性和版本演进策略清楚；
- 单元测试能够脱离具体产品运行；
- 没有形成 `packages/` 到 `apps/` 的反向依赖。
