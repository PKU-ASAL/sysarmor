# SysArmor 文档

SysArmor 是面向 Linux 的端点安全与关联分析系统。Agent 可以独立完成采集、检测和有界保存；接入管理平台后，系统增加集中策略、可靠上传、关联分析、调查和响应编排能力。

## 阅读路径

| 目标 | 文档 |
|---|---|
| 第一次运行 Agent | [快速开始](quickstart.md) |
| 理解 Event、Signal、Evidence 和 Incident | [安全数据模型](concepts/security-data-model.md) |
| 理解系统为什么这样设计 | [设计原则](design-principles.md) |
| 理解 Agent、平台和生产数据流 | [系统架构](architecture.md) |
| 了解尚未实现的目标 | [技术路线图](roadmap.md) |
| 配置 collection、detection、telemetry、response | [策略指南](guides/policy.md) |
| 安装、注册和管理 Agent | [Agent 管理](guides/agent-management.md) |
| 调查安全结果 | [调查指南](guides/investigation.md) |
| 部署 standalone Agent 或管理平台 | [部署指南](operations/deployment.md) |
| 升级、诊断和恢复 | [维护指南](operations/maintenance.md) |
| 查询精确配置和接口 | [配置参考](reference/configuration.md)、[API 参考](reference/api.md)、[CLI 参考](reference/cli.md) |
| 构建和验证项目 | [贡献指南](../CONTRIBUTING.md)、[测试指南](development/testing.md) |
| 开发或扩展云侧 Detector | [Detector 合同](development/detector-contract.md)、[流式检测术语表](development/streaming-concepts-glossary.md) |
推荐阅读顺序：

```text
新用户：README -> Quickstart -> Concepts
使用者：Concepts -> Architecture -> Guide -> Reference
贡献者：CONTRIBUTING -> Architecture -> Testing
```

## 文档职责

| 类型 | 回答的问题 |
|---|---|
| Tutorial | 第一次怎样运行？ |
| Concepts | 这些对象究竟是什么？ |
| Design Principles | 为什么这样取舍？ |
| Architecture | 当前生产系统怎样工作？ |
| Guide | 怎样完成一类任务？ |
| Reference | 精确字段和接口是什么？ |
| Operations | 怎样部署、维护和恢复？ |
| Development | 怎样贡献和验证？ |
| Roadmap | 哪些能力尚未实现？ |

## 唯一事实来源

| 主题 | 事实来源 |
|---|---|
| 核心安全数据概念 | [安全数据模型](concepts/security-data-model.md) |
| 三项设计原则 | [设计原则](design-principles.md) |
| 组件、运行模式和数据流 | [系统架构](architecture.md) |
| 中长期目标与退出标准 | [技术路线图](roadmap.md) |
| 四层策略模型 | [策略指南](guides/policy.md) |
| 配置字段和运行路径 | [配置参考](reference/configuration.md) |
| HTTP、gRPC 和 Wire Schema | [API 参考](reference/api.md)与 `packages/contracts/proto/` |
| CLI | [CLI 参考](reference/cli.md)与 `sysarmorctl --help` |
| 构建和代码边界 | [贡献指南](../CONTRIBUTING.md)与代码 |
| 测试方法 | [测试指南](development/testing.md)与 `test/Makefile help` |
| 溯源检测的当前实现与后续增强 | [溯源图检测平台计划](development/provenance-detection-plan.md)、[Detector 合同](development/detector-contract.md) |

## 维护规则

1. 一个主题只有一个定义，其他页面通过链接使用。
2. 当前能力、目标能力和研究设想必须明确区分。
3. Guide 不复制 Reference 字段，Architecture 不复制 Concepts 定义。
4. 命令以 Makefile 和 CLI `--help` 为准，协议以 Protobuf 为准。
5. 新页面必须有独立受众和职责；单页超过 500 行或具有独立生命周期时再拆分。
6. 实施计划、设计过程、商业材料和个人记录不进入公开文档树。
7. 性能数字和运行报告保存在 `test/.results/`，长期文档只说明测试方法。
8. 修改文档后运行文档合同和相关产品测试，不能留下失效链接。
