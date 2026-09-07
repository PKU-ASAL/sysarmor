# SysArmor 文档

这组文档面向三类读者：第一次运行 SysArmor 的使用者、负责部署和运维的平台人员、以及贡献检测算法的开发者。

## 推荐阅读

| 你想做什么 | 从这里开始 |
|---|---|
| 第一次运行 Agent | [快速开始](quickstart.md) |
| 理解系统里的数据 | [安全数据模型](concepts/security-data-model.md) |
| 理解检测和 Nodlink | [检测概念](concepts/detection.md) |
| 理解整体架构 | [架构总览](architecture/overview.md) |
| 理解设计取舍 | [设计原则](design/principles.md) |
| 配置和发布策略 | [策略指南](guides/policy.md) |
| 调查一个 Incident | [调查指南](guides/investigation.md) |
| 开发新的 Detector | [Detector 开发指南](guides/detector-development.md) |
| 部署和维护平台 | [部署指南](operations/deployment.md)、[维护指南](operations/maintenance.md) |
| 查找精确字段和命令 | [配置](reference/configuration.md)、[API](reference/api.md)、[CLI](reference/cli.md) |
| 验证代码和产品链路 | [测试指南](contributing/testing.md) |
| 查看后续能力 | [路线图](roadmap.md) |

## 文档地图

```text
quickstart.md                 最短可运行路径
concepts/                     对象和检测语义
architecture/                 组件职责和数据流
design/                       设计原则和取舍
guides/                       使用和贡献方法
operations/                   部署、升级、恢复
reference/                   精确接口、配置和 CLI
contributing/                 测试和贡献规范
roadmap.md                    尚未交付的长期能力
```

## 阅读约定

- 概念文档回答“它是什么”；架构文档回答“它怎样协作”；指南回答“怎样完成任务”；参考文档给出精确字段。
- 当前能力、后续能力和研究方向分开写。主文档不记录提交历史、迁移过程和临时排障笔记。
- 一个概念只在一个页面定义，其他页面通过链接引用。
- 命令以仓库 Makefile 和 `sysarmorctl --help` 为准，协议以 `packages/contracts/proto/` 为准。
- 性能报告和一次性实验材料保存在 `test/.results/` 或 `.scratchpad/`，不复制到长期文档。

## 事实来源

代码和测试是实现事实来源；本文档负责提供稳定的概念、边界和使用路径。发现文档与代码不一致时，先修正文档或明确记录尚未实现的能力，再提交变更。
